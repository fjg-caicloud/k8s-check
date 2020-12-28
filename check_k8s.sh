#!/bin/bash
:<<EOF
@author:fjg
@license: Apache Licence 
@file: check_k8s.sh
@time: 2020/12/24
@contact: fujiangong.fujg@bytedance.com
@site:  
@software: PyCharm

脚本中使用到的命令:
echo、curl、netstat、docker、grep、awk、kubelet、sed、date、cut、openssl、nmap、base64、cat、sort、uniq、read、nc
EOF

logCheckDay=1
certCheckDay=14
podRestartCheckNum=20
busyboxImage="busybox:1.28.0"
healthCheckDir="/tmp/healthCheck"
k8sConfDir="/etc/kubernetes"
externalDomain=("www.sina.com" "www.baidu.com" "www.fujiangong.com" "lucky fjg")
internalDomain=("kubernetes.default" "kube-dns.kube-system.svc.cluster.local")
podStatusCheck=("Running" "Completed" "CrashLoopBackOff" "ImagePullBackOff" "ContainerCreating" "Terminating" "Error")
tmpPodName="check-busybox-$(date +%F)"
clusterInfoDumpFile="$healthCheckDir/clusterInfo.dump"

if [ ! -d "$healthCheckDir" ]; then
 mkdir -p "$healthCheckDir"
fi

blue(){
    echo -e "\033[34m $1 \033[0m"
}

green(){
    echo -e "\033[32m $1 \033[0m"
}

bred(){
    echo -e "\033[31m\033[01m\033[05m $1 \033[0m"
}

byellow(){
    echo -e "\033[33m\033[01m\033[05m $1 \033[0m"
}

red(){
    echo -e "\033[31m\033[01m $1 \033[0m"
}

yellow(){
    echo -e "\033[33m\033[01m $1 \033[0m"
}

check_kube-apiserver() {
  green ".check apiserver"
  blue "├──check apiserver process"
  if ! netstat -ntlp|grep kube-api > /dev/null; then
    red "  └──Error: service kube-apiserver process is not running"
  else
    green "  └──[Info] apiserver process is exits"
    blue "├──check apiserver health"
  #  grep client-cert ~/.kube/config |cut -d" " -f 6|base64 -d > "$healthCheckDir"/apiserver-client.crt
  #  grep client-key-data ~/.kube/config |cut -d" " -f 6|base64 -d > "$healthCheckDir"/apiserver-client.key
  #  grep certificate-authority-data ~/.kube/config |cut -d" " -f 6|base64 -d > "$healthCheckDir"/apiserver-ca.crt
  #  local apiserver=$(kubectl config view |grep server|awk -F "server: " '{print $2}')
  #  local serverStatus=$(curl -s --cert "$healthCheckDir"/apiserver-client.crt --key "$healthCheckDir"/apiserver-client.key --cacert "$healthCheckDir"/apiserver-ca.crt "$apiserver"/healthz)
    local healthUrl="https://localhost:6443/healthz"
    local serverStatus=$(curl -sk "$healthUrl")
    if [[ "$serverStatus" == "ok" ]];then
      green  "  └──[Info] apiserver health check is ok"
    else
      red  "  └──[Error] apiserver health check is $serverStatus"
    fi
    blue "└──check apiserver [Error] log"
    local dockerId=$(docker ps|grep -v pause|grep apiserver|awk '{print $1}')
    docker logs --since $((logCheckDay * 24))h "$dockerId" --details >& "$healthCheckDir"/apiserver.log
    local errorLog=$(grep "^ E" "$healthCheckDir"/apiserver.log)
    if [[ "$errorLog" != "" ]];then
      red "  └──[Error] apiserver container $dockerId has error log in $logCheckDay days"
      red "$(grep "^ E" "$healthCheckDir"/apiserver.log|sed s'/^/      /')"
#      red "    └──$errorLog"
    else
      green "  └──no [error] log in $logCheckDay days"
    fi
  fi
}

check_kube-scheduler() {
  green ".check kube-scheduler"
  blue "├──check apiserver process"
  if ! netstat -ntlp|grep kube-schedule > /dev/null; then
    red "  └──[Error] service kube-schedule is not running"
  else
    green "  └──[Info] scheduler process is exits"
    blue "├──check kube-schedule health"
    local healthUrl="https://localhost:10259/healthz"
    local serverStatus=$(curl -sk "$healthUrl")
    if [[ "$serverStatus" == "ok" ]];then
      green  "  └──[Info] kube-scheduler health check is ok"
    else
      red  "  └──[Error] kube-scheduler health check is $serverStatus"
    fi
    blue "└──check scheduler [Error] log"
    local dockerId=$(docker ps|grep -v pause|grep scheduler|awk '{print $1}')
    docker logs --since $((logCheckDay * 24))h "$dockerId" --details >& "$healthCheckDir"/scheduler.log
    local errorLog=$(grep "^ E" "$healthCheckDir"/scheduler.log)
    if [[ "$errorLog" != "" ]];then
      red "  └──[Error] scheduler container $dockerId has error log in $logCheckDay days"
      red "$(grep "^ E" "$healthCheckDir"/scheduler.log|sed s'/^/      /')"
#      red "    └──$errorLog"
    else
      green "  └──no [error] log in $logCheckDay days"
    fi
  fi
}

check_kube-controller-manager() {
  green ".check kube-controll"
  blue "├──check kube-controll health"
  if ! netstat -ntlp|grep kube-controll > /dev/null; then
    red "  └──[Error] service kube-controll is not running"
  else
    green "  └──[info] kube-controll process is exits"
    blue "├──check kube-controll health"
    local healthUrl="https://localhost:10257/healthz"
    local serverStatus=$(curl -sk "$healthUrl")
    if [[ "$serverStatus" == "ok" ]];then
      green  "  └──[info] kube-controll health check is ok"
    else
      red  "  └──[Error] kube-controll health check is $serverStatus"
    fi
    blue "└──check kube-controll [Error] log"
    local dockerId=$(docker ps|grep -v pause|grep kube-controll|awk '{print $1}')
    docker logs --since $((logCheckDay * 24))h "$dockerId" --details >& "$healthCheckDir"/kube-controll.log
    local errorLog=$(grep "^ E" "$healthCheckDir"/kube-controll.log)
    if [[ "$errorLog" != "" ]];then
      red "  └──[Error] kube-controll container $dockerId has [error] log in $logCheckDay days"
      red "$(grep "^ E" "$healthCheckDir"/kube-controll.log|sed s'/^/      /')"
#      red "    └──$errorLog"
    else
      green "  └──[Info] no [error] log in $logCheckDay days"
    fi
  fi
}

check_etcd() {
  green ".check etcd"
  if ! netstat -ntlp|grep etcd > /dev/null; then
    red "  └──[Error] service etcd is not running"
  else
    green "  └──[info] etcd process is exits"
#    blue "├──check etcd health"
#    local healthUrl="http://localhost:2381/health"
#    local serverStatus=$(curl -s "$healthUrl"|awk -F :\" '{print $2 }'|cut -d \" -f  1)
#    if [[ "$serverStatus" == "true" ]];then
#      green  "  └──[info] etcd health check is ok"
#    else
#      red  "  └──[Error] etcd health check is $serverStatus"
#    fi
    blue "└──check etcd [Error] log"
    local dockerId=$(docker ps|grep -v pause|grep etcd|awk '{print $1}')
    docker logs --since $((logCheckDay * 24))h "$dockerId" --details >& "$healthCheckDir"/etcd.log
    local errorLog=$(grep "E |" "$healthCheckDir"/etcd.log)
    if [[ "$errorLog" != "" ]];then
      red "  └──[Error] etcd container $dockerId has [error] log in $logCheckDay days"
      red "$(grep "E |" "$healthCheckDir"/etcd.log|sed s'/^/      /')"
#      red "    └──$errorLog"
    else
      green "  └──[Info] no [error] log"
    fi
    blue "└──check etcd [too long] log"
    local tooLongLog=$(grep "too long" "$healthCheckDir"/etcd.log)
    if [[ "$tooLongLog" != "" ]];then
      red "  └──[warning] etcd container $dockerId has [too long] log in $logCheckDay days"
      red "$(grep "too long" "$healthCheckDir"/etcd.log|sed s'/^/      /')"
#      red "    └──$tooLongLog"
    else
      green "  └──[Info] no [too long] log in $logCheckDay days"
    fi
  fi
}

check_cert_time(){
    local cert=$1
    local notAfter=$(openssl x509 -in "$cert" -noout -dates|grep notAfter|awk -F = '{print $2}')
    local remainingTime=$(($(date +%s -d "$notAfter")-$(date +%s)))
    local warningTime=$((60*60*24*certCheckDay))
    if [[ "$remainingTime" -lt "$warningTime" ]];then
      yellow "  └──[Warning] $cert end time：[$notAfter]，remaining time：$((remainingTime/60/60/24)) days，threshold days is $certCheckDay days"
    else
      green "  └──[Info] $cert end time：[$notAfter]，remaining time：$((remainingTime/60/60/24)) days"
    fi
}

check_conf_cert(){
  local configFile=$1
  if [[ "$configFile" == "kubelet.conf" ]];then
    local configAuthCert=$(grep client-certificate /etc/kubernetes/kubelet.conf|awk -F ": " '{print $2}')
    if [[ ! -f "$configAuthCert" ]];then
      grep client-cert "$configFile" |cut -d" " -f 6|base64 -d > "$healthCheckDir"/"$configFile".crt
      local configAuthCert="$healthCheckDir/$configFile.crt"
    fi
  else
    grep client-cert "$configFile" |cut -d" " -f 6|base64 -d > "$healthCheckDir"/"$configFile".crt
    local configAuthCert="$healthCheckDir/$configFile.crt"
  fi
  check_cert_time "$configAuthCert"
}

check_cert() {
  green ".check cert"
  blue "├──check k8s cert"
  for cert in "$k8sConfDir"/pki/*.crt;do
    check_cert_time "$cert"
  done
  blue "├──check etcd cert"
  for cert in "$k8sConfDir"/pki/etcd/*.crt;do
    check_cert_time "$cert"
  done
  blue "├──check conf cert"
  cd "$k8sConfDir" || exit
  for conf in *.conf;do
    check_conf_cert "$conf"
  done
}

check_coredns_replicas(){
  green ".check coredns replicas"
  local availableReplicas=$(kubectl -n kube-system get deployments.apps coredns -o jsonpath='{.status.availableReplicas}')
  local readyReplicas=$(kubectl -n kube-system get deployments.apps coredns -o jsonpath='{.status.readyReplicas}')
  local replicas=$(kubectl -n kube-system get deployments.apps coredns -o jsonpath='{.spec.replicas}')
  if [[ "$availableReplicas" -eq 0 ]]||[[ "$readyReplicas" -eq 0 ]];then
    red "  └──[Error] coredns availableReplicas or readyReplicas is 0 "
  elif [[ "$availableReplicas" -ne "$replicas" ]]&&[[ "$readyReplicas" -ne "$replicas" ]];then
    yellow "  └──[Warning] coredns replica is $replicas ,availableReplicas is $availableReplicas, replicas is $readyReplicas"
  else
    green "  └──[Warning] coredns is ok，coredns replica is $replicas ,availableReplicas is $availableReplicas, replicas is $readyReplicas"
  fi
}
dns_check(){
  if ! host "$1" >/dev/null;then
    red "  └──[Error] node check domain $domain error"
  else
    green "  └──[Info] node check domain $domain pass"
  fi
}

check_pod_dns(){
  local podNum=$(kubectl get pods "$tmpPodName"|grep -c Running)
  while [[ "$podNum" -ne 1 ]] ;do
    local podNum=$(kubectl get pods "$tmpPodName"|grep -c Running)
  done
  if [[ "$podNum" -eq 1 ]];then
      for domain in "${internalDomain[@]}";do
        if kubectl exec "$tmpPodName" -- nslookup "$domain" >& /dev/null;then
          green "  └──[Info] pod check internal domain $domain pass"
        else
          red "  └──[Error] pod check internal domain $domain error"
        fi
      done
      for domain in "${externalDomain[@]}";do
        if kubectl exec "$tmpPodName" -- nslookup "$domain" >& /dev/null;then
          green "  └──[Info] pod check external domain $domain pass"
        else
          red "  └──[Error] pod check external domain $domain error"
        fi
      done
    fi
}

check_dns(){
  green ".check dns"
  blue "├──check node dns"
  check_node_dns
  blue "└──check pod dns"
  check_pod_dns
}

check_node_status(){
  kubectl cluster-info dump >& "$clusterInfoDumpFile"
  green ".check node info"
  blue "└──check node ready status"
  local availableNode=$(kubectl get nodes --no-headers|wc -l)
  local notReadyNodeNum=$(kubectl get nodes --no-headers |grep -cv Ready)
  if [[ "$notReadyNodeNum" -ne 0 ]];then
    local notReadyNode=$(kubectl get nodes --no-headers |grep -v Ready)
    red "  └──[Error] has $notReadyNodeNum node not ready：$notReadyNode"
  else
    green "  └──[Info] $availableNode nodes all ready."
  fi
}

check_pods_status(){
  green ".check pods status"
  for status in "${podStatusCheck[@]}";do
    local num=$(kubectl get pods --all-namespaces --no-headers |grep -c "$status")
    if [[ "$status" == "Running" ]]||[[ "$status" == "Completed" ]];then
      green "  └──[Info] $num pods is $status"
    elif [[ "$num" -ne 0 ]];then
      red "  └──[Error] $num pods is $status"
      red "$(kubectl get pods --all-namespaces --no-headers |grep "$status"|sed s'/^/      /')"
    fi
  done
  local restartPodNum=$(kubectl get pods --all-namespaces --no-headers |awk -v restartNum=$podRestartCheckNum '{if($5>restartNum) print $0}'|wc -l)
  if [[ "$restartPodNum" -ne 0 ]];then
    red "  └──[Error] $restartPodNum pods is restart > $podRestartCheckNum"
    red "$(kubectl get pods --all-namespaces --no-headers |awk -v restartNum=$podRestartCheckNum '{if($5>restartNum) print $0}'|sed s'/^/      /')"
  fi
}

check_svc_ip(){
  green ".check svc ip"
  kubectl cluster-info dump >& "$clusterInfoDumpFile"
  local svcCidrDump=$(grep -m 1 -Po '(?<=--service-cluster-ip-range=)[0-9.\/]+' $clusterInfoDumpFile)
  local svcCidrKubeadm=$(kubeadm config view | grep serviceSubnet|awk -F ": " '{print $2}'|awk -F '"' '{print $2}')
  if [[ $svcCidrDump == "" ]]&&[[ $svcCidrKubeadm == '""' ]];then
    yellow "  └──[Warning] can't get cluster-cidr"
    return
  elif [[ $svcCidrDump == "" ]];then
    local svcCidr=$svcCidrKubeadm
  else
    local svcCidr=$svcCidrDump
  fi
  local svcUsageNum=$(kubectl get svc --all-namespaces --no-headers |awk '{print $4}'|grep -civ none)
  local svcIpMax=$(nmap -sL -n "$svcCidr"|grep -c "Nmap scan report for")
  if [[ "$svcUsageNum" -gt $((svcIpMax * 8  / 10)) ]];then
    yellow "  └──[Warning] cluster ip used grater than 80%，used：$svcUsageNum，max: $svcIpMax"
  else
    green "  └──[Info] cluster ip used: $svcUsageNum, max: $svcIpMax，residue: $((svcIpMax - svcUsageNum))"
  fi
}

check_pod_ip(){
  green ".check pod ip"
  local podCidrDump=$(grep -m 1 -Po '(?<=--cluster-cidr=)[0-9.\/]+' $clusterInfoDumpFile)
  local podCidrKubeadm=$(kubeadm config view | grep podSubnet|awk -F ": " '{print $2}')
  if [[ $podCidrDump == "" ]]&&[[ $podCidrKubeadm == '""' ]];then
    yellow "  └──[Warning] can't get cluster-cidr"
    return
  elif [[ $podCidrDump == "" ]];then
    local podCidr=$podCidrKubeadm
  else
    local podCidr=$podCidrDump
  fi
  local allPodIpFile="$healthCheckDir/allPodIpList.log"
  kubectl get pods --all-namespaces --no-headers -owide |awk '{print $7}'|grep -civ none|sort|uniq > $allPodIpFile
  local nodeIpFile="$healthCheckDir/nodeIpList.log"
  kubectl get node -owide --no-headers|awk '{print $6}' > "$nodeIpFile"
  local ipUsageNum=$(sort "$nodeIpFile" $nodeIpFile $allPodIpFile|uniq -u|wc -l)
  local podIpMax=$(nmap -sL -n "$podCidr"|grep -c "Nmap scan report for")
  if [[ "$ipUsageNum" -gt $((podIpMax * 8  / 10)) ]];then
    yellow "  └──[Warning] cluster ip used grater than 80%，used：$ipUsageNum，max: $podIpMax"
  else
    green "  └──[Info] cluster ip used: $ipUsageNum, max: $podIpMax，residue: $((podIpMax - ipUsageNum))"
  fi
}

check_net(){
  green ".check net"
  local nodeIpFile="$healthCheckDir/nodeIpList.log"
  kubectl get node -owide --no-headers|awk '{print $6}' > "$nodeIpFile"
  local nsPodIpFile="$healthCheckDir/nsPodIpList.log"
  kubectl get pods --no-headers -n kube-system -owide|awk '{print $6}'|grep -iv none|sort|uniq > "$nsPodIpFile"
  local svcListFile="$healthCheckDir/svcList.log"
  kubectl get svc -oyaml -o=custom-columns=NAME:.metadata.name,CLUSTER-IP:.spec.clusterIP,PORT:.spec.ports[0].port --no-headers -n kube-system|grep -iv none > "$svcListFile"
  local nsPodIpList=$(sort "$nodeIpFile" $nodeIpFile $nsPodIpFile|uniq -u)
  local podNum=$(kubectl get pods "$tmpPodName"|grep -c Running)
  while [[ "$podNum" -ne 1 ]] ;do
    local podNum=$(kubectl get pods "$tmpPodName"|grep -c Running)
  done
  if [[ "$podNum" -eq 1 ]];then
    blue "├──check pod -> node"
    while IFS= read -r ip;do
      if ! kubectl exec "$tmpPodName" -- ping "$ip" -c 2 >&/dev/null;then
        red "  └──[Error] check pod -> node：$ip error"
      else
        green "  └──[Info] check pod -> node：$ip pass"
      fi
    done < "$nodeIpFile"
    blue "├──check pod -> svc"
    while IFS= read -r svc;do
      local svcName svcIp svcPort
      read -r svcName svcIp svcPort <<< "$(echo "$svc"|awk '{print $1,$2,$3}')"
      if ! timeout 5 kubectl exec "$tmpPodName" -- nc -z "$svcIp" "$svcPort";then
        red "  └──[Error] check pod -> svc [$svcName $svcIp $svcPort] error"
      else
        green "  └──[Info] check pod -> svc [$svcName $svcIp $svcPort] pass"
      fi
    done < "$svcListFile"
    blue "├──check node -> node"
    while IFS= read -r ip;do
      if ! ping "$ip" -c 2 >&/dev/null;then
        red "  └──[Error] check node -> node：$ip error"
      else
        green "  └──[Info] check node -> node：$ip pass"
      fi
    done < "$nodeIpFile"
    blue "└──check node -> pod"
    for ip in $nsPodIpList;do
      if ! ping "$ip" -c 2 >&/dev/null;then
        red "  └──[Error] check node -> pod：$ip error"
      else
        green "  └──[Info] check node -> pod：$ip pass"
      fi
    done
  fi
}

# all nodes check
check_conntrack(){
  green ".check conntrack"
  local nfConntrackCount="$(cat /proc/sys/net/netfilter/nf_conntrack_count)"
  local nfConntrackMax="$(cat /proc/sys/net/netfilter/nf_conntrack_max)"
  # nf_conntrack_usage_rate=$(echo "sclae=2; $nfConntrackCount/$nf_conntrack_max" | bc)
  local nfConntrackUsageRate=$(awk 'BEGIN{printf "%.4f\n","'"${nfConntrackCount}"'"/"'"${nfConntrackMax}"'"}')
  if [ "$(expr "${nfConntrackUsageRate}" \> 0.8)" -eq 1 ];then
    yellow "  └──[Error] conntrack usage rate > 80%，nfConntrackUsageRate"
  else
    green "  └──[Info] conntrack used $nfConntrackCount，max $nfConntrackMax"
  fi
}

check_containerd() {
  green ".check containerd"

  if ! pgrep -fl containerd|grep -Ev "shim|dockerd" > /dev/null ;then
    red "  └──[Error] service containerd is not running"
  else
    green "  └──[info] containerd process is exits"
  fi
}

check_kubelet_cert(){
  green ".check kubelet conf cert"
  cd "$k8sConfDir" || exit
  for conf in *.conf;do
    check_conf_cert "$conf"
  done
}

check_node_dns() {
  for domain in "${externalDomain[@]}";do
    dns_check "$domain"
  done
}

check_node_to_apiserver(){
  green ".check node -> apiserver"
  local apiserver=$(grep server "$k8sConfDir"/kubelet.conf|awk -F server: '{print $2}'|sed -e 's/^[[:space:]]*//')
  local serverStatus=$(curl -sk "$apiserver"/healthz)
  if [[ "$serverStatus" == "ok" ]];then
    green  "  └──[Info] node -> apiserver  is ok"
  else
    red  "  └──[Error] node -> apiserver is $serverStatus"
  fi
}

kubectl run "$tmpPodName" --image="$busyboxImage" --restart='Never' -- sleep 1h >& /dev/null
sleep 5s
# master and etcd 节点
check_kube-apiserver
check_kube-controller-manager
check_kube-scheduler
check_etcd
check_cert
check_coredns_replicas
check_dns
check_node_status
check_pods_status
check_svc_ip
check_pod_ip
check_net

# all node
#check_conntrack
#check_containerd
#check_kubelet_cert
#check_node_dns
#check_node_to_apiserver
kubectl delete pods "$tmpPodName" --force >& /dev/null