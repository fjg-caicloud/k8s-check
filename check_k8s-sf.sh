#!/bin/bash
:<<EOF
@author:fjg
@license: Apache Licence
@file: check_k8s.sh
@time: 2020/12/24
@contact: fujiangong.fujg@bytedance.com
@site:
@software: PyCharm

EOF

logCheckDay=1
certCheckDay=14
podRestartCheckNum=20
clusterRequestCheckPercent=80
busyboxImage="busybox:1.27.2"
healthCheckDir="/tmp/healthCheck"
k8sConfDir="/etc/kubernetes"
externalDomain=("www.sina.com" "www.baidu.com" "www.fujiangong.com" "lucky fjg")
internalDomain=("kubernetes.default" "kube-dns.kube-system.svc.cluster.local")
podStatusCheck=("Running" "Completed" "CrashLoopBackOff" "ImagePullBackOff" "ContainerCreating" "Terminating" "Error")
machineId=$(cat /etc/machine-id)
tmpPodName="check-pod-$machineId-$(date +%F)"
commandList=(echo curl netstat docker grep awk kubelet sed date cut openssl base64 cat sort uniq read host)
maxLogSize=20480
etcdConfigFile="/etc/etcd/cfg/etcd.conf"

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

check_command(){
  green ".check command"
  local checkPass="true"
  for cmd in "${commandList[@]}";do
    if ! command -v "$cmd" >& /dev/null;then
      red "  └──[Error] command [$cmd] could not found!"
      checkPass="false"
    else
      green "  └──[Info] command [$cmd] check pass"
    fi
  done
  if [[ "$checkPass" == "false" ]];then
    red "  └──[Error] some command not found!"
    exit 1
  fi
}

check_file_size(){
  du -b "$1" |awk -v size="$maxLogSize" '{if($1>size){print "true"}else{print "false"}}'
}

check_check_pod(){
  green ".check $tmpPodName pods status"
  if ! kubectl get pods "$tmpPodName" --no-headers >& /dev/null;then
    kubectl run "$tmpPodName" --image="$busyboxImage" --restart='Never' -- sleep 1h >& /dev/null
    sleep 10s
  fi
  local podNum=$(kubectl get pods "$tmpPodName"|grep -c Running)
  local checkTime=10
  local checked=0
  while [[ "$podNum" -ne 1 ]]&&[[ "$checked" -lt $checkTime ]] ;do
    local podNum=$(kubectl get pods "$tmpPodName"|grep -c Running)
    sleep 1s
    checked=$((checked+1))
  done
  if [[ "$podNum" -ne 1 ]]&&[[ "$checked" -eq "$checkTime" ]];then
    red "  └──[Error] check pod $tmpPodName not Running!!!!"
    kubectl delete pods "$tmpPodName" --force >& /dev/null
    exit 1
  else
    green "  └──[Info] pod $tmpPodName is Running!"
  fi
}

get_check_data() {
  green ".get check data"
  blue "└──get all node info"
  allNodeFile="$healthCheckDir/allNodeList.txt"
  kubectl get nodes --no-headers -owide >& "$allNodeFile"
  blue "└──get all node ip list"
  nodeIpFile="$healthCheckDir/nodeIpList.txt"
  awk '{print $6}' "$allNodeFile" > "$nodeIpFile"
  blue "└──get node capacity"
  nodeCapacityFile="$healthCheckDir/nodeCapacity.txt"
  kubectl get nodes -o custom-columns=NAME:.metadata.name,CPU:.status.capacity.cpu,MEM:.status.capacity.memory --no-headers > "$nodeCapacityFile"
  blue "└──get all pods info"
  allPodsFile="$healthCheckDir/allPodList.txt"
  kubectl get pods --all-namespaces --no-headers -owide >& "$allPodsFile"
  blue "└──get all pods ip list"
  allPodIpFile="$healthCheckDir/allPodIpList.txt"
  awk '{print $7}' "$allPodsFile"|grep -iv none|sort|uniq > $allPodIpFile
  blue "└──get ns kube-system pod ip list"
  nsPodIpFile="$healthCheckDir/nsPodIpList.txt"
  grep kube-system $allPodsFile|awk '{print $7}'|grep -iv none|sort|uniq > "$nsPodIpFile"
  blue "└──get all svc info"
  allServiceFile="$healthCheckDir/allServiceList.txt"
  kubectl get svc --all-namespaces --no-headers -owide >& "$allServiceFile"
  blue "└──get ns kube-system svc ip and port"
  svcListFile="$healthCheckDir/nsSvcList.txt"
  kubectl get svc -oyaml -o=custom-columns=NAME:.metadata.name,CLUSTER-IP:.spec.clusterIP,PORT:.spec.ports[0].port --no-headers -n kube-system|grep -iv none > "$svcListFile"
  blue "└──get weave pods list"
  weavePodsFile="$healthCheckDir/weavePodsList.txt"
  kubectl get pods -n kube-system -l name=weave-net -o wide --no-headers > "$weavePodsFile"
}

check_kube-apiserver() {
  green ".check apiserver"
  blue "└──check apiserver process"
  if ! ss -ntlp|grep kube-api > /dev/null; then
    red "  └──[Error] service kube-apiserver process is not running"
  else
    green "  └──[Info] apiserver process is exits"
    blue "└──check apiserver health"
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
    local errorLogFile="$healthCheckDir/apiserver-error.log"
    grep "^ E" "$healthCheckDir"/apiserver.log > $errorLogFile
    if [[ -s "$errorLogFile" ]];then
      if [[ $(check_file_size "$errorLogFile") == "false" ]];then
        red "  └──[Error] apiserver container $dockerId has error log in $logCheckDay days"
        red "$(sed s'/^/      /' "$errorLogFile")"
      else
        red "  └──[Error] logs file $errorLogFile greater than $maxLogSize，Please view the file yourself"
      fi
    else
      green "  └──[Info] no [error] log in $logCheckDay days"
    fi
  fi
}

check_kube-scheduler() {
  green ".check kube-scheduler"
  blue "└──check apiserver process"
  if ! ss -ntlp|grep kube-schedule > /dev/null; then
    red "  └──[Error] service kube-schedule is not running"
  else
    green "  └──[Info] scheduler process is exits"
    blue "└──check kube-schedule health"
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
    local errorLogFile="$healthCheckDir/scheduler-error.log"
    grep "^ E" "$healthCheckDir"/scheduler.log > $errorLogFile
    if [[ -s "$errorLogFile" ]];then
      if [[ $(check_file_size "$errorLogFile") == "false" ]];then
        red "  └──[Error] apiserver container $dockerId has error log in $logCheckDay days"
        red "$(sed s'/^/      /' "$errorLogFile")"
      else
        red "  └──[Error] logs file $errorLogFile greater than $maxLogSize，Please view the file yourself"
      fi
    else
      green "  └──[Info] no [error] log in $logCheckDay days"
    fi
  fi
}

check_kube-controller-manager() {
  green ".check kube-controll"
  blue "└──check kube-controll process"
  if ! ss -ntlp|grep kube-controll > /dev/null; then
    red "  └──[Error] service kube-controll is not running"
  else
    green "  └──[info] kube-controll process is exits"
    blue "└──check kube-controll health"
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
    local errorLogFile="$healthCheckDir/kube-controll-error.log"
    grep "^ E" "$healthCheckDir"/kube-controll.log > $errorLogFile
    if [[ -s "$errorLogFile" ]];then
      if [[ $(check_file_size "$errorLogFile") == "false" ]];then
        red "  └──[Error] apiserver container $dockerId has error log in $logCheckDay days"
        red "$(sed s'/^/      /' "$errorLogFile")"
      else
        red "  └──[Error] logs file $errorLogFile greater than $maxLogSize，Please view the file yourself"
      fi
    else
      green "  └──[Info] no [error] log in $logCheckDay days"
    fi
  fi
}

check_etcd() {
  green ".check etcd"
  blue "└──check etcd process"
  if ! ss -ntlp|grep etcd > /dev/null; then
    red "  └──[Error] service etcd is not running"
  else
    green "  └──[info] etcd process is exits"
    blue "└──check etcd service is active"
    local serverStatus=$(systemctl is-active etcd)
    if [[ "$serverStatus" == "active" ]];then
      green  "  └──[info] etcd server status is active"
    else
      red  "  └──[Error] etcd health check isn't active。$serverStatus"
    fi
    blue "└──check etcd cluster health"
    # shellcheck source=$etcdConfigFile
    source $etcdConfigFile
    local endpoints=$(ETCDCTL_API=3 $(which etcdctl) --cacert="$ETCD_CA_FILE" --cert="$ETCD_CERT_FILE" --key="$ETCD_KEY_FILE" --endpoints=https://127.0.0.1:2379 member list|awk '{print $NF}'|tr '\n' ',')
    local endpointHealthFile="$healthCheckDir/etcd-endpoint-health.log"
    ETCDCTL_API=3 $(which etcdctl) --cacert="$ETCD_CA_FILE" --cert="$ETCD_CERT_FILE" --key="$ETCD_KEY_FILE" --endpoints="${endpoints%,}" endpoint health > "$endpointHealthFile"
    while IFS= read -r endpoint;do
      local endpointStatus=$(echo "$endpoint"|awk '{print $3}')
      local endpointUrl=$(echo "$endpoint"|awk '{print $1}')
      if [[ "$endpointStatus" == "healthy:" ]];then
        green "  └──[info] $endpointUrl health check is ${endpointStatus%:}"
      else
        red "  └──[Error] $endpointUrl health check is ${endpointStatus%:}"
      fi
    done < "$endpointHealthFile"
    blue "└──check etcd [Error] log"
    local etcdLogFile="$healthCheckDir/etcd.log"
    journalctl -x --since "$(date +%F -d "$logCheckDay days ago")" -u etcd 1 >$etcdLogFile
    local errorLogFile="$healthCheckDir/etcd-error.log"
    grep "E |" "$etcdLogFile" > $errorLogFile
    if [[ -s "$errorLogFile" ]];then
      if [[ $(check_file_size "$errorLogFile") == "false" ]];then
        red "  └──[Error] etcd has error log in $logCheckDay days"
        red "$(sed s'/^/      /' "$errorLogFile")"
      else
        red "  └──[Error] logs file $errorLogFile greater than $maxLogSize，Please view the file yourself"
      fi
    else
      green "  └──[Info] no [error] log in $logCheckDay days"
    fi
    blue "└──check etcd [too long] log"
    local tooLongLogFile="$healthCheckDir/etcd-too-long.log"
    grep "too long" "$etcdLogFile" > $tooLongLogFile
    if [[ -s "$tooLongLogFile" ]];then
      if [[ $(check_file_size "$tooLongLogFile") == "false" ]];then
        red "  └──[Error] etcd has error log in $logCheckDay days"
        red "$(sed s'/^/      /' "$tooLongLogFile")"
      else
        red "  └──[Error] logs file $tooLongLogFile greater than $maxLogSize，Please view the file yourself"
      fi
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
  blue "└──check k8s cert"
  for cert in "$k8sConfDir"/pki/*.crt;do
    check_cert_time "$cert"
  done
  blue "└──check etcd cert"
  # shellcheck source=$etcdConfigFile
  source $etcdConfigFile
  check_cert_time "$ETCD_CA_FILE"
  check_cert_time "$ETCD_CERT_FILE"
  check_cert_time "$ETCD_PEER_CA_FILE"
  check_cert_time "$ETCD_PEER_CERT_FILE"
#  for cert in "$k8sConfDir"/pki/etcd/*.crt;do
#    check_cert_time "$cert"
#  done
  blue "└──check conf cert"
  cd "$k8sConfDir" || exit
  for conf in *.conf;do
    check_conf_cert "$conf"
  done
}

check_coredns_replicas(){
  green ".check coredns replicas"
  local availableReplicas readyReplicas replicas ready
  read -r availableReplicas ready <<< "$(kubectl -n kube-system get deployments.apps coredns --no-headers|awk '{print $4,$2}')"
  read -r readyReplicas replicas <<< "$(echo "$ready"|awk -F '/' '{print $1,$2}')"
  if [[ "$availableReplicas" -eq 0 ]]||[[ "$readyReplicas" -eq 0 ]];then
    red "  └──[Error] coredns availableReplicas or readyReplicas is 0 "
  elif [[ "$availableReplicas" -ne "$replicas" ]]&&[[ "$readyReplicas" -ne "$replicas" ]];then
    yellow "  └──[Warning] coredns replica is $replicas ,availableReplicas is $availableReplicas, replicas is $readyReplicas"
  else
    green "  └──[Info] coredns is ok，coredns replica is $replicas ,availableReplicas is $availableReplicas, replicas is $readyReplicas"
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
}

check_dns(){
  green ".check dns"
  blue "└──check node dns"
  check_node_dns
  blue "└──check pod dns"
  check_pod_dns
}

check_node_status(){
  green ".check node info"
  blue "└──check node ready status"
  local availableNode=$(wc -l "$allNodeFile"|awk '{print $1}')
  local notReadyNodeNum=$(grep -cv Ready "$allNodeFile")
  if [[ "$notReadyNodeNum" -ne 0 ]];then
    local notReadyNode=$(grep -v Ready "$allNodeFile")
    red "  └──[Error] has $notReadyNodeNum node not ready：$notReadyNode"
  else
    green "  └──[Info] $availableNode nodes all ready."
  fi
}

check_pods_status(){
  green ".check pods status"
  for status in "${podStatusCheck[@]}";do
    local num=$(grep -c "$status" "$allPodsFile")
    if [[ "$status" == "Running" ]]||[[ "$status" == "Completed" ]];then
      green "  └──[Info] $num pods is $status"
    elif [[ "$num" -ne 0 ]];then
      red "  └──[Error] $num pods is $status"
      red "$(grep "$status" "$allPodsFile"|sed s'/^/      /')"
    fi
  done
  local restartPodNum=$(awk -v restartNum=$podRestartCheckNum '{if($5>restartNum) print $0}' "$allPodsFile"|wc -l)
  if [[ "$restartPodNum" -ne 0 ]];then
    red "  └──[Error] $restartPodNum pods is restart > $podRestartCheckNum"
    red "$(awk -v restartNum=$podRestartCheckNum '{if($5>restartNum) print $0}' $allPodsFile|sed s'/^/      /')"
  fi
}

check_svc_ip(){
  green ".check svc ip"
  local svcCidr=$(kubectl get cm  -n kube-system kubeadm-config -o jsonpath='{.data.ClusterConfiguration}'|grep serviceSubnet|awk '{print $2}')
  if [[ ${#svcCidr} -lt 9 ]];then
    svcCidr=$(pgrep kube-api -a|awk 'NR==1{for(i=1;i<=NF;i++)if($i~/service-cluster-ip-range/)print $i}'|awk -F "=" '{print $2}')
    if [[ ${#svcCidr} -lt 9 ]];then
      svcCidr=$(kubeadm config view | grep serviceSubnet|awk '{print $2}')
      if [[ ${#svcCidr} -lt 9 ]];then
        yellow "  └──[Warning] can't get service cidr"
        return
      fi
    fi
  fi
  local netmaskNum=$(echo "$svcCidr"|awk -F '/' '{print $2}')
  local svcUsageNum=$(awk '{print $4}' "$allServiceFile"|grep -civ none)
  local svcIpMax=$((2**(32-netmaskNum)-2))
  if [[ "$svcUsageNum" -gt $((svcIpMax * 8  / 10)) ]];then
    yellow "  └──[Warning] service ip used grater than 80%，used：$svcUsageNum，max: $svcIpMax"
  else
    green "  └──[Info] service ip used: $svcUsageNum, max: $svcIpMax，residue: $((svcIpMax - svcUsageNum))"
  fi
}

check_pod_ip(){
  green ".check pod ip"
  local podCidr=$(curl -s 127.0.0.1:6784/status|grep Range|awk '{print $2}')
  if [[ ${#podCidr} -lt 9 ]];then
    yellow "  └──[Warning] can't get pod cidr"
    return
  fi
  local ipUsageNum=$(sort "$nodeIpFile" $nodeIpFile $allPodIpFile|uniq -u|wc -l)
  local netmaskNum=$(echo "$podCidr"|awk -F '/' '{print $2}')
  local podIpMax=$((2**(32-netmaskNum)-2))
  if [[ "$ipUsageNum" -gt $((podIpMax * 8  / 10)) ]];then
    yellow "  └──[Warning] pod ip used grater than 80%，used：$ipUsageNum，max: $podIpMax"
  else
    green "  └──[Info] pod ip used: $ipUsageNum, max: $podIpMax，residue: $((podIpMax - ipUsageNum))"
  fi
}

check_net(){
  green ".check net"
  local nsPodIpList=$(sort "$nodeIpFile" $nodeIpFile $nsPodIpFile|uniq -u)
  blue "└──check pod -> node"
  while IFS= read -r ip;do
    if ! kubectl exec "$tmpPodName" -- ping "$ip" -c 2 >&/dev/null;then
      red "  └──[Error] check pod -> node：$ip error"
    else
      green "  └──[Info] check pod -> node：$ip pass"
    fi
  done < "$nodeIpFile"
  blue "└──check pod -> svc"
  while IFS= read -r svc;do
    local svcName svcIp svcPort
    read -r svcName svcIp svcPort <<< "$(echo "$svc"|awk '{print $1,$2,$3}')"
    if ! timeout 5 kubectl exec "$tmpPodName" -- nc "$svcIp" "$svcPort";then
      red "  └──[Error] check pod -> svc [$svcName $svcIp $svcPort] error"
    else
      green "  └──[Info] check pod -> svc [$svcName $svcIp $svcPort] pass"
    fi
  done < "$svcListFile"
  blue "└──check pod -> pod"
  for ip in $nsPodIpList;do
    if ! kubectl exec "$tmpPodName" -- ping "$ip" -c 2 >&/dev/null;then
      red "  └──[Error] check pod -> pod：$ip error"
    else
      green "  └──[Info] check pod -> pod：$ip pass"
    fi
  done
  blue "└──check node -> node"
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
}

unit_conversion_cpu(){
  local unit=$(echo "$1"|tr -d '0-9')
  local num=$(echo "$1"|tr -cd '0-9')
  if [[ $num -eq 0 ]];then
    echo 0
  else
    case $unit in
    m)
      echo "$num"
      ;;
    *)
      echo $((num*1000))
      ;;
    esac
  fi
}

unit_conversion_mem() {
  local unit=$(echo "$1"|tr -d '0-9')
  local num=$(echo "$1"|tr -cd '0-9')
  if [[ $num -eq 0 ]];then
    echo 0
  else
    case $unit in
    Ki)
      echo $((num/1024))
      ;;
    Mi)
      echo "$num"
      ;;
    Gi)
      echo $((num*1024))
      ;;
    esac
  fi
}

get_cluster_resources() {
  green ".check node resources request"
  clusterCapacityCpu=0
  clusterCapacityMem=0
  clusterRequestsCpu=0
  clusterRequestsMem=0
  local clusterLimitsCpu=0
  local clusterLimitsMem=0
  while IFS= read -r line;do
    local nodeCapacityCpu nodeCapacityMem nodeName nodeRequestsCpu nodeRequestsMem nodeLimitsCpu nodeLimitsMem nodeRequestsCpuPercent nodeRequestsMemPercent
    read -r nodeName nodeCapacityCpu nodeCapacityMem <<< "$(echo "$line"|awk '{print $1,$2,$3}')"
    nodeCapacityCpu=$(unit_conversion_cpu "$nodeCapacityCpu")
    nodeCapacityMem=$(unit_conversion_mem "$nodeCapacityMem")
    clusterCapacityCpu=$((clusterCapacityCpu+nodeCapacityCpu))
    clusterCapacityMem=$((clusterCapacityMem+nodeCapacityMem))
    local nodeDescribeFile="$healthCheckDir/$nodeName.describe"
    kubectl describe nodes "$nodeName" |sed -n '/Allocated resources/,/Events/p' > "$nodeDescribeFile"
    read -r nodeRequestsCpu nodeRequestsCpuPercent nodeLimitsCpu <<< "$(sed -n '/cpu/p' "$nodeDescribeFile"|awk '{print $2,$3,$4}')"
    local nodeRequestsCpuPercentNum=$(echo "$nodeRequestsCpuPercent"|sed 's/(//;s/%)//')
    if [[ "$nodeRequestsCpuPercentNum" -gt "$clusterRequestCheckPercent" ]];then
      yellow "  └──[Warning] node($nodeName) request cpu used grater than ${clusterRequestCheckPercent}%，request：$nodeRequestsCpu；max：${nodeCapacityCpu}m；percent：$(echo "$nodeRequestsCpuPercent"|sed 's/(//;s/)//')"
    else
      green "  └──[Info] node($nodeName) request cpu info，request：$nodeRequestsCpu；max：${nodeCapacityCpu}m；percent：$(echo "$nodeRequestsCpuPercent"|sed 's/(//;s/)//')"
    fi
    nodeRequestsCpu=$(unit_conversion_cpu "$nodeRequestsCpu")
    nodeLimitsCpu=$(unit_conversion_cpu "$nodeLimitsCpu")
    clusterRequestsCpu=$((clusterRequestsCpu+nodeRequestsCpu))
    clusterLimitsCpu=$((clusterLimitsCpu+nodeLimitsCpu))
    read -r nodeRequestsMem nodeRequestsMemPercent nodeLimitsMem <<< "$(sed -n '/memory/p' "$nodeDescribeFile"|awk '{print $2,$3,$4}')"
    local nodeRequestsMemPercentNum=$(echo "$nodeRequestsMemPercent"|sed 's/(//;s/%)//')
    if [[ "$nodeRequestsMemPercentNum" -gt "$clusterRequestCheckPercent" ]];then
      yellow "  └──[Warning] node($nodeName) request mem used grater than ${clusterRequestCheckPercent}%，request：$nodeRequestsMem；max：${nodeCapacityMem}Mi；percent：$(echo "$nodeRequestsMemPercent"|sed 's/(//;s/)//')"
    else
      green "  └──[Info] node($nodeName) request mem info，request：$nodeRequestsMem；max：${nodeCapacityMem}Mi；percent：$(echo "$nodeRequestsMemPercent"|sed 's/(//;s/)//')"
    fi
    nodeRequestsMem=$(unit_conversion_mem "$nodeRequestsMem")
    nodeLimitsMem=$(unit_conversion_mem "$nodeLimitsMem")
    clusterRequestsMem=$((clusterRequestsMem+nodeRequestsMem))
    clusterLimitsMem=$((clusterLimitsMem+nodeLimitsMem))
  done < "$nodeCapacityFile"
}

check_resources_request() {
  green ".check cluster resources request"
  local memUsedPercent=$(awk 'BEGIN{printf "%.4f\n","'"${clusterRequestsMem}"'"/"'"${clusterCapacityMem}"'"}')
  local cpuUsedPercent=$(awk 'BEGIN{printf "%.4f\n","'"${clusterRequestsCpu}"'"/"'"${clusterCapacityCpu}"'"}')
  if [[ "$clusterRequestsMem" -gt $((clusterCapacityMem * clusterRequestCheckPercent / 100)) ]];then
    yellow "  └──[Warning] cluster request mem used grater than ${clusterRequestCheckPercent}%，used：${clusterRequestsMem}Mi，max: ${clusterCapacityMem}Mi，$(awk 'BEGIN{printf "%.0f\n","'"${memUsedPercent}"'"*100}')%"
  else
    green "  └──[Info] cluster request mem used：${clusterRequestsMem}Mi，max: ${clusterCapacityMem}Mi，$(awk 'BEGIN{printf "%.0f\n","'"${memUsedPercent}"'"*100}')%"
  fi
  if [[ "$clusterRequestsCpu" -gt $((clusterCapacityCpu * clusterRequestCheckPercent / 100)) ]];then
    yellow "  └──[Warning] cluster request cpu used grater than ${clusterRequestCheckPercent}%，used：${clusterRequestsCpu}m，max: ${clusterCapacityCpu}m，$(awk 'BEGIN{printf "%.0f\n","'"${cpuUsedPercent}"'"*100}')%"
  else
    green "  └──[Info] cluster request cpu used ${clusterRequestsCpu}m，max ${clusterCapacityCpu}m，$(awk 'BEGIN{printf "%.0f\n","'"${cpuUsedPercent}"'"*100}')%"
  fi
}

check_weave_status() {
  green ".check weave status"
  while IFS= read -r weave;do
    local weaveName weaveReady weaveStatus nodeIp nodeName ipamStatus
    read -r weaveName weaveReady weaveStatus nodeIp nodeName <<< "$(echo "$weave"|awk '{print $1,$2,$3,$6,$7}')"
    ipamStatus=$(kubectl -n kube-system exec "$weaveName" -c weave -- /home/weave/weave --local status|grep Status|awk '{print $2}')
    if [[ "$weaveReady" == "2/2" ]];then
      if [[ "$weaveStatus" == "Running" ]];then
        if [[ "$ipamStatus" == "ready" ]];then
          green "  └──[Info] node：$nodeName $nodeIp，pod：$weaveName $weaveReady $weaveStatus，ipam：$ipamStatus is healthy"
        else
          red "  └──[Error] node：$nodeName $nodeIp，pod：$weaveName $weaveReady $weaveStatus，ipam：$ipamStatus"
        fi
      else
        red "  └──[Error] node：$nodeName $nodeIp，pod：$weaveName $weaveReady $weaveStatus，ipam：$ipamStatus"
      fi
    else
      red "  └──[Error] node：$nodeName $nodeIp，pod：$weaveName $weaveReady $weaveStatus，ipam：$ipamStatus"
    fi
  done < "$weavePodsFile"
}

# all nodes check
check_conntrack(){
  green ".check conntrack"
  local nfConntrackCount="$(cat /proc/sys/net/netfilter/nf_conntrack_count)"
  local nfConntrackMax="$(cat /proc/sys/net/netfilter/nf_conntrack_max)"
  local nfConntrackUsageRate=$(awk 'BEGIN{printf "%.4f\n","'"${nfConntrackCount}"'"/"'"${nfConntrackMax}"'"}')
  if [ "$(expr "${nfConntrackUsageRate}" \> 0.8)" -eq 1 ];then
    yellow "  └──[Warning] conntrack used grater than 80%，$nfConntrackUsageRate"
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

# master and etcd 节点
check_command
check_check_pod
get_check_data
#check_kube-apiserver
#check_kube-controller-manager
#check_kube-scheduler
#check_etcd
#check_cert
check_coredns_replicas
check_dns
check_node_status
check_pods_status
check_svc_ip
check_pod_ip
check_net
get_cluster_resources
check_resources_request
check_weave_status

# all node
#check_conntrack
#check_containerd
#check_kubelet_cert
#check_node_dns
#check_node_to_apiserver
kubectl delete pods "$tmpPodName" --force >& /dev/null