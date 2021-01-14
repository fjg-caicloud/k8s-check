#!/bin/bash

if [ ! -d /tmp/healthCheck ]; then
  mkdir -p /tmp/healthCheck && cd /tmp/healthCheck
fi

logCheckDays=7
currentDay=$(date +%F)
sinceLogDay=$(date +%F -d "$logCheckDays days ago")

maxLogSize=20480
maxdiskUsagepercentage=85

#定义日志的最大字节数，20480B=20K
checkLogSize(){
  du -b $1 |awk -v size=$maxLogSize '{if($1>size){print false}else{print true}}'
}

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


	#输出uptime和负载
check_uptime(){
echo "[INFO] uptime is: `uptime`"
echo "[INFO] load average is: `uptime |awk -F ':' '{print  $NF}'`"
}
	#输出节点CPU使用率
  
	#输出节点内存使用率
  
	#输出磁盘使用率
check_diskUsage(){
echo  -e "[INFO] disk usage:\n`df -Th / /app |grep -v  Filesystem  |awk '{print $(NF-1),$NF}'` "
}
	
	#输出磁盘IO情况
check_diskIO(){
DISKS=$(ls /dev/sd[a-z] /dev/vd[a-z]  2>/dev/null)
for d in $DISKS
  do
	export logFileName=$(echo "`echo $d|awk -F'/' '{print $NF}'`-`date +%F`")
    iostat -x -d $d 1 30  1>/tmp/healthCheck/$logFileName.log
	cd /tmp/healthCheck
	maxReadIOPS=$(cat $logFileName.log|grep -v "_x86_64_" |awk '{print $4}'  |grep -v -E '^$|r\/s'|sort  -nr|head -n1 )
	avgReadIOPS=$(cat $logFileName.log|grep -v "_x86_64_" |awk '{print $4}'|grep -v -E '^$|r\/s'|awk '{sum+=$1} END {print sum/NR}')
	maxWriteIOPS=$(cat $logFileName.log|grep -v "_x86_64_" |awk '{print $5}'  |grep -v -E '^$|w\/s'|sort  -nr|head -n1 )
	avgWriteIOPS=$(cat $logFileName.log|grep -v "_x86_64_" |awk '{print $5}'|grep -v -E '^$|w\/s'|awk '{sum+=$1} END {print sum/NR}')
	maxReadKB=$(cat $logFileName.log|grep -v "_x86_64_" |awk '{print $6}'  |grep -v -E '^$|rkB\/s'|sort  -nr|head -n1 )
	avgReadKB=$(cat $logFileName.log|grep -v "_x86_64_" |awk '{print $6}'  |grep -v -E '^$|rkB\/s'|awk '{sum+=$1} END {print sum/NR}')
	maxWriteKB=$(cat $logFileName.log|grep -v "_x86_64_" |awk '{print $7}'  |grep -v -E '^$|wkB\/s'|sort  -nr|head -n1 )
	avgWriteKB=$(cat $logFileName.log|grep -v "_x86_64_" |awk '{print $7}'  |grep -v -E '^$|wkB\/s'|awk '{sum+=$1} END {print sum/NR}')
	maxAvgqu_sz=$(cat $logFileName.log|grep -v "_x86_64_" |awk '{print $9}'  |grep -v -E '^$|avgqu-sz'|sort  -nr|head -n1 )
	avgAvgqu_sz=$(cat $logFileName.log|grep -v "_x86_64_" |awk '{print $9}'  |grep -v -E '^$|avgqu-sz'|awk '{sum+=$1} END {print sum/NR}')
	maxAwait=$(cat $logFileName.log|grep -v "_x86_64_" |awk '{print $10}'  |grep -v -E '^$|await'|sort  -nr|head -n1 )
	avgAwait=$(cat $logFileName.log|grep -v "_x86_64_" |awk '{print $10}'  |grep -v -E '^$|await'|awk '{sum+=$1} END {print sum/NR}')
	maxR_await=$(cat $logFileName.log|grep -v "_x86_64_" |awk '{print $11}'|grep -v -E '^$|r_await'|sort  -nr|head -n1 )
	avgR_await=$(cat $logFileName.log|grep -v "_x86_64_" |awk '{print $11}'|grep -v -E '^$|r_await'|awk '{sum+=$1} END {print sum/NR}')
	maxW_await=$(cat $logFileName.log|grep -v "_x86_64_" |awk '{print $12}'|grep -v -E '^$|w_await'|sort  -nr|head -n1 )
	avgW_await=$(cat $logFileName.log|grep -v "_x86_64_" |awk '{print $12}'|grep -v -E '^$|w_await'|awk '{sum+=$1} END {print sum/NR}')
	echo -e "[INFO] disk $d:\nmaxReadIOPS:$maxReadIOPS\navgReadIOPS:$avgReadIOPS\nmaxWriteIOPS:$maxWriteIOPS\navgWriteIOPS:$avgWriteIOPS\nmaxReadKB:$maxReadKB\navgReadKB:$avgReadKB\nmaxWriteKB:$maxWriteKB\navgWriteKB:$avgWriteKB\nmaxAvgqu_sz:$maxAvgqu_sz\navgAvgqu_sz:$avgAvgqu_sz\nmaxAwait:$maxAwait\n"
  done
}


	#输出网卡情况,网卡不是eth开头时修改正则匹配
check_nic(){
NETDEV=$(ifconfig  -a |grep  -E  -o "^eth[0-9]*|^bond[0-9]*|^ens[0-9]*")
sar -n DEV 1  30 1>/tmp/healthCheck/netStatus.log
for n in $NETDEV
  do
    cd /tmp/healthCheck
    nicStatus=$(ip link show $n|grep  -o -E "state[[:space:]]*[[:upper:]]*"|awk '{print $NF}')
	maxRxpckPercent=$(cat netStatus.log |grep $n|grep -v -E "veth*|Average:"|awk '{print $3}'|sort  -nr |head -n1)
	maxTxpckPercent=$(cat netStatus.log |grep $n|grep -v -E "veth*|Average:"|awk '{print $4}'|sort  -nr |head -n1)
	maxRxkBPercent=$(cat netStatus.log |grep $n|grep -v -E "veth*|Average:"|awk '{print $5}'|sort  -nr |head -n1)
	maxTxkBPercent=$(cat netStatus.log |grep $n|grep -v -E "veth*|Average:"|awk '{print $6}'|sort  -nr |head -n1)
	avgRxpckPercent=$(cat netStatus.log |grep $n|grep -v -E "veth*"|grep Average|awk '{print $3}')
	avgTxpckPercent=$(cat netStatus.log |grep $n|grep -v -E "veth*"|grep Average|awk '{print $4}')
	avgRxkBPercent=$(cat netStatus.log |grep $n|grep -v -E "veth*"|grep Average|awk '{print $5}')
	avgTxkBPercent=$(cat netStatus.log |grep $n|grep -v -E "veth*"|grep Average|awk '{print $6}')
	echo -e "[INFO]NETDEV $n---\nStatus:$nicStatus\nmaxRxpckPercent:$maxRxpckPercent\nmaxTxpckPercent:$maxTxpckPercent\nmaxRxkBPercent:$maxRxkBPercent\nmaxTxkBPercent:$maxTxkBPercent\n"average is" $avgRxpckPercent $avgTxpckPercent $avgRxkBPercent $avgTxkBPercent\n---\n"
  done
}

	# 输出docker状态检查
	
	## docker服务状态
check_docker(){
dockerdIsActived=$(systemctl  is-active docker)
if  [[ $dockerdIsActived == "active" ]]; then
   echo "[INFO]the dockerd process status is active"
  else 
   echo "[ERROR]the dockerd process is not running"
fi
  
	## docker ps 没有hang住
dockerPsTMout=5s
timeout  $dockerPsTMout docker ps  1>/dev/null 2>&1
if [[ $? -eq 0 ]];then
   echo "[INFO] dockerd has hanged check passed"
else
   echo "[ERROR] dockerd hang happend"
fi
  

  
  ## docker 描述符
dockerPid=$(ps aux |grep /bin/dockerd|grep -v grep |awk '{print $2}')
if [[ ! -z $dockerPid ]] ;then
  dockerOpenfileLimit=$(cat /proc/$dockerPid/limits |grep files |awk '{print $(NF-1)}')
  usedFD=$(ls -lR  /proc/$dockerPid/fd |grep "^l"|wc -l)
  FDUsedPercentage=$(awk 'BEGIN{printf "%.1f%%\n",('$usedFD'/'$dockerOpenfileLimit')*100}')
  echo -e "[INFO] dockerd openfileLimit info:\nmax:$dockerOpenfileLimit\nusedFD:$usedFD\nFDUsedPercentage:$FDUsedPercentage\n"
fi 
  

  ## 检查docker和containerd容器状态是否一致
if which ctr &>/dev/null;then
 Upcontainers=$(docker ps |grep Up|awk '{print $1}')
 ctr --namespace moby --address /var/run/docker/containerd/containerd.sock  task  list 1>containerdTasks.list
  if [[ $? -eq 0 ]];then
	for i in $Upcontainers
	  do
		 cat containerdTasks.list|grep $i |grep -q  RUNNING
		 if [[ $? -ne 0 ]];then
		   echo "[ERROR] the abnormal container ID is: $i"
		 fi
	  done
  fi
fi	  
  
  ## 检查7天内dockers日志是否有error信息
journalctl -x  --since $sinceLogDay   -u docker  1>docker-$currentDay.log
grep -E -i "err|ERR|error|Error" docker-$currentDay.log 1>docker-$currentDay-Error.log
if [[ ! -z $(cat docker-$currentDay-Error.log) ]] && $(checkLogSize docker-$currentDay-Error.log); then
  echo  -e "[ERROR] docker error logs is: $(cat docker-$currentDay-Error.log)\n\n"
elif [[ -z $(cat docker-$currentDay-Error.log) ]];then
    echo  -e "[INFO] docker has no error logs\n\n"
else
  echo -e "[ERROR] docker error logs is too large,log file in /tmp/healthCheck/docker-$currentDay-Error.log"
fi

}

  # 输出kubelet检查结果
  ## kubelet进程状态
check_kubelet(){
kubeletIsActived=$(systemctl  is-active kubelet)
if  [[ $kubeletIsActived == "active" ]]; then
   echo -e "[INFO]the kubelet processs  status is active\n"
else 
   echo  -e "[ERROR] the kubelet  process is not running\n"
fi
  
  ## kubelet健康端口检查
kubeletCheckEndpoint=$(ss -tunlp|grep kubelet|grep 127.0.0.1|grep 10|awk '{print $5}')  
kubeletCheckResult=$(curl $kubeletCheckEndpoint/healthz)
if [[ $kubeletCheckResult == "ok" ]] ;then
  echo -e "[INFO] kubelet port health check passed\n"
else
  echo  -e "[ERROR]kubelet port health check not paased\n"
fi
  
  ## kubelet7天内日志
journalctl -x   --since $sinceLogDay   -u kubelet 1>kubelet-$currentDay.log 
grep -E  "E[0-9]+|err|ERR|error|Error" kubelet-$currentDay.log 1>kubelet-$currentDay-Error.log
if [[ ! -z $(cat kubelet-$currentDay-Error.log) ]] && $(checkLogSize kubelet-$currentDay-Error); then
  echo  -e "[ERROR] kubelet error logs is: $(cat kubelet-$currentDay-Error.log)\n\n"
elif [[ -z $(cat kubelet-$currentDay-Error.log) ]];then
  echo  -e "[INFO] kubelet has no error logs\n\n"
else
  echo -e "[ERROR] kubelet error logs is too large,log file in /tmp/healthCheck/kubelet-$currentDay-Error.log"
fi
  
}
  # 输出kube-proxy检查结果
check_kube_proxy(){
  ## kube-proxy 健康端口检查
kubeProxyCheckResult=$(curl 127.0.0.1:10249/healthz)
if [[ $kubeProxyCheckResult == "ok" ]] ;then
  echo "[INFO] kube-proxy port health check passed"
else
  echo "[ERROR]kube-proxy port health check not paased"
fi 
  
  ## kube-proxy错误日志过滤 
proxyContainerID=$(docker ps |grep kube-proxy|grep -v pause|awk '{print $1}')
docker logs $proxyContainerID  -t --since $sinceLogDay  --details >& kube-proxy-$currentDay.log
grep -E  "E[0-9]+|err|ERR|error|Error" kube-proxy-$currentDay.log 1>kube-proxy-$currentDay-Error.log
if [[ ! -z $(cat kube-proxy-$currentDay-Error.log) ]] && $(checkLogSize kube-proxy-$currentDay-Error.log); then
  echo  -e "[ERROR] kube-proxy error logs is: $(cat kube-proxy-$currentDay-Error.log)\n\n"
elif [[ -z $(cat kubelet-$currentDay-Error.log) ]];then
  echo  -e "[INFO]kube-proxy has no error logs\n\n"
else
  echo -e "[ERROR] kube-proxy error logs is too large,log file in /tmp/healthCheck/kube-proxy-$currentDay-Error.log"
fi
} 

 #检查最大文件打开数
check_openfiles(){
openfileUsed=$(cat /proc/sys/fs/file-nr|awk '{print $1}')
maxOpenfiles=$(cat /proc/sys/fs/file-nr|awk '{print $NF}')
filePercentage=$(awk 'BEGIN{printf "%.1f%%\n",('$openfileUsed'/'$maxOpenfiles')*100}')
pidMax=$(cat /proc/sys/kernel/pid_max)
echo -e "[INFO] the node file and pid info:\nopenfileUsed:$openfileUsed\nmaxOpenfiles:$maxOpenfiles\nopenfileUsedPercentage:$filePercentage\npid-max:$pidMax\n"
}

  #conntrack使用率
check_nf_conntrack(){
conntrackMax=$(cat /proc/sys/net/nf_conntrack_max) 
usedConntrack=$(cat /proc/net/nf_conntrack |wc -l)
usedConntrackPercentage=$(awk 'BEGIN{printf "%.1f%%\n",('$usedConntrack'/'$conntrackMax')*100}')
echo -e "[INFO]the node conntrack info:\nconntrackMax:$conntrackMax\nusedConntrack:$usedConntrack\nPercentage:$usedConntrackPercentage\n"
}
  
  #Z进程检查
check_z_process(){
ZNUM=$(top -n 1|grep Tasks|awk  -F',' '{print $NF}'|awk '{print $(NF-1)}' )
if [[ $ZNUM == 0 ]];then
  echo -e  "[INFO] no found zombie process\n\n"
else 
  ZTasks=$(ps -ef | grep defunct | grep -v grep)
  echo -e "[ERROR]found zombie process,the tasks is: $ZTasks\n\n"
fi
}
  #时间差检查
check_ntp(){  
echo -e "[INFO] the NTP time info is:"
chronyc sources
echo -e "\n"
}

 #message日志检查
check_msg_logs(){
grep -E "Container kill faild |\
Container kill faild.count |\
Trying direct SIGKILL |\
Container kill faild because of 'container not found' or 'no sudh process' |\
OOM KILL |\
Abort command issued |\
NIC link is down |\
Path is down |\
OFFILE unexpectedly |\
Call Trace |\
Not respoding |\
Write error |\
IO failure |\
Filesystem read-only |\
Failing path |\
No liveness for |\
xfs_log_force:error |\
I/O error |\
EXT4-fs error |\
Uncorrected hardware memory error |\
Device offlined |\
Unrecoverable medium error during recovery on PD |\
tx_timeout |\
Container runtime is down PLEG is not healthy |\
_Call_Trace"  /var/log/messages 1>message-$currentDay-Error.log

if [[ ! -z $(cat message-$currentDay-Error.log) ]] && $(checkLogSize message-$currentDay-Error.log); then
  echo  -e "[ERROR] message  error logs is: $(cat message-$currentDay-Error.log)\n\n"
elif [[ -z $(cat message-$currentDay-Error.log) ]];then
  echo  -e "[INFO]messages has no error logs\n\n"
else
  echo -e "[ERROR] message error logs is too large,log file in /tmp/healthCheck/message-$currentDay-Error.log"
fi
}

check_uptime
check_diskUsage
check_diskIO
check_nic
check_docker
check_kubelet
check_kube_proxy
check_nf_conntrack
check_openfiles
check_z_process
check_ntp
check_msg_logs

