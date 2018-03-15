#!/bin/sh
# 

set -e 

IPFIX="10.133.96"
Intervals=4
packet_num=300
localIP=`ifconfig |grep $IPFIX | awk '{print $2}'`

do_ping(){
	for ip in $IPFIX.{8..10}
	do 
	if [[ $localIP != $ip ]];then
		echo $ip
		loss_packet_rate=$(ping -f -c $packet_num $ip |grep packet |cut -d " " -f 6 |tr -d % >> /dev/null)
		if [ $loss_packet_rate -ne 0 ];then
			echo -e " `date "+%Y-%m-%d %H:%M:%S"`: $localIP ==> $ip loss packets" >> /var/log/test_pkg_loss.log
		fi
	fi 
	done
}

while : 
	do
		do_ping
		sleep $Intervals 
	done
   