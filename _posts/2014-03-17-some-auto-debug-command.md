---
layout: post
title: "一些常用的自动化调试的命令"
category: linux tool
excerpt: "对于开发测试内核，挺实用的" 
tags: "linux auto test"
--- 
{% include JB/setup %}

1.快速创建kvm虚拟机

    beaker_eth=`ip addr show |grep 10.66 |awk '{print $NF}'`
    mac_addr=""
    gip_addr=""
    
    sys_cls()
    {
    	killall qemu-kvm >/dev/null 2>&1 ;sleep 1
    	killall dhclient >/dev/null 2>&1 && sleep 1
    	dhclient br1  >/dev/null 2>&1
    	rm -f ips >/dev/null
    }
    sys_init()
    {
    	test -f /etc/yum.repos.d/beaker-tasks.repo && rm -f /etc/yum.repos.d/beaker-tasks.repo
            rpm -qa |grep qemu-kvm >/dev/null || yum -y install qemu-kvm >/dev/null
            rpm -qa |grep tcpdump >/dev/null || yum -y install tcpdump >/dev/null
            test -f /root/$img_name || wget http://10.66.13.12/sys/$img_name -O /root/$img_name
    	return 0
    }
    get_mac()
    {
    	rstr=`date +%s`
    	mac_addr=00:${rstr:0:2}:${rstr:2:2}:${rstr:4:2}:${rstr:6:2}:${rstr:8:2}
    	return 0
    }
    new_swit()
    {
    	if [ ! -f /etc/qemu-ifup ];then
                    cat << EOF > /etc/qemu-ifup 
    #!/bin/sh
    switch=br1
    /sbin/ifconfig \$1 0.0.0.0 up
    /usr/sbin/brctl addif \${switch} \$1
    EOF
                    chmod 755 /etc/qemu-ifup
            fi
    	if [ ! -f /etc/qemu-ifdown ];then
                    cat << EOF > /etc/qemu-ifdown
    #!/bin/sh
    switch=br1
    /usr/sbin/brctl delif \${switch} \$1
    EOF
                    chmod 755 /etc/qemu-ifdown
    	fi
    	brctl show |grep br1 > /dev/null && return 0
    	brctl addbr br1 && brctl addif br1 $beaker_eth || return -1
    	killall dhclient > /dev/null; sleep 1;dhclient br1 || return -1
    	ip addr flush $beaker_eth
    	return 0
    }
    new_br()
    {
    	if [ ! -f /etc/qemu-ifup-br0 ];then
                    cat << EOF > /etc/qemu-ifup-br0
    #!/bin/sh
    switch=br0
    /sbin/ifconfig \$1 0.0.0.0 up
    /usr/sbin/brctl addif \${switch} \$1
    EOF
                    chmod 755 /etc/qemu-ifup-br0
            fi
    	if [ ! -f /etc/qemu-ifdown-br0 ];then
                    cat << EOF > /etc/qemu-ifdown-br0
    #!/bin/sh
    switch=br0
    /usr/sbin/brctl delif \${switch} \$1
    EOF
                    chmod 755 /etc/qemu-ifdown-br0
            fi
    	brctl show |grep ^br0 > /dev/null && return 0
    	brctl addbr br0 && ip addr add 192.168.0.254/24 dev br0 || return -1
    	ip link set br0 up
    	return 0
    }
    start_vm()
    {
    	/usr/libexec/qemu-kvm -name vm1 \
    	-drive file=/root/$img_name,if=none,id=drive-virtio-disk1,media=disk,cache=none,snapshot=off,format=qcow2,aio=native  \
    	-device virtio-blk-pci,drive=drive-virtio-disk1,id=virtio-disk1,bootindex=0  \
    	-netdev tap,id=hostnet0,vhost=on,script=/etc/qemu-ifup,downscript=downscript=/etc/qemu-ifdown \
    	-device virtio-net-pci,netdev=hostnet0,id=virtio-net-pci0,mac=$mac_addr \
    	$kvm_append \
    	-smp 2,cores=1,threads=1,sockets=2  \
    	-m 4096 >>./ips 2>&1 &
    	return 0
    }
    get_gip()
    {
    	gip_addr=`timeout 200 tcpdump -i br1 ether src $mac_addr and arp[7]=1 and arp[15]!=0 -n -c 1 2>/dev/null| awk -F' |,' '{print $8}'`
    	test -z $gip_addr && return -1
    	sleep 1;
    	return 0;
    }
    exp_run()
    {
    	./sshrun $gip_addr $!
    }
    start_kvm()
    {
    	sys_init || { echo "sys init fail" ; exit -1;} && echo "sys init"
    	get_mac  || { echo "get mac  fail" ; exit -2;} && echo "get mac "$mac_addr
    	new_swit || { echo "new swit fail" ; exit -3;} && echo "net public br"
    	new_br   || { echo "new br0  fail" ; exit -4;} && echo "net pravite br"
    	start_vm || { echo "start vm fail" ; exit -5;} && echo "start vm "
    	get_gip  || { echo "get gip  fail" ; exit -6;} && echo $gip_addr >> ips
    	echo "successfully"
    }
    
    ##### main
    sys_cls
    #mac_addr="00:13:93:40:04:78"
    img_name="rhel7.qcow2"
    kvm_append="-netdev tap,id=hostnet1,vhost=on,script=/etc/qemu-ifup-br0,downscript=/etc/qemu-ifdown-br0 \
    -device virtio-net-pci,netdev=hostnet1,id=virtio-net-pci1,mac=00:00:00:00:00:01 \
    -netdev tap,id=hostnet2,vhost=on,script=/etc/qemu-ifup-br0,downscript=/etc/qemu-ifdown-br0 \
    -device virtio-net-pci,netdev=hostnet2,id=virtio-net-pci2,mac=00:00:00:00:00:02 \
    -serial pty -vnc :10"
    start_kvm
    #mac_addr="00:13:93:40:04:37"
    img_name="rhel7.1.qcow2"
    kvm_append="-netdev tap,id=hostnet1,vhost=on,script=/etc/qemu-ifup-br0,downscript=/etc/qemu-ifdown-br0 \
    -device virtio-net-pci,netdev=hostnet1,id=virtio-net-pci1,mac=00:00:00:00:00:03 \
    -netdev tap,id=hostnet2,vhost=on,script=/etc/qemu-ifup-br0,downscript=/etc/qemu-ifdown-br0 \
    -device virtio-net-pci,netdev=hostnet2,id=virtio-net-pci2,mac=00:00:00:00:00:04 \
    -serial pty -vnc :20"
    start_kvm

2.sriov测试自动化

    beaker_eth=`ip addr show |grep 10.66 |awk '{print $NF}'`
    mac_addr=""
    gip_addr=""
    sriov_dev="eth4"
    sriov_bus_brief=""
    
    sys_cls()
    {
    	killall qemu-kvm >/dev/null 2>&1 ;sleep 1
    	rm -f ips >/dev/null
    }
    sys_init()
    {
    	test -f /etc/yum.repos.d/beaker-tasks.repo && rm -f /etc/yum.repos.d/beaker-tasks.repo
            rpm -qa |grep qemu-kvm >/dev/null || yum -y install qemu-kvm >/dev/null
            test -f /root/$img_name || wget http://10.66.13.12/sys/$img_name -O /root/$img_name
    	return 0
    }
    get_mac()
    {
    	rstr=`date +%s`
    	mac_addr=00:${rstr:0:2}:${rstr:2:2}:${rstr:4:2}:${rstr:6:2}:${rstr:8:2}
    	return 0
    }
    new_swit()
    {
    	if [ ! -f /etc/qemu-ifup ];then
                    cat << EOF > /etc/qemu-ifup 
    #!/bin/sh
    switch=switch
    /sbin/ifconfig \$1 0.0.0.0 up
    /usr/sbin/brctl addif \${switch} \$1
    EOF
                    chmod 755 /etc/qemu-ifup
            fi
    	if [ ! -f /etc/qemu-ifdown ];then
                    cat << EOF > /etc/qemu-ifdown
    #!/bin/sh
    switch=switch
    /usr/sbin/brctl delif \${switch} \$1
    EOF
                    chmod 755 /etc/qemu-ifdown
    	fi
    	brctl show |grep switch > /dev/null && return 0
    	brctl addbr switch && brctl addif switch $beaker_eth || return -1
    	killall dhclient > /dev/null; sleep 1;dhclient switch || return -1
    	ip addr flush $beaker_eth
    	return 0
    }
    new_br()
    {
    	if [ ! -f /etc/qemu-ifup-br0 ];then
                    cat << EOF > /etc/qemu-ifup-br0
    #!/bin/sh
    switch=br0
    /sbin/ifconfig \$1 0.0.0.0 up
    /usr/sbin/brctl addif \${switch} \$1
    EOF
                    chmod 755 /etc/qemu-ifup-br0
            fi
    	if [ ! -f /etc/qemu-ifdown-br0 ];then
                    cat << EOF > /etc/qemu-ifdown-br0
    #!/bin/sh
    switch=br0
    /usr/sbin/brctl delif \${switch} \$1
    EOF
                    chmod 755 /etc/qemu-ifdown-br0
            fi
    	brctl show |grep br0 > /dev/null && return 0
    	brctl addbr br0 && ip addr add 192.168.0.254/24 dev br0 || return -1
    	ip link set br0 up
    	return 0
    }
    start_vm()
    {
    	/usr/libexec/qemu-kvm -name vm1 \
    	-drive file=/root/$img_name,if=none,id=drive-virtio-disk1,media=disk,cache=none,snapshot=off,format=qcow2,aio=native  \
    	-device virtio-blk-pci,drive=drive-virtio-disk1,id=virtio-disk1,bootindex=0  \
    	-netdev tap,id=hostnet0,vhost=on,script=/etc/qemu-ifup,downscript=downscript=/etc/qemu-ifdown \
    	-device virtio-net-pci,netdev=hostnet0,id=virtio-net-pci0,mac=$mac_addr \
    	$kvm_append \
    	-smp 2,cores=1,threads=1,sockets=2  \
    	-m 4096 >>./ips 2>&1 &
    	return 0
    }
    get_gip()
    {
    	gip_addr=`timeout 200 tcpdump -i switch ether src $mac_addr and arp[7]=1 and arp[15]!=0 -n -c 1 2>/dev/null| awk -F' |,' '{print $8}'`
    	test -z $gip_addr && return -1
    	sleep 1;
    	return 0;
    }
    exp_run()
    {
    	./sshrun $gip_addr $!
    }
    start_kvm()
    {
    	sys_init || { echo "sys init fail" ; exit -1;} && echo "sys init"
    	get_mac  || { echo "get mac  fail" ; exit -2;} && echo "get mac "$mac_addr
    	new_swit || { echo "new swit fail" ; exit -3;} && echo "net public br"
    	new_br   || { echo "new br0  fail" ; exit -4;} && echo "net pravite br"
    	start_vm || { echo "start vm fail" ; exit -5;} && echo "start vm "
    	get_gip  || { echo "get gip  fail" ; exit -6;} && echo $gip_addr >> ips
    	echo "successfully"
    }
    enable_sriov()
    {
    	ip link set $sriov_dev up
    	dev_bus=`ethtool -i $sriov_dev |grep bus-info |awk '{print $2}'`
    	echo 1 > /sys/bus/pci/devices/$dev_bus/sriov_numvfs
    	sriov_bus_brief=`lspci|grep "Virtual Function" |awk '{print $1}'`
    	sriov_bus=0000:$sriov_bus_brief
    	local sriov_num_tmp=`lspci -n -s $sriov_bus | awk '{ print $3 }'`
    	sriov_num=${sriov_num_tmp/:/ }
    	echo $sriov_num > /sys/bus/pci/drivers/pci-stub/new_id
    	echo $sriov_bus > /sys/bus/pci/devices/$sriov_bus/driver/unbind
    	echo $sriov_bus > /sys/bus/pci/drivers/pci-stub/bind
    	echo 1 > /sys/module/kvm/parameters/allow_unsafe_assigned_interrupts
    }
    ##### main
    sys_cls
    enable_sriov || { echo "enable sriov fail"; exit -1;} && echo "enable sriov done"
    img_name="win2012-64-virtio.qcow2"
    kvm_append="-device pci-assign,host=$sriov_bus_brief,id=vfnet1 -vnc :3 -usb -device usb-tablet"
    start_kvm

3. others 
