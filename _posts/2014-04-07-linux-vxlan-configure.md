---
layout: post
title: "linux vxlan的使用"
category: linux kernel
excerpt: "vxlan三种使用方式"
tags: "kernel"
---
{% include JB/setup %}
## 1.vxlan独立使用时：

* host1:

    ip link add vxlan10 type vxlan id 10 group 239.0.0.10 ttl 4 dev eth1
    ifconfig eth1 192.168.0.10/24 up
    ifconfig vxlan10 192.168.10.10/24 up
    iptables -F

* host2:

    ip link add vxlan10 type vxlan id 10 group 239.0.0.10 ttl 4 dev eth1
    ifconfig eth1 192.168.0.20/24 up
    ifconfig vxlan10 192.168.10.20/24 up
    iptables -F

## 2.vxlan在ovs中的使用:

* host1:

    ovs-vsctl add-br br1
    ifconfig br1 192.168.0.10 netmask 255.255.255.0
    ovs-vsctl add-port br1 vx1 -- set interface vx1 type=vxlan options:remote_ip=192.168.1.11
    ifconfig eth1 192.168.1.10/24 up

* host2:

    ovs-vsctl add-br br1
    ifconfig br1 192.168.0.11 netmask 255.255.255.0
    ovs-vsctl add-port br1 vx1 -- set interface vx1 type=vxlan options:remote_ip=192.168.1.10
    ifconfig eth1 192.168.1.11/24 up

## 3.vxlan作为设备加入bridge/ovs中:

* host1:

    brctl addbr br2
    ifconfig br2 192.168.3.10/24 up
    ip link add vxlan0 type vxlan id 42 group 239.1.1.1 dev eth1
    brctl addif br2 vxlan0

* host2:

    brctl addbr br2
    ifconfig br2 192.168.3.11/24 up
    ip link add vxlan0 type vxlan id 42 group 239.1.1.1 dev eth1
    brctl addif br2 vxlan0
