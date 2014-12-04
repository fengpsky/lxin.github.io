---
layout: post
title: "linux vs unix (freebsd) --network"
category: linux kernel
excerpt: "compare linux and freebsd network protocol stack"
tags: "kernel"
---
{% include JB/setup %}
bsd is a topical unix system, whose protocol stack is much elder than linux's. linux always study network from bsd, and backport many functions. through many years, linux has almost catch up with bsd in network, and also has some own special thing. of course , there are still some feature cannot copy form bsd, because of difference of some innate design. then let me show what I know about linux and bsd in network kernel stack

##common:

nothing to talk, the most import protocols and many popular techniques are supported in both of them.

##particular:

###linux:

1. netlink:

it's the main method to communicate between userland and kernel in linux. many system configuration tools are using it, like iproute, nft... while some old thing will be dropped, like net-tools. evidently, netlink is substituing some old userland-kernel communication tools, which includes setoptsock, ioctl, copyfrom/touser...

but in bsd, it also supply the socket method for userland-kernel communication. but it only use for specific modules, and is not a common procotol. for example, netgraph use that to configuration. so bsd seems will not complenment this new function.  which lead to that we can only use ifconfig, but not use ip to configure the network.

2. ipvs:

ipvs is complemented in netfilter of linux, and can be used to do transport-layer load balancing, which we called "Layer-4 switching". that's a amazing feature.

so bsd has a project to backport this to itself, this project is "LVS On FreeBSD" http://dragon.linux-vs.org/~dragonfly/htm/lvs_freebsd.htm.

###freebsd:

1. netgraph

like a graph, we can put some node and connect them together to complete ourself's protocols. which is called "Dynamic Procotol Stack".

linux is trying to backport with the 'lana' project

2. pf

a Object-Oriented firewall, run much faster than others. 

cannot find any project about this in linux community.

3. carp

common arp protocl, linuxer start to backport , but still not appear in mainstream

