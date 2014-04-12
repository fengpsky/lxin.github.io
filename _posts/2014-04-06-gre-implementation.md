---
layout: post
title: "vxlan的内核实现"
category: linux kernel
excerpt: "about linux vxlan"
tags: "kernel"
---
{% include JB/setup %}
gre的实现是基于ip_tunnel框架的.
#几个关键的结构体#
##struct##

#初始化#
##注册模块##
###gre_demux.ko###
gre_init()中
1.添加一个net_protocol项,inet_add_protocol(&net_gre_protocol, IPPROTO_GRE),这个数据结构应该比较清楚，里面的handler那是四层接收的入口

    static const struct net_protocol net_gre_protocol = {
            .handler     = gre_rcv,
            .err_handler = gre_err,
            .netns_ok    = 1,
    };

2.gre_add_protocol(&ipgre_protocol, GREPROTO_CISCO),添加一个自身内部协议处理接口

    static const struct gre_protocol ipgre_protocol = {
            .handler     = gre_cisco_rcv,
            .err_handler = gre_cisco_err,
    };

不过目前也没看到有另一个协议的加入，这个很明显己经是gre自己在为自己搭框架了，　ip_tunnel满足得了ipip, vti,却满足不了功能强大的gre

###ip_gre.ko###
ipgre_init()中
1.err = register_pernet_device(&ipgre_net_ops);

    static struct pernet_operations ipgre_net_ops = {
            .init = ipgre_init_net,
            .exit = ipgre_exit_net,
            .id   = &ipgre_net_id,
            .size = sizeof(struct ip_tunnel_net),
    };

前面说到过的pernet接口

2.err = rtnl_link_register(&ipgre_link_ops);

    static struct rtnl_link_ops ipgre_link_ops __read_mostly = {
            .kind           = "gre",
            .maxtype        = IFLA_GRE_MAX,
            .policy         = ipgre_policy,
            .priv_size      = sizeof(struct ip_tunnel),
            .setup          = ipgre_tunnel_setup,
            .validate       = ipgre_tunnel_validate,
            .newlink        = ipgre_newlink,
            .changelink     = ipgre_changelink,
            .dellink        = ip_tunnel_dellink,
            .get_size       = ipgre_get_size,
            .fill_info      = ipgre_fill_info,
    };

前面说过rtnl的接口

3.ipgre_init_net()中会调用ip_tunnel_init_net()，ip_tunnel框架中的接口.传入了一个参数ipgre_net_id，　用来找pernet变量的。

另外，与gre相应的也会有一个tap设备进行相似的设置，后面会说到

##创建##
ipgre_newlink()中完成
1.这是一个rtnl框架注册过的函数，　因此rtnl执行到这的时候net_device己经创建，并且己调用相应的setup()函数设置过,见rtnl_netlink分析.
ipgre_tunnel_setup()中，为net_device设置了ops, 并且会调用ip_tunnel中的ip_tunnel_setup()

    static const struct net_device_ops ipgre_netdev_ops = {
            .ndo_init               = ipgre_tunnel_init,
            .ndo_uninit             = ip_tunnel_uninit,
    #ifdef CONFIG_NET_IPGRE_BROADCAST
            .ndo_open               = ipgre_open,
            .ndo_stop               = ipgre_close,
    #endif
            .ndo_start_xmit         = ipgre_xmit,
            .ndo_do_ioctl           = ipgre_tunnel_ioctl,
            .ndo_change_mtu         = ip_tunnel_change_mtu,
            .ndo_get_stats64        = ip_tunnel_get_stats64,
    };

2.然后调用iptunnel框架中的ip_tunnel_newlink()

3.ndo_init会在ip_tunnel_newlink register设备时被触发，但ipgre_tunnel_init还是回调用ip_tunnel_init. 看来这个框架不是一般的绕啊.


#发送
