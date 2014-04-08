---
layout: post
title: "ip_tunnel框架"
category: linux kernel
excerpt: "ip_tunnel 的简单分析"
tags: "kernel"
---
{% include JB/setup %}

内核中一提到tunnel几乎都和这东西有关，当然除了xfrm框架中的tunnel_mode，见xfrm框架的分析。像ipip, vti, gre等.

#几个关键的结构体#
##struct ip_tunnel##

    struct ip_tunnel {
            struct ip_tunnel __rcu  *next;
            struct hlist_node hash_node;
            struct net_device       *dev;
            struct net              *net;   /* netns for packet i/o */

            int             err_count;      /* Number of arrived ICMP errors */
            unsigned long   err_time;       /* Time when the last ICMP error
                                             * arrived */

            /* These four fields used only by GRE */
            __u32           i_seqno;        /* The last seen seqno  */
            __u32           o_seqno;        /* The last output seqno */
            int             hlen;           /* Precalculated header length */
            int             mlink;

            struct ip_tunnel_dst __percpu *dst_cache;

            struct ip_tunnel_parm parms;

            /* for SIT */
    #ifdef CONFIG_IPV6_SIT_6RD
            struct ip_tunnel_6rd_parm ip6rd;
    #endif
            struct ip_tunnel_prl_entry __rcu *prl;  /* potential router list */
            unsigned int            prl_count;      /* # of entries in PRL */
            int                     ip_tnl_net_id;
            struct gro_cells        gro_cells;
    };

ip相关的tunnel中，一些通用的字段，由于它是个框架，而其它的tunnel又没有对它封装，而是直接使用它来承载，因此会有各自tunnel特有的字段

##struct ip_tunnel_parm##

    struct ip_tunnel_parm {
            char                    name[IFNAMSIZ];
            int                     link;
            __be16                  i_flags;
            __be16                  o_flags;
            __be32                  i_key;
            __be32                  o_key;
            struct iphdr            iph;
    };
重要的结构，用来接收及承载设置参数的

##ip_tunnel_net##

    struct ip_tunnel_net {
            struct net_device *fb_tunnel_dev;
            struct hlist_head tunnels[IP_TNL_HASH_SIZE];
    };

pernet的全局变量

#初始化#
##注册模块##
这个模块中，全是接口，没有加载时运行的函数，都需要别的模块如ip_gre.ko全触发.
ip_tunnel_init_net()中，通常在新建一个名字空间时被调
1.初始化名字空间里的tunnels:

    for (i = 0; i < IP_TNL_HASH_SIZE; i++)
            INIT_HLIST_HEAD(&itn->tunnels[i]);

2.创建fb_tunnel_dev设备,并将其加入全局tunnels中

    tn->fb_tunnel_dev = __ip_tunnel_create(net, ops, &parms);
    itn->fb_tunnel_dev->features |= NETIF_F_NETNS_LOCAL;
    ip_tunnel_add(itn, netdev_priv(itn->fb_tunnel_dev));

##创建##
1.ip_tunnel_setup()通常是在xtunnel(某种类型)中的setup函数中调用如ipgre_setup
在这个函数中仅设置了个net_id

2.ip_tunnel_newlink通常是在xtunnel中的newlink函数中调用:

ip_tunnel_find, 以ip_tunnel_parm为参数在全局的hash中查看是否己存在
从netdev_priv中取出ip_tunnel, 并nt->parms = *p,设置参数
ip_tunnel_bind_dev()下面会讲
注册net_device,同时在register_netdevice时利用ndo_init  并再ip_tunnel_add进hash中。

3.ip_tunnel_init中补充性地对struct ip_tunnel *tunnel作一些初始化及与dev 的关联

4.ip_tunnel_bind_dev:

    init_tunnel_flow(&fl4, iph->protocol, iph->daddr,               
                     iph->saddr, tunnel->parms.o_key,               
                     RT_TOS(iph->tos), tunnel->parms.link);         
    rt = ip_route_output_key(tunnel->net, &fl4);                    
                                                                    
    if (!IS_ERR(rt)) {                                              
            tdev = rt->dst.dev;                                     
            tunnel_dst_set(tunnel, &rt->dst);                       
            ip_rt_put(rt);                                          
    }                 

查找路由项，并更新t->dst_cache, 以及tdev = rt->dst.dev/ tdev = __dev_get_by_index(tunnel->net, tunnel->parms.link);获取物理网卡的mtu



##__ip_tunnel_create##
newlink接口是不会调用到这里的，只在ioctl和fb_tunnel_dev会调用到__ip_tunnel_create，在这个函数里会:

    dev = alloc_netdev(ops->priv_size, name, ops->setup);
    if (!dev) {
            err = -ENOMEM;
            goto failed;
    }
    dev_net_set(dev, net);

    dev->rtnl_link_ops = ops;

    tunnel = netdev_priv(dev);
    tunnel->parms = *parms;
    tunnel->net = net;

    err = register_netdevice(dev);

即与newlink做类似的操作
之所以存在fb_tunnel_dev,个人暂时的理解是在这个里面存了一些创建时需要的数据，像link_ops，需在使用ioctl接口创建时正是需要这个数据.

#发送#
