---
layout: post
title: "gre/gretap的内核实现"
category: linux kernel
excerpt: "about linux vxlan"
tags: "kernel"
---
{% include JB/setup %}
gre的实现是基于ip_tunnel框架的.

##几个关键的结构体

###struct

##初始化

###注册模块

####gre_demux.ko

gre_init()中

1. 添加一个net_protocol项,inet_add_protocol(&net_gre_protocol, IPPROTO_GRE),这个数据结构应该比较清楚，里面的handler那是四层接收的入口

        static const struct net_protocol net_gre_protocol = {
                .handler     = gre_rcv,
                .err_handler = gre_err,
                .netns_ok    = 1,
        };

2. gre_add_protocol(&ipgre_protocol, GREPROTO_CISCO),添加一个自身内部协议处理接口

        static const struct gre_protocol ipgre_protocol = {
                .handler     = gre_cisco_rcv,
                .err_handler = gre_cisco_err,
        };

不过目前也没看到有另一个协议的加入，这个很明显己经是gre自己在为自己搭框架了，　ip_tunnel满足得了ipip, vti,却满足不了功能强大的gre

####ip_gre.ko

ipgre_init()中

1. err = register_pernet_device(&ipgre_net_ops);

        static struct pernet_operations ipgre_net_ops = {
                .init = ipgre_init_net,
                .exit = ipgre_exit_net,
                .id   = &ipgre_net_id,
                .size = sizeof(struct ip_tunnel_net),
        };

    前面说到过的pernet接口

2. err = rtnl_link_register(&ipgre_link_ops);

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

3. err = gre_cisco_register(&ipgre_protocol);会在自己的框架中注册一个接口:

        static struct gre_cisco_protocol ipgre_protocol = {
                .handler        = ipgre_rcv,
                .err_handler    = ipgre_err,
                .priority       = 0,
        }; 

4. ipgre_init_net()中会调用ip_tunnel_init_net()，ip_tunnel框架中的接口.传入了一个参数ipgre_net_id，　用来找pernet变量的。

另外，与gre相应的也会有一个tap设备进行相似的设置，后面会说到

###创建

ipgre_newlink()中完成

1. 这是一个rtnl框架注册过的函数，　因此rtnl执行到这的时候net_device己经创建，并且己调用相应的setup()函数设置过,见rtnl_netlink分析.
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

2. 然后调用iptunnel框架中的ip_tunnel_newlink()

3. ndo_init会在ip_tunnel_newlink register设备时被触发，但ipgre_tunnel_init,先调用__gre_tunnel_init， 再初始化dev->header_ops = &ipgre_header_ops(后面会说)， 最后还是回调用ip_tunnel_init. 看来这个框架不是一般的绕啊.

4. 在__gre_tunnel_init中：

        tunnel->hlen = ip_gre_calc_hlen(tunnel->parms.o_flags);
        tunnel->parms.iph.protocol = IPPROTO_GRE;

        dev->needed_headroom    = LL_MAX_HEADER + sizeof(struct iphdr) + 4;
        dev->mtu                = ETH_DATA_LEN - sizeof(struct iphdr) - 4;

        dev->features           |= NETIF_F_NETNS_LOCAL | GRE_FEATURES;
        dev->hw_features        |= GRE_FEATURES;

    hlen为4-16表示， gre header长度， 这是个变量哦， needed_headroom需要给头部预留的

##发送

1. 从ip层经过的包会打上内层的ip, 即真正的目的方ip与local ip, 接下来会路由和进入neigh子系统，我们应该都知道对于二层的头，都应该是在neigh完， 进入dev_queue之前，调用dev->header_ops中的create来填上包头的。而对于gre, 这个结构就是:

        static const struct header_ops ipgre_header_ops = {
                .create = ipgre_header,
                .parse  = ipgre_header_parse,
        };

      在ipgre_header由于gre包的特性自然不是二层包头了， 或者说所谓的二层包头不再是mac，而是gre header ,看它的源码：

        iph = (struct iphdr *)skb_push(skb, t->hlen + sizeof(*iph));
        greh = (struct gre_base_hdr *)(iph+1);
        greh->flags = tnl_flags_to_gre_flags(t->parms.o_flags);
        greh->protocol = htons(type);

        memcpy(iph, &t->parms.iph, sizeof(struct iphdr));

        /* Set the source hardware address. */
        if (saddr)
                memcpy(&iph->saddr, saddr, 4);
        if (daddr)
                memcpy(&iph->daddr, daddr, 4);

    实际上它连外层ip, 即tunnel ip也在这里做了， 而不单单是gre header

2. 接下来会调用ndo_start_xmit, gre对应的就是ipgre_xmit, 有趣的是它还会对dev->header_ops的存在进行判断， 如果存在，则先用skb_cow_head对头部进行调整，再拿到skb->data，即外层ip头部， 并pull到skb里层ip头的位置

                /* Need space for new headers */
                if (skb_cow_head(skb, dev->needed_headroom -
                                      (tunnel->hlen + sizeof(struct iphdr))))
                        goto free_skb;

                tnl_params = (const struct iphdr *)skb->data;

                /* Pull skb since ip_tunnel_xmit() needs skb->data pointing
                 * to gre header.
                 */
                skb_pull(skb, tunnel->hlen + sizeof(struct iphdr));

    如果不存在， 就给gretap用的。这里就已经可以看出来gre与gretap设备的不同了， 显然后者是为加入bridge这样的设置而生的， 因为如果gre加入到bridge的话， 不会执行header_ops,但后面的外层ip ,却是从经过header_ops改变之后的skb->data中拿的。

3. 接着进入__gre_xmit中， 在这个函数中， 先利用tpi组织到gre header info, 然后再调用gre_build_header将头部加入， 这里问题就出来了， 前面header_ops不是做过了吗，为什么还有这样一步, 具体我也不清楚， 但这个函数要比前面，做的工作更细致， 尽管有重复。

4. 终于又要回到ip_tunnel的框架了ip_tunnel_xmit(), 完成外层ip的封装与发送， 显然， 又有一些重复， 还是与header_ops， 因为那里已经完成了外层ip的封装。

##接收

上面提到， 在gre_demux.ko初始化时， 会注册net_gre_protocol， 这是个net_protocol， 因些gre_rcv便是gre 接收包进行处理的入口。

1. 此时的skb包,data是在gre头部上的， gre_rcv只是取出ver， proto = rcu_dereference(gre_proto[ver]); 拿取proto, 而这个合法的proto是gre_protocol类型， 正是上面gre_demux初始化时注册的ipgre_protocol, 因此下面的ver接收函数是， gre_cisco_rcv， 这显然又是gre自身为自己创建的接口与框架。也便是gre_demux.ko的意义了。

2. 在gre_cisco_rcv 这个函数当中， 会先调用parse_gre_header来对gre头部进行解析，并将结果给一个tpi变量， 另个， 在parse_gre_header中，还调用了iptunnel_pull_header. 这个函数算属于ip_tunnel框架.

3. 接着cioso gre这个协议会从gre_cisco_proto_list中取出一个gre_cisco_protocol， 这显然是它自己的扩展接口， 这个接口是在ip_gre.ko中注册的ipgre_protocol, 因些最终会到ipgre_rcv, 真是挺绕

4. 此时， skb的data是在gre header之后的头部， 是什么取决于是tunnel什么协议了，目前两种，如为ETH_P_TEB， 则在pernet gretap list上找， 否则在pernet gre list中找， 当然是根据skb->dev->ifindex, tpi->flags, iph->saddr, iph->daddr, tpi->key等信息了。

5. 如果找着， 则调用ip_tunnel_rcv， 注意到在这个之前skb_pop_mac_header(skb);很显然这是防止是gretap时的处理. ip_tunnel_rcv这又交给ip_tunnel_rcv的框架了。

