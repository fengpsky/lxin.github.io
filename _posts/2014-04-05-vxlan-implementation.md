---
layout: post
title: "vxlan的内核实现"
category: linux kernel
excerpt: "about linux vxlan"
tags: "kernel"
---
{% include JB/setup %}

### 几个关键的结构体
#### vxlan_net

    struct vxlan_net {
            struct list_head  vxlan_list;
            struct hlist_head sock_list[PORT_HASH_SIZE];
            spinlock_t        sock_lock;
    };

一个每名字空间的数据块。

#### struct vxlan_sock

    struct vxlan_sock {
            struct hlist_node hlist;
            vxlan_rcv_t      *rcv;//接收函数，但事实上入口接收是encap_rcv()
            void             *data;
            struct work_struct del_work;
            struct socket    *sock;
            struct rcu_head   rcu;
            struct hlist_head vni_list[VNI_HASH_SIZE];//关联vni
            atomic_t          refcnt;
            struct udp_offload udp_offloads;//vxlan udp offloads使用
    };

#### struct vxlan_dev

    struct vxlan_dev {
            struct hlist_node hlist;        /* vni hash table */
            struct list_head  next;         /* vxlan's per namespace list */
            struct vxlan_sock *vn_sock;     /* listening socket */
            struct net_device *dev;
            struct vxlan_rdst default_dst;  /* default destination */
            union vxlan_addr  saddr;        /* source address */
            __be16            dst_port;
            __u16             port_min;     /* source port range */
            __u16             port_max;
            __u8              tos;          /* TOS override */
            __u8              ttl;
            u32               flags;        /* VXLAN_F_* below */

            struct work_struct sock_work;
            struct work_struct igmp_join;
            struct work_struct igmp_leave;//三个工作队列

            unsigned long     age_interval;
            struct timer_list age_timer;
            spinlock_t        hash_lock;
            unsigned int      addrcnt;
            unsigned int      addrmax;

            struct hlist_head fdb_head[FDB_HASH_SIZE];//转发表
    };

net_device的private成员，即vxlan设备的私有信息

#### struct vxlan_rdst

    struct vxlan_rdst {
            union vxlan_addr         remote_ip;
            __be16                   remote_port;
            u32                      remote_vni;
            u32                      remote_ifindex;
            struct list_head         list;
            struct rcu_head          rcu;
    };

存在在vxlan_fdb的remotes中用于描述远端的地址信息.

#### struct vxlan_fdb

    /* Forwarding table entry */
    struct vxlan_fdb {
            struct hlist_node hlist;        /* linked list of entries */
            struct rcu_head   rcu;
            unsigned long     updated;      /* jiffies */
            unsigned long     used;
            struct list_head  remotes;//struct vxlan_rdst链表
            u16               state;        /* see ndm_state */
            u8                flags;        /* see ndm_flags */
            u8                eth_addr[ETH_ALEN];//
    };

转发表，存在在vxlan_dev的fdb_head中


### 初始化
#### 注册模块
##### vxlan_init_module(),drivers/net/vxlan.c, 也是比较清晰的几行代码.

1. vxlan_wq = alloc_workqueue("vxlan", 0, 0);申请一个工作队列，后面会说到它的作用. vxlan_wq是global的
2. rc = register_pernet_subsys(&vxlan_net_ops);注册一个每名字空间的操作

        static struct pernet_operations vxlan_net_ops = {
                .init = vxlan_init_net,
                .id   = &vxlan_net_id,
                .size = sizeof(struct vxlan_net),
        };

3. rc = register_netdevice_notifier(&vxlan_notifier_block); 网络通知链
4. rc = rtnl_link_register(&vxlan_link_ops);rtnl框架注册link操作,见rtnl框架分析
5. 其中，在vxlan_init_net()中，获取一块空间，　用来存放一个pernet的vxlan_net,　并进行初始化。

#### 创建
##### vxlan_newlink()中完成
1. 这是一个rtnl框架注册过的函数，　因此rtnl执行到这的时候net_device己经创建，并且己调用相应的setup()函数设置过,见rtnl_netlink分析.

vxlan_setup()中，为net_device设置了ops, 以及初始化fdb, 还有三个工作队列

        static const struct net_device_ops vxlan_netdev_ops = {
                .ndo_init               = vxlan_init,
                .ndo_uninit             = vxlan_uninit,
                .ndo_open               = vxlan_open,
                .ndo_stop               = vxlan_stop,
                .ndo_start_xmit         = vxlan_xmit,
                .ndo_get_stats64        = ip_tunnel_get_stats64,
                .ndo_set_rx_mode        = vxlan_set_multicast_list,
                .ndo_change_mtu         = vxlan_change_mtu,
                .ndo_validate_addr      = eth_validate_addr,
                .ndo_set_mac_address    = eth_mac_addr,
                .ndo_fdb_add            = vxlan_fdb_add,
                .ndo_fdb_del            = vxlan_fdb_delete,
                .ndo_fdb_dump           = vxlan_fdb_dump,
        };

        INIT_WORK(&vxlan->igmp_join, vxlan_igmp_join);
        INIT_WORK(&vxlan->igmp_leave, vxlan_igmp_leave);
        INIT_WORK(&vxlan->sock_work, vxlan_sock_work);

最后面的这个工作队列会在netlink的时候触发(ndo_init).在它里面会创建传说中的vxlan_sock

2. 接着将其private还原成struct vxlan_dev,进行初始化, 如：

        struct vxlan_rdst *dst = &vxlan->default_dst;
        dst->remote_vni = vni;
        dst->remote_ip.sin.sin_addr.s_addr = nla_get_be32(data[IFLA_VXLAN_GROUP]);
        dst->remote_ip.sa.sa_family = AF_INET;
        vxlan->saddr.sin.sin_addr.s_addr = nla_get_be32(data[IFLA_VXLAN_LOCAL]);
        vxlan->saddr.sa.sa_family = AF_INET;
        dst->remote_ifindex = nla_get_u32(data[IFLA_VXLAN_LINK]
        ....
        vxlan->dst_port = nla_get_be16(data[IFLA_VXLAN_PORT]);

3. 并且会通过vxlan_find_vni(net, vni, vxlan->dst_port)对vni进行duplicate检测
4. 调用vxlan_fdb_create()创建条转发项

        err = vxlan_fdb_create(vxlan, all_zeros_mac,
                               &vxlan->default_dst.remote_ip,
                               NUD_REACHABLE|NUD_PERMANENT,
                               NLM_F_EXCL|NLM_F_CREATE,
                               vxlan->dst_port,
                               vxlan->default_dst.remote_vni,
                               vxlan->default_dst.remote_ifindex,
                               NTF_SELF);


5.注册net_device,同时在register_netdevice时利用ndo_init  queue_work(vxlan_wq, &vxlan->sock_work);触发vxlan_sock_work(). 此时就能用ifconfig 看到设备了,并再添加进行vxlan_net中。

#### 创建vxlan_socket
##### 在vxlan_sock_work()中完成
1. vxlan_sock_add(),调用vxlan_socket_create(),如果失败，就用vxlan_find_sock()在pernet中去根据port去找
2. 在,vxlan_socket_create中,先申请一个vs. 再创建一个sock

        if (ipv6)
                sock = create_v6_sock(net, port);
        else
                sock = create_v4_sock(net, port);

相信你会看个这个很水的sock,连创建函数都是定制的, create_v4_sock:

        struct sockaddr_in vxlan_addr = {
                .sin_family = AF_INET,
                .sin_addr.s_addr = htonl(INADDR_ANY),
                .sin_port = port,
        };
        rc = sock_create_kern(AF_INET, SOCK_DGRAM, IPPROTO_UDP, &sock);
        ....
        rc = kernel_bind(sock, (struct sockaddr *) &vxlan_addr,
                         sizeof(vxlan_addr));

上面才回到通用创建的接口上。
3. 还有一个重要的操作，就是vs->rcv = rcv，设置接收函数.当然先调用函数调用在下面设置：

        udp_sk(sk)->encap_type = 1;
        udp_sk(sk)->encap_rcv = vxlan_udp_encap_recv;

对于这个函数，会在接收时重点说。


### 打开
##### 既然是虚拟网络设置，就按个这个框架来说明，ifconfig vxlan* up, 调用vxlan_open()，做了两件事情
1. queue_work(vxlan_wq, &vxlan->igmp_join);唤醒另一个工作队列
2. 还有一个定时器，后面再做深入
3. vxlan_igmp_join()中，主要还是调用通用接口来设置vxlan_sock加入mgroup.

        struct sock *sk = vs->sock->sk;
        int ifindex = vxlan->default_dst.remote_ifindex;
        struct ip_mreqn mreq = {
                            .imr_multiaddr.s_addr   = ip->sin.sin_addr.s_addr,
                            .imr_ifindex            = ifindex,
                    };

                    ip_mc_join_group(sk, &mreq);

很显然，从一开始到现在都是让这个sock能有接收包的能力，似乎在发包时没有让你承载travel ip栈的想法


### 发送
##### ndo_start_xmit函数是vxlan_xmit, 自然由它完成发送,此时的发是一个完整的ether包。
1. f = vxlan_find_mac(vxlan, eth->h_dest); 先去fdb表中找vxlan_fdb转发项,相当于协议栈中的dst_entry, 当然是通过mac地址来找的
2. 如果没有找着，一开始还没学习通常都会这样，就会执行f = vxlan_find_mac(vxlan, all_zeros_mac); all_zeros_mac对应的那个项就是我们一开始添加的那个，所以应该会有期望结果返回，而返回的结中的目的地址就是添加时的参数里的那个多播地址，　就用在这里了。
3. 当然找着的转发项可能存在多个目的地址，因此：

        list_for_each_entry_rcu(rdst, &f->remotes, list) {
                struct sk_buff *skb1;

                if (!fdst) {
                        fdst = rdst;
                        continue;
                }
                skb1 = skb_clone(skb, GFP_ATOMIC);
                if (skb1)
                        vxlan_xmit_one(skb1, dev, rdst, did_rsc);
        }

        if (fdst)
                vxlan_xmit_one(skb, dev, fdst, did_rsc);

4. 可见在vxlan_xmit 中完成了转发项的查找，再调用vxlan_xmit_one, 关键性的几行代码:

        fl4.flowi4_oif = rdst->remote_ifindex;
        fl4.flowi4_tos = RT_TOS(tos);
        fl4.daddr = dst->sin.sin_addr.s_addr;
        fl4.saddr = vxlan->saddr.sin.sin_addr.s_addr;

        rt = ip_route_output_key(dev_net(dev), &fl4);

这便是构建flowi,完成路由的查找，　再往后的发送就是vxlan_xmit_skb了。

5. 在这个函数中,非常重要的一步:

        min_headroom = LL_RESERVED_SPACE(rt->dst.dev) + rt->dst.header_len
                        + VXLAN_HLEN + sizeof(struct iphdr)
                        + (vlan_tx_tag_present(skb) ? VLAN_HLEN : 0);

        /* Need space for new headers (invalidates iph ptr) */
        err = skb_cow_head(skb, min_headroom);

skb_cow_head是用来拷贝和扩展头部空间的,这个函数有点麻烦，就不分析了.

        vxh = (struct vxlanhdr *) __skb_push(skb, sizeof(vxh));
        vxh->vx_flags = htonl(VXLAN_FLAGS);
        vxh->vx_vni = vni;

        __skb_push(skb, sizeof(uh));
        skb_reset_transport_header(skb);
        uh = udp_hdr(skb);

        uh->dest = dst_port;
        uh->source = src_port;

        uh->len = htons(skb->len);
        uh->check = 0;

        err = handle_offloads(skb);
        if (err)
                return err;

        skb_set_owner_w(skb, vs->sock->sk);

这些代码不用说了，　就是扩展完之后，进行vxlan头部，　和udp头部的填充的,

6.再接iptunnel_xmit函数完成发送，　这个函数是ip_tunnel添加ip头部并发送的必调函数。见ip_tunnel框架的分析.

另外在vxlan整个代码处理过程中，虽说它是个tunnel，　但并没有套用用ip_tunnel这个框架，不明白为什么加载时还要依赖ip_tunnel这个模块

### 接收
##### 上面提到了vs对应的udp_sock中的encap_rcv = vxlan_udp_encap_recv，　则在接收于会交给这个接口，　默认你是了解udp_rcv的。
1. 此时到的数据是一个ether包+vxlan头部,因此首先获取vxh头，然后再利用ip_tunnel的另一个接口移动头部指针到正确位置:

        vxh = (struct vxlanhdr *)(udp_hdr(skb) + 1);
        ...
        if (iptunnel_pull_header(skb, VXLAN_HLEN, htons(ETH_P_TEB)))
            goto drop;

2. 接下来就调用到了vxlan_rcv:

        vxlan = vxlan_vs_find_vni(vs, vni);
        if (!vxlan)
                goto drop;

先判断vni是否存在，不存在就drop.

        if ((vxlan->flags & VXLAN_F_LEARN) &&
            vxlan_snoop(skb->dev, &saddr, eth_hdr(skb)->h_source))
                goto drop;

vxlan_snoop重要的一步，是fdb项的学习,它会把此次通信的包以mac为索引添加进fdb表.当然对于这种表，有添加就得有清理，类似于邻居表或路由表，还记得初始化那会一个定时器吗，没有讲，它的作用就是来根据时间做表的清理工作的。

3. 到此，就剩下把这个完整的ether包上交了, netif_rx(),好经典好古老的一个接口，相信你还记得它。

