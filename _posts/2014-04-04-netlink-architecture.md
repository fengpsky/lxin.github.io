---
layout: post
title: "netlink框架"
category: linux kernel
excerpt: "about netlink"
tags: "kernel"
---
{% include JB/setup %}

### 几个关键的结构体

#### netlink_table

net/netlink/af_netlink.h中

    struct netlink_table {
            struct nl_portid_hash   hash;//放这个协议的sock实例
            struct hlist_head       mc_list;//组播的sock实例列表
            struct listeners __rcu  *listeners;
            unsigned int            flags;
            unsigned int            groups;//组的个数
            struct mutex            *cb_mutex;
            struct module           *module;
            void                    (*bind)(int group);//要加入的组
            bool                    (*compare)(struct net *net, struct sock *sock);//查找时的对比参数
            int                     registered;
    };

描述一个netlink的procotol, netlink.h中定义了目前所有的，包括最常用的NETLINK_ROUTE, NETLINK_GENERIC;　这个结构体包含了最关键的nl_portid_hash类型结构的字段.
struct netlink_table *nl_table 是管理整个netlink procotol的表, 是global的.其创建是在af_netlink.c中的netlink_proto_init()中，各自初始化则是在相应的模块中，如NETLINK_ROUTE是在rtnetlink.c里的rtnetlink_net_init()中。

#### netlink_sock

net/netlink/af_netlink.h中

    struct netlink_sock {
            /* struct sock has to be the first member of netlink_sock */
            struct sock             sk;
            u32                     portid;
            u32                     dst_portid;
            u32                     dst_group;
            u32                     flags;
            u32                     subscriptions;
            u32                     ngroups;
            unsigned long           *groups;
            unsigned long           state;
            wait_queue_head_t       wait;
            bool                    cb_running;
            struct netlink_callback cb;
            struct mutex            *cb_mutex;
            struct mutex            cb_def_mutex;
            void                    (*netlink_rcv)(struct sk_buff *skb);
            void                    (*netlink_bind)(int group);
            struct module           *module;
    #ifdef CONFIG_NETLINK_MMAP
            struct mutex            pg_vec_lock;
            struct netlink_ring     rx_ring;
            struct netlink_ring     tx_ring;
            atomic_t                mapped;
    #endif /* CONFIG_NETLINK_MMAP */
    };

从名称就可以看出来是netlink自己的传输控制块， 不失一般性， 它封装的依然是我们熟悉的struct sock.里面再包含了一些特有的信息， 重要的如portid, netlink_rcv().

#### nlmsghdr & sockaddr_nl

    struct sockaddr_nl {
            __kernel_sa_family_t    nl_family;      /* AF_NETLINK   */
            unsigned short  nl_pad;         /* zero         */
            __u32           nl_pid;         /* port ID      */
            __u32           nl_groups;      /* multicast groups mask */
    };

    struct nlmsghdr {
            __u32           nlmsg_len;      /* Length of message including header */
            __u16           nlmsg_type;     /* Message content */
            __u16           nlmsg_flags;    /* Additional flags */
            __u32           nlmsg_seq;      /* Sequence number */
            __u32           nlmsg_pid;      /* Sending process port ID */
    };

两个重要的结构, 不过注释很清楚了,其中nl_groups, 作为bind 函数的参数，用于把调用进程加入到该nl_groups指定的多播组，如果设置为 0，表示调用者不加入任何多播组。作为sendto等函数的参数时。若nl_groups为0，配合nl_pid发送单播数据，当nl_groups不为0，配合nl_pid发送多播。
另外，　nl_pid, to kernel, =0, to user multicast , =0.

#### TLV(Type-Length-Value)

这个格式应该不会陌生，　使用的就是:

    struct nlattr {
            __u16           nla_len;
            __u16           nla_type;
    };

正是netlink message 的消息格式。


### 创建

#### 内核态

netlink_kernel_create(), net/netlink/af_netlink.c

在这个函数中：

1. 先创建struct socket, 通过socket_create_lite()

2. 再创建struct sock, 通过__netlink_create(), 并与上面的socket进行关联, 当然netlink_ops与netlink_proto都是必传的属性， 不过与用户态创建不同的是进入路径不再是通过的->create().

3. 下来还有很关键一步， nlk_sk(sk)->netlink_rcv = cfg->input， 绑定它的接收处理函数.而cfg就是创建时由各自模块传入的一个参数，如rtnetlink中

        struct netlink_kernel_cfg cfg = {
                .groups         = RTNLGRP_MAX,
                .input          = rtnetlink_rcv,
                .cb_mutex       = &rtnl_mutex,
                .flags          = NL_CFG_F_NONROOT_RECV,
        };

4. 当然还要将它添加到table->hash中呢，netlink_insert(sk, net, 0)，注意第三个参数一定是0,内核中的port id 总是为0.

5. 最后就是对应的nl_table表项中相应的实例进行添加.

#### 用户态

    通过 PF_NETLINK协议族，最终会调用netlink_create.下面是一个协议族该有的属性：

        static const struct net_proto_family netlink_family_ops = {
                .family = PF_NETLINK,
                .create = netlink_create,
                .owner  = THIS_MODULE,  /* for consistency 8) */
        };
    
        static struct proto netlink_proto = {
                .name     = "NETLINK",
                .owner    = THIS_MODULE,
                .obj_size = sizeof(struct netlink_sock),
        };
    
        static const struct proto_ops netlink_ops = {
                .family =       PF_NETLINK,
                .owner =        THIS_MODULE,
                .bind =         netlink_bind,
                .connect =      netlink_connect,
                .sendmsg =      netlink_sendmsg,
                .recvmsg =      netlink_recvmsg,
                ....
        };

1. 与内核态相同的是都会调用__netlink_create()进行struct sock的创建，　而struct socket的创建由于走的是通用socket接口因些此时已经被创建.

2. 由于是内核态创建套接字在先，　因些可以获取到相应的nl_table[protocol], 并拿到对应的一些属性，如bind, 赋值给nlk->netlink_bind.

### bind

通用socket接口，最终会调用netlink_bind()完成bind.

1. 如果指定了port id，就使用netlink_insert(), 这个函数中关键性的两步是:

        head = nl_portid_hashfn(hash, portid);
        ....
        nlk_sk(sk)->portid = portid;
        sk_add_node(sk, head);

2. 下来就是对group的处理了.


### connect

通用socket接口，netlink_connect().

没做很多工作，就是设置了下目的地址。

        if (err == 0) {
                sk->sk_state    = NETLINK_CONNECTED;
                nlk->dst_portid = nladdr->nl_pid;
                nlk->dst_group  = ffs(nladdr->nl_groups);
        }


### 发送

#### 用户态

netlink_sendmsg()

1. 先对组播进行处理，netlink_broadcast(), 组播的路径为:

        netlink_broadcast_filtered->do_one_broadcast->netlink_broadcast_deliver->(netlink_skb_set_owner_r)__netlink_sendskb
    
        sk_for_each_bound(sk, &nl_table[ssk->sk_protocol].mc_list)
                    do_one_broadcast(sk, &info);

    现在也该清楚mc_list里面是放什么的了, 在bind的时候会将有组播号的sock加入进来。方便在组播时快速找到，这里只是一个粗略的查找，对于精确的对于是在do_one_broadcast()中

        if (nlk->portid == p->portid || p->group - 1 >= nlk->ngroups ||
            !test_bit(p->group - 1, nlk->groups))
                goto out;

2. netlink_unicast()中再做处理, 其中代码:

        sk = netlink_getsockbyportid(ssk, portid);
        ...
        if (netlink_is_kernel(sk))
               return netlink_unicast_kernel(sk, skb, ssk);

    由于内核态的发送也是调用netlink_unicast()在这里就要做一下区分，如果是发送给kernel会走另一条路径。

3. 在netlink_getsockbyportid()中会通过netlink_lookup()在相应的nl_table->hash中查找。

        head = nl_portid_hashfn(hash, portid);
        sk_for_each(sk, head) {
                if (table->compare(net, sk) &&
                    (nlk_sk(sk)->portid == portid)) {
                        sock_hold(sk);
                        goto found;
                }
        }

4. 然后调用netlink_unicast_kernel():

        if (nlk->netlink_rcv != NULL) {
                ret = skb->len;
                netlink_skb_set_owner_r(skb, sk);
                NETLINK_CB(skb).sk = ssk;
                netlink_deliver_tap_kernel(sk, ssk, skb);
                nlk->netlink_rcv(skb);
                consume_skb(skb);
        } else {
                kfree_skb(skb);
        }

    在这个函数当中，　会将skb bound到sk上，再调用对应创建时指定的netlink_rcv函数。

#### 内核态

1. 对于组播的，　使用netlink_broadcast(),等同于用户态的

2. 对于单播的，　使用netlink_unicast(), 在用户态的第2步时，　会选择执行netlink_attachskb(),将套接字绑定，继续往下走

3. netlink_sendskb()中会调用skb_queue_tail(&sk->sk_receive_queue, skb);将skb 挂在sock的接收队列上,


### 接收

内核态的接收是被注册后，　被动触发的

用户态觉得也没什么可说的，　重要的就是从缓冲区中拿数据.
