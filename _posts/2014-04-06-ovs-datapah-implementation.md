---
layout: post
title: "ovs datapath模块的实现"
category: linux kernel
excerpt: "about linux openvswitch.ko, 有讲到vxlan"
tags: "kernel"
---
{% include JB/setup %}

>datapath是openvswitch在内核中的一个模块，是openvswitch的核心，openvswitch还有两用户态的模块，就是ovs-vswitchd和ovsdb-server,但是datapath似乎是很独立的，只要通过netlink给它配置，就能很好地工作.这个模块网上介绍的不是很多，　也不详细，就很奇怪，今天看完后才明白，代码写得太漂亮了，写文字给别人介绍可能还显得多余，　这里，我也只是作个笔记。　另外的两个用户态模块，　有空了也会分析,完整地理解下openflow在kernel中的实现.

### 几个关键的结构体

#### struct datapath

    struct datapath {
            struct rcu_head rcu;
            struct list_head list_node; //把自己和其它的datapath实例也连接起来

            /* Flow table. */
            struct flow_table table; //action前要查的流表

            /* Switch ports. */
            struct hlist_head *ports; //存放vport的hash

            /* Stats. */
            struct dp_stats_percpu __percpu *stats_percpu;

    #ifdef CONFIG_NET_NS
            /* Network namespace ref. */
            struct net *net;
    #endif

            u32 user_features;
    };

相当于bridge.ko中的net_bridge, 不同要清晰得多.

#### struct vport

    /**
     * struct vport - one port within a datapath
     * @rcu: RCU callback head for deferred destruction.
     * @dp: Datapath to which this port belongs.
     * @upcall_portid: The Netlink port to use for packets received on this port that
     * miss the flow table.
     * @port_no: Index into @dp's @ports array.
     * @hash_node: Element in @dev_table hash table in vport.c.
     * @dp_hash_node: Element in @datapath->ports hash table in datapath.c.
     * @ops: Class structure.
     * @percpu_stats: Points to per-CPU statistics used and maintained by vport
     * @stats_lock: Protects @err_stats;
     * @err_stats: Points to error statistics used and maintained by vport
     */
    struct vport {
            struct rcu_head rcu;
            struct datapath *dp;
            u32 upcall_portid;
            u16 port_no;

            struct hlist_node hash_node;
            struct hlist_node dp_hash_node;
            const struct vport_ops *ops;

            struct pcpu_sw_netstats __percpu *percpu_stats;

            spinlock_t stats_lock;
            struct vport_err_stats err_stats;
    };

    struct vport_parms {
            const char *name;
            enum ovs_vport_type type;
            struct nlattr *options;

            /* For ovs_vport_alloc(). */
            struct datapath *dp;
            u16 port_no;
            u32 upcall_portid;
    };

相当于bridge.ko中的net_bridge_port, 代表一个虚拟端口， 注释上面也有了

#### struct vport_ops

这个端口操作， 对于不同的类型的端口就是不同的实例， 由一个全局一变量来管理:

    static const struct vport_ops *vport_ops_list[] = {
            &ovs_netdev_vport_ops,
            &ovs_internal_vport_ops,

    #ifdef CONFIG_OPENVSWITCH_GRE
            &ovs_gre_vport_ops,
    #endif
    #ifdef CONFIG_OPENVSWITCH_VXLAN
            &ovs_vxlan_vport_ops,
    #endif
    };

#### struct ovs_net

    struct ovs_net {
            struct list_head dps;
            struct work_struct dp_notify_work;
            struct vport_net vport_net;
    };

不用解释，看看每个ns里都有什么全局信息

#### flow_table

    struct table_instance {
            struct flex_array *buckets;
            unsigned int n_buckets;
            struct rcu_head rcu;
            int node_ver;
            u32 hash_seed;
            bool keep_flows;
    };

    struct flow_table {
            struct table_instance __rcu *ti;
            struct list_head mask_list;
            unsigned long last_rehash;
            unsigned int count;
    };

每个datapath对应一个的流表，也就相当于bridge.ko中的net_bridge_fdb_entry.

#### struct sw_flow

    struct sw_flow {
            struct rcu_head rcu;
            struct hlist_node hash_node[2];
            u32 hash;

            struct sw_flow_key key;
            struct sw_flow_key unmasked_key;
            struct sw_flow_mask *mask;
            struct sw_flow_actions __rcu *sf_acts;
            struct sw_flow_stats stats;
    };

转发时用来保存flow信息在skb cb当中

### 初始化

####注册模块

dp_init()中

1. ovs_flow_init()流表初始化, flow_cache, 全局cache流表的创建

2. ovs_vport_init()端口初始化, dev_table, 全局hash表的初始化

3. register_pernet_device(&ovs_net_ops)每名字空间操作注册, ovs_init_net()主要完成对每名字空间变量里dps和dp_notify_work的初始化

4. 通知链注册,内核框架

5. dp_register_genl()：

        for (i = 0; i < ARRAY_SIZE(dp_genl_families); i++) {
                const struct genl_family_and_ops *f = &dp_genl_families[i];

                f->family->ops = f->ops;
                f->family->n_ops = f->n_ops;
                f->family->mcgrps = f->group;
                f->family->n_mcgrps = f->group ? 1 : 0;
                err = genl_register_family(f->family);
                if (err)
                        goto error;
                n_registered++;
        }

    这个函数重要，通过genetic框架注册了datapath, vport, flow, packet四类与用户空间来交互操作的接口:

        static const struct genl_family_and_ops dp_genl_families[] = {
                { &dp_datapath_genl_family,
                  dp_datapath_genl_ops, ARRAY_SIZE(dp_datapath_genl_ops),
                  &ovs_dp_datapath_multicast_group },
                { &dp_vport_genl_family,
                  dp_vport_genl_ops, ARRAY_SIZE(dp_vport_genl_ops),
                  &ovs_dp_vport_multicast_group },
                { &dp_flow_genl_family,
                  dp_flow_genl_ops, ARRAY_SIZE(dp_flow_genl_ops),
                  &ovs_dp_flow_multicast_group },
                { &dp_packet_genl_family,
                  dp_packet_genl_ops, ARRAY_SIZE(dp_packet_genl_ops),
                  NULL },
        };

    具体的见其它genl框架的分析

### 创建

#### datapath

ovs_dp_cmd_new():

        static const struct genl_ops dp_datapath_genl_ops[] = {
                { .cmd = OVS_DP_CMD_NEW,
                  .flags = GENL_ADMIN_PERM, /* Requires CAP_NET_ADMIN privilege. */
                  .policy = datapath_policy,
                  .doit = ovs_dp_cmd_new
                },
                { .cmd = OVS_DP_CMD_DEL,
                  .flags = GENL_ADMIN_PERM, /* Requires CAP_NET_ADMIN privilege. */
                  .policy = datapath_policy,
                  .doit = ovs_dp_cmd_del
                },
                { .cmd = OVS_DP_CMD_GET,
                  .flags = 0,               /* OK for unprivileged users. */
                  .policy = datapath_policy,
                  .doit = ovs_dp_cmd_get,
                  .dumpit = ovs_dp_cmd_dump
                },
                { .cmd = OVS_DP_CMD_SET,
                  .flags = GENL_ADMIN_PERM, /* Requires CAP_NET_ADMIN privilege. */
                  .policy = datapath_policy,
                  .doit = ovs_dp_cmd_set,
                },
        };

1. 申请dp,

2. 在ovs_flow_tbl_init(&dp->table)中申请flow_table

3. 申请dp->ports hash结构

4. 并调用vport = new_vport(&parms);创建一个internal类型的vport, params为struct vport_parms parms类型，用来描述一个vport.

5. 构建一个notify信息， 发出去。

### vport

ovs_vport_cmd_new():

        static const struct genl_ops dp_vport_genl_ops[] = {
                { .cmd = OVS_VPORT_CMD_NEW,
                  .flags = GENL_ADMIN_PERM, /* Requires CAP_NET_ADMIN privilege. */
                  .policy = vport_policy,
                  .doit = ovs_vport_cmd_new
                },
                { .cmd = OVS_VPORT_CMD_DEL,
                  .flags = GENL_ADMIN_PERM, /* Requires CAP_NET_ADMIN privilege. */
                  .policy = vport_policy,
                  .doit = ovs_vport_cmd_del
                },
                { .cmd = OVS_VPORT_CMD_GET,
                  .flags = 0,               /* OK for unprivileged users. */
                  .policy = vport_policy,
                  .doit = ovs_vport_cmd_get,
                  .dumpit = ovs_vport_cmd_dump
                },
                { .cmd = OVS_VPORT_CMD_SET,
                  .flags = GENL_ADMIN_PERM, /* Requires CAP_NET_ADMIN privilege. */
                  .policy = vport_policy,
                  .doit = ovs_vport_cmd_set,
                },
        };

1. 通过dp_ifindex找到dp,然后利用struct params组织vport信息。

2. 通过new_vport创建并添加进dp

3. 调用ovs_vport_add创建, 在这个函数中， 会调用相应的create函数，如vxlan就是vxlan_tnl_create:

        const struct vport_ops ovs_vxlan_vport_ops = {
                .type           = OVS_VPORT_TYPE_VXLAN,
                .create         = vxlan_tnl_create,
                .destroy        = vxlan_tnl_destroy,
                .get_name       = vxlan_get_name,
                .get_options    = vxlan_get_options,
                .send           = vxlan_tnl_send,
        };

    在vxlan_tnl_create中会调用先申请一个vport和vxlan_port， 这两个的关系vxlan_port=net_priv(vport).

4. 然后再申请vs, 调用我们前面分析过的vxlan_sock_add(), 再与vxlan_port关联, vxlan_port->vs = vs;

    可以看出来的是， 这个过程中间，对于vxlan设备来讲没有产生任何net_device，因些ifconfig -a 也就不会看到，有的也只是一个vport, 尽管中间抽取了一些vxlan源接口

5. 最后就是加入到dp中， 并发送notify信息

#### flow_table

ovs_flow_cmd_new_or_set():

        static const struct genl_ops dp_flow_genl_ops[] = {
                { .cmd = OVS_FLOW_CMD_NEW,
                  .flags = GENL_ADMIN_PERM, /* Requires CAP_NET_ADMIN privilege. */
                  .policy = flow_policy,
                  .doit = ovs_flow_cmd_new_or_set
                },
                { .cmd = OVS_FLOW_CMD_DEL,
                  .flags = GENL_ADMIN_PERM, /* Requires CAP_NET_ADMIN privilege. */
                  .policy = flow_policy,
                  .doit = ovs_flow_cmd_del
                },
                { .cmd = OVS_FLOW_CMD_GET,
                  .flags = 0,               /* OK for unprivileged users. */
                  .policy = flow_policy,
                  .doit = ovs_flow_cmd_get,
                  .dumpit = ovs_flow_cmd_dump
                },
                { .cmd = OVS_FLOW_CMD_SET,
                  .flags = GENL_ADMIN_PERM, /* Requires CAP_NET_ADMIN privilege. */
                  .policy = flow_policy,
                  .doit = ovs_flow_cmd_new_or_set,
                },
        };

这个由于与vxlan关系不大，以后再写

### 接收

#### net_dev

1. 从栈议栈中的netif_receive_skb开始吧，这个函数中会调用dev->rx_hander, 如果一个设备被加进了datapath, 那么为!NULL, 当作一个net_dev的设备添加进datapath, 就为netdev_frame_hook

2. 接着获取vport = ovs_netdev_get_vport(skb->dev); 调用netdev_port_receive(), 再调用ovs_vport_receive(),

3. 接着再调用ovs_dp_process_received_packet(), 这个函数才是真正接收到后进行处理的函数

        error = ovs_flow_extract(skb, p->port_no, &key);
        if (unlikely(error)) {
                kfree_skb(skb);
                return;
        }
    
        /* Look up flow. */
        flow = ovs_flow_tbl_lookup_stats(&dp->table, &key, &n_mask_hit);
        if (unlikely(!flow)) {
                struct dp_upcall_info upcall;
    
                upcall.cmd = OVS_PACKET_CMD_MISS;
                upcall.key = &key;
                upcall.userdata = NULL;
                upcall.portid = p->upcall_portid;
                ovs_dp_upcall(dp, skb, &upcall);
                consume_skb(skb);
                stats_counter = &stats->n_missed;
                goto out;
        }
    
        OVS_CB(skb)->flow = flow;
        OVS_CB(skb)->pkt_key = &key;
    
        ovs_flow_stats_update(OVS_CB(skb)->flow, skb);
        ovs_execute_actions(dp, skb);

    拿到流信息，更新进skb中的cb上，再在ovs_execute_actions中执行, 其中ovs_flow_extract是一个重要函数，在它里面对skb进行了解包分析

4. ovs_execute_actions中， 拿到struct sw_flow_actions *acts = rcu_dereference(OVS_CB(skb)->flow->sf_acts);再调用do_execute_actions(), 在这个函数中，进行转发：

        for (a = attr, rem = len; rem > 0;
             a = nla_next(a, &rem)) {
                int err = 0;

                if (prev_port != -1) {
                        do_output(dp, skb_clone(skb, GFP_ATOMIC), prev_port);
                        prev_port = -1;
                }

                switch (nla_type(a)) {
                case OVS_ACTION_ATTR_OUTPUT:
                        prev_port = nla_get_u32(a);
                        break;

    do_output是最终的调用,进入到这个函数中你就看到， 通过port_no查端口，而port_no应该就是在ovs_flow_tbl_lookup_stats()中拿到，还没来得及看， 并且ovs_vport_send发送了。

#### vxlan

你会经常看到在ovs中， 有vport，但没有对应的net_device, 像添加vxlan类型设备时，它的接收自然也就不会靠rx_handler了， 对于vxlan, 很显然，有一个监听着的sock,过来的包自然找得到， 通过以前的分析，知道vxlan sock的从udp来看接收包函数为vxlan_udp_encap_recv, 最终为vs->rcv, 即vxlan_rcv,当然名字相同，但声明了static, 在ovs中另有定义，
1. 在vxlan_rcv中， 会调用ovs_vport_receive(),回到上述的第三步


### 发送

其实就是转发， 接do_output后的ovs_vport_send()

1. vport->ops->send(vport, skb); 又回到了vport_ops, 接口自己实现， vxlan当初注册的是vxlan_tnl_send()

2. 打开这个函数后，你会发现它酷似当年在vxlan.ko中看到的vxlan_rcv,本来嘛，就是接口的抽取，就不要感到奇怪了,不过它直接调用的是vxlan_xmit_skb,所以得做vxlan_xmit_one的工作.

另外不知道有没有发现， 这种模式下vxlan没有fdb的学习接口， 想想为什么？ 想想配置时两者的区别就有了答案

大概看了下， 其它gre与vxlan在vxlan的实现很相似， 所以包括配置也很想像，可谓异曲同工.
