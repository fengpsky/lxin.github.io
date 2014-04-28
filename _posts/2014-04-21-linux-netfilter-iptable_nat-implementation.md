---
layout: post
title: "linux netfilter iptable_nat implementation (nf_conntrack)"
category: linux kernel
excerpt: linux netfilter中nat转发的实现
tags: [kernel]
---
{% include JB/setup %}
linux中nat转发表的实现，也是在xt_table框架之下的，　这个上一篇filter表己经说清楚了,  另外nat 的实现更依赖于另一个框架那就是nf_conntrack, 事实上转发表的规则在xt_table,　但内容却是在nf_conntrack中，　因此对它的分析也是必要的。

##nf_conntrack

###重要的数据结构

####nf_conn

    struct nf_conn {
            /* Usage count in here is 1 for hash table/destruct timer, 1 per skb,
               plus 1 for any connection(s) we are `master' for */
            struct nf_conntrack ct_general;

            spinlock_t lock;

            /* XXX should I move this to the tail ? - Y.K */
            /* These are my tuples; original and reply */
            struct nf_conntrack_tuple_hash tuplehash[IP_CT_DIR_MAX];

            /* Have we seen traffic both ways yet? (bitset) */
            unsigned long status;

            /* If we were expected by an expectation, this will be it */
            struct nf_conn *master;

            /* Timer function; drops refcnt when it goes off. */
            struct timer_list timeout;

    #if defined(CONFIG_NF_CONNTRACK_MARK)
            u_int32_t mark;
    #endif

    #ifdef CONFIG_NF_CONNTRACK_SECMARK
            u_int32_t secmark;
    #endif

            /* Extensions */
            struct nf_ct_ext *ext;
    #ifdef CONFIG_NET_NS
            struct net *ct_net;
    #endif

            /* Storage reserved for other modules, must be the last member */
            union nf_conntrack_proto proto;
    };

描述一个链接， 重要的成员有nf_ct_ext, 用来存储扩展数据， 如nat表; nf_conntrack_proto, 协议私有数据; nf_conntrack_tuple_hash,连接跟踪表，由一个全局变量管理;

#### struct nf_ct_ext/nf_ct_ext_type

    struct nf_ct_ext {
            struct rcu_head rcu;
            u8 offset[NF_CT_EXT_NUM];
            u8 len;
            char data[0];
    };

    struct nf_ct_ext_type {
            /* Destroys relationships (can be NULL). */
            void (*destroy)(struct nf_conn *ct);
            /* Called when realloacted (can be NULL).
               Contents has already been moved. */
            void (*move)(void *new, void *old);

            enum nf_ct_ext_id id;

            unsigned int flags;

            /* Length and min alignment. */
            u8 len;
            u8 align;
            /* initial size of nf_ct_ext. */
            u8 alloc_size;
    };

由于不是固定的格式， 可以进行很灵活的扩展, 是上一个struct的成员;后者为扩展项的类型， 如helper, nat就是一种, 后者由nf_ct_extend_register注册进全局变量nf_ct_ext_types。

#### nf_conntrack_tuple/nf_conntrack_tuple_hash

    /* Connections have two entries in the hash table: one for each way */
    struct nf_conntrack_tuple_hash {
            struct hlist_nulls_node hnnode;
            struct nf_conntrack_tuple tuple;
    };


    struct nf_conntrack_tuple {
            struct nf_conntrack_man src;

            /* These are the parts of the tuple which are fixed. */
            struct {
                    union nf_inet_addr u3;
                    union {
                            /* Add other protocols here. */
                            __be16 all;

                            struct {
                                    __be16 port;
                            } tcp;
                            struct {
                                    __be16 port;
                            } udp;
                            struct {
                                    u_int8_t type, code;
                            } icmp;
                            struct {
                                    __be16 port;
                            } dccp;
                            struct {
                                    __be16 port;
                            } sctp;
                            struct {
                                    __be16 key;
                            } gre;
                    } u;

                    /* The protocol. */
                    u_int8_t protonum;

                    /* The direction (for tuplehash) */
                    u_int8_t dir;
            } dst;
    };

真正用来存放表项的地方。这是一个hash表项, 通常一个nf_conn连接有两项， 表示两个方向,  这个结构即是nf_conn的两个方向的成员， 也是hash表项， 由一个全局hash变量来管理。

#### nf_conntrack_helper

    struct nf_conntrack_helper {
            struct hlist_node hnode;        /* Internal use. */

            char name[NF_CT_HELPER_NAME_LEN]; /* name of the module */
            struct module *me;              /* pointer to self */
            const struct nf_conntrack_expect_policy *expect_policy;

            /* length of internal data, ie. sizeof(struct nf_ct_*_master) */
            size_t data_len;

            /* Tuple of things we will help (compared against server response) */
            struct nf_conntrack_tuple tuple;

            /* Function to call when data passes; return verdict, or -1 to
               invalidate. */
            int (*help)(struct sk_buff *skb,
                        unsigned int protoff,
                        struct nf_conn *ct,
                        enum ip_conntrack_info conntrackinfo);

            void (*destroy)(struct nf_conn *ct);

            int (*from_nlattr)(struct nlattr *attr, struct nf_conn *ct);
            int (*to_nlattr)(struct sk_buff *skb, const struct nf_conn *ct);
            unsigned int expect_class_max;

            unsigned int flags;
            unsigned int queue_num;         /* For user-space helpers. */
    };

功能扩展的模块， 由nf_conntrack_helper_register注册进全局变量nf_ct_helper_hash中。helper自身也形成了一个框架， 对于要扩展处理的协议，只要实现对应的help就可以在nf_conntrack_help中被调到, nf_conntrack_ftp(...etc).c便是。

#### struct nf_conntrack_l4proto

    struct nf_conntrack_l4proto {
            /* L3 Protocol number. */
            u_int16_t l3proto;

            /* L4 Protocol number. */
            u_int8_t l4proto;

            /* Try to fill in the third arg: dataoff is offset past network protocol
               hdr.  Return true if possible. */
            bool (*pkt_to_tuple)(const struct sk_buff *skb, unsigned int dataoff,
                                 struct nf_conntrack_tuple *tuple);

            /* Invert the per-proto part of the tuple: ie. turn xmit into reply.
             * Some packets can't be inverted: return 0 in that case.
             */
            bool (*invert_tuple)(struct nf_conntrack_tuple *inverse,
                                 const struct nf_conntrack_tuple *orig);

            /* Returns verdict for packet, or -1 for invalid. */
            int (*packet)(struct nf_conn *ct,
                          const struct sk_buff *skb,
                          unsigned int dataoff,
                          enum ip_conntrack_info ctinfo,
                          u_int8_t pf,
                          unsigned int hooknum,
                          unsigned int *timeouts);

            /* Called when a new connection for this protocol found;
             * returns TRUE if it's OK.  If so, packet() called next. */
            bool (*new)(struct nf_conn *ct, const struct sk_buff *skb,
                        unsigned int dataoff, unsigned int *timeouts);

            /* Called when a conntrack entry is destroyed */
            void (*destroy)(struct nf_conn *ct);

            int (*error)(struct net *net, struct nf_conn *tmpl, struct sk_buff *skb,
                         unsigned int dataoff, enum ip_conntrack_info *ctinfo,
                         u_int8_t pf, unsigned int hooknum);

            /* Print out the per-protocol part of the tuple. Return like seq_* */
            int (*print_tuple)(struct seq_file *s,
                               const struct nf_conntrack_tuple *);

            /* Print out the private part of the conntrack. */
            int (*print_conntrack)(struct seq_file *s, struct nf_conn *);

            /* Return the array of timeouts for this protocol. */
            unsigned int *(*get_timeouts)(struct net *net);

            /* convert protoinfo to nfnetink attributes */
            int (*to_nlattr)(struct sk_buff *skb, struct nlattr *nla,
                             struct nf_conn *ct);
            /* Calculate protoinfo nlattr size */
            int (*nlattr_size)(void);

            /* convert nfnetlink attributes to protoinfo */
            int (*from_nlattr)(struct nlattr *tb[], struct nf_conn *ct);

            int (*tuple_to_nlattr)(struct sk_buff *skb,
                                   const struct nf_conntrack_tuple *t);
            /* Calculate tuple nlattr size */
            int (*nlattr_tuple_size)(void);
            int (*nlattr_to_tuple)(struct nlattr *tb[],
                                   struct nf_conntrack_tuple *t);
            const struct nla_policy *nla_policy;

            size_t nla_size;

    #if IS_ENABLED(CONFIG_NF_CT_NETLINK_TIMEOUT)
            struct {
                    size_t obj_size;
                    int (*nlattr_to_obj)(struct nlattr *tb[],
                                         struct net *net, void *data);
                    int (*obj_to_nlattr)(struct sk_buff *skb, const void *data);

                    unsigned int nlattr_max;
                    const struct nla_policy *nla_policy;
            } ctnl_timeout;
    #endif
            int     *net_id;
            /* Init l4proto pernet data */
            int (*init_net)(struct net *net, u_int16_t proto);

            /* Return the per-net protocol part. */
            struct nf_proto_net *(*get_net_proto)(struct net *net);

            /* Protocol name */
            const char *name;

            /* Module (if any) which this is connected to. */
            struct module *me;
    };

对四层协议的处理接口, 通过nf_ct_l4proto_register注册进nf_ct_protos[l4proto->l3proto][l4proto->l4proto]

#### struct nf_conntrack_l3proto

    struct nf_conntrack_l3proto {
            /* L3 Protocol Family number. ex) PF_INET */
            u_int16_t l3proto;

            /* Protocol name */
            const char *name;

            /*
             * Try to fill in the third arg: nhoff is offset of l3 proto
             * hdr.  Return true if possible.
             */
            bool (*pkt_to_tuple)(const struct sk_buff *skb, unsigned int nhoff,
                                 struct nf_conntrack_tuple *tuple);

            /*
             * Invert the per-proto part of the tuple: ie. turn xmit into reply.
             * Some packets can't be inverted: return 0 in that case.
             */
            bool (*invert_tuple)(struct nf_conntrack_tuple *inverse,
                                 const struct nf_conntrack_tuple *orig);

            /* Print out the per-protocol part of the tuple. */
            int (*print_tuple)(struct seq_file *s,
                               const struct nf_conntrack_tuple *);

            /*
             * Called before tracking.
             *      *dataoff: offset of protocol header (TCP, UDP,...) in skb
             *      *protonum: protocol number
             */
            int (*get_l4proto)(const struct sk_buff *skb, unsigned int nhoff,
                               unsigned int *dataoff, u_int8_t *protonum);
            int (*tuple_to_nlattr)(struct sk_buff *skb,
                                   const struct nf_conntrack_tuple *t);

            /*
             * Calculate size of tuple nlattr
             */
            int (*nlattr_tuple_size)(void);

            int (*nlattr_to_tuple)(struct nlattr *tb[],
                                   struct nf_conntrack_tuple *t);
            const struct nla_policy *nla_policy;

            size_t nla_size;

    #ifdef CONFIG_SYSCTL
            const char              *ctl_table_path;
    #endif /* CONFIG_SYSCTL */

            /* Init l3proto pernet data */
            int (*init_net)(struct net *net);

            /* Module (if any) which this is connected to. */
            struct module *me;
    };

对三层协议的处理接口, 通过nf_ct_l3proto_register注册进nf_ct_l3protos[proto->l3proto]


####struct nf_conntrack_expect

struct nf_conntrack_expect {
        /* Conntrack expectation list member */
        struct hlist_node lnode;

        /* Hash member */
        struct hlist_node hnode;

        /* We expect this tuple, with the following mask */
        struct nf_conntrack_tuple tuple;
        struct nf_conntrack_tuple_mask mask;

        /* Function to call after setup and insertion */
        void (*expectfn)(struct nf_conn *new,
                         struct nf_conntrack_expect *this);

        /* Helper to assign to new connection */
        struct nf_conntrack_helper *helper;

        /* The conntrack of the master connection */
        struct nf_conn *master;

        /* Timer function; deletes the expectation. */
        struct timer_list timeout;

        /* Usage count. */
        atomic_t use;

        /* Flags */
        unsigned int flags;

        /* Expectation class */
        unsigned int class;

fdef CONFIG_NF_NAT_NEEDED
        union nf_inet_addr saved_addr;
        /* This is the original per-proto part, used to map the
         * expected connection the way the recipient expects. */
        union nf_conntrack_man_proto saved_proto;
        /* Direction relative to the master connection. */
        enum ip_conntrack_dir dir;
#endif

        struct rcu_head rcu;
};

活动协议使用的结构体， 通过netlink, 最终调用nf_ct_expect_insert加入进net->ct.expect_hash中。

##初始化

### nf_conntrack_standalone.ko

1. nf_conntrack_standalone_init 中调用nf_conntrack_init_start完成初始化

2. 在后者中先为nf_conntrack_expect注册cache, ret = nf_conntrack_expect_init();, 再进行各个扩展的初始化：acct_extend/tstamp_extend/event_extend/timeout_extend/helper_extend/acct_extend/nf_ct_seqadj_extend/nf_ct_zone_extend

        ret = nf_conntrack_acct_init();
        if (ret < 0)
                goto err_acct;

        ret = nf_conntrack_tstamp_init();
        if (ret < 0)
                goto err_tstamp;

        ret = nf_conntrack_ecache_init();
        if (ret < 0)
                goto err_ecache;

        ret = nf_conntrack_timeout_init();
        if (ret < 0)
                goto err_timeout;

        ret = nf_conntrack_helper_init();
        if (ret < 0)
                goto err_helper;

        ret = nf_conntrack_labels_init();
        if (ret < 0)
                goto err_labels;

        ret = nf_conntrack_seqadj_init();
        if (ret < 0)
                goto err_seqadj;

        #ifdef CONFIG_NF_CONNTRACK_ZONES
                ret = nf_ct_extend_register(&nf_ct_zone_extend);
                if (ret < 0)
                        goto err_extend;
        #endif

3. 再进行协议初始化nf_conntrack_proto_init ， 主要是指定了一个通用的三层协议处理接口:

        for (i = 0; i < AF_MAX; i++)
                rcu_assign_pointer(nf_ct_l3protos[i],
                                   &nf_conntrack_l3proto_generic);

        struct nf_conntrack_l3proto nf_conntrack_l3proto_generic __read_mostly = {
                .l3proto         = PF_UNSPEC,
                .name            = "unknown",
                .pkt_to_tuple    = generic_pkt_to_tuple,
                .invert_tuple    = generic_invert_tuple,
                .print_tuple     = generic_print_tuple,
                .get_l4proto     = generic_get_l4proto,
        };

4. ret = register_pernet_subsys(&nf_conntrack_net_ops); nf_conntrack_pernet_init中主要调用nf_conntrack_init_net，主要初始化net.ct(netns_ct)中的成员， 大多为hash.

        net->ct.stat = alloc_percpu(struct ip_conntrack_stat);
        net->ct.slabname = kasprintf(GFP_KERNEL, "nf_conntrack_%p", net);
        net->ct.nf_conntrack_cachep = kmem_cache_create(net->ct.slabname,
                                                        sizeof(struct nf_conn), 0,
                                                        SLAB_DESTROY_BY_RCU, NULL);
        net->ct.htable_size = nf_conntrack_htable_size;
        net->ct.hash = nf_ct_alloc_hashtable(&net->ct.htable_size, 1);
        }
        ret = nf_conntrack_expect_pernet_init(net);
        if (ret < 0)
                goto err_expect;
        ret = nf_conntrack_acct_pernet_init(net);
        if (ret < 0)
                goto err_acct;
        ret = nf_conntrack_tstamp_pernet_init(net);
        if (ret < 0)
                goto err_tstamp;
        ret = nf_conntrack_ecache_pernet_init(net);
        if (ret < 0)
                goto err_ecache;
        ret = nf_conntrack_helper_pernet_init(net);
        if (ret < 0)
                goto err_helper;
        ret = nf_conntrack_proto_pernet_init(net);
        if (ret < 0)
                goto err_proto;


下面的是ipv4相关的：

###nf_defrag_ipv4.ko

1. nf_defrag_init中调用nf_register_hooks(ipv4_defrag_ops, ARRAY_SIZE(ipv4_defrag_ops));完成一个hook接口的插入:

        static struct nf_hook_ops ipv4_defrag_ops[] = {
                {
                        .hook           = ipv4_conntrack_defrag,
                        .owner          = THIS_MODULE,
                        .pf             = NFPROTO_IPV4,
                        .hooknum        = NF_INET_PRE_ROUTING,
                        .priority       = NF_IP_PRI_CONNTRACK_DEFRAG,
                },
                {
                        .hook           = ipv4_conntrack_defrag,
                        .owner          = THIS_MODULE,
                        .pf             = NFPROTO_IPV4,
                        .hooknum        = NF_INET_LOCAL_OUT,
                        .priority       = NF_IP_PRI_CONNTRACK_DEFRAG,
                },
        };

###nf_conntrack_l3proto_ipv4.ko

1. 在nf_conntrack_l3proto_ipv4_init中先调用ret = register_pernet_subsys(&ipv4_net_ops); ipv4_net_init中主要完成的是3个l4proto与1个l3proto在pernet的初始化：

        ret = nf_ct_l4proto_pernet_register(net, &nf_conntrack_l4proto_tcp4);
        if (ret < 0) {
                pr_err("nf_conntrack_tcp4: pernet registration failed\n");
                goto out_tcp;
        }
        ret = nf_ct_l4proto_pernet_register(net, &nf_conntrack_l4proto_udp4);
        if (ret < 0) {
                pr_err("nf_conntrack_udp4: pernet registration failed\n");
                goto out_udp;
        }
        ret = nf_ct_l4proto_pernet_register(net, &nf_conntrack_l4proto_icmp);
        if (ret < 0) {
                pr_err("nf_conntrack_icmp4: pernet registration failed\n");
                goto out_icmp;
        }
        ret = nf_ct_l3proto_pernet_register(net, &nf_conntrack_l3proto_ipv4);
        if (ret < 0) {
                pr_err("nf_conntrack_ipv4: pernet registration failed\n");

2. 再调用ret = nf_register_hooks(ipv4_conntrack_ops, ARRAY_SIZE(ipv4_conntrack_ops)); 注册其它三个hook接口：

        static struct nf_hook_ops ipv4_conntrack_ops[] __read_mostly = {
                {
                        .hook           = ipv4_conntrack_in,
                        .owner          = THIS_MODULE,
                        .pf             = NFPROTO_IPV4,
                        .hooknum        = NF_INET_PRE_ROUTING,
                        .priority       = NF_IP_PRI_CONNTRACK,
                },
                {
                        .hook           = ipv4_conntrack_local,
                        .owner          = THIS_MODULE,
                        .pf             = NFPROTO_IPV4,
                        .hooknum        = NF_INET_LOCAL_OUT,
                        .priority       = NF_IP_PRI_CONNTRACK,
                },
                {
                        .hook           = ipv4_helper,
                        .owner          = THIS_MODULE,
                        .pf             = NFPROTO_IPV4,
                        .hooknum        = NF_INET_POST_ROUTING,
                        .priority       = NF_IP_PRI_CONNTRACK_HELPER,
                },
                {
                        .hook           = ipv4_confirm,
                        .owner          = THIS_MODULE,
                        .pf             = NFPROTO_IPV4,
                        .hooknum        = NF_INET_POST_ROUTING,
                        .priority       = NF_IP_PRI_CONNTRACK_CONFIRM,
                },
                {
                        .hook           = ipv4_helper,
                        .owner          = THIS_MODULE,
                        .pf             = NFPROTO_IPV4,
                        .hooknum        = NF_INET_LOCAL_IN,
                        .priority       = NF_IP_PRI_CONNTRACK_HELPER,
                },
                {
                        .hook           = ipv4_confirm,
                        .owner          = THIS_MODULE,
                        .pf             = NFPROTO_IPV4,
                        .hooknum        = NF_INET_LOCAL_IN,
                        .priority       = NF_IP_PRI_CONNTRACK_CONFIRM,
                },
        };

4. 最后再相应地注册上面提到的3个4层， 1 个3层的协议：

        ret = nf_ct_l4proto_register(&nf_conntrack_l4proto_tcp4);
        if (ret < 0) {
                pr_err("nf_conntrack_ipv4: can't register tcp4 proto.\n");
                goto cleanup_hooks;
        }

        ret = nf_ct_l4proto_register(&nf_conntrack_l4proto_udp4);
        if (ret < 0) {
                pr_err("nf_conntrack_ipv4: can't register udp4 proto.\n");
                goto cleanup_tcp4;
        }

        ret = nf_ct_l4proto_register(&nf_conntrack_l4proto_icmp);
        if (ret < 0) {
                pr_err("nf_conntrack_ipv4: can't register icmpv4 proto.\n");
                goto cleanup_udp4;
        }

        ret = nf_ct_l3proto_register(&nf_conntrack_l3proto_ipv4);
        if (ret < 0) {
                pr_err("nf_conntrack_ipv4: can't register ipv4 proto.\n");
                goto cleanup_icmpv4;
        }

ps,其它几个协议模块则是以模块形式注册进来的：nf_conntrack_proto_gre.cnf_conntrack_proto_dccp.c,nf_conntrack_proto_sctp.c,nf_conntrack_proto_udplite.c

##包处理

### ipv4_conntrack_defrag

1. 这个函数， 首先调用ip_is_fragment(ip_hdr(skb)， 判断进入的数据包是否是分片， 如果不是， 则直接返回， 如果是， 则调用nf_ct_ipv4_gather_frags进一步处理

2. nf_ct_ipv4_gather_frags这个函数并没有做别的， 只是直接调用ip_defrag对ip分片进行聚合。

### ipv4_conntrack_in

1. 首先检测是否己经经过检测，并且已经形成模板, 如果是证明己经存在对应的nf_conn,就不用再添加了。如果没有， 则须继续。

        if (skb->nfct) {
                /* Previously seen (loopback or untracked)?  Ignore. */
                tmpl = (struct nf_conn *)skb->nfct;
                if (!nf_ct_is_template(tmpl)) {
                        NF_CT_STAT_INC_ATOMIC(net, ignore);
                        return NF_ACCEPT;
                }
                skb->nfct = NULL;
        }

2. 接下来查找对应的l3proto， 并获取四层协议的协议号protonum与数据偏移dataoff

        l3proto = __nf_ct_l3proto_find(pf);
        ret = l3proto->get_l4proto(skb, skb_network_offset(skb),
                                   &dataoff, &protonum);

3. 查找对应的四层协议, 并通过error()对其进行检测

        l4proto = __nf_ct_l4proto_find(pf, protonum);

        /* It may be an special packet, error, unclean...
         * inverse of the return code tells to the netfilter
         * core what to do with the packet. */
        if (l4proto->error != NULL) {
                ret = l4proto->error(net, tmpl, skb, dataoff, &ctinfo,
                                     pf, hooknum);
                if (ret <= 0) {
                        NF_CT_STAT_INC_ATOMIC(net, error);
                        NF_CT_STAT_INC_ATOMIC(net, invalid);
                        ret = -ret;
                        goto out;
                }
                /* ICMP[v6] protocol trackers may assign one conntrack. */
                if (skb->nfct)
                        goto out;
        }

4. 接下来是最重要的一步,查看是否存在这个链接，如果没有，则创建。resolve_normal_ct中完成

        ct = resolve_normal_ct(net, tmpl, skb, dataoff, pf, protonum,
                               l3proto, l4proto, &set_reply, &ctinfo);

5. timeouts = nf_ct_timeout_lookup(net, ct, l4proto);时间策略， 这是之前nf_ext注册过的，如果没有就会使用l4proto->get_timeouts(net);获取。

6. ret = l4proto->packet(ct, skb, dataoff, ctinfo, pf, hooknum, timeouts); 最后通过这个接口更新状态, 如udp_packet, 会通过__nf_ct_refresh_acct 更新timeout和accounting信息， acct扩展之前也己注册过。

7. 接下来，对 resolve_normal_ct接口进一步分析, 首先将传进来的信息转化成tuple:

        if (!nf_ct_get_tuple(skb, skb_network_offset(skb),
                             dataoff, l3num, protonum, &tuple, l3proto,
                             l4proto)) {
                pr_debug("resolve_normal_ct: Can't get tuple\n");
                return NULL;
        }

    转化的方式是其实就是调用l3/4proto->pkt_to_tuple()

8. 再拿到这个tuple的hash， 并在全局表net->ct.hash[bucket]中进行查找, 查找过程最終调用__nf_conntrack_find_get：

        hash = hash_conntrack_raw(&tuple, zone);
        h = __nf_conntrack_find_get(net, zone, &tuple, hash);
        if (!h) {
                h = init_conntrack(net, tmpl, &tuple, l3proto, l4proto,
                                   skb, dataoff, hash);
                if (!h)
                        return NULL;
                if (IS_ERR(h))
                        return (void *)h;
        }

    如果没有找到， 就会调用init_conntrack重新创建, 这个接口中，做了很多事， 像之前注册的扩展都会被调用到， 也会调用l4proto->new(ct, skb, dataoff, timeouts); 对于expect的处理也在这里,注这里还没有把这个连接加进hash, 只是加进unconfirm中：

        /* Overload tuple linked list to put us in unconfirmed list. */
        hlist_nulls_add_head_rcu(&ct->tuplehash[IP_CT_DIR_ORIGINAL].hnnode,
                       &net->ct.unconfirmed);


9.  ct = nf_ct_tuplehash_to_ctrack(h); 将tuple转成nf_conn, 再拿到ctinfo, 最后：

        skb->nfct = &ct->ct_general;
        skb->nfctinfo = *ctinfo;


### ipv4_helper

这个函数很简单， 拿到ct 和ctinfo, 找到其help,   再调用对应的helper。 可见help 的添加是在创建nf_conn时，调用则是在这里:

        ct = nf_ct_get(skb, &ctinfo);
        if (!ct || ctinfo == IP_CT_RELATED_REPLY)
                return NF_ACCEPT;

        help = nfct_help(ct);
        if (!help)
                return NF_ACCEPT;

        /* rcu_read_lock()ed by nf_hook_slow */
        helper = rcu_dereference(help->helper);
        if (!helper)
                return NF_ACCEPT;

        return helper->help(skb, skb_network_offset(skb) + ip_hdrlen(skb),
                            ct, ctinfo);


### ipv4_confirm

1. 基本的判断完后， 再调用nf_conntrack_confirm完成确认

2. 首先判断是否这个ct要被tracked,如果不是， 则直接return,

        if (ct && !nf_ct_is_untracked(ct)) {
                if (!nf_ct_is_confirmed(ct))
                        ret = __nf_conntrack_confirm(skb);
                if (likely(ret == NF_ACCEPT))
                        nf_ct_deliver_cached_events(ct);
        }
        return ret;

    否则再次判断是否已经被confirm, 如果没有， 则调用__nf_conntrack_confirm进行confirm, 最后会调用nf_ct_deliver_cached_events应该是对cached_event的处理。

3. __nf_conntrack_confirm中,代码很清晰， 拿到ct的hash与repl_hash, 并确认不在net->ct.hash中， 再删掉unconfirmed 中的hash项。 最后再更新ct的时间及状态，再insert进全局hash中：

        ct->timeout.expires += jiffies;
        add_timer(&ct->timeout);
        atomic_inc(&ct->ct_general.use);
        ct->status |= IPS_CONFIRMED;

        /* set conntrack timestamp, if enabled. */
        tstamp = nf_conn_tstamp_find(ct);
        if (tstamp) {
                if (skb->tstamp.tv64 == 0)
                        __net_timestamp(skb);

                tstamp->start = ktime_to_ns(skb->tstamp);
        }
        /* Since the lookup is lockless, hash insertion must be done after
         * starting the timer and setting the CONFIRMED bit. The RCU barriers
         * guarantee that no other CPU can find the conntrack before the above
         * stores are visible.
         */
        __nf_conntrack_hash_insert(ct, hash, repl_hash);


4. 最后再做cached_event的一些处理:

        help = nfct_help(ct);
        if (help && help->helper)
                nf_conntrack_event_cache(IPCT_HELPER, ct);

        nf_conntrack_event_cache(master_ct(ct) ?
                                 IPCT_RELATED : IPCT_NEW, ct);

另外对于hook点的对照图， 可查看这里：http://cupic.img168.net/bbsfile/forum/linux/month_0901/20090110_7c2dd7b0a74df49848aaR9Rih4DcMtPH.jpg
    对于包处理的流程图， 可参考这里：http://cupic.img168.net/bbsfile/forum/linux/month_0901/20090110_9bdaab8787c27bdadd47a1AiNjiN8ANg.jpg


##iptable_nat

###重要的结构体

#### nf_conn_nat

    struct nf_conn_nat {
            struct hlist_node bysource;
            struct nf_conn *ct;
            union nf_conntrack_nat_help help;
    #if defined(CONFIG_IP_NF_TARGET_MASQUERADE) || \
        defined(CONFIG_IP_NF_TARGET_MASQUERADE_MODULE) || \
        defined(CONFIG_IP6_NF_TARGET_MASQUERADE) || \
        defined(CONFIG_IP6_NF_TARGET_MASQUERADE_MODULE)
            int masq_index;
    #endif
    };

这个结构体嵌入在nf_conn中, 实际是在上面分析的nf_ct_ext的data中存放。

#### struct nf_nat_l3proto

    struct nf_nat_l3proto {
            u8      l3proto;

            bool    (*in_range)(const struct nf_conntrack_tuple *t,
                                const struct nf_nat_range *range);

            u32     (*secure_port)(const struct nf_conntrack_tuple *t, __be16);

            bool    (*manip_pkt)(struct sk_buff *skb,
                                 unsigned int iphdroff,
                                 const struct nf_nat_l4proto *l4proto,
                                 const struct nf_conntrack_tuple *target,
                                 enum nf_nat_manip_type maniptype);

            void    (*csum_update)(struct sk_buff *skb, unsigned int iphdroff,
                                   __sum16 *check,
                                   const struct nf_conntrack_tuple *t,
                                   enum nf_nat_manip_type maniptype);

            void    (*csum_recalc)(struct sk_buff *skb, u8 proto,
                                   void *data, __sum16 *check,
                                   int datalen, int oldlen);

            void    (*decode_session)(struct sk_buff *skb,
                                      const struct nf_conn *ct,
                                      enum ip_conntrack_dir dir,
                                      unsigned long statusbit,
                                      struct flowi *fl);

            int     (*nlattr_to_range)(struct nlattr *tb[],
                                       struct nf_nat_range *range);
    };

nat框架中的l3proto


#### struct nf_nat_l4proto

    struct nf_nat_l4proto {
            /* Protocol number. */
            u8 l4proto;

            /* Translate a packet to the target according to manip type.
             * Return true if succeeded.
             */
            bool (*manip_pkt)(struct sk_buff *skb,
                              const struct nf_nat_l3proto *l3proto,
                              unsigned int iphdroff, unsigned int hdroff,
                              const struct nf_conntrack_tuple *tuple,
                              enum nf_nat_manip_type maniptype);

            /* Is the manipable part of the tuple between min and max incl? */
            bool (*in_range)(const struct nf_conntrack_tuple *tuple,
                             enum nf_nat_manip_type maniptype,
                             const union nf_conntrack_man_proto *min,
                             const union nf_conntrack_man_proto *max);

            /* Alter the per-proto part of the tuple (depending on
             * maniptype), to give a unique tuple in the given range if
             * possible.  Per-protocol part of tuple is initialized to the
             * incoming packet.
             */
            void (*unique_tuple)(const struct nf_nat_l3proto *l3proto,
                                 struct nf_conntrack_tuple *tuple,
                                 const struct nf_nat_range *range,
                                 enum nf_nat_manip_type maniptype,
                                 const struct nf_conn *ct);

            int (*nlattr_to_range)(struct nlattr *tb[],
                                   struct nf_nat_range *range);
    };

nat框架中的l4proto


###初始化

####iptable_nat.ko

1. err = register_pernet_subsys(&iptable_nat_net_ops); iptable_nat_net_init与iptable_filter_net_init过程相同:

        static const struct xt_table nf_nat_ipv4_table = {
                .name           = "nat",
                .valid_hooks    = (1 << NF_INET_PRE_ROUTING) |
                                  (1 << NF_INET_POST_ROUTING) |
                                  (1 << NF_INET_LOCAL_OUT) |
                                  (1 << NF_INET_LOCAL_IN),
                .me             = THIS_MODULE,
                .af             = NFPROTO_IPV4,
        };

2. err = nf_register_hooks(nf_nat_ipv4_ops, ARRAY_SIZE(nf_nat_ipv4_ops)); 注册hook 点：

        static struct nf_hook_ops nf_nat_ipv4_ops[] __read_mostly = {
                /* Before packet filtering, change destination */
                {
                        .hook           = nf_nat_ipv4_in,
                        .owner          = THIS_MODULE,
                        .pf             = NFPROTO_IPV4,
                        .hooknum        = NF_INET_PRE_ROUTING,
                        .priority       = NF_IP_PRI_NAT_DST,
                },
                /* After packet filtering, change source */
                {
                        .hook           = nf_nat_ipv4_out,
                        .owner          = THIS_MODULE,
                        .pf             = NFPROTO_IPV4,
                        .hooknum        = NF_INET_POST_ROUTING,
                        .priority       = NF_IP_PRI_NAT_SRC,
                },
                /* Before packet filtering, change destination */
                {
                        .hook           = nf_nat_ipv4_local_fn,
                        .owner          = THIS_MODULE,
                        .pf             = NFPROTO_IPV4,
                        .hooknum        = NF_INET_LOCAL_OUT,
                        .priority       = NF_IP_PRI_NAT_DST,
                },
                /* After packet filtering, change source */
                {
                        .hook           = nf_nat_ipv4_fn,
                        .owner          = THIS_MODULE,
                        .pf             = NFPROTO_IPV4,
                        .hooknum        = NF_INET_LOCAL_IN,
                        .priority       = NF_IP_PRI_NAT_SRC,
                },
        };

####xt_nat.ko

1. xt_nat_init中注册xt_nat_target_reg target:

        static struct xt_target xt_nat_target_reg[] __read_mostly = {
                {
                        .name           = "SNAT",
                        .revision       = 0,
                        .checkentry     = xt_nat_checkentry_v0,
                        .target         = xt_snat_target_v0,
                        .targetsize     = sizeof(struct nf_nat_ipv4_multi_range_compat),
                        .family         = NFPROTO_IPV4,
                        .table          = "nat",
                        .hooks          = (1 << NF_INET_POST_ROUTING) |
                                          (1 << NF_INET_LOCAL_IN),
                        .me             = THIS_MODULE,
                },
                {
                        .name           = "DNAT",
                        .revision       = 0,
                        .checkentry     = xt_nat_checkentry_v0,
                        .target         = xt_dnat_target_v0,
                        .targetsize     = sizeof(struct nf_nat_ipv4_multi_range_compat),
                        .family         = NFPROTO_IPV4,
                        .table          = "nat",
                        .hooks          = (1 << NF_INET_PRE_ROUTING) |
                                          (1 << NF_INET_LOCAL_OUT),
                        .me             = THIS_MODULE,
                },
                {
                        .name           = "SNAT",
                        .revision       = 1,
                        .target         = xt_snat_target_v1,
                        .targetsize     = sizeof(struct nf_nat_range),
                        .table          = "nat",
                        .hooks          = (1 << NF_INET_POST_ROUTING) |
                                          (1 << NF_INET_LOCAL_IN),
                        .me             = THIS_MODULE,
                },
                {
                        .name           = "DNAT",
                        .revision       = 1,
                        .target         = xt_dnat_target_v1,
                        .targetsize     = sizeof(struct nf_nat_range),
                        .table          = "nat",
                        .hooks          = (1 << NF_INET_PRE_ROUTING) |
                                          (1 << NF_INET_LOCAL_OUT),
                        .me             = THIS_MODULE,
                },
        };

####nf_nat_core.ko

1. nf_nat_init中， ret = nf_ct_extend_register(&nat_extend); 首先注册nf_ct_ext:

        static struct nf_ct_ext_type nat_extend __read_mostly = {
                .len            = sizeof(struct nf_conn_nat),
                .align          = __alignof__(struct nf_conn_nat),
                .destroy        = nf_nat_cleanup_conntrack,
                .move           = nf_nat_move_storage,
                .id             = NF_CT_EXT_NAT,
                .flags          = NF_CT_EXT_F_PREALLOC,
        };

2. ret = register_pernet_subsys(&nf_nat_net_ops); nf_nat_net_init中， 申请hash:

        /* Leave them the same for the moment. */
        net->ct.nat_htable_size = net->ct.htable_size;
        net->ct.nat_bysource = nf_ct_alloc_hashtable(&net->ct.nat_htable_size, 0);

3. nf_ct_helper_expectfn_register(&follow_master_nat); 将follow_master_nat注册进全局变量nf_ct_helper_expectfn_list

        static struct nf_ct_helper_expectfn follow_master_nat = {
                .name           = "nat-follow-master",
                .expectfn       = nf_nat_follow_master,
        };

    这是helper框架

4. 设置初始状态， 设置一个全局变量，为netlink用。

        /* Initialize fake conntrack so that NAT will skip it */
        nf_ct_untracked_status_or(IPS_NAT_DONE_MASK);

        BUG_ON(nfnetlink_parse_nat_setup_hook != NULL);
        RCU_INIT_POINTER(nfnetlink_parse_nat_setup_hook,
                           nfnetlink_parse_nat_setup);


####nf_nat_l3proto_ipv4.ko

1. err = nf_nat_l4proto_register(NFPROTO_IPV4, &nf_nat_l4proto_icmp); 注册一个四层nat协议nf_nat_l4proto_icmp到全局变量nf_nat_l4protos[l3proto][l4proto->l4proto].

        const struct nf_nat_l4proto nf_nat_l4proto_icmp = {
                .l4proto                = IPPROTO_ICMP,
                .manip_pkt              = icmp_manip_pkt,
                .in_range               = icmp_in_range,
                .unique_tuple           = icmp_unique_tuple,
        #if defined(CONFIG_NF_CT_NETLINK) || defined(CONFIG_NF_CT_NETLINK_MODULE)
                .nlattr_to_range        = nf_nat_l4proto_nlattr_to_range,
        #endif
        };


2. err = nf_nat_l3proto_register(&nf_nat_l3proto_ipv4); 注册一个三层nat协议nf_nat_l3proto_ipv4到全局变量nf_nat_l3protos[l3proto->l3proto]

        static const struct nf_nat_l3proto nf_nat_l3proto_ipv4 = {
                .l3proto                = NFPROTO_IPV4,
                .in_range               = nf_nat_ipv4_in_range,
                .secure_port            = nf_nat_ipv4_secure_port,
                .manip_pkt              = nf_nat_ipv4_manip_pkt,
                .csum_update            = nf_nat_ipv4_csum_update,
                .csum_recalc            = nf_nat_ipv4_csum_recalc,
                .nlattr_to_range        = nf_nat_ipv4_nlattr_to_range,
        #ifdef CONFIG_XFRM
                .decode_session         = nf_nat_ipv4_decode_session,
        #endif
        };

另外nf_nat_proto_udp/tcp也都以同样的形式加载, 当然也有其它协议

        const struct nf_nat_l4proto nf_nat_l4proto_udp = {
                .l4proto                = IPPROTO_UDP,
                .manip_pkt              = udp_manip_pkt,
                .in_range               = nf_nat_l4proto_in_range,
                .unique_tuple           = udp_unique_tuple,
        #if defined(CONFIG_NF_CT_NETLINK) || defined(CONFIG_NF_CT_NETLINK_MODULE)
                .nlattr_to_range        = nf_nat_l4proto_nlattr_to_range,
        #endif
        };

        const struct nf_nat_l4proto nf_nat_l4proto_tcp = {
                .l4proto                = IPPROTO_TCP,
                .manip_pkt              = tcp_manip_pkt,
                .in_range               = nf_nat_l4proto_in_range,
                .unique_tuple           = tcp_unique_tuple,
        #if defined(CONFIG_NF_CT_NETLINK) || defined(CONFIG_NF_CT_NETLINK_MODULE)
                .nlattr_to_range        = nf_nat_l4proto_nlattr_to_range,
        #endif
        };


###创建

iptable_nat的实现基于xt_table框架， 因此创建与iptable_filter相同， 己经说过， 因些不再分析


###包处理

基本都是调用nf_nat_ipv4_fn完成的

1. enum nf_nat_manip_type maniptype = HOOK2MANIP(ops->hooknum);获取转换后的maniptype, 这个用于下面判断这个ct是否已经经过nat的初始化。

2. 从skb 中拿到enum ip_conntrack_info *ctinfo与(struct nf_conn *)skb->nfct，　如果连接为空，则说明没有被track。

        ct = nf_ct_get(skb, &ctinfo);
        /* Can't track?  It's not due to stress, or conntrack would
         * have dropped it.  Hence it's the user's responsibilty to
         * packet filter it out, or implement conntrack/NAT for that
         * protocol. 8) --RR
         */
        if (!ct)
                return NF_ACCEPT;

        if (nf_ct_is_untracked(ct))
                return NF_ACCEPT;

    或者被标为为untracked,也不再往下执行

3. 从ct 中拿到nat信息，　已经说过这是以ext形式存在在nfct中，　如果为空，则说明还被add进去，　则调用nf_ct_ext_add为其分配空间，注意这里不填充数据，而是在下面。

        nat = nfct_nat(ct);
        if (!nat) {
                /* NAT module was loaded late. */
                if (nf_ct_is_confirmed(ct))
                        return NF_ACCEPT;
                nat = nf_ct_ext_add(ct, NF_CT_EXT_NAT, GFP_ATOMIC);
                if (nat == NULL) {
                        pr_debug("failed to add NAT extension\n");
                        return NF_ACCEPT;
                }
        }

4. 我们重点关注这个状态，因为它代表着这个状态，还没有进入nf跟踪表，此时首先判断是否已经nat初始化过，判断方法就是查看ct->status & IPS_SRC_NAT/SNAT_DONE，　因为它的改变就是在nf_nat_rule_find中调用nat_setup_info完成的，　如果没有初始化则调用nf_nat_rule_find, 这个函数都再熟悉不过了，　在filter那节已经说过，　最终会通过一个target来完成，这便是上面说过的xt_nat_target_reg,它里面的target()会调用xt_s/dnat_target_v0/1->nf_nat_setup_info()完成上面nat ext扩展的信息填充。

        switch (ctinfo) {
        ...
        case IP_CT_NEW:
                /* Seen it before?  This can happen for loopback, retrans,
                 * or local packets.
                 */
                if (!nf_nat_initialized(ct, maniptype)) {
                        unsigned int ret;

                        ret = nf_nat_rule_find(skb, ops->hooknum, in, out, ct);
                        if (ret != NF_ACCEPT)
                                return ret;
                } else {
                        pr_debug("Already setup manip %s for ct %p\n",
                                 maniptype == NF_NAT_MANIP_SRC ? "SRC" : "DST",
                                 ct);
                        if (nf_nat_oif_changed(ops->hooknum, ctinfo, nat, out))
                                goto oif_changed;
                }
                break;
        ...
        }

5. nf_nat_rule_find中最终会调用target里的接口，以SNAT为例，　xt_snat_target_v0中，　xt_nat_convert_range(&range, &mr->range[0]);拿到ip/port range信息，调用xt_nat_convert_range(&range, &mr->range[0]);

    从REPLY方向拿到invert，第一次会是orgin方向的tuple，　这是为了获取tuple改变之前的tuple,因为经过这个接口后，orgin方向已经改变, 而对于下面的操作需要的是未改变包的内容

        nf_ct_invert_tuplepr(&curr_tuple,
                             &ct->tuplehash[IP_CT_DIR_REPLY].tuple);

   很重要的一个函数，主要是确保new_tuple的唯一性

        get_unique_tuple(&new_tuple, &curr_tuple, range, ct, maniptype);

   上面的函数通常会将转发信息填充至new_tuple，　&new_tuple, &curr_tuple不相等，　则导致nf_conntrack_alter_reply(ct, &reply)，　ct->tuplehash[IP_CT_DIR_REPLY].tuple = *newreply;这是一个比较绕的设计，这样做不会导致ORGIN的改变，但同样存储了转发信息：

        if (!nf_ct_tuple_equal(&new_tuple, &curr_tuple)) {
                struct nf_conntrack_tuple reply;

                /* Alter conntrack table so will recognize replies. */
                nf_ct_invert_tuplepr(&reply, &new_tuple);
                nf_conntrack_alter_reply(ct, &reply);

                /* Non-atomic: we own this at the moment. */
                if (maniptype == NF_NAT_MANIP_SRC)
                        ct->status |= IPS_SRC_NAT;
                else
                        ct->status |= IPS_DST_NAT;

                if (nfct_help(ct))
                        nfct_seqadj_ext_add(ct);
        }

    将自身添加到net->ct.nat_bysource hash 中：

        if (maniptype == NF_NAT_MANIP_SRC) {
                unsigned int srchash;

                srchash = hash_by_src(net, nf_ct_zone(ct),
                                      &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple);
                spin_lock_bh(&nf_nat_lock);
                /* nf_conntrack_alter_reply might re-allocate extension aera */
                nat = nfct_nat(ct);
                nat->ct = ct;
                hlist_add_head_rcu(&nat->bysource,
                                   &net->ct.nat_bysource[srchash]);
                spin_unlock_bh(&nf_nat_lock);
        }

    设备己done信息：

        if (maniptype == NF_NAT_MANIP_DST)
                ct->status |= IPS_DST_NAT_DONE;
        else
                ct->status |= IPS_SRC_NAT_DONE;

6. get_unique_tuple中，如果在range内，　并且没有被使用，　则new_tuple=orig_tuple, 返回。如果不在range,　则会进行udp hole处理，不作介绍

        if (maniptype == NF_NAT_MANIP_SRC &&
            !(range->flags & NF_NAT_RANGE_PROTO_RANDOM_ALL)) {
                /* try the original tuple first */
                if (in_range(l3proto, l4proto, orig_tuple, range)) {
                        if (!nf_nat_used_tuple(orig_tuple, ct)) {
                                *tuple = *orig_tuple;
                                goto out;
                        }
                } else if (find_appropriate_src(net, zone, l3proto, l4proto,
                                                orig_tuple, tuple, range)) {
                        pr_debug("get_unique_tuple: Found current src map\n");
                        if (!nf_nat_used_tuple(tuple, ct))
                                goto out;
                }
        }

    如果以上失败，即不在range内，　则仍会new_tuple=orgin_tuple, 但会重新获取ip和端口:

        *tuple = *orig_tuple;
        find_best_ips_proto(zone, tuple, range, ct, maniptype);

        /* 3) The per-protocol part of the manip is made to map into
         * the range to make a unique tuple.
         */

        /* Only bother mapping if it's not already in range and unique */
        if (!(range->flags & NF_NAT_RANGE_PROTO_RANDOM_ALL)) {
                if (range->flags & NF_NAT_RANGE_PROTO_SPECIFIED) {
                        if (l4proto->in_range(tuple, maniptype,
                                              &range->min_proto,
                                              &range->max_proto) &&
                            (range->min_proto.all == range->max_proto.all ||
                             !nf_nat_used_tuple(tuple, ct)))
                                goto out;
                } else if (!nf_nat_used_tuple(tuple, ct)) {
                        goto out;
                }
        }

        /* Last change: get protocol to try to obtain unique tuple. */
        l4proto->unique_tuple(l3proto, tuple, range, maniptype, ct);

    l4proto->unique_tuple找端口，　find_best_ips_proto找ip, 根据以下选项:

        #define NF_NAT_RANGE_MAP_IPS                    (1 << 0)
        #define NF_NAT_RANGE_PROTO_SPECIFIED            (1 << 1)
        #define NF_NAT_RANGE_PROTO_RANDOM               (1 << 2)
        #define NF_NAT_RANGE_PERSISTENT                 (1 << 3)
        #define NF_NAT_RANGE_PROTO_RANDOM_FULLY         (1 << 4)

7. 最后就是封包发送的处理 nf_nat_packet(),

                struct nf_conntrack_tuple target;

                /* We are aiming to look like inverse of other direction. */
                nf_ct_invert_tuplepr(&target, &ct->tuplehash[!dir].tuple);

                l3proto = __nf_nat_l3proto_find(target.src.l3num);
                l4proto = __nf_nat_l4proto_find(target.src.l3num,
                                                target.dst.protonum);
                if (!l3proto->manip_pkt(skb, 0, l4proto, &target, mtype))
                        return NF_DROP;

    分别找到l3proto, 与l4proto, 再调用l3proto->manip_pkt, ip 对应的就是nf_nat_ipv4_manip_pkt, 在这个接口里，　先调用l4proto->manip_pkt, udp的话用来改变port/csum,　再修改ip/csum, 最后完成后返回，　调用完成。

    到这里就完成了包的修改。snat的处理完成，　对于reply, 则就是要修改dst, 代码逻辑相似。
