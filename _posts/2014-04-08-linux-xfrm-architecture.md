---
layout: post
title: "linux xfrm框架"
category: linux kernel
excerpt: "linux kernel 自身ipsec的实现"
tags: "kernel"
---
{% include JB/setup %}

linux 下vpn的实现有好多种，大的分就是在用户态实现的和内核态的，而后者中的一类， 是inux内核自带的， 就是xfrm框架，xfrm本身就是一个存储数据的数据库， 里面有两个重要的'表'，SP(policy)和SA(state), 并且对外提供了，增删改查等操作。并且对于一些要存储的数据可自行进行定义扩展。

##重要数据结构

###xfrm_policy

    struct xfrm_policy {
    #ifdef CONFIG_NET_NS
            struct net              *xp_net;
    #endif
            struct hlist_node       bydst;
            struct hlist_node       byidx;

            /* This lock only affects elements except for entry. */
            rwlock_t                lock;
            atomic_t                refcnt;
            struct timer_list       timer;

            struct flow_cache_object flo;
            atomic_t                genid;
            u32                     priority;
            u32                     index;
            struct xfrm_mark        mark;
            struct xfrm_selector    selector;
            struct xfrm_lifetime_cfg lft;
            struct xfrm_lifetime_cur curlft;
            struct xfrm_policy_walk_entry walk;
            struct xfrm_policy_queue polq;
            u8                      type;
            u8                      action;
            u8                      flags;
            u8                      xfrm_nr;
            u16                     family;
            struct xfrm_sec_ctx     *security;
            struct xfrm_tmpl        xfrm_vec[XFRM_MAX_DEPTH];
    };

描述定义的策略,除在全局hash/list中外，　还有可能在sock中，　属于struct sock

###xfrm_state

    struct xfrm_state {
    #ifdef CONFIG_NET_NS
            struct net              *xs_net;
    #endif
            union {
                    struct hlist_node       gclist;
                    struct hlist_node       bydst;
            };
            struct hlist_node       bysrc;
            struct hlist_node       byspi;

            atomic_t                refcnt;
            spinlock_t              lock;

            struct xfrm_id          id;
            struct xfrm_selector    sel;
            struct xfrm_mark        mark;
            u32                     tfcpad;

            u32                     genid;

            /* Key manager bits */
            struct xfrm_state_walk  km;

            /* Parameters of this state. */
            struct {
                    u32             reqid;
                    u8              mode;
                    u8              replay_window;
                    u8              aalgo, ealgo, calgo;
                    u8              flags;
                    u16             family;
                    xfrm_address_t  saddr;
                    int             header_len;
                    int             trailer_len;
                    u32             extra_flags;
            } props;

            struct xfrm_lifetime_cfg lft;

            /* Data for transformer */
            struct xfrm_algo_auth   *aalg;
            struct xfrm_algo        *ealg;
            struct xfrm_algo        *calg;
            struct xfrm_algo_aead   *aead;

            /* Data for encapsulator */
            struct xfrm_encap_tmpl  *encap;

            /* Data for care-of address */
            xfrm_address_t  *coaddr;
            /* IPComp needs an IPIP tunnel for handling uncompressed packets */
            struct xfrm_state       *tunnel;

            /* If a tunnel, number of users + 1 */
            atomic_t                tunnel_users;

            /* State for replay detection */
            struct xfrm_replay_state replay;
            struct xfrm_replay_state_esn *replay_esn;

            /* Replay detection state at the time we sent the last notification */
            struct xfrm_replay_state preplay;
            struct xfrm_replay_state_esn *preplay_esn;

            /* The functions for replay detection. */
            struct xfrm_replay      *repl;

            /* internal flag that only holds state for delayed aevent at the
             * moment
            */
            u32                     xflags;

            /* Replay detection notification settings */
            u32                     replay_maxage;
            u32                     replay_maxdiff;

            /* Replay detection notification timer */
            struct timer_list       rtimer;

            /* Statistics */
            struct xfrm_stats       stats;

            struct xfrm_lifetime_cur curlft;
            struct tasklet_hrtimer  mtimer;

            /* used to fix curlft->add_time when changing date */
            long            saved_tmo;

            /* Last used time */
            unsigned long           lastused;

            /* Reference to data common to all the instances of this
             * transformer. */
            const struct xfrm_type  *type;
            struct xfrm_mode        *inner_mode;
            struct xfrm_mode        *inner_mode_iaf;
            struct xfrm_mode        *outer_mode;

            /* Security context */
            struct xfrm_sec_ctx     *security;
            /* Private data of this transformer, format is opaque,
             * interpreted by xfrm_type methods. */
            void                    *data;
    };

描述一个策略查找到的对应的加密算法，模式和协议等,除全局hash/list中外，它在存在于dst_entry当中，在dst_output中使用

###xfrm_tmpl

    struct xfrm_tmpl {
    /* id in template is interpreted as:
     * daddr - destination of tunnel, may be zero for transport mode.
     * spi   - zero to acquire spi. Not zero if spi is static, then
     *         daddr must be fixed too.
     * proto - AH/ESP/IPCOMP
     */
            struct xfrm_id          id;

    /* Source address of tunnel. Ignored, if it is not a tunnel. */
            xfrm_address_t          saddr;

            unsigned short          encap_family;

            u32                     reqid;

    /* Mode: transport, tunnel etc. */
            u8                      mode;

    /* Sharing mode: unique, this session only, this user only etc. */
            u8                      share;

    /* May skip this transfomration if no SA is found */
            u8                      optional;

    /* Skip aalgos/ealgos/calgos checks. */
            u8                      allalgs;

    /* Bit mask of algos allowed for acquisition */
            u32                     aalgos;
            u32                     ealgos;
            u32                     calgos;
    };

存在在xfrm_policy结构中， 用于查找对应的xfrm_state时，组织的参数。

###xfrm_mode

    struct xfrm_mode {
            /*
             * Remove encapsulation header.
             *
             * The IP header will be moved over the top of the encapsulation
             * header.
             *
             * On entry, the transport header shall point to where the IP header
             * should be and the network header shall be set to where the IP
             * header currently is.  skb->data shall point to the start of the
             * payload.
             */
            int (*input2)(struct xfrm_state *x, struct sk_buff *skb);

            /*
             * This is the actual input entry point.
             *
             * For transport mode and equivalent this would be identical to
             * input2 (which does not need to be set).  While tunnel mode
             * and equivalent would set this to the tunnel encapsulation function
             * xfrm4_prepare_input that would in turn call input2.
             */
            int (*input)(struct xfrm_state *x, struct sk_buff *skb);

            /*
             * Add encapsulation header.
             *
             * On exit, the transport header will be set to the start of the
             * encapsulation header to be filled in by x->type->output and
             * the mac header will be set to the nextheader (protocol for
             * IPv4) field of the extension header directly preceding the
             * encapsulation header, or in its absence, that of the top IP
             * header.  The value of the network header will always point
             * to the top IP header while skb->data will point to the payload.
             */
            int (*output2)(struct xfrm_state *x,struct sk_buff *skb);

            /*
             * This is the actual output entry point.
             *
             * For transport mode and equivalent this would be identical to
             * output2 (which does not need to be set).  While tunnel mode
             * and equivalent would set this to a tunnel encapsulation function
             * (xfrm4_prepare_output or xfrm6_prepare_output) that would in turn
             * call output2.
             */
            int (*output)(struct xfrm_state *x, struct sk_buff *skb);

            struct xfrm_state_afinfo *afinfo;
            struct module *owner;
            unsigned int encap;
            int flags;
    };

存在于xfrm_state中，用来描述传输时的模式，通常就是我们熟知的tranport 或tunnel，net/ipv4/xfrm4_mode_tunnel.c 和net/ipv4/ipv4/xfrm4_mode_transport.c

    static struct xfrm_mode xfrm4_tunnel_mode = {
            .input2 = xfrm4_mode_tunnel_input,
            .input = xfrm_prepare_input,
            .output2 = xfrm4_mode_tunnel_output,
            .output = xfrm4_prepare_output,
            .owner = THIS_MODULE,
            .encap = XFRM_MODE_TUNNEL,
            .flags = XFRM_MODE_FLAG_TUNNEL,
    };

    static struct xfrm_mode xfrm4_transport_mode = {
            .input = xfrm4_transport_input,
            .output = xfrm4_transport_output,
            .owner = THIS_MODULE,
            .encap = XFRM_MODE_TRANSPORT,
    };

当然在查找xfrm_state(SA), xfrm_tmpl中也得有这个参数


###xfrm_type

    struct xfrm_type {
            char                    *description;
            struct module           *owner;
            u8                      proto;
            u8                      flags;
    #define XFRM_TYPE_NON_FRAGMENT  1
    #define XFRM_TYPE_REPLAY_PROT   2
    #define XFRM_TYPE_LOCAL_COADDR  4
    #define XFRM_TYPE_REMOTE_COADDR 8

            int                     (*init_state)(struct xfrm_state *x);
            void                    (*destructor)(struct xfrm_state *);
            int                     (*input)(struct xfrm_state *, struct sk_buff *skb);
            int                     (*output)(struct xfrm_state *, struct sk_buff *pskb);
            int                     (*reject)(struct xfrm_state *, struct sk_buff *,
                                              const struct flowi *);
            int                     (*hdr_offset)(struct xfrm_state *, struct sk_buff *, u8 **);
            /* Estimate maximal size of result of transformation of a dgram */
            u32                     (*get_mtu)(struct xfrm_state *, int size);
    };

存在于xfrm_state中，用来描述传输时的协议类型，最常用的两个，ah 或esp,  net/ipv4/ah4.c和net/ipv4/esp4.c

    static const struct xfrm_type ah_type =
    {
            .description    = "AH4",
            .owner          = THIS_MODULE,
            .proto          = IPPROTO_AH,
            .flags          = XFRM_TYPE_REPLAY_PROT,
            .init_state     = ah_init_state,
            .destructor     = ah_destroy,
            .input          = ah_input,
            .output         = ah_output
    };

    static const struct xfrm_type esp_type =
    {
            .description    = "ESP4",
            .owner          = THIS_MODULE,
            .proto          = IPPROTO_ESP,
            .flags          = XFRM_TYPE_REPLAY_PROT,
            .init_state     = esp_init_state,
            .destructor     = esp_destroy,
            .get_mtu        = esp4_get_mtu,
            .input          = esp_input,
            .output         = esp_output
    };

同xfrm_mode, 在查找sa时也需要这个参数

###xfrm_policy_afinfo

    struct xfrm_policy_afinfo {
            unsigned short          family;
            struct dst_ops          *dst_ops;
            void                    (*garbage_collect)(struct net *net);
            struct dst_entry        *(*dst_lookup)(struct net *net, int tos,
                                                   const xfrm_address_t *saddr,
                                                   const xfrm_address_t *daddr);
            int                     (*get_saddr)(struct net *net, xfrm_address_t *saddr, xfrm_address_t *daddr);
            void                    (*decode_session)(struct sk_buff *skb,
                                                      struct flowi *fl,
                                                      int reverse);
            int                     (*get_tos)(const struct flowi *fl);
            void                    (*init_dst)(struct net *net,
                                                struct xfrm_dst *dst);
            int                     (*init_path)(struct xfrm_dst *path,
                                                 struct dst_entry *dst,
                                                 int nfheader_len);
            int                     (*fill_dst)(struct xfrm_dst *xdst,
                                                struct net_device *dev,
                                                const struct flowi *fl);
            struct dst_entry        *(*blackhole_route)(struct net *net, struct dst_entry *orig);
    };

不同协议族在SP上的不同操作，如AF_INET, 定义在net/ipv4/xfrm4_policy.c

    static struct xfrm_policy_afinfo xfrm4_policy_afinfo = {
            .family =               AF_INET,
            .dst_ops =              &xfrm4_dst_ops,
            .dst_lookup =           xfrm4_dst_lookup,
            .get_saddr =            xfrm4_get_saddr,
            .decode_session =       _decode_session4,
            .get_tos =              xfrm4_get_tos,
            .init_path =            xfrm4_init_path,
            .fill_dst =             xfrm4_fill_dst,
            .blackhole_route =      ipv4_blackhole_route,
    };

###xfrm_state_afinfo

    struct xfrm_state_afinfo {
            unsigned int            family;
            unsigned int            proto;
            __be16                  eth_proto;
            struct module           *owner;
            const struct xfrm_type  *type_map[IPPROTO_MAX];
            struct xfrm_mode        *mode_map[XFRM_MODE_MAX];
            int                     (*init_flags)(struct xfrm_state *x);
            void                    (*init_tempsel)(struct xfrm_selector *sel,
                                                    const struct flowi *fl);
            void                    (*init_temprop)(struct xfrm_state *x,
                                                    const struct xfrm_tmpl *tmpl,
                                                    const xfrm_address_t *daddr,
                                                    const xfrm_address_t *saddr);
            int                     (*tmpl_sort)(struct xfrm_tmpl **dst, struct xfrm_tmpl **src, int n);
            int                     (*state_sort)(struct xfrm_state **dst, struct xfrm_state **src, int n);
            int                     (*output)(struct sk_buff *skb);
            int                     (*output_finish)(struct sk_buff *skb);
            int                     (*extract_input)(struct xfrm_state *x,
                                                     struct sk_buff *skb);
            int                     (*extract_output)(struct xfrm_state *x,
                                                      struct sk_buff *skb);
            int                     (*transport_finish)(struct sk_buff *skb,
                                                        int async);
            void                    (*local_error)(struct sk_buff *skb, u32 mtu);
    };

sa也有类似的接口，　AF_INET对应的在net/ipv4/xfrm4_state.c

    static struct xfrm_state_afinfo xfrm4_state_afinfo = {
            .family                 = AF_INET,
            .proto                  = IPPROTO_IPIP,
            .eth_proto              = htons(ETH_P_IP),
            .owner                  = THIS_MODULE,
            .init_flags             = xfrm4_init_flags,
            .init_tempsel           = __xfrm4_init_tempsel,
            .init_temprop           = xfrm4_init_temprop,
            .output                 = xfrm4_output,
            .output_finish          = xfrm4_output_finish,
            .extract_input          = xfrm4_extract_input,
            .extract_output         = xfrm4_extract_output,
            .transport_finish       = xfrm4_transport_finish,
            .local_error            = xfrm4_local_error,
    };

###xfrm_mgr

    struct xfrm_mgr {
            struct list_head        list;
            char                    *id;
            int                     (*notify)(struct xfrm_state *x, const struct km_event *c);
            int                     (*acquire)(struct xfrm_state *x, struct xfrm_tmpl *, struct xfrm_policy *xp);
            struct xfrm_policy      *(*compile_policy)(struct sock *sk, int opt, u8 *data, int len, int *dir);
            int                     (*new_mapping)(struct xfrm_state *x, xfrm_address_t *ipaddr, __be16 sport);
            int                     (*notify_policy)(struct xfrm_policy *x, int dir, const struct km_event *c);
            int                     (*report)(struct net *net, u8 proto, struct xfrm_selector *sel, xfrm_address_t *addr);
            int                     (*migrate)(const struct xfrm_selector *sel,
                                               u8 dir, u8 type,
                                               const struct xfrm_migrate *m,
                                               int num_bundles,
                                               const struct xfrm_kmaddress *k);
    };

管理接口了，pf_key对应了一个

    static struct xfrm_mgr pfkeyv2_mgr =
    {
            .id             = "pfkeyv2",
            .notify         = pfkey_send_notify,
            .acquire        = pfkey_send_acquire,
            .compile_policy = pfkey_compile_policy,
            .new_mapping    = pfkey_send_new_mapping,
            .notify_policy  = pfkey_send_policy_notify,
            .migrate        = pfkey_send_migrate,
    };

###xfrm_dst

    struct xfrm_dst {
            union {
                    struct dst_entry        dst;
                    struct rtable           rt;
                    struct rt6_info         rt6;
            } u;
            struct dst_entry *route;
            struct flow_cache_object flo;
            struct xfrm_policy *pols[XFRM_POLICY_TYPE_MAX];
            int num_pols, num_xfrms;
    #ifdef CONFIG_XFRM_SUB_POLICY
            struct flowi *origin;
            struct xfrm_selector *partner;
    #endif
            u32 xfrm_genid;
            u32 policy_genid;
            u32 route_mtu_cached;
            u32 child_mtu_cached;
            u32 route_cookie;
            u32 path_cookie;
    };

由于xfrm输入输出转发是基于dst_entry的处理流程的，　因此这个结构体非常重要，它就是承载

##初始化

路径为：inet_init->ip_init->ip_rt_init->xfrm_init/ xfrm4_init

###xfrm_init中，　

1. register_pernet_subsys(&xfrm_net_ops);

		static struct pernet_operations __net_initdata xfrm_net_ops = {
		        .init = xfrm_net_init,
		        .exit = xfrm_net_exit,
		};

2. xfrm_input_init()输入相关初始化, 也就只创建了一个secpath_cache

3. xfrm_net_init中，三大步:

        rv = xfrm_state_init(net);
        if (rv < 0)
                goto out_state;
        rv = xfrm_policy_init(net);
        if (rv < 0)
                goto out_policy;
        xfrm_dst_ops_init(net);

4. xfrm_state_init, 初始化三个hash, hash_resize和gc两个工作队列

5. xfrm_policy_init, 添加一个xfrm_dst_cache, 初始化一个hash.和一个hash_resize工作队列，再注册一个notify，还有根据dir组级的，　policy_inexact(网上有说这是selector 相关长度不是标准时的一些特别策略，还没分析到) list和policy_bydst hash.

6. xfrm_dst_ops_init, net->xfrm.xfrm4_dst_ops = *afinfo->dst_ops; xfrm4_dst_ops给名字空间,后面会看到这个结构体

###xfrm4_init中

1. dst_entries_init(&xfrm4_dst_ops);

		static struct dst_ops xfrm4_dst_ops = {
		        .family =               AF_INET,
		        .protocol =             cpu_to_be16(ETH_P_IP),
		        .gc =                   xfrm4_garbage_collect,
		        .update_pmtu =          xfrm4_update_pmtu,
		        .redirect =             xfrm4_redirect,
		        .cow_metrics =          dst_cow_metrics_generic,
		        .destroy =              xfrm4_dst_destroy,
		        .ifdown =               xfrm4_dst_ifdown,
		        .local_out =            __ip_local_out,
		        .gc_thresh =            32768,
		};

2. xfrm4_state_init执行，　在这个当中，　就完成注册xfrm_state_afinfo[NPROTO]，xfrm_state_register_afinfo(&xfrm4_state_afinfo);

3. xfrm4_policy_init执行,  xfrm_policy_register_afinfo(&xfrm4_policy_afinfo);  xfrm_policy_afinfo[NPROTO]

###mode/type初始化

对于4种mode和4种type都作为了module来分开加载，由于比较独立，　因此这里就不跟踪了


##创建

sp和sa的创建，可利用pf_key ，或netlink的接口，　这里不做详细的分析，　下面只说下pocily创建的两种情况;

1. 对于policy的创建，第一类是在发送前得用set_sockopt进行创建，它创建的sockopt属于sock, 即sk_policy字段中。

2. 第二类就是一般的接口创建，　会进入全局的hash或list中

##发送

两大步:

###查找state

路径为　ip_route_output_flow->xfrm_lookup, 当flp4->flowi4_proto不为空时, xfrm_lookup，这是xfrm框架查找的入口

1. 在xfrm_lookup中，先判断sk->sk_policy[XFRM_POLICY_OUT]是否为空，　如果不为空，　就证明policy在sk中有，　应先处理，　如果为空就继续往下走。

2. 如果为空，　通常，xdst就为空，　进入flow_cache_lookup逻辑进行查找。

3. 以上两个逻辑中的任务一个进入，如果能找到并且不出错，都会得到一个链，　这个链为：

		xdst(0)-->xdst-->xdst-->dst

	一个或多个xdst加一个dst, 通过child指针相连，　dst一定为最后一个，　另个，　xdst的每一个route成员都为dst, 并且xdst0->route成员为dst.　另外xdst是dst的封装。　最后返回这个xdst0, 是以dst的形式.　完成查找.

4. 1中如果不为空的处理为通过xfrm_sk_policy_lookup()查找到对应的policy, 接着xfrm_expand_policies进行子策略处理，如果存在的话。最后通过xfrm_resolve_and_create_bundle来构建xdst链

5. 2中, flow_cache_lookup中，在全局flow_cache_lookup中找这个flow缓存，找着返回 ，不会再会有后面xdst链的创过程，应该是认为它会把所有的东西都缓存，包括xdst, 没有找着, 则创建一个缓存，再 需要调用xfrm_bundle_lookup进行查找xdst.

6. 在xfrm_bundle_lookup中， 如果传进来的flo缓存不为空， 则取出其它对应的xdst, 再判断xdst的pols->walk是否pol_dead,如果dead，则又将xdst置空

        if (oldflo) {
                xdst = container_of(oldflo, struct xfrm_dst, flo);
                num_pols = xdst->num_pols;
                num_xfrms = xdst->num_xfrms;
                pol_dead = 0;
                for (i = 0; i < num_pols; i++) {
                        pols[i] = xdst->pols[i];
                        pol_dead |= pols[i]->walk.dead;
                }
                if (pol_dead) {
                        dst_free(&xdst->u.dst);
                        xdst = NULL;
                        num_pols = 0;
                        num_xfrms = 0;
                        oldflo = NULL;
                }
        }

7. 如果xdst为空， 则使用__xfrm_policy_lookup()查找， 这个函数做用类似于xfrm_sk_policy_lookup , 不过最终会调用xfrm_policy_lookup_bytype完成查找, 同样也会调用xfrm_expand_policies进行subtype处理.

        if (xdst == NULL) {
                num_pols = 1;
                pols[0] = __xfrm_policy_lookup(net, fl, family,
                                               flow_to_policy_dir(dir));
                err = xfrm_expand_policies(fl, family, pols,
                                           &num_pols, &num_xfrms);
                if (err < 0)
                        goto inc_error;
                if (num_pols == 0)
                        return NULL;
                if (num_xfrms <= 0)
                        goto make_dummy_bundle;
        }

以前的最终结果，都为xfrm_resolve_and_create_bundle根据pols, fl, family dst_orig来新建xdst链.

1. xfrm_tmpl_resolve进行根据模板查找state, 很核心的操作， 路径为xfrm_tmpl_resolve_one->xfrm_state_find->xfrm_state_lookup

        for (i = 0; i < npols; i++) {
                if (cnx + pols[i]->xfrm_nr >= XFRM_MAX_DEPTH) {
                        error = -ENOBUFS;
                        goto fail;
                }

                ret = xfrm_tmpl_resolve_one(pols[i], fl, &tpp[cnx], family);
                if (ret < 0) {
                        error = ret;
                        goto fail;
                } else
                        cnx += ret;
        }

        if (npols > 1)
                xfrm_state_sort(xfrm, tpp, cnx, family);

    tpp为最终收集到的state, 它会成为xdst的成员。

2. 根据state和policy进行xdst链的构建

3. xfrm_tmpl_resolve_one中，遍历policy里的tmpl, 根据它进行state查找， 结合一看，总体是个双层循环:

        for (nx = 0, i = 0; i < policy->xfrm_nr; i++) {
                struct xfrm_state *x;
                xfrm_address_t *remote = daddr;
                xfrm_address_t *local  = saddr;
                struct xfrm_tmpl *tmpl = &policy->xfrm_vec[i];

                if (tmpl->mode == XFRM_MODE_TUNNEL ||
                    tmpl->mode == XFRM_MODE_BEET) {
                        remote = &tmpl->id.daddr;
                        local = &tmpl->saddr;
                        if (xfrm_addr_any(local, tmpl->encap_family)) {
                                error = xfrm_get_saddr(net, &tmp, remote, tmpl->encap_family);
                                if (error)
                                        goto fail;
                                local = &tmp;
                        }
                }

                x = xfrm_state_find(remote, local, fl, tmpl, policy, &error, family);

                if (x && x->km.state == XFRM_STATE_VALID) {
                        xfrm[nx++] = x;
                        daddr = remote;
                        saddr = local;
                        continue;
                }
                ......
        }

    另外对于TUNNEL mode remote, local也需要设置， 如果local是any, xfrm_get_saddr也是必要的一步, 最终会调用xfrm4_policy_afinfo->get_addr / xfrm4_get_saddr

4. xfrm_state_find中， 根据flowi, tmpl, policy来查询state,  第一次查找找着了返回， 没找着加上spi再找，使用xfrm_state_lookup, 找着报exist, 没有则新建state, 新建的state是acquire, 是发给用户空间协商的生成新的SA的， ike就是利用了这个特性

5. 对于xdst链的构建都在xfrm_bundle_create， 代码也很清晰， 另个需要注意的是header_len和trailer_len及nfheader_len都会在这里更新. 其中dst1->output的赋值给了xdst发送的出口，当然实际上只是封包

        for(...){
                dst1->xfrm = xfrm[i];
                xdst->xfrm_genid = xfrm[i]->genid;

                dst1->obsolete = DST_OBSOLETE_FORCE_CHK;
                dst1->flags |= DST_HOST;
                dst1->lastuse = now;

                dst1->input = dst_discard;
                dst1->output = inner_mode->afinfo->output;

                dst1->next = dst_prev;
                dst_prev = dst1;
                header_len += xfrm[i]->props.header_len;
                if (xfrm[i]->type->flags & XFRM_TYPE_NON_FRAGMENT)
                        nfheader_len += xfrm[i]->props.header_len;
                trailer_len += xfrm[i]->props.trailer_len;
        }

        for (dst_prev = dst0; dst_prev != dst; dst_prev = dst_prev->child) {
                struct xfrm_dst *xdst = (struct xfrm_dst *)dst_prev;

                err = xfrm_fill_dst(xdst, dev, fl);
                if (err)
                        goto free_dst;

                dst_prev->header_len = header_len;
                dst_prev->trailer_len = trailer_len;
                header_len -= xdst->u.dst.xfrm->props.header_len;
                trailer_len -= xdst->u.dst.xfrm->props.trailer_len;
        }

从上面的流程来看， 基本是policy上的操作，特别是xfrm4_policy_afinfo这个结构体里的操作, 而对于封包发送就会看到，大多是state上的操作， 特别是xfrm4_state_afinfo里的函函数，以及xfrm4_tunnel_mode/xfrm4_transport_mode, ah_type/esp_type里的操作了。

###封包发送

还记得， 上面查找state，构建xdst链时， 其中有一步是dst1->output = inner_mode->afinfo->output; 在xfrm_bundle_create中。这就是xfrm4_output, 由于它被设置为dst->output, 所以在dst_output后会被调用。

1. 在xfrm4_output中，只是为了过netfilter， 最终调用x->outer_mode->afinfo->output_finish， 即xfrm4_output_finish, 在这个函数中回到了通知接口xfrm_output.

2. 经过检查sum, 如果是gso, 调用xfrm_output_gso, 如果不是，则xfrm_output2, 当然前者最终还是全调用后者

3. xfrm_output2再调xfrm_output_resume. 这个函数差不多就到底了，一个while遍历xdst链，完成发送。

        while (likely((err = xfrm_output_one(skb, err)) == 0)) {
                nf_reset(skb);

                err = skb_dst(skb)->ops->local_out(skb);
                if (unlikely(err != 1))
                        goto out;

                if (!skb_dst(skb)->xfrm)
                        return dst_output(skb);

                err = nf_hook(skb_dst(skb)->ops->family,
                              NF_INET_POST_ROUTING, skb,
                              NULL, skb_dst(skb)->dev, xfrm_output2);
        }

4. xfrm_output_one中主要完成除next之外，的两个重要调用：

        err = x->outer_mode->output(x, skb);
        ...
        err = x->type->output(x, skb);

    这两个在调用什么就不用说了, 真正地在完成封包

5. 每次循环都会skb_dst(skb)->ops->local_out(skb); 就是__ip_local_out

6. 再判断skb_dst(skb)->xfrm即xfrm是空，　就到最后一个dst, 调用dst_output出去.

##接收

以后再写
