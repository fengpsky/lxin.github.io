---
layout: post
title: "linux net sched htb实现"
category: linux kernel
excerpt: "linux链路层流量控制--htb实现"
tags: "kernel"
---
{% include JB/setup %}
初次接触到tc 这个命令时， 一看它的那些参数，有云里雾里的， 去看man手册，在网上找各种资料， 也不能很好地理解它的意义。无奈之下就只有去看它的实现了， Qdisc的框架的确挺简单的， 但为了不同算法实现上的灵活， 很多接口都交给算法本身去实现了， 因些只看框架还是不能理解， 找个还算复杂，也较常用的来分析吧， htb.

##配置

    tc qdisc del dev eth0 root
    tc qdisc add dev eth0 root handle 1: htb
    tc class add dev  eth0 parent 1: classid 1:1 htb rate  100mbit ceil 100mbit
    tc class add dev  eth0 parent 1:1 classid 1:10 htb rate 10mbit ceil 10mbit
    tc qdisc add dev  eth0 parent 1:10 sfq handle 20: perturb 10
    tc filter add dev eth0 protocol ip parent 1: prio 2   u32 match ip dst 220.181.xxx.xx/32 flowid 1:1
    tc filter add dev eth0 protocol ip parent 1: prio 50 u32 match ip dst 0.0.0.0/0  flowid 1:10

从网上拷的一段htb的配置， 实现的是"只能向外发 10M 的数据",构造出来的树形图：

    root qdisc 1: ---  class 1:1 ---- class 1:10  (1-3行命令作用)
    
                                        qdisc sfq (4行命令作用)
    
    u32                 u32                       (5-6行命令作用)

qdisc是排除规则，规则里面都一个queue,默认为fifo, 也可指定， 如4行添加的qdisc是sfq的。

class是分类，分类可以组建树形结构，最开始的分类都是root qdisc的子类。其id的前16位与父qdisc同。

u32是过滤器，这种过过滤器是根据包内容过滤的，也有其它的如fw, route.不过u32很常用。

另外上面的树形结构是通过分类构建起来的， 事实上，sched的强大， 是因为在上面叶子结点上的qdisc，可以作为'root qdisc', 再次构建分类树。


##重要结构

###struct Qdisc

    struct Qdisc {
            int                     (*enqueue)(struct sk_buff *skb, struct Qdisc *dev);
            struct sk_buff *        (*dequeue)(struct Qdisc *dev);
            unsigned int            flags;
    #define TCQ_F_BUILTIN           1
    #define TCQ_F_INGRESS           2
    #define TCQ_F_CAN_BYPASS        4
    #define TCQ_F_MQROOT            8
    #define TCQ_F_ONETXQUEUE        0x10 /* dequeue_skb() can assume all skbs are for
                                          * q->dev_queue : It can test
                                          * netif_xmit_frozen_or_stopped() before
                                          * dequeueing next packet.
                                          * Its true for MQ/MQPRIO slaves, or non
                                          * multiqueue device.
                                          */
    
    #define TCQ_F_WARN_NONWC        (1 << 16)
            u32                     limit;
            const struct Qdisc_ops  *ops;//关联Qdisc_ops
            struct qdisc_size_table __rcu *stab;
            struct list_head        list;
            u32                     handle;
            u32                     parent;
            int                     (*reshape_fail)(struct sk_buff *skb,
                                            struct Qdisc *q);
    
            void                    *u32_node;
    
            /* This field is deprecated, but it is still used by CBQ
             * and it will live until better solution will be invented.
             */
            struct Qdisc            *__parent;
            struct netdev_queue     *dev_queue;
    
            struct gnet_stats_rate_est64    rate_est;
            struct Qdisc            *next_sched;
            struct sk_buff          *gso_skb;
            /*
             * For performance sake on SMP, we put highly modified fields at the end
             */
            unsigned long           state;
            struct sk_buff_head     q;
            struct gnet_stats_basic_packed bstats;
            unsigned int            __state;
            struct gnet_stats_queue qstats;
            struct rcu_head         rcu_head;
            int                     padded;
            atomic_t                refcnt;
    
            spinlock_t              busylock ____cacheline_aligned_in_smp;
    };

没想到这个结构己经变这么多参数了， 它描述了排除规，基算法的实现自然是其enqueue和dequeue成员,钽其扩展的接口 ，不是它， 还是下面的这个结构.

###struct qdisc_ops

    struct Qdisc_ops {
            struct Qdisc_ops        *next;
            const struct Qdisc_class_ops    *cl_ops;//关联类操作Qdisc_class_ops
            char                    id[IFNAMSIZ];
            int                     priv_size;
    
            int                     (*enqueue)(struct sk_buff *, struct Qdisc *);
            struct sk_buff *        (*dequeue)(struct Qdisc *);
            struct sk_buff *        (*peek)(struct Qdisc *);
            unsigned int            (*drop)(struct Qdisc *);
    
            int                     (*init)(struct Qdisc *, struct nlattr *arg);
            void                    (*reset)(struct Qdisc *);
            void                    (*destroy)(struct Qdisc *);
            int                     (*change)(struct Qdisc *, struct nlattr *arg);
            void                    (*attach)(struct Qdisc *);
    
            int                     (*dump)(struct Qdisc *, struct sk_buff *);
            int                     (*dump_stats)(struct Qdisc *, struct gnet_dump *);
    
            struct module           *owner;
    };

Qdisc中的enqueue/dequeue,实际上就会调用Qdisc_ops中的enqueue/dequeue, 而Qdisc_ops不同有qdisc就有不同的实现，如htb_qdisc_ops

###struct Qdisc_class_ops

    struct Qdisc_class_ops {
            /* Child qdisc manipulation */
            struct netdev_queue *   (*select_queue)(struct Qdisc *, struct tcmsg *);
            int                     (*graft)(struct Qdisc *, unsigned long cl,
                                            struct Qdisc *, struct Qdisc **);
            struct Qdisc *          (*leaf)(struct Qdisc *, unsigned long cl);
            void                    (*qlen_notify)(struct Qdisc *, unsigned long);
    
            /* Class manipulation routines */
            unsigned long           (*get)(struct Qdisc *, u32 classid);
            void                    (*put)(struct Qdisc *, unsigned long);
            int                     (*change)(struct Qdisc *, u32, u32,
                                            struct nlattr **, unsigned long *);
            int                     (*delete)(struct Qdisc *, unsigned long);
            void                    (*walk)(struct Qdisc *, struct qdisc_walker * arg);
    
            /* Filter manipulation */
            struct tcf_proto **     (*tcf_chain)(struct Qdisc *, unsigned long);
            unsigned long           (*bind_tcf)(struct Qdisc *, unsigned long,
                                            u32 classid);
            void                    (*unbind_tcf)(struct Qdisc *, unsigned long);
    
            /* rtnetlink specific */
            int                     (*dump)(struct Qdisc *, unsigned long,
                                            struct sk_buff *skb, struct tcmsg*);
            int                     (*dump_stats)(struct Qdisc *, unsigned long,
                                            struct gnet_dump *);
    };

qdisc对类的操作， 包括对类的查找， 及类中过滤器的获取, 不同qdisc也有不同实现htb_class

###struct xxx_class

    struct xxx_class
    {
    	u32 classid;
    	....
    	struct tcf_proto *filter_list;
    	....
    }

这个没有明确定义的结构，但各个qdisc都会按个模板来进行定义，如htb_class

###struct tcf_proto

    struct tcf_proto {
            /* Fast access part */
            struct tcf_proto        *next;
            void                    *root;
            int                     (*classify)(struct sk_buff *,
                                                const struct tcf_proto *,
                                                struct tcf_result *);
            __be16                  protocol;
    
            /* All the rest */
            u32                     prio;
            u32                     classid;
            struct Qdisc            *q;
            void                    *data;
            const struct tcf_proto_ops      *ops;
    };

描述一个过滤器，不过是一个通用的描述， 如classify， 会调用tcf_proto_ops中的接口, 类似于qdisc与qdisc_ops的关系

###struct tcf_proto_ops

    struct tcf_proto_ops {
            struct list_head        head;
            char                    kind[IFNAMSIZ];
    
            int                     (*classify)(struct sk_buff *,
                                                const struct tcf_proto *,
                                                struct tcf_result *);
            int                     (*init)(struct tcf_proto*);
            void                    (*destroy)(struct tcf_proto*);
    
            unsigned long           (*get)(struct tcf_proto*, u32 handle);
            void                    (*put)(struct tcf_proto*, unsigned long);
            int                     (*change)(struct net *net, struct sk_buff *,
                                            struct tcf_proto*, unsigned long,
                                            u32 handle, struct nlattr **,
                                            unsigned long *);
            int                     (*delete)(struct tcf_proto*, unsigned long);
            void                    (*walk)(struct tcf_proto*, struct tcf_walker *arg);
    
            /* rtnetlink specific */
            int                     (*dump)(struct net*, struct tcf_proto*, unsigned long,
                                            struct sk_buff *skb, struct tcmsg*);
    
            struct module           *owner;
    };

过滤器真正action的接口， 包括完成分类， 如u32是cls_u32_ops

###struct tcf_result

    struct tcf_result {
            unsigned long   class;
            u32             classid;
    };

描述报文报属分类。常作为函数调用结果返回用。


##框架调用

###输出##

1. dev_queue_xmit()开始,下来是__dev_xmit_skb(),　在这个函数中触发 q->enqueue(skb, q), 即htb_enqueue()的调用

        txq = netdev_pick_tx(dev, skb, accel_priv);
          q = rcu_dereference_bh(txq->qdisc);

    netdev_pick_tx()获取netdev_queue, 这个结构还没得及分析，然后会里面取出qdisc
                                    
2. 排完队后， 会调用qdisc_run来调度:

        while (qdisc_restart(q)) {
                /* 
                 * Ordered by possible occurrence: Postpone processing if
                 * 1. we've exceeded packet quota
                 * 2. another process needs the CPU;
                 */
                if (--quota <= 0 || need_resched()) {
                        __netif_schedule(q);
                        break;
                }
        }

    软中断触发后会调用qdisc_restart来将包发送出去

3. 在qdisc_restart中来完成将包发送或重排工作。

###输入

1. 从netif_receive_skb开始, 会调用handle_ing(), 再到ing_filter()

对于输入的流量控制， 没做过多的分析， 只是觉得比较难，可参考wangcong.org的一篇关于讲这方面的.


##htb的初始化

###模块的加载

主要是把htb_qdisc_ops注册进全局的&qdisc_base中

###队列的创建

htb_sched这个结构很重要，是qdisc的一个扩展 htb 里面的成员是构造树形规则的开始， 包括tcf_proto, Qdisc_class_hash, 使qdisc有了连节类与过滤器的能力， 方便与class进行树形结构的构建。

因些创建qdisc时， 会将htb_sched以priv形式附到qdisc的末尾

###类的创建

htb_class运行时， 通过遍历运行tcf_proto这个链表来进行分类， 自己对于分类也有树形连接的字段

###过滤器的添加

上面命令中给的是u32， 自己目前也没对它了解多少, 以后再写吧

##htb的处理

从htb_enqueue开始,

1. 首先会调用cl= htb_classify()进行分类并获取分类

2. 通过获取来的分类， 将包放进对应的队列中去qdisc_enqueue(skb, cl->un.leaf.q));
htb_classify的逻辑为：

            while (tcf && (result = tc_classify(skb, tcf, &res)) >= 0) {
        #ifdef CONFIG_NET_CLS_ACT
                    switch (result) {
                    case TC_ACT_QUEUED:
                    case TC_ACT_STOLEN:
                            *qerr = NET_XMIT_SUCCESS | __NET_XMIT_STOLEN;
                    case TC_ACT_SHOT:
                            return NULL;
                    }
        #endif
                    cl = (void *)res.class;
                    if (!cl) {
                            if (res.classid == sch->handle)
                                    return HTB_DIRECT;      /* X:0 (direct flow) */
                            cl = htb_find(res.classid, sch);
                            if (!cl)
                                    break;  /* filter selected invalid classid */
                    }
                    if (!cl->level)
                            return cl;      /* we hit leaf; return it */
    
                    /* we have got inner class; apply inner filter chain */
                    tcf = cl->filter_list;
            }

利用tc_classify在tcf链中查找正确的分类， 并且对查找到的分类进行判断， 如果是叶子节点， 就返回，不是就再这个类的tcf链中再查找， 就是一个树形查找的过程。
