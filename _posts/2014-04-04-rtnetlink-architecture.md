---
layout: post
title: "rtnetlink框架"
category: linux kernel
excerpt: "about rtnetlink"
tags: "kernel"
---
{% include JB/setup %}

### 几个关键的结构体

#### strct rtnl_link_ops

include/net/rtnetlink.h中

描述不同net_device的link操作，如new, dump, set等,因些一个设备想通过rtnetfilter配置就需要在这个框架中注册一项,如vxlan:

    static struct rtnl_link_ops vxlan_link_ops __read_mostly = {
            .kind           = "vxlan",
            .maxtype        = IFLA_VXLAN_MAX,
            .policy         = vxlan_policy,
            .priv_size      = sizeof(struct vxlan_dev),
            .setup          = vxlan_setup,
            .validate       = vxlan_validate,
            .newlink        = vxlan_newlink,
            .dellink        = vxlan_dellink,
            .get_size       = vxlan_get_size,
            .fill_info      = vxlan_fill_info,
    };

在其初始化时,rc = rtnl_link_register(&vxlan_link_ops);算是一种对于不同link的扩展.这个函数会在static LIST_HEAD(link_ops)中添加一项, 当然link_ops也是global的

####rtnl_link

net/core/rtnetlink.c中

    struct rtnl_link {
            rtnl_doit_func          doit;
            rtnl_dumpit_func        dumpit;
            rtnl_calcit_func        calcit;
    };

描述真实操作的函数，构建在rtnl_msg_handlers中，又一个global变量. 可通过rtnl_register()进行注册.

    void rtnl_register(int protocol, int msgtype,
                       rtnl_doit_func doit, rtnl_dumpit_func dumpit,
                       rtnl_calcit_func calcit)

如果有想通过rtnetfilter进行配置的操作可通过它来进行注册.可能会问到它与link_ops的关系。　事实上rtnl_register注册的link操作会调用link_ops这个VT进行操作.似乎刚注册进rtnl框架中的rtnl_link又变成了一个新框架给link_ops用。没办法，内核里面从来都是框架里面套框架 。rtnl自身在初始化时就通过这个接口添加了一堆重要的接口。rtnetlink_init()


### 初始化

rtnetlink_init(), net/core/rtnetlink.c

最清晰的几行代码.

1. register_pernet_subsys(&rtnetlink_net_ops)，网络名字空间框架的操作，另一篇中会提到，只要知道在创建名字空间时, init会被调用，删除时exit会被调用.

        static struct pernet_operations rtnetlink_net_ops = {
                .init = rtnetlink_net_init,
                .exit = rtnetlink_net_exit,
        };

    而在rtnetlink_net_init()中　sk = netlink_kernel_create(net, NETLINK_ROUTE, &cfg);　就被创建，　接netfiler框架分析, 还是需要提下rtnetlink_rcv()会在些被设置rcv函数，因为下面会说到。

2. register_netdevice_notifier(&rtnetlink_dev_notifier); 网络通知链接框架的操作，　不用多说。

3. rtnl_register(...), 下来是一堆的这样的函数，上面也已经提到过其作用。


### 接收

rtnetlink_rcv->netlink_rcv_skb->rtnetlink_rcv_msg

在rtnetlink_rcv_msg()中，分两类：

1. 为dump操作:

        dumpit = rtnl_get_dumpit(family, type);
        if (dumpit == NULL)
                return -EOPNOTSUPP;
        calcit = rtnl_get_calcit(family, type);
        if (calcit)
                min_dump_alloc = calcit(skb, nlh);
    
        __rtnl_unlock();
        rtnl = net->rtnl;
        {
                struct netlink_dump_control c = {
                        .dump           = dumpit,
                        .min_dump_alloc = min_dump_alloc,
                };
                err = netlink_dump_start(rtnl, skb, nlh, &c);
        }

    会先后从rtnl_msg_handlers中取dumpit接口，　和calcit接口，　后者拿到后会直接调用计算需要的空间大小，再组合传入netlink_dump_start()中

2. 为do操作:

        doit = rtnl_get_doit(family, type);
        if (doit == NULL)
                return -EOPNOTSUPP;
    
        return doit(skb, nlh);

    获取后直接执行

3. 在netlink_dump_start()中

        sk = netlink_lookup(sock_net(ssk), ssk->sk_protocol, NETLINK_CB(skb).portid);
        ...
        cb = &nlk->cb;
        memset(cb, 0, sizeof(cb));
        cb->dump = control->dump;
        cb->done = control->done;
        cb->nlh = nlh;
        cb->data = control->data;
        cb->module = control->module;
        cb->min_dump_alloc = control->min_dump_alloc;
        cb->skb = skb;
    
        nlk->cb_running = true;
    
        mutex_unlock(nlk->cb_mutex);
    
        ret = netlink_dump(sk);

    找着出去的socket,构建个cb,传入netlink_dump(), 上面的control就是1中的c

        skb = netlink_alloc_skb(sk, alloc_size, nlk->portid, GFP_KERNEL);
        if (!skb)
                goto errout_skb;
        netlink_skb_set_owner_r(skb, sk);
    
        len = cb->dump(skb, cb);
    
        if (len > 0) {
                mutex_unlock(nlk->cb_mutex);
    
                if (sk_filter(sk, skb))
                        kfree_skb(skb);
                else
                        __netlink_sendskb(sk, skb);
                return 0;
        }

netlink_dump()中，　重新生成skb, 并与外面的sock绑定, 再调用cb->dump(即c中的dumpit),最后调用__netlink_sendskb()，回到netlink的框架了


先写到这rtnl_newlink()与rtnl_dump_all()改天另作分析，　其中前者中就调用了rtnl_link_ops->net_link();
