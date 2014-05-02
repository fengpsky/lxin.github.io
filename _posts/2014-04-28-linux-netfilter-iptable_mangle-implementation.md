---
layout: post
title: "linux netfilter iptable_mangle (tproxy)"
category: linux kernel
excerpt: linux netfilter中mangle表的实现
tags: [kernel]
---
{% include JB/setup %}

mangle表的实现， 依然是xt_table的架构，事实上,其它几个tables也都是基于这个框架的， 因些不用详细再说， 它所完成的修改有TOS， TTL, MARK等传输特性，其也都有对就的xt_match和xt_target, 另外有一个很特殊的功能也在这个表里面实现， tproxy.

在不对数据包进行任何改变的前提下，就可以重定向数据包到本地的一个sock中，也就区别了nat的作用。 下面对基进行详细的描述。

##使用

1. client(192.168.0.10) <-------> (192.168.0.20)tproxy(192.168.1.10) <--------> (192.168.1.20)server

2. tproxy host 上:

        iptables -t mangle -A PREROUTING -p udp --dport 80 -j TPROXY  --tproxy-mark 0x1/0x1 --on-port 8000
        ip rule add fwmark 1 lookup 100
        ip route add local 0.0.0.0/0 dev eth1 table 100

    run a monitor and redirect socket like:

        #include <netinet/in.h>
        #include <sys/socket.h>
        #include <sys/types.h>
        #include <string.h>
        #include <stdio.h>

        #define TARGET "192.168.1.20"
        #define TPORT  80
        #define LOCAL  "0.0.0.0"
        #define LPORT  8000

        int main()
        {
        	struct sockaddr_in name, client[1], server;
        	int value = 1, opt=1;
        	char buffer[1024];
        	int len, ret;
        	len = sizeof(struct sockaddr_in);


        	int fd1;
        	fd1 = socket(AF_INET, SOCK_DGRAM, 0);
        	if (fd1 < 0){
        		perror("error");
        	}

        	ret = setsockopt(fd1, SOL_IP, IP_TRANSPARENT, &value, sizeof(value));
        	if (ret < 0){
        		perror("error");
        	}

        	name.sin_family = AF_INET;
        	name.sin_port = htons(LPORT);
        	name.sin_addr.s_addr = htonl(INADDR_ANY);
        	ret = bind(fd1, (struct sockaddr *)&name, sizeof(name));
        	if (ret < 0){
        		perror("error");
        	}


        	int fd2;
        	fd2 = socket(AF_INET, SOCK_DGRAM, 0);
        	if (fd2 < 0){
        		perror("error");
        	}

        	ret = setsockopt(fd2, SOL_IP, IP_TRANSPARENT, &value, sizeof(value));
        	if (ret < 0){
        		perror("error");
        	}

        	server.sin_family=AF_INET;
        	server.sin_port=htons(TPORT);
        	server.sin_addr.s_addr=inet_addr(TARGET);

        	ret = bind(fd2, (struct sockaddr *)&server, sizeof(server));
        	if (ret < 0){
        		perror("error");
        	}


        	int fd;
        	while(1){
        		memset(buffer, 0, sizeof(buffer));
        		ret = recvfrom(fd1,buffer,sizeof(buffer),0,(struct sockaddr*)&name,&len);
        		if (ret < 0){
        			perror("error");
        		}

        		if(name.sin_addr.s_addr != server.sin_addr.s_addr){
        			fd = fd1;
        			client[0] = name;
        			name = server;
        			printf("get the buffer from client: %s\n", buffer);
        		}
        		else{
        			fd = fd2;
        			name = client[0];
        			printf("get the buffer from server: %s\n", buffer);
        		}

        		ret = sendto(fd,buffer,strlen(buffer),0,(struct sockaddr *)&name,len);
        		if (ret < 0){
        			perror("error");
        		}
        	}

        }

3. in server host:

        #nc -l 80 -u

4. in client host:

        #ip route add 192.168.1.0/24 dev eth1
        #nc 192.168.1.20 80 -u

上面是对udp做的一个tproxy配合监听和转发socket来完成代理功能的一个简单实现， 当然是基于udp, 使用nc进行测试。 当然tcp也是同样的实现， 不同的是对建立连接时会更复杂一些，下面的实现也只对udp进行说明。

##实现

对于TPROXY的实现，不失一般性也是使用的是xt_target来完成的， 从其配置的命令便可以看出:

    iptables -t mangle -A PREROUTING -p udp --dport 80 -j TPROXY  --tproxy-mark 0x1/0x1 --on-port 8000

这是上面使用中配置最重要的一行， 其对应的target为:

        static struct xt_target tproxy_tg_reg[] __read_mostly = {
                {
                        .name           = "TPROXY",
                        .family         = NFPROTO_IPV4,
                        .table          = "mangle",
                        .target         = tproxy_tg4_v0,
                        .revision       = 0,
                        .targetsize     = sizeof(struct xt_tproxy_target_info),
                        .checkentry     = tproxy_tg4_check,
                        .hooks          = 1 << NF_INET_PRE_ROUTING,
                        .me             = THIS_MODULE,
                },
                {
                        .name           = "TPROXY",
                        .family         = NFPROTO_IPV4,
                        .table          = "mangle",
                        .target         = tproxy_tg4_v1,
                        .revision       = 1,
                        .targetsize     = sizeof(struct xt_tproxy_target_info_v1),
                        .checkentry     = tproxy_tg4_check,
                        .hooks          = 1 << NF_INET_PRE_ROUTING,
                        .me             = THIS_MODULE,
                },
        #ifdef XT_TPROXY_HAVE_IPV6
                {
                        .name           = "TPROXY",
                        .family         = NFPROTO_IPV6,
                        .table          = "mangle",
                        .target         = tproxy_tg6_v1,
                        .revision       = 1,
                        .targetsize     = sizeof(struct xt_tproxy_target_info_v1),
                        .checkentry     = tproxy_tg6_check,
                        .hooks          = 1 << NF_INET_PRE_ROUTING,
                        .me             = THIS_MODULE,
                },
        #endif

        };

    它的target()为tproxy_tg4_v0()

1. tproxy_tg4_v0会调用tproxy_tg4()来实现转发， 这个函数首先使用原理的saddr, daddr, sport, dport进行sk查找:

        sk = nf_tproxy_get_sock_v4(dev_net(skb->dev), iph->protocol,
                                   iph->saddr, iph->daddr,
                                   hp->source, hp->dest,
                                   skb->dev, NFT_LOOKUP_ESTABLISHED);

2. 如果上一步找到了， 就会对tcp 的TCP_TIME_WAIT状态，做进一步处理， 否则会利用saddr, laddr, sport, lport进行sk查找，udp在上面的测试中会走到这一步:

        /* UDP has no TCP_TIME_WAIT state, so we never enter here */
        if (sk && sk->sk_state == TCP_TIME_WAIT)
                /* reopening a TIME_WAIT connection needs special handling */
                sk = tproxy_handle_time_wait4(skb, laddr, lport, sk);
        else if (!sk)
                /* no, there's no established connection, check if
                 * there's a listener on the redirected addr/port */
                sk = nf_tproxy_get_sock_v4(dev_net(skb->dev), iph->protocol,
                                           iph->saddr, laddr,
                                           hp->source, lport,
                                           skb->dev, NFT_LOOKUP_LISTENER);

    很明显的对比， 可以看出，两次查找sk的不同在于一个是ESTABLISHED状态， 一个LISTENER状态， 而我们上面的使用是后者。

3.  下面这些代码是在ret = setsockopt(fd2, SOL_IP, IP_TRANSPARENT, &value, sizeof(value)); 的前提下才会执行得到。

        /* NOTE: assign_sock consumes our sk reference */
        if (sk && tproxy_sk_is_transparent(sk)) {
                /* This should be in a separate target, but we don't do multiple
                   targets on the same rule yet */
                skb->mark = (skb->mark & ~mark_mask) ^ mark_value;

                pr_debug("redirecting: proto %hhu %pI4:%hu -> %pI4:%hu, mark: %x\n",
                         iph->protocol, &iph->daddr, ntohs(hp->dest),
                         &laddr, ntohs(lport), skb->mark);

                nf_tproxy_assign_sock(skb, sk);
                return NF_ACCEPT;
        }

    拿到mark值，也就是上面shell命令配置的0x01, 才通过nf_tproxy_assign_sock将skb与sk进行bond, 这样就可以将skb为让sk接收做准备， 当然， 这之后还有很重要的一步就是上面的另两条ip route命令， 这两句使用skb不会被转发出去，而是让本地的sock 接收。

4. 对于nf_tproxy_get_sock_v4这个接口完成对sk的查找， 目前支持TCP/UDP, 对于这两者也都有不同的查找逻辑。基本到最后也都是调用协议栈通用接口完成。

这里只是对UDP listener的一种tproxy, 另外对于ESTABLISHED与tcp的可以自己再看下代码配置出来.

PS, 对于*tables比较重要的是清楚它的实现的框架xt_table与nf_conn, 其它的arp/eb/ip6也都是基于此，看似代码很多，大多也都是xt_match与xt_target的不同扩展出来的， 包括ipset， 代码很多， 但作为一个match , 也不过是管理多个ip的集合， 为iptables辅助使用，再看看用户态的配置规则就清楚了。

再如SYNPROXY, 作为一个target, 知道它的入口， 再去分析它的实现也就不难了.
