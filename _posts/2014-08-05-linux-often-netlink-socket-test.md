---
layout: post
title: "netlink (genl/rt) socket use"
category: auto test
excerpt: 测试中常用到的netlink例子
tags: [kernel]
---
{% include JB/setup %}

## raw netlink

###userspace

    #include <sys/stat.h>
    #include <unistd.h>
    #include <stdio.h>
    #include <stdlib.h>
    #include <sys/socket.h>
    #include <sys/types.h>
    #include <string.h>
    #include <asm/types.h>
    #include <linux/netlink.h>
    #include <linux/socket.h>

    #define NETLINK_TEST 17
    #define MAX_PAYLOAD 1024  /* maximum payload size*/
    struct sockaddr_nl src_addr, dest_addr;
    struct nlmsghdr *nlh = NULL;
    struct iovec iov;
    int sock_fd;
    struct msghdr msg;

    int main(int argc, char* argv[])
    {
            sock_fd = socket(PF_NETLINK, SOCK_RAW,NETLINK_TEST);
            memset(&msg, 0, sizeof(msg));
            memset(&src_addr, 0, sizeof(src_addr));
            src_addr.nl_family = AF_NETLINK;
            src_addr.nl_pid = getpid();  /* self pid */
            src_addr.nl_groups = 0;  /* not in mcast groups */
            bind(sock_fd, (struct sockaddr*)&src_addr, sizeof(src_addr));
            memset(&dest_addr, 0, sizeof(dest_addr));
            dest_addr.nl_family = AF_NETLINK;
            dest_addr.nl_pid = 0;   /* For Linux Kernel */
            dest_addr.nl_groups = 0; /* unicast */

            nlh=(struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
            /* Fill the netlink message header */
            nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
            nlh->nlmsg_pid = getpid();  /* self pid */
            nlh->nlmsg_flags = 0;
            /* Fill in the netlink message payload */
            strcpy(NLMSG_DATA(nlh), "Hello you!");

            iov.iov_base = (void *)nlh;
            iov.iov_len = nlh->nlmsg_len;
            msg.msg_name = (void *)&dest_addr;
            msg.msg_namelen = sizeof(dest_addr);
            msg.msg_iov = &iov;
            msg.msg_iovlen = 1;

            sendmsg(sock_fd, &msg, 0);

            /* Read message from kernel */
            memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
            recvmsg(sock_fd, &msg, 0);
            printf(" Received message payload: %s\n",
            NLMSG_DATA(nlh));

             /* Close Netlink Socket */
            close(sock_fd);
    }



###kernel

    #include <linux/kernel.h>
    #include <linux/module.h>
    #include <linux/types.h>
    #include <linux/sched.h>
    #include <net/sock.h>
    #include <linux/netlink.h>

    #define NETLINK_TEST 17
    struct sock *nl_sk = NULL;
    void nl_data_ready (struct sock *sk, int len)
    {
              wake_up_interruptible(sk->sk_sleep);
    }

    void test_netlink(void)
    {
            struct sk_buff * skb = NULL;
            struct nlmsghdr * nlh = NULL;
            int err;
            u32 pid;

            nl_sk = netlink_kernel_create(NETLINK_TEST, nl_data_ready);
            /* wait for message coming down from user-space */
            skb = skb_recv_datagram(nl_sk, 0, 0, &err);

            nlh = (struct nlmsghdr *)skb->data;
            printk("%s: received netlink message payload:%s\n", __FUNCTION__, (char*)NLMSG_DATA(nlh));

            pid = nlh->nlmsg_pid; /*pid of sending process */
            NETLINK_CB(skb).groups = 0; /* not in mcast group */
            NETLINK_CB(skb).pid = 0;      /* from kernel */
            NETLINK_CB(skb).dst_pid = pid;
            NETLINK_CB(skb).dst_groups = 0;  /* unicast */
            netlink_unicast(nl_sk, skb, pid, MSG_DONTWAIT);
            sock_release(nl_sk->sk_socket);
    }

    int init_module()
    {
            test_netlink();
            return 0;
    }
    void cleanup_module( )
    {
    }
    MODULE_LICENSE("GPL");

## raw multicast netlink

###userspace

    #include <sys/stat.h>
    #include <unistd.h>
    #include <stdio.h>
    #include <stdlib.h>
    #include <sys/socket.h>
    #include <sys/types.h>
    #include <string.h>
    #include <asm/types.h>
    #include <linux/netlink.h>
    #include <linux/socket.h>

    #define NETLINK_TEST 17
    #define MAX_PAYLOAD 1024  /* maximum payload size*/
    struct sockaddr_nl src_addr, dest_addr;
    struct nlmsghdr *nlh = NULL;
    struct iovec iov;
    int sock_fd;
    struct msghdr msg;

    int main(int argc, char* argv[])
    {

            sock_fd=socket(PF_NETLINK, SOCK_RAW, NETLINK_TEST);
            memset(&src_addr, 0, sizeof(src_addr));
            memset(&msg, 0, sizeof(msg));

            src_addr.nl_family = AF_NETLINK;
            src_addr.nl_pid = getpid();  /* self pid */
            /* interested in group 1<<0 */
            src_addr.nl_groups = 1;
            bind(sock_fd, (struct sockaddr*)&src_addr, sizeof(src_addr));
            memset(&dest_addr, 0, sizeof(dest_addr));
            nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
            memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));

            iov.iov_base = (void *)nlh;
            iov.iov_len = NLMSG_SPACE(MAX_PAYLOAD);
            msg.msg_name = (void *)&dest_addr;
            msg.msg_namelen = sizeof(dest_addr);
            msg.msg_iov = &iov;
            msg.msg_iovlen = 1;

            printf("Waiting for message from kernel\n");

             /* Read message from kernel */
            recvmsg(sock_fd, &msg, 0);

            printf("Received message payload: %s\n", NLMSG_DATA(nlh));
            close(sock_fd);
    }

###kernel

    #include <linux/kernel.h>
    #include <linux/module.h>
    #include <linux/types.h>
    #include <linux/sched.h>
    #include <net/sock.h>
    #include <linux/netlink.h>

    #define MAX_PAYLOAD 1024
    #define NETLINK_TEST 17

    struct sock *nl_sk = NULL;

    void nl_data_ready (struct sock *sk, int len)
    {
            wake_up_interruptible(sk->sk_sleep);
    }

    void test_netlink(void)
    {
            struct sk_buff *skb = NULL;
            struct nlmsghdr *nlh;

            nl_sk = netlink_kernel_create(NETLINK_TEST, nl_data_ready);
            skb = alloc_skb(NLMSG_SPACE(MAX_PAYLOAD),GFP_KERNEL);
            nlh = (struct nlmsghdr *)skb->data;
            nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
            nlh->nlmsg_pid = 0;  /* from kernel */
            nlh->nlmsg_flags = 0;
            nlh = (struct nlmsghdr *) skb_put(skb, NLMSG_SPACE(MAX_PAYLOAD));
            strcpy(NLMSG_DATA(nlh), "Greeting from kernel!");
            /* sender is in group 1<<0 */
            NETLINK_CB(skb).groups = 1;
            NETLINK_CB(skb).pid = 0;  /* from kernel */
            NETLINK_CB(skb).dst_pid = 0;  /* multicast */
            /* to mcast group 1<<0 */
            NETLINK_CB(skb).dst_groups = 1;
            /*multicast the message to all listening processes*/
            netlink_broadcast(nl_sk, skb, 0, 1, GFP_KERNEL);
            //printk("%s\n", NLMSG_DATA(nlh));

            sock_release(nl_sk->sk_socket);
    }

    int init_module()
    {
            test_netlink();
            return 0;
    }
    void cleanup_module( )
    {

    }
    MODULE_LICENSE("GPL");

##genl netlink

###userspace

    #include <stdlib.h>
    #include <stdio.h>
    #include <string.h>
    #include <asm/types.h>
    #include <netinet/in.h>
    #include <linux/socket.h>
    #include <linux/netlink.h>
    #include <linux/genetlink.h>
    #include <arpa/inet.h>
    #include <sys/types.h>
    #include <unistd.h>

    #define GENL_ID_TEST 0x110

    int main()
    {
            int nlfd;
            struct sockaddr_nl sock_loc, sock_ker;

            struct {
                    struct nlmsghdr nh;
                    struct genlmsghdr genlhdr;
            } req;

            memset(&req, 0, sizeof(req));
            req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(struct genlmsghdr));
            req.nh.nlmsg_flags = NLM_F_REQUEST;
            req.nh.nlmsg_type = GENL_ID_TEST;

            req.genlhdr.cmd = 0x1;
            req.genlhdr.version = 0x1;



            if ((nlfd = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC)) == -1) {
                    perror("netlink socket create failed");
                    exit(EXIT_FAILURE);
            }

            memset(&sock_loc, 0, sizeof(sock_loc));
            sock_loc.nl_family = AF_NETLINK;
            sock_loc.nl_pid = getpid();
            if (bind(nlfd, (struct sockaddr *)&sock_loc, sizeof(sock_loc)) == -1) {
                    perror("bind local netlink socket failed");
                    exit(EXIT_FAILURE);
            }

            memset(&sock_ker, 0, sizeof(sock_ker));
            sock_ker.nl_family = AF_NETLINK;
            sock_ker.nl_pid = 0;
            if (connect(nlfd, (struct sockaddr *) &sock_ker, sizeof(sock_ker)) == -1) {
                    perror("netlink socket connect kernel failed ");
                    exit(EXIT_FAILURE);
            }

            if (send(nlfd, &req, req.nh.nlmsg_len, 0) == -1) {
                    perror("send message to kernel error");
                    exit(EXIT_FAILURE);
            }
            return 0;
    }


###kernel

    #include <net/genetlink.h>
    #include <linux/module.h>

    #define TEST_GENL_NAME "GENLTEST"
    #define TEST_GENL_VERSION 0x1
    #define TEST_GENL_HDRLEN 0
    #define GENL_ID_TEST 0x110

    #define TEST_GENL_CMD 0x1

    static int handle_test_cmd(struct sk_buff *skb, struct genl_info *info)
    {
            printk("[handle_test_cmd]start==>");
            msleep(10000);
            printk("[handle_test_cmd]end\n");
            //mdelay(200);
            return 0;
    }
    static struct genl_family family = {
            .id             = GENL_ID_TEST,
            .name           = TEST_GENL_NAME,
            .version        = TEST_GENL_VERSION,
            .hdrsize        = TEST_GENL_HDRLEN,
            .maxattr        = 0,
    };

    static struct genl_ops ops = {
            .cmd            = TEST_GENL_CMD,
            .doit           = handle_test_cmd,
    };

    static int family_registered = 1;

    static int __init genltest_init(void)
    {
            if (genl_register_family(&family))
                    goto err;

            family_registered = 1;

            if (genl_register_ops(&family, &ops))
                    goto err_unregister;

            return 0;

    err_unregister:
            genl_unregister_family(&family);
            family_registered = 0;
    err:
            printk("Failed to register genltest interface\n");
            return -EFAULT;
    }

    static void __exit genltest_exit(void)
    {
            if (family_registered) {
                    genl_unregister_family(&family);
                    family_registered = 0;
            }
    }

    module_init(genltest_init);
    module_exit(genltest_exit);
    MODULE_LICENSE("GPL");


##rtnl netlink

###userspace

    #include <stdlib.h>
    #include <stdio.h>
    #include <string.h>
    #include <asm/types.h>
    #include <linux/netlink.h>
    #include <linux/rtnetlink.h>
    #include <sys/socket.h>
    #include <arpa/inet.h>
    #include <sys/types.h>
    #include <unistd.h>
    
    int
    main(int argc, char *argv[])
    {
            int nlfd;
            struct sockaddr_nl sock_loc, sock_ker;
            struct rtattr *rta;
    
            struct {
                    struct nlmsghdr nh;
                    struct ifaddrmsg addrmsg;
                    char attrbuf[512];
            } req;
    
            /* Check arguments */
            if (argc != 4) {
                    fprintf(stderr, "usage: %s index prefixlen ipv6addr", argv[0]);
                    exit(EXIT_FAILURE);
            }
    
            /* Build netlink message */
            memset(&req, 0, sizeof(req));
            req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
            req.nh.nlmsg_flags = NLM_F_REQUEST;
            req.nh.nlmsg_type = RTM_NEWADDR;
            req.addrmsg.ifa_family = AF_INET6;
            req.addrmsg.ifa_prefixlen = atoi(argv[2]);
            req.addrmsg.ifa_flags = 0;
            req.addrmsg.ifa_scope = RT_SCOPE_UNIVERSE;
            req.addrmsg.ifa_index = atoi(argv[1]);
            if (req.addrmsg.ifa_index <= 0) {
                    perror("interface index error");
                    exit(EXIT_FAILURE);
            }
    
            /* Set rta of in6_addr */
            rta = (struct rtattr *)(((char *) &req) +
                                            NLMSG_ALIGN(req.nh.nlmsg_len));
            rta->rta_len = RTA_LENGTH(sizeof(struct in6_addr));
            rta->rta_type = IFA_ADDRESS;
            if (inet_pton(AF_INET6, argv[3], RTA_DATA(rta)) != 1) {
                    perror("ipv6 address format error");
                    exit(EXIT_FAILURE);
            }
            req.nh.nlmsg_len =  NLMSG_ALIGN(req.nh.nlmsg_len) +
                                            RTA_LENGTH(sizeof(struct in6_addr));
    
            /* Set rta of IFA_FLAGS */
            rta = (struct rtattr *)(((char *) &req) +
                                            NLMSG_ALIGN(req.nh.nlmsg_len));
            rta->rta_len = RTA_LENGTH(sizeof(uint32_t));
            rta->rta_type = IFA_FLAGS;
            *(uint32_t *)(RTA_DATA(rta)) = IFA_F_MANAGETEMPADDR;
            req.nh.nlmsg_len =  NLMSG_ALIGN(req.nh.nlmsg_len) +
                                            RTA_LENGTH(sizeof(uint32_t));
    
            /* Create netlink socket */
            if ((nlfd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) == -1) {
                    perror("netlink socket create failed");
                    exit(EXIT_FAILURE);
            }
    
            /* Bind sock_loc address as our selected pid. */
            memset(&sock_loc, 0, sizeof(sock_loc));
            sock_loc.nl_family = AF_NETLINK;
            sock_loc.nl_pid = getpid();
            if (bind(nlfd, (struct sockaddr *)&sock_loc, sizeof(sock_loc)) == -1) {
                    perror("bind local netlink socket failed");
                    exit(EXIT_FAILURE);
            }
    
            /* Bind sock_ker address as the kernel (pid 0). */
            memset(&sock_ker, 0, sizeof(sock_ker));
            sock_ker.nl_family = AF_NETLINK;
            sock_ker.nl_pid = 0;
            if (connect(nlfd, (struct sockaddr *) &sock_ker, sizeof(sock_ker)) == -1) {
                    perror("netlink socket connect kernel failed ");
                    exit(EXIT_FAILURE);
            }
    
            /* Send message to kernel */
            if (send(nlfd, &req, req.nh.nlmsg_len, 0) == -1) {
                    perror("send message to kernel error");
                    exit(EXIT_FAILURE);
            }
    
            return EXIT_SUCCESS;
    }

###kernel

here use the socket from kernel. but if you want to implement yourself , just like genl above



otherwise, if you want to delelop fast, some library for netlink perhaps are good chioce, like libnl, libmnl ...
