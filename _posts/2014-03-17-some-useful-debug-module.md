---
layout: post
title: "写的几个有用的module"
category: linux tool
excerpt: "探测代码执行路径，调用网卡接口..."
tags: "autotest" 
--- 
{% include JB/setup %}

1.内核态绕过协议栈发包

    #include <linux/module.h>
    #include <linux/kernel.h>
    #include <linux/init.h>
    #include <linux/netfilter.h>
    #include <linux/skbuff.h>
    #include <linux/ip.h>
    #include <linux/inet.h>
    #include <linux/netdevice.h>
    #include <linux/if_ether.h>
    #include <linux/if_packet.h>
    #include <net/udp.h>
    #include <net/udp.h>
    #include <net/route.h>
    #include <net/icmp.h>
    #include <linux/netfilter_ipv4.h>
    
    MODULE_LICENSE("GPL");
    MODULE_AUTHOR("LUCIEN");
    
    #define ETH "eth4"
    #define SIP "192.168.1.40"
    #define DIP "192.168.1.19"
    #define SPORT 8000
    #define DPORT 8000
    
    unsigned char SMAC[ETH_ALEN] = {0x00,0x00,0xC9,0xE6,0x28,0xE8};
    //unsigned char DMAC[ETH_ALEN] = {0x90,0xE2,0xBA,0x4A,0x64,0xC0};
    unsigned char DMAC[ETH_ALEN] = {0x00,0x1B,0x21,0xA0,0x94,0xB6};
    
    
    unsigned char pkt[8977]="123";
    
    int cp_dev_xmit_udp (char * eth, u_char * smac, u_char * dmac,
    				u_char * pkt, int pkt_len,
    				u_long sip, u_long dip,
    				u_short sport, u_short dport, u_long seq, u_long ack_seq, u_char psh, u_char fin)
    {
    		struct sk_buff * skb = NULL;
    		struct net_device * dev = NULL;
    		struct ethhdr * ethdr = NULL;
    		struct iphdr * iph = NULL;
    		struct udphdr * udph = NULL;
    		u_char * pdata = NULL;
    		int nret = 1;
    		
    		if (NULL == smac || NULL == dmac) 
    			goto out;
    		
    		dev = dev_get_by_name(&init_net, eth);
    		if (NULL == dev)
    			goto out;
    		skb = alloc_skb (pkt_len + sizeof (struct iphdr) + sizeof (struct udphdr) + LL_RESERVED_SPACE (dev), GFP_ATOMIC);
    
    		if (NULL == skb)
    				goto out;
    		skb_reserve (skb, LL_RESERVED_SPACE (dev));//add data and tail
    		skb->dev = dev;
    		skb->pkt_type = PACKET_OTHERHOST;
    		skb->protocol = __constant_htons(ETH_P_IP);
    		skb->ip_summed = CHECKSUM_NONE;
    		skb->priority = 0;
    		
    		skb_set_network_header(skb, 0); //skb->network_header = skb->data + 0;
    		skb_put(skb, sizeof (struct iphdr)); //add tail and len
    		
    		skb_set_transport_header(skb, sizeof (struct iphdr));//skb->transport_header = skb->data + sizeof (struct iphdr)
    		skb_put(skb, sizeof (struct udphdr));
    		
    		pdata = skb_put (skb, pkt_len);
    		{
    				if (NULL != pkt)
    						memcpy (pdata, pkt, pkt_len);
    		}
    
    		{
    				udph = udp_hdr(skb);
    				memset (udph, 0, sizeof (struct udphdr));
    				udph->source = sport;
    				udph->dest = dport;
    				udph->len = htons(pkt_len+sizeof(struct udphdr)); //remember htons
    				udph->check = 0;
    		}
    
    		{
    				iph = ip_hdr(skb);
    				iph->version = 4;
    				iph->ihl = sizeof(struct iphdr)>>2;
    				iph->frag_off = 0;
    				iph->protocol = IPPROTO_UDP;
    				iph->tos = 0;
    				iph->daddr = dip;
    				iph->saddr = sip;
    				iph->ttl = 0x40;
    				iph->tot_len = __constant_htons(skb->len);
    				iph->check = 0;//remember to set 0
    				iph->check = ip_fast_csum((void *)iph,iph->ihl);
    		}
    
    		{
    				ethdr = (struct ethhdr*)skb_push (skb, 14);//reduce data and add len
    				memcpy (ethdr->h_dest, dmac, ETH_ALEN);
    				memcpy (ethdr->h_source, smac, ETH_ALEN);
    				ethdr->h_proto = __constant_htons (ETH_P_IP);
    		}
    				printk("%d\n", udph->len);
    		if (0 > dev_queue_xmit(skb)) goto out;
    		nret = 0;
    out:
    		if (0 != nret && NULL != skb)
    		{
    				dev_put (dev);
    				kfree_skb (skb);
    		}
    		return (nret);
    }
    
    static int __init init(void)
    {
    		cp_dev_xmit_udp (ETH, SMAC, DMAC,pkt, sizeof(pkt),
    						in_aton(SIP),in_aton(DIP),
    						htons(SPORT),htons(DPORT),
    						1, 0, 0, 0);
    		return 0;
    }
    
    static void __exit fini(void)
    {
    }
    
    module_init(init);
    module_exit(fini);

2.kprobe 内核调试通用模板

    #include <linux/module.h>
    #include <linux/kernel.h>
    #include <linux/string.h>
    #include <linux/init.h>
    #include <linux/kprobes.h>
    #include <linux/kallsyms.h>
    #include "asm/ptrace.h" 
    #include "asm/current.h" 
    #include "linux/utsname.h" 
    #include "linux/tcp.h"      
    #include "linux/in.h"
    
    struct kprobe probe; 
    
    static int pre_probe(struct kprobe *probe, struct pt_regs *regs) 
    { 
    	printk("hit it\n");
    	return 0; 
    } 
    
    static void post_probe(struct kprobe *probe, struct pt_regs *regs, unsigned long flags) 
    {} 
    
    static int __init kprobe_init(void) 
    { 
    	probe.pre_handler = pre_probe; 
    	probe.post_handler = post_probe; 
    
    	probe.addr = (kprobe_opcode_t *) kallsyms_lookup_name("#####"); 
    	if (probe.addr == NULL) { 
    		return 1; 
    	} 
    
    	register_kprobe(&probe); 
    	printk("register probe driver.n"); 
    	return 0; 
    } 
    
    static void __exit kprobe_exit(void) 
    { 
    	unregister_kprobe(&probe); 
    	printk("unregister probe driver.n"); 
    	return; 
    } 
    
    module_init(kprobe_init); 
    module_exit(kprobe_exit); 
    
    MODULE_AUTHOR("LUCIEN"); 
    MODULE_LICENSE("GPL");

3. netfilter 调用

    #include <linux/module.h>
    #include <linux/kernel.h>
    #include <linux/ip.h>
    #include <linux/netfilter_ipv4.h>
    #include <net/protocol.h>
    
    static struct nf_hook_ops nfho;
    
    unsigned int hook_func(unsigned int hooknum,
                    struct sk_buff **skb,
                    const struct net_device *in,
                    const struct net_device *out,
                    int (*okfn)(struct sk_buff *))
    {
            int protocol = (*skb)->nh.iph->protocol;
            if(protocol==132){
                    struct sk_buff *skb_l = skb_clone(*skb,GFP_ATOMIC);
                    okfn(skb_l);
                    struct sk_buff *skb_l2 = skb_clone(*skb,GFP_ATOMIC);
                    okfn(skb_l2);
                    struct sk_buff *skb_l3 = skb_clone(*skb,GFP_ATOMIC);
                    okfn(skb_l3);
            }
            return NF_ACCEPT;
    }
    
    int init_module()
    {
            nfho.hook = hook_func;
            nfho.hooknum  = NF_IP_LOCAL_IN;
            nfho.pf       = PF_INET;
            nfho.priority = NF_IP_PRI_FIRST;
    
            nf_register_hook(&nfho);
    
            return 0;
    }
    void cleanup_module()
    {
            nf_unregister_hook(&nfho);
    
    }
