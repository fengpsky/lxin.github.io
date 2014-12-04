---
layout: post
title: "linux and freebsd ipv6 implementation"
category: linux kernel
excerpt: "ipv6 network protocol stack"
tags: "kernel"
---
{% include JB/setup %}
I has tested ipv6 network protocol stack for one year since I joined redhat. I'd like to write some thing or tech-talk about it as a share.  but I cannot, because I'm afaid to waste people's time to listen or to read,  those things I will be able to talk can be found on internet. no mather whether in my blog or tech-talk, the only thing I want to share is what we can not seach from internet. I think that is valuable.

##some import rfc:

    IPv6 Core:
    2460    Internet Protocol, Version 6 (IPv6) Specification S. Deering, R. Hinden [December 1998] Obsoletes RFC1883. Updated by RFC5871
    4861    Neighbor Discovery for IP version 6 (IPv6) T. Narten, E. Nordmark, W. Simpson, H. Soliman [September 2007] Obsoletes RFC2461. Updated by RFC5942
    4862    IPv6 Stateless Address Autoconfiguration S. Thomson, T. Narten, T. Jinmei [September 2007] Obsoletes RFC2462
    1981    Path MTU Discovery for IP version 6 J. McCann, S. Deering, J. Mogul [August 1996]
    4443    Internet Control Message Protocol (ICMPv6) for the Internet Protocol Version 6 (IPv6) Specification A. Conta, S. Deering, M. Gupta, Ed. [March 2006] Obsoletes RFC2463. Updates RFC2780
  
    DHCPv6:
    3315    Dynamic Host Configuration Protocol for IPv6 (DHCPv6) R. Droms, Ed., J. Bound, B. Volz, T. Lemon, C. Perkins, M. Carney [July 2003] Updated by RFC4361
    3646    DNS Configuration options for Dynamic Host Configuration Protocol for IPv6 (DHCPv6) R. Droms, Ed. [December 2003]
    3736    Stateless Dynamic Host Configuration Protocol (DHCP) Service for IPv6 R. Droms [April 2004]
    3633    IPv6 Prefix Options for Dynamic Host Configuration Protocol (DHCP) version 6 O. Troan, R. Droms [December 2003]

    MLDv2:
    3810    Multicast Listener Discovery Version 2 (MLDv2) for IPv6 R. Vida, Ed., L. Costa, Ed. [June 2004] Updates RFC2710 Updated by RFC4604

    IPsec:
    4301    Security Architecture for the Internet Protocol S. Kent, K. Seo [December 2005] Obsoletes: 2401

    IKEv2:
    5996    Internet Key Exchange Protocol Version 2 (IKEv2) C. Kaufman, P. Hoffman,Y. Nir, P. Eronen [September 2010]Obsoletes: 4306, 4718

##some book about ipv6
they all talk about KAME project, which is a project implemented in bsd system. linux trace KAME to achieve itself's ipv6 protocol

[kame1.pdf](http://lxin.org/assets/tar/kame1.pdf)

[kame2.pdf](http://lxin.org/assets/tar/kame2.pdf)
