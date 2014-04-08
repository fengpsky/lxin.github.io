---
layout: post
title: "linux内核代码中的设计模式"
category: linux kernel
excerpt: "映射面向对向里的"
tags: "kernel"
---
{% include JB/setup %}
一谈到重构，设计模式，面向对象这些词，就不禁想到的全是python/c++等这类面向对象语言，也许以前是做这方面的吧，后面看到kernel中的代码后，发现了太多熟悉的代码模型， 才真实地感受到，这些词并不是它们所特有，而是编程思想, 多少年来程序员们总结出来的，不过还得感叹这些设计思想的经典。 代码谁可以写，门槛太底了，一个玩过电脑的小学生，给他一周的培训，也会编程写代码，然后有些人写的代码是诗， 有些人的代码却什么都不是, 只是当下的程序员大多算法上又有多高要求呢， 最大的区别就在这里了。

1. 封装，继承, 多态

封装随处可见， 虽然没有class, 但c的struct 也能将它演义的淋漓尽致。
继承这类太多了，如协议方面的控制块, sock, 派生自sock_common, 双被inet_sock继承， inet_sock又派生出sock_connect_sock/udp_sock, tcp_sock又承载了sock_connect
的确，c中没有虚函数， 却有void *, skb中的cb, net_device中的priv, 给了自己最灵活的扩展.

2.Observer观察者

内核中的通知链， 如网卡的事件， 别处模块随便注册进这个链中， 只要网卡down/up， 就会遍历这个链

3.Singleton单例

c代码也清楚， 全局变量很扯蛋，尽量不用，作为折中的方案，像net namespace中的pernet全局变量，就是一个很类似的作用。
