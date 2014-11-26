---
layout: post
title: "a techtalk about ipsec vpn in linux --ikev2"
category: network security
excerpt: 关于linux vpn的实现
tags: [vpn, ipsec, vpn]
---
{% include JB/setup %}

[vpn.pdf](http://lxin.org/assets/tar/vpn.pdf)

##topic
        *vpn categories
                1. openvpn
                2. libreswan/raccoon
                3. l2tp/pptp
        *ipsec basics
                1. 2-mode, 2-protocol
                2. spi, sa, sp
                3. xfrm && libreswan
        *network security basics
                1. Diffie-Hellman
                2. Certificate, Rsa, Psk
        
        a example for vpnc....
        
        *ikev2 init
                1. 4-shakes
                2. rekeying
        *ikev2 common function
                1. nat-t
                2. address-pool
                3. eap
        *ikev2 how to solve security issue
                1. Denial-of-Service
                2. Eavesdropping
                3. Data Modification
                4. Anti-reply
                5. Identity Spoofing
                6. Compromised key
                7. Man-in-the-Middle
        *ikev1 vs ikev2 vs ikev3

##ike with ipv4&nat-t/xauth/addr-pool
###client ipsec.conf

        config setup
                protostack=netkey
                nat_traversal=yes
                virtual_private=
                oe=off
                nhelpers=0
                plutodebug=all #uncomment this line for performance tests
                plutostderrlog="/tmp/pluto.log"
        conn htoh
                type=tunnel
                authby=secret
                left=192.168.10.1
                right=192.168.11.1
                aggrmode=yes
                phase2alg=3des-sha1
                ike=3des-sha1
                pfs=no
                auto=add
                dpddelay=10
                dpdtimeout=90
                dpdaction=clear
                ikelifetime=8h
                keylife=1h
                leftid=@[left]
                rightid=@[right]
                leftxauthclient=yes
                rightxauthserver=yes
                #leftxauthusername=use1
                #leftaddresspool=192.168.12.100-192.168.12.200
                rightsubnet=192.168.12.0/24
                #rightmodecfgserver=yes
                leftmodecfgclient=yes

###server ipsec.conf

        config setup
                protostack=netkey
                nat_traversal=yes
                virtual_private=
                oe=off
                nhelpers=0
                plutodebug=all #uncomment this line for performance tests
                plutostderrlog="/tmp/pluto.log"
        conn htoh
                type=tunnel
                authby=secret
                left=192.168.11.1
                right=%any
                aggrmode=yes
                phase2alg=3des-sha1
                ike=3des-sha1
                pfs=no
                auto=add
                dpddelay=10
                dpdtimeout=90
                dpdaction=clear
                ikelifetime=8h
                keylife=1h
                rightid=@[left]
                leftid=@[right]
                xauthby=file
                rightxauthclient=yes
                leftxauthserver=yes
                rightaddresspool=192.168.12.100-192.168.12.200
                leftsubnet=192.168.12.0/24
                leftmodecfgserver=yes
                rightmodecfgclient=yes

##ikev2 with ipv6&certs/rsa/psk
###client ipsec.conf

        config setup
                protostack=netkey
                nat_traversal=yes
                plutodebug=all
                plutostderrlog="/tmp/pluto.log"
        #       listen=2001:db8:10::ff:fe00:14
        #       virtual_private=%v6:2001:db8:10::/64,%v6:!2001:db8:11::/64
        conn %default
                connaddrfamily=ipv6
                ikev2=insist
                left=2001:db8:10::ff:fe00:14
                right=2001:db8:11::ff:fe00:15
                leftid=@east
                rightid=@west
        conn psk
        #        leftrsasigkey=%cert
        #        leftcert=clientKey.crt
        #        rightrsasigkey=%cert
        #        rightcert=serverKey.crt
        #       pfs=yes
                auto=add
                type=tunnel
                ike=3des-sha1;modp1024
                phase2=esp
                phase2alg=3des-sha1
                authby=secret
        conn rsa
                leftrsasigkey=0sAQOl9zbxBRD22mJZoa/84UI7cUzpg/ExCMKSHoifIUkTDK2HP2SotBmtvlOSueC/cGnT8T9ZoUJsJNC4IU3JqRew+Cz1c0y17qJhNaywRBxeb7F0ioP0XxbccHSOOCnuYxs92ApmBdMG/m4OeI/KwnsH+vnfBpq47CeObI8hgKRqPCHIUs3baCSso+xbnAyQdnraTC3af6IRxEMfhUsMGFnpqqGiCxd2fFvZrF3hLbcZXv5XcdAecrS8m4hMsW1tET2Dv02AeN6qTVYLitfXG4RanWBwgZ5TVhudyqJpMbVnVOk9D/T1LV58lY22FUkjT3aj9sqetIxQW9WphJjxCuoen3eq/EZ/zwKnWJ77eOKhUIJziSTiPjviVpAVC/ZhnC0N0C6l3aGM2ccWbCMKTK2rw6XbJT+kh2aOgsa7185BINd+mMe4H8ExuIqYKplH3s8kv5I7aGkQYm30EbOcC0edpzbjrlQejx7t5d/kndt6i5OCqmfZrk7ORgm5+rR5
                rightrsasigkey=0sAQPKqFYjVbal7bQ1qwUeQ+34Gm9fHLQTBc4B6cPYmaLodnVUUALT49eoJTptdIMk8MBGlOPzWw/SsmT2tbXh9NHfUd2rwfA4patbFW0x9tw5ERqR/Kxx9VaOpKCLX6HVSGcGYlXj/pyvkff3B8p3FdisaLGRb3/tDWtS3+mNzlbNmeLb3VJjx1Ab9KnwmbtYAyLLs+yOfzgEJ6PI5Dgf2X6Mwk/U91Xu7/5K7afOvmTfTTkpdSG7eDK7+eQu94TmYnGPKk1PYfjJ/qoi8/fc21TNPhEsmzOy5qmardceiz3VvWvyGHBBVH6GiLHdWq9eIuZ1GyYqd7eodHRy0UsyCSgPtf9m75blPZz6ZBXQ8mgR1a+vAJKx4NwI3dnW6RTZs4SkaOlPmuLFllO1iwPZab0W/ECXbuXxt/MO5rRusHmSxzTBbnAKRMy8rmIDNuuq0yYzyblogWLkQ+GgHpJC7Dn5oK5DJDGp6PxnKJNJX5WuVJ47bqAViNGWOPAo+ikd
                type=transport
                ike=3des-sha1;modp1024
                phase2=esp
                phase2alg=3des-sha1
                authby=rsasig
        #        authby=secret
        
        conn cert
        #       obelete
                type=transport
                ike=3des-sha1;modp1024
                phase2=esp
                phase2alg=3des-sha1
                authby=rsasig
                rightrsasigkey=%cert
                rightcert=/etc/ipsec.d/certs/serverKey.crt
        conn certnss
                type=transport
                ike=3des-sha1;modp1024
                phase2=esp
                phase2alg=3des-sha1
                authby=rsasig
                rightrsasigkey=%cert
                rightcert=serverKey.crt
                leftrsasigkey=%cert
                leftcert=clientKey.crt
                leftsendcert=always

###server ipsec.conf

        config setup
                protostack=netkey
                nat_traversal=yes
                plutodebug=all
                plutostderrlog="/tmp/pluto.log"
        #       listen=2001:db8:11::ff:fe00:15
        #       virtual_private=%v6:2001:db8:11::/64,%v6:!2001:db8:10::/64
        conn %default
                connaddrfamily=ipv6
                ikev2=insist
                left=2001:db8:11::ff:fe00:15
                right=%any
                leftid=@west
                rightid=@east
        #       force_busy #dos denial
        conn psk
        #        leftrsasigkey=%cert
        #        leftcert=clientKey.crt
        #        rightrsasigkey=%cert
        #        rightcert=serverKey.crt
        #        pfs=yes
        #       ikelifetime=10m
        #       salifetime=10m
        #       rekey=no
        #       dpdtimeout=1h
        #       compress=yes
                auto=add
                type=tunnel
                ike=3des-sha1;modp1024
                phase2=esp
                phase2alg=3des-sha1
                authby=secret
        conn rsa
                type=transport
                ike=3des-sha1;modp1024
                phase2=esp
                phase2alg=3des-sha1
                authby=rsasig
                rightrsasigkey=0sAQOl9zbxBRD22mJZoa/84UI7cUzpg/ExCMKSHoifIUkTDK2HP2SotBmtvlOSueC/cGnT8T9ZoUJsJNC4IU3JqRew+Cz1c0y17qJhNaywRBxeb7F0ioP0XxbccHSOOCnuYxs92ApmBdMG/m4OeI/KwnsH+vnfBpq47CeObI8hgKRqPCHIUs3baCSso+xbnAyQdnraTC3af6IRxEMfhUsMGFnpqqGiCxd2fFvZrF3hLbcZXv5XcdAecrS8m4hMsW1tET2Dv02AeN6qTVYLitfXG4RanWBwgZ5TVhudyqJpMbVnVOk9D/T1LV58lY22FUkjT3aj9sqetIxQW9WphJjxCuoen3eq/EZ/zwKnWJ77eOKhUIJziSTiPjviVpAVC/ZhnC0N0C6l3aGM2ccWbCMKTK2rw6XbJT+kh2aOgsa7185BINd+mMe4H8ExuIqYKplH3s8kv5I7aGkQYm30EbOcC0edpzbjrlQejx7t5d/kndt6i5OCqmfZrk7ORgm5+rR5
                leftrsasigkey=0sAQPKqFYjVbal7bQ1qwUeQ+34Gm9fHLQTBc4B6cPYmaLodnVUUALT49eoJTptdIMk8MBGlOPzWw/SsmT2tbXh9NHfUd2rwfA4patbFW0x9tw5ERqR/Kxx9VaOpKCLX6HVSGcGYlXj/pyvkff3B8p3FdisaLGRb3/tDWtS3+mNzlbNmeLb3VJjx1Ab9KnwmbtYAyLLs+yOfzgEJ6PI5Dgf2X6Mwk/U91Xu7/5K7afOvmTfTTkpdSG7eDK7+eQu94TmYnGPKk1PYfjJ/qoi8/fc21TNPhEsmzOy5qmardceiz3VvWvyGHBBVH6GiLHdWq9eIuZ1GyYqd7eodHRy0UsyCSgPtf9m75blPZz6ZBXQ8mgR1a+vAJKx4NwI3dnW6RTZs4SkaOlPmuLFllO1iwPZab0W/ECXbuXxt/MO5rRusHmSxzTBbnAKRMy8rmIDNuuq0yYzyblogWLkQ+GgHpJC7Dn5oK5DJDGp6PxnKJNJX5WuVJ47bqAViNGWOPAo+ikd
        
        conn cert
        #       obelete
                type=transport
                ike=3des-sha1;modp1024
                phase2=esp
                phase2alg=3des-sha1
                authby=rsasig
                rightrsasigkey=%cert
                rightcert=clientKey.crt
                leftrsasigkey=%cert
        
        conn certnss
                type=transport
                ike=3des-sha1;modp1024
                phase2=esp
                phase2alg=3des-sha1
                authby=rsasig
                rightrsasigkey=%cert
                rightcert=clientKey.crt
                leftrsasigkey=%cert
                leftcert=serverKey.crt
                leftsendcert=always

