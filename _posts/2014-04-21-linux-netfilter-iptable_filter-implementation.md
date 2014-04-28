---
layout: post
title: "linux netfilter iptable_filter (xt_table)"
category: linux kernel
excerpt: linux netfilter中比较简单的一个表的实现
tags: [kernel]
---
{% include JB/setup %}
netfilter对于linux网络协议栈来说非常重要,　因为是串行，可以对包做更多的处理, 目前己经由最开始的五个hooks点，增加到了18个，　分别对应于iptables(5)/ip6tables(5)/ebtables(6)/arptable(3),而这些hook点就是我们所说的链，　对于iptables中，也就是最常说的那5个点,PRE_ROUTING/POST_ROUTING/LOCAL_IN/LOCAL_OUT/FORWARD；　表则指是对数据包某一类行为的集合，　里面管理了很多规则；规则由match和target组成，　match相当于我们添加规则时的匹配条件，如tcp的端口范围等，　　target就是处理方式了，如accept/reject；　因些一个规则由0-n个match＋1个target组成。

##重要的数据结构

###xt_af

    struct xt_af {
            struct mutex mutex;
            struct list_head match;
            struct list_head target;
    #ifdef CONFIG_COMPAT
            struct mutex compat_mutex;
            struct compat_delta *compat_tab;
            unsigned int number; /* number of slots in compat_tab[] */
            unsigned int cur; /* number of used slots in compat_tab[] */
    #endif
    };

static struct xt_af *xt;一个全局的结构体，　用来管理注册的match和target,

### netns_xt

    struct netns_xt {
            struct list_head tables[NFPROTO_NUMPROTO];
            bool notrack_deprecated_warning;
    #if defined(CONFIG_BRIDGE_NF_EBTABLES) || \
        defined(CONFIG_BRIDGE_NF_EBTABLES_MODULE)
            struct ebt_table *broute_table;
            struct ebt_table *frame_filter;
            struct ebt_table *frame_nat;
    #endif
    #if IS_ENABLED(CONFIG_IP_NF_TARGET_ULOG)
            bool ulog_warn_deprecated;
    #endif
    #if IS_ENABLED(CONFIG_BRIDGE_EBT_ULOG)
            bool ebt_ulog_warn_deprecated;
    #endif
    };
    #endif

名字空间里的成员，　用来管理全局注册的表.

###xt_table

    struct xt_table {
            struct list_head list;

            /* What hooks you will enter on */
            unsigned int valid_hooks;

            /* Man behind the curtain... */
            struct xt_table_info *private;

            /* Set this to THIS_MODULE if you are a module, otherwise NULL */
            struct module *me;

            u_int8_t af;            /* address/protocol family */
            int priority;           /* hook order */

            /* A unique name... */
            const char name[XT_TABLE_MAXNAMELEN];
    };

代表一个表的通用信息

###xt_table_info

    struct xt_table_info {
            /* Size per table */
            unsigned int size;
            /* Number of entries: FIXME. --RR */
            unsigned int number;
            /* Initial number of entries. Needed for module usage count */
            unsigned int initial_entries;

            /* Entry points and underflows */
            unsigned int hook_entry[NF_INET_NUMHOOKS];
            unsigned int underflow[NF_INET_NUMHOOKS];

            /*
             * Number of user chains. Since tables cannot have loops, at most
             * @stacksize jumps (number of user chains) can possibly be made.
             */
            unsigned int stacksize;
            unsigned int __percpu *stackptr;
            void ***jumpstack;
            /* ipt_entry tables: one per CPU */
            /* Note : this field MUST be the last one, see XT_TABLE_INFO_SZ */
            void *entries[1];
    };

一个表的真实信息, 其中hook_entry和underflowe用于描述链的分界, entries才是存在数据的地方，　stackptr是在jump过程中记录调用栈的信息

###ipt_replace

    struct ipt_replace {
            /* Which table. */
            char name[XT_TABLE_MAXNAMELEN];

            /* Which hook entry points are valid: bitmask.  You can't
               change this. */
            unsigned int valid_hooks;

            /* Number of entries */
            unsigned int num_entries;

            /* Total size of new entries */
            unsigned int size;

            /* Hook entry points. */
            unsigned int hook_entry[NF_INET_NUMHOOKS];

            /* Underflow points. */
            unsigned int underflow[NF_INET_NUMHOOKS];

            /* Information about old entries: */
            /* Number of counters (must be equal to current number of entries). */
            unsigned int num_counters;
            /* The old entries' counters. */
            struct xt_counters __user *counters;

            /* The entries (hang off end: not really an array). */
            struct ipt_entry entries[0];
    };

很重要的一个结构体，　由于对表的操作iptables放到了用户态，　等处理完了会替换掉当时的内核中的表，　而替换时的信息就是由这个结构组织传递的

###ipt_entry

    struct ipt_entry {
            struct ipt_ip ip;

            /* Mark with fields that we care about. */
            unsigned int nfcache;

            /* Size of ipt_entry + matches */
            __u16 target_offset;
            /* Size of ipt_entry + matches + target */
            __u16 next_offset;

            /* Back pointer */
            unsigned int comefrom;

            /* Packet and byte counters. */
            struct xt_counters counters;

            /* The matches (if any), then the target. */
            unsigned char elems[0];
    };

描述一条规则的，其中的match 和target 的offset直接可以看出来

###xt_entry_match，xt_match

    struct xt_entry_match {
            union {
                    struct {
                            __u16 match_size;

                            /* Used by userspace */
                            char name[XT_EXTENSION_MAXNAMELEN];
                            __u8 revision;
                    } user;
                    struct {
                            __u16 match_size;

                            /* Used inside the kernel */
                            struct xt_match *match;
                    } kernel;

                    /* Total length */
                    __u16 match_size;
            } u;

            unsigned char data[0];
    };

    struct xt_match {
            struct list_head list;

            const char name[XT_EXTENSION_MAXNAMELEN];
            u_int8_t revision;

            /* Return true or false: return FALSE and set *hotdrop = 1 to
               force immediate packet drop. */
            /* Arguments changed since 2.6.9, as this must now handle
               non-linear skb, using skb_header_pointer and
               skb_ip_make_writable. */
            bool (*match)(const struct sk_buff *skb,
                          struct xt_action_param *);

            /* Called when user tries to insert an entry of this type. */
            int (*checkentry)(const struct xt_mtchk_param *);

            /* Called when entry of this type deleted. */
            void (*destroy)(const struct xt_mtdtor_param *);
    #ifdef CONFIG_COMPAT
            /* Called when userspace align differs from kernel space one */
            void (*compat_from_user)(void *dst, const void *src);
            int (*compat_to_user)(void __user *dst, const void *src);
    #endif
            /* Set this to THIS_MODULE if you are a module, otherwise NULL */
            struct module *me;

            const char *table;
            unsigned int matchsize;
    #ifdef CONFIG_COMPAT
            unsigned int compatsize;
    #endif
            unsigned int hooks;
            unsigned short proto;

            unsigned short family;
    };

这两个结构体是用来描述规则里的匹配的

###xt_entry_target, xt_target
    struct xt_entry_target {
            union {
                    struct {
                            __u16 target_size;

                            /* Used by userspace */
                            char name[XT_EXTENSION_MAXNAMELEN];
                            __u8 revision;
                    } user;
                    struct {
                            __u16 target_size;

                            /* Used inside the kernel */
                            struct xt_target *target;
                    } kernel;

                    /* Total length */
                    __u16 target_size;
            } u;

            unsigned char data[0];
    };

    struct xt_target {
            struct list_head list;

            const char name[XT_EXTENSION_MAXNAMELEN];
            u_int8_t revision;

            /* Returns verdict. Argument order changed since 2.6.9, as this
               must now handle non-linear skbs, using skb_copy_bits and
               skb_ip_make_writable. */
            unsigned int (*target)(struct sk_buff *skb,
                                   const struct xt_action_param *);

            /* Called when user tries to insert an entry of this type:
               hook_mask is a bitmask of hooks from which it can be
               called. */
            /* Should return 0 on success or an error code otherwise (-Exxxx). */
            int (*checkentry)(const struct xt_tgchk_param *);

            /* Called when entry of this type deleted. */
            void (*destroy)(const struct xt_tgdtor_param *);
    #ifdef CONFIG_COMPAT
            /* Called when userspace align differs from kernel space one */
            void (*compat_from_user)(void *dst, const void *src);
            int (*compat_to_user)(void __user *dst, const void *src);
    #endif
            /* Set this to THIS_MODULE if you are a module, otherwise NULL */
            struct module *me;

            const char *table;
            unsigned int targetsize;
    #ifdef CONFIG_COMPAT
            unsigned int compatsize;
    #endif
            unsigned int hooks;
            unsigned short proto;

            unsigned short family;
    };

与match相似，　不过是用来描述规则里的target的。

### xt_standard_target

    struct xt_standard_target {
            struct xt_entry_target target;
            int verdict;
    };

一个特殊的xt_entry_target, 其中的verdict更为神秘，后面再说

以上的这些结构体的关系事实上都是在描述一段连续的内存，以及它们之前的关系都可以在这个张图中看到, http://blog.chinaunix.net/photo/24896_061206192551.jpg, 当然有一些结构体的名称己经变了，但依然可以看出它们之间的关系，　另外上面提到，对于这些表的操作都是拷贝进用户态操作，完后再替换进内核态，因些在内核态同样有些相似的类型的结构体，　不过也有很多不同的地方，　毕竟它还要协助完成表的操作。

### xtables_globals

    struct xtables_globals
    {
            unsigned int option_offset;
            const char *program_name, *program_version;
            struct option *orig_opts;
            struct option *opts;
            void (*exit_err)(enum xtables_exittype status, const char *msg, ...) __attribute__((noreturn, format(printf,2,3)));
    };

struct xtables_globals iptables_globals 操作时保存一些命令行选项

### iptables_command_state

    struct iptables_command_state {
            union {
                    struct ipt_entry fw;
                    struct ip6t_entry fw6;
            };
            int invert;
            int c;
            unsigned int options;
            struct xtables_rule_match *matches;
            struct xtables_target *target;
            char *protocol;
            int proto_used;
            const char *jumpto;
            char **argv;
    };

保存解析出来的一些参数，　重要的如ip_entry, matches, target, protocol,  jumpto, 在解析命令行参数时用，　最后将参数传递给要操作的函数。

### xtc_handle

    struct xtc_handle {
            int sockfd;
            int changed;                     /* Have changes been made? */

            struct list_head chains;

            struct chain_head *chain_iterator_cur;
            struct rule_head *rule_iterator_cur;

            unsigned int num_chains;         /* number of user defined chains */

            struct chain_head **chain_index;   /* array for fast chain list access*/
            unsigned int        chain_index_sz;/* size of chain index array */

            int sorted_offsets; /* if chains are received sorted from kernel,
                                 * then the offsets are also sorted. Says if its
                                 * possible to bsearch offsets using chain_index.
                                 */

            STRUCT_GETINFO info;
            STRUCT_GET_ENTRIES *entries;
    };

用户态用来描述一个表，　chains它下面的链，　info用来保存从内核态中获取的表的private信息，　内容对应kernel中的xt_table_info, entries用来存放获取的内核中所有的规则.

### chain_head

    struct xtc_handle {
            int sockfd;
            int changed;                     /* Have changes been made? */

            struct list_head chains;

            struct chain_head *chain_iterator_cur;
            struct rule_head *rule_iterator_cur;

            unsigned int num_chains;         /* number of user defined chains */

            struct chain_head **chain_index;   /* array for fast chain list access*/
            unsigned int        chain_index_sz;/* size of chain index array */

            int sorted_offsets; /* if chains are received sorted from kernel,
                                 * then the offsets are also sorted. Says if its
                                 * possible to bsearch offsets using chain_index.
                                 */

            STRUCT_GETINFO info;
            STRUCT_GET_ENTRIES *entries;
    };

用户态用来描述一个链，　rules是它下面的规则，

### rule_head

    struct rule_head
    {
            struct list_head list;
            struct chain_head *chain;
            struct counter_map counter_map;

            unsigned int index;             /* index (needed for counter_map) */
            unsigned int offset;            /* offset in rule blob */

            enum iptcc_rule_type type;
            struct chain_head *jump;        /* jump target, if IPTCC_R_JUMP */

            unsigned int size;              /* size of entry data */
            STRUCT_ENTRY entry[0];
    };

用户态用来描述一个规则，　entry为其对应的信息。其类型就是下面的ipt_entry

### ipt_entry

    struct ipt_entry {
            struct ipt_ip ip;

            /* Mark with fields that we care about. */
            unsigned int nfcache;

            /* Size of ipt_entry + matches */
            __u16 target_offset;
            /* Size of ipt_entry + matches + target */
            __u16 next_offset;

            /* Back pointer */
            unsigned int comefrom;

            /* Packet and byte counters. */
            struct xt_counters counters;

            /* The matches (if any), then the target. */
            unsigned char elems[0];
    };

很明显和kernel中一样的结构体，它就是用来存入kernel中取出的数据的, 另外，　xt_match/xt_entry_match/xt_entry_target/xt_target/ipt_replace也是一样,对应的用户态也都会有。

### ipt_getinfo

    struct ipt_getinfo {
            /* Which table: caller fills this in. */
            char name[XT_TABLE_MAXNAMELEN];

            /* Kernel fills these in. */
            /* Which hook entry points are valid: bitmask */
            unsigned int valid_hooks;

            /* Hook entry points: one per netfilter hook. */
            unsigned int hook_entry[NF_INET_NUMHOOKS];

            /* Underflow points. */
            unsigned int underflow[NF_INET_NUMHOOKS];

            /* Number of entries */
            unsigned int num_entries;

            /* Size of entries. */
            unsigned int size;
    };

很想内核中的xt_table_info，　对，　它就是用来存放取出来的table info信息的，　在xtc_table结构中

### ipt_get_entries

    struct ipt_get_entries {
            /* Which table: user fills this in. */
            char name[XT_TABLE_MAXNAMELEN];

            /* User fills this in: total entry size. */
            unsigned int size;

            /* The entries. */
            struct ipt_entry entrytable[0];
    };

存放从kenrel中来的多个规则

### xtables_rule_match, xtables_match

    struct xtables_rule_match {
            struct xtables_rule_match *next;
            struct xtables_match *match;
            /* Multiple matches of the same type: the ones before
               the current one are completed from parsing point of view */
            bool completed;
    };

    struct xtables_match
    {
            /*
             * ABI/API version this module requires. Must be first member,
             * as the rest of this struct may be subject to ABI changes.
             */
            const char *version;

            struct xtables_match *next;

            const char *name;
            const char *real_name;

            /* Revision of match (0 by default). */
            u_int8_t revision;

            /* Extension flags */
            u_int8_t ext_flags;

            u_int16_t family;

            /* Size of match data. */
            size_t size;

            /* Size of match data relevant for userspace comparison purposes */
            size_t userspacesize;

            /* Function which prints out usage message. */
            void (*help)(void);

            /* Initialize the match. */
            void (*init)(struct xt_entry_match *m);

            /* Function which parses command options; returns true if it
               ate an option */
            /* entry is struct ipt_entry for example */
            int (*parse)(int c, char **argv, int invert, unsigned int *flags,
                         const void *entry,
                         struct xt_entry_match **match);

            /* Final check; exit if not ok. */
            void (*final_check)(unsigned int flags);

            /* Prints out the match iff non-NULL: put space at end */
            /* ip is struct ipt_ip * for example */
            void (*print)(const void *ip,
                          const struct xt_entry_match *match, int numeric);
            /* Saves the match info in parsable form to stdout. */
            /* ip is struct ipt_ip * for example */
            void (*save)(const void *ip, const struct xt_entry_match *match);

            /* Print match name or alias */
            const char *(*alias)(const struct xt_entry_match *match);

            /* Pointer to list of extra command-line options */
            const struct option *extra_opts;

            /* New parser */
            void (*x6_parse)(struct xt_option_call *);
            void (*x6_fcheck)(struct xt_fcheck_call *);
            const struct xt_option_entry *x6_options;

            /* Size of per-extension instance extra "global" scratch space */
            size_t udata_size;

            /* Ignore these men behind the curtain: */
            void *udata;
            unsigned int option_offset;
            struct xt_entry_match *m;
            unsigned int mflags;
            unsigned int loaded; /* simulate loading so options are merged properly */
    };

用户态组织match时用到，　主要做一些初始化设置等工作。

### xtables_target

    struct xtables_target
    {
            /*
             * ABI/API version this module requires. Must be first member,
             * as the rest of this struct may be subject to ABI changes.
             */
            const char *version;

            struct xtables_target *next;


            const char *name;

            /* Real target behind this, if any. */
            const char *real_name;

            /* Revision of target (0 by default). */
            u_int8_t revision;

            /* Extension flags */
            u_int8_t ext_flags;

            u_int16_t family;


            /* Size of target data. */
            size_t size;

            /* Size of target data relevant for userspace comparison purposes */
            size_t userspacesize;

            /* Function which prints out usage message. */
            void (*help)(void);

            /* Initialize the target. */
            void (*init)(struct xt_entry_target *t);

            /* Function which parses command options; returns true if it
               ate an option */
            /* entry is struct ipt_entry for example */
            int (*parse)(int c, char **argv, int invert, unsigned int *flags,
                         const void *entry,
                         struct xt_entry_target **targetinfo);

            /* Final check; exit if not ok. */
            void (*final_check)(unsigned int flags);

            /* Prints out the target iff non-NULL: put space at end */
            void (*print)(const void *ip,
                          const struct xt_entry_target *target, int numeric);

            /* Saves the targinfo in parsable form to stdout. */
            void (*save)(const void *ip,
                         const struct xt_entry_target *target);

            /* Print target name or alias */
            const char *(*alias)(const struct xt_entry_target *target);

            /* Pointer to list of extra command-line options */
            const struct option *extra_opts;

            /* New parser */
            void (*x6_parse)(struct xt_option_call *);
            void (*x6_fcheck)(struct xt_fcheck_call *);
            const struct xt_option_entry *x6_options;

            size_t udata_size;

            /* Ignore these men behind the curtain: */
            void *udata;
            unsigned int option_offset;
            struct xt_entry_target *t;
            unsigned int tflags;
            unsigned int used;
            unsigned int loaded; /* simulate loading so options are merged properly */
    };

同match，　用户态组织target用到。

一不说心帖了这么的结构体，　只是因为下面都会用到。

##初始化

iptables_filter.ko

1. iptable_filter_init中完成，首先注册pernet操作，　register_pernet_subsys(&iptable_filter_net_ops);

        static struct pernet_operations iptable_filter_net_ops = {
                .init = iptable_filter_net_init,
                .exit = iptable_filter_net_exit,
        }；

   最重要的一步，　xt_hook_link(&packet_filter, iptable_filter_hook);　注册了hook. 从这个函数里可以看出来，　filter的每个hook点都会调用这个接口

        for (i = 0, hooknum = 0; i < num_hooks && hook_mask != 0;
             hook_mask >>= 1, ++hooknum) {
                if (!(hook_mask & 1))
                        continue;
                ops[i].hook     = fn;
                ops[i].owner    = table->me;
                ops[i].pf       = table->af;
                ops[i].hooknum  = hooknum;
                ops[i].priority = table->priority;
                ++i;
        }

        ret = nf_register_hooks(ops, num_hooks);

2. 在iptable_filter_net_init中，先申请一个ipt_replace *repl, 里面的成员都是通过packet_filter初始化的，由xt_alloc_initial_table这个宏完成。

        static const struct xt_table packet_filter = {
                .name           = "filter",
                .valid_hooks    = FILTER_VALID_HOOKS,
                .me             = THIS_MODULE,
                .af             = NFPROTO_ARP,
                .priority       = NF_IP_PRI_FILTER,
        }; 　

3. 接着会初始化这个表的第一个target中的verdict.

        ((struct ipt_standard *)repl->entries)[1].target.verdict =
                forward ? -NF_ACCEPT - 1 : -NF_DROP - 1;

4. 最后net->ipv4.iptable_filter = ipt_register_table(net, &packet_filter, repl);完成注册，　并将注册成的filter 表给pernet全局变量

5. 注册过程中，　先申请xt_table_info *new_info, 再调用translate_table把repl解析出的信息给new_info, 最后调用xt_register_table，　将原始的table kmemdup一份table, 再将new_info给dump出来的table->private成员。当然kmemdup是必要的，　毕竟有ns存在，　原始的总在作为模板被dup, 之后再将链表添加进上面提到的pernet netns_xt全局变量中

6. translate_table很显然这个函数很重要，　添加规则时同样也会调用到，　这里就提前分析了，首先，检查所有规则的偏移是否都合法，由check_entry_size_and_hooks函数来完成每项检测, 具体的方式主要是边界的正确性, 如果对entries的结构很清楚，这个函数是很容易理解的。

        xt_entry_foreach(iter, entry0, newinfo->size) {
                ret = check_entry_size_and_hooks(iter, newinfo, entry0,
                                                 entry0 + repl->size,
                                                 repl->hook_entry,
                                                 repl->underflow,
                                                 repl->valid_hooks);
                if (ret != 0)
                        return ret;
                ++i;
                if (strcmp(ipt_get_target(iter)->u.user.name,
                    XT_ERROR_TARGET) == 0)
                        ++newinfo->stacksize;
        }

7. 经常上面的检测，　hook_entry与underflow应该都有了正确值，　不再是0xfffffff, 因些再对这两项进行检测，

8. 接下来是mark_source_chains，　这个函数比较有趣，　是要检测不存在规则环的，检测方式是按链进行，　先遍历每个链，　在链中拿到规则遍历ipt_entry e, 再从e中取出target, 再配个e->comefrom进行判断，看代码就会发现它不仅是对环的检测，还有其它像verdict检测.

9. 调用check_match/target 对所有的match/target再进行合法性检测, find_check_entry检测很复杂，　但最终会调用target/match->check_entry().

        xt_entry_foreach(iter, entry0, newinfo->size) {
                ret = find_check_entry(iter, net, repl->name, repl->size);
                if (ret != 0)
                        break;
                ++i;
        }

10. 最后为每一个cpu copy一份entries，　忘记说newinfo->entries是percpu变量。

        for_each_possible_cpu(i) {
                if (newinfo->entries[i] && newinfo->entries[i] != entry0)
                        memcpy(newinfo->entries[i], entry0, newinfo->size);
        }

##创建

由于对于表的操作都是在用户态进行的，　因此对于规则的添加同样也不例外，　因此进入iptables-1.4.21的代码分析：

iptables_main()为入口

1. xtables_init_all首先初始化一些全局的变量信息。存在iptable_globals中，　上面提到过这个结构。

2. do_command4是真正读取内核中的表并完成添加的函数

3. 最后会将修改好的表通过iptc_commit函数更新进内核表，当然上面的读取和这里的更新都是用set/getsockopt接口

4. do_command4中对各种参数进行解析，这里以" iptables -A INPUT -p tcp --dport 1000 -J ACCEPT"为例，当然中间也会解释一些对于一些复杂规则的接口

5. 一个大循环用来解析参数，-A INPUT：

                        add_command(&command, CMD_APPEND, CMD_NONE,
                                    cs.invert);
                        chain = optarg;

    command中添加CMD_APPEND命令，　chain 中会保存INPUT字符串.

    -p tcp:

                        set_option(&cs.options, OPT_PROTOCOL, &cs.fw.ip.invflags,
                                   cs.invert);

                        /* Canonicalize into lower case */
                        for (cs.protocol = optarg; *cs.protocol; cs.protocol++)
                                *cs.protocol = tolower( *cs.protocol);

                        cs.protocol = optarg;
                        cs.fw.ip.proto = xtables_parse_protocol(cs.protocol);

    解析协议，通过xtables_chain_protos将协议字符串转成对应的num, 给cs.fw.ip.proto

    --dport 1000:

    会交给command_default接口处理，这个接口会调用两次，第一次时，由于cs.matches为null, 在这个接口中会先调用m = load_proto(cs);加载相应的协议，　load_proto->find_proto->xtables_find_match, 这个函数会生成xtables_rule_match/xtables_xmatch 并返回。最终会存在cs.matches中，也就是tcp对应的match:

    static struct xtables_match tcp_match = {
            .family         = NFPROTO_UNSPEC,
            .name           = "tcp",
            .version        = XTABLES_VERSION,
            .size           = XT_ALIGN(sizeof(struct xt_tcp)),
            .userspacesize  = XT_ALIGN(sizeof(struct xt_tcp)),
            .help           = tcp_help,
            .init           = tcp_init,
            .parse          = tcp_parse,
            .print          = tcp_print,
            .save           = tcp_save,
            .extra_opts     = tcp_opts,
    };

    第二次时，　由于cs->matches已经有值，进入循环，并且调用xtables_option_mpcall拿到dport参数, 这个函数会调用tcp_parse会解析参数，最终会放到xt_tcp中，　而xt_tcp便是：struct xt_tcp *tcpinfo = (struct xt_tcp *)( *match)->data; 即放进了xt_match 的data中

        for (matchp = cs->matches; matchp; matchp = matchp->next) {
                m = matchp->match;

                if (matchp->completed ||
                    (m->x6_parse == NULL && m->parse == NULL))
                        continue;
                if (cs->c < matchp->match->option_offset ||
                    cs->c >= matchp->match->option_offset + XT_OPTION_OFFSET_SCALE)
                        continue;
                xtables_option_mpcall(cs->c, cs->argv, cs->invert, m, &cs->fw);
                return 0;
        }

        /* Try loading protocol */
        m = load_proto(cs);

    -j ACCEPT:

    command_jump(&cs);这个函数中先调用parse_target，拿到"ACCEPT", cs->jumpto = parse_target(optarg); 再调用xtables_find_target(), 去load target, 与match相似, 放进cs->target

        static struct xtables_target standard_target = {
                .family         = NFPROTO_UNSPEC,
                .name           = "standard",
                .version        = XTABLES_VERSION,
                .size           = XT_ALIGN(sizeof(int)),
                .userspacesize  = XT_ALIGN(sizeof(int)),
                .help           = standard_help,
        };

    在xtables_find_target中，将以下归为standard_target处理。

        if (strcmp(name, "") == 0
            || strcmp(name, XTC_LABEL_ACCEPT) == 0
            || strcmp(name, XTC_LABEL_DROP) == 0
            || strcmp(name, XTC_LABEL_QUEUE) == 0
            || strcmp(name, XTC_LABEL_RETURN) == 0)
                name = "standard";

    关于target与match的解析，经常会看到xtables_pending_targets／xtables_pending_matches,这里面其实存的是己load的模块，首先会在这个链中找，找不到才会加载。

5. 参数解析完后，　接下来开始从内核中取出INPUT表，xtc_handle　*handle = iptc_init(　*table); 在这个函数中，　做个两个操作：

        if (getsockopt(sockfd, TC_IPPROTO, SO_GET_INFO, &info, &s) < 0) {
                close(sockfd);
                return NULL;
        }
        ...
        if (getsockopt(h->sockfd, TC_IPPROTO, SO_GET_ENTRIES, h->entries,
                       &tmp) < 0)
                goto error;

    分别取出ipt_info 放进struct ipt_getinfo  h->info, entries放进h->entries(这是那个很长的数据块), 最后交给parse_table(h)，　完成表的解析，这个函数功能强大:

        ENTRY_ITERATE(h->entries->entrytable, h->entries->size,
                        cache_add_entry, h, &prev, &num);

    这个宏完成了链和规则的解析，　即转换成用户态的chain_head与rule_head,  前者被挂在上面的h上，　后者当然被挂在前者上。 进一步，　再做一些fixup

        list_for_each_entry(c, &h->chains, list) {
                struct rule_head *r;
                list_for_each_entry(r, &c->rules, list) {
                        struct chain_head *lc;
                        STRUCT_STANDARD_TARGET *t;

                        if (r->type != IPTCC_R_JUMP)
                                continue;

                        t = (STRUCT_STANDARD_TARGET *)GET_TARGET(r->entry);
                        lc = iptcc_find_chain_by_offset(h, t->verdict);
                        if (!lc)
                                return -1;
                        r->jump = lc;
                        lc->references++;
                }
        }

6. 考虑到jumpto可能是一个链，则多了下面的处理:

                if (!cs.target
                    && (strlen(cs.jumpto) == 0
                        || iptc_is_chain(cs.jumpto, *handle))) {
                        size_t size;

                        cs.target = xtables_find_target(XT_STANDARD_TARGET,
                                         XTF_LOAD_MUST_SUCCEED);

                        size = sizeof(struct xt_entry_target)
                                + cs.target->size;
                        cs.target->t = xtables_calloc(1, size);
                        cs.target->t->u.target_size = size;
                        strcpy(cs.target->t->u.user.name, cs.jumpto);
                        if (!iptc_is_chain(cs.jumpto, *handle))
                                cs.target->t->u.user.revision = cs.target->revision;
                        xs_init_target(cs.target);
                }

    它会以standart target 来处理，并且瘵cs.jumpto 放进xt_entry_target的user.name中, 再一次说明下entries的数据格式很重要，　能不能理解自定义链的实现完全得靠这个

7. e = generate_entry(&cs.fw, cs.matches, cs.target->t);　将前面组成的match/target完美转换成一个struct ipt_entry,

8. 最后：

        case CMD_APPEND:
                ret = append_entry(chain, e,
                                   nsaddrs, saddrs, smasks,
                                   ndaddrs, daddrs, dmasks,
                                   cs.options&OPT_VERBOSE,
                                   *handle);

    它要做的事情很简单，就是将刚生成的e ,转换成rule_head, append在对应的chain_head上就完成。

9. 用户态最后一步iptc_commit(handle); 这个函数要做的最重要的一步就是：

        ret = setsockopt(handle->sockfd, TC_IPPROTO, SO_SET_REPLACE, repl,
                         sizeof(　*repl) + repl->size);

    将整个表送至kernel, 而struct ipt_replace *repl正是载体，　因此在这之前，是需要将xt_handler转成repl.

    另外，　iptc_commit还更新了counters, 就没必要分析了。

10. sockopt到内核态iptables对应的是：

        static struct nf_sockopt_ops ipt_sockopts = {
                .pf             = PF_INET,
                .set_optmin     = IPT_BASE_CTL,
                .set_optmax     = IPT_SO_SET_MAX+1,
                .set            = do_ipt_set_ctl,
        #ifdef CONFIG_COMPAT
                .compat_set     = compat_do_ipt_set_ctl,
        #endif
                .get_optmin     = IPT_BASE_CTL,
                .get_optmax     = IPT_SO_GET_MAX+1,
                .get            = do_ipt_get_ctl,
        #ifdef CONFIG_COMPAT
                .compat_get     = compat_do_ipt_get_ctl,
        #endif
                .owner          = THIS_MODULE,
        };

    路径为do_ipt_set_ctl->do_replace():

        newinfo = xt_alloc_table_info(tmp.size);
        if (!newinfo)
                return -ENOMEM;

        /* choose the copy that is on our node/cpu */
        loc_cpu_entry = newinfo->entries[raw_smp_processor_id()];
        if (copy_from_user(loc_cpu_entry, user + sizeof(tmp),
                           tmp.size) != 0) {
                ret = -EFAULT;
                goto free_newinfo;
        }

        ret = translate_table(net, newinfo, loc_cpu_entry, &tmp);
        if (ret != 0)
                goto free_newinfo;

        duprintf("Translated table\n");

        ret = __do_replace(net, tmp.name, tmp.valid_hooks, newinfo,
                           tmp.num_counters, tmp.counters);


    先申请newinfo, 再将entries拷贝至newinfo->entries. 接着调用translate_table, 这个之前己经分析过了，　最后就是调用__do_replace->xt_replace_table(), 这个函数中，再申请初始化一些成员，最后将table->private = newinfo;完成替换。另外，　xt_jumpstack_alloc(newinfo);这个是为处理时jump用的。

##包处理

从初始化部分可以看出，　iptable_filter_hook是包处理的接口，　无论是哪个hook点, 这个函数调用的是ipt_do_table，　我们只需要分析这个函数就可以了。

1. struct xt_action_param acpar, 拿到处理时需要的一些参数

        struct xt_action_param {
                union {
                        const struct xt_match *match;
                        const struct xt_target *target;
                };
                union {
                        const void *matchinfo, *targinfo;
                };
                const struct net_device *in, *out;
                int fragoff;
                unsigned int thoff;
                unsigned int hooknum;
                u_int8_t family;
                bool hotdrop;
        };

        acpar.fragoff = ntohs(ip->frag_off) & IP_OFFSET;
        acpar.thoff   = ip_hdrlen(skb);
        acpar.hotdrop = false;
        acpar.in      = in;
        acpar.out     = out;
        acpar.family  = NFPROTO_IPV4;
        acpar.hooknum = hook;

    再拿到jumpstack信息和ipt_entry e:

        table_base = private->entries[cpu];
        jumpstack  = (struct ipt_entry **)private->jumpstack[cpu];
        stackptr   = per_cpu_ptr(private->stackptr, cpu);
        origptr    = *stackptr;

        e = get_entry(table_base, private->hook_entry[hook]);

2. 接着进入一个大循环，去遍历每指定链上的规则，　对每一个规则，首先遍历其matches, 如果有一个不匹配，则直接no_match, e = ipt_next_entry(e);进入下一条规则，　如果全都满足，则取出其target t = ipt_get_target(e);继续往下走

                xt_ematch_foreach(ematch, e) {
                        acpar.match     = ematch->u.kernel.match;
                        acpar.matchinfo = ematch->data;
                        if (!acpar.match->match(skb, &acpar))
                                goto no_match;
                }

3. 对于拿到地target，分两种情况进行处理，　一种是standard, 一种是非standard, 对于后者，则需要调用其verdict = t->u.kernel.target->target(skb, &acpar);　如果返回结果是continue则继续一下项，否则跳出循环。

4. 对于上述的前者，　处理就会复杂些，因为有可能是自定义链. 首先拿到verdict, 如果小于0, 证明是那四种结果之一，　如果不是RETURN, 就是最后一个了，　则break, 否则，　就要进行pop处理，　jumpstack就是在这里用的，　到上一个stack后再进行下一项规则。

                        v = ((struct xt_standard_target *)t)->verdict;
                        if (v < 0) {
                                /* Pop from stack? */
                                if (v != XT_RETURN) {
                                        verdict = (unsigned int)(-v) - 1;
                                        break;
                                }
                                if ( *stackptr <= origptr) {
                                        e = get_entry(table_base,
                                            private->underflow[hook]);
                                        pr_debug("Underflow (this is normal) "
                                                 "to %p\n", e);
                                } else {
                                        e = jumpstack[--*stackptr];
                                        pr_debug("Pulled %p out from pos %u\n",
                                                 e, *stackptr);
                                        e = ipt_next_entry(e);
                                }
                                continue;
                        }
                        if (table_base + v != ipt_next_entry(e) &&
                            !(e->ip.flags & IPT_F_GOTO)) {
                                if (*stackptr >= private->stacksize) {
                                        verdict = NF_DROP;
                                        break;
                                }
                                jumpstack[( *stackptr)++] = e;
                                pr_debug("Pushed %p into pos %u\n",
                                         e, *stackptr - 1);
                        }

                        e = get_entry(table_base, v);
                        continue;

    当然，如果v是大于0的，　就要进行入栈操作了，　因为这意味着会跳到另一个链，入栈是给返回作准备，此时会拿跳到的e再继续循环。

5. 到这个函数的结束，首先是对acpar结果作判断，因为这是传进target()里的，优先考虑它的值，如果它没有说drop，　就再会去拿verdict返回的结果。

        if (acpar.hotdrop)
                return NF_DROP;
        else return verdict;

    至此，数据也就处理完了，可见真正数据包的处理很简单，难的一直是数据包的组织，　而ip/ip6/eb/arptables都用的是xt_table这个框架来组织的，　这个框架的不完美在分析中也看到了，的确太复杂，因此新的框架己经存在了，　就是用来替换xt_tables, it's called nft. 另一篇再作分析。

