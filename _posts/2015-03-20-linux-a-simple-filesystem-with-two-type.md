---
layout: post
title: "linux two kinds of simple filesystem "
category: linux kernel
excerpt: "here are two way to a implement a simple filesystem"
tags: [kernel]
---
{% include JB/setup %}

I wrote two simple filesystem according to the cgroupfs, it has no function but doing read and write two child files and mkdir child directory.
but it complete the base steps to acheve a own filesystem. so hopefully it will be useful for your study of vfs and cgroup.

## vfs

###lxinfs

    #include <linux/module.h>
    #include <linux/kernel.h>
    #include <linux/string.h>
    #include <linux/init.h>
    #include <linux/fs.h>
    #include <linux/kallsyms.h>
    #include <linux/types.h>
    #include <linux/seq_file.h>
    #include <linux/slab.h>
    #include <linux/pagemap.h>
    #include <linux/namei.h>
    #include <linux/dcache.h>

    #define LXIN_SUPER_MAGIC 0x27e0eb
    struct inode *lxin_get_inode(struct super_block *sb,
                                    const struct inode *dir, umode_t mode);
    struct lxin
    {
            int leave_value;
            int stay_value;
            struct list_head child_list;
            struct list_head sibling_list;
            struct lxin *parent;
    };
    static struct lxin *lxin_root;

    static int lxin_show_options(struct seq_file *seq, struct dentry *dentry)
    {
            seq_printf(seq, ",created,by,lxin");
            return 0;
    }
    static int lxin_remount(struct super_block *sb, int *flags, char *data)
    {
            printk("[LXIN]:remount\n");
            return 0;
    }
    static const struct super_operations lxin_ops = {
        .statfs = simple_statfs,
        .drop_inode = generic_delete_inode,
        .show_options = lxin_show_options,
        .remount_fs = lxin_remount,
    };
    static int lxin_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
    {
    	struct inode *inode, *inode_l, *inode_s;
    	struct dentry *dentry_l, *dentry_s;
            struct lxin *lxin, *parent;
        	printk("[LXIN]:mkdir\n");
            parent = (struct lxin *) dentry->d_parent->d_fsdata;
            lxin = kzalloc(sizeof(*lxin), GFP_KERNEL);
            lxin->leave_value = 0;
            lxin->stay_value = 0;
            lxin->parent = parent;
            INIT_LIST_HEAD(&lxin->child_list);
            list_add(&lxin->sibling_list, &parent->child_list);

        	inode = lxin_get_inode(dir->i_sb, dir, mode | S_IFDIR);
        	d_instantiate(dentry, inode);
    	dentry->d_fsdata = lxin;
        	dir->i_mtime = dir->i_ctime = CURRENT_TIME;

    	mutex_lock(&dentry->d_inode->i_mutex);
    	dentry_l = lookup_one_len("leave", dentry, strlen("leave"));
    	mutex_unlock(&dentry->d_inode->i_mutex);
    	inode_l = lxin_get_inode(dir->i_sb, inode,  S_IFREG | S_IRUGO | S_IXUGO | S_IWUSR);
    	d_instantiate(dentry_l, inode_l);
    	dentry_l->d_fsdata = lxin;

    	mutex_lock(&dentry->d_inode->i_mutex);
    	dentry_s = lookup_one_len("stay", dentry, strlen("stay"));
    	mutex_unlock(&dentry->d_inode->i_mutex);
    	inode_s = lxin_get_inode(dir->i_sb, inode, S_IFREG | S_IRUGO | S_IXUGO | S_IWUSR);
    	d_instantiate(dentry_s, inode_s);
    	dentry_s->d_fsdata = lxin;

        	return 0;
    }
    int lxin_rmdir(struct inode *dir, struct dentry *dentry)
    {
            printk("[LXIN]:rmdir\n");
        	drop_nlink(dentry->d_inode);
        	simple_unlink(dir, dentry);
        	drop_nlink(dir);
        	return 0;
    }
    int lxin_rename(struct inode *old_dir, struct dentry *old_dentry,
            struct inode *new_dir, struct dentry *new_dentry)
    {
            printk("[LXIN]:rename\n");
            return 0;
    }

    static const struct inode_operations lxin_dir_inode_operations = {
        .mkdir = lxin_mkdir,
        .rmdir = lxin_rmdir,
        .rename = lxin_rename,
        .lookup = simple_lookup,
    };


    static ssize_t lxin_file_read(struct file *file, char __user *buf,
                       size_t nbytes, loff_t *ppos)

    {
    	char tmp[64];
    	int len;
    	struct lxin *lxin = (struct lxin *)file->f_path.dentry->d_fsdata;
    	if(strcmp(file->f_path.dentry->d_name.name,"leave") == 0)
    		len = sprintf(tmp, "%d\n", lxin->leave_value);
    	else
    		len = sprintf(tmp, "%d\n", lxin->stay_value);
            printk("[LXIN]:read\n");
    	return simple_read_from_buffer(buf, nbytes, ppos, tmp, len);
    }
    static ssize_t lxin_file_write(struct file *file, const char __user *buf,
                            size_t nbytes, loff_t *ppos)
    {
    	char buffer[64];
    	char *end;
    	u32 val;
    	struct lxin *lxin = (struct lxin *)file->f_path.dentry->d_fsdata;
    	if(copy_from_user(buffer, buf, nbytes))
    		return -EFAULT;
    	val = (u32)simple_strtoull(strstrip(buffer), &end, 0);
            printk("[LXIN]:write\n");
    	if(strcmp(file->f_path.dentry->d_name.name,"leave") == 0)
    		lxin->leave_value = val;
    	else
    		lxin->stay_value = val;
    	return nbytes;
    }
    const struct file_operations lxin_file_operations = {
        .read       = lxin_file_read,
        .write      = lxin_file_write,
    };

    const struct inode_operations lxin_file_inode_operations = {
        .setattr    = simple_setattr,
        .getattr    = simple_getattr,
    };


    struct inode *lxin_get_inode(struct super_block *sb,
                                    const struct inode *dir, umode_t mode)
    {
            struct inode * inode = new_inode(sb);

    	if (inode) {
    		inode->i_ino = get_next_ino();
    		inode_init_owner(inode, dir, mode);
    		inode->i_atime = inode->i_mtime = inode->i_ctime = CURRENT_TIME;
    		if (S_ISDIR(mode)){
        			inode->i_fop = &simple_dir_operations;
        			inode->i_op = &lxin_dir_inode_operations;
    			inc_nlink(inode);
    		}
    		else{
            		inode->i_size = 0;
            		inode->i_fop = &lxin_file_operations;
            		inode->i_op = &lxin_file_inode_operations;
    		}
    	}
    	return inode;
    }
    int lxin_fill_super(struct super_block *sb, void *data, int silent)
    {
    	struct inode *inode, *inode_l, *inode_s;
    	struct dentry *dentry_l, *dentry_s;
    	sb->s_fs_info = data;
    	sb->s_magic = LXIN_SUPER_MAGIC;
        	sb->s_blocksize = PAGE_CACHE_SIZE;
        	sb->s_blocksize_bits = PAGE_CACHE_SHIFT;
    	sb->s_op = &lxin_ops;

            lxin_root = kzalloc(sizeof(*lxin_root), GFP_KERNEL);
            lxin_root->leave_value = 0;
            lxin_root->stay_value = 0;
            lxin_root->parent = NULL;
            INIT_LIST_HEAD(&lxin_root->child_list);
            INIT_LIST_HEAD(&lxin_root->sibling_list);

    	inode = lxin_get_inode(sb, NULL, S_IFDIR | S_IRUGO | S_IXUGO | S_IWUSR);
    	sb->s_root = d_make_root(inode);
    	sb->s_root->d_fsdata = lxin_root;

    	mutex_lock(&sb->s_root->d_inode->i_mutex);
    	dentry_l = lookup_one_len("leave", sb->s_root, strlen("leave"));
    	mutex_unlock(&sb->s_root->d_inode->i_mutex);
    	inode_l = lxin_get_inode(sb, inode,  S_IFREG | S_IRUGO | S_IXUGO | S_IWUSR);
    	d_instantiate(dentry_l, inode_l);
    	dentry_l->d_fsdata = lxin_root;

    	mutex_lock(&sb->s_root->d_inode->i_mutex);
    	dentry_s = lookup_one_len("stay", sb->s_root, strlen("stay"));
    	mutex_unlock(&sb->s_root->d_inode->i_mutex);
    	inode_s = lxin_get_inode(sb, inode, S_IFREG | S_IRUGO | S_IXUGO | S_IWUSR);
    	d_instantiate(dentry_s, inode_s);
    	dentry_s->d_fsdata = lxin_root;
    	return 0;
    }
    static struct dentry *lxin_mount(struct file_system_type *fs_type,
                 int flags, const char *unused_dev_name,
                 void *data)
    {
    	return mount_nodev(fs_type, flags, data, lxin_fill_super);
    }
    static void lxin_kill_sb(struct super_block *sb)
    {
            printk("[LXIN]:kill sb\n");
    }
    static struct file_system_type lxin_fs_type = {
            .name = "lxin",
            .mount = lxin_mount,
            .kill_sb = lxin_kill_sb,
    	.fs_flags = FS_USERNS_MOUNT,
    };

    static int __init lxinfs_init(void)
    {
    	int err;
    	err = register_filesystem(&lxin_fs_type);
    	if (err < 0) {
            	printk("[LXIN]:lxinfs register fail\n");
    	}
            printk("[LXIN]:register lxinfs\n");
            return 0;
    }
    static void __exit lxinfs_exit(void)
    {
    	unregister_filesystem(&lxin_fs_type);
            printk("[LXIN]:unregister lxinfs\n");
            return;
    }
    module_init(lxinfs_init);
    module_exit(lxinfs_exit);

    MODULE_AUTHOR("LUCIEN");
    MODULE_LICENSE("GPL");

## kernfs

###pzhangfs

    #include <linux/module.h>
    #include <linux/kernel.h>
    #include <linux/string.h>
    #include <linux/init.h>
    #include <linux/fs.h>
    #include <linux/kernfs.h>
    #include <linux/kallsyms.h>
    #include <linux/types.h>
    #include <linux/seq_file.h>
    #include <linux/slab.h>

    #define PZHANG_SUPER_MAGIC 0x27e0eb
    struct kernfs_root *(*kernfs_create_root_p)(struct kernfs_syscall_ops *scops,
                           unsigned int flags, void *priv);
    typedef struct kernfs_root *(*kernfs_create_root_t)(struct kernfs_syscall_ops *scops,
    			unsigned int flags, void *priv);
    struct dentry *(*kernfs_mount_ns_p)(struct file_system_type *fs_type, int flags,
                       struct kernfs_root *root, unsigned long magic,
                       bool *new_sb_created, const void *ns);
    typedef struct dentry *(*kernfs_mount_ns_t)(struct file_system_type *fs_type, int flags,
                       struct kernfs_root *root, unsigned long magic,
                       bool *new_sb_created, const void *ns);
    void (*kernfs_activate_p)(struct kernfs_node *kn);
    typedef void (*kernfs_activate_t)(struct kernfs_node *kn);
    struct kernfs_node *(*__kernfs_create_file_p)(struct kernfs_node *parent,
                         const char *name,
                         umode_t mode, loff_t size,
                         const struct kernfs_ops *ops,
                         void *priv, const void *ns,
                         struct lock_class_key *key);
    typedef struct kernfs_node *(*__kernfs_create_file_t)(struct kernfs_node *parent,
                         const char *name,
                         umode_t mode, loff_t size,
                         const struct kernfs_ops *ops,
                         void *priv, const void *ns,
                         struct lock_class_key *key);
    struct kernfs_node *(*kernfs_create_dir_ns_p)(struct kernfs_node *parent,
                         const char *name, umode_t mode,
                         void *priv, const void *ns);
    typedef struct kernfs_node *(*kernfs_create_dir_ns_t)(struct kernfs_node *parent,
                         const char *name, umode_t mode,
                         void *priv, const void *ns);
    void (*kernfs_remove_p)(struct kernfs_node *kn);
    typedef void (*kernfs_remove_t)(struct kernfs_node *kn);
    void (*kernfs_break_active_protection_p)(struct kernfs_node *kn);
    typedef void (*kernfs_break_active_protection_t)(struct kernfs_node *kn);
    void (*kernfs_unbreak_active_protection_p)(struct kernfs_node *kn);
    typedef void (*kernfs_unbreak_active_protection_t)(struct kernfs_node *kn);


    struct pzhang
    {
    	int leave_value;
    	int stay_value;
    	struct list_head child_list;
    	struct list_head sibling_list;
    	struct pzhang *parent;
    };
    static struct pzhang *pzhang_root;


    static ssize_t pzhang_file_write(struct kernfs_open_file *of, char *buf,
                     size_t nbytes, loff_t off)
    {
    	struct kernfs_node *kn = of->kn;
    	struct pzhang* pzhang = (struct pzhang *)kn->priv;
    	unsigned long long v;
    	int ret;
            printk("[PZHANG]:file wirte\n");
            ret = kstrtoull(buf, 0, &v);

    	if(strcmp(kn->name, "leave")==0)
    		pzhang->leave_value = (u32)v;
    	else
    		pzhang->stay_value = (u32)v;
    	return nbytes;
    }
    static int pzhang_seqfile_show(struct seq_file *m, void *arg)
    {
    	struct kernfs_open_file *of = (struct kernfs_open_file *) m->private;
    	struct kernfs_node *kn = of->kn;
    	struct pzhang* pzhang = (struct pzhang *)kn->priv;
            printk("[PZHANG]:file show\n");
    	if(strcmp(kn->name, "leave")==0)
    		seq_printf(m, "%d\n", pzhang->leave_value);
    	else
    		seq_printf(m, "%d\n", pzhang->stay_value);
    	return 0;
    }
    static struct kernfs_ops pzhang_kf_ops = {
        .atomic_write_len   = PAGE_SIZE,
        .write          = pzhang_file_write,
        .seq_show       = pzhang_seqfile_show,
    };


    static int pzhang_rename(struct kernfs_node *kn, struct kernfs_node *new_parent,
                 const char *new_name_str)
    {
            printk("[PZHANG]:rename\n");
    	return 0;
    }
    static int pzhang_rmdir(struct kernfs_node *kn)
    {
    	struct pzhang *pzhang = (struct pzhang *)kn->priv;
            printk("[PZHANG]:rmdir\n");
    	kernfs_break_active_protection_p(kn);
    	kernfs_remove_p(kn);
    	kernfs_unbreak_active_protection_p(kn);
    	list_del(&pzhang->sibling_list);
    	return 0;
    }
    static int pzhang_show_options(struct seq_file *seq,
                       struct kernfs_root *kf_root)
    {
            seq_printf(seq, ",created,by,lxin");
    	return 0;
    }
    static int pzhang_remount(struct kernfs_root *kf_root, int *flags, char *data)
    {
            printk("[PZHANG]:remount\n");
    	return 0;
    }
    static int pzhang_mkdir(struct kernfs_node *parent_kn, const char *name,
                umode_t mode)
    {
    	struct kernfs_node *kn, *kf_node_l, *kf_node_s;
    	struct pzhang *pzhang, *parent;
            printk("[PZHANG]:mkdir\n");
    	parent = (struct pzhang *) parent_kn->priv;
    	pzhang = kzalloc(sizeof(*pzhang), GFP_KERNEL);
    	pzhang->leave_value = 0;
    	pzhang->stay_value = 0;
    	pzhang->parent = parent;
    	INIT_LIST_HEAD(&pzhang->child_list);
    	list_add(&pzhang->sibling_list, &parent->child_list);
    	kn = kernfs_create_dir_ns_p(parent_kn, name, mode, pzhang, NULL);
    	kf_node_l = __kernfs_create_file_p(kn, "leave", S_IRUGO|S_IWUSR, 0, &pzhang_kf_ops, pzhang, NULL, NULL);
    	kf_node_s = __kernfs_create_file_p(kn, "stay", S_IRUGO|S_IWUSR, 0, &pzhang_kf_ops, pzhang, NULL, NULL);
    	kernfs_activate_p(kn);
    	return 0;
    }
    static struct kernfs_syscall_ops pzhang_kf_syscall_ops = {
        .remount_fs     = pzhang_remount,
        .show_options       = pzhang_show_options,
        .mkdir          = pzhang_mkdir,
        .rmdir          = pzhang_rmdir,
        .rename         = pzhang_rename,
    };


    static struct dentry *pzhang_mount(struct file_system_type *fs_type,
                 int flags, const char *unused_dev_name,
                 void *data)
    {
    	bool new_sb;
    	struct kernfs_root *kf_root;
    	struct kernfs_node *kf_node_l, *kf_node_s;
    	struct dentry *dentry;
            printk("[PZHANG]:start to mount\n");
    	pzhang_root = kzalloc(sizeof(*pzhang_root), GFP_KERNEL);
    	pzhang_root->leave_value = 0;
    	pzhang_root->stay_value = 0;
    	pzhang_root->parent = NULL;
    	INIT_LIST_HEAD(&pzhang_root->child_list);
    	INIT_LIST_HEAD(&pzhang_root->sibling_list);
    	kf_root = kernfs_create_root_p(&pzhang_kf_syscall_ops,
                           KERNFS_ROOT_CREATE_DEACTIVATED,
                           pzhang_root);
    	kf_node_l = __kernfs_create_file_p(kf_root->kn, "leave", S_IRUGO|S_IWUSR, 0, &pzhang_kf_ops, pzhang_root, NULL, NULL);
    	kf_node_s = __kernfs_create_file_p(kf_root->kn, "stay", S_IRUGO|S_IWUSR, 0, &pzhang_kf_ops, pzhang_root, NULL, NULL);
    	kernfs_activate_p(kf_root->kn);
    	dentry = kernfs_mount_ns_p(fs_type, flags, kf_root,
                    PZHANG_SUPER_MAGIC, &new_sb, NULL);

    	return dentry;
    }
    static void pzhang_kill_sb(struct super_block *sb)
    {
            printk("[PZHANG]:kill sb\n");
    }
    static struct file_system_type pzhang_fs_type = {
            .name = "pzhang",
            .mount = pzhang_mount,
            .kill_sb = pzhang_kill_sb,
    };


    static int __init pzhangfs_init(void)
    {
    	int err;
    	kernfs_create_root_p = (kernfs_create_root_t) kallsyms_lookup_name("kernfs_create_root");
    	kernfs_mount_ns_p = (kernfs_mount_ns_t)kallsyms_lookup_name("kernfs_mount_ns");
    	kernfs_activate_p = (kernfs_activate_t)kallsyms_lookup_name("kernfs_activate");
    	__kernfs_create_file_p = (__kernfs_create_file_t)kallsyms_lookup_name("__kernfs_create_file");
    	kernfs_create_dir_ns_p = (kernfs_create_dir_ns_t)kallsyms_lookup_name("kernfs_create_dir_ns");
    	kernfs_remove_p = (kernfs_remove_t)kallsyms_lookup_name("kernfs_remove");
    	kernfs_break_active_protection_p =
    			(kernfs_break_active_protection_t)kallsyms_lookup_name("kernfs_break_active_protection");
    	kernfs_unbreak_active_protection_p =
    			(kernfs_unbreak_active_protection_t)kallsyms_lookup_name("kernfs_unbreak_active_protection");

    	err = register_filesystem(&pzhang_fs_type);
    	if (err < 0) {
            	printk("[PZHANG]:pzhangfs register fail\n");
    	}
            printk("[PZHANG]:register pzhangfs\n");
            return 0;
    }
    static void __exit pzhangfs_exit(void)
    {
    	unregister_filesystem(&pzhang_fs_type);
            printk("[PZHANG]:unregister pzhangfs\n");
            return;
    }
    module_init(pzhangfs_init);
    module_exit(pzhangfs_exit);

    MODULE_AUTHOR("LUCIEN");
    MODULE_LICENSE("GPL");
