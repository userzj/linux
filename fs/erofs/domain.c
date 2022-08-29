// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2022, Bytedance. All rights reserved.
 */

#include <linux/pseudo_fs.h>
#include <linux/fs_context.h>
#include <linux/magic.h>
#include <linux/fscache.h>
#include "internal.h"
static DEFINE_SPINLOCK(erofs_domain_list_lock);
static LIST_HEAD(erofs_domain_list);

static int erofs_fscache_domain_init_cookie(struct super_block *sb,
		struct erofs_fscache **fscache, char *name, bool need_inode)
{
	int ret;
	struct inode *inode;
	struct erofs_fscache *ctx;
	struct erofs_sb_info *sbi = EROFS_SB(sb);
	struct erofs_domain *domain = sbi->domain;

	ret = erofs_fscache_register_cookie(sb, &ctx, name, need_inode);
	if (ret)
		return ret;

	ctx->name = kstrdup(name, GFP_KERNEL);
	if (!ctx->name) {
		ret = -ENOMEM;
		goto err;
	}

	inode = new_inode(domain->mnt->mnt_sb);
	if (!inode) {
		kfree(ctx->name);
		goto err;
	}

	ctx->domain = domain;
	ctx->anon_inode = inode;
	inode->i_private = ctx;
	refcount_set(&ctx->ref, 1);
	erofs_fscache_domain_get(domain);
	*fscache = ctx;
	return 0;

err:
	erofs_fscache_unregister_cookie(&ctx);
	return ret;
}

int erofs_domain_register_cookie(struct super_block *sb,
	struct erofs_fscache **fscache, char *name, bool need_inode)
{
	int err;
	struct inode *inode;
	struct erofs_fscache *ctx;
	struct erofs_sb_info *sbi = EROFS_SB(sb);
	struct erofs_domain *domain = sbi->domain;
	struct super_block *psb = domain->mnt->mnt_sb;

	mutex_lock(&domain->mutex);
	list_for_each_entry(inode, &psb->s_inodes, i_sb_list) {
		ctx = inode->i_private;
		if (!ctx)
			continue;
		if (!strcmp(ctx->name, name)) {
			*fscache = ctx;
			refcount_inc(&ctx->ref);
			mutex_unlock(&domain->mutex);
			return 0;
		}
	}
	err = erofs_fscache_domain_init_cookie(sb, fscache, name,
				need_inode);
	mutex_unlock(&domain->mutex);

	return err;
}

void erofs_fscache_domain_get(struct erofs_domain *domain)
{
	if (!domain)
		return;
	refcount_inc(&domain->ref);
}

void erofs_fscache_domain_put(struct erofs_domain *domain)
{
	if (!domain)
		return;
	if (refcount_dec_and_test(&domain->ref)) {
		fscache_relinquish_volume(domain->volume, NULL, false);
		spin_lock(&erofs_domain_list_lock);
		list_del(&domain->list);
		spin_unlock(&erofs_domain_list_lock);
		kern_unmount(domain->mnt);
		kfree(domain->domain_id);
		kfree(domain);
	}
}

static int anon_inodefs_init_fs_context(struct fs_context *fc)
{
	struct pseudo_fs_context *ctx = init_pseudo(fc, ANON_INODE_FS_MAGIC);

	if (!ctx)
		return -ENOMEM;
	return 0;
}

static struct file_system_type anon_inode_fs_type = {
	.name		= "pseudo_domainfs",
	.init_fs_context = anon_inodefs_init_fs_context,
	.kill_sb	= kill_anon_super,
};

static int erofs_fscache_init_domain(struct super_block *sb)
{
    int err;
    struct erofs_domain *domain;
    struct vfsmount *pseudo_mnt;
    struct erofs_sb_info *sbi = EROFS_SB(sb);

    domain = kzalloc(sizeof(struct erofs_domain), GFP_KERNEL);
    if (!domain)
        return -ENOMEM;
    domain->domain_id = kstrdup(sbi->opt.domain_id, GFP_KERNEL);
    if (!domain->domain_id) {
        kfree(domain);
        return -ENOMEM;
    }

    sbi->domain = domain;

    pseudo_mnt = kern_mount(&anon_inode_fs_type);
    if (IS_ERR(pseudo_mnt)) {
        err = PTR_ERR(pseudo_mnt);
        goto out;
    }
    err = erofs_fscache_register_fs(sb);
    if (err) {
        kern_unmount(pseudo_mnt);
        goto out;
    }

    domain->mnt = pseudo_mnt;
    domain->volume = sbi->volume;
    refcount_set(&domain->ref, 1);
    mutex_init(&domain->mutex);

    pseudo_mnt->mnt_sb->s_fs_info = domain;
    list_add(&domain->list, &erofs_domain_list);
    return 0;
out:
    sbi->domain = NULL;
    kfree(domain->domain_id);
    kfree(domain);
    return err;
}

int erofs_fscache_register_domain(struct super_block *sb)
{
	int err;
	struct erofs_domain *domain;
	struct erofs_sb_info *sbi = EROFS_SB(sb);

	spin_lock(&erofs_domain_list_lock);
	list_for_each_entry(domain, &erofs_domain_list, list) {
		if (!strcmp(domain->domain_id, sbi->opt.domain_id)) {
			erofs_fscache_domain_get(domain);
			sbi->domain = domain;
			sbi->volume = domain->volume;
			spin_unlock(&erofs_domain_list_lock);
			return 0;
		}
	}
	err = erofs_fscache_init_domain(sb);
	spin_unlock(&erofs_domain_list_lock);

	return err;
}
