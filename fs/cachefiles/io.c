// SPDX-License-Identifier: GPL-2.0-or-later
/* kiocb-using read/write
 *
 * Copyright (C) 2021 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include <linux/mount.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/uio.h>
#include <linux/sched/mm.h>
#include <linux/pagevec.h>
#include <linux/netfs.h>
#include "internal.h"

struct cachefiles_kiocb {
	struct kiocb		iocb;
	refcount_t		ki_refcnt;
	loff_t			start;
	union {
		size_t		skipped;
		size_t		len;
	};
	netfs_io_terminated_t	term_func;
	void			*term_func_priv;
	bool			was_async;
};

static inline void cachefiles_put_kiocb(struct cachefiles_kiocb *ki)
{
	if (refcount_dec_and_test(&ki->ki_refcnt)) {
		fput(ki->iocb.ki_filp);
		kfree(ki);
	}
}

/*
 * Handle completion of a read from the cache.
 */
static void cachefiles_read_complete(struct kiocb *iocb, long ret, long ret2)
{
	struct cachefiles_kiocb *ki = container_of(iocb, struct cachefiles_kiocb, iocb);

	_enter("%ld,%ld", ret, ret2);

	if (ki->term_func) {
		if (ret >= 0)
			ret += ki->skipped;
		ki->term_func(ki->term_func_priv, ret, ki->was_async);
	}

	cachefiles_put_kiocb(ki);
}

static void cachefiles_page_copy(struct cachefiles_kiocb *ki, struct iov_iter *iter)
{
	struct address_space *mapping =  ki->iocb.ki_filp->f_mapping;
	struct kiocb *iocb = &ki->iocb;
	loff_t isize = i_size_read(mapping->host);
	loff_t end = min_t(loff_t, isize, iocb->ki_pos + iov_iter_count(iter));
	struct pagevec pv;
	pgoff_t index;
	unsigned int i;
	bool writably_mapped;
	int error = 0;

	while (iocb->ki_pos < end && !error) {
		index = iocb->ki_pos >> PAGE_SHIFT;
		pv.nr = find_get_pages_contig(mapping, index, PAGEVEC_SIZE, pv.pages);
		if (pv.nr == 0)
			break;
		writably_mapped = mapping_writably_mapped(mapping);

		for (i = 0; i < pv.nr; i++) {
			struct page *page = pv.pages[i];
			unsigned int offset = iocb->ki_pos & ~PAGE_MASK;
			unsigned int bytes = min_t(loff_t, end - iocb->ki_pos,
						   PAGE_SIZE - offset);
			unsigned int copied;

			if (page->index * PAGE_SIZE >= end)
				break;
			if (!PageUptodate(page)) {
				error = -1;
				break;
			}
			if (writably_mapped)
				flush_dcache_page(page);
			copied = copy_page_to_iter(page, offset, bytes, iter);
			iocb->ki_pos += copied;
			if (copied < bytes) {
				error = -1;
				break;
			}
		}
		for (i = 0; i < pv.nr; i++)
			put_page(pv.pages[i]);
	}
}

/*
 * Initiate a read from the cache.
 */
static int cachefiles_read(struct netfs_cache_resources *cres,
			   loff_t start_pos,
			   struct iov_iter *iter,
			   bool seek_data,
			   netfs_io_terminated_t term_func,
			   void *term_func_priv)
{
	struct cachefiles_kiocb *ki;
	struct file *file = cres->cache_priv2;
	unsigned int old_nofs;
	ssize_t ret = -ENOBUFS;
	size_t len = iov_iter_count(iter), skipped = 0;
	struct fscache_retrieval *op = cres->cache_priv;
	struct cachefiles_object *object = container_of(op->op.object,
									struct cachefiles_object, fscache);


	_enter("%pD,%li,%llx,%zx/%llx",
	       file, file_inode(file)->i_ino, start_pos, len,
	       i_size_read(file->f_inode));

	/* If the caller asked us to seek for data before doing the read, then
	 * we should do that now.  If we find a gap, we fill it with zeros.
	 */
	if (seek_data) {
		loff_t off = start_pos, off2;

		off2 = vfs_llseek(file, off, SEEK_DATA);
		if (off2 < 0 && off2 >= (loff_t)-MAX_ERRNO && off2 != -ENXIO) {
			skipped = 0;
			ret = off2;
			goto presubmission_error;
		}

		if (off2 == -ENXIO || off2 >= start_pos + len) {
			/* The region is beyond the EOF or there's no more data
			 * in the region, so clear the rest of the buffer and
			 * return success.
			 */
			iov_iter_zero(len, iter);
			skipped = len;
			ret = 0;
			goto presubmission_error;
		}

		skipped = off2 - off;
		iov_iter_zero(skipped, iter);
	}

	ret = -ENOBUFS;
	ki = kzalloc(sizeof(struct cachefiles_kiocb), GFP_KERNEL);
	if (!ki)
		goto presubmission_error;

	refcount_set(&ki->ki_refcnt, 2);
	ki->iocb.ki_filp	= file;
	ki->iocb.ki_pos		= start_pos + skipped;
	ki->iocb.ki_flags	= IOCB_DIRECT;
	ki->iocb.ki_hint	= ki_hint_validate(file_write_hint(file));
	ki->iocb.ki_ioprio	= get_current_ioprio();
	ki->skipped		= skipped;
	ki->term_func		= term_func;
	ki->term_func_priv	= term_func_priv;
	ki->was_async		= true;

	if (ki->term_func)
		ki->iocb.ki_complete = cachefiles_read_complete;

	get_file(ki->iocb.ki_filp);

	old_nofs = memalloc_nofs_save();

	// for ondemand mode try to fill iter form pagecache first
	if (cachefiles_in_ondemand_mode(container_of(object->fscache.cache,
					struct cachefiles_cache, cache))) {
		cachefiles_page_copy(ki, iter);
		if (!iov_iter_count(iter)) {
			memalloc_nofs_restore(old_nofs);
			ki->was_async = false;
			cachefiles_read_complete(&ki->iocb, len - skipped, 0);
			ret = 0;
			goto in_progress;
		}
	}
	ret = vfs_iocb_iter_read(file, &ki->iocb, iter);
	memalloc_nofs_restore(old_nofs);
	switch (ret) {
	case -EIOCBQUEUED:
		goto in_progress;

	case -ERESTARTSYS:
	case -ERESTARTNOINTR:
	case -ERESTARTNOHAND:
	case -ERESTART_RESTARTBLOCK:
		/* There's no easy way to restart the syscall since other AIO's
		 * may be already running. Just fail this IO with EINTR.
		 */
		ret = -EINTR;
		fallthrough;
	default:
		ki->was_async = false;
		cachefiles_read_complete(&ki->iocb, ret, 0);
		if (ret > 0)
			ret = 0;
		break;
	}

in_progress:
	cachefiles_put_kiocb(ki);
	_leave(" = %zd", ret);
	return ret;

presubmission_error:
	if (term_func)
		term_func(term_func_priv, ret < 0 ? ret : skipped, false);
	return ret;
}

/*
 * Handle completion of a write to the cache.
 */
static void cachefiles_write_complete(struct kiocb *iocb, long ret, long ret2)
{
	struct cachefiles_kiocb *ki = container_of(iocb, struct cachefiles_kiocb, iocb);
	struct inode *inode = file_inode(ki->iocb.ki_filp);

	_enter("%ld,%ld", ret, ret2);

	/* Tell lockdep we inherited freeze protection from submission thread */
	__sb_writers_acquired(inode->i_sb, SB_FREEZE_WRITE);
	__sb_end_write(inode->i_sb, SB_FREEZE_WRITE);

	if (ki->term_func)
		ki->term_func(ki->term_func_priv, ret, ki->was_async);

	cachefiles_put_kiocb(ki);
}

/*
 * Initiate a write to the cache.
 */
 int __cachefiles_write(struct cachefiles_object *object,
		       struct file *file,
		       loff_t start_pos,
		       struct iov_iter *iter,
		       netfs_io_terminated_t term_func,
		       void *term_func_priv)
{
	struct cachefiles_kiocb *ki;
	struct inode *inode;
	unsigned int old_nofs;
	ssize_t ret = -ENOBUFS;
	size_t len = iov_iter_count(iter);
	struct cachefiles_cache *cache = container_of(object->fscache.cache,
			     struct cachefiles_cache, cache);

	_enter("%pD,%li,%llx,%zx/%llx",
	       file, file_inode(file)->i_ino, start_pos, len,
	       i_size_read(file->f_inode));

	ki = kzalloc(sizeof(struct cachefiles_kiocb), GFP_KERNEL);
	if (!ki)
		goto presubmission_error;

	refcount_set(&ki->ki_refcnt, 2);
	ki->iocb.ki_filp	= file;
	ki->iocb.ki_pos		= start_pos;
	if (cachefiles_in_ondemand_mode(cache))
		ki->iocb.ki_flags	= IOCB_WRITE;
	else
		ki->iocb.ki_flags	= IOCB_DIRECT | IOCB_WRITE;
	ki->iocb.ki_hint	= ki_hint_validate(file_write_hint(file));
	ki->iocb.ki_ioprio	= get_current_ioprio();
	ki->start		= start_pos;
	ki->len			= len;
	ki->term_func		= term_func;
	ki->term_func_priv	= term_func_priv;
	ki->was_async		= true;

	if (ki->term_func)
		ki->iocb.ki_complete = cachefiles_write_complete;

	/* Open-code file_start_write here to grab freeze protection, which
	 * will be released by another thread in aio_complete_rw().  Fool
	 * lockdep by telling it the lock got released so that it doesn't
	 * complain about the held lock when we return to userspace.
	 */
	inode = file_inode(file);
	__sb_start_write(inode->i_sb, SB_FREEZE_WRITE);
	__sb_writers_release(inode->i_sb, SB_FREEZE_WRITE);

	get_file(ki->iocb.ki_filp);

	old_nofs = memalloc_nofs_save();
	ret = vfs_iocb_iter_write(file, &ki->iocb, iter);
	memalloc_nofs_restore(old_nofs);
	switch (ret) {
	case -EIOCBQUEUED:
		goto in_progress;

	case -ERESTARTSYS:
	case -ERESTARTNOINTR:
	case -ERESTARTNOHAND:
	case -ERESTART_RESTARTBLOCK:
		/* There's no easy way to restart the syscall since other AIO's
		 * may be already running. Just fail this IO with EINTR.
		 */
		ret = -EINTR;
		fallthrough;
	default:
		ki->was_async = false;
		cachefiles_write_complete(&ki->iocb, ret, 0);
		if (ret > 0)
			ret = 0;
		break;
	}

in_progress:
	cachefiles_put_kiocb(ki);
	_leave(" = %zd", ret);
	return ret;

presubmission_error:
	if (term_func)
		term_func(term_func_priv, -ENOMEM, false);
	return -ENOMEM;
}
static int cachefiles_write(struct netfs_cache_resources *cres,
			    loff_t start_pos,
			    struct iov_iter *iter,
			    netfs_io_terminated_t term_func,
			    void *term_func_priv)
{
	struct fscache_retrieval *op = cres->cache_priv;
	struct cachefiles_object *object = container_of(op->op.object,
									struct cachefiles_object, fscache);

	return __cachefiles_write(object, cres->cache_priv2,
							start_pos, iter, term_func, term_func_priv);
}

/*
 * Prepare a read operation, shortening it to a cached/uncached
 * boundary as appropriate.
 */
static enum netfs_read_source cachefiles_prepare_read(struct netfs_read_subrequest *subreq,
						      loff_t i_size)
{
	struct fscache_retrieval *op = subreq->rreq->cache_resources.cache_priv;
	struct cachefiles_object *object;
	struct cachefiles_cache *cache;
	const struct cred *saved_cred;
	struct file *file = subreq->rreq->cache_resources.cache_priv2;
	loff_t off, to;
	int rc;

	_enter("%zx @%llx/%llx", subreq->len, subreq->start, i_size);

	object = container_of(op->op.object,
			      struct cachefiles_object, fscache);
	cache = container_of(object->fscache.cache,
			     struct cachefiles_cache, cache);

	if (!file)
		goto cache_fail_nosec;

	if (subreq->start >= i_size)
		return NETFS_FILL_WITH_ZEROES;

	cachefiles_begin_secure(cache, &saved_cred);
retry:
	off = vfs_llseek(file, subreq->start, SEEK_DATA);
	if (off < 0 && off >= (loff_t)-MAX_ERRNO) {
		if (off == (loff_t)-ENXIO)
			goto download_and_store;
		goto cache_fail;
	}

	if (off >= subreq->start + subreq->len)
		goto download_and_store;

	if (off > subreq->start) {
		off = round_up(off, cache->bsize);
		subreq->len = off - subreq->start;
		goto download_and_store;
	}

	to = vfs_llseek(file, subreq->start, SEEK_HOLE);
	if (to < 0 && to >= (loff_t)-MAX_ERRNO)
		goto cache_fail;

	if (to < subreq->start + subreq->len) {
		if (subreq->start + subreq->len >= i_size)
			to = round_up(to, cache->bsize);
		else
			to = round_down(to, cache->bsize);
		subreq->len = to - subreq->start;
	}

	cachefiles_end_secure(cache, saved_cred);
	return NETFS_READ_FROM_CACHE;

download_and_store:
	if (cachefiles_has_space(cache, 0, (subreq->len + PAGE_SIZE - 1) / PAGE_SIZE) == 0) {
		__set_bit(NETFS_SREQ_WRITE_TO_CACHE, &subreq->flags);
		if (test_bit(NETFS_SREQ_ONDEMAND, &subreq->flags)) {
			rc = cachefiles_ondemand_read(object, subreq->start,
											subreq->len);
			if (!rc) {
				__clear_bit(NETFS_SREQ_ONDEMAND, &subreq->flags);
				goto retry;
			}
			cachefiles_end_secure(cache, saved_cred);
			return NETFS_INVALID_READ;
		}
	}
cache_fail:
	cachefiles_end_secure(cache, saved_cred);
cache_fail_nosec:
	return NETFS_DOWNLOAD_FROM_SERVER;
}

/*
 * Prepare for a write to occur.
 */
int cachefiles_prepare_write(struct netfs_cache_resources *cres,
				    loff_t *_start, size_t *_len, loff_t i_size)
{
	loff_t start = *_start;
	size_t len = *_len, down;

	/* Round to DIO size */
	down = start - round_down(start, PAGE_SIZE);
	*_start = start - down;
	*_len = round_up(down + len, PAGE_SIZE);
	return 0;
}

/*
 * Clean up an operation.
 */
static void cachefiles_end_operation(struct netfs_cache_resources *cres)
{
	struct fscache_retrieval *op = cres->cache_priv;
	struct file *file = cres->cache_priv2;

	_enter("");

	if (file)
		fput(file);
	if (op) {
		fscache_op_complete(&op->op, false);
		fscache_put_retrieval(op);
	}

	_leave("");
}

static const struct netfs_cache_ops cachefiles_netfs_cache_ops = {
	.end_operation		= cachefiles_end_operation,
	.read			= cachefiles_read,
	.write			= cachefiles_write,
	.prepare_read		= cachefiles_prepare_read,
	.prepare_write		= cachefiles_prepare_write,
};

/*
 * Open the cache file when beginning a cache operation.
 */
int cachefiles_begin_read_operation(struct netfs_read_request *rreq,
				    struct fscache_retrieval *op)
{
	struct cachefiles_object *object;
	struct cachefiles_cache *cache;
	struct path path;
	struct file *file;

	_enter("");

	object = container_of(op->op.object,
			      struct cachefiles_object, fscache);
	cache = container_of(object->fscache.cache,
			     struct cachefiles_cache, cache);

	if (cachefiles_in_ondemand_mode(cache) && object->file) {
		file = get_file(object->file);
	} else {
		path.mnt = cache->mnt;
		path.dentry = object->backer;
		file = open_with_fake_path(&path, O_RDWR | O_LARGEFILE | O_DIRECT,
					   d_inode(object->backer), cache->cache_cred);
		if (IS_ERR(file))
			return PTR_ERR(file);
		if (!S_ISREG(file_inode(file)->i_mode))
			goto error_file;
		if (unlikely(!file->f_op->read_iter) ||
		    unlikely(!file->f_op->write_iter)) {
			pr_notice("Cache does not support read_iter and write_iter\n");
			goto error_file;
		}
	}

	fscache_get_retrieval(op);
	rreq->cache_resources.cache_priv = op;
	rreq->cache_resources.cache_priv2 = file;
	rreq->cache_resources.ops = &cachefiles_netfs_cache_ops;
	rreq->cookie_debug_id = object->fscache.debug_id;
	_leave("");
	return 0;

error_file:
	fput(file);
	return -EIO;
}
