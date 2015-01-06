/*-
 * Copyright (c) 2010-2013 Hans Petter Selasky. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "opt_compat.h"

#include <sys/stdint.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/kernel.h>
#include <sys/bus.h>
#include <sys/linker_set.h>
#include <sys/module.h>
#include <sys/lock.h>
#include <sys/condvar.h>
#include <sys/sysctl.h>
#include <sys/unistd.h>
#include <sys/malloc.h>
#include <sys/priv.h>
#include <sys/uio.h>
#include <sys/poll.h>
#include <sys/lock.h>
#include <sys/queue.h>
#include <sys/fcntl.h>
#include <sys/proc.h>
#include <sys/vnode.h>
#include <sys/ptrace.h>

#include <sys/bus.h>

#include <vm/vm.h>
#include <vm/pmap.h>

#include <sys/devfs.h>

#define	HAVE_CUSE_IOCTL

#include "cuse4bsd.h"

MODULE_VERSION(cuse4bsd, 1);

#define	NBUSY	((uint8_t *)1)

#ifdef FEATURE
FEATURE(cuse4bsd, "Userspace character devices");
#endif

#define PROC_LOCK(s)
#define PROC_UNLOCK(s)

struct cuse_command;
struct cuse_server;
struct cuse_client;

struct cuse_client_command {
	TAILQ_ENTRY(cuse_client_command) entry;
	struct cuse_command sub;
	struct lock lk;
	struct cv cv;
	struct thread *entered;
	struct cuse_client *client;
	struct proc *proc_curr;
	int	proc_refs;
	int	got_signal;
	int	error;
	int	command;
};

struct cuse_memory {
	struct cuse_server *owner;
	uint8_t *virtaddr;
	uint32_t page_count;
	uint32_t is_allocated;
};

struct cuse_server_dev {
	TAILQ_ENTRY(cuse_server_dev) entry;
	struct cuse_server *server;
	struct cdev *kern_dev;
	struct cuse_dev *user_dev;
};

struct cuse_server {
	TAILQ_ENTRY(cuse_server) entry;
	TAILQ_HEAD(, cuse_client_command) head;
	TAILQ_HEAD(, cuse_server_dev) hdev;
	TAILQ_HEAD(, cuse_client) hcli;
	struct cv cv;
	struct kqinfo selinfo;
	int	is_closing;
	int	refs;
};

struct cuse_client {
	TAILQ_ENTRY(cuse_client) entry;
	TAILQ_ENTRY(cuse_client) entry_ref;
	struct cuse_client_command cmds[CUSE_CMD_MAX];
	struct cuse_server *server;
	struct cuse_server_dev *server_dev;

	uint8_t	ioctl_buffer[CUSE_BUFFER_MAX] __aligned(4);

	int	fflags;		/* file flags */
	int	cflags;		/* client flags */
#define	CUSE_CLI_IS_CLOSING 0x01
#define	CUSE_CLI_KNOTE_NEED_READ 0x02
#define	CUSE_CLI_KNOTE_NEED_WRITE 0x04
#define	CUSE_CLI_KNOTE_HAS_READ 0x08
#define	CUSE_CLI_KNOTE_HAS_WRITE 0x10
};

#define	CUSE_CLIENT_CLOSING(pcc) \
    ((pcc)->cflags & CUSE_CLI_IS_CLOSING)

static	MALLOC_DEFINE(M_CUSE4BSD, "cuse", "Cuse4BSD memory");

static TAILQ_HEAD(, cuse_server) cuse_server_head;
static struct lock cuse_lk;
static struct cdev *cuse_dev;
static struct cuse_server *cuse_alloc_unit[CUSE_DEVICES_MAX];
static int cuse_alloc_unit_id[CUSE_DEVICES_MAX];
static struct cuse_memory cuse_mem[CUSE_ALLOC_UNIT_MAX];

static void cuse_client_kqfilter_read_detach(struct knote *kn);
static void cuse_client_kqfilter_write_detach(struct knote *kn);
static int cuse_client_kqfilter_read_event(struct knote *kn, long hint);
static int cuse_client_kqfilter_write_event(struct knote *kn, long hint);

static struct filterops cuse_client_kqfilter_read_ops = {
	FILTEROP_ISFD | FILTEROP_MPSAFE /* XXX */,
	NULL,
	cuse_client_kqfilter_read_detach,
	cuse_client_kqfilter_read_event,
};

static struct filterops cuse_client_kqfilter_write_ops = {
	FILTEROP_ISFD | FILTEROP_MPSAFE /* XXX */,
	NULL,
	cuse_client_kqfilter_write_detach,
	cuse_client_kqfilter_write_event,
};

static d_open_t cuse_client_open;
static d_close_t cuse_client_close;
static d_ioctl_t cuse_client_ioctl;
static d_read_t cuse_client_read;
static d_write_t cuse_client_write;
static d_mmap_t cuse_client_mmap;
static d_kqfilter_t cuse_client_kqfilter;

static struct dev_ops cuse_client_devsw = {
	{ "cuse_client", 0, D_TRACKCLOSE | D_MPSAFE /* XXX */ },
	.d_open = cuse_client_open,
	.d_close = cuse_client_close,
	.d_ioctl = cuse_client_ioctl,
	.d_read = cuse_client_read,
	.d_write = cuse_client_write,
	.d_mmap = cuse_client_mmap,
	.d_kqfilter = cuse_client_kqfilter,
};

static d_open_t cuse_server_open;
static d_close_t cuse_server_close;
static d_ioctl_t cuse_server_ioctl;
static d_read_t cuse_server_read;
static d_write_t cuse_server_write;
static d_mmap_t cuse_server_mmap;

static struct dev_ops cuse_server_devsw = {
	{ "cuse_server", 0, D_TRACKCLOSE | D_MPSAFE /* XXX */ },
	.d_open = cuse_server_open,
	.d_close = cuse_server_close,
	.d_ioctl = cuse_server_ioctl,
	.d_read = cuse_server_read,
	.d_write = cuse_server_write,
	.d_mmap = cuse_server_mmap,
};

static void cuse_client_is_closing(struct cuse_client *);
static int cuse_free_unit_by_id_locked(struct cuse_server *, int);

static void
cuse_lock(void)
{
	lockmgr(&cuse_lk, LK_EXCLUSIVE);
}

static void
cuse_unlock(void)
{
	lockmgr(&cuse_lk, LK_RELEASE);
}

static void
cuse_cmd_lock(struct cuse_client_command *pccmd)
{
	lockmgr(&pccmd->lk, LK_EXCLUSIVE);
}

static void
cuse_cmd_unlock(struct cuse_client_command *pccmd)
{
	lockmgr(&pccmd->lk, LK_RELEASE); 
}

static void
cuse_kern_init(void *arg)
{
	TAILQ_INIT(&cuse_server_head);

	lockinit(&cuse_lk, "cuse-lock", 0, LK_CANRECURSE);

	cuse_dev = make_dev(&cuse_server_devsw, 0,
	    UID_ROOT, GID_OPERATOR, 0600, "cuse");

	kprintf("Cuse4BSD v%d.%d.%d @ /dev/cuse\n",
	    (CUSE_VERSION >> 16) & 0xFF, (CUSE_VERSION >> 8) & 0xFF,
	    (CUSE_VERSION >> 0) & 0xFF);
}

SYSINIT(cuse_kern_init, SI_SUB_VFS /* XXX */, SI_ORDER_ANY, cuse_kern_init, 0);

static void
cuse_kern_uninit(void *arg)
{
	void *ptr;

	while (1) {

		kprintf("Cuse4BSD: Please exit all /dev/cuse instances "
		    "and processes which have used this device.\n");

		tsleep(&ptr, 0, "DRAIN", 2 * hz);

		cuse_lock();
		ptr = TAILQ_FIRST(&cuse_server_head);
		cuse_unlock();

		if (ptr == NULL)
			break;
	}

	if (cuse_dev != NULL)
		destroy_dev(cuse_dev);

	lockuninit(&cuse_lk);
}

SYSUNINIT(cuse_kern_uninit, SI_SUB_VFS /* XXX */, SI_ORDER_ANY, cuse_kern_uninit, 0);

static int
cuse_server_get(struct file *fp, struct cuse_server **ppcs)
{
	struct cuse_server *pcs;
	int error;

	error = devfs_get_cdevpriv(fp, (void **)&pcs);
	if (error != 0) {
		*ppcs = NULL;
		return (error);
	}
	/* check if closing */
	cuse_lock();
	if (pcs->is_closing) {
		cuse_unlock();
		*ppcs = NULL;
		return (EINVAL);
	}
	cuse_unlock();
	*ppcs = pcs;
	return (0);
}

static void
cuse_server_is_closing(struct cuse_server *pcs)
{
	struct cuse_client *pcc;

	if (pcs->is_closing)
		return;

	pcs->is_closing = 1;

	TAILQ_FOREACH(pcc, &pcs->hcli, entry) {
		cuse_client_is_closing(pcc);
	}
}

static struct cuse_client_command *
cuse_server_find_command(struct cuse_server *pcs, struct thread *td)
{
	struct cuse_client *pcc;
	int n;

	if (pcs->is_closing)
		goto done;

	TAILQ_FOREACH(pcc, &pcs->hcli, entry) {
		if (CUSE_CLIENT_CLOSING(pcc))
			continue;
		for (n = 0; n != CUSE_CMD_MAX; n++) {
			if (pcc->cmds[n].entered == td)
				return (&pcc->cmds[n]);
		}
	}
done:
	return (NULL);
}

static void
cuse_str_filter(char *ptr)
{
	int c;

	while (((c = *ptr) != 0)) {

		if ((c >= 'a') && (c <= 'z')) {
			ptr++;
			continue;
		}
		if ((c >= 'A') && (c <= 'Z')) {
			ptr++;
			continue;
		}
		if ((c >= '0') && (c <= '9')) {
			ptr++;
			continue;
		}
		if ((c == '.') || (c == '_') || (c == '/')) {
			ptr++;
			continue;
		}
		*ptr = '_';

		ptr++;
	}
}

static int
cuse_convert_error(int error)
{
	;				/* indent fix */
	switch (error) {
	case CUSE_ERR_NONE:
		return (0);
	case CUSE_ERR_BUSY:
		return (EBUSY);
	case CUSE_ERR_WOULDBLOCK:
		return (EWOULDBLOCK);
	case CUSE_ERR_INVALID:
		return (EINVAL);
	case CUSE_ERR_NO_MEMORY:
		return (ENOMEM);
	case CUSE_ERR_FAULT:
		return (EFAULT);
	case CUSE_ERR_SIGNAL:
		return (EINTR);
	default:
		return (ENXIO);
	}
}

static void
cuse_server_free_memory(struct cuse_server *pcs)
{
	struct cuse_memory *mem;
	uint32_t n;

	for (n = 0; n != CUSE_ALLOC_UNIT_MAX; n++) {
		mem = &cuse_mem[n];

		/* this memory is never freed */
		if (mem->owner == pcs) {
			mem->owner = NULL;
			mem->is_allocated = 0;
		}
	}
}

static int
cuse_server_alloc_memory(struct cuse_server *pcs,
    struct cuse_memory *mem, uint32_t page_count)
{
	void *ptr;
	int error;

	cuse_lock();

	if (mem->virtaddr == NBUSY) {
		cuse_unlock();
		return (EBUSY);
	}
	if (mem->virtaddr != NULL) {
		if (mem->is_allocated != 0) {
			cuse_unlock();
			return (EBUSY);
		}
		if (mem->page_count == page_count) {
			mem->is_allocated = 1;
			mem->owner = pcs;
			cuse_unlock();
			return (0);
		}
		cuse_unlock();
		return (EBUSY);
	}
	memset(mem, 0, sizeof(*mem));

	mem->virtaddr = NBUSY;

	cuse_unlock();

	ptr = kmalloc(page_count * PAGE_SIZE, M_CUSE4BSD, M_WAITOK | M_ZERO);
	if (ptr == NULL)
		error = ENOMEM;
	else
		error = 0;

	cuse_lock();

	if (error) {
		mem->virtaddr = NULL;
		cuse_unlock();
		return (error);
	}
	mem->virtaddr = ptr;
	mem->page_count = page_count;
	mem->is_allocated = 1;
	mem->owner = pcs;
	cuse_unlock();

	return (0);
}

static int
cuse_client_get(struct file *fp, struct cuse_client **ppcc)
{
	struct cuse_client *pcc;
	int error;

	/* try to get private data */
	error = devfs_get_cdevpriv(fp, (void **)&pcc);
	if (error != 0) {
		*ppcc = NULL;
		return (error);
	}
	/* check if closing */
	cuse_lock();
	if (CUSE_CLIENT_CLOSING(pcc) || pcc->server->is_closing) {
		cuse_unlock();
		*ppcc = NULL;
		return (EINVAL);
	}
	cuse_unlock();
	*ppcc = pcc;
	return (0);
}

static void
cuse_client_is_closing(struct cuse_client *pcc)
{
	struct cuse_client_command *pccmd;
	uint32_t n;

	if (CUSE_CLIENT_CLOSING(pcc))
		return;

	pcc->cflags |= CUSE_CLI_IS_CLOSING;
	pcc->server_dev = NULL;

	for (n = 0; n != CUSE_CMD_MAX; n++) {

		pccmd = &pcc->cmds[n];

		if (pccmd->entry.tqe_prev != NULL) {
			TAILQ_REMOVE(&pcc->server->head, pccmd, entry);
			pccmd->entry.tqe_prev = NULL;
		}
		cv_broadcast(&pccmd->cv);
	}
}

static void
cuse_client_send_command_locked(struct cuse_client_command *pccmd,
    unsigned long data_ptr, unsigned long arg, int fflags, int ioflag)
{
	unsigned long cuse_fflags = 0;
	struct cuse_server *pcs;

	if (fflags & FREAD)
		cuse_fflags |= CUSE_FFLAG_READ;

	if (fflags & FWRITE)
		cuse_fflags |= CUSE_FFLAG_WRITE;

	if (ioflag & IO_NDELAY)
		cuse_fflags |= CUSE_FFLAG_NONBLOCK;

	pccmd->sub.fflags = cuse_fflags;
	pccmd->sub.data_pointer = data_ptr;
	pccmd->sub.argument = arg;

	pcs = pccmd->client->server;

	if ((pccmd->entry.tqe_prev == NULL) &&
	    (CUSE_CLIENT_CLOSING(pccmd->client) == 0) &&
	    (pcs->is_closing == 0)) {
		TAILQ_INSERT_TAIL(&pcs->head, pccmd, entry);
		cv_signal(&pcs->cv);
	}
}

static void
cuse_client_got_signal(struct cuse_client_command *pccmd)
{
	struct cuse_server *pcs;

	pccmd->got_signal = 1;

	pccmd = &pccmd->client->cmds[CUSE_CMD_SIGNAL];

	pcs = pccmd->client->server;

	if ((pccmd->entry.tqe_prev == NULL) &&
	    (CUSE_CLIENT_CLOSING(pccmd->client) == 0) &&
	    (pcs->is_closing == 0)) {
		TAILQ_INSERT_TAIL(&pcs->head, pccmd, entry);
		cv_signal(&pcs->cv);
	}
}

// TODO
static int proc_rwmem(struct proc *p, struct uio *uio) {
	return 0;
}

static int
cuse_client_receive_command_locked(struct cuse_client_command *pccmd,
    uint8_t *arg_ptr, uint32_t arg_len)
{
	int error;

	error = 0;

	pccmd->proc_curr = curthread->td_proc;

	if (CUSE_CLIENT_CLOSING(pccmd->client) ||
	    pccmd->client->server->is_closing) {
		error = CUSE_ERR_OTHER;
		goto done;
	}
	while (pccmd->command == CUSE_CMD_NONE) {
		if (error != 0) {
			cv_wait(&pccmd->cv, &cuse_lk);
		} else {
			error = cv_wait_sig(&pccmd->cv, &cuse_lk);

			if (error != 0)
				cuse_client_got_signal(pccmd);
		}
		if (CUSE_CLIENT_CLOSING(pccmd->client) ||
		    pccmd->client->server->is_closing) {
			error = CUSE_ERR_OTHER;
			goto done;
		}
	}

	error = pccmd->error;
	pccmd->command = CUSE_CMD_NONE;
	cv_signal(&pccmd->cv);

done:

	/* wait until all process references are gone */

	pccmd->proc_curr = NULL;

	while (pccmd->proc_refs != 0)
		cv_wait(&pccmd->cv, &cuse_lk);

	return (error);
}

/*------------------------------------------------------------------------*
 *	CUSE4BSD SERVER PART
 *------------------------------------------------------------------------*/

static void
cuse_server_free_dev(struct cuse_server_dev *pcsd)
{
	struct cuse_server *pcs;
	struct cuse_client *pcc;

	/* get server pointer */
	pcs = pcsd->server;

	/* prevent creation of more devices */
	cuse_lock();
	if (pcsd->kern_dev != NULL)
		pcsd->kern_dev->si_drv1 = NULL;

	TAILQ_FOREACH(pcc, &pcs->hcli, entry) {
		if (pcc->server_dev == pcsd)
			cuse_client_is_closing(pcc);
	}
	cuse_unlock();

	/* destroy device, if any */
	if (pcsd->kern_dev != NULL) {
		/* destroy device synchronously */
		destroy_dev(pcsd->kern_dev);
	}
	kfree(pcsd, M_CUSE4BSD);
}

static void
cuse_server_free(void *arg)
{
	struct cuse_server *pcs = arg;
	struct cuse_server_dev *pcsd;

	cuse_lock();
	pcs->refs--;
	if (pcs->refs != 0) {
		cuse_unlock();
		return;
	}
	cuse_server_is_closing(pcs);

	TAILQ_REMOVE(&cuse_server_head, pcs, entry);

	cuse_free_unit_by_id_locked(pcs, -1);

	while ((pcsd = TAILQ_FIRST(&pcs->hdev)) != NULL) {
		TAILQ_REMOVE(&pcs->hdev, pcsd, entry);
		cuse_unlock();
		cuse_server_free_dev(pcsd);
		cuse_lock();
	}

	cuse_server_free_memory(pcs);

#ifdef TODO
	knlist_clear(&pcs->selinfo.ki_note, 1);
	knlist_destroy(&pcs->selinfo.ki_note);
#endif

	cuse_unlock();

#ifdef TODO
	seldrain(&pcs->selinfo);
#endif

	cv_destroy(&pcs->cv);

	kfree(pcs, M_CUSE4BSD);
}

static int
cuse_server_open(struct dev_open_args *ap)
{
	struct file *fp = ap->a_fp;
	struct cuse_server *pcs;

	pcs = kmalloc(sizeof(*pcs), M_CUSE4BSD, M_WAITOK | M_ZERO);
	if (pcs == NULL)
		return (ENOMEM);

	if (devfs_set_cdevpriv(fp, pcs, &cuse_server_free)) {
		kprintf("Cuse4BSD: Cannot set cdevpriv.\n");
		kfree(pcs, M_CUSE4BSD);
		return (ENOMEM);
	}
	TAILQ_INIT(&pcs->head);
	TAILQ_INIT(&pcs->hdev);
	TAILQ_INIT(&pcs->hcli);

	cv_init(&pcs->cv, "cuse-server-cv");

	cuse_lock();
	pcs->refs++;
	TAILQ_INSERT_TAIL(&cuse_server_head, pcs, entry);
	cuse_unlock();

	return (0);
}

static int
cuse_server_close(struct dev_close_args *ap)
{
	struct file *fp = ap->a_fp;
	struct cuse_server *pcs;
	int error;

	error = cuse_server_get(fp, &pcs);
	if (error != 0)
		goto done;

	cuse_lock();
	cuse_server_is_closing(pcs);
#ifdef TODO
	knlist_clear(&pcs->selinfo.ki_note, 1);
#endif
	cuse_unlock();

done:
	return (0);
}

static int
cuse_server_read(struct dev_read_args *ap)
{
	return (ENXIO);
}

static int
cuse_server_write(struct dev_write_args *ap)
{
	return (ENXIO);
}

static int
cuse_server_ioctl_copy_locked(struct cuse_client_command *pccmd,
    struct cuse_data_chunk *pchk, int isread)
{
	struct proc *p_proc;
	uint32_t offset;
	int error;

	offset = pchk->peer_ptr - CUSE_BUF_MIN_PTR;

	if (pchk->length > CUSE_BUFFER_MAX)
		return (EFAULT);

	if (offset >= CUSE_BUFFER_MAX)
		return (EFAULT);

	if ((offset + pchk->length) > CUSE_BUFFER_MAX)
		return (EFAULT);

	p_proc = pccmd->proc_curr;
	if (p_proc == NULL)
		return (ENXIO);

	if (pccmd->proc_refs < 0)
		return (ENOMEM);

	pccmd->proc_refs++;

	cuse_unlock();

	if (isread == 0) {
		error = copyin(
		    (void *)pchk->local_ptr,
		    pccmd->client->ioctl_buffer + offset,
		    pchk->length);
	} else {
		error = copyout(
		    pccmd->client->ioctl_buffer + offset,
		    (void *)pchk->local_ptr,
		    pchk->length);
	}

	cuse_lock();

	pccmd->proc_refs--;

	if (pccmd->proc_curr == NULL)
		cv_signal(&pccmd->cv);

	return (error);
}

static int
cuse_proc2proc_copy(struct proc *proc_s, vm_offset_t data_s,
    struct proc *proc_d, vm_offset_t data_d, size_t len)
{
	struct thread *td;
	struct proc *proc_cur;
	int error;

	td = curthread;
	proc_cur = td->td_proc;

	if (proc_cur == proc_d) {
		struct iovec iov = {
			.iov_base = (caddr_t)data_d,
			.iov_len = len,
		};
		struct uio uio = {
			.uio_iov = &iov,
			.uio_iovcnt = 1,
			.uio_offset = (off_t)data_s,
			.uio_resid = len,
			.uio_segflg = UIO_USERSPACE,
			.uio_rw = UIO_READ,
			.uio_td = td,
		};

		PROC_LOCK(proc_s);
		PHOLD(proc_s);
		PROC_UNLOCK(proc_s);

		error = proc_rwmem(proc_s, &uio);

		PROC_LOCK(proc_s);
		PRELE(proc_s);
		PROC_UNLOCK(proc_s);

	} else if (proc_cur == proc_s) {
		struct iovec iov = {
			.iov_base = (caddr_t)data_s,
			.iov_len = len,
		};
		struct uio uio = {
			.uio_iov = &iov,
			.uio_iovcnt = 1,
			.uio_offset = (off_t)data_d,
			.uio_resid = len,
			.uio_segflg = UIO_USERSPACE,
			.uio_rw = UIO_WRITE,
			.uio_td = td,
		};

		PROC_LOCK(proc_d);
		PHOLD(proc_d);
		PROC_UNLOCK(proc_d);

		error = proc_rwmem(proc_d, &uio);

		PROC_LOCK(proc_d);
		PRELE(proc_d);
		PROC_UNLOCK(proc_d);
	} else {
		error = EINVAL;
	}
	return (error);
}

static int
cuse_server_data_copy_locked(struct cuse_client_command *pccmd,
    struct cuse_data_chunk *pchk, int isread)
{
	struct proc *p_proc;
	int error;

	p_proc = pccmd->proc_curr;
	if (p_proc == NULL)
		return (ENXIO);

	if (pccmd->proc_refs < 0)
		return (ENOMEM);

	pccmd->proc_refs++;

	cuse_unlock();

	if (isread == 0) {
		error = cuse_proc2proc_copy(
		    curthread->td_proc, pchk->local_ptr,
		    p_proc, pchk->peer_ptr,
		    pchk->length);
	} else {
		error = cuse_proc2proc_copy(
		    p_proc, pchk->peer_ptr,
		    curthread->td_proc, pchk->local_ptr,
		    pchk->length);
	}

	cuse_lock();

	pccmd->proc_refs--;

	if (pccmd->proc_curr == NULL)
		cv_signal(&pccmd->cv);

	return (error);
}

static int
cuse_alloc_unit_by_id_locked(struct cuse_server *pcs, int id)
{
	int n;
	int x = 0;
	int match;

	do {
		for (match = n = 0; n != CUSE_DEVICES_MAX; n++) {
			if (cuse_alloc_unit[n] != NULL) {
				if ((cuse_alloc_unit_id[n] ^ id) & CUSE_ID_MASK)
					continue;
				if ((cuse_alloc_unit_id[n] & ~CUSE_ID_MASK) == x) {
					x++;
					match = 1;
				}
			}
		}
	} while (match);

	if (x < 256) {
		for (n = 0; n != CUSE_DEVICES_MAX; n++) {
			if (cuse_alloc_unit[n] == NULL) {
				cuse_alloc_unit[n] = pcs;
				cuse_alloc_unit_id[n] = id | x;
				return (x);
			}
		}
	}
	return (-1);
}

static void
cuse_server_wakeup_locked(struct cuse_server *pcs)
{
#ifdef TODO
	selwakeup(&pcs->selinfo);
	KNOTE_LOCKED(&pcs->selinfo.ki_note, 0);
#endif
}

static int
cuse_free_unit_by_id_locked(struct cuse_server *pcs, int id)
{
	int n;
	int found = 0;

	for (n = 0; n != CUSE_DEVICES_MAX; n++) {
		if (cuse_alloc_unit[n] == pcs) {
			if (cuse_alloc_unit_id[n] == id || id == -1) {
				cuse_alloc_unit[n] = NULL;
				cuse_alloc_unit_id[n] = 0;
				found = 1;
			}
		}
	}

	return (found ? 0 : EINVAL);
}

static int
cuse_server_ioctl(struct dev_ioctl_args *ap)
{
	struct file *fp = ap->a_fp;
	u_long cmd = ap->a_cmd;
	caddr_t data = ap->a_data;

	struct cuse_server *pcs;
	int error;

	error = cuse_server_get(fp, &pcs);
	if (error != 0)
		return (error);

	switch (cmd) {
		struct cuse_client_command *pccmd;
		struct cuse_client *pcc;
		struct cuse_command *pcmd;
		struct cuse_alloc_info *pai;
		struct cuse_create_dev *pcd;
		struct cuse_server_dev *pcsd;
		struct cuse_data_chunk *pchk;
		int n;

	case CUSE_IOCTL_GET_COMMAND:
		pcmd = (void *)data;

		cuse_lock();

		while ((pccmd = TAILQ_FIRST(&pcs->head)) == NULL) {
			error = cv_wait_sig(&pcs->cv, &cuse_lk);

			if (pcs->is_closing)
				error = ENXIO;

			if (error) {
				cuse_unlock();
				return (error);
			}
		}

		TAILQ_REMOVE(&pcs->head, pccmd, entry);
		pccmd->entry.tqe_prev = NULL;

		pccmd->entered = curthread;

		*pcmd = pccmd->sub;

		cuse_unlock();

		break;

	case CUSE_IOCTL_SYNC_COMMAND:

		cuse_lock();
		while ((pccmd = cuse_server_find_command(pcs, curthread)) != NULL) {

			/* send sync command */
			pccmd->entered = NULL;
			pccmd->error = *(int *)data;
			pccmd->command = CUSE_CMD_SYNC;

			/* signal peer, if any */
			cv_signal(&pccmd->cv);
		}
		cuse_unlock();

		break;

	case CUSE_IOCTL_ALLOC_UNIT:

		cuse_lock();
		n = cuse_alloc_unit_by_id_locked(pcs,
		    CUSE_ID_DEFAULT(0));
		cuse_unlock();

		if (n < 0)
			error = ENOMEM;
		else
			*(int *)data = n;
		break;

	case CUSE_IOCTL_ALLOC_UNIT_BY_ID:

		n = *(int *)data;

		n = (n & CUSE_ID_MASK);

		cuse_lock();
		n = cuse_alloc_unit_by_id_locked(pcs, n);
		cuse_unlock();

		if (n < 0)
			error = ENOMEM;
		else
			*(int *)data = n;
		break;

	case CUSE_IOCTL_FREE_UNIT:

		n = *(int *)data;

		n = CUSE_ID_DEFAULT(n);

		cuse_lock();
		error = cuse_free_unit_by_id_locked(pcs, n);
		cuse_unlock();
		break;

	case CUSE_IOCTL_FREE_UNIT_BY_ID:

		n = *(int *)data;

		cuse_lock();
		error = cuse_free_unit_by_id_locked(pcs, n);
		cuse_unlock();
		break;

	case CUSE_IOCTL_ALLOC_MEMORY:

		pai = (void *)data;

		if (pai->alloc_nr >= CUSE_ALLOC_UNIT_MAX) {
			error = ENOMEM;
			break;
		}
		if (pai->page_count > CUSE_ALLOC_PAGES_MAX) {
			error = ENOMEM;
			break;
		}
		error = cuse_server_alloc_memory(pcs,
		    &cuse_mem[pai->alloc_nr], pai->page_count);
		break;

	case CUSE_IOCTL_FREE_MEMORY:
		pai = (void *)data;

		if (pai->alloc_nr >= CUSE_ALLOC_UNIT_MAX) {
			error = ENOMEM;
			break;
		}
		/* we trust the character device driver in this case */

		cuse_lock();
		if (cuse_mem[pai->alloc_nr].owner == pcs) {
			cuse_mem[pai->alloc_nr].is_allocated = 0;
			cuse_mem[pai->alloc_nr].owner = NULL;
		} else {
			error = EINVAL;
		}
		cuse_unlock();
		break;

	case CUSE_IOCTL_GET_SIG:

		cuse_lock();
		pccmd = cuse_server_find_command(pcs, curthread);

		if (pccmd != NULL) {
			n = pccmd->got_signal;
			pccmd->got_signal = 0;
		} else {
			n = 0;
		}
		cuse_unlock();

		*(int *)data = n;

		break;

	case CUSE_IOCTL_SET_PFH:

		cuse_lock();
		pccmd = cuse_server_find_command(pcs, curthread);

		if (pccmd != NULL) {
			pcc = pccmd->client;
			for (n = 0; n != CUSE_CMD_MAX; n++) {
				pcc->cmds[n].sub.per_file_handle = *(unsigned long *)data;
			}
		} else {
			error = ENXIO;
		}
		cuse_unlock();
		break;

	case CUSE_IOCTL_CREATE_DEV:

		error = priv_check(curthread, PRIV_DRIVER);
		if (error)
			break;

		pcd = (void *)data;

		/* filter input */

		pcd->devname[sizeof(pcd->devname) - 1] = 0;

		if (pcd->devname[0] == 0) {
			error = EINVAL;
			break;
		}
		cuse_str_filter(pcd->devname);

		pcd->permissions &= 0777;

		/* try to allocate a character device */

		pcsd = kmalloc(sizeof(*pcsd), M_CUSE4BSD, M_WAITOK | M_ZERO);

		if (pcsd == NULL) {
			error = ENOMEM;
			break;
		}
		pcsd->server = pcs;

		pcsd->user_dev = pcd->dev;

#if __FreeBSD_version >= 900023
		pcsd->kern_dev = make_dev_credf(MAKEDEV_CHECKNAME,
		    &cuse_client_devsw, 0, NULL, pcd->user_id, pcd->group_id,
		    pcd->permissions, "%s", pcd->devname);
#else
		pcsd->kern_dev = make_dev(&cuse_client_devsw,
		    0, pcd->user_id, pcd->group_id, pcd->permissions,
		    "%s", pcd->devname);
#endif

		if (pcsd->kern_dev == NULL) {
			kfree(pcsd, M_CUSE4BSD);
			error = ENOMEM;
			break;
		}
		pcsd->kern_dev->si_drv1 = pcsd;

		cuse_lock();
		TAILQ_INSERT_TAIL(&pcs->hdev, pcsd, entry);
		cuse_unlock();

		break;

	case CUSE_IOCTL_DESTROY_DEV:

		error = priv_check(curthread, PRIV_DRIVER);
		if (error)
			break;

		cuse_lock();

		error = EINVAL;

		pcsd = TAILQ_FIRST(&pcs->hdev);
		while (pcsd != NULL) {
			if (pcsd->user_dev == *(struct cuse_dev **)data) {
				TAILQ_REMOVE(&pcs->hdev, pcsd, entry);
				cuse_unlock();
				cuse_server_free_dev(pcsd);
				cuse_lock();
				error = 0;
				pcsd = TAILQ_FIRST(&pcs->hdev);
			} else {
				pcsd = TAILQ_NEXT(pcsd, entry);
			}
		}

		cuse_unlock();
		break;

	case CUSE_IOCTL_WRITE_DATA:
	case CUSE_IOCTL_READ_DATA:

		cuse_lock();
		pchk = (struct cuse_data_chunk *)data;

		pccmd = cuse_server_find_command(pcs, curthread);

		if (pccmd == NULL) {
			error = ENXIO;	/* invalid request */
		} else if (pchk->peer_ptr < CUSE_BUF_MIN_PTR) {
			error = EFAULT;	/* NULL pointer */
		} else if (pchk->peer_ptr < CUSE_BUF_MAX_PTR) {
			error = cuse_server_ioctl_copy_locked(pccmd,
			    pchk, cmd == CUSE_IOCTL_READ_DATA);
		} else {
			error = cuse_server_data_copy_locked(pccmd,
			    pchk, cmd == CUSE_IOCTL_READ_DATA);
		}
		cuse_unlock();
		break;

	case CUSE_IOCTL_SELWAKEUP:
		cuse_lock();
		/*
		 * We don't know which direction caused the event.
		 * Wakeup both!
		 */
		TAILQ_FOREACH(pcc, &pcs->hcli, entry) {
			pcc->cflags |= (CUSE_CLI_KNOTE_NEED_READ |
			    CUSE_CLI_KNOTE_NEED_WRITE);
		}
		cuse_server_wakeup_locked(pcs);
		cuse_unlock();
		break;

	default:
		error = ENXIO;
		break;
	}
	return (error);
}

static int
cuse_server_mmap(struct dev_mmap_args *ap)
{
	struct file *fp = ap->a_fp;
	uint32_t page_nr = ap->a_offset / PAGE_SIZE;
	uint32_t alloc_nr = page_nr / CUSE_ALLOC_PAGES_MAX;
	struct cuse_memory *mem;
	struct cuse_server *pcs;
	uint8_t *ptr;
	int error;

	if (alloc_nr >= CUSE_ALLOC_UNIT_MAX)
		return (ENOMEM);

	error = cuse_server_get(fp, &pcs);
	if (error != 0)
		pcs = NULL;

	cuse_lock();
	mem = &cuse_mem[alloc_nr];

	/* try to enforce slight ownership */
	if ((pcs != NULL) && (mem->owner != pcs)) {
		cuse_unlock();
		return (EINVAL);
	}
	if (mem->virtaddr == NULL) {
		cuse_unlock();
		return (ENOMEM);
	}
	if (mem->virtaddr == NBUSY) {
		cuse_unlock();
		return (ENOMEM);
	}
	page_nr %= CUSE_ALLOC_PAGES_MAX;

	if (page_nr >= mem->page_count) {
		cuse_unlock();
		return (ENXIO);
	}
	ptr = mem->virtaddr + (page_nr * PAGE_SIZE);
	cuse_unlock();

	ap->a_result = vtophys(ptr); // XXX: atop(...) ?

	return (0);
}

/*------------------------------------------------------------------------*
 *	CUSE4BSD CLIENT PART
 *------------------------------------------------------------------------*/
static void
cuse_client_free(void *arg)
{
	struct cuse_client *pcc = arg;
	struct cuse_client_command *pccmd;
	struct cuse_server *pcs;
	int n;

	cuse_lock();
	cuse_client_is_closing(pcc);
	TAILQ_REMOVE(&pcc->server->hcli, pcc, entry);
	cuse_unlock();

	for (n = 0; n != CUSE_CMD_MAX; n++) {

		pccmd = &pcc->cmds[n];

		lockuninit(&pccmd->lk);
		cv_destroy(&pccmd->cv);
	}

	pcs = pcc->server;

	kfree(pcc, M_CUSE4BSD);

	/* drop reference on server */
	cuse_server_free(pcs);
}

static int
cuse_client_open(struct dev_open_args *ap)
{
	struct file *fp = ap->a_fp;
	cdev_t dev = ap->a_head.a_dev;

	struct cuse_client_command *pccmd;
	struct cuse_server_dev *pcsd;
	struct cuse_client *pcc;
	struct cuse_server *pcs;
	struct cuse_dev *pcd;
	int error;
	int n;

	cuse_lock();
	pcsd = dev->si_drv1;
	if (pcsd != NULL) {
		pcs = pcsd->server;
		pcd = pcsd->user_dev;
		pcs->refs++;
		if (pcs->refs < 0) {
			/* overflow */
			pcs->refs--;
			pcsd = NULL;
		}
	} else {
		pcs = NULL;
		pcd = NULL;
	}
	cuse_unlock();

	if (pcsd == NULL)
		return (EINVAL);

	pcc = kmalloc(sizeof(*pcc), M_CUSE4BSD, M_WAITOK | M_ZERO);
	if (pcc == NULL) {
		/* drop reference on server */
		cuse_server_free(pcs);
		return (ENOMEM);
	}
	if (devfs_set_cdevpriv(fp, pcc, &cuse_client_free)) {
		kprintf("Cuse4BSD: Cannot set cdevpriv.\n");
		/* drop reference on server */
		cuse_server_free(pcs);
		kfree(pcc, M_CUSE4BSD);
		return (ENOMEM);
	}
	pcc->fflags = ap->a_oflags;
	pcc->server_dev = pcsd;
	pcc->server = pcs;

	for (n = 0; n != CUSE_CMD_MAX; n++) {

		pccmd = &pcc->cmds[n];

		pccmd->sub.dev = pcd;
		pccmd->sub.command = n;
		pccmd->client = pcc;

		lockinit(&pccmd->lk, "cuse-client-sx", 0, LK_CANRECURSE);
		cv_init(&pccmd->cv, "cuse-client-cv");
	}

	cuse_lock();

	/* cuse_client_free() assumes that the client is listed somewhere! */
	/* always enqueue */

	TAILQ_INSERT_TAIL(&pcs->hcli, pcc, entry);

	/* check if server is closing */
	if ((pcs->is_closing != 0) || (dev->si_drv1 == NULL)) {
		error = EINVAL;
	} else {
		error = 0;
	}
	cuse_unlock();

	if (error) {
		devfs_clear_cdevpriv(fp);	/* XXX bugfix */
		return (error);
	}
	pccmd = &pcc->cmds[CUSE_CMD_OPEN];

	cuse_cmd_lock(pccmd);

	cuse_lock();
	cuse_client_send_command_locked(pccmd, 0, 0, pcc->fflags, 0);

	error = cuse_client_receive_command_locked(pccmd, 0, 0);
	cuse_unlock();

	if (error < 0) {
		error = cuse_convert_error(error);
	} else {
		error = 0;
	}

	cuse_cmd_unlock(pccmd);

	if (error)
		devfs_clear_cdevpriv(fp);	/* XXX bugfix */

	return (error);
}

static int
cuse_client_close(struct dev_close_args *ap)
{
	struct file *fp = ap->a_fp;
	struct cuse_client_command *pccmd;
	struct cuse_client *pcc;
	int error;

	error = cuse_client_get(fp, &pcc);
	if (error != 0)
		return (0);

	pccmd = &pcc->cmds[CUSE_CMD_CLOSE];

	cuse_cmd_lock(pccmd);

	cuse_lock();
	cuse_client_send_command_locked(pccmd, 0, 0, pcc->fflags, 0);

	error = cuse_client_receive_command_locked(pccmd, 0, 0);
	cuse_unlock();

	cuse_cmd_unlock(pccmd);

	cuse_lock();
	cuse_client_is_closing(pcc);
	cuse_unlock();

	return (0);
}

static void
cuse_client_kqfilter_poll(struct cdev *dev, struct cuse_client *pcc)
{
	int temp;

	cuse_lock();
	temp = (pcc->cflags & (CUSE_CLI_KNOTE_HAS_READ |
	    CUSE_CLI_KNOTE_HAS_WRITE));
	pcc->cflags &= ~(CUSE_CLI_KNOTE_NEED_READ |
	    CUSE_CLI_KNOTE_NEED_WRITE);
	cuse_unlock();

	if (temp != 0) {
		/* get the latest polling state from the server */
#if TODO
		temp = cuse_client_poll(dev, POLLIN | POLLOUT, NULL);
#endif

		cuse_lock();
		if (temp & (POLLIN | POLLOUT)) {
			if (temp & POLLIN)
				pcc->cflags |= CUSE_CLI_KNOTE_NEED_READ;
			if (temp & POLLOUT)
				pcc->cflags |= CUSE_CLI_KNOTE_NEED_WRITE;

			/* make sure the "knote" gets woken up */
			cuse_server_wakeup_locked(pcc->server);
		}
		cuse_unlock();
	}
}

static int
cuse_client_read(struct dev_read_args *ap)
{
	cdev_t dev = ap->a_head.a_dev;
	struct file *fp = ap->a_fp;
	struct uio *uio = ap->a_uio;
	int ioflag = ap->a_ioflag;

	struct cuse_client_command *pccmd;
	struct cuse_client *pcc;
	int error;
	int len;

	error = cuse_client_get(fp, &pcc);
	if (error != 0)
		return (error);

	pccmd = &pcc->cmds[CUSE_CMD_READ];

	if (uio->uio_segflg != UIO_USERSPACE) {
		return (EINVAL);
	}
	uio->uio_segflg = UIO_NOCOPY;

	cuse_cmd_lock(pccmd);

	while (uio->uio_resid != 0) {

		if (uio->uio_iov->iov_len > CUSE_LENGTH_MAX) {
			error = ENOMEM;
			break;
		}

		len = uio->uio_iov->iov_len;

		cuse_lock();
		cuse_client_send_command_locked(pccmd,
		    (unsigned long)uio->uio_iov->iov_base,
		    (unsigned long)(unsigned int)len, pcc->fflags, ioflag);

		error = cuse_client_receive_command_locked(pccmd, 0, 0);
		cuse_unlock();

		if (error < 0) {
			error = cuse_convert_error(error);
			break;
		} else if (error == len) {
			error = uiomove(NULL, error, uio);
			if (error)
				break;
		} else {
			error = uiomove(NULL, error, uio);
			break;
		}
	}
	cuse_cmd_unlock(pccmd);

	uio->uio_segflg = UIO_USERSPACE;/* restore segment flag */

	if (error == EWOULDBLOCK)
		cuse_client_kqfilter_poll(dev, pcc);

	return (error);
}

static int
cuse_client_write(struct dev_write_args *ap)
{
	cdev_t dev = ap->a_head.a_dev;
	struct file *fp = ap->a_fp;
	struct uio *uio = ap->a_uio;
	int ioflag = ap->a_ioflag;

	struct cuse_client_command *pccmd;
	struct cuse_client *pcc;
	int error;
	int len;

	error = cuse_client_get(fp, &pcc);
	if (error != 0)
		return (error);

	pccmd = &pcc->cmds[CUSE_CMD_WRITE];

	if (uio->uio_segflg != UIO_USERSPACE) {
		return (EINVAL);
	}
	uio->uio_segflg = UIO_NOCOPY;

	cuse_cmd_lock(pccmd);

	while (uio->uio_resid != 0) {

		if (uio->uio_iov->iov_len > CUSE_LENGTH_MAX) {
			error = ENOMEM;
			break;
		}

		len = uio->uio_iov->iov_len;

		cuse_lock();
		cuse_client_send_command_locked(pccmd,
		    (unsigned long)uio->uio_iov->iov_base,
		    (unsigned long)(unsigned int)len, pcc->fflags, ioflag);

		error = cuse_client_receive_command_locked(pccmd, 0, 0);
		cuse_unlock();

		if (error < 0) {
			error = cuse_convert_error(error);
			break;
		} else if (error == len) {
			error = uiomove(NULL, error, uio);
			if (error)
				break;
		} else {
			error = uiomove(NULL, error, uio);
			break;
		}
	}
	cuse_cmd_unlock(pccmd);

	uio->uio_segflg = UIO_USERSPACE;/* restore segment flag */

	if (error == EWOULDBLOCK)
		cuse_client_kqfilter_poll(dev, pcc);

	return (error);
}

int
cuse_client_ioctl(struct dev_ioctl_args *ap)
{
	struct file *fp = ap->a_fp;
	cdev_t dev = ap->a_head.a_dev;
	u_long cmd = ap->a_cmd;
	caddr_t data = ap->a_data;
	int fflag = ap->a_fflag;

	struct cuse_client_command *pccmd;
	struct cuse_client *pcc;
	int error;
	int len;

	error = cuse_client_get(fp, &pcc);
	if (error != 0)
		return (error);

	len = IOCPARM_LEN(cmd);
	if (len > CUSE_BUFFER_MAX)
		return (ENOMEM);

	pccmd = &pcc->cmds[CUSE_CMD_IOCTL];

	cuse_cmd_lock(pccmd);

	if (cmd & IOC_IN)
		memcpy(pcc->ioctl_buffer, data, len);

	/*
	 * When the ioctl-length is zero drivers can pass information
	 * through the data pointer of the ioctl. Make sure this information
	 * is forwarded to the driver.
	 */

	cuse_lock();
	cuse_client_send_command_locked(pccmd,
	    (len == 0) ? *(long *)data : CUSE_BUF_MIN_PTR,
	    (unsigned long)cmd, pcc->fflags,
	    (fflag & O_NONBLOCK) ? IO_NDELAY : 0);

	error = cuse_client_receive_command_locked(pccmd, data, len);
	cuse_unlock();

	if (error < 0) {
		error = cuse_convert_error(error);
	} else {
		error = 0;
	}

	if (cmd & IOC_OUT)
		memcpy(data, pcc->ioctl_buffer, len);

	cuse_cmd_unlock(pccmd);

	if (error == EWOULDBLOCK)
		cuse_client_kqfilter_poll(dev, pcc);

	return (error);
}

#ifdef TODO
static int
cuse_client_poll(struct cdev *dev, int events, struct thread *td)
{
	struct cuse_client_command *pccmd;
	struct cuse_client *pcc;
	unsigned long temp;
	int error;
	int revents;

	error = cuse_client_get(fp, &pcc);
	if (error != 0)
		return (POLLNVAL);

	temp = 0;

	if (events & (POLLPRI | POLLIN | POLLRDNORM))
		temp |= CUSE_POLL_READ;

	if (events & (POLLOUT | POLLWRNORM))
		temp |= CUSE_POLL_WRITE;

	if (events & POLLHUP)
		temp |= CUSE_POLL_ERROR;

	pccmd = &pcc->cmds[CUSE_CMD_POLL];

	cuse_cmd_lock(pccmd);

	/* Need to selrecord() first to not loose any events. */
	if (temp != 0 && td != NULL)
		selrecord(td, &pcc->server->selinfo);

	cuse_lock();
	cuse_client_send_command_locked(pccmd,
	    0, temp, pcc->fflags, IO_NDELAY);

	error = cuse_client_receive_command_locked(pccmd, 0, 0);
	cuse_unlock();

	if (error < 0) {
		revents = POLLNVAL;
	} else {
		revents = 0;
		if (error & CUSE_POLL_READ)
			revents |= (events & (POLLPRI | POLLIN | POLLRDNORM));
		if (error & CUSE_POLL_WRITE)
			revents |= (events & (POLLOUT | POLLWRNORM));
		if (error & CUSE_POLL_ERROR)
			revents |= (events & POLLHUP);
	}

	cuse_cmd_unlock(pccmd);

	return (revents);
}
#endif

static int
cuse_client_mmap(struct dev_mmap_args *ap)
{
	struct file *fp = ap->a_fp;
	uint32_t page_nr = ap->a_offset / PAGE_SIZE;
	uint32_t alloc_nr = page_nr / CUSE_ALLOC_PAGES_MAX;
	struct cuse_memory *mem;
	struct cuse_server *pcs;
	struct cuse_client *pcc;
	uint8_t *ptr;
	int error;

	if (alloc_nr >= CUSE_ALLOC_UNIT_MAX)
		return (ENOMEM);

	error = cuse_client_get(fp, &pcc);
	if (error != 0)
		pcs = NULL;
	else
		pcs = pcc->server;

	cuse_lock();
	mem = &cuse_mem[alloc_nr];

	/* try to enforce slight ownership */
	if ((pcs != NULL) && (mem->owner != pcs)) {
		cuse_unlock();
		return (EINVAL);
	}
	if (mem->virtaddr == NULL) {
		cuse_unlock();
		return (ENOMEM);
	}
	if (mem->virtaddr == NBUSY) {
		cuse_unlock();
		return (ENOMEM);
	}
	page_nr %= CUSE_ALLOC_PAGES_MAX;

	if (page_nr >= mem->page_count) {
		cuse_unlock();
		return (ENXIO);
	}
	ptr = mem->virtaddr + (page_nr * PAGE_SIZE);
	cuse_unlock();

	ap->a_result = vtophys(ptr); // XXX: atop(...) ?

	return (0);
}

static void
cuse_client_kqfilter_read_detach(struct knote *kn)
{
	struct cuse_client *pcc;

	cuse_lock();
	pcc = (struct cuse_client *)kn->kn_hook;
#ifdef TODO
	knlist_remove(&pcc->server->selinfo.ki_note, kn, 1);
#endif
	cuse_unlock();
}

static void
cuse_client_kqfilter_write_detach(struct knote *kn)
{
	struct cuse_client *pcc;

	cuse_lock();
	pcc = (struct cuse_client *)kn->kn_hook;
#ifdef TODO
	knlist_remove(&pcc->server->selinfo.ki_note, kn, 1);
#endif
	cuse_unlock();
}

static int
cuse_client_kqfilter_read_event(struct knote *kn, long hint)
{
	struct cuse_client *pcc;

	KKASSERT(lockstatus(&cuse_lk, curthread) != 0);

	pcc = (struct cuse_client *)kn->kn_hook;
	return ((pcc->cflags & CUSE_CLI_KNOTE_NEED_READ) ? 1 : 0);
}

static int
cuse_client_kqfilter_write_event(struct knote *kn, long hint)
{
	struct cuse_client *pcc;

	KKASSERT(lockstatus(&cuse_lk, curthread) != 0);

	pcc = (struct cuse_client *)kn->kn_hook;
	return ((pcc->cflags & CUSE_CLI_KNOTE_NEED_WRITE) ? 1 : 0);
}

static int
cuse_client_kqfilter(struct dev_kqfilter_args *ap)
{
	struct file *fp = ap->a_fp;
	struct knote *kn = ap->a_kn;

	struct cuse_client *pcc;
	struct cuse_server *pcs;
	int error;

	error = cuse_client_get(fp, &pcc);
	if (error != 0)
		return (error);

	cuse_lock();
	pcs = pcc->server;
	switch (kn->kn_filter) {
	case EVFILT_READ:
		pcc->cflags |= CUSE_CLI_KNOTE_HAS_READ;
		kn->kn_hook = (void *)pcc;
		kn->kn_fop = &cuse_client_kqfilter_read_ops;
#ifdef TODO
		knlist_add(&pcs->selinfo.ki_note, kn, 1);
#endif
		break;
	case EVFILT_WRITE:
		pcc->cflags |= CUSE_CLI_KNOTE_HAS_WRITE;
		kn->kn_hook = (void *)pcc;
		kn->kn_fop = &cuse_client_kqfilter_write_ops;
#ifdef TODO
		knlist_add(&pcs->selinfo.ki_note, kn, 1);
#endif
		break;
	default:
		error = EINVAL;
		break;
	}
	cuse_unlock();

#ifdef TODO
	if (error == 0)
		cuse_client_kqfilter_poll(dev, pcc);
#endif
	return (error);
}
