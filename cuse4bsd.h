/*-
 * Copyright (c) 2010-2012 Hans Petter Selasky. All rights reserved.
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

#ifndef _CUSE4BSD_H_
#define	_CUSE4BSD_H_

#ifdef __cplusplus
extern "C" {
#endif

struct cuse_dev;

#define	CUSE_VERSION		0x000121

#define	CUSE_ERR_NONE		0
#define	CUSE_ERR_BUSY		-1
#define	CUSE_ERR_WOULDBLOCK	-2
#define	CUSE_ERR_INVALID	-3
#define	CUSE_ERR_NO_MEMORY	-4
#define	CUSE_ERR_FAULT		-5
#define	CUSE_ERR_SIGNAL		-6
#define	CUSE_ERR_OTHER		-7
#define	CUSE_ERR_NOT_LOADED	-8

#define	CUSE_POLL_NONE		0
#define	CUSE_POLL_READ		1
#define	CUSE_POLL_WRITE		2
#define	CUSE_POLL_ERROR		4

#define	CUSE_FFLAG_NONE		0
#define	CUSE_FFLAG_READ		1
#define	CUSE_FFLAG_WRITE	2
#define	CUSE_FFLAG_NONBLOCK	4

#define	CUSE_DBG_NONE		0
#define	CUSE_DBG_FULL		1

/* maximum data transfer length */
#define	CUSE_LENGTH_MAX		0x7FFFFFFFU

enum {
	CUSE_CMD_NONE,
	CUSE_CMD_OPEN,
	CUSE_CMD_CLOSE,
	CUSE_CMD_READ,
	CUSE_CMD_WRITE,
	CUSE_CMD_IOCTL,
	CUSE_CMD_POLL,
	CUSE_CMD_SIGNAL,
	CUSE_CMD_SYNC,
	CUSE_CMD_MAX,
};

typedef int (cuse_open_t)(struct cuse_dev *, int fflags);
typedef int (cuse_close_t)(struct cuse_dev *, int fflags);
typedef int (cuse_read_t)(struct cuse_dev *, int fflags, void *user_ptr, int len);
typedef int (cuse_write_t)(struct cuse_dev *, int fflags, const void *user_ptr, int len);
typedef int (cuse_ioctl_t)(struct cuse_dev *, int fflags, unsigned long cmd, void *user_data);
typedef int (cuse_poll_t)(struct cuse_dev *, int fflags, int events);

struct cuse_methods {
	cuse_open_t *cm_open;
	cuse_close_t *cm_close;
	cuse_read_t *cm_read;
	cuse_write_t *cm_write;
	cuse_ioctl_t *cm_ioctl;
	cuse_poll_t *cm_poll;
};

int	cuse_init(void);
int	cuse_uninit(void);

void   *cuse_vmalloc(int);
int	cuse_is_vmalloc_addr(void *);
void	cuse_vmfree(void *);
unsigned long cuse_vmoffset(void *ptr);

#define	CUSE_MAKE_ID(a,b,c,u) ((((a) & 0x7F) << 24)| \
    (((b) & 0xFF) << 16)|(((c) & 0xFF) << 8)|((u) & 0xFF))

#define	CUSE_ID_MASK 0x7FFFFF00U

/*
 * The following ID's are defined:
 * ===============================
 */
#define	CUSE_ID_DEFAULT(what) CUSE_MAKE_ID(0,0,what,0)
#define	CUSE_ID_WEBCAMD(what) CUSE_MAKE_ID('W','C',what,0)	/* Used by Webcamd. */
#define	CUSE_ID_SUNDTEK(what) CUSE_MAKE_ID('S','K',what,0)	/* Used by Sundtek. */
#define	CUSE_ID_CX88(what) CUSE_MAKE_ID('C','X',what,0)		/* Used by cx88 driver. */
#define	CUSE_ID_UHIDD(what) CUSE_MAKE_ID('U','D',what,0)	/* Used by uhidd. */

int	cuse_alloc_unit_number_by_id(int *, int);
int	cuse_free_unit_number_by_id(int, int);
int	cuse_alloc_unit_number(int *);
int	cuse_free_unit_number(int);

struct cuse_dev *cuse_dev_create(const struct cuse_methods *, void *, void *, uid_t, gid_t, int, const char *,...);
void	cuse_dev_destroy(struct cuse_dev *);

void   *cuse_dev_get_priv0(struct cuse_dev *);
void   *cuse_dev_get_priv1(struct cuse_dev *);

void	cuse_dev_set_priv0(struct cuse_dev *, void *);
void	cuse_dev_set_priv1(struct cuse_dev *, void *);

void	cuse_set_local(int);

int	cuse_wait_and_process(void);

void	cuse_dev_set_per_file_handle(struct cuse_dev *, void *);
void   *cuse_dev_get_per_file_handle(struct cuse_dev *);

int	cuse_copy_out(const void *src, void *user_dst, int len);
int	cuse_copy_in(const void *user_src, void *dst, int len);
int	cuse_got_peer_signal(void);
void	cuse_poll_wakeup(void);

struct cuse_dev *cuse_dev_get_current(int *);

extern int cuse_debug_level;

#ifdef HAVE_CUSE_IOCTL

#include <sys/ioccom.h>

#define	CUSE_BUFFER_MAX		PAGE_SIZE
#define	CUSE_DEVICES_MAX	64	/* units */
#define	CUSE_BUF_MIN_PTR	0x10000UL
#define	CUSE_BUF_MAX_PTR	0x20000UL
#define	CUSE_ALLOC_UNIT_MAX	128	/* units */
#define	CUSE_ALLOC_PAGES_MAX	(((16UL * 1024UL * 1024UL) + PAGE_SIZE - 1) / PAGE_SIZE)

struct cuse_data_chunk {
	unsigned long local_ptr;
	unsigned long peer_ptr;
	unsigned long length;
};

struct cuse_alloc_info {
	unsigned long page_count;
	unsigned long alloc_nr;
};

struct cuse_command {
	struct cuse_dev *dev;
	unsigned long fflags;
	unsigned long per_file_handle;
	unsigned long data_pointer;
	unsigned long argument;
	unsigned long command;		/* see CUSE_CMD_XXX */
};

struct cuse_create_dev {
	struct cuse_dev *dev;
	uid_t	user_id;
	gid_t	group_id;
	int	permissions;
	char	devname[80];		/* /dev/xxxxx */
};

/* Definition of internal IOCTLs for /dev/cuse */

#define	CUSE_IOCTL_GET_COMMAND		_IOR('C', 0, struct cuse_command)
#define	CUSE_IOCTL_WRITE_DATA		_IOW('C', 1, struct cuse_data_chunk)
#define	CUSE_IOCTL_READ_DATA		_IOW('C', 2, struct cuse_data_chunk)
#define	CUSE_IOCTL_SYNC_COMMAND		_IOW('C', 3, int)
#define	CUSE_IOCTL_GET_SIG		_IOR('C', 4, int)
#define	CUSE_IOCTL_ALLOC_MEMORY		_IOW('C', 5, struct cuse_alloc_info)
#define	CUSE_IOCTL_FREE_MEMORY		_IOW('C', 6, struct cuse_alloc_info)
#define	CUSE_IOCTL_SET_PFH		_IOW('C', 7, unsigned long)
#define	CUSE_IOCTL_CREATE_DEV		_IOW('C', 8, struct cuse_create_dev)
#define	CUSE_IOCTL_DESTROY_DEV		_IOW('C', 9, struct cuse_dev *)
#define	CUSE_IOCTL_ALLOC_UNIT		_IOR('C',10, int)
#define	CUSE_IOCTL_FREE_UNIT		_IOW('C',11, int)
#define	CUSE_IOCTL_SELWAKEUP		_IOW('C',12, int)
#define	CUSE_IOCTL_ALLOC_UNIT_BY_ID	_IOWR('C',13, int)
#define	CUSE_IOCTL_FREE_UNIT_BY_ID	_IOWR('C',14, int)

#endif					/* HAVE_CUSE_IOCTL */

#ifdef __cplusplus
}
#endif

#endif					/* _CUSE4BSD_H_ */

