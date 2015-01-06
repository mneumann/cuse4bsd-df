/*-
 * Copyright (c) 2013 Hans Petter Selasky. All rights reserved.
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

#include <stdio.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/event.h>
#include <string.h>
#include <cuse4bsd.h>
#include <pthread.h>
#include <err.h>
#include <fcntl.h>
#include <unistd.h>

static cuse_open_t cuse_open;
static cuse_close_t cuse_close;
static cuse_read_t cuse_read;
static cuse_write_t cuse_write;
static cuse_ioctl_t cuse_ioctl;
static cuse_poll_t cuse_poll;

static struct cuse_methods cuse_methods = {
	.cm_open = cuse_open,
	.cm_close = cuse_close,
	.cm_read = cuse_read,
	.cm_write = cuse_write,
	.cm_ioctl = cuse_ioctl,
	.cm_poll = cuse_poll,
};

static int read_ready;
static int write_ready;
static pthread_t thread;

static int
cuse_open(struct cuse_dev *dev, int fflags)
{
	return (CUSE_ERR_NONE);
}

static int
cuse_close(struct cuse_dev *dev, int fflags)
{
	return (CUSE_ERR_NONE);
}

static int
cuse_read(struct cuse_dev *dev, int fflags, void *peer_ptr, int len)
{
	if (read_ready) {
		read_ready--;
		return (len);
	} else {
		return (CUSE_ERR_WOULDBLOCK);
	}
}

static int
cuse_write(struct cuse_dev *dev, int fflags, const void *peer_ptr, int len)
{
	if (write_ready) {
		write_ready--;
		return (len);
	} else {
		return (CUSE_ERR_WOULDBLOCK);
	}
}

static int
cuse_ioctl(struct cuse_dev *dev, int fflags, unsigned long cmd, void *peer_data)
{
	return (CUSE_ERR_INVALID);
}

static int
cuse_poll(struct cuse_dev *dev, int fflags, int events)
{
	int retval = 0;

	if ((events & CUSE_POLL_READ) && read_ready)
		retval |= CUSE_POLL_READ;
	if ((events & CUSE_POLL_WRITE) && write_ready)
		retval |= CUSE_POLL_WRITE;
	return (retval);
}

static void *
event_thread(void *arg)
{
	while (1) {
		read_ready += 8;
		printf("State change rd=%d wr=%d\n",
		    read_ready, write_ready);
		cuse_poll_wakeup();
		usleep(1000000);

		read_ready += 8;
		write_ready += 8;
		printf("State change rd=%d wr=%d\n",
		    read_ready, write_ready);
		cuse_poll_wakeup();
		usleep(1000000);

		write_ready += 8;
		printf("State change rd=%d wr=%d\n",
		    read_ready, write_ready);
		cuse_poll_wakeup();
		usleep(1000000);
	}
}

static void *
io_thread(void *arg)
{
	struct kevent event[2];
	uint8_t buf[4];
	int f;
	int g;
	int h;
	int n;

	f = open("/dev/testkqfilter", O_RDWR);
	if (f < 0)
		err(1, "Cannot open test file");

	g = kqueue();

	EV_SET(&event[0], f, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, NULL);
	EV_SET(&event[1], f, EVFILT_WRITE, EV_ADD | EV_ENABLE, 0, 0, NULL);

	kevent(g, event, 2, NULL, 0, NULL);

	while (1) {
		memset(event, 0, sizeof(event));
		n = kevent(g, NULL, 0, event, 2, NULL);

		memset(buf, 0, sizeof(buf));

		printf("kevent() = %d, ", n);

		for (h = 0; h < n; h++) {
			if (event[h].filter == EVFILT_WRITE)
				printf("write() = %d, ", (int)write(f, buf, 4));
			if (event[h].filter == EVFILT_READ)
				printf("read() = %d, ", (int)read(f, buf, 4));
		}

		printf("done\n");
	}
	return (NULL);
}

int 
main()
{
	if (cuse_init() != CUSE_ERR_NONE)
		return (0);

	cuse_dev_create(&cuse_methods, NULL, NULL, 0, 0, 0666, "testkqfilter");

	pthread_create(&thread, NULL, event_thread, NULL);
	pthread_create(&thread, NULL, io_thread, NULL);

	while (1)
		cuse_wait_and_process();

	return (0);
}
