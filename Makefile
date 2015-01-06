#
# Copyright (c) 2010 Hans Petter Selasky. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#

VERSION=	0.1.35
DESTDIR?=
KMODNAME?=	cuse4bsd
KMODDIR?=	/boot/modules
PREFIX?=	/usr/local
LOCALBASE?=	/usr/local
LIBDIR?=	${PREFIX}/lib
INCLUDEDIR?=	${PREFIX}/include
MANDIR?=	${PREFIX}/man/man

MAKE_ARGS=
.if defined(HAVE_DEBUG)
MAKE_ARGS+=" HAVE_DEBUG=YES"
.endif
.if defined(PTHREAD_LIBS)
MAKE_ARGS+=" PTHREAD_LIBS=${PTHREAD_LIBS}"
.endif

MAKE_ARGS+= " DESTDIR=${DESTDIR}"
MAKE_ARGS+= " KMODNAME=${KMODNAME}"
MAKE_ARGS+= " KMODDIR=${KMODDIR}"
MAKE_ARGS+= " LIBDIR=${LIBDIR}"
MAKE_ARGS+= " INCLUDEDIR=${INCLUDEDIR}"
MAKE_ARGS+= " MANDIR=${MANDIR}"

all:
	make -f ${.CURDIR}/Makefile.lib ${MAKE_ARGS} all
	make -f ${.CURDIR}/Makefile.kmod ${MAKE_ARGS} all

clean:
	make -f ${.CURDIR}/Makefile.lib clean
	make -f ${.CURDIR}/Makefile.kmod clean cleandepend

install:
	make -f ${.CURDIR}/Makefile.lib ${MAKE_ARGS} install
	make -f ${.CURDIR}/Makefile.kmod ${MAKE_ARGS} install

package: clean

	tar -jcvf temp.tar.bz2 --exclude="*.txt" --exclude=".svn" \
	    Makefile Makefile.lib Makefile.kmod *.[3ch] \
	    tests/*.[3ch] tests/Makefile

	rm -rf cuse4bsd-kmod-${VERSION}

	mkdir cuse4bsd-kmod-${VERSION}

	tar -jxvf temp.tar.bz2 -C cuse4bsd-kmod-${VERSION}

	rm -rf temp.tar.bz2

	tar -jcvf cuse4bsd-kmod-${VERSION}.tar.bz2 cuse4bsd-kmod-${VERSION}
