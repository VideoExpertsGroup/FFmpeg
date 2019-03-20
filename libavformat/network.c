/*
 * Copyright (c) 2007 The FFmpeg Project
 *
 * This file is part of FFmpeg.
 *
 * FFmpeg is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * FFmpeg is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with FFmpeg; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <fcntl.h>
#include "network.h"
#include "tls.h"
#include "url.h"
#include "libavcodec/internal.h"
#include "libavutil/avutil.h"
#include "libavutil/mem.h"
#include "libavutil/time.h"

#if HAVE_THREADS
#if HAVE_PTHREADS
#include <pthread.h>
#elif HAVE_OS2THREADS
#include "compat/os2threads.h"
#else
#include "compat/w32pthreads.h"
#endif
#endif

int ff_tls_init(void)
{
#if CONFIG_TLS_OPENSSL_PROTOCOL
    int ret;
    if ((ret = ff_openssl_init()) < 0)
        return ret;
#endif
#if CONFIG_TLS_GNUTLS_PROTOCOL
    ff_gnutls_init();
#endif
    return 0;
}

void ff_tls_deinit(void)
{
#if CONFIG_TLS_OPENSSL_PROTOCOL
    ff_openssl_deinit();
#endif
#if CONFIG_TLS_GNUTLS_PROTOCOL
    ff_gnutls_deinit();
#endif
}

int ff_network_inited_globally;

int ff_network_init(void)
{
#if HAVE_WINSOCK2_H
    WSADATA wsaData;
#endif

    if (!ff_network_inited_globally)
        av_log(NULL, AV_LOG_WARNING, "Using network protocols without global "
                                     "network initialization. Please use "
                                     "avformat_network_init(), this will "
                                     "become mandatory later.\n");
#if HAVE_WINSOCK2_H
    if (WSAStartup(MAKEWORD(1,1), &wsaData))
        return 0;
#endif
    return 1;
}

int ff_network_wait_fd(int fd, int write)
{
    int ev = write ? POLLOUT : POLLIN;
    struct pollfd p = { .fd = fd, .events = ev, .revents = 0 };
    int ret;
    ret = poll(&p, 1, POLLING_TIME);
    return ret < 0 ? ff_neterrno() : p.revents & (ev | POLLERR | POLLHUP) ? 0 : AVERROR(EAGAIN);
}

int ff_network_wait_fd_timeout(int fd, int write, int64_t timeout, AVIOInterruptCB *int_cb)
{
    int ret;
    int64_t wait_start = 0;

    while (1) {
        if (ff_check_interrupt(int_cb))
            return AVERROR_EXIT;
        ret = ff_network_wait_fd(fd, write);
        if (ret != AVERROR(EAGAIN))
            return ret;
        if (timeout > 0) {
            if (!wait_start)
                wait_start = av_gettime_relative();
            else if (av_gettime_relative() - wait_start > timeout)
                return AVERROR(ETIMEDOUT);
            }
    }
}

void ff_network_close(void)
{
#if HAVE_WINSOCK2_H
    WSACleanup();
#endif
}

#if HAVE_WINSOCK2_H
int ff_neterrno(void)
{
    int err = WSAGetLastError();
    switch (err) {
    case WSAEWOULDBLOCK:
        return AVERROR(EAGAIN);
    case WSAEINTR:
        return AVERROR(EINTR);
    case WSAEPROTONOSUPPORT:
        return AVERROR(EPROTONOSUPPORT);
    case WSAETIMEDOUT:
        return AVERROR(ETIMEDOUT);
    case WSAECONNREFUSED:
        return AVERROR(ECONNREFUSED);
    case WSAEINPROGRESS:
        return AVERROR(EINPROGRESS);
    }
    return -err;
}
#endif

int ff_is_multicast_address(struct sockaddr *addr)
{
    if (addr->sa_family == AF_INET) {
        return IN_MULTICAST(ntohl(((struct sockaddr_in *)addr)->sin_addr.s_addr));
    }
#if HAVE_STRUCT_SOCKADDR_IN6
    if (addr->sa_family == AF_INET6) {
        return IN6_IS_ADDR_MULTICAST(&((struct sockaddr_in6 *)addr)->sin6_addr);
    }
#endif

    return 0;
}

static int ff_poll_interrupt(struct pollfd *p, nfds_t nfds, int timeout,
                             AVIOInterruptCB *cb)
{
    int runs = timeout / POLLING_TIME;
    int ret = 0;

    do {
        if (ff_check_interrupt(cb))
            return AVERROR_EXIT;
        ret = poll(p, nfds, POLLING_TIME);
        if (ret != 0) {
            if (ret < 0)
                ret = ff_neterrno();
            if (ret == AVERROR(EINTR))
                continue;
            break;
        }
    } while (timeout <= 0 || runs-- > 0);

    if (!ret)
        return AVERROR(ETIMEDOUT);
    return ret;
}

int ff_socket(int af, int type, int proto)
{
    int fd;

#ifdef SOCK_CLOEXEC
    fd = socket(af, type | SOCK_CLOEXEC, proto);
    if (fd == -1 && errno == EINVAL)
#endif
    {
        fd = socket(af, type, proto);
#if HAVE_FCNTL
        if (fd != -1) {
            if (fcntl(fd, F_SETFD, FD_CLOEXEC) == -1)
                av_log(NULL, AV_LOG_DEBUG, "Failed to set close on exec\n");
        }
#endif
    }
#ifdef SO_NOSIGPIPE
    if (fd != -1) {
        if (setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &(int){1}, sizeof(int))) {
             av_log(NULL, AV_LOG_WARNING, "setsockopt(SO_NOSIGPIPE) failed\n");
        }
    }
#endif
    return fd;
}

int ff_listen(int fd, const struct sockaddr *addr,
              socklen_t addrlen)
{
    int ret;
    int reuse = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse))) {
        av_log(NULL, AV_LOG_WARNING, "setsockopt(SO_REUSEADDR) failed\n");
    }
    ret = bind(fd, addr, addrlen);
    if (ret)
        return ff_neterrno();

    ret = listen(fd, 1);
    if (ret)
        return ff_neterrno();
    return ret;
}

int ff_accept(int fd, int timeout, URLContext *h)
{
    int ret;
    struct pollfd lp = { fd, POLLIN, 0 };

    ret = ff_poll_interrupt(&lp, 1, timeout, &h->interrupt_callback);
    if (ret < 0)
        return ret;

    ret = accept(fd, NULL, NULL);
    if (ret < 0)
        return ff_neterrno();
    if (ff_socket_nonblock(ret, 1) < 0)
        av_log(NULL, AV_LOG_DEBUG, "ff_socket_nonblock failed\n");

    return ret;
}

int ff_listen_bind(int fd, const struct sockaddr *addr,
                   socklen_t addrlen, int timeout, URLContext *h)
{
    int ret;
    if ((ret = ff_listen(fd, addr, addrlen)) < 0)
        return ret;
    if ((ret = ff_accept(fd, timeout, h)) < 0)
        return ret;
    closesocket(fd);
    return ret;
}

int ff_listen_connect(int fd, const struct sockaddr *addr,
                      socklen_t addrlen, int timeout, URLContext *h,
                      int will_try_next)
{
    struct pollfd p = {fd, POLLOUT, 0};
    int ret;
    socklen_t optlen;

    if (ff_socket_nonblock(fd, 1) < 0)
        av_log(NULL, AV_LOG_DEBUG, "ff_socket_nonblock failed\n");

    while ((ret = connect(fd, addr, addrlen))) {
        ret = ff_neterrno();
        switch (ret) {
        case AVERROR(EINTR):
            if (ff_check_interrupt(&h->interrupt_callback))
                return AVERROR_EXIT;
            continue;
        case AVERROR(EINPROGRESS):
        case AVERROR(EAGAIN):
            ret = ff_poll_interrupt(&p, 1, timeout, &h->interrupt_callback);
            if (ret < 0)
                return ret;
            optlen = sizeof(ret);
            if (getsockopt (fd, SOL_SOCKET, SO_ERROR, &ret, &optlen))
                ret = AVUNERROR(ff_neterrno());
            if (ret != 0) {
                char errbuf[100];
                ret = AVERROR(ret);
                av_strerror(ret, errbuf, sizeof(errbuf));
                if (will_try_next)
                    av_log(h, AV_LOG_WARNING,
                           "Connection to %s failed (%s), trying next address\n",
                           h->filename, errbuf);
                else
                    av_log(h, AV_LOG_ERROR, "Connection to %s failed: %s\n",
                           h->filename, errbuf);
            }
        default:
            return ret;
        }
    }
    return ret;
}

static int match_host_pattern(const char *pattern, const char *hostname)
{
    int len_p, len_h;
    if (!strcmp(pattern, "*"))
        return 1;
    // Skip a possible *. at the start of the pattern
    if (pattern[0] == '*')
        pattern++;
    if (pattern[0] == '.')
        pattern++;
    len_p = strlen(pattern);
    len_h = strlen(hostname);
    if (len_p > len_h)
        return 0;
    // Simply check if the end of hostname is equal to 'pattern'
    if (!strcmp(pattern, &hostname[len_h - len_p])) {
        if (len_h == len_p)
            return 1; // Exact match
        if (hostname[len_h - len_p - 1] == '.')
            return 1; // The matched substring is a domain and not just a substring of a domain
    }
    return 0;
}

int ff_http_match_no_proxy(const char *no_proxy, const char *hostname)
{
    char *buf, *start;
    int ret = 0;
    if (!no_proxy)
        return 0;
    if (!hostname)
        return 0;
    buf = av_strdup(no_proxy);
    if (!buf)
        return 0;
    start = buf;
    while (start) {
        char *sep, *next = NULL;
        start += strspn(start, " ,");
        sep = start + strcspn(start, " ,");
        if (*sep) {
            next = sep + 1;
            *sep = '\0';
        }
        if (match_host_pattern(start, hostname)) {
            ret = 1;
            break;
        }
        start = next;
    }
    av_free(buf);
    return ret;
}

#define ASYNC_GET_ADDR_INFO

//#ifdef ASYNC_GET_ADDR_INFO
// #include <sys/types.h>
// #include <sys/socket.h>
// #include <netinet/in.h>
// #include <netdb.h>

#define ASYNC_GET_ADDR_INFO_STACK_SIZE (100 * 1024)

typedef struct addrinfo_a {
    char            *node;
    char            *service;
    struct addrinfo *hints;
    struct addrinfo **res;
    int             ready;
    int             ret;
    int             exit;
    int             interrupted;
    pthread_mutex_t lock;
} addrinfo_a;

static struct addrinfo* copy_addrinfo(const struct addrinfo* info)
{
    struct addrinfo* copy = av_malloc(sizeof(struct addrinfo));

    // Copy all the fields (some of these are pointers, we will fix that next).
    memcpy(copy, info, sizeof(struct addrinfo));

    // ai_canonname is a NULL-terminated string.
    if (info->ai_canonname) {
        copy->ai_canonname = strdup(info->ai_canonname);
    }

    // ai_addr is a buffer of length ai_addrlen.
    if (info->ai_addr) {
        copy->ai_addr = (struct sockaddr*)av_malloc(info->ai_addrlen);
        memcpy(copy->ai_addr, info->ai_addr, info->ai_addrlen);
    }

    // Recursive copy.
    if (info->ai_next)
        copy->ai_next = copy_addrinfo(info->ai_next);

    return copy;
}

// free an addrinfo that was created by copy_addrinfo().
static void free_addrinfo(struct addrinfo* info)
{
    struct addrinfo* next = info->ai_next;

    if (info->ai_canonname)
        free(info->ai_canonname);  // Allocated by strdup.

    if (info->ai_addr)
        av_free(info->ai_addr);

    free(info);

    // Recursive free.
    if (next)
        free_addrinfo(next);
}

static void *input_thread(void *arg)
{
    addrinfo_a *f = arg;
    int ret = -1;
    struct addrinfo* res = NULL;

    av_log(NULL, AV_LOG_DEBUG, "getaddrinfo_a input_thread: id %lu, %p\n", pthread_self(), f);
    pthread_mutex_lock(&f->lock);
    if (f->exit)
    {
        pthread_mutex_unlock(&f->lock);
        pthread_mutex_destroy(&f->lock);
        av_log(NULL, AV_LOG_DEBUG, "av_free(f)1\n");

        if (f->node != NULL)
            free(f->node);
        if (f->service != NULL)
            free(f->service);
        if (f->hints != NULL)
            free_addrinfo(f->hints);

        av_free(f);
        return (void*)ret;
    }
    pthread_mutex_unlock(&f->lock);

    av_log(NULL, AV_LOG_DEBUG, "getaddrinfo_a input_thread: args node %p service %p hints %p res %p\n", f->node, f->service, f->hints, f->res);

    //f->exit 	= 0;
    ret = getaddrinfo(f->node,f->service,f->hints, &res);

    pthread_mutex_lock(&f->lock);
    if (!f->exit)
    {
        *(f->res) = res;
        av_log(NULL, AV_LOG_DEBUG, "getaddrinfo_a input_thread: %lu ret:%d exit:%d\n", pthread_self(), ret, f->exit);
    }
    f->ready = 1;
    pthread_mutex_unlock(&f->lock);

    while (!f->exit)
    {
        av_usleep(100000);
        av_log(NULL, AV_LOG_DEBUG, "getaddrinfo_a input_thread: exit %d\n",f->exit);
    }

    if (f->interrupted && res)
        freeaddrinfo(res);

    pthread_mutex_destroy(&f->lock);

    av_log(NULL, AV_LOG_DEBUG, "getaddrinfo_a input_thread: av_free(f)2\n");
    if (f->node != NULL)
        free(f->node);
    if (f->service != NULL)
        free(f->service);
    if (f->hints != NULL)
        free_addrinfo(f->hints);

    av_free(f);

    av_log(NULL, AV_LOG_DEBUG, "getaddrinfo_a input_thread: exit %d\n",f->exit);
    return (void*)ret;
}

int ff_getaddrinfo_a(URLContext *h, const char *node, const char *service,
                   const struct addrinfo *hints, struct addrinfo **res)
{
    int ret = -1;
    void* thread_ret = NULL;

    pthread_attr_t attr;
    pthread_t thread;

    addrinfo_a* addinfo = av_malloc(sizeof(addrinfo_a));
    av_log(NULL, AV_LOG_DEBUG, "ff_getaddrinfo_a: av_malloc(sizeof(addrinfo_a)) = %p\n", addinfo);
    if (NULL == addinfo)
        return AVERROR(EINVAL);

    addinfo->node           = ((node != NULL) ? strdup(node) : NULL);
    addinfo->service        = ((service != NULL)? strdup(service) : NULL);
    addinfo->hints          = ((hints != NULL)? copy_addrinfo(hints) : NULL);
    addinfo->res            = res;
    addinfo->ready          = 0;
    addinfo->exit           = 0;
    addinfo->interrupted    = 0;

    pthread_mutex_init(&addinfo->lock, NULL);
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, ASYNC_GET_ADDR_INFO_STACK_SIZE);
    if ((ret = pthread_create(&thread, &attr, input_thread, (void*)addinfo)))
    {
        pthread_attr_destroy(&attr);
        pthread_mutex_destroy(&addinfo->lock);
        if (addinfo->node != NULL)
           free(addinfo->node);
        if (addinfo->service != NULL)
           free(addinfo->service);
        if (addinfo->hints != NULL)
           free_addrinfo(addinfo->hints);

        av_free(addinfo);

        av_log(NULL, AV_LOG_ERROR, "ff_getaddrinfo_a: pthread_create failed: %s.\n", strerror(ret));

	return AVERROR(ret);
    }

    pthread_attr_destroy(&attr);

    while (!addinfo->ready)
    {
        if (ff_check_interrupt(&h->interrupt_callback))
        {
            pthread_mutex_lock(&addinfo->lock);
            addinfo->interrupted = 1;
            addinfo->exit = 1;
            av_log(NULL, AV_LOG_ERROR, "ff_getaddrinfo_a: INTERRUPTED addinfo %p\n", addinfo);
            pthread_mutex_unlock(&addinfo->lock);
            pthread_detach(thread);
            return AVERROR_EXIT;
        }
        av_usleep(1000);
        //av_log(NULL, AV_LOG_DEBUG, "getaddrinfo_a: wait %x \n",addinfo);
    }
    addinfo->exit = 1;
    av_log(NULL, AV_LOG_DEBUG, "ff_getaddrinfo_a: READY for %s \n",node);

    pthread_join(thread, &thread_ret);
    ret = (int)thread_ret;

    av_log(NULL, AV_LOG_DEBUG, "ff_getaddrinfo_a: exit %p\n", thread_ret);
    return ret;
}
//#endif
