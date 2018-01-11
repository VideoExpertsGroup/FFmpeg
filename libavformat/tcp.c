/*
 * TCP protocol
 * Copyright (c) 2002 Fabrice Bellard
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
#include "avformat.h"
#include "libavutil/avassert.h"
#include "libavutil/parseutils.h"
#include "libavutil/threadmessage.h"
#include "libavutil/opt.h"
#include "libavutil/time.h"

#include "internal.h"
#include "network.h"
#include "os_support.h"
#include "url.h"
#include "pthread.h"
#if HAVE_POLL_H
#include <poll.h>
#endif

typedef struct TCPContext {
    const AVClass *class;
    int fd;
    int listen;
    int open_timeout;
    int rw_timeout;
    int listen_timeout;
    int recv_buffer_size;
    int send_buffer_size;
} TCPContext;

#define OFFSET(x) offsetof(TCPContext, x)
#define D AV_OPT_FLAG_DECODING_PARAM
#define E AV_OPT_FLAG_ENCODING_PARAM
static const AVOption options[] = {
    { "listen",          "Listen for incoming connections",  OFFSET(listen),         AV_OPT_TYPE_INT, { .i64 = 0 },     0,       2,       .flags = D|E },
    { "timeout",     "set timeout (in microseconds) of socket I/O operations", OFFSET(rw_timeout),     AV_OPT_TYPE_INT, { .i64 = -1 },         -1, INT_MAX, .flags = D|E },
    { "listen_timeout",  "Connection awaiting timeout (in milliseconds)",      OFFSET(listen_timeout), AV_OPT_TYPE_INT, { .i64 = -1 },         -1, INT_MAX, .flags = D|E },
    { "send_buffer_size", "Socket send buffer size (in bytes)",                OFFSET(send_buffer_size), AV_OPT_TYPE_INT, { .i64 = -1 },         -1, INT_MAX, .flags = D|E },
    { "recv_buffer_size", "Socket receive buffer size (in bytes)",             OFFSET(recv_buffer_size), AV_OPT_TYPE_INT, { .i64 = -1 },         -1, INT_MAX, .flags = D|E },
    { NULL }
};

static const AVClass tcp_class = {
    .class_name = "tcp",
    .item_name  = av_default_item_name,
    .option     = options,
    .version    = LIBAVUTIL_VERSION_INT,
};

#define ASYNC_GET_ADDR_INFO	1

#ifdef ASYNC_GET_ADDR_INFO

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
    if (info->ai_canonname)
        free(info->ai_canonname);  // Allocated by strdup.

    if (info->ai_addr)
        free(info->ai_addr);

    struct addrinfo* next = info->ai_next;
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

    av_log(NULL, AV_LOG_DEBUG, "thread !!!!!!!!!!!!!!!!!! %d !!!!!!!!!!!!!!!!! 0x%x\n", pthread_self(), f);
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

    av_log(NULL, AV_LOG_DEBUG, "getaddrinfo_a input_thread %s %s\n", f->node, f->service);
    av_log(NULL, AV_LOG_DEBUG, "getaddrinfo_a args node %x service %x hints %x res %x\n", f->node, f->service, f->hints, f->res);

    //f->exit 	= 0;
    ret = getaddrinfo(f->node,f->service,f->hints, &res);

    pthread_mutex_lock(&f->lock);
    if (!f->exit)
    {
        *(f->res) = res;
        av_log(NULL, AV_LOG_DEBUG, "getaddrinfo_a input_thread %d ret:%d exit:%d\n", pthread_self(), ret, f->exit);
    }
    f->ready = 1;
    pthread_mutex_unlock(&f->lock);

    while (!f->exit)
    {
        av_usleep(100000);
        av_log(NULL, AV_LOG_DEBUG, "getaddrinfo_a: exit %d\n",f->exit);
    }	
	
    if (f->interrupted && res)
        freeaddrinfo(res);
    
    pthread_mutex_destroy(&f->lock);

    av_log(NULL, AV_LOG_DEBUG, "av_free(f)2\n");
    if (f->node != NULL)
        free(f->node);
    if (f->service != NULL)
        free(f->service);
    if (f->hints != NULL)
        free_addrinfo(f->hints);
  
    av_free(f);

    av_log(NULL, AV_LOG_DEBUG, "getaddrinfo_a input_thread exit:%d\n",f->exit);
    return (void*)ret;
}

static int getaddrinfo_a(URLContext *h, const char *node, const char *service,
                   const struct addrinfo *hints, struct addrinfo **res)
{
    int ret = -1;
    void* thread_ret = NULL;
    
    pthread_attr_t attr;
    pthread_t thread;
    
    addrinfo_a* addinfo = av_malloc(sizeof(addrinfo_a));
    av_log(NULL, AV_LOG_DEBUG, "av_malloc(sizeof(addrinfo_a)) = %d\n", addinfo);
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

        av_log(NULL, AV_LOG_ERROR, "getaddrinfo_a: pthread_create failed: %s.\n", strerror(ret));
	//av_thread_message_queue_free(&h->in_thread_queue);

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
            av_log(NULL, AV_LOG_ERROR, "INTERRUPTED addinfo 0x%x\n", addinfo);
            pthread_mutex_unlock(&addinfo->lock);
            pthread_detach(thread);
            return AVERROR_EXIT;
        }
        av_usleep(1000);
        //av_log(NULL, AV_LOG_DEBUG, "getaddrinfo_a: wait %x \n",addinfo);
    }
    addinfo->exit = 1;
    av_log(NULL, AV_LOG_DEBUG, "getaddrinfo_a: READY for %s \n",node);

    pthread_join(thread, &thread_ret);
    ret = (int)thread_ret;
    
    av_log(NULL, AV_LOG_DEBUG, "getaddrinfo_a: exit %x \n",thread_ret);
    return ret;
}
#endif


/* return non zero if error */
static int tcp_open(URLContext *h, const char *uri, int flags)
{
    struct addrinfo hints = { 0 }, *ai, *cur_ai;
    int port, fd = -1;
    TCPContext *s = h->priv_data;
    const char *p;
    char buf[256];
    int ret;
    char hostname[1024],proto[1024],path[1024];
    char portstr[10];
    s->open_timeout = 5000000;

    av_url_split(proto, sizeof(proto), NULL, 0, hostname, sizeof(hostname),
        &port, path, sizeof(path), uri);
    if (strcmp(proto, "tcp"))
        return AVERROR(EINVAL);
    if (port <= 0 || port >= 65536) {
        av_log(h, AV_LOG_ERROR, "Port missing in uri\n");
        return AVERROR(EINVAL);
    }
    p = strchr(uri, '?');
    if (p) {
        if (av_find_info_tag(buf, sizeof(buf), "listen", p)) {
            char *endptr = NULL;
            s->listen = strtol(buf, &endptr, 10);
            /* assume if no digits were found it is a request to enable it */
            if (buf == endptr)
                s->listen = 1;
        }
        if (av_find_info_tag(buf, sizeof(buf), "timeout", p)) {
            s->rw_timeout = strtol(buf, NULL, 10);
        }
        if (av_find_info_tag(buf, sizeof(buf), "listen_timeout", p)) {
            s->listen_timeout = strtol(buf, NULL, 10);
        }
    }
    if (s->rw_timeout >= 0) {
        s->open_timeout =
        h->rw_timeout   = s->rw_timeout;
    }
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(portstr, sizeof(portstr), "%d", port);
    if (s->listen)
        hints.ai_flags |= AI_PASSIVE;
	#ifdef ASYNC_GET_ADDR_INFO
    if (!hostname[0])
        ret = getaddrinfo_a(h, NULL, portstr, &hints, &ai);
    else
        ret = getaddrinfo_a(h, hostname, portstr, &hints, &ai);
	#else
    if (!hostname[0])
        ret = getaddrinfo(NULL, portstr, &hints, &ai);
    else
        ret = getaddrinfo(hostname, portstr, &hints, &ai);
    #endif    
    if (ret) {
        av_log(h, AV_LOG_ERROR,
               "Failed to resolve hostname %s: %s\n",
               hostname, gai_strerror(ret));
        return AVERROR(EIO);
    }

    cur_ai = ai;

 restart:
    fd = ff_socket(cur_ai->ai_family,
                   cur_ai->ai_socktype,
                   cur_ai->ai_protocol);
    if (fd < 0) {
        ret = ff_neterrno();
        goto fail;
    }

    if (s->listen == 2) {
        // multi-client
        if ((ret = ff_listen(fd, cur_ai->ai_addr, cur_ai->ai_addrlen)) < 0)
            goto fail1;
    } else if (s->listen == 1) {
        // single client
        if ((ret = ff_listen_bind(fd, cur_ai->ai_addr, cur_ai->ai_addrlen,
                                  s->listen_timeout, h)) < 0)
            goto fail1;
        // Socket descriptor already closed here. Safe to overwrite to client one.
        fd = ret;
    } else {
        if ((ret = ff_listen_connect(fd, cur_ai->ai_addr, cur_ai->ai_addrlen,
                                     s->open_timeout / 1000, h, !!cur_ai->ai_next)) < 0) {

            if (ret == AVERROR_EXIT)
                goto fail1;
            else
                goto fail;
        }
    }

    h->is_streamed = 1;
    s->fd = fd;
    /* Set the socket's send or receive buffer sizes, if specified.
       If unspecified or setting fails, system default is used. */
    if (s->recv_buffer_size > 0) {
        setsockopt (fd, SOL_SOCKET, SO_RCVBUF, &s->recv_buffer_size, sizeof (s->recv_buffer_size));
    }
    if (s->send_buffer_size > 0) {
        setsockopt (fd, SOL_SOCKET, SO_SNDBUF, &s->send_buffer_size, sizeof (s->send_buffer_size));
    }

    freeaddrinfo(ai);
    return 0;

 fail:
    if (cur_ai->ai_next) {
        /* Retry with the next sockaddr */
        cur_ai = cur_ai->ai_next;
        if (fd >= 0)
            closesocket(fd);
        ret = 0;
        goto restart;
    }
 fail1:
    if (fd >= 0)
        closesocket(fd);
    freeaddrinfo(ai);
    return ret;
}

static int tcp_accept(URLContext *s, URLContext **c)
{
    TCPContext *sc = s->priv_data;
    TCPContext *cc;
    int ret;
    av_assert0(sc->listen);
    if ((ret = ffurl_alloc(c, s->filename, s->flags, &s->interrupt_callback)) < 0)
        return ret;
    cc = (*c)->priv_data;
    ret = ff_accept(sc->fd, sc->listen_timeout, s);
    if (ret < 0)
        return ff_neterrno();
    cc->fd = ret;
    return 0;
}

static int tcp_read(URLContext *h, uint8_t *buf, int size)
{
    TCPContext *s = h->priv_data;
    int ret;

    if (!(h->flags & AVIO_FLAG_NONBLOCK)) {
        ret = ff_network_wait_fd_timeout(s->fd, 0, h->rw_timeout, &h->interrupt_callback);
        if (ret)
            return ret;
    }
    ret = recv(s->fd, buf, size, 0);
    return ret < 0 ? ff_neterrno() : ret;
}

static int tcp_write(URLContext *h, const uint8_t *buf, int size)
{
    TCPContext *s = h->priv_data;
    int ret;

    if (!(h->flags & AVIO_FLAG_NONBLOCK)) {
        ret = ff_network_wait_fd_timeout(s->fd, 1, h->rw_timeout, &h->interrupt_callback);
        if (ret)
            return ret;
    }
    ret = send(s->fd, buf, size, MSG_NOSIGNAL);
    return ret < 0 ? ff_neterrno() : ret;
}

static int tcp_shutdown(URLContext *h, int flags)
{
    TCPContext *s = h->priv_data;
    int how;

    if (flags & AVIO_FLAG_WRITE && flags & AVIO_FLAG_READ) {
        how = SHUT_RDWR;
    } else if (flags & AVIO_FLAG_WRITE) {
        how = SHUT_WR;
    } else {
        how = SHUT_RD;
    }

    return shutdown(s->fd, how);
}

static int tcp_close(URLContext *h)
{
    TCPContext *s = h->priv_data;
    closesocket(s->fd);
    return 0;
}

static int tcp_get_file_handle(URLContext *h)
{
    TCPContext *s = h->priv_data;
    return s->fd;
}

const URLProtocol ff_tcp_protocol = {
    .name                = "tcp",
    .url_open            = tcp_open,
    .url_accept          = tcp_accept,
    .url_read            = tcp_read,
    .url_write           = tcp_write,
    .url_close           = tcp_close,
    .url_get_file_handle = tcp_get_file_handle,
    .url_shutdown        = tcp_shutdown,
    .priv_data_size      = sizeof(TCPContext),
    .flags               = URL_PROTOCOL_FLAG_NETWORK,
    .priv_data_class     = &tcp_class,
};
