/****************************************************************************
 * apps/netutils/wiznet_main.c
 *
 *   Copyright 2020 Sony Corporation
 *
 * Based on usrsocktest_daemon.c
 *   Copyright (C) 2015, 2017 Haltian Ltd. All rights reserved.
 *    Author: Jussi Kivilinna <jussi.kivilinna@haltian.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name of Sony Corporation nor the names of its contributors
 *    used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 ****************************************************************************/

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <nuttx/config.h>

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <debug.h>
#include <fcntl.h>
#include <errno.h>
#include <poll.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>

#include <nuttx/net/usrsock.h>
#include <nuttx/net/wiznet.h>

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

/* #define WIZNET_TRACE */

#ifdef WIZNET_TRACE
# define wiznet_printf(v, ...) printf(v, ##__VA_ARGS__)
#else
# define wiznet_printf(v, ...)
#endif

#ifndef MIN
#  define MIN(a,b)  (((a) < (b)) ? (a) : (b))
#endif

#define SOCKET_BASE    10000
#define SOCKET_NUMBER  16

/****************************************************************************
 * Private Data Types
 ****************************************************************************/

enum sock_state_e
{
  CLOSED,
  OPENED,
  BOUND,
  CONNECTED,
};

struct usock_s
{
  enum sock_state_e  state;
  uint8_t            type;
  uint16_t           port;
  int                bind_sock;
  int                orig_sock;
  struct sockaddr_in bind_addr;
  int                backlog;
  struct sockaddr_in udpaddr;
};

struct wiznet_s
{
  int            gsfd;
  int            usock_enable;
  struct usock_s sockets[SOCKET_NUMBER];
};

/****************************************************************************
 * Private Function Prototypes
 ****************************************************************************/

static int socket_request(int fd, FAR struct wiznet_s *priv,
                          FAR void *hdrbuf);
static int close_request(int fd, FAR struct wiznet_s *priv,
                         FAR void *hdrbuf);
static int connect_request(int fd, FAR struct wiznet_s *priv,
                           FAR void *hdrbuf);
static int sendto_request(int fd, FAR struct wiznet_s *priv,
                          FAR void *hdrbuf);
static int recvfrom_request(int fd, FAR struct wiznet_s *priv,
                            FAR void *hdrbuf);
static int setsockopt_request(int fd, FAR struct wiznet_s *priv,
                              FAR void *hdrbuf);
static int getsockopt_request(int fd, FAR struct wiznet_s *priv,
                              FAR void *hdrbuf);
static int getsockname_request(int fd, FAR struct wiznet_s *priv,
                               FAR void *hdrbuf);
static int getpeername_request(int fd, FAR struct wiznet_s *priv,
                               FAR void *hdrbuf);
static int ioctl_request(int fd, FAR struct wiznet_s *priv,
                         FAR void *hdrbuf);
static int bind_request(int fd, FAR struct wiznet_s *priv,
                        FAR void *hdrbuf);
static int listen_request(int fd, FAR struct wiznet_s *priv,
                          FAR void *hdrbuf);
static int accept_request(int fd, FAR struct wiznet_s *priv,
                          FAR void *hdrbuf);

/****************************************************************************
 * Private Data
 ****************************************************************************/

static const struct usrsock_req_handler_s
{
  uint32_t hdrlen;
  int (CODE *fn)(int fd, FAR struct wiznet_s *priv, FAR void *req);
}
handlers[USRSOCK_REQUEST__MAX] =
{
{
  sizeof(struct usrsock_request_socket_s),
  socket_request,
},
{
  sizeof(struct usrsock_request_close_s),
  close_request,
},
{
  sizeof(struct usrsock_request_connect_s),
  connect_request,
},
{
  sizeof(struct usrsock_request_sendto_s),
  sendto_request,
},
{
  sizeof(struct usrsock_request_recvfrom_s),
  recvfrom_request,
},
{
  sizeof(struct usrsock_request_setsockopt_s),
  setsockopt_request,
},
{
  sizeof(struct usrsock_request_getsockopt_s),
  getsockopt_request,
},
{
  sizeof(struct usrsock_request_getsockname_s),
  getsockname_request,
},
{
  sizeof(struct usrsock_request_getpeername_s),
  getpeername_request,
},
{
  sizeof(struct usrsock_request_bind_s),
  bind_request,
},
{
  sizeof(struct usrsock_request_listen_s),
  listen_request,
},
{
  sizeof(struct usrsock_request_accept_s),
  accept_request,
},
{
  sizeof(struct usrsock_request_ioctl_s),
  ioctl_request,
},
};

static struct wiznet_s *_daemon;

/****************************************************************************
 * Private Functions
 ****************************************************************************/

/****************************************************************************
 * Name: f_usockid_to_sockfd
 ****************************************************************************/

static int f_usockid_to_sockfd(int usockid)
{
  return usockid - SOCKET_BASE;
}

/****************************************************************************
 * Name: f_sockfd_to_usock
 ****************************************************************************/

static int f_sockfd_to_usock(int sockfd)
{
  return sockfd + SOCKET_BASE;
}

/****************************************************************************
 * Name: f_write_to_usock
 ****************************************************************************/

static int f_write_to_usock(int fd, void *buf, size_t count)
{
  ssize_t wlen;

  wlen = write(fd, buf, count);

  if (wlen < 0)
    {
      return -errno;
    }

  if (wlen != (ssize_t)count)
    {
      return -ENOSPC;
    }

  return OK;
}

/****************************************************************************
 * Name: f_send_ack_common
 ****************************************************************************/

static int f_send_ack_common(int fd,
                             uint8_t xid,
                             FAR struct usrsock_message_req_ack_s *resp)
{
  resp->head.msgid = USRSOCK_MESSAGE_RESPONSE_ACK;
  resp->head.flags = 0;
  resp->xid = xid;

  /* Send ACK response. */

  return f_write_to_usock(fd, resp, sizeof(*resp));
}

/****************************************************************************
 * Name: f_socket_alloc
 ****************************************************************************/

static int16_t f_socket_alloc(FAR struct wiznet_s *priv, int type)
{
  FAR struct usock_s *usock;
  int16_t i;

  for (i = 1; i < SOCKET_NUMBER; i++)
    {
      usock = &priv->sockets[i];

      if (CLOSED == usock->state)
        {
          memset(usock, 0, sizeof(*usock));
          usock->state = OPENED;
          usock->type = type;
          usock->bind_sock = 0;
          usock->orig_sock = 0;
          return f_sockfd_to_usock(i);
        }
    }

  return -1;
}

/****************************************************************************
 * Name: f_socket_get
 ****************************************************************************/

static FAR struct usock_s *f_socket_get(FAR struct wiznet_s *priv,
                                        int sockid)
{
  if (sockid < SOCKET_BASE)
    {
      return NULL;
    }

  sockid = f_usockid_to_sockfd(sockid);

  if (sockid >= SOCKET_NUMBER)
    {
      return NULL;
    }

  return &priv->sockets[sockid];
}

/****************************************************************************
 * Name: f_socket_free
 ****************************************************************************/

static int f_socket_free(FAR struct wiznet_s *priv, int sockid)
{
  FAR struct usock_s *usock = f_socket_get(priv, sockid);

  if (!usock)
    {
      return -EBADFD;
    }

  if (CLOSED == usock->state)
    {
      return -EFAULT;
    }

  usock->state = CLOSED;

  return 0;
}

/****************************************************************************
 * Name: read_req
 ****************************************************************************/

static ssize_t
read_req(int fd, FAR const struct usrsock_request_common_s *com_hdr,
         FAR void *req, size_t reqsize)
{
  ssize_t rlen;

  rlen = read(fd, (uint8_t *)req + sizeof(*com_hdr),
              reqsize - sizeof(*com_hdr));

  if (rlen < 0)
    {
      return -errno;
    }

  if (rlen + sizeof(*com_hdr) != reqsize)
    {
      return -EMSGSIZE;
    }

  return rlen;
}

/****************************************************************************
 * Name: usrsock_request
 ****************************************************************************/

static int usrsock_request(int fd, FAR struct wiznet_s *priv)
{
  FAR struct usrsock_request_common_s *com_hdr;
  uint8_t hdrbuf[16];
  ssize_t rlen;

  com_hdr = (FAR struct usrsock_request_common_s *)hdrbuf;
  rlen = read(fd, com_hdr, sizeof(*com_hdr));

  if (rlen < 0)
    {
      return -errno;
    }

  if (rlen != sizeof(*com_hdr))
    {
      return -EMSGSIZE;
    }

  if (com_hdr->reqid >= USRSOCK_REQUEST__MAX ||
      !handlers[com_hdr->reqid].fn)
    {
      ASSERT(false);
      return -EIO;
    }

  assert(handlers[com_hdr->reqid].hdrlen < sizeof(hdrbuf));

  rlen = read_req(fd, com_hdr, hdrbuf,
                  handlers[com_hdr->reqid].hdrlen);

  if (rlen < 0)
    {
      return rlen;
    }

  return handlers[com_hdr->reqid].fn(fd, priv, hdrbuf);
}

/****************************************************************************
 * Name: usock_send_event
 ****************************************************************************/

static int usock_send_event(int fd, FAR struct wiznet_s *priv,
                            FAR struct usock_s *usock, int events)
{
  FAR struct usrsock_message_socket_event_s event;
  int i;

  memset(&event, 0, sizeof(event));
  event.head.flags = USRSOCK_MESSAGE_FLAG_EVENT;
  event.head.msgid = USRSOCK_MESSAGE_SOCKET_EVENT;

  for (i = 1; i < SOCKET_NUMBER; i++)
    {
      if (usock == &priv->sockets[i])
        {
          break;
        }
    }

  if (i == SOCKET_NUMBER)
    {
      return -EINVAL;
    }

  event.usockid = f_sockfd_to_usock(i);
  event.events  = events;

  return f_write_to_usock(fd, &event, sizeof(event));
}

/****************************************************************************
 * Name: socket_request
 ****************************************************************************/

static int socket_request(int fd, FAR struct wiznet_s *priv,
                          FAR void *hdrbuf)
{
  FAR struct usrsock_request_socket_s *req
    = (FAR struct usrsock_request_socket_s *)hdrbuf;
  struct usrsock_message_req_ack_s resp;
  struct wiznet_socket_msg cmsg;
  FAR struct usock_s *usock;
  int16_t usockid;
  int ret;

  wiznet_printf("%s: start type=%d \n",
                 __func__, req->type);

  /* Check domain requested */

  if (req->domain != AF_INET && req->domain != PF_USRSOCK)
    {
      usockid = -EAFNOSUPPORT;
    }
  else if (!priv->usock_enable && req->domain == AF_INET)
    {
      /* If domain is AF_INET while usock_enable is false,
       * set usockid to -EPROTONOSUPPORT to fallback kernel
       * network stack.
       */

      usockid = -EPROTONOSUPPORT;
    }
  else
    {
      /* Allocate socket. */

      usockid = f_socket_alloc(priv, req->type);
      ASSERT(0 < usockid);

      cmsg.sockfd   = f_usockid_to_sockfd(usockid);
      cmsg.domain   = req->domain;
      cmsg.type     = req->type;
      cmsg.protocol = req->protocol;
      ret = ioctl(priv->gsfd, WIZNET_IOC_SOCKET, (unsigned long)&cmsg);

      if (0 > ret)
        {
          f_socket_free(priv, usockid);
        }
    }

  /* Send ACK response */

  memset(&resp, 0, sizeof(resp));
  resp.result = usockid;
  ret = f_send_ack_common(fd, req->head.xid, &resp);

  if (0 > ret)
    {
      return ret;
    }

  if (req->type == SOCK_DGRAM)
    {
      /* NOTE: If the socket type is DGRAM, it's ready to send
       * a packet after creating user socket.
       */

      usock = f_socket_get(priv, usockid);
      usock_send_event(fd, priv, usock,
                       USRSOCK_EVENT_SENDTO_READY);
    }

  wiznet_printf("%s: end \n", __func__);
  return OK;
}

/****************************************************************************
 * Name: close_request
 ****************************************************************************/

static int close_request(int fd, FAR struct wiznet_s *priv,
                         FAR void *hdrbuf)
{
  FAR struct usrsock_request_close_s *req
    = (FAR struct usrsock_request_close_s *)hdrbuf;
  struct usrsock_message_req_ack_s resp;
  struct wiznet_close_msg cmsg;
  FAR struct usock_s *usock;
  int ret = 0;

  wiznet_printf("%s: start \n", __func__);

  /* Check if this socket exists. */

  usock = f_socket_get(priv, req->usockid);

  if (CLOSED == usock->state)
    {
      ret = -EBADFD;
      goto errout;
    }

  cmsg.sockfd = f_usockid_to_sockfd(req->usockid);
  ret = ioctl(priv->gsfd, WIZNET_IOC_CLOSE, (unsigned long)&cmsg);

  /* bind sock */

  if (usock->bind_sock > 0)
    {
      cmsg.sockfd = f_usockid_to_sockfd(usock->bind_sock);
      ioctl(priv->gsfd, WIZNET_IOC_CLOSE, (unsigned long)&cmsg);
    }

errout:

  /* Send ACK response */

  memset(&resp, 0, sizeof(resp));
  resp.result = ret;
  ret = f_send_ack_common(fd, req->head.xid, &resp);

  if (0 > ret)
    {
      return ret;
    }

  /* Free socket */

  if (usock->bind_sock > 0)
    {
      f_socket_free(priv, usock->bind_sock);
    }
  ret = f_socket_free(priv, req->usockid);

  wiznet_printf("%s: end \n", __func__);

  return OK;
}

/****************************************************************************
 * Name: connect_request
 ****************************************************************************/

static int connect_request(int fd, FAR struct wiznet_s *priv,
                           FAR void *hdrbuf)
{
  FAR struct usrsock_request_connect_s *req
    = (FAR struct usrsock_request_connect_s *)hdrbuf;
  struct usrsock_message_req_ack_s resp;
  struct wiznet_connect_msg cmsg;
  struct sockaddr_in *addr = (struct sockaddr_in *)&cmsg.addr;
  FAR struct usock_s *usock;
  int events;
  ssize_t wlen;
  ssize_t rlen;
  int ret = 0;

  DEBUGASSERT(priv);
  DEBUGASSERT(req);

  wiznet_printf("%s: start \n", __func__);

  /* Check if this socket exists. */

  usock = f_socket_get(priv, req->usockid);

  if (!usock)
    {
      ret = -EBADFD;
      goto prepare;
    }

  /* Check if this socket is already connected. */

  if ((usock->type == SOCK_STREAM) && (CONNECTED == usock->state))
    {
      ret = -EISCONN;
      goto prepare;
    }

  /* Check if address size ok. */

  if (req->addrlen > sizeof(struct sockaddr_in))
    {
      ret = -EFAULT;
      goto prepare;
    }

  /* Read address. */

  rlen = read(fd, addr, sizeof(struct sockaddr_in));

  if (rlen < 0 || rlen < req->addrlen)
    {
      ret = -EFAULT;
      goto prepare;
    }

  /* Check address family. */

  if (addr->sin_family != AF_INET)
    {
      ret = -EAFNOSUPPORT;
      goto prepare;
    }

  if (usock->type == SOCK_DGRAM)
    {
      usock->udpaddr = *addr;
      usock->state = CONNECTED;
    }
  else
    {
      cmsg.sockfd  = f_usockid_to_sockfd(req->usockid);
      cmsg.type    = usock->type;
      cmsg.addrlen = req->addrlen;
      ret = ioctl(priv->gsfd, WIZNET_IOC_CONNECT, (unsigned long)&cmsg);

      if (0 == ret)
        {
          usock->state = CONNECTED;
        }
    }

prepare:

  /* Send ACK response. */

  memset(&resp, 0, sizeof(resp));
  resp.result = ret;
  ret = f_send_ack_common(fd, req->head.xid, &resp);

  if (0 > ret)
    {
      return ret;
    }

  events = USRSOCK_EVENT_SENDTO_READY;
  wlen   = usock_send_event(fd, priv, usock, events);

  if (wlen < 0)
    {
      return wlen;
    }

  wiznet_printf("%s: end \n", __func__);
  return OK;
}

/****************************************************************************
 * Name: sendto_request
 ****************************************************************************/

static int sendto_request(int fd, FAR struct wiznet_s *priv,
                          FAR void *hdrbuf)
{
  FAR struct usrsock_request_sendto_s *req
    = (FAR struct usrsock_request_sendto_s *)hdrbuf;
  struct usrsock_message_req_ack_s resp;
  struct wiznet_send_msg cmsg;
  struct sockaddr_in *addr = (struct sockaddr_in *)&cmsg.addr;
  FAR struct usock_s *usock;
  uint8_t *sendbuf = NULL;
  ssize_t wlen;
  ssize_t rlen;
  int ret = 0;

  DEBUGASSERT(priv);
  DEBUGASSERT(req);

  wiznet_printf("%s: start (buflen=%d) \n",
                 __func__, req->buflen);

  /* Check if this socket exists. */

  usock = f_socket_get(priv, req->usockid);

  if (!usock)
    {
      ret = -EBADFD;
      goto prepare;
    }

  /* Check if this socket is connected. */

  if (SOCK_STREAM == usock->type && CONNECTED != usock->state)
    {
      ret = -ENOTCONN;
      goto prepare;
    }

  /* Check if the address size is non-zero.
   * connection-mode socket does not accept address
   */

  if (usock->type == SOCK_STREAM && req->addrlen > 0)
    {
      ret = -EISCONN;
      goto prepare;
    }

  /* For UDP, addlen must be provided */

  if (usock->type == SOCK_DGRAM)
    {
      if (CONNECTED != usock->state)
        {
          if (req->addrlen == 0)
            {
              ret = -EINVAL;
              goto prepare;
            }

          /* In UDP case, read the address. */

          rlen = read(fd, addr, sizeof(struct sockaddr_in));

          if (rlen < 0 || rlen < req->addrlen)
            {
              ret = -EFAULT;
              goto prepare;
            }

          wiznet_printf("%s: addr: %s:%d",
                        __func__,
                        inet_ntoa(addr->sin_addr), ntohs(addr->sin_port));
        }
      else /* DGRAM sock is alreay connected.. */
        {
          *addr = usock->udpaddr;
        }
    }

  /* Check if the request has data. */

  if (req->buflen > 0)
    {
      sendbuf = (uint8_t *)calloc(1, req->buflen);
      ASSERT(sendbuf);

      /* Read data from usrsock. */

      rlen = read(fd, sendbuf, req->buflen);

      if (rlen < 0 || rlen < req->buflen)
        {
          ret = -EFAULT;
          goto prepare;
        }

      cmsg.sockfd  = f_usockid_to_sockfd(req->usockid);
      cmsg.type    = usock->type;
      cmsg.buf     = sendbuf;
      cmsg.len     = req->buflen;
      cmsg.addrlen = req->addrlen;

      ret = ioctl(priv->gsfd, WIZNET_IOC_SEND, (unsigned long)&cmsg);

      if (0 == ret)
        {
          ret = cmsg.result;
        }
    }

prepare:

  if (sendbuf)
    {
      free(sendbuf);
    }

  /* Send ACK response. */

  memset(&resp, 0, sizeof(resp));
  resp.result = ret;
  ret = f_send_ack_common(fd, req->head.xid, &resp);

  if (0 > ret)
    {
      return ret;
    }

  /* Let kernel-side know that there is space for more send data. */

  wlen = usock_send_event(fd, priv, usock,
                          USRSOCK_EVENT_SENDTO_READY);

  if (wlen < 0)
    {
      return wlen;
    }

  wiznet_printf("%s: end \n", __func__);

  return OK;
}

/****************************************************************************
 * Name: recvfrom_request
 ****************************************************************************/

static int recvfrom_request(int fd, FAR struct wiznet_s *priv,
                            FAR void *hdrbuf)
{
  FAR struct usrsock_request_recvfrom_s *req
    = (FAR struct usrsock_request_recvfrom_s *)hdrbuf;
  struct usrsock_message_datareq_ack_s resp;
  struct wiznet_recv_msg cmsg;
  struct sockaddr_in *addr = (struct sockaddr_in *)&cmsg.addr;
  FAR struct usock_s *usock;
  uint8_t *recvbuf = NULL;
  int ret = 0;

  DEBUGASSERT(priv);
  DEBUGASSERT(req);

  wiznet_printf("%s: start (req->max_buflen=%d) \n",
                 __func__, req->max_buflen);

  /* Check if this socket exists. */

  usock = f_socket_get(priv, req->usockid);

  if (!usock)
    {
      ret = -EBADFD;
      goto prepare;
    }

  /* Check if this socket is connected. */

  if (SOCK_STREAM == usock->type && CONNECTED != usock->state)
    {
      ret = -ENOTCONN;
      goto prepare;
    }

  recvbuf = (uint8_t *)calloc(1, req->max_buflen);
  ASSERT(recvbuf);

  cmsg.sockfd  = f_usockid_to_sockfd(req->usockid);
  cmsg.type    = usock->type;
  cmsg.buf     = recvbuf;
  cmsg.len     = req->max_buflen;
  cmsg.addrlen = req->max_addrlen;

  ret = ioctl(priv->gsfd, WIZNET_IOC_RECV, (unsigned long)&cmsg);

  if (0 == ret)
    {
      ret = cmsg.result;
    }

prepare:

  /* Prepare response. */

  memset(&resp, 0, sizeof(resp));
  resp.reqack.result = ret;
  resp.reqack.xid = req->head.xid;
  resp.reqack.head.msgid = USRSOCK_MESSAGE_RESPONSE_DATA_ACK;
  resp.reqack.head.flags = 0;

  if (0 <= ret)
    {
      resp.valuelen_nontrunc = sizeof(struct sockaddr_in);
      resp.valuelen = MIN(resp.valuelen_nontrunc,
                          req->max_addrlen);

      if (0 == ret)
        {
          usock_send_event(fd, priv, usock,
                           USRSOCK_EVENT_REMOTE_CLOSED
                           );
        }
    }

  /* Send response. */

  ret = f_write_to_usock(fd, &resp, sizeof(resp));

  if (0 > ret)
    {
      goto err_out;
    }

  if (0 < resp.valuelen)
    {
      /* Send address (value) */

      ret = f_write_to_usock(fd, addr, resp.valuelen);

      if (0 > ret)
        {
          goto err_out;
        }
    }

  if (0 < resp.reqack.result)
    {
      /* Send buffer */

      ret = f_write_to_usock(fd, recvbuf, resp.reqack.result);

      if (0 > ret)
        {
          goto err_out;
        }
    }

err_out:

  wiznet_printf("%s: *** end ret=%d \n", __func__, ret);

  if (recvbuf)
    {
      free(recvbuf);
    }

  return ret;
}

/****************************************************************************
 * Name: bind_request
 ****************************************************************************/

static int bind_request(int fd, FAR struct wiznet_s *priv,
                        FAR void *hdrbuf)
{
  FAR struct usrsock_request_bind_s *req
    = (FAR struct usrsock_request_bind_s *)hdrbuf;
  struct usrsock_message_req_ack_s resp;
  struct wiznet_socket_msg smsg;
  struct wiznet_close_msg cmsg;
  struct wiznet_bind_msg bmsg;
  FAR struct usock_s *usock;
  FAR struct usock_s *new_usock = NULL;
  ssize_t rlen;
  int ret = 0;
  int16_t usockid; /* usockid for new client */

  DEBUGASSERT(priv);
  DEBUGASSERT(req);

  wiznet_printf("%s: called **** \n", __func__);

  /* Check if this socket exists. */

  usock = f_socket_get(priv, req->usockid);
  if (!usock)
    {
      ret = -EBADFD;
      goto prepare;
    }

  /* Check if address size ok. */

  if (req->addrlen > sizeof(struct sockaddr_in))
    {
      ret = -EFAULT;
      goto prepare;
    }

  /* Read address. */

  rlen = read(fd, &usock->bind_addr, sizeof(struct sockaddr_in));

  if (rlen < 0 || rlen < req->addrlen)
    {
      ret = -EFAULT;
      goto prepare;
    }

  /* Check address family. */

  if (usock->bind_addr.sin_family != AF_INET)
    {
      ret = -EAFNOSUPPORT;
      goto prepare;
    }

  if (SOCK_STREAM == usock->type)
    {
      /* allocate socket. */

      usockid = f_socket_alloc(priv, usock->type);
      ASSERT(0 < usockid);

      smsg.sockfd = f_usockid_to_sockfd(usockid);
      smsg.type   = usock->type;
      ret = ioctl(priv->gsfd, WIZNET_IOC_SOCKET, (unsigned long)&smsg);

      if (0 > ret)
        {
          f_socket_free(priv, usockid);
          goto prepare;
        }

      new_usock = f_socket_get(priv, usockid);
      usock->port = usock->bind_addr.sin_port;
      new_usock->port = usock->bind_addr.sin_port;

      bmsg.sockfd  = f_usockid_to_sockfd(usockid);
      memcpy(&bmsg.addr, &usock->bind_addr, sizeof(struct sockaddr_in));
      bmsg.addrlen = sizeof(struct sockaddr_in);
      ret = ioctl(priv->gsfd, WIZNET_IOC_BIND, (unsigned long)&bmsg);

      if (0 == ret)
        {
          new_usock->state = BOUND;
          usock->bind_sock = usockid;
          new_usock->orig_sock = req->usockid;
        }
      else
        {
          cmsg.sockfd = f_usockid_to_sockfd(usockid);
          ioctl(priv->gsfd, WIZNET_IOC_CLOSE, (unsigned long)&cmsg);
          f_socket_free(priv, usockid);
        }
    }
  else
    {
      usock->port = usock->bind_addr.sin_port;

      bmsg.sockfd  = f_usockid_to_sockfd(req->usockid);
      memcpy(&bmsg.addr, &usock->bind_addr, sizeof(struct sockaddr_in));
      bmsg.addrlen = sizeof(struct sockaddr_in);
      ret = ioctl(priv->gsfd, WIZNET_IOC_BIND, (unsigned long)&bmsg);

      if (0 == ret)
        {
          usock->state = BOUND;
          usock->orig_sock = req->usockid;
        }
    }

prepare:

  /* Send ACK response. */

  memset(&resp, 0, sizeof(resp));
  resp.result = ret;
  ret = f_send_ack_common(fd, req->head.xid, &resp);

  if (0 > ret)
    {
      return ret;
    }

  wiznet_printf("%s: end \n", __func__);
  return OK;
}

/****************************************************************************
 * Name: listen_request
 ****************************************************************************/

static int listen_request(int fd, FAR struct wiznet_s *priv,
                          FAR void *hdrbuf)
{
  FAR struct usrsock_request_listen_s *req
    = (FAR struct usrsock_request_listen_s *)hdrbuf;
  struct usrsock_message_req_ack_s resp;
  struct wiznet_listen_msg cmsg;
  FAR struct usock_s *usock;
  int ret = 0;

  DEBUGASSERT(priv);
  DEBUGASSERT(req);

  wiznet_printf("%s: called **** \n", __func__);

  /* Check if this socket exists. */

  usock = f_socket_get(priv, req->usockid);

  if (!usock)
    {
      ret = -EBADFD;
      goto prepare;
    }

  if (0 >= usock->bind_sock)
    {
      ret = -EBADFD;
      goto prepare;
    }

  cmsg.sockfd  = f_usockid_to_sockfd(usock->bind_sock);
  cmsg.backlog = req->backlog;
  ret = ioctl(priv->gsfd, WIZNET_IOC_LISTEN, (unsigned long)&cmsg);

prepare:

  /* Send ACK response. */

  memset(&resp, 0, sizeof(resp));
  resp.result = ret;
  ret = f_send_ack_common(fd, req->head.xid, &resp);

  if (0 > ret)
    {
      return ret;
    }

  usock->backlog = req->backlog;

  wiznet_printf("%s: end \n", __func__);
  return ret;
}

/****************************************************************************
 * Name: accept_request
 ****************************************************************************/

static int accept_request(int fd, FAR struct wiznet_s *priv,
                          FAR void *hdrbuf)
{
  FAR struct usrsock_request_accept_s *req
    = (FAR struct usrsock_request_accept_s *)hdrbuf;
  struct usrsock_message_datareq_ack_s resp;
  struct wiznet_accept_msg amsg;
  struct wiznet_close_msg cmsg;
  struct wiznet_socket_msg smsg;
  struct wiznet_bind_msg bmsg;
  struct wiznet_listen_msg lmsg;
  struct sockaddr_in *addr = (struct sockaddr_in *)&amsg.addr;
  FAR struct usock_s *usock;
  FAR struct usock_s *new_usock = NULL;
  int ret = 0;
  int16_t usockid; /* usockid for new client */

  DEBUGASSERT(priv);
  DEBUGASSERT(req);

  wiznet_printf("%s: called **** \n", __func__);

  /* Check if this socket exists. */

  usock = f_socket_get(priv, req->usockid);

  if (!usock)
    {
      ret = -EBADFD;
      goto prepare;
    }

  usockid = usock->bind_sock;
  if (0 >= usockid)
    {
      ret = -EBADFD;
      goto prepare;
    }

  new_usock = f_socket_get(priv, usockid);

  if (!new_usock)
    {
      ret = -EBADFD;
      goto prepare;
    }

  /* TODO: need to check if specified socket exists */

  amsg.sockfd  = f_usockid_to_sockfd(usockid);
  amsg.addrlen = sizeof(struct sockaddr_in);
  ret = ioctl(priv->gsfd, WIZNET_IOC_ACCEPT, (unsigned long)&amsg);

  if (0 == ret)
    {
      new_usock->state = CONNECTED;
    }
  else
    {
      cmsg.sockfd = f_usockid_to_sockfd(usockid);
      ioctl(priv->gsfd, WIZNET_IOC_CLOSE, (unsigned long)&cmsg);
      f_socket_free(priv, usockid);
    }

prepare:

  /* Prepare response. */

  memset(&resp, 0, sizeof(resp));
  resp.reqack.xid = req->head.xid;
  resp.reqack.head.msgid = USRSOCK_MESSAGE_RESPONSE_DATA_ACK;
  resp.reqack.head.flags = 0;

  if (0 == ret)
    {
      resp.reqack.result = 2; /* addr + usock */
      resp.valuelen_nontrunc = sizeof(struct sockaddr_in);
      resp.valuelen = resp.valuelen_nontrunc;
    }
  else
    {
      resp.reqack.result = ret;
      resp.valuelen = 0;
    }

  /* Send response. */

  ret = f_write_to_usock(fd, &resp, sizeof(resp));

  if (0 > ret)
    {
      goto err_out;
    }

  if (resp.valuelen > 0)
    {
      /* Send address (value) */

      ret = f_write_to_usock(fd, addr, resp.valuelen);

      if (0 > ret)
        {
          goto err_out;
        }

      /* Send new usockid info */

      ret = f_write_to_usock(fd, &usockid, sizeof(usockid));

      if (0 > ret)
        {
          goto err_out;
        }

      /* Set events of new_usock */

      usock_send_event(fd, priv, new_usock,
                       USRSOCK_EVENT_SENDTO_READY
                       );
    }

  /* Remake bind_sock */

  usockid = f_socket_alloc(priv, usock->type);
  ASSERT(0 < usockid);

  smsg.sockfd = f_usockid_to_sockfd(usockid);
  smsg.type   = usock->type;
  ret = ioctl(priv->gsfd, WIZNET_IOC_SOCKET, (unsigned long)&smsg);

  if (0 > ret)
    {
      f_socket_free(priv, usockid);
      usock->bind_sock = 0;
      goto err_out;
    }

  new_usock = f_socket_get(priv, usockid);
  new_usock->port = usock->port;

  bmsg.sockfd  = f_usockid_to_sockfd(usockid);
  memcpy(&bmsg.addr, &usock->bind_addr, sizeof(struct sockaddr_in));
  bmsg.addrlen = sizeof(struct sockaddr_in);
  ret = ioctl(priv->gsfd, WIZNET_IOC_BIND, (unsigned long)&bmsg);

  if (0 == ret)
    {
      new_usock->state = BOUND;
      usock->bind_sock = usockid;
      new_usock->orig_sock = req->usockid;
    }
  else
    {
      cmsg.sockfd = f_usockid_to_sockfd(usockid);
      ioctl(priv->gsfd, WIZNET_IOC_CLOSE, (unsigned long)&cmsg);
      f_socket_free(priv, usockid);
      usock->bind_sock = 0;
      goto err_out;
    }

  lmsg.sockfd  = f_usockid_to_sockfd(usockid);
  lmsg.backlog = usock->backlog;
  ret = ioctl(priv->gsfd, WIZNET_IOC_LISTEN, (unsigned long)&lmsg);

  if (0 > ret)
    {
      cmsg.sockfd = f_usockid_to_sockfd(usockid);
      ioctl(priv->gsfd, WIZNET_IOC_CLOSE, (unsigned long)&cmsg);
      f_socket_free(priv, usockid);
      usock->bind_sock = 0;
    }

err_out:
  wiznet_printf("%s: end \n", __func__);
  return ret;
}

/****************************************************************************
 * Name: setsockopt_request
 ****************************************************************************/

static int setsockopt_request(int fd, FAR struct wiznet_s *priv,
                              FAR void *hdrbuf)
{
  FAR struct usrsock_request_setsockopt_s *req
    = (FAR struct usrsock_request_setsockopt_s *)hdrbuf;
  struct usrsock_message_req_ack_s resp;
  FAR struct usock_s *usock;
  ssize_t rlen;
  int ret = 0;
  int value;

  DEBUGASSERT(priv);
  DEBUGASSERT(req);

  wiznet_printf("%s: called **** \n", __func__);

  /* Check if this socket exists. */

  usock = f_socket_get(priv, req->usockid);

  if (!usock)
    {
      ret = -EBADFD;
      goto prepare;
    }

  if (req->valuelen < sizeof(value))
    {
      ret = -EINVAL;
      goto prepare;
    }

  /* Read value. */

  rlen = read(fd, &value, sizeof(value));

  if (rlen < 0 || rlen < (ssize_t)sizeof(value))
    {
      ret = -EFAULT;
      goto prepare;
    }

  ret = OK;

prepare:

  /* Send ACK response */

  memset(&resp, 0, sizeof(resp));
  resp.result = ret;

  ret = f_send_ack_common(fd, req->head.xid, &resp);

  wiznet_printf("%s: end (ret=%d) \n", __func__, ret);
  return ret;
}

/****************************************************************************
 * Name: getsockopt_request
 ****************************************************************************/

static int getsockopt_request(int fd, FAR struct wiznet_s *priv,
                              FAR void *hdrbuf)
{
  FAR struct usrsock_request_getsockopt_s *req
    = (FAR struct usrsock_request_getsockopt_s *)hdrbuf;
  struct usrsock_message_datareq_ack_s resp;
  FAR struct usock_s *usock;
  int ret = 0;
  int value;

  DEBUGASSERT(priv);
  DEBUGASSERT(req);

  wiznet_printf("%s: called **** \n", __func__);

  /* Check if this socket exists. */

  usock = f_socket_get(priv, req->usockid);

  if (!usock)
    {
      ret = -EBADFD;
      goto prepare;
    }

  ret = OK;

prepare:

  /* Prepare response. */

  memset(&resp, 0, sizeof(resp));
  resp.reqack.result = ret;
  resp.reqack.xid = req->head.xid;
  resp.reqack.head.msgid = USRSOCK_MESSAGE_RESPONSE_DATA_ACK;
  resp.reqack.head.flags = 0;

  if (0 == ret)
    {
      resp.reqack.result = 1;
      resp.valuelen_nontrunc = sizeof(value);
      resp.valuelen = resp.valuelen_nontrunc;
    }
  else
    {
      resp.reqack.result = ret;
      resp.valuelen = 0;
    }

  /* Send response. */

  ret = f_write_to_usock(fd, &resp, sizeof(resp));

  if (0 > ret)
    {
      goto err_out;
    }

  if (0 < resp.valuelen)
    {
      /* Send address (value) */

      ret = f_write_to_usock(fd, &value, resp.valuelen);
    }

err_out:
  wiznet_printf("%s: end (ret=%d) \n", __func__, ret);
  return ret;
}

/****************************************************************************
 * Name: getsockname_request
 ****************************************************************************/

static int getsockname_request(int fd, FAR struct wiznet_s *priv,
                               FAR void *hdrbuf)
{
  FAR struct usrsock_request_getsockname_s *req
    = (FAR struct usrsock_request_getsockname_s *)hdrbuf;
  struct usrsock_message_datareq_ack_s resp;
  struct wiznet_name_msg cmsg;
  struct sockaddr_in *addr = (struct sockaddr_in *)&cmsg.addr;
  FAR struct usock_s *usock;
  int ret = 0;

  DEBUGASSERT(priv);
  DEBUGASSERT(req);

  wiznet_printf("%s: called **** \n", __func__);

  /* Check if this socket exists. */

  usock = f_socket_get(priv, req->usockid);

  if (!usock)
    {
      ret = -EBADFD;
      goto prepare;
    }

  cmsg.sockfd = f_usockid_to_sockfd(req->usockid);
  cmsg.local  = true;
  ret = ioctl(priv->gsfd, WIZNET_IOC_NAME, (unsigned long)&cmsg);

prepare:

  /* Prepare response. */

  memset(&resp, 0, sizeof(resp));
  resp.reqack.xid = req->head.xid;
  resp.reqack.head.msgid = USRSOCK_MESSAGE_RESPONSE_DATA_ACK;
  resp.reqack.head.flags = 0;
  resp.reqack.result = ret;

  if (0 == ret)
    {
      resp.valuelen_nontrunc = sizeof(struct sockaddr_in);
      resp.valuelen = resp.valuelen_nontrunc;

      if (resp.valuelen > req->max_addrlen)
        {
          resp.valuelen = req->max_addrlen;
        }
    }
  else
    {
      resp.valuelen_nontrunc = 0;
      resp.valuelen = 0;
    }

  /* Send response. */

  ret = f_write_to_usock(fd, &resp, sizeof(resp));

  if (0 > ret)
    {
      goto err_out;
    }

  if (resp.valuelen > 0)
    {
      /* Send address (value) */

      ret = f_write_to_usock(fd, addr, resp.valuelen);

      if (0 > ret)
        {
          goto err_out;
        }
    }

err_out:
  wiznet_printf("%s: end \n", __func__);
  return ret;
}

/****************************************************************************
 * Name: getpeername_request
 ****************************************************************************/

static int getpeername_request(int fd, FAR struct wiznet_s *priv,
                               FAR void *hdrbuf)
{
  FAR struct usrsock_request_getpeername_s *req
    = (FAR struct usrsock_request_getpeername_s *)hdrbuf;
  struct usrsock_message_datareq_ack_s resp;
  struct wiznet_name_msg cmsg;
  struct sockaddr_in *addr = (struct sockaddr_in *)&cmsg.addr;
  FAR struct usock_s *usock;
  int ret = 0;

  DEBUGASSERT(priv);
  DEBUGASSERT(req);

  wiznet_printf("%s: called **** \n", __func__);

  /* Check if this socket exists. */

  usock = f_socket_get(priv, req->usockid);

  if (!usock)
    {
      ret = -EBADFD;
      goto prepare;
    }

  cmsg.sockfd = f_usockid_to_sockfd(req->usockid);
  cmsg.local  = false;
  ret = ioctl(priv->gsfd, WIZNET_IOC_NAME, (unsigned long)&cmsg);

prepare:

  /* Prepare response. */

  memset(&resp, 0, sizeof(resp));
  resp.reqack.xid = req->head.xid;
  resp.reqack.head.msgid = USRSOCK_MESSAGE_RESPONSE_DATA_ACK;
  resp.reqack.head.flags = 0;
  resp.reqack.result = ret;

  if (0 == ret)
    {
      resp.valuelen_nontrunc = sizeof(struct sockaddr_in);
      resp.valuelen = resp.valuelen_nontrunc;

      if (resp.valuelen > req->max_addrlen)
        {
          resp.valuelen = req->max_addrlen;
        }
    }
  else
    {
      resp.valuelen_nontrunc = 0;
      resp.valuelen = 0;
    }

  /* Send response. */

  ret = f_write_to_usock(fd, &resp, sizeof(resp));

  if (0 > ret)
    {
      goto err_out;
    }

  if (resp.valuelen > 0)
    {
      /* Send address (value) */

      ret = f_write_to_usock(fd, addr, resp.valuelen);

      if (0 > ret)
        {
          goto err_out;
        }
    }

err_out:
  wiznet_printf("%s: end \n", __func__);
  return ret;
}

/****************************************************************************
 * Name: ioctl_request
 ****************************************************************************/

static int ioctl_request(int fd, FAR struct wiznet_s *priv,
                         FAR void *hdrbuf)
{
  FAR struct usrsock_request_ioctl_s *req
    = (FAR struct usrsock_request_ioctl_s *)hdrbuf;
  struct usrsock_message_req_ack_s resp;
  struct usrsock_message_datareq_ack_s resp2;
  struct wiznet_ifreq_msg cmsg;
  uint8_t sock_type;
  bool getreq = false;
  int ret = -EINVAL;

  memset(&cmsg.ifr, 0, sizeof(cmsg.ifr));

  switch (req->cmd)
    {
      case SIOCGIFHWADDR:
      case SIOCGIFADDR:
      case SIOCGIFDSTADDR:
      case SIOCGIFNETMASK:
        getreq = true;
        break;

      case SIOCSIFHWADDR:
      case SIOCSIFADDR:
      case SIOCSIFDSTADDR:
      case SIOCSIFNETMASK:

        read(fd, &cmsg.ifr, sizeof(cmsg.ifr));
        break;

      case SIOCDENYINETSOCK:

        read(fd, &sock_type, sizeof(uint8_t));

        if (sock_type == DENY_INET_SOCK_ENABLE)
          {
            /* Block to create INET socket */

            priv->usock_enable = FALSE;
          }
        else
          {
            /* Allow to create INET socket */

            priv->usock_enable = TRUE;
          }
        break;

      default:
        break;
    }

  cmsg.cmd = req->cmd;
  ret = ioctl(priv->gsfd, WIZNET_IOC_IFREQ, (unsigned long)&cmsg);

  if (!getreq)
    {
      /* Send ACK response */

      memset(&resp, 0, sizeof(resp));
      resp.result = ret;
      ret = f_send_ack_common(fd, req->head.xid, &resp);

      if (0 > ret)
        {
          return ret;
        }
    }

  if (getreq)
    {
      resp2.reqack.result = ret;
      resp2.reqack.xid = req->head.xid;
      resp2.reqack.head.msgid = USRSOCK_MESSAGE_RESPONSE_DATA_ACK;
      resp2.reqack.head.flags = 0;
      resp2.valuelen_nontrunc = sizeof(cmsg.ifr);
      resp2.valuelen = sizeof(cmsg.ifr);

      f_write_to_usock(fd, &resp2, sizeof(resp2));

      /* Return struct ifreq address */

      f_write_to_usock(fd, &cmsg.ifr, resp2.valuelen);
    }

  return ret;
}

/****************************************************************************
 * Name: wiznet_loop
 ****************************************************************************/

static int wiznet_loop(FAR struct wiznet_s *priv, FAR uint64_t *mac)
{
  struct wiznet_device_msg cmsg;
  struct pollfd fds[2];
  int  fd[2];
  int  cid;
  int  ret;
  FAR struct usock_s *usock;
  int16_t sockfd;

  fd[0] = open("/dev/usrsock", O_RDWR);
  ASSERT(0 <= fd[0]);

  fd[1] = open("/dev/wiznet", O_RDWR);
  ASSERT(0 <= fd[1]);
  priv->gsfd = fd[1];

  wiznet_printf("daemon started\n", __func__);

  cmsg.mac = *mac;

#ifdef CONFIG_NETUTILS_WIZNET_ENABLE_DHCP
  cmsg.dhcp = true;
#else
  cmsg.dhcp = false;
  inet_pton(AF_INET, CONFIG_NETUTILS_WIZNET_IP_ADDR, &cmsg.ipaddr);
  inet_pton(AF_INET, CONFIG_NETUTILS_WIZNET_GATEWAY_ADDR, &cmsg.draddr);
  inet_pton(AF_INET, CONFIG_NETUTILS_WIZNET_SUBNET_MASK, &cmsg.netmask);
  inet_pton(AF_INET, CONFIG_NETUTILS_WIZNET_DNS_ADDR, &cmsg.dnsaddr);
#endif

  while (true)
    {
      ret = ioctl(priv->gsfd, WIZNET_IOC_DEVICE, (unsigned long)&cmsg);

      if (0 == ret)
        {
          fprintf(stderr, "wiznet device configured\n");
          break;
        }

      fprintf(stderr, "wiznet device setup failed : retrying\n");
    }

  while (true)
    {
      memset(fds, 0, sizeof(fds));

      /* Check events from usrsock and wiznet */

      fds[0].fd     = fd[0];
      fds[0].events = POLLIN;
      fds[1].fd     = fd[1];
      fds[1].events = POLLIN;

      ret = poll(fds, 2, -1);
      ASSERT(0 < ret);

      if (fds[0].revents & POLLIN)
        {
          wiznet_printf("=== %s: event from /dev/usrsock \n",
                        __func__);

          ret = usrsock_request(fd[0], priv);
          ASSERT(0 == ret);
        }

      if (fds[1].revents & POLLIN)
        {
          wiznet_printf("=== %s: event from /dev/wiznet \n",
                        __func__);

          cid = 0;
          ret = read(fd[1], &cid, sizeof(cid));
          ASSERT(ret == sizeof(cid));

          usock = &priv->sockets[cid];

          if (BOUND == usock->state)
            {
              wiznet_printf("=== %s: %d is bound\n",
                            __func__, cid);
              sockfd = f_usockid_to_sockfd(usock->orig_sock);
              usock = &priv->sockets[sockfd];
              usock_send_event(fd[0], priv, usock,
                               USRSOCK_EVENT_RECVFROM_AVAIL);
            }
          else if (CONNECTED == usock->state)
            {
              wiznet_printf("=== %s: %d is connected\n",
                            __func__, cid);
              usock_send_event(fd[0], priv, usock,
                               USRSOCK_EVENT_RECVFROM_AVAIL);
            }
          else if ((OPENED == usock->state)
                   && (SOCK_DGRAM == usock->type))
            {
              wiznet_printf("=== %s: %d is stream\n",
                            __func__, cid);
              usock_send_event(fd[0], priv, usock,
                               USRSOCK_EVENT_RECVFROM_AVAIL);
            }
        }
    }

  close(fd[1]);
  close(fd[0]);

  wiznet_printf("finished: ret=%d\n", __func__, ret);

  return ret;
}

/****************************************************************************
 * Public Functions
 ****************************************************************************/

int main(int argc, FAR char *argv[])
{
  int ret;
  uint64_t mac_addr;

  if (_daemon)
    {
      fprintf(stderr, "%s is already running! \n", argv[0]);
      return -1;
    }

  _daemon = calloc(sizeof(struct wiznet_s), 1);
  ASSERT(_daemon);

  mac_addr = CONFIG_NETUTILS_WIZNET_DEFAULT_MAC_ADDR;
  if (argc == 3)
    {
      if (strncmp(argv[1], "-mac", 4)==0)
        {
          mac_addr = strtoll(argv[2], NULL, 16);
        }
    }

  _daemon->usock_enable = TRUE;

  ret = wiznet_loop(_daemon, &mac_addr);

  if (_daemon)
    {
      free(_daemon);
      _daemon = NULL;
    }

  return ret;
}
