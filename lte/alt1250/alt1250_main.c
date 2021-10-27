/****************************************************************************
 * apps/lte/alt1250/alt1250_main.c
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.  The
 * ASF licenses this file to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance with the
 * License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
 * License for the specific language governing permissions and limitations
 * under the License.
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
#include <debug.h>
#include <fcntl.h>
#include <errno.h>
#include <poll.h>
#include <unistd.h>
#include <mqueue.h>
#include <time.h>
#include <fcntl.h>
#include <assert.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>

#include <nuttx/net/netdev.h>
#include <nuttx/net/usrsock.h>
#include <nuttx/modem/alt1250.h>
#include <nuttx/wireless/lte/lte_ioctl.h>

#include "alt1250_evt.h"
#include "alt1250_dbg.h"
#include "lte/lapi.h"

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

#ifndef MIN
#  define MIN(a,b)  (((a) < (b)) ? (a) : (b))
#endif

#ifndef HEX
#  define HEX 16
#endif

#define DEV_USERSOCK "/dev/usrsock"
#define DEV_ALT1250  "/dev/alt1250"
#define SYNC_CMD_PREFIX "-s"
#define ALTFD   0
#define USOCKFD 1
#define RBUFSZ 16
#define OUTPUT_ARG_MAX 7
#define OPTVAL_LEN_MAX 16
#define SOCKID(idx) (idx)

#define TABLE_NUM(tbl) (sizeof(tbl)/sizeof(tbl[0]))

#define CONTAINER_MAX 10
#if defined(CONFIG_NET_USRSOCK_CONNS)
#  if (CONFIG_NET_USRSOCK_CONNS > ALTCOM_NSOCKET)
#    define SOCKET_COUNT ALTCOM_NSOCKET
#  else
#    define SOCKET_COUNT CONFIG_NET_USRSOCK_CONNS
#  endif
#else
#  define SOCKET_COUNT ALTCOM_NSOCKET
#endif

#define SELECT_CONTAINER_MAX 2

#define EVTTASK_NAME "lteevt_task"

#define RET_TERM        (1)
#define RET_NOTAVAIL    (2)
#define RET_MODEM_RESET (3)

#define GETSOCKOPT_PARAM_NUM 6

#define READSET_BIT   (1 << 0)
#define WRITESET_BIT  (1 << 1)
#define EXCEPTSET_BIT (1 << 2)

#define SELECT_MODE_NONBLOCK    (0)
#define SELECT_MODE_BLOCK       (1)
#define SELECT_MODE_BLOCKCANCEL (2)

#define EVENT_RESET (1)
#define EVENT_REPLY (2)

#define TX_BUFF_SIZE  (1500)
#define RX_BUFF_SIZE  (1500)

/****************************************************************************
 * Private Data Types
 ****************************************************************************/

enum sock_state_e
{
  CLOSED = 0,
  PREALLOC,
  OPEN,
  OPENED,
  CONNECTING,
  WAITCONN,
  CONNECTED,
  ABORTED,
  CLOSING
};

struct usock_s
{
  int altsock;
  enum sock_state_e state;
  unsigned long priv;
  struct usrsock_request_common_s req;
  int sockflags;
  int16_t domain;
  int16_t type;
  int16_t protocol;
  uint8_t connxid;

  /* store return code and error code */

  int32_t ret;
  int32_t errcode;

  union input_u
    {
      /* store the input arguments of connect(),
       * recvfrom(), bind(), accept(), getsockname()
       */

      struct
        {
          uint16_t addrlen;
          struct sockaddr_storage addr;
        } addr;

      /* store the input arguments of listen() */

      uint16_t backlog;

      /* store the input arguments of setsockopt(), getsockopt() */

      struct
        {
          int16_t level;
          int16_t option;
          uint16_t valuelen;
          uint8_t value[OPTVAL_LEN_MAX];
        } opt;
    } input;

  union output_u
    {
      /* store the output arguments of recvfrom(), accept() ,getsockname() */

      struct
        {
          uint32_t o_addlen;
          struct sockaddr_storage o_addr;
        } addr;

      /* store the output arguments of getsockopt() */

      struct
        {
          uint32_t o_optlen;
          uint8_t o_value[OPTVAL_LEN_MAX];
        } opt;
    } output;

  /* Stores the output arguments of getsockopt() that the daemon executes
   * when checking the result of connect().
   */

  int32_t  o_getoptret;
  int32_t  o_getopterr;
  int32_t  o_getoptlen;
  uint8_t  o_getoptval[OPTVAL_LEN_MAX];
  uint16_t o_getoptlv;
  uint16_t o_getoptopt;

  FAR void *out[OUTPUT_ARG_MAX];
  FAR void *outgetopt[GETSOCKOPT_PARAM_NUM];
};

struct alt1250_s
{
  int usockfd;
  int altfd;
  sq_queue_t freecontainer;
  int32_t scnt;
  int32_t sid;
  sem_t *syncsem;
  mqd_t evtq;
  struct net_driver_s net_dev;
  lte_apn_setting_t apn;
  char apn_name[LTE_APN_LEN];
  char user_name[LTE_APN_USER_NAME_LEN];
  char pass[LTE_APN_PASSWD_LEN];
  struct usock_s sockets[SOCKET_COUNT];
  lte_pdn_t o_pdn;
  bool recvfrom_processing;
};

typedef int (*waithdlr_t)(uint8_t event, unsigned long priv,
  FAR struct alt_container_s *reply, FAR struct usock_s *usock,
  FAR struct alt1250_s *dev);

struct waithdlr_s
{
  waithdlr_t hdlr;
  unsigned long priv;
};

struct select_params_s
{
  int32_t ret;
  int32_t err;
  int32_t id;
  altcom_fd_set readset;
  altcom_fd_set writeset;
  altcom_fd_set exceptset;
};

/****************************************************************************
 * Private Function Prototypes
 ****************************************************************************/

static int socket_request(int fd, FAR struct alt1250_s *dev,
                          FAR void *hdrbuf);
static int close_request(int fd, FAR struct alt1250_s *dev,
                         FAR void *hdrbuf);
static int connect_request(int fd, FAR struct alt1250_s *dev,
                           FAR void *hdrbuf);
static int sendto_request(int fd, FAR struct alt1250_s *dev,
                          FAR void *hdrbuf);
static int recvfrom_request(int fd, FAR struct alt1250_s *dev,
                            FAR void *hdrbuf);
static int setsockopt_request(int fd, FAR struct alt1250_s *dev,
                              FAR void *hdrbuf);
static int getsockopt_request(int fd, FAR struct alt1250_s *dev,
                              FAR void *hdrbuf);
static int getsockname_request(int fd, FAR struct alt1250_s *dev,
                               FAR void *hdrbuf);
static int getpeername_request(int fd, FAR struct alt1250_s *dev,
                               FAR void *hdrbuf);
static int ioctl_request(int fd, FAR struct alt1250_s *dev,
                         FAR void *hdrbuf);
static int bind_request(int fd, FAR struct alt1250_s *dev,
                        FAR void *hdrbuf);
static int listen_request(int fd, FAR struct alt1250_s *dev,
                          FAR void *hdrbuf);
static int accept_request(int fd, FAR struct alt1250_s *dev,
                          FAR void *hdrbuf);

static int handle_ifup(int16_t usockid, FAR struct alt1250_s *dev);
static int handle_ifdown(int16_t usockid, FAR struct alt1250_s *dev);

static int ioctl_lte_power(int fd, FAR struct alt1250_s *dev,
  FAR struct lte_ioctl_data_s *cmd, FAR uint16_t usockid);
static int ioctl_lte_nomdm(int fd, FAR struct alt1250_s *dev,
  FAR struct lte_ioctl_data_s *cmd, FAR uint16_t usockid);
static int ioctl_lte_event(int fd, FAR struct alt1250_s *dev,
  FAR struct lte_ioctl_data_s *cm, FAR uint16_t usockid);
static int ioctl_lte_normal(int fd, FAR struct alt1250_s *dev,
  FAR struct lte_ioctl_data_s *cmd, FAR uint16_t usockid, int8_t *flags);

static int handlereply_sockcommon(uint8_t event, unsigned long priv,
  FAR struct alt_container_s *reply, FAR struct usock_s *usock,
  FAR struct alt1250_s *dev);
static int handlereply_socket(uint8_t event, unsigned long priv,
  FAR struct alt_container_s *reply, FAR struct usock_s *usock,
  FAR struct alt1250_s *dev);
static int handlereply_connect(uint8_t event, unsigned long priv,
  FAR struct alt_container_s *reply, FAR struct usock_s *usock,
  FAR struct alt1250_s *dev);
static int handlereply_recvfrom(uint8_t event, unsigned long priv,
  FAR struct alt_container_s *reply, FAR struct usock_s *usock,
  FAR struct alt1250_s *dev);
static int handlereply_accept(uint8_t event, unsigned long priv,
  FAR struct alt_container_s *reply, FAR struct usock_s *usock,
  FAR struct alt1250_s *dev);
static int handlereply_getsockopt(uint8_t event, unsigned long priv,
  FAR struct alt_container_s *reply, FAR struct usock_s *usock,
  FAR struct alt1250_s *dev);
static int handlereply_getsockopt_conn(uint8_t event, unsigned long priv,
  FAR struct alt_container_s *reply, FAR struct usock_s *usock,
  FAR struct alt1250_s *dev);
static int handlereply_getsockname(uint8_t event, unsigned long priv,
  FAR struct alt_container_s *reply, FAR struct usock_s *usock,
  FAR struct alt1250_s *dev);
static int handlereply_getfl(uint8_t event, unsigned long priv,
  FAR struct alt_container_s *reply, FAR struct usock_s *usock,
  FAR struct alt1250_s *dev);
static int handlereply_setfl(uint8_t event, unsigned long priv,
  FAR struct alt_container_s *reply, FAR struct usock_s *usock,
  FAR struct alt1250_s *dev);

static int handlereply_repnetinfo(uint8_t event, unsigned long priv,
  FAR struct alt_container_s *reply, FAR struct usock_s *usock,
  FAR struct alt1250_s *dev);
static int handlereply_radioon(uint8_t event, unsigned long priv,
  FAR struct alt_container_s *reply, FAR struct usock_s *usock,
  FAR struct alt1250_s *dev);
static int handlereply_radiooff(uint8_t event, unsigned long priv,
  FAR struct alt_container_s *reply, FAR struct usock_s *usock,
  FAR struct alt1250_s *dev);
static int handlereply_actpdn(uint8_t event, unsigned long priv,
  FAR struct alt_container_s *reply, FAR struct usock_s *usock,
  FAR struct alt1250_s *dev);

/****************************************************************************
 * Private Data
 ****************************************************************************/

static const struct usrsock_req_handler_s
{
  uint32_t hdrlen;
  int (CODE *fn)(int fd, FAR struct alt1250_s *dev, FAR void *req);
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

static struct alt1250_s *g_daemon;
static struct alt_container_s g_container[CONTAINER_MAX];
static struct waithdlr_s g_waithdlrs[CONTAINER_MAX];

static uint8_t _tx_buff[TX_BUFF_SIZE];
static uint8_t _rx_buff[RX_BUFF_SIZE];
static uint16_t _rx_max_buflen;


static struct select_params_s g_select_params[SELECT_CONTAINER_MAX];

static void *g_selectargs[SELECT_CONTAINER_MAX][6];

static struct alt_container_s g_selectcontainers[SELECT_CONTAINER_MAX];
static FAR struct alt_container_s *g_pselectcontainer;

/****************************************************************************
 * Private Functions
 ****************************************************************************/

/****************************************************************************
 * Name: is_synccmd
 ****************************************************************************/

static inline bool is_synccmd(uint32_t cmdid)
{
  return !(cmdid & LTE_CMDOPT_ASYNC_BIT);
}

/****************************************************************************
 * Name: is_normalcmd
 ****************************************************************************/

static inline bool is_normalcmd(uint32_t cmdid)
{
  return LTE_ISCMDGRP_NORMAL(cmdid);
}

/****************************************************************************
 * Name: saveapn
 ****************************************************************************/

static void saveapn(FAR struct alt1250_s *dev, FAR lte_apn_setting_t *apn)
{
  memcpy(&dev->apn, apn, sizeof(lte_apn_setting_t));
  strncpy(dev->apn_name, (FAR const char *)apn->apn, LTE_APN_LEN);
  if ((apn->auth_type != LTE_APN_AUTHTYPE_NONE) && (apn->user_name))
    {
      strncpy(dev->user_name, (FAR const char *)apn->user_name,
        LTE_APN_USER_NAME_LEN);
    }

  if ((apn->auth_type != LTE_APN_AUTHTYPE_NONE) && (apn->password))
    {
      strncpy(dev->pass, (FAR const char *)apn->password,
        LTE_APN_PASSWD_LEN);
    }

  dev->apn.apn = dev->apn_name;
  dev->apn.user_name = dev->user_name;
  dev->apn.password = dev->pass;
}

/****************************************************************************
 * Name: getapn
 ****************************************************************************/

static void getapn(FAR struct alt1250_s *dev, FAR lte_apn_setting_t *apn)
{
  memcpy(apn, &dev->apn, sizeof(lte_apn_setting_t));
}

/****************************************************************************
 * Name: init_container
 ****************************************************************************/

static void init_container(FAR struct alt1250_s *dev)
{
  int i;

  memset(&g_container, 0, sizeof(g_container));

  sq_init(&dev->freecontainer);

  for (i = 0; i < TABLE_NUM(g_container); i++)
    {
      g_container[i].priv = (unsigned long)&g_waithdlrs[i];
      sq_next(&g_container[i].node) = NULL;
      sq_addlast(&g_container[i].node, &dev->freecontainer);
    }
}

/****************************************************************************
 * Name: clear_container
 ****************************************************************************/

static void clear_container(FAR struct alt_container_s *container)
{
  unsigned long priv = container->priv;

  memset(container, 0, sizeof(struct alt_container_s));
  container->priv = priv;
}

/****************************************************************************
 * Name: set_container
 ****************************************************************************/

static void set_container(FAR struct alt_container_s *container,
  int16_t usockid, uint32_t cmdid, FAR void *inp[], size_t insz,
  FAR void *outp[], size_t outsz, waithdlr_t hdlr, unsigned long priv)
{
  clear_container(container);

  container->sock = usockid;
  container->cmdid = cmdid;
  container->inparam = inp;
  container->inparamlen = insz;
  container->outparam = outp;
  container->outparamlen = outsz;
  ((FAR struct waithdlr_s *)container->priv)->hdlr = hdlr;
  ((FAR struct waithdlr_s *)container->priv)->priv = priv;

  alt1250_printf("set container: command ID: 0x%08lx\n", container->cmdid);
}

/****************************************************************************
 * Name: pick_containertop
 ****************************************************************************/

static FAR struct alt_container_s *
  pick_containertop(FAR struct alt_container_s **head)
{
  FAR struct alt_container_s *ret = *head;

  if (ret)
    {
      *head = (FAR struct alt_container_s *)sq_next(&ret->node);
      sq_next(&ret->node) = NULL;
    }

  return ret;
}

/****************************************************************************
 * Name: get_container
 ****************************************************************************/

static FAR struct alt_container_s *get_container(FAR struct alt1250_s *dev)
{
  FAR struct alt_container_s *ret = NULL;

  ret = (FAR struct alt_container_s *)sq_peek(&dev->freecontainer);
  if (ret)
    {
      sq_rem(&ret->node, &dev->freecontainer);
      sq_next(&ret->node) = NULL;
    }
  else
    {
      alt1250_printf("no container\n");
    }

  return ret;
}

/****************************************************************************
 * Name: free_container
 ****************************************************************************/

static void free_container(FAR struct alt1250_s *dev,
  FAR struct alt_container_s *container)
{
  alt1250_printf("free container: command ID: 0x%08lx\n", container->cmdid);

  sq_next(&container->node) = NULL;
  sq_addlast(&container->node, &dev->freecontainer);
}

/****************************************************************************
 * Name: is_container_exist
 ****************************************************************************/

static bool is_container_exist(FAR struct alt1250_s *dev)
{
  FAR struct alt_container_s *container = NULL;

  container = (FAR struct alt_container_s *)sq_peek(&dev->freecontainer);
  if (container)
    {
      return true;
    }
  else
    {
      return false;
    }
}

/****************************************************************************
 * Name: get_nfreecontainers
 ****************************************************************************/

static int get_nfreecontainers(FAR struct alt1250_s *dev)
{
  FAR struct alt_container_s *container = NULL;
  int ret = 0;

  container = (FAR struct alt_container_s *)sq_peek(&dev->freecontainer);

  while (container != NULL)
    {
      ret++;
      container = (FAR struct alt_container_s *)sq_next(&container->node);
    }

  return ret;
}

/****************************************************************************
 * Name: init_selectcontainer
 ****************************************************************************/

static void init_selectcontainer(FAR struct alt1250_s *dev)
{
  int i;

  for (i = 0; i < SELECT_CONTAINER_MAX; i++)
    {
      g_selectargs[i][0] = &g_select_params[i].ret;
      g_selectargs[i][1] = &g_select_params[i].err;
      g_selectargs[i][2] = &g_select_params[i].id;
      g_selectargs[i][3] = &g_select_params[i].readset;
      g_selectargs[i][4] = &g_select_params[i].writeset;
      g_selectargs[i][5] = &g_select_params[i].exceptset;

      g_selectcontainers[i].outparam = g_selectargs[i];
      g_selectcontainers[i].outparamlen = ARRAY_SZ(g_selectargs[i]);
    }

  g_pselectcontainer = &g_selectcontainers[0];

  /* At initialization, the alt1250 driver does not have a container,
   * so NULL pointer is set.
   */

  ioctl(dev->altfd, ALT1250_IOC_EXCHGCONTAINER, &g_pselectcontainer);

  g_pselectcontainer = &g_selectcontainers[1];
}

/****************************************************************************
 * Name: exchange_selectcontainer
 ****************************************************************************/

static FAR struct alt_container_s *exchange_selectcontainer(
  FAR struct alt1250_s *dev)
{
  /* The container used by the alt1250 driver is set as a pointer. */

  ioctl(dev->altfd, ALT1250_IOC_EXCHGCONTAINER, &g_pselectcontainer);

  return g_pselectcontainer;
}

/****************************************************************************
 * Name: evt_qclose
 ****************************************************************************/

static void evt_qclose(FAR mqd_t *mqd)
{
  if (*mqd != (mqd_t)-1)
    {
      mq_close(*mqd);
    }
}

/****************************************************************************
 * Name: evt_qopen
 ****************************************************************************/

static int evt_qopen(FAR const char *qname, FAR mqd_t *mqd)
{
  int ret = OK;

  evt_qclose(mqd);

  *mqd = mq_open(qname, O_WRONLY);
  if (*mqd == (mqd_t)-1)
    {
      ret = -errno;
      alt1250_printf("failed to open mq(%s): %d\n", qname, errno);
    }

  return ret;
}

/****************************************************************************
 * Name: evt_qsend
 ****************************************************************************/

static int evt_qsend(FAR mqd_t *mqd, uint64_t evtbitmap)
{
  int ret = ERROR;

  if (*mqd != (mqd_t)-1)
    {
      ret = mq_send(*mqd, (FAR const char *)&evtbitmap, sizeof(evtbitmap),
        0);
      if (ret < 0)
        {
          ret = -errno;
          alt1250_printf("failed to send mq: %d\n", errno);
        }
    }

  return ret;
}

/****************************************************************************
 * Name: _write_to_usock
 ****************************************************************************/

static int _write_to_usock(int fd, void *buf, size_t count)
{
  ssize_t wlen;

  wlen = write(fd, buf, count);

  if (wlen < 0)
    {
      return -errno;
    }

  if (wlen != count)
    {
      return -ENOSPC;
    }

  return OK;
}

/****************************************************************************
 * Name: _send_ack
 ****************************************************************************/

static int _send_ack(int fd, int8_t flags, uint8_t xid,
                     FAR struct usrsock_message_req_ack_s *resp)
{
  resp->head.msgid = USRSOCK_MESSAGE_RESPONSE_ACK;
  resp->head.flags = flags;
  resp->xid = xid;

  /* Send ACK response. */

  return _write_to_usock(fd, resp, sizeof(*resp));
}

/****************************************************************************
 * Name: _send_ack_common
 ****************************************************************************/

static int _send_ack_common(int fd,
                            uint8_t xid,
                            FAR struct usrsock_message_req_ack_s *resp)
{
  return _send_ack(fd, 0, xid, resp);
}

/****************************************************************************
 * Name: read_reqaddr
 ****************************************************************************/

static int read_reqaddr(int fd, FAR void *addr, size_t nbytes)
{
  int rlen = 0;

  if ((nbytes != sizeof(struct sockaddr_in)) &&
      (nbytes != sizeof(struct sockaddr_in6)))
    {
      alt1250_printf("Invalid addrlen: %u\n", nbytes);
      return -EINVAL;
    }

  rlen = read(fd, addr, nbytes);
  if (rlen < 0 || rlen < nbytes)
    {
      alt1250_printf("Failed to read: %d\n", rlen);
      return -EFAULT;
    }

  return rlen;
}

/****************************************************************************
 * Name: alt1250_socket_alloc
 ****************************************************************************/

static int16_t alt1250_socket_alloc(FAR struct alt1250_s *dev,
  int16_t domain, int16_t type, int16_t protocol)
{
  int16_t ret = -EBUSY;
  FAR struct usock_s *usock;
  int16_t i;

  for (i = 0; i < SOCKET_COUNT; i++)
    {
      usock = &dev->sockets[i];

      if (CLOSED == usock->state)
        {
          memset(usock, 0, sizeof(*usock));
          usock->altsock = -1;
          usock->state = PREALLOC;
          usock->domain = domain;
          usock->type = type;
          usock->protocol = protocol;
          ret = i;
          break;
        }
    }

  if (ret < 0)
    {
      alt1250_printf("alloc failed\n");
    }

  return ret;
}

/****************************************************************************
 * Name: alt1250_socket_get
 ****************************************************************************/

static FAR struct usock_s *alt1250_socket_get(FAR struct alt1250_s *dev,
                                             int sockid)
{
  if (sockid >= SOCKET_COUNT)
    {
      return NULL;
    }

  return &dev->sockets[sockid];
}

/****************************************************************************
 * Name: alt1250_socket_free
 ****************************************************************************/

static int alt1250_socket_free(FAR struct alt1250_s *dev, int sockid)
{
  FAR struct usock_s *usock = alt1250_socket_get(dev, sockid);

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
 * Name: alt1250_socket_allfree
 ****************************************************************************/

static int alt1250_socket_allfree(FAR struct alt1250_s *dev)
{
  int i;
  FAR struct usock_s *usock;

  for (i = 0; i < SOCKET_COUNT; i++)
    {
      usock = alt1250_socket_get(dev, i);
      if (usock && usock->state != CLOSED)
        {
          alt1250_socket_free(dev, i);
        }
    }

  /* Start over from scratch by closing /dev/usrsock */

  close(dev->usockfd);
  dev->usockfd = open(DEV_USERSOCK, O_RDWR);

  return 0;
}

/****************************************************************************
 * Name: read_usockreq
 ****************************************************************************/

static int read_usockreq(int fd, FAR uint8_t *buf, size_t sz)
{
  ssize_t rlen;
  int ret = OK;
  FAR struct usrsock_request_common_s *com_hdr;

  alt1250_printf("start\n");

  com_hdr = (FAR struct usrsock_request_common_s *)buf;

  rlen = read(fd, com_hdr, sizeof(*com_hdr));
  if (rlen < 0)
    {
      ret = -errno;
      alt1250_printf("failed to read usersock: %d\n", errno);
      return ret;
    }

  if (rlen != sizeof(*com_hdr))
    {
      alt1250_printf("unexpected read size: %d expected: %u\n", rlen,
        sizeof(*com_hdr));
      return -EMSGSIZE;
    }

  if (com_hdr->reqid >= USRSOCK_REQUEST__MAX || com_hdr->reqid < 0)
    {
      alt1250_printf("unexpected reqid: %d\n", com_hdr->reqid);
      return -1;
    }
  else if (!handlers[com_hdr->reqid].fn)
    {
      alt1250_printf("No handler has been registered. reqid: %d\n",
        com_hdr->reqid);
      return -1;
    }

  assert(handlers[com_hdr->reqid].hdrlen < sz);

  rlen = read(fd, buf + sizeof(*com_hdr),
              handlers[com_hdr->reqid].hdrlen - sizeof(*com_hdr));

  if (rlen < 0)
    {
      ret = -errno;
      alt1250_printf("failed to read usersock: %d\n", errno);
      return ret;
    }

  if (rlen != handlers[com_hdr->reqid].hdrlen - sizeof(*com_hdr))
    {
      alt1250_printf("unexpected read size: %d expected: %lu\n",
        rlen, handlers[com_hdr->reqid].hdrlen - sizeof(*com_hdr));
      return -EMSGSIZE;
    }

  alt1250_printf("end\n");

  return ret;
}

/****************************************************************************
 * Name: seek_usockreq
 ****************************************************************************/

static void seek_usockreq(int fd, size_t sz)
{
  uint8_t dummy;

  /* If the seek is called with the exact size, the seek will
   * result in an error. In order to avoid this, the process of
   * read is performed after seeking the specified size minus one byte.
   */

  if (lseek(fd, sz - 1, SEEK_CUR) >= 0)
    {
      read(fd, &dummy, 1);
    }
}

/****************************************************************************
 * Name: usock_send_event
 ****************************************************************************/

static int usock_send_event(int fd, FAR struct alt1250_s *dev,
                            FAR struct usock_s *usock, int events)
{
  FAR struct usrsock_message_socket_event_s event;
  int i;

  memset(&event, 0, sizeof(event));
  event.head.flags = USRSOCK_MESSAGE_FLAG_EVENT;
  event.head.msgid = USRSOCK_MESSAGE_SOCKET_EVENT;

  for (i = 0; i < SOCKET_COUNT; i++)
    {
      if (usock == &dev->sockets[i])
        {
          break;
        }
    }

  if (i == SOCKET_COUNT)
    {
      return -EINVAL;
    }

  event.usockid = i;
  event.events  = events;

  return _write_to_usock(fd, &event, sizeof(event));
}

/****************************************************************************
 * Name: write_to_altdev
 ****************************************************************************/

static int write_to_altdev(FAR struct alt1250_s *dev,
  FAR struct alt_container_s *container)
{
  int ret = OK;

  ret = ioctl(dev->altfd, ALT1250_IOC_SEND, (unsigned long)container);
  if (ret < 0)
    {
      ret = -errno;
      alt1250_printf("ioctl failed: %d\n", errno);
    }
  else
    {
      alt1250_printf("write to alt1250 success: %d\n", ret);
    }

  return ret;
}

/****************************************************************************
 * Name: send_commonreq
 ****************************************************************************/

static int send_commonreq(uint32_t cmdid, FAR void *in[], size_t icnt,
  FAR void *out[], size_t ocnt, int16_t usockid, waithdlr_t hdlr,
  unsigned long priv, FAR struct alt1250_s *dev,
  FAR struct alt_container_s *container)
{
  int ret = 0;

  if (container)
    {
      alt1250_printf("reuse container\n");
    }

  container = (container == NULL) ? get_container(dev) : container;
  if (container)
    {
      set_container(container, usockid, cmdid, in, icnt, out, ocnt, hdlr,
        priv);

      ret = write_to_altdev(dev, container);
      if (((ret < 0) && (ret != -ENETRESET)) || (out == NULL))
        {
          /* Non ENETRESET error is ocuured or no need to wait response */

          free_container(dev, container);
        }
    }
  else
    {
      ret = RET_NOTAVAIL;
    }

  return ret;
}

/****************************************************************************
 * Name: send_socketreq
 ****************************************************************************/

static int send_socketreq(int16_t domain, int16_t type, int16_t protocol,
  FAR void *out[], size_t ocnt, int16_t usockid, FAR struct alt1250_s *dev)
{
  FAR void *in[3];

  in[0] = &domain;
  in[1] = &type;
  in[2] = &protocol;

  return send_commonreq(LTE_CMDID_SOCKET, in, 3, out, ocnt,
    usockid, handlereply_socket, 0, dev, NULL);
}

/****************************************************************************
 * Name: send_closereq
 ****************************************************************************/

static int send_closereq(int32_t altsock, FAR void *out[], size_t ocnt,
  int16_t usockid, FAR struct alt1250_s *dev,
  FAR struct alt_container_s *container)
{
  FAR void *in[1];

  in[0] = &altsock;

  return send_commonreq(LTE_CMDID_CLOSE, in, 1, out, ocnt,
    usockid, handlereply_sockcommon, 0, dev, container);
}

/****************************************************************************
 * Name: send_fctlreq
 ****************************************************************************/

static int send_fctlreq(int32_t altsock, int32_t cmd, int32_t val,
  FAR void *out[], size_t ocnt, int16_t usockid, waithdlr_t hdlr,
  FAR struct alt1250_s *dev, FAR struct alt_container_s *container)
{
  FAR void *in[3];

  in[0] = &altsock;
  in[1] = &cmd;
  in[2] = &val;

  return send_commonreq(LTE_CMDID_FCNTL, in, 3, out, ocnt,
    usockid, hdlr, 0, dev, container);
}

/****************************************************************************
 * Name: send_connectreq
 ****************************************************************************/

static int send_connectreq(int32_t altsock, int16_t addrlen,
  struct sockaddr_storage *addr, FAR void *out[], size_t ocnt,
  int16_t usockid, FAR struct alt1250_s *dev,
  FAR struct alt_container_s *container)
{
  FAR void *in[3];

  in[0] = &altsock;
  in[1] = &addrlen;
  in[2] = addr;

  return send_commonreq(LTE_CMDID_CONNECT, in, 3, out, ocnt,
    usockid, handlereply_connect, 0, dev, container);
}

/****************************************************************************
 * Name: send_sendtoreq
 ****************************************************************************/

static int send_sendtoreq(int32_t altsock, int32_t flags, int16_t addrlen,
  uint16_t buflen, struct sockaddr_storage *to, uint8_t *buf,
  FAR void *out[], size_t ocnt, int16_t usockid, FAR struct alt1250_s *dev)
{
  FAR void *in[6];

  in[0] = &altsock;
  in[1] = &flags;
  in[2] = &addrlen;
  in[3] = &buflen;
  in[4] = to;
  in[5] = buf;

  return send_commonreq(LTE_CMDID_SENDTO, in, 6, out, ocnt,
    usockid, handlereply_sockcommon, 0, dev, NULL);
}

/****************************************************************************
 * Name: send_recvfromreq
 ****************************************************************************/

static int send_recvfromreq(int32_t altsock, int32_t flags, int16_t buflen,
  uint16_t addrlen, FAR void *out[], size_t ocnt, int16_t usockid,
  FAR struct alt1250_s *dev)
{
  FAR void *in[4];

  in[0] = &altsock;
  in[1] = &flags;
  in[2] = &buflen;
  in[3] = &addrlen;

  return send_commonreq(LTE_CMDID_RECVFROM, in, 4, out, ocnt,
    usockid, handlereply_recvfrom, 0, dev, NULL);
}

/****************************************************************************
 * Name: send_bindreq
 ****************************************************************************/

static int send_bindreq(int32_t altsock, uint16_t addrlen,
  struct sockaddr_storage *addr, FAR void *out[], size_t ocnt,
  int16_t usockid, FAR struct alt1250_s *dev,
  FAR struct alt_container_s *container)
{
  FAR void *in[3];

  in[0] = &altsock;
  in[1] = &addrlen;
  in[2] = addr;

  return send_commonreq(LTE_CMDID_BIND, in, 3, out, ocnt,
    usockid, handlereply_sockcommon, 0, dev, container);
}

/****************************************************************************
 * Name: send_listenreq
 ****************************************************************************/

static int send_listenreq(int32_t altsock, uint16_t backlog,
  FAR void *out[], size_t ocnt, int16_t usockid, FAR struct alt1250_s *dev,
  FAR struct alt_container_s *container)
{
  FAR void *in[2];

  in[0] = &altsock;
  in[1] = &backlog;

  return send_commonreq(LTE_CMDID_LISTEN, in, 2, out, ocnt,
    usockid, handlereply_sockcommon, 0, dev, container);
}

/****************************************************************************
 * Name: send_acceptreq
 ****************************************************************************/

static int send_acceptreq(int32_t altsock, uint16_t addrlen,
  FAR void *out[], size_t ocnt, int16_t usockid, FAR struct alt1250_s *dev)
{
  FAR void *in[2];

  in[0] = &altsock;
  in[1] = &addrlen;

  return send_commonreq(LTE_CMDID_ACCEPT, in, 2, out, ocnt,
    usockid, handlereply_accept, 0, dev, NULL);
}

/****************************************************************************
 * Name: send_setsockoptreq
 ****************************************************************************/

static int send_setsockoptreq(int32_t altsock, uint16_t level,
  uint16_t option, uint16_t valuelen, FAR uint8_t *value,
  FAR void *out[], size_t ocnt, int16_t usockid, FAR struct alt1250_s *dev,
  FAR struct alt_container_s *container)
{
  FAR void *in[5];

  in[0] = &altsock;
  in[1] = &level;
  in[2] = &option;
  in[3] = &valuelen;
  in[4] = value;

  return send_commonreq(LTE_CMDID_SETSOCKOPT, in, 5, out, ocnt,
    usockid, handlereply_sockcommon, 0, dev, container);
}

/****************************************************************************
 * Name: send_getsockoptreq
 ****************************************************************************/

static int send_getsockoptreq(int32_t altsock, uint16_t level,
  uint16_t option, uint16_t valuelen, FAR void *out[], size_t ocnt,
  int16_t usockid, waithdlr_t hdlr, FAR struct alt1250_s *dev,
  FAR struct alt_container_s *container)
{
  FAR void *in[GETSOCKOPT_PARAM_NUM];

  in[0] = &altsock;
  in[1] = &level;
  in[2] = &option;
  in[3] = &valuelen;

  return send_commonreq(LTE_CMDID_GETSOCKOPT, in, GETSOCKOPT_PARAM_NUM,
      out, ocnt, usockid, hdlr, 0, dev, container);
}

/****************************************************************************
 * Name: send_getsocknamereq
 ****************************************************************************/

static int send_getsocknamereq(int32_t altsock, uint16_t addrlen,
  FAR void *out[], size_t ocnt, int16_t usockid, FAR struct alt1250_s *dev,
  FAR struct alt_container_s *container)
{
  FAR void *in[2];

  in[0] = &altsock;
  in[1] = &addrlen;

  return send_commonreq(LTE_CMDID_GETSOCKNAME, in, 2, out, ocnt,
    usockid, handlereply_getsockname, 0, dev, container);
}

/****************************************************************************
 * Name: send_selectreq
 ****************************************************************************/

static int send_selectreq(int32_t mode, int32_t id, int32_t maxfds,
  FAR altcom_fd_set *readset, FAR altcom_fd_set *writeset,
  FAR altcom_fd_set *exceptset, int16_t usockid, FAR struct alt1250_s *dev,
  FAR struct alt_container_s *container)
{
  FAR void *in[7];
  uint16_t used_setbit = 0;

  if (readset)
    {
      used_setbit |= READSET_BIT;
    }

  if (writeset)
    {
      used_setbit |= WRITESET_BIT;
    }

  in[0] = &mode;
  in[1] = &id;
  in[2] = &maxfds;
  in[3] = &used_setbit;
  in[4] = readset;
  in[5] = writeset;
  in[6] = exceptset;

  return send_commonreq(LTE_CMDID_SELECT, in, 7, NULL, 0,
    usockid, NULL, 0, dev, container);
}

/****************************************************************************
 * Name: send_radioonreq
 ****************************************************************************/

static int send_radioonreq(FAR void *out[], size_t ocnt, int16_t usockid,
  FAR struct alt1250_s *dev)
{
  return send_commonreq(LTE_CMDID_RADIOON, NULL, 0, out, ocnt,
    usockid, handlereply_radioon, 0, dev, NULL);
}

/****************************************************************************
 * Name: send_radiooffreq
 ****************************************************************************/

static int send_radiooffreq(FAR void *out[], size_t ocnt, int16_t usockid,
  FAR struct alt1250_s *dev)
{
  return send_commonreq(LTE_CMDID_RADIOOFF, NULL, 0, out, ocnt,
    usockid, handlereply_radiooff, 0, dev, NULL);
}

/****************************************************************************
 * Name: send_actpdnreq
 ****************************************************************************/

static int send_actpdnreq(FAR lte_apn_setting_t *apn, FAR void *out[],
  size_t ocnt, int16_t usockid, FAR struct alt1250_s *dev,
  FAR struct alt_container_s *container)
{
  FAR void *in[1];

  in[0] = apn;

  return send_commonreq(LTE_CMDID_ACTPDN, in, 1, out, ocnt,
    usockid, handlereply_actpdn, 0, dev, container);
}

/****************************************************************************
 * Name: send_repnetinforeq
 ****************************************************************************/

static int send_repnetinforeq(FAR void *out[], size_t ocnt, int16_t usockid,
  FAR struct alt1250_s *dev)
{
  FAR void *in[1];

  uint8_t enable = 1;

  in[0] = &enable;

  return send_commonreq(LTE_CMDID_REPNETINFO, in, 1, out, ocnt,
    usockid, handlereply_repnetinfo, 0, dev, NULL);
}

/****************************************************************************
 * Name: select_cancel
 ****************************************************************************/

static int select_cancel(uint16_t usockid, FAR struct alt1250_s *dev,
  FAR struct alt_container_s *container)
{
  int ret = 0;
  int32_t maxfds = 0;
  altcom_fd_set readset;
  altcom_fd_set writeset;
  altcom_fd_set exceptset;

  if (dev->sid != -1)
    {
      ret = send_selectreq(SELECT_MODE_BLOCKCANCEL, dev->sid, maxfds,
        &readset, &writeset, &exceptset, usockid, dev, container);
      dev->sid = -1;
    }
  else if (container)
    {
      free_container(dev, container);
    }

  return ret;
}

/****************************************************************************
 * Name: select_start
 ****************************************************************************/

static int select_start(uint16_t usockid, FAR struct alt1250_s *dev,
  FAR struct alt_container_s *container)
{
  int ret = 0;
  int32_t maxfds = -1;
  altcom_fd_set readset;
  altcom_fd_set writeset;
  altcom_fd_set exceptset;
  FAR struct usock_s *usock;
  int i;

  dev->sid = (++dev->scnt & 0x7fffffff);

  ALTCOM_FD_ZERO(&readset);
  ALTCOM_FD_ZERO(&writeset);
  ALTCOM_FD_ZERO(&exceptset);

  for (i = 0; i < SOCKET_COUNT; i++)
    {
      usock = alt1250_socket_get(dev, i);
      if (usock && (usock->state != CLOSED) && (usock->state != PREALLOC) &&
        (usock->state != ABORTED) && (usock->state != CLOSING))
        {
          if (!(usock->sockflags & USRSOCK_EVENT_RECVFROM_AVAIL))
            {
              ALTCOM_FD_SET(usock->altsock, &readset);
            }

          if (!(usock->sockflags & USRSOCK_EVENT_SENDTO_READY))
            {
              ALTCOM_FD_SET(usock->altsock, &writeset);
            }

          ALTCOM_FD_SET(usock->altsock, &exceptset);
        }

      maxfds = ((maxfds > usock->altsock) ? maxfds : usock->altsock);
    }

  if (maxfds != -1)
    {
      ret = send_selectreq(SELECT_MODE_BLOCK, dev->sid, maxfds + 1, &readset,
        &writeset, &exceptset, usockid, dev, container);
    }
  else if (container)
    {
      free_container(dev, container);
    }

  return ret;
}

/****************************************************************************
 * Name: parse_socket_reply
 ****************************************************************************/

static int parse_socket_reply(int sockid, int errcode,
  FAR struct usock_s *usock)
{
  int ret = sockid;

  if (ret < 0)
    {
      ret = -errcode;
    }
  else
    {
      usock->altsock = sockid;
    }

  return ret;
}

/****************************************************************************
 * Name: parse_sockcommon_reply
 ****************************************************************************/

static int parse_sockcommon_reply(int result, int errcode)
{
  alt1250_printf("result:%d, errcode:%d\n", result, errcode);
  if (result < 0)
    {
      result = -errcode;
    }

  return result;
}

/****************************************************************************
 * Name: enable_netinforeport
 ****************************************************************************/

static int enable_netinforeport(FAR struct alt1250_s *dev)
{
  int ret;
  uint16_t usockid;
  FAR struct usock_s *usock;
  size_t ocnt = 0;

  /* Open in temporary and close when response is received */

  usockid = alt1250_socket_alloc(dev, AF_INET, SOCK_STREAM, 0);
  if (usockid < 0)
    {
      alt1250_printf("Failed to allocate socket...\n");
      ret = usockid;
    }
  else
    {
      usock = alt1250_socket_get(dev, usockid);
      DEBUGASSERT(usock);

      /* Change the setting to receive notifications
       * when the network status changes.
       */

      usock->out[ocnt++] = &usock->ret;

      ret = send_repnetinforeq(usock->out, ocnt, usockid, dev);
      if (ret < 0)
        {
          alt1250_socket_free(dev, usockid);
        }
    }

  return ret;
}

/****************************************************************************
 * Name: socket_request
 ****************************************************************************/

static int socket_request(int fd, FAR struct alt1250_s *dev,
                          FAR void *hdrbuf)
{
  FAR struct usrsock_request_socket_s *req = hdrbuf;
  struct usrsock_message_req_ack_s resp;
  FAR struct usock_s *usock;
  int16_t usockid;
  int ret = -1;

  alt1250_printf("start type=%d \n", req->type);

  /* Check domain requested */

  if (req->domain != AF_INET && req->domain != AF_INET6)
    {
      usockid = -EAFNOSUPPORT;
      alt1250_printf("Not support this domain: %u\n", req->domain);
      goto sendack;
    }

  /* Allocate socket. */

  usockid = alt1250_socket_alloc(dev,
    req->domain, req->type, req->protocol);
  if (usockid < 0)
    {
      alt1250_printf("socket alloc faild\n");
      goto sendack;
    }

  if (req->type != SOCK_STREAM)
    {
      usock = alt1250_socket_get(dev, usockid);
      if (usock)
        {
          usock->out[0] = &usock->ret;
          usock->out[1] = &usock->errcode;

          ret = send_socketreq(usock->domain, usock->type, usock->protocol,
            usock->out, 2, usockid, dev);
          if (ret >= 0)
            {
              if (ret == 0)
                {
                  /* Only zero means success */

                  memcpy(&usock->req, &req->head, sizeof(usock->req));
                  usock->state = OPEN;
                }
            }
          else
            {
              alt1250_socket_free(dev, usockid);
              usockid = ret;
            }
        }
      else
        {
          alt1250_socket_free(dev, usockid);
          usockid = -EBADFD;
        }
    }

sendack:
  if (ret < 0)
    {
      /* Send ACK response in error case */

      memset(&resp, 0, sizeof(resp));
      resp.result = usockid;
      _send_ack_common(fd, req->head.xid, &resp);
    }

  alt1250_printf("end\n");

  return ret;
}

/****************************************************************************
 * Name: close_request
 ****************************************************************************/

static int close_request(int fd, FAR struct alt1250_s *dev,
                         FAR void *hdrbuf)
{
  FAR struct usrsock_request_close_s *req = hdrbuf;
  struct usrsock_message_req_ack_s resp;
  FAR struct usock_s *usock;
  int result = 0;
  int ret = -1;
  size_t ocnt = 0;

  alt1250_printf("start\n");

  /* Check if this socket exists. */

  usock = alt1250_socket_get(dev, req->usockid);
  if (!usock)
    {
      result = -EBADFD;
      alt1250_printf("Failed to get socket context: %u\n", req->usockid);
      goto sendack;
    }

  if ((CLOSED == usock->state) || (CLOSING == usock->state))
    {
      result = -EBADFD;
      alt1250_printf("Unexpected state: %d\n", usock->state);
      goto sendack;
    }

  if (PREALLOC == usock->state)
    {
      alt1250_socket_free(dev, req->usockid);
    }
  else
    {
      /* Cancels the target fd before closing it */

      select_cancel(req->usockid, dev, NULL);

      usock->out[ocnt++] = &usock->ret;
      usock->out[ocnt++] = &usock->errcode;

      ret = send_closereq(usock->altsock, usock->out, ocnt, req->usockid,
        dev, NULL);
      if (ret >= 0)
        {
          if (ret == 0)
            {
               memcpy(&usock->req, &req->head, sizeof(usock->req));
               usock->state = CLOSING;
            }
        }
      else
        {
          result = ret;
          alt1250_socket_free(dev, req->usockid);
        }

      select_start(req->usockid, dev, NULL);
    }

sendack:
  if (ret < 0)
    {
      /* Send ACK response */

      memset(&resp, 0, sizeof(resp));
      resp.result = result;
      _send_ack_common(fd, req->head.xid, &resp);
    }

  alt1250_printf("end\n");

  return ret;
}

/****************************************************************************
 * Name: connect_request
 ****************************************************************************/

static int connect_request(int fd, FAR struct alt1250_s *dev,
                           FAR void *hdrbuf)
{
  FAR struct usrsock_request_connect_s *req = hdrbuf;
  struct usrsock_message_req_ack_s resp;
  FAR struct usock_s *usock;
  struct sockaddr_storage addr;
  ssize_t rlen;
  int ret = 0;
  int result = 0;
  bool is_ack = true;
  size_t ocnt = 0;

  DEBUGASSERT(dev);
  DEBUGASSERT(req);

  alt1250_printf("start\n");

  /* Check if this socket exists. */

  usock = alt1250_socket_get(dev, req->usockid);
  if (!usock)
    {
      result = -EBADFD;
      alt1250_printf("Failed to get socket context: %u\n", req->usockid);
      goto sendack;
    }

  if ((CLOSED == usock->state) || (CLOSING == usock->state))
    {
      result = -EBADFD;
      alt1250_printf("Unexpected state: %d\n", usock->state);
      goto sendack;
    }

  if (!is_container_exist(dev))
    {
      ret = RET_NOTAVAIL;
      goto noack;
    }

  /* Read address. */

  rlen = read_reqaddr(fd, &addr, req->addrlen);
  if (rlen < 0)
    {
      result = rlen;
      goto sendack;
    }

  if (PREALLOC == usock->state)
    {
      usock->out[ocnt++] = &usock->ret;
      usock->out[ocnt++] = &usock->errcode;

      ret = send_socketreq(usock->domain, usock->type, usock->protocol,
        usock->out, ocnt, req->usockid, dev);
      if (ret >= 0)
        {
          memcpy(&usock->req, &req->head, sizeof(usock->req));
          memcpy(&usock->input.addr.addr, &addr,
            sizeof(struct sockaddr_storage));
          usock->input.addr.addrlen = req->addrlen;
          usock->state = OPEN;
          is_ack = false;
        }
      else
        {
          result = ret;
        }
    }
  else
    {
      usock->out[ocnt++] = &usock->ret;
      usock->out[ocnt++] = &usock->errcode;

      ret = send_connectreq(usock->altsock, req->addrlen, &addr, usock->out,
        ocnt, req->usockid, dev, NULL);
      if (ret >= 0)
        {
          if (ret == 0)
            {
              memcpy(&usock->req, &req->head, sizeof(usock->req));
              usock->state = CONNECTING;
            }

          is_ack = false;
        }
      else
        {
          result = ret;
        }
    }

sendack:
  if (is_ack)
    {
      /* Send ACK response. */

      memset(&resp, 0, sizeof(resp));
      resp.result = result;
      _send_ack_common(fd, req->head.xid, &resp);
    }

noack:

  alt1250_printf("end\n");

  return ret;
}

/****************************************************************************
 * Name: sendto_request
 ****************************************************************************/

static int sendto_request(int fd, FAR struct alt1250_s *dev,
                          FAR void *hdrbuf)
{
  FAR struct usrsock_request_sendto_s *req = hdrbuf;
  struct usrsock_message_req_ack_s resp;
  FAR struct usock_s *usock;
  struct sockaddr_storage to;
  FAR struct sockaddr_storage *pto = NULL;
  ssize_t rlen;
  int ret = 0;
  int result = 0;
  bool is_ack = true;
  size_t ocnt = 0;

  DEBUGASSERT(dev);
  DEBUGASSERT(req);

  alt1250_printf("start (buflen=%d)\n", req->buflen);

  /* Check if this socket exists. */

  usock = alt1250_socket_get(dev, req->usockid);
  if (!usock)
    {
      result = -EBADFD;
      alt1250_printf("Failed to get socket context: %u\n", req->usockid);
      goto sendack;
    }

  /* Check if this socket is connected. */

  if (SOCK_STREAM == usock->type && CONNECTED != usock->state)
    {
      result = -ENOTCONN;
      alt1250_printf("Unexpected state: %d\n", usock->state);
      goto sendack;
    }

  if (!is_container_exist(dev))
    {
      ret = RET_NOTAVAIL;
      goto noack;
    }

  if (req->addrlen > 0)
    {
      /* Read address. */

      rlen = read_reqaddr(fd, &to, req->addrlen);
      if (rlen < 0)
        {
          result = rlen;
          goto sendack;
        }

      pto = &to;
    }

  /* Check if the request has data. */

  if (req->buflen > 0)
    {
      size_t sendlen = MIN(req->buflen, TX_BUFF_SIZE);

      /* Read data from usrsock. */

      rlen = read(fd, _tx_buff, sendlen);
      if ((rlen < 0) || (rlen < sendlen))
        {
          result = -EFAULT;
          alt1250_printf("Failed to read: %d\n", rlen);
          goto sendack;
        }

      /* If the send size exceeds TX_BUFF_SIZE,
       * use seek to discard the exceeded buffer.
       */

      if (req->buflen > sendlen)
        {
          seek_usockreq(fd, req->buflen - sendlen);
        }

      usock->out[ocnt++] = &usock->ret;
      usock->out[ocnt++] = &usock->errcode;

      ret = send_sendtoreq(usock->altsock, req->flags, req->addrlen,
        sendlen, pto, _tx_buff, usock->out, ocnt, req->usockid, dev);
      if (ret >= 0)
        {
          memcpy(&usock->req, &req->head, sizeof(usock->req));
          is_ack = false;
        }
      else
        {
          result = ret;
        }
    }
  else if(req->buflen == 0)
    {
      result = 0;
      usock->sockflags &= ~USRSOCK_EVENT_SENDTO_READY;
      select_cancel(req->usockid, dev, NULL);
      select_start(req->usockid, dev, NULL);
    }

sendack:

  if (is_ack)
    {
      /* Send ACK response. */

      memset(&resp, 0, sizeof(resp));
      resp.result = result;
      _send_ack_common(fd, req->head.xid, &resp);
    }

noack:

  alt1250_printf("end\n");

  return ret;
}

/****************************************************************************
 * Name: recvfrom_request
 ****************************************************************************/

static int recvfrom_request(int fd, FAR struct alt1250_s *dev,
                            FAR void *hdrbuf)
{
  FAR struct usrsock_request_recvfrom_s *req = hdrbuf;
  struct usrsock_message_req_ack_s resp;
  FAR struct usock_s *usock = NULL;
  int ret = 0;
  int result = 0;
  bool is_ack = true;
  socklen_t addrlen;
  size_t ocnt = 0;

  DEBUGASSERT(dev);
  DEBUGASSERT(req);

  alt1250_printf("start (req->max_buflen=%d)\n",
                 req->max_buflen);

  /* Check if this socket exists. */

  usock = alt1250_socket_get(dev, req->usockid);
  if (!usock)
    {
      result = -EBADFD;
      alt1250_printf("Failed to get socket context: %u\n", req->usockid);
      goto sendack;
    }

  /* Check if this socket is connected. */

  if (SOCK_STREAM == usock->type && CONNECTED != usock->state)
    {
      result = -ENOTCONN;
      alt1250_printf("Unexpected state: %d\n", usock->state);
      goto sendack;
    }

  if (!is_container_exist(dev))
    {
      ret = RET_NOTAVAIL;
      goto noack;
    }

  if (usock->domain == AF_INET)
    {
      addrlen = sizeof(struct sockaddr_in);
    }
  else
    {
      addrlen = sizeof(struct sockaddr_in6);
    }

  usock->out[ocnt++] = &usock->ret;
  usock->out[ocnt++] = &usock->errcode;
  usock->out[ocnt++] = &usock->output.addr.o_addlen;
  usock->out[ocnt++] = &usock->output.addr.o_addr;
  usock->out[ocnt++] = _rx_buff;
  _rx_max_buflen = MIN(req->max_buflen, RX_BUFF_SIZE);

  ret = send_recvfromreq(usock->altsock, req->flags, _rx_max_buflen,
    addrlen, usock->out, ocnt, req->usockid, dev);
  if (ret >= 0)
    {
      memcpy(&usock->req, &req->head, sizeof(usock->req));
      usock->input.addr.addrlen = req->max_addrlen;
      dev->recvfrom_processing = true;
      is_ack = false;
    }
  else
    {
      result = ret;
    }

sendack:

  if (is_ack)
    {
      /* Send ACK response. */

      memset(&resp, 0, sizeof(resp));
      resp.result = result;
      _send_ack_common(fd, req->head.xid, &resp);
    }

noack:

  alt1250_printf("end\n");

  return ret;
}

/****************************************************************************
 * Name: bind_request
 ****************************************************************************/

static int bind_request(int fd, FAR struct alt1250_s *dev,
                        FAR void *hdrbuf)
{
  FAR struct usrsock_request_bind_s *req = hdrbuf;
  struct usrsock_message_req_ack_s resp;
  FAR struct usock_s *usock;
  struct sockaddr_storage addr;
  ssize_t rlen;
  int ret = 0;
  int result = 0;
  bool is_ack = true;
  size_t ocnt = 0;

  DEBUGASSERT(dev);
  DEBUGASSERT(req);

  alt1250_printf("start\n");

  /* Check if this socket exists. */

  usock = alt1250_socket_get(dev, req->usockid);
  if (!usock)
    {
      result = -EBADFD;
      alt1250_printf("Failed to get socket context: %u\n", req->usockid);
      goto sendack;
    }

  if (!is_container_exist(dev))
    {
      ret = RET_NOTAVAIL;
      goto noack;
    }

  /* Read address. */

  rlen = read_reqaddr(fd, &addr, req->addrlen);
  if (rlen < 0)
    {
      result = rlen;
      goto sendack;
    }

  if (PREALLOC == usock->state)
    {
      usock->out[ocnt++] = &usock->ret;
      usock->out[ocnt++] = &usock->errcode;

      ret = send_socketreq(usock->domain, usock->type, usock->protocol,
        usock->out, ocnt, req->usockid, dev);
      if (ret >= 0)
        {
          memcpy(&usock->req, &req->head, sizeof(usock->req));
          memcpy(&usock->input.addr.addr, &addr,
            sizeof(struct sockaddr_storage));
          usock->input.addr.addrlen = req->addrlen;
          usock->state = OPEN;
          is_ack = false;
        }
      else
        {
          result = ret;
        }
    }
  else
    {
      usock->out[ocnt++] = &usock->ret;
      usock->out[ocnt++] = &usock->errcode;

      ret = send_bindreq(usock->altsock, req->addrlen, &addr, usock->out,
        ocnt, req->usockid, dev, NULL);
      if (ret >= 0)
        {
          memcpy(&usock->req, &req->head, sizeof(usock->req));
          is_ack = false;
        }
      else
        {
          result = ret;
        }
    }

sendack:

  if (is_ack)
    {
      /* Send ACK response. */

      memset(&resp, 0, sizeof(resp));
      resp.result = result;
      _send_ack_common(fd, req->head.xid, &resp);
    }

noack:

  alt1250_printf("end\n");

  return ret;
}

/****************************************************************************
 * Name: listen_request
 ****************************************************************************/

static int listen_request(int fd, FAR struct alt1250_s *dev,
                          FAR void *hdrbuf)
{
  FAR struct usrsock_request_listen_s *req = hdrbuf;
  struct usrsock_message_req_ack_s resp;
  FAR struct usock_s *usock;
  int ret = 0;
  int result = 0;
  bool is_ack = true;
  size_t ocnt = 0;

  DEBUGASSERT(dev);
  DEBUGASSERT(req);

  alt1250_printf("start\n");

  /* Check if this socket exists. */

  usock = alt1250_socket_get(dev, req->usockid);
  if (!usock)
    {
      result = -EBADFD;
      alt1250_printf("Failed to get socket context: %u\n", req->usockid);
      goto sendack;
    }

  if (!is_container_exist(dev))
    {
      ret = RET_NOTAVAIL;
      goto noack;
    }

  if (PREALLOC == usock->state)
    {
      usock->out[ocnt++] = &usock->ret;
      usock->out[ocnt++] = &usock->errcode;

      ret = send_socketreq(usock->domain, usock->type, usock->protocol,
        usock->out, ocnt, req->usockid, dev);
      if (ret >= 0)
        {
          memcpy(&usock->req, &req->head, sizeof(usock->req));
          usock->input.backlog = req->backlog;
          usock->state = OPEN;
          is_ack = false;
        }
      else
        {
          result = ret;
        }
    }
  else
    {
      usock->out[ocnt++] = &usock->ret;
      usock->out[ocnt++] = &usock->errcode;

      ret = send_listenreq(usock->altsock, req->backlog, usock->out, ocnt,
        req->usockid, dev, NULL);
      if (ret >= 0)
        {
          if (ret == 0)
            {
              memcpy(&usock->req, &req->head, sizeof(usock->req));
            }

          is_ack = false;
        }
      else
        {
          result = ret;
        }
    }

sendack:

  if (is_ack)
    {
      /* Send ACK response. */

      memset(&resp, 0, sizeof(resp));
      resp.result = result;
      _send_ack_common(fd, req->head.xid, &resp);
    }

noack:

  alt1250_printf("end\n");

  return ret;
}

/****************************************************************************
 * Name: accept_request
 ****************************************************************************/

static int accept_request(int fd, FAR struct alt1250_s *dev,
                          FAR void *hdrbuf)
{
  FAR struct usrsock_request_accept_s *req = hdrbuf;
  struct usrsock_message_req_ack_s resp;
  FAR struct usock_s *usock = NULL;
  int ret = 0;
  int result = 0;
  bool is_ack = true;
  socklen_t addrlen;
  size_t ocnt = 0;

  DEBUGASSERT(dev);
  DEBUGASSERT(req);

  alt1250_printf("start\n");

  /* Check if this socket exists. */

  usock = alt1250_socket_get(dev, req->usockid);
  if (!usock)
    {
      result = -EBADFD;
      alt1250_printf("Failed to get socket context: %u\n", req->usockid);
      goto sendack;
    }

  if (usock->domain == AF_INET)
    {
      addrlen = sizeof(struct sockaddr_in);
    }
  else
    {
      addrlen = sizeof(struct sockaddr_in6);
    }

  usock->out[ocnt++] = &usock->ret;
  usock->out[ocnt++] = &usock->errcode;
  usock->out[ocnt++] = &usock->output.addr.o_addlen;
  usock->out[ocnt++] = &usock->output.addr.o_addr;

  ret = send_acceptreq(usock->altsock, addrlen, usock->out, ocnt,
    req->usockid, dev);
  if (ret >= 0)
    {
      if (ret == 0)
        {
          memcpy(&usock->req, &req->head, sizeof(usock->req));
          usock->input.addr.addrlen = req->max_addrlen;
        }

      is_ack = false;
    }
  else
    {
      result = ret;
    }

sendack:

  if (is_ack)
    {
      /* Send ACK response. */

      memset(&resp, 0, sizeof(resp));
      resp.result = result;
      _send_ack_common(fd, req->head.xid, &resp);
    }

  alt1250_printf("end\n");

  return ret;
}

/****************************************************************************
 * Name: setsockopt_request
 ****************************************************************************/

static int setsockopt_request(int fd, FAR struct alt1250_s *dev,
                              FAR void *hdrbuf)
{
  FAR struct usrsock_request_setsockopt_s *req = hdrbuf;
  struct usrsock_message_req_ack_s resp;
  FAR struct usock_s *usock;
  ssize_t rlen;
  int ret = 0;
  int result = 0;
  bool is_ack = true;
  size_t ocnt = 0;

  DEBUGASSERT(dev);
  DEBUGASSERT(req);

  alt1250_printf("start\n");

  /* Check if this socket exists. */

  usock = alt1250_socket_get(dev, req->usockid);
  if (!usock)
    {
      result = -EBADFD;
      alt1250_printf("Failed to get socket context: %u\n", req->usockid);
      goto sendack;
    }

  if (req->valuelen > sizeof(usock->input.opt.value))
    {
      result = -EINVAL;
      goto sendack;
    }

  if (!is_container_exist(dev))
    {
      ret = RET_NOTAVAIL;
      goto noack;
    }

  /* Read value. */

  rlen = read(fd, &usock->input.opt.value, sizeof(usock->input.opt.value));
  if ((rlen < 0) || (rlen > sizeof(usock->input.opt.value)))
    {
      result = -EFAULT;
      goto sendack;
    }

  if (PREALLOC == usock->state)
    {
      usock->out[ocnt++] = &usock->ret;
      usock->out[ocnt++] = &usock->errcode;

      ret = send_socketreq(usock->domain, usock->type, usock->protocol,
        usock->out, ocnt, req->usockid, dev);
      if (ret >= 0)
        {
          if (ret == 0)
            {
              memcpy(&usock->req, &req->head, sizeof(usock->req));
              usock->input.opt.level = req->level;
              usock->input.opt.option = req->option;
              usock->input.opt.valuelen = req->valuelen;

              usock->state = OPEN;
            }

          is_ack = false;
        }
      else
        {
          result = ret;
        }
    }
  else
    {
      usock->out[ocnt++] = &usock->ret;
      usock->out[ocnt++] = &usock->errcode;

      ret = send_setsockoptreq(usock->altsock, req->level, req->option,
        req->valuelen, usock->input.opt.value, usock->out, ocnt,
        req->usockid, dev, NULL);
      if (ret >= 0)
        {
          if (ret == 0)
            {
              memcpy(&usock->req, &req->head, sizeof(usock->req));
            }

          is_ack = false;
        }
      else
        {
          result = ret;
        }
    }

sendack:

  if (is_ack)
    {
      /* Send ACK response */

      memset(&resp, 0, sizeof(resp));
      resp.result = result;

      _send_ack_common(fd, req->head.xid, &resp);
    }

noack:

  alt1250_printf("end (ret=%d)\n", ret);

  return ret;
}

/****************************************************************************
 * Name: getsockopt_request
 ****************************************************************************/

static int getsockopt_request(int fd, FAR struct alt1250_s *dev,
                              FAR void *hdrbuf)
{
  FAR struct usrsock_request_getsockopt_s *req = hdrbuf;
  struct usrsock_message_req_ack_s resp;
  FAR struct usock_s *usock;
  int ret = 0;
  int result = 0;
  bool is_ack = true;
  size_t ocnt = 0;

  DEBUGASSERT(dev);
  DEBUGASSERT(req);

  alt1250_printf("start\n");

  /* Check if this socket exists. */

  usock = alt1250_socket_get(dev, req->usockid);
  if (!usock)
    {
      result = -EBADFD;
      alt1250_printf("Failed to get socket context: %u\n", req->usockid);
      goto sendack;
    }

  if (req->max_valuelen > sizeof(usock->output.opt.o_value))
    {
      result = -EINVAL;
      goto sendack;
    }

  if (PREALLOC == usock->state)
    {
      usock->out[ocnt++] = &usock->ret;
      usock->out[ocnt++] = &usock->errcode;

      ret = send_socketreq(usock->domain, usock->type, usock->protocol,
        usock->out, ocnt, req->usockid, dev);
      if (ret >= 0)
        {
          if (ret == 0)
            {
              memcpy(&usock->req, &req->head, sizeof(usock->req));
              usock->input.opt.level = req->level;
              usock->input.opt.option = req->option;
              usock->input.opt.valuelen = req->max_valuelen;

              usock->state = OPEN;
            }

          is_ack = false;
        }
      else
        {
          result = ret;
        }
    }
  else
    {
      usock->out[ocnt++] = &usock->ret;
      usock->out[ocnt++] = &usock->errcode;
      usock->out[ocnt++] = &usock->output.opt.o_optlen;
      usock->out[ocnt++] = usock->output.opt.o_value;
      usock->out[ocnt++] = &req->level;
      usock->out[ocnt++] = &req->option;

      ret = send_getsockoptreq(usock->altsock, req->level, req->option,
        req->max_valuelen, usock->out, ocnt, req->usockid,
        handlereply_getsockopt, dev, NULL);
      if (ret >= 0)
        {
          if (ret == 0)
            {
              memcpy(&usock->req, &req->head, sizeof(usock->req));
              usock->input.opt.valuelen = req->max_valuelen;
            }

          is_ack = false;
        }
      else
        {
          result = ret;
        }
    }

sendack:

  if (is_ack)
    {
      /* Send ACK response */

      memset(&resp, 0, sizeof(resp));
      resp.result = result;

      _send_ack_common(fd, req->head.xid, &resp);
    }

  alt1250_printf("end (ret=%d)\n", ret);

  return ret;
}

/****************************************************************************
 * Name: getsockname_request
 ****************************************************************************/

static int getsockname_request(int fd, FAR struct alt1250_s *dev,
                               FAR void *hdrbuf)
{
  FAR struct usrsock_request_getsockname_s *req = hdrbuf;
  struct usrsock_message_req_ack_s resp;
  FAR struct usock_s *usock;
  int ret = 0;
  int result = 0;
  bool is_ack = true;
  socklen_t addrlen;
  size_t ocnt = 0;

  DEBUGASSERT(dev);
  DEBUGASSERT(req);

  alt1250_printf("start\n");

  /* Check if this socket exists. */

  usock = alt1250_socket_get(dev, req->usockid);
  if (!usock)
    {
      result = -EBADFD;
      alt1250_printf("Failed to get socket context: %u\n", req->usockid);
      goto sendack;
    }

  if (PREALLOC == usock->state)
    {
      usock->out[ocnt++] = &usock->ret;
      usock->out[ocnt++] = &usock->errcode;

      ret = send_socketreq(usock->domain, usock->type, usock->protocol,
        usock->out, ocnt, req->usockid, dev);
      if (ret >= 0)
        {
          if (ret == 0)
            {
              memcpy(&usock->req, &req->head, sizeof(usock->req));
              usock->input.addr.addrlen = req->max_addrlen;
              usock->state = OPEN;
            }

          is_ack = false;
        }
      else
        {
          result = ret;
        }
    }
  else
    {
      if (usock->domain == AF_INET)
        {
          addrlen = sizeof(struct sockaddr_in);
        }
      else
        {
          addrlen = sizeof(struct sockaddr_in6);
        }

      usock->out[ocnt++] = &usock->ret;
      usock->out[ocnt++] = &usock->errcode;
      usock->out[ocnt++] = &usock->output.addr.o_addlen;
      usock->out[ocnt++] = &usock->output.addr.o_addr;

      ret = send_getsocknamereq(usock->altsock, addrlen,
        usock->out, ocnt, req->usockid, dev, NULL);
      if (ret >= 0)
        {
          if (ret == 0)
            {
              memcpy(&usock->req, &req->head, sizeof(usock->req));
              usock->input.addr.addrlen = req->max_addrlen;
            }

          is_ack = false;
        }
      else
        {
          result = ret;
        }
    }

sendack:

  if (is_ack)
    {
      /* Send ACK response */

      memset(&resp, 0, sizeof(resp));
      resp.result = result;

      _send_ack_common(fd, req->head.xid, &resp);
    }

  alt1250_printf("end\n");

  return ret;
}

/****************************************************************************
 * Name: getpeername_request
 ****************************************************************************/

static int getpeername_request(int fd, FAR struct alt1250_s *dev,
                               FAR void *hdrbuf)
{
  FAR struct usrsock_request_getpeername_s *req = hdrbuf;
  struct usrsock_message_req_ack_s resp;

  alt1250_printf("start\n");

  /* Not support */

  memset(&resp, 0, sizeof(resp));
  resp.result = -ENOTSUP;
  _send_ack_common(fd, req->head.xid, &resp);

  alt1250_printf("end\n");

  return OK;
}

/****************************************************************************
 * Name: ioctl_request
 ****************************************************************************/

static int ioctl_request(int fd, FAR struct alt1250_s *dev,
                         FAR void *hdrbuf)
{
  int ret = OK;
  int result = OK;
  FAR struct usrsock_request_ioctl_s *req = hdrbuf;
  struct usrsock_message_req_ack_s resp;
  FAR struct usock_s *usock;
  bool is_ack = false;
  int8_t flags = 0;

  alt1250_printf("start: req->arglen=%u\n", req->arglen);

  usock = alt1250_socket_get(dev, req->usockid);
  if (usock == NULL)
    {
      result = -EBADFD;
      alt1250_printf("Failed to get socket context: %u\n", req->usockid);
      goto sendack;
    }

  switch (req->cmd)
    {
      case SIOCLTECMD:
        {
          struct lte_ioctl_data_s ltecmd;

          if (sizeof(ltecmd) < req->arglen)
            {
              alt1250_printf("SIOCLTECMD: unexpected size: %d, expect: %d\n",
                req->arglen, sizeof(ltecmd));
              result = -EFAULT;
              goto sendack;
            }

          ret = read(fd, &ltecmd, sizeof(ltecmd));
          if (0 > ret || ret < req->arglen)
            {
              alt1250_printf("read unexpected size:%d, expect: %d.\n",
                ret, req->arglen);
              result = -EFAULT;
              goto sendack;
            }

          alt1250_printf("SIOCLTECMD: cmdid:0x%08lx\n", ltecmd.cmdid);

          if (LTE_ISCMDGRP_NORMAL(ltecmd.cmdid))
            {
              ret = ioctl_lte_normal(fd, dev, &ltecmd, req->usockid, &flags);
              if (ret == OK)
                {
                  if (!is_synccmd(ltecmd.cmdid))
                    {
                      is_ack = true;
                    }
                }
              else if (ret < 0)
                {
                  result = ret;
                }
            }
          else if (LTE_ISCMDGRP_EVENT(ltecmd.cmdid))
            {
              ret = ioctl_lte_event(fd, dev, &ltecmd, req->usockid);
              if (ret == OK)
                {
                  if (!is_synccmd(ltecmd.cmdid))
                    {
                      is_ack = true;
                    }
                }
              else if (ret < 0)
                {
                  result = ret;
                }
            }
          else if (LTE_ISCMDGRP_NOMDM(ltecmd.cmdid))
            {
              ret = ioctl_lte_nomdm(fd, dev, &ltecmd, req->usockid);
              if (ret == OK)
                {
                  is_ack = true;
                }
              else if (ret < 0)
                {
                  result = ret;
                }
            }
          else if (LTE_ISCMDGRP_POWER(ltecmd.cmdid))
            {
              ret = ioctl_lte_power(fd, dev, &ltecmd, req->usockid);
              if ((ret == OK) || (ret == RET_TERM))
                {
                  is_ack = true;
                }
              else if (ret < 0)
                {
                  result = ret;
                }
            }
          else
            {
              alt1250_printf("SIOCLTECMD unexpected cmdid:0x%08lx\n",
                ltecmd.cmdid);
              result = -EINVAL;
              goto sendack;
            }

          if (ret == RET_NOTAVAIL)
            {
              /* If the container does not exist, this function
               * will be called again. Therefore, reset the offset
               * so that it is possible to read from the same offset
               * as last time.
               */

              int offset = -req->arglen;
              lseek(fd, offset, SEEK_CUR);
            }
        }
        break;

      case SIOCSIFFLAGS:
        {
          struct ifreq if_req;
          if (sizeof(struct ifreq) < req->arglen)
            {
              alt1250_printf("SIOCSIFFLAGS: unexpected size:%d, expect:%d\n",
                req->arglen, sizeof(struct ifreq));
              result = -EFAULT;
              goto sendack;
            }

          ret = read(fd, (FAR void *)&if_req, req->arglen);
          if (0 > ret || ret < req->arglen)
            {
              alt1250_printf("read unexpected size:%d, expect:%d.\n",
                ret, req->arglen);
              result = -EFAULT;
              goto sendack;
            }

          if (if_req.ifr_flags & IFF_UP)
            {
              ret = handle_ifup(req->usockid, dev);
              if (ret < 0)
                {
                  result = ret;
                }
            }
          else if(if_req.ifr_flags & IFF_DOWN)
            {
              ret = handle_ifdown(req->usockid, dev);
              if (ret < 0)
                {
                  result = ret;
                }
            }
          else
            {
              alt1250_printf("unexpected ifr_flags:0x%02x\n",
                if_req.ifr_flags);
              result = -EINVAL;
              goto sendack;
            }

          if (ret == RET_NOTAVAIL)
            {
              /* If the container does not exist, this function
               * will be called again. Therefore, reset the offset
               * so that it is possible to read from the same offset
               * as last time.
               */

              int offset = -req->arglen;
              lseek(fd, offset, SEEK_CUR);
            }
        }
        break;

      default:
        alt1250_printf("unexpected command:0x%08lx\n",
          req->cmd);
        result = -EINVAL;
        break;
    }

sendack:
  if ((result < 0) || (is_ack))
    {
      if (flags & USRSOCK_MESSAGE_FLAG_REQ_IN_PROGRESS)
        {
          /* save request parameter for delayed ack */

          memcpy(&usock->req, &req->head, sizeof(usock->req));
        }

       memset(&resp, 0, sizeof(resp));
       resp.result = result;
       _send_ack(fd, flags, req->head.xid, &resp);
    }
  else
    {
      /* save request parameter for delayed ack */

      memcpy(&usock->req, &req->head, sizeof(usock->req));
    }

  alt1250_printf("end\n");

  return ret;
}

/****************************************************************************
 * Name: ioctl_lte_power
 ****************************************************************************/

static int ioctl_lte_power(int fd, FAR struct alt1250_s *dev,
  FAR struct lte_ioctl_data_s *cmd, uint16_t usockid)
{
  int ret = -EINVAL;
  struct alt_power_s power;

  switch (cmd->cmdid)
    {
      case LTE_CMDID_POWERON:
      case LTE_CMDID_TAKEWLOCK:
      case LTE_CMDID_GIVEWLOCK:
        power.cmdid = cmd->cmdid;
        ret = ioctl(dev->altfd, ALT1250_IOC_POWER, (unsigned long)&power);
        if (ret < 0)
          {
            ret = -errno;
          }
        else
          {
            ret = OK;
          }
        break;
      case LTE_CMDID_POWEROFF:
        alt1250_clrevtcb(ALT1250_CLRMODE_WO_RESTART);
        power.cmdid = cmd->cmdid;
        ret = ioctl(dev->altfd, ALT1250_IOC_POWER, (unsigned long)&power);
        if (ret < 0)
          {
            ret = -errno;
          }
        else
          {
            ret = OK;
          }
        break;
      case LTE_CMDID_FIN:
        alt1250_clrevtcb(ALT1250_CLRMODE_ALL);
        ret = RET_TERM;
        break;

      default:
        ret = -EINVAL;
        break;
    }

  return ret;
}

/****************************************************************************
 * Name: ioctl_lte_nomdm
 ****************************************************************************/

static int ioctl_lte_nomdm(int fd, FAR struct alt1250_s *dev,
  FAR struct lte_ioctl_data_s *cmd, uint16_t usockid)
{
  int ret = OK;

  switch (cmd->cmdid)
    {
      case LTE_CMDID_SETRESTART:

        /* register callback */

        ret = alt1250_regevtcb(cmd->cmdid, cmd->cb);
        break;

      case LTE_CMDID_SETEVTCTX:
        {
          FAR struct lte_evtctx_in_s *in = cmd->inparam[0];
          FAR struct lte_evtctx_out_s *out = cmd->outparam[0];

          if ((in != NULL) && (in->mqname != NULL) && (out != NULL))
            {
              ret = evt_qopen(in->mqname, &dev->evtq);
              out->handle = alt1250_execcb;
            }
          else
            {
              ret = -EINVAL;
            }
        }
        break;

      case LTE_CMDID_GETERRINFO:
        {
          void **arg = alt1250_getevtarg(LTE_CMDID_GETERRINFO);

          if (arg && arg[0] && cmd->outparam && cmd->outparam[0])
            {
              memcpy(cmd->outparam[0], arg[0], sizeof(lte_errinfo_t));
            }
        }
        break;

      case LTE_CMDID_SAVEAPN:
        {
          FAR lte_apn_setting_t *apn;

          if (cmd->inparam && cmd->inparam[0])
            {
              apn = cmd->inparam[0];
              saveapn(dev, apn);
            }
        }
        break;

      case LTE_CMDID_GETAPN:
        {
          FAR lte_apn_setting_t *apn;

          if (cmd->outparam && cmd->outparam[0])
            {
              apn = cmd->outparam[0];
              getapn(dev, apn);
            }
        }
        break;

      default:
        ret = -EINVAL;
        break;
    }

  return ret;
}

/****************************************************************************
 * Name: ioctl_lte_event
 ****************************************************************************/

static int ioctl_lte_event(int fd, FAR struct alt1250_s *dev,
  FAR struct lte_ioctl_data_s *cmd, uint16_t usockid)
{
  int ret = OK;
  FAR struct usock_s *usock = NULL;

  usock = alt1250_socket_get(dev, usockid);
  if (!usock)
    {
      ret = -EBADFD;
      goto errout;
    }

  if (cmd->cmdid)
    {
      ret = alt1250_regevtcb(cmd->cmdid & ~LTE_CMDOPT_ASYNC_BIT, cmd->cb);
      if (ret < 0)
        {
          goto errout;
        }
    }

  ret = send_commonreq(cmd->cmdid, cmd->inparam, cmd->inparamlen,
    cmd->outparam, cmd->outparamlen, usockid, NULL, 0, dev, NULL);
  if (ret < 0)
    {
      /* clear callback */

      alt1250_regevtcb(cmd->cmdid, NULL);
    }

errout:
  return ret;
}

/****************************************************************************
 * Name: ioctl_lte_normal
 ****************************************************************************/

static int ioctl_lte_normal(int fd, FAR struct alt1250_s *dev,
  FAR struct lte_ioctl_data_s *cmd, uint16_t usockid, int8_t *flags)
{
  int ret = OK;
  FAR struct usock_s *usock = NULL;

  usock = alt1250_socket_get(dev, usockid);
  if (!usock)
    {
      ret = -EBADFD;
      goto errout;
    }

  if ((cmd->cmdid & LTE_CMDOPT_ASYNC_BIT) && (cmd->cb != NULL))
    {
      ret = alt1250_regevtcb(cmd->cmdid & ~LTE_CMDOPT_ASYNC_BIT, cmd->cb);
      if (ret < 0)
        {
          goto errout;
        }

      cmd->outparam = alt1250_getevtarg(
        cmd->cmdid & ~LTE_CMDOPT_ASYNC_BIT);
    }

  if (cmd->cmdid == LTE_CMDID_TLS_SSL_BIO)
    {
      int *altsock_fd;
      altsock_fd = (int *)cmd->inparam[5];
      *altsock_fd = usock->altsock;
    }

  ret = send_commonreq(cmd->cmdid, cmd->inparam, cmd->inparamlen,
    cmd->outparam, cmd->outparamlen, usockid, NULL, 0, dev, NULL);
  if (ret < 0)
    {
      /* clear callback */

      alt1250_regevtcb(cmd->cmdid & ~LTE_CMDOPT_ASYNC_BIT, NULL);
    }
  else
    {
      if ((cmd->cmdid & ~LTE_CMDOPT_ASYNC_BIT) == LTE_CMDID_ACTPDN)
        {
          FAR lte_apn_setting_t *apn;

          if (cmd->inparam && cmd->inparam[0])
            {
              /* Holds apn information for use with LTE_CMDID_GETAPN */

              apn = cmd->inparam[0];
              saveapn(dev, apn);
            }

          /* Returns EINPROGRESS for synchronous */

          if (cmd->cmdid == LTE_CMDID_ACTPDN)
            {
              *flags |= USRSOCK_MESSAGE_FLAG_REQ_IN_PROGRESS;
              ret = -EINPROGRESS;
            }
        }
      else if (cmd->cmdid == LTE_CMDID_TLS_SSL_HANDSHAKE)
        {
          /* The request from usersock cannot be accepted until the handshake
           * response is returned, so the EINPROGRESS is returned so that
           * the request can be accepted.
           */

          *flags |= USRSOCK_MESSAGE_FLAG_REQ_IN_PROGRESS;
          ret = -EINPROGRESS;
        }
    }

errout:
  return ret;
}

/****************************************************************************
 * Name: do_connectseq
 ****************************************************************************/

static int do_connectseq(FAR struct usock_s *usock, uint16_t usockid,
  FAR struct alt1250_s *dev, FAR struct alt_container_s *container)
{
  int ret;
  size_t ocnt = 0;

  usock->out[ocnt++] = &usock->ret;
  usock->out[ocnt++] = &usock->errcode;

  ret = send_connectreq(usock->altsock, usock->input.addr.addrlen,
    &usock->input.addr.addr, usock->out, ocnt, usockid, dev, container);
  if (ret >= 0)
    {
      if (ret == 0)
        {
          usock->state = CONNECTING;
        }
    }

  return ret;
}

/****************************************************************************
 * Name: do_bindseq
 ****************************************************************************/

static int do_bindseq(FAR struct usock_s *usock, uint16_t usockid,
  FAR struct alt1250_s *dev, FAR struct alt_container_s *container)
{
  int ret;
  size_t ocnt = 0;

  usock->out[ocnt++] = &usock->ret;
  usock->out[ocnt++] = &usock->errcode;

  ret = send_bindreq(usock->altsock, usock->input.addr.addrlen,
    &usock->input.addr.addr, usock->out, ocnt, usockid, dev, container);

  return ret;
}

/****************************************************************************
 * Name: do_listenseq
 ****************************************************************************/

static int do_listenseq(FAR struct usock_s *usock, uint16_t usockid,
  FAR struct alt1250_s *dev, FAR struct alt_container_s *container)
{
  int ret;
  size_t ocnt = 0;

  usock->out[ocnt++] = &usock->ret;
  usock->out[ocnt++] = &usock->errcode;

  ret = send_listenreq(usock->altsock, usock->input.backlog, usock->out,
    ocnt, usockid, dev, container);

  return ret;
}

/****************************************************************************
 * Name: do_setsockoptseq
 ****************************************************************************/

static int do_setsockoptseq(FAR struct usock_s *usock, uint16_t usockid,
  FAR struct alt1250_s *dev, FAR struct alt_container_s *container)
{
  int ret;
  size_t ocnt = 0;

  usock->out[ocnt++] = &usock->ret;
  usock->out[ocnt++] = &usock->errcode;

  ret = send_setsockoptreq(usock->altsock, usock->input.opt.level,
    usock->input.opt.option, usock->input.opt.valuelen,
    usock->input.opt.value, usock->out, ocnt, usockid, dev, container);

  return ret;
}

/****************************************************************************
 * Name: do_getsockoptseq
 ****************************************************************************/

static int do_getsockoptseq(FAR struct usock_s *usock, uint16_t usockid,
  FAR struct alt1250_s *dev, FAR struct alt_container_s *container)
{
  int ret;
  size_t ocnt = 0;

  usock->out[ocnt++] = &usock->ret;
  usock->out[ocnt++] = &usock->errcode;
  usock->out[ocnt++] = &usock->output.opt.o_optlen;
  usock->out[ocnt++] = usock->output.opt.o_value;
  usock->out[ocnt++] = &usock->input.opt.level;
  usock->out[ocnt++] = &usock->input.opt.option;

  ret = send_getsockoptreq(usock->altsock, usock->input.opt.level,
    usock->input.opt.option, usock->input.opt.valuelen, usock->out, ocnt,
    usockid, handlereply_getsockopt, dev, container);

  return ret;
}

/****************************************************************************
 * Name: do_getsocknameseq
 ****************************************************************************/

static int do_getsocknameseq(FAR struct usock_s *usock, uint16_t usockid,
  FAR struct alt1250_s *dev, FAR struct alt_container_s *container)
{
  int ret;
  size_t ocnt = 0;

  usock->out[ocnt++] = &usock->ret;
  usock->out[ocnt++] = &usock->errcode;
  usock->out[ocnt++] = &usock->output.addr.o_addlen;
  usock->out[ocnt++] = &usock->output.addr.o_addr;

  ret = send_getsocknamereq(usock->altsock, usock->input.addr.addrlen,
    usock->out, ocnt, usockid, dev, container);

  return ret;
}

/****************************************************************************
 * Name: handle_selectevt
 ****************************************************************************/

static int handle_selectevt(int32_t result, int32_t err, int32_t id,
  FAR altcom_fd_set *readset, FAR altcom_fd_set *writeset,
  FAR altcom_fd_set *exceptset, FAR struct alt1250_s *dev)
{
  int ret;
  int i;
  FAR struct usock_s *usock;

  alt1250_printf("select reply. ret=%ld err=%ld\n", result, err);

  if (id != dev->sid)
    {
      alt1250_printf("Select event come wish in no selected.id = %ld\n", id);

      return 0;
    }

  if (result < 0)
    {
      ret = -err;
    }
  else
    {
      for (i = 0; i < SOCKET_COUNT; i++)
        {
          usock = alt1250_socket_get(dev, i);
          if (usock && (usock->state != CLOSED) &&
              (usock->state != PREALLOC) && (usock->state != ABORTED) &&
              (usock->state != CLOSING) && (usock->state != OPEN))
            {
              if (ALTCOM_FD_ISSET(usock->altsock, exceptset))
                {
                  usock->state = ABORTED;
                  alt1250_printf("exceptset is set. usockid: %d\n",
                    SOCKID(i));
                }

              if (ALTCOM_FD_ISSET(usock->altsock, readset))
                {
                  alt1250_printf("readset is set. usockid: %d\n", SOCKID(i));
                  usock->sockflags |= USRSOCK_EVENT_RECVFROM_AVAIL;

                  usock_send_event(dev->usockfd, dev, usock,
                                   USRSOCK_EVENT_RECVFROM_AVAIL);
                }

              if (ALTCOM_FD_ISSET(usock->altsock, writeset))
                {
                  alt1250_printf("writeset is set. usockid: %d\n",
                    SOCKID(i));
                  usock->sockflags |= USRSOCK_EVENT_SENDTO_READY;

                  if (usock->state == WAITCONN)
                    {
                      usock->o_getoptlv  = SOL_SOCKET;
                      usock->o_getoptopt = SO_ERROR;

                      usock->connxid = usock->req.xid;
                      usock->outgetopt[0] = &usock->o_getoptret;
                      usock->outgetopt[1] = &usock->o_getopterr;
                      usock->outgetopt[2] = &usock->o_getoptlen;
                      usock->outgetopt[3] = usock->o_getoptval;
                      usock->outgetopt[4] = &usock->o_getoptlv;
                      usock->outgetopt[5] = &usock->o_getoptopt;

                      ret = send_getsockoptreq(usock->altsock,
                        usock->o_getoptlv, usock->o_getoptopt,
                        sizeof(int), usock->outgetopt, 6, i,
                        handlereply_getsockopt_conn, dev, NULL);

                      alt1250_printf("writeset is set. usockid: %d\n",
                        SOCKID(i));
                    }
                  else
                    {
                      usock_send_event(dev->usockfd, dev, usock,
                                       USRSOCK_EVENT_SENDTO_READY);
                    }
                }
            }
        }

      ret = select_start(0, dev, NULL);
    }

  return ret;
}

/****************************************************************************
 * Name: handle_ifup
 ****************************************************************************/

static int handle_ifup(int16_t usockid, FAR struct alt1250_s *dev)
{
  int ret;
  FAR struct usock_s *usock;
  size_t ocnt = 0;

  usock = alt1250_socket_get(dev, usockid);
  if (!usock)
    {
      return -EBADFD;
    }

  usock->out[ocnt++] = &usock->ret;

  ret = send_radioonreq(usock->out, ocnt, usockid, dev);

  return ret;
}

/****************************************************************************
 * Name: handle_ifdown
 ****************************************************************************/

static int handle_ifdown(int16_t usockid, FAR struct alt1250_s *dev)
{
  int ret;
  FAR struct usock_s *usock;
  size_t ocnt = 0;

  usock = alt1250_socket_get(dev, usockid);
  if (!usock)
    {
      return -EBADFD;
    }

  usock->out[ocnt++] = &usock->ret;

  ret = send_radiooffreq(usock->out, ocnt, usockid, dev);

  return ret;
}

/****************************************************************************
 * Name: handle_replypkt
 ****************************************************************************/

static int handle_replypkt(int fd, FAR struct alt_container_s *reply,
  FAR struct alt1250_s *dev)
{
  int ret = OK;
  FAR struct usock_s *usock;
  struct usrsock_message_req_ack_s resp;
  FAR struct waithdlr_s *ctx = (FAR struct waithdlr_s *)reply->priv;

  usock = alt1250_socket_get(dev, reply->sock);
  if (usock == NULL)
    {
      return -EINVAL;
    }

  alt1250_printf("reply->result: %d\n", reply->result);

  if (ctx && ctx->hdlr)
    {
      /* ctx->hdlr contains handlereply_xxxx() function pointer */

      ret = ctx->hdlr(EVENT_REPLY, ctx->priv, reply, usock, dev);
    }
  else
    {
      /* Send ACK response */

      memset(&resp, 0, sizeof(resp));
      resp.result = reply->result;
      _send_ack_common(fd, usock->req.xid, &resp);

      free_container(dev, reply);
    }

  return ret;
}

/****************************************************************************
 * Name: handlereply_sockcommon
 ****************************************************************************/

static int handlereply_sockcommon(uint8_t event, unsigned long priv,
  FAR struct alt_container_s *reply, FAR struct usock_s *usock,
  FAR struct alt1250_s *dev)
{
  int ret = 0;
  struct usrsock_message_req_ack_s resp;
  uint16_t usockid;

  alt1250_printf("start, event:%u\n", event);

  /* reply->outparam[0]: return code
   * reply->outparam[1]: error code
   */

  ret = parse_sockcommon_reply(*(int *)(reply->outparam[0]),
    *(int *)(reply->outparam[1]));

  usockid = reply->sock;

  switch (usock->req.reqid)
    {
    case USRSOCK_REQUEST_SENDTO:
      usock->sockflags &= ~USRSOCK_EVENT_SENDTO_READY;
      if (ret >= 0)
        {
          /* The select requires a container,
           * which is released when the send is complete.
           */

          select_cancel(usockid, dev, reply);
          select_start(usockid, dev, NULL);
        }
      else
        {
          free_container(dev, reply);
        }
        break;

    case USRSOCK_REQUEST_CLOSE:
      alt1250_socket_free(dev, usockid);
      free_container(dev, reply);
      break;

    default:
      free_container(dev, reply);
      break;
    }

  /* Send ACK response */

  memset(&resp, 0, sizeof(resp));
  resp.result = ret;

  _send_ack_common(dev->usockfd, usock->req.xid, &resp);

  alt1250_printf("end\n");

  return ret;
}

/****************************************************************************
 * Name: handlereply_socket
 ****************************************************************************/

static int handlereply_socket(uint8_t event, unsigned long priv,
  FAR struct alt_container_s *reply, FAR struct usock_s *usock,
  FAR struct alt1250_s *dev)
{
  int ret = 0;
  int32_t cmd = ALTCOM_GETFL;
  int32_t val = 0;
  size_t ocnt = 0;
  struct usrsock_message_req_ack_s resp;

  alt1250_printf("start, event:%u\n", event);

  /* reply->outparam[0]: socket fd
   * reply->outparam[1]: error code
   */

  ret = parse_socket_reply(*(int *)(reply->outparam[0]),
    *(int *)(reply->outparam[1]), usock);
  if (ret >= 0)
    {
      /* Get flag of socket fd */

      usock->out[ocnt++] = &usock->ret;
      usock->out[ocnt++] = &usock->errcode;

      ret = send_fctlreq(usock->altsock, cmd, val, usock->out, ocnt,
        reply->sock, handlereply_getfl, dev, reply);
    }
  else
    {
      usock->state = PREALLOC;
      if (usock->type == SOCK_DGRAM)
        {
          alt1250_socket_free(dev, reply->sock);
        }

      free_container(dev, reply);
    }

  if (ret < 0)
    {
      /* Send ACK response of the error. */

      memset(&resp, 0, sizeof(resp));
      resp.result = ret;
      _send_ack_common(dev->usockfd, usock->req.xid, &resp);
    }

  alt1250_printf("end\n");

  return ret;
}

/****************************************************************************
 * Name: handlereply_connect
 ****************************************************************************/

static int handlereply_connect(uint8_t event, unsigned long priv,
  FAR struct alt_container_s *reply, FAR struct usock_s *usock,
  FAR struct alt1250_s *dev)
{
  int ret = 0;
  struct usrsock_message_req_ack_s resp;
  int8_t flags = 0;

  alt1250_printf("start, event:%u\n", event);

  ret = parse_sockcommon_reply(*(int *)(reply->outparam[0]),
    *(int *)(reply->outparam[1]));
  if (ret == 0)
    {
      usock->state = CONNECTED;
    }
  else if ((ret < 0) && (ret == -EINPROGRESS))
    {
      usock->state = WAITCONN;
    }
  else
    {
      usock->state = OPENED;
    }

  /* Send ACK response. */

  if (usock->state != WAITCONN)
    {
      memset(&resp, 0, sizeof(resp));
      resp.result = ret;
      _send_ack(dev->usockfd, flags, usock->req.xid, &resp);
    }

  free_container(dev, reply);

  alt1250_printf("end\n");

  return ret;
}

/****************************************************************************
 * Name: handlereply_recvfrom
 ****************************************************************************/

static int handlereply_recvfrom(uint8_t event, unsigned long priv,
  FAR struct alt_container_s *reply, FAR struct usock_s *usock,
  FAR struct alt1250_s *dev)
{
  int ret = 0;
  int size = 0;
  uint16_t usockid;

  alt1250_printf("start, event:%u\n", event);

  dev->recvfrom_processing = false;

  usockid = reply->sock;
  usock->sockflags &= ~USRSOCK_EVENT_RECVFROM_AVAIL;

  /* reply->outparam[0]: recv size
   * reply->outparam[1]: error code
   * reply->outparam[2]: fromlen
   * reply->outparam[3]: address
   * reply->outparam[4]: buffer
   */

  size = parse_sockcommon_reply(*(int *)(reply->outparam[0]),
    *(int *)(reply->outparam[1]));
  if (size >= 0)
    {
      struct usrsock_message_datareq_ack_s resp;

      if ((size == 0) && (_rx_max_buflen != 0))
        {
          usock_send_event(dev->usockfd, dev, usock,
            USRSOCK_EVENT_REMOTE_CLOSED);
        }

      /* Send response. */

      memset(&resp, 0, sizeof(resp));
      resp.reqack.head.msgid = USRSOCK_MESSAGE_RESPONSE_DATA_ACK;
      resp.reqack.head.flags = 0;
      resp.reqack.xid = usock->req.xid;
      resp.reqack.result = size;

      resp.valuelen = MIN(usock->input.addr.addrlen,
        *(uint16_t *)(reply->outparam[2]));
      resp.valuelen_nontrunc = *(uint16_t *)(reply->outparam[2]);

      _write_to_usock(dev->usockfd, &resp, sizeof(resp));

      if (resp.valuelen > 0)
        {
          _write_to_usock(dev->usockfd,
            (FAR struct sockaddr_storage *)(reply->outparam[3]),
            resp.valuelen);
        }

      if (size > 0)
        {
          _write_to_usock(dev->usockfd, reply->outparam[4], size);
        }

      /* The select requires a container,
       * which is released when the send is complete.
       */

      select_cancel(usockid, dev, reply);
      select_start(usockid, dev, NULL);
    }
  else
    {
      struct usrsock_message_req_ack_s resp;

      /* Send ACK response */

      memset(&resp, 0, sizeof(resp));
      resp.result = size;
      _send_ack_common(dev->usockfd, usock->req.xid, &resp);

      free_container(dev, reply);
    }

  alt1250_printf("end\n");

  return ret;
}

/****************************************************************************
 * Name: handlereply_accept
 ****************************************************************************/

static int handlereply_accept(uint8_t event, unsigned long priv,
  FAR struct alt_container_s *reply, FAR struct usock_s *usock,
  FAR struct alt1250_s *dev)
{
  int ret = 0;
  int altsock;
  uint16_t usockid;
  FAR struct usock_s *newusock;

  alt1250_printf("start, event:%u\n", event);

  /* reply->outparam[0]: socket fd
   * reply->outparam[1]: error code
   * reply->outparam[2]: addrlen
   * reply->outparam[3]: accepted address
   */

  altsock = parse_sockcommon_reply(*(int *)(reply->outparam[0]),
    *(int *)(reply->outparam[1]));
  if (altsock >= 0)
    {
      usock->sockflags &= ~USRSOCK_EVENT_RECVFROM_AVAIL;

      usockid = alt1250_socket_alloc(dev,
        usock->domain, usock->type, usock->protocol);
      if (usockid < 0)
        {
          struct usrsock_message_req_ack_s resp;

          /* Send ACK response of the error */

          memset(&resp, 0, sizeof(resp));
          resp.result = usockid;

          _send_ack_common(dev->usockfd, usock->req.xid, &resp);

          free_container(dev, reply);
        }
      else
        {
          newusock = alt1250_socket_get(dev, usockid);
          if (newusock)
            {
              struct usrsock_message_datareq_ack_s resp;

              newusock->altsock = altsock;
              newusock->state = CONNECTED;

              /* Send response. */

              memset(&resp, 0, sizeof(resp));
              resp.reqack.head.msgid = USRSOCK_MESSAGE_RESPONSE_DATA_ACK;
              resp.reqack.head.flags = 0;
              resp.reqack.xid = usock->req.xid;
              resp.reqack.result  = sizeof(uint16_t);

              resp.valuelen = MIN(usock->input.addr.addrlen,
                *(uint16_t *)(reply->outparam[2]));
              resp.valuelen_nontrunc = *(uint16_t *)(reply->outparam[2]);

              _write_to_usock(dev->usockfd, &resp, sizeof(resp));

              if (resp.valuelen > 0)
                {
                  _write_to_usock(dev->usockfd,
                    (FAR struct sockaddr_storage *)(reply->outparam[3]),
                    resp.valuelen);
                }

              _write_to_usock(dev->usockfd, &usockid, sizeof(usockid));

              /* The select requires a container,
               * which is released when the send is complete.
               */

              select_cancel(usockid, dev, reply);
              select_start(usockid, dev, NULL);
            }
          else
            {
              struct usrsock_message_req_ack_s resp;

              /* Send ACK response of the error */

              memset(&resp, 0, sizeof(resp));
              resp.result = -EFAULT;

              _send_ack_common(dev->usockfd, usock->req.xid, &resp);

              free_container(dev, reply);
            }
        }
    }
  else
    {
      struct usrsock_message_req_ack_s resp;

      /* Send ACK response of the error */

      memset(&resp, 0, sizeof(resp));
      resp.result = altsock;

      _send_ack_common(dev->usockfd, usock->req.xid, &resp);

      free_container(dev, reply);
    }

  alt1250_printf("end\n");

  return ret;
}

/****************************************************************************
 * Name: handlereply_getsockopt
 ****************************************************************************/

static int handlereply_getsockopt(uint8_t event, unsigned long priv,
  FAR struct alt_container_s *reply, FAR struct usock_s *usock,
  FAR struct alt1250_s *dev)
{
  int ret = 0;

  alt1250_printf("start, event:%u\n", event);

  /* reply->outparam[0]: ret code
   * reply->outparam[1]: error code
   * reply->outparam[2]: optlen
   * reply->outparam[3]: optval
   */

  ret = parse_sockcommon_reply(*(int *)(reply->outparam[0]),
    *(int *)(reply->outparam[1]));
  if (ret < 0)
    {
      struct usrsock_message_req_ack_s resp;

      /* Send ACK response of the error */

      memset(&resp, 0, sizeof(resp));
      resp.result = ret;

      _send_ack_common(dev->usockfd, usock->req.xid, &resp);
    }
  else
    {
      struct usrsock_message_datareq_ack_s resp;

      /* Send response. */

      memset(&resp, 0, sizeof(resp));
      resp.reqack.head.msgid = USRSOCK_MESSAGE_RESPONSE_DATA_ACK;
      resp.reqack.head.flags = 0;
      resp.reqack.result = ret;
      resp.reqack.xid = usock->req.xid;

      if (ret >= 0)
        {
          resp.valuelen = MIN(usock->input.opt.valuelen,
            *(uint16_t *)(reply->outparam[2]));
          resp.valuelen_nontrunc = *(uint16_t *)(reply->outparam[2]);
        }
      else
        {
          resp.valuelen = 0;
          resp.valuelen_nontrunc = 0;
        }

      _write_to_usock(dev->usockfd, &resp, sizeof(resp));

      if (resp.valuelen > 0)
        {
          _write_to_usock(dev->usockfd,
            reply->outparam[3],
            resp.valuelen);
        }
    }

  free_container(dev, reply);

  alt1250_printf("end\n");

  return ret;
}

/****************************************************************************
 * Name: handlereply_getsockopt_conn
 ****************************************************************************/

static int handlereply_getsockopt_conn(uint8_t event, unsigned long priv,
  FAR struct alt_container_s *reply, FAR struct usock_s *usock,
  FAR struct alt1250_s *dev)
{
  int ret = 0;
  struct usrsock_message_req_ack_s resp;

  alt1250_printf("start, event:%u\n", event);

  /* reply->outparam[0]: ret code
   * reply->outparam[1]: error code
   * reply->outparam[2]: optlen
   * reply->outparam[3]: optval
   */

  ret = parse_sockcommon_reply(*(int *)(reply->outparam[0]),
    *(int *)(reply->outparam[1]));
  if (ret == 0)
    {
      memset(&resp, 0, sizeof(resp));
      resp.result = *(int32_t *)(reply->outparam[3]);
      if (resp.result > 0)
        {
          resp.result = -resp.result;
        }

      _send_ack_common(dev->usockfd, usock->connxid, &resp);

      if (resp.result == 0)
        {
          usock->state = CONNECTED;
        }
      else
        {
          usock->state = OPENED;
        }
    }
  else
    {
      usock->state = OPENED;

      /* Send ACK response of the error */

      memset(&resp, 0, sizeof(resp));
      resp.result = ret;

      _send_ack_common(dev->usockfd, usock->connxid, &resp);
    }

  usock_send_event(dev->usockfd, dev, usock, USRSOCK_EVENT_SENDTO_READY);

  free_container(dev, reply);

  alt1250_printf("end\n");

  return ret;
}

/****************************************************************************
 * Name: handlereply_getsockname
 ****************************************************************************/

static int handlereply_getsockname(uint8_t event, unsigned long priv,
  FAR struct alt_container_s *reply, FAR struct usock_s *usock,
  FAR struct alt1250_s *dev)
{
  int ret = 0;

  alt1250_printf("start, event:%u\n", event);

  /* reply->outparam[0]: ret code
   * reply->outparam[1]: error code
   * reply->outparam[2]: addrlen
   * reply->outparam[3]: address
   */

  ret = parse_sockcommon_reply(*(int *)(reply->outparam[0]),
    *(int *)(reply->outparam[1]));
  if (ret < 0)
    {
      struct usrsock_message_req_ack_s resp;

      /* Send ACK response */

      memset(&resp, 0, sizeof(resp));
      resp.result = ret;

      _send_ack_common(dev->usockfd, usock->req.xid, &resp);
    }
  else
    {
      struct usrsock_message_datareq_ack_s resp;

      /* Send response. */

      memset(&resp, 0, sizeof(resp));
      resp.reqack.head.msgid = USRSOCK_MESSAGE_RESPONSE_DATA_ACK;
      resp.reqack.head.flags = 0;
      resp.reqack.result     = ret;
      resp.reqack.xid        = usock->req.xid;

      if (ret >= 0)
        {
          resp.valuelen = MIN(usock->input.addr.addrlen,
            *(uint16_t *)(reply->outparam[2]));
          resp.valuelen_nontrunc = *(uint16_t *)(reply->outparam[2]);
        }
      else
        {
          resp.valuelen = 0;
          resp.valuelen_nontrunc = 0;
        }

      _write_to_usock(dev->usockfd, &resp, sizeof(resp));

      if (resp.valuelen > 0)
        {
          _write_to_usock(dev->usockfd,
            reply->outparam[3],
            resp.valuelen);
        }
    }

  free_container(dev, reply);

  alt1250_printf("end\n");

  return ret;
}

/****************************************************************************
 * Name: handlereply_getfl
 ****************************************************************************/

static int handlereply_getfl(uint8_t event, unsigned long priv,
  FAR struct alt_container_s *reply, FAR struct usock_s *usock,
  FAR struct alt1250_s *dev)
{
  int ret = 0;
  int32_t cmd = ALTCOM_SETFL;
  int32_t val = 0;
  size_t ocnt = 0;

  alt1250_printf("start, event:%u\n", event);

  val = parse_sockcommon_reply(*(int *)(reply->outparam[0]),
    *(int *)(reply->outparam[1]));
  if (val >= 0)
    {
      /* Set non-blocking flag of socket fd */

      val |= ALTCOM_O_NONBLOCK;

      usock->out[ocnt++] = &usock->ret;
      usock->out[ocnt++] = &usock->errcode;

      ret = send_fctlreq(usock->altsock, cmd, val, usock->out, ocnt,
        reply->sock, handlereply_setfl, dev, reply);
      if (ret == 0)
        {
          usock->state = OPEN;
        }
    }
  else
    {
      /* rollback */

      usock->out[ocnt++] = &usock->ret;
      usock->out[ocnt++] = &usock->errcode;

      ret = send_closereq(usock->altsock, usock->out, ocnt, reply->sock, dev,
        reply);
      if (ret == 0)
        {
          usock->state = CLOSING;
        }
    }

  alt1250_printf("end\n");

  return ret;
}

/****************************************************************************
 * Name: handlereply_setfl
 ****************************************************************************/

static int handlereply_setfl(uint8_t event, unsigned long priv,
  FAR struct alt_container_s *reply, FAR struct usock_s *usock,
  FAR struct alt1250_s *dev)
{
  int ret = 0;
  struct usrsock_message_req_ack_s resp;
  int usockid;

  alt1250_printf("start, event:%u\n", event);

  ret = parse_sockcommon_reply(*(int *)(reply->outparam[0]),
    *(int *)(reply->outparam[1]));

  usockid = reply->sock;
  free_container(dev, reply);

  if (ret >= 0)
    {
      usock->state = OPENED;

      select_cancel(usockid, dev, NULL);
      select_start(usockid, dev, NULL);

      switch (usock->req.reqid)
        {
          case USRSOCK_REQUEST_SOCKET:

            /* Send ACK response */

            memset(&resp, 0, sizeof(resp));
            resp.result = usockid;
            _send_ack_common(dev->usockfd, usock->req.xid, &resp);
            break;

          case USRSOCK_REQUEST_CONNECT:
            ret = do_connectseq(usock, usockid, dev, NULL);
            break;

          case USRSOCK_REQUEST_BIND:
            ret = do_bindseq(usock, usockid, dev, NULL);
            break;

          case USRSOCK_REQUEST_LISTEN:
            ret = do_listenseq(usock, usockid, dev, NULL);
            break;

          case USRSOCK_REQUEST_SETSOCKOPT:
            ret = do_setsockoptseq(usock, usockid, dev, NULL);
            break;

          case USRSOCK_REQUEST_GETSOCKOPT:
            ret = do_getsockoptseq(usock, usockid, dev, NULL);
            break;

          case USRSOCK_REQUEST_GETSOCKNAME:
            ret = do_getsocknameseq(usock, usockid, dev, NULL);
            break;

          default:
            alt1250_printf("unexpected sequense. reqid:0x%02x\n",
              usock->req.reqid);

            ret = -EFAULT;
            break;
        }
    }

  if (ret < 0)
    {
      /* Send ACK response of the error. */

      memset(&resp, 0, sizeof(resp));
      resp.result = ret;
      _send_ack_common(dev->usockfd, usock->req.xid, &resp);
    }

  alt1250_printf("end\n");

  return ret;
}

/****************************************************************************
 * Name: handlereply_repnetinfo
 ****************************************************************************/

static int handlereply_repnetinfo(uint8_t event, unsigned long priv,
  FAR struct alt_container_s *reply, FAR struct usock_s *usock,
  FAR struct alt1250_s *dev)
{
  alt1250_printf("start, event:%u\n", event);

  /* It was opened temporarily so close it */

  alt1250_socket_free(dev, reply->sock);

  free_container(dev, reply);

  alt1250_printf("end\n");

  return 0;
}

/****************************************************************************
 * Name: handlereply_radioon
 ****************************************************************************/

static int handlereply_radioon(uint8_t event, unsigned long priv,
  FAR struct alt_container_s *reply, FAR struct usock_s *usock,
  FAR struct alt1250_s *dev)
{
  int ret = 0;
  size_t ocnt = 0;
  struct usrsock_message_req_ack_s resp;

  alt1250_printf("start, event:%u\n", event);

  ret = *(int *)(reply->outparam[0]);
  if (ret >= 0)
    {
      usock->out[ocnt++] = &usock->ret;
      usock->out[ocnt++] = &dev->o_pdn;

      ret = send_actpdnreq(&dev->apn, usock->out, ocnt, reply->sock, dev,
        reply);
    }
  else
    {
      free_container(dev, reply);
    }

  if (ret < 0)
    {
      /* Send ACK response of the error. */

      memset(&resp, 0, sizeof(resp));
      resp.result = ret;
      _send_ack_common(dev->usockfd, usock->req.xid, &resp);
    }

  alt1250_printf("end\n");

  return ret;
}

/****************************************************************************
 * Name: handlereply_radiooff
 ****************************************************************************/

static int handlereply_radiooff(uint8_t event, unsigned long priv,
  FAR struct alt_container_s *reply, FAR struct usock_s *usock,
  FAR struct alt1250_s *dev)
{
  int ret = 0;
  struct usrsock_message_req_ack_s resp;

  alt1250_printf("start, event:%u\n", event);

  dev->net_dev.d_flags = IFF_DOWN;
#ifdef CONFIG_NET_IPv4
  memset(&dev->net_dev.d_ipaddr, 0, sizeof(dev->net_dev.d_ipaddr));
#endif
#ifdef CONFIG_NET_IPv6
  memset(&dev->net_dev.d_ipv6addr, 0, sizeof(dev->net_dev.d_ipv6addr));
#endif

  ret = *(int *)(reply->outparam[0]);

  /* Send ACK response */

  memset(&resp, 0, sizeof(resp));
  resp.result = ret;

  _send_ack_common(dev->usockfd, usock->req.xid, &resp);

  free_container(dev, reply);

  alt1250_printf("end\n");

  return ret;
}

/****************************************************************************
 * Name: handlereply_actpdn
 ****************************************************************************/

static int handlereply_actpdn(uint8_t event, unsigned long priv,
  FAR struct alt_container_s *reply, FAR struct usock_s *usock,
  FAR struct alt1250_s *dev)
{
  int i;
  int ret = 0;
  struct usrsock_message_req_ack_s resp;
  FAR lte_pdn_t *pdn;

  alt1250_printf("start, event:%u\n", event);

  ret = *(int *)(reply->outparam[0]);
  if (ret == 0)
    {
      pdn = reply->outparam[1];

      dev->net_dev.d_flags = IFF_UP;

      for (i = 0; i < pdn->ipaddr_num; i++)
        {
#ifdef CONFIG_NET_IPv4
          if (LTE_IPTYPE_V4 == pdn->address[i].ip_type)
            {
              inet_pton(AF_INET,
                        (FAR const char *)pdn->address[i].address,
                        (FAR void *)&dev->net_dev.d_ipaddr);
            }
#endif

#ifdef CONFIG_NET_IPv6
          if (LTE_IPTYPE_V6 == pdn->address[i].ip_type)
            {
              inet_pton(AF_INET6,
                        (FAR const char *)pdn->address[i].address,
                        (FAR void *)&dev->net_dev.d_ipv6addr);
            }
#endif
        }
    }

  /* Send ACK response */

  memset(&resp, 0, sizeof(resp));
  resp.result = ret;

  _send_ack_common(dev->usockfd, usock->req.xid, &resp);

  free_container(dev, reply);

  alt1250_printf("end\n");

  return ret;
}

/****************************************************************************
 * Name: alt1250_request
 ****************************************************************************/

static int alt1250_request(int fd, FAR struct alt1250_s *dev)
{
  struct alt_readdata_s rdata;
  uint64_t bit = 0ULL;
  ssize_t size;
  FAR struct alt_container_s *container = NULL;
  FAR struct alt_container_s *next;
  int rcvcontainers = 0;
  int freecontainers = 0;
  int ret = OK;

  alt1250_printf("start\n");

  /* read event from alt1250 device */

  size = read(dev->altfd, &rdata, sizeof(rdata));
  ASSERT(size == sizeof(rdata));

  alt1250_printf("evtbitmap=0x%llx\n", rdata.evtbitmap);

  next = rdata.head;

  /* is modem reset happen? */

  if (rdata.evtbitmap & ALT1250_EVTBIT_RESET)
    {
      alt1250_printf("Reset event received\n");

      freecontainers = get_nfreecontainers(dev);

      alt1250_printf("Number of free containers: %d\n", freecontainers);

      dev->recvfrom_processing = false;
      dev->net_dev.d_flags = IFF_DOWN;
#ifdef CONFIG_NET_IPv4
      memset(&dev->net_dev.d_ipaddr, 0, sizeof(dev->net_dev.d_ipaddr));
#endif
#ifdef CONFIG_NET_IPv6
      memset(&dev->net_dev.d_ipv6addr, 0, sizeof(dev->net_dev.d_ipv6addr));
#endif

      while ((container = pick_containertop(&next)) != NULL)
        {
          rcvcontainers++;
          free_container(dev, container);
        }

      alt1250_printf("Number of containers read: %d\n", rcvcontainers);

      alt1250_clrevtcb(ALT1250_CLRMODE_WO_RESTART);
      alt1250_socket_allfree(dev);

      alt1250_printf("Number of containers read: %d free: %d\n",
        rcvcontainers, freecontainers);
      ASSERT(rcvcontainers + freecontainers == CONTAINER_MAX);

      /* Enable events to be notified when the network state changes. */

      enable_netinforeport(dev);

      ret = RET_MODEM_RESET;
    }
  else
    {
      /* is reply packet? */

      if (rdata.evtbitmap & ALT1250_EVTBIT_REPLY)
        {
          alt1250_printf("Reply packet received\n");

          while ((container = pick_containertop(&next)) != NULL)
            {
              alt1250_printf("Requested command ID: 0x%08lx\n",
                container->cmdid);

              if (is_synccmd(container->cmdid))
                {
                  /* The container will be free inside this function. */

                  handle_replypkt(fd, container, dev);
                }
              else
                {
                  /* Free for the end of the process. */

                  free_container(dev, container);
                }
            }

          rdata.evtbitmap &= ~ALT1250_EVTBIT_REPLY;
        }

      if (alt1250_checkcmdid(LTE_CMDID_SELECT, rdata.evtbitmap, &bit))
        {
          FAR struct alt_container_s *selectcontainer;

          /* container->outparam[0]: return code
           * container->outparam[1]: error code
           * container->outparam[2]: select id
           * container->outparam[3]: readset
           * container->outparam[4]: writeset
           * container->outparam[5]: exceptset
           */

          selectcontainer = exchange_selectcontainer(dev);
          ASSERT(selectcontainer);

          handle_selectevt(
            *((int32_t *)selectcontainer->outparam[0]),
            *((int32_t *)selectcontainer->outparam[1]),
            *((int32_t *)selectcontainer->outparam[2]),
            (altcom_fd_set *)(selectcontainer->outparam[3]),
            (altcom_fd_set *)(selectcontainer->outparam[4]),
            (altcom_fd_set *)(selectcontainer->outparam[5]),
            dev);

          rdata.evtbitmap &= ~bit;
        }
    }

  /* notice event to event task */

  if (rdata.evtbitmap)
    {
      evt_qsend(&dev->evtq, rdata.evtbitmap);
    }

  alt1250_printf("end\n");

  return ret;
}

#ifdef CONFIG_LTE_ALT1250_LAUNCH_EVENT_TASK

/****************************************************************************
 * Name: evttask
 ****************************************************************************/

static int evttask(int argc, FAR char *argv[])
{
  int ret;
  bool is_running = true;

  ret = lapi_evtinit("/lapievt");
  if (ret < 0)
    {
      alt1250_printf("lapi_evtinit() failed: %d\n", ret);
      goto errout;
    }

  while (is_running)
    {
      ret = lapi_evtyield(-1);
      if (ret == 0)
        {
          alt1250_printf("lapi_evtyield() finish normaly\n");
          is_running = false;
        }
      else if (ret < 0)
        {
          alt1250_printf("lapi_evtyield() failed: %d\n", ret);
        }
    }

errout:
  lapi_evtdestoy();

  return 0;
}

#endif

/****************************************************************************
 * Name: release_sync_wait
 ****************************************************************************/

static void release_sync_wait(sem_t *syncsem)
{
  if (syncsem)
    {
      /* Notify release to lapi waiting for synchronization */

      sem_post(syncsem);
    }
}

/****************************************************************************
 * Name: alt1250_loop
 ****************************************************************************/

static int alt1250_loop(FAR struct alt1250_s *dev)
{
  struct pollfd fds[2];
  int  ret = OK;
  bool is_running = true;
  bool is_usockrcvd = false;
  nfds_t nfds;
  static uint8_t buf[RBUFSZ];
  FAR struct usrsock_request_common_s *com_hdr;
#ifdef CONFIG_LTE_ALT1250_LAUNCH_EVENT_TASK
  int pid;
#endif

  netdev_register(&dev->net_dev, NET_LL_ETHERNET);

#ifdef CONFIG_LTE_ALT1250_LAUNCH_EVENT_TASK

  pid = task_create(EVTTASK_NAME, CONFIG_LTE_ALT1250_EVENT_TASK_PRIORITY,
    CONFIG_LTE_ALT1250_EVENT_TASK_STACKSIZE, evttask, NULL);
  if (pid < 0)
    {
      alt1250_printf("failed to create event task: %d\n", errno);
      release_sync_wait(dev->syncsem);
      goto errout;
    }
#endif

  dev->usockfd = open(DEV_USERSOCK, O_RDWR);
  if (dev->usockfd < 0)
    {
      alt1250_printf("open(%s) failed:%d\n", DEV_USERSOCK, errno);
      release_sync_wait(dev->syncsem);
      goto errout;
    }

  dev->altfd = open(DEV_ALT1250, O_RDONLY);
  if (dev->altfd < 0)
    {
      alt1250_printf("open(%s) failed:%d\n", DEV_ALT1250, errno);
      close(dev->usockfd);
      release_sync_wait(dev->syncsem);
      goto errout;
    }

  init_container(dev);
  init_selectcontainer(dev);

  ret = alt1250_setevtbuff(dev->altfd);
  if (ret < 0)
    {
      close(dev->usockfd);
      close(dev->altfd);
      release_sync_wait(dev->syncsem);
      goto errout;
    }

  /* is -s (sync) option enable? */

  release_sync_wait(dev->syncsem);

  while (is_running)
    {
      memset(fds, 0, sizeof(fds));

      /* Check events from alt1250 */

      fds[ALTFD].fd = dev->altfd;
      fds[ALTFD].events = POLLIN;
      nfds = 1;

      if (!is_usockrcvd && !dev->recvfrom_processing)
        {
          /* Check events from usersock */

          fds[USOCKFD].fd = dev->usockfd;
          fds[USOCKFD].events = POLLIN;
          nfds++;
        }

      ret = poll(fds, nfds, -1);
      ASSERT(ret > 0);

      if (fds[ALTFD].revents & POLLIN)
        {
          ret = alt1250_request(dev->usockfd, dev);
        }
      else
        {
          ret = OK;
        }

      if ((ret != RET_MODEM_RESET) && (!dev->recvfrom_processing)
          && ((fds[USOCKFD].revents & POLLIN) || is_usockrcvd))
        {
          if (!is_usockrcvd)
            {
              ret = read_usockreq(dev->usockfd, buf, RBUFSZ);
              ASSERT(ret >= 0);
            }

          com_hdr = (FAR struct usrsock_request_common_s *)buf;
          ret = handlers[com_hdr->reqid].fn(dev->usockfd, dev, buf);
          switch (ret)
            {
              case RET_TERM:
                is_running = false;
                break;

              case RET_NOTAVAIL:

                /* Since the request couldn't be processed,
                 * it will be carried over to next time.
                 * So keep the request.
                 */

                is_usockrcvd = true;
                break;

              default:
                is_usockrcvd = false;
                break;
            }
        }
    }

  close(dev->usockfd);

  if (evt_qsend(&dev->evtq, 0ULL) == OK)
    {
#ifdef CONFIG_LTE_ALT1250_LAUNCH_EVENT_TASK
      int stat;

      waitpid(pid, &stat, WEXITED);
#endif
    }

  alt1250_evtdestroy();

  close(dev->altfd);

errout:
  evt_qclose(&dev->evtq);

  netdev_unregister(&dev->net_dev);

  alt1250_printf("finished: ret=%d\n", ret);

  return ret;
}

/****************************************************************************
 * Public Functions
 ****************************************************************************/

int main(int argc, FAR char *argv[])
{
  int ret;
  FAR char *endptr;
  sem_t *syncsem = NULL;

  if (argc > 1)
    {
      /* The format is "-sXXXXXXXX".
       * XXXXXXXXX indicates the pointer address to the semaphore
       * that will be posted at the timing when the daemon opens the
       * usersock device.
       */

      if (!(strncmp(argv[1], SYNC_CMD_PREFIX, strlen(SYNC_CMD_PREFIX))))
        {
          syncsem = (FAR sem_t *)strtol(&argv[1][strlen(SYNC_CMD_PREFIX)],
            &endptr, HEX);
          if (!syncsem || endptr == &argv[1][strlen(SYNC_CMD_PREFIX)] ||
            *endptr != '\0')
            {
              return -EINVAL;
            }
        }
    }

  if (g_daemon)
    {
      fprintf(stderr, "%s is already running! \n", argv[0]);

      /* is -s (sync) option enable? */

      release_sync_wait(syncsem);

      return -1;
    }

  g_daemon = calloc(sizeof(struct alt1250_s), 1);
  ASSERT(g_daemon);

  g_daemon->syncsem = syncsem;
  g_daemon->evtq = (mqd_t)-1;
  g_daemon->sid = -1;

  ret = alt1250_loop(g_daemon);
  if (g_daemon)
    {
      free(g_daemon);
      g_daemon = NULL;
    }

  /* Notify lapi that Daemon has finished */

  release_sync_wait(syncsem);

  return ret;
}
