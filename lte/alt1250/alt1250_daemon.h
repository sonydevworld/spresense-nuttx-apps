/****************************************************************************
 * apps/lte/alt1250/alt1250_daemon.h
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

#ifndef __LTE_ALT1250_ALT1250_DAEMON_H__
#define __LTE_ALT1250_ALT1250_DAEMON_H__

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <nuttx/config.h>

#include <stdint.h>
#include <stdbool.h>
#include <queue.h>
#include <mqueue.h>
#include <semaphore.h>
#include <string.h>

#include <nuttx/net/netdev.h>
#include <nuttx/wireless/lte/lte.h>
#include <nuttx/modem/alt1250.h>

#include "alt1250_socket.h"
#include "alt1250_usockif.h"
#include "alt1250_util.h"
#include "alt1250_fwupdate.h"

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

#if defined(CONFIG_NET_USRSOCK_CONNS)
#  if (CONFIG_NET_USRSOCK_CONNS > ALTCOM_NSOCKET)
#    define SOCKET_COUNT ALTCOM_NSOCKET
#  else
#    define SOCKET_COUNT CONFIG_NET_USRSOCK_CONNS
#  endif
#else
#  define SOCKET_COUNT ALTCOM_NSOCKET
#endif

#define ACCEPT_USOCK_REQUEST(dev) (!(dev)->is_usockrcvd && !(dev)->recvfrom_processing)
#define IS_USOCKREQ_RECEIVED(dev) ((dev)->is_usockrcvd)

#define MODEM_STATE(d)         ((d)->modem_state)
#define MODEM_STATE_POFF(d)    ((d)->modem_state = MODEM_POWER_OFF)
#define MODEM_STATE_PON(d)     ((d)->modem_state = MODEM_POWER_ON)
#define MODEM_STATE_B4PON(d)   ((d)->modem_state = MODEM_BEFORE_POWER_ON)
#define MODEM_STATE_RON(d)     ((d)->modem_state = MODEM_RADIO_ON)
#define MODEM_STATE_IS_RON(d)  ((d)->modem_state == MODEM_RADIO_ON)
#define MODEM_STATE_IS_POFF(d) ((d)->modem_state == MODEM_POWER_OFF)

#define OLD_FWVERSION "RK02_01_01_10_41_15"
#define IS_OLD_FWVERSION(d) (!strncmp(&((d)->fw_version), OLD_FWVERSION, 20))

/****************************************************************************
 * Public Data Types
 ****************************************************************************/

enum alt1250_state_e
{
  MODEM_POWER_OFF = 0,
  MODEM_BEFORE_POWER_ON,
  MODEM_POWER_ON,
  MODEM_RADIO_ON,
};

struct usrsock_request_buff_s;

struct alt1250_s
{
  int usockfd;
  int altfd;
  int usock_enable;

  int32_t scnt;
  int32_t sid;        /* Select ID requested to Alt1250 module.
                       * Negative value indicats no select request */
  FAR sem_t *syncsem; /* Semaphore to synchronize LAPI Caller */
  mqd_t evtq;         /* Event queue to communicate "Callback task" */
  struct net_driver_s net_dev;

  enum alt1250_state_e modem_state;

  lte_apn_setting_t apn;
  char apn_name[LTE_APN_LEN];
  char user_name[LTE_APN_USER_NAME_LEN];
  char pass[LTE_APN_PASSWD_LEN];
  lte_pdn_t o_pdn;

  struct usock_s sockets[SOCKET_COUNT];

  struct usrsock_request_buff_s usockreq;
  bool is_usockrcvd;  /* A flag indicates that daemon has already read
                       * usrsock request */
  bool recvfrom_processing;

  char fw_version[LTE_VER_NP_PACKAGE_LEN];
  struct update_info_s fwup_info;
};

#endif  /* __LTE_ALT1250_ALT1250_DAEMON_H__ */
