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
#include "alt1250_sms.h"

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

/* The maximum number of sockets that the ALT1250 modem can open. */

#define SOCKET_COUNT 5

#define _TX_BUFF_SIZE  (1500)
#define _RX_BUFF_SIZE  (1500)

#define ACCEPT_USOCK_REQUEST(dev) (!(dev)->is_usockrcvd && !(dev)->recvfrom_processing)
#define IS_USOCKREQ_RECEIVED(dev) ((dev)->is_usockrcvd)

#define MODEM_STATE(d)           ((d)->modem_state)
#define MODEM_STATE_POFF(d)      ((d)->modem_state = MODEM_POWER_OFF)
#define MODEM_STATE_PON(d)       ((d)->modem_state = MODEM_POWER_ON)
#define MODEM_STATE_B4PON(d)     ((d)->modem_state = MODEM_BEFORE_PON)
#define MODEM_STATE_B4PON_2ND(d) ((d)->modem_state = MODEM_BEFORE_PON_STAGE2)
#define MODEM_STATE_INTENTRST(d) ((d)->modem_state = MODEM_RST_INTENTIONAL)
#define MODEM_STATE_RON(d)       ((d)->modem_state = MODEM_RADIO_ON)
#define MODEM_STATE_IS_RON(d)    ((d)->modem_state == MODEM_RADIO_ON)
#define MODEM_STATE_IS_POFF(d)   ((d)->modem_state == MODEM_POWER_OFF)
#define MODEM_STATE_IS_PON(d)    ((d)->modem_state == MODEM_POWER_ON)

#define MODEM_FWVERSION(d)       ((d)->fw_version)

/****************************************************************************
 * Public Data Types
 ****************************************************************************/

enum alt1250_state_e
{
  MODEM_POWER_OFF = 0,
  MODEM_BEFORE_PON,
  MODEM_BEFORE_PON_STAGE2,
  MODEM_POWER_ON,
  MODEM_RST_INTENTIONAL,
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

  uint8_t tx_buff[_TX_BUFF_SIZE];
  uint8_t rx_buff[_RX_BUFF_SIZE];

  char fw_version[LTE_VER_NP_PACKAGE_LEN];
  struct update_info_s fwup_info;

  struct sms_info_s sms_info;
  bool is_support_lwm2m;
  int lwm2m_apply_xid;
};

#endif  /* __LTE_ALT1250_ALT1250_DAEMON_H__ */
