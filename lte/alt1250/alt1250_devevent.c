/****************************************************************************
 * apps/lte/alt1250/alt1250_devevent.c
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
#include <assert.h>

#include "alt1250_dbg.h"
#include "alt1250_evt.h"
#include "alt1250_devif.h"
#include "alt1250_devevent.h"
#include "alt1250_postproc.h"
#include "alt1250_container.h"
#include "alt1250_usockif.h"
#include "alt1250_usockevent.h"
#include "alt1250_socket.h"
#include "alt1250_usrsock_hdlr.h"
#include "alt1250_select.h"
#include "alt1250_sms.h"
#include "alt1250_netdev.h"
#include "alt1250_reset_seq.h"

/****************************************************************************
 * Private Functions
 ****************************************************************************/

/****************************************************************************
 * Name: handle_replypkt
 ****************************************************************************/

static int handle_replypkt(FAR struct alt1250_s *dev,
  FAR struct alt_container_s *reply,
  FAR int32_t *usock_result, uint8_t *usock_xid,
  FAR struct usock_ackinfo_s *ackinfo)
{
  int ret;
  FAR struct usock_s *usock;
  FAR struct postproc_s *pp = CONTAINER_POSTPROC(reply);

  usock = usocket_search(dev, CONTAINER_SOCKETID(reply));

  dbg_alt1250("reply->result: %d\n", CONTAINER_RESPRES(reply));

  *usock_result = CONTAINER_RESPRES(reply);
  *usock_xid = usock ? USOCKET_XID(usock) : -1;
  ret = usock ? REP_SEND_ACK : REP_NO_ACK;

  if (pp && pp->hdlr)
    {
      ret = pp->hdlr(dev, reply, usock, usock_result, usock_xid, ackinfo,
                     pp->priv);
    }

  return ret;
}

/****************************************************************************
 * Name: perform_alt1250_reply
 ****************************************************************************/

static int perform_alt1250_reply(FAR struct alt1250_s *dev,
    FAR struct alt_container_s *container)
{
  int ret = REP_NO_ACK;
  int32_t ack_result = OK;
  uint8_t ack_xid = 0;
  struct usock_ackinfo_s ackinfo;

  ret = handle_replypkt(dev, container, &ack_result, &ack_xid, &ackinfo);

  if (LTE_IS_ASYNC_CMD(container->cmdid))
    {
      ret = REP_NO_ACK;
    }

  usock_reply(dev->usockfd, ret, ack_result, ack_xid, &ackinfo);

  return ret;
}

/****************************************************************************
 * Name: handle_normal_reset
 ****************************************************************************/

static int handle_normal_reset(FAR struct alt1250_s *dev)
{
  alt1250_clrevtcb(ALT1250_CLRMODE_WO_RESTART);

  dev->recvfrom_processing = false;
  dev->lwm2m_apply_xid = -1;

  alt1250_netdev_ifdown(dev);

  usocket_freeall(dev);

  reset_fwupdate_info(dev);
  alt1250_reset_sms_info(dev);
  reset_usock_device(dev->usockfd);

  return REP_MODEM_RESET;
}

/****************************************************************************
 * name: handle_intentional_reset
 ****************************************************************************/

static int handle_intentional_reset(FAR struct alt1250_s *dev)
{
  if (dev->lwm2m_apply_xid >= 0)
    {
      usockif_sendack(dev->usockfd, 0, (uint8_t)dev->lwm2m_apply_xid, false);
      dev->lwm2m_apply_xid = -1;
    }

  alt1250_clrevtcb(ALT1250_CLRMODE_WO_RESTART);
  dev->recvfrom_processing = false;
  alt1250_netdev_ifdown(dev);
  usocket_freeall(dev);
  alt1250_reset_sms_info(dev);
  reset_usock_device(dev->usockfd);

  MODEM_STATE_PON(dev);

  return REP_NO_ACK;
}

/****************************************************************************
 * Name: perform_alt1250_resetevt
 ****************************************************************************/

static int perform_alt1250_resetevt(FAR struct alt1250_s *dev,
                                    FAR struct alt_container_s *rlist)
{
  int ret;

  container_free_all(rlist);

  dev->sid = -1;

  switch (MODEM_STATE(dev))
    {
      case MODEM_BEFORE_PON:
        ret = handle_poweron_reset(dev);
        break;

      case MODEM_BEFORE_PON_STAGE2:
        ret = handle_poweron_reset_stage2(dev);
        break;

      case MODEM_RST_INTENTIONAL:
        ret = handle_intentional_reset(dev);
        break;

      default:
        ret = handle_normal_reset(dev);
        break;
    }

  return ret;
}

/****************************************************************************
 * Public functions
 ****************************************************************************/

/****************************************************************************
 * Name: perform_alt1250events
 ****************************************************************************/

int perform_alt1250events(FAR struct alt1250_s *dev)
{
  int ret = OK;
  uint64_t bitmap;
  uint64_t select_bit;
  uint64_t smsreport_bit;
  FAR struct alt_container_s *reply_list;
  FAR struct alt_container_s *container;

  ret = altdevice_getevent(dev->altfd, &bitmap, &reply_list);
  ASSERT(ret == OK);

  if (bitmap & ALT1250_EVTBIT_RESET)
    {
      /* Handling reset event */

      ret = perform_alt1250_resetevt(dev, reply_list);
      if (ret != REP_MODEM_RESET)
        {
          /* No need to send reset event to application
           * in case of intentional reset
           */

          bitmap &= ~ALT1250_EVTBIT_RESET;
        }
    }
  else
    {
      /* Handling reply containers */

      if (bitmap & ALT1250_EVTBIT_REPLY)
        {
          while ((container = container_pick_listtop(&reply_list)) != NULL)
            {
              ret = perform_alt1250_reply(dev, container);
              if (IS_NEED_CONTAINER_FREE(ret))
                {
                  container_free(container);
                }
            }

          bitmap &= ~ALT1250_EVTBIT_REPLY;
        }

      /* Handling select async event */

      if ((select_bit = perform_select_event(dev, bitmap)) != 0ULL)
        {
          bitmap &= ~select_bit;
        }

      /* Handling sms report event */

      if ((smsreport_bit = perform_sms_report_event(dev, bitmap)) != 0ULL)
        {
          bitmap &= ~smsreport_bit;
        }
    }

  if (bitmap)
    {
      alt1250_evttask_sendmsg(dev, bitmap);
    }

  return ret;
}
