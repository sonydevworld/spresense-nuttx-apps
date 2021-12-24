/****************************************************************************
 * apps/lte/alt1250/usock_handlers/alt1250_ioctl_normal.c
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
#include <nuttx/net/usrsock.h>

#include "alt1250_dbg.h"
#include "alt1250_container.h"
#include "alt1250_atcmd.h"
#include "alt1250_ioctl_subhdlr.h"
#include "alt1250_usrsock_hdlr.h"

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/****************************************************************************
 * name: lwm2m_initialize
 ****************************************************************************/

int send_m2mnotice_command(uint32_t cmdid,
                           FAR struct alt1250_s *dev,
                           FAR struct alt_container_s *container,
                           FAR struct usock_s *usock,
                           FAR struct lte_ioctl_data_s *ltecmd,
                           FAR int32_t *ures)
{
  int ret = REP_SEND_ACK;
  *ures = OK;

  switch(cmdid)
    {
      case LTE_CMDID_LWM2M_READ_EVT:
      case LTE_CMDID_LWM2M_WRITE_EVT:
      case LTE_CMDID_LWM2M_EXEC_EVT:
      case LTE_CMDID_LWM2M_OVSTART_EVT:
      case LTE_CMDID_LWM2M_OVSTOP_EVT:

        /* TODO: Now unregister any events makes all event notify stop.
         *       This will be fixed in near future.
         */

        ret = lwm2mstub_send_m2mobjcmd(dev, container, USOCKET_USOCKID(usock),
                                ures, (ltecmd->cb != NULL));
        break;

      case LTE_CMDID_LWM2M_SERVEROP_EVT:
        ret = lwm2mstub_send_m2mopev(dev, container, USOCKET_USOCKID(usock),
                                ures, (ltecmd->cb != NULL));
        break;

      case LTE_CMDID_LWM2M_FWUP_EVT:
        ret = lwm2mstub_send_m2mev(dev, container, USOCKET_USOCKID(usock),
                                ures, (ltecmd->cb != NULL));
        break;

      default:
        *ures = -EINVAL;
        break;
    }

  return ret;
}
