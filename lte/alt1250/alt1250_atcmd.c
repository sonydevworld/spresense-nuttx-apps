/****************************************************************************
 * apps/lte/alt1250/alt1250_atcmd.c
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

#include <stdio.h>
#include <string.h>

#include "alt1250_dbg.h"
#include "alt1250_daemon.h"
#include "alt1250_atcmd.h"
#include "alt1250_devif.h"
#include "alt1250_postproc.h"
#include "alt1250_container.h"
#include "alt1250_usockevent.h"

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

/****************************************************************************
 * Private Data Type
 ****************************************************************************/

struct atcmd_postprocarg_t
{
  atcmd_postproc_t proc;
  unsigned long arg;
};

/****************************************************************************
 * Private Data
 ****************************************************************************/

static void *atcmd_oargs[3];
static int atcmd_reply_len;
static struct atcmd_postprocarg_t postproc_argument;

/****************************************************************************
 * Private Functions
 ****************************************************************************/

static int atcmdreply_ok_error(FAR struct alt_container_s *reply,
                                FAR char *rdata, int len, unsigned long arg,
                                FAR int32_t *usock_result)
{
  *usock_result = check_atreply_ok(rdata, len, NULL);
  return REP_SEND_ACK;
}

static int postproc_internal_atcmd(FAR struct alt1250_s *dev,
                                   FAR struct alt_container_s *reply,
                                   FAR struct usock_s *usock,
                                   FAR int32_t *usock_result,
                                   FAR uint8_t *usock_xid,
                                   FAR struct usock_ackinfo_s *ackinfo,
                                   unsigned long arg)
{
  int ret = REP_NO_ACK;
  struct atcmd_postprocarg_t *parg = (struct atcmd_postprocarg_t *)arg;

  if (parg->proc != NULL)
    {
      ret = parg->proc(reply,
        (FAR char *)reply->outparam[0], *(int *)reply->outparam[2],
        parg->arg, usock_result);
    }

  return ret;
}

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/****************************************************************************
 * name: send_internal_at_command
 ****************************************************************************/

int send_internal_at_command(FAR struct alt1250_s *dev,
      FAR struct alt_container_s *container, int16_t usockid,
      atcmd_postproc_t proc, unsigned long arg, FAR int32_t *usock_result)
{
  FAR void *inparam[2];

  inparam[0] = dev->tx_buff;
  inparam[1] = (void *)strlen((const char *)dev->tx_buff);

  atcmd_oargs[0] = dev->rx_buff;
  atcmd_oargs[1] = (void *)_RX_BUFF_SIZE;
  atcmd_oargs[2] = &atcmd_reply_len;

  postproc_argument.proc = proc;
  postproc_argument.arg = arg;

  set_container_ids(container, usockid, LTE_CMDID_SENDATCMD);
  set_container_argument(container, inparam, ARRAY_SZ(inparam));
  set_container_response(container, atcmd_oargs, ARRAY_SZ(atcmd_oargs));
  set_container_postproc(container, postproc_internal_atcmd,
                                    (unsigned long)&postproc_argument);

  return altdevice_send_command(dev->altfd, container, usock_result);
}

/****************************************************************************
 * name: check_atreply_ok
 ****************************************************************************/

int check_atreply_ok(FAR char *reply, int len, void *arg)
{
  int ret = ERROR;

  if (strstr(reply, "\nOK\r"))
    {
      ret = OK;
    }

  return ret;
}

/****************************************************************************
 * name: check_atreply_truefalse
 ****************************************************************************/

int check_atreply_truefalse(FAR char *reply, int len, void *arg)
{
  int ret = ERROR;
  struct atreply_truefalse_s *result = (struct atreply_truefalse_s *)arg;

  if (check_atreply_ok(reply, len, NULL) == OK)
    {
      ret = OK;
      if (strstr(reply, result->target_str))
        {
          result->result = true;
        }
      else
        {
          result->result = false;
        }
    }

  return ret;
}

/****************************************************************************
 * name: lwm2mstub_send_reset
 ****************************************************************************/

int lwm2mstub_send_reset(FAR struct alt1250_s *dev,
      FAR struct alt_container_s *container)
{
  int32_t dummy;
  snprintf((char *)dev->tx_buff, _TX_BUFF_SIZE, "ATZ\r");
  return send_internal_at_command(dev, container, -1, NULL, 0, &dummy);
}

/****************************************************************************
 * name: lwm2mstub_send_setenable
 ****************************************************************************/

int lwm2mstub_send_setenable(FAR struct alt1250_s *dev,
      FAR struct alt_container_s *container, bool en)
{
  int32_t dummy;
  snprintf((char *)dev->tx_buff, _TX_BUFF_SIZE,
      "AT%%SETACFG=modem_apps.LWM2M.AppEnable,\"%s\"\r",
                                      en ? "true" : "false");
  return send_internal_at_command(dev, container, -1, NULL, 0, &dummy);
}

/****************************************************************************
 * name: lwm2mstub_send_getenable
 ****************************************************************************/

int lwm2mstub_send_getenable(FAR struct alt1250_s *dev,
      FAR struct alt_container_s *container, FAR int32_t *usock_result)
{
  snprintf((char *)dev->tx_buff, _TX_BUFF_SIZE,
      "AT%%GETACFG=modem_apps.LWM2M.AppEnable\r");
  return send_internal_at_command(dev, container, -1, NULL, 0, usock_result);
}

/****************************************************************************
 * name: lwm2mstub_send_getnamemode
 ****************************************************************************/

int lwm2mstub_send_getnamemode(FAR struct alt1250_s *dev,
      FAR struct alt_container_s *container)
{
  int32_t dummy;
  snprintf((char *)dev->tx_buff, _TX_BUFF_SIZE,
      "AT%%GETACFG=LWM2M.Config.NameMode\r");
  return send_internal_at_command(dev, container, -1, NULL, 0, &dummy);
}

/****************************************************************************
 * name: lwm2mstub_send_setnamemode
 ****************************************************************************/

int lwm2mstub_send_setnamemode(FAR struct alt1250_s *dev,
      FAR struct alt_container_s *container, int mode)
{
  int32_t dummy;
  snprintf((char *)dev->tx_buff, _TX_BUFF_SIZE,
      "AT%%SETACFG=LWM2M.Config.NameMode,%d\r", mode);
  return send_internal_at_command(dev, container, -1, NULL, 0, &dummy);
}

/****************************************************************************
 * name: lwm2mstub_send_getversion
 ****************************************************************************/

int lwm2mstub_send_getversion(FAR struct alt1250_s *dev,
      FAR struct alt_container_s *container)
{
  int32_t dummy;
  snprintf((char *)dev->tx_buff, _TX_BUFF_SIZE,
      "AT%%GETACFG=LWM2M.Config.Version\r");
  return send_internal_at_command(dev, container, -1, NULL, 0, &dummy);
}

/****************************************************************************
 * name: lwm2mstub_send_setversion
 ****************************************************************************/

int lwm2mstub_send_setversion(FAR struct alt1250_s *dev,
      FAR struct alt_container_s *container, bool is_v1_1)
{
  int32_t dummy;
  snprintf((char *)dev->tx_buff, _TX_BUFF_SIZE,
      "AT%%SETACFG=LWM2M.Config.Version,\"%s\"\r", is_v1_1 ? "1.1" : "1.0");
  return send_internal_at_command(dev, container, -1, NULL, 0, &dummy);
}

/****************************************************************************
 * name: lwm2mstub_send_getwriteattr
 ****************************************************************************/

int lwm2mstub_send_getwriteattr(FAR struct alt1250_s *dev,
      FAR struct alt_container_s *container)
{
  int32_t dummy;
  snprintf((char *)dev->tx_buff, _TX_BUFF_SIZE,
      "AT%%GETACFG=LWM2M.HostObjects.HostEnableWriteAttrURCMode\r");
  return send_internal_at_command(dev, container, -1, NULL, 0, &dummy);
}

/****************************************************************************
 * name: lwm2mstub_send_setwriteattr
 ****************************************************************************/

int lwm2mstub_send_setwriteattr(FAR struct alt1250_s *dev,
      FAR struct alt_container_s *container, bool en)
{
  int32_t dummy;
  snprintf((char *)dev->tx_buff, _TX_BUFF_SIZE,
      "AT%%SETACFG=LWM2M.HostObjects.HostEnableWriteAttrURCMode,\"%s\"\r",
                            en ? "true" : "false");
  return send_internal_at_command(dev, container, -1, NULL, 0, &dummy);
}

/****************************************************************************
 * name: lwm2mstub_send_getautoconnect
 ****************************************************************************/

int lwm2mstub_send_getautoconnect(FAR struct alt1250_s *dev,
      FAR struct alt_container_s *container)
{
  int32_t dummy;
  snprintf((char *)dev->tx_buff, _TX_BUFF_SIZE,
      "AT%%GETACFG=LWM2M.Config.AutoConnect\r");
  return send_internal_at_command(dev, container, -1, NULL, 0, &dummy);
}

/****************************************************************************
 * name: lwm2mstub_send_setautoconnect
 ****************************************************************************/

int lwm2mstub_send_setautoconnect(FAR struct alt1250_s *dev,
      FAR struct alt_container_s *container, bool en)
{
  int32_t dummy;
  snprintf((char *)dev->tx_buff, _TX_BUFF_SIZE,
      "AT%%SETACFG=LWM2M.Config.AutoConnect,\"%s\"\r",
                            en ? "true" : "false");
  return send_internal_at_command(dev, container, -1, NULL, 0, &dummy);
}

int lwm2mstub_send_m2mopev(FAR struct alt1250_s *dev,
      FAR struct alt_container_s *container, int16_t usockid,
      FAR int32_t *ures, bool en)
{
  snprintf((char *)dev->tx_buff, _TX_BUFF_SIZE,
    "AT%%LWM2MOPEV=%c,100\r", en ? '1' : '0');
  return send_internal_at_command(dev, container, usockid,
                                  atcmdreply_ok_error, 0, ures);
}

int lwm2mstub_send_m2mev(FAR struct alt1250_s *dev,
      FAR struct alt_container_s *container, int16_t usockid,
      FAR int32_t *ures, bool en)
{
  snprintf((char *)dev->tx_buff, _TX_BUFF_SIZE,
    "AT%%LWM2MEV=%c\r", en ? '1' : '0');
  return send_internal_at_command(dev, container, usockid,
                                  atcmdreply_ok_error, 0, ures);
}

int lwm2mstub_send_m2mobjcmd(FAR struct alt1250_s *dev,
      FAR struct alt_container_s *container, int16_t usockid,
      FAR int32_t *ures, bool en)
{
  snprintf((char *)dev->tx_buff, _TX_BUFF_SIZE,
    "AT%%LWM2MOBJCMD=%c\r", en ? '1' : '0');
  return send_internal_at_command(dev, container, usockid,
                                  atcmdreply_ok_error, 0, ures);
}
