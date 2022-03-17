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
#include <unistd.h>

#include "alt1250_dbg.h"
#include "alt1250_container.h"
#include "alt1250_socket.h"
#include "alt1250_usockevent.h"
#include "alt1250_postproc.h"
#include "alt1250_devif.h"
#include "alt1250_evt.h"
#include "alt1250_util.h"
#include "alt1250_ioctl_subhdlr.h"
#include "alt1250_usrsock_hdlr.h"
#include "alt1250_netdev.h"

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

#define RADIOON_SYNC  (0)
#define RADIOON_ASYNC (1)

#define REPLY_RETCODE(rep, altrep) (((rep) == 0) ? (altrep) : (rep))

/* RK_02_01_01_10xxx FW version that does not support logging feature */

#define IS_LOG_UNAVAIL_FWVERSION(d) (!strncmp(MODEM_FWVERSION(d), \
                                              "RK_02_01_01", 11))

/****************************************************************************
 * Private Functions
 ****************************************************************************/

/****************************************************************************
 * name: postproc_reportnet
 ****************************************************************************/

static int postproc_reportnet(FAR struct alt1250_s *dev,
                              FAR struct alt_container_s *reply,
                              FAR struct usock_s *usock,
                              FAR int32_t *usock_result,
                              FAR uint8_t *usock_xid,
                              FAR struct usock_ackinfo_s *ackinfo,
                              unsigned long is_async)
{
  FAR void **resp = CONTAINER_RESPONSE(reply);
  int altcom_result = *((int *)(resp[0]));

  dbg_alt1250("%s start\n", __func__);

  *usock_result = REPLY_RETCODE(CONTAINER_RESPRES(reply), altcom_result);

  return (is_async) ? REP_NO_ACK: REP_SEND_ACK;
}

/****************************************************************************
 * name: postproc_radioon
 ****************************************************************************/

static int postproc_radioon(FAR struct alt1250_s *dev,
                            FAR struct alt_container_s *reply,
                            FAR struct usock_s *usock,
                            FAR int32_t *usock_result,
                            FAR uint8_t *usock_xid,
                            FAR struct usock_ackinfo_s *ackinfo,
                            unsigned long arg)
{
  int ret = REP_SEND_ACK;
  FAR void **resp = CONTAINER_RESPONSE(reply);
  int altcom_result = *((int *)(resp[0]));

  dbg_alt1250("%s start\n", __func__);

  *usock_result = REPLY_RETCODE(CONTAINER_RESPRES(reply), altcom_result);

  if (*usock_result == 0)
    {
      ret = send_reportnet_command(dev, reply, usock, postproc_reportnet,
                                   arg, usock_result);

      MODEM_STATE_RON(dev);
    }

  return ret;
}

/****************************************************************************
 * name: postproc_actpdn
 ****************************************************************************/

static int postproc_actpdn(FAR struct alt1250_s *dev,
                              FAR struct alt_container_s *reply,
                              FAR struct usock_s *usock,
                              FAR int32_t *usock_result,
                              FAR uint8_t *usock_xid,
                              FAR struct usock_ackinfo_s *ackinfo,
                              unsigned long is_async)
{
  FAR void **resp = CONTAINER_RESPONSE(reply);
  int altcom_result = *((int *)(resp[0]));
  FAR lte_pdn_t *pdn = resp[1];

  dbg_alt1250("%s start\n", __func__);

  *usock_result = REPLY_RETCODE(CONTAINER_RESPRES(reply), altcom_result);

  if (*usock_result == 0)
    {
      /* After connecting to the LTE network,
       * wait for the modem to register the network interface.
       */

      usleep(ALT1250_NETIF_READY_DELAY);
      alt1250_netdev_ifup(dev, pdn);
    }

  return (is_async) ? REP_NO_ACK: REP_SEND_ACK;
}

/****************************************************************************
 * name: postproc_fwgetversion
 ****************************************************************************/

int postproc_fwgetversion(FAR struct alt1250_s *dev,
                          FAR struct alt_container_s *reply,
                          FAR struct usock_s *usock,
                          FAR int32_t *usock_result,
                          FAR uint8_t *usock_xid,
                          FAR struct usock_ackinfo_s *ackinfo,
                          unsigned long arg)
{
  FAR void **resp = CONTAINER_RESPONSE(reply);
  int altcom_result = *((int *)(resp[0]));
  lte_version_t *version = (lte_version_t *)(resp[1]);

  dbg_alt1250("%s start\n", __func__);

  *usock_result = REPLY_RETCODE(CONTAINER_RESPRES(reply), altcom_result);

  if (*usock_result == 0)
    {
      /* Keep version information on the device context */

      strncpy(dev->fw_version, version->np_package, LTE_VER_NP_PACKAGE_LEN);
    }

  return usock ? REP_SEND_ACK : REP_NO_ACK;
}

/****************************************************************************
 * name: send_lapi_command
 ****************************************************************************/

int send_lapi_command(FAR struct alt1250_s *dev,
                      FAR struct alt_container_s *container,
                      FAR struct usock_s *usock,
                      FAR struct lte_ioctl_data_s *ltecmd,
                      FAR postproc_hdlr_t hdlr,
                      unsigned long priv,
                      FAR int32_t *usock_result)
{
  set_container_ids(container, USOCKET_USOCKID(usock), ltecmd->cmdid);
  set_container_argument(container, ltecmd->inparam, ltecmd->inparamlen);
  set_container_response(container, ltecmd->outparam, ltecmd->outparamlen);
  set_container_postproc(container, hdlr, priv);

  return altdevice_send_command(dev->altfd, container, usock_result);
}

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/****************************************************************************
 * name: usockreq_ioctl_normal
 ****************************************************************************/

int usockreq_ioctl_normal(FAR struct alt1250_s *dev,
                              FAR struct usrsock_request_buff_s *req,
                              FAR int32_t *usock_result,
                              FAR uint8_t *usock_xid,
                              FAR struct usock_ackinfo_s *ackinfo)
{
  FAR struct usrsock_request_ioctl_s *request = &req->request.ioctl_req;
  FAR struct lte_ioctl_data_s *ltecmd = &req->req_ioctl.ltecmd;
  FAR struct usock_s *usock = NULL;
  int ret = REP_SEND_ACK_WOFREE;
  uint32_t cmdid = LTE_PURE_CMDID(ltecmd->cmdid);
  FAR struct alt_container_s *container;
  postproc_hdlr_t postproc_hdlr = NULL;
  unsigned long priv = 0;

  dbg_alt1250("%s start\n", __func__);

  *usock_result = OK;
  *usock_xid = request->head.xid;

  usock = usocket_search(dev, request->usockid);
  if (usock == NULL)
    {
      dbg_alt1250("Failed to get socket context: %u\n",
                     request->usockid);
      *usock_result = -EBADFD;
      return REP_SEND_ACK_WOFREE;
    }

  container = container_alloc();
  if (container == NULL)
    {
      dbg_alt1250("no container\n");
      return REP_NO_CONTAINER;
    }

  if (LTE_IS_ASYNC_CMD(ltecmd->cmdid) && (ltecmd->cb != NULL))
    {
      ret = alt1250_regevtcb(cmdid, ltecmd->cb);
      if (ret < 0)
        {
          container_free(container);
          *usock_result = ret;
          return REP_SEND_ACK_WOFREE;
        }

      ltecmd->outparam = alt1250_getevtarg(cmdid);

      /* The outparam is a array of "*void".
       * In asynchronouse API case, the array size is known
       * by container in the alt1250 driver.
       * So don't need to set the outparamlen here.
       */
    }

  switch (cmdid)
    {
      case LTE_CMDID_ACTPDN:
        {
          alt1250_saveapn(dev, (FAR lte_apn_setting_t *)ltecmd->inparam[0]);

          /* The handler is set for post process */

          postproc_hdlr = postproc_actpdn;
          priv = LTE_IS_ASYNC_CMD(ltecmd->cmdid);
        }
        break;

      case LTE_CMDID_TLS_SSL_BIO:
        {
          /* Override socket id on input parameter from usock file descriptor
           * to alt1250 device's socket descriptor
           */

          *(FAR int *)(ltecmd->inparam[5]) = USOCKET_ALTSOCKID(usock);
        }
        break;

      case LTE_CMDID_GETVER:
        {
          /* The handler is set for post process,
           * but it will be avoided when the command is asynchronouse.
           */

          postproc_hdlr = postproc_fwgetversion;
        }
        break;

      case LTE_CMDID_RADIOON:
        {
          /* The handler is set for post process */

          postproc_hdlr = postproc_radioon;
          priv = LTE_IS_ASYNC_CMD(ltecmd->cmdid) ?
                   RADIOON_ASYNC : RADIOON_SYNC;
        }
        break;

      case LTE_CMDID_SAVE_LOG:
      case LTE_CMDID_GET_LOGLIST:
      case LTE_CMDID_LOGOPEN:
      case LTE_CMDID_LOGCLOSE:
      case LTE_CMDID_LOGREAD:
      case LTE_CMDID_LOGLSEEK:
      case LTE_CMDID_LOGREMOVE:
        {
          if (IS_LOG_UNAVAIL_FWVERSION(dev))
            {
              container_free(container);
              *usock_result = -ENOTSUP;
              return REP_SEND_ACK_WOFREE;
            }
        }
        break;

      case LTE_CMDID_RADIOOFF:
        {
          MODEM_STATE_PON(dev);
        }

      default:
        break;
    }

  USOCKET_SET_REQUEST(usock, request->head.reqid, request->head.xid);
  ret = send_lapi_command(dev, container, usock, ltecmd, postproc_hdlr, priv,
                          usock_result);

  if (IS_NEED_CONTAINER_FREE(ret))
    {
      container_free(container);
    }

  if (*usock_result < 0)
    {
      /* In error case, clear callback */

      if (LTE_IS_ASYNC_CMD(ltecmd->cmdid) && (ltecmd->cb != NULL))
        {
          alt1250_regevtcb(cmdid, NULL);
        }
    }
  else if ((ltecmd->cmdid == LTE_CMDID_ACTPDN) ||
           (cmdid == LTE_CMDID_TLS_SSL_HANDSHAKE))
    {
      /* The request from usersock cannot be accepted until the
       * response is returned, so the REP_SEND_INPROG is returned
       * to delay usock response and make this daemon to be able
       * to handle other requests.
       */

      ret = REP_SEND_INPROG;
    }
  else if (LTE_IS_ASYNC_CMD(ltecmd->cmdid))
    {
      ret = REP_SEND_ACK_WOFREE;
    }

  return ret;
}
