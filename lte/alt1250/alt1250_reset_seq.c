/****************************************************************************
 * apps/lte/alt1250/alt1250_reset_seq.c
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
#include "alt1250_devif.h"
#include "alt1250_devevent.h"
#include "alt1250_postproc.h"
#include "alt1250_container.h"
#include "alt1250_ioctl_subhdlr.h"
#include "alt1250_usrsock_hdlr.h"
#include "alt1250_reset_seq.h"

/****************************************************************************
 * Private Data Type
 ****************************************************************************/

struct reset_arg_s
{
  int seq_no;
  unsigned long arg;
};

/****************************************************************************
 * Private Data
 ****************************************************************************/

struct reset_arg_s reset_arg;

static postproc_hdlr_t ponreset_seq[] =
{
  postproc_fwgetversion,
};
#define PONRESET_SEQ_NUM  (sizeof(ponreset_seq) / sizeof(ponreset_seq[0]))

static int tmp_res;
static lte_version_t tmp_ver;
static void *tmp_verout[2] = { &tmp_res, &tmp_ver };

/****************************************************************************
 * Private Functions
 ****************************************************************************/

static int postproc_ponresetseq(FAR struct alt1250_s *dev,
  FAR struct alt_container_s *reply, FAR struct usock_s *usock,
  FAR int32_t *usock_result, FAR uint8_t *usock_xid,
  FAR struct usock_ackinfo_s *ackinfo, unsigned long arg)
{
  int ret = REP_NO_ACK_WOFREE;
  struct reset_arg_s *rarg = (struct reset_arg_s *)arg;
  ASSERT(rarg->seq_no < PONRESET_SEQ_NUM);

  ponreset_seq[rarg->seq_no](dev, reply, usock, usock_result, usock_xid,
                             ackinfo, rarg->arg);
  rarg->seq_no++;
  if (rarg->seq_no == PONRESET_SEQ_NUM)
    {
      /* On last postproc, container should be free */

      dev->recvfrom_processing = false;
      ret = REP_NO_ACK;
      MODEM_STATE_PON(dev);
    }

  return ret;
}

/****************************************************************************
 * name: send_getversion_onreset
 ****************************************************************************/

static int send_getversion_onreset(FAR struct alt1250_s *dev,
                                   FAR struct alt_container_s *container,
                                   FAR int32_t *usock_result)
{
  reset_arg.seq_no = 0;
  reset_arg.arg = 0;

  set_container_ids(container, -1, LTE_CMDID_GETVER);
  set_container_argument(container, NULL, 0);
  set_container_response(container, tmp_verout, 2);
  set_container_postproc(container, postproc_ponresetseq,
                         (unsigned long)&reset_arg);

  return altdevice_send_command(dev->altfd, container, usock_result);
}

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/****************************************************************************
 * name: handle_reset_sequence
 ****************************************************************************/

int handle_poweron_reset(FAR struct alt1250_s *dev)
{
  int ret;
  int32_t unused;

  FAR struct alt_container_s *container;

  container = container_alloc();
  ASSERT(container != 0);

  ret = send_getversion_onreset(dev, container, &unused);

  if (IS_NEED_CONTAINER_FREE(ret))
    {
      container_free(container);
    }

  if (ret > 0)
    {
      /* for blocking next usrsock request */

      dev->recvfrom_processing = true;
    }

  return ret;
}
