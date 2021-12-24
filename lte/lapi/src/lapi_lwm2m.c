/****************************************************************************
 * apps/lte/lapi/src/lapi_lwm2m.c
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

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <nuttx/wireless/lte/lte_ioctl.h>
#include <nuttx/wireless/lte/lte_lwm2m.h>

#include "lte/lapi.h"
#include "lte/lte_api.h"
#include "lapi_util.h"

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/****************************************************************************
 * Name: lte_commit_m2msetting
 ****************************************************************************/

int lte_commit_m2msetting(void)
{
  return lapi_req(LTE_CMDID_LWM2M_COMMIT_SETTING, NULL, 0, NULL, 0, NULL);
}

/****************************************************************************
 * Name: lte_set_report_m2mwrite
 ****************************************************************************/

int lte_set_report_m2mwrite(lwm2mstub_write_cb_t cb)
{
  return lapi_req(LTE_CMDID_LWM2M_WRITE_EVT, NULL, 0, NULL, 0, cb);
}

/****************************************************************************
 * Name: lte_set_report_m2mread
 ****************************************************************************/

int lte_set_report_m2mread(lwm2mstub_read_cb_t cb)
{
  return lapi_req(LTE_CMDID_LWM2M_READ_EVT, NULL, 0, NULL, 0, cb);
}

/****************************************************************************
 * Name: lte_set_report_m2mexec
 ****************************************************************************/

int lte_set_report_m2mexec(lwm2mstub_exec_cb_t cb)
{
  return lapi_req(LTE_CMDID_LWM2M_EXEC_EVT, NULL, 0, NULL, 0, cb);
}

/****************************************************************************
 * Name: lte_set_report_m2movstart
 ****************************************************************************/

int lte_set_report_m2movstart(lwm2mstub_ovstart_cb_t cb)
{
  return lapi_req(LTE_CMDID_LWM2M_OVSTART_EVT, NULL, 0, NULL, 0, cb);
}

/****************************************************************************
 * Name: lte_set_report_m2movstop
 ****************************************************************************/

int lte_set_report_m2movstop(lwm2mstub_ovstop_cb_t cb)
{
  return lapi_req(LTE_CMDID_LWM2M_OVSTOP_EVT, NULL, 0, NULL, 0, cb);
}

/****************************************************************************
 * Name: lte_set_report_m2mserverop
 ****************************************************************************/

int lte_set_report_m2mserverop(lwm2mstub_serverop_cb_t cb)
{
  return lapi_req(LTE_CMDID_LWM2M_SERVEROP_EVT, NULL, 0, NULL, 0, cb);
}

/****************************************************************************
 * Name: lte_set_report_m2mfwupdate
 ****************************************************************************/

int lte_set_report_m2mfwupdate(lwm2mstub_fwupstate_cb_t cb)
{
  return lapi_req(LTE_CMDID_LWM2M_FWUP_EVT, NULL, 0, NULL, 0, cb);
}
