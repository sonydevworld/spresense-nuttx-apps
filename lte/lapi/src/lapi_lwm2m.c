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

#include "lte/lapi.h"
#include "lte/lte_api.h"
#include "lte/lte_lwm2m.h"
#include "lapi_util.h"

/****************************************************************************
 * Private Functions
 ****************************************************************************/

/****************************************************************************
 * Name: check_instance
 ****************************************************************************/

static int check_instance(FAR struct lwm2mstub_instance_s *inst)
{
  int ret = OK;

  if (inst->object_id < 0 || inst->object_inst < 0 || inst->res_id < 0)
    {
      ret = ERROR;
    }

  return ret;
}

/****************************************************************************
 * Name: insert_sort
 ****************************************************************************/

static void insert_sort(uint16_t *array, int sz)
{
  int i;
  int j;
  uint16_t tmp;

  for (i = 1; i < sz; i++)
    {
      j = i;
      while (j > 0 && array[j - 1] > array[j])
        {
          tmp = array[j - 1];
          array[j - 1] = array[j];
          array[j] = tmp;
          j--;
        }
    }
}

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/****************************************************************************
 * Name: lte_m2m_connection
 ****************************************************************************/

int lte_m2m_connection(int cmd)
{
  if (cmd < LWM2MSTUB_CONNECT_REGISTER || cmd > LWM2MSTUB_CONNECT_BOOTSTRAP)
    {
      return -EINVAL;
    }

  return lapi_req(LTE_CMDID_LWM2M_CONNECT, (void **)cmd, 1, NULL, 0, NULL);
}

/****************************************************************************
 * Name: lte_m2m_readresponse
 ****************************************************************************/

int lte_m2m_readresponse(int seq_no, FAR struct lwm2mstub_instance_s *inst,
                         int resp, char *readvalue, int len)
{
  FAR void *inarg[5] = {
    (void *)seq_no, (void *)resp, inst, readvalue, (void *)len
  };

  if (!inst || !readvalue || len <= 0 || check_instance(inst) != OK)
    {
      return -EINVAL;
    }

  return lapi_req(LTE_CMDID_LWM2M_READRESP,
                  (void *)&inarg, 5, NULL, 0, NULL);
}

/****************************************************************************
 * Name: lte_m2m_writeresponse
 ****************************************************************************/

int lte_m2m_writeresponse(int seq_no, FAR struct lwm2mstub_instance_s *inst,
                          int resp)
{
  FAR void *inarg[3] = {
    (void *)seq_no, (void *)resp, inst
  };

  if (!inst || check_instance(inst) != OK)
    {
      return -EINVAL;
    }

  return lapi_req(LTE_CMDID_LWM2M_WRITERESP,
                  (void *)&inarg, 3, NULL, 0, NULL);
}

/****************************************************************************
 * Name: lte_m2m_executeresp
 ****************************************************************************/

int lte_m2m_executeresp(int seq_no, FAR struct lwm2mstub_instance_s *inst,
                          int resp)
{
  FAR void *inarg[3] = {
    (void *)seq_no, (void *)resp, inst
  };

  if (!inst || check_instance(inst) != OK)
    {
      return -EINVAL;
    }

  return lapi_req(LTE_CMDID_LWM2M_EXECRESP,
                  (void *)&inarg, 3, NULL, 0, NULL);
}

/****************************************************************************
 * Name: lte_m2m_observeresp
 ****************************************************************************/

int lte_m2m_observeresp(int seq_no, int resp)
{
  FAR void *inarg[2] = {
    (void *)seq_no, (void *)resp
  };

  return lapi_req(LTE_CMDID_LWM2M_OBSERVERESP,
                  (void *)&inarg, 2, NULL, 0, NULL);
}

/****************************************************************************
 * Name: lte_m2m_observeupdate
 ****************************************************************************/

int lte_m2m_observeupdate(char *token,
                          FAR struct lwm2mstub_instance_s *inst,
                          char *value, int len)
{
  FAR void *inarg[4] = {
    token, inst, value, (void *)len
  };

  if (!token || !inst || !value || len <= 0)
    {
      return -EINVAL;
    }

  return lapi_req(LTE_CMDID_LWM2M_OBSERVEUPDATE,
                  (void *)&inarg, 4, NULL, 0, NULL);
}

/****************************************************************************
 * Name: lte_setm2m_endpointname
 ****************************************************************************/

int lte_setm2m_endpointname(FAR char *name)
{
  return lapi_req(LTE_CMDID_LWM2M_SETEP, (void **)name, 1, NULL, 0, NULL);
}

/****************************************************************************
 * Name: lte_getm2m_endpointname
 ****************************************************************************/

int lte_getm2m_endpointname(FAR char *name, int len)
{
  FAR void *outarg[2] = {
    name, (void *)len
  };

  if (!name || len <= 0)
    {
      return -EINVAL;
    }

  return lapi_req(LTE_CMDID_LWM2M_GETEP, NULL, 0, (void *)&outarg, 2, NULL);
}

/****************************************************************************
 * Name: lte_getm2m_servernum
 ****************************************************************************/

int lte_getm2m_servernum(void)
{
  int dummy_arg; /* Dummy for blocking API call */
  return lapi_req(LTE_CMDID_LWM2M_GETSRVNUM, NULL, 0,
                           (FAR void **)&dummy_arg, 0, NULL);
}

/****************************************************************************
 * Name: lte_setm2m_servernum
 ****************************************************************************/

int lte_setm2m_serverinfo(FAR struct lwm2mstub_serverinfo_s *info, int id)
{
  FAR void *inarg[2] = {
    info, (void *)id
  };

  if (!info)
    {
      return -EINVAL;
    }

  return lapi_req(LTE_CMDID_LWM2M_SETSRVINFO, &inarg, 2, NULL, 0, NULL);
}

/****************************************************************************
 * Name: lte_getm2m_serverinfo
 ****************************************************************************/

int lte_getm2m_serverinfo(FAR struct lwm2mstub_serverinfo_s *info, int id)
{
  FAR void *outarg[2] = {
    info, (void *)id
  };

  if (!info)
    {
      return -EINVAL;
    }

  return lapi_req(LTE_CMDID_LWM2M_GETSRVINFO, NULL, 0, &outarg, 2, NULL);
}

/****************************************************************************
 * Name: lte_getm2m_enabled_objectnum
 ****************************************************************************/

int lte_getm2m_enabled_objectnum(void)
{
  int dummy_arg; /* Dummy for blocking API call */
  return lapi_req(LTE_CMDID_LWM2M_GETACTIVEOBJNUM, NULL, 0,
                           (FAR void *)&dummy_arg, 0, NULL);
}

/****************************************************************************
 * Name: lte_getm2m_enabled_objects
 ****************************************************************************/

int lte_getm2m_enabled_objects(uint16_t *objids, int objnum)
{
  FAR void *outarg[2] = {
    objids, (void *)objnum
  };

  if (!objids || objnum <= 0)
    {
      return -EINVAL;
    }

  return lapi_req(LTE_CMDID_LWM2M_GETACTIVEOBJ, NULL, 0, &outarg, 2, NULL);
}

/****************************************************************************
 * Name: lte_enablem2m_objects
 ****************************************************************************/

int lte_enablem2m_objects(uint16_t *objids, int objnum)
{
  FAR void *inarg[2] = {
    objids, (void *)objnum
  };

  if (!objids || objnum <= 0)
    {
      return -EINVAL;
    }

  insert_sort(objids, objnum);

  return lapi_req(LTE_CMDID_LWM2M_SETACTIVEOBJ, &inarg, 2, NULL, 0, NULL);
}

/****************************************************************************
 * Name: lte_getm2m_objresourcenum
 ****************************************************************************/

int lte_getm2m_objresourcenum(uint16_t objid)
{
  int dummy_arg; /* Dummy for blocking API call */
  return lapi_req(LTE_CMDID_LWM2M_GETOBJRESNUM, &objid, 1,
                           (FAR void *)&dummy_arg, 0, NULL);
}

/****************************************************************************
 * Name: lte_getm2m_objresourceinfo
 ****************************************************************************/

int lte_getm2m_objresourceinfo(uint16_t objid, int res_num,
                                struct lwm2mstub_resource_s *reses)
{
  FAR void *outarg[2] = {
    reses, (void *)res_num
  };

  if (!reses || res_num <= 0)
    {
      return -EINVAL;
    }

  return lapi_req(LTE_CMDID_LWM2M_GETOBJRESOURCE,
                  &objid, 1, outarg, 2, NULL);
}

/****************************************************************************
 * Name: lte_setm2m_objectdefinition
 ****************************************************************************/

int lte_setm2m_objectdefinition(uint16_t objids, int res_num,
                                struct lwm2mstub_resource_s *resucs)
{
  FAR void *inarg[3] = {
    (void *)(uint32_t)objids, (void *)res_num, resucs
  };

  return lapi_req(LTE_CMDID_LWM2M_SETOBJRESOURCE, inarg, 3, NULL, 0, NULL);
}

/****************************************************************************
 * Name: lte_apply_m2msetting
 ****************************************************************************/

int lte_apply_m2msetting(void)
{
  return lapi_req(LTE_CMDID_LWM2M_APPLY_SETTING, NULL, 0, NULL, 0, NULL);
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
 * Name: lte_set_report_m2moperation
 ****************************************************************************/

int lte_set_report_m2moperation(lwm2mstub_operation_cb_t cb)
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
