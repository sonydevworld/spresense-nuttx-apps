/****************************************************************************
 * apps/lte/lapi/src/lapi_firmware.c
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
#include <errno.h>
#include <nuttx/wireless/lte/lte_ioctl.h>

#include "lte/lapi.h"
#include "lte/lte_api.h"
#include "lte/lte_fw_api.h"

#include "lapi_util.h"

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

/****************************************************************************
 * Private Functions
 ****************************************************************************/

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/* Synchronous APIs */

int32_t lte_get_version_sync(lte_version_t *version)
{
  int32_t ret;
  int32_t result;
  FAR void *outarg[] =
    {
      &result, version
    };

  if (version == NULL)
    {
      return -EINVAL;
    }

  ret = lapi_req(LTE_CMDID_GETVER,
                 NULL, 0,
                 (FAR void *)outarg, ARRAY_SZ(outarg),
                 NULL);
  if (ret == 0)
    {
      ret = result;
    }

  return ret;
}

/* Asynchronous APIs */

int32_t lte_get_version(get_ver_cb_t callback)
{
  if (callback == NULL)
    {
      return -EINVAL;
    }

  return lapi_req(LTE_CMDID_GETVER | LTE_CMDOPT_ASYNC_BIT,
                  NULL, 0, NULL, 0, callback);
}

int32_t ltefw_inject_deltaimage(const struct ltefw_injectdata_s *inject_data,
  uint16_t *ltefw_result)
{
  /* TODO: implement */

  return -EOPNOTSUPP;
}

int32_t ltefw_get_deltaimage_len(void)
{
  /* TODO: implement */

  return -EOPNOTSUPP;
}

int32_t ltefw_exec_deltaupdate(uint16_t *ltefw_result)
{
  /* TODO: implement */

  return -EOPNOTSUPP;
}

int32_t ltefw_get_deltaupdate_result(uint16_t *ltefw_result)
{
  /* TODO: implement */

  return -EOPNOTSUPP;
}
