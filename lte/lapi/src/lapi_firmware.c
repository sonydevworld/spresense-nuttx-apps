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
#include <string.h>
#include <errno.h>
#include <nuttx/wireless/lte/lte_ioctl.h>

#include "lte/lapi.h"
#include "lte/lte_api.h"
#include "lte/lte_fw_api.h"

#include "lapi_util.h"

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

#define SPLIT_LEN 1500

/****************************************************************************
 * Private Functions
 ****************************************************************************/

static int ltefw_inject_deltaimage_inparam_check(
  const struct ltefw_injectdata_s *inject_data, uint16_t *ltefw_result)
{
  if ((inject_data == NULL) || (ltefw_result == NULL))
    {
      return -EINVAL;
    }

  if (inject_data->inject_mode > LTEFW_INJECTION_MODE_APPEND)
    {
      return -EINVAL;
    }

  return OK;
}

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/* Synchronous APIs */

int lte_get_version_sync(lte_version_t *version)
{
  int ret;
  int result;
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

int lte_get_version(get_ver_cb_t callback)
{
  if (callback == NULL)
    {
      return -EINVAL;
    }

  return lapi_req(LTE_CMDID_GETVER | LTE_CMDOPT_ASYNC_BIT,
                  NULL, 0, NULL, 0, callback);
}

int ltefw_inject_deltaimage(const struct ltefw_injectdata_s *inject_data,
  uint16_t *ltefw_result)
{
  int ret;
  int result;
  uint32_t totallen = 0;
  struct ltefw_injectdata_s req;
  FAR void *inarg[] =
    {
      &req
    };

  FAR void *outarg[] =
    {
      &result, ltefw_result
    };

  if (ltefw_inject_deltaimage_inparam_check(inject_data, ltefw_result))
    {
      return -EINVAL;
    }

  /* If 0 is input to data_len, return 0 without performing
   * the subsequent processing.
   */

  if (inject_data->data_len == 0)
    {
      return 0;
    }

  /* copy to working area */

  memcpy(&req, inject_data, sizeof(req));
  totallen = inject_data->data_len;

  do
    {
      req.data_len = (totallen > SPLIT_LEN) ? SPLIT_LEN : totallen;

      ret = lapi_req(LTE_CMDID_INJECTIMAGE,
                     (FAR void *)inarg, ARRAY_SZ(inarg),
                     (FAR void *)outarg, ARRAY_SZ(outarg),
                     NULL);
      if (ret < 0)
        {
          break;
        }
      else if (result < 0)
        {
          ret = result;
          break;
        }

      /* result is injected len */

      if (result > req.data_len)
        {
          ret = -EFAULT;
          break;
        }

      req.data += result;
      totallen -= result;
      req.inject_mode = LTEFW_INJECTION_MODE_APPEND;
    }
  while (totallen > 0);

  if (ret >= 0)
    {
      /* return value is injected size */

      ret = inject_data->data_len;
    }

  return ret;
}

int ltefw_get_deltaimage_len(void)
{
  int ret;
  int result;
  uint16_t ltefw_result;
  FAR void *outarg[] =
    {
      &result, &ltefw_result
    };

  ret = lapi_req(LTE_CMDID_GETIMAGELEN,
                 NULL, 0,
                 (FAR void *)outarg, ARRAY_SZ(outarg),
                 NULL);

  if (ret == 0)
    {
      ret = result;
    }

  return ret;
}

int ltefw_exec_deltaupdate(uint16_t *ltefw_result)
{
  int ret;
  int result;
  FAR void *outarg[] =
    {
      &result, ltefw_result
    };

  if (ltefw_result == NULL)
    {
      return -EINVAL;
    }

  ret = lapi_req(LTE_CMDID_EXEUPDATE,
                 NULL, 0,
                 (FAR void *)outarg, ARRAY_SZ(outarg),
                 NULL);

  if (ret == 0)
    {
      ret = result;
    }

  return ret;
}

int ltefw_get_deltaupdate_result(uint16_t *ltefw_result)
{
  int ret;
  int result;
  FAR void *outarg[] =
    {
      &result, ltefw_result
    };

  if (ltefw_result == NULL)
    {
      return -EINVAL;
    }

  ret = lapi_req(LTE_CMDID_GETUPDATERES,
                 NULL, 0,
                 (FAR void *)outarg, ARRAY_SZ(outarg),
                 NULL);

  if (ret == 0)
    {
      ret = result;
    }

  return ret;
}
