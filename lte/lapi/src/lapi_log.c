/****************************************************************************
 * apps/lte/lapi/src/lapi_log.c
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

#include <errno.h>
#include <nuttx/wireless/lte/lte_ioctl.h>

#include "lte/lapi.h"
#include "lte/lte_log.h"
#include "lapi_util.h"

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/****************************************************************************
 * Name: lte_log_collect
 ****************************************************************************/

int lte_log_collect(char output_fname[], size_t len)
{
  FAR void *inarg[] = { (FAR void *)&len };
  FAR void *outarg[] = { output_fname, (FAR void *)&len };

  if ((output_fname != NULL) && (len != LTE_LOG_NAME_LEN))
    {
      return -ENOBUFS;
    }

  len = LTE_LOG_NAME_LEN;

  return lapi_req(LTE_CMDID_SAVE_LOG,
                 inarg, ARRAY_SZ(inarg),
                 outarg, ARRAY_SZ(outarg),
                 NULL);
}

/****************************************************************************
 * Name: lte_log_getlist
 ****************************************************************************/

int lte_log_getlist(size_t listsize, size_t fnamelen,
                    char list[listsize][fnamelen])
{
  FAR void *inarg[] = { (FAR void *)fnamelen };
  FAR void *outarg[] = { list, (FAR void *)listsize, (FAR void *)fnamelen };

  if ((listsize == 0) || (list == NULL))
    {
      return -EINVAL;
    }

  if (fnamelen != LTE_LOG_NAME_LEN)
    {
      return -ENOBUFS;
    }

  return lapi_req(LTE_CMDID_GET_LOGLIST,
                 inarg, ARRAY_SZ(inarg),
                 outarg, ARRAY_SZ(outarg),
                 NULL);
}
