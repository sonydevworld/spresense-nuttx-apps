/****************************************************************************
 * apps/include/lte/lte_fw_api.h
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

#ifndef __APPS_INCLUDE_LTE_LTE_FW_API_H
#define __APPS_INCLUDE_LTE_LTE_FW_API_H

/* API call type
 *
 * |     Sync API                 |
 * | ---------------------------- |
 * | ltefw_inject_deltaimage      |
 * | ltefw_get_deltaimage_len     |
 * | ltefw_exec_deltaupdate       |
 * | ltefw_get_deltaupdate_result |
 *
 * attention
 * This API notifies the progress of the update by the callback set by
 * lte_set_report_restart(). You must call lte_set_report_restart()
 * before lte_power_on().
 */

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <stdint.h>
#include <nuttx/wireless/lte/lte.h>

#include "lte_fw_def.h"

#ifdef __cplusplus
#define EXTERN extern "C"
extern "C"
{
#else
#define EXTERN extern
#endif

/****************************************************************************
 * Public Function Prototypes
 ****************************************************************************/

/* Inject delta image to LTE modem.
 *
 * [in] inject_data: Setting of delta image to inject.
 * [out] ltefw_result: The pointer to the area to store an
 *                     LTEFW function result. As below value stored.
 * - LTEFW_RESULT_OK
 * - LTEFW_RESULT_NOT_ENOUGH_INJECTSTORAGE
 * - LTEFW_RESULT_DELTAIMAGE_HDR_CRC_ERROR
 * - LTEFW_RESULT_DELTAIMAGE_HDR_UNSUPPORTED
 *
 * On success, The length of the image successfully injected
 * to the modem is returned. On failure, a negative value or the
 * injected length will be returned. Negative values follow <errno.h>.
 */

int ltefw_inject_deltaimage(const struct ltefw_injectdata_s *inject_data,
  uint16_t *ltefw_result);

/* Get length of injected delta image file.
 *
 * On success, The length of injected data to the modem is returned.
 * On failure, a negative value is returned according to <errno.h>.
 */

int ltefw_get_deltaimage_len(void);

/* Execute delta update.
 * attention When this function is executed, the modem is automatically
 * rebooted multiple times. The progress of the update can be checked by
 * the callback set by lte_set_report_restart().
 *
 * [out] ltefw_result: The pointer to the area to store an
 *                      LTEFW function result. As below value stored.
 * - LTEFW_RESULT_OK
 * - LTEFW_RESULT_PRECHK_SET_DELTAIMAGE_FAILED
 * - LTEFW_RESULT_PRECHK_DELTAIMAGE_MISSING
 * - LTEFW_RESULT_PRECHK_OOM
 * - LTEFW_RESULT_PRECHK_SIZE_ERROR
 * - LTEFW_RESULT_PRECHK_PKG_ERROR
 * - LTEFW_RESULT_PRECHK_CRC_ERROR
 *
 * On success, 0 is returned. On failure,
 * negative value is returned according to <errno.h>.
 */

int ltefw_exec_deltaupdate(uint16_t *ltefw_result);

/* Get the result of delta update.
 * Execute this function after LTE_RESTART_MODEM_UPDATED is
 * notified to the callback set by lte_set_report_restart().
 *
 * [out] ltefw_result: The pointer to the area to store an
 *                     LTEFW function result. As below value stored.
 * - LTEFW_RESULT_OK
 * - LTEFW_RESULT_DELTAUPDATE_FAILED
 * - LTEFW_RESULT_DELTAUPDATE_NORESULT
 *
 * On success, 0 is returned. On failure,
 * negative value is returned according to <errno.h>.
 */

int ltefw_get_deltaupdate_result(uint16_t *ltefw_result);

#undef EXTERN
#ifdef __cplusplus
}
#endif

#endif /* __APPS_INCLUDE_LTE_LTE_FW_API_H */
