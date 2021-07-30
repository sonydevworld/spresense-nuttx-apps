/****************************************************************************
 * apps/include/lte/lte_fw_def.h
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

#ifndef __APPS_INCLUDE_LTE_LTE_FW_DEF_H
#define __APPS_INCLUDE_LTE_LTE_FW_DEF_H

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

/* Inject delta image from the beginning. */

#define LTEFW_INJECTION_MODE_NEW    (0)

/* Inject delta image from the continuation. */

#define LTEFW_INJECTION_MODE_APPEND (1)

/* LTEFW result code */

/* OK */

#define LTEFW_RESULT_OK                            (0x0000)

/* Not enough space for storage for injection */

#define LTEFW_RESULT_NOT_ENOUGH_INJECTSTORAGE      (0x0001)

/* CRC check error in header part of delta image */

#define LTEFW_RESULT_DELTAIMAGE_HDR_CRC_ERROR      (0x0002)

/* Unsupported header type of delta image */

#define LTEFW_RESULT_DELTAIMAGE_HDR_UNSUPPORTED    (0x0003)

/* Failed to set delta image */

#define LTEFW_RESULT_PRECHK_SET_DELTAIMAGE_FAILED  (0x0004)

/* Failed to delta update */

#define LTEFW_RESULT_DELTAUPDATE_FAILED            (0x0005)

/* Not found delta image */

#define LTEFW_RESULT_PRECHK_DELTAIMAGE_MISSING     (0x0006)

/* Out of memory that prepare for update */

#define LTEFW_RESULT_PRECHK_OOM                    (0x0007)

/* Invalid size of delta image */

#define LTEFW_RESULT_PRECHK_SIZE_ERROR             (0x0008)

/* Wrong delta image package */

#define LTEFW_RESULT_PRECHK_PKG_ERROR              (0x0009)

/* CRC check error in delta image */

#define LTEFW_RESULT_PRECHK_CRC_ERROR              (0x000A)

/* There is no update result */

#define LTEFW_RESULT_DELTAUPDATE_NORESULT          (0x000B)

#endif /* __APPS_INCLUDE_LTE_LTE_FW_DEF_H */
