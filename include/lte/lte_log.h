/****************************************************************************
 * apps/include/lte/lte_log.h
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

#ifndef __APPS_INCLUDE_LTE_LTE_LOG_H
#define __APPS_INCLUDE_LTE_LTE_LOG_H

/**
 * @brief LTE library for LTE firmware log
 *
 * API call type
 *
 * |     Sync API    |
 * | --------------- |
 * | lte_log_collect |
 * | lte_log_getlist |
 * | lte_log_open    |
 * | lte_log_close   |
 * | lte_log_read    |
 * | lte_log_remove  |
 * | lte_log_lseek   |
 *
 * @{
 * @file  lte_log.h
 */

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <sys/types.h>
#include <nuttx/wireless/lte/lte.h>

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

/** @name Functions */
/** @{ */

/**
 * Collect LTE modem FW logs and store them in the LTE modem storage.
 *
 * @param [out] output_fname: Buffer to store the name of the saved file.
 *                     If the saved file name is not needed, set it to NULL.
 * @param [in] len: Buffer length for output_fname. Sets LTE_LOG_NAME_LEN,
 *           except when the saved file name is not needed.
 *
 * @return Return value : Returns 0 on success. On error, a negative value is
 *                returned. The following values may be returned
 *                in error cases.
 *
 * - ENOBUFS
 * - ENOTSUP
 *
 */

int lte_log_collect(char output_fname[], size_t len);

/**
 * Get a list of logs stored in the LTE modem storage.
 *
 * @param [in] listsize: Number of arrays in which to store file names. The maximum
 *                number of arrays is LTE_LOG_LIST_SIZE.
 * @param [in] fnamelen: Buffer length for list. Sets LTE_LOG_NAME_LEN.
 * @param [in] list: Buffer to store the list of saved file names.
 *
 * @return Return value : Returns the number of stored file names on success.
 *                On error, a negative value is returned. The following
 *                values may be returned in error cases.
 *
 * - EINVAL
 * - ENOBUFS
 * - ENOTSUP
 *
 */

int lte_log_getlist(size_t listsize, size_t fnamelen,
                    char list[listsize][fnamelen]);

#ifdef CONFIG_LTE_LAPI_LOG_ACCESS

/**
 * Open a log file on LTE modem.
 *
 * @param [in] filename: Log file name to open.
 *
 * @return Return value : Returns the file descriptor on success.
 *                On error, a negative value is returned. The following
 *                values may be returned in error cases.
 *
 * - EINVAL
 * - ENAMETOOLONG
 * - ENOTSUP
 *
 */

int lte_log_open(const char *filename);

/**
 * Close a log file descriptor.
 *
 * @param [in] fd: File descriptor.
 *
 * @return Return value : Returns the 0 on success.
 *                On error, a negative value is returned. The following
 *                values may be returned in error cases.
 *
 * - EINVAL
 * - ENOTSUP
 *
 */

int lte_log_close(int fd);

/**
 * Read data from log file on LTE modem.
 *
 * @param [in] fd: File descriptor.
 * @param [out] buf: Buffer to read.
 * @param [in] len: Read length.
 *
 * @return Return value : Returns the number of bytes read on success.
 *                On error, a negative value is returned. The following
 *                values may be returned in error cases.
 *
 * - EINVAL
 * - ENOTSUP
 *
 */

ssize_t lte_log_read(int fd, void *buf, size_t len);

/**
 * Remove a file on LTE modem.
 *
 * @param [in] filename: Log file name to remove.
 *
 * @return Return value : Returns the 0 on success.
 *                On error, a negative value is returned. The following
 *                values may be returned in error cases.
 *
 * - ENAMETOOLONG
 * - ENOTSUP
 *
 */

int lte_log_remove(const char *filename);

/**
 * Set the file read offset.
 *
 * @param [in] fd: File descriptor.
 * @param [in] offset: The number of offset bytes.
 * @param [in] whence: Reference point of offset.
 *              Available @a whence are as follows.
 *              - SEEK_SET
 *              - SEEK_CUR
 *              - SEEK_END
 *
 * @return Return value : Returns the offset from the beginning of the file on
 *                success. On error, a negative value is returned.
 *                The following values may be returned in error cases.
 *
 * - EINVAL
 * - ENOTSUP
 *
 */

int lte_log_lseek(int fd, off_t offset, int whence);

/** @} */

/** @} */

#endif /* CONFIG_LTE_LAPI_LOG_ACCESS */

#undef EXTERN
#ifdef __cplusplus
}
#endif

#endif /* __APPS_INCLUDE_LTE_LTE_LOG_H */
