/****************************************************************************
 * apps/lte/alt1250/alt1250_atcmd.h
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

#ifndef __LTE_ALT1250_ALT1250_ATCMD_H__
#define __LTE_ALT1250_ALT1250_ATCMD_H__


/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <nuttx/config.h>

#include <stdbool.h>

#include <nuttx/net/usrsock.h>

#include "alt1250_dbg.h"
#include "alt1250_devif.h"
#include "alt1250_container.h"

/****************************************************************************
 * Public Data Type
 ****************************************************************************/

typedef int (*atreply_parser_t)(FAR char *reply, int len, void *arg);
typedef int (*atcmd_postproc_t)(FAR struct alt_container_s *container,
                                FAR char *rdata, int len, unsigned long arg);

struct atreply_truefalse_s
{
  FAR const char *target_str;
  FAR bool result;
};

/****************************************************************************
 * Public Functions
 ****************************************************************************/

int send_internal_at_command(FAR struct alt1250_s *dev,
      FAR struct alt_container_s *container,
      atcmd_postproc_t proc, unsigned long arg, FAR int32_t *usock_result);

int check_atreply_ok(FAR char *reply, int len, void *arg);
int check_atreply_truefalse(FAR char *reply, int len, void *arg);

int lwm2mstub_send_reset(FAR struct alt1250_s *dev,
      FAR struct alt_container_s *container);

int lwm2mstub_send_getenable(FAR struct alt1250_s *dev,
      FAR struct alt_container_s *container, FAR int32_t *usock_result);

int lwm2mstub_send_setenable(FAR struct alt1250_s *dev,
      FAR struct alt_container_s *container, bool en);

int lwm2mstub_send_getnamemode(FAR struct alt1250_s *dev,
      FAR struct alt_container_s *container);

int lwm2mstub_send_setnamemode(FAR struct alt1250_s *dev,
      FAR struct alt_container_s *container, int mode);

int lwm2mstub_send_getversion(FAR struct alt1250_s *dev,
      FAR struct alt_container_s *container);

int lwm2mstub_send_setversion(FAR struct alt1250_s *dev,
      FAR struct alt_container_s *container, bool is_v1_1);

#endif  /* __LTE_ALT1250_ALT1250_ATCMD_H__ */
