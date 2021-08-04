/****************************************************************************
 * apps/lte/lapi/src/lapi_power.c
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

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <strings.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <nuttx/wireless/lte/lte_ioctl.h>

#include "lte/lte_api.h"

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

#define DAEMON_NAME     "alt1250"
#define DAEMON_PRI      100
#define DAEMON_STACK_SZ 2048
#define CMD_PREFIX      "-s"
#define ADDR_LEN        (strlen(CMD_PREFIX) + 9)  /* 32bit + '\0' */

/****************************************************************************
 * Private Types
 ****************************************************************************/

/****************************************************************************
 * Public Function Prototypes
 ****************************************************************************/

int alt1250_main(int argc, char *argv[]);

/****************************************************************************
 * Private Data
 ****************************************************************************/

static sem_t g_lock = SEM_INITIALIZER(1);

/****************************************************************************
 * Private Functions
 ****************************************************************************/

/****************************************************************************
 * Name: lapi_lock
 ****************************************************************************/

static inline void lapi_lock(FAR sem_t *lock)
{
  int ret;

  do
    {
      ret = sem_wait(lock);
    }
  while (ret == -EINTR);
}

/****************************************************************************
 * Name: lapi_unlock
 ****************************************************************************/

static inline void lapi_unlock(FAR sem_t *lock)
{
  sem_post(lock);
}

/****************************************************************************
 * Name: is_daemon_running
 ****************************************************************************/

static bool is_daemon_running(void)
{
  int sock;
  bool is_run = false;

  sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock < 0)
    {
      if (errno == ENETDOWN)
        {
          is_run = false;
        }
      else
        {
          is_run = true;
        }
    }
  else
    {
      close(sock);
      is_run = true;
    }

  return is_run;
}

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/****************************************************************************
 * Name: lapi_req
 ****************************************************************************/

int lapi_req(uint32_t cmdid, FAR void *inp, size_t ilen, FAR void *outp,
  size_t olen, FAR void *cb)
{
  int ret;
  int sock;
  struct lte_ioctl_data_s cmd;

  sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock < 0)
    {
      ret = -errno;
      printf("failed to open socket:%d\n", errno);
    }
  else
    {
      cmd.cmdid = cmdid;
      cmd.inparam = inp;
      cmd.inparamlen = ilen;
      cmd.outparam = outp;
      cmd.outparamlen = olen;
      cmd.cb = cb;

      ret = ioctl(sock, SIOCLTECMD, (unsigned long)&cmd);
      if (ret < 0)
        {
          ret = -errno;
          printf("failed to ioctl:%d\n", errno);
        }

      close(sock);
    }

  return ret;
}

/****************************************************************************
 * Name: lte_initialize
 ****************************************************************************/

int32_t lte_initialize(void)
{
  int32_t ret = 0;

  lapi_lock(&g_lock);

  if (!is_daemon_running())
    {
      sem_t sync;
      char *argv[2];
      char addr[ADDR_LEN];

      sem_init(&sync, 0, 0);

      /* address -> ascii */

      snprintf(addr, ADDR_LEN, "%s%08lx", CMD_PREFIX, (unsigned long)&sync);

      argv[0] = addr;
      argv[1] = NULL; /* termination */

      ret = task_create(DAEMON_NAME, DAEMON_PRI, DAEMON_STACK_SZ,
        alt1250_main, argv);
      if (ret < 0)
        {
          ret = -errno;
          printf("failed to create task:%d\n", errno);
        }
      else
        {
          ret = 0;
          sem_wait(&sync);
        }

      sem_destroy(&sync);
    }
  else
    {
      ret = -EALREADY;
    }

  lapi_unlock(&g_lock);

  return ret;
}

/****************************************************************************
 * Name: lte_finalize
 ****************************************************************************/

int32_t lte_finalize(void)
{
  return lapi_req(LTE_CMDID_FIN, NULL, 0, NULL, 0, NULL);
}

/****************************************************************************
 * Name: lte_set_report_restart
 ****************************************************************************/

int32_t lte_set_report_restart(restart_report_cb_t callback)
{
  return lapi_req(LTE_CMDID_SETRESTART, NULL, 0, NULL, 0, callback);
}

/****************************************************************************
 * Name: lte_power_on
 ****************************************************************************/

int32_t lte_power_on(void)
{
  return lapi_req(LTE_CMDID_POWERON, NULL, 0, NULL, 0, NULL);
}

/****************************************************************************
 * Name: lte_power_off
 ****************************************************************************/

int32_t lte_power_off(void)
{
  return lapi_req(LTE_CMDID_POWEROFF, NULL, 0, NULL, 0, NULL);
}

/****************************************************************************
 * Name: lte_acquire_wakelock
 ****************************************************************************/

int lte_acquire_wakelock(void)
{
  return lapi_req(LTE_CMDID_TAKEWLOCK, NULL, 0, NULL, 0, NULL);
}

/****************************************************************************
 * Name: lte_release_wakelock
 ****************************************************************************/

int lte_release_wakelock(void)
{
  return lapi_req(LTE_CMDID_GIVEWLOCK, NULL, 0, NULL, 0, NULL);
}
