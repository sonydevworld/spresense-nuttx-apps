/****************************************************************************
 * apps/lte/alt1250/alt1250_main.c
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
#include <stdlib.h>
#include <string.h>
#include <semaphore.h>
#include <assert.h>
#include <sys/poll.h>

#include "alt1250_dbg.h"
#include "alt1250_daemon.h"
#include "alt1250_devif.h"
#include "alt1250_devevent.h"
#include "alt1250_usockif.h"
#include "alt1250_usockevent.h"
#include "alt1250_container.h"
#include "alt1250_select.h"
#include "alt1250_usrsock_hdlr.h"
#include "alt1250_evt.h"
#include "alt1250_netdev.h"
#include "alt1250_sms.h"

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

#define SYNC_CMD_PREFIX "-s"

#define ALTFDNO (0)
#define USOCKFDNO (1)

#define SET_POLLIN(fds, fid) { \
  (fds).fd = (fid);  \
  (fds).events = POLLIN; \
}

#define IS_POLLIN(fds) ((fds).revents & POLLIN)

/****************************************************************************
 * Private Data
 ****************************************************************************/

static struct alt1250_s *g_daemon = NULL;

/****************************************************************************
 * Private Functions
 ****************************************************************************/

/****************************************************************************
 * Name: notify_to_lapi_caller
 ****************************************************************************/

static void notify_to_lapi_caller(sem_t *syncsem)
{
  /* has -s (sync) option? */

  if (syncsem)
    {
      /* Notify release to lapi waiting for synchronization */

      sem_post(syncsem);
    }
}

/****************************************************************************
 * Name: initialize_daemon
 ****************************************************************************/

static int initialize_daemon(FAR struct alt1250_s *dev)
{
  int ret;

  /* Initialize sub-system */

  /* Event call back task must be started
   * before any device files are opened
   */

  ret = alt1250_evttask_start();
  ASSERT(ret > 0);

  dev->usockfd = init_usock_device();
  ASSERT(dev->usockfd >= 0);

  dev->altfd = init_alt1250_device();
  ASSERT(dev->altfd >= 0);

  ret = altdevice_seteventbuff(dev->altfd, init_event_buffer());
  ASSERT(ret >= 0);

  init_containers();
  init_selectcontainer(dev);
  alt1250_sms_initcontainer(dev);
  alt1250_netdev_register(dev);

  return OK;
}

/****************************************************************************
 * Name: finalize_daemon
 ****************************************************************************/

static void finalize_daemon(FAR struct alt1250_s *dev)
{
  alt1250_netdev_unregister(dev);
  alt1250_evtdatadestroy();
  finalize_alt1250_device(dev->altfd);
  finalize_usock_device(dev->usockfd);
  alt1250_evttask_stop(dev);
}

/****************************************************************************
 * Name: alt1250_loop
 ****************************************************************************/

static int alt1250_loop(FAR struct alt1250_s *dev)
{
  int ret;
  struct pollfd fds[2];
  nfds_t nfds;
  bool is_running = true;

  initialize_daemon(dev);
  notify_to_lapi_caller(dev->syncsem);

  /* Main loop of this daemon */

  while (is_running)
    {
      memset(fds, 0, sizeof(fds));

      SET_POLLIN(fds[ALTFDNO], dev->altfd);
      nfds = 1;

      /* if (!dev->is_usockrcvd && !dev->recvfrom_processing) */

      if (ACCEPT_USOCK_REQUEST(dev))
        {
          SET_POLLIN(fds[USOCKFDNO], dev->usockfd);
          nfds++;
        }

      ret = poll(fds, nfds, -1);
      ASSERT(ret > 0);
      ret = OK;

      if (IS_POLLIN(fds[ALTFDNO]))
        {
          ret = perform_alt1250events(dev);
        }

      dbg_alt1250("ret: %u, recvfrom_processing: %d,"
                  " IS_POLLIN: %d, is_usockrcvd: %d\n",
                  ret, dev->recvfrom_processing,
                  IS_POLLIN(fds[USOCKFDNO]), dev->is_usockrcvd);

      if ((ret != REP_MODEM_RESET) && (!dev->recvfrom_processing)
          && (IS_POLLIN(fds[USOCKFDNO]) || dev->is_usockrcvd))
        {
          switch (perform_usockrequest(dev))
            {
              case REP_SEND_TERM:
                is_running = false;
                break;

              case REP_NO_CONTAINER:

                /* Do nothing because request could
                 * not send to modem driver because of
                 * no more container. To wait for empty container.
                 */

                break;

              default:
                dev->is_usockrcvd = false;
                break;
            }
        }
    }

  finalize_daemon(dev);

  return OK;
}

/****************************************************************************
 * Public Functions
 ****************************************************************************/

int main(int argc, FAR char *argv[])
{
  int ret;
  FAR char *endptr;
  sem_t *syncsem = NULL;

  if (argc > 1)
    {
      /* The format is "-sXXXXXXXX".
       * XXXXXXXXX indicates the pointer address to the semaphore
       * that will be posted at the timing when the daemon opens the
       * usersock device.
       */

      if (!(strncmp(argv[1], SYNC_CMD_PREFIX, strlen(SYNC_CMD_PREFIX))))
        {
          syncsem = (FAR sem_t *)strtol(&argv[1][strlen(SYNC_CMD_PREFIX)],
            &endptr, 16);
          if (!syncsem || endptr == &argv[1][strlen(SYNC_CMD_PREFIX)] ||
            *endptr != '\0')
            {
              return -EINVAL;
            }
        }
    }

  if (g_daemon)
    {
      fprintf(stderr, "%s is already running! \n", argv[0]);
      notify_to_lapi_caller(syncsem);
      return -1;
    }

  g_daemon = calloc(sizeof(struct alt1250_s), 1);
  ASSERT(g_daemon);

  g_daemon->syncsem = syncsem;
  g_daemon->evtq = (mqd_t)-1;
  g_daemon->sid = -1;
  g_daemon->is_usockrcvd = false;
  g_daemon->usock_enable = TRUE;
  g_daemon->is_support_lwm2m = false;
  g_daemon->lwm2m_apply_xid = -1;
  MODEM_STATE_POFF(g_daemon);

  reset_fwupdate_info(g_daemon);

  ret = alt1250_loop(g_daemon);
  free(g_daemon);
  g_daemon = NULL;

  /* Notify lapi that Daemon has finished */

  notify_to_lapi_caller(syncsem);

  return ret;
}
