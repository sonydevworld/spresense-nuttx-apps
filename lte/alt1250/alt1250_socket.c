/****************************************************************************
 * apps/lte/alt1250/alt1250_socket.c
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

#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <sys/ioctl.h>

#include "alt1250_dbg.h"
#include "alt1250_daemon.h"
#include "alt1250_usockif.h"
#include "alt1250_socket.h"
#include "alt1250_select.h"

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/****************************************************************************
 * name: usocket_search
 ****************************************************************************/

FAR struct usock_s *usocket_search(FAR struct alt1250_s *dev, int usockid)
{
  dbg_alt1250("%s usockid: %d\n", __func__, usockid);

  ASSERT(usockid >= 0 && usockid < SOCKET_COUNT);

  return &dev->sockets[usockid];
}

/****************************************************************************
 * name: usocket_alloc
 ****************************************************************************/

FAR struct usock_s *usocket_alloc(FAR struct alt1250_s *dev)
{
  int i;
  FAR struct usock_s *sock;

  for (i = 0; i < ARRAY_SZ(dev->sockets); i++)
    {
      sock = &dev->sockets[i];
      if (sock->state == SOCKET_STATE_CLOSED)
        {
          sock->usockid = i;
          sock->altsockid = -1;
          sock->state = SOCKET_STATE_PREALLOC;
          sock->select_condition = SELECT_WRITABLE | SELECT_READABLE;
          return sock;
        }
    }

  return NULL;
}

/****************************************************************************
 * name: usocket_free
 ****************************************************************************/

void usocket_free(FAR struct usock_s *sock)
{
  sock->state = SOCKET_STATE_CLOSED;
}

/****************************************************************************
 * name: usocket_freeall
 ****************************************************************************/

void usocket_freeall(FAR struct alt1250_s *dev)
{
  int i;
  FAR struct usock_s *sock;

  for (i = 0; i < ARRAY_SZ(dev->sockets); i++)
    {
      sock = &dev->sockets[i];
      usocket_free(sock);
    }
}

/****************************************************************************
 * name: usocket_commitstate
 ****************************************************************************/

void usocket_commitstate(FAR struct alt1250_s *dev)
{
  restart_select(dev);
}
