/****************************************************************************
 * net/ieee80211/ieee80211_ifnet.c
 *
 *   Copyright (C) 2014 Gregory Nutt. All rights reserved.
 *   Author: Gregory Nutt <gnutt@nuttx.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name NuttX nor the names of its contributors may be
 *    used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 ****************************************************************************/

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <nuttx/config.h>

#include <stdbool.h>
#include <string.h>
#include <queue.h>

#include <nuttx/net/iob.h>

#include "ieee80211/ieee80211_ifnet.h"
#include "ieee80211/ieee80211_var.h"

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

#ifndef MIN
#  define MIN(a,b) ((a) < (b) ? (a) : (b))
#endif

/****************************************************************************
 * Private Types
 ****************************************************************************/

/****************************************************************************
 * Private Data
 ****************************************************************************/

/****************************************************************************
 * Public Data
 ****************************************************************************/

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/****************************************************************************
 * Private Functions
 ****************************************************************************/

/****************************************************************************
 * Name: ieee80211_ifinit
 *
 * Description:
 *   Set up the devices interface I/O buffers for normal operations.
 *
 ****************************************************************************/

void ieee80211_ifinit(FAR struct ieee80211_s *ic)
{
  /* Perform one-time initialization */
  /* Initialize the I/O buffering (okay to call multiple times */

  iob_initialize();

  /* Perform pre-instance initialization */
  /* NONE */
}

/****************************************************************************
 * Name: ieee80211_ifsend
 *
 * Description:
 *   Enqueue the packet to be sent by the Ethernet driver and begin
 *   accepting TX polls from the Ethernet driver (if we are not already doing
 *   so.
 *
 ****************************************************************************/

int ieee80211_ifsend(FAR struct ieee80211_s *ic, FAR struct iob_s *iob,
                     uint8_t flags)
{
  /* Add the I/O buffer chain to the driver output queue */
#warning Missing logic

  /* Are we currently accepting driver polls? */
#warning Missing logic

  /* No.. Allocate a callback structure */
#warning Missing logic

  /* Initialize the callback structure */
#warning Missing logic

  /* Indicate that we are accepting driver polls */
#warning Missing logic
}
