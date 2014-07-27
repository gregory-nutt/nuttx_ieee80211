/****************************************************************************
 * net/ieee80211/ieee80211_ifnet.h
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

#ifndef __NET_IEEE80211_IEEE80211_IFNET_H
#define __NET_IEEE80211_IEEE80211_IFNET_H

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <nuttx/config.h>
#include <nuttx/net/iob.h>

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

#define IFSEND_MCAST   (1 << 0) /* Send as multi-cast */

/****************************************************************************
 * Public Types
 ****************************************************************************/

/****************************************************************************
 * Global Data
 ****************************************************************************/

/****************************************************************************
 * Public Function Prototypes
 ****************************************************************************/

/****************************************************************************
 * Name: ieee80211_ifinit
 *
 * Description:
 *   Set up the devices interface I/O buffers for normal operations.
 *
 ****************************************************************************/

struct ieee80211_s;
void ieee80211_ifinit(FAR struct ieee80211_s *ic);

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
                     uint8_t flags);

#endif /* __NET_IEEE80211_IEEE80211_IFNET_H */
