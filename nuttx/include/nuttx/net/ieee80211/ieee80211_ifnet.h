/****************************************************************************
 * include/nuttx/net/ieee80211/ieee80211_ifnet.h
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

#ifndef _INCLUDE_NUTTX_NET_IEEE80211_IEEE80211_IFNET_H
#define _INCLUDE_NUTTX_NET_IEEE80211_IEEE80211_IFNET_H

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <nuttx/config.h>

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

/****************************************************************************
 * Public Types
 ****************************************************************************/

/* Represents one packet buffer */

struct ieee80211_iobuf_s
{
  sq_entry_t m_link;
  uint16_t   m_flags;
  uint16_t   m_len;
  uint16_t   m_pktlen;
  uint16_t   m_hdrlen;
#if NVLAN > 0
  uint16_t   m_vtag;
#endif
  void      *m_priv;
  uint8_t    m_data[CONFIG_IEEE80211_BUFSIZE];
};

/****************************************************************************
 * Global Data
 ****************************************************************************/

/* A list of all free, unallocated I/O buffers */

extern sq_queue_t g_ieee80211_freelist;

/****************************************************************************
 * Inline Functions
 ****************************************************************************/

static __inline FAR struct ieee80211_iobuf_s *ieee80211_ioalloc(void)
{
  return (FAR struct ieee80211_iobuf_s *)sq_remfirst(&g_ieee80211_freelist);
}

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

struct ieee80211com;
void ieee80211_ifinit(FAR struct ieee80211com *ic);

/* Start polling for queued packets if the device is ready and polling has
 * not already been started.
 */

void ieee80211_ifstart(void);

/* Enqueue the packet to be sent by the Ethernet driver */

int ieee80211_ifsend(struct ieee80211_iobuf_s *iob);

/****************************************************************************
 * Name: ieee80211_iofree
 *
 * Description:
 *   Free the I/O buffer at the head of a buffer chain returning it to the
 *   free list.  The link to  the next I/O buffer in the chain is return.
 *
 ****************************************************************************/

FAR struct ieee80211_iobuf_s *ieee80211_iofree(FAR struct ieee80211_iobuf_s *iob);

/****************************************************************************
 * Name: ieee80211_iopurge
 *
 * Description:
 *   Free an entire buffer chain
 *
 ****************************************************************************/

void ieee80211_iopurge(FAR sq_queue_t *q);

/****************************************************************************
 * Name: ieee80211_iocat
 *
 * Description:
 *   Concatenate ieee80211_iobuf_s chain iob2 to iob1.
 *
 ****************************************************************************/

void ieee80211_iocat(FAR struct ieee80211_iobuf_s *iob1,
                     FAR struct ieee80211_iobuf_s *iob2);

#endif /* _INCLUDE_NUTTX_NET_IEEE80211_IEEE80211_IFNET_H */
