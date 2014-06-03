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

#include <nuttx/net/ieee80211/ieee80211_ifnet.h>
#include <nuttx/net/ieee80211/ieee80211_var.h>

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

/* This is a pool of pre-allocated I/O buffers */

static struct ieee80211_iobuf_s g_iopool[CONFIG_IEEE80211_NBUFFERS];
static bool g_ioinitialized;

/****************************************************************************
 * Public Data
 ****************************************************************************/

/* A list of all free, unallocated I/O buffers */

sq_queue_t g_ieee80211_freelist;

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

void ieee80211_ifinit(FAR struct ieee80211com *ic)
{
  int i;

  /* Perform one-time initialization */

  if (!g_ioinitialized)
    {
      /* Add each I/O buffer to the free list */

      for (i = 0; i < CONFIG_IEEE80211_NBUFFERS; i++)
        {
          sq_addlast(&g_iopool[i].m_link, &g_ieee80211_freelist);
        }

      g_ioinitialized = true;
    }

  /* Perform pre-instance initialization */
  /* NONE */
}

/****************************************************************************
 * Name: ieee80211_iofree
 *
 * Description:
 *   Free the I/O buffer at the head of a buffer chain returning it to the
 *   free list.  The link to  the next I/O buffer in the chain is return.
 *
 ****************************************************************************/

FAR struct ieee80211_iobuf_s *ieee80211_iofree(FAR struct ieee80211_iobuf_s *iob)
{
  sq_entry_t *next = iob->m_link.flink;

  sq_addlast(&iob->m_link, &g_ieee80211_freelist);
  return (FAR struct ieee80211_iobuf_s *)next;
}

/****************************************************************************
 * Name: ieee80211_iopurge
 *
 * Description:
 *   Free an entire buffer chain
 *
 ****************************************************************************/

void ieee80211_iopurge(FAR sq_queue_t *q)
{
  /* If the free list is empty, then just move the entry queue to the the
   * free list.  Otherwise, append the list to the end of the free list.
   */

  if (g_ieee80211_freelist.tail)
    {
      g_ieee80211_freelist.tail->flink = q->head;
    }
  else
    {
      g_ieee80211_freelist.head = q->head;
    }

  /* In either case, the tail of the queue is the tail of queue becomes the
   * tail of the free list.
   */

  g_ieee80211_freelist.tail = q->tail;
}

/****************************************************************************
 * Name: ieee80211_iocpy
 *
 * Description:
 *  Copy data 'len' bytes of data into the user buffer starting at 'offset'
 *  in the I/O buffer.
 *
 ****************************************************************************/

void ieee80211_iocpy(FAR uint8_t *dest,
                     FAR const struct ieee80211_iobuf_s *iob,
                     unsigned int len, unsigned int offset)
{
  FAR const uint8_t *src;
  unsigned int ncopy;
  unsigned int avail;

  /* Skip to the I/O buffer containing the offset */

  while (offset >= iob->m_len)
    {
      offset -= iob->m_len;
      iob     = (FAR struct ieee80211_iobuf_s *)iob->m_link.flink;
    }

  /* Then loop until all of the I/O data is copied to the user buffer */

  while (len > 0)
    {
      ASSERT(iob);

      /* Get the source I/O buffer offset address and the amount of data
       * available from that address.
       */

      src   = &iob->m_data[offset];
      avail = iob->m_len - offset;

      /* Copy the whole I/O buffer in to the user buffer */

      ncopy = MIN(avail, len);
      memcpy(dest, src, ncopy);

      /* Adjust the total length of the copy and the destination address in
       * the user buffer.
       */

      len  -= ncopy;
      dest += ncopy;

      /* Skip to the next I/O buffer in the chain */

      iob = (FAR struct ieee80211_iobuf_s *)iob->m_link.flink;
      offset = 0;
    }
}

/****************************************************************************
 * Name: ieee80211_iocat
 *
 * Description:
 *   Concatenate ieee80211_iobuf_s chain iob2 to iob1.
 *
 ****************************************************************************/

void ieee80211_iocat(FAR struct ieee80211_iobuf_s *iob1,
                     FAR struct ieee80211_iobuf_s *iob2)
{
  unsigned int offset2;
  unsigned int ncopy;
  unsigned int navail;

  /* Find the last buffer in the iob1 buffer chain */
 
  while (iob1->m_link.flink)
    {
      iob1 = (FAR struct ieee80211_iobuf_s *)iob1->m_link.flink;
    }

  /* Then add data to the end of iob1 */

  offset2 = 0;
  while (iob2)
    {
      /* Is the iob1 tail buffer full? */

      if (iob1->m_len >= CONFIG_IEEE80211_BUFSIZE)
        {
          /* Yes.. Just connect the chains */

          iob1->m_link.flink = iob2->m_link.flink;

          /* Has the data offset in iob2? */

          if (offset2 > 0)
            {
              /* Yes, move the data down and adjust the size */

              iob2->m_len -= offset2;
              memcpy(iob2->m_data, &iob2->m_data[offset2], iob2->m_len);

              /* Set up to continue packing, but now into iob2 */

              iob1 = iob2;
              iob2 = (FAR struct ieee80211_iobuf_s *)iob2->m_link.flink;

              iob1->m_link.flink = NULL;
              offset2 = 0;
            }
          else
            {
              /* Otherwise, we are done */

              return;
            }
        }

      /* How many bytes can we copy from the source (iob2) */

      ncopy = iob2->m_len - offset2;

      /* Limit the size of the copy to the amount of free space in iob1 */

      navail = CONFIG_IEEE80211_BUFSIZE - iob1->m_len;
      if (ncopy > navail)
        {
          ncopy = navail;
        }

      /* Copy the data from iob2 into iob1 */

      memcpy(iob1->m_data + iob1->m_len, iob2->m_data, ncopy);
      iob1->m_len += ncopy;
      offset2 += ncopy;

      /* Have we consumed all of the data in the iob2 entry? */

      if (offset2 >= iob2->m_len)
        {
          /* Yes.. free the iob2 entry and start processing the next I/O
           * buffer in the iob2 chain.
           */

          iob2 = ieee80211_iofree(iob2);
          offset2 = 0;
        }
    }
}

/****************************************************************************
 * Name: ieee80211_iotrim_head
 *
 * Description:
 *   Remove bytes from the beginning of an I/O chain
 *
 ****************************************************************************/

void ieee80211_iotrim_head(FAR struct ieee80211_iobuf_s *iob,
                           unsigned int trimlen)
{
  FAR struct ieee80211_iobuf_s *entry;
  unsigned int len;

  if (iob && trimlen > 0)
    {
      entry = iob;
      len   = trimlen;

      /* Trim from the head of the I/IO buffer chain */

      while (entry != NULL && len > 0)
        {
          /* Do we trim this entire I/O buffer away? */

          if (entry->m_len <= len)
            {
              /* Yes.. just set is length to zero and skip to the next */

              len -= entry->m_len;
              entry->m_len = 0;
              entry = (FAR struct ieee80211_iobuf_s *)entry->m_link.flink;
            }
          else
            {
              /* No, then just take what we need from this I/O buffer and
               * stop the trim.
               */

              entry->m_len -= len;
              memcpy(entry->m_data, &entry->m_data[len], entry->m_len);
              len = 0;
            }
        }
    }
}

/****************************************************************************
 * Name: ieee80211_iotrim_tail
 *
 * Description:
 *   Remove bytes from the end of an I/O chain
 *
 ****************************************************************************/

void ieee80211_iotrim_tail(FAR struct ieee80211_iobuf_s *iob, unsigned int trimlen)
{
  FAR struct ieee80211_iobuf_s *entry;
  FAR struct ieee80211_iobuf_s *penultimate;
  FAR struct ieee80211_iobuf_s *last;
  unsigned int iosize;
  int len;

  if (iob && trimlen > 0)
    {
      len = trimlen;

      /* Loop until complete the trim */

      while (len > 0)
        {
          /* Calculate the total length of the data in the I/O buffer
           * chain and find the last entry in the chain.
           */

          penultimate = NULL;
          last = NULL;
          iosize = 0;

          for (entry = iob;
               entry;
               entry = (FAR struct ieee80211_iobuf_s *)entry->m_link.flink)
            {
              /* Accumulate the total size of all buffers in the list */

              iosize += entry->m_len;

              /* Remember the last and the next to the last in the chain */

              penultimate = last;
              last = entry;
            }

          /* Trim from the last entry in the chain.  Do we trim this entire
           * I/O buffer away?
           */

          if (last->m_len <= len)
            {
              /* Yes.. just set is length to zero and skip to the next */

              len -= last->m_len;
              last->m_len = 0;

              /* There should be a buffer before this one */

              if (!penultimate)
                {
                  return;
                }

              /* Free the last, empty buffer in the list */

              ieee80211_iofree(last);
              penultimate->m_link.flink = NULL;
            }
               
          else
            {
              /* No, then just take what we need from this I/O buffer and
               * stop the trim.
               */

              last->m_len -= len;
              memcpy(last->m_data, &last->m_data[len], last->m_len);
              len = 0;
            }
        }
    }
}
