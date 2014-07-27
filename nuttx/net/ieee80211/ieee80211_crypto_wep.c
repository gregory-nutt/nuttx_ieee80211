/****************************************************************************
 * net/ieee80211/ieee80211_cryto_wep.c
 *
 * This code implements Wired Equivalent Privacy (WEP) defined in
 * IEEE Std 802.11-2007 section 8.2.1.
 *
 * Copyright (c) 2008 Damien Bergamini <damien.bergamini@free.fr>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 ****************************************************************************/

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <nuttx/config.h>

#include <sys/socket.h>

#include <stdbool.h>
#include <string.h>
#include <errno.h>

#include <net/if.h>

#ifdef CONFIG_NET_ETHERNET
#  include <netinet/in.h>
#  include <nuttx/net/uip/uip.h>
#endif

#include <nuttx/kmalloc.h>
#include <nuttx/net/iob.h>

#include "ieee80211/ieee80211_crypto.h"
#include "ieee80211/ieee80211_crypto.h"

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

#ifndef MIN
#  define MIN(a,b) ((a) < (b) ? (a) : (b))
#endif

/****************************************************************************
 * Private Types
 ****************************************************************************/

/* WEP software crypto context */

struct ieee80211_wep_ctx
{
  struct rc4_ctx    rc4;
  uint32_t    iv;
};

/****************************************************************************
 * Private Functions
 ****************************************************************************/

/* Initialize software crypto context.  This function can be overridden
 * by drivers doing hardware crypto.
 */

int ieee80211_wep_set_key(struct ieee80211_s *ic, struct ieee80211_key *k)
{
  struct ieee80211_wep_ctx *ctx;

  ctx = kmalloc(sizeof(struct ieee80211_wep_ctx));
  if (ctx == NULL)
    {
      return -ENOMEM;
    }

  k->k_priv = ctx;
  return 0;
}

void ieee80211_wep_delete_key(struct ieee80211_s *ic, struct ieee80211_key *k)
{
  if (k->k_priv != NULL)
    {
      kfree(k->k_priv);
    }

  k->k_priv = NULL;
}

/* shortcut */
#define IEEE80211_WEP_HDRLEN    \
    (IEEE80211_WEP_IVLEN + IEEE80211_WEP_KIDLEN)

struct iob_s *ieee80211_wep_encrypt(struct ieee80211_s *ic, struct iob_s *m0,
    struct ieee80211_key *k)
{
    struct ieee80211_wep_ctx *ctx = k->k_priv;
    uint8_t wepseed[16];
    const struct ieee80211_frame *wh;
    struct iob_s *next0, *iob, *next;
    uint8_t *ivp, *icvp;
    uint32_t iv, crc;
    int left, moff, noff, len, hdrlen;

    next0 = iob_alloc(false);
    if (next0 == NULL)
      {
        goto nospace;
      }

    if (iob_clone(next0, m0) < 0)
      {
        goto nospace;
      }

    next0->io_pktlen += IEEE80211_WEP_HDRLEN;
    next0->io_len = CONFIG_IEEE80211_BUFSIZE;

    if (next0->io_len > next0->io_pktlen)
      {
        next0->io_len = next0->io_pktlen;
      }

    /* Copy 802.11 header */

    wh = (FAR struct ieee80211_frame *)IOB_DATA(m0);
    hdrlen = ieee80211_get_hdrlen(wh);
    memcpy(IOB_DATA(next0), wh, hdrlen);

    /* Select a new IV for every MPDU */

    iv = (ctx->iv != 0) ? ctx->iv : arc4random();

    /* Skip weak IVs from Fluhrer/Mantin/Shamir */

    if (iv >= 0x03ff00 && (iv & 0xf8ff00) == 0x00ff00)
      {
        iv += 0x000100;
      }

    ctx->iv = iv + 1;
    ivp = (FAR uint8_t *)IOB_DATA(next0) + hdrlen;
    ivp[0] = iv;
    ivp[1] = iv >> 8;
    ivp[2] = iv >> 16;
    ivp[3] = k->k_id << 6;

    /* compute WEP seed: concatenate IV and WEP Key */
    memcpy(wepseed, ivp, IEEE80211_WEP_IVLEN);
    memcpy(wepseed + IEEE80211_WEP_IVLEN, k->k_key, k->k_len);
    rc4_keysetup(&ctx->rc4, wepseed, IEEE80211_WEP_IVLEN + k->k_len);

    /* encrypt frame body and compute WEP ICV */
    iob = m0;
    next = next0;
    moff = hdrlen;
    noff = hdrlen + IEEE80211_WEP_HDRLEN;
    left = m0->io_pktlen - moff;
    crc = ~0;
    while (left > 0)
      {
        if (moff == iob->io_len)
          {
            /* Nothing left to copy from iob */

            iob  = iob->io_flink;
            moff = 0;
          }

        if (noff == next->io_len)
          {
            struct iob_s *newbuf;

            /* next is full and there's more data to copy */

            newbuf = iob_alloc(false);
            if (newbuf == NULL)
              {
                goto nospace;
              }

            next->io_flink = newbuf;
            next = newbuf;
            next->io_len = 0;

            if (next->io_len > left)
              {
                next->io_len = left;
              }

            noff = 0;
          }

        len = MIN(iob->io_len - moff, next->io_len - noff);

        crc = ether_crc32_le_update(crc, IOB_DATA(iob) + moff, len);
        rc4_crypt(&ctx->rc4, IOB_DATA(iob) + moff, IOB_DATA(next) + noff, len);

        moff += len;
        noff += len;
        left -= len;
    }

    /* reserve trailing space for WEP ICV */

    if (IOB_FREESPACE(next) < IEEE80211_WEP_CRCLEN)
      {
        struct iob_s *newbuf;

        newbuf = iob_alloc(false);
        if (newbuf == NULL)
          {
            goto nospace;
          }

        next->io_flink = newbuf;
        next = newbuf;
        next->io_len = 0;
      }

    /* Finalize WEP ICV */

    icvp    = (FAR void *)IOB_DATA(next) + next->io_len;
    crc     = ~crc;
    icvp[0] = crc;
    icvp[1] = crc >> 8;
    icvp[2] = crc >> 16;
    icvp[3] = crc >> 24;
    rc4_crypt(&ctx->rc4, icvp, icvp, IEEE80211_WEP_CRCLEN);
    next->io_len += IEEE80211_WEP_CRCLEN;
    next0->io_pktlen += IEEE80211_WEP_CRCLEN;

  iob_free_chain(m0);
  return next0;

nospace:
  iob_free_chain(m0);
  if (next0 != NULL)
    {
      iob_free_chain(next0);
    }

  return NULL;
}

struct iob_s *ieee80211_wep_decrypt(struct ieee80211_s *ic, struct iob_s *m0,
    struct ieee80211_key *k)
{
    struct ieee80211_wep_ctx *ctx = k->k_priv;
    struct ieee80211_frame *wh;
    uint8_t wepseed[16];
    uint32_t crc, crc0;
    uint8_t *ivp;
    struct iob_s *next0, *iob, *next;
    int hdrlen, left, moff, noff, len;

    wh = (FAR struct ieee80211_frame *)IOB_DATA(m0);
    hdrlen = ieee80211_get_hdrlen(wh);

    if (m0->io_pktlen < hdrlen + IEEE80211_WEP_TOTLEN)
      {
        iob_free_chain(m0);
        return NULL;
      }

    /* Concatenate IV and WEP Key */

    ivp = (uint8_t *)wh + hdrlen;
    memcpy(wepseed, ivp, IEEE80211_WEP_IVLEN);
    memcpy(wepseed + IEEE80211_WEP_IVLEN, k->k_key, k->k_len);
    rc4_keysetup(&ctx->rc4, wepseed, IEEE80211_WEP_IVLEN + k->k_len);

    next0 = iob_alloc(false);
    if (next0 == NULL)
      {
        goto nospace;
      }

    if (iob_clone(next0, m0) < 0)
      {
        goto nospace;
      }

    next0->io_pktlen -= IEEE80211_WEP_TOTLEN;
    next0->io_len = CONFIG_IEEE80211_BUFSIZE;

    if (next0->io_len > next0->io_pktlen)
      {
        next0->io_len = next0->io_pktlen;
      }

    /* Copy 802.11 header and clear protected bit */

    memcpy(IOB_DATA(next0), wh, hdrlen);
    wh = (FAR struct ieee80211_frame *)IOB_DATA(next0);
    wh->i_fc[1] &= ~IEEE80211_FC1_PROTECTED;

    /* Decrypt frame body and compute WEP ICV */

    iob = m0;
    next = next0;
    moff = hdrlen + IEEE80211_WEP_HDRLEN;
    noff = hdrlen;
    left = next0->io_pktlen - noff;
    crc = ~0;
    while (left > 0)
      {
        if (moff == iob->io_len)
          {
            /* Nothing left to copy from iob */

            iob  = iob->io_flink;
            moff = 0;
          }

        if (noff == next->io_len)
          {
            struct iob_s *newbuf;

            /* next is full and there's more data to copy */

            newbuf = iob_alloc(false);
            if (newbuf == NULL)
              {
                goto nospace;
              }

            next->io_flink = newbuf;
            next = newbuf;
            next->io_len = 0;

            if (next->io_len > left)
              {
                next->io_len = left;
              }

            noff = 0;
        }

        len = MIN(iob->io_len - moff, next->io_len - noff);

        rc4_crypt(&ctx->rc4, IOB_DATA(iob) + moff, IOB_DATA(next) + noff, len);
        crc = ether_crc32_le_update(crc, IOB_DATA(next) + noff, len);

        moff += len;
        noff += len;
        left -= len;
    }

    /* Cecrypt ICV and compare it with calculated ICV */

    iob_copyout((FAR uint8_t *)&crc0, iob, moff, IEEE80211_WEP_CRCLEN);
    rc4_crypt(&ctx->rc4, (void *)&crc0, (void *)&crc0, IEEE80211_WEP_CRCLEN);
    crc = ~crc;
    if (crc != letoh32(crc0))
      {
        iob_free_chain(m0);
        iob_free_chain(next0);
        return NULL;
     }

  iob_free_chain(m0);
  return next0;

nospace:
  iob_free_chain(m0);
  if (next0 != NULL)
    {
      iob_free_chain(next0);
    }

  return NULL;
}
