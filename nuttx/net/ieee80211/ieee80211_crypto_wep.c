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

#include <string.h>
#include <errno.h>

#include <net/if.h>

#ifdef CONFIG_NET_ETHERNET
#  include <netinet/in.h>
#  include <nuttx/net/uip/uip.h>
#endif

#include <nuttx/kmalloc.h>
#include <nuttx/net/ieee80211/ieee80211_ifnet.h>
#include <nuttx/net/ieee80211/ieee80211_crypto.h>
#include <nuttx/net/ieee80211/ieee80211_crypto.h>

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

/* Initialize software crypto context.  This function can be overridden
 * by drivers doing hardware crypto.
 */

int ieee80211_wep_set_key(struct ieee80211com *ic, struct ieee80211_key *k)
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

void ieee80211_wep_delete_key(struct ieee80211com *ic, struct ieee80211_key *k)
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

struct ieee80211_iobuf_s *ieee80211_wep_encrypt(struct ieee80211com *ic, struct ieee80211_iobuf_s *m0,
    struct ieee80211_key *k)
{
    struct ieee80211_wep_ctx *ctx = k->k_priv;
    uint8_t wepseed[16];
    const struct ieee80211_frame *wh;
    struct ieee80211_iobuf_s *next0, *iob, *next;
    uint8_t *ivp, *icvp;
    uint32_t iv, crc;
    int left, moff, noff, len, hdrlen;

    next0 = ieee80211_ioalloc();
    if (next0 == NULL)
      {
        goto nospace;
      }

    if (m_dup_pkthdr(next0, m0, M_DONTWAIT))
      {
        goto nospace;
      }

    next0->m_pktlen += IEEE80211_WEP_HDRLEN;
    next0->m_len = CONFIG_IEEE80211_BUFSIZE;
    if (next0->m_pktlen >= MINCLSIZE - IEEE80211_WEP_CRCLEN)
      {
        MCLGET(next0, M_DONTWAIT);
      }

    if (next0->m_len > next0->m_pktlen)
        next0->m_len = next0->m_pktlen;

    /* Copy 802.11 header */

    wh = (FAR struct ieee80211_frame *)m0->m_data;
    hdrlen = ieee80211_get_hdrlen(wh);
    memcpy(next0->m_data, wh, hdrlen);

    /* Select a new IV for every MPDU */

    iv = (ctx->iv != 0) ? ctx->iv : arc4random();

    /* Skip weak IVs from Fluhrer/Mantin/Shamir */

    if (iv >= 0x03ff00 && (iv & 0xf8ff00) == 0x00ff00)
      {
        iv += 0x000100;
      }

    ctx->iv = iv + 1;
    ivp = (FAR uint8_t *)next0->m_data + hdrlen;
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
    left = m0->m_pktlen - moff;
    crc = ~0;
    while (left > 0)
      {
        if (moff == iob->m_len)
          {
            /* Nothing left to copy from iob */

            iob = (struct ieee80211_iobuf_s *)iob->m_link.flink;
            moff = 0;
          }

        if (noff == next->m_len)
          {
            struct ieee80211_iobuf_s *newbuf;

            /* next is full and there's more data to copy */

            newbuf = ieee80211_ioalloc();
            if (newbuf == NULL)
              {
                goto nospace;
              }

            next->m_link.flink = (sq_entry_t *)newbuf;
            next = newbuf;
            next->m_len = 0;

            if (left >= MINCLSIZE - IEEE80211_WEP_CRCLEN)
              {
                MCLGET(next, M_DONTWAIT);
              }

            if (next->m_len > left)
              {
                next->m_len = left;
              }

            noff = 0;
          }

        len = MIN(iob->m_len - moff, next->m_len - noff);

        crc = ether_crc32_le_update(crc, iob->m_data + moff, len);
        rc4_crypt(&ctx->rc4, iob->m_data + moff, next->m_data + noff, len);

        moff += len;
        noff += len;
        left -= len;
    }

    /* reserve trailing space for WEP ICV */

    if (M_TRAILINGSPACE(next) < IEEE80211_WEP_CRCLEN)
      {
        struct ieee80211_iobuf_s *newbuf;

        newbuf = ieee80211_ioalloc();
        if (newbuf == NULL)
          {
            goto nospace;
          }

        next->m_link.flink = (sq_entry_t *)newbuf;
        next = newbuf;
        next->m_len = 0;
      }

    /* Finalize WEP ICV */

    icvp    = (FAR void *)next->m_data + next->m_len;
    crc     = ~crc;
    icvp[0] = crc;
    icvp[1] = crc >> 8;
    icvp[2] = crc >> 16;
    icvp[3] = crc >> 24;
    rc4_crypt(&ctx->rc4, icvp, icvp, IEEE80211_WEP_CRCLEN);
    next->m_len += IEEE80211_WEP_CRCLEN;
    next0->m_pktlen += IEEE80211_WEP_CRCLEN;

    ieee80211_iofree(m0);
    return next0;
 nospace:
    ic->ic_stats.is_tx_nombuf++;
    ieee80211_iofree(m0);
    if (next0 != NULL)
        ieee80211_iofree(next0);
    return NULL;
}

struct ieee80211_iobuf_s *ieee80211_wep_decrypt(struct ieee80211com *ic, struct ieee80211_iobuf_s *m0,
    struct ieee80211_key *k)
{
    struct ieee80211_wep_ctx *ctx = k->k_priv;
    struct ieee80211_frame *wh;
    uint8_t wepseed[16];
    uint32_t crc, crc0;
    uint8_t *ivp;
    struct ieee80211_iobuf_s *next0, *iob, *next;
    int hdrlen, left, moff, noff, len;

    wh = (FAR struct ieee80211_frame *)m0->m_data;
    hdrlen = ieee80211_get_hdrlen(wh);

    if (m0->m_pktlen < hdrlen + IEEE80211_WEP_TOTLEN)
      {
        ieee80211_iofree(m0);
        return NULL;
      }

    /* Concatenate IV and WEP Key */

    ivp = (uint8_t *)wh + hdrlen;
    memcpy(wepseed, ivp, IEEE80211_WEP_IVLEN);
    memcpy(wepseed + IEEE80211_WEP_IVLEN, k->k_key, k->k_len);
    rc4_keysetup(&ctx->rc4, wepseed, IEEE80211_WEP_IVLEN + k->k_len);

    next0 = ieee80211_ioalloc();
    if (next0 == NULL)
      {
        goto nospace;
      }

    if (m_dup_pkthdr(next0, m0, M_DONTWAIT))
      {
        goto nospace;
      }

    next0->m_pktlen -= IEEE80211_WEP_TOTLEN;
    next0->m_len = CONFIG_IEEE80211_BUFSIZE;
    if (next0->m_pktlen >= MINCLSIZE)
      {
        MCLGET(next0, M_DONTWAIT);
      }

    if (next0->m_len > next0->m_pktlen)
      {
        next0->m_len = next0->m_pktlen;
      }

    /* Copy 802.11 header and clear protected bit */

    memcpy(next0->m_data, wh, hdrlen);
    wh = (FAR struct ieee80211_frame *)next0->m_data;
    wh->i_fc[1] &= ~IEEE80211_FC1_PROTECTED;

    /* Decrypt frame body and compute WEP ICV */

    iob = m0;
    next = next0;
    moff = hdrlen + IEEE80211_WEP_HDRLEN;
    noff = hdrlen;
    left = next0->m_pktlen - noff;
    crc = ~0;
    while (left > 0)
      {
        if (moff == iob->m_len)
          {
            /* Nothing left to copy from iob */

            iob =(struct ieee80211_iobuf_s *) iob->m_link.flink;
            moff = 0;
          }

        if (noff == next->m_len)
          {
            struct ieee80211_iobuf_s *newbuf;

            /* next is full and there's more data to copy */

            newbuf = ieee80211_ioalloc();
            if (newbuf == NULL)
              {
                goto nospace;
              }

            next->m_link.flink = (sq_entry_t *)newbuf;
            next = newbuf;
            next->m_len = 0;

            if (left >= MINCLSIZE)
              {
                MCLGET(next, M_DONTWAIT);
              }

            if (next->m_len > left)
              {
                next->m_len = left;
              }

            noff = 0;
        }

        len = MIN(iob->m_len - moff, next->m_len - noff);

        rc4_crypt(&ctx->rc4, iob->m_data + moff, next->m_data + noff, len);
        crc = ether_crc32_le_update(crc, next->m_data + noff, len);

        moff += len;
        noff += len;
        left -= len;
    }

    /* decrypt ICV and compare it with calculated ICV */
    ieee80211_iocpy(iob, moff, IEEE80211_WEP_CRCLEN, (void *)&crc0);
    rc4_crypt(&ctx->rc4, (void *)&crc0, (void *)&crc0,
        IEEE80211_WEP_CRCLEN);
    crc = ~crc;
    if (crc != letoh32(crc0)) {
        ic->ic_stats.is_rx_decryptcrc++;
        ieee80211_iofree(m0);
        ieee80211_iofree(next0);
        return NULL;
    }

    ieee80211_iofree(m0);
    return next0;
 nospace:
    ic->ic_stats.is_rx_nombuf++;
    ieee80211_iofree(m0);
    if (next0 != NULL)
        ieee80211_iofree(next0);
    return NULL;
}
