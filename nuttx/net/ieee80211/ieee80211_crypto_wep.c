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

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/kernel.h>
#include <sys/socket.h>
#include <sys/endian.h>

#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_media.h>
#include <net/if_arp.h>

#ifdef CONFIG_NET_ETHERNET
#include <netinet/in.h>
#include <nuttx/net/uip/uip.h>
#endif

#include <nuttx/net/ieee80211/ieee80211_var.h>
#include <nuttx/net/ieee80211/ieee80211_crypto.h>

#include <dev/rndvar.h>
#include <crypto/arc4.h>

/* WEP software crypto context */

struct ieee80211_wep_ctx
{
  struct rc4_ctx    rc4;
  uint32_t    iv;
};

/*
 * Initialize software crypto context.  This function can be overridden
 * by drivers doing hardware crypto.
 */
int
ieee80211_wep_set_key(struct ieee80211com *ic, struct ieee80211_key *k)
{
    struct ieee80211_wep_ctx *ctx;

    ctx = malloc(sizeof(*ctx), M_DEVBUF, M_NOWAIT | M_ZERO);
    if (ctx == NULL)
        return ENOMEM;
    k->k_priv = ctx;
    return 0;
}

void
ieee80211_wep_delete_key(struct ieee80211com *ic, struct ieee80211_key *k)
{
    if (k->k_priv != NULL)
        free(k->k_priv, M_DEVBUF);
    k->k_priv = NULL;
}

/* shortcut */
#define IEEE80211_WEP_HDRLEN    \
    (IEEE80211_WEP_IVLEN + IEEE80211_WEP_KIDLEN)

struct ieee80211_iobuf *ieee80211_wep_encrypt(struct ieee80211com *ic, struct ieee80211_iobuf *m0,
    struct ieee80211_key *k)
{
    struct ieee80211_wep_ctx *ctx = k->k_priv;
    uint8_t wepseed[16];
    const struct ieee80211_frame *wh;
    struct ieee80211_iobuf *n0, *m, *n;
    uint8_t *ivp, *icvp;
    uint32_t iv, crc;
    int left, moff, noff, len, hdrlen;

    MGET(n0, M_DONTWAIT, m0->m_type);
    if (n0 == NULL)
        goto nospace;
    if (m_dup_pkthdr(n0, m0, M_DONTWAIT))
        goto nospace;
    n0->m_pktlen += IEEE80211_WEP_HDRLEN;
    n0->m_len = MHLEN;
    if (n0->m_pktlen >= MINCLSIZE - IEEE80211_WEP_CRCLEN) {
        MCLGET(n0, M_DONTWAIT);
        if (n0->m_flags & M_EXT)
            n0->m_len = n0->m_ext.ext_size;
    }
    if (n0->m_len > n0->m_pktlen)
        n0->m_len = n0->m_pktlen;

    /* copy 802.11 header */
    wh = mtod(m0, struct ieee80211_frame *);
    hdrlen = ieee80211_get_hdrlen(wh);
    memcpy(mtod(n0, void *), wh, hdrlen);

    /* select a new IV for every MPDU */
    iv = (ctx->iv != 0) ? ctx->iv : arc4random();
    /* skip weak IVs from Fluhrer/Mantin/Shamir */
    if (iv >= 0x03ff00 && (iv & 0xf8ff00) == 0x00ff00)
        iv += 0x000100;
    ctx->iv = iv + 1;
    ivp = mtod(n0, uint8_t *) + hdrlen;
    ivp[0] = iv;
    ivp[1] = iv >> 8;
    ivp[2] = iv >> 16;
    ivp[3] = k->k_id << 6;

    /* compute WEP seed: concatenate IV and WEP Key */
    memcpy(wepseed, ivp, IEEE80211_WEP_IVLEN);
    memcpy(wepseed + IEEE80211_WEP_IVLEN, k->k_key, k->k_len);
    rc4_keysetup(&ctx->rc4, wepseed, IEEE80211_WEP_IVLEN + k->k_len);

    /* encrypt frame body and compute WEP ICV */
    m = m0;
    n = n0;
    moff = hdrlen;
    noff = hdrlen + IEEE80211_WEP_HDRLEN;
    left = m0->m_pktlen - moff;
    crc = ~0;
    while (left > 0)
      {
        if (moff == m->m_len)
          {
            /* Nothing left to copy from m */

            m = (struct ieee80211_iobuf *)m->m_link.flink;
            moff = 0;
          }

        if (noff == n->m_len)
          {
            /* n is full and there's more data to copy */

            MGET((struct ieee80211_iobuf *)n->m_link.flink, M_DONTWAIT, n->m_type);
            if (n->m_link.flink == NULL)
              {
                goto nospace;
              }

            n = (struct ieee80211_iobuf *)n->m_link.flink;
            n->m_len = MLEN;
            if (left >= MINCLSIZE - IEEE80211_WEP_CRCLEN) {
                MCLGET(n, M_DONTWAIT);
                if (n->m_flags & M_EXT)
                    n->m_len = n->m_ext.ext_size;
            }
            if (n->m_len > left)
                n->m_len = left;
            noff = 0;
        }
        len = min(m->m_len - moff, n->m_len - noff);

        crc = ether_crc32_le_update(crc, mtod(m, void *) + moff, len);
        rc4_crypt(&ctx->rc4, mtod(m, void *) + moff,
            mtod(n, void *) + noff, len);

        moff += len;
        noff += len;
        left -= len;
    }

    /* reserve trailing space for WEP ICV */

    if (M_TRAILINGSPACE(n) < IEEE80211_WEP_CRCLEN)
      {
        MGET((struct ieee80211_iobuf *)n->m_link.flink, M_DONTWAIT, n->m_type);
        if (n->m_link.flink == NULL)
          {
            goto nospace;
          }

        n = (struct ieee80211_iobuf *)n->m_link.flink;
        n->m_len = 0;
    }

    /* finalize WEP ICV */
    icvp = mtod(n, void *) + n->m_len;
    crc = ~crc;
    icvp[0] = crc;
    icvp[1] = crc >> 8;
    icvp[2] = crc >> 16;
    icvp[3] = crc >> 24;
    rc4_crypt(&ctx->rc4, icvp, icvp, IEEE80211_WEP_CRCLEN);
    n->m_len += IEEE80211_WEP_CRCLEN;
    n0->m_pktlen += IEEE80211_WEP_CRCLEN;

    m_freem(m0);
    return n0;
 nospace:
    ic->ic_stats.is_tx_nombuf++;
    m_freem(m0);
    if (n0 != NULL)
        m_freem(n0);
    return NULL;
}

struct ieee80211_iobuf *ieee80211_wep_decrypt(struct ieee80211com *ic, struct ieee80211_iobuf *m0,
    struct ieee80211_key *k)
{
    struct ieee80211_wep_ctx *ctx = k->k_priv;
    struct ieee80211_frame *wh;
    uint8_t wepseed[16];
    uint32_t crc, crc0;
    uint8_t *ivp;
    struct ieee80211_iobuf *n0, *m, *n;
    int hdrlen, left, moff, noff, len;

    wh = mtod(m0, struct ieee80211_frame *);
    hdrlen = ieee80211_get_hdrlen(wh);

    if (m0->m_pktlen < hdrlen + IEEE80211_WEP_TOTLEN) {
        m_freem(m0);
        return NULL;
    }

    /* concatenate IV and WEP Key */
    ivp = (uint8_t *)wh + hdrlen;
    memcpy(wepseed, ivp, IEEE80211_WEP_IVLEN);
    memcpy(wepseed + IEEE80211_WEP_IVLEN, k->k_key, k->k_len);
    rc4_keysetup(&ctx->rc4, wepseed, IEEE80211_WEP_IVLEN + k->k_len);

    MGET(n0, M_DONTWAIT, m0->m_type);
    if (n0 == NULL)
        goto nospace;
    if (m_dup_pkthdr(n0, m0, M_DONTWAIT))
        goto nospace;
    n0->m_pktlen -= IEEE80211_WEP_TOTLEN;
    n0->m_len = MHLEN;
    if (n0->m_pktlen >= MINCLSIZE) {
        MCLGET(n0, M_DONTWAIT);
        if (n0->m_flags & M_EXT)
            n0->m_len = n0->m_ext.ext_size;
    }
    if (n0->m_len > n0->m_pktlen)
        n0->m_len = n0->m_pktlen;

    /* copy 802.11 header and clear protected bit */
    memcpy(mtod(n0, void *), wh, hdrlen);
    wh = mtod(n0, struct ieee80211_frame *);
    wh->i_fc[1] &= ~IEEE80211_FC1_PROTECTED;

    /* decrypt frame body and compute WEP ICV */
    m = m0;
    n = n0;
    moff = hdrlen + IEEE80211_WEP_HDRLEN;
    noff = hdrlen;
    left = n0->m_pktlen - noff;
    crc = ~0;
    while (left > 0)
      {
        if (moff == m->m_len)
          {
            /* Nothing left to copy from m */

            m =(struct ieee80211_iobuf *) m->m_link.flink;
            moff = 0;
          }

        if (noff == n->m_len)
          {
            /* n is full and there's more data to copy */

            MGET((struct ieee80211_iobuf *)n->m_link.flink, M_DONTWAIT, n->m_type);
            if (n->m_link.flink == NULL)
              {
                goto nospace;
              }

            n = (struct ieee80211_iobuf *)n->m_link.flink;
            n->m_len = MLEN;
            if (left >= MINCLSIZE)
              {
                MCLGET(n, M_DONTWAIT);
                if (n->m_flags & M_EXT)
                  {
                    n->m_len = n->m_ext.ext_size;
                  }
              }

            if (n->m_len > left)
                n->m_len = left;
            noff = 0;
        }
        len = min(m->m_len - moff, n->m_len - noff);

        rc4_crypt(&ctx->rc4, mtod(m, void *) + moff,
            mtod(n, void *) + noff, len);
        crc = ether_crc32_le_update(crc, mtod(n, void *) + noff, len);

        moff += len;
        noff += len;
        left -= len;
    }

    /* decrypt ICV and compare it with calculated ICV */
    m_copydata(m, moff, IEEE80211_WEP_CRCLEN, (void *)&crc0);
    rc4_crypt(&ctx->rc4, (void *)&crc0, (void *)&crc0,
        IEEE80211_WEP_CRCLEN);
    crc = ~crc;
    if (crc != letoh32(crc0)) {
        ic->ic_stats.is_rx_decryptcrc++;
        m_freem(m0);
        m_freem(n0);
        return NULL;
    }

    m_freem(m0);
    return n0;
 nospace:
    ic->ic_stats.is_rx_nombuf++;
    m_freem(m0);
    if (n0 != NULL)
        m_freem(n0);
    return NULL;
}
