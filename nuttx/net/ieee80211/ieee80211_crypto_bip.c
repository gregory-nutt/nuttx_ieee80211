/****************************************************************************
 * net/ieee80211/ieee80211_crypto_bip.c
 *
 * This code implements the Broadcast/Multicast Integrity Protocol (BIP)
 * defined in IEEE P802.11w/D7.0 section 8.3.4.
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
#include <nuttx/compiler.h>

#include <sys/socket.h>

#include <string.h>
#include <errno.h>

#include <net/if.h>

#ifdef CONFIG_NET_ETHERNET
#  include <netinet/in.h>
#  include <nuttx/net/uip/uip.h>
#endif

#include <nuttx/kmalloc.h>
#include <nuttx/net/iob.h>
#include <nuttx/net/ieee80211/ieee80211_var.h>
#include <nuttx/net/ieee80211/ieee80211_crypto.h>
#include <nuttx/net/ieee80211/ieee80211_priv.h>

/* BIP software crypto context */

struct ieee80211_bip_ctx
{
    AES_CMAC_CTX    cmac;
};

/* Initialize software crypto context.  This function can be overridden
 * by drivers doing hardware crypto.
 */

int ieee80211_bip_set_key(struct ieee80211_s *ic, struct ieee80211_key *k)
{
  struct ieee80211_bip_ctx *ctx;

  ctx = kmalloc(sizeof(*ctx));
  if (ctx == NULL)
    {
      return -ENOMEM;
    }

  AES_CMAC_SetKey(&ctx->cmac, k->k_key);
  k->k_priv = ctx;
  return 0;
}

void ieee80211_bip_delete_key(struct ieee80211_s *ic, struct ieee80211_key *k)
{
  if (k->k_priv != NULL)
    {
      kfree(k->k_priv);
    }

  k->k_priv = NULL;
}

/* pseudo-header used for BIP MIC computation */
struct ieee80211_bip_frame {
    uint8_t    i_fc[2];
    uint8_t    i_addr1[IEEE80211_ADDR_LEN];
    uint8_t    i_addr2[IEEE80211_ADDR_LEN];
    uint8_t    i_addr3[IEEE80211_ADDR_LEN];
} packed_struct;

struct iob_s *ieee80211_bip_encap(struct ieee80211_s *ic, struct iob_s *iob0,
    struct ieee80211_key *k)
{
    struct ieee80211_bip_ctx *ctx = k->k_priv;
    struct ieee80211_bip_frame aad;
    struct ieee80211_frame *wh;
    uint8_t *mmie, mic[AES_CMAC_DIGEST_LENGTH];
    struct iob_s *iob;

    wh = (FAR struct ieee80211_frame *)iob0->io_data;
    DEBUGASSERT((wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK) == IEEE80211_FC0_TYPE_MGT);

    /* Clear Protected bit from group management frames */

    wh->i_fc[1] &= ~IEEE80211_FC1_PROTECTED;

    /* Construct AAD (additional authenticated data) */

    aad.i_fc[0] = wh->i_fc[0];
    aad.i_fc[1] = wh->i_fc[1] & ~(IEEE80211_FC1_RETRY |
        IEEE80211_FC1_PWR_MGT | IEEE80211_FC1_MORE_DATA);

    /* XXX 11n may require clearing the Order bit too */

    IEEE80211_ADDR_COPY(aad.i_addr1, wh->i_addr1);
    IEEE80211_ADDR_COPY(aad.i_addr2, wh->i_addr2);
    IEEE80211_ADDR_COPY(aad.i_addr3, wh->i_addr3);

    AES_CMAC_Init(&ctx->cmac);
    AES_CMAC_Update(&ctx->cmac, (uint8_t *)&aad, sizeof aad);
    AES_CMAC_Update(&ctx->cmac, (uint8_t *)&wh[1],
        iob0->io_len - sizeof(*wh));

    iob = iob0;

    /* Reserve trailing space for MMIE */

    if (M_TRAILINGSPACE(iob) < IEEE80211_MMIE_LEN)
      {
        struct iob_s *newbuf;

        newbuf = iob_alloc();
        if (iob->io_link.flink == NULL)
          {
            goto nospace;
          }

        iob->io_link.flink = (sq_entry_t *)newbuf;
        iob = newbuf;
        iob->io_len = 0;
      }

    /* construct Management MIC IE */

    mmie    = (FAR uint8_t *)iob->io_data + iob->io_len;
    mmie[0] = IEEE80211_ELEMID_MMIE;
    mmie[1] = 16;
    LE_WRITE_2(&mmie[2], k->k_id);
    LE_WRITE_6(&mmie[4], k->k_tsc);
    memset(&mmie[10], 0, 8);    /* MMIE MIC field set to 0 */

    AES_CMAC_Update(&ctx->cmac, mmie, IEEE80211_MMIE_LEN);
    AES_CMAC_Final(mic, &ctx->cmac);
    /* truncate AES-128-CMAC to 64-bit */
    memcpy(&mmie[10], mic, 8);

    iob->io_len += IEEE80211_MMIE_LEN;
    iob0->io_pktlen += IEEE80211_MMIE_LEN;

    k->k_tsc++;

    return iob0;
 nospace:
    ic->ic_stats.is_tx_nombuf++;
    iob_free(iob0);
    return NULL;
}

struct iob_s *ieee80211_bip_decap(struct ieee80211_s *ic, struct iob_s *iob0,
    struct ieee80211_key *k)
{
    struct ieee80211_bip_ctx *ctx = k->k_priv;
    struct ieee80211_frame *wh;
    struct ieee80211_bip_frame aad;
    uint8_t *mmie, mic0[8], mic[AES_CMAC_DIGEST_LENGTH];
    uint64_t ipn;

    wh = (FAR struct ieee80211_frame *)iob0->io_data;
    DEBUGASSERT((wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK) == IEEE80211_FC0_TYPE_MGT);

    /* It is assumed that management frames are contiguous and that
     * the buffer length has already been checked to contain at least
     * a header and a MMIE (checked in ieee80211_decrypt()).
     */

    DEBUGASSERT(iob0->io_len >= sizeof(*wh) + IEEE80211_MMIE_LEN);
    mmie = (FAR uint8_t *)iob0->io_data + iob0->io_len - IEEE80211_MMIE_LEN;

    ipn = LE_READ_6(&mmie[4]);
    if (ipn <= k->k_mgmt_rsc)
      {
        /* Replayed frame, discard */

        ic->ic_stats.is_cmac_replays++;
        iob_free(iob0);
        return NULL;
      }

    /* Save and mask MMIE MIC field to 0 */

    memcpy(mic0, &mmie[10], 8);
    memset(&mmie[10], 0, 8);

    /* Construct AAD (additional authenticated data) */

    aad.i_fc[0] = wh->i_fc[0];
    aad.i_fc[1] = wh->i_fc[1] & ~(IEEE80211_FC1_RETRY |
        IEEE80211_FC1_PWR_MGT | IEEE80211_FC1_MORE_DATA);
    /* XXX 11n may require clearing the Order bit too */
    IEEE80211_ADDR_COPY(aad.i_addr1, wh->i_addr1);
    IEEE80211_ADDR_COPY(aad.i_addr2, wh->i_addr2);
    IEEE80211_ADDR_COPY(aad.i_addr3, wh->i_addr3);

    /* compute MIC */
    AES_CMAC_Init(&ctx->cmac);
    AES_CMAC_Update(&ctx->cmac, (uint8_t *)&aad, sizeof aad);
    AES_CMAC_Update(&ctx->cmac, (uint8_t *)&wh[1],
        iob0->io_len - sizeof(*wh));
    AES_CMAC_Final(mic, &ctx->cmac);

  /* Check that MIC matches the one in MMIE */

  if (timingsafe_bcmp(mic, mic0, 8) != 0)
    {
      ic->ic_stats.is_cmac_icv_errs++;
      iob_free(iob0);
      return NULL;
    }

  /* There is no need to trim the MMIE from the buffer since it is
   * an information element and will be ignored by upper layers.
   * We do it anyway as it is cheap to do it here and because it
   * may be confused with fixed fields by upper layers.
   */

  iob0 = iob_trimtail(iob0, IEEE80211_MMIE_LEN);

  /* Update last seen packet number (MIC is validated) */

  k->k_mgmt_rsc = ipn;
  return iob0;
}
