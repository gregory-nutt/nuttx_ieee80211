/****************************************************************************
 * net/mini802/ieee80211_pae_output.c
 *
 * This code implements the 4-Way Handshake and Group Key Handshake protocols
 * (both Supplicant and Authenticator Key Transmit state machines) defined in
 * IEEE Std 802.11-2007 section 8.5.
 *
 * Copyright (c) 2007,2008 Damien Bergamini <damien.bergamini@free.fr>
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
#include <wdog.h>
#include <assert.h>
#include <debug.h>

#include <net/if.h>

#ifdef CONFIG_NET_ETHERNET
#  include <netinet/in.h>
#  include <nuttx/net/uip/uip.h>
#  include <netinet/ip.h>
#endif

#include <nuttx/net/arp.h>
#include <nuttx/net/iob.h>

#include "mini802/ieee80211_debug.h"
#include "mini802/ieee80211_ifnet.h"
#include "mini802/ieee80211_var.h"
#include "mini802/ieee80211_priv.h"

/****************************************************************************
 * Private Function Prototypes
 ****************************************************************************/

static int ieee80211_send_eapol_key(struct ieee80211_s *, struct iob_s *,
                                    struct ieee80211_node *,
                                    const struct ieee80211_ptk *);
static struct iob_s *ieee80211_get_eapol_key(int, unsigned int);

/****************************************************************************
 * Private Functions
 ****************************************************************************/

/* Send an EAPOL-Key frame to node `ni'.  If MIC or encryption is required,
 * the PTK must be passed (otherwise it can be set to NULL.)
 */

static int ieee80211_send_eapol_key(FAR struct ieee80211_s *ic,
                                    FAR struct iob_s *iob,
                                    FAR struct ieee80211_node *ni,
                                    FAR const struct ieee80211_ptk *ptk)
{
  FAR struct uip_eth_hdr *ethhdr;
  struct ieee80211_eapol_key *key;
  uint16_t info;
  uip_lock_t flags;
  int len;
  int error;

  iob_contig(iob, sizeof(struct uip_eth_hdr));
  if (iob == NULL)
    {
      return -ENOMEM;
    }

  /* No need to iob_pack here (ok by construction) */

  ethhdr = (FAR struct uip_eth_hdr * *)IOB_DATA(iob);
  ethhdr->type = htons(UIP_ETHTYPE_PAE);
  IEEE80211_ADDR_COPY(ethhdr->src, ic->ic_myaddr);
  IEEE80211_ADDR_COPY(ethhdr->dest, ni->ni_macaddr);

  key = (struct ieee80211_eapol_key *)&ethhdr[1];
  key->version = EAPOL_VERSION;
  key->type = EAPOL_KEY;
  key->desc =
    (ni->ni_rsnprotos ==
     IEEE80211_PROTO_RSN) ? EAPOL_KEY_DESC_IEEE80211 : EAPOL_KEY_DESC_WPA;

  info = BE_READ_2(key->info);

  /* Use V3 descriptor if KDF is SHA256-based */

  if (ieee80211_is_sha256_akm(ni->ni_rsnakms))
    {
      info |= EAPOL_KEY_DESC_V3;
    }

  /* Use V2 descriptor if pairwise or group cipher is CCMP */

  else if (ni->ni_rsncipher == IEEE80211_CIPHER_CCMP ||
           ni->ni_rsngroupcipher == IEEE80211_CIPHER_CCMP)
    {
      info |= EAPOL_KEY_DESC_V2;
    }
  else
    {
      info |= EAPOL_KEY_DESC_V1;
    }

  BE_WRITE_2(key->info, info);

  len = iob->io_len - sizeof(struct uip_eth_hdr);
  BE_WRITE_2(key->paylen, len - sizeof(*key));
  BE_WRITE_2(key->len, len - 4);

  if (info & EAPOL_KEY_KEYMIC)
    {
      ieee80211_eapol_key_mic(key, ptk->kck);
    }

  len = iob->io_pktlen;
  flags = uip_lock();

  error = ieee80211_ifsend(ic, iob, 0);
  uip_unlock(flags);
  return error;
}

static FAR struct iob_s *ieee80211_get_eapol_key(int type, unsigned int pktlen)
{
  FAR struct iob_s *iob;

  /* Reserve space for 802.11 encapsulation and EAPOL-Key header */

  pktlen += sizeof(struct ieee80211_frame) + LLC_SNAPFRAMELEN +
    sizeof(struct ieee80211_eapol_key);
  DEBUGASSERT(pktlen <= MCLBYTES);

  iob = iob_alloc(false);
  if (iob == NULL)
    {
      return NULL;
    }

  if (pktlen > CONFIG_IEEE80211_BUFSIZE)
    {
      return iob_free(iob);
    }

  io->len = sizeof(struct ieee80211_frame) + LLC_SNAPFRAMELEN;
  return iob;
}

/* Send 4-Way Handshake Message 2 to the authenticator */

int ieee80211_send_4way_msg2(struct ieee80211_s *ic, struct ieee80211_node *ni,
                             const uint8_t * replaycnt,
                             const struct ieee80211_ptk *tptk)
{
  struct ieee80211_eapol_key *key;
  struct iob_s *iob;
  uint16_t info;
  uint8_t *frm;

  iob = ieee80211_get_eapol_key(MT_DATA,
                                (ni->ni_rsnprotos == IEEE80211_PROTO_WPA) ?
                                2 + IEEE80211_WPAIE_MAXLEN :
                                2 + IEEE80211_RSNIE_MAXLEN);

  if (iob == NULL)
    {
      return -ENOMEM;
    }

  key = (FAR struct ieee80211_eapol_key *)IOB_DATA(iob);
  memset(key, 0, sizeof(*key));

  info = EAPOL_KEY_PAIRWISE | EAPOL_KEY_KEYMIC;
  BE_WRITE_2(key->info, info);

  /* Copy key replay counter from Message 1/4 */

  memcpy(key->replaycnt, replaycnt, 8);

  /* Copy the supplicant's nonce (SNonce) */

  memcpy(key->nonce, ic->ic_nonce, EAPOL_KEY_NONCE_LEN);

  frm = (uint8_t *) & key[1];

  /* Add the WPA/RSN IE used in the (Re)Association Request */

  if (ni->ni_rsnprotos == IEEE80211_PROTO_WPA)
    {
      int keylen;
      frm = ieee80211_add_wpa(frm, ic, ni);

      /* WPA sets the key length field here */

      keylen = ieee80211_cipher_keylen(ni->ni_rsncipher);
      BE_WRITE_2(key->keylen, keylen);
    }
  else
    {
      /* RSN */

      frm = ieee80211_add_rsn(frm, ic, ni);
    }

  iob->io_pktlen = iob->io_len = frm - (uint8_t *) key;

  nvdbg("%s: sending msg %d/%d of the %s handshake to %s\n",
        ic->ic_ifname, 2, 4, "4-way", ieee80211_addr2str(ni->ni_macaddr));

  return ieee80211_send_eapol_key(ic, iob, ni, tptk);
}

/* Send 4-Way Handshake Message 4 to the authenticator */

int ieee80211_send_4way_msg4(struct ieee80211_s *ic, struct ieee80211_node *ni)
{
  struct ieee80211_eapol_key *key;
  struct iob_s *iob;
  uint16_t info;

  iob = ieee80211_get_eapol_key(MT_DATA, 0);
  if (iob == NULL)
    {
      return -ENOMEM;
    }

  key = (FAR struct ieee80211_eapol_key *)IOB_DATA(iob);
  memset(key, 0, sizeof(*key));

  info = EAPOL_KEY_PAIRWISE | EAPOL_KEY_KEYMIC;

  /* Copy key replay counter from authenticator */

  BE_WRITE_8(key->replaycnt, ni->ni_replaycnt);

  if (ni->ni_rsnprotos == IEEE80211_PROTO_WPA)
    {
      int keylen;

      /* WPA sets the key length field here */

      keylen = ieee80211_cipher_keylen(ni->ni_rsncipher);
      BE_WRITE_2(key->keylen, keylen);
    }
  else
    {
      info |= EAPOL_KEY_SECURE;
    }

  /* Write the key info field */

  BE_WRITE_2(key->info, info);

  /* Empty key data field */

  iob->io_pktlen = iob->io_len = sizeof(*key);

  nvdbg("%s: sending msg %d/%d of the %s handshake to %s\n",
        ic->ic_ifname, 4, 4, "4-way", ieee80211_addr2str(ni->ni_macaddr));

  return ieee80211_send_eapol_key(ic, iob, ni, &ni->ni_ptk);
}

/* Send Group Key Handshake Message 2 to the authenticator */

int ieee80211_send_group_msg2(struct ieee80211_s *ic, struct ieee80211_node *ni,
                              const struct ieee80211_key *k)
{
  struct ieee80211_eapol_key *key;
  uint16_t info;
  struct iob_s *iob;

  iob = ieee80211_get_eapol_key(MT_DATA, 0);
  if (iob == NULL)
    {
      return -ENOMEM;
    }

  key = (FAR struct ieee80211_eapol_key *)IOB_DATA(iob);
  memset(key, 0, sizeof(*key));

  info = EAPOL_KEY_KEYMIC | EAPOL_KEY_SECURE;

  /* Copy key replay counter from authenticator */

  BE_WRITE_8(key->replaycnt, ni->ni_replaycnt);

  if (ni->ni_rsnprotos == IEEE80211_PROTO_WPA)
    {
      /* WPA sets the key length and key id fields here */

      BE_WRITE_2(key->keylen, k->k_len);
      info |= (k->k_id & 3) << EAPOL_KEY_WPA_KID_SHIFT;
    }

  /* Write the key info field */

  BE_WRITE_2(key->info, info);

  /* Empty key data field */

  iob->io_pktlen = iob->io_len = sizeof(*key);

  nvdbg("%s: sending msg %d/%d of the %s handshake to %s\n",
        ic->ic_ifname, 2, 2, "group key", ieee80211_addr2str(ni->ni_macaddr));

  return ieee80211_send_eapol_key(ic, iob, ni, &ni->ni_ptk);
}

/* EAPOL-Key Request frames are sent by the supplicant to request that the
 * authenticator initiates either a 4-Way Handshake or Group Key Handshake,
 * or to report a MIC failure in a TKIP MSDU.
 */

int ieee80211_send_eapol_key_req(FAR struct ieee80211_s *ic,
                                 FAR struct ieee80211_node *ni,
                                 uint16_t info, uint64_t tsc)
{
  FAR struct ieee80211_eapol_key *key;
  FAR struct iob_s *iob;

  iob = ieee80211_get_eapol_key(MT_DATA, 0);
  if (iob == NULL)
    {
      return -ENOMEM;
    }

  key = (FAR struct ieee80211_eapol_key *)IOB_DATA(iob);
  memset(key, 0, sizeof(*key));

  info |= EAPOL_KEY_REQUEST;
  BE_WRITE_2(key->info, info);

  /* in case of TKIP MIC failure, fill the RSC field */

  if (info & EAPOL_KEY_ERROR)
    {
      LE_WRITE_6(key->rsc, tsc);
    }

  /* Use our separate key replay counter for key requests */

  BE_WRITE_8(key->replaycnt, ni->ni_reqreplaycnt);
  ni->ni_reqreplaycnt++;

  nvdbg("%s: sending EAPOL-Key request to %s\n",
        ic->ic_ifname, ieee80211_addr2str(ni->ni_macaddr));

  return ieee80211_send_eapol_key(ic, iob, ni, &ni->ni_ptk);
}
