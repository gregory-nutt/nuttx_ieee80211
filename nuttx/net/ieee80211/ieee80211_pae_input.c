/****************************************************************************
 * net/ieee80211/ieee80211_pae_input.c
 *
 * This code implements the 4-Way Handshake and Group Key Handshake protocols
 * (both Supplicant and Authenticator Key Receive state machines) defined in
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

#include <string.h>
#include <wdog.h>
#include <errno.h>
#include <debug.h>

#include <net/if.h>

#ifdef CONFIG_NET_ETHERNET
#  include <netinet/in.h>
#  include <nuttx/net/uip/uip.h>
#endif

#include <nuttx/net/arp.h>
#include <nuttx/net/iob.h>
#include <nuttx/net/ieee80211/ieee80211_debug.h>
#include <nuttx/net/ieee80211/ieee80211_ifnet.h>
#include <nuttx/net/ieee80211/ieee80211_var.h>
#include <nuttx/net/ieee80211/ieee80211_priv.h>

void    ieee80211_recv_4way_msg1(struct ieee80211_s *,
        struct ieee80211_eapol_key *, struct ieee80211_node *);
#ifdef CONFIG_IEEE80211_AP
void    ieee80211_recv_4way_msg2(struct ieee80211_s *,
        struct ieee80211_eapol_key *, struct ieee80211_node *,
        const uint8_t *);
#endif
void    ieee80211_recv_4way_msg3(struct ieee80211_s *,
        struct ieee80211_eapol_key *, struct ieee80211_node *);
#ifdef CONFIG_IEEE80211_AP
void    ieee80211_recv_4way_msg4(struct ieee80211_s *,
        struct ieee80211_eapol_key *, struct ieee80211_node *);
void    ieee80211_recv_4way_msg2or4(struct ieee80211_s *,
        struct ieee80211_eapol_key *, struct ieee80211_node *);
#endif
void    ieee80211_recv_rsn_group_msg1(struct ieee80211_s *,
        struct ieee80211_eapol_key *, struct ieee80211_node *);
void    ieee80211_recv_wpa_group_msg1(struct ieee80211_s *,
        struct ieee80211_eapol_key *, struct ieee80211_node *);
#ifdef CONFIG_IEEE80211_AP
void    ieee80211_recv_group_msg2(struct ieee80211_s *,
        struct ieee80211_eapol_key *, struct ieee80211_node *);
void    ieee80211_recv_eapol_key_req(struct ieee80211_s *,
        struct ieee80211_eapol_key *, struct ieee80211_node *);
#endif

/* Process an incoming EAPOL frame.  Notice that we are only interested in
 * EAPOL-Key frames with an IEEE 802.11 or WPA descriptor type.
 */

void ieee80211_eapol_key_input(FAR struct ieee80211_s *ic, FAR struct iob_s *iob,
                               FAR struct ieee80211_node *ni)
{
  FAR struct uip_eth_hdr *ethhdr;
  struct ieee80211_eapol_key *key;
  uint16_t info, desc;
  int totlen;

  ethhdr = (FAR struct uip_eth_hdr *)iob->io_data;
  if (IEEE80211_IS_MULTICAST(ethhdr->dest))
    {
      goto done;
    }

  iob = iob_trimhead(iob, sizeof(struct uip_eth_hdr));
  if (iob->io_pktlen < sizeof(*key))
    {
      goto done;
    }

  if (iob->io_len < sizeof(*key) &&
      (iob = iob_pack(iob)) == NULL)
    {
      goto done;
    }

  key = (FAR struct ieee80211_eapol_key *)iob->io_data;
  if (key->type != EAPOL_KEY)
    {
      goto done;
    }

  if ((ni->ni_rsnprotos == IEEE80211_PROTO_RSN &&
       key->desc != EAPOL_KEY_DESC_IEEE80211) ||
      (ni->ni_rsnprotos == IEEE80211_PROTO_WPA &&
       key->desc != EAPOL_KEY_DESC_WPA))
      goto done;

  /* Check packet body length */

  if (iob->io_pktlen < 4 + BE_READ_2(key->len))
    {
      goto done;
    }

  /* Check key data length */

  totlen = sizeof(*key) + BE_READ_2(key->paylen);
  if (iob->io_pktlen < totlen || totlen > MCLBYTES)
    {
      goto done;
    }

  info = BE_READ_2(key->info);

  /* Discard EAPOL-Key frames with an unknown descriptor version */

  desc = info & EAPOL_KEY_VERSION_MASK;
  if (desc < EAPOL_KEY_DESC_V1 || desc > EAPOL_KEY_DESC_V3)
    {
      goto done;
    }

  if (ieee80211_is_sha256_akm(ni->ni_rsnakms))
    {
      if (desc != EAPOL_KEY_DESC_V3)
        {
          goto done;
        }
    }
  else if (ni->ni_rsncipher == IEEE80211_CIPHER_CCMP ||
           ni->ni_rsngroupcipher == IEEE80211_CIPHER_CCMP)
    {
      if (desc != EAPOL_KEY_DESC_V2)
        {
          goto done;
        }
    }

  /* Make sure the key data field is contiguous */

  if (iob->io_len < totlen && (iob = iob_pack(iob)) == NULL)
    {
      goto done;
    }

  key = (FAR struct ieee80211_eapol_key *)iob->io_data;

  /* Determine message type (see 8.5.3.7) */

  if (info & EAPOL_KEY_REQUEST)
    {
#ifdef CONFIG_IEEE80211_AP
      /* EAPOL-Key Request frame */

      ieee80211_recv_eapol_key_req(ic, key, ni);
#endif
    }
  else if (info & EAPOL_KEY_PAIRWISE)
    {
      /* 4-Way Handshake */

      if (info & EAPOL_KEY_KEYMIC)
        {
          if (info & EAPOL_KEY_KEYACK)
            {
              ieee80211_recv_4way_msg3(ic, key, ni);
            }
#ifdef CONFIG_IEEE80211_AP
          else
            {
              ieee80211_recv_4way_msg2or4(ic, key, ni);
            }
#endif
        }
      else if (info & EAPOL_KEY_KEYACK)
        {
          ieee80211_recv_4way_msg1(ic, key, ni);
        }
    }
  else
    {
      /* Group Key Handshake */

      if (!(info & EAPOL_KEY_KEYMIC))
        {
          goto done;
        }

      if (info & EAPOL_KEY_KEYACK)
        {
          if (key->desc == EAPOL_KEY_DESC_WPA)
            {
              ieee80211_recv_wpa_group_msg1(ic, key, ni);
            }
          else
            {
              ieee80211_recv_rsn_group_msg1(ic, key, ni);
            }
        }

#ifdef CONFIG_IEEE80211_AP
      else
        {
          ieee80211_recv_group_msg2(ic, key, ni);
        }
#endif
    }
 done:
  if (iob != NULL)
    {
      iob_free_chain(iob);
    }
}

/* Process Message 1 of the 4-Way Handshake (sent by Authenticator) */

void ieee80211_recv_4way_msg1(struct ieee80211_s *ic, struct ieee80211_eapol_key *key, struct ieee80211_node *ni)
{
    struct ieee80211_ptk tptk;
    struct ieee80211_pmk *pmk;
    const uint8_t *frm, *efrm;
    const uint8_t *pmkid;

#ifdef CONFIG_IEEE80211_AP
    if (ic->ic_opmode != IEEE80211_M_STA &&
        ic->ic_opmode != IEEE80211_M_IBSS)
        return;
#endif
    if (ni->ni_replaycnt_ok &&
        BE_READ_8(key->replaycnt) <= ni->ni_replaycnt) {
        return;
    }

    /* parse key data field (may contain an encapsulated PMKID) */
    frm = (const uint8_t *)&key[1];
    efrm = frm + BE_READ_2(key->paylen);

    pmkid = NULL;
    while (frm + 2 <= efrm) {
        if (frm + 2 + frm[1] > efrm)
            break;
        switch (frm[0]) {
        case IEEE80211_ELEMID_VENDOR:
            if (frm[1] < 4)
                break;
            if (memcmp(&frm[2], IEEE80211_OUI, 3) == 0) {
                switch (frm[5]) {
                case IEEE80211_KDE_PMKID:
                    pmkid = frm;
                    break;
                }
            }
            break;
        }
        frm += 2 + frm[1];
    }
    /* check that the PMKID KDE is valid (if present) */
    if (pmkid != NULL && pmkid[1] != 4 + 16)
        return;

    if (ieee80211_is_8021x_akm(ni->ni_rsnakms)) {
        /* retrieve the PMK for this (AP,PMKID) */
        pmk = ieee80211_pmksa_find(ic, ni,
            (pmkid != NULL) ? &pmkid[6] : NULL);
        if (pmk == NULL) {
            ndbg("ERROR: no PMK available for %s\n", ieee80211_addr2str(ni->ni_macaddr));
            return;
        }
        memcpy(ni->ni_pmk, pmk->pmk_key, IEEE80211_PMK_LEN);
    } else    /* use pre-shared key */
        memcpy(ni->ni_pmk, ic->ic_psk, IEEE80211_PMK_LEN);
    ni->ni_flags |= IEEE80211_NODE_PMK;

    /* save authenticator's nonce (ANonce) */
    memcpy(ni->ni_nonce, key->nonce, EAPOL_KEY_NONCE_LEN);

    /* generate supplicant's nonce (SNonce) */
    arc4random_buf(ic->ic_nonce, EAPOL_KEY_NONCE_LEN);

    /* TPTK = CalcPTK(PMK, ANonce, SNonce) */

    ieee80211_derive_ptk(ni->ni_rsnakms, ni->ni_pmk, ni->ni_macaddr,
        ic->ic_myaddr, ni->ni_nonce, ic->ic_nonce, &tptk);

    nvdbg("%s: received msg %d/%d of the %s handshake from %s\n",
          ic->ic_ifname, 1, 4, "4-way", ieee80211_addr2str(ni->ni_macaddr));

    /* Send message 2 to authenticator using TPTK */

    (void)ieee80211_send_4way_msg2(ic, ni, key->replaycnt, &tptk);
}

#ifdef CONFIG_IEEE80211_AP
/*
 * Process Message 2 of the 4-Way Handshake (sent by Supplicant).
 */
void
ieee80211_recv_4way_msg2(struct ieee80211_s *ic,
    struct ieee80211_eapol_key *key, struct ieee80211_node *ni,
    const uint8_t *rsnie)
{
    struct ieee80211_ptk tptk;

    if (ic->ic_opmode != IEEE80211_M_HOSTAP &&
        ic->ic_opmode != IEEE80211_M_IBSS)
        return;

    /* discard if we're not expecting this message */
    if (ni->ni_rsn_state != RSNA_PTKSTART &&
        ni->ni_rsn_state != RSNA_PTKCALCNEGOTIATING) {
        ndbg("ERROR: unexpected in state: %d\n", ni->ni_rsn_state);
        return;
    }
    ni->ni_rsn_state = RSNA_PTKCALCNEGOTIATING;

    /* NB: replay counter has already been verified by caller */

    /* PTK = CalcPTK(ANonce, SNonce) */
    ieee80211_derive_ptk(ni->ni_rsnakms, ni->ni_pmk, ic->ic_myaddr,
        ni->ni_macaddr, ni->ni_nonce, key->nonce, &tptk);

    /* check Key MIC field using KCK */
    if (ieee80211_eapol_key_check_mic(key, tptk.kck) != 0) {
        ndbg("ERROR: key MIC failed\n");
        return;    /* will timeout.. */
    }

    wd_cancel(ni->ni_eapol_to);
    ni->ni_rsn_state = RSNA_PTKCALCNEGOTIATING_2;
    ni->ni_rsn_retries = 0;

    /* install TPTK as PTK now that MIC is verified */
    memcpy(&ni->ni_ptk, &tptk, sizeof(tptk));

    /*
     * The RSN IE must match bit-wise with what the STA included in its
     * (Re)Association Request.
     */
    if (ni->ni_rsnie == NULL || rsnie[1] != ni->ni_rsnie[1] ||
        memcmp(rsnie, ni->ni_rsnie, 2 + rsnie[1]) != 0) {
        IEEE80211_SEND_MGMT(ic, ni, IEEE80211_FC0_SUBTYPE_DEAUTH,
            IEEE80211_REASON_RSN_DIFFERENT_IE);
        ieee80211_node_leave(ic, ni);
        return;
    }

  nvdbg("%s: received msg %d/%d of the %s handshake from %s\n",
        ic->ic_ifname, 2, 4, "4-way", ieee80211_addr2str(ni->ni_macaddr));

  /* Send message 3 to supplicant */

  (void)ieee80211_send_4way_msg3(ic, ni);
}
#endif /* CONFIG_IEEE80211_AP */

/*
 * Process Message 3 of the 4-Way Handshake (sent by Authenticator).
 */
void
ieee80211_recv_4way_msg3(struct ieee80211_s *ic,
    struct ieee80211_eapol_key *key, struct ieee80211_node *ni)
{
    struct ieee80211_ptk tptk;
    struct ieee80211_key *k;
    const uint8_t *frm, *efrm;
    const uint8_t *rsnie1, *rsnie2, *gtk, *igtk;
    uint16_t info, reason = 0;
    int keylen;

#ifdef CONFIG_IEEE80211_AP
    if (ic->ic_opmode != IEEE80211_M_STA &&
        ic->ic_opmode != IEEE80211_M_IBSS)
        return;
#endif
    if (ni->ni_replaycnt_ok &&
        BE_READ_8(key->replaycnt) <= ni->ni_replaycnt) {
        return;
    }
    /* make sure that a PMK has been selected */
    if (!(ni->ni_flags & IEEE80211_NODE_PMK)) {
        ndbg("ERROR: no PMK found for %s\n", ieee80211_addr2str(ni->ni_macaddr));
        return;
    }
    /* check that ANonce matches that of Message 1 */
    if (memcmp(key->nonce, ni->ni_nonce, EAPOL_KEY_NONCE_LEN) != 0) {
        ndbg("ERROR: ANonce does not match msg 1/4\n");
        return;
    }
    /* TPTK = CalcPTK(PMK, ANonce, SNonce) */
    ieee80211_derive_ptk(ni->ni_rsnakms, ni->ni_pmk, ni->ni_macaddr,
        ic->ic_myaddr, key->nonce, ic->ic_nonce, &tptk);

    info = BE_READ_2(key->info);

    /* check Key MIC field using KCK */
    if (ieee80211_eapol_key_check_mic(key, tptk.kck) != 0) {
        ndbg("ERROR: key MIC failed\n");
        return;
    }
    /* install TPTK as PTK now that MIC is verified */
    memcpy(&ni->ni_ptk, &tptk, sizeof(tptk));

    /* if encrypted, decrypt Key Data field using KEK */
    if ((info & EAPOL_KEY_ENCRYPTED) &&
        ieee80211_eapol_key_decrypt(key, ni->ni_ptk.kek) != 0) {
        ndbg("ERROR: decryption failed\n");
        return;
    }

    /* parse key data field */
    frm = (const uint8_t *)&key[1];
    efrm = frm + BE_READ_2(key->paylen);

    /*
     * Some WPA1+WPA2 APs (like hostapd) appear to include both WPA and
     * RSN IEs in message 3/4.  We only take into account the IE of the
     * version of the protocol we negotiated at association time.
     */
    rsnie1 = rsnie2 = gtk = igtk = NULL;
    while (frm + 2 <= efrm) {
        if (frm + 2 + frm[1] > efrm)
            break;
        switch (frm[0]) {
        case IEEE80211_ELEMID_RSN:
            if (ni->ni_rsnprotos != IEEE80211_PROTO_RSN)
                break;
            if (rsnie1 == NULL)
                rsnie1 = frm;
            else if (rsnie2 == NULL)
                rsnie2 = frm;
            /* ignore others if more than two RSN IEs */
            break;
        case IEEE80211_ELEMID_VENDOR:
            if (frm[1] < 4)
                break;
            if (memcmp(&frm[2], IEEE80211_OUI, 3) == 0) {
                switch (frm[5]) {
                case IEEE80211_KDE_GTK:
                    gtk = frm;
                    break;
                case IEEE80211_KDE_IGTK:
                    if (ni->ni_flags & IEEE80211_NODE_MFP)
                        igtk = frm;
                    break;
                }
            } else if (memcmp(&frm[2], MICROSOFT_OUI, 3) == 0) {
                switch (frm[5]) {
                case 1:    /* WPA */
                    if (ni->ni_rsnprotos !=
                        IEEE80211_PROTO_WPA)
                        break;
                    rsnie1 = frm;
                    break;
                }
            }
            break;
        }
        frm += 2 + frm[1];
    }
    /* first WPA/RSN IE is mandatory */
    if (rsnie1 == NULL) {
        ndbg("ERROR: missing RSN IE\n");
        return;
    }
    /* key data must be encrypted if GTK is included */
    if (gtk != NULL && !(info & EAPOL_KEY_ENCRYPTED)) {
        ndbg("ERROR: GTK not encrypted\n");
        return;
    }
    /* GTK KDE must be included if IGTK KDE is present */
    if (igtk != NULL && gtk == NULL) {
        ndbg("ERROR: IGTK KDE found but GTK KDE missing\n");
        return;
    }
    /* check that the Install bit is set if using pairwise keys */
    if (ni->ni_rsncipher != IEEE80211_CIPHER_USEGROUP &&
        !(info & EAPOL_KEY_INSTALL)) {
        ndbg("ERROR: pairwise cipher but !Install\n");
        return;
    }

    /*
     * Check that first WPA/RSN IE is identical to the one received in
     * the beacon or probe response frame.
     */
    if (ni->ni_rsnie == NULL || rsnie1[1] != ni->ni_rsnie[1] ||
        memcmp(rsnie1, ni->ni_rsnie, 2 + rsnie1[1]) != 0) {
        reason = IEEE80211_REASON_RSN_DIFFERENT_IE;
        goto deauth;
    }

    /*
     * If a second RSN information element is present, use its pairwise
     * cipher suite or deauthenticate.
     */
    if (rsnie2 != NULL) {
        struct ieee80211_rsnparams rsn;

        if (ieee80211_parse_rsn(ic, rsnie2, &rsn) == 0) {
            if (rsn.rsn_akms != ni->ni_rsnakms ||
                rsn.rsn_groupcipher != ni->ni_rsngroupcipher ||
                rsn.rsn_nciphers != 1 ||
                !(rsn.rsn_ciphers & ic->ic_rsnciphers)) {
                reason = IEEE80211_REASON_BAD_PAIRWISE_CIPHER;
                goto deauth;
            }
            /* use pairwise cipher suite of second RSN IE */
            ni->ni_rsnciphers = rsn.rsn_ciphers;
            ni->ni_rsncipher = ni->ni_rsnciphers;
        }
    }

    /* update the last seen value of the key replay counter field */

    ni->ni_replaycnt = BE_READ_8(key->replaycnt);
    ni->ni_replaycnt_ok = 1;

    nvdbg("%s: received msg %d/%d of the %s handshake from %s\n",
          ic->ic_ifname, 3, 4, "4-way", ieee80211_addr2str(ni->ni_macaddr));

    /* Send message 4 to authenticator */

    if (ieee80211_send_4way_msg4(ic, ni) != 0)
        return;    /* ..authenticator will retry */

    if (ni->ni_rsncipher != IEEE80211_CIPHER_USEGROUP) {
        uint64_t prsc;

        /* check that key length matches that of pairwise cipher */
        keylen = ieee80211_cipher_keylen(ni->ni_rsncipher);
        if (BE_READ_2(key->keylen) != keylen) {
            reason = IEEE80211_REASON_AUTH_LEAVE;
            goto deauth;
        }
        prsc = (gtk == NULL) ? LE_READ_6(key->rsc) : 0;

        /* map PTK to 802.11 key */
        k = &ni->ni_pairwise_key;
        memset(k, 0, sizeof(*k));
        k->k_cipher = ni->ni_rsncipher;
        k->k_rsc[0] = prsc;
        k->k_len = keylen;
        memcpy(k->k_key, ni->ni_ptk.tk, k->k_len);
        /* install the PTK */
        if ((*ic->ic_set_key)(ic, ni, k) != 0) {
            reason = IEEE80211_REASON_AUTH_LEAVE;
            goto deauth;
        }
        ni->ni_flags &= ~IEEE80211_NODE_TXRXPROT;
        ni->ni_flags |= IEEE80211_NODE_RXPROT;
    }
    if (gtk != NULL) {
        uint8_t kid;

        /* check that key length matches that of group cipher */
        keylen = ieee80211_cipher_keylen(ni->ni_rsngroupcipher);
        if (gtk[1] != 6 + keylen) {
            reason = IEEE80211_REASON_AUTH_LEAVE;
            goto deauth;
        }
        /* map GTK to 802.11 key */
        kid = gtk[6] & 3;
        k = &ic->ic_nw_keys[kid];
        memset(k, 0, sizeof(*k));
        k->k_id = kid;    /* 0-3 */
        k->k_cipher = ni->ni_rsngroupcipher;
        k->k_flags = IEEE80211_KEY_GROUP;
        if (gtk[6] & (1 << 2))
            k->k_flags |= IEEE80211_KEY_TX;
        k->k_rsc[0] = LE_READ_6(key->rsc);
        k->k_len = keylen;
        memcpy(k->k_key, &gtk[8], k->k_len);
        /* install the GTK */
        if ((*ic->ic_set_key)(ic, ni, k) != 0) {
            reason = IEEE80211_REASON_AUTH_LEAVE;
            goto deauth;
        }
    }
    if (igtk != NULL) {    /* implies MFP && gtk != NULL */
        uint16_t kid;

        /* check that the IGTK KDE is valid */
        if (igtk[1] != 4 + 24) {
            reason = IEEE80211_REASON_AUTH_LEAVE;
            goto deauth;
        }
        kid = LE_READ_2(&igtk[6]);
        if (kid != 4 && kid != 5) {
            ndbg("ERROR: unsupported IGTK id %u\n", kid);
            reason = IEEE80211_REASON_AUTH_LEAVE;
            goto deauth;
        }
        /* map IGTK to 802.11 key */
        k = &ic->ic_nw_keys[kid];
        memset(k, 0, sizeof(*k));
        k->k_id = kid;    /* either 4 or 5 */
        k->k_cipher = ni->ni_rsngroupmgmtcipher;
        k->k_flags = IEEE80211_KEY_IGTK;
        k->k_mgmt_rsc = LE_READ_6(&igtk[8]);    /* IPN */
        k->k_len = 16;
        memcpy(k->k_key, &igtk[14], k->k_len);
        /* install the IGTK */
        if ((*ic->ic_set_key)(ic, ni, k) != 0) {
            reason = IEEE80211_REASON_AUTH_LEAVE;
            goto deauth;
        }
    }
    if (info & EAPOL_KEY_INSTALL)
        ni->ni_flags |= IEEE80211_NODE_TXRXPROT;

    if (info & EAPOL_KEY_SECURE) {
        ni->ni_flags |= IEEE80211_NODE_TXRXPROT;
#ifdef CONFIG_IEEE80211_AP
        if (ic->ic_opmode != IEEE80211_M_IBSS ||
            ++ni->ni_key_count == 2)
#endif
        {
            ndbg("ERROR: marking port %s valid\n", ieee80211_addr2str(ni->ni_macaddr));
            ni->ni_port_valid = 1;
            ieee80211_set_link_state(ic, LINKSTATE_UP);
        }
    }
 deauth:
    if (reason != 0) {
        IEEE80211_SEND_MGMT(ic, ni, IEEE80211_FC0_SUBTYPE_DEAUTH,
            reason);
        ieee80211_new_state(ic, IEEE80211_S_SCAN, -1);
    }
}

#ifdef CONFIG_IEEE80211_AP
/*
 * Process Message 4 of the 4-Way Handshake (sent by Supplicant).
 */
void
ieee80211_recv_4way_msg4(struct ieee80211_s *ic,
    struct ieee80211_eapol_key *key, struct ieee80211_node *ni)
{
    if (ic->ic_opmode != IEEE80211_M_HOSTAP &&
        ic->ic_opmode != IEEE80211_M_IBSS)
        return;

    /* discard if we're not expecting this message */
    if (ni->ni_rsn_state != RSNA_PTKINITNEGOTIATING) {
        ndbg("ERROR: unexpected in state: %d\n", ni->ni_rsn_state);
        return;
    }

    /* NB: replay counter has already been verified by caller */

    /* check Key MIC field using KCK */
    if (ieee80211_eapol_key_check_mic(key, ni->ni_ptk.kck) != 0) {
        ndbg("ERROR: key MIC failed\n");
        return;    /* will timeout.. */
    }

    wd_cancel(ni->ni_eapol_to);
    ni->ni_rsn_state = RSNA_PTKINITDONE;
    ni->ni_rsn_retries = 0;

    if (ni->ni_rsncipher != IEEE80211_CIPHER_USEGROUP) {
        struct ieee80211_key *k;

        /* map PTK to 802.11 key */
        k = &ni->ni_pairwise_key;
        memset(k, 0, sizeof(*k));
        k->k_cipher = ni->ni_rsncipher;
        k->k_len = ieee80211_cipher_keylen(k->k_cipher);
        memcpy(k->k_key, ni->ni_ptk.tk, k->k_len);
        /* install the PTK */
        if ((*ic->ic_set_key)(ic, ni, k) != 0) {
            IEEE80211_SEND_MGMT(ic, ni,
                IEEE80211_FC0_SUBTYPE_DEAUTH,
                IEEE80211_REASON_ASSOC_TOOMANY);
            ieee80211_node_leave(ic, ni);
            return;
        }
        ni->ni_flags |= IEEE80211_NODE_TXRXPROT;
    }
    if (ic->ic_opmode != IEEE80211_M_IBSS || ++ni->ni_key_count == 2) {
        ndbg("ERROR: marking port %s valid\n", ieee80211_addr2str(ni->ni_macaddr));
        ni->ni_port_valid = 1;
    }

  nvdbg("%s: received msg %d/%d of the %s handshake from %s\n",
        ic->ic_ifname, 4, 4, "4-way", ieee80211_addr2str(ni->ni_macaddr));

  /* initiate a group key handshake for WPA */

  if (ni->ni_rsnprotos == IEEE80211_PROTO_WPA)
    {
      (void)ieee80211_send_group_msg1(ic, ni);
    }
  else
    {
      ni->ni_rsn_gstate = RSNA_IDLE;
    }
}

/*
 * Differentiate Message 2 from Message 4 of the 4-Way Handshake based on
 * the presence of an RSN or WPA Information Element.
 */
void
ieee80211_recv_4way_msg2or4(struct ieee80211_s *ic,
    struct ieee80211_eapol_key *key, struct ieee80211_node *ni)
{
    const uint8_t *frm, *efrm;
    const uint8_t *rsnie;

    if (BE_READ_8(key->replaycnt) != ni->ni_replaycnt) {
        return;
    }

    /* parse key data field (check if an RSN IE is present) */
    frm = (const uint8_t *)&key[1];
    efrm = frm + BE_READ_2(key->paylen);

    rsnie = NULL;
    while (frm + 2 <= efrm) {
        if (frm + 2 + frm[1] > efrm)
            break;
        switch (frm[0]) {
        case IEEE80211_ELEMID_RSN:
            rsnie = frm;
            break;
        case IEEE80211_ELEMID_VENDOR:
            if (frm[1] < 4)
                break;
            if (memcmp(&frm[2], MICROSOFT_OUI, 3) == 0) {
                switch (frm[5]) {
                case 1:    /* WPA */
                    rsnie = frm;
                    break;
                }
            }
        }
        frm += 2 + frm[1];
    }
    if (rsnie != NULL)
        ieee80211_recv_4way_msg2(ic, key, ni, rsnie);
    else
        ieee80211_recv_4way_msg4(ic, key, ni);
}
#endif /* CONFIG_IEEE80211_AP */

/*
 * Process Message 1 of the RSN Group Key Handshake (sent by Authenticator).
 */
void
ieee80211_recv_rsn_group_msg1(struct ieee80211_s *ic,
    struct ieee80211_eapol_key *key, struct ieee80211_node *ni)
{
    struct ieee80211_key *k;
    const uint8_t *frm, *efrm;
    const uint8_t *gtk, *igtk;
    uint16_t info, kid, reason = 0;
    int keylen;

#ifdef CONFIG_IEEE80211_AP
    if (ic->ic_opmode != IEEE80211_M_STA &&
        ic->ic_opmode != IEEE80211_M_IBSS)
        return;
#endif
    if (BE_READ_8(key->replaycnt) <= ni->ni_replaycnt) {
        return;
    }
    /* check Key MIC field using KCK */
    if (ieee80211_eapol_key_check_mic(key, ni->ni_ptk.kck) != 0) {
        ndbg("ERROR: key MIC failed\n");
        return;
    }
    info = BE_READ_2(key->info);

    /* check that encrypted and decrypt Key Data field using KEK */
    if (!(info & EAPOL_KEY_ENCRYPTED) ||
        ieee80211_eapol_key_decrypt(key, ni->ni_ptk.kek) != 0) {
        ndbg("ERROR: decryption failed\n");
        return;
    }

    /* parse key data field (shall contain a GTK KDE) */
    frm = (const uint8_t *)&key[1];
    efrm = frm + BE_READ_2(key->paylen);

    gtk = igtk = NULL;
    while (frm + 2 <= efrm) {
        if (frm + 2 + frm[1] > efrm)
            break;
        switch (frm[0]) {
        case IEEE80211_ELEMID_VENDOR:
            if (frm[1] < 4)
                break;
            if (memcmp(&frm[2], IEEE80211_OUI, 3) == 0) {
                switch (frm[5]) {
                case IEEE80211_KDE_GTK:
                    gtk = frm;
                    break;
                case IEEE80211_KDE_IGTK:
                    if (ni->ni_flags & IEEE80211_NODE_MFP)
                        igtk = frm;
                    break;
                }
            }
            break;
        }
        frm += 2 + frm[1];
    }
    /* check that the GTK KDE is present */
    if (gtk == NULL) {
        ndbg("ERROR: GTK KDE missing\n");
        return;
    }

    /* check that key length matches that of group cipher */
    keylen = ieee80211_cipher_keylen(ni->ni_rsngroupcipher);
    if (gtk[1] != 6 + keylen)
        return;

    /* map GTK to 802.11 key */
    kid = gtk[6] & 3;
    k = &ic->ic_nw_keys[kid];
    memset(k, 0, sizeof(*k));
    k->k_id = kid;    /* 0-3 */
    k->k_cipher = ni->ni_rsngroupcipher;
    k->k_flags = IEEE80211_KEY_GROUP;
    if (gtk[6] & (1 << 2))
        k->k_flags |= IEEE80211_KEY_TX;
    k->k_rsc[0] = LE_READ_6(key->rsc);
    k->k_len = keylen;
    memcpy(k->k_key, &gtk[8], k->k_len);
    /* install the GTK */
    if ((*ic->ic_set_key)(ic, ni, k) != 0) {
        reason = IEEE80211_REASON_AUTH_LEAVE;
        goto deauth;
    }
    if (igtk != NULL) {    /* implies MFP */
        /* check that the IGTK KDE is valid */
        if (igtk[1] != 4 + 24) {
            reason = IEEE80211_REASON_AUTH_LEAVE;
            goto deauth;
        }
        kid = LE_READ_2(&igtk[6]);
        if (kid != 4 && kid != 5) {
            ndbg("ERROR: unsupported IGTK id %u\n", kid);
            reason = IEEE80211_REASON_AUTH_LEAVE;
            goto deauth;
        }
        /* map IGTK to 802.11 key */
        k = &ic->ic_nw_keys[kid];
        memset(k, 0, sizeof(*k));
        k->k_id = kid;    /* either 4 or 5 */
        k->k_cipher = ni->ni_rsngroupmgmtcipher;
        k->k_flags = IEEE80211_KEY_IGTK;
        k->k_mgmt_rsc = LE_READ_6(&igtk[8]);    /* IPN */
        k->k_len = 16;
        memcpy(k->k_key, &igtk[14], k->k_len);
        /* install the IGTK */
        if ((*ic->ic_set_key)(ic, ni, k) != 0) {
            reason = IEEE80211_REASON_AUTH_LEAVE;
            goto deauth;
        }
    }
    if (info & EAPOL_KEY_SECURE) {
#ifdef CONFIG_IEEE80211_AP
        if (ic->ic_opmode != IEEE80211_M_IBSS ||
            ++ni->ni_key_count == 2)
#endif
        {
            nvdbg("marking port %s valid\n", ieee80211_addr2str(ni->ni_macaddr));
            ni->ni_port_valid = 1;
            ieee80211_set_link_state(ic, LINKSTATE_UP);
        }
    }

  /* Update the last seen value of the key replay counter field */

  ni->ni_replaycnt = BE_READ_8(key->replaycnt);

  nvdbg("%s: received msg %d/%d of the %s handshake from %s\n",
        ic->ic_ifname, 1, 2, "group key", ieee80211_addr2str(ni->ni_macaddr));

  /* Send message 2 to authenticator */

  (void)ieee80211_send_group_msg2(ic, ni, NULL);
  return;

deauth:
  IEEE80211_SEND_MGMT(ic, ni, IEEE80211_FC0_SUBTYPE_DEAUTH, reason);
  ieee80211_new_state(ic, IEEE80211_S_SCAN, -1);
}

/* Process Message 1 of the WPA Group Key Handshake (sent by Authenticator) */

void ieee80211_recv_wpa_group_msg1(struct ieee80211_s *ic,
    struct ieee80211_eapol_key *key, struct ieee80211_node *ni)
{
    struct ieee80211_key *k;
    uint16_t info;
    uint8_t kid;
    int keylen;

#ifdef CONFIG_IEEE80211_AP
    if (ic->ic_opmode != IEEE80211_M_STA &&
        ic->ic_opmode != IEEE80211_M_IBSS)
        return;
#endif
    if (BE_READ_8(key->replaycnt) <= ni->ni_replaycnt) {
        return;
    }
    /* check Key MIC field using KCK */
    if (ieee80211_eapol_key_check_mic(key, ni->ni_ptk.kck) != 0) {
        ndbg("ERROR: key MIC failed\n");
        return;
    }
    /*
     * EAPOL-Key data field is encrypted even though WPA doesn't set
     * the ENCRYPTED bit in the info field.
     */
    if (ieee80211_eapol_key_decrypt(key, ni->ni_ptk.kek) != 0) {
        ndbg("ERROR: decryption failed\n");
        return;
    }

    /* check that key length matches that of group cipher */
    keylen = ieee80211_cipher_keylen(ni->ni_rsngroupcipher);
    if (BE_READ_2(key->keylen) != keylen)
        return;

    /* check that the data length is large enough to hold the key */
    if (BE_READ_2(key->paylen) < keylen)
        return;

    info = BE_READ_2(key->info);

    /* map GTK to 802.11 key */
    kid = (info >> EAPOL_KEY_WPA_KID_SHIFT) & 3;
    k = &ic->ic_nw_keys[kid];
    memset(k, 0, sizeof(*k));
    k->k_id = kid;    /* 0-3 */
    k->k_cipher = ni->ni_rsngroupcipher;
    k->k_flags = IEEE80211_KEY_GROUP;
    if (info & EAPOL_KEY_WPA_TX)
        k->k_flags |= IEEE80211_KEY_TX;
    k->k_rsc[0] = LE_READ_6(key->rsc);
    k->k_len = keylen;
    /* key data field contains the GTK */
    memcpy(k->k_key, &key[1], k->k_len);
    /* install the GTK */
    if ((*ic->ic_set_key)(ic, ni, k) != 0) {
        IEEE80211_SEND_MGMT(ic, ni, IEEE80211_FC0_SUBTYPE_DEAUTH,
            IEEE80211_REASON_AUTH_LEAVE);
        ieee80211_new_state(ic, IEEE80211_S_SCAN, -1);
        return;
    }
    if (info & EAPOL_KEY_SECURE) {
#ifdef CONFIG_IEEE80211_AP
        if (ic->ic_opmode != IEEE80211_M_IBSS ||
            ++ni->ni_key_count == 2)
#endif
        {
            nvdbg("marking port %s valid\n",  ieee80211_addr2str(ni->ni_macaddr));
            ni->ni_port_valid = 1;
            ieee80211_set_link_state(ic, LINKSTATE_UP);
        }
    }

  /* Update the last seen value of the key replay counter field */

  ni->ni_replaycnt = BE_READ_8(key->replaycnt);

  nvdbg("%s: received msg %d/%d of the %s handshake from %s\n",
        ic->ic_ifname, 1, 2, "group key", ieee80211_addr2str(ni->ni_macaddr));

  /* Send message 2 to authenticator */

  (void)ieee80211_send_group_msg2(ic, ni, k);
}

#ifdef CONFIG_IEEE80211_AP
/*
 * Process Message 2 of the Group Key Handshake (sent by Supplicant).
 */
void
ieee80211_recv_group_msg2(struct ieee80211_s *ic,
    struct ieee80211_eapol_key *key, struct ieee80211_node *ni)
{
    if (ic->ic_opmode != IEEE80211_M_HOSTAP &&
        ic->ic_opmode != IEEE80211_M_IBSS)
        return;

    /* discard if we're not expecting this message */
    if (ni->ni_rsn_gstate != RSNA_REKEYNEGOTIATING) {
        ndbg("ERROR: %s: unexpected in state: %d\n", ni->ni_rsn_gstate);
        return;
    }
    if (BE_READ_8(key->replaycnt) != ni->ni_replaycnt) {
        return;
    }
    /* check Key MIC field using KCK */
    if (ieee80211_eapol_key_check_mic(key, ni->ni_ptk.kck) != 0) {
        ndbg("ERROR: key MIC failed\n");
        return;
    }

    wd_cancel(ni->ni_eapol_to);
    ni->ni_rsn_gstate = RSNA_REKEYESTABLISHED;

    if ((ni->ni_flags & IEEE80211_NODE_REKEY) &&
        --ic->ic_rsn_keydonesta == 0)
        ieee80211_setkeysdone(ic);
    ni->ni_flags &= ~IEEE80211_NODE_REKEY;
    ni->ni_flags |= IEEE80211_NODE_TXRXPROT;

    ni->ni_rsn_gstate = RSNA_IDLE;
    ni->ni_rsn_retries = 0;

  nvdbg("%s: received msg %d/%d of the %s handshake from %s\n",
        ic->ic_ifname, 2, 2, "group key", ieee80211_addr2str(ni->ni_macaddr));
}

/* EAPOL-Key Request frames are sent by the supplicant to request that the
 * authenticator initiates either a 4-Way Handshake or Group Key Handshake,
 * or to report a MIC failure in a TKIP MSDU.
 */

void ieee80211_recv_eapol_key_req(struct ieee80211_s *ic,
    struct ieee80211_eapol_key *key, struct ieee80211_node *ni)
{
    uint16_t info;

    if (ic->ic_opmode != IEEE80211_M_HOSTAP &&
        ic->ic_opmode != IEEE80211_M_IBSS)
        return;

    /* enforce monotonicity of key request replay counter */
    if (ni->ni_reqreplaycnt_ok &&
        BE_READ_8(key->replaycnt) <= ni->ni_reqreplaycnt) {
        return;
    }
    info = BE_READ_2(key->info);

    if (!(info & EAPOL_KEY_KEYMIC) ||
        ieee80211_eapol_key_check_mic(key, ni->ni_ptk.kck) != 0) {
        ndbg("ERROR: key request MIC failed\n");
        return;
    }
    /* update key request replay counter now that MIC is verified */
    ni->ni_reqreplaycnt = BE_READ_8(key->replaycnt);
    ni->ni_reqreplaycnt_ok = 1;

    if (info & EAPOL_KEY_ERROR) {    /* TKIP MIC failure */
        /* ignore reports from STAs not using TKIP */
        if (ic->ic_bss->ni_rsngroupcipher != IEEE80211_CIPHER_TKIP &&
            ni->ni_rsncipher != IEEE80211_CIPHER_TKIP) {
            ndbg("ERROR: MIC failure report from !TKIP STA: %s\n", ieee80211_addr2str(ni->ni_macaddr));
            return;
        }
        ieee80211_michael_mic_failure(ic, LE_READ_6(key->rsc));

    } else if (info & EAPOL_KEY_PAIRWISE) {
        /* initiate a 4-Way Handshake */

    } else {
        /*
         * Should change the GTK, initiate the 4-Way Handshake and
         * then execute a Group Key Handshake with all supplicants.
         */
    }
}
#endif /* CONFIG_IEEE80211_AP */
