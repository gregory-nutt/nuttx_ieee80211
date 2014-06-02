/****************************************************************************
 * net/ieee80211/ieee80211_input.c
 *
 * Copyright (c) 2001 Atsushi Onoe
 * Copyright (c) 2002, 2003 Sam Leffler, Errno Consulting
 * Copyright (c) 2007-2009 Damien Bergamini
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 ****************************************************************************/

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <nuttx/config.h>

#include <sys/socket.h>

#include <string.h>
#include <wdog.h>
#include <assert.h>
#include <errno.h>
#include <debug.h>

#include <net/if.h>

#ifdef CONFIG_NET_ETHERNET
#  include <netinet/in.h>
#  include <nuttx/net/uip/uip.h>
#endif

#include <nuttx/kmalloc.h>
#include <nuttx/net/ieee80211/ieee80211_debug.h>
#include <nuttx/net/ieee80211/ieee80211_ifnet.h>
#include <nuttx/net/ieee80211/ieee80211_var.h>
#include <nuttx/net/ieee80211/ieee80211_priv.h>

struct ieee80211_iobuf_s *ieee80211_defrag(struct ieee80211com *, struct ieee80211_iobuf_s *, int);
void ieee80211_defrag_timeout(void *);
#ifdef CONFIG_IEEE80211_HT
void ieee80211_input_ba(struct ieee80211com *, struct ieee80211_iobuf_s *,
        struct ieee80211_node *, int, struct ieee80211_rxinfo *);
void ieee80211_ba_move_window(struct ieee80211com *,
        struct ieee80211_node *, uint8_t, uint16_t);
#endif
struct ieee80211_iobuf_s *ieee80211_align_iobuf(struct ieee80211_iobuf_s *);
void ieee80211_decap(struct ieee80211com *, struct ieee80211_iobuf_s *,
        struct ieee80211_node *, int);
#ifdef CONFIG_IEEE80211_HT
void ieee80211_amsdu_decap(struct ieee80211com *, struct ieee80211_iobuf_s *,
        struct ieee80211_node *, int);
#endif
void ieee80211_deliver_data(struct ieee80211com *, struct ieee80211_iobuf_s *,
        struct ieee80211_node *);
int ieee80211_parse_edca_params_body(struct ieee80211com *,
        const uint8_t *);
int ieee80211_parse_edca_params(struct ieee80211com *, const uint8_t *);
int ieee80211_parse_wmm_params(struct ieee80211com *, const uint8_t *);
enum ieee80211_cipher ieee80211_parse_rsn_cipher(const uint8_t[]);
enum ieee80211_akm ieee80211_parse_rsn_akm(const uint8_t[]);
int ieee80211_parse_rsn_body(struct ieee80211com *, const uint8_t *,
        unsigned int, struct ieee80211_rsnparams *);
int ieee80211_save_ie(const uint8_t *, uint8_t **);
void ieee80211_recv_probe_resp(struct ieee80211com *, struct ieee80211_iobuf_s *,
        struct ieee80211_node *, struct ieee80211_rxinfo *, int);
#ifdef CONFIG_IEEE80211_AP
void ieee80211_recv_probe_req(struct ieee80211com *, struct ieee80211_iobuf_s *,
        struct ieee80211_node *, struct ieee80211_rxinfo *);
#endif
void ieee80211_recv_auth(struct ieee80211com *, struct ieee80211_iobuf_s *,
        struct ieee80211_node *, struct ieee80211_rxinfo *);
#ifdef CONFIG_IEEE80211_AP
void ieee80211_recv_assoc_req(struct ieee80211com *, struct ieee80211_iobuf_s *,
        struct ieee80211_node *, struct ieee80211_rxinfo *, int);
#endif
void ieee80211_recv_assoc_resp(struct ieee80211com *, struct ieee80211_iobuf_s *,
        struct ieee80211_node *, int);
void ieee80211_recv_deauth(struct ieee80211com *, struct ieee80211_iobuf_s *,
        struct ieee80211_node *);
void ieee80211_recv_disassoc(struct ieee80211com *, struct ieee80211_iobuf_s *,
        struct ieee80211_node *);
#ifdef CONFIG_IEEE80211_HT
void ieee80211_recv_addba_req(struct ieee80211com *, struct ieee80211_iobuf_s *,
        struct ieee80211_node *);
void ieee80211_recv_addba_resp(struct ieee80211com *, struct ieee80211_iobuf_s *,
        struct ieee80211_node *);
void ieee80211_recv_delba(struct ieee80211com *, struct ieee80211_iobuf_s *,
        struct ieee80211_node *);
#endif
void ieee80211_recv_sa_query_req(struct ieee80211com *, struct ieee80211_iobuf_s *,
        struct ieee80211_node *);
#ifdef CONFIG_IEEE80211_AP
void ieee80211_recv_sa_query_resp(struct ieee80211com *, struct ieee80211_iobuf_s *,
        struct ieee80211_node *);
#endif
void ieee80211_recv_action(struct ieee80211com *, struct ieee80211_iobuf_s *,
        struct ieee80211_node *);
#ifdef CONFIG_IEEE80211_AP
void    ieee80211_recv_pspoll(struct ieee80211com *, struct ieee80211_iobuf_s *,
        struct ieee80211_node *);
#endif
#ifdef CONFIG_IEEE80211_HT
void ieee80211_recv_bar(struct ieee80211com *, struct ieee80211_iobuf_s *,
        struct ieee80211_node *);
void ieee80211_bar_tid(struct ieee80211com *, struct ieee80211_node *,
        uint8_t, uint16_t);
#endif
#if defined(CONFIG_DEBUG_NET) && defined(CONFIG_DEBUG_VERBOSE)
void ieee80211_input_print(struct ieee80211com *,  struct ieee80211com *,
        struct ieee80211_frame *, struct ieee80211_rxinfo *);
#endif
void ieee80211_input_print_task(void *, void *);

/* Retrieve the length in bytes of an 802.11 header */

unsigned int ieee80211_get_hdrlen(const struct ieee80211_frame *wh)
{
    unsigned int size = sizeof(*wh);

    /* NB: does not work with control frames */
    DEBUGASSERT(ieee80211_has_seq(wh));

    if (ieee80211_has_addr4(wh))
        size += IEEE80211_ADDR_LEN;    /* i_addr4 */
    if (ieee80211_has_qos(wh))
        size += sizeof(uint16_t);    /* i_qos */
    if (ieee80211_has_htc(wh))
        size += sizeof(uint32_t);    /* i_ht */
    return size;
}

#if defined(CONFIG_DEBUG_NET) && defined(CONFIG_DEBUG_VERBOSE)
/* Work queue task that prints a received frame.  Avoids nvdbg() from
 * interrupt context at IPL_NET making slow machines unusable when many
 * frames are received and the interface is put in debug mode.
 */

void ieee80211_input_print_task(void *arg1, void *arg2)
{
  char *msg = arg1;

  nvdbg("%s", msg);
  kfree(msg);
}

static void ieee80211_input_print(struct ieee80211com *ic, struct ieee80211_frame *wh, struct ieee80211_rxinfo *rxi)
{
  int error;
  char *msg;
  msg = kmalloc(1024);
  if (msg == NULL)
    {
      return;
    }

  snprintf(msg, 1024, "%s: received %s from %s rssi %d mode %s\n",
           ic->ic_ifname,
           ieee80211_mgt_subtype_name[subtype >> IEEE80211_FC0_SUBTYPE_SHIFT],
           ieee80211_addr2str(wh->i_addr2), rxi->rxi_rssi,
           ieee80211_phymode_name[ieee80211_chan2mode(ic, ic->ic_bss->ni_chan)]);

  error = workq_add_task(NULL, 0, ieee80211_input_print_task, msg, NULL);
  if (error)
    {
      kfree(msg);
    }
}
#endif

/* Process a received frame.  The node associated with the sender
 * should be supplied.  If nothing was found in the node table then
 * the caller is assumed to supply a reference to ic_bss instead.
 * The RSSI and a timestamp are also supplied.  The RSSI data is used
 * during AP scanning to select a AP to associate with; it can have
 * any units so long as values have consistent units and higher values
 * mean ``better signal''.  The receive timestamp is currently not used
 * by the 802.11 layer.
 */

void ieee80211_input(struct ieee80211com *ic, struct ieee80211_iobuf_s *iob, struct ieee80211_node *ni,
    struct ieee80211_rxinfo *rxi)
{
    struct ieee80211_frame *wh;
    uint16_t *orxseq, nrxseq, qos;
    uint8_t dir, type, subtype, tid;
    int hdrlen, hasqos;

    DEBUGASSERT(ni != NULL);

    /* in monitor mode, send everything directly to bpf */
    if (ic->ic_opmode == IEEE80211_M_MONITOR)
        goto out;

    /*
     * Do not process frames without an Address 2 field any further.
     * Only CTS and ACK control frames do not have this field.
     */
    if (iob->m_len < sizeof(struct ieee80211_frame_min)) {
        ndbg("ERROR: frame too short, len %u\n", iob->m_len);
        ic->ic_stats.is_rx_tooshort++;
        goto out;
    }

    wh = mtod(iob, struct ieee80211_frame *);
    if ((wh->i_fc[0] & IEEE80211_FC0_VERSION_MASK) !=
        IEEE80211_FC0_VERSION_0) {
        ndbg("ERROR: frame with wrong version: %x\n", wh->i_fc[0]);
        ic->ic_stats.is_rx_badversion++;
        goto err;
    }

    dir = wh->i_fc[1] & IEEE80211_FC1_DIR_MASK;
    type = wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK;

    if (type != IEEE80211_FC0_TYPE_CTL)
      {
        hdrlen = ieee80211_get_hdrlen(wh);
        if (iob->m_len < hdrlen)
          {
            ndbg("ERROR: frame too short, len %u\n", iob->m_len);
            ic->ic_stats.is_rx_tooshort++;
            goto err;
          }
      }

    if ((hasqos = ieee80211_has_qos(wh))) {
        qos = ieee80211_get_qos(wh);
        tid = qos & IEEE80211_QOS_TID;
    } else {
        qos = 0;
        tid = 0;
    }

    /* duplicate detection (see 9.2.9) */
    if (ieee80211_has_seq(wh) &&
        ic->ic_state != IEEE80211_S_SCAN) {
        nrxseq = letoh16(*(uint16_t *)wh->i_seq) >>
            IEEE80211_SEQ_SEQ_SHIFT;
        if (hasqos)
            orxseq = &ni->ni_qos_rxseqs[tid];
        else
            orxseq = &ni->ni_rxseq;
        if ((wh->i_fc[1] & IEEE80211_FC1_RETRY) &&
            nrxseq == *orxseq) {
            /* duplicate, silently discarded */
            ic->ic_stats.is_rx_dup++;
            goto out;
        }
        *orxseq = nrxseq;
    }
    if (ic->ic_state != IEEE80211_S_SCAN) {
        ni->ni_rssi = rxi->rxi_rssi;
        ni->ni_rstamp = rxi->rxi_tstamp;
        ni->ni_inact = 0;
    }

#ifdef CONFIG_IEEE80211_AP
    if (ic->ic_opmode == IEEE80211_M_HOSTAP &&
        (ic->ic_caps & IEEE80211_C_APPMGT) &&
        ni->ni_state == IEEE80211_STA_ASSOC) {
        if (wh->i_fc[1] & IEEE80211_FC1_PWR_MGT) {
            if (ni->ni_pwrsave == IEEE80211_PS_AWAKE) {
                /* turn on PS mode */
                ni->ni_pwrsave = IEEE80211_PS_DOZE;
                ic->ic_pssta++;
                nvdbg("PS mode on for %s, count %d\n",
                    ieee80211_addr2str(wh->i_addr2), ic->ic_pssta);
            }
        } else if (ni->ni_pwrsave == IEEE80211_PS_DOZE) {
            /* turn off PS mode */
            ni->ni_pwrsave = IEEE80211_PS_AWAKE;
            ic->ic_pssta--;
            nvdbg("PS mode off for %s, count %d\n",
                ieee80211_addr2str(wh->i_addr2), ic->ic_pssta);

            (*ic->ic_set_tim)(ic, ni->ni_associd, 0);

            /* dequeue buffered unicast frames */
            while (!sq_empty(&ni->ni_savedq)) {
                struct ieee80211_iobuf_s *iob;
                iob = (struct ieee80211_iobuf_s *iob)sq_remfirst(&ni->ni_savedq);
                sq_addlast((sq_entry_t *)iob, &ic->ic_pwrsaveq);
                ieee80211_ifstart();
            }
        }
    }
#endif
    switch (type)
      {
      case IEEE80211_FC0_TYPE_DATA:
        switch (ic->ic_opmode)
          {
          case IEEE80211_M_STA:
            if (dir != IEEE80211_FC1_DIR_FROMDS)
              {
                ic->ic_stats.is_rx_wrongdir++;
                goto out;
              }

            if (ic->ic_state != IEEE80211_S_SCAN &&
                !IEEE80211_ADDR_EQ(wh->i_addr2, ni->ni_bssid))
              {
                /* Source address is not our BSS. */

                nvdbg("discard frame from SA %s\n",
                    ieee80211_addr2str(wh->i_addr2));

                ic->ic_stats.is_rx_wrongbss++;
                goto out;
              }

            if (/* REVISIT: (dev->d_flags & IFF_SIMPLEX) && */
                IEEE80211_IS_MULTICAST(wh->i_addr1) &&
                IEEE80211_ADDR_EQ(wh->i_addr3, ic->ic_myaddr))
             {
                /* In IEEE802.11 network, multicast frame
                 * sent from me is broadcast from AP.
                 * It should be silently discarded for
                 * SIMPLEX interface.
                 */

                ic->ic_stats.is_rx_mcastecho++;
                goto out;
              }
            break;
#ifdef CONFIG_IEEE80211_AP
        case IEEE80211_M_IBSS:
        case IEEE80211_M_AHDEMO:
            if (dir != IEEE80211_FC1_DIR_NODS) {
                ic->ic_stats.is_rx_wrongdir++;
                goto out;
            }
            if (ic->ic_state != IEEE80211_S_SCAN &&
                !IEEE80211_ADDR_EQ(wh->i_addr3,
                ic->ic_bss->ni_bssid) &&
                !IEEE80211_ADDR_EQ(wh->i_addr3,
                etherbroadcastaddr)) {
                /* Destination is not our BSS or broadcast. */
                nvdbg("discard data frame to DA %s\n",
                    ieee80211_addr2str(wh->i_addr3));
                ic->ic_stats.is_rx_wrongbss++;
                goto out;
            }
            break;
        case IEEE80211_M_HOSTAP:
            if (dir != IEEE80211_FC1_DIR_TODS)
              {
                ic->ic_stats.is_rx_wrongdir++;
                goto out;
              }

            if (ic->ic_state != IEEE80211_S_SCAN &&
                !IEEE80211_ADDR_EQ(wh->i_addr1,
                ic->ic_bss->ni_bssid) &&
                !IEEE80211_ADDR_EQ(wh->i_addr1,
                etherbroadcastaddr)) {
                /* BSS is not us or broadcast. */
                nvdbg("discard data frame to BSS %s\n",
                    ieee80211_addr2str(wh->i_addr1));
                ic->ic_stats.is_rx_wrongbss++;
                goto out;
            }

            /* check if source STA is associated */

            if (ni == ic->ic_bss)
              {
                ndbg("ERROR: data from unknown src %s\n",  ieee80211_addr2str(wh->i_addr2));

                /* NB: caller deals with reference */

                ni = ieee80211_find_node(ic, wh->i_addr2);
                if (ni == NULL)
                  {
                    ni = ieee80211_dup_bss(ic, wh->i_addr2);
                  }

                if (ni != NULL)
                  {
                    IEEE80211_SEND_MGMT(ic, ni,
                        IEEE80211_FC0_SUBTYPE_DEAUTH,
                        IEEE80211_REASON_NOT_AUTHED);
                  }

                ic->ic_stats.is_rx_notassoc++;
                goto err;
              }

            if (ni->ni_associd == 0) {
                ndbg("ERROR: data from unassoc src %s\n",
                    ieee80211_addr2str(wh->i_addr2));
                IEEE80211_SEND_MGMT(ic, ni,
                    IEEE80211_FC0_SUBTYPE_DISASSOC,
                    IEEE80211_REASON_NOT_ASSOCED);
                ic->ic_stats.is_rx_notassoc++;
                goto err;
            }
            break;
#endif /* CONFIG_IEEE80211_AP */
        default:
            /* can't get there */
            goto out;
        }

#ifdef CONFIG_IEEE80211_HT
        if (!(rxi->rxi_flags & IEEE80211_RXI_AMPDU_DONE) &&
            hasqos && (qos & IEEE80211_QOS_ACK_POLICY_MASK) ==
            IEEE80211_QOS_ACK_POLICY_BA) {
            /* check if we have a BA agreement for this RA/TID */
            if (ni->ni_rx_ba[tid].ba_state !=
                IEEE80211_BA_AGREED) {
                ndbg("ERROR: no BA agreement for %s, TID %d\n",
                    ieee80211_addr2str(ni->ni_macaddr), tid);
                /* send a DELBA with reason code UNKNOWN-BA */
                IEEE80211_SEND_ACTION(ic, ni,
                    IEEE80211_CATEG_BA, IEEE80211_ACTION_DELBA,
                    IEEE80211_REASON_SETUP_REQUIRED << 16 |
                    tid);
                goto err;
            }

            /* Go through A-MPDU reordering */

            ieee80211_input_ba(ic, iob, ni, tid, rxi);
            return;    /* don't free iob! */
        }
#endif
        if ((ic->ic_flags & IEEE80211_F_WEPON) ||
            ((ic->ic_flags & IEEE80211_F_RSNON) &&
             (ni->ni_flags & IEEE80211_NODE_RXPROT))) {
            /* protection is on for Rx */
            if (!(rxi->rxi_flags & IEEE80211_RXI_HWDEC)) {
                if (!(wh->i_fc[1] & IEEE80211_FC1_PROTECTED)) {
                    /* drop unencrypted */
                    ic->ic_stats.is_rx_unencrypted++;
                    goto err;
                }
                /* do software decryption */
                iob = ieee80211_decrypt(ic, iob, ni);
                if (iob == NULL) {
                    ic->ic_stats.is_rx_wepfail++;
                    goto err;
                }
                wh = mtod(iob, struct ieee80211_frame *);
            }
        } else if ((wh->i_fc[1] & IEEE80211_FC1_PROTECTED) ||
            (rxi->rxi_flags & IEEE80211_RXI_HWDEC)) {
            /* frame encrypted but protection off for Rx */
            ic->ic_stats.is_rx_nowep++;
            goto out;
        }

#ifdef CONFIG_IEEE80211_HT
        if ((ni->ni_flags & IEEE80211_NODE_HT) &&
            hasqos && (qos & IEEE80211_QOS_AMSDU))
            ieee80211_amsdu_decap(ic, iob, ni, hdrlen);
        else
#endif
            ieee80211_decap(ic, iob, ni, hdrlen);
        return;

    case IEEE80211_FC0_TYPE_MGT:
        if (dir != IEEE80211_FC1_DIR_NODS) {
            ic->ic_stats.is_rx_wrongdir++;
            goto err;
        }
#ifdef CONFIG_IEEE80211_AP
        if (ic->ic_opmode == IEEE80211_M_AHDEMO) {
            ic->ic_stats.is_rx_ahdemo_mgt++;
            goto out;
        }
#endif
        subtype = wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;

        /* drop frames without interest */
        if (ic->ic_state == IEEE80211_S_SCAN) {
            if (subtype != IEEE80211_FC0_SUBTYPE_BEACON &&
                subtype != IEEE80211_FC0_SUBTYPE_PROBE_RESP) {
                ic->ic_stats.is_rx_mgtdiscard++;
                goto out;
            }
        }

        if (ni->ni_flags & IEEE80211_NODE_RXMGMTPROT) {
            /* MMPDU protection is on for Rx */
            if (subtype == IEEE80211_FC0_SUBTYPE_DISASSOC ||
                subtype == IEEE80211_FC0_SUBTYPE_DEAUTH ||
                subtype == IEEE80211_FC0_SUBTYPE_ACTION) {
                if (!IEEE80211_IS_MULTICAST(wh->i_addr1) &&
                    !(wh->i_fc[1] & IEEE80211_FC1_PROTECTED)) {
                    /* unicast mgmt not encrypted */
                    goto out;
                }
                /* do software decryption */
                iob = ieee80211_decrypt(ic, iob, ni);
                if (iob == NULL) {
                    /* XXX stats */
                    goto out;
                }
                wh = mtod(iob, struct ieee80211_frame *);
            }
        } else if ((ic->ic_flags & IEEE80211_F_RSNON) &&
            (wh->i_fc[1] & IEEE80211_FC1_PROTECTED)) {
            /* encrypted but MMPDU Rx protection off for TA */
            goto out;
        }

#if defined(CONFIG_DEBUG_NET) && defined(CONFIG_DEBUG_VERBOSE)
       ieee80211_input_print(ic, ic, wh, rxi);
#endif

        (*ic->ic_recv_mgmt)(ic, iob, ni, rxi, subtype);
        ieee80211_iofree(iob);
        return;

    case IEEE80211_FC0_TYPE_CTL:
        ic->ic_stats.is_rx_ctl++;
        subtype = wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;
        switch (subtype) {
#ifdef CONFIG_IEEE80211_AP
        case IEEE80211_FC0_SUBTYPE_PS_POLL:
            ieee80211_recv_pspoll(ic, iob, ni);
            break;
#endif
#ifdef CONFIG_IEEE80211_HT
        case IEEE80211_FC0_SUBTYPE_BAR:
            ieee80211_recv_bar(ic, iob, ni);
            break;
#endif
        default:
            break;
        }
        goto out;

    default:
        ndbg("ERROR: bad frame type %x\n", type);
        /* should not come here */
        break;
    }
 err:
 out:
    if (iob != NULL) {
        ieee80211_iofree(iob);
    }
}

/* Handle defragmentation (see 9.5 and Annex C).  We support the concurrent
 * reception of fragments of three fragmented MSDUs or MMPDUs.
 */

struct ieee80211_iobuf_s *ieee80211_defrag(struct ieee80211com *ic, struct ieee80211_iobuf_s *iob, int hdrlen)
{
    const struct ieee80211_frame *owh, *wh;
    struct ieee80211_defrag *df;
    uint16_t rxseq, seq;
    uint8_t frag;
    int i;

    wh = mtod(iob, struct ieee80211_frame *);
    rxseq = letoh16(*(const uint16_t *)wh->i_seq);
    seq = rxseq >> IEEE80211_SEQ_SEQ_SHIFT;
    frag = rxseq & IEEE80211_SEQ_FRAG_MASK;

    if (frag == 0 && !(wh->i_fc[1] & IEEE80211_FC1_MORE_FRAG))
        return iob;    /* not fragmented */

    if (frag == 0) {
        /* first fragment, setup entry in the fragment cache */
        if (++ic->ic_defrag_cur == IEEE80211_DEFRAG_SIZE)
            ic->ic_defrag_cur = 0;
        df = &ic->ic_defrag[ic->ic_defrag_cur];
        if (df->df_m != NULL)
            ieee80211_iofree(df->df_m);    /* discard old entry */
        df->df_seq = seq;
        df->df_frag = 0;
        df->df_m = iob;
        /* start receive MSDU timer of aMaxReceiveLifetime */
        wd_start(df->df_to,  SEC2TICK(1));
        return NULL;    /* MSDU or MMPDU not yet complete */
    }

    /* find matching entry in the fragment cache */
    for (i = 0; i < IEEE80211_DEFRAG_SIZE; i++) {
        df = &ic->ic_defrag[i];
        if (df->df_m == NULL)
            continue;
        if (df->df_seq != seq || df->df_frag + 1 != frag)
            continue;
        owh = mtod(df->df_m, struct ieee80211_frame *);
        /* frame type, source and destination must match */
        if (((wh->i_fc[0] ^ owh->i_fc[0]) & IEEE80211_FC0_TYPE_MASK) ||
            !IEEE80211_ADDR_EQ(wh->i_addr1, owh->i_addr1) ||
            !IEEE80211_ADDR_EQ(wh->i_addr2, owh->i_addr2))
            continue;
        /* matching entry found */
        break;
    }
    if (i == IEEE80211_DEFRAG_SIZE) {
        /* no matching entry found, discard fragment */
        ieee80211_iofree(iob);
        return NULL;
    }

    df->df_frag = frag;
    /* strip 802.11 header and concatenate fragment */
    m_adj(iob, hdrlen);
    m_cat(df->df_m, iob);
    df->df_m->m_pktlen += iob->m_pktlen;

    if (wh->i_fc[1] & IEEE80211_FC1_MORE_FRAG)
        return NULL;    /* MSDU or MMPDU not yet complete */

    /* MSDU or MMPDU complete */
    wd_cancel(df->df_to);
    iob = df->df_m;
    df->df_m = NULL;
    return iob;
}

/*
 * Receive MSDU defragmentation timer exceeds aMaxReceiveLifetime.
 */
void
ieee80211_defrag_timeout(void *arg)
{
    struct ieee80211_defrag *df = arg;
    int s = splnet();

    /* discard all received fragments */
    ieee80211_iofree(df->df_m);
    df->df_m = NULL;

    splx(s);
}

#ifdef CONFIG_IEEE80211_HT
/* Process a received data MPDU related to a specific HT-immediate Block Ack
 * agreement (see 9.10.7.6).
 */

void ieee80211_input_ba(struct ieee80211com *ic, struct ieee80211_iobuf_s *iob,
    struct ieee80211_node *ni, int tid, struct ieee80211_rxinfo *rxi)
{
    struct ieee80211_rx_ba *ba = &ni->ni_rx_ba[tid];
    struct ieee80211_frame *wh;
    int idx, count;
    uint16_t sn;

    wh = mtod(iob, struct ieee80211_frame *);
    sn = letoh16(*(uint16_t *)wh->i_seq) >> IEEE80211_SEQ_SEQ_SHIFT;

    /* reset Block Ack inactivity timer */
    wd_start(ba->ba_to, USEC2TICK(ba->ba_timeout_val), ieee80211_rx_ba_timeout, 1, ba);

    if (SEQ_LT(sn, ba->ba_winstart)) {    /* SN < WinStartB */
        ieee80211_iofree(iob);    /* discard the MPDU */
        return;
    }
    if (SEQ_LT(ba->ba_winend, sn)) {    /* WinEndB < SN */
        count = (sn - ba->ba_winend) & 0xfff;
        if (count > ba->ba_winsize)    /* no overlap */
            count = ba->ba_winsize;
        while (count-- > 0) {
            /* gaps may exist */
            if (ba->ba_buf[ba->ba_head].iob != NULL) {
                ieee80211_input(ic, ba->ba_buf[ba->ba_head].iob,
                    ni, &ba->ba_buf[ba->ba_head].rxi);
                ba->ba_buf[ba->ba_head].iob = NULL;
            }
            ba->ba_head = (ba->ba_head + 1) %
                IEEE80211_BA_MAX_WINSZ;
        }
        /* move window forward */
        ba->ba_winend = sn;
        ba->ba_winstart = (sn - ba->ba_winsize + 1) & 0xfff;
    }
    /* WinStartB <= SN <= WinEndB */

    idx = (sn - ba->ba_winstart) & 0xfff;
    idx = (ba->ba_head + idx) % IEEE80211_BA_MAX_WINSZ;
    /* store the received MPDU in the buffer */
    if (ba->ba_buf[idx].iob != NULL) {
        ieee80211_iofree(iob);
        return;
    }
    ba->ba_buf[idx].iob = iob;
    /* store Rx meta-data too */
    rxi->rxi_flags |= IEEE80211_RXI_AMPDU_DONE;
    ba->ba_buf[idx].rxi = *rxi;

    /* pass reordered MPDUs up to the next MAC process */
    while (ba->ba_buf[ba->ba_head].iob != NULL) {
        ieee80211_input(ic, ba->ba_buf[ba->ba_head].iob, ni,
            &ba->ba_buf[ba->ba_head].rxi);
        ba->ba_buf[ba->ba_head].iob = NULL;

        ba->ba_head = (ba->ba_head + 1) % IEEE80211_BA_MAX_WINSZ;
        /* move window forward */
        ba->ba_winstart = (ba->ba_winstart + 1) & 0xfff;
    }
    ba->ba_winend = (ba->ba_winstart + ba->ba_winsize - 1) & 0xfff;
}

/* Change the value of WinStartB (move window forward) upon reception of a
 * BlockAckReq frame or an ADDBA Request (PBAC).
 */

void ieee80211_ba_move_window(struct ieee80211com *ic, struct ieee80211_node *ni, uint8_t tid, uint16_t ssn)
{
    struct ieee80211_rx_ba *ba = &ni->ni_rx_ba[tid];
    int count;

    /* assert(WinStartB <= SSN) */

    count = (ssn - ba->ba_winstart) & 0xfff;
    if (count > ba->ba_winsize)    /* no overlap */
        count = ba->ba_winsize;
    while (count-- > 0) {
        /* gaps may exist */
        if (ba->ba_buf[ba->ba_head].iob != NULL) {
            ieee80211_input(ic, ba->ba_buf[ba->ba_head].iob, ni,
                &ba->ba_buf[ba->ba_head].rxi);
            ba->ba_buf[ba->ba_head].iob = NULL;
        }
        ba->ba_head = (ba->ba_head + 1) % IEEE80211_BA_MAX_WINSZ;
    }
    /* move window forward */
    ba->ba_winstart = ssn;

    /* pass reordered MPDUs up to the next MAC process */
    while (ba->ba_buf[ba->ba_head].iob != NULL) {
        ieee80211_input(ic, ba->ba_buf[ba->ba_head].iob, ni,
            &ba->ba_buf[ba->ba_head].rxi);
        ba->ba_buf[ba->ba_head].iob = NULL;

        ba->ba_head = (ba->ba_head + 1) % IEEE80211_BA_MAX_WINSZ;
        /* move window forward */
        ba->ba_winstart = (ba->ba_winstart + 1) & 0xfff;
    }
    ba->ba_winend = (ba->ba_winstart + ba->ba_winsize - 1) & 0xfff;
}
#endif /* !CONFIG_IEEE80211_HT */

void ieee80211_deliver_data(struct ieee80211com *ic, struct ieee80211_iobuf_s *iob,
    struct ieee80211_node *ni)
{
  struct ether_header *eh;
  struct ieee80211_iobuf_s *m1;

  eh = mtod(iob, struct ether_header *);

  if ((ic->ic_flags & IEEE80211_F_RSNON) && !ni->ni_port_valid &&
        eh->ether_type != htons(ETHERTYPE_PAE))
    {
      ndbg("ERROR: port not valid: %s\n", ieee80211_addr2str(eh->ether_dhost));
      ic->ic_stats.is_rx_unauth++;
      ieee80211_iofree(iob);
      return;
    }

  /* Perform as a bridge within the AP.  Notice that we do not
   * bridge EAPOL frames as suggested in C.1.1 of IEEE Std 802.1X.
   */

  m1 = NULL;
#ifdef CONFIG_IEEE80211_AP
  if (ic->ic_opmode == IEEE80211_M_HOSTAP &&
      !(ic->ic_flags & IEEE80211_F_NOBRIDGE) &&
      eh->ether_type != htons(ETHERTYPE_PAE))
    {
      struct ieee80211_node *ni1;
      int len;
      int error;

      if (ETHER_IS_MULTICAST(eh->ether_dhost))
        {
          m1 = m_copym2(iob, 0, M_COPYALL, M_DONTWAIT);
          if (m1 != NULL)
            {
              m1->m_flags |= M_MCAST;
            }
        }
      else
        {
          ni1 = ieee80211_find_node(ic, eh->ether_dhost);
          if (ni1 != NULL && ni1->ni_state == IEEE80211_STA_ASSOC)
            {
              m1 = iob;
              iob = NULL;
            }
        }

      if (m1 != NULL)
        {
          len = m1->m_pktlen;
          error = ieee80211_ifsend(m1);
          if (!error)
            {
              ieee80211_ifstart();
            }
        }
    }
#endif
    if (iob != NULL)
      {
        if ((ic->ic_flags & IEEE80211_F_RSNON) &&
            eh->ether_type == htons(ETHERTYPE_PAE))
          {
            ieee80211_eapol_key_input(ic, iob, ni);
          }
        else
          {
            ether_input_mbuf(ic, iob);
          }
    }
}

#ifdef __STRICT_ALIGNMENT
/* Make sure protocol header (e.g. IP) is aligned on a 32-bit boundary.
 * This is achieved by copying I/O buffers so drivers should try to map their
 * buffers such that this copying is not necessary.  It is however not
 * always possible because 802.11 header length may vary (non-QoS+LLC
 * is 32 bytes while QoS+LLC is 34 bytes).  Some devices are smart and
 * add 2 padding bytes after the 802.11 header in the QoS case so this
 * function is there for stupid drivers/devices only.
 *
 * XXX -- this is horrible
 */

struct ieee80211_iobuf_s *ieee80211_align_iobuf(struct ieee80211_iobuf_s *iob)
{
  struct ieee80211_iobuf_s *next, *next0, **np;
  void *newdata;
  int off, pktlen;

  next0 = NULL;
  np = &next0;
  off = 0;
  pktlen = iob->m_pktlen;
  while (pktlen > off)
    {
      if (next0 == NULL)
        {
          next = ieee80211_ioalloc();
          if (next == NULL)
            {
              ieee80211_iofree(iob);
              return NULL;
            }

          if (m_dup_pkthdr(next, iob, M_DONTWAIT))
            {
              ieee80211_iofree(next);
              ieee80211_iofree(iob);
              return (NULL);
            }

          next->m_len = MHLEN;
        }
      else
        {
          next = ieee80211_ioalloc();
          if (next == NULL)
            {
              ieee80211_iofree(iob);
              ieee80211_iofree(next0);
              return NULL;
            }

          next->m_len = 0;
        }

      if (pktlen - off >= MINCLSIZE)
        {
          MCLGET(next, M_DONTWAIT);
          if (next->m_flags & M_EXT)
            {
              next->m_len = next->m_ext.ext_size;
            }
        }

      if (next0 == NULL)
        {
          newdata = (void *)ALIGN(next->m_data + ETHER_HDR_LEN) - ETHER_HDR_LEN;
          next->m_len -= newdata - next->m_data;
          next->m_data = newdata;
        }

      if (next->m_len > pktlen - off)
        {
          next->m_len = pktlen - off;
        }

      m_copydata(iob, off, next->m_len, mtod(next, void *));
      off += next->m_len;
      *np = next;
      np = &(struct ieee80211_iobuf_s *)next->m_link.flink;
    }

  ieee80211_iofree(iob);
  return next0;
}
#endif /* __STRICT_ALIGNMENT */

void ieee80211_decap(struct ieee80211com *ic, struct ieee80211_iobuf_s *iob, struct ieee80211_node *ni, int hdrlen)
{
    struct ether_header eh;
    struct ieee80211_frame *wh;
    struct llc *llc;

    if (iob->m_len < hdrlen + LLC_SNAPFRAMELEN &&
        (iob = m_pullup(iob, hdrlen + LLC_SNAPFRAMELEN)) == NULL)
      {
        ic->ic_stats.is_rx_decap++;
        return;
      }

    wh = mtod(iob, struct ieee80211_frame *);
    switch (wh->i_fc[1] & IEEE80211_FC1_DIR_MASK)
      {
      case IEEE80211_FC1_DIR_NODS:
        IEEE80211_ADDR_COPY(eh.ether_dhost, wh->i_addr1);
        IEEE80211_ADDR_COPY(eh.ether_shost, wh->i_addr2);
        break;

      case IEEE80211_FC1_DIR_TODS:
        IEEE80211_ADDR_COPY(eh.ether_dhost, wh->i_addr3);
        IEEE80211_ADDR_COPY(eh.ether_shost, wh->i_addr2);
        break;

      case IEEE80211_FC1_DIR_FROMDS:
        IEEE80211_ADDR_COPY(eh.ether_dhost, wh->i_addr1);
        IEEE80211_ADDR_COPY(eh.ether_shost, wh->i_addr3);
        break;

      case IEEE80211_FC1_DIR_DSTODS:
        IEEE80211_ADDR_COPY(eh.ether_dhost, wh->i_addr3);
        IEEE80211_ADDR_COPY(eh.ether_shost,
                            ((struct ieee80211_frame_addr4 *)wh)->i_addr4);
        break;
    }

    llc = (struct llc *)((void *)wh + hdrlen);
    if (llc->llc_dsap == LLC_SNAP_LSAP &&
        llc->llc_ssap == LLC_SNAP_LSAP &&
        llc->llc_control == LLC_UI &&
        llc->llc_snap.org_code[0] == 0 &&
        llc->llc_snap.org_code[1] == 0 &&
        llc->llc_snap.org_code[2] == 0)
      {
        eh.ether_type = llc->llc_snap.ether_type;
        m_adj(iob, hdrlen + LLC_SNAPFRAMELEN - ETHER_HDR_LEN);
      }
    else
      {
        eh.ether_type = htons(iob->m_pktlen - hdrlen);
        m_adj(iob, hdrlen - ETHER_HDR_LEN);
      }

    memcpy(mtod(iob, &eh, ETHER_HDR_LEN);

#ifdef __STRICT_ALIGNMENT
    if (!ALIGNED_POINTER(mtod(iob, void *) + ETHER_HDR_LEN, uint32_t))
      {
        if ((iob = ieee80211_align_iobuf(iob)) == NULL)
          {
            ic->ic_stats.is_rx_decap++;
            return;
          }
      }
#endif

    ieee80211_deliver_data(ic, iob, ni);
}

#ifdef CONFIG_IEEE80211_HT
/* Decapsulate an Aggregate MSDU (see 7.2.2.2) */

void ieee80211_amsdu_decap(struct ieee80211com *ic, struct ieee80211_iobuf_s *iob,
    struct ieee80211_node *ni, int hdrlen)
{
    struct ieee80211_iobuf_s *next;
    struct ether_header *eh;
    struct llc *llc;
    int len, pad;

    /* strip 802.11 header */
    m_adj(iob, hdrlen);

    for (;;) {
        /* process an A-MSDU subframe */
        if (iob->m_len < ETHER_HDR_LEN + LLC_SNAPFRAMELEN) {
            iob = m_pullup(iob, ETHER_HDR_LEN + LLC_SNAPFRAMELEN);
            if (iob == NULL) {
                ic->ic_stats.is_rx_decap++;
                break;
            }
        }
        eh = mtod(iob, struct ether_header *);
        /* examine 802.3 header */
        len = ntohs(eh->ether_type);
        if (len < LLC_SNAPFRAMELEN) {
            ndbg("ERROR: A-MSDU subframe too short (%d)\n", len);
            /* stop processing A-MSDU subframes */
            ic->ic_stats.is_rx_decap++;
            ieee80211_iofree(iob);
            break;
        }
        llc = (struct llc *)&eh[1];
        /* examine 802.2 LLC header */
        if (llc->llc_dsap == LLC_SNAP_LSAP &&
            llc->llc_ssap == LLC_SNAP_LSAP &&
            llc->llc_control == LLC_UI &&
            llc->llc_snap.org_code[0] == 0 &&
            llc->llc_snap.org_code[1] == 0 &&
            llc->llc_snap.org_code[2] == 0) {
            /* convert to Ethernet II header */
            eh->ether_type = llc->llc_snap.ether_type;
            /* strip LLC+SNAP headers */
            memmove((uint8_t *)eh + LLC_SNAPFRAMELEN, eh,
                ETHER_HDR_LEN);
            m_adj(iob, LLC_SNAPFRAMELEN);
            len -= LLC_SNAPFRAMELEN;
        }
        len += ETHER_HDR_LEN;

        /* "detach" our A-MSDU subframe from the others */
        next = m_split(iob, len, M_NOWAIT);
        if (next == NULL) {
            /* stop processing A-MSDU subframes */
            ic->ic_stats.is_rx_decap++;
            ieee80211_iofree(iob);
            break;
        }
        ieee80211_deliver_data(ic, iob, ni);

        iob = next;
        /* remove padding */
        pad = ((len + 3) & ~3) - len;
        m_adj(iob, pad);
    }
}
#endif /* !CONFIG_IEEE80211_HT */

/*
 * Parse an EDCA Parameter Set element (see 7.3.2.27).
 */
int
ieee80211_parse_edca_params_body(struct ieee80211com *ic, const uint8_t *frm)
{
    unsigned int updtcount;
    int aci;

    /*
     * Check if EDCA parameters have changed XXX if we miss more than
     * 15 consecutive beacons, we might not detect changes to EDCA
     * parameters due to wraparound of the 4-bit Update Count field.
     */
    updtcount = frm[0] & 0xf;
    if (updtcount == ic->ic_edca_updtcount)
        return 0;    /* no changes to EDCA parameters, ignore */
    ic->ic_edca_updtcount = updtcount;

    frm += 2;    /* skip QoS Info & Reserved fields */

    /* parse AC Parameter Records */
    for (aci = 0; aci < EDCA_NUM_AC; aci++) {
        struct ieee80211_edca_ac_params *ac = &ic->ic_edca_ac[aci];

        ac->ac_acm       = (frm[0] >> 4) & 0x1;
        ac->ac_aifsn     = frm[0] & 0xf;
        ac->ac_ecwmin    = frm[1] & 0xf;
        ac->ac_ecwmax    = frm[1] >> 4;
        ac->ac_txoplimit = LE_READ_2(frm + 2);
        frm += 4;
    }
    /* give drivers a chance to update their settings */
    if ((ic->ic_flags & IEEE80211_F_QOS) && ic->ic_updateedca != NULL)
        (*ic->ic_updateedca)(ic);

    return 0;
}

int
ieee80211_parse_edca_params(struct ieee80211com *ic, const uint8_t *frm)
{
    if (frm[1] < 18) {
        ic->ic_stats.is_rx_elem_toosmall++;
        return IEEE80211_REASON_IE_INVALID;
    }
    return ieee80211_parse_edca_params_body(ic, frm + 2);
}

int
ieee80211_parse_wmm_params(struct ieee80211com *ic, const uint8_t *frm)
{
    if (frm[1] < 24) {
        ic->ic_stats.is_rx_elem_toosmall++;
        return IEEE80211_REASON_IE_INVALID;
    }
    return ieee80211_parse_edca_params_body(ic, frm + 8);
}

enum ieee80211_cipher
ieee80211_parse_rsn_cipher(const uint8_t selector[4])
{
    if (memcmp(selector, MICROSOFT_OUI, 3) == 0) {    /* WPA */
        switch (selector[3]) {
        case 0:    /* use group data cipher suite */
            return IEEE80211_CIPHER_USEGROUP;
        case 1:    /* WEP-40 */
            return IEEE80211_CIPHER_WEP40;
        case 2:    /* TKIP */
            return IEEE80211_CIPHER_TKIP;
        case 4:    /* CCMP (RSNA default) */
            return IEEE80211_CIPHER_CCMP;
        case 5:    /* WEP-104 */
            return IEEE80211_CIPHER_WEP104;
        }
    } else if (memcmp(selector, IEEE80211_OUI, 3) == 0) {    /* RSN */
        /* from IEEE Std 802.11 - Table 20da */
        switch (selector[3]) {
        case 0:    /* use group data cipher suite */
            return IEEE80211_CIPHER_USEGROUP;
        case 1:    /* WEP-40 */
            return IEEE80211_CIPHER_WEP40;
        case 2:    /* TKIP */
            return IEEE80211_CIPHER_TKIP;
        case 4:    /* CCMP (RSNA default) */
            return IEEE80211_CIPHER_CCMP;
        case 5:    /* WEP-104 */
            return IEEE80211_CIPHER_WEP104;
        case 6:    /* BIP */
            return IEEE80211_CIPHER_BIP;
        }
    }
    return IEEE80211_CIPHER_NONE;    /* ignore unknown ciphers */
}

enum ieee80211_akm
ieee80211_parse_rsn_akm(const uint8_t selector[4])
{
    if (memcmp(selector, MICROSOFT_OUI, 3) == 0) {    /* WPA */
        switch (selector[3]) {
        case 1:    /* IEEE 802.1X (RSNA default) */
            return IEEE80211_AKM_8021X;
        case 2:    /* PSK */
            return IEEE80211_AKM_PSK;
        }
    } else if (memcmp(selector, IEEE80211_OUI, 3) == 0) {    /* RSN */
        /* from IEEE Std 802.11i-2004 - Table 20dc */
        switch (selector[3]) {
        case 1:    /* IEEE 802.1X (RSNA default) */
            return IEEE80211_AKM_8021X;
        case 2:    /* PSK */
            return IEEE80211_AKM_PSK;
        case 5:    /* IEEE 802.1X with SHA256 KDF */
            return IEEE80211_AKM_SHA256_8021X;
        case 6:    /* PSK with SHA256 KDF */
            return IEEE80211_AKM_SHA256_PSK;
        }
    }
    return IEEE80211_AKM_NONE;    /* ignore unknown AKMs */
}

/*
 * Parse an RSN element (see 7.3.2.25).
 */
int
ieee80211_parse_rsn_body(struct ieee80211com *ic, const uint8_t *frm,
    unsigned int len, struct ieee80211_rsnparams *rsn)
{
    const uint8_t *efrm;
    uint16_t iob, next, s;

    efrm = frm + len;

    /* check Version field */
    if (LE_READ_2(frm) != 1)
        return IEEE80211_STATUS_RSN_IE_VER_UNSUP;
    frm += 2;

    /* all fields after the Version field are optional */

    /* if Cipher Suite missing, default to CCMP */
    rsn->rsn_groupcipher = IEEE80211_CIPHER_CCMP;
    rsn->rsn_nciphers = 1;
    rsn->rsn_ciphers = IEEE80211_CIPHER_CCMP;
    /* if Group Management Cipher Suite missing, defaut to BIP */
    rsn->rsn_groupmgmtcipher = IEEE80211_CIPHER_BIP;
    /* if AKM Suite missing, default to 802.1X */
    rsn->rsn_nakms = 1;
    rsn->rsn_akms = IEEE80211_AKM_8021X;
    /* if RSN capabilities missing, default to 0 */
    rsn->rsn_caps = 0;
    rsn->rsn_npmkids = 0;

    /* read Group Data Cipher Suite field */
    if (frm + 4 > efrm)
        return 0;
    rsn->rsn_groupcipher = ieee80211_parse_rsn_cipher(frm);
    if (rsn->rsn_groupcipher == IEEE80211_CIPHER_USEGROUP)
        return IEEE80211_STATUS_BAD_GROUP_CIPHER;
    frm += 4;

    /* read Pairwise Cipher Suite Count field */
    if (frm + 2 > efrm)
        return 0;
    iob = rsn->rsn_nciphers = LE_READ_2(frm);
    frm += 2;

    /* read Pairwise Cipher Suite List */
    if (frm + iob * 4 > efrm)
        return IEEE80211_STATUS_IE_INVALID;
    rsn->rsn_ciphers = IEEE80211_CIPHER_NONE;
    while (iob-- > 0) {
        rsn->rsn_ciphers |= ieee80211_parse_rsn_cipher(frm);
        frm += 4;
    }
    if (rsn->rsn_ciphers & IEEE80211_CIPHER_USEGROUP) {
        if (rsn->rsn_ciphers != IEEE80211_CIPHER_USEGROUP)
            return IEEE80211_STATUS_BAD_PAIRWISE_CIPHER;
        if (rsn->rsn_groupcipher == IEEE80211_CIPHER_CCMP)
            return IEEE80211_STATUS_BAD_PAIRWISE_CIPHER;
    }

    /* read AKM Suite List Count field */
    if (frm + 2 > efrm)
        return 0;
    next = rsn->rsn_nakms = LE_READ_2(frm);
    frm += 2;

    /* read AKM Suite List */
    if (frm + next * 4 > efrm)
        return IEEE80211_STATUS_IE_INVALID;
    rsn->rsn_akms = IEEE80211_AKM_NONE;
    while (next-- > 0) {
        rsn->rsn_akms |= ieee80211_parse_rsn_akm(frm);
        frm += 4;
    }

    /* read RSN Capabilities field */
    if (frm + 2 > efrm)
        return 0;
    rsn->rsn_caps = LE_READ_2(frm);
    frm += 2;

    /* read PMKID Count field */
    if (frm + 2 > efrm)
        return 0;
    s = rsn->rsn_npmkids = LE_READ_2(frm);
    frm += 2;

    /* read PMKID List */
    if (frm + s * IEEE80211_PMKID_LEN > efrm)
        return IEEE80211_STATUS_IE_INVALID;
    if (s != 0) {
        rsn->rsn_pmkids = frm;
        frm += s * IEEE80211_PMKID_LEN;
    }

    /* read Group Management Cipher Suite field */
    if (frm + 4 > efrm)
        return 0;
    rsn->rsn_groupmgmtcipher = ieee80211_parse_rsn_cipher(frm);

    return IEEE80211_STATUS_SUCCESS;
}

int
ieee80211_parse_rsn(struct ieee80211com *ic, const uint8_t *frm,
    struct ieee80211_rsnparams *rsn)
{
    if (frm[1] < 2) {
        ic->ic_stats.is_rx_elem_toosmall++;
        return IEEE80211_STATUS_IE_INVALID;
    }
    return ieee80211_parse_rsn_body(ic, frm + 2, frm[1], rsn);
}

int
ieee80211_parse_wpa(struct ieee80211com *ic, const uint8_t *frm,
    struct ieee80211_rsnparams *rsn)
{
    if (frm[1] < 6) {
        ic->ic_stats.is_rx_elem_toosmall++;
        return IEEE80211_STATUS_IE_INVALID;
    }
    return ieee80211_parse_rsn_body(ic, frm + 6, frm[1] - 4, rsn);
}

/* Create (or update) a copy of an information element */

int ieee80211_save_ie(const uint8_t *frm, uint8_t **ie)
{
  if (*ie == NULL || (*ie)[1] != frm[1])
    {
      if (*ie != NULL)
        {
          kfree(*ie);
        }

      *ie = kmalloc(2 + frm[1]);
      if (*ie == NULL)
        {
          return -ENOMEM;
        }
    }

  memcpy(*ie, frm, 2 + frm[1]);
  return 0;
}

/* Beacon/Probe response frame format:
 * [8]   Timestamp
 * [2]   Beacon interval
 * [2]   Capability
 * [tlv] Service Set Identifier (SSID)
 * [tlv] Supported rates
 * [tlv] DS Parameter Set (802.11g)
 * [tlv] ERP Information (802.11g)
 * [tlv] Extended Supported Rates (802.11g)
 * [tlv] RSN (802.11i)
 * [tlv] EDCA Parameter Set (802.11e)
 * [tlv] QoS Capability (Beacon only, 802.11e)
 * [tlv] HT Capabilities (802.11n)
 * [tlv] HT Operation (802.11n)
 */

void ieee80211_recv_probe_resp(struct ieee80211com *ic, struct ieee80211_iobuf_s *iob,
    struct ieee80211_node *ni, struct ieee80211_rxinfo *rxi, int isprobe)
{
  const struct ieee80211_frame *wh;
  const uint8_t *frm;
  const uint8_t *efrm;
  const uint8_t *tstamp;
  const uint8_t *ssid;
  const uint8_t *rates;
  const uint8_t *xrates;
  const uint8_t *edcaie;
  const uint8_t *wmmie;
  const uint8_t *rsnie;
  const uint8_t *wpaie;
  const uint8_t *htcaps;
  const uint8_t *htop;
  uint16_t capinfo;
  uint16_t bintval;
  uint8_t chan;
  uint8_t bchan;
  uint8_t erp;
  int ndx;
  int bit
  int is_new;

  /* We process beacon/probe response frames for:
   *    o station mode: to collect state
   *      updates such as 802.11g slot time and for passive
   *      scanning of APs
   *    o adhoc mode: to discover neighbors
   *    o hostap mode: for passive scanning of neighbor APs
   *    o when scanning
   * In other words, in all modes other than monitor (which
   * does not process incoming frames) and adhoc-demo (which
   * does not use management frames at all).
   */

  DEBUGASSERT(ic->ic_opmode == IEEE80211_M_STA ||
#ifdef CONFIG_IEEE80211_AP
              ic->ic_opmode == IEEE80211_M_IBSS ||
              ic->ic_opmode == IEEE80211_M_HOSTAP ||
#endif
              ic->ic_state == IEEE80211_S_SCAN);

  /* Make sure all mandatory fixed fields are present */

  if (iob->m_len < sizeof(*wh) + 12)
    {
      ndbg("ERROR: frame too short\n");
      return;
    }

  wh = mtod(iob, struct ieee80211_frame *);
  frm = (const uint8_t *)&wh[1];
  efrm = mtod(iob, uint8_t *) + iob->m_len;

  tstamp  = frm; frm += 8;
  bintval = LE_READ_2(frm); frm += 2;
  capinfo = LE_READ_2(frm); frm += 2;

  ssid = rates = xrates = edcaie = wmmie = rsnie = wpaie = NULL;
  htcaps = htop = NULL;
  bchan = ieee80211_chan2ieee(ic, ic->ic_bss->ni_chan);
  chan = bchan;
  erp = 0;
  while (frm + 2 <= efrm)
    {
      if (frm + 2 + frm[1] > efrm)
        {
          ic->ic_stats.is_rx_elem_toosmall++;
          break;
        }

      switch (frm[0])
        {
        case IEEE80211_ELEMID_SSID:
          ssid = frm;
          break;

        case IEEE80211_ELEMID_RATES:
          rates = frm;
          break;

        case IEEE80211_ELEMID_DSPARMS:
          if (frm[1] < 1)
            {
              ic->ic_stats.is_rx_elem_toosmall++;
              break;
              }

          chan = frm[2];
          break;

        case IEEE80211_ELEMID_XRATES:
          xrates = frm;
          break;

        case IEEE80211_ELEMID_ERP:
          if (frm[1] < 1)
            {
              ic->ic_stats.is_rx_elem_toosmall++;
              break;
            }

          erp = frm[2];
          break;

        case IEEE80211_ELEMID_RSN:
          rsnie = frm;
          break;

        case IEEE80211_ELEMID_EDCAPARMS:
          edcaie = frm;
          break;

#ifdef CONFIG_IEEE80211_HT
        case IEEE80211_ELEMID_HTCAPS:
          htcaps = frm;
          break;

        case IEEE80211_ELEMID_HTOP:
          htop = frm;
          break;
#endif

        case IEEE80211_ELEMID_VENDOR:
          if (frm[1] < 4)
            {
              ic->ic_stats.is_rx_elem_toosmall++;
              break;
            }

          if (memcmp(frm + 2, MICROSOFT_OUI, 3) == 0)
            {
              if (frm[5] == 1)
                {
                  wpaie = frm;
                }
              else if (frm[1] >= 5 && frm[5] == 2 && frm[6] == 1)
                {
                  wmmie = frm;
                }
            }

          break;
        }

      frm += 2 + frm[1];
    }

  /* Supported rates element is mandatory */

  if (rates == NULL || rates[1] > IEEE80211_RATE_MAXSIZE)
    {
      ndbg("ERROR: invalid supported rates element\n");
      return;
    }

  /* SSID element is mandatory */

  if (ssid == NULL || ssid[1] > IEEE80211_NWID_LEN)
    {
      ndbg("ERROR: invalid SSID element\n");
      return;
    }

  ndx = (chan >> 3);
  bit = (chan & 7);

  if (
#if IEEE80211_CHAN_MAX < 255
      chan > IEEE80211_CHAN_MAX ||
#endif
      (ic->ic_chan_active[ndx] & (1 << bit)) == 0)
    {
      ndbg("ERROR: ignore %s with invalid channel %u\n",
          isprobe ? "probe response" : "beacon", chan);

      ic->ic_stats.is_rx_badchan++;
      return;
    }

  if ((ic->ic_state != IEEE80211_S_SCAN ||
       !(ic->ic_caps & IEEE80211_C_SCANALL)) &&
      chan != bchan)
    {
      /* Frame was received on a channel different from the
       * one indicated in the DS params element id;
       * silently discard it.
       *
       * NB: this can happen due to signal leakage.
       */

      ndbg("ERROR: ignore %s on channel %u marked for channel %u\n",
          isprobe ? "probe response" : "beacon", bchan, chan);

      ic->ic_stats.is_rx_chanmismatch++;
      return;
    }

  /* Use mac, channel and rssi so we collect only the
   * best potential AP with the equal bssid while scanning.
   * Collecting all potential APs may result in bloat of
   * the node tree. This call will return NULL if the node
   * for this APs does not exist or if the new node is the
   * potential better one.
   */

  if ((ni = ieee80211_find_node_for_beacon(ic, wh->i_addr2,
      &ic->ic_channels[chan], ssid, rxi->rxi_rssi)) != NULL)
    {
      return;
    }

#ifdef CONFIG_DEBUG_NET
  if ((ni == NULL || ic->ic_state == IEEE80211_S_SCAN))
    {
      nvdbg("%s%s on chan %u (bss chan %u) ",
            (ni == NULL ? "new " : ""),
            isprobe ? "probe response" : "beacon",
            chan, bchan);

      ieee80211_print_essid(ssid + 2, ssid[1]);

      nvdbg(" from %s\n", ieee80211_addr2str((uint8_t *)wh->i_addr2));
      nvdbg("caps 0x%x bintval %u erp 0x%x\n",
            capinfo, bintval, erp);
    }
#endif

  if ((ni = ieee80211_find_node(ic, wh->i_addr2)) == NULL)
    {
      ni = ieee80211_alloc_node(ic, wh->i_addr2);
      if (ni == NULL)
        {
          return;
        }

      is_new = 1;
    }
  else
    {
      is_new = 0;
    }

  /* When operating in station mode, check for state updates while we're
   * associated. We consider only 11g stuff right now.
   */

  if (ic->ic_opmode == IEEE80211_M_STA &&
      ic->ic_state == IEEE80211_S_RUN &&
      ni->ni_state == IEEE80211_STA_BSS)
    {
      /* Check if protection mode has changed since last beacon */

      if (ni->ni_erp != erp)
        {
          nvdbg("[%s] erp change: was 0x%x, now 0x%x\n",
              ieee80211_addr2str((uint8_t *)wh->i_addr2),
              ni->ni_erp, erp);

          if (ic->ic_curmode == IEEE80211_MODE_11G &&
              (erp & IEEE80211_ERP_USE_PROTECTION))
            {
              ic->ic_flags |= IEEE80211_F_USEPROT;
            }
          else
            {
              ic->ic_flags &= ~IEEE80211_F_USEPROT;
            }

          ic->ic_bss->ni_erp = erp;
        }

      /* Check if AP short slot time setting has changed since last beacon
       * and give the driver a chance to update the hardware.
       */

      if ((ni->ni_capinfo ^ capinfo) & IEEE80211_CAPINFO_SHORT_SLOTTIME)
        {
          ieee80211_set_shortslottime(ic,
              ic->ic_curmode == IEEE80211_MODE_11A ||
              (capinfo & IEEE80211_CAPINFO_SHORT_SLOTTIME));
        }
    }

  /* We do not try to update EDCA parameters if QoS was not negotiated
   * with the AP at association time.
   */

  if (ni->ni_flags & IEEE80211_NODE_QOS)
    {
      /* Always prefer EDCA IE over Wi-Fi Alliance WMM IE */

      if (edcaie != NULL)
        {
          ieee80211_parse_edca_params(ic, edcaie);
        }
      else if (wmmie != NULL)
        {
          ieee80211_parse_wmm_params(ic, wmmie);
        }
    }

  if (ic->ic_state == IEEE80211_S_SCAN &&
#ifdef CONFIG_IEEE80211_AP
      ic->ic_opmode != IEEE80211_M_HOSTAP &&
#endif
      (ic->ic_flags & IEEE80211_F_RSNON))
    {
      struct ieee80211_rsnparams rsn;
      const uint8_t *saveie = NULL;

      /* If the AP advertises both RSN and WPA IEs (WPA1+WPA2),
       * we only store the parameters of the highest protocol
       * version we support.
       */

      if (rsnie != NULL && (ic->ic_rsnprotos & IEEE80211_PROTO_RSN))
        {
          if (ieee80211_parse_rsn(ic, rsnie, &rsn) == 0)
            {
              ni->ni_rsnprotos = IEEE80211_PROTO_RSN;
              saveie = rsnie;
            }
        }
      else if (wpaie != NULL && (ic->ic_rsnprotos & IEEE80211_PROTO_WPA))
        {
          if (ieee80211_parse_wpa(ic, wpaie, &rsn) == 0)
            {
              ni->ni_rsnprotos = IEEE80211_PROTO_WPA;
              saveie = wpaie;
            }
        }

      if (saveie != NULL && ieee80211_save_ie(saveie, &ni->ni_rsnie) == 0)
        {
          ni->ni_rsnakms = rsn.rsn_akms;
          ni->ni_rsnciphers = rsn.rsn_ciphers;
          ni->ni_rsngroupcipher = rsn.rsn_groupcipher;
          ni->ni_rsngroupmgmtcipher = rsn.rsn_groupmgmtcipher;
          ni->ni_rsncaps = rsn.rsn_caps;
        }
      else
        {
          ni->ni_rsnprotos = IEEE80211_PROTO_NONE;
        }
    }
  else if (ic->ic_state == IEEE80211_S_SCAN)
    {
      ni->ni_rsnprotos = IEEE80211_PROTO_NONE;
    }

  if (ssid[1] != 0 && ni->ni_esslen == 0)
    {
      ni->ni_esslen = ssid[1];
      memset(ni->ni_essid, 0, sizeof(ni->ni_essid));

      /* We know that ssid[1] <= IEEE80211_NWID_LEN */

      memcpy(ni->ni_essid, &ssid[2], ssid[1]);
    }

  IEEE80211_ADDR_COPY(ni->ni_bssid, wh->i_addr3);
  ni->ni_rssi = rxi->rxi_rssi;
  ni->ni_rstamp = rxi->rxi_tstamp;
  memcpy(ni->ni_tstamp, tstamp, sizeof(ni->ni_tstamp));
  ni->ni_intval = bintval;
  ni->ni_capinfo = capinfo;

  /* XXX validate channel # */

  ni->ni_chan = &ic->ic_channels[chan];
  ni->ni_erp = erp;

  /* NB: must be after ni_chan is setup */

  ieee80211_setup_rates(ic, ni, rates, xrates, IEEE80211_F_DOSORT);

  /* When scanning we record results (nodes) with a zero
   * refcnt.  Otherwise we want to hold the reference for
   * ibss neighbors so the nodes don't get released prematurely.
   * Anything else can be discarded (XXX and should be handled
   * above so we don't do so much work).
   */

  if (
#ifdef CONFIG_IEEE80211_AP
      ic->ic_opmode == IEEE80211_M_IBSS ||
#endif
      (is_new && isprobe))
    {
      /* Fake an association so the driver can setup it's
       * private state.  The rate set has been setup above;
       * there is no handshake as in ap/station operation.
       */

      if (ic->ic_newassoc)
        {
          (*ic->ic_newassoc)(ic, ni, 1);
        }
    }
}

#ifdef CONFIG_IEEE80211_AP
/* Probe request frame format:
 * [tlv] SSID
 * [tlv] Supported rates
 * [tlv] Extended Supported Rates (802.11g)
 * [tlv] HT Capabilities (802.11n)
 */

void ieee80211_recv_probe_req(struct ieee80211com *ic, struct ieee80211_iobuf_s *iob,
    struct ieee80211_node *ni, struct ieee80211_rxinfo *rxi)
{
    const struct ieee80211_frame *wh;
    const uint8_t *frm, *efrm;
    const uint8_t *ssid, *rates, *xrates, *htcaps;
    uint8_t rate;

    if (ic->ic_opmode == IEEE80211_M_STA ||
        ic->ic_state != IEEE80211_S_RUN)
        return;

    wh = mtod(iob, struct ieee80211_frame *);
    frm = (const uint8_t *)&wh[1];
    efrm = mtod(iob, uint8_t *) + iob->m_len;

    ssid = rates = xrates = htcaps = NULL;
    while (frm + 2 <= efrm) {
        if (frm + 2 + frm[1] > efrm) {
            ic->ic_stats.is_rx_elem_toosmall++;
            break;
        }
        switch (frm[0]) {
        case IEEE80211_ELEMID_SSID:
            ssid = frm;
            break;
        case IEEE80211_ELEMID_RATES:
            rates = frm;
            break;
        case IEEE80211_ELEMID_XRATES:
            xrates = frm;
            break;
#ifdef CONFIG_IEEE80211_HT
        case IEEE80211_ELEMID_HTCAPS:
            htcaps = frm;
            break;
#endif
        }
        frm += 2 + frm[1];
    }
    /* supported rates element is mandatory */
    if (rates == NULL || rates[1] > IEEE80211_RATE_MAXSIZE) {
        ndbg("ERROR: invalid supported rates element\n");
        return;
    }
    /* SSID element is mandatory */
    if (ssid == NULL || ssid[1] > IEEE80211_NWID_LEN) {
        ndbg("ERROR: invalid SSID element\n");
        return;
    }
    /* check that the specified SSID (if not wildcard) matches ours */
    if (ssid[1] != 0 && (ssid[1] != ic->ic_bss->ni_esslen ||
        memcmp(&ssid[2], ic->ic_bss->ni_essid, ic->ic_bss->ni_esslen)))
      {
        ndbg("ERROR: SSID mismatch\n");
        ic->ic_stats.is_rx_ssidmismatch++;
        return;
      }

    /* refuse wildcard SSID if we're hiding our SSID in beacons */

    if (ssid[1] == 0 && (ic->ic_flags & IEEE80211_F_HIDENWID)) {
        ndbg("ERROR: wildcard SSID rejected");
        ic->ic_stats.is_rx_ssidmismatch++;
        return;
    }

    if (ni == ic->ic_bss)
      {
        ni = ieee80211_find_node(ic, wh->i_addr2);
        if (ni == NULL)
            ni = ieee80211_dup_bss(ic, wh->i_addr2);
        if (ni == NULL)
            return;
        ndbg("ERROR: new probe req from %s\n",
            ieee80211_addr2str((uint8_t *)wh->i_addr2));
      }

    ni->ni_rssi = rxi->rxi_rssi;
    ni->ni_rstamp = rxi->rxi_tstamp;
    rate = ieee80211_setup_rates(ic, ni, rates, xrates,
        IEEE80211_F_DOSORT | IEEE80211_F_DOFRATE | IEEE80211_F_DONEGO |
        IEEE80211_F_DODEL);
    if (rate & IEEE80211_RATE_BASIC) {
        ndbg("ERROR: rate mismatch for %s\n",
            ieee80211_addr2str((uint8_t *)wh->i_addr2));
        return;
    }
    IEEE80211_SEND_MGMT(ic, ni, IEEE80211_FC0_SUBTYPE_PROBE_RESP, 0);
}
#endif /* CONFIG_IEEE80211_AP */

/* Authentication frame format:
 * [2] Authentication algorithm number
 * [2] Authentication transaction sequence number
 * [2] Status code
 */

void ieee80211_recv_auth(struct ieee80211com *ic, struct ieee80211_iobuf_s *iob,
    struct ieee80211_node *ni, struct ieee80211_rxinfo *rxi)
{
    const struct ieee80211_frame *wh;
    const uint8_t *frm;
    uint16_t algo, seq, status;

    /* make sure all mandatory fixed fields are present */
    if (iob->m_len < sizeof(*wh) + 6) {
        ndbg("ERROR: frame too short\n");
        return;
    }
    wh = mtod(iob, struct ieee80211_frame *);
    frm = (const uint8_t *)&wh[1];

    algo   = LE_READ_2(frm); frm += 2;
    seq    = LE_READ_2(frm); frm += 2;
    status = LE_READ_2(frm); frm += 2;
    nvdbg("auth %d seq %d from %s\n", algo, seq,
        ieee80211_addr2str((uint8_t *)wh->i_addr2));

    /* only "open" auth mode is supported */
    if (algo != IEEE80211_AUTH_ALG_OPEN) {
        ndbg("ERROR: unsupported auth algorithm %d from %s\n",
            algo, ieee80211_addr2str((uint8_t *)wh->i_addr2));
        ic->ic_stats.is_rx_auth_unsupported++;
#ifdef CONFIG_IEEE80211_AP
        if (ic->ic_opmode == IEEE80211_M_HOSTAP)
          {
            /* XXX hack to workaround calling convention */

            IEEE80211_SEND_MGMT(ic, ni,
                IEEE80211_FC0_SUBTYPE_AUTH,
                IEEE80211_STATUS_ALG << 16 | ((seq + 1) & 0xffff));
          }
#endif
        return;
    }
    ieee80211_auth_open(ic, wh, ni, rxi, seq, status);
}

#ifdef CONFIG_IEEE80211_AP
/* (Re)Association request frame format:
 * [2]   Capability information
 * [2]   Listen interval
 * [6*]  Current AP address (Reassociation only)
 * [tlv] SSID
 * [tlv] Supported rates
 * [tlv] Extended Supported Rates (802.11g)
 * [tlv] RSN (802.11i)
 * [tlv] QoS Capability (802.11e)
 * [tlv] HT Capabilities (802.11n)
 */

void ieee80211_recv_assoc_req(struct ieee80211com *ic, struct ieee80211_iobuf_s *iob,
    struct ieee80211_node *ni, struct ieee80211_rxinfo *rxi, int reassoc)
{
    const struct ieee80211_frame *wh;
    const uint8_t *frm, *efrm;
    const uint8_t *ssid, *rates, *xrates, *rsnie, *wpaie, *htcaps;
    uint16_t capinfo, bintval;
    int resp, status = 0;
    struct ieee80211_rsnparams rsn;
    uint8_t rate;

    if (ic->ic_opmode != IEEE80211_M_HOSTAP ||
        ic->ic_state != IEEE80211_S_RUN)
        return;

    /* make sure all mandatory fixed fields are present */
    if (iob->m_len < sizeof(*wh) + (reassoc ? 10 : 4)) {
        ndbg("ERROR: frame too short\n");
        return;
    }
    wh = mtod(iob, struct ieee80211_frame *);
    frm = (const uint8_t *)&wh[1];
    efrm = mtod(iob, uint8_t *) + iob->m_len;

    if (!IEEE80211_ADDR_EQ(wh->i_addr3, ic->ic_bss->ni_bssid))
      {
        ndbg("ERROR: ignore other bss from %s\n",
            ieee80211_addr2str((uint8_t *)wh->i_addr2));
        ic->ic_stats.is_rx_assoc_bss++;
        return;
      }

    capinfo = LE_READ_2(frm); frm += 2;
    bintval = LE_READ_2(frm); frm += 2;
    if (reassoc) {
        frm += IEEE80211_ADDR_LEN;    /* skip current AP address */
        resp = IEEE80211_FC0_SUBTYPE_REASSOC_RESP;
    } else
        resp = IEEE80211_FC0_SUBTYPE_ASSOC_RESP;

    ssid = rates = xrates = rsnie = wpaie = htcaps = NULL;
    while (frm + 2 <= efrm) {
        if (frm + 2 + frm[1] > efrm) {
            ic->ic_stats.is_rx_elem_toosmall++;
            break;
        }
        switch (frm[0]) {
        case IEEE80211_ELEMID_SSID:
            ssid = frm;
            break;
        case IEEE80211_ELEMID_RATES:
            rates = frm;
            break;
        case IEEE80211_ELEMID_XRATES:
            xrates = frm;
            break;
        case IEEE80211_ELEMID_RSN:
            rsnie = frm;
            break;
        case IEEE80211_ELEMID_QOS_CAP:
            break;
#ifdef CONFIG_IEEE80211_HT
        case IEEE80211_ELEMID_HTCAPS:
            htcaps = frm;
            break;
#endif
        case IEEE80211_ELEMID_VENDOR:
            if (frm[1] < 4) {
                ic->ic_stats.is_rx_elem_toosmall++;
                break;
            }
            if (memcmp(frm + 2, MICROSOFT_OUI, 3) == 0) {
                if (frm[5] == 1)
                    wpaie = frm;
            }
            break;
        }
        frm += 2 + frm[1];
    }
    /* supported rates element is mandatory */
    if (rates == NULL || rates[1] > IEEE80211_RATE_MAXSIZE) {
        ndbg("ERROR: invalid supported rates element\n");
        return;
    }
    /* SSID element is mandatory */
    if (ssid == NULL || ssid[1] > IEEE80211_NWID_LEN)
      {
        ndbg("ERROR: invalid SSID element\n");
        return;
      }

    /* check that the specified SSID matches ours */

    if (ssid[1] != ic->ic_bss->ni_esslen ||
        memcmp(&ssid[2], ic->ic_bss->ni_essid, ic->ic_bss->ni_esslen))
      {
        ndbg("ERROR: SSID mismatch\n");
        ic->ic_stats.is_rx_ssidmismatch++;
        return;
      }

    if (ni->ni_state != IEEE80211_STA_AUTH &&
        ni->ni_state != IEEE80211_STA_ASSOC) {
        nvdbg("deny %sassoc from %s, not authenticated\n",
            reassoc ? "re" : "",
            ieee80211_addr2str((uint8_t *)wh->i_addr2));
        ni = ieee80211_find_node(ic, wh->i_addr2);
        if (ni == NULL)
            ni = ieee80211_dup_bss(ic, wh->i_addr2);
        if (ni != NULL) {
            IEEE80211_SEND_MGMT(ic, ni,
                IEEE80211_FC0_SUBTYPE_DEAUTH,
                IEEE80211_REASON_ASSOC_NOT_AUTHED);
        }
        ic->ic_stats.is_rx_assoc_notauth++;
        return;
    }

    if (ni->ni_state == IEEE80211_STA_ASSOC &&
        (ni->ni_flags & IEEE80211_NODE_MFP)) {
        if (ni->ni_flags & IEEE80211_NODE_SA_QUERY_FAILED) {
            /* send a protected Disassociate frame */
            IEEE80211_SEND_MGMT(ic, ni,
                IEEE80211_FC0_SUBTYPE_DISASSOC,
                IEEE80211_REASON_AUTH_EXPIRE);
            /* terminate the old SA */
            ieee80211_node_leave(ic, ni);
        } else {
            /* reject the (Re)Association Request temporarily */
            IEEE80211_SEND_MGMT(ic, ni, resp,
                IEEE80211_STATUS_TRY_AGAIN_LATER);
            /* start SA Query procedure if not already engaged */
            if (!(ni->ni_flags & IEEE80211_NODE_SA_QUERY))
                ieee80211_sa_query_request(ic, ni);
            /* do not modify association state */
        }
        return;
    }

    if (!(capinfo & IEEE80211_CAPINFO_ESS)) {
        ic->ic_stats.is_rx_assoc_capmismatch++;
        status = IEEE80211_STATUS_CAPINFO;
        goto end;
    }
    rate = ieee80211_setup_rates(ic, ni, rates, xrates,
        IEEE80211_F_DOSORT | IEEE80211_F_DOFRATE | IEEE80211_F_DONEGO |
        IEEE80211_F_DODEL);
    if (rate & IEEE80211_RATE_BASIC) {
        ic->ic_stats.is_rx_assoc_norate++;
        status = IEEE80211_STATUS_BASIC_RATE;
        goto end;
    }

    if (ic->ic_flags & IEEE80211_F_RSNON) {
        const uint8_t *saveie;
        /*
         * A station should never include both a WPA and an RSN IE
         * in its (Re)Association Requests, but if it does, we only
         * consider the IE of the highest version of the protocol
         * that is allowed (ie RSN over WPA).
         */
        if (rsnie != NULL &&
            (ic->ic_rsnprotos & IEEE80211_PROTO_RSN)) {
            status = ieee80211_parse_rsn(ic, rsnie, &rsn);
            if (status != 0)
                goto end;
            ni->ni_rsnprotos = IEEE80211_PROTO_RSN;
            saveie = rsnie;
        } else if (wpaie != NULL &&
            (ic->ic_rsnprotos & IEEE80211_PROTO_WPA)) {
            status = ieee80211_parse_wpa(ic, wpaie, &rsn);
            if (status != 0)
                goto end;
            ni->ni_rsnprotos = IEEE80211_PROTO_WPA;
            saveie = wpaie;
        } else {
            /*
             * In an RSN, an AP shall not associate with STAs
             * that fail to include the RSN IE in the
             * (Re)Association Request.
             */
            status = IEEE80211_STATUS_IE_INVALID;
            goto end;
        }
        /*
         * The initiating STA's RSN IE shall include one authentication
         * and pairwise cipher suite among those advertised by the
         * targeted AP.  It shall also specify the group cipher suite
         * specified by the targeted AP.
         */
        if (rsn.rsn_nakms != 1 ||
            !(rsn.rsn_akms & ic->ic_bss->ni_rsnakms))
          {
            status = IEEE80211_STATUS_BAD_AKMP;
            goto end;
          }

        if (rsn.rsn_nciphers != 1 ||
            !(rsn.rsn_ciphers & ic->ic_bss->ni_rsnciphers))
          {
            status = IEEE80211_STATUS_BAD_PAIRWISE_CIPHER;
            goto end;
          }

        if (rsn.rsn_groupcipher != ic->ic_bss->ni_rsngroupcipher)
          {
            status = IEEE80211_STATUS_BAD_GROUP_CIPHER;
            goto end;
          }

        if ((ic->ic_bss->ni_rsncaps & IEEE80211_RSNCAP_MFPR) &&
            !(rsn.rsn_caps & IEEE80211_RSNCAP_MFPC))
          {
            status = IEEE80211_STATUS_MFP_POLICY;
            goto end;
          }

        if ((ic->ic_bss->ni_rsncaps & IEEE80211_RSNCAP_MFPC) &&
            (rsn.rsn_caps & (IEEE80211_RSNCAP_MFPC |
             IEEE80211_RSNCAP_MFPR)) == IEEE80211_RSNCAP_MFPR)
          {
            /* STA advertises an invalid setting */
            status = IEEE80211_STATUS_MFP_POLICY;
            goto end;
          }

        /* A STA that has associated with Management Frame Protection
         * enabled shall not use cipher suite pairwise selector WEP40,
         * WEP104, TKIP, or "Use Group cipher suite".
         */

        if ((rsn.rsn_caps & IEEE80211_RSNCAP_MFPC) &&
            (rsn.rsn_ciphers != IEEE80211_CIPHER_CCMP ||
             rsn.rsn_groupmgmtcipher !=
             ic->ic_bss->ni_rsngroupmgmtcipher))
          {
            status = IEEE80211_STATUS_MFP_POLICY;
            goto end;
          }

        /* Disallow new associations using TKIP if countermeasures
         * are active.
         */

        if ((ic->ic_flags & IEEE80211_F_COUNTERM) &&
            (rsn.rsn_ciphers == IEEE80211_CIPHER_TKIP ||
             rsn.rsn_groupcipher == IEEE80211_CIPHER_TKIP))
          {
            status = IEEE80211_STATUS_CIPHER_REJ_POLICY;
            goto end;
          }

        /* everything looks fine, save IE and parameters */
        if (ieee80211_save_ie(saveie, &ni->ni_rsnie) != 0) {
            status = IEEE80211_STATUS_TOOMANY;
            goto end;
        }
        ni->ni_rsnakms = rsn.rsn_akms;
        ni->ni_rsnciphers = rsn.rsn_ciphers;
        ni->ni_rsngroupcipher = ic->ic_bss->ni_rsngroupcipher;
        ni->ni_rsngroupmgmtcipher = ic->ic_bss->ni_rsngroupmgmtcipher;
        ni->ni_rsncaps = rsn.rsn_caps;

        if (ieee80211_is_8021x_akm(ni->ni_rsnakms)) {
            struct ieee80211_pmk *pmk = NULL;
            const uint8_t *pmkid = rsn.rsn_pmkids;

            /* Check if we have a cached PMK entry matching one
             * of the PMKIDs specified in the RSN IE.
             */

            while (rsn.rsn_npmkids-- > 0)
              {
                pmk = ieee80211_pmksa_find(ic, ni, pmkid);
                if (pmk != NULL)
                  {
                    break;
                  }

                pmkid += IEEE80211_PMKID_LEN;
              }

            if (pmk != NULL)
              {
                memcpy(ni->ni_pmk, pmk->pmk_key, IEEE80211_PMK_LEN);
                memcpy(ni->ni_pmkid, pmk->pmk_pmkid, IEEE80211_PMKID_LEN);
                ni->ni_flags |= IEEE80211_NODE_PMK;
              }
        }
    } else
        ni->ni_rsnprotos = IEEE80211_PROTO_NONE;

    ni->ni_rssi = rxi->rxi_rssi;
    ni->ni_rstamp = rxi->rxi_tstamp;
    ni->ni_intval = bintval;
    ni->ni_capinfo = capinfo;
    ni->ni_chan = ic->ic_bss->ni_chan;
 end:
    if (status != 0) {
        IEEE80211_SEND_MGMT(ic, ni, resp, status);
        ieee80211_node_leave(ic, ni);
    } else
        ieee80211_node_join(ic, ni, resp);
}
#endif /* CONFIG_IEEE80211_AP */

/* (Re)Association response frame format:
 * [2]   Capability information
 * [2]   Status code
 * [2]   Association ID (AID)
 * [tlv] Supported rates
 * [tlv] Extended Supported Rates (802.11g)
 * [tlv] EDCA Parameter Set (802.11e)
 * [tlv] HT Capabilities (802.11n)
 * [tlv] HT Operation (802.11n)
 */

void ieee80211_recv_assoc_resp(struct ieee80211com *ic, struct ieee80211_iobuf_s *iob,
    struct ieee80211_node *ni, int reassoc)
{
    const struct ieee80211_frame *wh;
    const uint8_t *frm, *efrm;
    const uint8_t *rates, *xrates, *edcaie, *wmmie, *htcaps, *htop;
    uint16_t capinfo, status, associd;
    uint8_t rate;

    if (ic->ic_opmode != IEEE80211_M_STA ||
        ic->ic_state != IEEE80211_S_ASSOC) {
        ic->ic_stats.is_rx_mgtdiscard++;
        return;
    }

    /* make sure all mandatory fixed fields are present */
    if (iob->m_len < sizeof(*wh) + 6) {
        ndbg("ERROR: frame too short\n");
        return;
    }
    wh = mtod(iob, struct ieee80211_frame *);
    frm = (const uint8_t *)&wh[1];
    efrm = mtod(iob, uint8_t *) + iob->m_len;

    capinfo = LE_READ_2(frm); frm += 2;
    status =  LE_READ_2(frm); frm += 2;
    if (status != IEEE80211_STATUS_SUCCESS)
      {
        nvdbg("%s: %sassociation failed (status %d) for %s\n",
              ic->ic_ifname, reassoc ?  "re" : "",
              status, ieee80211_addr2str((uint8_t *)wh->i_addr3));

        if (ni != ic->ic_bss)
          {
            ni->ni_fails++;
          }

        ic->ic_stats.is_rx_auth_fail++;
        return;
    }
    associd = LE_READ_2(frm); frm += 2;

    rates = xrates = edcaie = wmmie = htcaps = htop = NULL;
    while (frm + 2 <= efrm) {
        if (frm + 2 + frm[1] > efrm) {
            ic->ic_stats.is_rx_elem_toosmall++;
            break;
        }
        switch (frm[0]) {
        case IEEE80211_ELEMID_RATES:
            rates = frm;
            break;
        case IEEE80211_ELEMID_XRATES:
            xrates = frm;
            break;
        case IEEE80211_ELEMID_EDCAPARMS:
            edcaie = frm;
            break;
#ifdef CONFIG_IEEE80211_HT
        case IEEE80211_ELEMID_HTCAPS:
            htcaps = frm;
            break;
        case IEEE80211_ELEMID_HTOP:
            htop = frm;
            break;
#endif
        case IEEE80211_ELEMID_VENDOR:
            if (frm[1] < 4) {
                ic->ic_stats.is_rx_elem_toosmall++;
                break;
            }
            if (memcmp(frm + 2, MICROSOFT_OUI, 3) == 0) {
                if (frm[1] >= 5 && frm[5] == 2 && frm[6] == 1)
                    wmmie = frm;
            }
            break;
        }
        frm += 2 + frm[1];
    }
    /* supported rates element is mandatory */
    if (rates == NULL || rates[1] > IEEE80211_RATE_MAXSIZE) {
        ndbg("ERROR: invalid supported rates element\n");
        return;
    }
    rate = ieee80211_setup_rates(ic, ni, rates, xrates,
        IEEE80211_F_DOSORT | IEEE80211_F_DOFRATE | IEEE80211_F_DONEGO |
        IEEE80211_F_DODEL);
    if (rate & IEEE80211_RATE_BASIC) {
        ndbg("ERROR: rate mismatch for %s\n",
            ieee80211_addr2str((uint8_t *)wh->i_addr2));
        ic->ic_stats.is_rx_assoc_norate++;
        return;
    }

    ni->ni_capinfo = capinfo;
    ni->ni_associd = associd;
    if (edcaie != NULL || wmmie != NULL)
      {
        /* force update of EDCA parameters */
        ic->ic_edca_updtcount = -1;

        if ((edcaie != NULL &&
             ieee80211_parse_edca_params(ic, edcaie) == 0) ||
            (wmmie != NULL &&
             ieee80211_parse_wmm_params(ic, wmmie) == 0))
            ni->ni_flags |= IEEE80211_NODE_QOS;
        else    /* for Reassociation */
            ni->ni_flags &= ~IEEE80211_NODE_QOS;
      }

    /*
     * Configure state now that we are associated.
     */
    if (ic->ic_curmode == IEEE80211_MODE_11A ||
        (ni->ni_capinfo & IEEE80211_CAPINFO_SHORT_PREAMBLE))
        ic->ic_flags |= IEEE80211_F_SHPREAMBLE;
    else
        ic->ic_flags &= ~IEEE80211_F_SHPREAMBLE;

    ieee80211_set_shortslottime(ic,
        ic->ic_curmode == IEEE80211_MODE_11A ||
        (ni->ni_capinfo & IEEE80211_CAPINFO_SHORT_SLOTTIME));
    /*
     * Honor ERP protection.
     */
    if (ic->ic_curmode == IEEE80211_MODE_11G &&
        (ni->ni_erp & IEEE80211_ERP_USE_PROTECTION))
        ic->ic_flags |= IEEE80211_F_USEPROT;
    else
        ic->ic_flags &= ~IEEE80211_F_USEPROT;
    /*
     * If not an RSNA, mark the port as valid, otherwise wait for
     * 802.1X authentication and 4-way handshake to complete..
     */
    if (ic->ic_flags & IEEE80211_F_RSNON) {
        /* XXX ic->ic_mgt_timer = 5; */
    } else if (ic->ic_flags & IEEE80211_F_WEPON)
        ni->ni_flags |= IEEE80211_NODE_TXRXPROT;

    ieee80211_new_state(ic, IEEE80211_S_RUN,
        IEEE80211_FC0_SUBTYPE_ASSOC_RESP);
}

/* Deauthentication frame format:
 * [2] Reason code
 */

void ieee80211_recv_deauth(struct ieee80211com *ic, struct ieee80211_iobuf_s *iob,
    struct ieee80211_node *ni)
{
    const struct ieee80211_frame *wh;
    const uint8_t *frm;
    uint16_t reason;

    /* make sure all mandatory fixed fields are present */
    if (iob->m_len < sizeof(*wh) + 2) {
        ndbg("ERROR: frame too short\n");
        return;
    }
    wh = mtod(iob, struct ieee80211_frame *);
    frm = (const uint8_t *)&wh[1];

    reason = LE_READ_2(frm);

    ic->ic_stats.is_rx_deauth++;
    switch (ic->ic_opmode) {
    case IEEE80211_M_STA:
        ieee80211_new_state(ic, IEEE80211_S_AUTH,
            IEEE80211_FC0_SUBTYPE_DEAUTH);
        break;
#ifdef CONFIG_IEEE80211_AP
    case IEEE80211_M_HOSTAP:
        if (ni != ic->ic_bss)
          {
            nvdbg("%s: station %s deauthenticated by peer (reason %d)\n",
                  ic->ic_ifname, ieee80211_addr2str(ni->ni_macaddr), reason);

            ieee80211_node_leave(ic, ni);
          }
        break;
#endif
    default:
        break;
    }
}

/* Disassociation frame format:
 * [2] Reason code
 */

void ieee80211_recv_disassoc(struct ieee80211com *ic, struct ieee80211_iobuf_s *iob,
    struct ieee80211_node *ni)
{
    const struct ieee80211_frame *wh;
    const uint8_t *frm;
    uint16_t reason;

    /* make sure all mandatory fixed fields are present */
    if (iob->m_len < sizeof(*wh) + 2) {
        ndbg("ERROR: frame too short\n");
        return;
    }
    wh = mtod(iob, struct ieee80211_frame *);
    frm = (const uint8_t *)&wh[1];

    reason = LE_READ_2(frm);

    ic->ic_stats.is_rx_disassoc++;
    switch (ic->ic_opmode) {
    case IEEE80211_M_STA:
        ieee80211_new_state(ic, IEEE80211_S_ASSOC,
            IEEE80211_FC0_SUBTYPE_DISASSOC);
        break;
#ifdef CONFIG_IEEE80211_AP
    case IEEE80211_M_HOSTAP:
        if (ni != ic->ic_bss)
          {
            nvdbg("%s: station %s disassociated by peer (reason %d)\n",
                  ic->ic_ifname, ieee80211_addr2str(ni->ni_macaddr), reason);

            ieee80211_node_leave(ic, ni);
        }
        break;
#endif
    default:
        break;
    }
}

#ifdef CONFIG_IEEE80211_HT
/* ADDBA Request frame format:
 * [1] Category
 * [1] Action
 * [1] Dialog Token
 * [2] Block Ack Parameter Set
 * [2] Block Ack Timeout Value
 * [2] Block Ack Starting Sequence Control
 */

void ieee80211_recv_addba_req(struct ieee80211com *ic, struct ieee80211_iobuf_s *iob,
    struct ieee80211_node *ni)
{
    const struct ieee80211_frame *wh;
    const uint8_t *frm;
    struct ieee80211_rx_ba *ba;
    uint16_t params, ssn, bufsz, timeout, status;
    uint8_t token, tid;

    if (!(ni->ni_flags & IEEE80211_NODE_HT))
      {
        ndbg("ERROR: received ADDBA req from non-HT STA %s\n",
            ieee80211_addr2str(ni->ni_macaddr));
        return;
      }

    if (iob->m_len < sizeof(*wh) + 9)
      {
        ndbg("ERROR: frame too short\n");
        return;
      }

    /* MLME-ADDBA.indication */

    wh = mtod(iob, struct ieee80211_frame *);
    frm = (const uint8_t *)&wh[1];

    token = frm[2];
    params = LE_READ_2(&frm[3]);
    tid = (params >> 2) & 0xf;
    bufsz = (params >> 6) & 0x3ff;
    timeout = LE_READ_2(&frm[5]);
    ssn = LE_READ_2(&frm[7]) >> 4;

    ba = &ni->ni_rx_ba[tid];
    /* check if we already have a Block Ack agreement for this RA/TID */
    if (ba->ba_state == IEEE80211_BA_AGREED) {
        /* XXX should we update the timeout value? */
        /* reset Block Ack inactivity timer */
        wd_start(ba->ba_to, USEC2TICK(ba->ba_timeout_val), ieee80211_rx_ba_timeout, 1, ba);

        /* check if it's a Protected Block Ack agreement */
        if (!(ni->ni_flags & IEEE80211_NODE_MFP) ||
            !(ni->ni_rsncaps & IEEE80211_RSNCAP_PBAC))
            return;    /* not a PBAC, ignore */

        /* PBAC: treat the ADDBA Request like a BlockAckReq */
        if (SEQ_LT(ba->ba_winstart, ssn))
            ieee80211_ba_move_window(ic, ni, tid, ssn);
        return;
    }
    /* if PBAC required but RA does not support it, refuse request */
    if ((ic->ic_flags & IEEE80211_F_PBAR) &&
        (!(ni->ni_flags & IEEE80211_NODE_MFP) ||
         !(ni->ni_rsncaps & IEEE80211_RSNCAP_PBAC))) {
        status = IEEE80211_STATUS_REFUSED;
        goto resp;
    }
    /*
     * If the TID for which the Block Ack agreement is requested is
     * configured with a no-ACK policy, refuse the agreement.
     */
    if (ic->ic_tid_noack & (1 << tid)) {
        status = IEEE80211_STATUS_REFUSED;
        goto resp;
    }
    /* check that we support the requested Block Ack Policy */
    if (!(ic->ic_htcaps & IEEE80211_HTCAP_DELAYEDBA) &&
        !(params & IEEE80211_BA_ACK_POLICY)) {
        status = IEEE80211_STATUS_INVALID_PARAM;
        goto resp;
    }

    /* setup Block Ack agreement */
    ba->ba_state = IEEE80211_BA_INIT;
    ba->ba_timeout_val = timeout * IEEE80211_DUR_TU;
    if (ba->ba_timeout_val < IEEE80211_BA_MIN_TIMEOUT)
        ba->ba_timeout_val = IEEE80211_BA_MIN_TIMEOUT;
    else if (ba->ba_timeout_val > IEEE80211_BA_MAX_TIMEOUT)
        ba->ba_timeout_val = IEEE80211_BA_MAX_TIMEOUT;
    ba->to = wd_create();
    ba->ba_winsize = bufsz;
    if (ba->ba_winsize == 0 || ba->ba_winsize > IEEE80211_BA_MAX_WINSZ)
        ba->ba_winsize = IEEE80211_BA_MAX_WINSZ;
    ba->ba_winstart = ssn;
    ba->ba_winend = (ba->ba_winstart + ba->ba_winsize - 1) & 0xfff;

    /* Allocate and setup our reordering buffer */

    ba->ba_buf = kmalloc(IEEE80211_BA_MAX_WINSZ * sizeof(*ba->ba_buf));
    if (ba->ba_buf == NULL)
      {
        status = IEEE80211_STATUS_REFUSED;
        goto resp;
      }

    ba->ba_head = 0;

    /* Notify drivers of this new Block Ack agreement */

    if (ic->ic_ampdu_rx_start != NULL &&
        ic->ic_ampdu_rx_start(ic, ni, tid) != 0)
      {
        /* Driver failed to setup, rollback */

        kfree(ba->ba_buf);
        ba->ba_buf = NULL;
        status = IEEE80211_STATUS_REFUSED;
        goto resp;
      }

    ba->ba_state = IEEE80211_BA_AGREED;
    /* start Block Ack inactivity timer */
    wd_start(ba->ba_to, USEC2TICK(ba->ba_timeout_val), ieee80211_rx_ba_timeout, 1, ba);
    status = IEEE80211_STATUS_SUCCESS;
 resp:
    /* MLME-ADDBA.response */
    IEEE80211_SEND_ACTION(ic, ni, IEEE80211_CATEG_BA,
        IEEE80211_ACTION_ADDBA_RESP, status << 16 | token << 8 | tid);
}

/* ADDBA Response frame format:
 * [1] Category
 * [1] Action
 * [1] Dialog Token
 * [2] Status Code
 * [2] Block Ack Parameter Set
 * [2] Block Ack Timeout Value
 */

void ieee80211_recv_addba_resp(struct ieee80211com *ic, struct ieee80211_iobuf_s *iob,
    struct ieee80211_node *ni)
{
    const struct ieee80211_frame *wh;
    const uint8_t *frm;
    struct ieee80211_tx_ba *ba;
    uint16_t status, params, bufsz, timeout;
    uint8_t token, tid;

    if (iob->m_len < sizeof(*wh) + 9)
      {
        ndbg("ERROR: frame too short\n");
        return;
      }

    wh = mtod(iob, struct ieee80211_frame *);
    frm = (const uint8_t *)&wh[1];

    token = frm[2];
    status = LE_READ_2(&frm[3]);
    params = LE_READ_2(&frm[5]);
    tid = (params >> 2) & 0xf;
    bufsz = (params >> 6) & 0x3ff;
    timeout = LE_READ_2(&frm[7]);

    nvdbg("received ADDBA resp from %s, TID %d, status %d\n",
        ieee80211_addr2str(ni->ni_macaddr), tid, status);

    /*
     * Ignore if no ADDBA request has been sent for this RA/TID or
     * if we already have a Block Ack agreement.
     */
    ba = &ni->ni_tx_ba[tid];
    if (ba->ba_state != IEEE80211_BA_REQUESTED) {
        ndbg("ERROR: no matching ADDBA req found\n");
        return;
    }
    if (token != ba->ba_token) {
        ndbg("ERROR: ignoring ADDBA resp from %s: token %x!=%x\n",
            ieee80211_addr2str(ni->ni_macaddr), token, ba->ba_token);
        return;
    }
    /* we got an ADDBA Response matching our request, stop timeout */
    wd_cancel(ba->ba_to);

    if (status != IEEE80211_STATUS_SUCCESS) {
        /* MLME-ADDBA.confirm(Failure) */
        ba->ba_state = IEEE80211_BA_INIT;
        return;
    }
    /* MLME-ADDBA.confirm(Success) */
    ba->ba_state = IEEE80211_BA_AGREED;

    /* notify drivers of this new Block Ack agreement */
    if (ic->ic_ampdu_tx_start != NULL)
        (void)ic->ic_ampdu_tx_start(ic, ni, tid);

    /* start Block Ack inactivity timeout */
    if (ba->ba_timeout_val != 0)
        wd_start(ba->ba_to, USEC2TICK(ba->ba_timeout_val), ieee80211_rx_ba_timeout, 1, ba);
}

/* DELBA frame format:
 * [1] Category
 * [1] Action
 * [2] DELBA Parameter Set
 * [2] Reason Code
 */

void ieee80211_recv_delba(struct ieee80211com *ic, struct ieee80211_iobuf_s *iob,
    struct ieee80211_node *ni)
{
    const struct ieee80211_frame *wh;
    const uint8_t *frm;
    uint16_t params, reason;
    uint8_t tid;
    int i;

    if (iob->m_len < sizeof(*wh) + 6) {
        ndbg("ERROR: frame too short\n");
        return;
    }
    wh = mtod(iob, struct ieee80211_frame *);
    frm = (const uint8_t *)&wh[1];

    params = LE_READ_2(&frm[2]);
    reason = LE_READ_2(&frm[4]);
    tid = params >> 12;

    nvdbg("received DELBA from %s, TID %d, reason %d\n",
        ieee80211_addr2str(ni->ni_macaddr), tid, reason);

    if (params & IEEE80211_DELBA_INITIATOR) {
        /* MLME-DELBA.indication(Originator) */
        struct ieee80211_rx_ba *ba = &ni->ni_rx_ba[tid];

        if (ba->ba_state != IEEE80211_BA_AGREED) {
            ndbg("ERROR: no matching Block Ack agreement\n");
            return;
        }
        /* notify drivers of the end of the Block Ack agreement */
        if (ic->ic_ampdu_rx_stop != NULL)
            ic->ic_ampdu_rx_stop(ic, ni, tid);

        ba->ba_state = IEEE80211_BA_INIT;
        /* stop Block Ack inactivity timer */
        wd_cancel(ba->ba_to);

        if (ba->ba_buf != NULL)
          {
            /* Free all MSDUs stored in reordering buffer */

            for (i = 0; i < IEEE80211_BA_MAX_WINSZ; i++)
              {
                if (ba->ba_buf[i].iob != NULL)
                  {
                    ieee80211_iofree(ba->ba_buf[i].iob);
                  }
              }

            /* Free reordering buffer */

            kfree(ba->ba_buf, M_DEVBUF);
            ba->ba_buf = NULL;
          }
    } else {
        /* MLME-DELBA.indication(Recipient) */
        struct ieee80211_tx_ba *ba = &ni->ni_tx_ba[tid];

        if (ba->ba_state != IEEE80211_BA_AGREED) {
            ndbg("ERROR: no matching Block Ack agreement\n");
            return;
        }
        /* notify drivers of the end of the Block Ack agreement */
        if (ic->ic_ampdu_tx_stop != NULL)
            ic->ic_ampdu_tx_stop(ic, ni, tid);

        ba->ba_state = IEEE80211_BA_INIT;
        /* stop Block Ack inactivity timer */
        wd_cancel(ba->ba_to);
    }
}
#endif /* !CONFIG_IEEE80211_HT */

/* SA Query Request frame format:
 * [1] Category
 * [1] Action
 * [2] Transaction Identifier
 */

void ieee80211_recv_sa_query_req(struct ieee80211com *ic, struct ieee80211_iobuf_s *iob,
    struct ieee80211_node *ni)
{
    const struct ieee80211_frame *wh;
    const uint8_t *frm;

    if (ic->ic_opmode != IEEE80211_M_STA ||
        !(ni->ni_flags & IEEE80211_NODE_MFP)) {
        ndbg("ERROR: unexpected SA Query req from %s\n",
            ieee80211_addr2str(ni->ni_macaddr));
        return;
    }
    if (iob->m_len < sizeof(*wh) + 4) {
        ndbg("ERROR: frame too short\n");
        return;
    }
    wh = mtod(iob, struct ieee80211_frame *);
    frm = (const uint8_t *)&wh[1];

    /* MLME-SAQuery.indication */

    /* save Transaction Identifier for SA Query Response */
    ni->ni_sa_query_trid = LE_READ_2(&frm[2]);

    /* MLME-SAQuery.response */
    IEEE80211_SEND_ACTION(ic, ni, IEEE80211_CATEG_SA_QUERY,
        IEEE80211_ACTION_SA_QUERY_RESP, 0);
}

#ifdef CONFIG_IEEE80211_AP
/* SA Query Response frame format:
 * [1] Category
 * [1] Action
 * [2] Transaction Identifier
 */

void ieee80211_recv_sa_query_resp(struct ieee80211com *ic, struct ieee80211_iobuf_s *iob,
    struct ieee80211_node *ni)
{
    const struct ieee80211_frame *wh;
    const uint8_t *frm;

    /* ignore if we're not engaged in an SA Query with that STA */
    if (!(ni->ni_flags & IEEE80211_NODE_SA_QUERY)) {
        ndbg("ERROR: unexpected SA Query resp from %s\n",
            ieee80211_addr2str(ni->ni_macaddr));
        return;
    }
    if (iob->m_len < sizeof(*wh) + 4) {
        ndbg("ERROR: frame too short\n");
        return;
    }
    wh = mtod(iob, struct ieee80211_frame *);
    frm = (const uint8_t *)&wh[1];

    /* check that Transaction Identifier matches */
    if (ni->ni_sa_query_trid != LE_READ_2(&frm[2])) {
        ndbg("ERROR: transaction identifier does not match\n");
        return;
    }
    /* MLME-SAQuery.confirm */
    wd_cancel(ni->ni_sa_query_to);
    ni->ni_flags &= ~IEEE80211_NODE_SA_QUERY;
}
#endif

/* Action frame format:
 * [1] Category
 * [1] Action
 */

void ieee80211_recv_action(struct ieee80211com *ic, struct ieee80211_iobuf_s *iob,
    struct ieee80211_node *ni)
{
    const struct ieee80211_frame *wh;
    const uint8_t *frm;

    if (iob->m_len < sizeof(*wh) + 2) {
        ndbg("ERROR: frame too short\n");
        return;
    }
    wh = mtod(iob, struct ieee80211_frame *);
    frm = (const uint8_t *)&wh[1];

    switch (frm[0]) {
#ifdef CONFIG_IEEE80211_HT
    case IEEE80211_CATEG_BA:
        switch (frm[1]) {
        case IEEE80211_ACTION_ADDBA_REQ:
            ieee80211_recv_addba_req(ic, iob, ni);
            break;
        case IEEE80211_ACTION_ADDBA_RESP:
            ieee80211_recv_addba_resp(ic, iob, ni);
            break;
        case IEEE80211_ACTION_DELBA:
            ieee80211_recv_delba(ic, iob, ni);
            break;
        }
        break;
#endif
    case IEEE80211_CATEG_SA_QUERY:
        switch (frm[1]) {
        case IEEE80211_ACTION_SA_QUERY_REQ:
            ieee80211_recv_sa_query_req(ic, iob, ni);
            break;
#ifdef CONFIG_IEEE80211_AP
        case IEEE80211_ACTION_SA_QUERY_RESP:
            ieee80211_recv_sa_query_resp(ic, iob, ni);
            break;
#endif
        }
        break;
    default:
        ndbg("ERROR: action frame category %d not handled\n", frm[0]);
        break;
    }
}

void ieee80211_recv_mgmt(struct ieee80211com *ic, struct ieee80211_iobuf_s *iob,
    struct ieee80211_node *ni, struct ieee80211_rxinfo *rxi, int subtype)
{
    switch (subtype) {
    case IEEE80211_FC0_SUBTYPE_BEACON:
        ieee80211_recv_probe_resp(ic, iob, ni, rxi, 0);
        break;
    case IEEE80211_FC0_SUBTYPE_PROBE_RESP:
        ieee80211_recv_probe_resp(ic, iob, ni, rxi, 1);
        break;
#ifdef CONFIG_IEEE80211_AP
    case IEEE80211_FC0_SUBTYPE_PROBE_REQ:
        ieee80211_recv_probe_req(ic, iob, ni, rxi);
        break;
#endif
    case IEEE80211_FC0_SUBTYPE_AUTH:
        ieee80211_recv_auth(ic, iob, ni, rxi);
        break;
#ifdef CONFIG_IEEE80211_AP
    case IEEE80211_FC0_SUBTYPE_ASSOC_REQ:
        ieee80211_recv_assoc_req(ic, iob, ni, rxi, 0);
        break;
    case IEEE80211_FC0_SUBTYPE_REASSOC_REQ:
        ieee80211_recv_assoc_req(ic, iob, ni, rxi, 1);
        break;
#endif
    case IEEE80211_FC0_SUBTYPE_ASSOC_RESP:
        ieee80211_recv_assoc_resp(ic, iob, ni, 0);
        break;
    case IEEE80211_FC0_SUBTYPE_REASSOC_RESP:
        ieee80211_recv_assoc_resp(ic, iob, ni, 1);
        break;
    case IEEE80211_FC0_SUBTYPE_DEAUTH:
        ieee80211_recv_deauth(ic, iob, ni);
        break;
    case IEEE80211_FC0_SUBTYPE_DISASSOC:
        ieee80211_recv_disassoc(ic, iob, ni);
        break;
    case IEEE80211_FC0_SUBTYPE_ACTION:
        ieee80211_recv_action(ic, iob, ni);
        break;
    default:
        ndbg("ERROR: mgmt frame with subtype 0x%x not handled\n",
            subtype);
        ic->ic_stats.is_rx_badsubtype++;
        break;
    }
}

#ifdef CONFIG_IEEE80211_AP
/* Process an incoming PS-Poll control frame (see 11.2) */

void ieee80211_recv_pspoll(struct ieee80211com *ic, struct ieee80211_iobuf_s *iob,
    struct ieee80211_node *ni)
{
    struct ieee80211_frame_pspoll *psp;
    struct ieee80211_frame *wh;
    uint16_t aid;

    if (ic->ic_opmode != IEEE80211_M_HOSTAP ||
        !(ic->ic_caps & IEEE80211_C_APPMGT) ||
        ni->ni_state != IEEE80211_STA_ASSOC)
        return;

    if (iob->m_len < sizeof(*psp)) {
        ndbg("ERROR: frame too short, len %u\n", iob->m_len);
        ic->ic_stats.is_rx_tooshort++;
        return;
    }
    psp = mtod(iob, struct ieee80211_frame_pspoll *);
    if (!IEEE80211_ADDR_EQ(psp->i_bssid, ic->ic_bss->ni_bssid))
      {
        ndbg("ERROR: discard pspoll frame to BSS %s\n",
            ieee80211_addr2str(psp->i_bssid));
        ic->ic_stats.is_rx_wrongbss++;
        return;
      }

    aid = letoh16(*(uint16_t *)psp->i_aid);
    if (aid != ni->ni_associd) {
        ndbg("ERROR: invalid pspoll aid %x from %s\n", aid,
            ieee80211_addr2str(psp->i_ta));
        return;
    }

    /* take the first queued frame and put it out.. */

    iob = (struct ieee80211_iobuf_s *)sq_remfirst(&ni->ni_savedq);
    if (iob == NULL)
      {
        return;
      }

    if (sq_empty(&ni->ni_savedq))
      {
        /* last queued frame, turn off the TIM bit */

        (*ic->ic_set_tim)(ic, ni->ni_associd, 0);
      }
    else
      {
        /* more queued frames, set the more data bit */

        wh = mtod(iob, struct ieee80211_frame *);
        wh->i_fc[1] |= IEEE80211_FC1_MORE_DATA;
      }

    sq_addlast((sq_entry_t*)iob, &ic->ic_pwrsaveq);
    ieee80211_ifstart();
}
#endif /* CONFIG_IEEE80211_AP */

#ifdef CONFIG_IEEE80211_HT
/* Process an incoming BlockAckReq control frame (see 7.2.1.7) */

void ieee80211_recv_bar(struct ieee80211com *ic, struct ieee80211_iobuf_s *iob,
    struct ieee80211_node *ni)
{
    const struct ieee80211_frame_min *wh;
    const uint8_t *frm;
    uint16_t ctl, ssn;
    uint8_t tid, ntids;

    if (!(ni->ni_flags & IEEE80211_NODE_HT)) {
        ndbg("ERROR: received BlockAckReq from non-HT STA %s\n",
            ieee80211_addr2str(ni->ni_macaddr));
        return;
    }
    if (iob->m_len < sizeof(*wh) + 4) {
        ndbg("ERROR: frame too short\n");
        return;
    }
    wh = mtod(iob, struct ieee80211_frame_min *);
    frm = (const uint8_t *)&wh[1];

    /* read BlockAckReq Control field */
    ctl = LE_READ_2(&frm[0]);
    tid = ctl >> 12;

    /* determine BlockAckReq frame variant */
    if (ctl & IEEE80211_BA_MULTI_TID) {
        /* Multi-TID BlockAckReq variant (PSMP only) */
        ntids = tid + 1;

        if (iob->m_len < sizeof(*wh) + 2 + 4 * ntids) {
            ndbg("ERROR: MTBAR frame too short\n");
            return;
        }
        frm += 2;    /* skip BlockAckReq Control field */
        while (ntids-- > 0) {
            /* read MTBAR Information field */
            tid = LE_READ_2(&frm[0]) >> 12;
            ssn = LE_READ_2(&frm[2]) >> 4;
            ieee80211_bar_tid(ic, ni, tid, ssn);
            frm += 4;
        }
    } else {
        /* Basic or Compressed BlockAckReq variants */
        ssn = LE_READ_2(&frm[2]) >> 4;
        ieee80211_bar_tid(ic, ni, tid, ssn);
    }
}

/*
 * Process a BlockAckReq for a specific TID (see 9.10.7.6.3).
 * This is the common back-end for all BlockAckReq frame variants.
 */
void
ieee80211_bar_tid(struct ieee80211com *ic, struct ieee80211_node *ni,
    uint8_t tid, uint16_t ssn)
{
    struct ieee80211_rx_ba *ba = &ni->ni_rx_ba[tid];

    /* check if we have a Block Ack agreement for RA/TID */
    if (ba->ba_state != IEEE80211_BA_AGREED) {
        /* XXX not sure in PBAC case */
        /* send a DELBA with reason code UNKNOWN-BA */
        IEEE80211_SEND_ACTION(ic, ni, IEEE80211_CATEG_BA,
            IEEE80211_ACTION_DELBA,
            IEEE80211_REASON_SETUP_REQUIRED << 16 | tid);
        return;
    }
    /* check if it is a Protected Block Ack agreement */
    if ((ni->ni_flags & IEEE80211_NODE_MFP) &&
        (ni->ni_rsncaps & IEEE80211_RSNCAP_PBAC)) {
        /* ADDBA Requests must be used in PBAC case */
        if (SEQ_LT(ssn, ba->ba_winstart) ||
            SEQ_LT(ba->ba_winend, ssn))
            ic->ic_stats.is_pbac_errs++;
        return;    /* PBAC, do not move window */
    }
    /* reset Block Ack inactivity timer */
    wd_start(ba->ba_to, USEC2TICK(ba->ba_timeout_val), ieee80211_rx_ba_timeout, 1, ba);

    if (SEQ_LT(ba->ba_winstart, ssn))
        ieee80211_ba_move_window(ic, ni, tid, ssn);
}
#endif /* !CONFIG_IEEE80211_HT */
