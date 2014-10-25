/****************************************************************************
 * net/mini802/ieee80211_input.c
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

#include <stdbool.h>
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
#include <nuttx/clock.h>

#include <nuttx/net/arp.h>
#include <nuttx/net/iob.h>

#include "mini802/ieee80211_debug.h"
#include "mini802/ieee80211_ifnet.h"
#include "mini802/ieee80211_var.h"
#include "mini802/ieee80211_priv.h"

/****************************************************************************
 * Private Function Prototypes
 ****************************************************************************/

struct iob_s *ieee80211_defrag(struct ieee80211_s *, struct iob_s *, int);
void ieee80211_defrag_timeout(void *);
struct iob_s *ieee80211_align_iobuf(struct iob_s *);
static void ieee80211_decap(struct ieee80211_s *, struct iob_s *,
                            struct ieee80211_node *, int);
static void ieee80211_deliver_data(struct ieee80211_s *, struct iob_s *,
                                   struct ieee80211_node *);
int ieee80211_parse_edca_params_body(struct ieee80211_s *, const uint8_t *);
int ieee80211_parse_edca_params(struct ieee80211_s *, const uint8_t *);
int ieee80211_parse_wmm_params(struct ieee80211_s *, const uint8_t *);
enum ieee80211_cipher ieee80211_parse_rsn_cipher(const uint8_t[]);
enum ieee80211_akm ieee80211_parse_rsn_akm(const uint8_t[]);
int ieee80211_parse_rsn_body(struct ieee80211_s *, const uint8_t *,
                             unsigned int, struct ieee80211_rsnparams *);
int ieee80211_save_ie(const uint8_t *, uint8_t **);
void ieee80211_recv_probe_resp(struct ieee80211_s *, struct iob_s *,
                               struct ieee80211_node *,
                               struct ieee80211_rxinfo *, int);
void ieee80211_recv_auth(struct ieee80211_s *, struct iob_s *,
                         struct ieee80211_node *, struct ieee80211_rxinfo *);
void ieee80211_recv_assoc_resp(struct ieee80211_s *, struct iob_s *,
                               struct ieee80211_node *, int);
void ieee80211_recv_deauth(struct ieee80211_s *, struct iob_s *,
                           struct ieee80211_node *);
void ieee80211_recv_disassoc(struct ieee80211_s *, struct iob_s *,
                             struct ieee80211_node *);
void ieee80211_recv_sa_query_req(struct ieee80211_s *, struct iob_s *,
                                 struct ieee80211_node *);
void ieee80211_recv_action(struct ieee80211_s *, struct iob_s *,
                           struct ieee80211_node *);

/****************************************************************************
 * Private Functions
 ****************************************************************************/

/* Retrieve the length in bytes of an 802.11 header */

unsigned int ieee80211_get_hdrlen(FAR const struct ieee80211_frame *wh)
{
  unsigned int size = sizeof(*wh);

  /* NB: does not work with control frames */

  DEBUGASSERT(ieee80211_has_seq(wh));

  if (ieee80211_has_addr4(wh))
    {
      size += IEEE80211_ADDR_LEN;       /* i_addr4 */
    }

  if (ieee80211_has_qos(wh))
    {
      size += sizeof(uint16_t); /* i_qos */
    }

  if (ieee80211_has_htc(wh))
    {
      size += sizeof(uint32_t); /* i_ht */
    }

  return size;
}

/* Process a received frame.  The node associated with the sender
 * should be supplied.  If nothing was found in the node table then
 * the caller is assumed to supply a reference to ic_bss instead.
 * The RSSI and a timestamp are also supplied.  The RSSI data is used
 * during AP scanning to select a AP to associate with; it can have
 * any units so long as values have consistent units and higher values
 * mean ``better signal''.  The receive timestamp is currently not used
 * by the 802.11 layer.
 */

void ieee80211_input(struct ieee80211_s *ic, struct iob_s *iob,
                     struct ieee80211_node *ni, struct ieee80211_rxinfo *rxi)
{
  struct ieee80211_frame *wh;
  uint16_t *orxseq, nrxseq, qos;
  uint8_t dir, type, subtype, tid;
  int hdrlen, hasqos;

  DEBUGASSERT(ni != NULL);

  /* in monitor mode, send everything directly to bpf */

  if (ic->ic_opmode == IEEE80211_M_MONITOR)
    goto out;

  /* Do not process frames without an Address 2 field any further.
   * Only CTS and ACK control frames do not have this field.
   */

   if (iob->io_len < sizeof(struct ieee80211_frame_min))
    {
      ndbg("ERROR: frame too short, len %u\n", iob->io_len);
      goto out;
    }

  wh = (FAR struct ieee80211_frame *)IOB_DATA(iob);
  if ((wh->i_fc[0] & IEEE80211_FC0_VERSION_MASK) != IEEE80211_FC0_VERSION_0)
    {
      ndbg("ERROR: frame with wrong version: %x\n", wh->i_fc[0]);
      goto err;
    }

  dir = wh->i_fc[1] & IEEE80211_FC1_DIR_MASK;
  type = wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK;

  if (type != IEEE80211_FC0_TYPE_CTL)
    {
      hdrlen = ieee80211_get_hdrlen(wh);
      if (iob->io_len < hdrlen)
        {
          ndbg("ERROR: frame too short, len %u\n", iob->io_len);
          goto err;
        }
    }

  if ((hasqos = ieee80211_has_qos(wh)))
    {
      qos = ieee80211_get_qos(wh);
      tid = qos & IEEE80211_QOS_TID;
    }
  else
    {
      qos = 0;
      tid = 0;
    }

  /* duplicate detection (see 9.2.9) */

  if (ieee80211_has_seq(wh) && ic->ic_state != IEEE80211_S_SCAN)
    {
      nrxseq = letoh16(*(uint16_t *) wh->i_seq) >> IEEE80211_SEQ_SEQ_SHIFT;
      if (hasqos)
        orxseq = &ni->ni_qos_rxseqs[tid];
      else
        orxseq = &ni->ni_rxseq;
      if ((wh->i_fc[1] & IEEE80211_FC1_RETRY) && nrxseq == *orxseq)
        {
          /* duplicate, silently discarded */

          goto out;
        }

      *orxseq = nrxseq;
    }

  if (ic->ic_state != IEEE80211_S_SCAN)
    {
      ni->ni_rssi = rxi->rxi_rssi;
      ni->ni_rstamp = rxi->rxi_tstamp;
      ni->ni_inact = 0;
    }

  switch (type)
    {
    case IEEE80211_FC0_TYPE_DATA:
      switch (ic->ic_opmode)
        {
        case IEEE80211_M_STA:
          if (dir != IEEE80211_FC1_DIR_FROMDS)
            {
              goto out;
            }

          if (ic->ic_state != IEEE80211_S_SCAN &&
              !IEEE80211_ADDR_EQ(wh->i_addr2, ni->ni_bssid))
            {
              /* Source address is not our BSS. */

              nvdbg("discard frame from SA %s\n",
                    ieee80211_addr2str(wh->i_addr2));

              goto out;
            }

          if (                  /* REVISIT: (dev->d_flags & IFF_SIMPLEX) && */
               IEEE80211_IS_MULTICAST(wh->i_addr1) &&
               IEEE80211_ADDR_EQ(wh->i_addr3, ic->ic_myaddr))
            {
              /* In IEEE802.11 network, multicast frame sent from me is
               * broadcast from AP. It should be silently discarded for SIMPLEX 
               * interface.
               */

              goto out;
            }
          break;

        case IEEE80211_M_IBSS:   /* AP only */
        case IEEE80211_M_AHDEMO: /* AP only */
        case IEEE80211_M_HOSTAP: /* AP only */
        default:
          /* can't get there */
          goto out;
        }

      if ((ic->ic_flags & IEEE80211_F_WEPON) ||
          ((ic->ic_flags & IEEE80211_F_RSNON) &&
           (ni->ni_flags & IEEE80211_NODE_RXPROT)))
        {
          /* protection is on for Rx */

          if (!(rxi->rxi_flags & IEEE80211_RXI_HWDEC))
            {
              if (!(wh->i_fc[1] & IEEE80211_FC1_PROTECTED))
                {
                  /* drop unencrypted */

                  goto err;
                }

              /* Do software decryption */

              iob = ieee80211_decrypt(ic, iob, ni);
              if (iob == NULL)
                {
                  goto err;
                }

              wh = (FAR struct ieee80211_frame *)IOB_DATA(iob);
            }
        }
      else if ((wh->i_fc[1] & IEEE80211_FC1_PROTECTED) ||
               (rxi->rxi_flags & IEEE80211_RXI_HWDEC))
        {
          /* Frame encrypted but protection off for Rx */

          goto out;
        }

      ieee80211_decap(ic, iob, ni, hdrlen);
      return;

    case IEEE80211_FC0_TYPE_MGT:
      if (dir != IEEE80211_FC1_DIR_NODS)
        {
          goto err;
        }

      subtype = wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;

      /* drop frames without interest */

      if (ic->ic_state == IEEE80211_S_SCAN)
        {
          if (subtype != IEEE80211_FC0_SUBTYPE_BEACON &&
              subtype != IEEE80211_FC0_SUBTYPE_PROBE_RESP)
            {
              goto out;
            }
        }

      if (ni->ni_flags & IEEE80211_NODE_RXMGMTPROT)
        {
          /* MMPDU protection is on for Rx */
          if (subtype == IEEE80211_FC0_SUBTYPE_DISASSOC ||
              subtype == IEEE80211_FC0_SUBTYPE_DEAUTH ||
              subtype == IEEE80211_FC0_SUBTYPE_ACTION)
            {
              if (!IEEE80211_IS_MULTICAST(wh->i_addr1) &&
                  !(wh->i_fc[1] & IEEE80211_FC1_PROTECTED))
                {
                  /* unicast mgmt not encrypted */

                  goto out;
                }

              /* Do software decryption */

              iob = ieee80211_decrypt(ic, iob, ni);
              if (iob == NULL)
                {
                  /* XXX stats */

                  goto out;
                }

              wh = (FAR struct ieee80211_frame *)IOB_DATA(iob);
            }
        }
      else if ((ic->ic_flags & IEEE80211_F_RSNON) &&
               (wh->i_fc[1] & IEEE80211_FC1_PROTECTED))
        {
          /* Encrypted but MMPDU Rx protection off for TA */

          goto out;
        }

      nvdbg("%s: received %s from %s rssi %d mode %s\n",
            ic->ic_ifname,
            ieee80211_mgt_subtype_name[subtype >> IEEE80211_FC0_SUBTYPE_SHIFT],
            ieee80211_addr2str(wh->i_addr2), rxi->rxi_rssi,
            ieee80211_phymode_name[ieee80211_chan2mode
                                   (ic, ic->ic_bss->ni_chan)]);

      (*ic->ic_recv_mgmt) (ic, iob, ni, rxi, subtype);
      iob_free_chain(iob);
      return;

    case IEEE80211_FC0_TYPE_CTL: /* 802.11n only  and AP only */
    default:
      ndbg("ERROR: bad frame type %x\n", type);

      /* should not come here */

      break;
    }

err:
out:
  if (iob != NULL)
    {
      iob_free_chain(iob);
    }
}

/* Handle defragmentation (see 9.5 and Annex C).  We support the concurrent
 * reception of fragments of three fragmented MSDUs or MMPDUs.
 */

struct iob_s *ieee80211_defrag(struct ieee80211_s *ic, struct iob_s *iob,
                               int hdrlen)
{
  const struct ieee80211_frame *owh, *wh;
  struct ieee80211_defrag *df;
  uint16_t rxseq, seq;
  uint8_t frag;
  int i;

  wh = (FAR struct ieee80211_frame *)IOB_DATA(iob);
  rxseq = letoh16(*(const uint16_t *)wh->i_seq);
  seq = rxseq >> IEEE80211_SEQ_SEQ_SHIFT;
  frag = rxseq & IEEE80211_SEQ_FRAG_MASK;

  if (frag == 0 && !(wh->i_fc[1] & IEEE80211_FC1_MORE_FRAG))
    return iob;                 /* not fragmented */

  if (frag == 0)
    {
      /* first fragment, setup entry in the fragment cache */

      if (++ic->ic_defrag_cur == IEEE80211_DEFRAG_SIZE)
        ic->ic_defrag_cur = 0;

      df = &ic->ic_defrag[ic->ic_defrag_cur];
      if (df->df_m != NULL)
        {
          /* Discard old entry */

          iob_free_chain(df->df_m);
        }

      df->df_seq = seq;
      df->df_frag = 0;
      df->df_m = iob;

      /* Start receive MSDU timer of aMaxReceiveLifetime */

      wd_start(df->df_to, SEC2TICK(1));
      return NULL;              /* MSDU or MMPDU not yet complete */
    }

  /* find matching entry in the fragment cache */

  for (i = 0; i < IEEE80211_DEFRAG_SIZE; i++)
    {
      df = &ic->ic_defrag[i];
      if (df->df_m == NULL)
        {
          continue;
        }

      if (df->df_seq != seq || df->df_frag + 1 != frag)
        {
          continue;
        }

      owh = (FAR struct ieee80211_frame *)IOB_DATA(df->df_m);

      /* Frame type, source and destination must match */

      if (((wh->i_fc[0] ^ owh->i_fc[0]) & IEEE80211_FC0_TYPE_MASK) ||
          !IEEE80211_ADDR_EQ(wh->i_addr1, owh->i_addr1) ||
          !IEEE80211_ADDR_EQ(wh->i_addr2, owh->i_addr2))
        {
          continue;
        }

      /* Matching entry found */

      break;
    }

  if (i == IEEE80211_DEFRAG_SIZE)
    {
      /* No matching entry found, discard fragment */

      iob_free_chain(iob);
      return NULL;
    }

  df->df_frag = frag;

  /* Strip 802.11 header and concatenate fragment */

  iob = iob_trimhead(iob, hdrlen);
  iob_concat(df->df_m, iob);
  df->df_m->io_pktlen += iob->io_pktlen;

  if (wh->i_fc[1] & IEEE80211_FC1_MORE_FRAG)
    return NULL;                /* MSDU or MMPDU not yet complete */

  /* MSDU or MMPDU complete */

  wd_cancel(df->df_to);
  iob = df->df_m;
  df->df_m = NULL;
  return iob;
}

/* Receive MSDU defragmentation timer exceeds aMaxReceiveLifetime  */

void ieee80211_defrag_timeout(void *arg)
{
  struct ieee80211_defrag *df = arg;
  uip_lock_t flags = uip_lock();

  /* Discard all received fragments */

  iob_free_chain(df->df_m);
  df->df_m = NULL;

  uip_unlock(flags);
}

static void ieee80211_deliver_data(FAR struct ieee80211_s *ic,
                                   FAR struct iob_s *iob,
                                   FAR struct ieee80211_node *ni)
{
  FAR struct uip_eth_hdr *ethhdr;

  ethhdr = (FAR struct uip_eth_hdr *)IOB_DATA(iob);

  if ((ic->ic_flags & IEEE80211_F_RSNON) && !ni->ni_port_valid &&
      ethhdr->type != htons(UIP_ETHTYPE_PAE))
    {
      ndbg("ERROR: port not valid: %s\n", ieee80211_addr2str(ethhdr->dest));
      iob_free_chain(iob);
      return;
    }

  if (iob != NULL)
    {
      if ((ic->ic_flags & IEEE80211_F_RSNON) &&
          ethhdr->type == htons(UIP_ETHTYPE_PAE))
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

struct iob_s *ieee80211_align_iobuf(struct iob_s *iob)
{
  struct iob_s *next, *next0, **np;
  void *newdata;
  int off, pktlen;

  next0 = NULL;
  np = &next0;
  off = 0;
  pktlen = iob->io_pktlen;
  while (pktlen > off)
    {
      if (next0 == NULL)
        {
          next = iob_alloc(false);
          if (next == NULL)
            {
              iob_free_chain(iob);
              return NULL;
            }

          if (iob_clone(next, iob) < 0)
            {
              iob_free(next);
              iob_free_chain(iob);
              return NULL;
            }

          next->io_len = CONFIG_IEEE80211_BUFSIZE;
        }
      else
        {
          next = iob_alloc(false);
          if (next == NULL)
            {
              iob_free_chain(iob);
              iob_free_chain(next0);
              return NULL;
            }

          next->io_len = 0;
        }

      if (next0 == NULL)
        {
          unsigned int offset;

          newdata =
            (FAR void *)ALIGN(IOB_DATA(next) + UIP_ETHH_LEN) - UIP_ETHH_LEN;
          offset = newdata - IOB_DATA(next);
          next->io_offset += offset;
          next->io_len -= offset;
        }

      if (next->io_len > pktlen - off)
        {
          next->io_len = pktlen - off;
        }

      iob_copyout(IOB_DATA(next), iob, off, next->io_len);
      off += next->io_len;
      *np = next;
      np = next->io_flink;
    }

  iob_free_chain(iob);
  return next0;
}
#endif /* __STRICT_ALIGNMENT */

static void ieee80211_decap(struct ieee80211_s *ic, struct iob_s *iob,
                            struct ieee80211_node *ni, int hdrlen)
{
  struct uip_eth_hdr ethhdr;
  struct ieee80211_frame *wh;
  struct llc *llc;

  if (iob->io_len < hdrlen + LLC_SNAPFRAMELEN && (iob = iob_pack(iob)) == NULL)
    {
      return;
    }

  wh = (FAR struct ieee80211_frame *)IOB_DATA(iob);
  switch (wh->i_fc[1] & IEEE80211_FC1_DIR_MASK)
    {
    case IEEE80211_FC1_DIR_NODS:
      IEEE80211_ADDR_COPY(ethhdr.dest, wh->i_addr1);
      IEEE80211_ADDR_COPY(ethhdr.src, wh->i_addr2);
      break;

    case IEEE80211_FC1_DIR_TODS:
      IEEE80211_ADDR_COPY(ethhdr.dest, wh->i_addr3);
      IEEE80211_ADDR_COPY(ethhdr.src, wh->i_addr2);
      break;

    case IEEE80211_FC1_DIR_FROMDS:
      IEEE80211_ADDR_COPY(ethhdr.dest, wh->i_addr1);
      IEEE80211_ADDR_COPY(ethhdr.src, wh->i_addr3);
      break;

    case IEEE80211_FC1_DIR_DSTODS:
      IEEE80211_ADDR_COPY(ethhdr.dest, wh->i_addr3);
      IEEE80211_ADDR_COPY(ethhdr.src,
                          ((struct ieee80211_frame_addr4 *)wh)->i_addr4);
      break;
    }

  llc = (struct llc *)((void *)wh + hdrlen);
  if (llc->llc_dsap == LLC_SNAP_LSAP &&
      llc->llc_ssap == LLC_SNAP_LSAP &&
      llc->llc_control == LLC_UI &&
      llc->llc_snap.org_code[0] == 0 &&
      llc->llc_snap.org_code[1] == 0 && llc->llc_snap.org_code[2] == 0)
    {
      ethhdr.type = llc->llc_snap.type;
      iob = iob_trimhead(iob, hdrlen + LLC_SNAPFRAMELEN - UIP_ETHH_LEN);
    }
  else
    {
      ethhdr.type = htons(iob->io_pktlen - hdrlen);
      iob = iob_trimhead(iob, hdrlen - UIP_ETHH_LEN);
    }

  memcpy(IOB_DATA(iob), &ethhdr, UIP_ETHH_LEN);

#ifdef __STRICT_ALIGNMENT
  if (!ALIGNED_POINTER(IOB_DATA(iob) + UIP_ETHH_LEN, uint32_t))
    {
      if ((iob = ieee80211_align_iobuf(iob)) == NULL)
        {
          return;
        }
    }
#endif

  ieee80211_deliver_data(ic, iob, ni);
}

/* Parse an EDCA Parameter Set element (see 7.3.2.27) */

int ieee80211_parse_edca_params_body(struct ieee80211_s *ic,
                                     const uint8_t * frm)
{
  unsigned int updtcount;
  int aci;

  /* Check if EDCA parameters have changed XXX if we miss more than
   * 15 consecutive beacons, we might not detect changes to EDCA
   * parameters due to wraparound of the 4-bit Update Count field.
   */

  updtcount = frm[0] & 0xf;
  if (updtcount == ic->ic_edca_updtcount)
    return 0;                   /* no changes to EDCA parameters, ignore */
  ic->ic_edca_updtcount = updtcount;

  frm += 2;                     /* skip QoS Info & Reserved fields */

  /* parse AC Parameter Records */

  for (aci = 0; aci < EDCA_NUM_AC; aci++)
    {
      struct ieee80211_edca_ac_params *ac = &ic->ic_edca_ac[aci];

      ac->ac_acm = (frm[0] >> 4) & 0x1;
      ac->ac_aifsn = frm[0] & 0xf;
      ac->ac_ecwmin = frm[1] & 0xf;
      ac->ac_ecwmax = frm[1] >> 4;
      ac->ac_txoplimit = LE_READ_2(frm + 2);
      frm += 4;
    }

  /* give drivers a chance to update their settings */

  if ((ic->ic_flags & IEEE80211_F_QOS) && ic->ic_updateedca != NULL)
    (*ic->ic_updateedca) (ic);

  return 0;
}

int ieee80211_parse_edca_params(struct ieee80211_s *ic, const uint8_t * frm)
{
  if (frm[1] < 18)
    {
      return IEEE80211_REASON_IE_INVALID;
    }
  return ieee80211_parse_edca_params_body(ic, frm + 2);
}

int ieee80211_parse_wmm_params(struct ieee80211_s *ic, const uint8_t * frm)
{
  if (frm[1] < 24)
    {
      return IEEE80211_REASON_IE_INVALID;
    }
  return ieee80211_parse_edca_params_body(ic, frm + 8);
}

enum ieee80211_cipher ieee80211_parse_rsn_cipher(const uint8_t selector[4])
{
  if (memcmp(selector, MICROSOFT_OUI, 3) == 0)
    {                           /* WPA */
      switch (selector[3])
        {
        case 0:                /* use group data cipher suite */
          return IEEE80211_CIPHER_USEGROUP;
        case 1:                /* WEP-40 */
          return IEEE80211_CIPHER_WEP40;
        case 2:                /* TKIP */
          return IEEE80211_CIPHER_TKIP;
        case 4:                /* CCMP (RSNA default) */
          return IEEE80211_CIPHER_CCMP;
        case 5:                /* WEP-104 */
          return IEEE80211_CIPHER_WEP104;
        }
    }
  else if (memcmp(selector, IEEE80211_OUI, 3) == 0)
    {                           /* RSN */
      /* from IEEE Std 802.11 - Table 20da */
      switch (selector[3])
        {
        case 0:                /* use group data cipher suite */
          return IEEE80211_CIPHER_USEGROUP;
        case 1:                /* WEP-40 */
          return IEEE80211_CIPHER_WEP40;
        case 2:                /* TKIP */
          return IEEE80211_CIPHER_TKIP;
        case 4:                /* CCMP (RSNA default) */
          return IEEE80211_CIPHER_CCMP;
        case 5:                /* WEP-104 */
          return IEEE80211_CIPHER_WEP104;
        case 6:                /* BIP */
          return IEEE80211_CIPHER_BIP;
        }
    }
  return IEEE80211_CIPHER_NONE; /* ignore unknown ciphers */
}

enum ieee80211_akm ieee80211_parse_rsn_akm(const uint8_t selector[4])
{
  if (memcmp(selector, MICROSOFT_OUI, 3) == 0)
    {                           /* WPA */
      switch (selector[3])
        {
        case 1:                /* IEEE 802.1X (RSNA default) */
          return IEEE80211_AKM_8021X;
        case 2:                /* PSK */
          return IEEE80211_AKM_PSK;
        }
    }
  else if (memcmp(selector, IEEE80211_OUI, 3) == 0)
    {                           /* RSN */
      /* from IEEE Std 802.11i-2004 - Table 20dc */
      switch (selector[3])
        {
        case 1:                /* IEEE 802.1X (RSNA default) */
          return IEEE80211_AKM_8021X;
        case 2:                /* PSK */
          return IEEE80211_AKM_PSK;
        case 5:                /* IEEE 802.1X with SHA256 KDF */
          return IEEE80211_AKM_SHA256_8021X;
        case 6:                /* PSK with SHA256 KDF */
          return IEEE80211_AKM_SHA256_PSK;
        }
    }
  return IEEE80211_AKM_NONE;    /* ignore unknown AKMs */
}

/* Parse an RSN element (see 7.3.2.25). */

int
ieee80211_parse_rsn_body(struct ieee80211_s *ic, const uint8_t * frm,
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
  while (iob-- > 0)
    {
      rsn->rsn_ciphers |= ieee80211_parse_rsn_cipher(frm);
      frm += 4;
    }
  if (rsn->rsn_ciphers & IEEE80211_CIPHER_USEGROUP)
    {
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
  while (next-- > 0)
    {
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

  if (s != 0)
    {
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
ieee80211_parse_rsn(struct ieee80211_s *ic, const uint8_t * frm,
                    struct ieee80211_rsnparams *rsn)
{
  if (frm[1] < 2)
    {
      return IEEE80211_STATUS_IE_INVALID;
    }
  return ieee80211_parse_rsn_body(ic, frm + 2, frm[1], rsn);
}

int
ieee80211_parse_wpa(struct ieee80211_s *ic, const uint8_t * frm,
                    struct ieee80211_rsnparams *rsn)
{
  if (frm[1] < 6)
    {
      return IEEE80211_STATUS_IE_INVALID;
    }
  return ieee80211_parse_rsn_body(ic, frm + 6, frm[1] - 4, rsn);
}

/* Create (or update) a copy of an information element */

int ieee80211_save_ie(const uint8_t * frm, uint8_t ** ie)
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

void ieee80211_recv_probe_resp(struct ieee80211_s *ic, struct iob_s *iob,
                               struct ieee80211_node *ni,
                               struct ieee80211_rxinfo *rxi, int isprobe)
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
  uint16_t capinfo;
  uint16_t bintval;
  uint8_t chan;
  uint8_t bchan;
  uint8_t erp;
  int ndx;
  int bit;
  int is_new;

  /* We process beacon/probe response frames for: o station mode: to collect
   * state updates such as 802.11g slot time and for passive scanning of APs o
   * adhoc mode: to discover neighbors o hostap mode: for passive scanning of
   * neighbor APs o when scanning In other words, in all modes other than
   * monitor (which does not process incoming frames) and adhoc-demo (which
   * does not use management frames at all).
   */

  DEBUGASSERT(ic->ic_opmode == IEEE80211_M_STA ||
              ic->ic_state == IEEE80211_S_SCAN);

  /* Make sure all mandatory fixed fields are present */

  if (iob->io_len < sizeof(*wh) + 12)
    {
      ndbg("ERROR: frame too short\n");
      return;
    }

  wh = (FAR struct ieee80211_frame *)IOB_DATA(iob);
  frm = (const uint8_t *)&wh[1];
  efrm = IOB_DATA(iob) + iob->io_len;

  tstamp = frm;
  frm += 8;
  bintval = LE_READ_2(frm);
  frm += 2;
  capinfo = LE_READ_2(frm);
  frm += 2;

  ssid = NULL;
  rates = NULL;
  xrates = NULL;
  edcaie = NULL;
  wmmie = NULL;
  rsnie NULL;
  wpaie = NULL;

  bchan = ieee80211_chan2ieee(ic, ic->ic_bss->ni_chan);
  chan = bchan;
  erp = 0;
  while (frm + 2 <= efrm)
    {
      if (frm + 2 + frm[1] > efrm)
        {
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

        case IEEE80211_ELEMID_VENDOR:
          if (frm[1] < 4)
            {
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

        case IEEE80211_ELEMID_HTCAPS: /* 802.11n only */
        case IEEE80211_ELEMID_HTOP: /* 802.11n only */
        default:
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

      return;
    }

  if ((ic->ic_state != IEEE80211_S_SCAN ||
       !(ic->ic_caps & IEEE80211_C_SCANALL)) && chan != bchan)
    {
      /* Frame was received on a channel different from the one indicated in
       * the DS params element id; silently discard it. NB: this can happen
       * due to signal leakage.
       */

      ndbg("ERROR: ignore %s on channel %u marked for channel %u\n",
           isprobe ? "probe response" : "beacon", bchan, chan);

      return;
    }

  /* Use mac, channel and rssi so we collect only the best potential AP with
   * the equal bssid while scanning. Collecting all potential APs may result in 
   * bloat of the node tree. This call will return NULL if the node for this
   * APs does not exist or if the new node is the potential better one.
   */

  if ((ni = ieee80211_find_node_for_beacon(ic, wh->i_addr2,
                                           &ic->ic_channels[chan], ssid,
                                           rxi->rxi_rssi)) != NULL)
    {
      return;
    }

#ifdef CONFIG_DEBUG_NET
  if ((ni == NULL || ic->ic_state == IEEE80211_S_SCAN))
    {
      nvdbg("%s%s on chan %u (bss chan %u) ",
            (ni == NULL ? "new " : ""),
            isprobe ? "probe response" : "beacon", chan, bchan);

      ieee80211_print_essid(ssid + 2, ssid[1]);

      nvdbg(" from %s\n", ieee80211_addr2str((uint8_t *) wh->i_addr2));
      nvdbg("caps 0x%x bintval %u erp 0x%x\n", capinfo, bintval, erp);
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
      ic->ic_state == IEEE80211_S_RUN && ni->ni_state == IEEE80211_STA_BSS)
    {
      /* Check if protection mode has changed since last beacon */

      if (ni->ni_erp != erp)
        {
          nvdbg("[%s] erp change: was 0x%x, now 0x%x\n",
                ieee80211_addr2str((uint8_t *) wh->i_addr2), ni->ni_erp, erp);

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

      /* Check if AP short slot time setting has changed since last beacon and
       * give the driver a chance to update the hardware.
       */

      if ((ni->ni_capinfo ^ capinfo) & IEEE80211_CAPINFO_SHORT_SLOTTIME)
        {
          ieee80211_set_shortslottime(ic,
                                      ic->ic_curmode == IEEE80211_MODE_11A ||
                                      (capinfo &
                                       IEEE80211_CAPINFO_SHORT_SLOTTIME));
        }
    }

  /* We do not try to update EDCA parameters if QoS was not negotiated with the 
   * AP at association time.
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
      (ic->ic_flags & IEEE80211_F_RSNON))
    {
      struct ieee80211_rsnparams rsn;
      const uint8_t *saveie = NULL;

      /* If the AP advertises both RSN and WPA IEs (WPA1+WPA2), we only store
       * the parameters of the highest protocol version we support.
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

  /* When scanning we record results (nodes) with a zero refcnt.  Otherwise we
   * want to hold the reference for ibss neighbors so the nodes don't get
   * released prematurely. Anything else can be discarded (XXX and should be
   * handled above so we don't do so much work).
   */

  if (is_new && isprobe)
    {
      /* Fake an association so the driver can setup it's private state.  The
       * rate set has been setup above; there is no handshake as in ap/station
       * operation.
       */

      if (ic->ic_newassoc)
        {
          (*ic->ic_newassoc) (ic, ni, 1);
        }
    }
}

/* Authentication frame format:
 * [2] Authentication algorithm number
 * [2] Authentication transaction sequence number
 * [2] Status code
 */

void ieee80211_recv_auth(struct ieee80211_s *ic, struct iob_s *iob,
                         struct ieee80211_node *ni,
                         struct ieee80211_rxinfo *rxi)
{
  const struct ieee80211_frame *wh;
  const uint8_t *frm;
  uint16_t algo, seq, status;

  /* Make sure all mandatory fixed fields are present */

  if (iob->io_len < sizeof(*wh) + 6)
    {
      ndbg("ERROR: frame too short\n");
      return;
    }

  wh = (FAR struct ieee80211_frame *)IOB_DATA(iob);
  frm = (const uint8_t *)&wh[1];

  algo = LE_READ_2(frm);
  frm += 2;
  seq = LE_READ_2(frm);
  frm += 2;
  status = LE_READ_2(frm);
  frm += 2;
  nvdbg("auth %d seq %d from %s\n", algo, seq,
        ieee80211_addr2str((uint8_t *) wh->i_addr2));

  /* only "open" auth mode is supported */

  if (algo != IEEE80211_AUTH_ALG_OPEN)
    {
      ndbg("ERROR: unsupported auth algorithm %d from %s\n",
           algo, ieee80211_addr2str((uint8_t *) wh->i_addr2));

      return;
    }

  ieee80211_auth_open(ic, wh, ni, rxi, seq, status);
}

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

void ieee80211_recv_assoc_resp(struct ieee80211_s *ic, struct iob_s *iob,
                               struct ieee80211_node *ni, int reassoc)
{
  const struct ieee80211_frame *wh;
  const uint8_t *frm;
  const uint8_t *efrm;
  const uint8_t *rates;
  const uint8_t *xrates;
  const uint8_t *edcaie;
  const uint8_t *wmmie;
  uint16_t capinfo;
  uint16_t status;
  uint16_t associd;
  uint8_t rate;

  if (ic->ic_opmode != IEEE80211_M_STA || ic->ic_state != IEEE80211_S_ASSOC)
    {
      return;
    }

  /* Make sure all mandatory fixed fields are present */

  if (iob->io_len < sizeof(*wh) + 6)
    {
      ndbg("ERROR: frame too short\n");
      return;
    }

  wh = (FAR struct ieee80211_frame *)IOB_DATA(iob);
  frm = (const uint8_t *)&wh[1];
  efrm = IOB_DATA(iob) + iob->io_len;

  capinfo = LE_READ_2(frm);
  frm += 2;
  status = LE_READ_2(frm);
  frm += 2;
  if (status != IEEE80211_STATUS_SUCCESS)
    {
      nvdbg("%s: %sassociation failed (status %d) for %s\n",
            ic->ic_ifname, reassoc ? "re" : "",
            status, ieee80211_addr2str((uint8_t *) wh->i_addr3));

      if (ni != ic->ic_bss)
        {
          ni->ni_fails++;
        }

      return;
    }
  associd = LE_READ_2(frm);
  frm += 2;

  rates = NULL;
  xrates = NULL;
  edcaie = NULL;
  wmmie = NULL;

  while (frm + 2 <= efrm)
    {
      if (frm + 2 + frm[1] > efrm)
        {
          break;
        }

      switch (frm[0])
        {
        case IEEE80211_ELEMID_RATES:
          rates = frm;
          break;
        case IEEE80211_ELEMID_XRATES:
          xrates = frm;
          break;
        case IEEE80211_ELEMID_EDCAPARMS:
          edcaie = frm;
          break;

        case IEEE80211_ELEMID_VENDOR:
          if (frm[1] < 4)
            {
              break;
            }
          if (memcmp(frm + 2, MICROSOFT_OUI, 3) == 0)
            {
              if (frm[1] >= 5 && frm[5] == 2 && frm[6] == 1)
                wmmie = frm;
            }
          break;

        case IEEE80211_ELEMID_HTCAPS: /* 802.11n only */
        case IEEE80211_ELEMID_HTOP: /* 802.11n only */
        default:
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

  rate = ieee80211_setup_rates(ic, ni, rates, xrates,
                               IEEE80211_F_DOSORT | IEEE80211_F_DOFRATE |
                               IEEE80211_F_DONEGO | IEEE80211_F_DODEL);

  if (rate & IEEE80211_RATE_BASIC)
    {
      ndbg("ERROR: rate mismatch for %s\n",
           ieee80211_addr2str((uint8_t *) wh->i_addr2));
      return;
    }

  ni->ni_capinfo = capinfo;
  ni->ni_associd = associd;

  if (edcaie != NULL || wmmie != NULL)
    {
      /* Force update of EDCA parameters */

      ic->ic_edca_updtcount = -1;

      if ((edcaie != NULL &&
           ieee80211_parse_edca_params(ic, edcaie) == 0) ||
          (wmmie != NULL && ieee80211_parse_wmm_params(ic, wmmie) == 0))
        {
          ni->ni_flags |= IEEE80211_NODE_QOS;
        }
      else
        {
          /* for Reassociation */

          ni->ni_flags &= ~IEEE80211_NODE_QOS;
        }
    }

  /* Configure state now that we are associated */

  if (ic->ic_curmode == IEEE80211_MODE_11A ||
      (ni->ni_capinfo & IEEE80211_CAPINFO_SHORT_PREAMBLE))
    {
      ic->ic_flags |= IEEE80211_F_SHPREAMBLE;
    }
  else
    {
      ic->ic_flags &= ~IEEE80211_F_SHPREAMBLE;
    }

  ieee80211_set_shortslottime(ic,
                              ic->ic_curmode == IEEE80211_MODE_11A ||
                              (ni->
                               ni_capinfo & IEEE80211_CAPINFO_SHORT_SLOTTIME));
  /* Honor ERP protection */

  if (ic->ic_curmode == IEEE80211_MODE_11G &&
      (ni->ni_erp & IEEE80211_ERP_USE_PROTECTION))
    {
      ic->ic_flags |= IEEE80211_F_USEPROT;
    }
  else
    {
      ic->ic_flags &= ~IEEE80211_F_USEPROT;
    }

  /* If not an RSNA, mark the port as valid, otherwise wait for 802.1X
   * authentication and 4-way handshake to complete..
   */

  if (ic->ic_flags & IEEE80211_F_RSNON)
    {
      /* XXX ic->ic_mgt_timer = 5; */
    }
  else if (ic->ic_flags & IEEE80211_F_WEPON)
    {
      ni->ni_flags |= IEEE80211_NODE_TXRXPROT;
    }

  ieee80211_new_state(ic, IEEE80211_S_RUN, IEEE80211_FC0_SUBTYPE_ASSOC_RESP);
}

/* Deauthentication frame format:
 * [2] Reason code
 */

void ieee80211_recv_deauth(struct ieee80211_s *ic, struct iob_s *iob,
                           struct ieee80211_node *ni)
{
  const struct ieee80211_frame *wh;
  const uint8_t *frm;
  uint16_t reason;

  /* Make sure all mandatory fixed fields are present */

  if (iob->io_len < sizeof(*wh) + 2)
    {
      ndbg("ERROR: frame too short\n");
      return;
    }

  wh = (FAR struct ieee80211_frame *)IOB_DATA(iob);
  frm = (const uint8_t *)&wh[1];

  reason = LE_READ_2(frm);

  switch (ic->ic_opmode)
    {
    case IEEE80211_M_STA:
      ieee80211_new_state(ic, IEEE80211_S_AUTH, IEEE80211_FC0_SUBTYPE_DEAUTH);
      break;

    case IEEE80211_M_HOSTAP: /* AP only */
    default:
      break;
    }
}

/* Disassociation frame format:
 * [2] Reason code
 */

void ieee80211_recv_disassoc(struct ieee80211_s *ic, struct iob_s *iob,
                             struct ieee80211_node *ni)
{
  const struct ieee80211_frame *wh;
  const uint8_t *frm;
  uint16_t reason;

  /* Make sure all mandatory fixed fields are present */

  if (iob->io_len < sizeof(*wh) + 2)
    {
      ndbg("ERROR: frame too short\n");
      return;
    }

  wh = (FAR struct ieee80211_frame *)IOB_DATA(iob);
  frm = (const uint8_t *)&wh[1];

  reason = LE_READ_2(frm);

  switch (ic->ic_opmode)
    {
    case IEEE80211_M_STA:
      ieee80211_new_state(ic, IEEE80211_S_ASSOC,
                          IEEE80211_FC0_SUBTYPE_DISASSOC);
      break;

    case IEEE80211_M_HOSTAP: /* AP only */
    default:
      break;
    }
}

/* SA Query Request frame format:
 * [1] Category
 * [1] Action
 * [2] Transaction Identifier
 */

void ieee80211_recv_sa_query_req(struct ieee80211_s *ic, struct iob_s *iob,
                                 struct ieee80211_node *ni)
{
  const struct ieee80211_frame *wh;
  const uint8_t *frm;

  if (ic->ic_opmode != IEEE80211_M_STA || !(ni->ni_flags & IEEE80211_NODE_MFP))
    {
      ndbg("ERROR: unexpected SA Query req from %s\n",
           ieee80211_addr2str(ni->ni_macaddr));
      return;
    }

  if (iob->io_len < sizeof(*wh) + 4)
    {
      ndbg("ERROR: frame too short\n");
      return;
    }

  wh = (FAR struct ieee80211_frame *)IOB_DATA(iob);
  frm = (const uint8_t *)&wh[1];

  /* MLME-SAQuery.indication */

  /* Save Transaction Identifier for SA Query Response */

  ni->ni_sa_query_trid = LE_READ_2(&frm[2]);

  /* MLME-SAQuery.response */

  IEEE80211_SEND_ACTION(ic, ni, IEEE80211_CATEG_SA_QUERY,
                        IEEE80211_ACTION_SA_QUERY_RESP, 0);
}

/* Action frame format:
 * [1] Category
 * [1] Action
 */

void ieee80211_recv_action(struct ieee80211_s *ic, struct iob_s *iob,
                           struct ieee80211_node *ni)
{
  const struct ieee80211_frame *wh;
  const uint8_t *frm;

  if (iob->io_len < sizeof(*wh) + 2)
    {
      ndbg("ERROR: frame too short\n");
      return;
    }

  wh = (FAR struct ieee80211_frame *)IOB_DATA(iob);
  frm = (const uint8_t *)&wh[1];

  switch (frm[0])
    {
    case IEEE80211_CATEG_SA_QUERY:
      switch (frm[1])
        {
        case IEEE80211_ACTION_SA_QUERY_REQ:
          ieee80211_recv_sa_query_req(ic, iob, ni);
          break;
        }
      break;

    case IEEE80211_ACTION_SA_QUERY_RESP: /* AP only */
    case IEEE80211_CATEG_BA:  /* 802.11n only */
    default:
      ndbg("ERROR: action frame category %d not handled\n", frm[0]);
      break;
    }
}

void ieee80211_recv_mgmt(struct ieee80211_s *ic, struct iob_s *iob,
                         struct ieee80211_node *ni,
                         struct ieee80211_rxinfo *rxi, int subtype)
{
  switch (subtype)
    {
    case IEEE80211_FC0_SUBTYPE_BEACON:
      ieee80211_recv_probe_resp(ic, iob, ni, rxi, 0);
      break;
    case IEEE80211_FC0_SUBTYPE_PROBE_RESP:
      ieee80211_recv_probe_resp(ic, iob, ni, rxi, 1);
      break;
    case IEEE80211_FC0_SUBTYPE_AUTH:
      ieee80211_recv_auth(ic, iob, ni, rxi);
      break;
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

    case IEEE80211_FC0_SUBTYPE_PROBE_REQ:   /* AP only */
    case IEEE80211_FC0_SUBTYPE_ASSOC_REQ:   /* AP only */
    case IEEE80211_FC0_SUBTYPE_REASSOC_REQ: /* AP only */
    default:
      ndbg("ERROR: mgmt frame with subtype 0x%x not handled\n", subtype);
      break;
    }
}
