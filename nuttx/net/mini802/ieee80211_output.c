/****************************************************************************
 * net/ieee980211/ieee80211_output.c
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
#include <errno.h>
#include <assert.h>
#include <debug.h>

#include <net/if.h>

#ifdef CONFIG_NET_ETHERNET
#  include <netinet/in.h>
#  include <nuttx/net/uip/uip.h>
#  include <netinet/ip.h>
#  ifdef CONFIG_NET_IPv6
#    include <netinet/ip6.h>
#  endif
#endif

#include <nuttx/net/arp.h>
#include <nuttx/net/iob.h>
#include <nuttx/net/uip/uip.h>
#include <nuttx/net/uip/uip-arch.h>

#include "mini802/ieee80211_debug.h"
#include "mini802/ieee80211_ifnet.h"
#include "mini802/ieee80211_var.h"
#include "mini802/ieee80211_priv.h"

#include "net_internal.h"

/****************************************************************************
 * Private Function Prototypes
 ****************************************************************************/

int ieee80211_classify(struct ieee80211_s *, struct iob_s *);
static int ieee80211_mgmt_output(struct ieee80211_s *, struct ieee80211_node *,
                                 struct iob_s *, int);
uint8_t *ieee80211_add_rsn_body(uint8_t *, struct ieee80211_s *,
                                const struct ieee80211_node *, int);
struct iob_s *ieee80211_getmgmt(int, unsigned int);
struct iob_s *ieee80211_get_probe_req(struct ieee80211_s *,
                                      struct ieee80211_node *);
struct iob_s *ieee80211_get_auth(struct ieee80211_s *,
                                 struct ieee80211_node *, uint16_t, uint16_t);
struct iob_s *ieee80211_get_deauth(struct ieee80211_s *,
                                   struct ieee80211_node *, uint16_t);
struct iob_s *ieee80211_get_assoc_req(struct ieee80211_s *,
                                      struct ieee80211_node *, int);
struct iob_s *ieee80211_get_disassoc(struct ieee80211_s *,
                                     struct ieee80211_node *, uint16_t);
struct iob_s *ieee80211_get_sa_query(struct ieee80211_s *,
                                     struct ieee80211_node *, uint8_t);
struct iob_s *ieee80211_get_action(struct ieee80211_s *,
                                   struct ieee80211_node *, uint8_t, uint8_t,
                                   int);

/****************************************************************************
 * Private Functions
 ****************************************************************************/

/* IEEE 802.11 output routine. Normally this will directly call the
 * Ethernet output routine because 802.11 encapsulation is called
 * later by the driver. This function can be used to send raw frames
 * if the buffer has been tagged with a 802.11 data link type.
 */

#warning REVISIT: This was registered via the ifnet structure for use the driver level.
#warning REVISIT: It is not currently integrated with the rest of the logic
#warning REVISIT: Perhaps it should be included in ieee80211_ifsend()?

/* The BSD networking layer calls back (via the now non-nonexistent if_output
 * function pointer) when the interface is ready to send data.  The original
 * logic set the if_output pointer to ieee80211_output().
 *
 * Output occurred when the if_output function was called.  The parameter
 * iob is the I/O buffer chain to be sent and dst is the destination address.
 * The output routine encapsulates the supplied datagram if necessary (or may
 * send the the data as raw Ethernet data) then transmits it on its medium.
 */

int ieee80211_output(FAR struct ieee80211_s *ic, FAR struct iob_s *iob,
                     FAR struct sockaddr *dst, uint8_t flags)
{
  FAR struct uip_driver_s *dev;
  FAR struct ieee80211_frame *wh;
  FAR struct m_tag *mtag;
  uip_lock_t flags;
  int error = 0;

  /* Get the driver structure */

  dev = netdev_findbyaddr(ic->ic_ifname);
  if (!dev)
    {
      error = -ENODEV;
      goto bad;
    }

  /* Interface has to be up and running */

  if ((dev->d_flags & (IFF_UP | IFF_RUNNING)) != (IFF_UP | IFF_RUNNING))
    {
      error = -ENETDOWN;
      goto bad;
    }

  /* Try to get the DLT from a buffer tag */

  if ((mtag = m_tag_find(iob, PACKET_TAG_DLT, NULL)) != NULL)
    {
      unsigned int dlt = *(unsigned int *)(mtag + 1);

      /* Fallback to Ethernet for non-802.11 linktypes */

      if (!(dlt == DLT_IEEE802_11 || dlt == DLT_IEEE802_11_RADIO))
        {
          goto fallback;
        }

      if (iob->io_pktlen < sizeof(struct ieee80211_frame_min))
        {
          return -EINVAL;
        }

      wh = (FAR struct ieee80211_frame *)IOB_DATA(iob);
      if ((wh->i_fc[0] & IEEE80211_FC0_VERSION_MASK) != IEEE80211_FC0_VERSION_0)
        {
          return -EINVAL;
        }

      if (!(ic->ic_caps & IEEE80211_C_RAWCTL) &&
          (wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK) == IEEE80211_FC0_TYPE_CTL)
        {
          return -EINVAL;
        }

      /* Queue message on interface without adding any further headers, and
       * start output if interface not yet active.
       */

      flags = uip_lock();
      error = ieee80211_ifsend(ic, iob, flags);
      if (error)
        {
          /* buffer is already freed */

          uip_unlock(flags);
          ndbg("ERROR: %s: failed to queue raw tx frame\n", ic->ic_ifname);
          return error;
        }

      uip_unlock(flags);
      return error;
    }

fallback:
  return ether_output(ic, iob, dst);

bad:
  if (iob)
    {
      iob_free_chain(iob);
    }

  return error;
}

/* Send a management frame to the specified node.  The node pointer
 * must have a reference as the pointer will be passed to the driver
 * and potentially held for a long time.  If the frame is successfully
 * dispatched to the driver, then it is responsible for freeing the
 * reference (and potentially free'ing up any associated storage).
 */

static int ieee80211_mgmt_output(struct ieee80211_s *ic,
                                 struct ieee80211_node *ni, struct iob_s *iob,
                                 int type)
{
  struct ieee80211_frame *wh;
  int error;

  DEBUGASSERT(ni != NULL);
  ni->ni_inact = 0;

  /* We want to pass the node down to the driver's start routine.  We could
   * stick this in an m_tag and tack that on to the buffer.  However that's
   * rather expensive to do for every frame so instead we stuff it in a special 
   * pkthdr field.
   */

  error = iob_contig(iob, sizeof(struct ieee80211_frame));
  if (error < 0)
    {
      ndbg("ERROR: Failed to make contiguous: %d\n", error);
      return error;
    }

#warning REVISIT:  We do not want to burden everty IOB with this information
//iob->io_priv = ni;

  wh = (FAR struct ieee80211_frame *)IOB_DATA(iob);
  wh->i_fc[0] = IEEE80211_FC0_VERSION_0 | IEEE80211_FC0_TYPE_MGT | type;
  wh->i_fc[1] = IEEE80211_FC1_DIR_NODS;
  *(uint16_t *) & wh->i_dur[0] = 0;
  *(uint16_t *) & wh->i_seq[0] =
    htole16(ni->ni_txseq << IEEE80211_SEQ_SEQ_SHIFT);
  ni->ni_txseq++;
  IEEE80211_ADDR_COPY(wh->i_addr1, ni->ni_macaddr);
  IEEE80211_ADDR_COPY(wh->i_addr2, ic->ic_myaddr);
  IEEE80211_ADDR_COPY(wh->i_addr3, ni->ni_bssid);

  /* Check if protection is required for this mgmt frame */

  if ((ic->ic_caps & IEEE80211_C_MFP) &&
      (type == IEEE80211_FC0_SUBTYPE_DISASSOC ||
       type == IEEE80211_FC0_SUBTYPE_DEAUTH ||
       type == IEEE80211_FC0_SUBTYPE_ACTION))
    {
      /* Hack: we should not set the Protected bit in outgoing group management 
       * frames, however it is used as an indication to the drivers that they
       * must encrypt the frame.  Drivers should clear this bit from group
       * management frames (software crypto code will do it).
       */

      if (IEEE80211_IS_MULTICAST(wh->i_addr1) ||
          (ni->ni_flags & IEEE80211_NODE_TXMGMTPROT))
        {
          wh->i_fc[1] |= IEEE80211_FC1_PROTECTED;
        }
    }

#if defined(CONFIG_DEBUG_NET) && defined (CONFIG_DEBUG_VERBOSE)
  /* avoid to print too many frames */

  if ((type & IEEE80211_FC0_SUBTYPE_MASK) != IEEE80211_FC0_SUBTYPE_PROBE_RESP)
    {
      nvdbg("%s: sending %s to %s on channel %u mode %s\n",
            ic->ic_ifname,
            ieee80211_mgt_subtype_name[(type & IEEE80211_FC0_SUBTYPE_MASK) >>
                                       IEEE80211_FC0_SUBTYPE_SHIFT],
            ieee80211_addr2str(ni->ni_macaddr), ieee80211_chan2ieee(ic,
                                                                    ni->
                                                                    ni_chan),
            ieee80211_phymode_name[ieee80211_chan2mode(ic, ni->ni_chan)]);
    }
#endif

  iob_add_queue(iob, &ic->ic_mgtq);
  return 0;
}

/* EDCA tables are computed using the following formulas:
 *
 * 1) EDCATable (non-AP QSTA)
 *
 * AC     CWmin        CWmax       AIFSN  TXOP limit(ms)
 * -------------------------------------------------------------
 * AC_BK  aCWmin       aCWmax       7      0
 * AC_BE  aCWmin       aCWmax       3      0
 * AC_VI  (aCWmin+1)/2-1   aCWmin       2      agn=3.008 b=6.016 others=0
 * AC_VO  (aCWmin+1)/4-1   (aCWmin+1)/2-1  2      agn=1.504 b=3.264 others=0
 *
 * 2) QAPEDCATable (QAP)
 *
 * AC     CWmin        CWmax       AIFSN  TXOP limit(ms)
 * -------------------------------------------------------------
 * AC_BK  aCWmin       aCWmax       7      0
 * AC_BE  aCWmin       4*(aCWmin+1)-1  3      0
 * AC_VI  (aCWmin+1)/2-1   aCWmin       1      agn=3.008 b=6.016 others=0
 * AC_VO  (aCWmin+1)/4-1   (aCWmin+1)/2-1  1      agn=1.504 b=3.264 others=0
 *
 * and the following aCWmin/aCWmax values:
 *
 * PHY        aCWmin    aCWmax
 * ---------------------------
 * 11A        15    1023
 * 11B      31    1023
 * 11G        15*    1023    (*) aCWmin(1)
 * Turbo A/G    7    1023    (Atheros proprietary mode)
 */
#if 0
static const struct ieee80211_edca_ac_params
  ieee80211_edca_table[IEEE80211_MODE_MAX][EDCA_NUM_AC] = {
  [IEEE80211_MODE_11B] = {
                          [EDCA_AC_BK] = {5, 10, 7, 0},
                          [EDCA_AC_BE] = {5, 10, 3, 0},
                          [EDCA_AC_VI] = {4, 5, 2, 188},
                          [EDCA_AC_VO] = {3, 4, 2, 102}
                          },
  [IEEE80211_MODE_11A] = {
                          [EDCA_AC_BK] = {4, 10, 7, 0},
                          [EDCA_AC_BE] = {4, 10, 3, 0},
                          [EDCA_AC_VI] = {3, 4, 2, 94},
                          [EDCA_AC_VO] = {2, 3, 2, 47}
                          },
  [IEEE80211_MODE_11G] = {
                          [EDCA_AC_BK] = {4, 10, 7, 0},
                          [EDCA_AC_BE] = {4, 10, 3, 0},
                          [EDCA_AC_VI] = {3, 4, 2, 94},
                          [EDCA_AC_VO] = {2, 3, 2, 47}
                          },
  [IEEE80211_MODE_TURBO] = {
                            [EDCA_AC_BK] = {3, 10, 7, 0},
                            [EDCA_AC_BE] = {3, 10, 2, 0},
                            [EDCA_AC_VI] = {2, 3, 2, 94},
                            [EDCA_AC_VO] = {2, 2, 1, 47}
                            }
};
#endif

/*
 * Return the EDCA Access Category to be used for transmitting a frame with
 * user-priority `up'.
 */
enum ieee80211_edca_ac ieee80211_up_to_ac(struct ieee80211_s *ic, int up)
{
  /* see Table 9-1 */
  static const enum ieee80211_edca_ac up_to_ac[] =
    {
      EDCA_AC_BE,               /* BE */
      EDCA_AC_BK,               /* BK */
      EDCA_AC_BK,               /* -- */
      EDCA_AC_BE,               /* EE */
      EDCA_AC_VI,               /* CL */
      EDCA_AC_VI,               /* VI */
      EDCA_AC_VO,               /* VO */
      EDCA_AC_VO                /* NC */
    };
  enum ieee80211_edca_ac ac;

  ac = (up <= 7) ? up_to_ac[up] : EDCA_AC_BE;

  /* We do not support the admission control procedure defined in
   * IEEE Std 802.11-2007 section 9.9.3.1.2.  The spec says that
   * non-AP QSTAs that don't support this procedure shall use EDCA
   * parameters of a lower priority AC that does not require
   * admission control.
   */

  while (ac != EDCA_AC_BK && ic->ic_edca_ac[ac].ac_acm)
    {
      switch (ac)
        {
        case EDCA_AC_BK:
          /* can't get there */

          break;
        case EDCA_AC_BE:
          /* BE shouldn't require admission control */

          ac = EDCA_AC_BK;
          break;
        case EDCA_AC_VI:
          ac = EDCA_AC_BE;
          break;
        case EDCA_AC_VO:
          ac = EDCA_AC_VI;
          break;
        }
    }
  return ac;
}

/* Get buffer's user-priority: if buffer is not VLAN tagged, select user-priority
 * based on the DSCP (Differentiated Services Codepoint) field.
 */

int ieee80211_classify(struct ieee80211_s *ic, struct iob_s *iob)
{
#ifdef CONFIG_NET_ETHERNET
  FAR struct uip_eth_hdr *ethhdr;
  uint8_t ds_field;
#endif
#ifdef __NO_VLAN__
  if (iob->io_flags & IOBFLAGS_VLANTAG) /* use VLAN 802.1D user-priority */
    return EVL_PRIOFTAG(iob->io_vtag);
#endif

#ifdef CONFIG_NET_ETHERNET
  ethhdr = (FAR struct uip_eth_hdr *)IOB_DATA(iob);

#  ifdef CONFIG_NET_IPv6
  if (ethhdr->type == htons(UIP_ETHTYPE_IP6))
    {
      FAR struct uip_ip_hdr6_hdr *ip6hdr =
        (FAR struct uip_ip_hdr6_hdr *)&ethhdr[1];
      uint32_t flowlabel;

      flowlabel = ntohl(ip6hdr->flow);
      if ((flowlabel >> 28) != 6)
        {
          return 0;
        }

      ds_field = (flowlabel >> 20) & 0xff;
    }
#  else
  if (ethhdr->type == htons(UIP_ETHTYPE_IP))
    {
      FAR struct uip_ip_hdr *iphdr = (FAR struct uip_ip_hdr *)&ethhdr[1];
      if (iphdr->vhl != 4)
        {
          return 0;
        }

      ds_field = iphdr->tos;
    }

#  endif /* CONFIG_NET_IPv6 */

  /* Not IPv4/IPv6 */

  else
    {
      return 0;
    }

  /* Map Differentiated Services Codepoint field (see RFC2474). Preserves
   * backward compatibility with IP Precedence field.
   */

  switch (ds_field & 0xfc)
    {
    case IPTOS_PREC_PRIORITY:
      return 2;
    case IPTOS_PREC_IMMEDIATE:
      return 1;
    case IPTOS_PREC_FLASH:
      return 3;
    case IPTOS_PREC_FLASHOVERRIDE:
      return 4;
    case IPTOS_PREC_CRITIC_ECP:
      return 5;
    case IPTOS_PREC_INTERNETCONTROL:
      return 6;
    case IPTOS_PREC_NETCONTROL:
      return 7;
    }
#endif /* CONFIG_NET_ETHERNET */
  return 0;                     /* default to Best-Effort */
}

/* Encapsulate an outbound data frame.  The buffer chain is updated and
 * a reference to the destination node is returned.  If an error is
 * encountered NULL is returned and the node reference will also be NULL.
 *
 * NB: The caller is responsible for free'ing a returned node reference.
 *     The convention is ic_bss is not reference counted; the caller must
 *     maintain that.
 */

FAR struct iob_s *ieee80211_encap(FAR struct ieee80211_s *ic,
                                  FAR struct iob_s *iob,
                                  FAR struct ieee80211_node **pni)
{
  struct uip_eth_hdr ethhdr;
  FAR struct ieee80211_frame *wh;
  FAR struct ieee80211_node *ni = NULL;
  struct llc *llc;
  FAR struct m_tag *mtag;
  FAR uint8_t *addr;
  unsigned int dlt;
  unsigned int hdrlen;
  int addqos;
  int tid;
  int error;

  /* Handle raw frames if buffer is tagged as 802.11 */

  if ((mtag = m_tag_find(iob, PACKET_TAG_DLT, NULL)) != NULL)
    {
      dlt = *(unsigned int *)(mtag + 1);

      if (!(dlt == DLT_IEEE802_11 || dlt == DLT_IEEE802_11_RADIO))
        {
          goto fallback;
        }

      wh = (FAR struct ieee80211_frame *)IOB_DATA(iob);
      switch (wh->i_fc[1] & IEEE80211_FC1_DIR_MASK)
        {
        case IEEE80211_FC1_DIR_NODS:
        case IEEE80211_FC1_DIR_FROMDS:
          addr = wh->i_addr1;
          break;

        case IEEE80211_FC1_DIR_DSTODS:
        case IEEE80211_FC1_DIR_TODS:
          addr = wh->i_addr3;
          break;

        default:
          goto bad;
        }

      ni = ieee80211_find_txnode(ic, addr);
      if (ni == NULL)
        {
          ni = ieee80211_ref_node(ic->ic_bss);
        }

      if (ni == NULL)
        {
          nvdbg("%s: no node for dst %s, discard raw tx frame\n",
                ic->ic_ifname, ieee80211_addr2str(addr));
          goto bad;
        }

      ni->ni_inact = 0;
      *pni = ni;
      return (iob);
    }

fallback:
  if (iob->io_len < sizeof(struct uip_eth_hdr))
    {
      iob = iob_pack(iob);
      if (iob == NULL)
        {
          goto bad;
        }
    }

  memcpy(&ethhdr, IOB_DATA(iob), sizeof(struct uip_eth_hdr));

  ni = ieee80211_find_txnode(ic, ethhdr.dest);
  if (ni == NULL)
    {
      ndbg("ERROR: no node for dst %s, discard frame\n",
           ieee80211_addr2str(ethhdr.dest));
      goto bad;
    }

  if ((ic->ic_flags & IEEE80211_F_RSNON) && !ni->ni_port_valid &&
      ethhdr.type != htons(UIP_ETHTYPE_PAE))
    {
      ndbg("ERROR: port not valid: %s\n", ieee80211_addr2str(ethhdr.dest));
      goto bad;
    }

  if ((ic->ic_flags & IEEE80211_F_COUNTERM) && ni->ni_rsncipher == IEEE80211_CIPHER_TKIP)       /* XXX 
                                                                                                 * TKIP 
                                                                                                 * countermeasures! 
                                                                                                 */ ;
  {
    ni->ni_inact = 0;
  }

  if ((ic->ic_flags & IEEE80211_F_QOS) && (ni->ni_flags & IEEE80211_NODE_QOS) &&
      /* do not QoS-encapsulate EAPOL frames */
      ethhdr.type != htons(UIP_ETHTYPE_PAE))
    {
      tid = ieee80211_classify(ic, iob);
      hdrlen = sizeof(struct ieee80211_qosframe);
      addqos = 1;
    }
  else
    {
      hdrlen = sizeof(struct ieee80211_frame);
      addqos = 0;
    }

  iob = iob_trimhead(iob, sizeof(struct uip_eth_hdr) - LLC_SNAPFRAMELEN);
  llc = (FAR struct llc *)IOB_DATA(iob);
  llc->llc_dsap = llc->llc_ssap = LLC_SNAP_LSAP;
  llc->llc_control = LLC_UI;
  llc->llc_snap.org_code[0] = 0;
  llc->llc_snap.org_code[1] = 0;
  llc->llc_snap.org_code[2] = 0;
  llc->llc_snap.type = ethhdr.type;

  error = iob_contig(iob, hdrlen);
  if (error < 0)
    {
      ndbg("ERROR: Failed to make contiguous: %d\n", error);
      goto bad;
    }

  wh = (FAR struct ieee80211_frame *)IOB_DATA(iob);
  wh->i_fc[0] = IEEE80211_FC0_VERSION_0 | IEEE80211_FC0_TYPE_DATA;
  *(uint16_t *) & wh->i_dur[0] = 0;
  if (addqos)
    {
      FAR struct ieee80211_qosframe *qwh = (struct ieee80211_qosframe *)wh;
      uint16_t qos = tid;

      if (ic->ic_tid_noack & (1 << tid))
        {
          qos |= IEEE80211_QOS_ACK_POLICY_NOACK;
        }

      qwh->i_fc[0] |= IEEE80211_FC0_SUBTYPE_QOS;
      *(uint16_t *) qwh->i_qos = htole16(qos);
      *(uint16_t *) qwh->i_seq =
        htole16(ni->ni_qos_txseqs[tid] << IEEE80211_SEQ_SEQ_SHIFT);
      ni->ni_qos_txseqs[tid]++;
    }
  else
    {
      *(uint16_t *) & wh->i_seq[0] =
        htole16(ni->ni_txseq << IEEE80211_SEQ_SEQ_SHIFT);
      ni->ni_txseq++;
    }

  switch (ic->ic_opmode)
    {
    case IEEE80211_M_STA:
      wh->i_fc[1] = IEEE80211_FC1_DIR_TODS;
      IEEE80211_ADDR_COPY(wh->i_addr1, ni->ni_bssid);
      IEEE80211_ADDR_COPY(wh->i_addr2, ethhdr.src);
      IEEE80211_ADDR_COPY(wh->i_addr3, ethhdr.dest);
      break;

    case IEEE80211_M_IBSS:   /* AP only */
    case IEEE80211_M_AHDEMO: /* AP only */
    case IEEE80211_M_HOSTAP: /* AP only */
    default:
      /* Should not get there */

      goto bad;
    }

  if ((ic->ic_flags & IEEE80211_F_WEPON) ||
      ((ic->ic_flags & IEEE80211_F_RSNON) &&
       (ni->ni_flags & IEEE80211_NODE_TXPROT)))
    {
      wh->i_fc[1] |= IEEE80211_FC1_PROTECTED;
    }

  *pni = ni;
  return iob;

bad:
  if (iob != NULL)
    {
      iob_free_chain(iob);
    }

  if (ni != NULL)
    {
      ieee80211_release_node(ic, ni);
    }

  *pni = NULL;
  return NULL;
}

/* Add a Capability Information field to a frame (see 7.3.1.4). */

uint8_t *ieee80211_add_capinfo(uint8_t * frm, struct ieee80211_s * ic,
                               const struct ieee80211_node * ni)
{
  uint16_t capinfo;

  capinfo = 0;

  /* NB: some 11a AP's reject the request when short preamble is set */

  if ((ic->ic_flags & IEEE80211_F_SHPREAMBLE) &&
      IEEE80211_IS_CHAN_2GHZ(ni->ni_chan))
    capinfo |= IEEE80211_CAPINFO_SHORT_PREAMBLE;
  if (ic->ic_flags & IEEE80211_F_SHSLOT)
    capinfo |= IEEE80211_CAPINFO_SHORT_SLOTTIME;
  LE_WRITE_2(frm, capinfo);
  return frm + 2;
}

/* Add an SSID element to a frame (see 7.3.2.1). */

uint8_t *ieee80211_add_ssid(uint8_t * frm, const uint8_t * ssid,
                            unsigned int len)
{
  *frm++ = IEEE80211_ELEMID_SSID;
  *frm++ = len;
  memcpy(frm, ssid, len);
  return frm + len;
}

/* Add a supported rates element to a frame (see 7.3.2.2). */

uint8_t *ieee80211_add_rates(uint8_t * frm, const struct ieee80211_rateset * rs)
{
  int nrates;

  *frm++ = IEEE80211_ELEMID_RATES;
  nrates = MIN(rs->rs_nrates, IEEE80211_RATE_SIZE);
  *frm++ = nrates;
  memcpy(frm, rs->rs_rates, nrates);
  return frm + nrates;
}

/* Add a QoS Capability element to a frame (see 7.3.2.35). */

uint8_t *ieee80211_add_qos_capability(uint8_t * frm, struct ieee80211_s * ic)
{
  *frm++ = IEEE80211_ELEMID_QOS_CAP;
  *frm++ = 1;
  *frm++ = 0;                   /* QoS Info */
  return frm;
}

/* Add an RSN element to a frame (see 7.3.2.25). */

uint8_t *ieee80211_add_rsn_body(uint8_t * frm, struct ieee80211_s * ic,
                                const struct ieee80211_node * ni, int wpa)
{
  const uint8_t *oui = wpa ? MICROSOFT_OUI : IEEE80211_OUI;
  uint8_t *pcount;
  uint16_t count;

  /* write Version field */

  LE_WRITE_2(frm, 1);
  frm += 2;

  /* write Group Data Cipher Suite field (see Table 20da) */

  memcpy(frm, oui, 3);
  frm += 3;
  switch (ni->ni_rsngroupcipher)
    {
    case IEEE80211_CIPHER_WEP40:
      *frm++ = 1;
      break;
    case IEEE80211_CIPHER_TKIP:
      *frm++ = 2;
      break;
    case IEEE80211_CIPHER_CCMP:
      *frm++ = 4;
      break;
    case IEEE80211_CIPHER_WEP104:
      *frm++ = 5;
      break;
    default:
      /* Can't get there */

      ndbg("ERROR: invalid group data cipher!\n");
      PANIC();
    }

  pcount = frm;
  frm += 2;
  count = 0;

  /* write Pairwise Cipher Suite List */

  if (ni->ni_rsnciphers & IEEE80211_CIPHER_USEGROUP)
    {
      memcpy(frm, oui, 3);
      frm += 3;
      *frm++ = 0;
      count++;
    }
  if (ni->ni_rsnciphers & IEEE80211_CIPHER_TKIP)
    {
      memcpy(frm, oui, 3);
      frm += 3;
      *frm++ = 2;
      count++;
    }
  if (ni->ni_rsnciphers & IEEE80211_CIPHER_CCMP)
    {
      memcpy(frm, oui, 3);
      frm += 3;
      *frm++ = 4;
      count++;
    }

  /* write Pairwise Cipher Suite Count field */

  LE_WRITE_2(pcount, count);

  pcount = frm;
  frm += 2;
  count = 0;

  /* write AKM Suite List (see Table 20dc) */

  if (ni->ni_rsnakms & IEEE80211_AKM_8021X)
    {
      memcpy(frm, oui, 3);
      frm += 3;
      *frm++ = 1;
      count++;
    }
  if (ni->ni_rsnakms & IEEE80211_AKM_PSK)
    {
      memcpy(frm, oui, 3);
      frm += 3;
      *frm++ = 2;
      count++;
    }
  if (!wpa && (ni->ni_rsnakms & IEEE80211_AKM_SHA256_8021X))
    {
      memcpy(frm, oui, 3);
      frm += 3;
      *frm++ = 5;
      count++;
    }
  if (!wpa && (ni->ni_rsnakms & IEEE80211_AKM_SHA256_PSK))
    {
      memcpy(frm, oui, 3);
      frm += 3;
      *frm++ = 6;
      count++;
    }

  /* write AKM Suite List Count field */

  LE_WRITE_2(pcount, count);

  if (wpa)
    return frm;

  /* write RSN Capabilities field */

  LE_WRITE_2(frm, ni->ni_rsncaps);
  frm += 2;

  if (ni->ni_flags & IEEE80211_NODE_PMKID)
    {
      /* write PMKID Count field */

      LE_WRITE_2(frm, 1);
      frm += 2;

      /* write PMKID List (only 1) */

      memcpy(frm, ni->ni_pmkid, IEEE80211_PMKID_LEN);
      frm += IEEE80211_PMKID_LEN;
    }
  else
    {
      /* no PMKID (PMKID Count=0) */

      LE_WRITE_2(frm, 0);
      frm += 2;
    }

  if (!(ic->ic_caps & IEEE80211_C_MFP))
    return frm;

  /* write Group Integrity Cipher Suite field */

  memcpy(frm, oui, 3);
  frm += 3;
  switch (ic->ic_rsngroupmgmtcipher)
    {
    case IEEE80211_CIPHER_BIP:
      *frm++ = 6;
      break;
    default:
      /* Can't get there */

      ndbg("ERROR: invalid integrity group cipher!");
      PANIC();
    }
  return frm;
}

uint8_t *ieee80211_add_rsn(uint8_t * frm, struct ieee80211_s * ic,
                           const struct ieee80211_node * ni)
{
  uint8_t *plen;

  *frm++ = IEEE80211_ELEMID_RSN;
  plen = frm++;                 /* length filled in later */
  frm = ieee80211_add_rsn_body(frm, ic, ni, 0);

  /* write length field */

  *plen = frm - plen - 1;
  return frm;
}

/* Add a vendor-specific WPA element to a frame.
 * This is required for compatibility with Wi-Fi Alliance WPA.
 */
 
uint8_t *ieee80211_add_wpa(uint8_t * frm, struct ieee80211_s * ic,
                           const struct ieee80211_node * ni)
{
  uint8_t *plen;

  *frm++ = IEEE80211_ELEMID_VENDOR;
  plen = frm++;                 /* length filled in later */
  memcpy(frm, MICROSOFT_OUI, 3);
  frm += 3;
  *frm++ = 1;                   /* WPA */
  frm = ieee80211_add_rsn_body(frm, ic, ni, 1);

  /* write length field */

  *plen = frm - plen - 1;
  return frm;
}

/* Add an extended supported rates element to a frame (see 7.3.2.14). */

uint8_t *ieee80211_add_xrates(uint8_t * frm,
                              const struct ieee80211_rateset * rs)
{
  int nrates;

  DEBUGASSERT(rs->rs_nrates > IEEE80211_RATE_SIZE);

  *frm++ = IEEE80211_ELEMID_XRATES;
  nrates = rs->rs_nrates - IEEE80211_RATE_SIZE;
  *frm++ = nrates;
  memcpy(frm, rs->rs_rates + IEEE80211_RATE_SIZE, nrates);
  return frm + nrates;
}

struct iob_s *ieee80211_getmgmt(int type, unsigned int pktlen)
{
  struct iob_s *iob;

  /* Reserve space for 802.11 header */

  pktlen += sizeof(struct ieee80211_frame);
  DEBUGASSERT(pktlen <= MCLBYTES);

  iob = iob_alloc(false);
  if (iob == NULL)
    {
      return NULL;
    }

  if (pktlen > CONFIG_IEEE80211_BUFSIZE)
    {
      iob_free(iob);
      return NULL;
    }

  iob->io_len = sizeof(struct ieee80211_frame);
  return iob;
}

/* Probe request frame format:
 * [tlv] SSID
 * [tlv] Supported rates
 * [tlv] Extended Supported Rates (802.11g)
 * [tlv] HT Capabilities (802.11n)
 */

struct iob_s *ieee80211_get_probe_req(FAR struct ieee80211_s *ic,
                                      FAR struct ieee80211_node *ni)
{
  FAR const struct ieee80211_rateset *rs =
    &ic->ic_sup_rates[ieee80211_chan2mode(ic, ni->ni_chan)];
  FAR struct iob_s *iob;
  FAR uint8_t *frm;

  iob = ieee80211_getmgmt(MT_DATA,
                          2 + ic->ic_des_esslen +
                          2 + MIN(rs->rs_nrates, IEEE80211_RATE_SIZE) +
                          ((rs->rs_nrates > IEEE80211_RATE_SIZE) ?
                           2 + rs->rs_nrates - IEEE80211_RATE_SIZE : 0) +
                          ((ni->ni_flags & IEEE80211_NODE_HT) ? 28 : 0));

  if (iob == NULL)
    {
      return NULL;
    }

  frm = (FAR uint8_t *) IOB_DATA(iob);
  frm = ieee80211_add_ssid(frm, ic->ic_des_essid, ic->ic_des_esslen);
  frm = ieee80211_add_rates(frm, rs);
  if (rs->rs_nrates > IEEE80211_RATE_SIZE)
    {
      frm = ieee80211_add_xrates(frm, rs);
    }

  iob->io_pktlen = iob->io_len = frm - IOB_DATA(iob);
  return iob;
}

/* Authentication frame format:
 * [2] Authentication algorithm number
 * [2] Authentication transaction sequence number
 * [2] Status code
 */

struct iob_s *ieee80211_get_auth(struct ieee80211_s *ic,
                                 struct ieee80211_node *ni, uint16_t status,
                                 uint16_t seq)
{
  struct iob_s *iob;
  uint8_t *frm;

  iob = iob_alloc(false);
  if (iob == NULL)
    {
      return NULL;
    }

  IOB_ALIGN(iob, 2 * 3);
  iob->io_pktlen = iob->io_len = 2 * 3;

  frm = (FAR uint8_t *) IOB_DATA(iob);
  LE_WRITE_2(frm, IEEE80211_AUTH_ALG_OPEN);
  frm += 2;
  LE_WRITE_2(frm, seq);
  frm += 2;
  LE_WRITE_2(frm, status);

  return iob;
}

/* Deauthentication frame format:
 * [2] Reason code
 */

struct iob_s *ieee80211_get_deauth(struct ieee80211_s *ic,
                                   struct ieee80211_node *ni, uint16_t reason)
{
  struct iob_s *iob;

  iob = iob_alloc(false);
  if (iob == NULL)
    {
      return NULL;
    }

  IOB_ALIGN(iob, 2);

  iob->io_pktlen = iob->io_len = 2;
  (FAR uint16_t *) IOB_DATA(iob) = htole16(reason);

  return iob;
}

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

struct iob_s *ieee80211_get_assoc_req(struct ieee80211_s *ic,
                                      struct ieee80211_node *ni, int type)
{
  const struct ieee80211_rateset *rs = &ni->ni_rates;
  struct iob_s *iob;
  uint8_t *frm;
  uint16_t capinfo;

  iob = ieee80211_getmgmt(MT_DATA,
                          2 + 2 +
                          ((type == IEEE80211_FC0_SUBTYPE_REASSOC_REQ) ?
                           IEEE80211_ADDR_LEN : 0) +
                          2 + ni->ni_esslen +
                          2 + MIN(rs->rs_nrates, IEEE80211_RATE_SIZE) +
                          ((rs->rs_nrates > IEEE80211_RATE_SIZE) ?
                           2 + rs->rs_nrates - IEEE80211_RATE_SIZE : 0) +
                          (((ic->ic_flags & IEEE80211_F_RSNON) &&
                            (ni->ni_rsnprotos & IEEE80211_PROTO_RSN)) ?
                           2 + IEEE80211_RSNIE_MAXLEN : 0) +
                          ((ni->ni_flags & IEEE80211_NODE_QOS) ? 2 + 1 : 0) +
                          (((ic->ic_flags & IEEE80211_F_RSNON) &&
                            (ni->ni_rsnprotos & IEEE80211_PROTO_WPA)) ?
                           2 + IEEE80211_WPAIE_MAXLEN : 0) +
                          ((ni->ni_flags & IEEE80211_NODE_HT) ? 28 : 0));

  if (iob == NULL)
    {
      return NULL;
    }

  frm = (FAR uint8_t *) IOB_DATA(iob);
  capinfo = IEEE80211_CAPINFO_ESS;
  if (ic->ic_flags & IEEE80211_F_WEPON)
    capinfo |= IEEE80211_CAPINFO_PRIVACY;
  if ((ic->ic_flags & IEEE80211_F_SHPREAMBLE) &&
      IEEE80211_IS_CHAN_2GHZ(ni->ni_chan))
    capinfo |= IEEE80211_CAPINFO_SHORT_PREAMBLE;
  if (ic->ic_caps & IEEE80211_C_SHSLOT)
    capinfo |= IEEE80211_CAPINFO_SHORT_SLOTTIME;
  LE_WRITE_2(frm, capinfo);
  frm += 2;
  LE_WRITE_2(frm, ic->ic_lintval);
  frm += 2;
  if (type == IEEE80211_FC0_SUBTYPE_REASSOC_REQ)
    {
      IEEE80211_ADDR_COPY(frm, ic->ic_bss->ni_bssid);
      frm += IEEE80211_ADDR_LEN;
    }
  frm = ieee80211_add_ssid(frm, ni->ni_essid, ni->ni_esslen);
  frm = ieee80211_add_rates(frm, rs);
  if (rs->rs_nrates > IEEE80211_RATE_SIZE)
    frm = ieee80211_add_xrates(frm, rs);
  if ((ic->ic_flags & IEEE80211_F_RSNON) &&
      (ni->ni_rsnprotos & IEEE80211_PROTO_RSN))
    frm = ieee80211_add_rsn(frm, ic, ni);
  if (ni->ni_flags & IEEE80211_NODE_QOS)
    frm = ieee80211_add_qos_capability(frm, ic);
  if ((ic->ic_flags & IEEE80211_F_RSNON) &&
      (ni->ni_rsnprotos & IEEE80211_PROTO_WPA))
    frm = ieee80211_add_wpa(frm, ic, ni);

  iob->io_pktlen = iob->io_len = frm - IOB_DATA(iob);
  return iob;
}

/* Disassociation frame format:
 * [2] Reason code
 */

struct iob_s *ieee80211_get_disassoc(struct ieee80211_s *ic,
                                     struct ieee80211_node *ni, uint16_t reason)
{
  struct iob_s *iob;

  iob = iob_alloc(false);
  if (iob == NULL)
    {
      return NULL;
    }

  IOB_ALIGN(iob, 2);

  iob->io_pktlen = iob->io_len = 2;
  (FAR uint16_t *) IOB_DATA(iob) = htole16(reason);
  return iob;
}

/* SA Query Request/Response frame format:
 * [1]  Category
 * [1]  Action
 * [16] Transaction Identifier
 */

struct iob_s *ieee80211_get_sa_query(struct ieee80211_s *ic,
                                     struct ieee80211_node *ni, uint8_t action)
{
  struct iob_s *iob;
  uint8_t *frm;

  iob = ieee80211_getmgmt(MT_DATA, 4);
  if (iob == NULL)
    {
      return NULL;
    }

  frm = (FAR uint8_t *) IOB_DATA(iob);
  *frm++ = IEEE80211_CATEG_SA_QUERY;
  *frm++ = action;              /* ACTION_SA_QUERY_REQ/RESP */
  LE_WRITE_2(frm, ni->ni_sa_query_trid);
  frm += 2;

  iob->io_pktlen = iob->io_len = frm - IOB_DATA(iob);
  return iob;
}

struct iob_s *ieee80211_get_action(struct ieee80211_s *ic,
                                   struct ieee80211_node *ni, uint8_t categ,
                                   uint8_t action, int arg)
{
  struct iob_s *iob = NULL;

  switch (categ)
    {
    case IEEE80211_CATEG_SA_QUERY:
      switch (action)
        {
        case IEEE80211_ACTION_SA_QUERY_RESP:
          iob = ieee80211_get_sa_query(ic, ni, action);
          break;

        case IEEE80211_ACTION_SA_QUERY_REQ: /* AP only */
        case IEEE80211_CATEG_BA:  /* IEEE 802.11n only */
        default:
          break;
        }
      break;
    }
  return iob;
}

/* Send a management frame.  The node is for the destination (or ic_bss
 * when in station mode).  Nodes other than ic_bss have their reference
 * count bumped to reflect our use for an indeterminant time.
 */

int ieee80211_send_mgmt(struct ieee80211_s *ic, struct ieee80211_node *ni,
                        int type, int arg1, int arg2)
{
  struct iob_s *iob;
  int timer;
  int ret DEBUGASSERT(ni != NULL);

  /* Hold a reference on the node so it doesn't go away until after the xmit is 
   * complete all the way in the driver.  On error we will remove our
   * reference.
   */

  ieee80211_ref_node(ni);
  timer = 0;
  switch (type)
    {
    case IEEE80211_FC0_SUBTYPE_PROBE_REQ:
      if ((iob = ieee80211_get_probe_req(ic, ni)) == NULL)
        {
          ret = -ENOMEM;
          goto bad;
        }

      timer = IEEE80211_TRANS_WAIT;
      break;

    case IEEE80211_FC0_SUBTYPE_AUTH:
      iob = ieee80211_get_auth(ic, ni, arg1 >> 16, arg1 & 0xffff);
      if (iob == NULL)
        {
          ret = -ENOMEM;
          goto bad;
        }

      if (ic->ic_opmode == IEEE80211_M_STA)
        timer = IEEE80211_TRANS_WAIT;
      break;

    case IEEE80211_FC0_SUBTYPE_DEAUTH:
      if ((iob = ieee80211_get_deauth(ic, ni, arg1)) == NULL)
        {
          ret = -ENOMEM;
          goto bad;
        }

      nvdbg("%s: station %s deauthenticate (reason %d)\n",
            ic->ic_ifname, ieee80211_addr2str(ni->ni_macaddr), arg1);
      break;

    case IEEE80211_FC0_SUBTYPE_ASSOC_REQ:
    case IEEE80211_FC0_SUBTYPE_REASSOC_REQ:
      if ((iob = ieee80211_get_assoc_req(ic, ni, type)) == NULL)
        {
          ret = -ENOMEM;
          goto bad;
        }

      timer = IEEE80211_TRANS_WAIT;
      break;

    case IEEE80211_FC0_SUBTYPE_DISASSOC:
      if ((iob = ieee80211_get_disassoc(ic, ni, arg1)) == NULL)
        {
          ret = -ENOMEM;
          goto bad;
        }

      nvdbg("%s: station %s disassociate (reason %d)\n",
            ic->ic_ifname, ieee80211_addr2str(ni->ni_macaddr), arg1);
      break;

    case IEEE80211_FC0_SUBTYPE_ACTION:
      iob = ieee80211_get_action(ic, ni, arg1 >> 16, arg1 & 0xffff, arg2);
      if (iob == NULL)
        {
          ret = -ENOMEM;
          goto bad;
        }
      break;

    case IEEE80211_FC0_SUBTYPE_PROBE_RESP:   /* AP only */
    case IEEE80211_FC0_SUBTYPE_ASSOC_RESP:   /* AP only */
    case IEEE80211_FC0_SUBTYPE_REASSOC_RESP: /* AP only */
    default:
      ndbg("ERROR: invalid mgmt frame type %u\n", type);
      ret = -EINVAL;
      goto bad;
    }

  ret = ieee80211_mgmt_output(ic, ni, iob, type);
  if (ret == 0)
    {
      if (timer)
        {
          ic->ic_mgt_timer = timer;
        }
    }
  else
    {
    bad:
      ieee80211_release_node(ic, ni);
    }

  return ret;
}

/* Build a RTS (Request To Send) control frame (see 7.2.1.1) */

struct iob_s *ieee80211_get_rts(struct ieee80211_s *ic,
                                const struct ieee80211_frame *wh, uint16_t dur)
{
  struct ieee80211_frame_rts *rts;
  struct iob_s *iob;

  iob = iob_alloc(false);
  if (iob == NULL)
    {
      return NULL;
    }

  iob->io_pktlen = iob->io_len = sizeof(struct ieee80211_frame_rts);

  rts = (FAR struct ieee80211_frame_rts *)IOB_DATA(iob);
  rts->i_fc[0] =
    IEEE80211_FC0_VERSION_0 | IEEE80211_FC0_TYPE_CTL |
    IEEE80211_FC0_SUBTYPE_RTS;
  rts->i_fc[1] = IEEE80211_FC1_DIR_NODS;
  *(uint16_t *) rts->i_dur = htole16(dur);
  IEEE80211_ADDR_COPY(rts->i_ra, wh->i_addr1);
  IEEE80211_ADDR_COPY(rts->i_ta, wh->i_addr2);

  return iob;
}

/* Build a CTS-to-self (Clear To Send) control frame (see 7.2.1.2) */

struct iob_s *ieee80211_get_cts_to_self(struct ieee80211_s *ic, uint16_t dur)
{
  struct ieee80211_frame_cts *cts;
  struct iob_s *iob;

  iob = iob_alloc(false);
  if (iob == NULL)
    {
      return NULL;
    }

  iob->io_pktlen = iob->io_len = sizeof(struct ieee80211_frame_cts);

  cts = (FAR struct ieee80211_frame_cts *)IOB_DATA(iob);
  cts->i_fc[0] =
    IEEE80211_FC0_VERSION_0 | IEEE80211_FC0_TYPE_CTL |
    IEEE80211_FC0_SUBTYPE_CTS;
  cts->i_fc[1] = IEEE80211_FC1_DIR_NODS;
  *(uint16_t *) cts->i_dur = htole16(dur);
  IEEE80211_ADDR_COPY(cts->i_ra, ic->ic_myaddr);

  return iob;
}
