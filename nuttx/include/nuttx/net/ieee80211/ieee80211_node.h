/****************************************************************************
 * include/nuttx/net/ieee80211/ieee80211_node.h
 *
 * Copyright (c) 2001 Atsushi Onoe
 * Copyright (c) 2002, 2003 Sam Leffler, Errno Consulting
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

#ifndef _INCLUDE_NUTTX_NET_IEEE80211_IEEE80211_NODE_H
#define _INCLUDE_NUTTX_NET_IEEE80211_IEEE80211_NODE_H

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <nuttx/config.h>

#include <wdog.h>
#include <queue.h>

#include <nuttx/tree.h>

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

#define IEEE80211_PSCAN_WAIT    5        /* passive scan wait */
#define IEEE80211_TRANS_WAIT    5        /* transition wait */
#define IEEE80211_INACT_WAIT    5        /* inactivity timer interval */
#define IEEE80211_INACT_MAX    (300/IEEE80211_INACT_WAIT)
#define IEEE80211_CACHE_SIZE    100
#define IEEE80211_CACHE_WAIT    3600

/****************************************************************************
 * Public Types
 ****************************************************************************/

struct ieee80211_rateset
{
  uint8_t rs_nrates;
  uint8_t rs_rates[IEEE80211_RATE_MAXSIZE];
};

/****************************************************************************
 * Public Data
 ****************************************************************************/

extern const struct ieee80211_rateset ieee80211_std_rateset_11a;
extern const struct ieee80211_rateset ieee80211_std_rateset_11b;
extern const struct ieee80211_rateset ieee80211_std_rateset_11g;

enum ieee80211_node_state
{
  IEEE80211_STA_CACHE,     /* cached node */
  IEEE80211_STA_BSS,       /* ic->ic_bss, the network we joined */
  IEEE80211_STA_AUTH,      /* successfully authenticated */
  IEEE80211_STA_ASSOC,     /* successfully associated */
  IEEE80211_STA_COLLECT    /* This node remains in the cache while
                            * the driver sends a de-auth message;
                            * afterward it should be freed to make room
                            * for a new node.
                            */
};

#define ieee80211_node_newstate(__ni, __state)    \
    do {                    \
        (__ni)->ni_state = (__state);    \
    } while (0)

enum ieee80211_node_psstate
{
  IEEE80211_PS_AWAKE,
  IEEE80211_PS_DOZE
};

/* Authenticator state machine: 4-Way Handshake (see 8.5.6.1.1) */

enum
{
  RSNA_INITIALIZE,
  RSNA_AUTHENTICATION,
  RSNA_AUTHENTICATION_2,
  RSNA_INITPMK,
  RSNA_INITPSK,
  RSNA_PTKSTART,
  RSNA_PTKCALCNEGOTIATING,
  RSNA_PTKCALCNEGOTIATING_2,
  RSNA_PTKINITNEGOTIATING,
  RSNA_PTKINITDONE,
  RSNA_DISCONNECT,
  RSNA_DISCONNECTED
};

/* Authenticator state machine: Group Key Handshake (see 8.5.6.1.2) */

enum
{
  RSNA_IDLE,
  RSNA_REKEYNEGOTIATING,
  RSNA_REKEYESTABLISHED,
  RSNA_KEYERROR
};

struct ieee80211_rxinfo
{
  uint32_t        rxi_flags;
  uint32_t        rxi_tstamp;
  int             rxi_rssi;
};

#define IEEE80211_RXI_HWDEC        0x00000001
#define IEEE80211_RXI_AMPDU_DONE    0x00000002

/* Block Acknowledgement Record */

struct ieee80211_tx_ba
{
  struct ieee80211_node *ba_ni;        /* backpointer for callbacks */
  WDOG_ID        ba_to;
  int            ba_timeout_val;
#define IEEE80211_BA_MIN_TIMEOUT    (10 * 1000)        /* 10msec */
#define IEEE80211_BA_MAX_TIMEOUT    (10 * 1000 * 1000) /* 10sec */

  int            ba_state;
#define IEEE80211_BA_INIT    0
#define IEEE80211_BA_REQUESTED    1
#define IEEE80211_BA_AGREED    2

  uint16_t       ba_winstart;
  uint16_t       ba_winend;
  uint16_t       ba_winsize;
#define IEEE80211_BA_MAX_WINSZ    128  /* maximum we will accept */

  uint8_t        ba_token;
};

struct ieee80211_rx_ba
{
  struct ieee80211_node *ba_ni;        /* backpointer for callbacks */
  struct
  {
    struct ieee80211_iobuf *m;
    struct ieee80211_rxinfo rxi;
  }             *ba_buf;
  WDOG_ID        ba_to;
  int            ba_timeout_val;
  int            ba_state;
  uint16_t       ba_winstart;
  uint16_t       ba_winend;
  uint16_t       ba_winsize;
  uint16_t       ba_head;
};

/* Node specific information.  Note that drivers are expected
 * to derive from this structure to add device-specific per-node
 * state.  This is done by overriding the ic_node_* methods in
 * the ieee80211com structure.
 */

struct ieee80211_node
{
  RB_ENTRY(ieee80211_node) ni_node;

  struct ieee80211com *ni_ic;          /* back-pointer */

  unsigned int    ni_refcnt;
  unsigned int    ni_scangen;          /* gen# for timeout scan */

  /* hardware */

  uint32_t        ni_rstamp;           /* recv timestamp */
  uint8_t         ni_rssi;             /* recv ssi */

  /* header */

  uint8_t         ni_macaddr[IEEE80211_ADDR_LEN];
  uint8_t         ni_bssid[IEEE80211_ADDR_LEN];

  /* beacon, probe response */

  uint8_t         ni_tstamp[8];        /* from last rcv'd beacon */
  uint16_t        ni_intval;           /* beacon interval */
  uint16_t        ni_capinfo;          /* capabilities */
  uint8_t         ni_esslen;
  uint8_t         ni_essid[IEEE80211_NWID_LEN];
  struct ieee80211_rateset ni_rates;   /* negotiated rate set */
  struct ieee80211_channel *ni_chan;
  uint8_t         ni_erp;              /* 11g only */

  /* power saving mode */

  uint8_t         ni_pwrsave;
  sq_queue_t      ni_savedq;           /* packets queued for pspoll */

  /* RSN */

  WDOG_ID         ni_eapol_to;
  unsigned int    ni_rsn_state;
  unsigned int    ni_rsn_gstate;
  unsigned int    ni_rsn_retries;
  unsigned int    ni_rsnprotos;
  unsigned int    ni_rsnakms;
  unsigned int    ni_rsnciphers;
  enum ieee80211_cipher ni_rsngroupcipher;
  enum ieee80211_cipher ni_rsngroupmgmtcipher;
  uint16_t        ni_rsncaps;
  enum ieee80211_cipher ni_rsncipher;
  uint8_t         ni_nonce[EAPOL_KEY_NONCE_LEN];
  uint8_t         ni_pmk[IEEE80211_PMK_LEN];
  uint8_t         ni_pmkid[IEEE80211_PMKID_LEN];
  uint64_t        ni_replaycnt;
  uint8_t         ni_replaycnt_ok;
  uint64_t        ni_reqreplaycnt;
  uint8_t         ni_reqreplaycnt_ok;
  uint8_t        *ni_rsnie;
  struct ieee80211_key ni_pairwise_key;
  struct ieee80211_ptk ni_ptk;
  uint8_t         ni_key_count;
  int             ni_port_valid;

  /* SA Query */

  uint16_t        ni_sa_query_trid;
  WDOG_ID         ni_sa_query_to;
  int             ni_sa_query_count;

  /* Block Ack records */

  struct ieee80211_tx_ba ni_tx_ba[IEEE80211_NUM_TID];
  struct ieee80211_rx_ba ni_rx_ba[IEEE80211_NUM_TID];

  /* others */

  uint16_t        ni_associd;          /* assoc response */
  uint16_t        ni_txseq;            /* seq to be transmitted */
  uint16_t        ni_rxseq;            /* seq previous received */
  uint16_t        ni_qos_txseqs[IEEE80211_NUM_TID];
  uint16_t        ni_qos_rxseqs[IEEE80211_NUM_TID];
  int             ni_fails;            /* failure count to associate */
  int             ni_inact;            /* inactivity mark count */
  int             ni_txrate;           /* index to ni_rates[] */
  int             ni_state;

  uint16_t        ni_flags;            /* special-purpose state */
#define IEEE80211_NODE_ERP             0x0001
#define IEEE80211_NODE_QOS             0x0002
#define IEEE80211_NODE_REKEY           0x0004    /* GTK rekeying in progress */
#define IEEE80211_NODE_RXPROT          0x0008    /* RX protection ON */
#define IEEE80211_NODE_TXPROT          0x0010    /* TX protection ON */
#define IEEE80211_NODE_TXRXPROT \
    (IEEE80211_NODE_TXPROT | IEEE80211_NODE_RXPROT)
#define IEEE80211_NODE_RXMGMTPROT      0x0020    /* RX MMPDU protection ON */
#define IEEE80211_NODE_TXMGMTPROT      0x0040    /* TX MMPDU protection ON */
#define IEEE80211_NODE_MFP             0x0080    /* MFP negotiated */
#define IEEE80211_NODE_PMK             0x0100    /* ni_pmk set */
#define IEEE80211_NODE_PMKID           0x0200    /* ni_pmkid set */
#define IEEE80211_NODE_HT              0x0400    /* HT negotiated */
#define IEEE80211_NODE_SA_QUERY        0x0800    /* SA Query in progress */
#define IEEE80211_NODE_SA_QUERY_FAILED 0x1000    /* last SA Query failed */
};

RB_HEAD(ieee80211_tree, ieee80211_node);

/****************************************************************************
 * Global Data
 ****************************************************************************/

extern struct ieee80211com;
extern sq_queue_t g_ieee80211_freelist;

#ifdef MALLOC_DECLARE
MALLOC_DECLARE(M_80211_NODE);
#endif

/****************************************************************************
 * Inline Functions
 ****************************************************************************/

static __inline void ieee80211_ifpurge(sq_queue_t *q)
{
  /* If the free list is empty, then just move the entry queue to the the
   * free list.  Otherwise, append the list to the end of the freelist.
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

static __inline void ieee80211_node_incref(struct ieee80211_node *ni)
{
  int s;

  s = splnet();
  ni->ni_refcnt++;
  splx(s);
}

static __inline unsigned int ieee80211_node_decref(struct ieee80211_node *ni)
{
  unsigned int refcnt;
  int s;

  s = splnet();
  refcnt = --ni->ni_refcnt;
  splx(s);
  return refcnt;
}

static __inline struct ieee80211_node *ieee80211_ref_node(struct ieee80211_node *ni)
{
  ieee80211_node_incref(ni);
  return ni;
}

static __inline void ieee80211_unref_node(struct ieee80211_node **ni)
{
  ieee80211_node_decref(*ni);
  *ni = NULL;            /* guard against use */
}

void ieee80211_node_attach(struct ifnet *);
void ieee80211_node_lateattach(struct ifnet *);
void ieee80211_node_detach(struct ifnet *);

void ieee80211_begin_scan(struct ifnet *);
void ieee80211_next_scan(struct ifnet *);
void ieee80211_end_scan(struct ifnet *);
void ieee80211_reset_scan(struct ifnet *);
struct ieee80211_node *ieee80211_alloc_node(struct ieee80211com *,
        const uint8_t *);
struct ieee80211_node *ieee80211_dup_bss(struct ieee80211com *,
        const uint8_t *);
struct ieee80211_node *ieee80211_find_node(struct ieee80211com *,
        const uint8_t *);
struct ieee80211_node *ieee80211_find_rxnode(struct ieee80211com *,
        const struct ieee80211_frame *);
struct ieee80211_node *ieee80211_find_txnode(struct ieee80211com *,
        const uint8_t *);
struct ieee80211_node *
        ieee80211_find_node_for_beacon(struct ieee80211com *,
        const uint8_t *, const struct ieee80211_channel *,
        const char *, uint8_t);
void ieee80211_release_node(struct ieee80211com *,
        struct ieee80211_node *);
void ieee80211_free_allnodes(struct ieee80211com *);
typedef void ieee80211_iter_func(void *, struct ieee80211_node *);
void ieee80211_iterate_nodes(struct ieee80211com *ic,
        ieee80211_iter_func *, void *);
void ieee80211_clean_nodes(struct ieee80211com *, int);
int ieee80211_setup_rates(struct ieee80211com *,
        struct ieee80211_node *, const uint8_t *, const uint8_t *, int);
extern  int ieee80211_iserp_sta(const struct ieee80211_node *);

void ieee80211_node_join(struct ieee80211com *,
        struct ieee80211_node *, int);
void ieee80211_node_leave(struct ieee80211com *,
        struct ieee80211_node *);
int ieee80211_match_bss(struct ieee80211com *,
        struct ieee80211_node *);
void ieee80211_create_ibss(struct ieee80211com* ,
        struct ieee80211_channel *);
void ieee80211_notify_dtim(struct ieee80211com *);
void ieee80211_set_tim(struct ieee80211com *, int, int);

int ieee80211_node_cmp(const struct ieee80211_node *,
        const struct ieee80211_node *);
RB_PROTOTYPE(ieee80211_tree, ieee80211_node, ni_node, ieee80211_node_cmp);

#endif /* _INCLUDE_NUTTX_NET_IEEE80211_IEEE80211_NODE_H */
