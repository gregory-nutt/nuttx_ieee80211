/****************************************************************************
 * include/nuttx/net/ieee80211/ieee80211_proto.h
 *
 * 802.11 protocol implementation definitions.
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

#ifndef _NET80211_IEEE80211_PROTO_H_
#define _NET80211_IEEE80211_PROTO_H_

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <nuttx/config.h>
#include <nuttx/net/ieee80211/ieee80211_ifnet.h>

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

/****************************************************************************
 * Public Types
 ****************************************************************************/

enum ieee80211_state
{
  IEEE80211_S_INIT    = 0,             /* default state */
  IEEE80211_S_SCAN    = 1,             /* scanning */
  IEEE80211_S_AUTH    = 2,             /* try to authenticate */
  IEEE80211_S_ASSOC   = 3,             /* try to assoc */
  IEEE80211_S_RUN     = 4              /* associated */
};

#define    IEEE80211_S_MAX        (IEEE80211_S_RUN+1)

#define    IEEE80211_SEND_MGMT(_ic,_ni,_type,_arg) \
    ((*(_ic)->ic_send_mgmt)(_ic, _ni, _type, _arg, 0))
/* shortcut */
#define IEEE80211_SEND_ACTION(_ic,_ni,_categ,_action,_arg) \
    ((*(_ic)->ic_send_mgmt)(_ic, _ni, IEEE80211_FC0_SUBTYPE_ACTION, \
        (_categ) << 16 | (_action), _arg))

extern const char * const ieee80211_mgt_subtype_name[];
extern const char * const ieee80211_state_name[IEEE80211_S_MAX];
extern const char * const ieee80211_phymode_name[];

void ieee80211_proto_attach(struct ifnet *);
void ieee80211_proto_detach(struct ifnet *);

struct ieee80211_node;
struct ieee80211_rxinfo;
struct ieee80211_rsnparams;
void ieee80211_set_link_state(struct ieee80211com *ic, enum ieee80211_linkstate_e linkstate);
unsigned int ieee80211_get_hdrlen(const struct ieee80211_frame *);
void ieee80211_input(struct ifnet *, struct ieee80211_iobuf_s *,
        struct ieee80211_node *, struct ieee80211_rxinfo *);
int ieee80211_output(struct ifnet *, struct ieee80211_iobuf_s *, struct sockaddr *,
        struct rtentry *);
void ieee80211_recv_mgmt(struct ieee80211com *, struct ieee80211_iobuf_s *,
        struct ieee80211_node *, struct ieee80211_rxinfo *, int);
int ieee80211_send_mgmt(struct ieee80211com *, struct ieee80211_node *,
        int, int, int);
void ieee80211_eapol_key_input(struct ieee80211com *, struct ieee80211_iobuf_s *,
        struct ieee80211_node *);
struct ieee80211_iobuf_s *ieee80211_encap(struct ifnet *, struct ieee80211_iobuf_s *,
        struct ieee80211_node **);
struct ieee80211_iobuf_s *ieee80211_get_rts(struct ieee80211com *,
        const struct ieee80211_frame *, uint16_t);
struct ieee80211_iobuf_s *ieee80211_get_cts_to_self(struct ieee80211com *,
        uint16_t);
struct ieee80211_iobuf_s *ieee80211_beacon_alloc(struct ieee80211com *,
        struct ieee80211_node *);
extern int ieee80211_save_ie(const uint8_t *, uint8_t **);
void ieee80211_eapol_timeout(void *);

int ieee80211_send_4way_msg1(struct ieee80211com *,
        struct ieee80211_node *);
int ieee80211_send_4way_msg2(struct ieee80211com *,
        struct ieee80211_node *, const uint8_t *,
        const struct ieee80211_ptk *);
int ieee80211_send_4way_msg3(struct ieee80211com *,
        struct ieee80211_node *);
int ieee80211_send_4way_msg4(struct ieee80211com *,
        struct ieee80211_node *);
int ieee80211_send_group_msg1(struct ieee80211com *,
        struct ieee80211_node *);
int ieee80211_send_group_msg2(struct ieee80211com *,
        struct ieee80211_node *, const struct ieee80211_key *);
int ieee80211_send_eapol_key_req(struct ieee80211com *,
        struct ieee80211_node *, uint16_t, uint64_t);
int ieee80211_pwrsave(struct ieee80211com *, struct ieee80211_iobuf_s *,
        struct ieee80211_node *);
#define    ieee80211_new_state(_ic, _nstate, _arg) \
    (((_ic)->ic_newstate)((_ic), (_nstate), (_arg)))
enum ieee80211_edca_ac ieee80211_up_to_ac(struct ieee80211com *, int);
uint8_t *ieee80211_add_capinfo(uint8_t *, struct ieee80211com *,
        const struct ieee80211_node *);
uint8_t *ieee80211_add_ssid(uint8_t *, const uint8_t *, unsigned int);
uint8_t *ieee80211_add_rates(uint8_t *,
        const struct ieee80211_rateset *);
uint8_t *ieee80211_add_fh_params(uint8_t *, struct ieee80211com *,
        const struct ieee80211_node *);
uint8_t *ieee80211_add_ds_params(uint8_t *, struct ieee80211com *,
        const struct ieee80211_node *);
uint8_t *ieee80211_add_tim(uint8_t *, struct ieee80211com *);
uint8_t *ieee80211_add_ibss_params(uint8_t *,
        const struct ieee80211_node *);
uint8_t *ieee80211_add_edca_params(uint8_t *, struct ieee80211com *);
uint8_t *ieee80211_add_erp(uint8_t *, struct ieee80211com *);
uint8_t *ieee80211_add_qos_capability(uint8_t *,
        struct ieee80211com *);
uint8_t *ieee80211_add_rsn(uint8_t *, struct ieee80211com *,
        const struct ieee80211_node *);
uint8_t *ieee80211_add_wpa(uint8_t *, struct ieee80211com *,
        const struct ieee80211_node *);
uint8_t *ieee80211_add_xrates(uint8_t *,
        const struct ieee80211_rateset *);
uint8_t *ieee80211_add_htcaps(uint8_t *, struct ieee80211com *);
uint8_t *ieee80211_add_htop(uint8_t *, struct ieee80211com *);
uint8_t *ieee80211_add_tie(uint8_t *, uint8_t, uint32_t);

int ieee80211_parse_rsn(struct ieee80211com *, const uint8_t *,
        struct ieee80211_rsnparams *);
int ieee80211_parse_wpa(struct ieee80211com *, const uint8_t *,
        struct ieee80211_rsnparams *);
#if defined(CONFIG_DEBUG_NET) && defined(CONFIG_DEBUG_VERBOSE)
void ieee80211_print_essid(const uint8_t *, int);
void ieee80211_dump_pkt(const uint8_t *, int, int, int);
#endif
int ieee80211_ibss_merge(struct ieee80211com *,
        struct ieee80211_node *, uint64_t);
void ieee80211_reset_erp(struct ieee80211com *);
void ieee80211_set_shortslottime(struct ieee80211com *, int);
void ieee80211_auth_open(struct ieee80211com *,
        const struct ieee80211_frame *, struct ieee80211_node *,
        struct ieee80211_rxinfo *rs, uint16_t, uint16_t);
void ieee80211_gtk_rekey_timeout(void *);
int ieee80211_keyrun(struct ieee80211com *, uint8_t *);
void ieee80211_setkeys(struct ieee80211com *);
void ieee80211_setkeysdone(struct ieee80211com *);
void ieee80211_sa_query_timeout(void *);
void ieee80211_sa_query_request(struct ieee80211com *,
        struct ieee80211_node *);

#ifdef CONFIG_IEEE80211_HT
void ieee80211_tx_ba_timeout(void *);
void ieee80211_rx_ba_timeout(void *);
int ieee80211_addba_request(struct ieee80211com *,
        struct ieee80211_node *,  uint16_t, uint8_t);
void ieee80211_delba_request(struct ieee80211com *,
        struct ieee80211_node *, uint16_t, uint8_t, uint8_t);
#endif

#endif /* _NET80211_IEEE80211_PROTO_H_ */
