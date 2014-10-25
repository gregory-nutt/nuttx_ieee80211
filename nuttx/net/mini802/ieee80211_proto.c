/****************************************************************************
 * net/mini802/ieee80211_proto.c
 * IEEE 802.11 protocol support.
 *
 * Copyright (c) 2001 Atsushi Onoe
 * Copyright (c) 2002, 2003 Sam Leffler, Errno Consulting
 * Copyright (c) 2008, 2009 Damien Bergamini
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
#include <errno.h>
#include <assert.h>
#include <debug.h>

#include <net/if.h>

#ifdef CONFIG_NET_ETHERNET
#  include <netinet/in.h>
#  include <nuttx/net/uip/uip.h>
#endif

#include <nuttx/tree.h>
#include <nuttx/kmalloc.h>
#include <nuttx/net/iob.h>

#include "mini802/ieee80211_debug.h"
#include "mini802/ieee80211_var.h"
#include "mini802/ieee80211_priv.h"

const char *const ieee80211_mgt_subtype_name[] = {
  "assoc_req", "assoc_resp", "reassoc_req", "reassoc_resp",
  "probe_req", "probe_resp", "reserved#6", "reserved#7",
  "beacon", "atim", "disassoc", "auth",
  "deauth", "action", "action_noack", "reserved#15"
};

const char *const ieee80211_state_name[IEEE80211_S_MAX] = {
  "INIT",                       /* IEEE80211_S_INIT */
  "SCAN",                       /* IEEE80211_S_SCAN */
  "AUTH",                       /* IEEE80211_S_AUTH */
  "ASSOC",                      /* IEEE80211_S_ASSOC */
  "RUN"                         /* IEEE80211_S_RUN */
};

const char *const ieee80211_phymode_name[] = {
  "auto",                       /* IEEE80211_MODE_AUTO */
  "11a",                        /* IEEE80211_MODE_11A */
  "11b",                        /* IEEE80211_MODE_11B */
  "11g",                        /* IEEE80211_MODE_11G */
  "turbo",                      /* IEEE80211_MODE_TURBO */
};

static int ieee80211_newstate(struct ieee80211_s *, enum ieee80211_state, int);

void ieee80211_proto_attach(struct ieee80211_s *ic)
{
#ifdef notdef
  ic->ic_rtsthreshold = IEEE80211_RTS_DEFAULT;
#else
  ic->ic_rtsthreshold = IEEE80211_RTS_MAX;
#endif
  ic->ic_fragthreshold = 2346;  /* XXX not used yet */
  ic->ic_fixed_rate = -1;       /* no fixed rate */
  ic->ic_protmode = IEEE80211_PROT_CTSONLY;

  /* protocol state change handler */

  ic->ic_newstate = ieee80211_newstate;

  /* initialize management frame handlers */

  ic->ic_recv_mgmt = ieee80211_recv_mgmt;
  ic->ic_send_mgmt = ieee80211_send_mgmt;
}

void ieee80211_proto_detach(struct ieee80211_s *ic)
{
  iob_free_queue(&ic->ic_mgtq);
  iob_free_queue(&ic->ic_pwrsaveq);
}

#if defined(CONFIG_DEBUG_NET) && defined(CONFIG_DEBUG_VERBOSE)
void ieee80211_print_essid(const uint8_t * essid, int len)
{
  int i;
  const uint8_t *p;

  if (len > IEEE80211_NWID_LEN)
    {
      len = IEEE80211_NWID_LEN;
    }

  /* determine printable or not */

  for (i = 0, p = essid; i < len; i++, p++)
    {
      if (*p < ' ' || *p > 0x7e)
        {
          break;
        }
    }

  if (i == len)
    {
      nvdbg("\"");
      for (i = 0, p = essid; i < len; i++, p++)
        {
          nvdbg("%c", *p);
        }

      nvdbg("\"");
    }
  else
    {
      nvdbg("0x");
      for (i = 0, p = essid; i < len; i++, p++)
        {
          nvdbg("%02x", *p);
        }
    }
}
#endif

#if defined(CONFIG_DEBUG_NET) && defined(CONFIG_DEBUG_VERBOSE)
void ieee80211_dump_pkt(const uint8_t * buf, int len, int rate, int rssi)
{
  struct ieee80211_frame *wh;
  int i;

  wh = (struct ieee80211_frame *)buf;
  switch (wh->i_fc[1] & IEEE80211_FC1_DIR_MASK)
    {
    case IEEE80211_FC1_DIR_NODS:
      nvdbg("NODS %s", ieee80211_addr2str(wh->i_addr2));
      nvdbg("->%s", ieee80211_addr2str(wh->i_addr1));
      nvdbg("(%s)", ieee80211_addr2str(wh->i_addr3));
      break;
    case IEEE80211_FC1_DIR_TODS:
      nvdbg("TODS %s", ieee80211_addr2str(wh->i_addr2));
      nvdbg("->%s", ieee80211_addr2str(wh->i_addr3));
      nvdbg("(%s)", ieee80211_addr2str(wh->i_addr1));
      break;
    case IEEE80211_FC1_DIR_FROMDS:
      nvdbg("FRDS %s", ieee80211_addr2str(wh->i_addr3));
      nvdbg("->%s", ieee80211_addr2str(wh->i_addr1));
      nvdbg("(%s)", ieee80211_addr2str(wh->i_addr2));
      break;
    case IEEE80211_FC1_DIR_DSTODS:
      nvdbg("DSDS %s", ieee80211_addr2str((uint8_t *) & wh[1]));
      nvdbg("->%s", ieee80211_addr2str(wh->i_addr3));
      nvdbg("(%s", ieee80211_addr2str(wh->i_addr2));
      nvdbg("->%s)", ieee80211_addr2str(wh->i_addr1));
      break;
    }
  switch (wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK)
    {
    case IEEE80211_FC0_TYPE_DATA:
      nvdbg(" data");
      break;
    case IEEE80211_FC0_TYPE_MGT:
      nvdbg(" %s", ieee80211_mgt_subtype_name[(wh->
                                               i_fc[0] &
                                               IEEE80211_FC0_SUBTYPE_MASK) >>
                                              IEEE80211_FC0_SUBTYPE_SHIFT]);
      break;
    default:
      nvdbg(" type#%d", wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK);
      break;
    }

  if (wh->i_fc[1] & IEEE80211_FC1_WEP)
    {
      nvdbg(" WEP");
    }

  if (rate >= 0)
    {
      nvdbg(" %d%sM", rate / 2, (rate & 1) ? ".5" : "");
    }

  if (rssi >= 0)
    {
      nvdbg(" +%d", rssi);
    }

  nvdbg("\n");
  if (len > 0)
    {
      for (i = 0; i < len; i++)
        {
          if ((i & 1) == 0)
            {
              nvdbg(" ");
            }

          nvdbg("%02x", buf[i]);
        }

      nvdbg("\n");
    }
}
#endif

int
ieee80211_fix_rate(struct ieee80211_s *ic, struct ieee80211_node *ni, int flags)
{
#define    RV(v)    ((v) & IEEE80211_RATE_VAL)
  int i, j, ignore, error;
  int okrate, badrate, fixedrate;
  const struct ieee80211_rateset *srs;
  struct ieee80211_rateset *nrs;
  uint8_t r;

  /* If the fixed rate check was requested but no fixed rate has been
   * defined then just remove the check.
   */

  if ((flags & IEEE80211_F_DOFRATE) && ic->ic_fixed_rate == -1)
    flags &= ~IEEE80211_F_DOFRATE;

  error = 0;
  okrate = badrate = fixedrate = 0;
  srs = &ic->ic_sup_rates[ieee80211_chan2mode(ic, ni->ni_chan)];
  nrs = &ni->ni_rates;
  for (i = 0; i < nrs->rs_nrates;)
    {
      ignore = 0;
      if (flags & IEEE80211_F_DOSORT)
        {
          /* Sort rates. */

          for (j = i + 1; j < nrs->rs_nrates; j++)
            {
              if (RV(nrs->rs_rates[i]) > RV(nrs->rs_rates[j]))
                {
                  r = nrs->rs_rates[i];
                  nrs->rs_rates[i] = nrs->rs_rates[j];
                  nrs->rs_rates[j] = r;
                }
            }
        }
      r = nrs->rs_rates[i] & IEEE80211_RATE_VAL;
      badrate = r;
      if (flags & IEEE80211_F_DOFRATE)
        {
          /* Check fixed rate is included. */

          if (r == RV(srs->rs_rates[ic->ic_fixed_rate]))
            fixedrate = r;
        }
      if (flags & IEEE80211_F_DONEGO)
        {
          /* Check against supported rates. */

          for (j = 0; j < srs->rs_nrates; j++)
            {
              if (r == RV(srs->rs_rates[j]))
                {
                  /* Overwrite with the supported rate
                   * value so any basic rate bit is set.
                   * This insures that response we send
                   * to stations have the necessary basic
                   * rate bit set.
                   */

                  nrs->rs_rates[i] = srs->rs_rates[j];
                  break;
                }
            }

          if (j == srs->rs_nrates)
            {
              ignore++;
            }
        }
      if (flags & IEEE80211_F_DODEL)
        {
          /* Delete unacceptable rates. */

          if (ignore)
            {
              nrs->rs_nrates--;
              for (j = i; j < nrs->rs_nrates; j++)
                nrs->rs_rates[j] = nrs->rs_rates[j + 1];
              nrs->rs_rates[j] = 0;
              continue;
            }
        }
      if (!ignore)
        okrate = nrs->rs_rates[i];
      i++;
    }
  if (okrate == 0 || error != 0 ||
      ((flags & IEEE80211_F_DOFRATE) && fixedrate == 0))
    return badrate | IEEE80211_RATE_BASIC;
  else
    return RV(okrate);
#undef RV
}

/* Reset 11g-related state. */

void ieee80211_reset_erp(struct ieee80211_s *ic)
{
  ic->ic_flags &= ~IEEE80211_F_USEPROT;
  ic->ic_nonerpsta = 0;
  ic->ic_longslotsta = 0;

  /* Enable short slot time iff:
   * - we're operating in 802.11a or
   * - we're operating in 802.11g and we're not in IBSS mode and
   *   the device supports short slot time
   */

  ieee80211_set_shortslottime(ic, ic->ic_curmode == IEEE80211_MODE_11A);

  if (ic->ic_curmode == IEEE80211_MODE_11A ||
      (ic->ic_caps & IEEE80211_C_SHPREAMBLE))
    ic->ic_flags |= IEEE80211_F_SHPREAMBLE;
  else
    ic->ic_flags &= ~IEEE80211_F_SHPREAMBLE;
}

/* Set the short slot time state and notify the driver. */

void ieee80211_set_shortslottime(struct ieee80211_s *ic, int on)
{
  if (on)
    ic->ic_flags |= IEEE80211_F_SHSLOT;
  else
    ic->ic_flags &= ~IEEE80211_F_SHSLOT;

  /* notify the driver */
  if (ic->ic_updateslot != NULL)
    ic->ic_updateslot(ic);
}

/* This function is called by the 802.1X PACP machine (via an ioctl) when
 * the transmit key machine (4-Way Handshake for 802.11) should run.
 */

int ieee80211_keyrun(struct ieee80211_s *ic, uint8_t * macaddr)
{
  /* STA must be associated or AP must be ready */

  if (ic->ic_state != IEEE80211_S_RUN || !(ic->ic_flags & IEEE80211_F_RSNON))
    return -ENETDOWN;

  return 0;                   /* supplicant only, do nothing */
}

void ieee80211_auth_open(struct ieee80211_s *ic,
                         const struct ieee80211_frame *wh,
                         struct ieee80211_node *ni,
                         struct ieee80211_rxinfo *rxi, uint16_t seq,
                         uint16_t status)
{
  switch (ic->ic_opmode)
    {
    case IEEE80211_M_STA:
      if (ic->ic_state != IEEE80211_S_AUTH ||
          seq != IEEE80211_AUTH_OPEN_RESPONSE)
        {
          nvdbg("discard auth from %s; state %u, seq %u\n",
                ieee80211_addr2str((uint8_t *) wh->i_addr2), ic->ic_state, seq);
          return;
        }
      if (ic->ic_flags & IEEE80211_F_RSNON)
        {
          /* XXX not here! */

          ic->ic_bss->ni_flags &= ~IEEE80211_NODE_TXRXPROT;
          ic->ic_bss->ni_port_valid = 0;
          ic->ic_bss->ni_replaycnt_ok = 0;
          (*ic->ic_delete_key) (ic, ic->ic_bss, &ic->ic_bss->ni_pairwise_key);
        }

      if (status != 0)
        {
          nvdbg("%s: open authentication failed (reason %d) for %s\n",
                ic->ic_ifname, status,
                ieee80211_addr2str((uint8_t *) wh->i_addr3));

          if (ni != ic->ic_bss)
            {
              ni->ni_fails++;
            }

          return;
        }

      ieee80211_new_state(ic, IEEE80211_S_ASSOC,
                          wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK);
      break;

    case IEEE80211_M_IBSS:   /* AP only */
    case IEEE80211_M_AHDEMO: /* AP only */
    case IEEE80211_M_HOSTAP: /* AP only */
    default:
      break;
    }
}

static int ieee80211_newstate(struct ieee80211_s *ic,
                              enum ieee80211_state nstate, int mgt)
{
  struct ieee80211_node *ni;
  enum ieee80211_state ostate;
  unsigned int rate;
#endif

  ostate = ic->ic_state;
  nvdbg("%s -> %s\n", ieee80211_state_name[ostate],
        ieee80211_state_name[nstate]);
  ic->ic_state = nstate;        /* state transition */
  ni = ic->ic_bss;              /* NB: no reference held */
  if (ostate == IEEE80211_S_RUN)
    {
      ieee80211_set_link_state(ic, LINKSTATE_DOWN);
    }

  switch (nstate)
    {
    case IEEE80211_S_INIT:
      /* If mgt = -1, driver is already partway down, so do
       * not send management frames.
       */

      switch (ostate)
        {
        case IEEE80211_S_INIT:
          break;
        case IEEE80211_S_RUN:
          if (mgt == -1)
            goto justcleanup;
          switch (ic->ic_opmode)
            {
            case IEEE80211_M_STA:
              IEEE80211_SEND_MGMT(ic, ni,
                                  IEEE80211_FC0_SUBTYPE_DISASSOC,
                                  IEEE80211_REASON_ASSOC_LEAVE);
              break;

            case IEEE80211_M_HOSTAP: /* AP only */
            default:
              break;
            }

          /* FALLTHROUGH */

        case IEEE80211_S_ASSOC:
          if (mgt == -1)
            goto justcleanup;
          switch (ic->ic_opmode)
            {
            case IEEE80211_M_STA:
              IEEE80211_SEND_MGMT(ic, ni,
                                  IEEE80211_FC0_SUBTYPE_DEAUTH,
                                  IEEE80211_REASON_AUTH_LEAVE);
              break;

            case IEEE80211_M_HOSTAP: /* AP only */
            default:
              break;
            }

          /* FALLTHROUGH */

        case IEEE80211_S_AUTH:
        case IEEE80211_S_SCAN:
        justcleanup:
          ic->ic_mgt_timer = 0;
          iob_free_queue(&ic->ic_mgtq);
          iob_free_queue(&ic->ic_pwrsaveq);
          ieee80211_free_allnodes(ic);
          break;
        }
      break;
    case IEEE80211_S_SCAN:
      ic->ic_flags &= ~IEEE80211_F_SIBSS;

      /* initialize bss for probe request */

      IEEE80211_ADDR_COPY(ni->ni_macaddr, etherbroadcastaddr);
      IEEE80211_ADDR_COPY(ni->ni_bssid, etherbroadcastaddr);
      ni->ni_rates = ic->ic_sup_rates[ieee80211_chan2mode(ic, ni->ni_chan)];
      ni->ni_associd = 0;
      ni->ni_rstamp = 0;
      switch (ostate)
        {
        case IEEE80211_S_INIT:
          ieee80211_begin_scan(ic);
          break;

        case IEEE80211_S_SCAN:
          /* scan next */

          if (ic->ic_flags & IEEE80211_F_ASCAN)
            {
              IEEE80211_SEND_MGMT(ic, ni, IEEE80211_FC0_SUBTYPE_PROBE_REQ, 0);
            }
          break;

        case IEEE80211_S_RUN:
          /* beacon miss */

          nvdbg("%s: no recent beacons from %s; rescanning\n",
                ic->ic_ifname, ieee80211_addr2str(ic->ic_bss->ni_bssid));

          ieee80211_free_allnodes(ic);

          /* FALLTHROUGH */

        case IEEE80211_S_AUTH:
        case IEEE80211_S_ASSOC:
          /* timeout restart scan */

          ni = ieee80211_find_node(ic, ic->ic_bss->ni_macaddr);
          if (ni != NULL)
            ni->ni_fails++;
          ieee80211_begin_scan(ic);
          break;
        }
      break;
    case IEEE80211_S_AUTH:
      switch (ostate)
        {
        case IEEE80211_S_INIT:
          ndbg("ERROR: invalid transition\n");
          break;
        case IEEE80211_S_SCAN:
          IEEE80211_SEND_MGMT(ic, ni, IEEE80211_FC0_SUBTYPE_AUTH, 1);
          break;
        case IEEE80211_S_AUTH:
        case IEEE80211_S_ASSOC:
          switch (mgt)
            {
            case IEEE80211_FC0_SUBTYPE_AUTH:
              /* ??? */

              IEEE80211_SEND_MGMT(ic, ni, IEEE80211_FC0_SUBTYPE_AUTH, 2);
              break;
            case IEEE80211_FC0_SUBTYPE_DEAUTH:
              /* ignore and retry scan on timeout */

              break;
            }
          break;
        case IEEE80211_S_RUN:
          switch (mgt)
            {
            case IEEE80211_FC0_SUBTYPE_AUTH:
              IEEE80211_SEND_MGMT(ic, ni, IEEE80211_FC0_SUBTYPE_AUTH, 2);
              ic->ic_state = ostate;    /* stay RUN */
              break;
            case IEEE80211_FC0_SUBTYPE_DEAUTH:
              /* try to reauth */

              IEEE80211_SEND_MGMT(ic, ni, IEEE80211_FC0_SUBTYPE_AUTH, 1);
              break;
            }
          break;
        }
      break;
    case IEEE80211_S_ASSOC:
      switch (ostate)
        {
        case IEEE80211_S_INIT:
        case IEEE80211_S_SCAN:
        case IEEE80211_S_ASSOC:
          ndbg("ERROR: invalid transition\n");
          break;
        case IEEE80211_S_AUTH:
          IEEE80211_SEND_MGMT(ic, ni, IEEE80211_FC0_SUBTYPE_ASSOC_REQ, 0);
          break;
        case IEEE80211_S_RUN:
          IEEE80211_SEND_MGMT(ic, ni, IEEE80211_FC0_SUBTYPE_ASSOC_REQ, 1);
          break;
        }
      break;
    case IEEE80211_S_RUN:
      switch (ostate)
        {
        case IEEE80211_S_INIT:
        case IEEE80211_S_AUTH:
        case IEEE80211_S_RUN:
          ndbg("ERROR: invalid transition\n");
          break;

        case IEEE80211_S_SCAN: /* adhoc/hostap mode */
        case IEEE80211_S_ASSOC:        /* infra mode */
          DEBUGASSERT(ni->ni_txrate < ni->ni_rates.rs_nrates);

#if defined(CONFIG_DEBUG_NET) && defined(CONFIG_DEBUG_VERBOSE)
          nvdbg("%s: %s with %s ssid ",
                ic->ic_ifname,
                ic->ic_opmode ==
                IEEE80211_M_STA ? "associated" : "synchronized",
                ieee80211_addr2str(ni->ni_bssid));

          ieee80211_print_essid(ic->ic_bss->ni_essid, ni->ni_esslen);
          rate = ni->ni_rates.rs_rates[ni->ni_txrate] & IEEE80211_RATE_VAL;

          nvdbg(" channel %d start %u%sMb",
                ieee80211_chan2ieee(ic, ni->ni_chan),
                rate / 2, (rate & 1) ? ".5" : "");
          nvdbg(" %s preamble %s slot time%s\n",
                (ic->ic_flags & IEEE80211_F_SHPREAMBLE) ? "short" : "long",
                (ic->ic_flags & IEEE80211_F_SHSLOT) ? "short" : "long",
                (ic->
                 ic_flags & IEEE80211_F_USEPROT) ? " protection enabled" : "");
#endif

          if (!(ic->ic_flags & IEEE80211_F_RSNON))
            {
              /* NB: When RSN is enabled, we defer setting the link up until
               * the port is valid.
               */

              ieee80211_set_link_state(ic, LINKSTATE_UP);
            }

          ic->ic_mgt_timer = 0;
          break;
        }
      break;
    }
  return 0;
}

void ieee80211_set_link_state(struct ieee80211_s *ic,
                              enum ieee80211_linkstate_e linkstate)
{
  switch (ic->ic_opmode)
    {
    case IEEE80211_M_MONITOR:
      linkstate = LINKSTATE_DOWN;
      break;

    case IEEE80211_M_IBSS:   /* AP only */
    case IEEE80211_M_HOSTAP: /* AP only */
    default:
      break;
    }

  ic->ic_linkstate = linkstate;
}
