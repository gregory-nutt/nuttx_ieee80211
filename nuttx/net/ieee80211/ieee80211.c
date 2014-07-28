/****************************************************************************
 * net/ieee80211/i33380211.c
 * IEEE 802.11 generic handler
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

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <nuttx/config.h>

#include <sys/socket.h>
#include <sys/sockio.h>

#include <string.h>
#include <queue.h>
#include <errno.h>
#include <assert.h>
#include <debug.h>

#include <net/if.h>

#ifdef CONFIG_NET_ETHERNET
#  include <netinet/in.h>
#  include <nuttx/net/uip/uip.h>
#endif

#include <nuttx/kmalloc.h>
#include <nuttx/net/iob.h>

#include "ieee80211/ieee80211_ifnet.h"
#include "ieee80211/ieee80211_var.h"
#include "ieee80211/ieee80211_priv.h"

int ieee80211_cache_size = IEEE80211_CACHE_SIZE;

dq_queue_t ieee80211_s_head;

void ieee80211_setbasicrates(FAR struct ieee80211_s *);
int ieee80211_findrate(FAR struct ieee80211_s *, enum ieee80211_phymode, int);

/****************************************************************************
 * Name: ieee80211_initialize
 *
 * Description:
 *   Initialize the IEEE 802.11 stack for operation with the selected device.
 *
 ****************************************************************************/

iee80211_handle ieee80211_initialize(FAR const char *ifname)
{
  FAR struct ieee80211_s *ic;
  FAR struct ieee80211_channel *chan;
  int ndx;
  int bit;
  int i;

  /* Allocate the IEEE 802.11 stack state structure */

  ic = (FAR struct ieee80211_s *)kzalloc(sizeof(struct ieee80211_s));
  if (ic == NULL)
    {
      ndbg("ERROR:  Failed to allocate state structure\n");
      return NULL;
    }

  /* Save the device name in the state structure */

  strncpy(ic->ic_ifname, ifname, IFNAMSIZ);

  /* Set up the devices interface I/O buffers for normal operations */

  ieee80211_ifinit(ic);

  /* Initialize cypto support */

  ieee80211_crypto_attach(ic);

  /* Fill in 802.11 available channel set, mark all available channels as
   * active, and pick a default channel if not already specified. */

  memset(ic->ic_chan_avail, 0, sizeof(ic->ic_chan_avail));
  ic->ic_modecaps |= 1 << IEEE80211_MODE_AUTO;
  for (i = 0; i <= IEEE80211_CHAN_MAX; i++)
    {
      chan = &ic->ic_channels[i];
      if (chan->ic_flags)
        {
          /* Verify driver passed us valid data */

          if (i != ieee80211_chan2ieee(ic, chan))
            {
              nvdbg
                ("ERROR %s: bad channel ignored; freq %u flags %x number %u\n",
                 ic->ic_ifname, chan->ic_freq, chan->ic_flags, i);

              chan->ic_flags = 0;       /* NB: remove */
              continue;
            }

          ndx = (i >> 3);
          bit = (i & 7);
          ic->ic_chan_avail[ndx] |= (1 << bit);

          /* Identify mode capabilities */

          if (IEEE80211_IS_CHAN_A(chan))
            {
              ic->ic_modecaps |= 1 << IEEE80211_MODE_11A;
            }

          if (IEEE80211_IS_CHAN_B(chan))
            {
              ic->ic_modecaps |= 1 << IEEE80211_MODE_11B;
            }

          if (IEEE80211_IS_CHAN_PUREG(chan))
            {
              ic->ic_modecaps |= 1 << IEEE80211_MODE_11G;
            }

          if (IEEE80211_IS_CHAN_T(chan))
            {
              ic->ic_modecaps |= 1 << IEEE80211_MODE_TURBO;
            }
        }
    }

  /* validate ic->ic_curmode */

  if ((ic->ic_modecaps & (1 << ic->ic_curmode)) == 0)
    {
      ic->ic_curmode = IEEE80211_MODE_AUTO;
    }

  ic->ic_des_chan = IEEE80211_CHAN_ANYC;        /* any channel is ok */
  ic->ic_scan_lock = IEEE80211_SCAN_UNLOCKED;

  /* IEEE 802.11 defines a MTU >= 2290 */

  ieee80211_setbasicrates(ic);
  (void)ieee80211_setmode(ic, ic->ic_curmode);

  if (ic->ic_lintval == 0)
    {
      ic->ic_lintval = 100;     /* default sleep */
    }

  ic->ic_bmisstimeout = 7 * ic->ic_lintval;     /* default 7 beacons */
  ic->ic_dtim_period = 1;       /* all TIMs are DTIMs */

  dq_addfirst((FAR dq_entry_t *) ic, &ieee80211_s_head);
  ieee80211_node_attach(ic);
  ieee80211_proto_attach(ic);

  return (iee80211_handle) ic;
}

/****************************************************************************
 * Name: ieee80211_uninitialize
 *
 * Description:
 *   Initialize the IEEE 802.11 stack for operation with the selected device.
 *
 ****************************************************************************/

void ieee80211_uninitialize(iee80211_handle handle)
{
  FAR struct ieee80211_s *ic = (FAR struct ieee80211_s *)handle;

  ieee80211_proto_detach(ic);
  ieee80211_crypto_detach(ic);
  ieee80211_node_detach(ic);
  // ifmedia_delete_instance(&ic->ic_media, IFM_INST_ANY);

  /* Final, free the memory allocation for the IEEE 802.11 stack state
   * structure */

  kfree(ic);
}

/* Convert MHz frequency to IEEE channel number */

unsigned int ieee80211_mhz2ieee(unsigned int freq, unsigned int flags)
{
  if (flags & IEEE80211_CHAN_2GHZ)
    {
      /* 2GHz band */

      if (freq == 2484)
        {
          return 14;
        }

      if (freq < 2484)
        {
          return (freq - 2407) / 5;
        }

      else
        {
          return 15 + ((freq - 2512) / 20);
        }
    }
  else if (flags & IEEE80211_CHAN_5GHZ)
    {
      /* 5GHz band */

      return (freq - 5000) / 5;
    }
  else
    {
      /* either, guess */

      if (freq == 2484)
        {
          return 14;
        }

      if (freq < 2484)
        {
          return (freq - 2407) / 5;
        }

      if (freq < 5000)
        {
          return 15 + ((freq - 2512) / 20);
        }

      return (freq - 5000) / 5;
    }
}

/* Convert channel to IEEE channel number */

unsigned int ieee80211_chan2ieee(struct ieee80211_s *ic,
                                 const struct ieee80211_channel *chan)
{
  if (ic->ic_channels <= chan && chan <= &ic->ic_channels[IEEE80211_CHAN_MAX])
    {
      return chan - ic->ic_channels;
    }
  else if (chan == IEEE80211_CHAN_ANYC)
    {
      return IEEE80211_CHAN_ANY;
    }
  else if (chan != NULL)
    {
      ndbg("ERROR: %s: invalid channel freq %u flags %x\n",
           ic->ic_ifname, chan->ic_freq, chan->ic_flags);
      return 0;
    }
  else
    {
      ndbg("ERROR: %s: invalid channel (NULL)\n", ic->ic_ifname);
      return 0;
    }
}

/* Convert IEEE channel number to MHz frequency */

unsigned int ieee80211_ieee2mhz(unsigned int chno, unsigned int flags)
{
  if (flags & IEEE80211_CHAN_2GHZ)
    {                           /* 2GHz band */
      if (chno == 14)
        return 2484;
      if (chno < 14)
        return 2407 + chno * 5;
      else
        return 2512 + ((chno - 15) * 20);
    }
  else if (flags & IEEE80211_CHAN_5GHZ)
    {                           /* 5GHz band */
      return 5000 + (chno * 5);
    }
  else
    {                           /* either, guess */
      if (chno == 14)
        return 2484;
      if (chno < 14)            /* 0-13 */
        return 2407 + chno * 5;
      if (chno < 27)            /* 15-26 */
        return 2512 + ((chno - 15) * 20);
      return 5000 + (chno * 5);
    }
}

void ieee80211_watchdog(struct ieee80211_s *ic)
{
  if (ic->ic_mgt_timer && --ic->ic_mgt_timer == 0)
    {
      ieee80211_new_state(ic, IEEE80211_S_SCAN, -1);
    }
}

const struct ieee80211_rateset ieee80211_std_rateset_11a =
  { 8, {12, 18, 24, 36, 48, 72, 96, 108} };

const struct ieee80211_rateset ieee80211_std_rateset_11b =
  { 4, {2, 4, 11, 22} };

const struct ieee80211_rateset ieee80211_std_rateset_11g =
  { 12, {2, 4, 11, 22, 12, 18, 24, 36, 48, 72, 96, 108} };

/* Mark the basic rates for the 11g rate table based on the
 * operating mode.  For real 11g we mark all the 11b rates
 * and 6, 12, and 24 OFDM.  For 11b compatibility we mark only
 * 11b rates.  There's also a pseudo 11a-mode used to mark only
 * the basic OFDM rates.
 */

void ieee80211_setbasicrates(struct ieee80211_s *ic)
{
  static const struct ieee80211_rateset basic[] = {
    {0},                        /* IEEE80211_MODE_AUTO */
    {3, {12, 24, 48}},          /* IEEE80211_MODE_11A */
    {2, {2, 4}},                /* IEEE80211_MODE_11B */
    {4, {2, 4, 11, 22}},        /* IEEE80211_MODE_11G */
    {0},                        /* IEEE80211_MODE_TURBO */
  };
  enum ieee80211_phymode mode;
  struct ieee80211_rateset *rs;
  int i, j;

  for (mode = 0; mode < IEEE80211_MODE_MAX; mode++)
    {
      rs = &ic->ic_sup_rates[mode];
      for (i = 0; i < rs->rs_nrates; i++)
        {
          rs->rs_rates[i] &= IEEE80211_RATE_VAL;
          for (j = 0; j < basic[mode].rs_nrates; j++)
            {
              if (basic[mode].rs_rates[j] == rs->rs_rates[i])
                {
                  rs->rs_rates[i] |= IEEE80211_RATE_BASIC;
                  break;
                }
            }
        }
    }
}

/* Set the current phy mode and recalculate the active channel
 * set based on the available channels for this mode.  Also
 * select a new default/current channel if the current one is
 * inappropriate for this mode.
 */

int ieee80211_setmode(struct ieee80211_s *ic, enum ieee80211_phymode mode)
{
#define    N(a)    (sizeof(a) / sizeof(a[0]))
  static const unsigned int chanflags[] = {
    0,                          /* IEEE80211_MODE_AUTO */
    IEEE80211_CHAN_A,           /* IEEE80211_MODE_11A */
    IEEE80211_CHAN_B,           /* IEEE80211_MODE_11B */
    IEEE80211_CHAN_PUREG,       /* IEEE80211_MODE_11G */
    IEEE80211_CHAN_T,           /* IEEE80211_MODE_TURBO */
  };
  const struct ieee80211_channel *chan;
  unsigned int modeflags;
  int ibss;
  int ndx;
  int bit;
  int i;

  /* validate new mode */
  if ((ic->ic_modecaps & (1 << mode)) == 0)
    {
      ndbg("ERROR: mode %u not supported (caps 0x%x)\n", mode, ic->ic_modecaps);
      return -EINVAL;
    }

  /* Verify at least one channel is present in the available channel list
   * before committing to the new mode. */

  DEBUGASSERT(mode < N(chanflags));

  modeflags = chanflags[mode];
  for (i = 0; i <= IEEE80211_CHAN_MAX; i++)
    {
      chan = &ic->ic_channels[i];
      if (mode == IEEE80211_MODE_AUTO)
        {
          /* ignore turbo channels for autoselect */
          if ((chan->ic_flags & ~IEEE80211_CHAN_TURBO) != 0)
            break;
        }
      else
        {
          if ((chan->ic_flags & modeflags) == modeflags)
            break;
        }
    }
  if (i > IEEE80211_CHAN_MAX)
    {
      ndbg("ERROR: no channels found for mode %u\n", mode);
      return -EINVAL;
    }

  /* Calculate the active channel set */

  memset(ic->ic_chan_active, 0, sizeof(ic->ic_chan_active));
  for (i = 0; i <= IEEE80211_CHAN_MAX; i++)
    {
      chan = &ic->ic_channels[i];
      ndx = (i >> 3);
      bit = (i & 7);

      if (mode == IEEE80211_MODE_AUTO)
        {
          /* Take anything but pure turbo channels */

          if ((chan->ic_flags & ~IEEE80211_CHAN_TURBO) != 0)
            {
              ic->ic_chan_active[ndx] |= (1 << bit);
            }
        }
      else if ((chan->ic_flags & modeflags) == modeflags)
        {
          ic->ic_chan_active[ndx] |= (1 << bit);
        }
    }

  /* If no current/default channel is setup or the current channel is wrong for 
   * the mode then pick the first available channel from the active list.  This 
   * is likely not the right one. */

  ibss = ieee80211_chan2ieee(ic, ic->ic_ibss_chan);
  ndx = (ibss >> 3);
  bit = (ibss & 7);

  if (ic->ic_ibss_chan == NULL || (ic->ic_chan_active[ndx] & (1 << bit)) == 0)
    {
      for (i = 0; i <= IEEE80211_CHAN_MAX; i++)
        {
          ndx = (i >> 3);
          bit = (i & 7);

          if ((ic->ic_chan_active[ndx] & (1 << i)) != 0)
            {
              ic->ic_ibss_chan = &ic->ic_channels[i];
              break;
            }
        }

      ibss = ieee80211_chan2ieee(ic, ic->ic_ibss_chan);
      ndx = (ibss >> 3);
      bit = (ibss & 7);

      if ((ic->ic_ibss_chan == NULL) ||
          (ic->ic_chan_active[ndx] & (1 << bit)) == 0)
        {
          ndbg("ERROR: Bad IBSS channel %u", ibss);
          PANIC();
        }
    }

  /* Reset the scan state for the new mode. This avoids scanning of invalid
   * channels, ie. 5GHz channels in 11b mode. */

  ieee80211_reset_scan(ic);

  ic->ic_curmode = mode;
  ieee80211_reset_erp(ic);      /* reset ERP state */

  return 0;
#undef N
}

enum ieee80211_phymode ieee80211_next_mode(struct ieee80211_s *ic)
{
  if (ic->ic_curmode != IEEE80211_MODE_AUTO)
    {
      /* 
       * Reset the scan state and indicate a wrap around
       * if we're running in a fixed, user-specified phy mode.
       */
      ieee80211_reset_scan(ic);
      return (IEEE80211_MODE_AUTO);
    }

  /* 
   * Get the next supported mode
   */
  for (++ic->ic_curmode;
       ic->ic_curmode <= IEEE80211_MODE_TURBO; ic->ic_curmode++)
    {
      /* Wrap around and ignore turbo mode */
      if (ic->ic_curmode >= IEEE80211_MODE_TURBO)
        {
          ic->ic_curmode = IEEE80211_MODE_AUTO;
          break;
        }

      if (ic->ic_modecaps & (1 << ic->ic_curmode))
        break;
    }

  ieee80211_setmode(ic, ic->ic_curmode);

  return (ic->ic_curmode);
}

/*
 * Return the phy mode for with the specified channel so the
 * caller can select a rate set.  This is problematic and the
 * work here assumes how things work elsewhere in this code.
 *
 * XXX never returns turbo modes -dcy
 */

enum ieee80211_phymode ieee80211_chan2mode(struct ieee80211_s *ic,
                                           const struct ieee80211_channel *chan)
{
  /* 
   * NB: this assumes the channel would not be supplied to us
   *     unless it was already compatible with the current mode.
   */
  if (ic->ic_curmode != IEEE80211_MODE_AUTO || chan == IEEE80211_CHAN_ANYC)
    return ic->ic_curmode;
  /* 
   * In autoselect mode; deduce a mode based on the channel
   * characteristics.  We assume that turbo-only channels
   * are not considered when the channel set is constructed.
   */
  if (IEEE80211_IS_CHAN_T(chan))
    return IEEE80211_MODE_TURBO;
  else if (IEEE80211_IS_CHAN_5GHZ(chan))
    return IEEE80211_MODE_11A;
  else if (chan->ic_flags & (IEEE80211_CHAN_OFDM | IEEE80211_CHAN_DYN))
    return IEEE80211_MODE_11G;
  else
    return IEEE80211_MODE_11B;
}

/* Convert bit rate (in 0.5Mbps units) to PLCP signal (R4-R1) and vice versa */

uint8_t ieee80211_rate2plcp(uint8_t rate, enum ieee80211_phymode mode)
{
  rate &= IEEE80211_RATE_VAL;

  if (mode == IEEE80211_MODE_11B)
    {
      /* IEEE Std 802.11b-1999 page 15, subclause 18.2.3.3 */

      switch (rate)
        {
        case 2:
          return 10;
        case 4:
          return 20;
        case 11:
          return 55;
        case 22:
          return 110;

          /* IEEE Std 802.11g-2003 page 19, subclause 19.3.2.1 */

        case 44:
          return 220;
        }
    }
  else if (mode == IEEE80211_MODE_11G || mode == IEEE80211_MODE_11A)
    {
      /* IEEE Std 802.11a-1999 page 14, subclause 17.3.4.1 */

      switch (rate)
        {
        case 12:
          return 0x0b;
        case 18:
          return 0x0f;
        case 24:
          return 0x0a;
        case 36:
          return 0x0e;
        case 48:
          return 0x09;
        case 72:
          return 0x0d;
        case 96:
          return 0x08;
        case 108:
          return 0x0c;
        }
    }
  else
    {
      ndbg("ERROR: Unexpected mode %u", mode);
      PANIC();
    }

  ndbg("ERROR: unsupported rate %u\n", rate);
  return 0;
}

uint8_t ieee80211_plcp2rate(uint8_t plcp, enum ieee80211_phymode mode)
{
  if (mode == IEEE80211_MODE_11B)
    {
      /* IEEE Std 802.11g-2003 page 19, subclause 19.3.2.1 */

      switch (plcp)
        {
        case 10:
          return 2;
        case 20:
          return 4;
        case 55:
          return 11;
        case 110:
          return 22;

          /* IEEE Std 802.11g-2003 page 19, subclause 19.3.2.1 */

        case 220:
          return 44;
        }
    }
  else if (mode == IEEE80211_MODE_11G || mode == IEEE80211_MODE_11A)
    {
      /* IEEE Std 802.11a-1999 page 14, subclause 17.3.4.1 */

      switch (plcp)
        {
        case 0x0b:
          return 12;
        case 0x0f:
          return 18;
        case 0x0a:
          return 24;
        case 0x0e:
          return 36;
        case 0x09:
          return 48;
        case 0x0d:
          return 72;
        case 0x08:
          return 96;
        case 0x0c:
          return 108;
        }
    }
  else
    {
      ndbg("ERROR: Unexpected mode %u", mode);
      PANIC();
    }

  ndbg("ERROR: unsupported plcp %u\n", plcp);
  return 0;
}
