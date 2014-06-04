/****************************************************************************
 * IEEE 802.11 ioctls
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

#ifndef _NET80211_IEEE80211_IOCTL_H_
#define _NET80211_IEEE80211_IOCTL_H_

/****************************************************************************
 * Included Files
 ****************************************************************************/

/****************************************************************************
 * Public Types
 ****************************************************************************/

/* Statistics are not supported */

#define SIOCG80211STATS        _IOWR('i', 242, struct ifreq)
#define SIOCG80211ZSTATS       _IOWR('i', 243, struct ifreg)

/* network identifier (ESSID), nwid is pointed at by ifr.ifr_data */

struct ieee80211_nwid
{
  uint8_t    i_len;
  uint8_t    i_nwid[IEEE80211_NWID_LEN];
};

#define SIOCS80211NWID        _IOWR('i', 230, struct ifreq)
#define SIOCG80211NWID        _IOWR('i', 231, struct ifreq)

/* Network key (WEP), the first member must be matched with struct ifreq */

struct ieee80211_nwkey
{
  char       i_name[IFNAMSIZ];   /* if_name, e.g. "wi0" */
  int        i_wepon;            /* wep enabled flag */
  int        i_defkid;           /* default encrypt key id */
  struct
  {
    int        i_keylen;
    uint8_t    *i_keydat;
  } i_key[IEEE80211_WEP_NKID];
};

#define IEEE80211_NWKEY_OPEN       0        /* No privacy */
#define IEEE80211_NWKEY_WEP        1        /* WEP enabled */
#define IEEE80211_NWKEY_EAP        2        /* EAP enabled */
#define IEEE80211_NWKEY_PERSIST    0x100    /* designate persist keyset */

#define SIOCS80211NWKEY         _IOW('i', 232, struct ieee80211_nwkey)
#define SIOCG80211NWKEY        _IOWR('i', 233, struct ieee80211_nwkey)

/* power management parameters */

struct ieee80211_power
{
  char       i_name[IFNAMSIZ];    /* if_name, e.g. "wi0" */
  int        i_enabled;           /* 1 == on, 0 == off */
  int        i_maxsleep;          /* max sleep in ms */
};

#define SIOCS80211POWER        _IOW('i', 234, struct ieee80211_power)
#define SIOCG80211POWER        _IOWR('i', 235, struct ieee80211_power)

/* Authentication type */

struct ieee80211_auth
{
  char        i_name[IFNAMSIZ];    /* if_name, e.g. "wi0" */
  int        i_authtype;
};

#define IEEE80211_AUTH_NONE    0
#define IEEE80211_AUTH_OPEN    1
#define IEEE80211_AUTH_SHARED  2

#define SIOCS80211AUTH        _IOW('i', 236, struct ieee80211_auth)
#define SIOCG80211AUTH        _IOWR('i', 237, struct ieee80211_auth)

/* channel request */

struct ieee80211chanreq
{
  char        i_name[IFNAMSIZ];    /* if_name, e.g. "wi0" */
  uint16_t    i_channel;
};

struct ieee80211_chanreq_all
{
  char        i_name[IFNAMSIZ];    /* if_name, e.g. "wi0" */
  struct ieee80211_channel *i_chans;
};

#ifndef IEEE80211_CHAN_ANY
# define IEEE80211_CHAN_ANY    0xffff
#endif

#define SIOCS80211CHANNEL    _IOW('i', 238, struct ieee80211chanreq)
#define SIOCG80211CHANNEL    _IOWR('i', 239, struct ieee80211chanreq)
#define SIOCG80211ALLCHANS   _IOWR('i', 215, struct ieee80211_chanreq_all)

/* BSS identifier */

struct ieee80211_bssid
{
  char        i_name[IFNAMSIZ];    /* if_name, e.g. "wi0" */
  uint8_t    i_bssid[IEEE80211_ADDR_LEN];
};

#define SIOCS80211BSSID         _IOW('i', 240, struct ieee80211_bssid)
#define SIOCG80211BSSID        _IOWR('i', 241, struct ieee80211_bssid)

/* transmit power */

struct ieee80211_txpower
{
  char        i_name[IFNAMSIZ];    /* if_name, e.g. "wi0" */
  int        i_mode;               /* auto, manual */
  int16_t        i_val;            /* dBm */
};

#define SIOCS80211TXPOWER    _IOW('i', 243, struct ieee80211_txpower)
#define SIOCG80211TXPOWER    _IOWR('i', 244, struct ieee80211_txpower)

#define IEEE80211_TXPOWER_MODE_FIXED   0    /* fixed tx power value */
#define IEEE80211_TXPOWER_MODE_AUTO    1    /* auto level control */

struct ieee80211_wpapsk
{
  char        i_name[IFNAMSIZ];    /* if_name, e.g. "wi0" */
  int        i_enabled;
  uint8_t    i_psk[32];
};

#define SIOCS80211WPAPSK    _IOW('i', 245, struct ieee80211_wpapsk)
#define SIOCG80211WPAPSK    _IOWR('i', 246, struct ieee80211_wpapsk)

#define IEEE80211_WPA_PROTO_WPA1    0x01
#define IEEE80211_WPA_PROTO_WPA2    0x02

#define IEEE80211_WPA_CIPHER_NONE        0x00
#define IEEE80211_WPA_CIPHER_USEGROUP    0x01
#define IEEE80211_WPA_CIPHER_WEP40       0x02
#define IEEE80211_WPA_CIPHER_TKIP        0x04
#define IEEE80211_WPA_CIPHER_CCMP        0x08
#define IEEE80211_WPA_CIPHER_WEP104      0x10

#define IEEE80211_WPA_AKM_PSK             0x01
#define IEEE80211_WPA_AKM_8021X           0x02
#define IEEE80211_WPA_AKM_SHA256_PSK      0x04
#define IEEE80211_WPA_AKM_SHA256_8021X    0x08

struct ieee80211_wpaparams
{
  char    i_name[IFNAMSIZ];        /* if_name, e.g. "wi0" */
  int    i_enabled;
  unsigned int    i_protos;
  unsigned int    i_akms;
  unsigned int    i_ciphers;
  unsigned int    i_groupcipher;
};

#define SIOCS80211WPAPARMS     _IOW('i', 247, struct ieee80211_wpaparams)
#define SIOCG80211WPAPARMS    _IOWR('i', 248, struct ieee80211_wpaparams)

struct ieee80211_wmmparams
{
  char    i_name[IFNAMSIZ];        /* if_name, e.g. "wi0" */
  int    i_enabled;
  /* XXX more */
};

#define SIOCS80211WMMPARMS     _IOW('i', 249, struct ieee80211_wmmparams)
#define SIOCG80211WMMPARMS    _IOWR('i', 250, struct ieee80211_wmmparams)

struct ieee80211_keyavail
{
  char        i_name[IFNAMSIZ];    /* if_name, e.g. "wi0" */
  uint8_t    i_macaddr[IEEE80211_ADDR_LEN];
  uint8_t    i_key[32];
  uint32_t    i_lifetime;
};

struct ieee80211_keyrun
{
  char        i_name[IFNAMSIZ];    /* if_name, e.g. "wi0" */
  uint8_t    i_macaddr[IEEE80211_ADDR_LEN];
};

#define SIOCS80211KEYAVAIL    _IOW('i', 251, struct ieee80211_keyavail)
#define SIOCS80211KEYRUN      _IOW('i', 252, struct ieee80211_keyrun)

/* Scan request (will block) */
#define IEEE80211_SCAN_TIMEOUT    30    /* timeout in seconds */

#define SIOCS80211SCAN         _IOW('i', 210, struct ifreq)

/* Node and requests */

struct ieee80211_nodereq
{
  char        nr_ifname[IFNAMSIZ];        /* e.g. "ath0" */

  /* Node address and name information */

  uint8_t    nr_macaddr[IEEE80211_ADDR_LEN];    /* node lladdr */
  uint8_t    nr_bssid[IEEE80211_ADDR_LEN];      /* bssid */
  uint8_t    nr_nwid_len;                       /* ESSID length */
  uint8_t    nr_nwid[IEEE80211_NWID_LEN];       /* ESSID */

  /* Channel and rates */

  uint16_t    nr_channel;               /* last channel */
  uint16_t    nr_chan_flags;            /* channel flags */
  uint8_t    nr_nrates;                 /* rate count */
  uint8_t    nr_rates[IEEE80211_RATE_MAXSIZE];    /* rate set */

  /* Node status information */

  uint8_t    nr_rssi;    /* received signal strength */
  uint8_t    nr_max_rssi;    /* maximum rssi */
  uint8_t    nr_tstamp[8];    /* from last received beacon */
  uint16_t    nr_intval;    /* beacon interval */
  uint16_t    nr_capinfo;    /* capabilities */
  uint16_t    nr_fhdwell;    /* FH only */
  uint8_t    nr_fhindex;    /* FH only */
  uint8_t    nr_erp;        /* 11g only */
  uint8_t    nr_pwrsave;    /* power saving mode */
  uint16_t    nr_associd;    /* assoc response */
  uint16_t    nr_txseq;    /* seq to be transmitted */
  uint16_t    nr_rxseq;    /* seq previous received */
  uint32_t    nr_fails;    /* failure count to associate */
  uint32_t    nr_inact;    /* inactivity mark count */
  uint8_t    nr_txrate;    /* index to nr_rates[] */
  uint16_t    nr_state;    /* node state in the cache */

  /* XXX RSN */

  /* Node flags */

  uint8_t    nr_flags;
};

#define IEEE80211_NODEREQ_STATE(_s)    (1 << _s)
#define IEEE80211_NODEREQ_STATE_BITS                    \
    "\20\01CACHE\02BSS\03AUTH\04ASSOC\05COLLECT"

#define IEEE80211_NODEREQ_RSSI(_nr)                    \
    ((unsigned int)(((float)(_nr)->nr_rssi / (_nr)->nr_max_rssi) * 100))

#define IEEE80211_NODEREQ_STA        0x00    /* station */
#define IEEE80211_NODEREQ_AP         0x01    /* access point */
#define IEEE80211_NODEREQ_AP_BSS     0x02    /* current bss access point */
#define IEEE80211_NODEREQ_COPY       0x04    /* add node with flags */

#define SIOCG80211NODE        _IOWR('i', 211, struct ieee80211_nodereq)
#define SIOCS80211NODE        _IOW('i', 212, struct ieee80211_nodereq)
#define SIOCS80211DELNODE     _IOW('i', 213, struct ieee80211_nodereq)

/* Get the entire node cache */

struct ieee80211_nodereq_all
{
  char               na_ifname[IFNAMSIZ];    /* e.g. "ath0" */

  int                na_nodes;               /* returned count */
  size_t             na_size;                /* size of node buffer */
  struct ieee80211_nodereq    *na_node;      /* allocated node buffer */

  /* Match nodes by flag */

  uint8_t            na_flags;    /* IEEE80211_NODEREQ_* */
};

#define SIOCG80211ALLNODES    _IOWR('i', 214, struct ieee80211_nodereq)

/* net80211 specific interface flags */

#define IEEE80211_F_HIDENWID    0x10000000    /* CONF: hidden ssid mode */
#define IEEE80211_F_NOBRIDGE    0x20000000    /* CONF: no internal bridging */
#define IEEE80211_F_HOSTAPMASK  0x30000000
#define IEEE80211_F_USERSHIFT   28
#define IEEE80211_F_USERBITS    "\20\01HIDENWID\02NOBRIDGE"

struct ieee80211_flags
{
  const char        *f_name;
  unsigned int            f_flag;
};

#define IEEE80211_FLAGS    {                        \
    { "hidenwid", IEEE80211_F_HIDENWID >> IEEE80211_F_USERSHIFT },    \
    { "nobridge", IEEE80211_F_NOBRIDGE >> IEEE80211_F_USERSHIFT }    \
}

#define SIOCG80211FLAGS        _IOWR('i', 216, struct ifreq)
#define SIOCS80211FLAGS        _IOW('i', 217, struct ifreq)

#endif /* _NET80211_IEEE80211_IOCTL_H_ */
