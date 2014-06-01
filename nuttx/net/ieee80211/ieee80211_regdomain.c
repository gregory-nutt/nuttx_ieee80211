/****************************************************************************
 * net/ieee80211/ieee80211_regdomain.c
 *
 * Basic regulation domain extensions for the IEEE 802.11 stack
 *
 * Copyright (c) 2004, 2005 Reyk Floeter <reyk@openbsd.org>
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

#include <errno.h>

#include <net/if.h>

#ifdef CONFIG_NET_ETHERNET
#  include <netinet/in.h>
#  include <nuttx/net/uip/uip.h>
#endif

#include <nuttx/net/ieee80211/ieee80211_var.h>
#include <nuttx/net/ieee80211/ieee80211_regdomain.h>

int ieee80211_regdomain_compare_cn(const void *, const void *);
int ieee80211_regdomain_compare_rn(const void *, const void *);

static const struct ieee80211_regdomainname
ieee80211_r_names[] = IEEE80211_REGDOMAIN_NAMES;

static const struct ieee80211_regdomainmap
ieee80211_r_map[] = IEEE80211_REGDOMAIN_MAP;

static const struct ieee80211_countryname
ieee80211_r_ctry[] = IEEE80211_REGDOMAIN_COUNTRY_NAMES;

#ifndef bsearch
const void *bsearch(const void *, const void *, size_t, size_t,
    int (*)(const void *, const void *));

const void *
bsearch(const void *key, const void *base0, size_t nmemb, size_t size,
    int (*compar)(const void *, const void *))
{
    const char *base = base0;
    int lim, cmp;
    const void *p;

    for (lim = nmemb; lim != 0; lim >>= 1) {
        p = base + (lim >> 1) * size;
        cmp = (*compar)(key, p);
        if (cmp == 0)
            return ((const void *)p);
        if (cmp > 0) {  /* key > p: move right */
            base = (const char *)p + size;
            lim--;
        } /* else move left */
    }
    return (NULL);
}
#endif

int
ieee80211_regdomain_compare_cn(const void *a, const void *b)
{
    return (strcmp(((const struct ieee80211_countryname*)a)->cn_name,
        ((const struct ieee80211_countryname*)b)->cn_name));
}

int
ieee80211_regdomain_compare_rn(const void *a, const void *b)
{
    return (strcmp(((const struct ieee80211_regdomainname*)a)->rn_name,
        ((const struct ieee80211_regdomainname*)b)->rn_name));
}

uint16_t
ieee80211_name2countrycode(const char *name)
{
    const struct ieee80211_countryname key = { CTRY_DEFAULT, name }, *value;

    if ((value = bsearch(&key, &ieee80211_r_ctry,
        sizeof(ieee80211_r_ctry) / sizeof(ieee80211_r_ctry[0]),
        sizeof(struct ieee80211_countryname),
        ieee80211_regdomain_compare_cn)) != NULL)
        return (value->cn_code);

    return (CTRY_DEFAULT);
}

uint32_t
ieee80211_name2regdomain(const char *name)
{
    const struct ieee80211_regdomainname *value;
    struct ieee80211_regdomainname key;

    key.rn_domain = DMN_DEFAULT;
    key.rn_name = name;

    if ((value = bsearch(&key, &ieee80211_r_names,
        sizeof(ieee80211_r_names) / sizeof(ieee80211_r_names[0]),
        sizeof(struct ieee80211_regdomainname),
        ieee80211_regdomain_compare_rn)) != NULL)
        return ((uint32_t)value->rn_domain);

    return ((uint32_t)DMN_DEFAULT);
}

const char *
ieee80211_countrycode2name(uint16_t code)
{
    int i;

    /* Linear search over the table */
    for (i = 0; i < (sizeof(ieee80211_r_ctry) /
        sizeof(ieee80211_r_ctry[0])); i++)
        if (ieee80211_r_ctry[i].cn_code == code)
            return (ieee80211_r_ctry[i].cn_name);

    return (NULL);
}

const char *
ieee80211_regdomain2name(uint32_t regdomain)
{
    int i;

    /* Linear search over the table */
    for (i = 0; i < (sizeof(ieee80211_r_names) /
        sizeof(ieee80211_r_names[0])); i++)
        if (ieee80211_r_names[i].rn_domain == regdomain)
            return (ieee80211_r_names[i].rn_name);

    return (ieee80211_r_names[0].rn_name);
}

uint32_t
ieee80211_regdomain2flag(uint16_t regdomain, uint16_t mhz)
{
    int i;

    for (i = 0; i < (sizeof(ieee80211_r_map) /
        sizeof(ieee80211_r_map[0])); i++) {
        if (ieee80211_r_map[i].rm_domain == regdomain) {
            if (mhz >= 2000 && mhz <= 3000)
                return ((uint32_t)
                    ieee80211_r_map[i].rm_domain_2ghz);
            if (mhz >= IEEE80211_CHANNELS_5GHZ_MIN &&
                mhz <= IEEE80211_CHANNELS_5GHZ_MAX)
                return ((uint32_t)
                    ieee80211_r_map[i].rm_domain_5ghz);
        }
    }

    return ((uint32_t)DMN_DEBUG);
}

uint32_t
ieee80211_countrycode2regdomain(uint16_t code)
{
    int i;

    for (i = 0;
         i < (sizeof(ieee80211_r_ctry) / sizeof(ieee80211_r_ctry[0])); i++)
        if (ieee80211_r_ctry[i].cn_code == code)
            return (ieee80211_r_ctry[i].cn_domain);

    return ((uint32_t)DMN_DEFAULT);
}
