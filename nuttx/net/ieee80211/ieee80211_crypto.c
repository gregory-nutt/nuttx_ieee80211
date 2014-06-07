/****************************************************************************
 * net/ieee80211_cypto.c
 *
 * Copyright (c) 2008 Damien Bergamini <damien.bergamini@free.fr>
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

#include <queue.h>

#include <sys/socket.h>

#include <string.h>
#include <queue.h>
#include <errno.h>

#include <net/if.h>

#ifdef CONFIG_NET_ETHERNET
#  include <netinet/in.h>
#  include <nuttx/net/uip/uip.h>
#endif

#include <nuttx/kmalloc.h>
#include <nuttx/net/iob.h>
#include <nuttx/net/ieee80211/ieee80211_var.h>
#include <nuttx/net/ieee80211/ieee80211_priv.h>

void ieee80211_prf(const uint8_t *, size_t, const uint8_t *, size_t,
        const uint8_t *, size_t, uint8_t *, size_t);
void ieee80211_kdf(const uint8_t *, size_t, const uint8_t *, size_t,
        const uint8_t *, size_t, uint8_t *, size_t);
void ieee80211_derive_pmkid(enum ieee80211_akm, const uint8_t *,
        const uint8_t *, const uint8_t *, uint8_t *);

void ieee80211_crypto_attach(struct ieee80211_s *ic)
{
    sq_init(&ic->ic_pmksa);
    if (ic->ic_caps & IEEE80211_C_RSN) {
        ic->ic_rsnprotos = IEEE80211_PROTO_WPA | IEEE80211_PROTO_RSN;
        ic->ic_rsnakms = IEEE80211_AKM_PSK;
        ic->ic_rsnciphers = IEEE80211_CIPHER_TKIP |
            IEEE80211_CIPHER_CCMP;
        ic->ic_rsngroupcipher = IEEE80211_CIPHER_TKIP;
        ic->ic_rsngroupmgmtcipher = IEEE80211_CIPHER_BIP;
    }
    ic->ic_set_key = ieee80211_set_key;
    ic->ic_delete_key = ieee80211_delete_key;
}

void ieee80211_crypto_detach(struct ieee80211_s *ic)
{
  FAR struct ieee80211_pmk *pmk;
  int i;

  /* Purge the PMKSA cache */

  while ((pmk = (FAR struct ieee80211_pmk *)sq_peek(&ic->ic_pmksa)) != NULL)
    {
      sq_remfirst(&ic->ic_pmksa);
      memset(pmk, 0, sizeof(struct ieee80211_pmk));
      kfree(pmk);
    }

  /* Clear all group keys from memory */

    for (i = 0; i < IEEE80211_GROUP_NKID; i++)
      {
        struct ieee80211_key *k = &ic->ic_nw_keys[i];
        if (k->k_cipher != IEEE80211_CIPHER_NONE)
          {
            (*ic->ic_delete_key)(ic, NULL, k);
          }

        memset(k, 0, sizeof(*k));
    }

  /* Clear pre-shared key from memory */

  memset(ic->ic_psk, 0, IEEE80211_PMK_LEN);
}

/*
 * Return the length in bytes of a cipher suite key (see Table 60).
 */

int ieee80211_cipher_keylen(enum ieee80211_cipher cipher)
{
    switch (cipher) {
    case IEEE80211_CIPHER_WEP40:
        return 5;
    case IEEE80211_CIPHER_TKIP:
        return 32;
    case IEEE80211_CIPHER_CCMP:
        return 16;
    case IEEE80211_CIPHER_WEP104:
        return 13;
    case IEEE80211_CIPHER_BIP:
        return 16;
    default:    /* unknown cipher */
        return 0;
    }
}

int ieee80211_set_key(struct ieee80211_s *ic, struct ieee80211_node *ni,
    struct ieee80211_key *k)
{
    int error;

    switch (k->k_cipher) {
    case IEEE80211_CIPHER_WEP40:
    case IEEE80211_CIPHER_WEP104:
        error = ieee80211_wep_set_key(ic, k);
        break;
    case IEEE80211_CIPHER_TKIP:
        error = ieee80211_tkip_set_key(ic, k);
        break;
    case IEEE80211_CIPHER_CCMP:
        error = ieee80211_ccmp_set_key(ic, k);
        break;
    case IEEE80211_CIPHER_BIP:
        error = ieee80211_bip_set_key(ic, k);
        break;
    default:
        /* should not get there */
        error = EINVAL;
    }
    return error;
}

void ieee80211_delete_key(struct ieee80211_s *ic, struct ieee80211_node *ni,
    struct ieee80211_key *k)
{
    switch (k->k_cipher) {
    case IEEE80211_CIPHER_WEP40:
    case IEEE80211_CIPHER_WEP104:
        ieee80211_wep_delete_key(ic, k);
        break;
    case IEEE80211_CIPHER_TKIP:
        ieee80211_tkip_delete_key(ic, k);
        break;
    case IEEE80211_CIPHER_CCMP:
        ieee80211_ccmp_delete_key(ic, k);
        break;
    case IEEE80211_CIPHER_BIP:
        ieee80211_bip_delete_key(ic, k);
        break;
    default:
        /* should not get there */
        break;
    }

  memset(k, 0, sizeof(*k));
}

struct ieee80211_key *ieee80211_get_txkey(struct ieee80211_s *ic, const struct ieee80211_frame *wh,
    struct ieee80211_node *ni)
{
    int kid;

    if ((ic->ic_flags & IEEE80211_F_RSNON) &&
        !IEEE80211_IS_MULTICAST(wh->i_addr1) &&
        ni->ni_rsncipher != IEEE80211_CIPHER_USEGROUP)
        return &ni->ni_pairwise_key;

    if (!IEEE80211_IS_MULTICAST(wh->i_addr1) ||
        (wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK) !=
        IEEE80211_FC0_TYPE_MGT)
        kid = ic->ic_def_txkey;
    else
        kid = ic->ic_igtk_kid;
    return &ic->ic_nw_keys[kid];
}

struct iob_s *ieee80211_encrypt(struct ieee80211_s *ic, struct iob_s *iob0,
    struct ieee80211_key *k)
{
    switch (k->k_cipher) {
    case IEEE80211_CIPHER_WEP40:
    case IEEE80211_CIPHER_WEP104:
        iob0 = ieee80211_wep_encrypt(ic, iob0, k);
        break;
    case IEEE80211_CIPHER_TKIP:
        iob0 = ieee80211_tkip_encrypt(ic, iob0, k);
        break;
    case IEEE80211_CIPHER_CCMP:
        iob0 = ieee80211_ccmp_encrypt(ic, iob0, k);
        break;
    case IEEE80211_CIPHER_BIP:
        iob0 = ieee80211_bip_encap(ic, iob0, k);
        break;
    default:
        /* Should not get there */

        iob_free_chain(iob0);
        iob0 = NULL;
    }

  return iob0;
}

struct iob_s *ieee80211_decrypt(FAR struct ieee80211_s *ic, FAR struct iob_s *iob0, struct ieee80211_node *ni)
{
    FAR struct ieee80211_frame *wh;
    FAR struct ieee80211_key *k;
    FAR uint8_t *ivp;
    FAR uint8_t *mmie;
    uint16_t kid;
    int hdrlen;

    /* Find key for decryption */

    
    wh = (FAR struct ieee80211_frame *)IOB_DATA(iob0);
    if ((ic->ic_flags & IEEE80211_F_RSNON) &&
        !IEEE80211_IS_MULTICAST(wh->i_addr1) &&
        ni->ni_rsncipher != IEEE80211_CIPHER_USEGROUP)
      {
        k = &ni->ni_pairwise_key;

      }
    else if (!IEEE80211_IS_MULTICAST(wh->i_addr1) ||
            (wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK) != IEEE80211_FC0_TYPE_MGT)
      {
        /* Retrieve group data key id from IV field */

        hdrlen = ieee80211_get_hdrlen(wh);

        /* Check that IV field is present */

        if (iob0->io_len < hdrlen + 4)
          {
            iob_free_chain(iob0);
            return NULL;
          }

        ivp = (uint8_t *)wh + hdrlen;
        kid = ivp[3] >> 6;
        k = &ic->ic_nw_keys[kid];
    } else {
        /* retrieve integrity group key id from MMIE */

        if (iob0->io_len < sizeof(*wh) + IEEE80211_MMIE_LEN)
          {
            iob_free_chain(iob0);
            return NULL;
          }

        /* It is assumed management frames are contiguous */

        mmie = (uint8_t *)wh + iob0->io_len - IEEE80211_MMIE_LEN;

        /* Check that MMIE is valid */

        if (mmie[0] != IEEE80211_ELEMID_MMIE || mmie[1] != 16)
          {
            iob_free_chain(iob0);
            return NULL;
          }

        kid = LE_READ_2(&mmie[2]);
        if (kid != 4 && kid != 5)
          {
            iob_free_chain(iob0);
            return NULL;
          }

        k = &ic->ic_nw_keys[kid];
    }
    switch (k->k_cipher) {
    case IEEE80211_CIPHER_WEP40:
    case IEEE80211_CIPHER_WEP104:
        iob0 = ieee80211_wep_decrypt(ic, iob0, k);
        break;
    case IEEE80211_CIPHER_TKIP:
        iob0 = ieee80211_tkip_decrypt(ic, iob0, k);
        break;
    case IEEE80211_CIPHER_CCMP:
        iob0 = ieee80211_ccmp_decrypt(ic, iob0, k);
        break;
    case IEEE80211_CIPHER_BIP:
        iob0 = ieee80211_bip_decap(ic, iob0, k);
        break;
    default:
        /* Key not defined */

        iob_free_chain(iob0);
        iob0 = NULL;
    }
    return iob0;
}

/*
 * SHA1-based Pseudo-Random Function (see 8.5.1.1).
 */

void ieee80211_prf(const uint8_t *key, size_t key_len, const uint8_t *label,
    size_t label_len, const uint8_t *context, size_t context_len,
    uint8_t *output, size_t len)
{
    HMAC_SHA1_CTX ctx;
    uint8_t digest[SHA1_DIGEST_LENGTH];
    uint8_t count;

    for (count = 0; len != 0; count++) {
        HMAC_SHA1_Init(&ctx, key, key_len);
        HMAC_SHA1_Update(&ctx, label, label_len);
        HMAC_SHA1_Update(&ctx, context, context_len);
        HMAC_SHA1_Update(&ctx, &count, 1);
        if (len < SHA1_DIGEST_LENGTH) {
            HMAC_SHA1_Final(digest, &ctx);
            /* truncate HMAC-SHA1 to len bytes */
            memcpy(output, digest, len);
            break;
        }
        HMAC_SHA1_Final(output, &ctx);
        output += SHA1_DIGEST_LENGTH;
        len -= SHA1_DIGEST_LENGTH;
    }
}

/*
 * SHA256-based Key Derivation Function (see 8.5.1.5.2).
 */

void ieee80211_kdf(const uint8_t *key, size_t key_len, const uint8_t *label,
    size_t label_len, const uint8_t *context, size_t context_len,
    uint8_t *output, size_t len)
{
    HMAC_SHA256_CTX ctx;
    uint8_t digest[SHA256_DIGEST_LENGTH];
    uint16_t i, iter, length;

    length = htole16(len * 8);
    for (i = 1; len != 0; i++) {
        HMAC_SHA256_Init(&ctx, key, key_len);
        iter = htole16(i);
        HMAC_SHA256_Update(&ctx, (uint8_t *)&iter, sizeof iter);
        HMAC_SHA256_Update(&ctx, label, label_len);
        HMAC_SHA256_Update(&ctx, context, context_len);
        HMAC_SHA256_Update(&ctx, (uint8_t *)&length, sizeof length);
        if (len < SHA256_DIGEST_LENGTH) {
            HMAC_SHA256_Final(digest, &ctx);
            /* truncate HMAC-SHA-256 to len bytes */
            memcpy(output, digest, len);
            break;
        }
        HMAC_SHA256_Final(output, &ctx);
        output += SHA256_DIGEST_LENGTH;
        len -= SHA256_DIGEST_LENGTH;
    }
}

/*
 * Derive Pairwise Transient Key (PTK) (see 8.5.1.2).
 */

void ieee80211_derive_ptk(enum ieee80211_akm akm, const uint8_t *pmk,
    const uint8_t *aa, const uint8_t *spa, const uint8_t *anonce,
    const uint8_t *snonce, struct ieee80211_ptk *ptk)
{
    void (*kdf)(const uint8_t *, size_t, const uint8_t *, size_t,
        const uint8_t *, size_t, uint8_t *, size_t);
    uint8_t buf[2 * IEEE80211_ADDR_LEN + 2 * EAPOL_KEY_NONCE_LEN];
    int ret;

    /* Min(AA,SPA) || Max(AA,SPA) */
    ret = memcmp(aa, spa, IEEE80211_ADDR_LEN) < 0;
    memcpy(&buf[ 0], ret ? aa : spa, IEEE80211_ADDR_LEN);
    memcpy(&buf[ 6], ret ? spa : aa, IEEE80211_ADDR_LEN);

    /* Min(ANonce,SNonce) || Max(ANonce,SNonce) */
    ret = memcmp(anonce, snonce, EAPOL_KEY_NONCE_LEN) < 0;
    memcpy(&buf[12], ret ? anonce : snonce, EAPOL_KEY_NONCE_LEN);
    memcpy(&buf[44], ret ? snonce : anonce, EAPOL_KEY_NONCE_LEN);

    kdf = ieee80211_is_sha256_akm(akm) ? ieee80211_kdf : ieee80211_prf;
    (*kdf)(pmk, IEEE80211_PMK_LEN, "Pairwise key expansion", 23,
        buf, sizeof buf, (uint8_t *)ptk, sizeof(*ptk));
}

static void ieee80211_pmkid_sha1(const uint8_t *pmk, const uint8_t *aa,
    const uint8_t *spa, uint8_t *pmkid)
{
    HMAC_SHA1_CTX ctx;
    uint8_t digest[SHA1_DIGEST_LENGTH];

    HMAC_SHA1_Init(&ctx, pmk, IEEE80211_PMK_LEN);
    HMAC_SHA1_Update(&ctx, "PMK Name", 8);
    HMAC_SHA1_Update(&ctx, aa, IEEE80211_ADDR_LEN);
    HMAC_SHA1_Update(&ctx, spa, IEEE80211_ADDR_LEN);
    HMAC_SHA1_Final(digest, &ctx);
    /* use the first 128 bits of HMAC-SHA1 */
    memcpy(pmkid, digest, IEEE80211_PMKID_LEN);
}

static void ieee80211_pmkid_sha256(const uint8_t *pmk, const uint8_t *aa,
    const uint8_t *spa, uint8_t *pmkid)
{
    HMAC_SHA256_CTX ctx;
    uint8_t digest[SHA256_DIGEST_LENGTH];

    HMAC_SHA256_Init(&ctx, pmk, IEEE80211_PMK_LEN);
    HMAC_SHA256_Update(&ctx, "PMK Name", 8);
    HMAC_SHA256_Update(&ctx, aa, IEEE80211_ADDR_LEN);
    HMAC_SHA256_Update(&ctx, spa, IEEE80211_ADDR_LEN);
    HMAC_SHA256_Final(digest, &ctx);
    /* use the first 128 bits of HMAC-SHA-256 */
    memcpy(pmkid, digest, IEEE80211_PMKID_LEN);
}

/*
 * Derive Pairwise Master Key Identifier (PMKID) (see 8.5.1.2).
 */

void ieee80211_derive_pmkid(enum ieee80211_akm akm, const uint8_t *pmk,
    const uint8_t *aa, const uint8_t *spa, uint8_t *pmkid)
{
    if (ieee80211_is_sha256_akm(akm))
        ieee80211_pmkid_sha256(pmk, aa, spa, pmkid);
    else
        ieee80211_pmkid_sha1(pmk, aa, spa, pmkid);
}

typedef union _ANY_CTX
{
  HMAC_MD5_CTX    md5;
  HMAC_SHA1_CTX    sha1;
  AES_CMAC_CTX    cmac;
} ANY_CTX;

/* Compute the Key MIC field of an EAPOL-Key frame using the specified Key
 * Confirmation Key (KCK).  The hash function can be HMAC-MD5, HMAC-SHA1
 * or AES-128-CMAC depending on the EAPOL-Key Key Descriptor Version.
 */

void ieee80211_eapol_key_mic(struct ieee80211_eapol_key *key, const uint8_t *kck)
{
    uint8_t digest[SHA1_DIGEST_LENGTH];
    ANY_CTX ctx;    /* XXX off stack? */
    unsigned int len;

    len = BE_READ_2(key->len) + 4;

    switch (BE_READ_2(key->info) & EAPOL_KEY_VERSION_MASK) {
    case EAPOL_KEY_DESC_V1:
        HMAC_MD5_Init(&ctx.md5, kck, 16);
        HMAC_MD5_Update(&ctx.md5, (uint8_t *)key, len);
        HMAC_MD5_Final(key->mic, &ctx.md5);
        break;
    case EAPOL_KEY_DESC_V2:
        HMAC_SHA1_Init(&ctx.sha1, kck, 16);
        HMAC_SHA1_Update(&ctx.sha1, (uint8_t *)key, len);
        HMAC_SHA1_Final(digest, &ctx.sha1);
        /* truncate HMAC-SHA1 to its 128 MSBs */
        memcpy(key->mic, digest, EAPOL_KEY_MIC_LEN);
        break;
    case EAPOL_KEY_DESC_V3:
        AES_CMAC_Init(&ctx.cmac);
        AES_CMAC_SetKey(&ctx.cmac, kck);
        AES_CMAC_Update(&ctx.cmac, (uint8_t *)key, len);
        AES_CMAC_Final(key->mic, &ctx.cmac);
        break;
    }
}

/*
 * Check the MIC of a received EAPOL-Key frame using the specified Key
 * Confirmation Key (KCK).
 */

int ieee80211_eapol_key_check_mic(struct ieee80211_eapol_key *key,
    const uint8_t *kck)
{
    uint8_t mic[EAPOL_KEY_MIC_LEN];

    memcpy(mic, key->mic, EAPOL_KEY_MIC_LEN);
    memset(key->mic, 0, EAPOL_KEY_MIC_LEN);
    ieee80211_eapol_key_mic(key, kck);

    return timingsafe_bcmp(key->mic, mic, EAPOL_KEY_MIC_LEN) != 0;
}

#ifdef CONFIG_IEEE80211_AP
/*
 * Encrypt the Key Data field of an EAPOL-Key frame using the specified Key
 * Encryption Key (KEK).  The encryption algorithm can be either ARC4 or
 * AES Key Wrap depending on the EAPOL-Key Key Descriptor Version.
 */

void ieee80211_eapol_key_encrypt(struct ieee80211_s *ic,
    struct ieee80211_eapol_key *key, const uint8_t *kek)
{
    union {
        struct rc4_ctx rc4;
        aes_key_wrap_ctx aes;
    } ctx;    /* XXX off stack? */
    uint8_t keybuf[EAPOL_KEY_IV_LEN + 16];
    uint16_t len, info;
    uint8_t *data;
    int n;

    len  = BE_READ_2(key->paylen);
    info = BE_READ_2(key->info);
    data = (uint8_t *)(key + 1);

    switch (info & EAPOL_KEY_VERSION_MASK) {
    case EAPOL_KEY_DESC_V1:
        /* set IV to the lower 16 octets of our global key counter */
        memcpy(key->iv, ic->ic_globalcnt + 16, 16);
        /* increment our global key counter (256-bit, big-endian) */
        for (n = 31; n >= 0 && ++ic->ic_globalcnt[n] == 0; n--);

        /* concatenate the EAPOL-Key IV field and the KEK */
        memcpy(keybuf, key->iv, EAPOL_KEY_IV_LEN);
        memcpy(keybuf + EAPOL_KEY_IV_LEN, kek, 16);

        rc4_keysetup(&ctx.rc4, keybuf, sizeof keybuf);
        /* discard the first 256 octets of the ARC4 key stream */
        rc4_skip(&ctx.rc4, RC4STATE);
        rc4_crypt(&ctx.rc4, data, data, len);
        break;
    case EAPOL_KEY_DESC_V2:
    case EAPOL_KEY_DESC_V3:
        if (len < 16 || (len & 7) != 0) {
            /* insert padding */
            n = (len < 16) ? 16 - len : 8 - (len & 7);
            data[len++] = IEEE80211_ELEMID_VENDOR;
            memset(&data[len], 0, n - 1);
            len += n - 1;
        }
        aes_key_wrap_set_key_wrap_only(&ctx.aes, kek, 16);
        aes_key_wrap(&ctx.aes, data, len / 8, data);
        len += 8;    /* AES Key Wrap adds 8 bytes */
        /* update key data length */
        BE_WRITE_2(key->paylen, len);
        /* update packet body length */
        BE_WRITE_2(key->len, sizeof(*key) + len - 4);
        break;
    }
}
#endif /* CONFIG_IEEE80211_AP */

/* Decrypt the Key Data field of an EAPOL-Key frame using the specified Key
 * Encryption Key (KEK).  The encryption algorithm can be either ARC4 or
 * AES Key Wrap depending on the EAPOL-Key Key Descriptor Version.
 */

int ieee80211_eapol_key_decrypt(struct ieee80211_eapol_key *key,
    const uint8_t *kek)
{
    union {
        struct rc4_ctx rc4;
        aes_key_wrap_ctx aes;
    } ctx;    /* XXX off stack? */
    uint8_t keybuf[EAPOL_KEY_IV_LEN + 16];
    uint16_t len, info;
    uint8_t *data;

    len  = BE_READ_2(key->paylen);
    info = BE_READ_2(key->info);
    data = (uint8_t *)(key + 1);

    switch (info & EAPOL_KEY_VERSION_MASK) {
    case EAPOL_KEY_DESC_V1:
        /* concatenate the EAPOL-Key IV field and the KEK */
        memcpy(keybuf, key->iv, EAPOL_KEY_IV_LEN);
        memcpy(keybuf + EAPOL_KEY_IV_LEN, kek, 16);

        rc4_keysetup(&ctx.rc4, keybuf, sizeof keybuf);
        /* discard the first 256 octets of the ARC4 key stream */
        rc4_skip(&ctx.rc4, RC4STATE);
        rc4_crypt(&ctx.rc4, data, data, len);
        return 0;
    case EAPOL_KEY_DESC_V2:
    case EAPOL_KEY_DESC_V3:
        /* Key Data Length must be a multiple of 8 */
        if (len < 16 + 8 || (len & 7) != 0)
            return 1;
        len -= 8;    /* AES Key Wrap adds 8 bytes */
        aes_key_wrap_set_key(&ctx.aes, kek, 16);
        return aes_key_unwrap(&ctx.aes, data, data, len / 8);
    }

    return 1;    /* unknown Key Descriptor Version */
}

/* Add a PMK entry to the PMKSA cache */

struct ieee80211_pmk *ieee80211_pmksa_add(struct ieee80211_s *ic, enum ieee80211_akm akm, const uint8_t *macaddr, const uint8_t *key, uint32_t lifetime)
{
  struct ieee80211_pmk *pmk;
  sq_entry_t *entry;

  /* Check if an entry already exists for this (STA,AKMP) */

  for (entry = ic->ic_pmksa.head; entry; entry = entry->flink)
    {
      pmk = (struct ieee80211_pmk *)entry;
      if (pmk->pmk_akm == akm && IEEE80211_ADDR_EQ(pmk->pmk_macaddr, macaddr))
        {
          break;
        }
    }

  if (pmk == NULL)
    {
      /* Allocate a new PMKSA entry */

      if ((pmk = kmalloc(sizeof(struct ieee80211_pmk))) == NULL)
        {
          return NULL;
        }

      pmk->pmk_akm = akm;
      IEEE80211_ADDR_COPY(pmk->pmk_macaddr, macaddr);
      sq_addlast((sq_entry_t *)pmk, &ic->ic_pmksa);
    }

  memcpy(pmk->pmk_key, key, IEEE80211_PMK_LEN);
  pmk->pmk_lifetime = lifetime;    /* XXX not used yet */
#ifdef CONFIG_IEEE80211_AP
  if (ic->ic_opmode == IEEE80211_M_HOSTAP)
    {
        ieee80211_derive_pmkid(pmk->pmk_akm, pmk->pmk_key,
            ic->ic_myaddr, macaddr, pmk->pmk_pmkid);
    }
  else
#endif
    {
        ieee80211_derive_pmkid(pmk->pmk_akm, pmk->pmk_key,
            macaddr, ic->ic_myaddr, pmk->pmk_pmkid);
    }

  return pmk;
}

/*
 * Check if we have a cached PMK entry for the specified node and PMKID.
 */

struct ieee80211_pmk *ieee80211_pmksa_find(struct ieee80211_s *ic, struct ieee80211_node *ni, const uint8_t *pmkid)
{
  struct ieee80211_pmk *pmk;
  sq_entry_t *entry;

  for (entry = ic->ic_pmksa.head; entry; entry = entry->flink)
    {
      pmk = (struct ieee80211_pmk *)entry;
      if (pmk->pmk_akm == ni->ni_rsnakms &&
          IEEE80211_ADDR_EQ(pmk->pmk_macaddr, ni->ni_macaddr) &&
          (pmkid == NULL ||
           memcmp(pmk->pmk_pmkid, pmkid, IEEE80211_PMKID_LEN) == 0))
        {
          break;
        }
    }

  return pmk;
}
