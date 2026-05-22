/*
 * Copyright (C) 2015-2018 Jolla Ltd.
 * Copyright (C) 2015-2018 Slava Monich <slava.monich@jolla.com>
 *
 * You may use this file under the terms of BSD license as follows:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *   3. Neither the names of the copyright holders nor the names of its
 *      contributors may be used to endorse or promote products derived from
 *      this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef GSUPPLICANT_BSS_H
#define GSUPPLICANT_BSS_H

#include <gsupplicant_types.h>
#include <gio/gio.h>

G_BEGIN_DECLS

typedef struct gsupplicant_bss_wpa {
    GSUPPLICANT_KEYMGMT keymgmt;
    GSUPPLICANT_CIPHER pairwise;
    GSUPPLICANT_CIPHER group;
} GSupplicantBSSWPA;

typedef struct gsupplicant_bss_rsn {
    GSUPPLICANT_KEYMGMT keymgmt;
    GSUPPLICANT_CIPHER pairwise;
    GSUPPLICANT_CIPHER group;
    GSUPPLICANT_CIPHER mgmt_group;
} GSupplicantBSSRSN;

typedef struct gsupplicant_bss_connect_params {
    guint flags;  /* Should be zero */
    GSUPPLICANT_AUTH_FLAGS auth_flags;
    GSUPPLICANT_EAP_METHOD eap;
    const char* bgscan;
    const char* passphrase;
    /* EAP */
    const char* identity;
    const char* anonymous_identity;
    const char* ca_cert_file;
    const char* client_cert_file;
    const char* private_key_file;
    const char* private_key_passphrase;
    const char* subject_match;
    const char* altsubject_match;
    const char* domain_suffix_match;
    const char* domain_match;
    GSUPPLICANT_EAP_METHOD phase2;
    const char* ca_cert_file2;
    const char* client_cert_file2;
    const char* private_key_file2;
    const char* private_key_passphrase2;
    const char* subject_match2;
    const char* altsubject_match2;
    const char* domain_suffix_match2;
} GSupplicantBSSConnectParams;

typedef enum gsupplicant_bss_property {
    GSUPPLICANT_BSS_PROPERTY_ANY,
    GSUPPLICANT_BSS_PROPERTY_VALID,
    GSUPPLICANT_BSS_PROPERTY_PRESENT,
    GSUPPLICANT_BSS_PROPERTY_SSID,
    GSUPPLICANT_BSS_PROPERTY_BSSID,
    GSUPPLICANT_BSS_PROPERTY_WPA,
    GSUPPLICANT_BSS_PROPERTY_RSN,
    GSUPPLICANT_BSS_PROPERTY_MODE,
    GSUPPLICANT_BSS_PROPERTY_WPS_CAPS,
    GSUPPLICANT_BSS_PROPERTY_IES,
    GSUPPLICANT_BSS_PROPERTY_PRIVACY,
    GSUPPLICANT_BSS_PROPERTY_FREQUENCY,
    GSUPPLICANT_BSS_PROPERTY_RATES,
    GSUPPLICANT_BSS_PROPERTY_MAXRATE,
    GSUPPLICANT_BSS_PROPERTY_SIGNAL,
    GSUPPLICANT_BSS_PROPERTY_COUNT
} GSUPPLICANT_BSS_PROPERTY;

typedef enum gsupplicant_bss_mode {
    GSUPPLICANT_BSS_MODE_UNKNOWN,
    GSUPPLICANT_BSS_MODE_INFRA,
    GSUPPLICANT_BSS_MODE_AD_HOC
} GSUPPLICANT_BSS_MODE;

typedef struct gsupplicant_bss_priv GSupplicantBSSPriv;

struct gsupplicant_bss {
    GObject object;
    GSupplicantBSSPriv* priv;
    GSupplicantInterface* iface;
    const char* path;
    gboolean valid;
    gboolean present;
    GBytes* bssid;
    GBytes* ssid;
    const char* ssid_str;
    const GSupplicantBSSWPA* wpa;
    const GSupplicantBSSRSN* rsn;
    GSUPPLICANT_WPS_CAPS wps_caps;
    GSUPPLICANT_BSS_MODE mode;
    GBytes* ies;
    gsize ies_length;
    gboolean privacy;
    guint frequency;
    const GSupplicantUIntArray* rates;
    guint maxrate;
    gint signal;
};

typedef
void
(*GSupplicantBSSFunc)(
    GSupplicantBSS* bss,
    void* data);

typedef
void
(*GSupplicantBSSStringResultFunc)(
    GSupplicantBSS* bss,
    GCancellable* cancel,
    const GError* error,
    const char* result,
    void* data);

typedef
void
(*GSupplicantBSSPropertyFunc)(
    GSupplicantBSS* bss,
    GSUPPLICANT_BSS_PROPERTY property,
    void* data);

GSupplicantBSS*
gsupplicant_bss_new(
    const char* path);

GSupplicantBSS*
gsupplicant_bss_ref(
    GSupplicantBSS* bss);

void
gsupplicant_bss_unref(
    GSupplicantBSS* bss);

gulong
gsupplicant_bss_add_handler(
    GSupplicantBSS* bss,
    GSUPPLICANT_BSS_PROPERTY property,
    GSupplicantBSSFunc fn,
    void* data);

gulong
gsupplicant_bss_add_property_changed_handler(
    GSupplicantBSS* bss,
    GSUPPLICANT_BSS_PROPERTY property,
    GSupplicantBSSPropertyFunc fn,
    void* data);

void
gsupplicant_bss_remove_handler(
    GSupplicantBSS* bss,
    gulong id);

void
gsupplicant_bss_remove_handlers(
    GSupplicantBSS* bss,
    gulong* ids,
    guint count);

GSUPPLICANT_SECURITY
gsupplicant_bss_security(
    GSupplicantBSS* bss);

GSUPPLICANT_KEYMGMT
gsupplicant_bss_keymgmt(
    GSupplicantBSS* bss);

GSUPPLICANT_CIPHER
gsupplicant_bss_pairwise(
    GSupplicantBSS* bss);

GCancellable*
gsupplicant_bss_connect(
    GSupplicantBSS* bss,
    const GSupplicantBSSConnectParams* params,
    guint flags, /* None defined yet */
    GSupplicantBSSStringResultFunc fn,
    void* data);

#define gsupplicant_bss_remove_all_handlers(bss, ids) \
    gsupplicant_bss_remove_handlers(bss, ids, G_N_ELEMENTS(ids))

G_END_DECLS

#endif /* GSUPPLICANT_BSS_H */

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
