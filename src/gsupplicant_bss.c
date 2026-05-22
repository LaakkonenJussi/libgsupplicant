/*
 * Copyright (C) 2015-2021 Jolla Ltd.
 * Copyright (C) 2023 Slava Monich <slava@monich.com>
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
 *      contributors may be used to endorse or promote products derived
 *      from this software without specific prior written permission.
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

#define GLIB_DISABLE_DEPRECATION_WARNINGS /* G_ADD_PRIVATE */

#include "gsupplicant_bss.h"
#include "gsupplicant_interface.h"
#include "gsupplicant_p.h"
#include "gsupplicant_util_p.h"
#include "gsupplicant_dbus.h"
#include "gsupplicant_log.h"

#include <gutil_misc.h>
#include <gutil_strv.h>

#include <ctype.h>

#include "mcs_index_rates.h"

/* Generated headers */
#include "fi.w1.wpa_supplicant1.BSS.h"

/* Object definition */
enum supplicant_bss_proxy_handler_id {
    PROXY_GPROPERTIES_CHANGED,
    PROXY_PROPERTIES_CHANGED,
    PROXY_HANDLER_COUNT
};

enum supplicant_iface_handler_id {
    INTERFACE_VALID_CHANGED,
    INTERFACE_BSSS_CHANGED,
    INTERFACE_HANDLER_COUNT
};

typedef struct gsupplicant_bss_connect_data {
    GSupplicantBSS* bss;
    GSupplicantBSSStringResultFunc fn;
    void* fn_data;
} GSupplicantBSSConnectData;

struct gsupplicant_bss_priv {
    FiW1Wpa_supplicant1BSS* proxy;
    gulong proxy_handler_id[PROXY_HANDLER_COUNT];
    gulong iface_handler_id[INTERFACE_HANDLER_COUNT];
    char* path;
    char* ssid_str;
    GSupplicantBSSWPA wpa;
    GSupplicantBSSRSN rsn;
    GSupplicantUIntArray rates;
    guint* rates_values;
    guint32 pending_signals;
};

typedef enum wps_methods {
    WPS_METHODS_NONE     = (0x00000000),
    WPS_METHODS_PIN      = (0x00000001),
    WPS_METHODS_BUTTON   = (0x00000002)
} WPS_METHODS;

typedef struct gsupplicant_wps_info {
    guint flags;

#define WPS_INFO_VERSION        (0x0001)
#define WPS_INFO_STATE          (0x0002)
#define WPS_INFO_METHODS        (0x0004)
#define WPS_INFO_REGISTRAR      (0x0008)
#define WPS_INFO_REQUIRED       (WPS_INFO_VERSION | WPS_INFO_STATE)

    guint32 version;
    guint32 state;
    guint32 registrar;
    WPS_METHODS methods;
} GSupplicantWPSInfo;

#define WPS_TLV_VERSION         0x104a
#define WPS_TLV_STATE           0x1044
#define WPS_TLV_METHOD          0x1012
#define WPS_TLV_REGISTRAR       0x1041
#define WPS_TLV_DEVICENAME      0x1011
#define WPS_TLV_UUID            0x1047

#define WMM_WPA1_WPS_INFO       0xdd
#define WMM_WPA1_WPS_OUI        0x00,0x50,0xf2,0x04
#define WPS_VERSION             0x10
#define WPS_METHOD_PUSH_BUTTON  0x04
#define WPS_METHOD_PIN          0x00
#define WPS_STATE_CONFIGURED    0x02

typedef GObjectClass GSupplicantBSSClass;
G_DEFINE_TYPE(GSupplicantBSS, gsupplicant_bss, G_TYPE_OBJECT)
#define GSUPPLICANT_BSS_TYPE (gsupplicant_bss_get_type())
#define GSUPPLICANT_BSS(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), \
        GSUPPLICANT_BSS_TYPE, GSupplicantBSS))
#define SUPER_CLASS gsupplicant_bss_parent_class

/* BSS properties */
#define GSUPPLICANT_BSS_PROPERTIES_(p) \
    p(VALID,valid) \
    p(PRESENT,present) \
    p(SSID,ssid) \
    p(BSSID,bssid) \
    p(WPA,wpa) \
    p(RSN,rsn) \
    p(MODE,mode) \
    p(WPS_CAPS,wpscaps) \
    p(IES,ies) \
    p(PRIVACY,privacy) \
    p(FREQUENCY,frequency) \
    p(RATES,rates) \
    p(MAXRATE,maxrate) \
    p(SIGNAL,signal)

typedef enum gsupplicant_bss_signal {
#define SIGNAL_ENUM_(P,p) SIGNAL_##P##_CHANGED,
    GSUPPLICANT_BSS_PROPERTIES_(SIGNAL_ENUM_)
#undef SIGNAL_ENUM_
    SIGNAL_PROPERTY_CHANGED,
    SIGNAL_COUNT
} GSUPPLICANT_BSS_SIGNAL;

#define SIGNAL_BIT(name) (1 << SIGNAL_##name##_CHANGED)

/*
 * The code assumes that VALID is the first one and that their number
 * doesn't exceed the number of bits in pending_signals (currently, 32)
 */
G_STATIC_ASSERT(SIGNAL_VALID_CHANGED == 0);
G_STATIC_ASSERT(SIGNAL_PROPERTY_CHANGED <= 32);

/* Assert that we have covered all publicly defined properties */
G_STATIC_ASSERT((int)SIGNAL_PROPERTY_CHANGED ==
               ((int)GSUPPLICANT_BSS_PROPERTY_COUNT-1));

#define SIGNAL_PROPERTY_CHANGED_NAME            "property-changed"
#define SIGNAL_PROPERTY_CHANGED_DETAIL          "%x"
#define SIGNAL_PROPERTY_CHANGED_DETAIL_MAX_LEN  (8)

static GQuark gsupplicant_bss_property_quarks[SIGNAL_PROPERTY_CHANGED];
static guint gsupplicant_bss_signals[SIGNAL_COUNT];
static const char* gsupplicant_bss_signame[] = {
#define SIGNAL_NAME_(P,p) #p "-changed",
    GSUPPLICANT_BSS_PROPERTIES_(SIGNAL_NAME_)
#undef SIGNAL_NAME_
    SIGNAL_PROPERTY_CHANGED_NAME
};
G_STATIC_ASSERT(G_N_ELEMENTS(gsupplicant_bss_signame) == SIGNAL_COUNT);

/* Proxy properties */
#define PROXY_PROPERTY_NAME_SSID        "SSID"
#define PROXY_PROPERTY_NAME_BSSID       "BSSID"
#define PROXY_PROPERTY_NAME_WPA         "WPA"
#define PROXY_PROPERTY_NAME_RSN         "RSN"
#define PROXY_PROPERTY_NAME_WPS         "WPS"
#define PROXY_PROPERTY_NAME_IES         "IEs"
#define PROXY_PROPERTY_NAME_PRIVACY     "Privacy"
#define PROXY_PROPERTY_NAME_MODE        "Mode"
#define PROXY_PROPERTY_NAME_SIGNAL      "Signal"
#define PROXY_PROPERTY_NAME_FREQUENCY   "Frequency"
#define PROXY_PROPERTY_NAME_RATES       "Rates"

/* Weak references to the instances of GSupplicantBSS */
static GHashTable* gsupplicant_bss_table = NULL;

/*==========================================================================*
 * Implementation
 *==========================================================================*/

static
void
gsupplicant_bss_connect_data_free(
    GSupplicantBSSConnectData* data)
{
    gsupplicant_bss_unref(data->bss);
    g_slice_free(GSupplicantBSSConnectData, data);
}

static
GSupplicantBSSConnectData*
gsupplicant_bss_connect_data_new(
    GSupplicantBSS* bss,
    GSupplicantBSSStringResultFunc fn,
    void* fn_data)
{
    GSupplicantBSSConnectData* data = g_slice_new0(GSupplicantBSSConnectData);
    data->fn = fn;
    data->fn_data = fn_data;
    data->bss = gsupplicant_bss_ref(bss);
    return data;
}

static
void
gsupplicant_bss_connect_free(
    gpointer data)
{
    gsupplicant_bss_connect_data_free(data);
}

static
void
gsupplicant_bss_connect_done(
    GSupplicantInterface* iface,
    GCancellable* cancel,
    const GError* error,
    const char* result,
    void* data)
{
    GSupplicantBSSConnectData* cp = data;
    cp->fn(cp->bss, cancel, error, result, cp->fn_data);
}

static
void
gsupplicant_bss_fill_network_params(
    GSupplicantBSS* bss,
    const GSupplicantBSSConnectParams* cp,
    guint flags, /* None defined yet */
    GSupplicantNetworkParams* np)
{
    memset(np, 0, sizeof(*np));
    /*
     * Ignore BSS frequency. It is ignored in the infrastructure
     * mode anyway. It's only used by the station that creates the
     * IBSS (adhoc network). If an IBSS network with the configured
     * SSID is already present, the frequency of the network will be
     * used instead of the configured value.
     *
     np->frequency = bss->frequency;
     */
    np->ssid = bss->ssid;
    np->mode = (bss->mode == GSUPPLICANT_BSS_MODE_AD_HOC) ?
        GSUPPLICANT_OP_MODE_IBSS : GSUPPLICANT_OP_MODE_INFRA;
    np->security = gsupplicant_bss_security(bss);
    np->scan_ssid = 1;
    np->eap = cp->eap;
    np->auth_flags = cp->auth_flags;
    np->bgscan = cp->bgscan;
    np->passphrase = cp->passphrase;
    np->identity = cp->identity;
    np->anonymous_identity = cp->anonymous_identity;
    np->ca_cert_file = cp->ca_cert_file;
    np->client_cert_file = cp->client_cert_file;
    np->private_key_file = cp->private_key_file;
    np->private_key_passphrase = cp->private_key_passphrase;
    np->subject_match = cp->subject_match;
    np->altsubject_match = cp->altsubject_match;
    np->domain_suffix_match = cp->domain_suffix_match;
    np->domain_match = cp->domain_match;
    np->phase2 = cp->phase2;
    np->ca_cert_file2 = cp->ca_cert_file2;
    np->client_cert_file2 = cp->client_cert_file2;
    np->private_key_file2 = cp->private_key_file2;
    np->private_key_passphrase2 = cp->private_key_passphrase2;
    np->subject_match2 = cp->subject_match2;
    np->altsubject_match2 = cp->altsubject_match2;
    np->domain_suffix_match2 = cp->domain_suffix_match2;
    np->keymgmt = gsupplicant_bss_keymgmt(bss);
}

static inline
GSUPPLICANT_BSS_PROPERTY
gsupplicant_bss_property_from_signal(
    GSUPPLICANT_BSS_SIGNAL sig)
{
    switch (sig) {
#define SIGNAL_PROPERTY_MAP_(P,p) \
    case SIGNAL_##P##_CHANGED: return GSUPPLICANT_BSS_PROPERTY_##P;
    GSUPPLICANT_BSS_PROPERTIES_(SIGNAL_PROPERTY_MAP_)
#undef SIGNAL_PROPERTY_MAP_
    default: /* unreachable */ return GSUPPLICANT_BSS_PROPERTY_ANY;
    }
}

static
void
gsupplicant_bss_signal_property_change(
    GSupplicantBSS* self,
    GSUPPLICANT_BSS_SIGNAL sig,
    GSUPPLICANT_BSS_PROPERTY prop)
{
    GSupplicantBSSPriv* priv = self->priv;
    GASSERT(prop > GSUPPLICANT_BSS_PROPERTY_ANY);
    GASSERT(prop < GSUPPLICANT_BSS_PROPERTY_COUNT);
    GASSERT(sig < G_N_ELEMENTS(gsupplicant_bss_property_quarks));
    if (!gsupplicant_bss_property_quarks[sig]) {
        char buf[SIGNAL_PROPERTY_CHANGED_DETAIL_MAX_LEN + 1];
        snprintf(buf, sizeof(buf), SIGNAL_PROPERTY_CHANGED_DETAIL, prop);
        buf[sizeof(buf)-1] = 0;
        gsupplicant_bss_property_quarks[sig] = g_quark_from_string(buf);
    }
    priv->pending_signals &= ~(1 << sig);
    g_signal_emit(self, gsupplicant_bss_signals[sig], 0);
    g_signal_emit(self, gsupplicant_bss_signals[SIGNAL_PROPERTY_CHANGED],
        gsupplicant_bss_property_quarks[sig], prop);
}

static
void
gsupplicant_bss_emit_pending_signals(
    GSupplicantBSS* self)
{
    GSupplicantBSSPriv* priv = self->priv;
    GSUPPLICANT_BSS_SIGNAL sig;
    gboolean valid_changed;

    /* Handlers could drops their references to us */
    gsupplicant_bss_ref(self);

    /* VALID is the last one to be emitted if we BECOME valid */
    if ((priv->pending_signals & SIGNAL_BIT(VALID)) && self->valid) {
        priv->pending_signals &= ~SIGNAL_BIT(VALID);
        valid_changed = TRUE;
    } else {
        valid_changed = FALSE;
    }

    /* Emit the signals. Not that in case if valid has become FALSE, then
     * VALID is emitted first, otherwise it's emitted last */
    for (sig = SIGNAL_VALID_CHANGED;
         sig < SIGNAL_PROPERTY_CHANGED && priv->pending_signals;
         sig++) {
        if (priv->pending_signals & (1 << sig)) {
            gsupplicant_bss_signal_property_change(self, sig,
                gsupplicant_bss_property_from_signal(sig));
        }
    }

    /* Then emit VALID if valid has become TRUE */
    if (valid_changed) {
        gsupplicant_bss_signal_property_change(self, SIGNAL_VALID_CHANGED,
            GSUPPLICANT_BSS_PROPERTY_VALID);
    }

    /* And release the temporary reference */
    gsupplicant_bss_unref(self);
}

static
gboolean
gsupplicant_bss_bytes_equal(
    GBytes* b1,
    GBytes* b2)
{
    if (b1 && b2) {
        return g_bytes_equal(b1, b2);
    } else {
        return (!b1 && !b2);
    }
}

static
GBytes*
gsupplicant_bss_get_bytes(
    GSupplicantBSS* self,
    const char* name)
{
    GSupplicantBSSPriv* priv = self->priv;
    if (priv->proxy) {
        GDBusProxy *proxy = G_DBUS_PROXY(priv->proxy);
        GVariant* var = g_dbus_proxy_get_cached_property(proxy, name);
        if (var && g_variant_is_of_type(var, G_VARIANT_TYPE_BYTESTRING)) {
            GBytes* bytes = gsupplicant_variant_data_as_bytes(var);
            g_variant_unref(var);
            return bytes;
        }
    }
    return NULL;
}

static
void
gsupplicant_bss_update_valid(
    GSupplicantBSS* self)
{
    GSupplicantBSSPriv* priv = self->priv;
    const gboolean valid = priv->proxy && self->iface->valid;
    if (self->valid != valid) {
        self->valid = valid;
        GDEBUG("BSS %s is %svalid", priv->path, valid ? "" : "in");
        priv->pending_signals |= SIGNAL_BIT(VALID);
    }
}

static
void
gsupplicant_bss_update_present(
    GSupplicantBSS* self)
{
    GSupplicantBSSPriv* priv = self->priv;
    const gboolean present = priv->proxy && self->iface->valid &&
        gutil_strv_contains(self->iface->bsss, priv->path);
    if (self->present != present) {
        self->present = present;
        GDEBUG("BSS %s is %spresent", priv->path, present ? "" : "not ");
        priv->pending_signals |= SIGNAL_BIT(PRESENT);
    }
}

static
void
gsupplicant_bss_update_ssid(
    GSupplicantBSS* self)
{
    GSupplicantBSSPriv* priv = self->priv;
    GBytes* ssid = gsupplicant_bss_get_bytes(self, PROXY_PROPERTY_NAME_SSID);
    if (!gsupplicant_bss_bytes_equal(self->ssid, ssid)) {
        if (self->ssid) {
            g_bytes_unref(self->ssid);
        }
        g_free(priv->ssid_str);
        if (ssid) {
            priv->ssid_str = gsupplicant_utf8_from_bytes(ssid);
            GDEBUG("[%s] " PROXY_PROPERTY_NAME_SSID ": %s \"%s\"",
                self->path, gsupplicant_format_bytes(ssid, FALSE),
                priv->ssid_str);
        } else {
            priv->ssid_str = NULL;
            GDEBUG("[%s] " PROXY_PROPERTY_NAME_SSID ": %s",
                self->path, gsupplicant_format_bytes(ssid, FALSE));
        }
        self->ssid_str = priv->ssid_str;
        self->ssid = ssid;
        priv->pending_signals |= SIGNAL_BIT(SSID);
    } else if (ssid) {
        g_bytes_unref(ssid);
    }
}

static
void
gsupplicant_bss_update_bssid(
    GSupplicantBSS* self)
{
    GSupplicantBSSPriv* priv = self->priv;
    GBytes* bssid = gsupplicant_bss_get_bytes(self, PROXY_PROPERTY_NAME_BSSID);
    if (!gsupplicant_bss_bytes_equal(self->bssid, bssid)) {
        if (self->bssid) {
            g_bytes_unref(self->bssid);
        }
        self->bssid = bssid;
        GDEBUG("[%s] " PROXY_PROPERTY_NAME_BSSID ": %s",
            self->path, gsupplicant_format_bytes(bssid, FALSE));
        priv->pending_signals |= SIGNAL_BIT(BSSID);
    } else if (bssid) {
        g_bytes_unref(bssid);
    }
}

static
void
gsupplicant_bss_parse_wpa(
    const char* name,
    GVariant* value,
    void* data)
{
    GSupplicantBSSWPA* wpa = data;
    if (!g_strcmp0(name, "KeyMgmt")) {
        wpa->keymgmt = gsupplicant_parse_keymgmt_list(name, value);
    } else if (!g_strcmp0(name, "Pairwise")) {
        wpa->pairwise = gsupplicant_parse_cipher_list(name, value);
    } else if (!g_strcmp0(name, "Group")) {
        wpa->group = gsupplicant_parse_cipher_value(name, value);
    } else {
        GWARN("Unexpected WPA dictionary key %s", name);
    }
}

static
void
gsupplicant_bss_update_wpa(
    GSupplicantBSS* self)
{
    GSupplicantBSSPriv* priv = self->priv;
    const GSupplicantBSSWPA wpa = priv->wpa;
    GVariant* dict;
    memset(&priv->wpa, 0, sizeof(priv->wpa));
    GVERBOSE("[%s] WPA:", self->path);
    dict = fi_w1_wpa_supplicant1_bss_get_wpa(priv->proxy);
    gsupplicant_dict_parse(dict, gsupplicant_bss_parse_wpa, &priv->wpa);
    if (dict) {
        if (self->wpa) {
            if (memcmp(&wpa, &priv->wpa, sizeof(wpa))) {
                priv->pending_signals |= SIGNAL_BIT(WPA);
            }
        } else {
            priv->pending_signals |= SIGNAL_BIT(WPA);
        }
        self->wpa = &priv->wpa;
    } else if (self->wpa) {
        self->wpa = NULL;
        priv->pending_signals |= SIGNAL_BIT(WPA);
    }
}

static
void
gsupplicant_bss_parse_rsn(
    const char* name,
    GVariant* value,
    void* data)
{
    GSupplicantBSSRSN* rsn = data;
    if (!g_strcmp0(name, "KeyMgmt")) {
        rsn->keymgmt = gsupplicant_parse_keymgmt_list(name, value);
    } else if (!g_strcmp0(name, "Pairwise")) {
        rsn->pairwise = gsupplicant_parse_cipher_list(name, value);
    } else if (!g_strcmp0(name, "Group")) {
        rsn->group = gsupplicant_parse_cipher_value(name, value);
    } else if (!g_strcmp0(name, "MgmtGroup")) {
        rsn->mgmt_group = gsupplicant_parse_cipher_value(name, value);
    } else {
        GWARN("Unexpected RSN dictionary key %s", name);
    }
}

static
void
gsupplicant_bss_update_rsn(
    GSupplicantBSS* self)
{
    GSupplicantBSSPriv* priv = self->priv;
    const GSupplicantBSSRSN rsn = priv->rsn;
    GVariant* dict;
    memset(&priv->rsn, 0, sizeof(priv->rsn));
    GVERBOSE("[%s] RSN:", self->path);
    dict = fi_w1_wpa_supplicant1_bss_get_rsn(priv->proxy);
    gsupplicant_dict_parse(dict, gsupplicant_bss_parse_rsn, &priv->rsn);
    if (dict) {
        if (self->rsn) {
            if (memcmp(&rsn, &priv->rsn, sizeof(rsn))) {
                priv->pending_signals |= SIGNAL_BIT(RSN);
            }
        } else {
            priv->pending_signals |= SIGNAL_BIT(RSN);
        }
        self->rsn = &priv->rsn;
    } else if (self->rsn) {
        self->rsn = NULL;
        priv->pending_signals |= SIGNAL_BIT(RSN);
    }
}

#if GUTIL_LOG_VERBOSE
static
const char*
gsupplicant_bss_wps_oui_type_name(
    guint type)
{
    switch (type) {
    case WPS_TLV_VERSION:   return "version";
    case WPS_TLV_STATE:     return "state";
    case WPS_TLV_METHOD:    return "method";
    case WPS_TLV_REGISTRAR: return "registrar";
    default:                return NULL;
    }
}
#endif /* GUTIL_LOG_VERBOSE */

static
gboolean
gsupplicant_bss_parse_wps_oui(
    const guint8* ie,
    guint len,
    GSupplicantWPSInfo* wps)
{
    const guint8* end = ie + len;
    memset(wps, 0, sizeof(*wps));
    while (ie + 4 <= end) {
        /* Parse and skip the header */
        const guint v_type = (ie[0] << 8) + ie[1];
        const guint v_len = (ie[2] << 8) + ie[3];
        ie += 4;

        /* The data */
        if (v_len <= 4 && ie + v_len <= end) {
            guint32* data;
            guint32 tmp;
            guint flag;
            switch (v_type) {
            case WPS_TLV_VERSION:
                flag = WPS_INFO_VERSION;
                data = &wps->version;
                break;
            case WPS_TLV_STATE:
                flag = WPS_INFO_STATE;
                data = &wps->state;
                break;
            case WPS_TLV_METHOD:
                flag = WPS_INFO_METHODS;
                data = &tmp;
                break;
            case WPS_TLV_REGISTRAR:
                flag = WPS_INFO_REGISTRAR;
                data = &wps->registrar;
                break;
            default:
                data = NULL;
                break;
            }
            if (data) {
                guint i;
                *data = 0;
                for (i=0; i<v_len; i++) {
                    *data = ((*data) << 8) | ie[i];
                }
                wps->flags |= flag;
                GVERBOSE_("0x%04x (%s): 0x%02x", v_type,
                    gsupplicant_bss_wps_oui_type_name(v_type), *data);
                if (v_type == WPS_TLV_METHOD) {
                    switch (tmp) {
                    case WPS_METHOD_PIN:
                        wps->methods |= WPS_METHODS_PIN;
                        break;
                    case WPS_METHOD_PUSH_BUTTON:
                        wps->methods |= WPS_METHODS_BUTTON;
                        break;
                    default:
                        break;
                    }
                }
            }
        }

        /* Advance to the next element */
        ie += v_len;
    }
    GASSERT(ie == end);
    return (ie == end);
}

static
GSUPPLICANT_WPS_CAPS
gsupplicant_bss_parse_ies(
    GBytes* ies)
{
    GSUPPLICANT_WPS_CAPS wps_caps = GSUPPLICANT_WPS_NONE;
    gsize len = 0;
    const guint8 *ie = NULL;
    if (ies) {
        ie = g_bytes_get_data(ies, &len);
    }
    if (len >= 2) {
        const guint8 *end = ie + len;
        while (ie + 1 < end && (ie + 1 + ie[1]) < end) {
            static const guint8 WPS_OUI[] = {WMM_WPA1_WPS_OUI};
            if (ie[0] == WMM_WPA1_WPS_INFO && ie[1] >= sizeof(WPS_OUI) &&
                !memcmp(ie + 2, WPS_OUI, sizeof(WPS_OUI))) {
                GSupplicantWPSInfo wps;
                GVERBOSE_("found WPS_OUI (%u bytes)", ie[1]);
                /* Version and state fields are mandatory */
                if (gsupplicant_bss_parse_wps_oui(ie + 6, ie[1] - 4, &wps) &&
                    (wps.flags & WPS_INFO_REQUIRED) == WPS_INFO_REQUIRED &&
                    wps.version == WPS_VERSION) {
                    wps_caps |= GSUPPLICANT_WPS_SUPPORTED;
                    if (wps.state == WPS_STATE_CONFIGURED) {
                        wps_caps |= GSUPPLICANT_WPS_CONFIGURED;
                    }
                    if (wps.registrar) {
                        wps_caps |= GSUPPLICANT_WPS_REGISTRAR;
                    }
                    if (wps.flags & WPS_INFO_METHODS) {
                        if (wps.methods & WPS_METHODS_PIN) {
                            wps_caps |= GSUPPLICANT_WPS_PIN;
                            GVERBOSE_("WPS method: pin");
                        }
                        if (wps.methods & WPS_METHODS_BUTTON) {
                            wps_caps |= GSUPPLICANT_WPS_PUSH_BUTTON;
                            GVERBOSE_("WPS method: button");
                        }
                    } else {
                        /* Assuming push and pin */
                        GVERBOSE_("WPS methods: assuming pin+push");
                        wps_caps |= GSUPPLICANT_WPS_PIN |
                            GSUPPLICANT_WPS_PUSH_BUTTON;
                    }
                }
            }
            ie += ie[1] + 2;
        }
    }
    return wps_caps;
}

static
void
gsupplicant_bss_update_ies(
    GSupplicantBSS* self)
{
    GSupplicantBSSPriv* priv = self->priv;
    GBytes* ies = gsupplicant_bss_get_bytes(self, PROXY_PROPERTY_NAME_IES);
    if (!gsupplicant_bss_bytes_equal(self->ies, ies)) {
        const GSUPPLICANT_WPS_CAPS wps_caps = gsupplicant_bss_parse_ies(ies);
        if (self->ies) {
            g_bytes_unref(self->ies);
        }
        self->ies = ies;
        GVERBOSE("[%s] " PROXY_PROPERTY_NAME_IES ": %s",
            self->path, gsupplicant_format_bytes(ies, FALSE));
        priv->pending_signals |= SIGNAL_BIT(IES);
        if (self->wps_caps != wps_caps) {
            self->wps_caps = wps_caps;
            GDEBUG("[%s] WPS caps 0x%02x", self->path, wps_caps);
            priv->pending_signals |= SIGNAL_BIT(WPS_CAPS);
        }
    } else if (ies) {
        g_bytes_unref(ies);
    }
}

static
void
gsupplicant_bss_update_privacy(
    GSupplicantBSS* self)
{
    GSupplicantBSSPriv* priv = self->priv;
    gboolean privacy = fi_w1_wpa_supplicant1_bss_get_privacy(priv->proxy);
    if (self->privacy != privacy) {
        self->privacy = privacy;
        GVERBOSE("[%s] %s: %s", self->path, PROXY_PROPERTY_NAME_PRIVACY,
            privacy ? "yes" : "no");
        priv->pending_signals |= SIGNAL_BIT(PRIVACY);
    }
}

static
void
gsupplicant_bss_update_mode(
    GSupplicantBSS* self)
{
    static const GSupNameIntPair mode_map [] = {
        { "infrastructure", GSUPPLICANT_BSS_MODE_INFRA  },
        { "ad-hoc",         GSUPPLICANT_BSS_MODE_AD_HOC },
    };
    GSupplicantBSSPriv* priv = self->priv;
    GSUPPLICANT_BSS_MODE mode = GSUPPLICANT_BSS_MODE_UNKNOWN;
    const char* name = fi_w1_wpa_supplicant1_bss_get_mode(priv->proxy);
    const GSupNameIntPair* pair = gsupplicant_name_int_find_name_i(name,
        mode_map, G_N_ELEMENTS(mode_map));
    if (pair) {
        mode = pair->value;
    }
    if (self->mode != mode) {
        self->mode = mode;
        GVERBOSE("[%s] %s: %s", self->path, PROXY_PROPERTY_NAME_MODE, name);
        priv->pending_signals |= SIGNAL_BIT(MODE);
    }
}

static
void
gsupplicant_bss_update_signal(
    GSupplicantBSS* self)
{
    GSupplicantBSSPriv* priv = self->priv;
    const gint sig = fi_w1_wpa_supplicant1_bss_get_signal(priv->proxy);
    if (self->signal != sig) {
        self->signal = sig;
        GVERBOSE("[%s] %s: %d", self->path, PROXY_PROPERTY_NAME_SIGNAL, sig);
        priv->pending_signals |= SIGNAL_BIT(SIGNAL);
    }
}

static
void
gsupplicant_bss_update_frequency(
    GSupplicantBSS* self)
{
    GSupplicantBSSPriv* priv = self->priv;
    const guint f = fi_w1_wpa_supplicant1_bss_get_frequency(priv->proxy);
    if (self->frequency != f) {
        self->frequency = f;
        GVERBOSE("[%s] %s: %u", self->path, PROXY_PROPERTY_NAME_FREQUENCY, f);
        priv->pending_signals |= SIGNAL_BIT(FREQUENCY);
    }
}

static
void
gsupplicant_bss_clear_rates(
    GSupplicantBSS* self)
{
    GSupplicantBSSPriv* priv = self->priv;
    if (self->rates) {
        self->rates = NULL;
        memset(&priv->rates, 0, sizeof(priv->rates));
        g_free(priv->rates_values);
        priv->rates_values = NULL;
        priv->pending_signals |= SIGNAL_BIT(RATES);
        GVERBOSE("[%s] %s: <null>", self->path, PROXY_PROPERTY_NAME_RATES);
    }
    if (self->maxrate) {
        self->maxrate = 0;
        priv->pending_signals |= SIGNAL_BIT(MAXRATE);
    }
}

static void handle_legacy(GSupplicantBSS* self, const guint *values, gsize n)
{
    GSupplicantBSSPriv* priv = self->priv;

    if (priv->rates.count != n ||
        memcmp(priv->rates.values, values, sizeof(guint)*n)) {
        guint i, maxrate = 0;

        /* Store the rates */
        g_free(priv->rates_values);
        priv->rates_values = gutil_memdup(values, sizeof(guint)*n);
        priv->rates.values = priv->rates_values;
        priv->rates.count = n;
        self->rates = &priv->rates;
        priv->pending_signals |= SIGNAL_BIT(RATES);

        /* Update the maximum rate */
        for (i=0; i<n; i++) {
            if (maxrate < values[i]) {
                maxrate = values[i];
            }
        }
        if (self->maxrate != maxrate) {
            self->maxrate = maxrate;
            priv->pending_signals |= SIGNAL_BIT(MAXRATE);
        }
    }
}

#include <stdint.h>
#include <glib.h>

typedef struct {
    gboolean ht;           /* 802.11n support */
    gboolean vht;          /* 802.11ac support */
    gboolean he;           /* 802.11ax support */

    guint8 nss;            /* Number of spatial streams (1-8) */
    guint8 mcs_index;      /* Maximum MCS index */
                           /* HT: 0-31 (NSS * 8 + MCS within NSS) */
                           /* VHT: 0-9 per NSS */
                           /* HE: 0-11 per NSS */

    guint width;           /* Channel width: 20/40/80/160 MHz */
    gboolean short_gi;     /* Short Guard Interval support */
} gsupplicant_wifi_capability_t;

/* HT Capabilities IE (802.11n) - IE type 45 */
typedef struct {
    uint16_t capabilities;      /* Offset 0-1 */
    uint8_t ampdu_params;       /* Offset 2 */
    uint8_t mcs_set[16];        /* Offset 3-18: MCS 0-127 support */
    uint16_t ht_extended_cap;   /* Offset 19-20 */
    uint32_t tx_beamform_cap;   /* Offset 21-24 */
    uint8_t asel_cap;           /* Offset 25 */
} ht_cap_t;

/* HT Operation IE (802.11n) - IE type 61 */
typedef struct {
    uint8_t primary_channel;    /* Offset 0 */
    uint8_t ht_param;           /* Offset 1: bit 2 = secondary channel offset */
    uint16_t ht_operation_1;    /* Offset 2-3 */
    uint16_t ht_operation_2;    /* Offset 4-5 */
    uint16_t ht_operation_3;    /* Offset 6-7 */
    uint8_t mcs_set[16];        /* Offset 8-23: Basic MCS Set */
} ht_oper_t;

/* VHT Capabilities IE (802.11ac) - IE type 191 */
typedef struct {
    uint32_t vht_capabilities;  /* Offset 0-3: capability bits */
    uint16_t mcs_nss_set;       /* Offset 4-11: MCS set per NSS (RX) */
    uint16_t rx_mcs_map;        /* RX MCS map */
    uint16_t rx_highest_rate;   /* RX highest rate */
    uint16_t tx_mcs_map;        /* TX MCS map */
    uint16_t tx_highest_rate;   /* TX highest rate */
} vht_cap_t;

/* VHT Operation IE (802.11ac) - IE type 192 */
typedef struct {
    uint8_t channel_width;      /* Offset 0: 0=20/40, 1=80, 2=160, 3=80+80 */
    uint8_t channel_cf1;        /* Offset 1: Center frequency segment 1 */
    uint8_t channel_cf2;        /* Offset 2: Center frequency segment 2 */
    uint16_t mcs_nss_set;       /* Offset 3-4: Basic MCS-NSS set */
} vht_oper_t;

/* HE Capabilities IE (802.11ax) - IE type 255, extension 35 */
typedef struct {
    uint8_t mac_cap[6];         /* Offset 0-5: MAC capabilities */
    uint8_t phy_cap[11];        /* Offset 6-16: PHY capabilities */
    /* MCS-NSS set follows: variable length depending on bandwidth support */
} he_cap_t;

/* HE Operation IE (802.11ax) - IE type 255, extension 36 */
typedef struct {
    uint8_t oper_param[3];      /* Offset 0-2: VHT operation info + HE operation info */
    uint16_t mcs_nss_set;       /* Offset 3-4: Basic MCS-NSS set */
} he_oper_t;

/**
 * Extract Short GI support from HT Capabilities
 *
 * HT Capabilities (IE 45):
 * - Byte 0-1: HT Capabilities Info
 *   - Bit 5: Short GI for 20 MHz
 *   - Bit 6: Short GI for 40 MHz
 *
 * Returns TRUE if Short GI is supported for the current width
 */
static gboolean
ht_parse_short_gi(const uint8_t *ie, gsize len, guint channel_width)
{
    const ht_cap_t *ht_cap;

    if (len < sizeof(ht_cap_t))
        return FALSE;

    ht_cap = (const ht_cap_t *)ie;
    uint16_t cap_info =
        (uint16_t)ie[0] |
        ((uint16_t)ie[1] << 8);

    if (channel_width == 20) {
        return (cap_info & 0x20) ? TRUE : FALSE;  /* Bit 5 */
    } else if (channel_width == 40) {
        return (cap_info & 0x40) ? TRUE : FALSE;  /* Bit 6 */
    }

    return FALSE;
}

/**
 * Extract maximum MCS index from HT Capabilities
 *
 * The MCS Set field (Offset 3-18) contains 16 bytes:
 * - Bytes 0-3: Supported MCS for spatial stream 1-4
 * - Byte 12 (bit 0-1): RX highest data rate
 *
 * Returns the highest MCS index (0-31), or -1 on error
 */
static gint
ht_parse_max_mcs(const uint8_t *ie, gsize len, guint8 *out_nss)
{
    const ht_cap_t *ht_cap;
    guint8 nss = 0;
    gint max_mcs_idx = -1;

    if (len < sizeof(ht_cap_t))
        return -1;

    ht_cap = (const ht_cap_t *)ie;

    /* Parse MCS set to find highest supported MCS per spatial stream */
    for (int stream = 0; stream < 4; stream++) {
        guint8 mcs_byte = ht_cap->mcs_set[stream];

        if (mcs_byte == 0)
            continue;

        nss = stream + 1;

        /* Find highest bit set in this MCS byte */
        for (int i = 7; i >= 0; i--) {
            if (mcs_byte & (1 << i)) {
                gint this_mcs = (stream * 8) + i;
                if (this_mcs > max_mcs_idx) {
                    max_mcs_idx = this_mcs;
                }
                break;
            }
        }
    }

    *out_nss = nss;
    return max_mcs_idx;
}

/**
 * Parse HT Capabilities IE (type 45)
 *
 * Fixed length: 26 bytes
 */
static void
parse_ht_capabilities(const uint8_t *ie, gsize len,
                      gsupplicant_wifi_capability_t *cap)
{
    guint8 nss = 0;
    gint mcs_idx;

    if (len < 26) {
        GVERBOSE_("HT Capabilities IE too short: %zu bytes", len);
        return;
    }

    cap->ht = TRUE;

    /* Extract maximum MCS index */
    mcs_idx = ht_parse_max_mcs(ie, len, &nss);
    if (mcs_idx >= 0) {
        cap->nss = nss;
        cap->mcs_index = (guint8)mcs_idx;
        GVERBOSE_("HT: NSS=%u, MCS=%u", nss, cap->mcs_index);
    } else {
        cap->nss = 1;
        cap->mcs_index = 7;  /* Fallback to MCS7 (safest) */
        GVERBOSE_("HT: Could not parse MCS, using fallback MCS7");
    }

    /* Short GI will be determined after width is known */
}

/**
 * Parse HT Operation IE (type 61)
 *
 * Variable length, minimum 5 bytes for 20 MHz, typically 22 bytes with MCS set
 *
 * Channel width info:
 * - Offset 1, Bit 2: Secondary Channel Offset
 *   - 0 = No secondary channel
 *   - 1 = Secondary channel above primary
 *   - 3 = Secondary channel below primary
 */
static void
parse_ht_operation(const uint8_t *ie, gsize len,
                   gsupplicant_wifi_capability_t *cap)
{
    const ht_oper_t *ht_oper;

    if (len < 5) {
        GVERBOSE_("HT Operation IE too short: %zu bytes", len);
        return;
    }

    ht_oper = (const ht_oper_t *)ie;
    uint8_t ht_param = ht_oper->ht_param;

    /* Bit 2: Secondary Channel Offset */
    uint8_t sec_channel = (ht_param >> 2) & 0x03;

    if (sec_channel == 0) {
        cap->width = 20;
    } else {
        cap->width = 40;
    }

    GVERBOSE_("HT Operation: width=%u MHz", cap->width);
}

/**
 * Extract Short GI support from VHT Capabilities
 *
 * VHT Capabilities (IE 191):
 * - Byte 0-3: VHT Capability Info
 *   - Bit 5: Short GI for 80 MHz
 *   - Bit 6: Short GI for 160 and 80+80 MHz
 *
 * Returns TRUE if Short GI is supported for the current width
 */
static gboolean
vht_parse_short_gi(const uint8_t *ie, gsize len, guint channel_width)
{
    const vht_cap_t *vht_cap;

    if (len < 4)
        return FALSE;

    vht_cap = (const vht_cap_t *)ie;
    uint32_t cap_info = vht_cap->vht_capabilities;

    if (channel_width == 80) {
        return (cap_info & 0x20) ? TRUE : FALSE;  /* Bit 5 */
    } else if (channel_width == 160) {
        return (cap_info & 0x40) ? TRUE : FALSE;  /* Bit 6 */
    }

    return FALSE;
}

/**
 * Parse VHT MCS-NSS Set
 *
 * Each 2-byte MCS-NSS Set contains 8 entries (2 bits each) for MCS 0-7:
 * - 0 = MCS 0-7 supported
 * - 1 = MCS 0-8 supported
 * - 2 = MCS 0-9 supported
 * - 3 = Not supported
 *
 * Iterates through all spatial streams to find maximum MCS supported
 */
static guint8
vht_parse_max_mcs(const uint8_t *ie, gsize len, guint8 *out_nss)
{
    const vht_cap_t *vht_cap;
    guint8 max_mcs = 0;
    guint8 nss = 0;

    if (len < 12)
        return 0;

    vht_cap = (const vht_cap_t *)ie;

    /* Parse RX MCS map (2 bytes) to find maximum MCS per NSS */
    uint16_t mcs_map = vht_cap->rx_mcs_map | (vht_cap->rx_highest_rate & 0x03) << 14;

    for (int ss = 0; ss < 8; ss++) {
        uint8_t mcs_support = (mcs_map >> (ss * 2)) & 0x03;

        if (mcs_support == 3)  /* Not supported */
            continue;

        nss = ss + 1;

        /* Convert MCS support level to actual MCS index */
        switch (mcs_support) {
        case 0:
            max_mcs = 7;
            break;
        case 1:
            max_mcs = 8;
            break;
        case 2:
            max_mcs = 9;
            break;
        }
    }

    *out_nss = nss;
    return max_mcs;
}

/**
 * Parse VHT Capabilities IE (type 191)
 *
 * Fixed length: 12 bytes
 */
static void
parse_vht_capabilities(const uint8_t *ie, gsize len,
                       gsupplicant_wifi_capability_t *cap)
{
    guint8 nss = 0;

    if (len < 12) {
        GVERBOSE_("VHT Capabilities IE too short: %zu bytes", len);
        return;
    }

    cap->vht = TRUE;

    /* Extract maximum MCS index */
    cap->mcs_index = vht_parse_max_mcs(ie, len, &nss);
    cap->nss = nss;

    GVERBOSE_("VHT: NSS=%u, MCS=%u", nss, cap->mcs_index);

    /* Short GI will be determined after width is known */
}

/**
 * Parse VHT Operation IE (type 192)
 *
 * Fixed length: 5 bytes
 *
 * Channel width:
 * - Offset 0: Channel Width field
 *   - 0 = 20 or 40 MHz (use HT operation for distinction)
 *   - 1 = 80 MHz
 *   - 2 = 160 MHz
 *   - 3 = 80+80 MHz (not fully supported here)
 */
static void
parse_vht_operation(const uint8_t *ie, gsize len,
                    gsupplicant_wifi_capability_t *cap)
{
    const vht_oper_t *vht_oper;

    if (len < 5) {
        GVERBOSE_("VHT Operation IE too short: %zu bytes", len);
        return;
    }

    vht_oper = (const vht_oper_t *)ie;
    uint8_t channel_width = vht_oper->channel_width;

    switch (channel_width) {
    case 0:
        /* Fall back to HT operation for 20/40 MHz determination */
        if (cap->width == 0)
            cap->width = 80;  /* VHT default if HT not parsed */
        break;
    case 1:
        cap->width = 80;
        break;
    case 2:
        cap->width = 160;
        break;
    case 3:
        /* 80+80 MHz - report as 160 for rate calculation */
        cap->width = 160;
        GVERBOSE_("VHT: 80+80 MHz detected (reported as 160)");
        break;
    default:
        GVERBOSE_("VHT: Invalid channel width %u", channel_width);
        break;
    }

    GVERBOSE_("VHT Operation: width=%u MHz", cap->width);
}

/**
 * Parse HE Capabilities IE (802.11ax - IE type 255, extension 35)
 *
 * Variable length, minimum 21 bytes (MAC cap 6 + PHY cap 11 + minimal MCS-NSS)
 *
 * PHY Capabilities (offset 6-16, 11 bytes):
 * - Byte 8, Bit 1: Short GI for 80 MHz
 * - Byte 8, Bit 2: Short GI for 160 MHz
 *
 * MCS-NSS Set (offset 17+):
 * - Varies by bandwidth support in PHY capabilities
 * - Minimum: 4 bytes (80 MHz only)
 * - Maximum: 12 bytes (20/40/80/160 MHz)
 */
static void
parse_he_capabilities(const uint8_t *ie, gsize len,
                      gsupplicant_wifi_capability_t *cap)
{
    const he_cap_t *he_cap;
    guint8 best_mcs = 0;
    guint8 best_nss = 1;

    if (len < 21) {
        GVERBOSE_("HE Capabilities IE too short: %zu bytes", len);
        return;
    }

    cap->he = TRUE;
    he_cap = (const he_cap_t *)ie;

    /* Parse HE-MCS-NSS set - first set is for 80 MHz (mandatory) */
    /* MCS-NSS set structure: 2 bytes per NSS, 8 NSS entries = 16 bytes minimum */
    if (len >= 37) {
        /* Parse 80 MHz MCS-NSS set (mandatory, at offset 17) */
        const uint8_t *mcs_set = &ie[17];

        for (int ss = 0; ss < 8; ss++) {
            /* 2-bit MCS index per NSS */
            uint8_t mcs_idx = (mcs_set[ss >> 2] >> ((ss & 3) * 2)) & 0x03;

            if (mcs_idx == 3)  /* Not supported */
                continue;

            best_nss = ss + 1;

            /* Map 802.11ax MCS levels (0-2) to MCS indices (0-11) */
            /* HE supports MCS 0-11 (vs VHT's 0-9) */
            switch (mcs_idx) {
            case 0:
                best_mcs = 7;
                break;
            case 1:
                best_mcs = 10;
                break;
            case 2:
                best_mcs = 11;
                break;
            }
        }
    }

    cap->nss = best_nss;
    cap->mcs_index = best_mcs;

    GVERBOSE_("HE: NSS=%u, MCS=%u", best_nss, best_mcs);

    /* HE operation will determine width, default to 80 MHz */
    if (cap->width == 0)
        cap->width = 80;
}

/**
 * Parse HE Operation IE (802.11ax - IE type 255, extension 36)
 *
 * Variable length, minimum 5 bytes
 *
 * Channel width info in HE Operation Parameter (offset 0-2):
 * - This is complex and band-dependent (2.4/5/6 GHz)
 * - For 5 GHz: Similar to VHT operation
 */
static void
parse_he_operation(const uint8_t *ie, gsize len,
                   gsupplicant_wifi_capability_t *cap)
{
    const he_oper_t *he_oper;

    if (len < 5) {
        GVERBOSE_("HE Operation IE too short: %zu bytes", len);
        return;
    }

    he_oper = (const he_oper_t *)ie;

    /* HE Operation Parameter field (byte 0-2) is complex and band-dependent */
    /* For simplification, use VHT-like width determination if available */
    /* In real implementation, parse VHT Operation Info within HE Operation */

    /* Default has been set to 80 MHz in HE capabilities parsing */
    GVERBOSE_("HE Operation: width=%u MHz (from capabilities)", cap->width);
}

/**
 * Compute 802.11n/ac/ax PHY rate from parsed capabilities
 *
 * Returns rate in bps (not Mbps!)
 *
 * IMPORTANT: mcs_index_rates contains rates in Mbps as floats
 * We multiply by 1,000,000 to convert to bps
 */
static guint
compute_phy_rate(const gsupplicant_wifi_capability_t *cap)
{
    float rate_mbps = 0.0f;
    int gi_idx;
    int width_idx;

    /* Determine Guard Interval index (0 = long, 1 = short) */
    gi_idx = cap->short_gi ? 1 : 0;

    /* Determine width index for rate lookup table */
    switch (cap->width) {
    case 20:
        width_idx = 0;
        break;
    case 40:
        width_idx = 1;
        break;
    case 80:
        width_idx = 2;
        break;
    case 160:
        width_idx = 3;
        break;
    default:
        GVERBOSE_("Invalid channel width: %u", cap->width);
        return 0;
    }

    /* Lookup rate based on standard type and parameters */
    if (cap->he) {
        /* HE uses same table as VHT for compatibility */
        if (cap->mcs_index <= 11 && cap->nss >= 1 && cap->nss <= 8) {
            rate_mbps = get_80211ac_rate(cap->width, gi_idx,
                cap->mcs_index > 9 ? 9 : cap->mcs_index,  /* Cap to VHT max */
                cap->nss);
        }
    } else if (cap->vht) {
        if (cap->mcs_index <= 9 && cap->nss >= 1 && cap->nss <= 8) {
            rate_mbps = get_80211ac_rate(cap->width, gi_idx,
                cap->mcs_index, cap->nss);
        }
    } else if (cap->ht) {
        /* HT MCS index is 0-31 (NSS * 8 + MCS) */
        if (cap->mcs_index <= 31) {
            rate_mbps = get_80211n_rate(cap->width, gi_idx,
                cap->mcs_index);
        }
    }

    if (rate_mbps <= 0) {
        GVERBOSE_("Rate lookup failed: HT=%d VHT=%d HE=%d MCS=%u NSS=%u",
            cap->ht, cap->vht, cap->he, cap->mcs_index, cap->nss);
        return 0;
    }

    /* Convert Mbps to bps */
    return (guint)(rate_mbps * 1000000.0f);
}

/**
 * Parse all Information Elements from IEs buffer
 *
 * Processes HT/VHT/HE capabilities and operation IEs
 * to determine maximum rate, MCS, NSS, and channel width
 *
 * Returns computed PHY rate in bps
 */
guint
gsupplicant_bss_parse_ies_for_rate(const guint8 *ies, gsize ies_len)
{
    gsupplicant_wifi_capability_t cap = {0};
    gsize i = 0;

    if (!ies || ies_len < 2) {
        GVERBOSE_("Invalid IEs buffer");
        return 0;
    }

    /* Iterate through Information Elements */
    while (i + 2 <= ies_len) {
        uint8_t ie_type = ies[i];
        uint8_t ie_len = ies[i + 1];
        const uint8_t *ie_data = &ies[i + 2];

        /* Validate IE length */
        if (i + 2 + ie_len > ies_len) {
            GVERBOSE_("IE truncated at offset %zu", i);
            break;
        }

        GVERBOSE_("IE type=%u len=%u", ie_type, ie_len);

        switch (ie_type) {
        case 45:  /* HT Capabilities */
            parse_ht_capabilities(ie_data, ie_len, &cap);
            break;

        case 61:  /* HT Operation */
            parse_ht_operation(ie_data, ie_len, &cap);
            break;

        case 191:  /* VHT Capabilities */
            parse_vht_capabilities(ie_data, ie_len, &cap);
            break;

        case 192:  /* VHT Operation */
            parse_vht_operation(ie_data, ie_len, &cap);
            break;

        case 255:  /* Extension IE */
            if (ie_len > 0) {
                uint8_t ext_type = ie_data[0];

                if (ext_type == 35) {  /* HE Capabilities */
                    parse_he_capabilities(ie_data, ie_len, &cap);
                } else if (ext_type == 36) {  /* HE Operation */
                    parse_he_operation(ie_data, ie_len, &cap);
                }
            }
            break;

        default:
            break;
        }

        i += 2 + ie_len;
    }

    /* Determine Short GI based on final width */
    if (cap.width > 0) {
        if (cap.vht || cap.he) {
            cap.short_gi = vht_parse_short_gi(ies, ies_len, cap.width);
        } else if (cap.ht) {
            cap.short_gi = ht_parse_short_gi(ies, ies_len, cap.width);
        }
    }

    /* Log final capabilities */
    GVERBOSE_("Final: HT=%d VHT=%d HE=%d Width=%u MCS=%u NSS=%u SGI=%d",
        cap.ht, cap.vht, cap.he, cap.width, cap.mcs_index, cap.nss, cap.short_gi);

    /* Compute and return rate */
    return compute_phy_rate(&cap);
}


static void
store_rates(GSupplicantBSS* self,
            const guint *rates,
            gsize count)
{
    GSupplicantBSSPriv* priv = self->priv;

    g_free(priv->rates_values);

    priv->rates_values =
        gutil_memdup(rates, sizeof(guint) * count);

    priv->rates.values = priv->rates_values;
    priv->rates.count = count;

    self->rates = &priv->rates;

    priv->pending_signals |= SIGNAL_BIT(RATES);
}

static void update_maxrate(GSupplicantBSS* self, guint maxrate)
{
    GSupplicantBSSPriv* priv = self->priv;

    if (self->maxrate != maxrate) {
        self->maxrate = maxrate;
        priv->pending_signals |= SIGNAL_BIT(MAXRATE);
    }
}

/**
 * CORRECTED VERSION: Parse and compute PHY rate from IEs
 * 
 * This replaces the flawed handle_ies() and related functions
 */
static void
gsupplicant_bss_update_rates(
    GSupplicantBSS* self)
{
    GSupplicantBSSPriv* priv = self->priv;
    GVariant* value;
    guint new_rate = 0;

    /* Get IEs from BSS proxy */
    value = fi_w1_wpa_supplicant1_bss_dup_ies(priv->proxy);
    if (value) {
        gsize n = 0;
        const guint8* ies_data;

        if (g_variant_is_of_type(value, G_VARIANT_TYPE_VARIANT)) {
            GVariant* tmp = g_variant_get_variant(value);
            g_variant_unref(value);
            value = tmp;
        }

        /* Extract IEs as byte array */
        ies_data = g_variant_get_fixed_array(value, &n, sizeof(guint8));
        if (ies_data && n > 0) {
            /* Parse IEs and compute rate */
            new_rate = gsupplicant_bss_parse_ies_for_rate(ies_data, n);

            if (new_rate == 0) {
                GVERBOSE_("[%s] Could not determine rate from IEs, clearing rates",
                    self->path);
                gsupplicant_bss_clear_rates(self);
            } else {
                /* Store the computed rate */
                guint rates[1] = { new_rate };

                if (priv->rates.count != 1 ||
                    memcmp(priv->rates.values, rates, sizeof(guint))) {

                    g_free(priv->rates_values);
                    priv->rates_values = gutil_memdup(rates, sizeof(guint));
                    priv->rates.values = priv->rates_values;
                    priv->rates.count = 1;
                    self->rates = &priv->rates;
                    priv->pending_signals |= SIGNAL_BIT(RATES);

                    update_maxrate(self, new_rate);

                    GVERBOSE_("[%s] %s: %u bps (%.1f Mbps)", self->path,
                        PROXY_PROPERTY_NAME_RATES, new_rate, new_rate / 1000000.0f);
                }
            }

            g_variant_unref(value);
        } else {
            gsupplicant_bss_clear_rates(self);
        }
    } else {
        gsupplicant_bss_clear_rates(self);
    }
}

static
void
gsupplicant_bss_proxy_gproperties_changed(
    GDBusProxy* proxy,
    GVariant* changed,
    GStrv invalidated,
    gpointer data)
{
    GSupplicantBSS* self = GSUPPLICANT_BSS(data);
    GSupplicantBSSPriv* priv = self->priv;
    if (invalidated) {
        char** ptr;
        for (ptr = invalidated; *ptr; ptr++) {
            const char* name = *ptr;
            if (!strcmp(name, PROXY_PROPERTY_NAME_SSID)) {
                if (self->ssid) {
                    g_bytes_unref(self->ssid);
                    g_free(priv->ssid_str);
                    self->ssid = NULL;
                    self->ssid_str = priv->ssid_str = NULL;
                    priv->pending_signals |= SIGNAL_BIT(SSID);
                }
            } else if (!strcmp(name, PROXY_PROPERTY_NAME_BSSID)) {
                if (self->bssid) {
                    g_bytes_unref(self->bssid);
                    self->bssid = NULL;
                    priv->pending_signals |= SIGNAL_BIT(BSSID);
                }
            } else if (!strcmp(name, PROXY_PROPERTY_NAME_WPA)) {
                if (self->wpa) {
                    self->wpa = NULL;
                    priv->pending_signals |= SIGNAL_BIT(WPA);
                }
            } else if (!strcmp(name, PROXY_PROPERTY_NAME_RSN)) {
                if (self->rsn) {
                    self->rsn = NULL;
                    priv->pending_signals |= SIGNAL_BIT(RSN);
                }
            } else if (!strcmp(name, PROXY_PROPERTY_NAME_IES)) {
                if (self->ies) {
                    g_bytes_unref(self->ies);
                    self->ies = NULL;
                    priv->pending_signals |= SIGNAL_BIT(IES);
                }
            } else if (!strcmp(name, PROXY_PROPERTY_NAME_PRIVACY)) {
                if (self->privacy) {
                    self->privacy = FALSE;
                    priv->pending_signals |= SIGNAL_BIT(PRIVACY);
                }
            } else if (!strcmp(name, PROXY_PROPERTY_NAME_MODE)) {
                if (self->mode != GSUPPLICANT_BSS_MODE_UNKNOWN) {
                    self->mode = GSUPPLICANT_BSS_MODE_UNKNOWN;
                    priv->pending_signals |= SIGNAL_BIT(MODE);
                }
            } else if (!strcmp(name, PROXY_PROPERTY_NAME_SIGNAL)) {
                if (self->signal) {
                    self->signal = 0;
                    priv->pending_signals |= SIGNAL_BIT(SIGNAL);
                }
            } else if (!strcmp(name, PROXY_PROPERTY_NAME_FREQUENCY)) {
                if (self->frequency) {
                    self->frequency = 0;
                    priv->pending_signals |= SIGNAL_BIT(FREQUENCY);
                }
            } else if (!strcmp(name, PROXY_PROPERTY_NAME_RATES)) {
                gsupplicant_bss_clear_rates(self);
            } else if (!strcmp(name, PROXY_PROPERTY_NAME_FREQUENCY)) {
                if (self->frequency) {
                    self->frequency = 0;
                    priv->pending_signals |= SIGNAL_BIT(FREQUENCY);
                }
            }
        }
    }
    if (changed) {
        GVariantIter it;
        GVariant* value;
        const char* name;
        g_variant_iter_init(&it, changed);
        while (g_variant_iter_next(&it, "{&sv}", &name, &value)) {
            if (!strcmp(name, PROXY_PROPERTY_NAME_SSID)) {
                gsupplicant_bss_update_ssid(self);
            } else if (!strcmp(name, PROXY_PROPERTY_NAME_BSSID)) {
                gsupplicant_bss_update_bssid(self);
            } else if (!strcmp(name, PROXY_PROPERTY_NAME_WPA)) {
                gsupplicant_bss_update_wpa(self);
            } else if (!strcmp(name, PROXY_PROPERTY_NAME_RSN)) {
                gsupplicant_bss_update_rsn(self);
            } else if (!strcmp(name, PROXY_PROPERTY_NAME_IES)) {
                gsupplicant_bss_update_ies(self);
            } else if (!strcmp(name, PROXY_PROPERTY_NAME_PRIVACY)) {
                gsupplicant_bss_update_privacy(self);
            } else if (!strcmp(name, PROXY_PROPERTY_NAME_MODE)) {
                gsupplicant_bss_update_mode(self);
            } else if (!strcmp(name, PROXY_PROPERTY_NAME_SIGNAL)) {
                gsupplicant_bss_update_signal(self);
            } else if (!strcmp(name, PROXY_PROPERTY_NAME_FREQUENCY)) {
                gsupplicant_bss_update_frequency(self);
            } else if (!strcmp(name, PROXY_PROPERTY_NAME_RATES)) {
                gsupplicant_bss_update_rates(self);
            }
            g_variant_unref(value);
        }
    }
    gsupplicant_bss_emit_pending_signals(self);
}

static
void
gsupplicant_bss_proxy_properties_changed(
    GDBusProxy* proxy,
    GVariant* change,
    gpointer data)
{
    gsupplicant_bss_proxy_gproperties_changed(proxy, change, NULL, data);
}

static
void
gsupplicant_bss_interface_valid_changed(
    GSupplicantInterface* iface,
    void* data)
{
    GSupplicantBSS* self = GSUPPLICANT_BSS(data);
    GASSERT(self->iface == iface);
    gsupplicant_bss_update_valid(self);
    gsupplicant_bss_update_present(self);
    gsupplicant_bss_emit_pending_signals(self);
}

static
void
gsupplicant_bss_interface_bsss_changed(
    GSupplicantInterface* iface,
    void* data)
{
    GSupplicantBSS* self = GSUPPLICANT_BSS(data);
    GASSERT(self->iface == iface);
    gsupplicant_bss_update_present(self);
    gsupplicant_bss_emit_pending_signals(self);
}

static
void
gsupplicant_bss_proxy_created(
    GObject* bus,
    GAsyncResult* result,
    gpointer data)
{
    GSupplicantBSS* self = GSUPPLICANT_BSS(data);
    GSupplicantBSSPriv* priv = self->priv;
    GError* error = NULL;
    GASSERT(!self->valid);
    GASSERT(!priv->proxy);
    priv->proxy = fi_w1_wpa_supplicant1_bss_proxy_new_for_bus_finish(result,
        &error);
    if (priv->proxy) {
        priv->proxy_handler_id[PROXY_GPROPERTIES_CHANGED] =
            g_signal_connect(priv->proxy, "g-properties-changed",
            G_CALLBACK(gsupplicant_bss_proxy_gproperties_changed), self);
        priv->proxy_handler_id[PROXY_PROPERTIES_CHANGED] =
            g_signal_connect(priv->proxy, "properties-changed",
            G_CALLBACK(gsupplicant_bss_proxy_properties_changed), self);

        priv->iface_handler_id[INTERFACE_VALID_CHANGED] =
            gsupplicant_interface_add_handler(self->iface,
                GSUPPLICANT_INTERFACE_PROPERTY_VALID,
                gsupplicant_bss_interface_valid_changed, self);
        priv->iface_handler_id[INTERFACE_BSSS_CHANGED] =
            gsupplicant_interface_add_handler(self->iface,
                GSUPPLICANT_INTERFACE_PROPERTY_BSSS,
                gsupplicant_bss_interface_bsss_changed, self);

        gsupplicant_bss_update_valid(self);
        gsupplicant_bss_update_present(self);
        gsupplicant_bss_update_ssid(self);
        gsupplicant_bss_update_bssid(self);
        gsupplicant_bss_update_wpa(self);
        gsupplicant_bss_update_rsn(self);
        gsupplicant_bss_update_ies(self);
        gsupplicant_bss_update_privacy(self);
        gsupplicant_bss_update_mode(self);
        gsupplicant_bss_update_frequency(self);
        gsupplicant_bss_update_rates(self);
        gsupplicant_bss_update_signal(self);

        gsupplicant_bss_emit_pending_signals(self);
    } else {
        GERR("%s", GERRMSG(error));
        g_error_free(error);
    }
    gsupplicant_bss_unref(self);
}

static
void
gsupplicant_bss_destroyed(
    gpointer key,
    GObject* dead)
{
    GVERBOSE_("%s", (char*)key);
    GASSERT(gsupplicant_bss_table);
    if (gsupplicant_bss_table) {
        GASSERT(g_hash_table_lookup(gsupplicant_bss_table, key) == dead);
        g_hash_table_remove(gsupplicant_bss_table, key);
        if (g_hash_table_size(gsupplicant_bss_table) == 0) {
            g_hash_table_unref(gsupplicant_bss_table);
            gsupplicant_bss_table = NULL;
        }
    }
}

static
GSupplicantBSS*
gsupplicant_bss_create(
    const char* path)
{
    /*
     * Let's assume that BSS path has the following format:
     *
     *   /fi/w1/wpa_supplicant1/Interfaces/xxx/BSSs/yyy
     *
     * and we just have to strip the last two elements of the path to get
     * the interface path.
     */
    int slash_count = 0;
    const char* ptr;
    for (ptr = path + strlen(path); ptr > path; ptr--) {
        if (ptr[0] == '/') {
            slash_count++;
            if (slash_count == 2) {
                break;
            }
        }
    }
    if (ptr > path) {
        GSupplicantInterface* iface;
        char* path2 = g_strdup(path);
        /* Temporarily shorten the path to lookup the interface */
        const gsize slash_index = ptr - path;
        path2[slash_index] = 0;
        GDEBUG_("%s -> %s", path, path2);
        iface = gsupplicant_interface_new(path2);
        if (iface) {
            GSupplicantBSS* self = g_object_new(GSUPPLICANT_BSS_TYPE,NULL);
            GSupplicantBSSPriv* priv = self->priv;
            /* Path is already allocated (but truncated) */
            path2[slash_index] = '/';
            self->path = priv->path = path2;
            self->iface = iface;
            fi_w1_wpa_supplicant1_bss_proxy_new_for_bus(GSUPPLICANT_BUS_TYPE,
                G_DBUS_PROXY_FLAGS_NONE, GSUPPLICANT_SERVICE, self->path, NULL,
                gsupplicant_bss_proxy_created, gsupplicant_bss_ref(self));
            return self;
        }
        g_free(path2);
    }
    return NULL;
}

/*==========================================================================*
 * API
 *==========================================================================*/

GSupplicantBSS*
gsupplicant_bss_new(
    const char* path)
{
    GSupplicantBSS* self = NULL;
    if (G_LIKELY(path)) {
        self = gsupplicant_bss_table ?
            gsupplicant_bss_ref(g_hash_table_lookup(gsupplicant_bss_table,
            path)) : NULL;
        if (!self) {
            self = gsupplicant_bss_create(path);
            if (self) {
                gpointer key = g_strdup(path);
                if (!gsupplicant_bss_table) {
                    gsupplicant_bss_table =
                        g_hash_table_new_full(g_str_hash, g_str_equal,
                            g_free, NULL);
                }
                g_hash_table_replace(gsupplicant_bss_table, key, self);
                g_object_weak_ref(G_OBJECT(self), gsupplicant_bss_destroyed,
                    key);
            }
        }
    }
    return self;
}

GSupplicantBSS*
gsupplicant_bss_ref(
    GSupplicantBSS* self)
{
    if (G_LIKELY(self)) {
        g_object_ref(GSUPPLICANT_BSS(self));
        return self;
    } else {
        return NULL;
    }
}

void
gsupplicant_bss_unref(
    GSupplicantBSS* self)
{
    if (G_LIKELY(self)) {
        g_object_unref(GSUPPLICANT_BSS(self));
    }
}

gulong
gsupplicant_bss_add_property_changed_handler(
    GSupplicantBSS* self,
    GSUPPLICANT_BSS_PROPERTY property,
    GSupplicantBSSPropertyFunc fn,
    void* data)
{
    if (G_LIKELY(self) && G_LIKELY(fn)) {
        const char* signal_name;
        char buf[sizeof(SIGNAL_PROPERTY_CHANGED_NAME) + 2 +
            SIGNAL_PROPERTY_CHANGED_DETAIL_MAX_LEN];
        if (property) {
            snprintf(buf, sizeof(buf), SIGNAL_PROPERTY_CHANGED_NAME "::"
                SIGNAL_PROPERTY_CHANGED_DETAIL, property);
            buf[sizeof(buf)-1] = 0;
            signal_name = buf;
        } else {
            signal_name = SIGNAL_PROPERTY_CHANGED_NAME;
        }
        return g_signal_connect(self, signal_name, G_CALLBACK(fn), data);
    }
    return 0;
}

gulong
gsupplicant_bss_add_handler(
    GSupplicantBSS* self,
    GSUPPLICANT_BSS_PROPERTY prop,
    GSupplicantBSSFunc fn,
    void* data)
{
    if (G_LIKELY(self) && G_LIKELY(fn)) {
        const char* signame;
        switch (prop) {
#define SIGNAL_NAME_(P,p) case GSUPPLICANT_BSS_PROPERTY_##P: \
            signame = gsupplicant_bss_signame[SIGNAL_##P##_CHANGED]; \
            break;
            GSUPPLICANT_BSS_PROPERTIES_(SIGNAL_NAME_)
        default:
            signame = NULL;
            break;
        }
        if (G_LIKELY(signame)) {
            return g_signal_connect(self, signame, G_CALLBACK(fn), data);
        }
    }
    return 0;
}

void
gsupplicant_bss_remove_handler(
    GSupplicantBSS* self,
    gulong id)
{
    if (G_LIKELY(self) && G_LIKELY(id)) {
        g_signal_handler_disconnect(self, id);
    }
}

void
gsupplicant_bss_remove_handlers(
    GSupplicantBSS* self,
    gulong* ids,
    guint count)
{
    gutil_disconnect_handlers(self, ids, count);
}

GSUPPLICANT_SECURITY
gsupplicant_bss_security(
    GSupplicantBSS* self)
{
    if (G_LIKELY(self) && self->valid && self->present) {
        GSUPPLICANT_KEYMGMT keymgmt = gsupplicant_bss_keymgmt(self);
        if (keymgmt & (GSUPPLICANT_KEYMGMT_WPA_EAP |
                        GSUPPLICANT_KEYMGMT_WPA_FT_EAP |
                        GSUPPLICANT_KEYMGMT_WPA_EAP_SHA256 |
                        GSUPPLICANT_KEYMGMT_IEEE8021X)) {
            return GSUPPLICANT_SECURITY_EAP;
        }
        if (keymgmt & (GSUPPLICANT_KEYMGMT_SAE |
                        GSUPPLICANT_KEYMGMT_SAE_EXT_KEY |
                        GSUPPLICANT_KEYMGMT_FT_SAE |
                        GSUPPLICANT_KEYMGMT_FT_SAE_EXT_KEY)) {
            if (keymgmt & (GSUPPLICANT_KEYMGMT_WPA_PSK |
                            GSUPPLICANT_KEYMGMT_WPA_FT_PSK |
                            GSUPPLICANT_KEYMGMT_WPA_PSK_SHA256)) {
                return GSUPPLICANT_SECURITY_PSK_SAE;
            } else {
                return GSUPPLICANT_SECURITY_SAE;
            }
        }
        if (keymgmt & (GSUPPLICANT_KEYMGMT_WPA_PSK |
                        GSUPPLICANT_KEYMGMT_WPA_FT_PSK |
                        GSUPPLICANT_KEYMGMT_WPA_PSK_SHA256)) {
            return GSUPPLICANT_SECURITY_PSK;
        }
        if (self->privacy) {
            return GSUPPLICANT_SECURITY_WEP;
        }
    }
    return GSUPPLICANT_SECURITY_NONE;
}

GSUPPLICANT_KEYMGMT
gsupplicant_bss_keymgmt(
    GSupplicantBSS* self)
{
    GSUPPLICANT_KEYMGMT keymgmt = GSUPPLICANT_KEYMGMT_INVALID;
    if (G_LIKELY(self)) {
        if (self->wpa) {
            keymgmt |= self->wpa->keymgmt;
        }
        if (self->rsn) {
            keymgmt |= self->rsn->keymgmt;
        }
    }
    return keymgmt;
}

GSUPPLICANT_CIPHER
gsupplicant_bss_pairwise(
    GSupplicantBSS* self)
{
    GSUPPLICANT_CIPHER pairwise = GSUPPLICANT_CIPHER_INVALID;
    if (G_LIKELY(self)) {
        if (self->wpa) {
            pairwise |= self->wpa->pairwise;
        }
        if (self->rsn) {
            pairwise |= self->rsn->pairwise;
        }
    }
    return pairwise;
}

GCancellable*
gsupplicant_bss_connect(
    GSupplicantBSS* self,
    const GSupplicantBSSConnectParams* cp,
    guint flags, /* None defined yet */
    GSupplicantBSSStringResultFunc fn,
    void* data)
{
    if (G_LIKELY(self) && self->valid) {
        GSupplicantInterfaceStringResultFunc call_done = NULL;
        GDestroyNotify call_free = NULL;
        void* call_data = NULL;
        GCancellable* cancel;
        GSupplicantNetworkParams np;
        gsupplicant_bss_fill_network_params(self, cp, flags, &np);
        if (fn) {
            call_data = gsupplicant_bss_connect_data_new(self, fn, data);
            call_done = gsupplicant_bss_connect_done;
            call_free = gsupplicant_bss_connect_free;
        }
        cancel = gsupplicant_interface_add_network_full(self->iface, NULL,
            &np, GSUPPLICANT_ADD_NETWORK_DELETE_OTHER |
            GSUPPLICANT_ADD_NETWORK_SELECT | GSUPPLICANT_ADD_NETWORK_ENABLE,
            call_done, call_free, call_data);
        if (cancel) {
            return cancel;
        } else if (call_free) {
            call_free(call_data);
        }
    }
    return NULL;
}

/*==========================================================================*
 * Internals
 *==========================================================================*/

/**
 * Per instance initializer
 */
static
void
gsupplicant_bss_init(
    GSupplicantBSS* self)
{
    self->priv = G_TYPE_INSTANCE_GET_PRIVATE(self, GSUPPLICANT_BSS_TYPE,
        GSupplicantBSSPriv);
}

/**
 * First stage of deinitialization (release all references).
 * May be called more than once in the lifetime of the object.
 */
static
void
gsupplicant_bss_dispose(
    GObject* object)
{
    GSupplicantBSS* self = GSUPPLICANT_BSS(object);
    GSupplicantBSSPriv* priv = self->priv;
    if (priv->proxy) {
        gutil_disconnect_handlers(priv->proxy, priv->proxy_handler_id,
            G_N_ELEMENTS(priv->proxy_handler_id));
        g_object_unref(priv->proxy);
        priv->proxy = NULL;
    }
    gsupplicant_interface_remove_all_handlers(self->iface,
        priv->iface_handler_id);
    G_OBJECT_CLASS(SUPER_CLASS)->dispose(object);
}

/**
 * Final stage of deinitialization
 */
static
void
gsupplicant_bss_finalize(
    GObject* object)
{
    GSupplicantBSS* self = GSUPPLICANT_BSS(object);
    GSupplicantBSSPriv* priv = self->priv;
    GASSERT(!priv->proxy);
    if (self->ssid) {
        g_bytes_unref(self->ssid);
    }
    if (self->bssid) {
        g_bytes_unref(self->bssid);
    }
    if (self->ies) {
        g_bytes_unref(self->ies);
    }
    g_free(priv->ssid_str);
    g_free(priv->rates_values);
    g_free(priv->path);
    gsupplicant_interface_unref(self->iface);
    G_OBJECT_CLASS(SUPER_CLASS)->finalize(object);
}

/**
 * Per class initializer
 */
static
void
gsupplicant_bss_class_init(
    GSupplicantBSSClass* klass)
{
    int i;
    GObjectClass* object_class = G_OBJECT_CLASS(klass);
    object_class->dispose = gsupplicant_bss_dispose;
    object_class->finalize = gsupplicant_bss_finalize;
    G_GNUC_BEGIN_IGNORE_DEPRECATIONS
    g_type_class_add_private(klass, sizeof(GSupplicantBSSPriv));
    G_GNUC_END_IGNORE_DEPRECATIONS
    for (i=0; i<SIGNAL_PROPERTY_CHANGED; i++) {
        gsupplicant_bss_signals[i] =  g_signal_new(
            gsupplicant_bss_signame[i], G_OBJECT_CLASS_TYPE(klass),
            G_SIGNAL_RUN_FIRST, 0, NULL, NULL, NULL, G_TYPE_NONE, 0);
    }
    gsupplicant_bss_signals[SIGNAL_PROPERTY_CHANGED] =
        g_signal_new(SIGNAL_PROPERTY_CHANGED_NAME, G_OBJECT_CLASS_TYPE(klass),
            G_SIGNAL_RUN_FIRST | G_SIGNAL_DETAILED, 0, NULL, NULL, NULL,
            G_TYPE_NONE, 1, G_TYPE_UINT);
}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
