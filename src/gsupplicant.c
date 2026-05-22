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

#include "gsupplicant.h"
#include "gsupplicant_dbus.h"
#include "gsupplicant_util_p.h"
#include "gsupplicant_error.h"
#include "gsupplicant_log.h"

#include <gutil_strv.h>
#include <gutil_misc.h>

/* Generated headers */
#include "fi.w1.wpa_supplicant1.h"

/* Log module */
GLOG_MODULE_DEFINE("gsupplicant");

/* Object definition */
enum gsupplicant_proxy_handler_id {
    PROXY_INTERFACE_ADDED,
    PROXY_INTERFACE_REMOVED,
    PROXY_NOTIFY_NAME_OWNER,
    PROXY_NOTIFY_CAPABILITIES,
    PROXY_NOTIFY_EAP_METHODS,
    PROXY_NOTIFY_INTERFACES,
    PROXY_HANDLER_COUNT
};

struct gsupplicant_priv {
    GDBusConnection* bus;
    FiW1Wpa_supplicant1* proxy;
    guint32 pending_signals;
    GStrV* interfaces;
    gulong proxy_handler_id[PROXY_HANDLER_COUNT];
};

typedef GObjectClass GSupplicantClass;
G_DEFINE_TYPE(GSupplicant, gsupplicant, G_TYPE_OBJECT)
#define GSUPPLICANT_TYPE (gsupplicant_get_type())
#define GSUPPLICANT(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), \
        GSUPPLICANT_TYPE, GSupplicant))

typedef union gsupplicant_call_func_union {
    GCallback cb;
    GSupplicantResultFunc fn_void;
    GSupplicantStringResultFunc fn_string;
} GSupplicantCallFuncUnion;

typedef
void
(*GSupplicantCallFinishFunc)(
    GSupplicant* supplicant,
    GCancellable* cancel,
    GAsyncResult* result,
    GSupplicantCallFuncUnion fn,
    void* data);

typedef struct gsupplicant_call {
    GSupplicant* supplicant;
    GCancellable* cancel;
    gulong cancel_id;
    GSupplicantCallFinishFunc finish;
    GSupplicantCallFuncUnion fn;
    void* data;
} GSupplicantCall;

/* Supplicant properties */
#define GSUPPLICANT_PROPERTIES_(p) \
    p(VALID,valid) \
    p(CAPABILITIES,capabilities) \
    p(EAP_METHODS,eap-methods) \
    p(INTERFACES,interfaces)

/* Supplicant signals */
typedef enum gsupplicant_signal {
#define SIGNAL_ENUM_(P,p) SIGNAL_##P##_CHANGED,
    GSUPPLICANT_PROPERTIES_(SIGNAL_ENUM_)
#undef SIGNAL_ENUM_
    SIGNAL_PROPERTY_CHANGED,
    SIGNAL_COUNT
} GSUPPLICANT_SIGNAL;

#define SIGNAL_BIT(name) (1 << SIGNAL_##name##_CHANGED)

/* Assert that we have covered all publicly defined properties */
G_STATIC_ASSERT((int)SIGNAL_PROPERTY_CHANGED ==
               ((int)GSUPPLICANT_PROPERTY_COUNT-1));

#define SIGNAL_PROPERTY_CHANGED_NAME            "property-changed"
#define SIGNAL_PROPERTY_CHANGED_DETAIL          "%x"
#define SIGNAL_PROPERTY_CHANGED_DETAIL_MAX_LEN  (8)

static GQuark gsupplicant_property_quarks[SIGNAL_PROPERTY_CHANGED];
static guint gsupplicant_signals[SIGNAL_COUNT];
static const char* gsupplicant_signame[SIGNAL_COUNT] = {
#define SIGNAL_NAME_(P,p) #p "-changed",
    GSUPPLICANT_PROPERTIES_(SIGNAL_NAME_)
#undef SIGNAL_NAME_
    SIGNAL_PROPERTY_CHANGED_NAME
};
G_STATIC_ASSERT(G_N_ELEMENTS(gsupplicant_signame) == SIGNAL_COUNT);

/* Proxy properties */
#define PROXY_PROPERTY_NAME_DEBUG_LEVEL     "DebugLevel"
#define PROXY_PROPERTY_NAME_DEBUG_SHOW_KEYS "DebugShowKeys"
#define PROXY_PROPERTY_NAME_DEBUG_TIMESTAMP "DebugTimestamp"
#define PROXY_PROPERTY_NAME_CAPABILITIES    "Capabilities"
#define PROXY_PROPERTY_NAME_EAP_METHODS     "EapMethods"
#define PROXY_PROPERTY_NAME_INTERFACES      "Interfaces"

/* Capabilities */
static const GSupNameIntPair gsupplicant_caps [] = {
    { "ap",             GSUPPLICANT_CAPS_AP },
    { "ibss-rsn",       GSUPPLICANT_CAPS_IBSS_RSN },
    { "p2p",            GSUPPLICANT_CAPS_P2P },
    { "interworking",   GSUPPLICANT_CAPS_INTERWORKING }
};

/* EAP methods */
static const GSupNameIntPair gsupplicant_eap_methods [] = {
    { "MD5",            GSUPPLICANT_EAP_METHOD_MD5 },
    { "TLS",            GSUPPLICANT_EAP_METHOD_TLS },
    { "MSCHAPV2",       GSUPPLICANT_EAP_METHOD_MSCHAPV2 },
    { "PEAP",           GSUPPLICANT_EAP_METHOD_PEAP },
    { "TTLS",           GSUPPLICANT_EAP_METHOD_TTLS },
    { "GTC",            GSUPPLICANT_EAP_METHOD_GTC },
    { "OTP",            GSUPPLICANT_EAP_METHOD_OTP },
    { "SIM",            GSUPPLICANT_EAP_METHOD_SIM },
    { "LEAP",           GSUPPLICANT_EAP_METHOD_LEAP },
    { "PSK",            GSUPPLICANT_EAP_METHOD_PSK },
    { "AKA",            GSUPPLICANT_EAP_METHOD_AKA },
    { "FAST",           GSUPPLICANT_EAP_METHOD_FAST },
    { "PAX",            GSUPPLICANT_EAP_METHOD_PAX },
    { "SAKE",           GSUPPLICANT_EAP_METHOD_SAKE },
    { "GPSK",           GSUPPLICANT_EAP_METHOD_GPSK },
    { "WSC",            GSUPPLICANT_EAP_METHOD_WSC },
    { "IKEV2",          GSUPPLICANT_EAP_METHOD_IKEV2 },
    { "TNC",            GSUPPLICANT_EAP_METHOD_TNC },
    { "PWD",            GSUPPLICANT_EAP_METHOD_PWD }
};

static const GSupNameIntPair gsupplicant_cipher_suites [] = {
    { "none",           GSUPPLICANT_CIPHER_NONE },
    { "ccmp",           GSUPPLICANT_CIPHER_CCMP },
    { "tkip",           GSUPPLICANT_CIPHER_TKIP },
    { "wep104",         GSUPPLICANT_CIPHER_WEP104 },
    { "wep40",          GSUPPLICANT_CIPHER_WEP40 },
    { "aes128cmac",     GSUPPLICANT_CIPHER_AES128_CMAC },
    { "ccmp-256",       GSUPPLICANT_CIPHER_CCMP_256 },
    { "gcmp",           GSUPPLICANT_CIPHER_GCMP },
    { "gcmp-256",       GSUPPLICANT_CIPHER_GCMP_256 }
};

static const GSupNameIntPair gsupplicant_keymgmt_suites [] = {
    { "none",           GSUPPLICANT_KEYMGMT_NONE },
    { "wpa-psk",        GSUPPLICANT_KEYMGMT_WPA_PSK },
    { "wpa-ft-psk",     GSUPPLICANT_KEYMGMT_WPA_FT_PSK },
    { "wpa-psk-sha256", GSUPPLICANT_KEYMGMT_WPA_PSK_SHA256 },
    { "wpa-eap",        GSUPPLICANT_KEYMGMT_WPA_EAP },
    { "wpa-ft-eap",     GSUPPLICANT_KEYMGMT_WPA_FT_EAP },
    { "wpa-eap-sha256", GSUPPLICANT_KEYMGMT_WPA_EAP_SHA256 },
    { "ieee8021x",      GSUPPLICANT_KEYMGMT_IEEE8021X },
    { "wpa-none",       GSUPPLICANT_KEYMGMT_WPA_NONE },
    { "wps",            GSUPPLICANT_KEYMGMT_WPS },
    { "sae",            GSUPPLICANT_KEYMGMT_SAE },
    { "sae-ext-key",    GSUPPLICANT_KEYMGMT_SAE_EXT_KEY },
    { "ft-sae",         GSUPPLICANT_KEYMGMT_FT_SAE },
    { "ft-sae-ext-key", GSUPPLICANT_KEYMGMT_FT_SAE_EXT_KEY }
};

/*==========================================================================*
 * Implementation
 *==========================================================================*/

static
void
gsupplicant_call_cancelled(
    GCancellable* cancel,
    gpointer data)
{
    GSupplicantCall* call = data;
    GASSERT(call->supplicant);
    GASSERT(call->cancel == cancel);
    gsupplicant_unref(call->supplicant);
    call->supplicant = NULL;
}

static
void
gsupplicant_call_finished(
    GObject* proxy,
    GAsyncResult* result,
    gpointer data)
{
    GSupplicantCall* call = data;
    g_signal_handler_disconnect(call->cancel, call->cancel_id);
    if (!g_cancellable_is_cancelled(call->cancel)) {
        GASSERT(call->supplicant);
        call->finish(call->supplicant, call->cancel, result,
            call->fn, call->data);
    } else {
        /* Generic cleanup */
        GVariant* var = g_dbus_proxy_call_finish(G_DBUS_PROXY(proxy),
            result, NULL);
        if (var) {
            g_variant_unref(var);
        }
    }
    gsupplicant_unref(call->supplicant);
    g_object_unref(call->cancel);
    g_slice_free(GSupplicantCall, call);
}

static
GSupplicantCall*
gsupplicant_call_new(
    GSupplicant* supplicant,
    GSupplicantCallFinishFunc finish,
    GCallback cb,
    void* data)
{
    GSupplicantCall* call = g_slice_new0(GSupplicantCall);
    call->cancel = g_cancellable_new();
    call->cancel_id = g_cancellable_connect(call->cancel,
        G_CALLBACK(gsupplicant_call_cancelled), call, NULL);
    call->supplicant = gsupplicant_ref(supplicant);
    call->finish = finish;
    call->fn.cb = cb;
    call->data = data;
    return call;
}

static
void
gsupplicant_call_finish_void(
    GSupplicant* supplicant,
    GCancellable* cancel,
    GAsyncResult* result,
    GSupplicantCallFuncUnion fn,
    void* data)
{
    GError* error = NULL;
    GDBusProxy* proxy = G_DBUS_PROXY(supplicant->priv->proxy);
    GVariant* var = g_dbus_proxy_call_finish(proxy, result, &error);
    if (var) {
        g_variant_unref(var);
    }
    if (fn.fn_void) {
        fn.fn_void(supplicant, cancel, error, data);
    }
    if (error) {
        g_error_free(error);
    }
}

static
void
gsupplicant_call_finish_string(
    GSupplicant* supplicant,
    GCancellable* cancel,
    GAsyncResult* result,
    gboolean (*get_result)(
        FiW1Wpa_supplicant1* proxy,
        gchar** str,
        GAsyncResult* res,
        GError** error),
    GSupplicantStringResultFunc fn,
    void* data)
{
    char* str = NULL;
    GError* error = NULL;
    GSupplicantPriv* priv = supplicant->priv;
    get_result(priv->proxy, &str, result, &error);
    if (fn) {
        fn(supplicant, cancel, error, str, data);
    }
    if (error) {
        g_error_free(error);
    }
    g_free(str);
}

static
void
gsupplicant_call_finish_create_interface(
    GSupplicant* supplicant,
    GCancellable* cancel,
    GAsyncResult* result,
    GSupplicantCallFuncUnion fn,
    void* data)
{
    gsupplicant_call_finish_string(supplicant, cancel, result,
        fi_w1_wpa_supplicant1_call_create_interface_finish, fn.fn_string, data);
}

static
void
gsupplicant_call_finish_get_interface(
    GSupplicant* supplicant,
    GCancellable* cancel,
    GAsyncResult* result,
    GSupplicantCallFuncUnion fn,
    void* data)
{
    gsupplicant_call_finish_string(supplicant, cancel, result,
        fi_w1_wpa_supplicant1_call_get_interface_finish, fn.fn_string, data);
}

static inline
GSUPPLICANT_PROPERTY
gsupplicant_property_from_signal(
    GSUPPLICANT_SIGNAL sig)
{
    switch (sig) {
#define SIGNAL_PROPERTY_MAP_(P,p) \
    case SIGNAL_##P##_CHANGED: return GSUPPLICANT_PROPERTY_##P;
    GSUPPLICANT_PROPERTIES_(SIGNAL_PROPERTY_MAP_)
#undef SIGNAL_PROPERTY_MAP_
    default: /* unreachable */ return GSUPPLICANT_PROPERTY_ANY;
    }
}

static
void
gsupplicant_signal_property_change(
    GSupplicant* self,
    GSUPPLICANT_SIGNAL sig,
    GSUPPLICANT_PROPERTY prop)
{
    GSupplicantPriv* priv = self->priv;
    GASSERT(prop > GSUPPLICANT_PROPERTY_ANY);
    GASSERT(prop < GSUPPLICANT_PROPERTY_COUNT);
    GASSERT(sig < G_N_ELEMENTS(gsupplicant_property_quarks));
    if (!gsupplicant_property_quarks[sig]) {
        char buf[SIGNAL_PROPERTY_CHANGED_DETAIL_MAX_LEN + 1];
        snprintf(buf, sizeof(buf), SIGNAL_PROPERTY_CHANGED_DETAIL, prop);
        buf[sizeof(buf)-1] = 0;
        gsupplicant_property_quarks[sig] = g_quark_from_string(buf);
    }
    priv->pending_signals &= ~(1 << sig);
    g_signal_emit(self, gsupplicant_signals[sig], 0);
    g_signal_emit(self, gsupplicant_signals[SIGNAL_PROPERTY_CHANGED],
        gsupplicant_property_quarks[sig], prop);
}

static
void
gsupplicant_emit_pending_signals(
    GSupplicant* self)
{
    GSupplicantPriv* priv = self->priv;
    GSUPPLICANT_SIGNAL sig;
    gboolean valid_changed;

    /* Handlers could drop their references to us */
    gsupplicant_ref(self);

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
            gsupplicant_signal_property_change(self, sig,
                gsupplicant_property_from_signal(sig));
        }
    }

    /* Then emit VALID if valid has become TRUE */
    if (valid_changed) {
        gsupplicant_signal_property_change(self,
            SIGNAL_VALID_CHANGED, GSUPPLICANT_PROPERTY_VALID);
    }

    /* And release the temporary reference */
    gsupplicant_unref(self);
}

static
guint
gsupplicant_convert_to_bitmask(
    const gchar* const* values,
    const GSupNameIntPair* list,
    size_t count)
{
    guint mask = 0;
    if (values) {
        const gchar* const* name = values;
        while (*name) {
            const GSupNameIntPair* pair =
                gsupplicant_name_int_find_name(*name, list, count);
            if (pair) mask |= pair->value;
            name++;
        }
    }
    return mask;
}

static
guint
gsupplicant_get_capabilities(
    GSupplicant* self)
{
    return self->valid ? gsupplicant_convert_to_bitmask(
        fi_w1_wpa_supplicant1_get_capabilities(self->priv->proxy),
        gsupplicant_caps, G_N_ELEMENTS(gsupplicant_caps)) : 0;
}

static
guint
gsupplicant_get_eap_methods(
    GSupplicant* self)
{
    return self->valid ? gsupplicant_convert_to_bitmask(
        fi_w1_wpa_supplicant1_get_eap_methods(self->priv->proxy),
        gsupplicant_eap_methods, G_N_ELEMENTS(gsupplicant_eap_methods)) : 0;
}

static
void
gsupplicant_update_name_owner(
    GSupplicant* self)
{
    GSupplicantPriv* priv = self->priv;
    char* owner = g_dbus_proxy_get_name_owner(G_DBUS_PROXY(priv->proxy));
    const gboolean valid = (owner != NULL);
    g_free(owner);
    if (self->valid != valid) {
        self->valid = valid;
        priv->pending_signals |= SIGNAL_BIT(VALID);
    }
}

static
void
gsupplicant_update_interfaces(
    GSupplicant* self)
{
    GSupplicantPriv* priv = self->priv;
    gchar** interfaces = (char**)(self->valid ?
        fi_w1_wpa_supplicant1_get_interfaces(priv->proxy) : NULL);
    /* If the stub is generated by gdbus-codegen < 2.56 then the getting
     * returns shallow copy, i.e. the return result should be released
     * with g_free(), but the individual strings must not be modified. */
    if (!gutil_strv_equal((const GStrV*)interfaces, priv->interfaces)) {
#if STRV_GETTERS_RETURN_SHALLOW_COPY
        GStrV* ptr;
        for (ptr = interfaces; *ptr; ptr++) {
            *ptr = g_strdup(*ptr);
        }
#else
        interfaces = g_strdupv(interfaces);
#endif
        g_strfreev(priv->interfaces);
        self->interfaces = priv->interfaces = interfaces;
        priv->pending_signals |= SIGNAL_BIT(INTERFACES);
    }
#if STRV_GETTERS_RETURN_SHALLOW_COPY
    else {
        g_free(interfaces);
    }
#endif
}

static
void
gsupplicant_update_capabilities(
    GSupplicant* self)
{
    const guint caps = gsupplicant_get_capabilities(self);
    if (self->caps != caps) {
        self->caps = caps;
        self->priv->pending_signals |= SIGNAL_BIT(CAPABILITIES);
    }
}

static
void
gsupplicant_update_eap_methods(
    GSupplicant* self)
{
    const guint methods = gsupplicant_get_eap_methods(self);
    if (self->eap_methods != methods) {
        self->eap_methods = methods;
        self->priv->pending_signals |= SIGNAL_BIT(EAP_METHODS);
    }
}

static
void
gsupplicant_notify_name_owner(
    FiW1Wpa_supplicant1* proxy,
    GParamSpec* param,
    gpointer data)
{
    GSupplicant* self = GSUPPLICANT(data);
    gsupplicant_update_name_owner(self);
    gsupplicant_emit_pending_signals(self);
}

static
void
gsupplicant_notify_capabilities(
    FiW1Wpa_supplicant1* proxy,
    GParamSpec* param,
    gpointer data)
{
    GSupplicant* self = GSUPPLICANT(data);
    gsupplicant_update_capabilities(self);
    gsupplicant_emit_pending_signals(self);
}

static
void
gsupplicant_notify_eap_methods(
    FiW1Wpa_supplicant1* proxy,
    GParamSpec* param,
    gpointer data)
{
    GSupplicant* self = GSUPPLICANT(data);
    gsupplicant_update_eap_methods(self);
    gsupplicant_emit_pending_signals(self);
}

static
void
gsupplicant_notify_interfaces(
    FiW1Wpa_supplicant1* proxy,
    GParamSpec* param,
    gpointer data)
{
    GSupplicant* self = GSUPPLICANT(data);
    gsupplicant_update_interfaces(self);
    gsupplicant_emit_pending_signals(self);
}

static
void
gsupplicant_proxy_interface_added(
    GDBusProxy* proxy,
    const char* path,
    GVariant* properties,
    gpointer data)
{
    GSupplicant* self = GSUPPLICANT(data);
    GSupplicantPriv* priv = self->priv;
    GDEBUG("Interface added: %s", path);
    if (!gutil_strv_contains(priv->interfaces, path)) {
        self->interfaces = priv->interfaces =
            gutil_strv_add(priv->interfaces, path);
        priv->pending_signals |= SIGNAL_BIT(INTERFACES);
        gsupplicant_emit_pending_signals(self);
    }
}

static
void
gsupplicant_proxy_interface_removed(
    GDBusProxy* proxy,
    const char* path,
    gpointer data)
{
    GSupplicant* self = GSUPPLICANT(data);
    GSupplicantPriv* priv = self->priv;
    const int pos = gutil_strv_find(priv->interfaces, path);
    GDEBUG("Interface removed: %s", path);
    if (pos >= 0) {
        self->interfaces = priv->interfaces =
            gutil_strv_remove_at(priv->interfaces, pos, TRUE);
        priv->pending_signals |= SIGNAL_BIT(INTERFACES);
        gsupplicant_emit_pending_signals(self);
    }
}

static
void
gsupplicant_proxy_created(
    GObject* bus,
    GAsyncResult* result,
    gpointer data)
{
    GSupplicant* self = GSUPPLICANT(data);
    GSupplicantPriv* priv = self->priv;
    GError* error = NULL;
    FiW1Wpa_supplicant1* proxy = fi_w1_wpa_supplicant1_proxy_new_finish(
        result, &error);
    if (proxy) {
        GASSERT(!priv->proxy);
        GASSERT(!self->valid);

        priv->proxy = proxy;
        priv->proxy_handler_id[PROXY_INTERFACE_ADDED] =
            g_signal_connect(proxy, "interface-added",
            G_CALLBACK(gsupplicant_proxy_interface_added), self);
        priv->proxy_handler_id[PROXY_INTERFACE_REMOVED] =
            g_signal_connect(proxy, "interface-removed",
            G_CALLBACK(gsupplicant_proxy_interface_removed), self);

        priv->proxy_handler_id[PROXY_NOTIFY_NAME_OWNER] =
            g_signal_connect(priv->proxy, "notify::g-name-owner",
            G_CALLBACK(gsupplicant_notify_name_owner), self);
        priv->proxy_handler_id[PROXY_NOTIFY_CAPABILITIES] =
            g_signal_connect(priv->proxy, "notify::capabilities",
            G_CALLBACK(gsupplicant_notify_capabilities), self);
        priv->proxy_handler_id[PROXY_NOTIFY_EAP_METHODS] =
            g_signal_connect(priv->proxy, "notify::eap-methods",
            G_CALLBACK(gsupplicant_notify_eap_methods), self);
        priv->proxy_handler_id[PROXY_NOTIFY_INTERFACES] =
            g_signal_connect(priv->proxy, "notify::interfaces",
            G_CALLBACK(gsupplicant_notify_interfaces), self);

        gsupplicant_update_name_owner(self);
        gsupplicant_update_capabilities(self);
        gsupplicant_update_eap_methods(self);
        gsupplicant_update_interfaces(self);
        gsupplicant_emit_pending_signals(self);
    } else {
        GERR("%s", GERRMSG(error));
        g_error_free(error);
    }
    gsupplicant_unref(self);
}

static
void
gsupplicant_bus_get_finished(
    GObject* object,
    GAsyncResult* result,
    gpointer data)
{
    GSupplicant* self = GSUPPLICANT(data);
    GSupplicantPriv* priv = self->priv;
    GError* error = NULL;
    priv->bus = g_bus_get_finish(result, &error);
    if (priv->bus) {
        GDEBUG("Bus connected");
        /* Start the initialization sequence */
        fi_w1_wpa_supplicant1_proxy_new(priv->bus, G_DBUS_PROXY_FLAGS_NONE,
            GSUPPLICANT_SERVICE, GSUPPLICANT_PATH, NULL,
            gsupplicant_proxy_created, gsupplicant_ref(self));
    } else {
        GERR("Failed to attach to system bus: %s", GERRMSG(error));
        g_error_free(error);
    }
    gsupplicant_unref(self);
}

/*==========================================================================*
 * API
 *==========================================================================*/

GSupplicant*
gsupplicant_new()
{
    /* Weak reference to the single instance of GSupplicant */
    static GSupplicant* gsupplicant_instance = NULL;
    if (gsupplicant_instance) {
        gsupplicant_ref(gsupplicant_instance);
    } else {
        gsupplicant_instance = g_object_new(GSUPPLICANT_TYPE, NULL);
        g_bus_get(GSUPPLICANT_BUS_TYPE, NULL, gsupplicant_bus_get_finished,
            gsupplicant_ref(gsupplicant_instance));
        g_object_add_weak_pointer(G_OBJECT(gsupplicant_instance),
            (gpointer*)(&gsupplicant_instance));
    }
    return gsupplicant_instance;
}

GSupplicant*
gsupplicant_ref(
    GSupplicant* self)
{
    if (G_LIKELY(self)) {
        g_object_ref(GSUPPLICANT(self));
        return self;
    } else {
        return NULL;
    }
}

void
gsupplicant_unref(
    GSupplicant* self)
{
    if (G_LIKELY(self)) {
        g_object_unref(GSUPPLICANT(self));
    }
}

gulong
gsupplicant_add_property_changed_handler(
    GSupplicant* self,
    GSUPPLICANT_PROPERTY property,
    GSupplicantPropertyFunc fn,
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
gsupplicant_add_handler(
    GSupplicant* self,
    GSUPPLICANT_PROPERTY prop,
    GSupplicantFunc fn,
    void* data)
{
    if (G_LIKELY(self) && G_LIKELY(fn)) {
        const char* signame;
        switch (prop) {
#define SIGNAL_NAME_(P,p) case GSUPPLICANT_PROPERTY_##P: \
            signame = gsupplicant_signame[SIGNAL_##P##_CHANGED]; \
            break;
            GSUPPLICANT_PROPERTIES_(SIGNAL_NAME_)
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
gsupplicant_remove_handler(
    GSupplicant* self,
    gulong id)
{
    if (G_LIKELY(self) && G_LIKELY(id)) {
        g_signal_handler_disconnect(self, id);
    }
}

void
gsupplicant_remove_handlers(
    GSupplicant* self,
    gulong* ids,
    guint count)
{
    gutil_disconnect_handlers(self, ids, count);
}

GCancellable*
gsupplicant_create_interface(
    GSupplicant* self,
    const GSupplicantCreateInterfaceParams* params,
    GSupplicantStringResultFunc fn,
    void* data)
{
    if (G_LIKELY(self) && self->valid && params && params->ifname) {
        GSupplicantPriv* priv = self->priv;
        GSupplicantCall* call = gsupplicant_call_new(self,
            gsupplicant_call_finish_create_interface, G_CALLBACK(fn), data);
        GVariantBuilder builder;
        GVariant* dict;
        g_variant_builder_init(&builder, G_VARIANT_TYPE_VARDICT);
        gsupplicant_dict_add_string(&builder, "Ifname", params->ifname);
        gsupplicant_dict_add_string0(&builder, "BridgeIfname",
            params->bridge_ifname);
        gsupplicant_dict_add_string0(&builder, "Driver", params->driver);
        gsupplicant_dict_add_string0(&builder, "ConfigFile",
            params->config_file);
        dict = g_variant_ref_sink(g_variant_builder_end(&builder));
        fi_w1_wpa_supplicant1_call_create_interface(priv->proxy, dict,
            call->cancel, gsupplicant_call_finished, call);
        g_variant_unref(dict);
        return call->cancel;
    }
    return NULL;
}

GCancellable*
gsupplicant_remove_interface(
    GSupplicant* self,
    const char* path,
    GSupplicantResultFunc fn,
    void* data)
{
    if (G_LIKELY(self) && self->valid &&
        path && g_variant_is_object_path(path)) {
        GSupplicantPriv* priv = self->priv;
        GSupplicantCall* call = gsupplicant_call_new(self,
            gsupplicant_call_finish_void, G_CALLBACK(fn), data);
        fi_w1_wpa_supplicant1_call_remove_interface(priv->proxy, path,
            call->cancel, gsupplicant_call_finished, call);
        return call->cancel;
    }
    return NULL;
}

GCancellable*
gsupplicant_get_interface(
    GSupplicant* self,
    const char* ifname,
    GSupplicantStringResultFunc fn,
    void* data)
{
    if (G_LIKELY(self) && self->valid) {
        GSupplicantPriv* priv = self->priv;
        GSupplicantCall* call = gsupplicant_call_new(self,
            gsupplicant_call_finish_get_interface, G_CALLBACK(fn), data);
        fi_w1_wpa_supplicant1_call_get_interface(priv->proxy, ifname,
            call->cancel, gsupplicant_call_finished, call);
        return call->cancel;
    }
    return NULL;
}

const char*
gsupplicant_caps_name(
    guint caps,
    guint* cap)
{
    return gsupplicant_name_int_find_bit(caps, cap,
        gsupplicant_caps, G_N_ELEMENTS(gsupplicant_caps));
}

const char*
gsupplicant_eap_method_name(
    guint methods,
    guint* method)
{
    return gsupplicant_name_int_find_bit(methods, method,
        gsupplicant_eap_methods, G_N_ELEMENTS(gsupplicant_eap_methods));
}

const char*
gsupplicant_cipher_suite_name(
    guint cipher_suites,
    guint* cipher_suite)
{
    return gsupplicant_name_int_find_bit(cipher_suites, cipher_suite,
        gsupplicant_cipher_suites, G_N_ELEMENTS(gsupplicant_cipher_suites));
}

const char*
gsupplicant_keymgmt_suite_name(
    guint keymgmt_suites,
    guint* keymgmt_suite)
{
    return gsupplicant_name_int_find_bit(keymgmt_suites, keymgmt_suite,
        gsupplicant_keymgmt_suites, G_N_ELEMENTS(gsupplicant_keymgmt_suites));
}

void
gsupplicant_set_wpa3_support(
    GSupplicant *supplicant,
    GSUPPLICANT_WPA3_SUPPORT wpa3_support)
{
    if (supplicant)
        supplicant->wpa3_support = wpa3_support;
}

/*==========================================================================*
 * Internal API
 *==========================================================================*/

GSUPPLICANT_CIPHER
gsupplicant_parse_cipher_value(
    const char* name,
    GVariant* value)
{
    return gsupplicant_parse_bit_value(name, value,
        gsupplicant_cipher_suites, G_N_ELEMENTS(gsupplicant_cipher_suites));
}

GSUPPLICANT_CIPHER
gsupplicant_parse_cipher_list(
    const char* name,
    GVariant* value)
{
    return gsupplicant_parse_bits_array(0, name, value,
        gsupplicant_cipher_suites, G_N_ELEMENTS(gsupplicant_cipher_suites));
}

GSUPPLICANT_KEYMGMT
gsupplicant_parse_keymgmt_list(
    const char* name,
    GVariant* value)
{
    return gsupplicant_parse_bits_array(0, name, value,
        gsupplicant_keymgmt_suites, G_N_ELEMENTS(gsupplicant_keymgmt_suites));
}

/*==========================================================================*
 * Internals
 *==========================================================================*/

/**
 * Per instance initializer
 */
static
void
gsupplicant_init(
    GSupplicant* self)
{
    GSupplicantPriv* priv = G_TYPE_INSTANCE_GET_PRIVATE(self,
        GSUPPLICANT_TYPE, GSupplicantPriv);
    self->priv = priv;
    gutil_log_default.level = GLOG_LEVEL_VERBOSE;
}

/**
 * Final stage of deinitialization
 */
static
void
gsupplicant_finalize(
    GObject* object)
{
    GSupplicant* self = GSUPPLICANT(object);
    GSupplicantPriv* priv = self->priv;
    GVERBOSE_("");
    if (priv->proxy) {
        gutil_disconnect_handlers(priv->proxy, priv->proxy_handler_id,
            G_N_ELEMENTS(priv->proxy_handler_id));
        g_object_unref(priv->proxy);
    }
    if (priv->bus) {
        g_dbus_connection_flush_sync(priv->bus, NULL, NULL);
        g_object_unref(priv->bus);
    }
    g_strfreev(priv->interfaces);
    G_OBJECT_CLASS(gsupplicant_parent_class)->finalize(object);
}

/**
 * Per class initializer
 */
static
void
gsupplicant_class_init(
    GSupplicantClass* klass)
{
    int i;
    G_OBJECT_CLASS(klass)->finalize = gsupplicant_finalize;
    G_GNUC_BEGIN_IGNORE_DEPRECATIONS
    g_type_class_add_private(klass, sizeof(GSupplicantPriv));
    G_GNUC_END_IGNORE_DEPRECATIONS
    for (i=0; i<SIGNAL_PROPERTY_CHANGED; i++) {
        gsupplicant_signals[i] =  g_signal_new(gsupplicant_signame[i],
            G_OBJECT_CLASS_TYPE(klass), G_SIGNAL_RUN_FIRST,
            0, NULL, NULL, NULL, G_TYPE_NONE, 0);
    }
    gsupplicant_signals[SIGNAL_PROPERTY_CHANGED] =
        g_signal_new(SIGNAL_PROPERTY_CHANGED_NAME, G_OBJECT_CLASS_TYPE(klass),
            G_SIGNAL_RUN_FIRST | G_SIGNAL_DETAILED, 0, NULL, NULL, NULL,
            G_TYPE_NONE, 1, G_TYPE_UINT);
    /* Register errors with gio */
    gsupplicant_error_quark();
}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
