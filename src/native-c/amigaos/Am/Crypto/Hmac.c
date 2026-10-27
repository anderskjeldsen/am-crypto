#include <libc/core.h>
#include <Am/Crypto/Hmac.h>
#include <amigaos/Am/Crypto/Hmac.h>
#include <Am/Lang/ClassRef.h>
#include <Am/Lang/UByte.h>
#include <Am/Lang/Array.h>
#include <Am/Lang/Object.h>
#include <libc/core_inline_functions.h>

// AmigaOS m68k HMAC binding — the twin of libc/Am/Crypto/Hmac.c. Library
// bring-up is shared through am_crypto_amissl_init.{c,h}; see Sha256.c
// next door for why that lives in one place.
//
// Declarations only, no C89 violations: this builds with the m68k
// toolchain, so every local is declared at the top of its block.

#include <amigaos/am_crypto_amissl_init.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

function_result Am_Crypto_CryptoPrivate_f_openSslInitialized_0(void);
function_result Am_Crypto_CryptoPrivate_f_setOpenSslInitialized_0(void);

function_result Am_Crypto_Hmac__native_init_0(aobject * const this)
{
    function_result __result = { .has_return_value = false };
    if (this != NULL) { __increase_reference_count(this); }
__exit: ;
    if (this != NULL) { __decrease_reference_count(this); }
    return __result;
}

function_result Am_Crypto_Hmac__native_release_0(aobject * const this)
{
    function_result __result = { .has_return_value = false };
    return __result;
}

function_result Am_Crypto_Hmac__native_mark_children_0(aobject * const this)
{
    function_result __result = { .has_return_value = false };
    return __result;
}

static int hmac_ensure_amissl(function_result * const result, const char * const site) {
    function_result openssl_state = Am_Crypto_CryptoPrivate_f_openSslInitialized_0();
    if (!openssl_state.return_value.value.bool_value) {
        if (!am_crypto_amissl_ensure_initialised()) {
            __throw_simple_exception("Failed to initialise AmiSSL", site, result);
            return 0;
        }
        Am_Crypto_CryptoPrivate_f_setOpenSslInitialized_0();
    }
    if (!am_crypto_amissl_ensure_initialised_for_current_task()) {
        __throw_simple_exception("Failed per-task AmiSSL init", site, result);
        return 0;
    }
    return 1;
}

// One byte to point at when the key is empty. HMAC with a zero-length key
// is well defined (it is zero-padded to the block size like any short
// key), but the pointer still has to be a pointer.
static const unsigned char hmac_empty_key = 0;

static aobject * hmac_compute(const EVP_MD *md, aobject * var_key, aobject * var_message)
{
    array_holder *k_holder;
    array_holder *m_holder;
    const unsigned char *key_data;
    unsigned int key_len;
    unsigned char mac[EVP_MAX_MD_SIZE];
    unsigned int mac_len;
    aobject *result_array;
    array_holder *r_holder;
    unsigned char *result_data;
    unsigned int i;

    k_holder = (array_holder *) &var_key[1];
    m_holder = (array_holder *) &var_message[1];
    key_data = (const unsigned char *) k_holder->array_data;
    key_len = k_holder->size;
    mac_len = 0;

    if (key_len == 0) { key_data = &hmac_empty_key; }

    if (HMAC(md, key_data, (int) key_len,
             (const unsigned char *) m_holder->array_data, m_holder->size,
             mac, &mac_len) == NULL) {
        return NULL;
    }

    result_array = __create_array(mac_len, 1, &Am_Lang_Array_ta_Am_Lang_UByte, uchar_type);
    r_holder = (array_holder *) &result_array[1];
    result_data = (unsigned char *) r_holder->array_data;
    for (i = 0; i < mac_len; i++) {
        result_data[i] = mac[i];
    }
    return result_array;
}

function_result Am_Crypto_Hmac_sha256_0(aobject * var_key, aobject * var_message)
{
    function_result __result = { .has_return_value = true };
    bool __returning = false;
    aobject *mac;

    if (var_key != NULL) { __increase_reference_count(var_key); }
    if (var_message != NULL) { __increase_reference_count(var_message); }

    if (!hmac_ensure_amissl(&__result, "in Am_Crypto_Hmac_sha256_0")) {
        goto __exit;
    }
    mac = hmac_compute(EVP_sha256(), var_key, var_message);
    if (mac == NULL) {
        __throw_simple_exception("HMAC-SHA-256 failed", "in Am_Crypto_Hmac_sha256_0", &__result);
        goto __exit;
    }
    __result.return_value.flags = 0;
    __result.return_value.value.object_value = mac;

__exit: ;
    if (var_message != NULL) { __decrease_reference_count(var_message); }
    if (var_key != NULL) { __decrease_reference_count(var_key); }
    return __result;
}

function_result Am_Crypto_Hmac_sha1_0(aobject * var_key, aobject * var_message)
{
    function_result __result = { .has_return_value = true };
    bool __returning = false;
    aobject *mac;

    if (var_key != NULL) { __increase_reference_count(var_key); }
    if (var_message != NULL) { __increase_reference_count(var_message); }

    if (!hmac_ensure_amissl(&__result, "in Am_Crypto_Hmac_sha1_0")) {
        goto __exit;
    }
    mac = hmac_compute(EVP_sha1(), var_key, var_message);
    if (mac == NULL) {
        __throw_simple_exception("HMAC-SHA-1 failed", "in Am_Crypto_Hmac_sha1_0", &__result);
        goto __exit;
    }
    __result.return_value.flags = 0;
    __result.return_value.value.object_value = mac;

__exit: ;
    if (var_message != NULL) { __decrease_reference_count(var_message); }
    if (var_key != NULL) { __decrease_reference_count(var_key); }
    return __result;
}

// Lengths are equal when this is reached — the AmLang `verify` wrapper
// checks them, which is why there is no early return on length here to
// undo the whole point of the function.
//
// Written out here rather than calling CRYPTO_memcmp as the libc twin
// does, and so no AmiSSL bring-up either: whether AmiSSL's stub set
// exports CRYPTO_memcmp varies by version, and a six-line loop removes the
// question entirely. The accumulator is volatile so the m68k compiler
// cannot fold the loop back into an early exit, which is the one property
// this function exists to have.
function_result Am_Crypto_Hmac_constantTimeEquals_0(aobject * var_a, aobject * var_b)
{
    function_result __result = { .has_return_value = true };
    bool __returning = false;
    array_holder *a_holder;
    array_holder *b_holder;
    const unsigned char *ad;
    const unsigned char *bd;
    volatile unsigned char diff;
    unsigned int i;
    int equal;

    if (var_a != NULL) { __increase_reference_count(var_a); }
    if (var_b != NULL) { __increase_reference_count(var_b); }

    a_holder = (array_holder *) &var_a[1];
    b_holder = (array_holder *) &var_b[1];
    equal = 0;
    if (a_holder->size == b_holder->size) {
        ad = (const unsigned char *) a_holder->array_data;
        bd = (const unsigned char *) b_holder->array_data;
        diff = 0;
        for (i = 0; i < a_holder->size; i++) {
            diff = diff | (unsigned char) (ad[i] ^ bd[i]);
        }
        equal = (diff == 0) ? 1 : 0;
    }
    __result.return_value.flags = 0;
    __result.return_value.value.bool_value = equal ? true : false;

__exit: ;
    if (var_b != NULL) { __decrease_reference_count(var_b); }
    if (var_a != NULL) { __decrease_reference_count(var_a); }
    return __result;
}
