#include <libc/core.h>
#include <Am/Crypto/Hmac.h>
#include <Am/Lang/UByte.h>
#include <Am/Lang/Array.h>
#include <libc/core_inline_functions.h>

#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

// The libc twin of amigaos/Am/Crypto/Hmac.c. Stateless statics only — no
// custom_value, no streaming — because a MAC is computed over a message
// the caller already has, and the one caller shape that would want
// streaming (a MAC over something too large to hold) does not exist on
// the hosts this targets.
//
// The lifecycle hooks below are still defined: amlc emits declarations
// for them on every native class, instantiated or not.

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

// One byte to point at when the key is empty. HMAC with a zero-length key
// is well defined (it is zero-padded to the block size like any short
// key), but the pointer still has to be a pointer.
static const unsigned char hmac_empty_key = 0;

static aobject * hmac_compute(const EVP_MD *md, aobject * var_key, aobject * var_message)
{
    array_holder *k_holder = (array_holder *) &var_key[1];
    array_holder *m_holder = (array_holder *) &var_message[1];
    const unsigned char *key_data = (const unsigned char *) k_holder->array_data;
    unsigned int key_len = k_holder->size;
    unsigned char mac[EVP_MAX_MD_SIZE];
    unsigned int mac_len = 0;
    aobject *result_array;
    array_holder *r_holder;
    unsigned char *result_data;
    unsigned int i;

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
    if (var_key != NULL) { __increase_reference_count(var_key); }
    if (var_message != NULL) { __increase_reference_count(var_message); }

    {
        aobject *mac = hmac_compute(EVP_sha256(), var_key, var_message);
        if (mac == NULL) {
            __throw_simple_exception("HMAC-SHA-256 failed", "in Am_Crypto_Hmac_sha256_0", &__result);
        } else {
            __result.return_value.flags = 0;
            __result.return_value.value.object_value = mac;
        }
    }

__exit: ;
    if (var_message != NULL) { __decrease_reference_count(var_message); }
    if (var_key != NULL) { __decrease_reference_count(var_key); }
    return __result;
}

function_result Am_Crypto_Hmac_sha1_0(aobject * var_key, aobject * var_message)
{
    function_result __result = { .has_return_value = true };
    bool __returning = false;
    if (var_key != NULL) { __increase_reference_count(var_key); }
    if (var_message != NULL) { __increase_reference_count(var_message); }

    {
        aobject *mac = hmac_compute(EVP_sha1(), var_key, var_message);
        if (mac == NULL) {
            __throw_simple_exception("HMAC-SHA-1 failed", "in Am_Crypto_Hmac_sha1_0", &__result);
        } else {
            __result.return_value.flags = 0;
            __result.return_value.value.object_value = mac;
        }
    }

__exit: ;
    if (var_message != NULL) { __decrease_reference_count(var_message); }
    if (var_key != NULL) { __decrease_reference_count(var_key); }
    return __result;
}

// Lengths are equal when this is reached — the AmLang `verify` wrapper
// checks them, which is why there is no early return on length here to
// undo the whole point of the function.
function_result Am_Crypto_Hmac_constantTimeEquals_0(aobject * var_a, aobject * var_b)
{
    function_result __result = { .has_return_value = true };
    bool __returning = false;
    if (var_a != NULL) { __increase_reference_count(var_a); }
    if (var_b != NULL) { __increase_reference_count(var_b); }

    {
        array_holder *a_holder = (array_holder *) &var_a[1];
        array_holder *b_holder = (array_holder *) &var_b[1];
        int equal = 0;
        if (a_holder->size != b_holder->size) {
            equal = 0;
        } else if (a_holder->size == 0) {
            // Two empty byte strings are equal, and CRYPTO_memcmp with a
            // length of 0 is not somewhere to find out what the platform
            // thinks about that.
            equal = 1;
        } else {
            equal = (CRYPTO_memcmp(a_holder->array_data, b_holder->array_data, a_holder->size) == 0) ? 1 : 0;
        }
        __result.return_value.flags = 0;
        __result.return_value.value.bool_value = equal ? true : false;
    }

__exit: ;
    if (var_b != NULL) { __decrease_reference_count(var_b); }
    if (var_a != NULL) { __decrease_reference_count(var_a); }
    return __result;
}
