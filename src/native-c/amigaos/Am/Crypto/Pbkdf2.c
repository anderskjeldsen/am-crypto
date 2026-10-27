#include <libc/core.h>
#include <Am/Crypto/Pbkdf2.h>
#include <amigaos/Am/Crypto/Pbkdf2.h>
#include <Am/Lang/ClassRef.h>
#include <Am/Lang/UByte.h>
#include <Am/Lang/Array.h>
#include <Am/Lang/Object.h>
#include <libc/core_inline_functions.h>

// AmigaOS m68k PBKDF2 binding — the twin of libc/Am/Crypto/Pbkdf2.c.
// Library bring-up is shared through am_crypto_amissl_init.{c,h}.
//
// A word on cost: this is the one function in am-crypto that is SUPPOSED
// to be slow, and on a 68k it will be very slow indeed — a derivation at
// the iteration counts modern servers use is minutes of a machine that
// cannot do anything else meanwhile, since AmiSSL runs on the calling
// task. Pick the count for the hardware, not from a web page; the AmLang
// side documents the trade in full.
//
// Declarations only, no C89 violations: this builds with the m68k
// toolchain, so every local is declared at the top of its block.

#include <amigaos/am_crypto_amissl_init.h>
#include <openssl/evp.h>

function_result Am_Crypto_CryptoPrivate_f_openSslInitialized_0(void);
function_result Am_Crypto_CryptoPrivate_f_setOpenSslInitialized_0(void);

function_result Am_Crypto_Pbkdf2__native_init_0(aobject * const this)
{
    function_result __result = { .has_return_value = false };
    if (this != NULL) { __increase_reference_count(this); }
__exit: ;
    if (this != NULL) { __decrease_reference_count(this); }
    return __result;
}

function_result Am_Crypto_Pbkdf2__native_release_0(aobject * const this)
{
    function_result __result = { .has_return_value = false };
    return __result;
}

function_result Am_Crypto_Pbkdf2__native_mark_children_0(aobject * const this)
{
    function_result __result = { .has_return_value = false };
    return __result;
}

static int pbkdf2_ensure_amissl(function_result * const result, const char * const site) {
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

static aobject * pbkdf2_derive(const EVP_MD *md, aobject * var_password, aobject * var_salt,
                               int iterations, int length)
{
    array_holder *p_holder;
    array_holder *s_holder;
    aobject *result_array;
    array_holder *r_holder;

    p_holder = (array_holder *) &var_password[1];
    s_holder = (array_holder *) &var_salt[1];
    result_array = __create_array(length, 1, &Am_Lang_Array_ta_Am_Lang_UByte, uchar_type);
    r_holder = (array_holder *) &result_array[1];

    // Derived straight into the result array: PBKDF2's output is the only
    // thing in it, there is no partial state to hide, and a scratch
    // buffer would just be a second copy of a secret to forget to clear.
    if (PKCS5_PBKDF2_HMAC((const char *) p_holder->array_data, (int) p_holder->size,
                          (const unsigned char *) s_holder->array_data, (int) s_holder->size,
                          iterations, md, length,
                          (unsigned char *) r_holder->array_data) != 1) {
        __decrease_reference_count(result_array);
        return NULL;
    }
    return result_array;
}

function_result Am_Crypto_Pbkdf2_deriveSha256_0(aobject * var_password, aobject * var_salt, int var_iterations, int var_length)
{
    function_result __result = { .has_return_value = true };
    bool __returning = false;
    aobject *key;

    if (var_password != NULL) { __increase_reference_count(var_password); }
    if (var_salt != NULL) { __increase_reference_count(var_salt); }

    if (!pbkdf2_ensure_amissl(&__result, "in Am_Crypto_Pbkdf2_deriveSha256_0")) {
        goto __exit;
    }
    key = pbkdf2_derive(EVP_sha256(), var_password, var_salt, var_iterations, var_length);
    if (key == NULL) {
        __throw_simple_exception("PBKDF2-HMAC-SHA-256 failed", "in Am_Crypto_Pbkdf2_deriveSha256_0", &__result);
        goto __exit;
    }
    __result.return_value.flags = 0;
    __result.return_value.value.object_value = key;

__exit: ;
    if (var_salt != NULL) { __decrease_reference_count(var_salt); }
    if (var_password != NULL) { __decrease_reference_count(var_password); }
    return __result;
}

function_result Am_Crypto_Pbkdf2_deriveSha1_0(aobject * var_password, aobject * var_salt, int var_iterations, int var_length)
{
    function_result __result = { .has_return_value = true };
    bool __returning = false;
    aobject *key;

    if (var_password != NULL) { __increase_reference_count(var_password); }
    if (var_salt != NULL) { __increase_reference_count(var_salt); }

    if (!pbkdf2_ensure_amissl(&__result, "in Am_Crypto_Pbkdf2_deriveSha1_0")) {
        goto __exit;
    }
    key = pbkdf2_derive(EVP_sha1(), var_password, var_salt, var_iterations, var_length);
    if (key == NULL) {
        __throw_simple_exception("PBKDF2-HMAC-SHA-1 failed", "in Am_Crypto_Pbkdf2_deriveSha1_0", &__result);
        goto __exit;
    }
    __result.return_value.flags = 0;
    __result.return_value.value.object_value = key;

__exit: ;
    if (var_salt != NULL) { __decrease_reference_count(var_salt); }
    if (var_password != NULL) { __decrease_reference_count(var_password); }
    return __result;
}
