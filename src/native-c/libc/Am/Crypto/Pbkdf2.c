#include <libc/core.h>
#include <Am/Crypto/Pbkdf2.h>
#include <Am/Lang/UByte.h>
#include <Am/Lang/Array.h>
#include <libc/core_inline_functions.h>

#include <openssl/evp.h>

// The libc twin of amigaos/Am/Crypto/Pbkdf2.c. Stateless statics; the
// iteration count and output length were range-checked by the AmLang
// wrapper, so a negative length cannot arrive here and be read as an
// enormous unsigned one.

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

static aobject * pbkdf2_derive(const EVP_MD *md, aobject * var_password, aobject * var_salt,
                               int iterations, int length)
{
    array_holder *p_holder = (array_holder *) &var_password[1];
    array_holder *s_holder = (array_holder *) &var_salt[1];
    aobject *result_array = __create_array(length, 1, &Am_Lang_Array_ta_Am_Lang_UByte, uchar_type);
    array_holder *r_holder = (array_holder *) &result_array[1];

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
    if (var_password != NULL) { __increase_reference_count(var_password); }
    if (var_salt != NULL) { __increase_reference_count(var_salt); }

    {
        aobject *key = pbkdf2_derive(EVP_sha256(), var_password, var_salt, var_iterations, var_length);
        if (key == NULL) {
            __throw_simple_exception("PBKDF2-HMAC-SHA-256 failed", "in Am_Crypto_Pbkdf2_deriveSha256_0", &__result);
        } else {
            __result.return_value.flags = 0;
            __result.return_value.value.object_value = key;
        }
    }

__exit: ;
    if (var_salt != NULL) { __decrease_reference_count(var_salt); }
    if (var_password != NULL) { __decrease_reference_count(var_password); }
    return __result;
}

function_result Am_Crypto_Pbkdf2_deriveSha1_0(aobject * var_password, aobject * var_salt, int var_iterations, int var_length)
{
    function_result __result = { .has_return_value = true };
    bool __returning = false;
    if (var_password != NULL) { __increase_reference_count(var_password); }
    if (var_salt != NULL) { __increase_reference_count(var_salt); }

    {
        aobject *key = pbkdf2_derive(EVP_sha1(), var_password, var_salt, var_iterations, var_length);
        if (key == NULL) {
            __throw_simple_exception("PBKDF2-HMAC-SHA-1 failed", "in Am_Crypto_Pbkdf2_deriveSha1_0", &__result);
        } else {
            __result.return_value.flags = 0;
            __result.return_value.value.object_value = key;
        }
    }

__exit: ;
    if (var_salt != NULL) { __decrease_reference_count(var_salt); }
    if (var_password != NULL) { __decrease_reference_count(var_password); }
    return __result;
}
