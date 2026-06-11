#include <libc/core.h>
#include <Am/Crypto/Sha1.h>
#include <amigaos/Am/Crypto/Sha1.h>
#include <Am/Lang/ClassRef.h>
#include <Am/Lang/UByte.h>
#include <Am/Lang/Array.h>
#include <Am/Lang/Object.h>
#include <libc/core_inline_functions.h>

// AmigaOS m68k SHA-1 binding. Library opening / global library bases
// live in src/native-c/amigaos/amissl_init.{c,h} so every native
// class in am-crypto that uses OpenSSL APIs can share one set of
// strong-symbol globals (defining them per-file would multiply-define
// AmiSSLBase / SocketBase / etc. at link time).

#include <amigaos/am_crypto_amissl_init.h>
#include <openssl/sha.h>

function_result Am_Crypto_CryptoPrivate_f_openSslInitialized_0(void);
function_result Am_Crypto_CryptoPrivate_f_setOpenSslInitialized_0(void);

// Lifecycle hooks — Sha1 is a stateless static-only `native class`,
// so all three are no-ops. We deliberately do NOT close AmiSSL
// here — see amissl_init.c for the rationale.

function_result Am_Crypto_Sha1__native_init_0(aobject * const this)
{
    function_result __result = { .has_return_value = false };
    if (this != NULL) { __increase_reference_count(this); }
__exit: ;
    if (this != NULL) { __decrease_reference_count(this); }
    return __result;
}

function_result Am_Crypto_Sha1__native_release_0(aobject * const this)
{
    function_result __result = { .has_return_value = false };
    return __result;
}

function_result Am_Crypto_Sha1__native_mark_children_0(aobject * const this)
{
    function_result __result = { .has_return_value = false };
    return __result;
}

function_result Am_Crypto_Sha1_digest_0(aobject * var_input)
{
    function_result __result = { .has_return_value = true };
    bool __returning = false;
    aobject *result_array;
    array_holder *a_holder;
    array_holder *r_holder;
    unsigned int input_len;
    unsigned char *input_data;
    unsigned char *result_data;
    unsigned char digest[SHA_DIGEST_LENGTH]; // 20 bytes
    int i;

    if (var_input != NULL) { __increase_reference_count(var_input); }

    {
        function_result openssl_state = Am_Crypto_CryptoPrivate_f_openSslInitialized_0();
        if (!openssl_state.return_value.value.bool_value) {
            if (!am_crypto_amissl_ensure_initialised()) {
                __throw_simple_exception("Failed to initialise AmiSSL", "in Am_Crypto_Sha1_digest_0", &__result);
                goto __exit;
            }
            Am_Crypto_CryptoPrivate_f_setOpenSslInitialized_0();
        }
    }

    // Per-task AmiSSL bring-up. amisslauto handled main task at
    // constructor time; worker tasks need their own InitAmiSSL pair
    // before any AmiSSL/OpenSSL call. Idempotent — returns 1 fast on
    // an already-brought-up task, and on non-AmLang tasks.
    if (!am_crypto_amissl_ensure_initialised_for_current_task()) {
        __throw_simple_exception("Failed per-task AmiSSL init", "in Am_Crypto_Sha1_digest_0", &__result);
        goto __exit;
    }

    a_holder = (array_holder *) &var_input[1];
    input_len = a_holder->size;
    input_data = (unsigned char *) a_holder->array_data;

    SHA1(input_data, input_len, digest);

    result_array = __create_array(SHA_DIGEST_LENGTH, 1, &Am_Lang_Array_ta_Am_Lang_UByte, uchar_type);
    r_holder = (array_holder *) &result_array[1];
    result_data = (unsigned char *) r_holder->array_data;
    for (i = 0; i < SHA_DIGEST_LENGTH; i++) {
        result_data[i] = digest[i];
    }

    __result.return_value.flags = 0;
    __result.return_value.value.object_value = result_array;

__exit: ;
    if (var_input != NULL) { __decrease_reference_count(var_input); }
    return __result;
}

// Thread finalizer registered by Sha1.nativeInit (the AmLang lambda
// added in Sha1.aml). Runs on the worker task as it shuts down, so
// FindTask(NULL) inside am_crypto_amissl_close_for_current_task
// resolves to the task whose AmiSSL state we're tearing down.
function_result Am_Crypto_Sha1_closeAmiSSLForThread_0(void)
{
    function_result __result = { .has_return_value = false };
    am_crypto_amissl_close_for_current_task();
    return __result;
}
