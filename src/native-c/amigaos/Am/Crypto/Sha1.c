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

// Streaming hasher state (see the libc twin for the full rationale) —
// lives in custom_value, freed in release so abandoned hashers don't
// leak. SHA1_Init/Update/Final are AmiSSL calls here, so every entry
// point below runs the same AmiSSL bring-up digest() does BEFORE
// touching the context.
typedef struct {
    SHA_CTX ctx;
    int finished;
} sha1_stream_state;

static sha1_stream_state * sha1_stream_get(aobject * const self, function_result * const result, const char * const site) {
    sha1_stream_state *st;
    st = (sha1_stream_state *) self->object_properties.class_object_properties.object_data.value.custom_value;
    if (st == NULL) {
        st = (sha1_stream_state *) calloc(1, sizeof(sha1_stream_state));
        if (st == NULL) {
            __throw_simple_exception("Out of memory allocating Sha1 stream state", site, result);
            return NULL;
        }
        SHA1_Init(&st->ctx);
        self->object_properties.class_object_properties.object_data.value.custom_value = st;
    }
    if (st->finished) {
        __throw_simple_exception("Sha1 hasher already finished - create a new Sha1 to hash again", site, result);
        return NULL;
    }
    return st;
}

// The AmiSSL bring-up shared by digest/updateNative/finish. Returns
// 0 with the exception recorded on failure.
static int sha1_ensure_amissl(function_result * const result, const char * const site) {
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

function_result Am_Crypto_Sha1__native_release_0(aobject * const this)
{
    function_result __result = { .has_return_value = false };
    sha1_stream_state *st;
    st = (sha1_stream_state *) this->object_properties.class_object_properties.object_data.value.custom_value;
    if (st != NULL) {
        free(st);
        this->object_properties.class_object_properties.object_data.value.custom_value = NULL;
    }
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

function_result Am_Crypto_Sha1_updateNative_0(aobject * const this, aobject * var_input, unsigned int var_offset, unsigned int var_length)
{
    function_result __result = { .has_return_value = false };
    sha1_stream_state *st;
    array_holder *a_holder;

    if (this != NULL) { __increase_reference_count(this); }
    if (var_input != NULL) { __increase_reference_count(var_input); }

    if (!sha1_ensure_amissl(&__result, "in Am_Crypto_Sha1_updateNative_0")) {
        goto __exit;
    }
    // Range was validated by the AmLang updateRange wrapper.
    st = sha1_stream_get(this, &__result, "in Am_Crypto_Sha1_updateNative_0");
    if (st != NULL) {
        a_holder = (array_holder *) &var_input[1];
        SHA1_Update(&st->ctx, ((unsigned char *) a_holder->array_data) + var_offset, var_length);
    }

__exit: ;
    if (var_input != NULL) { __decrease_reference_count(var_input); }
    if (this != NULL) { __decrease_reference_count(this); }
    return __result;
}

function_result Am_Crypto_Sha1_finish_0(aobject * const this)
{
    function_result __result = { .has_return_value = true };
    sha1_stream_state *st;
    unsigned char digest[SHA_DIGEST_LENGTH];
    aobject *result_array;
    array_holder *r_holder;
    unsigned char *result_data;
    int i;

    if (this != NULL) { __increase_reference_count(this); }

    if (!sha1_ensure_amissl(&__result, "in Am_Crypto_Sha1_finish_0")) {
        goto __exit;
    }
    // An empty stream (finish with no update) inits here — SHA-1 of the
    // empty input, same as digest("").
    st = sha1_stream_get(this, &__result, "in Am_Crypto_Sha1_finish_0");
    if (st != NULL) {
        SHA1_Final(digest, &st->ctx);
        st->finished = 1;
        result_array = __create_array(SHA_DIGEST_LENGTH, 1, &Am_Lang_Array_ta_Am_Lang_UByte, uchar_type);
        r_holder = (array_holder *) &result_array[1];
        result_data = (unsigned char *) r_holder->array_data;
        for (i = 0; i < SHA_DIGEST_LENGTH; i++) {
            result_data[i] = digest[i];
        }
        __result.return_value.flags = 0;
        __result.return_value.value.object_value = result_array;
    }

__exit: ;
    if (this != NULL) { __decrease_reference_count(this); }
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
