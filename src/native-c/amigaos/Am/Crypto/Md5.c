#include <libc/core.h>
#include <Am/Crypto/Md5.h>
#include <amigaos/Am/Crypto/Md5.h>
#include <Am/Lang/ClassRef.h>
#include <Am/Lang/UByte.h>
#include <Am/Lang/Array.h>
#include <Am/Lang/Object.h>
#include <libc/core_inline_functions.h>

// AmigaOS m68k MD5 binding. Library opening / global library bases live in
// src/native-c/amigaos/am_crypto_amissl_init.{c,h} so every native class in
// am-crypto that uses OpenSSL APIs shares one set of strong-symbol globals
// (defining them per-file would multiply-define AmiSSLBase / SocketBase at
// link time). This file therefore adds a digest WITHOUT adding any library
// bookkeeping — which is the whole reason MD5 belongs in am-crypto rather
// than in each caller.
//
// Declarations only, no C89 violations: this builds with the m68k toolchain,
// so every local is declared at the top of its block.

#include <amigaos/am_crypto_amissl_init.h>
#include <openssl/md5.h>

function_result Am_Crypto_CryptoPrivate_f_openSslInitialized_0(void);
function_result Am_Crypto_CryptoPrivate_f_setOpenSslInitialized_0(void);

function_result Am_Crypto_Md5__native_init_0(aobject * const this)
{
    function_result __result = { .has_return_value = false };
    if (this != NULL) { __increase_reference_count(this); }
__exit: ;
    if (this != NULL) { __decrease_reference_count(this); }
    return __result;
}

// Streaming hasher state (see the libc twin for the full rationale) — lives
// in custom_value, freed in release so abandoned hashers don't leak.
// MD5_Init/Update/Final are AmiSSL calls here, so every entry point below
// runs the same AmiSSL bring-up digest() does BEFORE touching the context.
typedef struct {
    MD5_CTX ctx;
    int finished;
} md5_stream_state;

static md5_stream_state * md5_stream_get(aobject * const self, function_result * const result, const char * const site) {
    md5_stream_state *st;
    st = (md5_stream_state *) self->object_properties.class_object_properties.object_data.value.custom_value;
    if (st == NULL) {
        st = (md5_stream_state *) calloc(1, sizeof(md5_stream_state));
        if (st == NULL) {
            __throw_simple_exception("Out of memory allocating Md5 stream state", site, result);
            return NULL;
        }
        MD5_Init(&st->ctx);
        self->object_properties.class_object_properties.object_data.value.custom_value = st;
    }
    if (st->finished) {
        __throw_simple_exception("Md5 hasher already finished - create a new Md5 to hash again", site, result);
        return NULL;
    }
    return st;
}

// The AmiSSL bring-up shared by digest/updateNative/finish, and the same
// sequence Sha1 runs. Returns 0 with the exception recorded on failure.
static int md5_ensure_amissl(function_result * const result, const char * const site) {
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

function_result Am_Crypto_Md5__native_release_0(aobject * const this)
{
    function_result __result = { .has_return_value = false };
    md5_stream_state *st;
    st = (md5_stream_state *) this->object_properties.class_object_properties.object_data.value.custom_value;
    if (st != NULL) {
        free(st);
        this->object_properties.class_object_properties.object_data.value.custom_value = NULL;
    }
    return __result;
}

function_result Am_Crypto_Md5__native_mark_children_0(aobject * const this)
{
    function_result __result = { .has_return_value = false };
    return __result;
}

function_result Am_Crypto_Md5_digest_0(aobject * var_input)
{
    function_result __result = { .has_return_value = true };
    bool __returning = false;
    aobject *result_array;
    array_holder *a_holder;
    array_holder *r_holder;
    unsigned int input_len;
    unsigned char *input_data;
    unsigned char *result_data;
    unsigned char digest[MD5_DIGEST_LENGTH]; // 16 bytes
    int i;

    if (var_input != NULL) { __increase_reference_count(var_input); }

    if (!md5_ensure_amissl(&__result, "in Am_Crypto_Md5_digest_0")) {
        goto __exit;
    }

    a_holder = (array_holder *) &var_input[1];
    input_len = a_holder->size;
    input_data = (unsigned char *) a_holder->array_data;

    MD5(input_data, input_len, digest);

    result_array = __create_array(MD5_DIGEST_LENGTH, 1, &Am_Lang_Array_ta_Am_Lang_UByte, uchar_type);
    r_holder = (array_holder *) &result_array[1];
    result_data = (unsigned char *) r_holder->array_data;
    for (i = 0; i < MD5_DIGEST_LENGTH; i++) {
        result_data[i] = digest[i];
    }

    __result.return_value.flags = 0;
    __result.return_value.value.object_value = result_array;

__exit: ;
    if (var_input != NULL) { __decrease_reference_count(var_input); }
    return __result;
}

function_result Am_Crypto_Md5_updateNative_0(aobject * const this, aobject * var_input, unsigned int var_offset, unsigned int var_length)
{
    function_result __result = { .has_return_value = false };
    md5_stream_state *st;
    array_holder *a_holder;

    if (this != NULL) { __increase_reference_count(this); }
    if (var_input != NULL) { __increase_reference_count(var_input); }

    if (!md5_ensure_amissl(&__result, "in Am_Crypto_Md5_updateNative_0")) {
        goto __exit;
    }
    // Range was validated by the AmLang updateRange wrapper.
    st = md5_stream_get(this, &__result, "in Am_Crypto_Md5_updateNative_0");
    if (st != NULL) {
        a_holder = (array_holder *) &var_input[1];
        MD5_Update(&st->ctx, ((unsigned char *) a_holder->array_data) + var_offset, var_length);
    }

__exit: ;
    if (var_input != NULL) { __decrease_reference_count(var_input); }
    if (this != NULL) { __decrease_reference_count(this); }
    return __result;
}

function_result Am_Crypto_Md5_finish_0(aobject * const this)
{
    function_result __result = { .has_return_value = true };
    md5_stream_state *st;
    unsigned char digest[MD5_DIGEST_LENGTH];
    aobject *result_array;
    array_holder *r_holder;
    unsigned char *result_data;
    int i;

    if (this != NULL) { __increase_reference_count(this); }

    if (!md5_ensure_amissl(&__result, "in Am_Crypto_Md5_finish_0")) {
        goto __exit;
    }
    // An empty stream (finish with no update) inits here — MD5 of the empty
    // input, same as digest("").
    st = md5_stream_get(this, &__result, "in Am_Crypto_Md5_finish_0");
    if (st != NULL) {
        MD5_Final(digest, &st->ctx);
        st->finished = 1;
        result_array = __create_array(MD5_DIGEST_LENGTH, 1, &Am_Lang_Array_ta_Am_Lang_UByte, uchar_type);
        r_holder = (array_holder *) &result_array[1];
        result_data = (unsigned char *) r_holder->array_data;
        for (i = 0; i < MD5_DIGEST_LENGTH; i++) {
            result_data[i] = digest[i];
        }
        __result.return_value.flags = 0;
        __result.return_value.value.object_value = result_array;
    }

__exit: ;
    if (this != NULL) { __decrease_reference_count(this); }
    return __result;
}
