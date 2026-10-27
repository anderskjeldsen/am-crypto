#include <libc/core.h>
#include <Am/Crypto/Sha256.h>
#include <Am/Lang/UByte.h>
#include <Am/Lang/Array.h>
#include <libc/core_inline_functions.h>

#include <openssl/sha.h>

// The libc twin of amigaos/Am/Crypto/Sha256.c, and a close mirror of
// Md5.c and Sha1.c next door: same lifecycle hooks, same custom_value
// stream state, same array construction. Kept parallel on purpose — the
// digests are read side by side, and a difference in shape here reads as
// a difference in meaning.

function_result Am_Crypto_Sha256__native_init_0(aobject * const this)
{
    function_result __result = { .has_return_value = false };
    if (this != NULL) { __increase_reference_count(this); }
__exit: ;
    if (this != NULL) { __decrease_reference_count(this); }
    return __result;
}

// Streaming hasher state, kept in the instance's custom_value slot.
// Allocated lazily by the first updateNative (or by finish on an empty
// stream); freed in release so an abandoned hasher — one that was updated
// but never finished — doesn't leak.
typedef struct {
    SHA256_CTX ctx;
    int finished;
} sha256_stream_state;

static sha256_stream_state * sha256_stream_get(aobject * const self, function_result * const result, const char * const site) {
    sha256_stream_state *st = (sha256_stream_state *) self->object_properties.class_object_properties.object_data.value.custom_value;
    if (st == NULL) {
        st = (sha256_stream_state *) calloc(1, sizeof(sha256_stream_state));
        if (st == NULL) {
            __throw_simple_exception("Out of memory allocating Sha256 stream state", site, result);
            return NULL;
        }
        SHA256_Init(&st->ctx);
        self->object_properties.class_object_properties.object_data.value.custom_value = st;
    }
    if (st->finished) {
        __throw_simple_exception("Sha256 hasher already finished - create a new Sha256 to hash again", site, result);
        return NULL;
    }
    return st;
}

function_result Am_Crypto_Sha256__native_release_0(aobject * const this)
{
    function_result __result = { .has_return_value = false };
    sha256_stream_state *st = (sha256_stream_state *) this->object_properties.class_object_properties.object_data.value.custom_value;
    if (st != NULL) {
        free(st);
        this->object_properties.class_object_properties.object_data.value.custom_value = NULL;
    }
    return __result;
}

function_result Am_Crypto_Sha256__native_mark_children_0(aobject * const this)
{
    function_result __result = { .has_return_value = false };
    return __result;
}

function_result Am_Crypto_Sha256_digest_0(aobject * var_input)
{
    function_result __result = { .has_return_value = true };
    bool __returning = false;
    if (var_input != NULL) { __increase_reference_count(var_input); }

    array_holder *a_holder = (array_holder *) &var_input[1];
    unsigned int input_len = a_holder->size;
    unsigned char *input_data = (unsigned char *) a_holder->array_data;

    unsigned char digest[SHA256_DIGEST_LENGTH]; // 32 bytes
    SHA256(input_data, input_len, digest);

    aobject *result_array = __create_array(SHA256_DIGEST_LENGTH, 1, &Am_Lang_Array_ta_Am_Lang_UByte, uchar_type);
    array_holder *r_holder = (array_holder *) &result_array[1];
    unsigned char *result_data = (unsigned char *) r_holder->array_data;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        result_data[i] = digest[i];
    }

    __result.return_value.flags = 0;
    __result.return_value.value.object_value = result_array;

__exit: ;
    if (var_input != NULL) { __decrease_reference_count(var_input); }
    return __result;
}

function_result Am_Crypto_Sha256_updateNative_0(aobject * const this, aobject * var_input, unsigned int var_offset, unsigned int var_length)
{
    function_result __result = { .has_return_value = false };
    if (this != NULL) { __increase_reference_count(this); }
    if (var_input != NULL) { __increase_reference_count(var_input); }

    // Range was validated by the AmLang updateRange wrapper.
    {
        sha256_stream_state *st = sha256_stream_get(this, &__result, "in Am_Crypto_Sha256_updateNative_0");
        if (st != NULL) {
            array_holder *a_holder = (array_holder *) &var_input[1];
            SHA256_Update(&st->ctx, ((unsigned char *) a_holder->array_data) + var_offset, var_length);
        }
    }

    if (var_input != NULL) { __decrease_reference_count(var_input); }
    if (this != NULL) { __decrease_reference_count(this); }
    return __result;
}

function_result Am_Crypto_Sha256_finish_0(aobject * const this)
{
    function_result __result = { .has_return_value = true };
    if (this != NULL) { __increase_reference_count(this); }

    {
        // An empty stream (finish with no update) allocates + inits here,
        // yielding SHA-256 of the empty input — same as digest("").
        sha256_stream_state *st = sha256_stream_get(this, &__result, "in Am_Crypto_Sha256_finish_0");
        if (st != NULL) {
            unsigned char digest[SHA256_DIGEST_LENGTH];
            aobject *result_array;
            array_holder *r_holder;
            unsigned char *result_data;
            int i;
            SHA256_Final(digest, &st->ctx);
            st->finished = 1;
            result_array = __create_array(SHA256_DIGEST_LENGTH, 1, &Am_Lang_Array_ta_Am_Lang_UByte, uchar_type);
            r_holder = (array_holder *) &result_array[1];
            result_data = (unsigned char *) r_holder->array_data;
            for (i = 0; i < SHA256_DIGEST_LENGTH; i++) {
                result_data[i] = digest[i];
            }
            __result.return_value.flags = 0;
            __result.return_value.value.object_value = result_array;
        }
    }

    if (this != NULL) { __decrease_reference_count(this); }
    return __result;
}
