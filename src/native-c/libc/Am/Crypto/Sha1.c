#include <libc/core.h>
#include <Am/Crypto/Sha1.h>
#include <Am/Lang/UByte.h>
#include <Am/Lang/Array.h>
#include <libc/core_inline_functions.h>

#include <openssl/sha.h>

// Lifecycle hooks — Sha1 is stateless, but every `native class` needs
// these symbols defined so the runtime's class table can dispatch them.

function_result Am_Crypto_Sha1__native_init_0(aobject * const this)
{
    function_result __result = { .has_return_value = false };
    if (this != NULL) { __increase_reference_count(this); }
__exit: ;
    if (this != NULL) { __decrease_reference_count(this); }
    return __result;
}

// Streaming hasher state, kept in the instance's custom_value slot.
// Allocated lazily by the first updateNative (or by finish on an
// empty stream); freed here in release so an abandoned hasher — one
// that was updated but never finished — doesn't leak.
typedef struct {
    SHA_CTX ctx;
    int finished;
} sha1_stream_state;

// Fetch (allocating + SHA1_Init-ing on first use) the stream state.
// Returns NULL with an exception already recorded when the hasher was
// already finished or the allocation failed.
static sha1_stream_state * sha1_stream_get(aobject * const self, function_result * const result, const char * const site) {
    sha1_stream_state *st = (sha1_stream_state *) self->object_properties.class_object_properties.object_data.value.custom_value;
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

function_result Am_Crypto_Sha1__native_release_0(aobject * const this)
{
    function_result __result = { .has_return_value = false };
    sha1_stream_state *st = (sha1_stream_state *) this->object_properties.class_object_properties.object_data.value.custom_value;
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
    if (var_input != NULL) { __increase_reference_count(var_input); }

    array_holder *a_holder = (array_holder *) &var_input[1];
    unsigned int input_len = a_holder->size;
    unsigned char *input_data = (unsigned char *) a_holder->array_data;

    unsigned char digest[SHA_DIGEST_LENGTH]; // 20 bytes
    SHA1(input_data, input_len, digest);

    aobject *result_array = __create_array(SHA_DIGEST_LENGTH, 1, &Am_Lang_Array_ta_Am_Lang_UByte, uchar_type);
    array_holder *r_holder = (array_holder *) &result_array[1];
    unsigned char *result_data = (unsigned char *) r_holder->array_data;
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
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
    if (this != NULL) { __increase_reference_count(this); }
    if (var_input != NULL) { __increase_reference_count(var_input); }

    // Range was validated by the AmLang updateRange wrapper.
    {
        sha1_stream_state *st = sha1_stream_get(this, &__result, "in Am_Crypto_Sha1_updateNative_0");
        if (st != NULL) {
            array_holder *a_holder = (array_holder *) &var_input[1];
            SHA1_Update(&st->ctx, ((unsigned char *) a_holder->array_data) + var_offset, var_length);
        }
    }

    if (var_input != NULL) { __decrease_reference_count(var_input); }
    if (this != NULL) { __decrease_reference_count(this); }
    return __result;
}

function_result Am_Crypto_Sha1_finish_0(aobject * const this)
{
    function_result __result = { .has_return_value = true };
    if (this != NULL) { __increase_reference_count(this); }

    {
        // An empty stream (finish with no update) allocates + inits here,
        // yielding SHA-1 of the empty input — same as digest("").
        sha1_stream_state *st = sha1_stream_get(this, &__result, "in Am_Crypto_Sha1_finish_0");
        if (st != NULL) {
            unsigned char digest[SHA_DIGEST_LENGTH];
            aobject *result_array;
            array_holder *r_holder;
            unsigned char *result_data;
            int i;
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
    }

    if (this != NULL) { __decrease_reference_count(this); }
    return __result;
}

// No-op on libc backends — there's no per-task AmiSSL state to tear
// down. The AmLang Sha1.nativeInit lambda still calls this through
// the Thread finalizer; it just doesn't do anything here.
function_result Am_Crypto_Sha1_closeAmiSSLForThread_0(void)
{
    function_result __result = { .has_return_value = false };
    return __result;
}
