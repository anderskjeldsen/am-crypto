// One-shot OpenSSL-level setup for AmigaOS m68k.
//
// Library bring-up (bsdsocket.library, amisslmaster.library, AmiSSL
// itself) is handled by `-lamisslauto`'s constructor before main runs.
// What amisslauto does NOT do is the OpenSSL-level init that AmiSSL's
// own test/https.c performs explicitly — without those two calls,
// `SSL_CTX_new` produces a context with no usable cipher list and the
// TLS handshake silently fails (peer closes connection during
// ClientHello). Verified by stripping ssl-c-test down to match
// https.c.
//
// So `am_crypto_amissl_ensure_initialised()` here is a thin idempotent wrapper
// that calls:
//   1) OPENSSL_init_ssl with ADD_ALL_CIPHERS|ADD_ALL_DIGESTS — populates
//      the EVP cipher table.
//   2) RAND_seed with weak entropy — m68k has no /dev/urandom and the
//      handshake needs random bytes for ClientHello.random and
//      ephemeral keys.
//
// Library globals (AmiSSLBase / AmiSSLExtBase / AmiSSLMasterBase /
// SocketBase) are NOT defined here any more — amisslauto declares them
// WEAK and we let it own them. am-net's amigaos Socket.c also weak-
// defines SocketBase, so when both are linked everyone shares the same
// global through amisslauto's strong-after-link resolution.

#include <libc/core.h>
#include <amigaos/am_crypto_amissl_init.h>

#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>

#include <exec/types.h>
#include <exec/tasks.h>
#include <proto/exec.h>
#include <proto/amisslmaster.h>
#include <proto/amissl.h>
#include <libraries/amisslmaster.h>

extern struct Library *SocketBase;       // owned by am-net's Socket.c
extern struct Library *AmiSSLMasterBase; // owned by amisslauto
extern struct Library *AmiSSLBase;       // owned by amisslauto

function_result Am_Util_Random_randomInt_0(int max);

static void seed_rand(void)
{
    unsigned char buf[256];
    unsigned int i;
    for (i = 0; i < sizeof(buf); i++) {
        function_result random_value = Am_Util_Random_randomInt_0(256);
        buf[i] = (unsigned char)(random_value.return_value.value.int_value & 0xFF);
    }
    RAND_seed(buf, sizeof(buf));
}

int am_crypto_amissl_ensure_initialised(void)
{
    OPENSSL_init_ssl(
        OPENSSL_INIT_SSL_DEFAULT
        | OPENSSL_INIT_ADD_ALL_CIPHERS
        | OPENSSL_INIT_ADD_ALL_DIGESTS,
        NULL);
    seed_rand();
    return 1;
}

// Per-AmLang-Thread AmiSSL bring-up tracker. Same shape as am-net's
// per-task bsdsocket tracker — keyed by the AmLang Thread aobject
// (FindTask(NULL)->tc_UserData) so nativeInit and the matching
// finalizer agree on the task identity.
//
// Per amissl.library/InitAmiSSLA docs, subprocesses share the
// AmiSSLBase the main process opened — we only call OpenLibrary on
// amisslmaster + InitAmiSSL per subprocess (no per-task OpenAmiSSL,
// which the docs flag as wasting resources). errno_slot is the
// per-task `int errno` we hand AmiSSL via the AmiSSL_ErrNoPtr tag;
// each task needs its own so two workers can't trample each other's
// last-error.
struct crypto_task_node {
    aobject *thread;
    int errno_slot;
    struct crypto_task_node *next;
};

static struct crypto_task_node *crypto_task_list = NULL;

static aobject *current_amlang_thread(void)
{
    struct Task *task = FindTask(NULL);
    if (task == NULL) {
        return NULL;
    }
    return (aobject *) task->tc_UserData;
}

static struct crypto_task_node *crypto_task_lookup(aobject *thread)
{
    struct crypto_task_node *n;
    struct crypto_task_node *found = NULL;
    Forbid();
    for (n = crypto_task_list; n != NULL; n = n->next) {
        if (n->thread == thread) {
            found = n;
            break;
        }
    }
    Permit();
    return found;
}

static struct crypto_task_node *crypto_task_register(aobject *thread)
{
    struct crypto_task_node *node =
        (struct crypto_task_node *) malloc(sizeof(struct crypto_task_node));
    if (node == NULL) {
        return NULL;
    }
    node->thread = thread;
    node->errno_slot = 0;
    Forbid();
    node->next = crypto_task_list;
    crypto_task_list = node;
    Permit();
    return node;
}

static struct crypto_task_node *crypto_task_unregister(aobject *thread)
{
    struct crypto_task_node *prev = NULL;
    struct crypto_task_node *n;
    Forbid();
    for (n = crypto_task_list; n != NULL; n = n->next) {
        if (n->thread == thread) {
            if (prev == NULL) {
                crypto_task_list = n->next;
            } else {
                prev->next = n->next;
            }
            break;
        }
        prev = n;
    }
    Permit();
    return n;   // caller frees
}

// Forward declaration so the bring-up path can call back into the
// AmLang Sha1 class to register the Thread finalizer. The symbol
// follows the generated `<Class>_f_<method>_<index>` convention for
// non-native AmLang static methods.
extern function_result Am_Crypto_Sha1_f_nativeInit_0(void);

int am_crypto_amissl_ensure_initialised_for_current_task(void)
{
    // EXPERIMENT (2026-05-27): per the AmiSSL docs, subprocesses must
    // call InitAmiSSL / CleanupAmiSSL. But our SHA-1-on-worker test
    // Gurus inside amisslauto's destructor at process exit, while the
    // identical run without the per-task bring-up (and without using
    // SHA-1 on the worker) exits cleanly. So this version is a
    // hypothesis test: maybe newer AmiSSL builds tolerate (or even
    // require) the worker to just use the shared AmiSSLBase with no
    // per-task Init at all. If the SHA-1 test exits cleanly with this
    // stub, the per-task contract documented in
    // AmiSsl/dist/amissl.doc no longer applies (or never applied to
    // pure-crypto subprocesses).
    //
    // Side effects of this experiment:
    //   * worker never gets its own errno_slot — any AmiSSL error on
    //     the worker will write to main's errno location (or wherever
    //     AmiSSL falls back to). Fine for SHA-1 because SHA-1 doesn't
    //     produce errors of interest.
    //   * worker never bumps the amisslmaster open count, so
    //     amisslauto's destructor sees the count it expects.
    //   * the Sha1.nativeInit finalizer registration is also skipped
    //     (so no worker-side teardown ever runs).
    (void) crypto_task_lookup;
    (void) crypto_task_register;
    (void) crypto_task_unregister;
    return 1;
}

void am_crypto_amissl_close_for_current_task(void)
{
    aobject *thread;
    struct crypto_task_node *node;

    printf("close_for_current_task: enter (task=%p)\n", (void *) FindTask(NULL));
    fflush(stdout);

    thread = current_amlang_thread();
    printf("close_for_current_task: amlang thread=%p\n", (void *) thread);
    fflush(stdout);
    if (thread == NULL) {
        return;
    }
    node = crypto_task_unregister(thread);
    printf("close_for_current_task: unregister returned node=%p\n", (void *) node);
    fflush(stdout);
    if (node == NULL) {
        return;
    }
    // CleanupAmiSSL releases this task's per-task SSL state and
    // disassociates the errno pointer we set in InitAmiSSL. No
    // CloseAmiSSL — per docs subprocesses don't open AmiSSL.
    printf("close_for_current_task: calling CleanupAmiSSL\n");
    fflush(stdout);
    CleanupAmiSSL(TAG_DONE);
    printf("close_for_current_task: CleanupAmiSSL done\n");
    fflush(stdout);
    if (AmiSSLMasterBase != NULL) {
        printf("close_for_current_task: calling CloseLibrary(AmiSSLMasterBase=%p)\n",
               (void *) AmiSSLMasterBase);
        fflush(stdout);
        CloseLibrary(AmiSSLMasterBase);
        printf("close_for_current_task: CloseLibrary done\n");
        fflush(stdout);
    }
    free(node);
    printf("close_for_current_task: free(node) done; returning\n");
    fflush(stdout);
}
