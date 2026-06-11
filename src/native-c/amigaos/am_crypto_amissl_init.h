#ifndef AM_CRYPTO_AMIGAOS_AMISSL_INIT_H
#define AM_CRYPTO_AMIGAOS_AMISSL_INIT_H

// Shared one-shot OpenSSL-level init for every native class in am-crypto
// that calls OpenSSL APIs on AmigaOS m68k. Library opens are handled
// by `-lamisslauto` (its constructor runs before main); what we add
// here is OPENSSL_init_ssl + RAND_seed, which amisslauto does not do
// itself. See am_crypto_amissl_init.c for the full rationale.
//
// Package-prefixed filename + include guard so the analogous header in
// am-ssl (am_ssl_amissl_init.h) doesn't collide via the shared
// `-I additional/<pkg>/` search path.

// Idempotent — call from every native function that uses an OpenSSL
// API. Returns 1 on success. (Currently always succeeds; the int
// return is kept so consumers can guard a graceful failure path if a
// future implementation needs to.)
int am_crypto_amissl_ensure_initialised(void);

// Per-AmLang-Thread bring-up of AmiSSL. Per amissl.library/InitAmiSSLA
// docs: subprocesses share the main task's AmiSSLBase but each must
// call InitAmiSSL(...) before any other AmiSSL call and CleanupAmiSSL()
// before exit. amisslauto's constructor did this for the main task;
// worker threads need their own pair.
//
// Returns 1 on success (or already brought up, or called from a
// non-AmLang task). Returns 0 if OpenLibrary or InitAmiSSL fails.
// Counterpart cleanup is `am_crypto_amissl_close_for_current_task`,
// dispatched from the Thread finalizer Sha1.nativeInit() registers.
int am_crypto_amissl_ensure_initialised_for_current_task(void);

// Per-task tear-down. Called via the Thread finalizer registered by
// Sha1.nativeInit(); runs on the same task that opened, so
// `FindTask(NULL)` is the task whose AmiSSL state we're releasing.
void am_crypto_amissl_close_for_current_task(void);

#endif
