# ISC License
#
# Copyright (c) 2019, Robin Linden
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#

# Modified by Stuart Schechter
set(LIBSODIUM_REPOSITORY_DIR ${CMAKE_CURRENT_SOURCE_DIR}/extern/libsodium)

cmake_minimum_required(VERSION 3.11)

if(POLICY CMP0077)
    cmake_policy(SET CMP0077 NEW)
endif()

project("sodium")

option(SODIUM_MINIMAL "Only compile the minimum set of functions required for the high-level API" OFF)
option(SODIUM_ENABLE_BLOCKING_RANDOM "Enable this switch only if /dev/urandom is totally broken on the target platform" OFF)
option(SODIUM_PRETEND_TO_BE_CONFIGURED "Silence warnings about build system not being properly configured" ON)

set (SODIUM_SRC_BASE ${LIBSODIUM_REPOSITORY_DIR}/src/libsodium)

add_library(${PROJECT_NAME}
    ${SODIUM_SRC_BASE}/crypto_aead/aes256gcm/aesni/aead_aes256gcm_aesni.c
    ${SODIUM_SRC_BASE}/crypto_aead/chacha20poly1305/sodium/aead_chacha20poly1305.c
    ${SODIUM_SRC_BASE}/crypto_aead/xchacha20poly1305/sodium/aead_xchacha20poly1305.c
    ${SODIUM_SRC_BASE}/crypto_auth/crypto_auth.c
    ${SODIUM_SRC_BASE}/crypto_auth/hmacsha256/auth_hmacsha256.c
    ${SODIUM_SRC_BASE}/crypto_auth/hmacsha512/auth_hmacsha512.c
    ${SODIUM_SRC_BASE}/crypto_auth/hmacsha512256/auth_hmacsha512256.c
    ${SODIUM_SRC_BASE}/crypto_box/crypto_box.c
    ${SODIUM_SRC_BASE}/crypto_box/crypto_box_easy.c
    ${SODIUM_SRC_BASE}/crypto_box/crypto_box_seal.c
    ${SODIUM_SRC_BASE}/crypto_box/curve25519xsalsa20poly1305/box_curve25519xsalsa20poly1305.c
    ${SODIUM_SRC_BASE}/crypto_core/ed25519/ref10/ed25519_ref10.c
    ${SODIUM_SRC_BASE}/crypto_core/hchacha20/core_hchacha20.c
    ${SODIUM_SRC_BASE}/crypto_core/hsalsa20/core_hsalsa20.c
    ${SODIUM_SRC_BASE}/crypto_core/hsalsa20/ref2/core_hsalsa20_ref2.c
    ${SODIUM_SRC_BASE}/crypto_core/salsa/ref/core_salsa_ref.c
    ${SODIUM_SRC_BASE}/crypto_generichash/blake2b/generichash_blake2.c
    ${SODIUM_SRC_BASE}/crypto_generichash/blake2b/ref/blake2b-compress-avx2.c
    ${SODIUM_SRC_BASE}/crypto_generichash/blake2b/ref/blake2b-compress-ref.c
    ${SODIUM_SRC_BASE}/crypto_generichash/blake2b/ref/blake2b-compress-sse41.c
    ${SODIUM_SRC_BASE}/crypto_generichash/blake2b/ref/blake2b-compress-ssse3.c
    ${SODIUM_SRC_BASE}/crypto_generichash/blake2b/ref/blake2b-ref.c
    ${SODIUM_SRC_BASE}/crypto_generichash/blake2b/ref/generichash_blake2b.c
    ${SODIUM_SRC_BASE}/crypto_generichash/crypto_generichash.c
    ${SODIUM_SRC_BASE}/crypto_hash/crypto_hash.c
    ${SODIUM_SRC_BASE}/crypto_hash/sha256/cp/hash_sha256_cp.c
    ${SODIUM_SRC_BASE}/crypto_hash/sha256/hash_sha256.c
    ${SODIUM_SRC_BASE}/crypto_hash/sha512/cp/hash_sha512_cp.c
    ${SODIUM_SRC_BASE}/crypto_hash/sha512/hash_sha512.c
    ${SODIUM_SRC_BASE}/crypto_kdf/blake2b/kdf_blake2b.c
    ${SODIUM_SRC_BASE}/crypto_kdf/crypto_kdf.c
    ${SODIUM_SRC_BASE}/crypto_kx/crypto_kx.c
    ${SODIUM_SRC_BASE}/crypto_onetimeauth/crypto_onetimeauth.c
    ${SODIUM_SRC_BASE}/crypto_onetimeauth/poly1305/donna/poly1305_donna.c
    ${SODIUM_SRC_BASE}/crypto_onetimeauth/poly1305/onetimeauth_poly1305.c
    ${SODIUM_SRC_BASE}/crypto_onetimeauth/poly1305/sse2/poly1305_sse2.c
    ${SODIUM_SRC_BASE}/crypto_pwhash/argon2/argon2-core.c
    ${SODIUM_SRC_BASE}/crypto_pwhash/argon2/argon2-encoding.c
    ${SODIUM_SRC_BASE}/crypto_pwhash/argon2/argon2-fill-block-avx2.c
    ${SODIUM_SRC_BASE}/crypto_pwhash/argon2/argon2-fill-block-avx512f.c
    ${SODIUM_SRC_BASE}/crypto_pwhash/argon2/argon2-fill-block-ref.c
    ${SODIUM_SRC_BASE}/crypto_pwhash/argon2/argon2-fill-block-ssse3.c
    ${SODIUM_SRC_BASE}/crypto_pwhash/argon2/argon2.c
    ${SODIUM_SRC_BASE}/crypto_pwhash/argon2/blake2b-long.c
    ${SODIUM_SRC_BASE}/crypto_pwhash/argon2/pwhash_argon2i.c
    ${SODIUM_SRC_BASE}/crypto_pwhash/argon2/pwhash_argon2id.c
    ${SODIUM_SRC_BASE}/crypto_pwhash/crypto_pwhash.c
    ${SODIUM_SRC_BASE}/crypto_scalarmult/crypto_scalarmult.c
    ${SODIUM_SRC_BASE}/crypto_scalarmult/curve25519/ref10/x25519_ref10.c
    ${SODIUM_SRC_BASE}/crypto_scalarmult/curve25519/sandy2x/curve25519_sandy2x.c
    ${SODIUM_SRC_BASE}/crypto_scalarmult/curve25519/sandy2x/fe51_invert.c
    ${SODIUM_SRC_BASE}/crypto_scalarmult/curve25519/sandy2x/fe_frombytes_sandy2x.c
    ${SODIUM_SRC_BASE}/crypto_scalarmult/curve25519/scalarmult_curve25519.c
    ${SODIUM_SRC_BASE}/crypto_secretbox/crypto_secretbox.c
    ${SODIUM_SRC_BASE}/crypto_secretbox/crypto_secretbox_easy.c
    ${SODIUM_SRC_BASE}/crypto_secretbox/xsalsa20poly1305/secretbox_xsalsa20poly1305.c
    ${SODIUM_SRC_BASE}/crypto_secretstream/xchacha20poly1305/secretstream_xchacha20poly1305.c
    ${SODIUM_SRC_BASE}/crypto_shorthash/crypto_shorthash.c
    ${SODIUM_SRC_BASE}/crypto_shorthash/siphash24/ref/shorthash_siphash24_ref.c
    ${SODIUM_SRC_BASE}/crypto_shorthash/siphash24/shorthash_siphash24.c
    ${SODIUM_SRC_BASE}/crypto_sign/crypto_sign.c
    ${SODIUM_SRC_BASE}/crypto_sign/ed25519/ref10/keypair.c
    ${SODIUM_SRC_BASE}/crypto_sign/ed25519/ref10/open.c
    ${SODIUM_SRC_BASE}/crypto_sign/ed25519/ref10/sign.c
    ${SODIUM_SRC_BASE}/crypto_sign/ed25519/sign_ed25519.c
    ${SODIUM_SRC_BASE}/crypto_stream/chacha20/dolbeau/chacha20_dolbeau-avx2.c
    ${SODIUM_SRC_BASE}/crypto_stream/chacha20/dolbeau/chacha20_dolbeau-ssse3.c
    ${SODIUM_SRC_BASE}/crypto_stream/chacha20/ref/chacha20_ref.c
    ${SODIUM_SRC_BASE}/crypto_stream/chacha20/stream_chacha20.c
    ${SODIUM_SRC_BASE}/crypto_stream/crypto_stream.c
    ${SODIUM_SRC_BASE}/crypto_stream/salsa20/ref/salsa20_ref.c
    ${SODIUM_SRC_BASE}/crypto_stream/salsa20/stream_salsa20.c
    ${SODIUM_SRC_BASE}/crypto_stream/salsa20/xmm6/salsa20_xmm6.c
    ${SODIUM_SRC_BASE}/crypto_stream/salsa20/xmm6int/salsa20_xmm6int-avx2.c
    ${SODIUM_SRC_BASE}/crypto_stream/salsa20/xmm6int/salsa20_xmm6int-sse2.c
    ${SODIUM_SRC_BASE}/crypto_stream/xsalsa20/stream_xsalsa20.c
    ${SODIUM_SRC_BASE}/crypto_verify/sodium/verify.c
    ${SODIUM_SRC_BASE}/randombytes/internal/randombytes_internal_random.c
    ${SODIUM_SRC_BASE}/randombytes/randombytes.c
    ${SODIUM_SRC_BASE}/randombytes/sysrandom/randombytes_sysrandom.c
    ${SODIUM_SRC_BASE}/sodium/codecs.c
    ${SODIUM_SRC_BASE}/sodium/core.c
    ${SODIUM_SRC_BASE}/sodium/runtime.c
    ${SODIUM_SRC_BASE}/sodium/utils.c
    ${SODIUM_SRC_BASE}/sodium/version.c
    ${SODIUM_SRC_BASE}/crypto_box/curve25519xchacha20poly1305/box_curve25519xchacha20poly1305.c
    ${SODIUM_SRC_BASE}/crypto_box/curve25519xchacha20poly1305/box_seal_curve25519xchacha20poly1305.c
    ${SODIUM_SRC_BASE}/crypto_core/ed25519/core_ed25519.c
    ${SODIUM_SRC_BASE}/crypto_core/ed25519/core_ristretto255.c
    ${SODIUM_SRC_BASE}/crypto_pwhash/scryptsalsa208sha256/crypto_scrypt-common.c
    ${SODIUM_SRC_BASE}/crypto_pwhash/scryptsalsa208sha256/nosse/pwhash_scryptsalsa208sha256_nosse.c
    ${SODIUM_SRC_BASE}/crypto_pwhash/scryptsalsa208sha256/pbkdf2-sha256.c
    ${SODIUM_SRC_BASE}/crypto_pwhash/scryptsalsa208sha256/pwhash_scryptsalsa208sha256.c
    ${SODIUM_SRC_BASE}/crypto_pwhash/scryptsalsa208sha256/scrypt_platform.c
    ${SODIUM_SRC_BASE}/crypto_pwhash/scryptsalsa208sha256/sse/pwhash_scryptsalsa208sha256_sse.c
    ${SODIUM_SRC_BASE}/crypto_scalarmult/ed25519/ref10/scalarmult_ed25519_ref10.c
    ${SODIUM_SRC_BASE}/crypto_scalarmult/ristretto255/ref10/scalarmult_ristretto255_ref10.c
    ${SODIUM_SRC_BASE}/crypto_secretbox/xchacha20poly1305/secretbox_xchacha20poly1305.c
    ${SODIUM_SRC_BASE}/crypto_shorthash/siphash24/ref/shorthash_siphashx24_ref.c
    ${SODIUM_SRC_BASE}/crypto_shorthash/siphash24/shorthash_siphashx24.c
    ${SODIUM_SRC_BASE}/crypto_stream/salsa2012/ref/stream_salsa2012_ref.c
    ${SODIUM_SRC_BASE}/crypto_stream/salsa2012/stream_salsa2012.c
    ${SODIUM_SRC_BASE}/crypto_stream/salsa208/ref/stream_salsa208_ref.c
    ${SODIUM_SRC_BASE}/crypto_stream/salsa208/stream_salsa208.c
    ${SODIUM_SRC_BASE}/crypto_stream/xchacha20/stream_xchacha20.c
)

set_target_properties(${PROJECT_NAME}
    PROPERTIES
        C_STANDARD 99
)

target_include_directories(${PROJECT_NAME}
    PUBLIC
        ${SODIUM_SRC_BASE}/include
    PRIVATE
        ${SODIUM_SRC_BASE}/include/sodium
)

target_compile_definitions(${PROJECT_NAME}
    PUBLIC
        $<$<NOT:$<BOOL:${BUILD_SHARED_LIBS}>>:SODIUM_STATIC>
        $<$<BOOL:${SODIUM_MINIMAL}>:SODIUM_LIBRARY_MINIMAL>
    PRIVATE
        $<$<BOOL:${BUILD_SHARED_LIBS}>:SODIUM_DLL_EXPORT>
        $<$<BOOL:${SODIUM_ENABLE_BLOCKING_RANDOM}>:USE_BLOCKING_RANDOM>
        $<$<BOOL:${SODIUM_MINIMAL}>:MINIMAL>
        $<$<BOOL:${SODIUM_PRETEND_TO_BE_CONFIGURED}>:CONFIGURED>
)

# Variables that need to be exported to version.h.in
set(VERSION 1.0.18)
set(SODIUM_LIBRARY_VERSION_MAJOR 10)
set(SODIUM_LIBRARY_VERSION_MINOR 3)
if(SODIUM_MINIMAL)
    set(SODIUM_LIBRARY_MINIMAL_DEF "#define SODIUM_LIBRARY_MINIMAL 1")
endif()

configure_file(
    ${SODIUM_SRC_BASE}/include/sodium/version.h.in
    ${SODIUM_SRC_BASE}/include/sodium/version.h
)
