/* Copyright (c) 2015, Google Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

#include <gtest/gtest.h>

#include <openssl/x509.h>

#include "../internal.h"
#include "pkcs11.h"
#include "config.h"

bssl::UniquePtr<RSA> rsa(RSA_new());
bssl::UniquePtr<EC_KEY> ec(EC_KEY_new_by_curve_name(NID_X9_62_prime256v1));

TEST(PKCS11Test, RSAKeyGen) {
#ifdef ENABLE_PKCS11
    PKCS11_init();
    CK_SESSION_HANDLE session;
    ASSERT_TRUE(PKCS11_login(&session, PKCS11_TOKEN_LABEL, (unsigned char *) PKCS11_TOKEN_PIN, strlen(PKCS11_TOKEN_PIN)));

    bssl::UniquePtr<BIGNUM> e(BN_new());
    BN_set_word(e.get(), RSA_F4);

    ASSERT_TRUE(PKCS11_RSA_generate_key_ex(session, rsa.get(), 2048, e.get()));
    ASSERT_EQ(BN_num_bits(rsa.get()->n), (unsigned)2048);
    ASSERT_TRUE(BN_cmp(e.get(), rsa.get()->e) == 0);

    PKCS11_logout(session);
    PKCS11_kill();
#endif
}

TEST(PKCS11Test, RSAEncryptDecrypt) {
#ifdef ENABLE_PKCS11
    PKCS11_init();
    CK_SESSION_HANDLE session;
    ASSERT_TRUE(PKCS11_login(&session, PKCS11_TOKEN_LABEL, (unsigned char *) PKCS11_TOKEN_PIN, strlen(PKCS11_TOKEN_PIN)));

    unsigned char msg[] = "some junk text";
    unsigned char encrypted[256];
    size_t enclen = 256;

    ASSERT_TRUE(PKCS11_RSA_encrypt(session, rsa.get(), encrypted, &enclen, enclen, msg, 14, RSA_PKCS1_PADDING));

    unsigned char decrypted[256];
    size_t declen = 256;

    ASSERT_TRUE(PKCS11_RSA_decrypt(session, rsa.get(), decrypted, &declen, declen, encrypted, enclen, RSA_PKCS1_PADDING));
    ASSERT_TRUE(memcmp(msg, decrypted, declen) == 0);

    PKCS11_logout(session);
    PKCS11_kill();
#endif
}

TEST(PKCS11Test, RSASignVerify) {
#ifdef ENABLE_PKCS11
    PKCS11_init();
    CK_SESSION_HANDLE session;
    ASSERT_TRUE(PKCS11_login(&session, PKCS11_TOKEN_LABEL, (unsigned char *) PKCS11_TOKEN_PIN, strlen(PKCS11_TOKEN_PIN)));

    unsigned char msg[] = "testing string";
    unsigned char signature[256];
    size_t siglen = 256;
    int ok;

    ASSERT_TRUE(PKCS11_RSA_sign(session, rsa.get(), NID_sha512, signature, &siglen, msg, 14));
    ASSERT_TRUE(PKCS11_RSA_verify(session, rsa.get(), NID_sha512, msg, 14, signature, siglen, &ok));
    ASSERT_TRUE(ok);

    PKCS11_logout(session);
    PKCS11_kill();
#endif
}

TEST(PKCS11, ECKeyGen) {
#ifdef ENABLE_PKCS11
    PKCS11_init();
    CK_SESSION_HANDLE session;
    ASSERT_TRUE(PKCS11_login(&session, PKCS11_TOKEN_LABEL, (unsigned char *) PKCS11_TOKEN_PIN, strlen(PKCS11_TOKEN_PIN)));

    ASSERT_TRUE(PKCS11_EC_KEY_generate_key(session, ec.get()));

    PKCS11_logout(session);
    PKCS11_kill();
#endif
}

TEST(PKCS11, ECDSASignVerify) {
#ifdef ENABLE_PKCS11
    PKCS11_init();
    CK_SESSION_HANDLE session;
    ASSERT_TRUE(PKCS11_login(&session, PKCS11_TOKEN_LABEL, (unsigned char *) PKCS11_TOKEN_PIN, strlen(PKCS11_TOKEN_PIN)));

    unsigned char hash[] = "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD";
    unsigned char signature[256];
    size_t siglen = 256;

    ASSERT_TRUE(PKCS11_ECDSA_sign(session, ec.get(), hash, 64, signature, &siglen));
    ASSERT_TRUE(PKCS11_ECDSA_verify(session, ec.get(), hash, 64, signature, siglen));

    ///// TO DO /////
    //@Zhang Xichu
    // test the new version of ECDSA sign and verify function
    unsigned char msg[] = "testing string";
    unsigned char signature_new[256];
    size_t siglen_new = 256;
    int ok;
    ASSERT_TRUE(PKCS11_ECDSA_sign_new(session, ec.get(), NID_sha512, signature_new, &siglen_new, msg, 14));
    ASSERT_TRUE(PKCS11_ECDSA_verify_new(session, ec.get(), NID_sha512, msg, 14, signature_new, siglen_new, &ok));

    // ASSERT_TRUE(PKCS11_RSA_verify(session, rsa.get(), NID_sha512, msg, 14, signature, siglen, &ok));
    /////////////////////

    PKCS11_logout(session);
    PKCS11_kill();
#endif
}