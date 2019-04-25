#include <memory.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/nid.h>
#include <openssl/ec_key.h>
#include <openssl/bytestring.h>
#include <openssl/mem.h>
#include "pkcs11.h"
#include "config.h"

#ifdef ENABLE_PKCS11
    #include PKCS11_HEADER
    #include "../fipsmodule/ec/internal.h"
#endif

//#define BUFFER_MAX_ECPOINT_LEN ((528*2 / 8) + 1)
#define BUFFER_MAX_ECPOINT_LEN 2048

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

static CK_BBOOL CTRUE  = TRUE;
static CK_BBOOL CFALSE = FALSE;

// Common functions

int PKCS11_init(void)
{
#ifndef ENABLE_PKCS11
    OPENSSL_PUT_ERROR(PKCS11,PKCS11_NOT_ENABLED);
    return 0;
#endif
	CK_RV ret;
	if ((ret = C_Initialize(NULL)) != CKR_OK) {
		OPENSSL_PUT_ERROR(PKCS11,ret);
		return 0;
	}
	return 1;
}

int PKCS11_kill(void)
{
#ifndef ENABLE_PKCS11
    OPENSSL_PUT_ERROR(PKCS11,PKCS11_NOT_ENABLED);
    return 0;
#endif
	CK_RV ret;
	if ((ret = C_Finalize(NULL)) != CKR_OK) {
		OPENSSL_PUT_ERROR(PKCS11,ret);
		return 0;
	}
	return 1;
}

static int find_the_token(CK_SLOT_ID *slot, const char *label) {
    CK_RV ret;

    /* get slot list: */
    unsigned long count = 0;
    if ((ret = C_GetSlotList(TRUE, NULL, &count)) != CKR_OK) {
        OPENSSL_PUT_ERROR(PKCS11,ret);
        return 0;
    }
    CK_SLOT_ID slots[count];
    if ((ret = C_GetSlotList(TRUE, slots, &count)) != CKR_OK) {
        OPENSSL_PUT_ERROR(PKCS11,ret);
        return 0;
    }

    /* find the desired token: */
    int token_found = 0;
    for (unsigned long i = 0; i < count; i++) {
        CK_TOKEN_INFO token;
        if ((ret = C_GetTokenInfo(slots[i], &token)) != CKR_OK) {
            OPENSSL_PUT_ERROR(PKCS11,ret);
            return 0;
        }
        if (memcmp(label, token.label, strlen(label)) == 0) {
            token_found = 1;
            *slot = slots[i];
            break;
        }
    }
    if (!token_found) {
        OPENSSL_PUT_ERROR(PKCS11,PKCS11_LABEL_NOT_FOUND);
        return 0;
    }
    return 1;
}

int PKCS11_login(CK_SESSION_HANDLE* session, const char *label, unsigned char *pin, size_t pinlength) {
#ifndef ENABLE_PKCS11
    OPENSSL_PUT_ERROR(PKCS11,PKCS11_NOT_ENABLED);
    return 0;
#endif
    CK_RV ret;
    CK_SLOT_ID slot;

    if (!find_the_token(&slot, label)) {
        return 0;
    }

    if ((ret = C_OpenSession(slot, CKF_RW_SESSION | CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, session)) != CKR_OK) {
        OPENSSL_PUT_ERROR(PKCS11,ret);
        return 0;
    }

    if ((ret = C_Login(*session, CKU_USER, pin, pinlength)) != CKR_OK) {
        OPENSSL_PUT_ERROR(PKCS11,ret);
        return 0;
    }

    return 1;
}

int PKCS11_logout(CK_SESSION_HANDLE session)
{
#ifndef ENABLE_PKCS11
    OPENSSL_PUT_ERROR(PKCS11,PKCS11_NOT_ENABLED);
    return 0;
#endif
    CK_RV ret;
	if((ret = C_Logout(session)) != CKR_OK)
	{
		return 0;
	}
	if((ret = C_CloseSession(session)) != CKR_OK)
	{
		return 0;
	}

	return 1;
}

// RSA private functions

static int fill_rsa_pub(RSA *rsa, CK_SESSION_HANDLE *session, CK_OBJECT_HANDLE *public, CK_ULONG bits) {
    CK_RV ret;
    CK_ULONG bytes = bits / 8;
    CK_BYTE modulus[bytes];
    CK_BYTE exp[bytes];

    CK_ATTRIBUTE templ[] = {
            { CKA_MODULUS, modulus, bytes },
            { CKA_PUBLIC_EXPONENT, exp, bytes }
    };

    if ((ret = C_GetAttributeValue(*session, *public, templ, ARRAY_SIZE(templ))) != CKR_OK) {
        OPENSSL_PUT_ERROR(PKCS11, ret);
        return 0;
    }

    BIGNUM *e = NULL;
    BIGNUM *n = NULL;
    n = BN_bin2bn(modulus, templ[0].ulValueLen, NULL);
    e = BN_bin2bn(exp, templ[1].ulValueLen, NULL);
    rsa->e = e;
    rsa->n = n;

    return 1;
}

static int get_rsa_key(const CK_SESSION_HANDLE *session, CK_OBJECT_HANDLE *key, const RSA *rsa, CK_OBJECT_CLASS class) {
    CK_RV ret;
    CK_KEY_TYPE type = CKK_RSA;
    CK_BYTE modulus[BN_num_bytes(rsa->n)];
    CK_BYTE exponent[BN_num_bytes(rsa->e)];
    BN_bn2bin(rsa->n, modulus);
    BN_bn2bin(rsa->e, exponent);
    CK_ATTRIBUTE templ[] = {
            { CKA_KEY_TYPE, &type, sizeof(type) },
            { CKA_CLASS, &class, sizeof(class) },
            { CKA_TOKEN, &CTRUE, sizeof(CTRUE) },
            { CKA_MODULUS, modulus, BN_num_bytes(rsa->n) },
            { CKA_PUBLIC_EXPONENT, exponent, BN_num_bytes(rsa->e) }
    };

    if ((ret = C_FindObjectsInit(*session, templ, 5)) != CKR_OK) {
        OPENSSL_PUT_ERROR(PKCS11,ret);
        return 0;
    }

    CK_ULONG count;
    if ((ret = C_FindObjects(*session, key, 1, &count)) != CKR_OK) {
        OPENSSL_PUT_ERROR(PKCS11,ret);
        return 0;
    }

    if (count < 1UL) {
        OPENSSL_PUT_ERROR(PKCS11,PKCS11_OBJECT_NOT_FOUND);
        return 0;
    }

    if ((ret = C_FindObjectsFinal(*session)) != CKR_OK) {
        OPENSSL_PUT_ERROR(PKCS11,ret);
        return 0;
    }

    return 1;
}

// RSA public functions

int PKCS11_RSA_generate_key_ex(CK_SESSION_HANDLE session, RSA *rsa, int bits, const BIGNUM *e_value) {
#ifndef ENABLE_PKCS11
    OPENSSL_PUT_ERROR(PKCS11,PKCS11_NOT_ENABLED);
    return 0;
#endif
    if (!rsa || !e_value) {
        OPENSSL_PUT_ERROR(PKCS11,ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    CK_RV ret;
    CK_MECHANISM mech = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0 };

    CK_ULONG ck_bits = bits;
    CK_BYTE ck_exponent[BN_num_bytes(e_value)];
    BN_bn2bin(e_value, ck_exponent);
    CK_ATTRIBUTE RSA_PUB_TEMPLATE[] = {
            { CKA_TOKEN, &CTRUE, sizeof(CTRUE) },
            { CKA_MODULUS_BITS, &ck_bits, sizeof(ck_bits) },
            { CKA_ENCRYPT, &CTRUE, sizeof(CTRUE) },
            { CKA_VERIFY, &CTRUE, sizeof(CTRUE) },
            { CKA_PUBLIC_EXPONENT, ck_exponent, BN_num_bytes(e_value) }
    };

    CK_ATTRIBUTE RSA_PRIV_TEMPLATE[] = {
            { CKA_TOKEN, &CTRUE, sizeof(CTRUE) },
            { CKA_EXTRACTABLE, &CFALSE, sizeof(CFALSE) },
            { CKA_SENSITIVE, &CTRUE, sizeof(CTRUE) },
            { CKA_DECRYPT, &CTRUE, sizeof(CTRUE)  },
            { CKA_SIGN, &CTRUE, sizeof(CTRUE)  }
    };

    CK_OBJECT_HANDLE priv_key, pub_key;
    if ((ret = C_GenerateKeyPair(session, &mech,
                            RSA_PUB_TEMPLATE, ARRAY_SIZE(RSA_PUB_TEMPLATE),
                            RSA_PRIV_TEMPLATE, ARRAY_SIZE(RSA_PRIV_TEMPLATE),
                            &pub_key, &priv_key)) != CKR_OK) {
        OPENSSL_PUT_ERROR(PKCS11,ret);
        return 0;
    }

    if (!fill_rsa_pub(rsa, &session, &pub_key, bits)) {
        OPENSSL_PUT_ERROR(PKCS11,PKCS11_FILL_RSA_ERR);
        return 0;
    }

    return 1;
}

int PKCS11_RSA_encrypt(CK_SESSION_HANDLE session, RSA *rsa, uint8_t *out, size_t *out_len, size_t max_out, const uint8_t *in, size_t in_len, int padding) {
#ifndef ENABLE_PKCS11
    OPENSSL_PUT_ERROR(PKCS11,PKCS11_NOT_ENABLED);
    return 0;
#endif
    if (rsa->n == NULL || rsa->e == NULL) {
        OPENSSL_PUT_ERROR(PKCS11, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    if (max_out < RSA_size(rsa)) {
        OPENSSL_PUT_ERROR(PKCS11, ERR_R_OVERFLOW);
        return 0;
    }

    CK_RV ret;

    CK_MECHANISM mech = { 0, NULL_PTR, 0 };
    CK_RSA_PKCS_OAEP_PARAMS oaepPar = { CKM_SHA_1, CKG_MGF1_SHA1, 1, NULL_PTR, 0 };
    switch (padding) {
        case RSA_PKCS1_PADDING : mech.mechanism = CKM_RSA_PKCS; break;
        case RSA_NO_PADDING : mech.mechanism = CKM_RSA_X_509; break;
        case RSA_PKCS1_OAEP_PADDING : mech.mechanism = CKM_RSA_PKCS_OAEP; mech.pParameter = &oaepPar; mech.ulParameterLen = sizeof(oaepPar); break;
        case RSA_PKCS1_PSS_PADDING : mech.mechanism = CKM_RSA_PKCS_PSS; break;
        default : OPENSSL_PUT_ERROR(PKCS11, PKCS11_UNKNOWN_PADDING); return 0;
    }

    CK_OBJECT_HANDLE public;
    if (!get_rsa_key(&session, &public, rsa, CKO_PUBLIC_KEY)) {
        return 0;
    }

    if ((ret = C_EncryptInit(session, &mech, public)) != CKR_OK) {
        OPENSSL_PUT_ERROR(PKCS11,ret);
        return 0;
    }

    if ((ret = C_Encrypt(session, (unsigned char*)in, in_len, out, out_len)) != CKR_OK) {
        OPENSSL_PUT_ERROR(PKCS11,ret);
        return 0;
    }
    return 1;
}

int PKCS11_RSA_decrypt(CK_SESSION_HANDLE session, RSA *rsa, uint8_t *out, size_t *out_len, size_t max_out, const uint8_t *in, size_t in_len, int padding) {
#ifndef ENABLE_PKCS11
    OPENSSL_PUT_ERROR(PKCS11,PKCS11_NOT_ENABLED);
    return 0;
#endif
    if (rsa->n == NULL || rsa->e == NULL) {
        OPENSSL_PUT_ERROR(PKCS11, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    if (max_out < RSA_size(rsa)) {
        OPENSSL_PUT_ERROR(PKCS11, ERR_R_OVERFLOW);
        return 0;
    }

    CK_RV ret;

    CK_MECHANISM mech = { 0, NULL_PTR, 0 };
    CK_RSA_PKCS_OAEP_PARAMS oaepPar = { CKM_SHA_1, CKG_MGF1_SHA1, 1, NULL_PTR, 0 };
    switch (padding) {
        case RSA_PKCS1_PADDING : mech.mechanism = CKM_RSA_PKCS; break;
        case RSA_NO_PADDING : mech.mechanism = CKM_RSA_X_509; break;
        case RSA_PKCS1_OAEP_PADDING : mech.mechanism = CKM_RSA_PKCS_OAEP; mech.pParameter = &oaepPar; mech.ulParameterLen = sizeof(oaepPar); break;
        case RSA_PKCS1_PSS_PADDING : mech.mechanism = CKM_RSA_PKCS_PSS; break;
        default : OPENSSL_PUT_ERROR(PKCS11, PKCS11_UNKNOWN_PADDING); return 0;
    }

    CK_OBJECT_HANDLE private;
    if (!get_rsa_key(&session, &private, rsa, CKO_PRIVATE_KEY))
        return 0;

    if ((ret = C_DecryptInit(session, &mech, private)) != CKR_OK) {
        OPENSSL_PUT_ERROR(PKCS11,ret);
        return 0;
    }

    if ((ret = C_Decrypt(session, (unsigned char*)in, in_len, out, out_len)) != CKR_OK) {
        OPENSSL_PUT_ERROR(PKCS11,ret);
        return 0;
    }
    return 1;
}

int PKCS11_RSA_sign(CK_SESSION_HANDLE session, RSA *rsa, int hash_nid, uint8_t *out, size_t *out_len, const uint8_t *in, size_t in_len) {
#ifndef ENABLE_PKCS11
    OPENSSL_PUT_ERROR(PKCS11,PKCS11_NOT_ENABLED);
    return 0;
#endif
    if (rsa->n == NULL || rsa->e == NULL) {
        OPENSSL_PUT_ERROR(PKCS11, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    CK_RV ret;

    CK_MECHANISM_TYPE type;
    switch(hash_nid) {
        case NID_md2 : type = CKM_MD2_RSA_PKCS; break;
        case NID_md5 : type = CKM_MD5_RSA_PKCS; break;
        case NID_sha1 : type = CKM_SHA1_RSA_PKCS; break;
        case NID_sha224 : type = CKM_SHA224_RSA_PKCS; break;
        case NID_sha256 : type = CKM_SHA256_RSA_PKCS; break;
        case NID_sha384 : type = CKM_SHA384_RSA_PKCS; break;
        case NID_sha512 : type = CKM_SHA512_RSA_PKCS; break;
        case NID_ripemd160 : type = CKM_RIPEMD160_RSA_PKCS; break;
        default : OPENSSL_PUT_ERROR(PKCS11, PKCS11_UNKNOWN_HASH); return 0;
    }

    CK_MECHANISM mech = { type, NULL_PTR, 0 };

    CK_OBJECT_HANDLE private;
    if (!get_rsa_key(&session, &private, rsa, CKO_PRIVATE_KEY))
        return 0;

    if ((ret = C_SignInit(session, &mech, private)) != CKR_OK) {
        OPENSSL_PUT_ERROR(PKCS11,ret);
        return 0;
    }

    CK_ULONG ret_out_len;
    if ((ret = C_Sign(session, (unsigned char*)in, in_len, out, &ret_out_len)) != CKR_OK) {
        OPENSSL_PUT_ERROR(PKCS11,ret);
        return 0;
    }
    *out_len = ret_out_len;

    return 1;
}

int PKCS11_RSA_verify(PKCS11_session session, RSA *rsa, int hash_nid, uint8_t *msg, size_t msg_len, const uint8_t *signature, size_t sig_len, int *correct) {
#ifndef ENABLE_PKCS11
    OPENSSL_PUT_ERROR(PKCS11,PKCS11_NOT_ENABLED);
    return 0;
#endif
    if (rsa->n == NULL || rsa->e == NULL) {
        OPENSSL_PUT_ERROR(PKCS11, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    CK_RV ret;

    CK_MECHANISM_TYPE type;
    switch(hash_nid) {
        case NID_md2 : type = CKM_MD2_RSA_PKCS; break;
        case NID_md5 : type = CKM_MD5_RSA_PKCS; break;
        case NID_sha1 : type = CKM_SHA1_RSA_PKCS; break;
        case NID_sha224 : type = CKM_SHA224_RSA_PKCS; break;
        case NID_sha256 : type = CKM_SHA256_RSA_PKCS; break;
        case NID_sha384 : type = CKM_SHA384_RSA_PKCS; break;
        case NID_sha512 : type = CKM_SHA512_RSA_PKCS; break;
        case NID_ripemd160 : type = CKM_RIPEMD160_RSA_PKCS; break;
        default : OPENSSL_PUT_ERROR(PKCS11, PKCS11_UNKNOWN_HASH); return 0;
    }

    CK_MECHANISM mech = { type, NULL_PTR, 0 };

    CK_OBJECT_HANDLE public;
    if (!get_rsa_key(&session, &public, rsa, CKO_PUBLIC_KEY))
        return 0;

    if ((ret = C_VerifyInit(session, &mech, public)) != CKR_OK) {
        OPENSSL_PUT_ERROR(PKCS11,ret);
        return 0;
    }

    ret = C_Verify(session, msg, msg_len, (uint8_t*) signature, sig_len);
    if(ret == CKR_OK)
	    *correct = 1;
    else if((ret == CKR_SIGNATURE_INVALID) || (ret == CKR_SIGNATURE_LEN_RANGE))
	    *correct = 0;
    else {
        OPENSSL_PUT_ERROR(PKCS11,ret);
        return 0;
    }

    return 1;
}

// ECDSA private functions

static int fill_ec_key(EC_KEY *key, CK_SESSION_HANDLE *session, CK_OBJECT_HANDLE *public) {
    CK_RV ret;
    CK_BYTE point_asn1[BUFFER_MAX_ECPOINT_LEN];

    CK_ATTRIBUTE templ[] = {
            { CKA_EC_POINT, point_asn1, sizeof(point_asn1) }
    };

    if ((ret = C_GetAttributeValue(*session, *public, templ, ARRAY_SIZE(templ))) != CKR_OK) {
        OPENSSL_PUT_ERROR(PKCS11, ret);
        return 0;
    }

    EC_POINT *point = EC_POINT_new(key->group);
    EC_POINT_oct2point(key->group, point, point_asn1 + 3, templ[0].ulValueLen - 3, NULL);
    key->pub_key = point;

    point_conversion_form_t form = point_asn1[3];
    const int y_bit = form & 1;
    form = form & ~1U;
    if ((form != POINT_CONVERSION_COMPRESSED &&
         form != POINT_CONVERSION_UNCOMPRESSED) ||
        (form == POINT_CONVERSION_UNCOMPRESSED && y_bit)) {
        OPENSSL_PUT_ERROR(PKCS11, PKCS11_INVALID_ENCODING);
        return 0;
    }
    key->conv_form = form;

    return 1;
}

static int get_ec_key(const CK_SESSION_HANDLE *session, CK_OBJECT_HANDLE *key, const EC_KEY *ec, CK_OBJECT_CLASS class) {
    CK_RV ret;
    CK_KEY_TYPE type = CKK_EC;
    CBB out_params, out_point;

    CK_BYTE *point;
    size_t point_size;
    if (!CBB_init(&out_point, 0) || !EC_POINT_point2cbb(&out_point, ec->group, ec->pub_key, ec->conv_form, NULL)) {
        OPENSSL_PUT_ERROR(PKCS11,PKCS11_EXTRACT_ASN1_FAIL);
        return 0;
    }
    CBB_finish(&out_point, &point, &point_size);

    CK_BYTE der_point[2 + point_size];
    der_point[0] = 0x04;
    der_point[1] = (uint8_t)point_size;
    OPENSSL_memcpy(&der_point[2],point,point_size);
    OPENSSL_free(point);

    CK_BYTE *params;
    size_t params_size;
    if (!CBB_init(&out_params, 0) || EC_KEY_marshal_curve_name(&out_params, ec->group)) {
        OPENSSL_PUT_ERROR(PKCS11,PKCS11_EXTRACT_ASN1_FAIL);
        return 0;
    }
    CBB_finish(&out_params, &params, &params_size);

    CK_ATTRIBUTE templ[] = {
            { CKA_KEY_TYPE, &type, sizeof(type) },
            { CKA_CLASS, &class, sizeof(class) },
            { CKA_TOKEN, &CTRUE, sizeof(CTRUE) },
            { CKA_EC_PARAMS, params, params_size },
            { CKA_EC_POINT, der_point, point_size+2 }
    };

    if ((ret = C_FindObjectsInit(*session, templ, 6)) != CKR_OK) {
        OPENSSL_PUT_ERROR(PKCS11,ret);
        return 0;
    }

    CK_ULONG count;
    if ((ret = C_FindObjects(*session, key, 1, &count)) != CKR_OK) {
        OPENSSL_PUT_ERROR(PKCS11,ret);
        return 0;
    }

    if (count < 1) {
        OPENSSL_PUT_ERROR(PKCS11,PKCS11_OBJECT_NOT_FOUND);
        return 0;
    }

    if ((ret = C_FindObjectsFinal(*session)) != CKR_OK) {
        OPENSSL_PUT_ERROR(PKCS11,ret);
        return 0;
    }

    OPENSSL_free(params);

    return 1;
}

// ECDSA public functions

int PKCS11_EC_KEY_generate_key(CK_SESSION_HANDLE session, EC_KEY *key) {
#ifndef ENABLE_PKCS11
    OPENSSL_PUT_ERROR(PKCS11,PKCS11_NOT_ENABLED);
    return 0;
#endif
    if (!key || !(key->group)) {
        OPENSSL_PUT_ERROR(PKCS11,ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    CK_RV ret;
    CK_MECHANISM mech = { CKM_EC_KEY_PAIR_GEN, NULL_PTR, 0 };

    CK_BYTE *params;
    size_t params_size;
    CBB cbb;
    if (!CBB_init(&cbb, 0)) {
	    return 0;
    }
    if(!EC_KEY_marshal_curve_name(&cbb, key->group)) {
        OPENSSL_PUT_ERROR(PKCS11,PKCS11_EXTRACT_ASN1_FAIL);
        return 0;
    }
    CBB_finish(&cbb, &params, &params_size);

    CK_ATTRIBUTE RSA_PUB_TEMPLATE[] = {
            { CKA_TOKEN, &CTRUE, sizeof(CTRUE) },
            { CKA_EC_PARAMS, params, sizeof(params)},
    };

    CK_ATTRIBUTE RSA_PRIV_TEMPLATE[] = {
            { CKA_TOKEN, &CTRUE, sizeof(CTRUE) },
            { CKA_SENSITIVE, &CTRUE, sizeof(CTRUE) },
            { CKA_DERIVE, &CTRUE, sizeof(CTRUE) },
            { CKA_EXTRACTABLE, &CFALSE, sizeof(CFALSE) },
    };

    CK_OBJECT_HANDLE priv_key, pub_key;

    if ((ret = C_GenerateKeyPair(session, &mech,
                                 RSA_PUB_TEMPLATE, ARRAY_SIZE(RSA_PUB_TEMPLATE),
                                 RSA_PRIV_TEMPLATE, ARRAY_SIZE(RSA_PRIV_TEMPLATE),
                                 &pub_key, &priv_key)) != CKR_OK) {
        OPENSSL_PUT_ERROR(PKCS11,ret);
        return 0;
    }

    if (!fill_ec_key(key, &session, &pub_key)) {
        OPENSSL_PUT_ERROR(PKCS11,PKCS11_FILL_EC_ERR);
        return 0;
    }

    return 1;
}

int PKCS11_ECDSA_sign(CK_SESSION_HANDLE session, const EC_KEY *key, const uint8_t *digest, size_t digest_len, uint8_t *sig, size_t *sig_len) {
#ifndef ENABLE_PKCS11
    OPENSSL_PUT_ERROR(PKCS11,PKCS11_NOT_ENABLED);
    return 0;
#endif
    if (key == NULL || digest == NULL) {
        OPENSSL_PUT_ERROR(PKCS11, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    CK_RV ret;
    CK_MECHANISM mech = { CKM_ECDSA, NULL_PTR, 0 };

    CK_OBJECT_HANDLE private;
    if (!get_ec_key(&session, &private, key, CKO_PRIVATE_KEY))
        return 0;

    if ((ret = C_SignInit(session, &mech, private)) != CKR_OK) {
        OPENSSL_PUT_ERROR(PKCS11,ret);
        return 0;
    }

    CK_ULONG ret_out_len;
    if ((ret = C_Sign(session, (unsigned char *)digest, digest_len, sig, &ret_out_len)) != CKR_OK) {
        OPENSSL_PUT_ERROR(PKCS11,ret);
        return 0;
    }
    *sig_len = ret_out_len;

    return 1;
}

int PKCS11_ECDSA_sign_new(PKCS11_session session, const EC_KEY *key, int hash_nid, uint8_t *sig, size_t *sig_len, const uint8_t *in, size_t in_len){
#ifndef ENABLE_PKCS11
    OPENSSL_PUT_ERROR(PKCS11,PKCS11_NOT_ENABLED);
    return 0;
#endif
    if (key == NULL) {
        OPENSSL_PUT_ERROR(PKCS11, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    CK_RV ret;

    CK_MECHANISM_TYPE type;
    switch(hash_nid) {
        case NID_md2 : type = CKM_MD2_RSA_PKCS; break;
        case NID_md5 : type = CKM_MD5_RSA_PKCS; break;
        case NID_sha1 : type = CKM_SHA1_RSA_PKCS; break;
        case NID_sha224 : type = CKM_SHA224_RSA_PKCS; break;
        case NID_sha256 : type = CKM_SHA256_RSA_PKCS; break;
        case NID_sha384 : type = CKM_SHA384_RSA_PKCS; break;
        case NID_sha512 : type = CKM_SHA512_RSA_PKCS; break;
        case NID_ripemd160 : type = CKM_RIPEMD160_RSA_PKCS; break;
        default : OPENSSL_PUT_ERROR(PKCS11, PKCS11_UNKNOWN_HASH); return 0;
    }

    CK_MECHANISM mech = { type, NULL_PTR, 0 };

    CK_OBJECT_HANDLE private;
    if (!get_ec_key(&session, &private, key, CKO_PRIVATE_KEY))
        return 0;

    if ((ret = C_SignInit(session, &mech, private)) != CKR_OK) {
        OPENSSL_PUT_ERROR(PKCS11,ret);
        return 0;
    }

    CK_ULONG ret_out_len;
    if ((ret = C_Sign(session, (unsigned char*)in, in_len, sig, &ret_out_len)) != CKR_OK) {
        OPENSSL_PUT_ERROR(PKCS11,ret);
        return 0;
    }
    *sig_len = ret_out_len;

    return 1;

}


int PKCS11_ECDSA_verify(CK_SESSION_HANDLE session, const EC_KEY *key, const uint8_t *digest, size_t digest_len, const uint8_t *sig, size_t sig_len) {
#ifndef ENABLE_PKCS11
    OPENSSL_PUT_ERROR(PKCS11,PKCS11_NOT_ENABLED);
    return 0;
#endif
    if (key == NULL || digest == NULL || sig == NULL) {
        OPENSSL_PUT_ERROR(PKCS11, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    CK_RV ret;
    CK_MECHANISM mech = { CKM_ECDSA, NULL_PTR, 0 };

    CK_OBJECT_HANDLE public;
    if (!get_ec_key(&session, &public, key, CKO_PUBLIC_KEY))
        return 0;

    if ((ret = C_VerifyInit(session, &mech, public)) != CKR_OK) {
        OPENSSL_PUT_ERROR(PKCS11,ret);
        return 0;
    }

    if (C_Verify(session, (unsigned char*)digest, digest_len, (unsigned char*)sig, sig_len) != CKR_OK) {
        return 0;
    }

    return 1;
}

int PKCS11_ECDSA_verify_new(PKCS11_session session, const EC_KEY *key, int hash_nid, uint8_t *msg, size_t msg_len, const uint8_t *signature, size_t sig_len, int *correct){
#ifndef ENABLE_PKCS11
    OPENSSL_PUT_ERROR(PKCS11,PKCS11_NOT_ENABLED);
    return 0;
#endif
    if (key == NULL ||signature == NULL) {
        OPENSSL_PUT_ERROR(PKCS11, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    CK_RV ret;

    CK_MECHANISM_TYPE type;
    switch(hash_nid) {
        case NID_md2 : type = CKM_MD2_RSA_PKCS; break;
        case NID_md5 : type = CKM_MD5_RSA_PKCS; break;
        case NID_sha1 : type = CKM_SHA1_RSA_PKCS; break;
        case NID_sha224 : type = CKM_SHA224_RSA_PKCS; break;
        case NID_sha256 : type = CKM_SHA256_RSA_PKCS; break;
        case NID_sha384 : type = CKM_SHA384_RSA_PKCS; break;
        case NID_sha512 : type = CKM_SHA512_RSA_PKCS; break;
        case NID_ripemd160 : type = CKM_RIPEMD160_RSA_PKCS; break;
        default : OPENSSL_PUT_ERROR(PKCS11, PKCS11_UNKNOWN_HASH); return 0;
    }

    CK_MECHANISM mech = { type, NULL_PTR, 0 };

    CK_OBJECT_HANDLE public;

    if (!get_ec_key(&session, &public, key, CKO_PUBLIC_KEY))
        return 0;

    if ((ret = C_VerifyInit(session, &mech, public)) != CKR_OK) {
        OPENSSL_PUT_ERROR(PKCS11,ret);
        return 0;
    }

    ret = C_Verify(session, msg, msg_len, (uint8_t*) signature, sig_len);
    if(ret == CKR_OK)
	    *correct = 1;
    else if((ret == CKR_SIGNATURE_INVALID) || (ret == CKR_SIGNATURE_LEN_RANGE))
	    *correct = 0;
    else {
        OPENSSL_PUT_ERROR(PKCS11,ret);
        return 0;
    }

    return 1;  
}