#include "HybridEncryptor.h"
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/kdf.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <iomanip>
#include <sstream>
#include <iostream>

HybridEncryptor::HybridEncryptor() : pkey(nullptr) {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
}

HybridEncryptor::~HybridEncryptor() {
    if (pkey) EVP_PKEY_free(pkey);
}

bool HybridEncryptor::generateKeys() {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    if (!ctx) return false;

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    if (pkey) EVP_PKEY_free(pkey);
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    EVP_PKEY_CTX_free(ctx);
    return true;
}

bool HybridEncryptor::saveKeys(const std::string& publicFile, const std::string& privateFile) {
    if (!pkey) return false;

    BIO* pub = BIO_new_file(publicFile.c_str(), "w");
    if (pub) {
        PEM_write_bio_PUBKEY(pub, pkey);
        BIO_free(pub);
    }

    BIO* priv = BIO_new_file(privateFile.c_str(), "w");
    if (priv) {
        PEM_write_bio_PrivateKey(priv, pkey, nullptr, nullptr, 0, nullptr, nullptr);
        BIO_free(priv);
    }

    return true;
}

bool HybridEncryptor::loadKeys(const std::string& publicFile, const std::string& privateFile) {
    BIO* priv = BIO_new_file(privateFile.c_str(), "r");
    if (priv) {
        if (pkey) EVP_PKEY_free(pkey);
        pkey = PEM_read_bio_PrivateKey(priv, nullptr, nullptr, nullptr);
        BIO_free(priv);
    }

    if (!pkey) {
        BIO* pub = BIO_new_file(publicFile.c_str(), "r");
        if (pub) {
            pkey = PEM_read_bio_PUBKEY(pub, nullptr, nullptr, nullptr);
            BIO_free(pub);
        }
    }

    return pkey != nullptr;
}

bool HybridEncryptor::encrypt(const std::string& plaintext, EncryptedPackage& package) {
    if (!pkey) return false;

    // 1. Generate Ephemeral Key for ECIES
    EVP_PKEY* ephemeral = nullptr;
    EVP_PKEY_CTX* kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    EVP_PKEY_keygen_init(kctx);
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(kctx, NID_X9_62_prime256v1);
    EVP_PKEY_keygen(kctx, &ephemeral);
    EVP_PKEY_CTX_free(kctx);

    // 2. Derive Shared Secret (ECDH)
    std::vector<unsigned char> sharedSecret;
    if (!deriveSharedSecret(ephemeral, pkey, sharedSecret)) {
        EVP_PKEY_free(ephemeral);
        return false;
    }

    // 3. Derive AES-256 Key
    std::vector<unsigned char> aesKey(32);
    EVP_MD_CTX* mctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(mctx, sharedSecret.data(), sharedSecret.size());
    EVP_DigestFinal_ex(mctx, aesKey.data(), nullptr);
    EVP_MD_CTX_free(mctx);

    // 4. Encrypt with AES
    std::vector<unsigned char> iv, ciphertext;
    if (!encryptAES(plaintext, aesKey, iv, ciphertext)) {
        EVP_PKEY_free(ephemeral);
        return false;
    }

    // 5. Extract RAW COMPRESSED Public Key (Saves ~80 characters)
    EC_KEY* ec_key = EVP_PKEY_get1_EC_KEY(ephemeral);
    const EC_GROUP* group = EC_KEY_get0_group(ec_key);
    const EC_POINT* point = EC_KEY_get0_public_key(ec_key);
    
    size_t pubLen = EC_POINT_point2oct(group, point, POINT_CONVERSION_COMPRESSED, nullptr, 0, nullptr);
    std::vector<unsigned char> pubRaw(pubLen);
    EC_POINT_point2oct(group, point, POINT_CONVERSION_COMPRESSED, pubRaw.data(), pubLen, nullptr);
    
    package.ephemeralPublicKey = base64Encode(pubRaw.data(), pubLen);
    
    EC_KEY_free(ec_key);
    EVP_PKEY_free(ephemeral);

    package.iv = base64Encode(iv.data(), iv.size());
    package.ciphertext = base64Encode(ciphertext.data(), ciphertext.size());

    return true;
}

bool HybridEncryptor::decrypt(const EncryptedPackage& package, std::string& plaintext) {
    if (!pkey) return false;

    // 1. Decode Raw Compressed Public Key
    std::vector<unsigned char> pubBytes = base64Decode(package.ephemeralPublicKey);
    
    EC_KEY* ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    const EC_GROUP* group = EC_KEY_get0_group(ec_key);
    EC_POINT* point = EC_POINT_new(group);
    
    if (EC_POINT_oct2point(group, point, pubBytes.data(), pubBytes.size(), nullptr) <= 0) {
        EC_POINT_free(point);
        EC_KEY_free(ec_key);
        return false;
    }
    
    EC_KEY_set_public_key(ec_key, point);
    EVP_PKEY* ephemeral = EVP_PKEY_new();
    EVP_PKEY_assign_EC_KEY(ephemeral, ec_key);
    EC_POINT_free(point);

    // 2. Derive Shared Secret
    std::vector<unsigned char> sharedSecret;
    if (!deriveSharedSecret(pkey, ephemeral, sharedSecret)) {
        EVP_PKEY_free(ephemeral);
        return false;
    }

    // 3. Derive AES-256 Key
    std::vector<unsigned char> aesKey(32);
    EVP_MD_CTX* mctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(mctx, sharedSecret.data(), sharedSecret.size());
    EVP_DigestFinal_ex(mctx, aesKey.data(), nullptr);
    EVP_MD_CTX_free(mctx);

    // 4. Decrypt AES
    std::vector<unsigned char> iv = base64Decode(package.iv);
    std::vector<unsigned char> ciphertext = base64Decode(package.ciphertext);
    bool success = decryptAES(ciphertext, aesKey, iv, plaintext);

    EVP_PKEY_free(ephemeral);
    return success;
}

bool HybridEncryptor::deriveSharedSecret(EVP_PKEY* privKey, EVP_PKEY* pubKey, std::vector<unsigned char>& secret) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(privKey, nullptr);
    if (!ctx || EVP_PKEY_derive_init(ctx) <= 0 || EVP_PKEY_derive_set_peer(ctx, pubKey) <= 0) {
        if (ctx) EVP_PKEY_CTX_free(ctx);
        return false;
    }

    size_t secretLen;
    EVP_PKEY_derive(ctx, nullptr, &secretLen);
    secret.resize(secretLen);
    if (EVP_PKEY_derive(ctx, secret.data(), &secretLen) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    EVP_PKEY_CTX_free(ctx);
    return true;
}

bool HybridEncryptor::encryptAES(const std::string& plaintext, const std::vector<unsigned char>& key,
                               std::vector<unsigned char>& iv, std::vector<unsigned char>& ciphertext) {
    iv.resize(16);
    RAND_bytes(iv.data(), iv.size());

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data());

    int len;
    ciphertext.resize(plaintext.size() + 16);
    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, (unsigned char*)plaintext.c_str(), plaintext.size());
    int ciphertext_len = len;

    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
    ciphertext_len += len;

    ciphertext.resize(ciphertext_len);
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

bool HybridEncryptor::decryptAES(const std::vector<unsigned char>& ciphertext, const std::vector<unsigned char>& key,
                               const std::vector<unsigned char>& iv, std::string& plaintext) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data());

    std::vector<unsigned char> plain(ciphertext.size());
    int len;
    if (EVP_DecryptUpdate(ctx, plain.data(), &len, ciphertext.data(), ciphertext.size()) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    int plain_len = len;

    if (EVP_DecryptFinal_ex(ctx, plain.data() + len, &len) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    plain_len += len;

    plaintext.assign((char*)plain.data(), plain_len);
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

std::string HybridEncryptor::base64Encode(const unsigned char* data, size_t len) {
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, data, len);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);

    std::string result(bufferPtr->data, bufferPtr->length);
    BIO_free_all(bio);

    return result;
}

std::vector<unsigned char> HybridEncryptor::base64Decode(const std::string& b64query) {
    BIO *bio, *b64;
    int decodeLen = (b64query.length() * 3) / 4 + 1;
    std::vector<unsigned char> buffer(decodeLen);

    bio = BIO_new_mem_buf(b64query.data(), b64query.length());
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    int len = BIO_read(bio, buffer.data(), b64query.length());
    buffer.resize(len > 0 ? len : 0);
    BIO_free_all(bio);

    return buffer;
}

std::string HybridEncryptor::bytesToHex(const unsigned char* data, size_t len) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i) ss << std::setw(2) << (int)data[i];
    return ss.str();
}

std::vector<unsigned char> HybridEncryptor::hexToBytes(const std::string& hex) {
    std::vector<unsigned char> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        unsigned char byte = (unsigned char)strtol(byteString.c_str(), nullptr, 16);
        bytes.push_back(byte);
    }
    return bytes;
}
