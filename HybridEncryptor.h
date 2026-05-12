#ifndef HYBRID_ENCRYPTOR_H
#define HYBRID_ENCRYPTOR_H

#include <string>
#include <vector>
#include <openssl/evp.h>
#include <openssl/pem.h>

class HybridEncryptor {
public:
    HybridEncryptor();
    ~HybridEncryptor();

    // Key Management
    bool generateKeys(); // Generates ECC P-256 keys
    bool saveKeys(const std::string& publicFile, const std::string& privateFile);
    bool loadKeys(const std::string& publicFile, const std::string& privateFile);

    // Encryption/Decryption
    struct EncryptedPackage {
        std::string ephemeralPublicKey; // Base64 ECC Public Key
        std::string iv;                // Base64 IV
        std::string ciphertext;        // Base64 Ciphertext
    };

    bool encrypt(const std::string& plaintext, EncryptedPackage& package);
    bool decrypt(const EncryptedPackage& package, std::string& plaintext);

    // Utilities
    static std::string base64Encode(const unsigned char* data, size_t len);
    static std::vector<unsigned char> base64Decode(const std::string& b64query);
    
    static std::string bytesToHex(const unsigned char* data, size_t len);
    static std::vector<unsigned char> hexToBytes(const std::string& hex);

private:
    EVP_PKEY* pkey; // ECC key pair (P-256)

    bool encryptAES(const std::string& plaintext, const std::vector<unsigned char>& key, 
                    std::vector<unsigned char>& iv, std::vector<unsigned char>& ciphertext);
    bool decryptAES(const std::vector<unsigned char>& ciphertext, const std::vector<unsigned char>& key, 
                    const std::vector<unsigned char>& iv, std::string& plaintext);
    
    // Internal ECC helper
    bool deriveSharedSecret(EVP_PKEY* privKey, EVP_PKEY* pubKey, std::vector<unsigned char>& secret);
};

#endif // HYBRID_ENCRYPTOR_H
