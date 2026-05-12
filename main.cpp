#include <iostream>
#include <string>
#include <vector>
#include "HybridEncryptor.h"

void printBanner() {
    std::cout << "===========================================" << std::endl;
    std::cout << "   Secure Hybrid Encryption System (C++)   " << std::endl;
    std::cout << "         ECC P-256 + AES-256-CBC           " << std::endl;
    std::cout << "===========================================" << std::endl;
}

int main(int argc, char* argv[]) {
    HybridEncryptor encryptor;

    // CLI Mode for Web Integration (Supports Base64 for UTF-8/Emoji safety)
    if (argc > 1) {
        std::string mode = argv[1];
        if (!encryptor.loadKeys("public.pem", "private.pem")) {
            encryptor.generateKeys();
            encryptor.saveKeys("public.pem", "private.pem");
        }

        if (mode == "--encrypt" && argc > 2) {
            // Read Base64 encoded message to avoid CLI encoding issues (emojis)
            std::vector<unsigned char> decodedMsg = encryptor.base64Decode(argv[2]);
            std::string message((char*)decodedMsg.data(), decodedMsg.size());
            
            HybridEncryptor::EncryptedPackage package;
            if (encryptor.encrypt(message, package)) {
                std::cout << package.ephemeralPublicKey << ":" << package.iv << ":" << package.ciphertext << std::endl;
                return 0;
            }
            return 1;
        }
        
        if (mode == "--decrypt" && argc > 2) {
            std::string input = argv[2];
            HybridEncryptor::EncryptedPackage package;
            size_t firstColon = input.find(':');
            size_t lastColon = input.rfind(':');
            if (firstColon != std::string::npos && lastColon != std::string::npos) {
                package.ephemeralPublicKey = input.substr(0, firstColon);
                package.iv = input.substr(firstColon + 1, lastColon - firstColon - 1);
                package.ciphertext = input.substr(lastColon + 1);
                
                std::string plaintext;
                if (encryptor.decrypt(package, plaintext)) {
                    // Output as Base64 to ensure emojis reach Node.js safely
                    std::cout << encryptor.base64Encode((unsigned char*)plaintext.c_str(), plaintext.size()) << std::endl;
                    return 0;
                }
            }
            return 1;
        }
    }

    // Original Interactive Mode
    printBanner();
    while (true) {
        std::cout << "\nChoose an option:\n1. Generate New ECC Keys\n2. Encrypt a Message\n3. Decrypt a Message\n4. Exit\n> ";
        int choice;
        if (!(std::cin >> choice)) {
            std::cin.clear();
            std::cin.ignore(10000, '\n');
            continue;
        }
        std::cin.ignore(10000, '\n');

        if (choice == 1) {
            if (encryptor.generateKeys()) {
                encryptor.saveKeys("public.pem", "private.pem");
                std::cout << "Keys generated." << std::endl;
            }
        } else if (choice == 2) {
            encryptor.loadKeys("public.pem", "private.pem");
            std::cout << "Enter message: ";
            std::string msg;
            std::getline(std::cin, msg);
            HybridEncryptor::EncryptedPackage pkg;
            if (encryptor.encrypt(msg, pkg)) {
                std::cout << "Payload: " << pkg.ephemeralPublicKey << ":" << pkg.iv << ":" << pkg.ciphertext << std::endl;
            }
        } else if (choice == 3) {
            encryptor.loadKeys("public.pem", "private.pem");
            std::cout << "Enter payload: ";
            std::string input;
            std::getline(std::cin, input);
            HybridEncryptor::EncryptedPackage package;
            size_t firstColon = input.find(':');
            size_t lastColon = input.rfind(':');
            if (firstColon != std::string::npos && lastColon != std::string::npos) {
                package.ephemeralPublicKey = input.substr(0, firstColon);
                package.iv = input.substr(firstColon + 1, lastColon - firstColon - 1);
                package.ciphertext = input.substr(lastColon + 1);
                std::string plaintext;
                if (encryptor.decrypt(package, plaintext)) {
                    std::cout << "Decrypted: " << plaintext << std::endl;
                }
            }
        } else if (choice == 4) break;
    }
    return 0;
}
