#ifndef __PROGTEST__
#include <cstdlib>
#include <cstdio>
#include <cctype>
#include <climits>
#include <cstdint>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <string_view>
#include <memory>
#include <vector>
#include <fstream>
#include <cassert>
#include <cstring>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/pem.h>

using namespace std;

#endif /* __PROGTEST__ */

int seal(const std::string &inFile, const std::string &outFile, const std::string &publicKeyFile, const std::string &symmetricCipher)
{
    // Open input and output files
    FILE *inF = fopen(inFile.c_str(), "rb");
    if (!inF)
        return EXIT_FAILURE;

    // Get input file size
    fseek(inF, 0, SEEK_END);
    fseek(inF, 0, SEEK_SET);

    // Open public key file
    FILE *pubKeyF = fopen(publicKeyFile.c_str(), "r");
    if (!pubKeyF)
    {
        fclose(inF);
        return EXIT_FAILURE;
    }

    // Read public key
    EVP_PKEY *publicKey = PEM_read_PUBKEY(pubKeyF, NULL, NULL, NULL);
    fclose(pubKeyF);
    if (!publicKey)
    {
        fclose(inF);
        return EXIT_FAILURE;
    }

    // Get cipher
    const EVP_CIPHER *cipher = EVP_get_cipherbyname(symmetricCipher.c_str());
    if (!cipher)
    {
        EVP_PKEY_free(publicKey);
        fclose(inF);
        return EXIT_FAILURE;
    }

    // Create context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        EVP_PKEY_free(publicKey);
        fclose(inF);
        return EXIT_FAILURE;
    }

    // Allocate memory for encrypted key
    int keySize = EVP_PKEY_size(publicKey);
    unsigned char *ek = (unsigned char *)malloc(keySize);
    if (!ek)
    {
        EVP_CIPHER_CTX_free(ctx);
        EVP_PKEY_free(publicKey);
        fclose(inF);
        return EXIT_FAILURE;
    }

    // Allocate memory for IV if needed
    int ivLen = EVP_CIPHER_iv_length(cipher);
    unsigned char *iv = NULL;
    if (ivLen > 0)
    {
        iv = (unsigned char *)malloc(ivLen);
        if (!iv)
        {
            free(ek);
            EVP_CIPHER_CTX_free(ctx);
            EVP_PKEY_free(publicKey);
            fclose(inF);
            return EXIT_FAILURE;
        }
    }

    // Initialize encryption
    int ekLen = 0;
    if (EVP_SealInit(ctx, cipher, &ek, &ekLen, iv, &publicKey, 1) != 1)
    {
        if (iv)
            free(iv);
        free(ek);
        EVP_CIPHER_CTX_free(ctx);
        EVP_PKEY_free(publicKey);
        fclose(inF);
        return EXIT_FAILURE;
    }

    // Open output file
    FILE *outF = fopen(outFile.c_str(), "wb");
    if (!outF)
    {
        if (iv)
            free(iv);
        free(ek);
        EVP_CIPHER_CTX_free(ctx);
        EVP_PKEY_free(publicKey);
        fclose(inF);
        return EXIT_FAILURE;
    }

    // Write header information
    int numId = EVP_CIPHER_nid(cipher);
    if (fwrite(&numId, sizeof(numId), 1, outF) != 1 ||
        fwrite(&ekLen, sizeof(ekLen), 1, outF) != 1 ||
        fwrite(ek, ekLen, 1, outF) != 1)
    {
        fclose(outF);
        remove(outFile.c_str());
        if (iv)
            free(iv);
        free(ek);
        EVP_CIPHER_CTX_free(ctx);
        EVP_PKEY_free(publicKey);
        fclose(inF);
        return EXIT_FAILURE;
    }

    // Write IV if needed
    if (ivLen > 0)
    {
        if (fwrite(iv, ivLen, 1, outF) != 1)
        {
            fclose(outF);
            remove(outFile.c_str());
            free(iv);
            free(ek);
            EVP_CIPHER_CTX_free(ctx);
            EVP_PKEY_free(publicKey);
            fclose(inF);
            return EXIT_FAILURE;
        }
    }

    // Process file in chunks to avoid memory issues
    const int BUFFER_SIZE = 4096;
    unsigned char inBuffer[BUFFER_SIZE];
    unsigned char outBuffer[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];
    int bytesRead;
    int outLen;
    int success = 1;

    while ((bytesRead = fread(inBuffer, 1, BUFFER_SIZE, inF)) > 0)
    {
        if (EVP_SealUpdate(ctx, outBuffer, &outLen, inBuffer, bytesRead) != 1)
        {
            success = 0;
            break;
        }
        if (outLen > 0 && fwrite(outBuffer, 1, outLen, outF) != (size_t)outLen)
        {
            success = 0;
            break;
        }
    }

    // Finalize encryption
    if (success && EVP_SealFinal(ctx, outBuffer, &outLen) == 1)
    {
        if (outLen > 0)
        {
            if (fwrite(outBuffer, 1, outLen, outF) != (size_t)outLen)
            {
                success = 0;
            }
        }
    }
    else
    {
        success = 0;
    }

    // Clean up
    fclose(outF);
    fclose(inF);
    if (iv)
        free(iv);
    free(ek);
    EVP_CIPHER_CTX_free(ctx);
    EVP_PKEY_free(publicKey);

    // Delete output file if encryption failed
    if (!success)
    {
        remove(outFile.c_str());
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

int open(const std::string &inFile, const std::string &outFile, const std::string &privateKeyFile)
{
    // Open input file
    FILE *inF = fopen(inFile.c_str(), "rb");
    if (!inF)
        return EXIT_FAILURE;

    // Read header information
    int numId, ekLen;
    if (fread(&numId, sizeof(numId), 1, inF) != 1 ||
        fread(&ekLen, sizeof(ekLen), 1, inF) != 1 || ekLen <= 0)
    {
        fclose(inF);
        return EXIT_FAILURE;
    }

    // Get cipher from NID
    const EVP_CIPHER *cipher = EVP_get_cipherbynid(numId);
    if (!cipher)
    {
        fclose(inF);
        return EXIT_FAILURE;
    }

    // Allocate memory for encrypted key
    unsigned char *ek = (unsigned char *)malloc(ekLen);
    if (!ek)
    {
        fclose(inF);
        return EXIT_FAILURE;
    }

    // Read encrypted key
    if (fread(ek, ekLen, 1, inF) != 1)
    {
        free(ek);
        fclose(inF);
        return EXIT_FAILURE;
    }

    // Allocate memory for IV if needed
    int ivLen = EVP_CIPHER_iv_length(cipher);
    unsigned char *iv = NULL;
    if (ivLen > 0)
    {
        iv = (unsigned char *)malloc(ivLen);
        if (!iv)
        {
            free(ek);
            fclose(inF);
            return EXIT_FAILURE;
        }

        // Read IV
        if (fread(iv, ivLen, 1, inF) != 1)
        {
            free(iv);
            free(ek);
            fclose(inF);
            return EXIT_FAILURE;
        }
    }

    // Open private key file
    FILE *privKeyF = fopen(privateKeyFile.c_str(), "r");
    if (!privKeyF)
    {
        if (iv)
            free(iv);
        free(ek);
        fclose(inF);
        return EXIT_FAILURE;
    }

    // Read private key
    EVP_PKEY *privateKey = PEM_read_PrivateKey(privKeyF, NULL, NULL, NULL);
    fclose(privKeyF);
    if (!privateKey)
    {
        if (iv)
            free(iv);
        free(ek);
        fclose(inF);
        return EXIT_FAILURE;
    }

    // Create decryption context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        EVP_PKEY_free(privateKey);
        if (iv)
            free(iv);
        free(ek);
        fclose(inF);
        return EXIT_FAILURE;
    }

    // Initialize decryption
    if (EVP_OpenInit(ctx, cipher, ek, ekLen, iv, privateKey) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        EVP_PKEY_free(privateKey);
        if (iv)
            free(iv);
        free(ek);
        fclose(inF);
        return EXIT_FAILURE;
    }

    // Open output file
    FILE *outF = fopen(outFile.c_str(), "wb");
    if (!outF)
    {
        EVP_CIPHER_CTX_free(ctx);
        EVP_PKEY_free(privateKey);
        if (iv)
            free(iv);
        free(ek);
        fclose(inF);
        return EXIT_FAILURE;
    }

    // Process file in chunks to avoid memory issues
    const int BUFFER_SIZE = 4096;
    unsigned char inBuffer[BUFFER_SIZE];
    unsigned char outBuffer[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];
    int bytesRead;
    int outLen;
    int success = 1;

    while ((bytesRead = fread(inBuffer, 1, BUFFER_SIZE, inF)) > 0)
    {
        if (EVP_OpenUpdate(ctx, outBuffer, &outLen, inBuffer, bytesRead) != 1)
        {
            success = 0;
            break;
        }
        if (outLen > 0 && fwrite(outBuffer, 1, outLen, outF) != (size_t)outLen)
        {
            success = 0;
            break;
        }
    }

    // Finalize decryption
    if (success && EVP_OpenFinal(ctx, outBuffer, &outLen) == 1)
    {
        if (outLen > 0)
        {
            if (fwrite(outBuffer, 1, outLen, outF) != (size_t)outLen)
            {
                success = 0;
            }
        }
    }
    else
    {
        success = 0;
    }

    // Clean up
    fclose(outF);
    fclose(inF);
    EVP_CIPHER_CTX_free(ctx);
    EVP_PKEY_free(privateKey);
    if (iv)
        free(iv);
    free(ek);

    if (!success)
    {
        remove(outFile.c_str());
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

#ifndef __PROGTEST__

int main(void)
{
    assert(EXIT_SUCCESS == seal("sample_plaintext.txt", "sealed.bin", "PublicKey.pem", "aes-128-cbc"));

    assert(EXIT_SUCCESS == open("sealed.bin", "opened.bin", "PrivateKey.pem"));
    // Verify that opened.bin and sample_plaintext.bin are identical.

    assert(EXIT_SUCCESS == open("sample_ciphertext.bin", "opened.bin", "PrivateKey.pem"));
    // Verify that opened.bin and sample_plaintext.bin are identical.

    return 0;
}

#endif /* __PROGTEST__ */
