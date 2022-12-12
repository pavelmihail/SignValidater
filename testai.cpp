#include <iostream>
#include <fstream>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <sstream>
#include <iomanip>
#include <stdio.h>

using namespace std;

void getHashedValue(unsigned char* hash)
{
    ifstream file("ignis-10M.txt");
    if (!file.is_open())
    {
        // Handle error
        cout <<"if (!file.is_open())";
        // return NULL;
    }

    // Initialize the context for the hash computation
    EVP_MD_CTX *ctx = EVP_MD_CTX_create();
    if (ctx == NULL)
    {
        // Handle error
        cout <<"if (ctx == NULL)\n";
        // return NULL;
    }

    // Initialize the hash computation
    if (EVP_DigestInit(ctx, EVP_sha256()) != 1)
    {
        // Handle error
        cout <<"if (EVP_DigestInit(ctx, EVP_sha256()) != 1)\n";
        // return NULL;
    }

    // Compute the hash of the file
    char buffer[1024];
    while (file.good())
    {
        file.read(buffer, sizeof(buffer));
        if (file.gcount() > 0)
        {
            if (EVP_DigestUpdate(ctx, buffer, file.gcount()) != 1)
            {
                // Handle error
                cout <<"if (EVP_DigestUpdate(ctx, buffer, file.gcount()) != 1)\n";
                // return NULL;
            }
        }
    }

    // Get the final hash value
    unsigned int hash_len;
    if (EVP_DigestFinal(ctx, hash, &hash_len) != 1)
    {
        // Handle error
        cout <<"if (EVP_DigestFinal(ctx, hash, &hash_len) != 1)\n";
        // return NULL;
    }

    // Clean up
    EVP_MD_CTX_destroy(ctx);
}

int main()
{
    unsigned char sha256value[SHA256_DIGEST_LENGTH];
    getHashedValue(sha256value);

    if (sha256value != NULL)
    {
        cout << "SHA256 for file: ";

        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        {
            cout << hex << (int)sha256value[i] << " ";
        }
        cout << "\n";
    } else {
        //Error Handleing
        cout << "Error occured, check the file input \n";
    }

    ///////////////////////////////////////////////////////////////

    // Decrypt signature
    FILE* signatureFile = NULL;
    signatureFile = fopen("RSASign.sig", "rb");

        FILE* pubKeyFile;
        unsigned char* sigBuffer = NULL;
        unsigned char* signatureContent = NULL;
        RSA* rsa = RSA_new();
        pubKeyFile = fopen("pubKeySender.pem", "r");
        rsa = PEM_read_RSAPublicKey(pubKeyFile, NULL, NULL, NULL);
        fclose(pubKeyFile);

        sigBuffer = (unsigned char*)malloc(RSA_size(rsa));
        fread(sigBuffer, RSA_size(rsa), 1, signatureFile);

        signatureContent = (unsigned char*)malloc(32);
        RSA_public_decrypt(RSA_size(rsa), sigBuffer, signatureContent, rsa,
            RSA_PKCS1_PADDING);
        fclose(signatureFile);

        cout << "Decryoted signature message: ";
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
            printf("%2X ", signatureContent[i]);
        cout << endl;

        if (memcmp(signatureContent, sha256value, SHA256_DIGEST_LENGTH) == 0)
            cout << "\n Valid signature\n";
        else
            cout << "\n Invalid signature\n";

        free(signatureContent);
        free(sigBuffer);
        RSA_free(rsa);

    return 0;
}