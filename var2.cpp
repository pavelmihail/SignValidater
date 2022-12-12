#include<stdio.h>
#include<stdlib.h>
#include <malloc.h>
#include <memory.h>
#include <iostream>
#include<openssl/pem.h>
#include<openssl/rsa.h>
#include<openssl/sha.h>
using namespace std;

int main(int argc, char** argv) {

    if (argc != 3) {
        printf("Provide the plaintext file and the signature file!");
        return 1;
    }
    
        // prepare to get files
        FILE* plaintextFile = NULL;
        FILE* signatureFile = NULL;  

        //compute the sha-256 message digest for the file ignis-10M.txt 

        SHA256_CTX ctx;
        unsigned char messageDigest[SHA256_DIGEST_LENGTH];
        SHA256_Init(&ctx);

        unsigned char* plaintextBuffer = NULL;

        plaintextFile = fopen(argv[1], "rb");
        fseek(plaintextFile, 0, SEEK_END);
        int fileSize = ftell(plaintextFile);
        fseek(plaintextFile, 0, SEEK_SET);
    
        plaintextBuffer = (unsigned char*)malloc(fileSize);
        unsigned char* tempBuffer = plaintextBuffer;
        unsigned bytes = 0;

        // Read data in chunks and send it to openssl SHA256
        while ((bytes = fread(plaintextBuffer, 1, fileSize, plaintextFile)))
        {
            SHA256_Update(&ctx, tempBuffer, fileSize);
        }

        SHA256_Final(messageDigest, &ctx);

        printf("The SHA-256 message digest computed for the file ignis-10M.txt: ");
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            printf("%2X ", messageDigest[i]);
        }
        printf("\n");

        fclose(plaintextFile);

        //verify the digital signature 
        signatureFile = fopen(argv[2], "rb");

        
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

        printf("\nThe content decrypted from RSASign.sig: ");
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
            printf("%2X ", signatureContent[i]);
        printf("\n");

       /* int result = RSA_verify(NID_sha256, (const unsigned char*)messageDigest, SHA256_DIGEST_LENGTH,
            (const unsigned char*)outputBuffer, RSA_size(rsa), rsa);

        if (result == 1)
        {
            printf("Signature is valid\n");
            return 0;
        }
        else if(result == 0)
        {
            printf("Signature is invalid\n");
            return 1;
        }*/

        if (memcmp(signatureContent, messageDigest, SHA256_DIGEST_LENGTH) == 0)
            printf("\n Signature is valid!\n");
        else
            printf("\n Signature is invalid!\n");

        free(signatureContent);
        free(sigBuffer);
        RSA_free(rsa);

    return 0;
}