#include <iostream>
#include <fstream>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <stdio.h>

using namespace std;

int padding = RSA_PKCS1_PADDING;

RSA *createRSA(unsigned char *key, int isPublic)
{
    RSA *rsa = NULL;
    BIO *keybio;
    keybio = BIO_new_mem_buf(key, -1);
    if (keybio == NULL)
    {
        printf("Failed to create key BIO");
        return 0;
    }
    if (isPublic)
    {
        rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
    }
    else
    {
        rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
    }
    if (rsa == NULL)
    {
        printf("Failed to create RSA");
    }

    return rsa;
}

int private_encrypt(unsigned char *data, int data_len, unsigned char *key, unsigned char *encrypted)
{
    RSA *rsa = createRSA(key, 0);
    int result = RSA_private_encrypt(data_len, data, encrypted, rsa, padding);
    return result;
}
int public_decrypt(unsigned char *enc_data, int data_len, unsigned char *key, unsigned char *decrypted)
{
    RSA *rsa = createRSA(key, 1);
    int result = RSA_public_decrypt(data_len, enc_data, decrypted, rsa, padding);
    return result;
}

void printLastError(char *msg)
{
    char err[30];
    ERR_load_crypto_strings();
    ERR_error_string(ERR_get_error(), err);
    printf("%s ERROR: %s\n", msg, err);
    free(err);
}

int main()
{
    unsigned char decrypted[1000000000000];

    ifstream myfile("pubKeySender.pem");

    char publicKey[sizeof(myfile)];
    char current_char;
    int num_characters = 0;
    int i = 0;

    if (myfile.is_open())
    {
        while (!myfile.eof())
        {
            myfile.get(publicKey[i]);
            i++;
            num_characters++;
        }
    }

    //print the key to console
    for (int i = 0; i <= num_characters; i++)
    {
        cout << publicKey[i];
    }

    // close the file
    myfile.close();

    ifstream infile;
    infile.open("RSASign.sig", ios::binary | ios::in);

    char sign[sizeof(infile)];
    char current_char_sign;
    int num_characters_sign = 0;
    int j = 0;

    if (infile.is_open())
    {
        while (infile.get(sign[j]))
        {
            j++;
            num_characters_sign++;
        }
    }

    for (int i = 0; i <sizeof(sign); i++){
        cout << sign[i];
    }

    //close the file
    infile.close();

    int decrypted_length = public_decrypt((unsigned char*)sign, 128, (unsigned char*)publicKey, decrypted);
    if (decrypted_length == -1)
    {
        printLastError("Public Decrypt failed");
        exit(0);
    }
    printf("Decrypted Text =%s\n", decrypted);
    printf("Decrypted Length =%d\n", decrypted_length);

    return 0;
}