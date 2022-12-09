#include <iostream>
#include <fstream>
#include <stdio.h>
#include <string.h>

using namespace std;

int main(){

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

    return 0;
}