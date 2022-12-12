# SignValidater
A simple C/C++ application that will validate a digital signature by using the 3rd party development library OpenSSL.
The digital signature is stored by the file RSASign.sig and the public 1024-bit RSA key is stored by the file pubKeySender.pem in PEM format.
Signature was generated for SHA-256 by considering the padding RSA_PKCS1_PADDING.

# Run commands
g++ <filnename>.cpp -lcrypto -o <outputfilename>
./<outputfilename>

# Requirements
install openSSL in ubuntu https://linuxpip.org/install-openssl-linux/

for the libry to be seen $ sudo apt-get install libpcap-dev libssl-dev
