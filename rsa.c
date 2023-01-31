#include "mc.h"
int main(void)
{
	//const unsigned char *secret = "aaaaaaaaaaaaaaaa";
	unsigned char *secret = (unsigned char *)malloc(17);
	for (int i = 0; i < 16; i++)
		secret[i] = 'a';
	secret[16] = '\0';
	RSA *rsa = RSA_generate_key(1024, 3, NULL, NULL);
        if (rsa == NULL) {
		fprintf(stderr, "failed to generate key\n");
        	return -1;
	}
	RSA *rsa_private = RSAPrivateKey_dup(rsa);
	RSA *rsa_public = RSAPublicKey_dup(rsa);

	unsigned char *pubkey;
	int publickey_len = i2d_RSA_PUBKEY(rsa, NULL);
	unsigned char *throwaway2 = pubkey = (unsigned char *)malloc(publickey_len);
	publickey_len = i2d_RSA_PUBKEY(rsa, &throwaway2);
	if (publickey_len <= 0) {
		fprintf(stderr, "failed to encode public key\n");
		return -1;
	}

        const unsigned char *throwaway = pubkey; 
        RSA *rsa_public2 = d2i_RSA_PUBKEY(NULL, &throwaway, publickey_len);
        if (rsa_public2 == NULL) {
		fprintf(stderr, "failed to read pubkey\n");
		return -1;
	}
				
	unsigned char *ret = (unsigned char *)malloc(RSA_size(rsa));
	int retlen;
        if ((retlen=RSA_public_encrypt(16, secret, ret, rsa, RSA_PKCS1_PADDING)) < 0) {
                fprintf(stderr, "failed to encrypt\n");
                return -1;
        }
	unsigned char *decrypted_secret = (unsigned char *)malloc(17);
	decrypted_secret[16] = '\0';
        if ((retlen=RSA_private_decrypt(retlen, ret, decrypted_secret, rsa, RSA_PKCS1_PADDING)) < 0) {
                fprintf(stderr, "failed to decrypt \n");
                return -1;
        }
	fprintf(stderr, "decrypted secret: %s\n", decrypted_secret);

	return 0;

}

