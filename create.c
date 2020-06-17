#include "lock.h"

// 生成公钥文件和私钥文件，私钥文件带密码
int createRSAKey(const char *pub_keyfile, const char *pri_keyfile, 
					   const unsigned char *passwd, int passwd_len)
{
	RSA *rsa = NULL;
	RAND_seed(rand_seed, sizeof(rand_seed));
	rsa = RSA_generate_key(RSA_KEY_LENGTH, RSA_F4, NULL, NULL);
	if(rsa == NULL)
	{
		printf("RSA_generate_key error!\n");
		return -1;
	}

	// 开始生成公钥文件
	BIO *bp = BIO_new(BIO_s_file());
	if(NULL == bp)
	{
		printf("generate_key bio file new error!\n");
		return -1;
	}

	if(BIO_write_filename(bp, (void *)pub_keyfile) <= 0)
	{
		printf("BIO_write_filename error!\n");
		return -1;
	}

	if(PEM_write_bio_RSAPublicKey(bp, rsa) != 1)
	{
		printf("PEM_write_bio_RSAPublicKey error!\n");
		return -1;
	}
	
	// 公钥文件生成成功，释放资源
	printf("Create public key ok!\n");
	BIO_free_all(bp);

	// 生成私钥文件
	bp = BIO_new_file(pri_keyfile, "w+");
        if(NULL == bp)
	{
		printf("generate_key bio file new error2!\n");
		return -1;
	}

	if(PEM_write_bio_RSAPrivateKey(bp, rsa,
		EVP_des_ede3_ofb(), (unsigned char *)passwd, 
		passwd_len, NULL, NULL) != 1)
	{
		printf("PEM_write_bio_RSAPublicKey error!\n");
		return -1;
	}

	// 释放资源
	printf("Create private key ok!\n");
	BIO_free_all(bp);
	RSA_free(rsa);

	return 0;
}

int main(){
    createRSAKey(PUBLIC_KEY_FILE, PRIVATE_KEY_FILE, 
		 (const unsigned char *)RSA_PRIKEY_PSW, strlen(RSA_PRIKEY_PSW));
}