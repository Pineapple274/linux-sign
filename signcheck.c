#include "lock.h"

const char *check_OK = "用于 x86体系linux 的 MicroLock (R) 64位ELF 文件签名验证系统 20.16.27051版\n版权所有(C) MicroLock Corporation。保留所有权利。";

const char *test = "this is a test.";

//使用密钥解密，这种封装格式只适用公钥加密，私钥解密，这里key必须是私钥
char* rsa_key_decrypt(char *filename, unsigned char *out_data, const unsigned char *in_data, const unsigned char *passwd)
{
	RSA *rsa = RSA_new();
	char *p_de;
	int rsa_len;
	OpenSSL_add_all_algorithms();
	
	BIO *bp = NULL;
	bp = BIO_new_file(filename, "rb"); 
	
	if(bp == NULL){
	  printf("open_private_key bio file new error!\n");
	  RSA_free(rsa);
	  BIO_free(bp);
	  return NULL;
	}
	
	rsa = PEM_read_bio_RSAPrivateKey(bp, &rsa, NULL, (void *)passwd);
	if(rsa == NULL)
	{
		printf("open_private_key failed to PEM_read_bio_RSAPrivateKey!\n");
		BIO_free(bp);
		RSA_free(rsa);
		return NULL;
	}
	
	//printf("open_private_key success to PEM_read_bio_RSAPrivateKey!\n");
	
	OpenSSL_add_all_ciphers();

	rsa_len = RSA_size(rsa);
    //printf("%d\n",rsa_len);
	p_de = (unsigned char *)malloc(rsa_len+1);
	memset(p_de,0,rsa_len+1);
	
	if(RSA_private_decrypt(rsa_len,(unsigned char *)in_data,
	  (unsigned char*)p_de,rsa,RSA_NO_PADDING)<0){
		printf("Decrypt failed\n");
		RSA_free(rsa);
		BIO_free(bp);
		return NULL;
	}
	
	RSA_free(rsa);
	BIO_free(bp);
	return p_de;
}
    

int main(int argc, char **argv){
    if(argc != 2)
    {
        printf("usage:%s elf_file\n", argv[0]);
        return -1;
    }

    if(have_Sign(argv[1])!=2){
         return 0;
    }
    unsigned char sha256_digest[SHA256_DIGEST_LENGTH];
    unsigned char *dersa_data;
    FILE* fl = NULL;
    unsigned char data[256];
    char *load_file;
    char *aim_file;
	Elf64_Ehdr elf_head;
	Elf64_Shdr shdr;
    

    aim_file = argv[1];
    load_file = getAllLoadSegments(aim_file);
    sha256_hash("LOAD Segments",sha256_digest);
    //printf("%08x\n",file_Size(load_file));
    remove(load_file);
    //printf("load hash again: ");
    //print_hex_hash(sha256_digest,32);
    //printf("\n");

    fl=fopen(aim_file,"r");
	fread(&elf_head, sizeof(Elf64_Ehdr), 1, fl);
    fseek(fl,elf_head.e_shoff+elf_head.e_shentsize*(elf_head.e_shnum-1),SEEK_SET);
	fread(&shdr, sizeof(Elf64_Shdr), 1, fl);
	fseek(fl,shdr.sh_offset, SEEK_SET);
    fread(data,1,256,fl);//break
    //print_hex_hash(data,256);
    //printf("\n");
    
    dersa_data = rsa_key_decrypt(PRIVATE_KEY_FILE,dersa_data,data,RSA_PRIKEY_PSW);
    //print_hex_hash(dersa_data,32);
    //printf("\n");
    fclose(fl);
    //printf("%s\n\n\n",check_OK);



    if(strcmp(sha256_digest,dersa_data)!=0){
        printf("%s\n\n\n",check_OK);
    }   

_OVER_:
    
    return 0;
    
}
