#include "lock.h"

int setNewSection(char* filename,char* sign)
{
	int shnum, a;
	FILE *fp;
	FILE *wp;
	Elf64_Ehdr elf_head;
	Elf64_Ehdr elf_head1;
	fp = fopen(filename, "r");
	wp = fopen(filename, "r+");
	if (NULL == fp)
	{
		printf("open file fail\n");
		return 1;
	}
	a = fread(&elf_head, sizeof(Elf64_Ehdr), 1, fp);
	if (a == 0)
	{
		printf("READ elf_hear ERROR\n");
		return 1;
	}

	if (elf_head.e_ident[0] != 0x7F || elf_head.e_ident[1] != 'E' || elf_head.e_ident[2] != 'L' || elf_head.e_ident[3] != 'F')
	{
		printf("Not a ELF format file\n");
		return 1;
	}

	Elf64_Shdr *shdr = (Elf64_Shdr*)malloc(sizeof(Elf64_Shdr) * elf_head.e_shnum);

	if (shdr == NULL)
	{
		printf("shdr malloc failed\n");
		return 1;
	}
	a = fseek(fp, elf_head.e_shoff, SEEK_SET);
	if(a!=0)
	{
		printf("shdr fseek ERROR\n");
		return 1;
	}
	a = fread(shdr, sizeof(Elf64_Shdr) * elf_head.e_shnum, 1, fp);
	if (a == 0)
	{
		printf("READ shdr ERROR\n");
		return 1;
	}

 rewind(fp);
    a=fseek(fp, shdr[elf_head.e_shstrndx].sh_offset, SEEK_SET);
    if(a!=0)
    {
        printf("shstrtab fseek ERROR\n");
        return 1;
    }
 char shstrtab[shdr[elf_head.e_shstrndx].sh_size];
    char *temp = shstrtab;
    a = fread(shstrtab, shdr[elf_head.e_shstrndx].sh_size, 1, fp);
    if(a==0)
    {
    printf("READ shstetab ERROR\n");
    return 1;
    }

for(shnum = 0; shnum < elf_head.e_shnum; shnum++)
{
temp = shstrtab;
temp = temp + shdr[shnum].sh_name;
if(strcmp(temp, "sign")==0)
{
return 0;
}

}
	rewind(fp);
	
	elf_head.e_shoff = elf_head.e_shoff + 0x105;

	elf_head.e_shnum= elf_head.e_shnum +1;
	
	a = fwrite(&elf_head, sizeof(Elf64_Ehdr), 1, wp);
	if (a == 0)
	{
		printf("WRITE ELF_HEAD ERROR\n");
		return 1;
	}
	fclose(wp);
	wp = NULL;
		
	a = fread(&elf_head1, sizeof(Elf64_Ehdr), 1, fp);
	if (a == 0)
	{
		printf("READ ELF_HEAD1 ERROR\n");
		return 1;
	}
	
	wp = fopen(filename, "r+");
	
	a = fseek(wp, elf_head1.e_shoff, SEEK_SET);
	if(a!=0)
	{
		printf("shdr write fseek ERROR\n");
		return 1;
	}

	shdr[elf_head1.e_shstrndx].sh_size = shdr[elf_head1.e_shstrndx].sh_size+0x5;


	a = fwrite(shdr, sizeof(Elf64_Shdr) * (elf_head1.e_shnum-1), 1, wp);
	if(a==0)
	{
		printf("WRITE SHDR ERROR\n");
		return 1;
	}


	Elf64_Shdr shdr1;
	shdr1.sh_name = shdr[elf_head1.e_shstrndx].sh_size - 0x5;
	shdr1.sh_type = 0x3;
	shdr1.sh_flags =0x0;
	shdr1.sh_addr = shdr[elf_head1.e_shnum - 2].sh_addr;
	shdr1.sh_offset = shdr[elf_head1.e_shnum - 2].sh_offset + shdr[elf_head1.e_shnum - 2].sh_size;
	shdr1.sh_size = 0x100;
	shdr1.sh_link = 0x0;
	shdr1.sh_info = 0x0;
	shdr1.sh_addralign =0x1;
	shdr1.sh_entsize = 0x0;
	
	a = fwrite(&shdr1, sizeof(Elf64_Shdr), 1, wp);
	if(a==0)
	{
		printf("WRITE  shdr1 ERROR\n");
		return 1;
	}

	a = fseek(wp, shdr[elf_head1.e_shnum - 2].sh_offset + shdr[elf_head1.e_shnum - 2].sh_size, SEEK_SET);
	if (a != 0)
	{
		printf("stnew fseek1 ERROR\n");
		return 1;
	}

	a = fwrite(sign, 1, 256, wp);
	if (a == 0)
	{
		printf("WRITE  STNEW ERROR\n");
		return 1;
	}


	char ts[5] = { 0x73,0x69,0x67,0x6E,0x00 };
	a = fseek(wp, shdr[elf_head1.e_shstrndx].sh_offset+ shdr[elf_head1.e_shstrndx].sh_size-0x5, SEEK_SET);

	if(a!=0)
	{
		printf("shstrtab fseek ERROR\n");
		return 1;
	}
	
	a = fwrite(ts, 5, 1, wp);
	if(a==0)
	{
		printf("WRITE  shstrndx ERROR\n");
		return 1;
	}
	
	free(shdr);
	fclose(fp);
	shdr = NULL;
	fp = NULL;
	fclose(wp);
	wp = NULL;
    return 2;
}

char* rsa_key_encrypt(char *filename, unsigned char *out_data, const unsigned char *in_data){
	RSA *rsa = NULL;
	int rsa_len;
	char *p_en;

	OpenSSL_add_all_algorithms();
	BIO *bp = BIO_new(BIO_s_file());;
	BIO_read_filename(bp, filename);
	if(bp==NULL){
	
		printf("open_public_key bio file new error!\n");
		return NULL;
	}

	rsa = PEM_read_bio_RSAPublicKey(bp, NULL, NULL, NULL);
	if(rsa == NULL)
	{
		printf("open_public_key failed to PEM_read_bio_RSAPublicKey!\n");
		BIO_free(bp);
		RSA_free(rsa);
		return NULL;
	}

	//printf("open_public_key success to PEM_read_bio_RSAPublicKey!\n");

	OpenSSL_add_all_ciphers();	
	rsa_len=RSA_size(rsa);
	//printf("rsa_len : %d\n",rsa_len);
	p_en = (unsigned char *)malloc(rsa_len+1);
	memset(p_en,0,rsa_len+1);

	if(RSA_public_encrypt(rsa_len,(unsigned char *)in_data,(unsigned char*)p_en,rsa,RSA_NO_PADDING)<0)
	{
		printf("RSA's lock failed\n");
		RSA_free(rsa);
		BIO_free(bp);
		return NULL;
	}
    printf("End RSA's lock\n");
	RSA_free(rsa);
	BIO_free(bp);
	return p_en;
}

/**/
int main(int argc, char **argv)
{
	int sign;
    unsigned char sha256_digest[SHA256_DIGEST_LENGTH];
    unsigned char *rsa_data;
    char *aim_file;
    char *load_file;
    if(argc != 2)
    {
        printf("usage:%s elf_file\n", argv[0]);
        return -1;
    }

    /**/
    aim_file = argv[1];
    sign = have_Sign(aim_file);
    if(sign==1){                
        printf("find sign failed\n");
        goto _OVER_;
    }
    else if(sign == 2){
        printf("sign exist\n");
        goto _OVER_;
    }
        
    /**/
    load_file = getAllLoadSegments(aim_file);
    sha256_hash("LOAD Segments",sha256_digest);
    //printf("%08x\n",file_Size(load_file));
    remove(load_file);
    //print_hex_hash(sha256_digest,32);
    //printf("\n");
    
    rsa_data = rsa_key_encrypt(PUBLIC_KEY_FILE,rsa_data,sha256_digest);
    //print_hex_hash(rsa_data,256);
    //printf("\n");
    setNewSection(argv[1],rsa_data);

    /**/

_OVER_:

    return 0;

}