#include <stdio.h>
#include <stdlib.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <elf.h>
#include <string.h>
#include <errno.h>
#include <string.h>

#define READ_SIZE 32768
#define RSA_KEY_LENGTH 2048
static const char rand_seed[] = "string to make the random number generator initialized";

#define PRIVATE_KEY_FILE "rsapri.key"
#define PUBLIC_KEY_FILE "rsapub.key"
#define LOAD_FILE "LOAD Segments"

#define RSA_PRIKEY_PSW "123"

size_t file_Size(char *filename){
	FILE *fd = NULL;
	fd = fopen(filename,"rb");
	if(fd == NULL){
		printf("No such file: %s\n",filename);
		return 0;
	}
	fseek(fd,0,SEEK_END);
	size_t size = ftell(fd);
	return size;
}

int sha256_hash (char* path, unsigned char *digest)
{
	char hash[SHA256_DIGEST_LENGTH];
	SHA256_CTX sha256;
	char *buffer = NULL;
	const int bufsize = READ_SIZE;
	int bytes_read = 0;

	FILE *file = fopen(path, "rb");
	if (!file) {
		printf("%s: can not open %s\n", __func__, path);
		return -1;
	}

	SHA256_Init(&sha256);

	buffer = malloc(bufsize);
	if (!buffer) {
		printf("%s: malloc failed\n", __func__);
		fclose(file);
		return -1;
	}

	while((bytes_read = fread(buffer, 1, bufsize, file)))
		SHA256_Update(&sha256, buffer, bytes_read);

	SHA256_Final(digest, &sha256);

	fclose(file);
	free(buffer);

	return 0;
}

void print_hex_hash(unsigned char* digest, int length)
{
	int i;
	for(i=0; i < length; i++)
		printf("%02x", digest[i]);
}

void getLoadSegment(Elf64_Phdr *phdr,char *filename){
  
    FILE *fr=NULL;
    fr = fopen(filename,"rb");
    FILE *fd = NULL;
    fd=fopen(LOAD_FILE,"a+");
    fseek(fr,(phdr->p_offset),SEEK_SET);

    unsigned char buffer[2];
    int num=0;
    while(1){
      num++;
      fread(buffer,1,1,fr);
        //printf("%02x",buffer[0]);
      fwrite(buffer,1,1,fd);
      if(ftell(fr)==((phdr->p_offset)+(phdr->p_filesz)))
	break;
    }
    fclose(fr);
    fclose(fd);
   
}

char *getAllLoadSegments(char *filename){
	int ret_val = -1;
    int i=0;
    FILE *fp = NULL;
    Elf64_Ehdr elf_header;
    Elf64_Phdr elf_Phdr;
	fp=fopen(filename,"r");	
	char *rm_file=LOAD_FILE;
	if(fp == NULL)
    {
        printf("fopen Failed\n");
        return NULL;
    }
	ret_val = fread((void *)&elf_header, 1, sizeof(Elf64_Ehdr), fp);
	if(ret_val != sizeof(Elf64_Ehdr))
    {
        printf("fread Failed(%d)\n", ret_val);
        return NULL;
    }
    fseek(fp,(&elf_header)->e_phoff,SEEK_SET);
    for(i=0;i<(&elf_header)->e_phnum;i++){     
      bzero((void *)&elf_Phdr,sizeof(Elf64_Phdr));
      fread((void *)&elf_Phdr,1,sizeof(Elf64_Phdr),fp);
      if((&elf_Phdr)->p_type==1){
	    getLoadSegment(&elf_Phdr,filename);
      }	
    }
    fclose(fp);
	return rm_file;
}

int have_Sign(char *filename)
{
	int shnum, a;
	FILE *fp;
	Elf64_Ehdr elf_head;
	fp = fopen(filename, "r");
	if (NULL == fp)
	{
		printf(" have_Sign open file fail\n");
		return 1;
	}
	a = fread(&elf_head, sizeof(Elf64_Ehdr), 1, fp);
	if (a == 0)
	{
		printf(" have_Sign READ elf_hear ERROR\n");
		return 1;
	}
	Elf64_Shdr *shdr = (Elf64_Shdr*)malloc(sizeof(Elf64_Shdr) * elf_head.e_shnum);

	if (shdr == NULL)
	{
		printf(" have_Sign shdr malloc failed\n");
		return 1;
	}
	a = fseek(fp, elf_head.e_shoff, SEEK_SET);
	if (a != 0)
	{
		printf(" have_Sign shdr fseek ERROR\n");
		return 1;
	}
	a = fread(shdr, sizeof(Elf64_Shdr) * elf_head.e_shnum, 1, fp);
	if (a == 0)
	{
		printf(" have_Sign READ shdr ERROR\n");
		return 1;
	}
	a = fseek(fp, shdr[elf_head.e_shstrndx].sh_offset, SEEK_SET);
	if (a != 0)
	{
		printf(" have_Sign shstrtab fseek ERROR\n");
		return 1;
	}
	char shstrtab[shdr[elf_head.e_shstrndx].sh_size];
	char *temp = shstrtab;
	a = fread(shstrtab, shdr[elf_head.e_shstrndx].sh_size, 1, fp);
	if (a == 0)
	{
		printf(" have_Sign READ shstetab ERROR\n");
		return 1;
	}
	//比对
	for (shnum = 0; shnum < elf_head.e_shnum; shnum++)
	{
		temp = shstrtab;
		temp = temp + shdr[shnum].sh_name;
		if (strcmp(temp, "sign") == 0)
		{
			return 2;
		}

	}
	return 0;

}



