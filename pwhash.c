#define _GNU_SOURCE
#include <ctype.h>
#include <dirent.h>
#include <fcntl.h>
#include <ftw.h>
#include <libgen.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <utime.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <openssl/md4.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

/*===========================================================================*/
void base64(const unsigned char* buffer, size_t length, char** b64text)
{
BIO *bio, *b64;
BUF_MEM *bufferPtr;

b64 = BIO_new(BIO_f_base64());
bio = BIO_new(BIO_s_mem());
bio = BIO_push(b64, bio);

BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
BIO_write(bio, buffer, length);
BIO_flush(bio);
BIO_get_mem_ptr(bio, &bufferPtr);
BIO_set_close(bio, BIO_NOCLOSE);
BIO_free_all(bio);
*b64text=(*bufferPtr).data;
return;
}
/*===========================================================================*/
int main(int argc, char *argv[])
{
int p;
int k;
int maclen = 12;
int keysetlen = 58;

char *macstring = NULL;
char *keystring = NULL;
char *hashrecord = NULL;

SHA_CTX ctxsha1;
SHA256_CTX ctxsha256;
SHA512_CTX ctxsha512;
MD5_CTX ctxmd5;
MD4_CTX ctxmd4;

unsigned char digestsha1[SHA_DIGEST_LENGTH];
unsigned char digestsha256[SHA256_DIGEST_LENGTH];
unsigned char digestsha512[SHA512_DIGEST_LENGTH];
unsigned char digestmd5[MD5_DIGEST_LENGTH];
unsigned char digestmd4[MD4_DIGEST_LENGTH];

char testmacstring[] = "112233445566";
char testkeysetstring[] = "1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

macstring = testmacstring;
keystring = testkeysetstring;

if(argc == 3)
	{
	macstring = argv[1];
	maclen = strlen(argv[1]);
	keystring = argv[2];
	keysetlen = strlen(argv[2]);
	}

else
	{
	printf("usage: pwhash word charset\nexample: pwhash %s %s\n", testmacstring, testkeysetstring);
	}


SHA512_Init(&ctxsha512);
SHA512_Update(&ctxsha512, macstring, maclen);
SHA512_Final(digestsha512, &ctxsha512);

printf("\nsha512-hex....: ");
for (p = 0; p < SHA512_DIGEST_LENGTH; p++)
	{
	printf("%02x", digestsha512[p]);
	}

base64(digestsha512, SHA512_DIGEST_LENGTH, &hashrecord);
printf("\nsha512-base64.: %s", hashrecord);
free(hashrecord);

printf("\nsha512-ascii..: ");
for (p = 0; p < SHA512_DIGEST_LENGTH; p++)
	{
	k = (digestsha512[p] %keysetlen);
	printf("%c", keystring[k]);
	}

SHA256_Init(&ctxsha256);
SHA256_Update(&ctxsha256, macstring, maclen);
SHA256_Final(digestsha256, &ctxsha256);

printf("\nsha256-hex....: ");
for (p = 0; p < SHA256_DIGEST_LENGTH; p++)
	{
	printf("%02x", digestsha256[p]);
	}

base64(digestsha256,SHA256_DIGEST_LENGTH, &hashrecord);
printf("\nsha256-base64.: %s", hashrecord);
free(hashrecord);

printf("\nsha256-ascii..: ");
for (p = 0; p < SHA256_DIGEST_LENGTH; p++)
	{
	k = (digestsha256[p] %keysetlen);
	printf("%c", keystring[k]);
	}

SHA1_Init(&ctxsha1);
SHA1_Update(&ctxsha1, macstring, maclen);
SHA1_Final(digestsha1, &ctxsha1);

printf("\nsha1-hex......: ");
for (p = 0; p < SHA_DIGEST_LENGTH; p++)
	{
	printf("%02x", digestsha1[p]);
	}

base64(digestsha1, SHA_DIGEST_LENGTH, &hashrecord);
printf("\nsha1-base64...: %s", hashrecord);
free(hashrecord);

printf("\nsha1-ascii....: ");
for (p = 0; p < SHA_DIGEST_LENGTH; p++)
	{
	k = (digestsha1[p] %keysetlen);
	printf("%c", keystring[k]);
	}

MD5_Init(&ctxmd5);
MD5_Update(&ctxmd5, macstring, maclen);
MD5_Final(digestmd5, &ctxmd5);

printf("\nmd5-hex.......: ");
for (p = 0; p < MD5_DIGEST_LENGTH; p++)
	{
	printf("%02x", digestmd5[p]);
	}

base64(digestmd5, MD5_DIGEST_LENGTH, &hashrecord);
printf("\nsmd5-base64...: %s", hashrecord);
free(hashrecord);

printf("\nmd5-ascii.....: ");
for (p = 0; p < MD5_DIGEST_LENGTH; p++)
	{
	k = (digestmd5[p] %keysetlen);
	printf("%c", keystring[k]);
	}

MD4_Init(&ctxmd4);
MD4_Update(&ctxmd4, macstring, maclen);
MD4_Final(digestmd4, &ctxmd4);

printf("\nmd4-hex.......: ");
for (p = 0; p < MD4_DIGEST_LENGTH; p++)
	{
	printf("%02x", digestmd4[p]);
	}

base64(digestmd4, MD4_DIGEST_LENGTH, &hashrecord);
printf("\nmd4-base64....: %s", hashrecord);
free(hashrecord);

printf("\nmd4-ascii.....: ");
for (p = 0; p < MD4_DIGEST_LENGTH; p++)
	{
	k = (digestmd4[p] %keysetlen);
	printf("%c", keystring[k]);
	}


printf("\n\n");

return EXIT_SUCCESS;
}
