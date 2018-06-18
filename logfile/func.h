/**func.h*/
#include <stdio.h>
#include <string.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <wordexp.h>
#include <openssl/bio.h>
#include <openssl/rand.h>

#ifndef _func_h
#define _func_h

void pad_key(unsigned char * key);
int validate_token(unsigned char * token, unsigned char * storedToken);
int validate_log(unsigned char * token,void * h_log, 
  unsigned char * enc_log, unsigned int logLength, unsigned char ** log);
unsigned int logHash( unsigned char * md_value, char * token);
unsigned int readFILE(FILE * fp, unsigned char ** token, 
  unsigned char ** h_e_log, unsigned char ** log);
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
  unsigned char *iv, unsigned char *ciphertext);
int decrypt(unsigned char * ciphertext, int ciphertext_len,
	unsigned char *key, unsigned char *iv, unsigned char *plaintext);
void handleErrors(void);
int hash_str(unsigned char * str, unsigned char * digest_name, unsigned char * md_value);

#endif

#ifndef HASH_SIZE
#define HASH_SIZE 32
#endif

#ifndef KEY_SIZE
#define KEY_SIZE 16
#endif