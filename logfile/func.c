

#include "func.h"


//token used is "secret"
//iv is "0123456789012345"


void handleErrors(void){
  printf("invalid");
  exit(255);
  //ERR_print_errors_fp(stderr);
  //abort();
}


/*
Get the encryption key
% openssl dec aes-128-cbc -e  -in cipher.txt -out var2 -K  (word from word.txt) -iv 0000000000000000
 if var2 == task3.txt the MATH else NO MATCH
*/
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key2,
  unsigned char *iv, unsigned char *ciphertext)
{
  //make sure key is of the right size
  unsigned char key[KEY_SIZE + 1];
  int size  = strlen((const char *)key2);
  if (size > KEY_SIZE){
    strncpy(key,key2,KEY_SIZE);
    key[KEY_SIZE] = '\0';
  }else{
    strncpy(key,key2,size);
    key[size] = '\0';
  }  
  pad_key(key);

  EVP_CIPHER_CTX *ctx;
  int len;
  int ciphertext_len;

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

  /* Initialise the encryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits */
  if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
    handleErrors();

  /* Provide the message to be encrypted, and obtain the encrypted output.
   * EVP_EncryptUpdate can be called multiple times if necessary
   */
  if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    handleErrors();
  ciphertext_len = len;

  /* Finalise the encryption. Further ciphertext bytes may be written at
   * this stage.
   */
  if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
  ciphertext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return ciphertext_len;
}

int decrypt(unsigned char * ciphertext, int ciphertext_len,
	 unsigned char *key2, unsigned char *iv, unsigned char *plaintext)
{
  //make sure key is of the right size
  unsigned char key[KEY_SIZE + 1];
  int size  = strlen((const char *)key2);
  if (size > KEY_SIZE){
    strncpy(key,key2,KEY_SIZE);
    key[KEY_SIZE] = '\0';
  }else{
    strncpy(key,key2,size);
    key[size] = '\0';
  }  
  pad_key(key);


	EVP_CIPHER_CTX *ctx;
	int len;
	int plaintext_len;

	/*Create and initialize the context */
	if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

	/*Initialize the decryption operation */
	if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv ))
		handleErrors();

	/*Provide message to be decrypted and obtain the plaintext output 
	EVP_DecryptUpdate can be called multiple times if necessary
	*/

	if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
		handleErrors();
	plaintext_len = len;

	/*Finalize the decryption. Further plaintext bytes might be written at this stage 
	*/
	if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
		handleErrors();

	plaintext_len += len;

	/*Clean up*/
	EVP_CIPHER_CTX_free(ctx);

	return plaintext_len;
}

/**
Function read and stores the different contents of a FILE i.e
hashed token, h_e_log, log
arguments: 
fp: FILE to extract values from
token: variable to store the hashedtoken 
h_e_log: variable to store the hashed encrypted log
log: variable to store the log Events
returns the size of log
NOTE: make sure to FREE token, h_e_log, log
*/
 unsigned int readFILE(FILE * fp, unsigned char ** token,
  unsigned char ** h_e_log, unsigned char ** log ){

    //printf("readfile");
    //get size of FILE
    fseek(fp, 0, SEEK_END);
    unsigned int logLength = (unsigned int) ftell(fp);

    //allocate memory
    *token = (unsigned char *)malloc(HASH_SIZE + 1);
    *h_e_log = (unsigned char *)malloc(HASH_SIZE + 1);
    *log = (unsigned char *)malloc(logLength-(HASH_SIZE*2));
    
    //reset pointer to start reading from the start
    fseek(fp,0, SEEK_SET);

    //read FILE
    fread(*token, 1, HASH_SIZE,fp);
    fread(*h_e_log, 1, HASH_SIZE,fp);
    fseek(fp,65, SEEK_SET);
    fread(*log, 1, (logLength-65), fp);

    //reset pointer
    fseek(fp,0, SEEK_SET);

    (*token)[HASH_SIZE] = '\0';
    (*h_e_log)[HASH_SIZE] = '\0';
    (*log)[logLength-(HASH_SIZE*2)-1] = '\0';

    return logLength;
}

/**
arguments:
token: what to hash
md_value: where to store hashed token
*/
unsigned int logHash(unsigned char* md_value, char* token){

      unsigned int md_len;
      const EVP_MD *md; 
      EVP_MD_CTX *mdctx;
      OpenSSL_add_all_digests();
      md = EVP_get_digestbyname("sha256");
      mdctx = EVP_MD_CTX_create();
      EVP_DigestInit_ex(mdctx, md, NULL);
      EVP_DigestUpdate(mdctx, token, strlen(token));
      EVP_DigestFinal_ex(mdctx, md_value, &md_len);
      EVP_MD_CTX_destroy(mdctx);
      return md_len;

}

/**
function takes token given by user in the command line, 
hashes the given token and compares it with the hashed token that 
was stored in the log file
arguments:
token: token provided by user.
storedToken: hashedToken that was stored in log FILE

returns 0 if token is valid 
*/
int validate_token(unsigned char * token, unsigned char * storedToken){
  unsigned char hashedToken[HASH_SIZE];
  logHash(hashedToken, token);
  return memcmp(storedToken,hashedToken, HASH_SIZE);
}

/**
function validates that the logEvents haven't been changed.

Arguments:
token: token provider by at the command line.
h_e_log: hashed encrypted log events
log: pointer to logEvents
logLength: size of log.

return 0 if file contents haven't been changed
*/
int validate_log(unsigned char * token,void * h_log, 
  unsigned char * enc_log, unsigned int encLogLength, unsigned char ** log ){
  //procedure
  //Encrpyt the log
  //hashes the encrpyted token
  //memcmp hashes of encrpyted 
  //unsigned char * t = "secret";
  unsigned char * iv = (unsigned char *)"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
  *log = (unsigned char *)malloc(encLogLength);
  unsigned char hashed_text[HASH_SIZE];
  int log_len;
  //printf("test2");
  log_len = decrypt(enc_log, encLogLength, token,iv,*log);
  (*log)[log_len] = '\0';
  //printf("Cipher text: %s", *log);
  //printf("Cipher text length: %d\n", ciphertext_len);
  //printf("compare ciphertext: %d\n", strcmp(ciphertext, cipher));
  logHash(hashed_text, *log);
  //printf("hashed enc log: %s\n", hashed_cipher);

  //free(ciphertext);
  return memcmp(hashed_text, h_log, HASH_SIZE);
}

/**
Could be used to free memory allocated using readFile
*/
void freeMemory(unsigned char * token, 
  unsigned char * h_e_log, unsigned char * log){

  //allocate memory
  free(token);
  free(h_e_log);
  free(log);

}

//pads key to be 128 bits
void pad_key(unsigned char * key){
  int size = (int)strlen(key);
  key[KEY_SIZE] = '\0';
  if (size < KEY_SIZE){     
    for (int i = size-1; i < 16; i++){
      key[i] = ' ';
    }
  }
}
