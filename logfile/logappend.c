#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wordexp.h>
#include <getopt.h>
#include <openssl/conf.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#define KEY_SIZE 16

decrypt(unsigned char * ciphertext, int ciphertext_len,
   unsigned char *key2, unsigned char *iv, unsigned char *plaintext);
unsigned int logHash(unsigned char* md_value, char* token, int len);
int strtoi (char *str);
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key2,
  unsigned char *iv, unsigned char *ciphertext);
void handleErrors(void);
int hashcmp(char *he, char *key, char *buffer);
int truehashcmp(char *he, char *buffer, int len);
void pad_key(unsigned char * key);

int parse_cmdline(int argc, char *argv[]) {


  //added by joseph
  unsigned char * iv = (unsigned char *)"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
  unsigned char * cipher;
  int enc_length;

  int opt = -1;
  int is_good = -1;

   // file content to add

  //stored token
   char *token;
   // Stored Hash
   unsigned char md_value[33];
   unsigned int md_len;

   //stored time stamp
   int timestamp = 0;

   //stored guest or employee switch 
   char ptype[2];
   ptype[1] = '\0';

   //stored name 
   char *name;

   //stored direction 
  	int direction = 0;
  	char dtype [2];
  	dtype[1] = '\0';
  	int room = -1;
  //pick up the switches
  while ((opt = getopt(argc, argv, "T:K:E:G:ALR:B:")) != -1) {
    switch(opt) {
      case 'B':
        printf("unimplemented");
        exit(0);
        //batch file
        break;

      case 'T':
        //time stamp
      	timestamp = strtoi(optarg);
      	if (timestamp < 1) {
      		printf("invalid");
      		exit(255);
      	}
        break;

      case 'K':
        //secret token
      	token = malloc(strlen(optarg) + 1);
      	// token[strlen(optarg)] = '\0';
      	strncpy(token,optarg, strlen(optarg));
      	token[strlen(optarg)] = '\0';
      	md_len = logHash(md_value, optarg, strlen(optarg));
      	md_value[md_len] = '\0';
        break;

      case 'A':
        //arrival
      	direction = 1;
      	dtype[0] = 'A';
        break;

      case 'L':
        //departure
      	direction = 2;
      	dtype[0] = 'L';
        break;

      case 'E':
      	//employee name
        if (ptype[0] == 'G'){
          printf("invalid");
          exit(255);
        }

       	  ptype[0] = 'E';
        
       	// printf("size: %ld\n",strlen(optarg));
       	name = malloc(strlen(optarg) + 1);
       	strncpy(name, optarg, strlen(optarg));
       	name[strlen(optarg)] = '\0';
        break;

      case 'G':
        //guest name
        if (ptype[0] == 'E'){
          printf("invalid");
          exit(255);
        }
      	ptype[0] = 'G';
      	name = malloc(strlen(optarg) + 1);
       	strncpy(name, optarg, strlen(optarg));
       	name[strlen(optarg)] = '\0';
        break;

      case 'R':
        //room ID
      	room = strtoi(optarg);
        break;

      default:
        printf("invalid");
        exit(255);
        break;
    }

  }


  //pick up the positional argument for log path
  if(optind < argc) {
  	char *logpath;
    logpath = argv[optind];
	  FILE * fpout;
    fpout = fopen(logpath, "r+");

    //if file doesn't exist
    if(fpout == NULL){
       	fpout = fopen(logpath, "w+");

       	if (fpout == NULL)
       	{
       		printf("invalid");
          exit(255);
       	}
       	else{
       		char *outstring;
       		// unsigned char *ciphertext;
       		unsigned int hash_len = 0;
       		unsigned char hash_value[33];
       		int sizetest = 0;

       		//if entering gallary
       		if (room == -1 && direction == 1){
       			//if room id is not present, which it should not be
       			sizetest = snprintf(NULL, 0, "-T %d -%s %s -%s -R -1\n", timestamp, ptype, name, dtype);
       			//should i add null terminator??????
       			outstring = malloc(sizetest + 1);
       			sprintf(outstring, "-T %d -%s %s -%s -R -1\n", timestamp, ptype, name, dtype);
       			outstring[sizetest] = '\0';
       			// printf("String: %s\n", outstring);
       			//printf("outstring: %s and %d and %ld\n", outstring, sizetest, strlen(outstring));
       			//printf("HERE1\n");
       			
       			
       		}
       		else {
       			printf("invalid");
       			exit(255);
	
       		}
       		//write hashed token to file, first 32 bytes
       		fseek(fpout, 0, SEEK_SET);
       		fwrite(md_value, 1, md_len, fpout);
       		//printf("MDLEN: %d\n", md_len);
       		//hashes message
       		//printf("outstring strlen: %ld and sizetest: %d\n", strlen(outstring), sizetest);
       		//log hash takes in hashbuffer, outstring - wish is complete formated string
       		//to be placed in file, and size of outstring which is sizetest
       		hash_len = logHash(hash_value, outstring, sizetest);
       		hash_value[32] = '\0';
       		//printf("%d\n", hash_len);
       		//printf("HASHED ciphertext VALUE: %s\n", hash_value);
       		// writes hash to file
          //if sha256 returns different size of inputs,
          //then the line below could be wrong
       		fwrite(hash_value, 1, hash_len, fpout);
       		//printf("HASHLEN: %d\n", hash_len); 
       		//print new line
       		fprintf(fpout, "\n");

       		//writes event 
          //ENCRYPT
          cipher = (unsigned char *) malloc(sizetest*1.5);
          enc_length = encrypt(outstring, strlen(outstring), token, iv, cipher);
          cipher[enc_length] = '\0';
          fwrite(cipher, 1, enc_length, fpout);
          free(cipher);
          

       		//fprintf(fpout, "%s", outstring);
       		free(outstring);
       		//printf("Sucess file created");

       	}
   	}
    // if file already exists
   	else{
   		
   		//note: sha256 returns different size hash for different inputs, so make old token buffer larger or fix.
   		// char old_token[65];
   		// int testbyte;
   		//reads in entire file to buffer 
   		char * buffer;
   		long lengthbuffer;

   		//start at begining of file
   		fseek(fpout,0,SEEK_SET);
      fseek(fpout, 0, SEEK_END);
   		
   		//get size of file and store in lengthbuffer
   		lengthbuffer = ftell(fpout);

   		//maybe +1?
   		buffer = malloc(lengthbuffer);
   		if(buffer){
        //added

        unsigned char * log = (unsigned char *)malloc(lengthbuffer-65);
        unsigned char * enc_log = (unsigned char *)malloc(lengthbuffer-65);
        int log_len;
        fseek(fpout,65,SEEK_SET);
        fread(enc_log,1, lengthbuffer-65, fpout);
        //printf("Ciphertext before adding to file is:\n%s %d\n",enc_log, lengthbuffer);
        log_len = decrypt(enc_log, (lengthbuffer-65), token,iv,log);
        log[log_len] = '\0';
        free(enc_log);

   			char hashedtoken[33];
   			// hashedtoken[32] = '\0';
   			fseek(fpout, 0, SEEK_SET);
   			//get entire file and store in buffer
   			fread(buffer,1, lengthbuffer, fpout);
   			// buffer[lengthbuffer] = '\0';
   			//get first 32 bytes which is the hashed token
   			memcpy(hashedtoken, buffer, 32);
   			hashedtoken[32] = '\0';
   			//if hashed token is same as hashed token from file
   			if(memcmp(hashedtoken, md_value, 32) == 0){
   				char he_text[33];
   				// he_text[32] = '\0';
   				//printf("SAME TO SAME\n");
   				//get next 32 bytes which is hashed log events
   				memcpy(he_text, buffer + 32, 32);
   				he_text[32] = '\0';
   				//printf("extracted ciphertext hash: %s\n", he_text);
   				 //check integrity 
   				//change truehashcmp to take in length which is lengthbuffer - 65.
   				if (truehashcmp(he_text, log, log_len) == 0){
   					//if valid -> start parsing
   					char *outstring;
            char * log_copy = (char *)malloc(strlen(log));
            memcpy(log_copy, log, strlen(log));

            char * pos;
            unsigned char * line = strtok_r(log_copy, "\n", &pos);
   					//char line[lengthbuffer];
   					//fseek(fpout, 65, SEEK_SET);
   					//tokenizer pointer
   					char *eventptr;
   					//variables that contain information of a specific person from the last time they appeared in the log
   					int extimestamp2 = 0;
   					int exroom2 = 0;
   					//addrooms will be either -1 or 1; -1 if person arrives somewhere; 1 if person leaves somewhere.
   					int addrooms = 0;
   					int sizetest = 0;
   					//if match is 1 then person is found in log, if 0 then person is new.
   					int match = 0;
   					char exname2[lengthbuffer];
   					//go through log events , line by line
   					//while (fgets(line, lengthbuffer, fpout) != NULL){
            while (line != NULL){
   						// line[lengthbuffer - 1] = '\0';
   						// if (strncmp(line, "\n", strlen(line)) != 0){
   							
                char * pos2;
	   						eventptr = strtok_r(line, " ", &pos2);
	   						int extimestamp = 0;
	   						int exroom = 0;
	   						char exname[lengthbuffer];
                memset(exname, '.', sizeof(char)*lengthbuffer);
	   						int stropts = 0;
	   						//if arrival then AL is -1, else AL is 1
	   						int AL = 1;
	   						//if employee -E then EG is "E", if guest -G then EG is "G"
	   						char EG[2];
	   						EG[1] = '\0';
	   						while(eventptr != NULL){
	   							switch(stropts){
	   								case 0:
	   									break;
	   								case 1: 
	   									extimestamp = strtoi(eventptr);
	   									//printf("timestamp: %d\n", extimestamp);
	   									break;
	   								case 2:
	   									if (strncmp("-E", eventptr, strlen(eventptr)) == 0){
	   										EG[0] = 'E';
	   									}
	   									else if(strncmp("-G", eventptr, strlen(eventptr)) == 0){
	   										EG[0] = 'G';
	   									}
	   									break; 
	   								case 3:
	   									strncpy(exname, eventptr, strlen(eventptr));
	   									exname[strlen(eventptr)] = '\0';
	   									//printf("log person name: %s and length: %ld\n",exname, strlen(exname));
	   									break; 
	   								case 4: 
	   									if (strncmp("-A", eventptr, strlen(eventptr)) == 0){
	   										AL = -1;
	   										//printf("Arrival\n");
	   									}
	   									else{
	   										AL = 1;
	   										//printf("Departure\n");
	   									}
	   									break;
	   								case 5:
	   									break;
	   								case 6:
	   									//printf("EXROOM: %s and length: %ld\n", eventptr, strlen(eventptr));
	   									//eventptr[strlen(eventptr) - 1] = '\0';
	   									if (strncmp("-1", eventptr, strlen(eventptr)) == 0){
	   										exroom = -1;
	   									}
	   									else{
                        //printf("eventptr: %s\n", eventptr);
	   										exroom = strtoi(eventptr);
                        //printf("Exroom: %d\n", exroom);
	   									}
	   									
	   									break;
	   							}
	   							
	   							// printf("ptr: %s\n", eventptr);
	   							stropts += 1;
	   							eventptr = strtok_r(NULL, " ", &pos2);
	   						}
	   						//makes sure time stamp is increasing only 
	   						if (timestamp > extimestamp){
                  //printf("timestamp: %d. extimestamp%d\n", timestamp , extimestamp);
	   							//if person is found with same length and name, and -E / -G .
	   							if (strlen(name) == strlen(exname) && strncmp(name, exname, strlen(exname)) == 0 && strncmp(EG, ptype, strlen(ptype)) == 0){
									strncpy(exname2, exname, strlen(exname));
                  //printf("name: %s exname: %s\n", name, exname);
									match = 1;
									exroom2 = exroom;
									addrooms = AL;

	   							//printf("Sucesses %s %s %d %d\n", exname, EG, exroom, addrooms);
	   							}
	   							
	   						}
	   						else{
	   							printf("invalid");
	   							exit(255);
	   						}
							
	   						 // printf("ptrHERE: %d\n", exroom);
	   					// }
   					
            line = strtok_r(NULL, "\n", &pos);
            }

            //added
            free(log_copy);
   					//line[lengthbuffer - 1] = '\0';

   					//printf("THIS IS THE LINE I GOT FROM FILE: %s\n", line);

				//if room id is not present
   				if (room == -1){
	  
	       			sizetest = snprintf(NULL, 0, "-T %d -%s %s -%s -R -1\n", timestamp, ptype, name, dtype);
	       			//should i add null terminator??????
	       			outstring = malloc(sizetest + 1);
	       			// outstring[sizetest] = '\0';
	       			sprintf(outstring, "-T %d -%s %s -%s -R -1\n", timestamp, ptype, name, dtype);
	       			// outstring[sizetest] = '\0';
	       			// printf("String: %s\n", outstring);
	       			//printf("outstring: %s and %d and %ld\n", outstring, sizetest, strlen(outstring));
	       			//printf("HERE1\n");
	       			
       			
       				}

       				//if room id is present
     			else {
       			
       			sizetest = snprintf(NULL, 0, "-T %d -%s %s -%s -R %d\n", timestamp, ptype, name, dtype, room);
       			//should i add null ternimator???????
       			outstring = malloc(sizetest + 1);
       			// outstring[sizetest] = '\0';
       			sprintf(outstring, "-T %d -%s %s -%s -R %d\n", timestamp, ptype, name, dtype, room);
       			// outstring[sizetest] = '\0';
       			// printf("String: %s\n", outstring);
       			//printf("outstring: %s and %d and %ld\n", outstring, sizetest, strlen(outstring));
       			//printf("HERE2\n");
     			
     			}

   					//person arrived in room last so is arrived in room or in gallery
   					if (addrooms < 0 && direction == 2 && room == exroom2){

     						// unsigned char *ciphertext;
			       		unsigned int hash_len = 0;
			       		unsigned char hash_value[33];

                //3
                int newlengthbuffer = log_len + strlen(outstring);
                unsigned char newbuffer[newlengthbuffer];
                strncpy(newbuffer, log, log_len);
                strncpy(newbuffer+log_len, outstring, strlen(outstring));
                  /*
     						int newlngthbuffer = lengthbuffer - 65 + sizetest;
     						char newbuffer[newlengthbuffer];
     						memcpy(newbuffer, buffer + 65, lengthbuffer - 65);
     						memcpy(newbuffer + lengthbuffer - 65, outstring, strlen(outstring));
     						*/
                // newbuffer[newlengthbuffer - 1] = '\0';
  			       		//prints out hashed token
  			       		fseek(fpout, 0, SEEK_SET);
  			       		fwrite(md_value, 1, md_len, fpout);

  			       		//make logHash take in length of newbuffer, dont use strlen newbuffer
  			       		hash_len = logHash(hash_value, newbuffer, newlengthbuffer);
  			       		hash_value[hash_len] = '\0';
  			       		
  			       		//printf("%d\n", hash_len);
  			       		//printf("HASHED log VALUE: %s\n", hash_value);
  			       		// writes hash
  			       		fseek(fpout, 32, SEEK_SET);
  			       		fwrite(hash_value, 1, hash_len, fpout);

  			       		//writes new log content 3 
       						cipher =  (unsigned char *)malloc(newlengthbuffer*1.5);
                  enc_length = encrypt(newbuffer, newlengthbuffer, token,iv, cipher); 
                  //printf("%s\n", newbuffer);
                  cipher[enc_length] = '\0';
                  fseek(fpout, 65, SEEK_SET);
                  fwrite(cipher,1, enc_length, fpout);
                  free(cipher);
						
   					}
            //addrooms -1 last value was arrival 
            //direction 1 arriving 2 leaving
   					//if last direction was leaving and this direction is arriving
   					else if (addrooms > 0 && direction == 1){
   						//if last room left was gallery and you are now entering the gallery OR if last room was room and you want to go to another room thats not the gallery
     					if ((exroom2 == -1 && room == -1) || (exroom2 != -1 && room != -1)){

  			       		// unsigned char *ciphertext;
  			       		unsigned int hash_len = 0;
  			       		unsigned char hash_value[33];

                  //4
  	   						int newlengthbuffer = log_len + strlen(outstring);
                  unsigned char newbuffer[newlengthbuffer];
                  strncpy(newbuffer, log, log_len);
                  strncpy(newbuffer+log_len, outstring, strlen(outstring));
                  //printf("%s\n", newbuffer);
  	   						// newbuffer[newlengthbuffer - 1] = '\0';
  			       		//prints out hashed token
  			       		fseek(fpout, 0, SEEK_SET);
  			       		fwrite(md_value, 1, md_len, fpout);

  			       		//make logHash take in length of newbuffer, dont use strlen newbuffer
  			       		hash_len = logHash(hash_value, newbuffer, newlengthbuffer);
  			       		hash_value[hash_len] = '\0';
  			       		
  			       		//printf("%d\n", hash_len);
  			       		//printf("HASHED log VALUE: %s\n", hash_value);
  			       		// writes hash
  			       		fseek(fpout, 32, SEEK_SET);
  			       		fwrite(hash_value, 1, hash_len, fpout);

  			       		//writes new log content 10
  	   						cipher =  (unsigned char *)malloc(newlengthbuffer*1.5);
                  enc_length = encrypt(newbuffer, newlengthbuffer, token,iv, cipher); 
                  cipher[enc_length] = '\0';
                  fseek(fpout, 65, SEEK_SET);
                  fwrite(cipher,1, enc_length, fpout);
                  free(cipher);


                  //printf("%s\n", newbuffer);
     							//printf("SUCCESSES of course 1\n");
   						}


   						//if last room left was gallery and you are entering a room - invalid
   						else if (exroom2 == -1 && room != -1){
   							printf("invalid");
                exit(255);
   						}
   						else{
   							printf("invalid");
                exit(255);
   						}

   					}
   					//first time in gallery -> if last direction was arriving and you are entering make sure that room is not gallery and the last room is not the same as new room
   					else if (addrooms < 0 && direction == 1 && exroom2 == -1 && exroom2 != room){
		       		// unsigned char *ciphertext;
		       		unsigned int hash_len = 0;
		       		unsigned char hash_value[33];

              //5
   						int newlengthbuffer = log_len + strlen(outstring);
              unsigned char newbuffer[newlengthbuffer];
              strncpy(newbuffer, log, log_len);
              strncpy(newbuffer+log_len, outstring, strlen(outstring));
   						// newbuffer[newlengthbuffer - 1] = '\0';
			       		//prints out hashed token
			       		fseek(fpout, 0, SEEK_SET);
			       		fwrite(md_value, 1, md_len, fpout);

			       		//make logHash take in length of newbuffer, dont use strlen newbuffer
			       		hash_len = logHash(hash_value, newbuffer, newlengthbuffer);
			       		hash_value[hash_len] = '\0';
			       		
			       		//printf("%d\n", hash_len);
			       		//printf("HASHED log VALUE: %s\n", hash_value);
			       		// writes hash
			       		fseek(fpout, 32, SEEK_SET);
			       		fwrite(hash_value, 1, hash_len, fpout);

			       		//writes new log contents 
   						
              //write content 5
              cipher =  (unsigned char *)malloc(newlengthbuffer*1.5);
              enc_length = encrypt(newbuffer, newlengthbuffer, token,iv, cipher); 
              cipher[enc_length] = '\0';
              fseek(fpout, 65, SEEK_SET);
              fwrite(cipher,1, enc_length, fpout);
              free(cipher);
              


   						//printf("SUCCESSES of course 2\n");
   					}

   					else if (match == 0 && room == -1 && direction == 1) {
   						// unsigned char *ciphertext;
		       		unsigned int hash_len = 0;
		       		unsigned char hash_value[33];

              //1
   						int newlengthbuffer = log_len + strlen(outstring);
              unsigned char newbuffer[newlengthbuffer];
              strncpy(newbuffer, log, log_len);
              strncpy(newbuffer+log_len, outstring, strlen(outstring));
   						// newbuffer[newlengthbuffer - 1] = '\0';
		       		//prints out hashed token
		       		fseek(fpout, 0, SEEK_SET);
		       		fwrite(md_value, 1, md_len, fpout);

		       		//make logHash take in length of newbuffer, dont use strlen newbuffer
		       		hash_len = logHash(hash_value, newbuffer, newlengthbuffer);
		       		hash_value[hash_len] = '\0';
		       		
		       		//printf("%d\n", hash_len);
		       		//printf("HASHED log VALUE: %s\n", hash_value);
		       		// writes hash
		       		fseek(fpout, 32, SEEK_SET);
		       		fwrite(hash_value, 1, hash_len, fpout);

			       	//writes new log content 2
              //unsigned char * iv = (unsigned char *)"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
             
   						cipher =  (unsigned char *)malloc(newlengthbuffer*1.5);
              enc_length = encrypt(newbuffer, newlengthbuffer, token,iv, cipher); 
              cipher[enc_length] = '\0';
              fseek(fpout, 65, SEEK_SET);
              fwrite(cipher,1, enc_length, fpout);
              free(cipher);

              //printf("%s\n", newbuffer);
   						//printf("SUCCESSES of course 3\n");
   					}
   					//if last room left was room and now you are in gallery and want to leave the gallery
   					else if(exroom2 != -1 && direction == 2 && room == -1){
		       		// unsigned char *ciphertext;
		       		unsigned int hash_len = 0;
		       		unsigned char hash_value[33];

              //2
   						int newlengthbuffer = log_len + strlen(outstring);
              unsigned char newbuffer[newlengthbuffer];
              strncpy(newbuffer, log, log_len);
              strncpy(newbuffer+log_len, outstring, strlen(outstring));
   						// newbuffer[newlengthbuffer - 1] = '\0';
		       		//prints out hashed token
		       		fseek(fpout, 0, SEEK_SET);
		       		fwrite(md_value, 1, md_len, fpout);

		       		//make logHash take in length of newbuffer, dont use strlen newbuffer
		       		hash_len = logHash(hash_value, newbuffer, newlengthbuffer);
		       		hash_value[hash_len] = '\0';
		       		
		       		//printf("%d\n", hash_len);
		       		//printf("HASHED log VALUE: %s\n", hash_value);
		       		// writes hash
		       		fseek(fpout, 32, SEEK_SET);
		       		fwrite(hash_value, 1, hash_len, fpout);

			       	//writes new log content 6 
   						cipher =  (unsigned char *)malloc(newlengthbuffer*1.5);
              enc_length = encrypt(newbuffer, newlengthbuffer, token,iv, cipher); 
              cipher[enc_length] = '\0';
              fseek(fpout, 65, SEEK_SET);
              fwrite(cipher,1, enc_length, fpout);
              free(cipher);
              
              //printf("%s\n", newbuffer);
   						// fprintf(fpout, "\n" );
   						// free(ciphertext);

   						//printf("SUCCESSES of course 4\n");
   					}
   					else{
   						printf("invalid");
              exit(255);
   					}

   					free(outstring);
   					//printf("INTEGRITY VALID\n");
   				}
   				else{
   					//if integrity not valid 
   					printf("invalid");
   					exit(255);
   				}

   			}
   			else{
   				printf("invalid");
   				exit(255);
   				// printf("%s\n", hashedtoken);
   			}
   			// printf("%s\n", buffer + 65);
   		
      free(log);
      }

   		free(buffer);
   		
   		//printf("Sucess file exists\n");

   	}
   	//printf("Sucess IN\n");
  }

  free(token);
  free(name);


  return is_good;
}

unsigned int logHash(unsigned char* md_value, char* token, int len){
		  const EVP_MD *md;
		  EVP_MD_CTX *mdctx;
		  unsigned int md_len;
		  OpenSSL_add_all_digests();
          md = EVP_get_digestbyname("sha256");
          mdctx = EVP_MD_CTX_create();
          EVP_DigestInit_ex(mdctx, md, NULL);
          EVP_DigestUpdate(mdctx, token, len);
          EVP_DigestFinal_ex(mdctx, md_value, &md_len);
          EVP_MD_CTX_destroy(mdctx);

          return md_len;
}

int strtoi (char *str) {
	char *endpt;
	errno = 0;
	long l = strtol(str, &endpt, 10);
	if (errno == ERANGE || *endpt != '\0' || str == endpt){
		printf("");
		exit(0);
	}

	if (l < INT_MIN || l > INT_MAX || l < 0 || l > 1073741823) 
	{
		printf("invalid");
		exit(255);
	}

	return (int) l;
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

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key2,
  unsigned char *iv, unsigned char *ciphertext)
{

  //make sure key is of the right size
  unsigned char key[KEY_SIZE + 1];
  int size  = strlen((const char *)key2);
  if (size > KEY_SIZE){
    strncpy((char * restrict)key,(const char*)key2,KEY_SIZE);
    key[KEY_SIZE] = '\0';
  }else{
    strncpy((char * restrict)key,(char * restrict)key2,size);
    key[size] = '\0';
  }  
  pad_key(key);

  EVP_CIPHER_CTX *ctx;
  int len;
  int ciphertext_len;

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

   // Initialise the encryption operation. IMPORTANT - ensure you use a key
   // * and IV size appropriate for your cipher
   // * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   // * IV size for *most* modes is the same as the block size. For AES this
   // * is 128 bits 
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

void handleErrors(void){
	printf("invalid");
	exit(255);
	//ERR_print_errors_fp(stderr);
	//abort();
}

int truehashcmp(char *he, char *buffer, int len){
	// char *outstring;
    unsigned int hash_len = 0;
   	unsigned char hash_value[33];
    // int sizetest = 0;
	 //printf("BUFFER in truehashcmp: %s and size: %ld\n", buffer, strlen(buffer));
   //hashes message
   hash_len = logHash(hash_value, buffer, len);
   hash_value[hash_len] = '\0';
   //printf("length of extracted text %ld and %s and inputed length is: %d\n", strlen(buffer), buffer, len);
   //printf("HASHED VALUE from event extraction: %s\n", hash_value);
   //printf("HASH VALUE IN FILE: %s\n", he);


   return memcmp(hash_value, he, 32);
}

int hashcmp(char *he, char *key, char *buffer){
	// char *outstring;
    unsigned char *ciphertext;
    unsigned int hash_len = 0;
    int cipher_len = 0;
   	unsigned char hash_value[EVP_MAX_MD_SIZE];
    // int sizetest = 0;
    unsigned char *iv = (unsigned char *)"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

	// ciphertext = malloc(strlen(buffer));
    // ciphertext[strlen(buffer)] = '\0';
       		//before was sizetest + 1 ... just commented out and had static 128 bit allocation for ciphertext
       		if (strlen(buffer) < 32){
       			ciphertext = malloc(33);
       		}
       		else if(strlen(buffer) % 16 == 0) {
       			ciphertext = malloc(strlen(buffer) + 12);
       		}
       		else if(strlen(buffer) % 16 != 0 && strlen(buffer) > 32){
       			int space = 0;
       			space = ((strlen(buffer) / 16) + 1) * 16;
       			//printf("space allocated: %d\n", space + 1);
       			ciphertext = malloc(space + 1);
       		}

   //encrypts message 
   cipher_len = encrypt ((unsigned char * )buffer, strlen(buffer) - 1, (unsigned char *)key, iv, ciphertext);
   // ciphertext[strlen(buffer) - 1] = '\0';
   ciphertext[cipher_len] = '\0';
   //hashes message
   // printf("length of cipher text: %d\n", cipher_len);
   // printf("encrypted from plaintext file: %s\n",ciphertext);
   hash_len = logHash(hash_value, (char *)ciphertext, cipher_len);
   hash_value[hash_len] = '\0';
   // printf("length of extracted text %ld and %s\n", strlen(buffer) - 1, buffer);
   // printf("HASHED ciphertext VALUE from File: %s\n", hash_value);

   free(ciphertext);

   return memcmp(hash_value, he, 32);
}

//pads key to be 128 bits
void pad_key(unsigned char * key){
  int size = (int)strlen((const char *)key);
  key[KEY_SIZE] = '\0';
  if (size < KEY_SIZE){     
    for (int i = size-1; i < 16; i++){
      key[i] = ' ';
    }
  }
}

int main(int argc, char *argv[]) {

  int result;
  result = parse_cmdline(argc, argv);




  return 0;
}
