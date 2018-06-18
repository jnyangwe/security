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
#include <getopt.h>

#include "func.h"

#define BUF_SIZE 1024

//keeps track of rooms visited by user
typedef struct visited{
  int roomId;
  struct visited *  next;
} visited_t;

typedef struct person{
	unsigned char * name;
	struct person * next;
} person_t;


typedef struct room {
	int roomId;
	struct room * next; //next room
	struct person * nextPerson;
} room_t;

void print_rooms_visited(visited_t * head);
void clean_rooms_visited(visited_t * head);
void print_person(person_t * head);
void print_state(person_t * guests, person_t * employees, room_t * structure); 
void cleanup_person_t(person_t * head);
void cleanup_rooms(room_t * structure);
room_t * search_for_room(room_t * p, char * name, int roomId);
person_t * search_for_name(person_t * p, char * name);
//void search_name(person_t * p, char * name);
void add_name(person_t * p, char * name);
void enter_room(room_t * r, char * name, int roomId);
void remove_name(person_t * p, char * name);
void leave_room(room_t * r, char * name, int roomId);
void extract_str(char * line, char * E_G,
   char ** name, char * A_L,char * R, int * roomId);


int main(int argc, char *argv[]) {
  int   opt,len;
  char  *logpath = NULL;
  char * personName = NULL;
  char typePerson = ' ';
  char command = 'N'; //'N' stands for no command
  FILE * fp;
  char buf[BUF_SIZE];
  unsigned char * token;


  while ((opt = getopt(argc, argv, "K:PSRE:G:VTI")) != -1) {
    switch(opt) {
      case 'T':
        printf("unimplemented");
          exit(0);
   
      break;
      case 'I':
        printf("unimplemented");
        exit(0);
      
      break;
      case 'V':
        break;

      case 'P':
        break;

      case 'K':
      /*
        token = (unsigned char *)malloc(sizeof(optarg)+1);
        token[sizeof(optarg)] = '\0';
        strncpy(token, optarg, sizeof(optarg));
        */
      if (optarg != NULL)
        token = (unsigned char *)optarg; 
      else{
        printf("invalid");
        exit(255);
      }    
        break;

      case 'S':
        if(command == 'N' || command == 'S' )
        command = 'S';
      else{
        printf("invalid");
        exit(255);
      }
      break;

      case 'R':
        if(command == 'N' || command == 'R' )
        command = 'R';
      else{
        printf("invalid");
        exit(255);
      }
        break;

      case 'E':
      if (optarg != NULL){
        personName = optarg;
        typePerson = 'E';
      }else{
        printf("invalid");
        exit(255);
      }
        break;
      
      case 'G':
       if (optarg != NULL){
          personName = optarg;
          typePerson = 'G';
        }else{
          printf("invalid");
          exit(255);
        }
          break;
    }
  }

  if(optind < argc) {
    logpath = argv[optind];
  }

/*
  if (command == 'I' || command == 'T'){
    printf("");
    exit(0);
  }
  */

  fp = fopen(logpath, "r");
  
  //Check if file can be opened
  if (fp != NULL ){
     
      unsigned char * hashedToken;
      unsigned char * h_log;
      unsigned char * log;
      unsigned char * enc_log;

      unsigned int logLength = readFILE(fp, &hashedToken, &h_log, &enc_log);
      //printf("%s", log);



      //if token is valid and file has not been tampered with
      int validToken = validate_token(token,hashedToken);
      //token = "secret";

      int validLog = validate_log(token, h_log, enc_log, (logLength-65), &log);
     
      //printf("token: %s,", token);
      //printf("t_token: %s\n", t_token);
      
      //printf("log: %s\n", log);
      //printf("valid token: %d\n", validToken);
      //printf("valid log: %d\n", validLog);
      //printf("log length(log read): %s\n", (int)strlen(log));
      if ( validToken == 0 && validLog == 0)
      {
        //printf("token and log is valid");
        //printf("log:\n%s\n", log);
        char E_G = '0';     
        char * name;
        char A_L = '0';
        char R = '0';
        unsigned int roomId = 0;
        char * pos;
        unsigned char * line = strtok_r(log, "\n", &pos);
        
        //check what command to run
        //if want current state
        if (command == 'S'){
          
          
          person_t * employees = (person_t *)malloc(sizeof(person_t));
          person_t * guests = (person_t *)malloc(sizeof(person_t));
          room_t * structure = (room_t *)malloc(sizeof(room_t));

          employees->next =  NULL;
          employees->name = NULL;
          guests->next =  NULL;
          guests->name = NULL;
          structure->next =  NULL;
          structure->nextPerson = NULL;
          structure->roomId = -1;

          //read file line by line
          while(line != NULL){
            //buf[strlen(buf)-1] = '\0'; //eats the newline
            //printf("%s\n", line);
            extract_str(line, &E_G, &name, &A_L, &R , &roomId);
            //printf("%c %s %c -%c %d\n", E_G, name, A_L, R, roomId);
            //printf("%s\n", name);
             

            //if entering gallery/room
            if (A_L == 'A'){
              
              //if entering gallery
              if (roomId == -1){
                //printf("%c\n", E_G);
                if(E_G == 'E'){
                  add_name(employees, name);
                 // printf("emp: %s\n", name);
                }else{
                  add_name(guests, name);
                  //printf("G: %s\n", name);
                }
              
              }//else if entering room
              else{
                enter_room(structure, name, roomId);
              }  }

            //if leaving gallery/room
            else if(A_L == 'L'){
              
              //if leaving gallery 
              if ( roomId == -1){
                if(E_G == 'E'){
                  remove_name(employees, name);
                }else{
                  remove_name(guests, name);
                }
                
              }//else if leaving room
              else{
                leave_room(structure, name, roomId);
              }  
            }
            //else if -A -R
            //if -L R only
            //if -L only
            R = ' ';
            A_L = ' ';
            E_G = ' ';
            roomId = -1;
            free(name);
            line = strtok_r(NULL, "\n", &pos);
          }
         
          print_state(guests, employees, structure); 
          //printf("name2\n");
          cleanup_rooms(structure);
          cleanup_person_t(employees);
          cleanup_person_t(guests);
        }

        //if want all rooms visited by guest/employee
        else if (command == 'R'){

          visited_t * head = (visited_t *)malloc(sizeof(visited_t) );
          head->next = NULL;
          visited_t * temp = head;
          //read file line by line
          while(line != NULL){
            //buf[strlen(buf)-1] = '\0'; //eats the newline
            //printf("%s\n", buf);
            extract_str(line, &E_G, &name, &A_L, &R , &roomId);

            //if string reach matches type of person(employee/guest)
            if (typePerson == E_G && roomId != -1 && A_L=='A' 
              && strcmp(name, personName) == 0){
                temp->next = (visited_t *)malloc(sizeof(visited_t));
                temp->next->roomId = roomId;
                temp->next->next = NULL;
                temp = temp->next;
            }

            R = ' ';
            A_L = ' '; 
            E_G = ' ';
            roomId = -1;
            line = strtok_r(NULL, "\n", &pos);
            free(name);

          }
         // printf("%s\n", personName);

          print_rooms_visited(head);
          clean_rooms_visited(head);
          
        }
        else{
          printf("invalid");
          exit(255);
        }

        free(hashedToken);
        free(h_log);
        free(enc_log);
        free(log);
      }else{
        printf("integrity violation");
        exit(255);
      }
    fclose(fp);

  }else{
    printf("invalid");
    exit(255);
  }

}


//make sure to free name
void extract_str(char * line, char * E_G,char ** name, char * A_L, char * R, int * roomId){
  
  char * p;
  char * substr = strtok_r(line, " ", &p);
  substr = strtok_r(NULL, " ", &p);
  //printf("%s\n", line);
  int len = 0;
  int count = 0;
  while( substr != NULL){
    switch(count){
    case 0://ignore timestamp
    break;
    case 1: //-E or -G
      *E_G = substr[1]; 
    break;
    case 2: //name
      //name = substr;
      len = strlen(substr);
      void * memory =  malloc(len+1);

      if (memory!= NULL){
        *name = (char *) memory;
        strncpy(*name, substr, len);
        (*name)[len] = '\0';
      }
    break;
    case 3: //-A or -L
      *A_L = substr[1];
    break;
    case 4: 
      *R = substr[1];
    break;
    case 5:
      *roomId = atoi(substr);
    break;
    default:
    break;

   }
   count = count + 1;
  substr = strtok_r(NULL, " ", &p);
  }
}

void add_name(person_t * p, char * name){

  int len = 0;
  person_t * prev = search_for_name(p, name);
  person_t * temp = prev->next;
   
  //create and add new node
  if (!(temp != NULL && strcmp(name, temp->name) == 0)){
    prev->next = (person_t *)malloc(sizeof(person_t));
    len = strlen(name);

    (prev->next)->name =  (char *)malloc(len+1);
    strncpy((prev->next)->name,name,len);
    //printf("%s %d\n",(prev->next)->name, len );
    ((prev->next)->name)[len] = '\0';
    (prev->next)->next = temp;
  }

}

void enter_room(room_t * r, char * name, int roomId){
  
  room_t * prev = search_for_room(r, name, roomId);
  room_t * pt = prev->next;

  if (pt != NULL && pt->roomId == roomId){
    //pt->nextPerson = (person_t *)malloc(sizeof(person_t));
    //(pt->nextPerson)->name;
    //(pt->nextPerson)->next = NULL;
    add_name(pt->nextPerson, name);

  }else{
  prev->next = (room_t *)malloc(sizeof(room_t));
  (prev->next)->roomId = roomId;
  (prev->next)->nextPerson = (person_t *)malloc(sizeof(person_t));
  add_name((prev->next)->nextPerson, name);
  (prev->next)->next = pt;
  }
}

void remove_name(person_t * p, char * name){
  
  person_t * prev = search_for_name(p, name);
  person_t * temp = prev->next;
  //if found name
  if(temp!=NULL && strcmp(name,temp->name) == 0 ){
    prev->next = temp->next;
      
    free(temp->name);
    temp->name = NULL;
    free(temp);
  }
}

void leave_room(room_t * r, char * name, int roomId){
  room_t * prev = search_for_room(r, name, roomId);
  room_t * curr = prev->next;

  //if found
  if (curr != NULL && curr->roomId == roomId ){
    //printf("%s\n", name);
    remove_name(curr->nextPerson, name);
  }

}

person_t * search_for_name(person_t * p, char * name){
  person_t * prev = p;
  person_t * pt = p->next;
  
  //insert name in correct position(list in ascending order)
  while(pt != NULL){
    if (strcmp(pt->name, name) >= 0){
      break;
    }else{
      prev = prev->next;
      pt = prev-> next;
    }
  }
  return prev;
}

room_t * search_for_room(room_t * p, char * name, int roomId){
  room_t * prev = p;
  room_t * pt = p->next;
  
  //insert name in correct position(list in ascending order)
  while(pt != NULL){
    if (pt->roomId >= roomId){
      break;
    }else{
      prev = prev->next;
      pt = prev-> next;
    }
  }
  return prev;
}


void cleanup_rooms(room_t * structure){
  room_t * curr = structure->next;
  room_t * prev = structure;
  room_t * temp;

  //reverse pointers
  while(curr != NULL){
    temp = curr->next;
    curr->next = prev;
    prev = curr;
    curr = temp;
  }

  //free memory

  while( prev != NULL && prev->nextPerson != NULL){
    temp = prev->next;
    //printf("cleanroom: %d\n", prev->roomId);
    cleanup_person_t(prev->nextPerson);

    free(prev);
    prev = temp;

  }

  free(structure);
}
void cleanup_person_t(person_t * head){
  person_t * curr = head->next;
  head->next = NULL;
  person_t * prev = head;
  person_t * temp;

  //reverse pointers
  while(curr != NULL){
    temp = curr->next;
    curr->next = prev;  //reverse
    prev = curr;
    curr = temp;

  }

  //free memory
  while( prev != NULL && prev->next != NULL){
    temp = prev->next;
    //printf("Clean person: %s\n", prev->name);
    //printf("%s\n", prev->name);
    free(prev->name);
    free(prev);
    prev = temp;
  }

  //printf("Clean person head\n");
  free(head);
}

void print_state(person_t * guests, person_t * employees, room_t * structure){
  print_person(employees);
  printf("\n");
  print_person(guests);
  printf("\n");

  //print rooms
  room_t * curr = structure->next;
  while(curr != NULL){
    if (curr->nextPerson != NULL && curr->nextPerson->next != NULL){
      printf("%d: ", curr->roomId);
      print_person(curr->nextPerson);    
    if (curr->next != NULL ){
            printf("\n");
        }
    }
    
    curr = curr -> next;
  }

}


void print_person(person_t * head){
  person_t * curr = head->next;
  while(curr != NULL && curr->name != NULL){
    printf("%s", curr->name);
    curr = curr->next;
    if(curr != NULL && curr->name != NULL){
      printf(",");
    }
  }
  //printf("\n");
}

//prints all the rooms visited by user
void print_rooms_visited(visited_t * head){
  visited_t * temp = head->next;
  while(temp != NULL){
    printf("%d", temp->roomId);
    
    if(temp->next != NULL){
      printf(",");
    }
    temp = temp->next;
  }
  //printf("\n");
}

//releases all memmory held by visited_t and all it's children
void clean_rooms_visited(visited_t * head){

  visited_t * prev = head;
  visited_t * curr = head->next;
  head->next = NULL;
  visited_t * temp;

  //reverse pointers
  while(curr != NULL){
    temp = curr->next;
    curr->next = prev;
    prev = curr;
    curr = temp;
  }

  //release memory
  while(prev != NULL){
    temp = prev->next;
    free(prev);
    prev = temp;
  }
  

}
