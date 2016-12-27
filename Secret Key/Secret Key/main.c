//
//  main.c
//  Secret Key
//
//  Purpose: Encrypts/Decrypts character arrays contain 8 characters
//
//  Created by Grace Akpan on 9/8/16.
//  Copyright © 2016 Grace Akpan. All rights reserved.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define SIZE 8
#define COLS 95
#define ROWS 8
#define MAXLENGTH 95
#define ROUNDS 16

// function declarations
void copy_string (char *target, char *source);
void createSubTables(char *str);
void deleteChar(char* a, int i);
int randomNumber (int min, int max);
void generateKey(char *pswd);
char* encryptInput(char *in);
void permutation();
void subTable(int t);
void swap(char *c1, char *c2);
void initTables(char* str);
void concat(char *s1, char *s2);
int getCharIndex(char* tbl, char c);
char getCharacter(char* tbl, int i);
void printTable(char a[] ,int n);
char* encryptAlgo(char* msg);
char* decryptAlgo(char * msg);
char* decryptInput(char * msg);

static char beta[] = " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~";
//static char alpha[] = "abcdef";


char Key[SIZE] = "";
char temp[MAXLENGTH];

// substitution tables
char table0[COLS] = "";
char table1[COLS] = "";
char table2[COLS] = "";
char table3[COLS] = "";
char table4[COLS] = "";
char table5[COLS] = "";
char table6[COLS] = "";
char table7[COLS] = "";


/**
 * Implements the encryption algorithm
 *  1) take the input array and xor it with the key.
 *  2) using xored output, perform a character-by-character substitution
 *     using the different substitution tables.
 *  3) Perform permutation step once after the substitution step
 *       Permutation step: shift the bit pattern by one to the left with
 *       the leftmost bit becoming the rightmost bit.
 *  4) repeat 16 times
 */
char* encryptAlgo(char* msg){
    
    char *res = encryptInput(msg);
    
    for(int i = 0; i < ROUNDS; i++){
  
        res = encryptInput(res);
    }
    return res;
}

/**
 * Implements the decryption algorithm (reverse of the encryption algorithm)
 * 1) permutation step: shift the bit pattern by one to the right with the
 *    rightmost bit becoming the leftmost bit
 * 2) perform character-by-character reverse substitution using the control 
 *    table (beta) with the different substitution tables
 * 3) reverse xor of the in put array and key (Example: let 'a' represent
 *    the input, 'b' represents the key and 'c' the result of xor. To obtain
 *    'a' again: a = c ^ b.
 * 4) repeat 16 times
 */
char* decryptAlgo(char * msg){
    char * res = decryptInput(msg);
    for(int i = 0; i < ROUNDS; i++){
        res = decryptInput(res);
    }
    // removes any trailing character that appear after the max size
    if(strlen(res) > 8)
        deleteChar(res, 8);
    
    return res;
}
/**
 * helper function for decryptAlgo
 */
char* decryptInput(char * msg){
    int t1 = 0;
    char c = ' ';
    char* result = malloc(SIZE);
    
    // perform permutation step (1x)
    char temp = msg[SIZE-1];
    int i = SIZE-1, j = i-1;
    
    while(i >=0 && j >=0){
        msg[i] = msg[j];
        i--;
        j = i-1;
    }
    msg[i] = temp;
    
    for(int i = 0; i < SIZE; i++){
        // perform reverse substitution
        if(i == 0) t1 = getCharIndex(table0, msg[i]);
        else if(i == 1) t1 = getCharIndex(table1, msg[i]);
        else if(i == 2) t1 = getCharIndex(table2, msg[i]);
        else if(i == 3) t1 = getCharIndex(table3, msg[i]);
        else if(i == 4) t1 = getCharIndex(table4, msg[i]);
        else if(i == 5) t1 = getCharIndex(table5, msg[i]);
        else if(i == 6) t1 = getCharIndex(table6, msg[i]);
        else if(i == 7) t1 = getCharIndex(table7, msg[i]);
        
        if(t1 == -1) c = msg[i];
        else c = getCharacter(beta, t1);
        
        result[i] = c;
    }
    
    for(int i = 0; i < SIZE; i++){
        // inverse the xor
        result[i] = result[i] ^ Key[i];
        
    }
    
    return result;
}


/**
 * helper function for encryptAlgo
 */
char* encryptInput(char *input){
    char* result = malloc(SIZE);
    int t1 = 0;
    char c = ' ';
    
    for(int i = 0; i < SIZE; i++){
        // take input array and xor it with the key
        result[i] = input[i]^Key[i];
        //result[i] = input[i];
    }
    
    
        // using the xored output, perform a character by
        // character substitution using the different substitution
        // tables
    for(int i = 0; i < SIZE; i++){
         t1 = getCharIndex(beta, result[i]);
        if(i == 0){
            if(t1 == -1)
                c = result[i];
            else
                c = getCharacter(table0, t1);
        }else if(i == 1){
            if(t1 == -1)
                c = result[i];
            else
                c = getCharacter(table1, t1);
        }else if(i == 2){
            if(t1 == -1)
                c = result[i];
            else
                c = getCharacter(table2, t1);
        }else if(i == 3){
            if(t1 == -1){
                c = result[i];
            }
            else{
                c = getCharacter(table3, t1);
            }
        }else if(i == 4){
            if(t1 == -1)
                c = result[i];
            else{
                c = getCharacter(table4, t1);
            }
        }else if(i == 5){
            if(t1 == -1)
                c = result[i];
            else{
                c = getCharacter(table5, t1);
            }
        }else if(i == 6){
            if(t1 == -1){
                c = result[i];
            }
            else{
                c = getCharacter(table6, t1);
            }
        }else if(i == 7){
            if(t1 == -1){
                c = result[i];
            }
            else{
                c = getCharacter(table7, t1);
            }
        }
        result[i] = c;
    }
    
    // perform permutation step (1x)
    char temp = result[0];
    int i = 0, j = i+1;
    
    while(i < SIZE && j < SIZE){
        result[i] = result[j];
        i++;
        j = i+1;
    }
    result[i] = temp;
    
    
    return result;
}


/**
 * generates an 8 character array based on 
 * the beta character array
 */
void generateKey(char *pswd){
    
    for(int i = 0; i < strlen(pswd); i++){
        int a = 0;
        char c = ' ';
        
        if(i == 0){
            a = getCharIndex(beta, pswd[i]);
            c = getCharacter(table0, a);
            concat(Key, &c);
            
        }else if(i == 1){
            a = getCharIndex(beta, pswd[i]);
            c = getCharacter(table1, a);
            concat(Key, &c);
        }else if(i == 2){
            a = getCharIndex(beta, pswd[i]);
            c = getCharacter(table2, a);
            concat(Key, &c);
            
        }else if (i == 3){
            a = getCharIndex(beta, pswd[i]);
            c = getCharacter(table3, a);
            concat(Key, &c);
            
        }else if (i == 4){
            a = getCharIndex(beta, pswd[i]);
            c = getCharacter(table4, a);
            concat(Key, &c);
            
        }else if (i == 5){
            a = getCharIndex(beta, pswd[i]);
            c = getCharacter(table5, a);
            concat(Key, &c);
            
        }else if (i == 6){
            a = getCharIndex(beta, pswd[i]);
            c = getCharacter(table6, a);
            concat(Key, &c);
            
        }else if (i == 7){
            a = getCharIndex(beta, pswd[i]);
            c = getCharacter(table7, a);
            concat(Key, &c);
            
        }
    }
}

/**
 * generate a random number
 * - includes minimum number but one less the maximum number
 */
int randomNumber (int min, int max){
    int r = max+1;
    // hold the secons on clock
    time_t seconds;
    
    // get value of system clock and place in second value
    time(&seconds);
    
    // convert seconds to a unsigned integer
    srand((unsigned int) seconds);
    
    // get random number
   // r = (int)(rand()%(max-min)+min);
    
    while(r > max){
        r = (int)(rand()%(max-min)+min);
    }
    
    return r;
}

/**
 * Creates 8 substitution tables representing the 
 * max length of character for this application
 */
void initTables(char* str){
    
    
    // initialize tables
    for(int i = 0; i < strlen(str); i++){
        
        // make copy of character array
        copy_string (temp, beta);
        
        if(i == 0){
            subTable(0);
            continue;
        }
        if(i == 1){
            subTable(1);
            continue;
        }
        if(i == 2){
            subTable(2);
            continue;
        }
        if(i == 3){
            subTable(3);
            continue;
        }
        if(i == 4){
            subTable(4);
            continue;
        }
        if(i == 5){
            subTable(5);
            continue;
        }
        if(i == 6){
            subTable(6);
            continue;
        }
        if(i == 7){
            subTable(7);
            continue;
        }
    }
}


/**
 * creates the substitution tables
 */
void subTable(int t){
    int num = 0;
    
    for(int j = 0; j < COLS; j++){
        
        // generate random number
        num = randomNumber(0, (int)strlen(temp));
        
        // select char from copy array
        char c = temp[num];
        
        if(j == 0 && t == 0){
            concat(&table0[j], &c);
        }else if(t == 0){
            concat(&table0[j], &c);
        }else if(j == 0 && t == 1){
            concat(&table1[j], &c);
        }else if(t == 1){
            concat(&table1[j], &c);
        }else if(j == 0 && t == 2){
            concat(&table2[j], &c);
        }else if(t == 2){
            concat(&table2[j], &c);
        }else if(j == 0 && t == 3){
            concat(&table3[j], &c);
        }else if(t == 3){
            concat(&table3[j], &c);
        }else if(j == 0 && t == 4){
            concat(&table4[j], &c);
        }else if(t == 4){
            concat(&table4[j], &c);
        }else if(j == 0 && t == 5){
            concat(&table5[j], &c);
        }else if(t == 5){
            concat(&table5[j], &c);
        }else if(j == 0 && t == 6){
            concat(&table6[j], &c);
        }else if(t == 6){
            concat(&table6[j], &c);
        }else if(j == 0 && t == 7){
            concat(&table7[j], &c);
        }else if(t == 7){
            concat(&table7[j], &c);
        }
        // delete item from temp
        deleteChar(temp, num);
    }
    
}

/**
 * return the index associated witha character
 */
int getCharIndex(char* tbl, char c){
    int r = -1;
    for(int i = 0; i < strlen(tbl); i++){
        if(tbl[i] == c){
            r = i;
            break;
        }
    }
    return r;
}

/**
 * returns a character based on a give index
 */
char getCharacter(char* tbl, int i){
    return tbl[i];
}

/**
 * prints a substitution table
 */
void printTable(char a[] ,int n){
    for(int i=0; i < COLS; i++){
        printf("table%d (%d): %c ",n,i,a[i]);
    }
    printf("\n\n");
}

/**
 * swap pointers in substitution tables
 */
void swap(char *c1, char *c2){
    char *temp = (char*)malloc((strlen(c1) + 1) * sizeof(char));
    strcpy(temp, c1);
    strcpy(c1, c2);
    strcpy(c2, temp);
    free(temp);
}

/**
 * concatenates strings
 */
void concat(char *s1, char *s2){
    int i;
    for(i = 0; s1[i] != '\0'; i++)
        continue;
    s1[i] = *s2;
    i++;
    s1[i+1] = '\0';
}

/**
 * copy one character array to another character array
 */

void copy_string (char *target, char *source){
    while(*source){
        *target = *source;
        source++;
        target++;
    }
    *target = '\0';
}

/**
 * Deletes an item from an array
 */
void deleteChar(char* a, int i){
    char *src;
    for(src = a+i; *src != '\0'; *src = *(src+1), ++src)
        *src = '\0';
}

int main(int argc, const char * argv[]) {
    char msg[] = "booyahhs";
    char pswd[] ="kisthcoo";
    
    // create substitution tables
    initTables(msg);
    
    // key is derived from password
    generateKey(pswd);
    
    printf("Original message: ");
    for(int i = 0; i < sizeof(msg)/sizeof(msg[0]); i++){
        printf("%c ", msg[i]);
    }
    printf("\n");
    
    
    // encrypt message
   char* encrypt =  encryptAlgo(msg);
    
    printf("Encrypted message: ");
    for(int i = 0; i < strlen(encrypt); i++){
        printf("%x ", encrypt[i]);
    }
    printf("\n");
    
    // decrypt message
    char* decrypt = decryptAlgo(encrypt);
    printf("Decrypted message: ");
    for(int i = 0; i < strlen(decrypt); i++){
        printf("%c ", decrypt[i]);
    }
    printf("\n");
    
    // free up memory
    free(encrypt);
    free(decrypt);
    
    return 0;
}
