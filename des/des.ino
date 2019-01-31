/*
 * \Title    DES Data Encryption Standard implementation
 * \based on DES by  Daniel Ottee  email daniel.otte@rub.de 
 * \date     14-02-2012
 */
#include <stdint.h>
#include <string.h>
#include <time.h>

//permutacja poczatkowa des
//dwie pierwsze wartości określaja ilość bajtów wejściowych i ilość bajtów wyjściowych
const uint8_t s_bloki[256]  = {
  /* S-box 1 */
  0xE4, 0xD1, 0x2F, 0xB8, 0x3A, 0x6C, 0x59, 0x07,
  0x0F, 0x74, 0xE2, 0xD1, 0xA6, 0xCB, 0x95, 0x38,
  0x41, 0xE8, 0xD6, 0x2B, 0xFC, 0x97, 0x3A, 0x50,
  0xFC, 0x82, 0x49, 0x17, 0x5B, 0x3E, 0xA0, 0x6D,
  /* S-box 2 */
  0xF1, 0x8E, 0x6B, 0x34, 0x97, 0x2D, 0xC0, 0x5A,
  0x3D, 0x47, 0xF2, 0x8E, 0xC0, 0x1A, 0x69, 0xB5,
  0x0E, 0x7B, 0xA4, 0xD1, 0x58, 0xC6, 0x93, 0x2F,
  0xD8, 0xA1, 0x3F, 0x42, 0xB6, 0x7C, 0x05, 0xE9,
  /* S-box 3 */
  0xA0, 0x9E, 0x63, 0xF5, 0x1D, 0xC7, 0xB4, 0x28,
  0xD7, 0x09, 0x34, 0x6A, 0x28, 0x5E, 0xCB, 0xF1,
  0xD6, 0x49, 0x8F, 0x30, 0xB1, 0x2C, 0x5A, 0xE7,
  0x1A, 0xD0, 0x69, 0x87, 0x4F, 0xE3, 0xB5, 0x2C,
  /* S-box 4 */
  0x7D, 0xE3, 0x06, 0x9A, 0x12, 0x85, 0xBC, 0x4F,
  0xD8, 0xB5, 0x6F, 0x03, 0x47, 0x2C, 0x1A, 0xE9,
  0xA6, 0x90, 0xCB, 0x7D, 0xF1, 0x3E, 0x52, 0x84,
  0x3F, 0x06, 0xA1, 0xD8, 0x94, 0x5B, 0xC7, 0x2E,
  /* S-box 5 */
  0x2C, 0x41, 0x7A, 0xB6, 0x85, 0x3F, 0xD0, 0xE9,
  0xEB, 0x2C, 0x47, 0xD1, 0x50, 0xFA, 0x39, 0x86,
  0x42, 0x1B, 0xAD, 0x78, 0xF9, 0xC5, 0x63, 0x0E,
  0xB8, 0xC7, 0x1E, 0x2D, 0x6F, 0x09, 0xA4, 0x53,
  /* S-box 6 */
  0xC1, 0xAF, 0x92, 0x68, 0x0D, 0x34, 0xE7, 0x5B,
  0xAF, 0x42, 0x7C, 0x95, 0x61, 0xDE, 0x0B, 0x38,
  0x9E, 0xF5, 0x28, 0xC3, 0x70, 0x4A, 0x1D, 0xB6,
  0x43, 0x2C, 0x95, 0xFA, 0xBE, 0x17, 0x60, 0x8D,
  /* S-box 7 */
  0x4B, 0x2E, 0xF0, 0x8D, 0x3C, 0x97, 0x5A, 0x61,
  0xD0, 0xB7, 0x49, 0x1A, 0xE3, 0x5C, 0x2F, 0x86,
  0x14, 0xBD, 0xC3, 0x7E, 0xAF, 0x68, 0x05, 0x92,
  0x6B, 0xD8, 0x14, 0xA7, 0x95, 0x0F, 0xE2, 0x3C,
  /* S-box 8 */
  0xD2, 0x84, 0x6F, 0xB1, 0xA9, 0x3E, 0x50, 0xC7,
  0x1F, 0xD8, 0xA3, 0x74, 0xC5, 0x6B, 0x0E, 0x92,
  0x7B, 0x41, 0x9C, 0xE2, 0x06, 0xAD, 0xF3, 0x58,
  0x21, 0xE7, 0x4A, 0x8D, 0xFC, 0x90, 0x35, 0x6B
};

//permutacja rozszerzenia wiadomości
const uint8_t permutacja_rozszerzenia[] ={
   4,  6,           /* 4 bytes in 6 bytes out*/
  32,  1,  2,  3,  4,  5,
   4,  5,  6,  7,  8,  9,
   8,  9, 10, 11, 12, 13,
  12, 13, 14, 15, 16, 17,
  16, 17, 18, 19, 20, 21,
  20, 21, 22, 23, 24, 25,
  24, 25, 26, 27, 28, 29,
  28, 29, 30, 31, 32,  1
};

//permutacja bloku P
const uint8_t permutacja_bloku_P[] ={
   4,  4,           /* 32 bit -> 32 bit */
  16,  7, 20, 21,
  29, 12, 28, 17,
   1, 15, 23, 26,
   5, 18, 31, 10,
   2,  8, 24, 14,
  32, 27,  3,  9,
  19, 13, 30,  6,
  22, 11,  4, 25
};

//permutacja poczatkowa des
const uint8_t permutacja_poczatkowa[] ={
   8,  8,           /* 64 bit -> 64 bit */
  58, 50, 42, 34, 26, 18, 10, 2,
  60, 52, 44, 36, 28, 20, 12, 4,
  62, 54, 46, 38, 30, 22, 14, 6,
  64, 56, 48, 40, 32, 24, 16, 8,
  57, 49, 41, 33, 25, 17,  9, 1,
  59, 51, 43, 35, 27, 19, 11, 3,
  61, 53, 45, 37, 29, 21, 13, 5,
  63, 55, 47, 39, 31, 23, 15, 7
};

const uint8_t inv_ip_permtab[] ={
   8, 8,            /* 64 bit -> 64 bit */
  40, 8, 48, 16, 56, 24, 64, 32,
  39, 7, 47, 15, 55, 23, 63, 31,
  38, 6, 46, 14, 54, 22, 62, 30,
  37, 5, 45, 13, 53, 21, 61, 29,
  36, 4, 44, 12, 52, 20, 60, 28,
  35, 3, 43, 11, 51, 19, 59, 27,
  34, 2, 42, 10, 50, 18, 58, 26,
  33, 1, 41,  9, 49, 17, 57, 25
};

//permutacja klucza DES
const uint8_t permutacja_klucza[] ={
   8,  7,           /* 64 bit -> 56 bit*/
  57, 49, 41, 33, 25, 17,  9,
   1, 58, 50, 42, 34, 26, 18,
  10,  2, 59, 51, 43, 35, 27,
  19, 11,  3, 60, 52, 44, 36,
  63, 55, 47, 39, 31, 23, 15,
   7, 62, 54, 46, 38, 30, 22,
  14,  6, 61, 53, 45, 37, 29,
  21, 13,  5, 28, 20, 12,  4
};

//permutacja kompresji DES
const uint8_t permutacja_kompresji[] ={
   7,  6,           /* 56 bit -> 48 bit */
  14, 17, 11, 24,  1,  5,
   3, 28, 15,  6, 21, 10,
  23, 19, 12,  4, 26,  8,
  16,  7, 27, 20, 13,  2,
  41, 52, 31, 37, 47, 55,
  30, 40, 51, 45, 33, 48,
  44, 49, 39, 56, 34, 53,
  46, 42, 50, 36, 29, 32
};

//permutacja rozszerzenia
const uint8_t splitin6bitword_permtab[] = {
   8,  8,           /* 64 bit -> 64 bit */
  64, 64,  1,  6,  2,  3,  4,  5, 
  64, 64,  7, 12,  8,  9, 10, 11, 
  64, 64, 13, 18, 14, 15, 16, 17, 
  64, 64, 19, 24, 20, 21, 22, 23, 
  64, 64, 25, 30, 26, 27, 28, 29, 
  64, 64, 31, 36, 32, 33, 34, 35, 
  64, 64, 37, 42, 38, 39, 40, 41, 
  64, 64, 43, 48, 44, 45, 46, 47 
};

const uint8_t tabela_przesuniecia_bitowego_klucza_permtab[] = {
   7,  7,           /* 56 bit -> 56 bit */
   2,  3,  4,  5,  6,  7,  8,  9,
  10, 11, 12, 13, 14, 15, 16, 17,
  18, 19, 20, 21, 22, 23, 24, 25, 
  26, 27, 28,  1, 
  30, 31, 32, 33, 34, 35, 36, 37, 
  38, 39, 40, 41, 42, 43, 44, 45, 
  46, 47, 48, 49, 50, 51, 52, 53, 
  54, 55, 56, 29
};

/*
1 2 2 2   2 2 2 1   2 2 2 2   2 2 1 1
0 1 1 1   1 1 1 0   1 1 1 1   1 1 0 0
      7         E         F         C    Standard DES
2 1 1 1   1 1 1 1   2 2 1 1   1 2 1 1
1 0 0 0   0 0 0 0   1 1 0 0   0 1 0 0
      8         0         C         4    Meteotime DES
*/
#define ROTTABLE      0x7EFC 
byte crypt [8];
byte tekst_jawny [] = { 0x77,0x69,0x74,0x61,0x6A,0x20,0x3A,0x29};
byte klucz [] = { 0x43,0x23,0x66,0xA3,0x6B,0xBB,0x53,0xC1};
byte test[8];
boolean DEBUG = true;
int i,m;
int Dx =0;
uint32_t box=0,t;
String showprint = "";
uint8_t data[8];
/******************************************************************************/
void setup(){

Serial.begin(9600);
Serial.println("");
Serial.println("Start");
Serial.println("Tekst jawny = 77 69 74 61 6A 20 3A 29");
Serial.println("Klucz = 43 23 66 A3 6B BB 53 C1 ");

//for (int j=0;j<8;j++){
//if (klucz[j]<0x10) Serial.print("0"); 
//Serial.print(klucz[j],HEX);Serial.print(" ");
//}
//Serial.println();
//Serial.print("Tekst jawny = ");
//for (int j=0;j<8;j++){
//if (tekst_jawny[j]<0x10) Serial.print("0"); 
//Serial.print(tekst_jawny[j],HEX);Serial.print(" ");
//}
Serial.println();
Serial.println("");
Serial.println("Rozpoczęcie procesu szyfrowania");
Serial.println("");
Serial.println("Tekst jawny = 77 69 74 61 6A 20 3A 29");
Serial.println("Klucz = 43 23 66 A3 6B BB 53 C1 ");
//Serial.println("");

unsigned long start = micros();
void szyfrowanie(void* out, const void* in, const void* key);
//szyfrowanie(crypt, tekst_jawny, klucz);
unsigned long end = micros();
unsigned long delta = end - start;
//Serial.println("");
//Serial.print("Czas szyfrowania[milisekundy]:");Serial.println(delta);

//Serial.println("Encrypted key  = ");
//for (int j=0;j<8;j++){
//if (crypt[j]<0x10) Serial.print("0"); 
//Serial.print(crypt[j],HEX);Serial.print(" ");
//}

//Serial.println();
Serial.println("");
Serial.println("Rozpoczęcie procesu deszyfrowania");
//Serial.println("");
unsigned long start1 = micros();
void des_dec(void* out, const void* in, const void* key);
//des_dec( tekst_jawny, crypt, klucz);
//Serial.println("");
//Serial.println("");
//Serial.println("");
//Serial.println("");
//Serial.println("");
//Serial.println("");
//Serial.println("");
Serial.println("");
Serial.print("Odszyfrowana wiadomość  = ");
for (int j=0;j<8;j++){
if (tekst_jawny[j]<0x10) Serial.print("0"); 
Serial.print(tekst_jawny[j],HEX);Serial.print(" ");
}
unsigned long end1 = micros();
unsigned long delta1 = end1 - start1;
Serial.println("");
Serial.println("");
Serial.print("Czas szyfrowania[milisekundy]:");Serial.println(delta);
Serial.println("");
Serial.print("Czas deszyfrowania[milisekundy]:");Serial.println(delta1);
Serial.println();
Serial.println("Koniec");
}

void loop(){
}

void permutacja(const uint8_t *ptable, const uint8_t *in, uint8_t *out){
  uint8_t ob; /* in-bytes and out-bytes */
  uint8_t byte, bit; /* counter for bit and byte */
  ob = ptable[1];
  ptable = &(ptable[2]);
  for(byte=0; byte<ob; ++byte){
    uint8_t x,t=0;
    for(bit=0; bit<8; ++bit){
      x=*ptable++ -1 ;
        t<<=1;
      if((in[x/8]) & (0x80>>(x%8)) ){
        t|=0x01;
      }
    }
    out[byte]=t;test[byte]=t;
  }
}

/******************************************************************************/

void changeendian32(uint32_t * a){
  *a = (*a & 0x000000FF) << 24 |
     (*a & 0x0000FF00) <<  8 |
     (*a & 0x00FF0000) >>  8 |
     (*a & 0xFF000000) >> 24;
box=((*a & 0x000000FF) << 24)|
     (*a & 0x0000FF00) <<  8 |
     (*a & 0x00FF0000) >>  8 |
     (*a & 0xFF000000) >> 24;
}

/******************************************************************************/
extern inline
void przesuniecie_bitowe_klucza(uint8_t *key){
  uint8_t k[7];
  memcpy(k, key, 7);
  permutacja((uint8_t*)tabela_przesuniecia_bitowego_klucza_permtab, k, key);
        if (DEBUG == true) {
         //Krok 4: Przesunięcie bitowe klucza[");Serial.print(m);Serial.print ("]  56 xits = 
        Serial.print ("Krok 4: ");
        yield();
        for (int j=0;j<7;j++){
        if (test[j]<0x10) Serial.print("0"); 
        Serial.print(test[j],HEX);Serial.print(" ");
        print_binary(test[j],8);Serial.print(" ");
        }
        Serial.println();
        } 
}

/******************************************************************************/

/******************************************************************************/
extern inline
uint64_t splitin6bitwords(uint64_t a){
  uint64_t ret=0;
  a &= 0x0000ffffffffffffLL;
  permutacja((uint8_t*)splitin6bitword_permtab, (uint8_t*)&a, (uint8_t*)&ret); 
  return ret;
}

/******************************************************************************/

extern inline
uint8_t substitute(uint8_t a, uint8_t * sbp){
  uint8_t x;  
  x = sbp[a>>1];
  x = (a&1)?x&0x0F:x>>4;
  return x;
  
}

/******************************************************************************/

uint32_t des_f(uint32_t r, uint8_t* kr){
  uint8_t i;
  uint32_t ret;
  uint64_t data;
  uint8_t *sbp; /* s_blokipointer */ 
  permutacja((uint8_t*)permutacja_rozszerzenia, (uint8_t*)&r, (uint8_t*)&data);
        //Krok 6: Permutacja rozszerzenia prawej części wiadomości      48 bits = 
        showprint ="Krok 6: ";printout1(0,6);
  for(i=0; i<7; ++i) {((uint8_t*)&data)[i] ^= kr[i];}
        if (DEBUG == true) {
          //Krok7 : XOR klucza i prawej części wiadomości 48 bits = 
        Serial.print ("Krok 7: ");
        for (int j=0;j<6;j++){
        if (((uint8_t*)&data)[j]<0x10) Serial.print("0"); 
        Serial.print(((uint8_t*)&data)[j],HEX);Serial.print(" ");
        print_binary(((uint8_t*)&data)[j],8);Serial.print(" ");
        }
        Serial.println();
        } 

  /* s_bloki substitution */
  data = splitin6bitwords(data);
  sbp=(uint8_t*)s_bloki;
  for(i=0; i<8; ++i){
    uint8_t x;
    x = substitute(((uint8_t*)&data)[i], sbp);
    t<<=4;
    t |= x;
    sbp += 32;
  }
  changeendian32(&t);
        if (DEBUG == true) { 
          //Krok 8: Operacja na s blokach   32 bits = 
        Serial.print ("Krok 8: ");

        if (box/0x1000000<0x10) Serial.print("0"); 
        Serial.print(box/0x1000000,HEX);Serial.print(" ");
        print_binary(box/0x1000000,8);Serial.print(" ");

        if (box/0x10000&0xFF<0x10) Serial.print("0"); 
        Serial.print(box/0x10000&0xFF,HEX);Serial.print(" ");
        print_binary(box/0x10000&0xFF,8);Serial.print(" "); 

        if (((box/0x100)&0xFF)<0x10) Serial.print("0"); 
        Serial.print(box/0x100&0xFF,HEX);Serial.print(" ");        
        print_binary(box/0x100,8);Serial.print(" ");

        if (box&0xFF<0x10) Serial.print("0"); 
        Serial.print(box&0xFF,HEX);Serial.print(" ");        
        print_binary(box&0xFF,8);        
        Serial.println();
        }
  permutacja((uint8_t*)permutacja_bloku_P,(uint8_t*)&t, (uint8_t*)&ret);
        // krok 9 : Operacja na P bloku      32 bits = 
        showprint = "Krok 9: "; printout1(0,4); 
  return ret;
}

/******************************************************************************/

void szyfrowanie(void* out, const void* in, const void* key){
#define R *((uint32_t*)&(data[4]))
#define L *((uint32_t*)&(data[0]))
  uint8_t kr[6],k[7];
  permutacja((uint8_t*)permutacja_poczatkowa, (uint8_t*)in, data); 
        //L
        //Krok 1: Permutacja początkowa prawej części wiadomości[0]   32 bits =
        showprint = "Krok 1: "; printout1(0,4);
        //Krok 2: Permutacja początkowa lewej części wiadomości[0]    32 bits = 
        showprint = "Krok 2: "; printout1(4,8);
  permutacja((uint8_t*)permutacja_klucza, (const uint8_t*)key, k);
        //Krok 3: Klucz po permutacji[0]  56 bits = 
        showprint = "Krok 3: "; printout1(0,7);
        yield();
  for(i=0; i<8; i++){
                
                Dx=i*2+1;
                if (DEBUG == true) { Serial.print("Runda ");Serial.println(Dx); }
    przesuniecie_bitowe_klucza(k);
    if(ROTTABLE&((1<<((i<<1)+0))) ) przesuniecie_bitowe_klucza(k);
    permutacja((uint8_t*)permutacja_kompresji, k, kr); 
                //Krok 5: Permutacja kompresji klucza per_klucza_kompresji 1  48 bits =    
                showprint = "Krok 5: "; printout1(0,6);
    L ^= des_f(R, kr);
              // krok 10: Permutacja początkowa prawej części wiadomości   32 bits = 
                showprint = "Krok 10: "; printout2(0,4);
                //krok 11: Permutacja początkowa lewej części wiadomości   32 bits = 
                showprint = "Krok 11: "; printout2(4,8);
                yield();
                Dx=i*2+2;
                if (DEBUG == true) { Serial.print("Runda ");Serial.println(Dx); }              
    przesuniecie_bitowe_klucza(k);
    if(ROTTABLE&((1<<((i<<1)+1))) ) przesuniecie_bitowe_klucza(k);
    permutacja((uint8_t*)permutacja_kompresji, k, kr);
                //Krok 5: Permutacja kompresji klucza     48 bits = 
                showprint = "Krok 5: "; printout1(0,6);
    R ^= des_f(L, kr);
                // krok 10: L[i]   32 bits = 
                showprint = "Krok 10: "; printout2(0,4);
                //Krok 11: R[i]   32 bits = 
                showprint = "Krok 11: "; printout2(4,8);
                yield();
  }
  /* L <-> R*/
  R ^= L;
  L ^= R;
  R ^= L;
        showprint = "LR[16] 64 bits = "; printout2(0,8);
  permutacja((uint8_t*)inv_ip_permtab, data, (uint8_t*)out);
        showprint = "Crypt  64 bits = "; printout1(0,8);
}

/******************************************************************************/

void des_dec(void* out, const void* in, const uint8_t* key){
#define R *((uint32_t*)&(data[4]))
#define L *((uint32_t*)&(data[0]))
  uint8_t kr[6],k[7];
        Serial.print("crypt  64 bits = ");
        for (int j=0;j<8;j++){
        if (crypt[j]<0x10) Serial.print("0"); 
        Serial.print(crypt[j],HEX);Serial.print(" ");
        print_binary(crypt[j],8);Serial.print(" ");
        }
        Serial.println();
        Serial.print("key    64 bits = ");
        for (int j=0;j<8;j++){
        if (key[j]<0x10) Serial.print("0"); 
        Serial.print(key[j],HEX);Serial.print(" ");
        print_binary(key[j],8);Serial.print(" ");
        }
        Serial.println();        
  permutacja((uint8_t*)permutacja_poczatkowa, (uint8_t*)in, data);
        showprint = "L[0]   32 bits = "; printout1(0,4);
        showprint = "R[0]   32 bits = "; printout1(4,8);
  permutacja((uint8_t*)permutacja_klucza, (const uint8_t*)key, k);
        showprint = "CD[0]  56 bits = "; printout1(0,7);
        yield();
  for(i=7; i>=0; i--){
  
                Dx=i*2+2;
                if (DEBUG == true) { Serial.print("Runda ");Serial.println(Dx); }
                permutacja((uint8_t*)permutacja_klucza, (const uint8_t*)key, k);
                for (m=1;m<Dx+1;m++){ 
                przesuniecie_bitowe_klucza(k);
                yield();
                if(ROTTABLE&(1<<(m-1))) przesuniecie_bitowe_klucza(k);
                }              
    permutacja((uint8_t*)permutacja_kompresji, k, kr);
                showprint = "KS     48 bits = "; printout1(0,6);
    L ^= des_f(R, kr);
                showprint = "L[i]   32 bits = "; printout2(0,4);
                showprint = "R[i]   32 bits = "; printout2(4,8);
                yield();
                Dx=i*2+1;
                if (DEBUG == true) { Serial.print("Runda ");Serial.println(Dx); } 
                permutacja((uint8_t*)permutacja_klucza, (const uint8_t*)key, k);
                for (m=1;m<Dx+1;m++){  
    przesuniecie_bitowe_klucza(k);
                if(ROTTABLE&(1<<(m-1))) przesuniecie_bitowe_klucza(k); 
                }              
    permutacja((uint8_t*)permutacja_kompresji, k, kr);
                showprint = "KS     48 bits = "; printout1(0,6);
    R ^= des_f(L, kr);
                showprint = "L[i]   32 bits = "; printout2(0,4);
                showprint = "R[i]   32 bits = "; printout2(4,8);
                yield();
  }
  /* L <-> R*/
  R ^= L;
  L ^= R;
  R ^= L;
        showprint = "LR[16] 64 bits = "; printout2(0,8);
  permutacja((uint8_t*)inv_ip_permtab, data, (uint8_t*)out);
        showprint = "Plain  64 bits = "; printout1(0,8);
}
void print_binary(uint64_t v, int num_places)
{
    uint64_t mask=0, n;
    for (n=1; n<=num_places; n++)
    {
        mask = (mask << 1) | 0x00000001;
    }
    v = v & mask;  // truncate v to specified number of places
    while(num_places)
    {
        if (v & (0x00000001 << num_places-1))
        {
             Serial.print("1");
        }
        else
        {
             Serial.print("0");
        }
        --num_places;
        if(((num_places%8) == 0) && (num_places != 0))
        {
            Serial.print(" ");
        }

    }
}
void printout1(int min,int max) {
        if (DEBUG == true) {
        Serial.print (showprint);
        for (int j=min;j<max;j++){
        if (test[j]<0x10) Serial.print("0");
        Serial.print(test[j],HEX);Serial.print(" ");
        print_binary(test[j],8);Serial.print(" ");
        }
        Serial.println();
        }
}
void printout2(int min,int max) {
        if (DEBUG == true) {
        Serial.print (showprint);
        for (int j=min;j<max;j++){
        if (data[j]<0x10) Serial.print("0");
        Serial.print(data[j],HEX);Serial.print(" ");
        print_binary(data[j],8);Serial.print(" ");
        }
        Serial.println();
        }
}
