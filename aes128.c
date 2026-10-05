#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <strings.h>

#define NR 10

typedef uint8_t byte;

static byte sbox[256];
static byte inv_sbox[256];

byte xtime(byte x){ /*mult by 2*/
    return (byte)((x << 1) ^ ((x >> 7) * 0x1b));
}

byte gmul(byte a, byte b){ /*general gf2^8 multiplication*/
    byte p = 0;
    while (b){
        if (b & 1) p ^= a; 
        a = xtime(a);
        b >>= 1;
    }
    return p;
}

void sbox_gen(){
    for (int i = 0; i<256; i++){
        byte inv = 0;
        if (i != 0){
            for (int j = 1; j < 256; j++){
                if (gmul((byte)i, (byte)j) == 1){ /*finding gf mult inverse*/ 
                 inv = (byte)j; 
                 break; 
                 }
            }
        }
        byte s = inv, x = inv;
        for (int k = 0; k < 4; k++){ /*affine*/
            x = (byte)((x << 1) | (x >> 7));
            s ^= x;
        }
        sbox[i] = s ^ 0x63; /*add aes const*/
    }
}

void inv_sbox_gen(){
	sbox_gen();
	for(int i = 0; i<256; i++){
		inv_sbox[sbox[i]] = i;
	}
}

void key_expansion(const byte key[16], byte rk[16 * (NR + 1)]) {
    byte rcon = 0x01;
    memcpy(rk, key, 16); /*copy key into round keys as first 16 bytes/first 4 words*/
    for (int i = 16; i < 16 * (NR + 1); i += 4) {
        byte temp[4];
        memcpy(temp, rk + i - 4, 4);
        if (i % 16 == 0) {
            /* rotword, subword, then add round const*/
            byte first = temp[0];
            temp[0] = sbox[temp[1]] ^ rcon;
            temp[1] = sbox[temp[2]];
            temp[2] = sbox[temp[3]];
            temp[3] = sbox[first];
            rcon = xtime(rcon);
        }
        for (int j = 0; j < 4; j++)
            rk[i + j] = rk[i - 16 + j] ^ temp[j]; /*previous word xored with word 4 positions back*/
    }
}

void add_round_key(byte state[16], const byte *rk){
	for(int i = 0;i < 16; i++){
		state[i] ^= rk[i]; /*add state and round key*/
	}
}

void sub_bytes(byte state[16]){
	for(int i = 0;i<16;i++){
		state[i] = sbox[state[i]];
	}
}

void inv_sub_bytes(byte state[16]){
	for(int i = 0;i<16;i++){
		state[i] = inv_sbox[state[i]];
	}
}

void shift_rows(byte state[16]){
	byte temp[16];
	for (int c = 0; c < 4; c++)
        for (int r = 0; r < 4; r++)
            temp[r + 4*c] = state[r + 4*((c+r)%4)]; /*rotate rows by their number to the left*/
    memcpy(state, temp, 16);
}

void inv_shift_rows(byte state[16]){
	byte temp[16];
	for (int c = 0; c < 4; c++)
        for (int r = 0; r < 4; r++)
            temp[r + 4*((c+r)%4)] = state[r + 4*c]; /*rotate rows by their number to the right*/
    memcpy(state, temp, 16);
}

void mix_columns(byte state[16]){
	/*matrix multplication with a predefined encryption matrix using gf(2^8) operators*/
	for(int c = 0; c<4; c++){
		byte *col = state + 4*c; /*set location to beginning of current column in state*/
		byte a0 = col[0], a1 = col[1], a2 = col[2], a3 = col[3];
		
		col[0] = xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3; /* xtime multiplies by 2 and xor adds*/
        col[1] = a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3;
        col[2] = a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3);
        col[3] = (xtime(a0) ^ a0) ^ a1 ^ a2 ^ xtime(a3);
	} 
}

void inv_mix_columns(byte state[16]){
	/*matrix multplication with inverse of encryption matrix using gf(2^8) operators*/
	for(int c = 0; c<4; c++){
		byte *col = state + 4*c; /*set location to beginning of current column in state*/
		byte a0 = col[0], a1 = col[1], a2 = col[2], a3 = col[3];
		
		col[0] = gmul(0xe, a0) ^ gmul(0xb, a1) ^ gmul(0xd, a2) ^ gmul(0x9, a3);
        col[1] = gmul(0x9, a0) ^ gmul(0xe, a1) ^ gmul(0xb, a2) ^ gmul(0xd, a3);
        col[2] = gmul(0xd, a0) ^ gmul(0x9, a1) ^ gmul(0xe, a2) ^ gmul(0xb, a3);
        col[3] = gmul(0xb, a0) ^ gmul(0xd, a1) ^ gmul(0x9, a2) ^ gmul(0xe, a3);
	} 
}

void aes128_encrypt(const byte input[16],const byte key[16], byte output[16]){
	byte state[16];
	byte rk[(NR+1)*16];
	
	key_expansion(key,rk);
	memcpy(state,input,16);
	
	add_round_key(state,rk); /*round 0*/
	for(int round = 1; round<NR; round++){ /*rounds 1-9*/
		sub_bytes(state);
		shift_rows(state);
		mix_columns(state);
		add_round_key(state, rk+(16*round));
	}
	/*final round w/o mixcolumns (for symmetry and ease of decryption)*/
	sub_bytes(state);
	shift_rows(state);
	add_round_key(state, rk+(16*NR));
	
	memcpy(output,state,16);
}

void aes128_decrypt(const byte input[16],const byte key[16], byte output[16]){
	byte state[16];
	byte rk[(NR+1)*16];
	
	key_expansion(key,rk);
	memcpy(state,input,16);
	
	add_round_key(state, rk+(16*NR));
	
	for(int round = NR-1; round>0; round--){ /*rounds 9-1*/
		inv_shift_rows(state);
		inv_sub_bytes(state);
		add_round_key(state, rk+(16*round));
		inv_mix_columns(state);
	}
	inv_shift_rows(state);
	inv_sub_bytes(state);
	add_round_key(state, rk); /*undos round 0*/
	
	memcpy(output,state,16);
}

void padding(const char plaint[], byte padded[]){
	int len = strlen(plaint);
	int padding = 16 - (len%16);
	
	memcpy(padded,plaint,len);
	memset(padded+len,(byte)padding,padding);
}

void vig_enc(const char plaint[], const char keyword[], char ct[]){
	int keylen = strlen(plaint);
	char k[keylen+1];
	for(int i = 0; i<keylen; i++){
		k[i] = keyword[i%strlen(keyword)];
	}
	
	for(int i = 0; i<keylen; i++){
		int raw_char = ((plaint[i]-32)+(k[i]-32))%95 + 32;
		ct[i] = raw_char;
	}
	ct[keylen] = '\0';
}

void vig_dec(const char ct[], const char keyword[], char plaint[]){
	int keylen = strlen(ct);
	char k[keylen+1];
	for(int i = 0; i<keylen; i++){
		k[i] = keyword[i%strlen(keyword)];
	}
	
	for(int i = 0; i<keylen; i++){
		int raw_char = ((ct[i]-32)-(k[i]-32) + 95)%95 + 32; /*adding 95 to prevent negative numbers*/
		plaint[i] = raw_char;
	}
	plaint[keylen] = '\0';
}

int file_size;

void block_xor(byte a[16], byte b[16]){
	for(int i = 0; i<16; i++){
		a[i] ^= b[i];
	}
}

byte* read_stdin(){
	int stdin_chunk = 4096; /*read 4KB at a time from stdin*/
	int capacity = stdin_chunk;
	file_size = 0;
	
	byte *buf = malloc(capacity);
	
	while(1){
		int bytes = fread(buf+file_size, 1, stdin_chunk, stdin); 
		file_size += bytes;
		if(bytes < stdin_chunk){
			if(feof(stdin)){
				break;
			} else{perror("Error reading from stdin");}
		}
		capacity += stdin_chunk;
		byte *new = realloc(buf, capacity);
		if(new == NULL){
			perror("Couldn't reallocate ur input buffer");
			free(buf);
			return NULL;
			}
		buf = new;
	}
	return buf;
}

int main(int argc, char *argv[]){
	if (argc < 4){
        fprintf(stderr, "Usage: %s <-e/-d> <vig/aes/aes-cbc> <32-char-hex-key> <plaintext/cipher>\n", argv[0]);
        fprintf(stderr, "Example: %s -e aes 31323334353637383930313233343536 abcdefghijklmnop\n", argv[0]);
        fprintf(stderr, "For aes-cbc: %s -e aes-cbc 31323334353637383930313233343536 abcdefghijklmnop <IV>\n", argv[0]);
        return 1;
    }
    
    if ((strcmp(argv[2], "aes") == 0) && (strlen(argv[3]) != 32)) {
        fprintf(stderr, "Error: Hex key must be exactly 32 characters long.\n");
        return 1;
    }
    
    if ((strcmp(argv[2], "aes-cbc") == 0) && (argc < 5) && (strlen(argv[argc-1]) != 32)) {
        fprintf(stderr, "Error: aes-cbc mode requires a valid IV.\n");
        return 1;
    }
    
    if ((strcmp(argv[2], "aes") != 0) && (strcmp(argv[2], "vig") != 0) && (strcmp(argv[2], "aes-cbc") != 0)) {
        fprintf(stderr, "Error: Enter a valid cipher(aes/vig).\n");
        return 1;
    }
    
    if(strcmp(argv[1], "-e") == 0){
    	if(strcmp(argv[2], "aes") == 0){
    		sbox_gen();
    		byte k[16];
			for(int i = 0; i < 16; i++){
				sscanf(&argv[3][2*i],"%2hhx",k+i); /* %hhx is for the single byte value*/ 
			}
			if(argc == 5){
				int padlen = strlen(argv[4]) + (16-(strlen(argv[4])%16));
				byte padded[padlen];
				padding(argv[4], padded); /*padded plaintext*/
				
				byte cipher[padlen];
				
				for(int i = 0; i < (padlen/16); i++){ /*ECB mode loop*/
					byte c[16];
					aes128_encrypt(padded+(16*i),k,c);
					memcpy(cipher+(16*i),c,16);
				}
				printf("Hex: ");
				for(int i = 0; i<padlen; i++){
				printf("%02X", cipher[i]);
				}} /*text input through argument mode*/
			else{
				byte *file = read_stdin();
				char file_in[file_size];
				memcpy(file_in, file, file_size);
				free(file);
				
				int padlen = file_size + (16-(file_size%16));
				int pad_byte = 16 - (file_size % 16);
				byte padded[padlen];
				memcpy(padded, file_in, file_size); /*custom padding for raw files*/
				memset(padded + file_size, (byte)pad_byte, pad_byte);
				
				byte cipher[padlen];
				
				for(int i = 0; i < (padlen/16); i++){ /*ECB mode loop*/
					byte c[16];
					aes128_encrypt(padded+(16*i),k,c);
					memcpy(cipher+(16*i),c,16);
				}
				for(int i = 0; i<padlen; i++){
					putchar(cipher[i]); /*raw bytes output*/
				}
			} /*file input through redirect/pipe mode*/
	
			return 0;
		} else if(strcmp(argv[2], "vig") == 0){
			int len = strlen(argv[4]); 
			
			char cipher[len+1];
			
			vig_enc(argv[4],argv[3],cipher);
			printf("%s\n", cipher);
			
			return 0;
		} else if(strcmp(argv[2], "aes-cbc") == 0){
			sbox_gen();
    		byte k[16];
    		byte iv[16];
			for(int i = 0; i < 16; i++){
				sscanf(&argv[3][2*i],"%2hhx",k+i); /* %hhx is for the single byte value*/ 
			}
			
			if(argc == 6){
				for(int i = 0; i < 16; i++){
					sscanf(&argv[5][2*i],"%2hhx",iv+i);
				}
				
				int padlen = strlen(argv[4]) + (16-(strlen(argv[4])%16));
				byte padded[padlen];
				padding(argv[4], padded); /*padded plaintext*/
				
				byte cipher[padlen];
				block_xor(padded, iv);
				aes128_encrypt(padded,k,cipher);
				
				for(int i = 1; i < (padlen/16); i++){ /*CBC mode loop*/
					byte c[16];
					block_xor(padded+(16*i),cipher+(16*(i-1)));
					aes128_encrypt(padded+(16*i),k,c);
					memcpy(cipher+(16*i),c,16);
				}
				printf("Hex: ");
				for(int i = 0; i<padlen; i++){
				printf("%02X", cipher[i]);
				}} /*text input through argument mode*/
			else{
				for(int i = 0; i < 16; i++){
					sscanf(&argv[4][2*i],"%2hhx",iv+i); /*reading IV from 4th argument*/
				}
				
				byte *file = read_stdin();
				char file_in[file_size];
				memcpy(file_in, file, file_size);
				free(file);
				
				int padlen = file_size + (16-(file_size%16));
				int pad_byte = 16 - (file_size % 16);
				byte padded[padlen];
				memcpy(padded, file_in, file_size); /*custom padding for raw files*/
				memset(padded + file_size, (byte)pad_byte, pad_byte);
				
				byte cipher[padlen];
				block_xor(padded, iv);
				aes128_encrypt(padded,k,cipher);
				
				for(int i = 1; i < (padlen/16); i++){ /*CBC mode loop*/
					byte c[16];
					block_xor(padded+(16*i),cipher+(16*(i-1)));
					aes128_encrypt(padded+(16*i),k,c);
					memcpy(cipher+(16*i),c,16);
				}
				for(int i = 0; i<padlen; i++){
					putchar(cipher[i]); /*raw bytes output*/
				}
			} /*file input through redirect/pipe mode*/
			return 0;
		}
    } else if(strcmp(argv[1], "-d") == 0){
    	if(strcmp(argv[2], "aes") == 0){
    		inv_sbox_gen();
    		byte k[16];
    		
    		for(int i = 0; i < 16; i++){
				sscanf(&argv[3][2*i],"%2hhx",k+i); /* %hhx is for the single byte value*/ 
			}
    		
    		if(argc == 5){
				int padlen = (strlen(argv[4]))/2;
				byte cipher[padlen];
				
				for(int i = 0; i < padlen; i++){
				sscanf(&argv[4][2*i],"%2hhx",cipher+i); /* scanning ct hex*/ 
				}
		 
				byte plain[padlen];
	
				for(int i = 0; i < (padlen/16); i++){ /*ECB mode loop*/
					byte p[16];
					aes128_decrypt(cipher+(16*i),k,p);
					memcpy(plain+(16*i),p,16);
				}
				int len = padlen - plain[padlen-1];
		
				printf("Decrypted text: ");
				for(int i = 0; i<len; i++){
					printf("%c", plain[i]);
				}} /*text input through argument mode, plaintext out*/
			else{
				byte *file = read_stdin();
				byte file_in[file_size];
				memcpy(file_in, file, file_size);
				free(file);
		 		
		 		
				byte plain[file_size];
	
				for(int i = 0; i < (file_size/16); i++){ /*ECB mode loop*/
					byte p[16];
					aes128_decrypt(file_in+(16*i),k,p);
					memcpy(plain+(16*i),p,16);
				}
				
				int len = (file_size) - plain[(file_size)-1];
		
				for(int i = 0; i<len; i++){
					putchar(plain[i]); /*raw bytes output*/
				}
			}
			
			return 0;
		} else if(strcmp(argv[2], "vig") == 0){
			int len = strlen(argv[4]); 
			
			char plaint[len+1];
			
			vig_dec(argv[4],argv[3],plaint);
			printf("%s\n", plaint);
			
			return 0;
		} else if(strcmp(argv[2], "aes-cbc") == 0){
			inv_sbox_gen();
    		byte k[16];
    		byte iv[16];
			for(int i = 0; i < 16; i++){
				sscanf(&argv[3][2*i],"%2hhx",k+i); /* %hhx is for the single byte value*/ 
			}
			
			if(argc == 6){
				for(int i = 0; i < 16; i++){
					sscanf(&argv[5][2*i],"%2hhx",iv+i);
				}
				
				int padlen = (strlen(argv[4]))/2;
				byte cipher[padlen];
				
				for(int i = 0; i < padlen; i++){
					sscanf(&argv[4][2*i],"%2hhx",cipher+i); /* scanning ct hex*/ 
				}
				
				byte plain[padlen];
				
				for(int i = ((padlen/16) - 1); i > 0; i--){ /*CBC mode loop*/
					aes128_decrypt(cipher+(16*i),k,plain+(16*i));
					block_xor(plain+(16*i),cipher+(16*(i-1)));
				}
				
				aes128_decrypt(cipher,k,plain);
				block_xor(plain,iv); /*xoring iv here returns the first plaintext block*/
				
				int len = padlen - plain[padlen-1];
				
				printf("Decrypted text: ");
				for(int i = 0; i<len; i++){
					printf("%c", plain[i]);
				}} /*text input through argument mode*/
			else{
				for(int i = 0; i < 16; i++){
					sscanf(&argv[4][2*i],"%2hhx",iv+i); /*reading IV from 4th argument*/
				}
			
				byte *file = read_stdin();
				byte file_in[file_size];
				memcpy(file_in, file, file_size);
				free(file);
		 		
		 		
				byte plain[file_size];
	
				for(int i = ((file_size/16) - 1); i > 0; i--){ /*CBC mode loop*/
					aes128_decrypt(file_in+(16*i),k,plain+(16*i));
					block_xor(plain+(16*i),file_in+(16*(i-1)));
				}
				
				aes128_decrypt(file_in,k,plain);
				block_xor(plain,iv); /*xoring iv here returns the first plaintext block*/
				
				int len = (file_size) - plain[(file_size)-1];
		
				for(int i = 0; i<len; i++){
					putchar(plain[i]); /*raw bytes output*/
				}
			}
			return 0;
		}
    } else{
    	fprintf(stderr, "Error: Enter a valid option(-e/-d).\n");
        return 1;
    }
}