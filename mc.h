#include <stdlib.h>
#include <stdio.h> 
#include <string.h>
struct MemoryStruct {
  char *memory;
  size_t size;
};


struct varint {
	int len;
	char *data;
};
typedef struct varint *varint_t;

typedef struct packet { char *data; int len; } *packet_t;
typedef struct string { char *data; int len;  } *string_t;
typedef struct blob { char *data; int len; } blob_t;
int write_str(char *str, int len);
int read_str(char *str, int len);
int write_varint(int value);
int write_byte(int value);
int read_byte();
int flush_write_buf();
int read_varint();
int sendpk(packet_t pk, int sock);
packet_t hspack(varint_t proto, char *addr, unsigned short int port, varint_t next);
int sendvarint(varint_t value, int sock);
varint_t itov(int value);
int vtoi(varint_t value);
int vtoi_raw(char *v);

packet_t handshake_packet(varint_t proto, char *addr, unsigned short int port, varint_t next);
packet_t hspk(varint_t proto, string_t addr, unsigned short int port, varint_t next);
string_t ctos(const char *c);
packet_t wrapck(int id, packet_t pack);
packet_t loginpk(const char *user);
packet_t lipk(const char *user);
int vtois(char *data, char **next);
int handle_er(char *data);
int readpk(packet_t pk);
char *mkauthjson(const char *uname, const char *pword);
static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp);
int authenticate(char *uname, char *pword);
int authenticate2(char *uname, char *pword);
unsigned char *twoscom(unsigned char *num);
unsigned char *btox(unsigned char b, unsigned char *x);
unsigned char *shatohex(unsigned char *num);
#define ENCRYPTION_REQUEST 0x01
#define SET_COMPRESSION 0x03
#define LOGIN_SUCCESS 0x02
#define DISCONNECT_LOGIN 0x00
#define DISCONNECT_PLAY 0x1a
#define TRUE 1
#define FALSE 0
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <unistd.h>
packet_t decpk(packet_t pk, unsigned char *key, EVP_CIPHER_CTX *ctx);
