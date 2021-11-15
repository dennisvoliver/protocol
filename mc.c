#include "mc.h"
#include <strings.h>
#include <errno.h>
#include <string.h>
//#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/types.h>
#include <stdio.h>
#include <sys/socket.h>
#include <uuid/uuid.h>
#include <curl/curl.h>
/*
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
*/
#include "cJSON/cJSON.h"

#define MAX_BYTES 500
#define MAX_PACKET_BYTES 2097151
#define PORT 25565
#define PLAYER_INFO 0x36
#define KEEP_ALIVE 0x1f
#define JOIN_GAME 0x24
#define PARTICLE 0x22
#define BOSS_BAR 0x0c
#define PLUGIN_MESSAGE 0x17
#define DECLARE_RECIPES 0x5a
#define TAGS 0x5b
#define ENTITY_STATUS 0x1a
char read_buf[MAX_BYTES];
char write_buf[MAX_BYTES];
int read_max;
int write_max;
int read_index;
int write_index;
int sockfd;
int encryption_enabled;
int compression_enabled;
int compression_threshold;

char *stoc(string_t s);
unsigned char *shared_secret;
unsigned char *server_hash;
unsigned char *player_uuid; /* without dashes */
unsigned char *player_name; 
unsigned char *access_token;
unsigned char *server_pubkey;
long server_pubkey_len;
unsigned char *mksrvhash(unsigned char *srvid, int n, unsigned char *sharedsec, int m, unsigned char *srvpubkey, int l);
int parseauth(unsigned char *payload);
CURLcode mojang_response;
long http_code;
unsigned char *encrypt(unsigned  char *msg, long len, unsigned const char *pubkey, long n);
char *readba(char *from, char **to, int *len);
const char *hosttoip(const char *host);
packet_t erespk(unsigned char *ess, int sslen, unsigned char *evtoken,  int vtlen);
//packet_t decpk(packet_t pk, unsigned char *key, EVP_CIPHER_CTX *ctx);
EVP_CIPHER_CTX *enc_ctx;
EVP_CIPHER_CTX *dec_ctx;
int print_response;
int handle_disconnect_login(char *data);
int handle_set_compression(char *data);
int server_state;
int handle_keep_alive(char *data);
packet_t encpk(packet_t pk, EVP_CIPHER_CTX *ctx);
int handle_keep_alive(char *data);
int vtoisk(char *data, char **next, int *k);
int chopk(char *s, int n);
char *readtcpk(int fd, int *n);
int vtoik(char *data, int *k);
int initbuf(void);
int filbuf(void);
packet_t getpk();
typedef  struct pkbuf_s {
	char buf[MAX_PACKET_BYTES + 1];
	char *start;
	int avail;
} *pkbuf_t;

pkbuf_t packets_buffer;

packet_t fetchpk();

int main(int argc, char **argv)
{
	if (initbuf() < 0) {
		fprintf(stderr, "main: failed to initialize packets buffer\n");
		return -1;
	}
	print_response = FALSE;	
	dec_ctx = EVP_CIPHER_CTX_new();
	enc_ctx = EVP_CIPHER_CTX_new();
	encryption_enabled = FALSE;
	compression_enabled = FALSE;
	compression_threshold = 0;
	server_state = STATE_HANDSHAKE;
	//authenticate2("ctholdaway@gmail.com", "Corman999");
	//authenticate2("jj4u@live.be", "Jelte123");
	authenticate2("broskkii88@icloud.com", "Jakers01!");
	int read_max = 0;
	int write_max = 0;
	int read_index = 0;
	int write_index = 0;
	if (argc != 2) {
		fprintf(stderr, "arg ip address\n");
		return -1;
	}
	struct sockaddr_in servaddr;
	if( (sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 1) {
		fprintf(stderr, "socket() error\n");
		return -1;
	}
	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(PORT);
	const char *ip = hosttoip(argv[1]);
	if (ip == NULL) {
		fprintf(stderr, "hosttoip failed\n");
		return -1;
	}
	if (inet_pton(AF_INET, ip, &servaddr.sin_addr) <= 0) {
		fprintf(stderr, "inet_pton error\n");
		return -1;
	}
	if (connect(sockfd, (struct sockaddr *) &servaddr, sizeof(servaddr)) < 0) {
		fprintf(stderr, "%s", strerror(errno));
		fprintf(stderr, "connect error\n");
		return -1;
	}

	int sentpk;
	packet_t pkpk = hspk(itov(754), ctos(argv[1]), 25565, itov(2));
	sentpk = sendpk(pkpk, sockfd);
	server_state = STATE_LOGIN;
	sleep(1);
	sendpk(lipk(player_name), sockfd);
	fprintf(stderr, "player name: %s\n", player_name);
	char buf[MAX_PACKET_BYTES];
	int rn = 0;
	packet_t pk;  
	char *s;
	//while ((pk=getpk()) != NULL){
	while (1){
		//if ((rn=read(sockfd,buf,MAX_PACKET_BYTES)) > 0) {
		//if ((pk=getpk()) != NULL) {
		if ((pk=fetchpk()) != NULL) {
			/*
			pk = (packet_t)malloc(sizeof(struct packet));
			pk->data = (char *)malloc(rn);
			pk->len = rn;
			//strncpy(pk->data, buf, pk->len);
			for (int i = 0; i < pk->len; i++) {
				(pk->data)[i] = buf[i];
			}
			if (print_response) {
				fprintf(stderr, "writing response packet\n");
				write(1, buf, rn);
			}
			if (readpk(pk) != 0)
				return -1;
			*/
			//fprintf(stderr, "received packet from server, size = %d\n", rn);
			if (readpk(pk) != 0)
				return -1;
		//	free(pk);
			//free(s);
		} else
			return -1;
	}
	return 0;
}
packet_t fetchpk()
{
	int rn;
	char buf[MAX_PACKET_BYTES + 1];
	if ((rn=read(sockfd,buf,MAX_PACKET_BYTES)) <= 0) { 
		fprintf(stderr, "fetchpk: read failed\n");
		return NULL;
	}

	//fprintf(stderr, "received packets from server, size = %d\n", rn);
	packet_t pk = (packet_t)malloc(sizeof(struct packet));
	pk->data = (char *)malloc(rn);
	pk->len = rn;
	memcpy(pk->data, buf, pk->len);
	packet_t tmpk = pk;
	if (encryption_enabled) {
		//fprintf(stderr, "reading encrypted packet\n");
		if ((pk = decpk(pk, shared_secret, dec_ctx)) == NULL) {
			fprintf(stderr, "failed to decrypt packet\n");
			return NULL;
		}
		free(tmpk);
	}
	//fprintf(stderr, "received packet from server, size = %d\n", rn);
	return pk;

}

	/*
packet_t getpk()
{
	static char buf[MAX_PACKET_BYTES + 1];
	static char *start = buf;
	static char *end = start; 
	static int avail = end - start;
	int read = 0;
	if (avail == 0) {
		if ((read=read(sockfd,buf,MAX_PACKET_BYTES)) <= 0) {
			fprintf(stderr, "getpk error: failed to read from sockfd = %d\n", sockfd);
			return NULL;
		}
		end = start + read;
	}
	int k = 0;
	int pklen = vtoik(start, &k);
	packet_t ret = (packet_t)malloc(sizeof(struct packet));
	ret->len = pklen + k;
	ret->data = (char *)malloc(ret->len);
	int len = ret->len;
	char *data = ret->data;
	while (len > avail) {
		memcpy(data, start, avail);
		len -= avail;
		data += avail;
		if ((avail=read(sockfd,buf,MAX_PACKET_BYTES)) <= 0) {
			fprintf(stderr, "getpk error: failed to read from sockfd, read = %d\n", avail);
			return NULL;
		}
		start = buf;
	}
	memcpy(data, start, len);
	start += len;
	avail -= len;
	return ret;


}
*/


int filbuf(void)
{
	pkbuf_t buf = packets_buffer;
	if ((buf->avail=read(sockfd,buf->buf, MAX_PACKET_BYTES)) <= 0) {
		fprintf(stderr, "filbuf: socket read failed\n");
		return 0;

	}
	packet_t tmpk, pk;
	if (encryption_enabled) {
		tmpk = pk = (packet_t)malloc(sizeof(struct packet));	
		pk->data = buf->buf;
		pk->len = buf->avail;
		//fprintf(stderr, "reading encrypted packet\n");
		if ((pk = decpk(pk, shared_secret, dec_ctx)) == NULL) {
			fprintf(stderr, "failed to decrypt packet\n");
			return -1;
		}
		memcpy(buf->buf, pk->data, pk->len);
		free(tmpk);
		free(pk);
	}
	buf->start = buf->buf;
	return buf->avail;
}

int initbuf(void)
{
	packets_buffer = (pkbuf_t)malloc(sizeof(struct pkbuf_s));
	pkbuf_t buf = packets_buffer;
	if (buf == NULL) {
		fprintf(stderr, "initbuf: error, malloc failed\n");
		return -1;
	}
	buf->start = buf->buf;
	buf->avail = 0;
	return 0;
}

packet_t getpk(void)
{
	pkbuf_t buf = packets_buffer;
	if (buf->avail == 0) {
		if (filbuf() <= 0) 
			return NULL;

	}
	//fprintf(stderr, "getpk called, avail = %d\n", buf->avail);
	int k = 0;
	int pklen = vtoik(buf->start, &k);
	fprintf(stderr, "getpk called: pklen = %d, k = %d, avail = %d\n", pklen, k, buf->avail);
	if (pklen < 1) {
		fprintf(stderr, "packet length < 1, pklen = %d", pklen);
		//write(1, buf->start, buf->avail);
		return NULL;
	}
	packet_t ret = (packet_t)malloc(sizeof(struct packet));
	ret->len = k + pklen;
	if (ret->len > MAX_PACKET_BYTES) {
	//if (ret->len > 1000) {
		fprintf(stderr, "packet length too big, k = %d, pklen = %d\n", k, pklen);
		return NULL;
	}
	ret->data = (char *)malloc(ret->len);
	int len = ret->len;
	char *data = ret->data;
	while (len > buf->avail) {
		fprintf(stderr, "getpk: packet incomplete, len = %d, buf->avail = %d, pklen = %d, k = %d\n", len, buf->avail, pklen, k);
		memcpy(data, buf->start, buf->avail);
		len -= buf->avail;
		data += buf->avail;
		if (filbuf() <= 0) {
			fprintf(stderr, "getpk: can't fill packets buffer\n");
			return NULL;

		}
	//	end = buf + avail;
	}

	memcpy(data, buf->start, len);
	buf->start += len;
	buf->avail -= len;
	fprintf(stderr, "getpk done: len = %d, buf->avail = %d\n", len, buf->avail);
	//write(1, "xxxxxxxxxxxxxxxx", 16);
	//write(1, ret->data, ret->len);
	return ret;
}

char *readtcpk(int fd, int *n)
{

	char buf[MAX_PACKET_BYTES];
	int rn = 0;
	char *ret;
	if ((rn=read(sockfd,buf,MAX_PACKET_BYTES)) <= 0)
		return NULL;
	ret = (char *)malloc(rn);
	memcpy(ret, buf, rn);
	*n = rn;
	return ret;
		
}
/* slices a continguous block of chars into packets and then reads them */
/* does not modify s  but creates copies of its content */
int chopk(char *s, int n)
{
	if (n <= 0)
		return -1;
	char **next = (char **)malloc(sizeof(char *));
	char *start = *next = s;
	int k = 0;
	int rn = 0;
	char *snew = NULL;
	char *scat = NULL;
	char *prevs = NULL;
	packet_t pk;  
	do {
		pk = (packet_t)malloc(sizeof(struct packet));
		pk->len = vtoisk(*next, next, &k);
		pk->len += k;
		if (pk->len > (MAX_PACKET_BYTES - 3)) {
			fprintf(stderr, "packet length too big\n");
			return -1;
		}
		/*
		if (pk->len > n) {
			//fprintf(stderr, "chopk: packet length reading error\n");
			//write(1, s, n);
			//return -1;
		}
		*/
		prevs = start;
		while (pk->len > n) {
			fprintf(stderr, "packet was cutoff, requesting more tcp packets\n");
			fprintf(stderr, "chopk: n = %d\n", n);
			fprintf(stderr, "chopk: pklen  = %d\n", pk->len);
			fprintf(stderr, "chopk: pklen + k = %d\n", pk->len);
			if ((snew=readtcpk(sockfd, &rn)) == NULL) {
				fprintf(stderr, "chopk: could not complete current packet\n");
				free(next);
				return -1;
			}
			scat = (char *)malloc(n + rn);
			if (scat == NULL) {
				fprintf(stderr, "chopk: malloc failed\n");
				free(next);
				return -1;
			}
			memcpy(scat, prevs, n);
			memcpy(scat + n, snew, rn);
			if (prevs != start)
				free(prevs);
			free(snew);
			n += rn;
			*next = scat;

		}
		pk->data = (char *)malloc(pk->len);
		memcpy(pk->data, start, pk->len);
		start = *next;
		if (readpk(pk) != 0) {
			free(pk->data);
			free(pk);
			free(next);
			return -1;
		}
		n -= pk->len;
	} while (n > 0);
	free(next);
	return 0;

}

/* same as vtoisk but doesn't save next pointer */
int vtoik(char *data, int *k)
{
        int i = vtoi_raw(data);
	int j = 1;
        while ((*data++ & 0x80) > 0)
		j++;
	*k = j;
        return i;
}

/* same as vtois but stores length of varint to k */
int vtoisk(char *data, char **next, int *k)
{
        int i = vtoi_raw(data);
	int j = 1;
        while ((*data++ & 0x80) > 0)
                j += 1;
        *next = data;
	*k = j;
        return i;
}

const char *hosttoip(const char *host)
{
	struct hostent *hostentp = gethostbyname(host);
	if (hostentp == NULL ) {
		fprintf(stderr, "gethosbyname(%s) returned nothing\n", host);
		return NULL;
	}
	char **addr_list = hostentp->h_addr_list;	
	char *src = addr_list[0];	
	char *addrbuf = (char *)malloc(100);
	int i = 0;
	/*
	while (addr_list[i] != NULL) {
		fprintf(stderr, "ipaddr: %s\n", inet_ntop(AF_INET, (const void *) addr_list[i], addrbuf, 100));
		i++;
	}
	*/
	return  inet_ntop(AF_INET, (const void *) src, addrbuf, 100); 
}
#define cjson_get(x, y) cJSON_GetObjectItemCaseSensitive((x), (y))
/* parse response from /authenticate */
int parseauth(unsigned char *payload)
{
	if (http_code == 403) {
		fprintf(stderr, "authentication failed\n");
		return -1;
	}
	cJSON *payload_json = cJSON_Parse(payload);
	player_uuid = cjson_get(cjson_get(payload_json, "selectedProfile"), "id")->valuestring;
	player_name = cjson_get(cjson_get(payload_json, "selectedProfile"), "name")->valuestring;
	access_token = cjson_get(payload_json, "accessToken")->valuestring;
	free(payload);
	return 0;

}
#define nibtox(nib) (((nib) < 10) ? (nib) + '0' : ((nib) - 10) + 'a')
/* takes big-endian signed 20-byte int num, computes its two's complement and returns a big-endian signed hex string */ 
unsigned char *shatohex(unsigned char *num)
{
	unsigned char *ret = (unsigned char *)malloc(42);
	unsigned char *pin = ret;
	unsigned char *tmp;
	if ((num[0] & 0x80) > 0) {
		*pin = '-';
		tmp = num;
		num = twoscom(num);
		free(tmp);
		pin++;
	}
	int len = 20;
	/* remove trailing zeroes */
	while (len > 0 && *num == 0) {
		num++;
		len--;
	}
	/* if first nibble is zero */
	if ((*num & 0xf0) == 0) {
		*pin = nibtox(*num);
		num++;
		pin++;
		len--;
	}
	for (int i = 0; i < len; i++) {
		pin = btox(num[i], pin);

	}
	*pin = '\0';
	return ret;
	

}
/* prints b into hex format to string x, x must be able to contain at least 2 chars */
/* returns x + 2 */
/* b and x are big-endian */
unsigned char *btox(unsigned char b, unsigned char *x)
{
	*x++ = nibtox((b >> 4) & 0x0f);
	*x++ = nibtox( b & 0x0f);
	return x;
}

/* big end-endian, 20 bytes */
unsigned char *twoscom(unsigned char *num)
{
	unsigned char *ret = (unsigned char *)malloc(20);
	unsigned int carry = 1;
	int i = 19;
	for (; i >= 0; i--) {
		carry += !(num[i] & 0xff);
		carry += (num[i] ^ 0xff);
		ret[i] = carry & 0xff;
		carry >>= 8;
	}
	return ret;
}
char *mksesjson(char *tkn, char *puuid, char *srvhash)
{
	cJSON *payload = cJSON_CreateObject();
	cJSON_AddItemToObject(payload, "accessToken", cJSON_CreateString(tkn));
	cJSON_AddItemToObject(payload, "selectedProfile", cJSON_CreateString(puuid));
	cJSON_AddItemToObject(payload, "serverId", cJSON_CreateString(srvhash));
	return cJSON_Print(payload);
}
char *mkauthjson(const char *uname, const char *pword)
{

	cJSON *payload = cJSON_CreateObject();
	cJSON *agent = cJSON_CreateObject();
	cJSON *name = cJSON_CreateString("Minecraft");
	cJSON_AddItemToObject(agent, "name", name);
	cJSON *version = cJSON_CreateNumber(1);
	cJSON_AddItemToObject(agent, "version", version);
	cJSON *username = cJSON_CreateString(uname);
	cJSON *password = cJSON_CreateString(pword);
	uuid_t out;
	uuid_generate(out);
	char *token = (char *)malloc(36);
	uuid_unparse(out, token);
	cJSON *clientToken = cJSON_CreateString(token);
	cJSON *requestUser = cJSON_CreateTrue();
	cJSON_AddItemToObject(payload, "agent", agent);
	cJSON_AddItemToObject(payload, "username", username);
	cJSON_AddItemToObject(payload, "password", password);
	cJSON_AddItemToObject(payload, "clientToken", clientToken);
	cJSON_AddItemToObject(payload, "requestUser", requestUser);
	return cJSON_Print(payload);
}

char *mojangapi(char *payload, char *url)
{
	CURL *curl;
	CURLcode res;
	char *ret;
	struct MemoryStruct chunk;
 
	chunk.memory = malloc(1);	/* will be grown as needed by realloc above */
	chunk.size = 0;		/* no data at this point */
 
	curl_global_init(CURL_GLOBAL_ALL);
	curl = curl_easy_init();
	if(curl) {
		curl_easy_setopt(curl, CURLOPT_URL, url);
 
		/* send all data to this function	*/
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
 
		/* we pass our 'chunk' struct to the callback function */
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
 
		/* some servers don't like requests that are made without a user-agent
			 field, so we provide one */
		curl_easy_setopt(curl, CURLOPT_USERAGENT, "libcurl-agent/1.0");
 
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload);
 
		/* if we don't provide POSTFIELDSIZE, libcurl will strlen() by
			 itself */
		curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(payload));

		/* add content-type header */
		struct curl_slist *headers = curl_slist_append(NULL, "Content-Type: application/json"); 
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers); 
 
		/* Perform the request, res will get the return code */
		res = curl_easy_perform(curl);
		mojang_response = res;
		curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
		/* Check for errors */
		if(res != CURLE_OK) {
			fprintf(stderr, "curl_easy_perform() failed: %s\n",
			        curl_easy_strerror(res));
			//chunk.memory = 0xff;
		}
		else {
			/*
			 * Now, our chunk.memory points to a memory block that is chunk.size
			 * bytes big and contains the remote file.
			 *
			 * Do something nice with it!
			 */
			//printf("%s\n",chunk.memory);
			//parseauth(chunk.memory);
			ret = chunk.memory;
		}
 
		/* always cleanup */
		curl_easy_cleanup(curl);
		curl_slist_free_all(headers);
	}
 
	//free(chunk.memory);
	curl_global_cleanup();
	return ret;
}
int authenticate2(char *uname, char *pword)
{
	parseauth(mojangapi(mkauthjson(uname, pword), "https://authserver.mojang.com/authenticate"));
}
int join()
{
	mojangapi(mksesjson(access_token, player_uuid, server_hash), "https://sessionserver.mojang.com/session/minecraft/join");
	return (http_code == 204) ? 1 : 0;
//	return (mojang_response == CURLE_OK) ? 1 : 0;
}
int authenticate(char *uname, char *pword)
{

	CURL *curl;
	CURLcode res;
	struct MemoryStruct chunk;
//	static const char *payload = "Field=1&Field=2&Field=3";
	char *payload = mkauthjson(uname, pword);
 
	chunk.memory = malloc(1);	/* will be grown as needed by realloc above */
	chunk.size = 0;		/* no data at this point */
 
	curl_global_init(CURL_GLOBAL_ALL);
	curl = curl_easy_init();
	if(curl) {
		curl_easy_setopt(curl, CURLOPT_URL, "https://authserver.mojang.com/authenticate");
 
		/* send all data to this function	*/
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
 
		/* we pass our 'chunk' struct to the callback function */
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
 
		/* some servers don't like requests that are made without a user-agent
			 field, so we provide one */
		curl_easy_setopt(curl, CURLOPT_USERAGENT, "libcurl-agent/1.0");
 
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload);
 
		/* if we don't provide POSTFIELDSIZE, libcurl will strlen() by
			 itself */
		curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(payload));

		/* add content-type header */
		struct curl_slist *headers = curl_slist_append(NULL, "Content-Type: application/json"); 
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers); 
 
		/* Perform the request, res will get the return code */
		res = curl_easy_perform(curl);
		/* Check for errors */
		if(res != CURLE_OK) {
			fprintf(stderr, "curl_easy_perform() failed: %s\n",
			        curl_easy_strerror(res));
		}
		else {
			/*
			 * Now, our chunk.memory points to a memory block that is chunk.size
			 * bytes big and contains the remote file.
			 *
			 * Do something nice with it!
			 */
			printf("%s\n",chunk.memory);
			parseauth(chunk.memory);
		}
 
		/* always cleanup */
		curl_easy_cleanup(curl);
		curl_slist_free_all(headers);
	}
 
	free(chunk.memory);
	curl_global_cleanup();
	return 0;
} 
static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
  size_t realsize = size * nmemb;
  struct MemoryStruct *mem = (struct MemoryStruct *)userp;
 
  char *ptr = realloc(mem->memory, mem->size + realsize + 1);
  if(!ptr) {
    /* out of memory! */
    printf("not enough memory (realloc returned NULL)\n");
    return 0;
  }
 
  mem->memory = ptr;
  memcpy(&(mem->memory[mem->size]), contents, realsize);
  mem->size += realsize;
  mem->memory[mem->size] = 0;
 
  return realsize;
}


/*
packet_t decpk(packet_t pk, unsigned char *key, EVP_CIPHER_CTX *ctx)
{
	packet_t ret = (packet_t)malloc(sizeof(struct packet));
	int block_size = EVP_CIPHER_CTX_block_size(ctx);
	ret->len = pk->len + block_size;
	ret->data = (char *)malloc(ret->len);
	int outl;
	if (!EVP_DecryptUpdate(ctx, ret->data,  &outl, pk->data, pk->len)) {
		fprintf(stderr, "packet decryption failed\n");
		return NULL;
	}
	ret->len = outl;
	return ret;
}
*/

/* returns encrypted pk */
packet_t encpk(packet_t pk, EVP_CIPHER_CTX *ctx)
{
        packet_t ret = (packet_t)malloc(sizeof(struct packet));
        int block_size = EVP_CIPHER_CTX_block_size(ctx);
        ret->len = pk->len + block_size;
        ret->data = (char *)malloc(ret->len);
        int outl;
        if (!EVP_EncryptUpdate(ctx, ret->data,  &outl, pk->data, pk->len)) {
                fprintf(stderr, "packet encryption failed\n");
                return NULL;
        }
        ret->len = outl;
        return ret;
}

/* return compressed pk */
packet_t compk(packet_t pk)
{
	char **next = (char **)malloc(sizeof(char *));
	*next = pk->data;
	int pklen = vtois(*next, next);
	varint_t vpklen = itov(pklen);
	packet_t ret = (packet_t)malloc(sizeof(struct packet));
	char *pin;
	if (pklen < compression_threshold) {
		pin = ret->data = (char *)malloc(pk->len + 1);
		memcpy(pin, vpklen->data, vpklen->len);
		pin += vpklen->len;
		*pin++ = 0; /* data length 0 to signal noncompression */
		memcpy(pin, *next, pklen);
		ret->len = pklen + 1;
		return ret;
	}
        z_stream *strm = (z_stream *)malloc(sizeof(struct z_stream_s));
        strm->zalloc = Z_NULL;
        strm->zfree =  Z_NULL;
        strm->opaque = Z_NULL;
        strm->next_in = *next;
        strm->avail_in = pklen;
        unsigned char *comp = (unsigned char *)malloc(pklen);
        strm->next_out = comp;
        strm->avail_out = pklen;

        if (deflateInit(strm, Z_DEFAULT_COMPRESSION) != Z_OK) {
	        if (strm->msg != NULL) {
                        fprintf(stderr, "deflateInit failed, error: %s\n", strm->msg);
                        return NULL;
                }
        }
	int retval;
        if ((retval=deflate(strm, Z_NO_FLUSH)) != Z_STREAM_END) {
	        if (strm->msg != NULL) {
                        fprintf(stderr, "deflate failed, error: %s\n", strm->msg);
                        return NULL;
                }
		return NULL;
	}
	int cpklen = strm->total_out + vpklen->len;
	varint_t vcpklen = itov(cpklen);

	ret->len = vcpklen->len + vpklen->len + strm->total_out;
	pin = ret->data = (char *)malloc(ret->len);
	memcpy(pin, vcpklen->data, vcpklen->len);
	pin += vcpklen->len;
	memcpy(pin, vpklen->data, vpklen->len);
	pin += vpklen->len;
	memcpy(pin, comp, strm->total_out);

	free(vcpklen->data);
	free(vcpklen);
	free(vpklen->data);
	free(vpklen);
	free(comp);
	free(next);


	return ret;

}

/* turns compressed pk into uncompressed pk*/
/* you can free pk after calling this */
packet_t uncpk(packet_t pk)
{
	char **next = (char **)malloc(sizeof(char *));
	*next = pk->data;
	int pklen = vtois(*next, next);
	//fprintf(stderr, "pklen = %d\n", pklen);
	int dtn = vton_raw(*next); /* length of Data Length varint */
	//fprintf(stderr, "dtn = %d\n", dtn);
	int dtlen = vtois(*next, next);
	//fprintf(stderr, "dtlen = %d\n", dtlen);
	packet_t ret = (packet_t)malloc(sizeof(struct packet));
	varint_t vpklen;
	if (dtlen == 0) {
		vpklen = itov(pklen - 1);
		ret->len = vpklen->len + pklen - 1;  /* remove the  data length */
		ret->data = (char *)malloc(ret->len);
		memcpy(ret->data, vpklen->data, vpklen->len);
		memcpy(ret->data + vpklen->len, *next, pklen - 1);
		return ret;
	}
        z_stream *strm = (z_stream *)malloc(sizeof(struct z_stream_s));
        strm->zalloc = Z_NULL;
        strm->zfree =  Z_NULL;
        strm->opaque = Z_NULL;
        strm->next_in = *next;
        strm->avail_in = pk->len - dtn;
        unsigned char *decomp = (unsigned char *)malloc(dtlen);
        strm->next_out = decomp;
        strm->avail_out = dtlen;

        if (inflateInit(strm) != Z_OK) {
	        if (strm->msg != NULL) {
                        fprintf(stderr, "inflateInit failed, error: %s\n", strm->msg);
                        return NULL;
                }
        }
	int retval;
 
        if ((retval=inflate(strm, Z_FINISH)) != Z_STREAM_END) {
                if (strm->msg != NULL) {
                        fprintf(stderr, "inflate failed, error: %s\n", strm->msg);
                }
		switch (retval) {
		case Z_STREAM_ERROR :
			fprintf(stderr, "Z_STREAM_ERROR\n");
			break;
		case Z_DATA_ERROR :
			fprintf(stderr, "Z_DATA_ERROR\n");
			break;
		case Z_OK :
			fprintf(stderr, "inflate partial progress\n");
		default :
			fprintf(stderr, "unknown cause of inflate failure\n");
			break;
		}
                return NULL;
        }
	vpklen = itov(dtlen);
	ret->len = dtlen + vpklen->len;
	ret->data = (char *)malloc(ret->len);
	memcpy(ret->data, vpklen->data, vpklen->len);
	memcpy(ret->data + vpklen->len, decomp, dtlen);
	free(decomp);
	free(vpklen->data);
	free(vpklen);
	free(next);
	return ret;
}
int readpk(packet_t pk)
{
	packet_t tmpk = pk;
	/*
	if (encryption_enabled) {
		//fprintf(stderr, "reading encrypted packet\n");
		if ((pk = decpk(pk, shared_secret, dec_ctx)) == NULL) {
			fprintf(stderr, "failed to decrypt packet\n");
			return -1;
		}
		free(tmpk);
	}
	*/
//	fprintf(stderr, "readpk: pk->len = %d\n", pk->len);
	tmpk = pk;
	if (compression_enabled) {
		if ((pk = uncpk(pk)) == NULL) {
			fprintf(stderr, "failed to uncompress packet\n");
			return -1;
		}
		free(tmpk);

	}
	/* read from packet id  to data */
	char *data = pk->data;
	int len  = pk->len;
	int k = 1;
	int pklen = vtoi_raw(data);
	while ((*data++  & 0x80) > 0)
		k++;
	fprintf(stderr, "pklen=%d,k=%d,pk->len=%d\n", pklen, k, pk->len);
	if ((pklen + k) != pk->len) {
		fprintf(stderr, "pklen + k != pk->len, pklen=%d,k=%d,pk->len=%d\n", pklen, k, pk->len);
		write(1, "xxxxxxxxxx", 10);
		write(1, pk->data, pk->len);
	}
	int pkid = vtoi_raw(data);
	while ((*data++ & 0x80) > 0)
		;
	switch (server_state) {
	case STATE_HANDSHAKE:
		break;
	case STATE_LOGIN :
		switch(pkid) {
		case ENCRYPTION_REQUEST :
			fprintf(stderr, "encryption request\n");
			handle_er(data);
			break;
		case LOGIN_SUCCESS :
			fprintf(stderr, "login success\n");
			server_state = STATE_PLAY;
			break;
		case SET_COMPRESSION :
			fprintf(stderr, "set compression\n");
			//fprintf(stderr, "readpk: = %d, pklen = %d\n", pkid, pk->len);
			//write(1, pk->data, pk->len);
			handle_set_compression(data);
			break;
		case DISCONNECT_LOGIN :
			fprintf(stderr, "disconnect login\n");
			handle_disconnect_login(data);
			break;
		default :
			fprintf(stderr, "readpk: weird id = %d, pklen = %d\n", pkid, pk->len);
			break;
		}
		break;
	case STATE_PLAY :
		switch (pkid) {
		case PLUGIN_MESSAGE :
			fprintf(stderr, "plugin message\n");
			//write(1, pk->data, pk->len);
			break;
		case DISCONNECT_PLAY :
			fprintf(stderr, "disconnect play, reason: %s\n", stoc_raw(data));
			
			break;
		case KEEP_ALIVE :
			fprintf(stderr, "got keep alive\n");
			handle_keep_alive(data);
			//write(1, "keep alive", 10);
			break;
		case DECLARE_RECIPES :
			fprintf(stderr, "declare recipes\n");
			break;
		case TAGS :
			fprintf(stderr, "tags\n");
			break;
		case PLAYER_INFO :
		//	fprintf(stderr, "player info\n");
			break;
		case JOIN_GAME :
			fprintf(stderr, "received join game\n");
			break;
		case ENTITY_STATUS :
			fprintf(stderr, "entity status\n");
			write(1, "xxxxxxxxxx", 10);
			write(1, pk->data, pk->len);
			break;
		case PARTICLE :
			//write(1, pk->data, pk->len);
			fprintf(stderr, "particle\n");
			break;
		case BOSS_BAR :
			//write(1, pk->data, pk->len);
			fprintf(stderr, "boss bar\n");
			break;
		default :
			fprintf(stderr, "readpk: weird id = %d, pklen = %d\n", pkid, pk->len);
			break;
		}
		break;
	default :
		fprintf(stderr, "unknown server state\n");
		return -1;
		break;
	}
	return 0;
	
	
}
int handle_keep_alive(char *data)
{
	fprintf(stderr, "handling keep alive\n");
	packet_t retpk;
	retpk = (packet_t)malloc(sizeof(struct packet));
	retpk->data = data;
	retpk->len = 8;
	packet_t tempk = retpk;
	retpk = wrapck(0x0f, retpk);
	//fprintf(stderr, "free 1\n");
	//free(tempk);
	tempk = retpk;
	if ((retpk = compk(retpk)) == NULL) {
		fprintf(stderr, "error handle_keep_alive: could not compress packet\n");
		return -1;
	}
	//fprintf(stderr, "free 2\n");
	//free(tempk);
	tempk = retpk;
	if ((retpk = encpk(retpk, enc_ctx)) == NULL) {
		fprintf(stderr, "error handle_keep_alive: could not encrypt packet\n");
		return -1;
	}
	//fprintf(stderr, "free 3\n");
	//free(tempk);
	if (sendpk(retpk, sockfd) != retpk->len) {
		fprintf(stderr, "error handle_keep_alive: could not send packet\n");
		return -1;
	}
	return 0;

}
int handle_set_compression(char *data)
{
	if ((compression_threshold =  vtoi_raw(data)) > 0)
		compression_enabled = TRUE;
	return 0;
}
/* read Byte Array */
char *readba(char *from, char **to, int *len)
{
	char **next = (char **)malloc(sizeof(char *));
	*len = vtois(from, next);
	*to = (char *)malloc(*len);
	for (int i = 0; i < *len; i++) {
		(*to)[i] = (*next)[i];
	}
	return *next + *len;


}

int handle_disconnect_login(char *data)
{
	fprintf(stderr, "disconnect reason:\n%s\n", stoc_raw(data));

}
int handle_er(char *data)
{
	char **next = (char **)malloc(sizeof(char *));
	/* copy server id */
	/* we're treating String as Byte Array because Server ID doesn't use non-ascii anyway */
	int srv_n = 0;
	data = readba(data, next, &srv_n);
	char *serverid = *next;
	/* copy public key */
	int pub_n = 0;
	data = readba(data, next, &pub_n);
	char *pubkey = *next;
	// output public key
	/* copy verify token */
	int tok_n = 0;
	data = readba(data, next, &tok_n);
	char *vtoken = *next;

	/* make shared secret */
	int len = 16;
	shared_secret = (unsigned char *)malloc(len);
	if (RAND_bytes(shared_secret, len) == 0) {
		fprintf(stderr, "failed to generate random shared secret\n");
		return -1;
	}
	server_hash = mksrvhash(serverid, srv_n, shared_secret, len, pubkey, pub_n);
	//join() == 1 ?  fprintf(stderr, "joined\n") : fprintf(stderr, "join failed");
	if (join() != 1) {
		fprintf(stderr, "join failed\n");
		return -1;
	}
	
	unsigned char *encrypted_shared_secret = encrypt(shared_secret, len, pubkey, pub_n);
	if (encrypted_shared_secret == NULL) {
		fprintf(stderr, "failed to encrypt shared secret\n");
		return -1;
	}
	unsigned char *encrypted_vtoken = encrypt(vtoken, tok_n, pubkey, pub_n);
	if (encrypted_vtoken == NULL) {
		fprintf(stderr, "failed to encrypt vtoken\n");
		return -1;
	}
	packet_t response = erespk(encrypted_shared_secret, 128, encrypted_vtoken, 128);
	if (sendpk(response, sockfd) != response->len) {
		fprintf(stderr, "failed to send encryption response packet\n");
		return -1;

	}
	encryption_enabled = TRUE;
	//fprintf(stderr, "enabling encryption\n");
	EVP_CIPHER_CTX_init(dec_ctx);
	EVP_DecryptInit_ex(dec_ctx, EVP_aes_128_cfb8(), NULL, shared_secret, shared_secret);
	EVP_CIPHER_CTX_init(enc_ctx);
	EVP_DecryptInit_ex(enc_ctx, EVP_aes_128_cfb8(), NULL, shared_secret, shared_secret);
	//print_response = TRUE;
	return 0;
	
}
unsigned char *encrypt(unsigned  char *msg, long len, unsigned const char *pubkey, long n)
{
	const unsigned char *throwaway = pubkey; /* because d2i modifies the pointer for some reason */
	RSA *rsa = d2i_RSA_PUBKEY(NULL, &throwaway, n);
	if (rsa == NULL) {
		fprintf(stderr, "failed to read pubkey\n");
		return NULL;
	}

	if (len >= (RSA_size(rsa) - 11)) {
		fprintf(stderr, "len is greater than RSA_size(rsa) - 11\nlen = %ld, RSA_size(rsa) = %d\n", len, RSA_size(rsa));
		return NULL;
	}
	unsigned char *ret = (unsigned char *)malloc(RSA_size(rsa));
	int retlen;
	if ((retlen=RSA_public_encrypt(len, msg, ret, rsa, RSA_PKCS1_PADDING)) < 0) {
		fprintf(stderr, "failed to encrypt\n");
		return NULL;
	}
	return ret;
	

}
unsigned char *mksrvhash(unsigned char *srvid, int n, unsigned char *sharedsec, int m, unsigned char *srvpubkey, int l)
{
	SHA_CTX *ctx = (SHA_CTX *)malloc(sizeof(SHA_CTX));
	SHA1_Init(ctx);
	SHA1_Update(ctx, srvid, n);
	SHA1_Update(ctx, sharedsec, m);
	SHA1_Update(ctx, srvpubkey, l);
	unsigned char *md = (unsigned char *)malloc(20);
	SHA1_Final(md, ctx);
	return shatohex(md);

}
/* same as vtoi_raw but sets next to the byte after the end of data */
/*
int vtois(char *data, char **next)
{
	int i = vtoi_raw(data);
	while ((*data++ & 0x80) > 0)
		;
	*next = data;
	return i;
}
*/


int read_varint()
{
	int value = 0;
	int bit_offset = 0;
	char current_byte;
	do {
		if (bit_offset == 35); {
			fprintf(stderr, "var_Int too big\n");
			fprintf(stderr, "can't be more than 5 bytes");
			return -1;
		}
		if ((current_byte = read_byte()) == EOF) {
			fprintf(stderr, "no more bytes");
			return -1;
		}
		value |= (current_byte & 0x7f) << bit_offset;
		bit_offset += 7;
	} while ((current_byte & 0x80) != 0);
	return value;
}
int read_byte()
{
	if (read_index < read_max)
		return read_buf[read_index++];
	if((read_max = read(sockfd, read_buf, MAX_BYTES)) > 0) {
		read_index = 0;
		return read_buf[read_index++];
	}
	return EOF;
}

int write_byte(int value)
{
	if (write_index < MAX_BYTES)
		return (write_buf[write_index++] = value);
	return flush_write_buf();
}
int write_varint(int value)
{
	while(1) {
		if ((value & 0xffffff80) == 0) {
			write_byte(value);
			return 0;
		}
		write_byte(value & 0x7f | 0x80);
		value >>= 7;

	}
}

int write_str(char *str, int len)
{
	int i = 0;
	while (i < len)
		write_byte(str[i++]);
	flush_write_buf();
	return 0;
}
int flush_write_buf()
{
	if((write_max = write(sockfd, write_buf, write_index)) > 0) {
		write_index = 0;
		return write_max;
	}
	return -1;
}

int read_str(char *str, int len)
{
	int i = 0;
	while (i++ < len)
		fprintf(stderr, "%c", read_byte());
}
/*
int sendpk(packet_t pk, int sock)
{
	fprintf(stderr, "sending packet\n");
	return write(sock, pk->data, pk->len);

}
*/
int sendvarint(varint_t value, int sock)
{
	return write(sock, value->data, value->len);

}

/*
packet_t wrapck(int id, packet_t pack)
{
	packet_t ret = (packet_t)malloc(sizeof(struct packet));
	varint_t packid = itov(id);
	varint_t packlen = itov(packid->len + pack->len);
//	fprintf(stderr, "packid->len + pack->len = %d\n", packid->len + pack->len);
//	fprintf(stderr, "pack->len = %d\n", pack->len);
	ret->len = packid->len + packlen->len + pack->len;
	ret->data = (char *)malloc(ret->len);
	char *pin = ret->data;
	for (int i = 0; i < packlen->len; i++) {
		*pin++ = packlen->data[i];
	}
	for (int i = 0; i < packid->len; i++) {
		*pin++ = packid->data[i];
	}
	for (int i = 0; i < pack->len; i++) {
		*pin++ = pack->data[i];
	}
	free(packid->data);
	free(packlen->data);
	free(pack->data);
	free(packid);
	free(packlen);
	free(pack);
	return ret;
	
}
*/

packet_t loginpk(const char *user)
{
	packet_t retpk = (packet_t)malloc(sizeof(struct packet));
	retpk->data = (char *)malloc(16);
	retpk->len = 16;
	strncpy(retpk->data, user, 16);
	return wrapck(0, retpk);
	
	
}
packet_t lipk(const char *user)
{
	packet_t retpk = (packet_t)malloc(sizeof(struct packet));
	string_t s = ctos(user);
	retpk->len = s->len;
	retpk->data = s->data;
	return wrapck(0, retpk);
	
	
}
packet_t erespk(unsigned char *ess, int sslen, unsigned char *evtoken,  int vtlen)
{
	varint_t essv = itov(sslen);
	varint_t vtlenv = itov(vtlen);
	packet_t ret = (packet_t)malloc(sizeof(struct packet));
	ret->len = sslen + essv->len + vtlen + vtlenv->len;
	ret->data = (char *)malloc(ret->len);
	char *pin = ret->data;
	for (int i = 0; i < essv->len; i++) {
		*pin++ = essv->data[i];
	}
	for (int i = 0; i < sslen; i++) {
		*pin++ = ess[i];
	}
	for (int i = 0; i < vtlenv->len; i++) {
		*pin++ = vtlenv->data[i];
	}
	for (int i = 0; i < vtlen; i++) {
		*pin++ = evtoken[i];
	}
	return wrapck(1, ret);

}
packet_t handshake_packet(varint_t proto, char *addr, unsigned short int port, varint_t next)
{
	packet_t ret = (packet_t)malloc(sizeof(struct packet));
	ret->len = proto->len + 255 + 2 + next->len;
	ret->data = (char *)malloc(ret->len);
	int i;
	/* dump protocol version */
	for (i = 0; i < proto->len; i++) {
		ret->data[i] = proto->data[i];
	}
	int j = i;
	/* copy server address */
	while (*addr != '\0' && i < j + 254)
		ret->data[i++] = *addr++;
	ret->data[i] = '\0';
	j += 255;
	ret->data[j++] = (port >> 8) & 0xff;
	ret->data[j++] = port & 0xff; /* network is big-endian */
	/* dump next state */
	for (i = 0; i < next->len; i++) {
		ret->data[j+i] = next->data[i];
	}
	/* handshake packet id is 0x00 */
	return wrapck(0, ret); 

}
packet_t hspk(varint_t proto, string_t addr, unsigned short int port, varint_t next)
{
	packet_t ret = (packet_t)malloc(sizeof(struct packet));
	ret->len = proto->len + addr->len + sizeof(port) + next->len;
	ret->data = (char *)malloc(ret->len);
	int i;
	char *pin = ret->data;
	/* dump protocol version */
	for (i = 0; i < proto->len; i++) {
		*pin++ = proto->data[i];
	}
	/* copy server address */
	for (i = 0; i < addr->len; i++)
		*pin++ = addr->data[i];
	/* add 16-bit port number in big-endian */
	*pin++ = (port >> 8) & 0xff;
	*pin++ = port & 0xff;
	/* dump next state */
	for (i = 0; i < next->len; i++) {
		*pin++ = next->data[i];
	}
	/* handshake packet id is 0x00 */
	return wrapck(0, ret); 

}

/* varint len of packet id + data
   varint packed id
   byte_array data
*/

packet_t hspack(varint_t proto, char *addr, unsigned short int port, varint_t next)
{
	packet_t ret = (packet_t)malloc(sizeof(struct packet));
	ret->len = proto->len + 255 + 16 + next->len;
	varint_t packlen, packid;
	packid = itov(0);
	packlen = itov(ret->len + packid->len);
	/* actual size of the packet */
	int trulen = packlen->len + ret->len + packid->len;
	ret->data = (char *)malloc(trulen);
	int k, l;
	/* dump packet length */
	for (k = 0; k < packlen->len; k++) {
		ret->data[k] = packlen->data[k];
	}
	/* dump packet id */
	for (l = 0; l < packid->len; l++) {
		ret->data[k + l] = packid->data[l];

	}
	l += k;
	int i;
	/* dump protocol version */
	for (i = 0; i < proto->len; i++) {
		ret->data[i + l] = proto->data[i];
	}
	i += l;
	int j = i;
	/* copy server address */
	while (*addr != '\0' && i < j + 254)
		ret->data[i++] = *addr++;
	ret->data[i] = '\0';
	j += 255;
	ret->data[j++] = (port >> 8) & 0xff;
	ret->data[j++] = port & 0xff; /* network is big-endian */
	/* dump next state */
	for (i = 0; i < next->len; i++) {
		ret->data[j+i] = next->data[i];
	}
	return ret;

}

/*
#include <stdio.h>
#include <stdlib.h>


string_t ctos(const char *c)
{
	string_t s = (string_t)malloc(sizeof(struct string));
	int slen = strlen(c);
	varint_t len = itov(slen);
	s->len = len->len + slen;
	s->data = (char *)malloc(s->len);
	char *sp = s->data;
	for (int i = 0; i < len->len; i++)
		*sp++ = len->data[i];
	while (*c != '\0')
		*sp++ = *c++;
	return s;

}
*/
char *stoc(string_t s)
{
	int len = vtoi_raw(s->data);
	char *c = (char *)malloc(len + 1);
	char *pin = s->data + s->len - len;
	for (int i = 0; i < len; i++)
		c[i] = pin[i];
	c[len] = '\0';
	return c;
}
/*
varint_t itov(int value)
{
	int tmp = value;
	int len = 0;
//	 count bytes 
	while (1) {
		if ((tmp & 0xffffff80) == 0) { 
			len++;
			break;
		}		
		len++;
		tmp >>= 7;
	}
	varint_t ret = (varint_t)malloc(sizeof(struct varint));
	ret->data = (char *)malloc(len);
	ret->len = len;
// store value
	int i;
	for (i = 0; i < len - 1; i++) {
		ret->data[i] = (value & 0x7f | 0x80);
		value >>= 7;

	}
	ret->data[i] = value & 0x7f;
	return ret;
}
*/

int vtoi(varint_t value)
{
	int ret = 0;
	int i = 0;
	do {
		ret |= ((value->data[i] & 0x7f) << (i * 7));
		i++;
	} while (i < value->len);
	return ret;

}
	
