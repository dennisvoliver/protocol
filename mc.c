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
#define PORT 25565
char read_buf[MAX_BYTES];
char write_buf[MAX_BYTES];
int read_max;
int write_max;
int read_index;
int write_index;
int sockfd;
int encryption_enabled;

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

int main(int argc, char **argv)
{
	/*
	char *msg = "hello";
	varint_t num = itov(strlen(msg) + 1);
	char *data = (char *)malloc(num->len + strlen(msg) + 1);
	int i;
	for (i = 0; i < num->len; i++) {
		data[i] = num->data[i];
	}
	int j;
	for (j = 0; j < strlen(msg) + 1; j++) {
		data[i + j] = msg[j];
	}
	char **prt = (char **)malloc(sizeof(char *));
	int n;
	readba(data, prt, &n);
	fprintf(stderr, "readba test: %s\n", *prt);

	return 0;
	*/
	//fprintf(stderr, "payload:\n%s\n", mkauthjson("myusername", "mypassword"));
//	return 0;
	print_response = FALSE;	
	dec_ctx = EVP_CIPHER_CTX_new();
	enc_ctx = EVP_CIPHER_CTX_new();
	encryption_enabled = FALSE;
	//authenticate2("ctholdaway@gmail.com", "Corman999");
	authenticate2("jj4u@live.be", "Jelte123");
	fprintf(stderr, "done authenticating");
	int read_max = 0;
	int write_max = 0;
	int read_index = 0;
	int write_index = 0;
	if (argc != 2) {
		fprintf(stderr, "arg ip address\n");
		return -1;
	}
	struct sockaddr_in servaddr;
	fprintf(stderr, "creating socket\n");
	if( (sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 1) {
		fprintf(stderr, "socket() error\n");
		return -1;
	}
	fprintf(stderr, "created socket\n");
	bzero(&servaddr, sizeof(servaddr));
	fprintf(stderr, "initialized servaddr\n");
	servaddr.sin_family = AF_INET;
	fprintf(stderr, "set servaddr.sin_family to AF_INET\n");
	//servaddr.sin_port = htons(PORT);
	servaddr.sin_port = htons(25565);
	fprintf(stderr,"set servaddr.sin_port to 25565\n");
	fprintf(stderr, "%s = %s\n", argv[1], hosttoip(argv[1]));
	const char *ip = hosttoip(argv[1]);
	if (ip == NULL) {
		fprintf(stderr, "hosttoip failed\n");
		return -1;
	}
	if (inet_pton(AF_INET, ip, &servaddr.sin_addr) <= 0) {
		fprintf(stderr, "inet_pton error\n");
		return -1;
	}
//	return 0;
	fprintf(stderr, "connecting\n");
	if (connect(sockfd, (struct sockaddr *) &servaddr, sizeof(servaddr)) < 0) {
		fprintf(stderr, "%s", strerror(errno));
		fprintf(stderr, "connect error\n");
		return -1;
	}

	int sentpk;
	//sentpk = sendpk(hspk(itov(754), ctos("mc.hypixel.net"), 25565, itov(2)), sockfd);
	fprintf(stderr, "sending handshake packet to server\n");
	packet_t pkpk = hspk(itov(754), ctos(argv[1]), 25565, itov(2));
	sentpk = sendpk(pkpk, sockfd);
	//write(1, pkpk->data, pkpk->len);
//	fprintf(stderr, "sentpk = %d\n", sentpk);
	sleep(1);
	fprintf(stderr, "sending login start packet\n");
	sendpk(lipk(player_name), sockfd);
	char buf[MAX_BYTES];
	int rn = 0;
	packet_t pk;  
	while (1){
		if ((rn=read(sockfd,buf,MAX_BYTES)) > 0) {
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
		}
	}
	return 0;
}
const char *hosttoip(const char *host)
{
	fprintf(stderr, "looking for ip of %s\n", host);
	struct hostent *hostentp = gethostbyname(host);
	if (hostentp == NULL ) {
		fprintf(stderr, "gethosbyname(%s) returned nothing\n", host);
		return NULL;
	}
	char **addr_list = hostentp->h_addr_list;	
	fprintf(stderr, "called gethostbyname\n");
	char *src = addr_list[0];	
	char *addrbuf = (char *)malloc(100);
	int i = 0;
	/*
	while (addr_list[i] != NULL) {
		fprintf(stderr, "ipaddr: %s\n", inet_ntop(AF_INET, (const void *) addr_list[i], addrbuf, 100));
		i++;
	}
	*/
	fprintf(stderr, "doing inet_ntop\n");
	return  inet_ntop(AF_INET, (const void *) src, addrbuf, 100); 
}
#define cjson_get(x, y) cJSON_GetObjectItemCaseSensitive((x), (y))
/* parse response from /authenticate */
int parseauth(unsigned char *payload)
{
	fprintf(stderr, "parsing auth json %s\n", payload);
	//write(1, payload, strlen(payload));
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
		//fprintf(stderr, "%x ", carry);
		ret[i] = carry & 0xff;
		carry >>= 8;
	}
	return ret;
}
char *mksesjson(char *tkn, char *puuid, char *srvhash)
{
	fprintf(stderr, "making session\n");
	cJSON *payload = cJSON_CreateObject();
	cJSON_AddItemToObject(payload, "accessToken", cJSON_CreateString(tkn));
	fprintf(stderr, "adding puuid to json\n");
	cJSON_AddItemToObject(payload, "selectedProfile", cJSON_CreateString(puuid));
	fprintf(stderr, "srvhash: %s\n", srvhash);
	cJSON_AddItemToObject(payload, "serverId", cJSON_CreateString(srvhash));
	fprintf(stderr, "printing json\n");
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
	fprintf(stderr,"calling mojang api\n");
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
int readpk(packet_t pk)
{
	packet_t tmpk = pk;
	if (encryption_enabled) {
		fprintf(stderr, "reading encrypted packet\n");
		if ((pk = decpk(pk, shared_secret, dec_ctx)) == NULL) {
			fprintf(stderr, "failed to decrypt packet\n");
		}
		free(tmpk);
	}
	char *data = pk->data;
	int len  = pk->len;
	while ((*data++  & 0x80) > 0)
		;
	fprintf(stderr, "pklen: %d\n", pk->len);
	int state = vtoi_raw(data);
	while ((*data++ & 0x80) > 0)
		;
	switch(state) {
	case ENCRYPTION_REQUEST :
		handle_er(data);
		break;
	case LOGIN_SUCCESS :
		fprintf(stderr, "login success\n");
		break;
	case SET_COMPRESSION :
		fprintf(stderr, "compression request\n");
		break;
	case DISCONNECT_PLAY :
		fprintf(stderr, "disconnect play\n");
		break;
	case DISCONNECT_LOGIN :
		fprintf(stderr, "disconnect login\n");
		break;
	default :
		fprintf(stderr, "weird state: %x\n", state);
		break;
	}
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
//		fprintf(stderr, "(*to)[%d] = %x\n", i, (*to)[i]);
//		fprintf(stderr, "(*next)[%d] = %x\n", i, (*next)[i]);
	}
	return *next + *len;


}
int handle_er(char *data)
{
	fprintf(stderr, "handling encryption request\n");
	char **next = (char **)malloc(sizeof(char *));
	/* copy server id */
	/* we're treating String as Byte Array because Server ID doesn't use non-ascii anyway */
	int srv_n = 0;
	data = readba(data, next, &srv_n);
	char *serverid = *next;
	fprintf(stderr, "srv_n: %d\n", srv_n);
	for (int i = 0; i < srv_n; i++)
		fprintf(stderr, "%c", serverid[i]);
	/* copy public key */
	int pub_n = 0;
	data = readba(data, next, &pub_n);
	char *pubkey = *next;
	// output public key
	fprintf(stderr, "pubkey_n: %d\n", pub_n);
	/* copy verify token */
	int tok_n = 0;
	data = readba(data, next, &tok_n);
	char *vtoken = *next;
	fprintf(stderr, "tok_n: %d\n", tok_n);

	/* make shared secret */
	int len = 16;
	shared_secret = (unsigned char *)malloc(len);
	RAND_bytes(shared_secret, len);
	fprintf(stderr, "making server hash\n");
	server_hash = mksrvhash(serverid, srv_n, shared_secret, len, pubkey, pub_n);
	fprintf(stderr, "joining\n");
	//write(1, server_pubkey, server_pubkey_len);
	join() == 1 ?  fprintf(stderr, "joined\n") : fprintf(stderr, "join failed");
	
	fprintf(stderr, "about to encrypt shared secre\n");
	//write(2, pubkey, pub_n);
	fprintf(stderr, "wrote pubkey in sderror\n");
	unsigned char *encrypted_shared_secret = encrypt(shared_secret, len, pubkey, pub_n);
	if (encrypted_shared_secret == NULL) {
		fprintf(stderr, "failed to encrypt encrypted shared secret\n");
		return -1;
	}
	unsigned char *encrypted_vtoken = encrypt(vtoken, tok_n, pubkey, pub_n);
	if (encrypted_vtoken == NULL) {
		fprintf(stderr, "failed to encrypt encrypted vtoken\n");
		return -1;
	}
	fprintf(stderr, "encrypted verify token\n");
	/*
	if (encrypted_shared_secret != NULL && encrypted_vtoken != NULL)
		fprintf(stderr, "encrypt success\n");
		*/
	packet_t response = erespk(encrypted_shared_secret, 16, encrypted_vtoken, 16);
	//fprintf(stderr, "outputting encryption response packet\n");
	//write(1, response->data, response->len);
	fprintf(stderr, "sending encryption response\n");
	if (sendpk(response, sockfd) != response->len) {
		fprintf(stderr, "failed to send encryption response packet\n");
		return -1;

	}
	encryption_enabled = TRUE;
	EVP_CIPHER_CTX_init(dec_ctx);
	EVP_DecryptInit_ex(dec_ctx, EVP_aes_128_cfb8(), NULL, shared_secret, shared_secret);
	EVP_CIPHER_CTX_init(enc_ctx);
	EVP_DecryptInit_ex(enc_ctx, EVP_aes_128_cfb8(), NULL, shared_secret, shared_secret);
	/*
	fprintf(stderr, "done initializing encryption/decryption contexts\n");
	write(1, response->data, response->len);
	*/
	//print_response = TRUE;
	return 0;
	
}
unsigned char *encrypt(unsigned  char *msg, long len, unsigned const char *pubkey, long n)
{
	RSA **rsap = (RSA **)malloc(sizeof(RSA *));;
	*rsap = RSA_new();
	const unsigned char *throwaway = pubkey; /* because d2i modifies the pointer for some reason */
	RSA *rsa = d2i_RSA_PUBKEY(NULL, &throwaway, n);
	//write(1, pubkey, n);
	if (rsa == NULL) {
		fprintf(stderr, "failed to read pubkey\n");
		return NULL;
	}
	int pkeylen = i2d_RSA_PUBKEY(rsa, NULL);
	char *pkey = (char *)malloc(pkeylen);
	throwaway = pkey;
	pkeylen = i2d_RSA_PUBKEY(rsa, (unsigned char **)&throwaway);
	if (pkeylen > 0) {
		write(1, pkey, pkeylen);
	}
	unsigned char *ret = (unsigned char *)malloc(RSA_size(rsa));
	if (RSA_public_encrypt(len, msg, ret, rsa, RSA_PKCS1_PADDING) < 0) {
		fprintf(stderr, "failed to encrypt\n");
		return NULL;
	}
	//write(1, ret, 16);
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
//			fprintf(stderr, "var_Int too big\n");
//			fprintf(stderr, "can't be more than 5 bytes");
			return -1;
		}
		if ((current_byte = read_byte()) == EOF) {
//			fprintf(stderr, "no more bytes");
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
//	fprintf(stderr, "proto->len = %d\n", proto->len);
//	fprintf(stderr, "next->len = %d\n", next->len);
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
	fprintf(stderr, "port %d\n", port);
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
	//fprintf(stderr, "port: %d\n", port);
	//fprintf(stderr, "first byte of port: %d\n", (port >> 8) & 0xff);
	*pin++ = (port >> 8) & 0xff;
	//fprintf(stderr, "second byte of port: %d\n", port & 0xff);
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
	
