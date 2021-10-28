#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/types.h>
#include "mc.h"

#define MAXLINE 100
#define STATE_HANDSHAKE 0
#define PKID_HANDSHAKE 0
#define PKID_LOGINSTART 0
#define PKID_ENCRYPTION_RESPONSE 1
#define STATE_LOGIN 2
#define STATE_STATUS 1
#define MAX_BYTES 500

int server_state;
unsigned short int server_port;
char *server_address;
char *player_name;
string_t serverid;
unsigned char *publickey;
int publickey_len;
unsigned char *vtoken;
int vtoken_len;
int listenfd, connfd;
int encryption_enabled;
unsigned char *shared_secret;
EVP_CIPHER_CTX *enc_ctx;
EVP_CIPHER_CTX *dec_ctx;


char *stoc_raw(char *s);
packet_t mker();
int handle_loginstart(packet_t pk);
int handle_handshake(packet_t pk);
int handle_connection(int sockfd);
int send_packet(packet_t pk);

int main(int argc, char **argv)
{
	encryption_enabled = FALSE;
	server_state = STATE_HANDSHAKE;
	struct sockaddr_in	servaddr;
	char				buff[MAXLINE];
	time_t				ticks;

	listenfd = socket(AF_INET, SOCK_STREAM, 0);
	if (listenfd < 0) {
		fprintf(stderr, "bind:%s", strerror(errno));
		return -1;
	}

	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family      = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port        = htons(25565);	/* web */

	bind(listenfd, (struct sockaddr *) &servaddr, sizeof(servaddr));
	if (errno != 0) {
		fprintf(stderr, "listen: %s\n", strerror(errno));
		return -1;
	}

	if (listen(listenfd, 10) < 0) {
		fprintf(stderr, "listen: %s\n", strerror(errno));
		return -1;
	}

	for ( ; ; ) {
		connfd = accept(listenfd, (struct sockaddr *) NULL, NULL);
		if (connfd < 0) {
			fprintf(stderr, "accept: %s\n", strerror(errno));
			return -1;
		}

		//fprintf(stderr, "accepted\n");
		/*
		int n = 0;
		while ((n = read(connfd, buff, MAXLINE)) > 0) {
			//write(connfd, buff, n);
			//write(1, buff, n);
		}
		*/
		handle_connection(connfd);
		fprintf(stderr, "closing connfd: %d\n", connfd);
		close(connfd);
	}
}
/* handle client packets */
int handle_cpk(packet_t pk)
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
		len--;
	fprintf(stderr, "pklen: %d\n", pk->len);
	int pkid = vtoi_raw(data);
	fprintf(stderr, "pkid: %d\n", pkid);
	while ((*data++ & 0x80) > 0)
		len--;
	pk->data = data;
	pk->len = len;
	switch(pkid) {
		/*
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
		*/
	case PKID_HANDSHAKE :
		if (server_state == STATE_HANDSHAKE) {
			handle_handshake(pk);
		} else if (server_state == STATE_LOGIN) {
			handle_loginstart(pk);
		} else {
			fprintf(stderr, "got loginstart/handshake while in state %d\n", server_state);
		}
		break;
	case PKID_ENCRYPTION_RESPONSE :
		fprintf(stderr, "received encryption response\n");
		break;
	default :
		fprintf(stderr, "weird packet id: %x\n", pkid);
		break;
	}
	return 0;
	
	
}
int handle_loginstart(packet_t pk)
{
	fprintf(stderr, "handling loginstart packet\n");
	player_name = stoc_raw(pk->data);
	if (player_name == NULL) {
		fprintf(stderr, "cannot read username\n");
		return -1;
	}
	fprintf(stderr, "sending encryption request packet\n");
	packet_t ret = mker();
	if (ret == NULL) {
		fprintf(stderr, "failed to create encryption request packet\n");
		return -1;
	}
	if(send_packet(ret) <= 0) {
		fprintf(stderr, "failed to send encryption packet\n");
		return -1;
	}

}
/* sendpk wrapper */
int send_packet(packet_t pk)
{
	//write(1, pk->data, pk->len);
	return sendpk(pk, connfd);
}
/* makes encryption request packet */
packet_t mker()
{
	//fprintf(stderr, "creating encryption request packet\n");
	serverid = ctos("0123456789abcdef");
	//RSA *rsap = RSA_generate_key(1024, 3, NULL, NULL);
	RSA *rsap = RSA_new();
	/*
	if (rsap == NULL) {
		fprintf(stderr, "failed to initialize RSA struct\n");
		return NULL;
	}
	BIGNUM *e = BN_new();
	if (e == NULL) {
		fprintf(stderr, "cannot initialize BIGNUM\n");
		return NULL;
	}
	if (BN_rand(e, 1024, 0, 1) != 1) {
		fprintf(stderr, "failed to create RSA seed\n");
		return NULL;
	}
	if (BN_set_word(e, 65537u) != 1) {
		fprintf(stderr, "failed assigning bignum\n");
		return NULL;
	}
	fprintf(stderr, "generating public key\n");
	if (!RSA_generate_key_ex(rsap, 1024, e, NULL)) {
		fprintf(stderr, "failed to enerate key\n");
		return NULL;
	}
	*/
	if ((rsap=RSA_generate_key( 1024, 3, NULL, NULL)) == NULL) {
		fprintf(stderr, "failed to enerate key\n");
		return NULL;
	}
	if (rsap == NULL) {
		fprintf(stderr, "failed to generate key\n");
		return NULL;
	}
	unsigned char **pubkey = (unsigned char **)malloc(sizeof(unsigned char *));
	publickey_len = i2d_RSA_PUBKEY(rsap, NULL);
	unsigned char *throwaway = publickey = (char *)malloc(publickey_len);
	publickey_len = i2d_RSA_PUBKEY(rsap, &throwaway);
	fprintf(stderr, "publickey_len %d\n", publickey_len);
	if (publickey_len <= 0) {
		fprintf(stderr, "failed to encode public key\n");
		return NULL;
	}
	write(1, publickey, publickey_len);
	varint_t publickey_len_v = itov(publickey_len);
	vtoken = "abcd";
	vtoken_len = 4;
	varint_t vtoken_len_v = itov(4);
	packet_t ret = (packet_t)malloc(sizeof(struct packet));
	ret->len = serverid->len + publickey_len_v->len + publickey_len + vtoken_len_v->len + vtoken_len;
	ret->data = (char *)malloc(ret->len);
	char *pin = ret->data;
	for (int i = 0; i < serverid->len; i++)
		*pin++ = (serverid->data)[i];
	for (int i = 0; i < publickey_len_v->len; i++)
		*pin++ = (publickey_len_v->data)[i];
	for (int i = 0; i < publickey_len; i++)
		*pin++ = publickey[i];
	for (int i = 0; i < vtoken_len_v->len; i++)
		*pin++ = (vtoken_len_v->data)[i];
	for (int i = 0; i < vtoken_len; i++)
		*pin++ = vtoken[i];
	return wrapck(1, ret);
}

/* reads minecraft String into a char */
char *stoc_raw(char *s)
{
	char **next = (char **)malloc(sizeof(char *));
	*next = s;
	int len = vtois(*next, next);
	char *c = (char *)malloc(len + 1);
	for (int i = 0; i < len; i++) {
		c[i] = (*next)[i];
	}
	c[len] = '\0';
	free(next);
	return c;
}
int handle_handshake(packet_t pk)
{
	fprintf(stderr, "handling handshake packet\n");
	char **pin = (char **)malloc(sizeof(char *));
	*pin = pk->data;
	int protocol = vtois(*pin, pin);
	fprintf(stderr, "protocol: %d\n", protocol);
	int slen = vtois(*pin, pin);
	fprintf(stderr, "server address len: %d\n", slen);
	server_address = (char *)malloc(slen + 1);
	server_address[slen] = '\0';
	for (int i = 0; i < slen; i++) {
		server_address[i] = **pin;
		*pin = *pin + 1;
	}
	fprintf(stderr, "server address: %s\n", server_address);
	fprintf(stderr, "first byte of server port %d\n", **pin);
	server_port = **pin;
	server_port *= 0x100;
	*pin = *pin + 1;
	//fprintf(stderr, "2nd byte of server port %u\n", (unsigned char)*(*pin));
	server_port |= (unsigned char)*(*pin);
	fprintf(stderr, "server port: %d\n", server_port);
	*pin = *pin + 1;
	server_state = vtois(*pin, pin);
	fprintf(stderr, "handle_handshake: server state: %d\n", server_state);
	free(pk);
	fprintf(stderr, "done handling handshake packet\n");
	return server_state;
}
int handle_connection(int sockfd)
{
	char buf[MAX_BYTES];
	int rn = 0;
	packet_t pk;  
	while (1){
		if ((rn=read(sockfd,buf,MAX_BYTES)) > 0) {
			fprintf(stderr, "received new packet\n");
			//write(1, buf, rn);
			pk = (packet_t)malloc(sizeof(struct packet));
			pk->data = (char *)malloc(rn);
			pk->len = rn;
			//strncpy(pk->data, buf, pk->len);
			for (int i = 0; i < pk->len; i++) {
				(pk->data)[i] = buf[i];
			}
			if (handle_cpk(pk) != 0)
				return -1;
			fprintf(stderr, "packet handled\n");
		} else {
			//fprintf(stderr, "received 0 byte packet or read error\n");
		}
		//fprintf(stderr, "main loop done\n");
	}
}
