#include "mc.h"


/*
int readpk(packet_t pk)
{
	packet_t tmpk = pk;
	char *data = pk->data;
	int len  = pk->len;
	int pklen = vtoi_raw(data); 
	while ((*data++  & 0x80) > 0)
		;
	fprintf(stderr, "pklen: %d\n", pklen);
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
*/
int vtoi_raw(char *c)
{
	int i = 0;
	int j = 0;
	do {
		i |= ((c[j] & 0x7f) << (j * 7));
	} while ((c[j++] & 0x80) != 0);
	return i;

}
/* same as vtoi_raw but sets next to the byte after the end of data */
int vtois(char *data, char **next)
{
	int i = vtoi_raw(data);
	while ((*data++ & 0x80) > 0)
		;
	*next = data;
	return i;
}
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
int sendpk(packet_t pk, int sock)
{
	//fprintf(stderr, "sending packet\n");
	return write(sock, pk->data, pk->len);

}
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
