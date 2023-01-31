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
/* returns the length of the Varint from the draw data */
int vton_raw(char *c)
{
	int i = 0;
	while ((c[i++] & 0x80))
		;
	return i;

}
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
/*  this function frees pack so don't free it again */
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
	ret->len = pk->len + (block_size != 1 ? block_size : 0);
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
packet_t encpk(packet_t pk, EVP_CIPHER_CTX *ctx)
{
        packet_t ret = (packet_t)malloc(sizeof(struct packet));
        int block_size = EVP_CIPHER_CTX_block_size(ctx);
        ret->len = pk->len + block_size;
        ret->data = (char *)malloc(ret->len);
        int outl;
        if (!EVP_EncryptUpdate(ctx, ret->data,  &outl, pk->data, pk->len)) {
                fprintf(stderr, "encpk: packet encryption failed\n");
		fprintf(stderr, "ret->len = %d, pk->len = %d, block_size = %d\n", ret->len, pk->len, block_size);
                return NULL;
        }
        ret->len = outl;
        return ret;
}
packet_t uncpk(packet_t pk)
{
	char **next = (char **)malloc(sizeof(char *));
	*next = pk->data;
	int pklen = vtois(*next, next);
	//fprintf(stderr, "pklen = %d\n", pklen);
	int dtn = vton_raw(*next); // length of Data Length varint //
	//fprintf(stderr, "dtn = %d\n", dtn);
	int dtlen = vtois(*next, next);
	//fprintf(stderr, "dtlen = %d\n", dtlen);
	packet_t ret = (packet_t)malloc(sizeof(struct packet));
	varint_t vpklen;
	if (dtlen == 0) {
		vpklen = itov(pklen - 1);
		ret->len = vpklen->len + pklen - 1;  // remove the  data length //
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
			break;
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
packet_t compk(packet_t pk, int threshold)
{
	//write(1, "rrrrrrrrrr", 10);
	//write(1, pk->data, pk->len);
	char **next = (char **)malloc(sizeof(char *));
	*next = pk->data;
	int pklen = vtois(*next, next);
	varint_t vpklen = itov(pklen);
	packet_t ret = (packet_t)malloc(sizeof(struct packet));
	char *pin;
	fprintf(stderr, "compk: compression threshold = %d, pklen = %d\n", threshold, pklen);
	varint_t  vcpklen;
	if (pklen < threshold) {
		fprintf(stderr, "compk: creating uncompressed data in compression-enabled packet format\n");
		vcpklen = itov(pklen + 1); // length of id+packet + length of varint Data Length (1 because data length is zero)
		ret->len = vcpklen->len + pklen + 1;
		pin = ret->data = (char *)malloc(ret->len);
		memcpy(pin, vcpklen->data, vcpklen->len);
		pin += vcpklen->len;
		*pin++ = 0; // data length 0 to signal noncompression //
		memcpy(pin, *next, pklen);
		fprintf(stderr, "ret->len = %d\n", ret->len);
//		write(1, "dddddddddd", 10);
//		write(1, ret->data, ret->len);
		fprintf(stderr, "compk: varint packet length %d\n", vtoi_raw(ret->data));
		return ret;
	}
	fprintf(stderr, "compk: creating compressed data in compression-enabled packet format\n");
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
		fprintf(stderr, "compk: deflateInit failed\n");
	        if (strm->msg != NULL) {
                        fprintf(stderr, "deflateInit failed, error: %s\n", strm->msg);
                        return NULL;
                }
        }
	int retval;
        if ((retval=deflate(strm, Z_NO_FLUSH)) != Z_STREAM_END) {
		fprintf(stderr, "compk: deflate failed\n");
	        if (strm->msg != NULL) {
                        fprintf(stderr, "deflate failed, error: %s\n", strm->msg);
                        return NULL;
                }
		return NULL;
	}
	int cpklen = strm->total_out + vpklen->len;
	vcpklen = itov(cpklen);

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
/* sends packet taking into consideration the compression and encryption */
int send_packet(packet_t retpk, int sock, int cmp, int enc, int thres, EVP_CIPHER_CTX *ctx)
{

	packet_t tempk;
	// compression enabled ?
	if (cmp) {
		tempk = retpk;
		if ((retpk = compk(retpk, thres)) == NULL) {
			fprintf(stderr, "send_packet: could not compress packet\n");
			return -1;
		}
		free(tempk->data);
		free(tempk);
	}
	if (enc) {
		tempk = retpk;
		if ((retpk = encpk(retpk, ctx)) == NULL) {
			fprintf(stderr, "send_packet: could not encrypt packet\n");
			return -1;
		}
		free(tempk->data);
		free(tempk);
	}
	if (sendpk(retpk, sock) != retpk->len) {
		fprintf(stderr, "send_packet: could not send packet\n");
		free(retpk->data);
		free(retpk);
		return -1;
	}
	free(retpk->data);
	free(retpk);
}
