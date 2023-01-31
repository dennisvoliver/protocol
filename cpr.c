#include <zlib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
	unsigned char *s = "asdfjashdfioahfaihefoiajhfjkasdhfuahwoeifhasjdfhaiehofiuahfjahsdjfhasdhf3421928j34f0";
	z_stream *strm = (z_stream *)malloc(sizeof(struct z_stream_s));
	strm->zalloc = Z_NULL;
	strm->zfree =  Z_NULL;
	strm->opaque = Z_NULL;
	if (deflateInit(strm, Z_DEFAULT_COMPRESSION) != Z_OK) {
		if (strm->msg != NULL) {
			fprintf(stderr, "deflateInit failed, error: %s\n", strm->msg);
			return -1;
		}
	}
	int slen = strlen(s) + 1;
	strm->next_in = s;
	strm->avail_in = slen;
	unsigned char *o = (unsigned char *)malloc(slen);
	strm->next_out = o;
	strm->avail_out = slen;
	int retval;
	retval = deflate(strm, Z_FINISH);
	switch (retval) {
	case Z_OK :
		fprintf(stderr, "partial deflation\n");
		break;
	case Z_STREAM_END :
		fprintf(stderr, "everything ok\n");
		break;
	case Z_STREAM_ERROR :
		fprintf(stderr, "state inconsistent\n");
		break;
	case Z_BUF_ERROR :
		fprintf(stderr, "need more buffer space\n");
		if (strm->msg != NULL)
			fprintf(stderr, "strm->msg: %s\n", strm->msg);
		break;

	default :
		fprintf(stderr, "no idea, doesn't work \n");
		break;
	}
	fprintf(stderr, "strm->total_out = %lu\n", strm->total_out);
	fprintf(stderr, "strlen(s) = %d\n", strlen(s));
	//write(1, o, strm->total_out);
	strm->next_in = o;
	strm->avail_in = strm->total_out;
	unsigned char *decomp = (unsigned char *)malloc(slen);
	strm->next_out = decomp;
	strm->avail_out = slen;

	if (inflateInit(strm) != Z_OK) {
		if (strm->msg != NULL) {
			fprintf(stderr, "deflateInit failed, error: %s\n", strm->msg);
			return -1;
		}
	}

	retval = inflate(strm, Z_FINISH);
	if (retval != Z_STREAM_END) {
		fprintf(stderr, "inflate fail\n");
		return -1;
	}
	//decomp[slen-1] = '\0';
	fprintf(stderr, "decompressed: %s\n", decomp);


	return 0;

}
