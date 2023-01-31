#include "mas.h"
// returns http body that contains device code, user code and verification uri
char *get_devcode(char *client_id)
{
	char scope[256];
	char payload[1024];
	sprintf(payload, "client_id=%s&scope=%s", client_id, urlencode("XboxLive.signin offline_access"));
	char url[] = "https://login.microsoftonline.com/consumers/oauth2/v2.0/devicecode";
	char *res = https_post(payload, url, "application/x-www-form-urlencoded");
	if (res == NULL) {
		fprintf(stderr, "get_devcode: http_post returned NULL\n");
		return NULL;
	}
	char *body = http_body(res);
	if (body == NULL) {
		fprintf(stderr, "get_devcode: http_body returned NULL\n");
		return NULL;
	}
//	char *device_code = jsonstr("device_code", body);
//	char *device_code = jsonstr("device_code", body);
//	char *user_code = jsonstr("user_code", body);
//	char *verification_uri = jsonstr("verification_uri", body);
//	printf("verification_uri = %s\nuser_code=%s\n", verification_uri, user_code);
	return body;
}
char *get_acctoken(char *client_id, char *device_code)
{
	char payload[4096];
	sprintf(payload, "grant_type=urn:ietf:params:oauth:grant-type:device_code&client_id=%s&device_code=%s", device_code, client_id);
	char *res = https_post(payload, "https://login.microsoftonline.com/consumers/oauth2/v2.0/token", "application/x-www-form-urlencoded");
	return http_body(res);

}
char *http_body(char *message)
{
	char *body = (char *)malloc(4096);
	char headers[1024];
	if ((body=frep(message, "\r\n\r\n.*$")) == NULL) {
		fprintf(stderr, "http_body: regex failed, message:\n%s", message);
		return NULL;
	}
	// discarding the \r\n\r\n
	return body + 4;
}
// returns first string that matches regular expression
char *frep(char *s, char *regex)
{

	regex_t preg;
	regmatch_t pmatch[1];
	if (regcomp(&preg, regex, 0) != 0) {
		fprintf(stderr, "frep: regcomp failed\n");
		return NULL;
	}
	if (regexec(&preg, s, 1, pmatch, 0) != 0) {
		fprintf(stderr, "frep: regexec failed\n");
		return NULL;
	}
	regoff_t off, len;
	off = pmatch[0].rm_so;
	len = pmatch[0].rm_eo;
	char *ret = (char *)malloc((size_t)len + 1);
	if (ret == NULL) {
		perror("frep: malloc failedn");
		return NULL;
	}
	strncpy(ret, (char *)(s + off ), (size_t)len);
	ret[len + 1] = '\0';
	return ret;
}

// treats json as a json object and retrieves key, assumes key value is also string
char *jsonstr(char *key, char *json)
{
	cJSON *jsonobj = cJSON_Parse(json);
	char *ret =  cJSON_GetObjectItemCaseSensitive(jsonobj, key)->valuestring;
	cJSON_free(jsonobj);
	return ret;

}
