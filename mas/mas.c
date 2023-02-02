#include "mas.h"
/*  returns http body that contains device code, user code and verification uri */
char *get_devcode(const char *client_id)
{
/* 	char scope[256]; */
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
/* 	char *device_code = jsonstr("device_code", body); */
/* 	char *device_code = jsonstr("device_code", body); */
/* 	char *user_code = jsonstr("user_code", body); */
/* 	char *verification_uri = jsonstr("verification_uri", body); */
/* 	printf("verification_uri = %s\nuser_code=%s\n", verification_uri, user_code); */
	return body;
}
char *get_acctoken(const char *client_id, char *device_code)
{
	const char fmt[] = "grant_type=urn:ietf:params:oauth:grant-type:device_code&client_id=%s&device_code=%s";
	char *payload = malloc(strlen(fmt) + strlen(client_id) + strlen(device_code) + 1);
	if (payload == NULL) {
		perror("get_acctoken: malloc");
		return NULL;
	}
	if (sprintf(payload, fmt, client_id, device_code) < 0) {
		free(payload);
		perror("get_acctoken: sprintf");
		return NULL;
	}
	char *res = https_post(payload, "https://login.microsoftonline.com/consumers/oauth2/v2.0/token", "application/x-www-form-urlencoded");
	if (res == NULL) {
		perror("get_acctoken: http_post returned NULL");
		free(payload);
		return NULL;
	}
	free(payload);
	char *body = http_body(res);
	if (body == NULL) {
		perror("get_acctoken: could not retrieve body");
		return NULL;
	}
	return body;

}
/*  removes \r\n\r\n at beginning of message */
char *http_body(const char *message)
{
/*
 	char *body = (char *)malloc(strlen(message) + 1); 
	if (body == NULL) {
		perror("http_body: can't malloc body");
		return NULL;
	}
 	char *headers = (char *)malloc(strlen(message) + 1); 
 	if ((body=frep(message, "\r\n\r\n.*$")) == NULL) { 
*/
	char *body = NULL;
	if ((body=strstr(message, "\r\n\r\n")) == NULL) {
		fprintf(stderr, "http_body: regex failed, message:\n%s", message);
		return NULL;
	}
	char *ret = (char *)malloc(strlen(body + 1));
	if (ret == NULL) {
		perror("http_body: malloc");
		return NULL;
	}
	if (strcpy(ret, (const char *)(body + 4)) == NULL) {
		perror("http_body: strcpy");
		free(ret);
		return NULL;
	}
	return ret;
}
/*  returns first string that matches regular expression */
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
/* 	perror("frep: malloc"); */
	char *ret = (char *)malloc((size_t)len + 1);
	if (ret == NULL) {
		perror("frep: malloc failed");
		return NULL;
	}
	strncpy(ret, (char *)(s + off ), (size_t)len);
	ret[len + 1] = '\0';
	return ret;
}

/*  returns value of key, treats everything as string */
char *jsonstr(const char *key, const char *json)
{
	cJSON *json_body = cJSON_Parse(json);
	if (json_body == NULL) {
		perror("jsonstr: can't parse json");
		return NULL;
	}
	cJSON *json_value = cJSON_GetObjectItemCaseSensitive(json_body, key);
	if (json_value == NULL) {
/* 		perror("jsonstr: can't find key in json object"); */
/* 		fprintf(stderr, "key=%s json=%s\n", key, json); */
		cJSON_free(json_body);
		return NULL;
	}
	char *ret = NULL;
	if (cJSON_IsNumber(json_value)) {
		ret = (char *)malloc(32);
		if (errno != 0) {
			perror("jsonstr: malloc(32)");
			ret = NULL;
		}
		if (snprintf(ret, 32, "%d", json_value->valueint) < 0) {
			perror("jsonstr: sprintf");
			ret = NULL;
		}
	} else if(cJSON_IsString(json_value)) {
		ret =  json_value->valuestring;
		if (ret == NULL) {
			perror("jsonstr: can't convert value to string");
			fprintf(stderr, "key=%s json=%s\n", key, json);
			ret = NULL;
		}
	} else {
		fprintf(stderr, "jsonstr: type unknown, key=%s json%s\n", key, json);
		ret = NULL;
	}
	cJSON_free(json_body);
	return ret;

}
int jsonint(char *key, char *json)
{
	cJSON *json_body = cJSON_Parse(json);
	if (json_body == NULL) {
		perror("jsonint: can't parse json");
		die();
	}
	cJSON *json_value = cJSON_GetObjectItemCaseSensitive(json_body, key);
	if (json_value == NULL) {
		perror("jsonint: can't find key in object");
		cJSON_free(json_body);
		die();
	}
	if (!cJSON_IsNumber(json_value)) {
		perror("jsonint: can't convert value to int");
/* 		fprintf(stderr, "key=%s json=%s\n", key, json); */
		cJSON_free(json_body);
		die();
	}
	int ret =  json_value->valueint;
	cJSON_free(json_body);
	return ret;

}
/* enum ACCERR { WAIT, DECLINED, BADCODE, EXPIRED}; */

char *accpoll(const char *client_id, char *device_code, int interval)
{
	char *body, *err;
	body = get_acctoken(client_id, device_code);
	if (body == NULL) {
		perror("accpoll: get_acctoken returned NULL");
		return NULL;
	}
	while ((err=jsonstr("error", body)) != NULL) {
		if (strcmp(err, "authorization_pending") == 0) {
/* 			fprintf(stderr, "accpoll: sleeping for %d seconds\n", interval); */
			free(body);
			sleep(interval);
			body = get_acctoken(client_id, device_code);
		} else if (strcmp(err, "authorization_declined") == 0) {
			free(body);
			perror("accpoll: authorization_declined");
			return NULL;
		} else if (strcmp(err, "bad_verification_code") == 0) {
			perror("accpoll: bad_verification_code");
			die();
		} else if (strcmp(err, "expired_token") == 0) {
			perror("accpoll: expired_token");
			free(body);
			return NULL;
		} else {
			perror("accpoll: should never get here");
			die();
		}
	}

	return body;

}
/* extract access_token from accpoll() */
char *exacc(const char *accbody)
{
	char *token = jsonstr("access_token", accbody);
	if (token == NULL) {
		perror("exacc: can't find access_token from json");
		return NULL;
	}
	return token;

}
int masauth(const char *client_id, char **authcodes)
{
	char *body = get_devcode(client_id);
	if (body == NULL) {
		perror("main: can't get devcode");
		return -1;
	}
	char *device_code = jsonstr("device_code", body);
	char *user_code = jsonstr("user_code", body);
	char *verification_uri = jsonstr("verification_uri", body);
	char *expires_in = jsonstr("expires_in", body);
	char *interval = jsonstr("interval", body);
	authcodes[0] = device_code;
	authcodes[1] = user_code;
	authcodes[2] = verification_uri;
	authcodes[3] = expires_in;
	authcodes[4] = interval;
/*
	int expires_in = jsonint("expires_in", body);
	if (sprintf(authcodes[3], "%d", expires_in) < 0) {
		perror("masauth: can't convert expires_in");
		die();
	}
	if (sprintf(authcodes[4], "%d", jsonint("interval", body)) < 0) {
	authcodes[5] = jsonstr("message", body);
		perror("masauth: sprintf interval");
		die();
	}
*/
	return 0;
}
/* authenticate in xboxlive, token is the access_token from oauth */
char *xbox_auth(const char *token)
{
	char fmt[] = "{\"Properties\":{\"AuthMethod\":\"RPS\",\"SiteName\":\"user.auth.xboxlive.com\",\"RpsTicket\":\"d=%s\"},\"RelyingParty\":\"http://auth.xboxlive.com\",\"TokenType\":\"JWT\"}";
	char *body = (char *)malloc(strlen(token) + strlen(fmt) + 1);
	if (body == NULL) {
		perror("xbox_auth: malloc");
		return NULL;
	}
	if (sprintf(body, fmt, token) < 0) {
		perror("xbox_auth: sprintf");
		free(body);
		return NULL;

	}
	const char url[] = "https://user.auth.xboxlive.com/user/authenticate";
	char *res = https_post(body, url, "application/json");
	if (res == NULL) {
		perror("xbox_auth: https_post");
		free(body);
		return NULL;

	}
	free(body);
	if ((body=http_body(res)) == NULL) {
		perror("xbox_auth: http_body");
		free(res);
		return NULL;
	}
	return body;
}
/* extract token and user hash from json body response of xbox live auth
 * tokens[0] is the token, tokens[1] is the user hash
 * returns 0 for success
 * < 0 for error
 */
int exbox(const char *body, char **tokens)
{

	char *token = jsonstr("Token", body);
	if (token == NULL) {
		perror("exbox: can't extract token");
		return -1;
	}
	char *hash = getuhs(body);
	if (hash == NULL) {
		perror("exbox: getuhs");
		free(token);
		return -1;
	}
	tokens[0] = token;
	tokens[1] = hash;
	return 0;
}
/* will perform the microsoft oauth process, returns json string with access token */
char *masloop(const char *client_id)
{

	char *authcodes[6];
	char *user_code, *verification_uri, *device_code;
	char *accbody;
	int interval;
	int expires_in = 300;
	do {
		if (masauth(client_id, authcodes) != 0) {
			return NULL;
		}
		device_code = authcodes[0];
		user_code = authcodes[1];
		verification_uri = authcodes[2];
		fprintf(stderr, "masloop verification_uri=%s user_code=%s\n", verification_uri, user_code);
		interval = strtol(authcodes[4],  NULL, 10);
		if (errno != 0) {
			perror("masloop strtol");
			interval = 10;
		}
		expires_in = strtol(authcodes[3],  NULL, 10);
		if (errno != 0) {
			perror("masloop strtol");
			expires_in = 300;
		}
		perror("masloop: polling");
	} while ((accbody=accpoll(client_id, device_code, interval)) == NULL);
	return accbody;
}
char *getuhs(const char *json)
{
	char *claim = jsonstr("DisplayClaims", json);
	if (claim == NULL) {
		perror("can't extract DisplayClaims");
		return NULL;
	}
	cJSON *claimj = cJSON_Parse(claim);
	if (claimj == NULL) {
		perror("getuhs: can't parse claim");
		cJSON_Delete(claimj);
		return NULL;
	}
	cJSON *xui = cJSON_GetObjectItemCaseSensitive(claimj, "xui");
	if (!cJSON_IsArray(xui)) {
		perror("getuhs: gen't get xui");
		cJSON_Delete(claimj);
		return NULL;
	}
	cJSON *uhso = cJSON_GetArrayItem(xui, 0);
	if (!cJSON_IsObject(uhso)) {
		perror("getuhs: getarray xui");
		cJSON_Delete(claimj);
		return NULL;
	}
	cJSON *uhss = cJSON_GetObjectItem(uhso, "uhs");
	if (!cJSON_IsString(uhss)) {
		perror("can't extract string uhs from object");
		cJSON_Delete(claimj);
		return NULL;
	}
	if (uhss->valuestring == NULL) {
		perror("uhs value string null");
		cJSON_Delete(claimj);
		return NULL;
	}
	return uhss->valuestring;
}
