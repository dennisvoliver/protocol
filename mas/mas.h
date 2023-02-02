#include "../../https/https.h"
#include <errno.h>
#include <cjson/cJSON.h>
#include <regex.h>
#define die() exit(EXIT_FAILURE)
#define serror(x,y) fprintf(stderr,(x),(y))
char *frep(char *s, char *regex);
int jsonint(char *key, char *json);
char *http_body(const char *message);
char *exacc(const char *accbody);
char *masloop(const char *client_id);
int exbox(const char *body, char **tokens);
char *xbox_auth(const char *token);
char *jsonstr(const char *key, const char *json);
int masauth(const char *client_id, char **authcodes);
char *get_acctoken(const char *client_id, char *device_code);
char *get_devcode(const char *client_id);
char *accpoll(const char *client_id, char *device_code, int interval);
char *getuhs(const char *json);
