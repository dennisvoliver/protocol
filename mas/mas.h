#include "../../https/https.h"
#include <cjson/cJSON.h>
#include <regex.h>
char *get_devcode(char *client_id);
char *http_body(char *message);
char *frep(char *s, char *regex);
char *jsonstr(char *key, char *json);
char *get_acctoken(char *client_id, char *device_code);
