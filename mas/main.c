#include <stdio.h>
#include "mas.h"
char *getatok(const char *client_id);
int main(int argc, char *argv[])
{

/*
	char client_id[] = "feb3836f-0333-4185-8eb9-4cbf0498f947";
	char *acctok = getatok(client_id);
	if (acctok == NULL) {
		perror("main: getatok");
		return -1;
	}
	printf("%s", acctok);
	return 0;
*/
	char acctok[] = "EwAoA+pvBAAUKods63Ys1fGlwiccIFJ+qE1hANsAAUGIWSvscEV7Gk92TcxgVjF++phniYFYaD6dzt+E5xEryQU/fwSG20Wskqxwil3f32PN1HVMJd6rOABzUCR3G3vv5YM/iN6WK6/KtyoM5p7k4fLJ9gZn1ZZxpqynf7VqlMhKLi7M1h5MBuoS4h+6CE8J9Fw4vYC9DMiW8GdUpgFZzaEp7OBLbF/5iUfqX21VEKloI6KaKT/9ZF6QRwDOSkYwN1WIMInjXZt5C6YjnYIenUTz93CPxk4+iXDBkxNKl9wX/n/zSmvigHNf4GeNQIrZ7y1YSXa6F0MJdHEnEkttM78UTAI5jI8Yg6ZYX2e1hHEaMBZg+Za8S0eqmZe0ID8DZgAACGNoTfZ8tKK8+AE3KLJsDcsGuKoX95xZ2o6ymUM+tyI3SVYPWVAzE2XHsB1e+tz0vtPjuxxQ4v8Smy+FEP2iGURUqKvjda1pcV8bPHOXIEjEaLE08+a+Ze4oLjJn87Vsx8CTVF2dXtHdWFXE8x9yY9i/2FR6ir5DFFBSzNyApMiYieH+7OE3j2K03odpJasVoW4L1JUO+hM6gbnTtXCzXnLoOsGU9euwVJAfYcXTQiMIeUqcVwsRni88N28Q2Cs5Cym047oRwSPUkglBDtRqm/4+ZJlpOYEIsZFR95jXbdU88+yPwTMb6DPBJ6WjzCExWNvxAX+6WOHk48gG2NxyOpDR5URq7i1/fXKbyp6DA9LPoQVyNWE0z8MHna4fx+W2m+FvQhmSoR1hxLjw6lN7pt1OUqjMExypskdOl9JcxAAGMJPR+53MwVQ0W9nzj2vH6d4wMK2IIdFaH7YFaJdm0KHVrxnmMvVMZrCiJTmNkcNKXOcj8w8QsiLrz2+IR1sY56flGUVEgWSNkHEH0Zo2pNwaiCIk+yIXz+7hslBs9h7K7ZBxVUMpJJb7DyOzjq6dvr2bDothnSW7TmHahr/mAwgULBaI59KsmFh3AXG7WHbjWWaD7gQgyFUpgxKH1QpzmC3zP84q9s/3EWdSyevjLFwAA/RopShcURIE2vGjCkfnqwcnAg==";
	char *xbody = xbox_auth(acctok);
/* 	free(acctok); */
	if (xbody == NULL) {
		perror("masloop xbox_auth fail");
		return -1;
	}
	char *tokens[2];
	if (exbox(xbody, tokens) != 0) {
		perror("main: exbox");
		free(xbody);
		return -1;
	}
	printf("xbox_token=%suser_hash=%s\n", tokens[0], tokens[1]);
	return 0;
}
char *getatok(const char *client_id)
{
	char *accbody = masloop(client_id);
	if (accbody == NULL) {
		perror("getatok: masloop");
		return NULL;
	}
	char *acctok = exacc(accbody);
	free(accbody);
	if (acctok == NULL) {
		perror("getatok: masloop can't extract access token from accbody");
		return NULL;
	}
	return acctok;
}
