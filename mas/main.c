#include <stdio.h>
#include "mas.h"
int main(int argc, char *argv[])
{
	char client_id[] = "feb3836f-0333-4185-8eb9-4cbf0498f947";
	char *devcode = get_devcode(client_id);
	if (devcode == NULL) {
		perror("main: can't get devcode\n");
		return -1;
	}
	char *device_code = jsonstr("device_code", body);
	char *user_code = jsonstr("user_code", body);
	char *verification_uri = jsonstr("verification_uri", body);
	printf("verification_uri = %s\nuser_code=%s\n", verification_uri, user_code);
	return 0;

}
