#!/bin/sh
gcc mc.c packet.c -lz -lssl -lcrypto -luuid -lcurl cJSON/cJSON.c -o mc
