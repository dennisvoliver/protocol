#!/bin/sh
gcc mc.c packet.c -Wno-deprecated-declarations -lz -lssl -lcrypto -luuid -lcurl cJSON/cJSON.c -o mc  2>&1 | more && ./mc a a a
