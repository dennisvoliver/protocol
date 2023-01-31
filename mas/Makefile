CC=gcc
CFLAGS=-c -I../../https.h -Wno-deprecated-declarations
LDFLAGS =   -lcurl -lssl -lcrypto   -lcjson
SOURCES=main.c mas.c
OBJECTS=$(SOURCES:.c=.o) ../../https/https.o
EXECUTABLE=a.out

all: $(SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(OBJECTS) $(LDFLAGS) -o $@

.c.o:
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -rf $(OBJECTS) $(EXECUTABLE)
