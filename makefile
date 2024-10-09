CC := gcc
CFLAGS := -Wall -O2
LDFLAGS := -lssl -lcrypto
TARGET_DIR := build

SERVER_DIR  := openssl_s
SERVER_SRCS := $(SERVER_DIR)/main.c $(SERVER_DIR)/socket_s.c
SERVER_OBJS := $(SERVER_SRCS:.c=.o)
SERVER_EXEC := server

CLIENT_DIR  := openssl_c
CLIENT_SRCS := $(CLIENT_DIR)/main.c $(CLIENT_DIR)/socket_c.c
CLIENT_OBJS := $(CLIENT_SRCS:.c=.o)
CLIENT_EXEC := client

build: server client

server: $(SERVER_OBJS)
	$(CC) $(CFLAGS) -o $(TARGET_DIR)/$(SERVER_EXEC) $(SERVER_OBJS) $(LDFLAGS)

client: $(CLIENT_OBJS)
	$(CC) $(CFLAGS) -o $(TARGET_DIR)/$(CLIENT_EXEC) $(CLIENT_OBJS) $(LDFLAGS)
	
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET_DIR)/$(SERVER_EXEC)
	rm -f $(TARGET_DIR)/$(CLIENT_EXEC)
	rm -f $(SERVER_OBJS) $(CLIENT_OBJS)
	
