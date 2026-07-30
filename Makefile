CC ?= cc
BUILD_DIR ?= build
CFLAGS ?= -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2
WARN_FLAGS = -Wall -Wextra -Werror
OPENSSL_FLAGS = $(shell pkg-config --cflags --libs openssl)
COMMON_FLAGS = $(CFLAGS) $(WARN_FLAGS)

COMMON_UTILS = Utils/socketUtil.c Utils/sha256.c Utils/aes.c Utils/identity.c \
	Utils/tls.c Utils/platform.c Utils/protocol.c
CLIENT_UTILS = $(COMMON_UTILS) Utils/contacts.c Utils/ecdh.c Utils/history.c
HEADERS = $(wildcard Utils/*.h)

.PHONY: all test unit smoke sanitize clean

all: $(BUILD_DIR)/server $(BUILD_DIR)/client $(BUILD_DIR)/client_tui

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/server: Server/server.c $(COMMON_UTILS) Utils/session.c $(HEADERS) | $(BUILD_DIR)
	$(CC) $(COMMON_FLAGS) Server/server.c $(COMMON_UTILS) Utils/session.c \
		-o $@ $(OPENSSL_FLAGS) -lpthread

$(BUILD_DIR)/client: Client/client.c $(CLIENT_UTILS) $(HEADERS) | $(BUILD_DIR)
	$(CC) $(COMMON_FLAGS) Client/client.c $(CLIENT_UTILS) -o $@ $(OPENSSL_FLAGS) -lpthread

$(BUILD_DIR)/client_tui: Client/client_tui.c $(CLIENT_UTILS) $(HEADERS) | $(BUILD_DIR)
	$(CC) $(COMMON_FLAGS) Client/client_tui.c $(CLIENT_UTILS) -o $@ $(OPENSSL_FLAGS) -lpthread

$(BUILD_DIR)/unit_security: tests/unit_security.c Utils/socketUtil.c \
	Utils/platform.c Utils/protocol.c Utils/aes.c Utils/sha256.c $(HEADERS) | $(BUILD_DIR)
	$(CC) $(COMMON_FLAGS) tests/unit_security.c Utils/socketUtil.c \
		Utils/platform.c Utils/protocol.c Utils/aes.c Utils/sha256.c \
		-o $@ $(OPENSSL_FLAGS) -lpthread

unit: $(BUILD_DIR)/unit_security
	$(BUILD_DIR)/unit_security

smoke:
	./tests/smoke_cli.sh

test: unit smoke

sanitize: | $(BUILD_DIR)
	$(CC) -O1 -g $(WARN_FLAGS) -fsanitize=address,undefined \
		tests/unit_security.c Utils/socketUtil.c Utils/platform.c \
		Utils/protocol.c Utils/aes.c Utils/sha256.c \
		-o $(BUILD_DIR)/unit_security_sanitize $(OPENSSL_FLAGS) -lpthread
	$(BUILD_DIR)/unit_security_sanitize

clean:
	rm -rf $(BUILD_DIR)
