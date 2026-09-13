.PHONY: all build test install uninstall clean

BIN_NAME := maccleaner
INSTALL_DIR := $(HOME)/.local/bin

all: test build

build:
	@mkdir -p bin
	go build -ldflags="-s -w" -o bin/$(BIN_NAME) ./cmd/maccleaner
	@echo "Built binary at bin/$(BIN_NAME)"

test:
	go test -v ./...

install: build
	@mkdir -p $(INSTALL_DIR)
	cp bin/$(BIN_NAME) $(INSTALL_DIR)/$(BIN_NAME)
	chmod +x $(INSTALL_DIR)/$(BIN_NAME)
	@echo "Successfully installed $(BIN_NAME) to $(INSTALL_DIR)/$(BIN_NAME)"
	@echo "You can now run '$(BIN_NAME)' from any terminal!"

uninstall:
	rm -f $(INSTALL_DIR)/$(BIN_NAME)
	@echo "Uninstalled $(BIN_NAME) from $(INSTALL_DIR)"

clean:
	rm -rf bin/
