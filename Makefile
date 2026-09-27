# Makefile for LIM WAF

APP_NAME = lim-waf
VERSION ?= $(shell git describe --tags --always --dirty)
BUILD_DIR = build
GO_FILES = $(shell find . -name '*.go')

# Build targets
.PHONY: all build build-stresstest clean install release

all: build

build: $(BUILD_DIR)/$(APP_NAME)

$(BUILD_DIR)/$(APP_NAME): $(GO_FILES)
	@echo "Building $(APP_NAME)..."
	@mkdir -p $(BUILD_DIR)
	go build -o $@ -ldflags="-X main.Version=$(VERSION)" ./cmd/lim-waf

build-stresstest: $(GO_FILES)
	@echo "Building lim-stresstest..."
	@mkdir -p $(BUILD_DIR)
	go build -o $(BUILD_DIR)/lim-stresstest ./cmd/lim-stresstest

clean:
	@echo "Cleaning up..."
	@rm -rf $(BUILD_DIR)
	@go clean


install: build
	@echo "Installing to /usr/local/bin..."
	@sudo cp $(BUILD_DIR)/$(APP_NAME) /usr/local/bin/$(APP_NAME)

release:
	@echo "Building release for Linux AMD64..."
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 go build -o $(BUILD_DIR)/$(APP_NAME)-linux-amd64 -ldflags="-X main.Version=$(VERSION)" ./cmd/lim-waf
	@echo "Release build complete."
