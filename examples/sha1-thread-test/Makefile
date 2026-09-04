AMLC=amlc.jar
CMD=java -jar $(AMLC)

UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)
ifeq ($(UNAME_S),Darwin)
  ifeq ($(UNAME_M),arm64)
    HOST_BT := macos-arm
  else
    HOST_BT := macos
  endif
else
  HOST_BT := linux-x64
endif

build:
	$(CMD) build . -bt $(HOST_BT)

build-force-deps:
	$(CMD) build . -fld -bt $(HOST_BT)

build-amigaos:
	$(CMD) build . -bt amigaos_docker -ll5

run: build
	./builds/bin/$(HOST_BT)/app
