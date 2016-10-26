GIT_VERSION := $(shell git describe --abbrev=40 --long --dirty --always --tags)

all:
	gcc -O2 -DVERSION=\"$(GIT_VERSION)\" -o init -static grimes.c
