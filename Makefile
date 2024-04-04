CFLAGS+=-g $(shell pkg-config --cflags libusb-1.0)
LDFLAGS+=$(shell pkg-config --libs libusb-1.0)

xrom-usb: xrom-usb.c gba_multiboot.o xrom_4149.o
