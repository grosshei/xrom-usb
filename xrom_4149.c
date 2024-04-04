#include <stdio.h>
#include <stdlib.h>
#include <libusb.h>

#include "xrom_4149.h"
#include "usb_commands_4149.h"

#define VERBOSE 1
#define CPUCS 0x7F92
#define MAX_8051_MEM_ADDR 0x1B40

int init_xrom_4149(){
  int status = libusb_init(NULL);
  if (status < 0) {
		printf("libusb_init() failed: %s\n", libusb_error_name(status));
		return -1;
	}
	libusb_set_option(NULL, LIBUSB_OPTION_LOG_LEVEL, VERBOSE);

  libusb_device_handle *device = libusb_open_device_with_vid_pid(NULL, 0x4542, 0x4149);
  if(device == NULL){
    return 0;
  }

  unsigned int opcode = 0xA0;
  unsigned int timeout = 1000;

  printf("Initializing... \n00.0%%");

  for(int i = 0; i < usb_commands_4149_count; i++){

    printf("\b\b\b\b\b%02.1f%%", ((float)i / (float)usb_commands_4149_count) * 100);
    // printf("%02.1f%%\n", ((float)i / (float)usb_commands_4149_count) * 100);

    fflush(NULL);


    struct usb_command cmd = usb_commands_4149[i];

    unsigned char *data = calloc(cmd.len, sizeof(char));

    for(int i = 0; i < cmd.len; i++){
      sscanf(cmd.data + i * 2, "%02hhX", data + i);
    }

    status = libusb_control_transfer(device, LIBUSB_ENDPOINT_OUT | LIBUSB_REQUEST_TYPE_VENDOR | LIBUSB_RECIPIENT_DEVICE,
                                    opcode, cmd.addr & 0xFFFF, 0x0000,
                                    data, (uint16_t)cmd.len, timeout);
    if (status != (signed)cmd.len) {
      if(i >= usb_commands_4149_count - 2) continue;
      if (status < 0){
        printf("libusb error: %s\n", libusb_error_name(status));
      }
    } 
  }
  printf("\b\b\b\b\b100.0%%\nComplete.\n");

  libusb_close(device);

  //wait for usb enumeration for 4144 device
  struct timespec rqtp = {3, 0};
  nanosleep(&rqtp, NULL);
  return 1;
}