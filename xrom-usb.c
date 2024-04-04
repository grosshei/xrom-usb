#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libusb.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <errno.h>


// #include "usbcable_payload2.h"
#include "gba_multiboot.h"
// #include "usbcable_rom.h"
#include "xrom_4149.h"


// bEndpointAddress     0x82  EP 2 IN
#define BULK_EP_IN 0x82
// bEndpointAddress     0x02  EP 2 OUT
#define BULK_EP_OUT 0x02

//verbose global
int verbose = 1;


void asprintf_hex(char **ret, unsigned char *data, size_t len){
  char *string = calloc((len * 2) + 1, sizeof(char));
  for(int i = 0; i < len; i++){
    snprintf(string + (i * 2), 3, "%02hhx", data[i]);
//      printf("[%02hhx]", data[i]);
  }
//    printf("\n");
  *ret = string;
}
void send_only_bytes(libusb_device_handle *device, unsigned char *send_data, size_t send_data_len){
    int status;

    char *printable_hex_to_send;
    asprintf_hex(&printable_hex_to_send, send_data, send_data_len);
    if(verbose == 2) printf("-> %s\n", printable_hex_to_send);

    //send usb
    int xfer_out_len;
    status = libusb_bulk_transfer(device, LIBUSB_ENDPOINT_OUT | 02, send_data, send_data_len, &xfer_out_len, 500);      
    if(status == -7){ 
      printf("not sent\n");
      return; 
    }
    if (status != 0) {
      printf("usb error: %d - %s\n", status, libusb_error_name(status));
      printf("that's all for now.\n");
      exit(-1);
    }
}

//return xfer len from device
int send_and_get_bytes(libusb_device_handle *device, unsigned char *send_data, size_t send_data_len, unsigned char **result_data){
    int status;

    char *printable_hex_to_send;
    asprintf_hex(&printable_hex_to_send, send_data, send_data_len);
    if(verbose == 2) printf("-> %s\n", printable_hex_to_send);

    //send usb
    int xfer_out_len;
    status = libusb_bulk_transfer(device, LIBUSB_ENDPOINT_OUT | 02, send_data, send_data_len, &xfer_out_len, 500);      
    if(status == -7){ 
      printf("not sent\n");
      return 0; 
    }
    if (status != 0) {
      printf("usb error: %d - %s\n", status, libusb_error_name(status));
      printf("that's all for now.\n");
      exit(-1);
    }

    unsigned char *usb_data_from_device = calloc(64, sizeof(char));
    int xfer_in_len = 0;
    
    //get data from device
    status = libusb_bulk_transfer(device, LIBUSB_ENDPOINT_IN | 0x82, usb_data_from_device, 64, &xfer_in_len, 1000);
    if (status != 0) {
      printf("usb error: %d - %s\n", status, libusb_error_name(status));
    }
    if(status == -7){
      printf("read timeout\n");
      return 0;
    }

    //print result
    char *printable_hex_from_device;
    asprintf_hex(&printable_hex_from_device, usb_data_from_device, (size_t)xfer_in_len);
    if(verbose == 2) printf("<- %s\n", printable_hex_from_device);

    *result_data = usb_data_from_device;
    return xfer_in_len;
}

//return output len
int send_and_get_string(libusb_device_handle *device, char *input, size_t input_len, char **output){
    int status;
    
//     if(verbose) printf("-> %s\n", input);

    unsigned char *usb_data = calloc(64, sizeof(char));
    size_t usb_data_len = 0;
    for(int i = 0; i < (input_len) / 2; i++, usb_data_len++){
      sscanf(input + i * 2, "%02hhx", usb_data + i);
    }
    
    //double check data correctly parsed? 
    char *printable_hex_to_send;
    asprintf_hex(&printable_hex_to_send, usb_data, usb_data_len);
    if(verbose == 2) printf("-> %s\n", printable_hex_to_send);

    //send usb
    int xfer_out_len;
    status = libusb_bulk_transfer(device, LIBUSB_ENDPOINT_OUT | 02, usb_data, usb_data_len, &xfer_out_len, 500);      
    if(status == -7){ 
      printf("not sent\n");
      return 0; 
    }
    if (status != 0) {
      printf("usb error: %d - %s\n", status, libusb_error_name(status));
      printf("that's all for now.\n");
      exit(-1);
    }
    
    free(usb_data);
    
    unsigned char *usb_data_from_device = calloc(64, sizeof(char));
    int xfer_in_len = 0;
    
    //wait
    struct timespec rqtp = {0, 1e7};
    nanosleep(&rqtp, NULL);
    
    //get data from device
    status = libusb_bulk_transfer(device, LIBUSB_ENDPOINT_IN | 0x82, usb_data_from_device, 64, &xfer_in_len, 1000);
    if (status != 0) {
      printf("usb error: %d - %s\n", status, libusb_error_name(status));
    }
    if(status == -7){
      printf("read timeout\n");
      return 0;
    }
    
//     printf("rresponse:[%d] '%s'\n", xfer_in_len, usb_data_from_device);
//     printf("[%x][%x][%x][%x][%x]", usb_data_from_device[0], usb_data_from_device[1], usb_data_from_device[2], usb_data_from_device[3], usb_data_from_device[4]);
    
    //print 
    char *printable_hex_from_device;
    asprintf_hex(&printable_hex_from_device, usb_data_from_device, (size_t)xfer_in_len);
//     printf("response: [%d] '%s'\n", xfer_in_len, printable_hex_from_device);
    if(verbose == 2) printf("<- %s\n", printable_hex_from_device);
    
    
    *output = printable_hex_from_device;
    
//     free(printable_hex_from_device);
    free(usb_data_from_device);

    return xfer_in_len;
}

unsigned char CLIENT_OKAY[] = {0x01, 0x02, 0x72};

int xrom_multiboot(libusb_device_handle *device, FILE *multiboot_file){
 
  size_t multiboot_file_len = 0;
  unsigned char *multiboot_file_data;
  if(multiboot_file){
    printf("Sending requested multiboot\n");

    struct stat mb_stat;
    int rc = fstat(fileno(multiboot_file), &mb_stat);
    if(rc != 0){
      printf("Cannot get size of file\n");
      exit(-1);
    }
    multiboot_file_len = mb_stat.st_size;

    //Add extra space for padding to multiple of 16 bytes
    multiboot_file_data = calloc(multiboot_file_len + 0xf, 1);
    fread(multiboot_file_data, multiboot_file_len, 1, multiboot_file);

  }else{
    // printf("Sending default multiboot\n");
    // multiboot_file_len = usbcable_payload2_bin_len;
    // multiboot_file_data = usbcable_payload2_bin;
    exit(-1);
  }

  //amount of time to send to nanosleep() anytime we need to wait for a device
  struct timespec wait_time = {0, 1e6}; //1e6 nanoseconds = 1 milliseconds

  char *getversion = "01";
  char *result;
  send_and_get_string(device, getversion, strlen(getversion), &result);



  
  //maybe asking if 'XROM OS' is installed/available?
  for(int i = 0; i < 3; i++){
    char *getstatus = "0455aa0006";
    send_and_get_string(device, getstatus, strlen(getstatus), &result);
  }

  int failsafe = 0;
  do{
    char *asktocontinue = "020262";
    send_and_get_string(device, asktocontinue, strlen(asktocontinue), &result);
    nanosleep(&wait_time, NULL);
    failsafe++;
  }while(strncmp(result, "010272", strlen("010272")) != 0 && failsafe < 100);
  
  //020061 #of packets? 0x61 * 2 = 0xc2 bytes = c0 of header + 1 extra packet?
  send_and_get_string(device, "020061", strlen("020061"), &result);
  
  unsigned char *result_bytes;
  size_t result_len;

  //send gba header 0x00..0xc0
  for(int i = 0; i < 0xc0; i+=2){
    unsigned char packet[] = {0x02, multiboot_file_data[i], multiboot_file_data[i+1]};
    result_len = send_and_get_bytes(device, packet, 3, &result_bytes);
  }

  // //usbcable.exe seems to send the same 4 bytes, instead of first 4 of header
  // // doing this doesn't fix things, though
  // //020102
  // unsigned char packet00[] = {0x02, 0x01, 0x02};
  // result_len = send_and_get_bytes(device, packet00, 3, &result_bytes);

  // //0260ea
  // unsigned char packet01[] = {0x02, 0x60, 0xea};
  // result_len = send_and_get_bytes(device, packet01, 3, &result_bytes);

  // //send gba header 0x00..0xc0
  // for(int i = 4; i < 0xc0; i+=2){
  //   unsigned char packet[] = {0x02, multiboot_file_data[i], multiboot_file_data[i+1]};
  //   result_len = send_and_get_bytes(device, packet, 3, &result_bytes);
  // }


  //010201 //response to last packet of header

  unsigned char header_complete[] = {0x02, 0x02, 0x62};
  result_len = send_and_get_bytes(device, header_complete, 3, &result_bytes);

  unsigned char *secrets[4];
  //send c163, begin multiboot transfer, device should respond clientok (010272)
  unsigned char begin_multiboot_transfer[] = {0x02, 0xc1, 0x63};
  result_len = send_and_get_bytes(device, begin_multiboot_transfer, 3, &result_bytes);

  //send c163, again, then device will send first "secret" packet
  result_len = send_and_get_bytes(device, begin_multiboot_transfer, 3, &secrets[0]);

  //add 0x0f to middle byte, and respond 0x02XX64
  // unsigned char secret_response = {0x02, (secrets[0][1] + 0x0f), 0x73};
  secrets[1] = (unsigned char[]){0x02, (secrets[0][1] + 0x0f), 0x64};
  result_len = send_and_get_bytes(device, secrets[1], 3, &secrets[2]);


  //wait
  nanosleep(&wait_time, NULL);  

  // size_t send_end = ((multiboot_file_len) + 0x0f) & ~0xf;
  //if necessary, pad to multiple of 16
  size_t send_end = multiboot_file_len + (16 - (multiboot_file_len % 16) ) % 16;



  //respond with 023400 (length of payload2 that will be sent)
  uint32_t payload2_computed_len = ((((multiboot_file_len) + 0xf & 0xfffffff0) - 0xc0) >> 2) - 0x34;
  // uint32_t payload2_computed_len = (send_len >> 2) - 0x34;

  unsigned char len_high = (payload2_computed_len >> 8) & 0xff;
  unsigned char len_low = payload2_computed_len & 0xff;

  unsigned char payload2_len_packet[] = {0x02, len_low, len_high};
  result_len = send_and_get_bytes(device, payload2_len_packet, 3, &secrets[3]);

  //begin payload2 sending loop

  // uint32_t original_key = 0x720273bd;
  uint32_t original_key = secrets[0][1];
  uint32_t key = setup_key(original_key);

  uint32_t crc = CRC_MAGIC_1;
  unsigned char last;

  //start at 0xc0 of payload aka skip 192 bytes or exact size of GBA header
  //payload size = 0x254 (596)
  //4144_2.bin size = 0x1A2 (418)
  //payload2 0x254 - 0xc0 offset = 0x194 (404)  = 0xE(14) overcapture of 7 extra packets? 

  // payload 2 starts at 0xc0, after its GBA header
  for(size_t i = 0xc0; i < send_end; i+=4){
      
      //rotate the key or something
      key = next_key(key);
      unsigned char *encoded_bytes;
      encode_payload_4bytes(key, i, &multiboot_file_data[i], &encoded_bytes);
      crc = crc_step(crc, data_to_int(&multiboot_file_data[i]));


      // printf("02%02hhx%02hhx\n", encoded_bytes[0], encoded_bytes[1]);
      // printf("02%02hhx%02hhx\n", encoded_bytes[2], encoded_bytes[3]);

      unsigned char packet1[] = {0x02, encoded_bytes[0], encoded_bytes[1]};
      result_len = send_and_get_bytes(device, packet1, 3, &result_bytes);

      if (result_bytes[1] != (i & 0xff)) {
          printf("payload 2 failure at byte %02zx : %02hhx\n", i, result_bytes[1]);
          // exit(-1);
      }

      unsigned char packet2[] = {0x02, encoded_bytes[2], encoded_bytes[3]};
      result_len = send_and_get_bytes(device, packet2, 3, &result_bytes);



      if (result_bytes[1] != (i & 0xff) + 2) {
          printf("payload 2 failure at byte %02zx : %02hhx\n", i+2, result_bytes[1]);
          // exit(-1);
      }

      // printf("crc: %08x\n", crc);
      printf("crc: %x\n", crc);
      fflush(NULL);
      // last = result_bytes[2];
  }

  printf("penultimate crc: %08x\n", crc);
  printf("file sz? %zu\n", multiboot_file_len);
  fflush(NULL);


  //finalize CRC
  crc = crc_step(crc, 0xFFFF0000 | ((((uint32_t)secrets[0][1] + 0x0f)) & 0xff) | (secrets[3][1]) << 8);

  //wait for checksum
  unsigned char waiting_for_checksum_packet[] = {0x02, 0x65, 0x00};
  do{
    result_len = send_and_get_bytes(device, waiting_for_checksum_packet, 3, &result_bytes);
    nanosleep(&wait_time, NULL);
  }while((result_bytes[1] != 0x75) || (result_bytes[2] != 0x00));

  unsigned char checksum_is_next_packet[] = {0x02, 0x66, 0x00};
  result_len = send_and_get_bytes(device, checksum_is_next_packet, 3, &result_bytes);


  printf("final crc: %08x\n", crc);
  fflush(NULL);


  unsigned char checksum_packet[] = {0x02, crc & 0xff, (crc >> 8) & 0xff};
  result_len = send_and_get_bytes(device, checksum_packet, 3, &result_bytes);

  printf("CRC check ours: %02hhx%02hhx device: %02hhx%02hhx\n",
         crc & 0xff, (crc >> 8) & 0xff, result_bytes[1], result_bytes[2]);

  if((crc & 0xff) != result_bytes[1] ||  ((crc >> 8) & 0xff) != result_bytes[2]){
    printf("Error CRC mismatch, exiting.\n");
    exit(-1);
  }else{
    return 1;
  }

}

/*
int xrom_fastload(libusb_device_handle *device, FILE *multiboot_file){

size_t multiboot_file_len = 0;
unsigned char *multiboot_file_data;
if(multiboot_file){
  printf("Sending requested multiboot\n");

  struct stat mb_stat;
  int rc = fstat(fileno(multiboot_file), &mb_stat);
  if(rc != 0){
    printf("Cannot get size of file\n");
    exit(-1);
  }
  multiboot_file_len = mb_stat.st_size;

  }else{
    printf("Sending default xrom os\n");
    multiboot_file_len = usbcable_rom_gba_len;
  }

  //xromos_rom_len  is 0x24C0 (9408) 

  char *result;
  unsigned char *result_bytes;
  size_t result_len;
  struct timespec wait_time = {0, 1e6}; //1e6 nanoseconds = 1 milliseconds



  //wait until ready 030600aa55
  //0111406325
  // unsigned char fastloader_ready_response[] = {0x01, 0xff, 0xff, 0xff, 0xff};
  // unsigned char fastloader_ready_response[] = {0x01, 0x01, 0x34, 0x56, 0x12};
  unsigned char wait_for_fastloader[] = {0x03, 0x06, 0x00, 0xaa, 0x55};
  do{
    result_len = send_and_get_bytes(device, wait_for_fastloader, 5, &result_bytes);
    nanosleep(&wait_time, NULL);  
  // }while((result_bytes[3] == 0xff) && (result_bytes[4] == 0xff));
  // }while(memcmp(result_bytes, fastloader_ready_response, 5) != 0);
  }while(result_bytes[1] == 0xff);

  // host	030600aa55 //wait for fastloader
  // 0.5.2	0101345612

  //once more, then continue
  result_len = send_and_get_bytes(device, wait_for_fastloader, 5, &result_bytes);

  char *a, *b;
  asprintf_hex(&a, result_bytes, 5);
  // asprintf_hex(&b, fastloader_ready_response, 5);

  printf("fastloader ready: %s %s\n", a, b);

//expected                  actual
// host	  030600aa55   // -> 030600aa55
// 0.5.2	0101345612   // <- 014904d058
// host	  0455990002   // -> 0455990002
// 0.5.2	0112563401   // <- 0158d00412
// host	  0403001000   // -> 0403001000
// 0.5.2	0112563402   // <- 0156340112
// host	  0400000930   // -> 0400000930
// 0.5.2	0103001000   // <- 0156340112
// host	  06009300   // -> 06009300


// 0112563401

  //xromos_rom_len  is 0x24C0 (9408) 

  // host	0455990002
  // 0.5.2	0112563401
  send_and_get_string(device, "0455990002", strlen("0455990002"), &result);

  // host	0403001000
  // 0.5.2	0112563402
  send_and_get_string(device, "0403001000", strlen("0403001000"), &result);

  // host	0400000930
  // 0.5.2	0103001000
  // send_and_get_string(device, "0400000930", strlen("0400000930"), &result);
  // mb_len >> 2 ? 
  uint32_t computer_rom_len_a = multiboot_file_len >> 2;
  unsigned char computed_rom_len_packet_a[] = {0x04,
                                          (computer_rom_len_a & 0x00ff0000) >> 24,
                                          (computer_rom_len_a & 0x00ff0000) >> 16,
                                          (computer_rom_len_a & 0x0000ff00) >> 8,
                                          (computer_rom_len_a & 0x000000ff) >> 0,
                                          };
  send_and_get_bytes(device, computed_rom_len_packet_a, 5, &result_bytes);


  // host	06009300
  //send 06 (gba_len * 4)
  uint32_t computed_rom_len = multiboot_file_len * 4;
  unsigned char computed_rom_len_packet[] = {0x06,
                                            (computed_rom_len & 0x00ff0000) >> 16,
                                            (computed_rom_len & 0x0000ff00) >> 8,
                                            (computed_rom_len & 0x000000ff) >> 0,
                                            };

  send_only_bytes(device, computed_rom_len_packet, 4);

  // host	2e0000ea24ffae51699aa2213d8
  //start sending large gba, full 64 bytes per packet
  unsigned char usbbuf[64];
  for(size_t i = 0; i < multiboot_file_len; i+=64){

    struct timespec waiterman = {0, 1e7}; //1e6 nanoseconds = 1 milliseconds
    nanosleep(&waiterman, NULL);



    size_t last_packet_len = multiboot_file_len - i; 
    if(last_packet_len <= 64){
      if(multiboot_file){
        fread(usbbuf, last_packet_len, 1, multiboot_file);
        result_len = send_and_get_bytes(device, usbbuf, last_packet_len, &result_bytes);
      }else{
        result_len = send_and_get_bytes(device, &usbcable_rom_gba[i], last_packet_len, &result_bytes);
      }
    }else{
      //not last packet, only send
      if(multiboot_file){
        fread(usbbuf, 64, 1, multiboot_file);
        send_only_bytes(device, usbbuf, 64);
      }else{
        send_only_bytes(device, &usbcable_rom_gba[i], 64);
      }
    }
  }

  if(result_bytes[0] == 0x30){
    printf("gba 'XROM OS' payload complete\n");
  }

  //send 0455990003, recv 010078cc1c and "XROM OS" should appear on screen
  send_and_get_string(device, "0455990003", strlen("0455990003"), &result);

  //now what?



  return 1;
}
*/

int main(int argc, char **argv) {

  int status;
	libusb_device_handle *device = NULL;



	status = libusb_init(NULL);
	if (status < 0) {
		printf("libusb_init() failed: %s\n", libusb_error_name(status));
		return -1;
	}
	libusb_set_option(NULL, LIBUSB_OPTION_LOG_LEVEL, verbose);
	
  device = libusb_open_device_with_vid_pid(NULL, 0x4542, 0x4144);
  if(device == NULL){
    libusb_close(device);
    //look for uninitialized device
    if(init_xrom_4149() <= 0){
      printf("Cannot find either XROM device (4542:4144 or 4542:4149)\n");
      exit(-1);
    }
  }

  //init_xrom_4149() succeeded, try again  
  device = libusb_open_device_with_vid_pid(NULL, 0x4542, 0x4144);
  if(device == NULL){
    printf("Cannot find XROM LinkPort device (4542:4144)\n");
    exit(-1);
  }
  
  if(libusb_kernel_driver_active(device, 0) == 1){
    printf("\nKernel Driver Active\n");
    if(libusb_detach_kernel_driver(device, 0) == 0)
        printf("\nKernel Driver Detached!\n");
    else
    {
        printf("\nCouldn't detach kernel driver!\n");
    }
  }else{
    printf("no kernel driver active\n");
  }
  
  
  if(libusb_claim_interface(device, 1) < 0){
      printf("\nCannot Claim Interface");
  }
  else printf("\nClaimed Interface\n");
  
//       //wait
//     struct timespec rqtp = {1, 0};
//     nanosleep(&rqtp, NULL);
  
  printf("ok\n");
  
  // xrom_multiboot(device, NULL);

  FILE *multiboot_file = fopen(argv[1], "r");
  xrom_multiboot(device, multiboot_file);
  // xrom_multiboot(device, NULL);

  // xrom_fastload(device, multiboot_file);
  
  exit(0);
  
  //an interactive mode
  for(;;){

    ssize_t input_len = 0;
    char *input = NULL;
    size_t cap = 0;
    printf("> ");
    fflush(NULL);
    input_len = getline(&input, &cap, stdin);
    input[--input_len] = 0x0;
    
    char *result;
    send_and_get_string(device, input, input_len, &result);
    printf(">>>%s<<<\n", result);
  }

  return 0;
}