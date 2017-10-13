#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <curses.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <features.h>
#include <pthread.h>
#include <signal.h>

#define PORT 4040
#define TIMEOUT 1000
#define LISTEN_QUEUE_LIMIT 6

extern int errno;
const char *READER_ID = "00:02";
extern int errno;
int totalwladdr =0;
static int wlstatus = 0;
static int device;
/* Global functions */
struct hci_request ble_hci_request(uint16_t ocf, int clen, void * status, void * cparam)
{
	struct hci_request rq;
	memset(&rq, 0, sizeof(rq));
	rq.ogf = OGF_LE_CTL;
	rq.ocf = ocf;
	rq.cparam = cparam;
	rq.clen = clen;
	rq.rparam = status;
	rq.rlen = 1;
	return rq;
}
/* PRESCAN */
int prescan (){
  device = hci_open_dev(hci_get_route(NULL));
	if ( device < 0 ) {
		perror("Failed to open HCI device.");
		return 0;
	}
}
/* whitelist clear */
void whitelist_clr(){
  int err;
  prescan();
  err = hci_le_clear_white_list(device, TIMEOUT);
  if (err < 0) {
		err = -errno;
		fprintf(stderr, "Couldn't clear white list: %s(%d)\n",strerror(-err), -err);
		hci_close_dev(device);
    exit(1);
  }
	printf("Whitelist has been cleared\n" );
	hci_close_dev(device);
 	return ;
}
/* whitelisting */
int configure_whitelist(){
  FILE *fp;
  size_t line_size = 0;
  ssize_t read;
  char *line = malloc(sizeof(18));
	char *newBuf = (char *)malloc(17);
  bdaddr_t ba;
  int tag_count = 0,dd;
	whitelist_clr();
  if ((fp = fopen("whitelist.conf","r")) == NULL) {
      perror ("\n Failed to open file");
      hci_close_dev(device);
    	return -1;
  }
  printf("\nProcessing the Addresses\n");
  printf("************************************************************\n" );
  // whitelisting definition
  while (((read = getline(&line,&line_size,fp)) != -1 ) && !feof(fp)) {
    perror("Line read ");
    memcpy(newBuf,line,17);
		perror("memcpy ");
    printf("%s \n",newBuf );
    int ret =  str2ba(newBuf,&ba);
		perror("str2ba ");
    prescan();
    if((hci_le_add_white_list(device, &ba ,LE_PUBLIC_ADDRESS, TIMEOUT)) == -1){
			perror(" couldn't add to WL \n",newBuf,totalwladdr);
			hci_close_dev(device);
			return -1;
  	}
		totalwladdr++;
	}

	printf("************************************************************\n" );
	printf("whitelist has been successfully registered for %d Addresses \n\n",totalwladdr );
  if (line) {
    free(line);
  }
	fclose(fp);
  hci_close_dev(device);
  return 0;
}
/* BLE SCAN THREAD HANDLER */
static void *scan_le(void *client_sock)
{
    //Get the socket descriptor
	int sock = *(int*)client_sock; //Get the socket descriptor
	int read_size;
	int ret, status;
	prescan();
   // Set BLE scan parameters.
  le_set_scan_parameters_cp scan_params_cp;
  memset(&scan_params_cp, 0, sizeof(scan_params_cp));
	scan_params_cp.type 			= 0x00; //00 Passive 01 Active
	scan_params_cp.interval 		= htobs(0x0010);
	scan_params_cp.window 			= htobs(0x0010);
	scan_params_cp.own_bdaddr_type 	= 0x00; // Public Device Address (default).
  if (wlstatus == 0)
	 scan_params_cp.filter 			= 0x00; //00 Accept all.
  else
   scan_params_cp.filter 			= 0x01; //whitelist
	struct hci_request scan_params_rq = ble_hci_request(OCF_LE_SET_SCAN_PARAMETERS, LE_SET_SCAN_PARAMETERS_CP_SIZE, &status, &scan_params_cp);
	ret = hci_send_req(device, &scan_params_rq, TIMEOUT);
	if ( ret < 0 ) {
		hci_close_dev(device);
		perror("Failed to set scan parameters data.");
		exit (1);
	}
	// Set BLE events report mask.
	le_set_event_mask_cp event_mask_cp;
	memset(&event_mask_cp, 0, sizeof(le_set_event_mask_cp));
	int i = 0;
	for ( i = 0 ; i < 8 ; i++ ) event_mask_cp.mask[i] = 0xFF;

	struct hci_request set_mask_rq = ble_hci_request(OCF_LE_SET_EVENT_MASK, LE_SET_EVENT_MASK_CP_SIZE, &status, &event_mask_cp);
	ret = hci_send_req(device, &set_mask_rq, TIMEOUT);
	if ( ret < 0 ) {
		hci_close_dev(device);
		perror("Failed to set event mask.");
		exit (1);
	}
  le_set_scan_enable_cp scan_cp;
	memset(&scan_cp, 0, sizeof(scan_cp));
  scan_cp.enable 		= 0x01;	// Enable flag.
	scan_cp.filter_dup 	= 0x00; // Filtering disabled.
	struct hci_request enable_adv_rq = ble_hci_request(OCF_LE_SET_SCAN_ENABLE, LE_SET_SCAN_ENABLE_CP_SIZE, &status, &scan_cp);
	ret = hci_send_req(device, &enable_adv_rq, TIMEOUT);
	if ( ret < 0 ) {
		hci_close_dev(device);
		perror("Failed to enable scan.");
		exit (1);
	}
	// Get Results.
	struct hci_filter nf;
	hci_filter_clear(&nf);
	hci_filter_set_ptype(HCI_EVENT_PKT, &nf);
	hci_filter_set_event(EVT_LE_META_EVENT, &nf);
	if ( setsockopt(device, SOL_HCI, HCI_FILTER, &nf, sizeof(nf)) < 0 ) {
		hci_close_dev(device);
		perror("Could not set socket options\n");
		exit (1);
	}
	printf("Scanning....\n");
	uint8_t buf[HCI_MAX_EVENT_SIZE];
	evt_le_meta_event * meta_event;
	le_advertising_info * info;
	int len;
	while (sock) {
		len = read(device, buf, sizeof(buf));
		if ( len >= HCI_EVENT_HDR_SIZE ) {
			meta_event = (evt_le_meta_event*)(buf+HCI_EVENT_HDR_SIZE+1);
			if ( meta_event->subevent == EVT_LE_ADVERTISING_REPORT ) {
				uint8_t reports_count = meta_event->data[0];
				void * offset = meta_event->data + 1;
				while ( reports_count-- ) {
					info = (le_advertising_info *)offset;
					char addr[18];
					char buffer[64];
					int8_t rssi;
					int tag_type = 1;
					int tag_battery =30;
					int button_status = 0;
					int motion_status = 0;
					ba2str(&(info->bdaddr), addr);
					rssi = (int8_t)info->data[info->length];
					sprintf(buffer,"$%d,",reports_count+1);
					sprintf(buffer + strlen(buffer),"%s,",READER_ID);
					sprintf(buffer + strlen(buffer),"%d,",tag_type);
					sprintf(buffer + strlen(buffer),"%s,",addr);
					sprintf(buffer + strlen(buffer),"%d,",tag_battery);
					sprintf(buffer + strlen(buffer),"%d,",button_status);
					sprintf(buffer + strlen(buffer),"%d,",motion_status);
					sprintf(buffer + strlen(buffer),"%d#",rssi);
					printf("%s \n",buffer);
					signal(SIGPIPE, SIG_IGN);
					write(sock , buffer , sizeof(buffer));
					offset = info->data + info->length + 2;
					/*
					if(errno == EPIPE){
            memset(&scan_cp, 0, sizeof(scan_cp));
          	scan_cp.enable = 0x00;	// Disable flag.
          	struct hci_request disable_adv_rq = ble_hci_request(OCF_LE_SET_SCAN_ENABLE, LE_SET_SCAN_ENABLE_CP_SIZE, &status, &scan_cp);
          	ret = hci_send_req(device, &disable_adv_rq, 1000);
          	if ( ret < 0 ) {
          		hci_close_dev(device);
          		perror("Failed to disable scan.");
          	}
            hci_close_dev(device);
            pthread_exit(NULL);
          }
					*/
		    }
      }
    }
	}
  // Disable scanning.
    memset(&scan_cp, 0, sizeof(scan_cp));
    scan_cp.enable = 0x00;	// Disable flag.
    struct hci_request disable_adv_rq = ble_hci_request(OCF_LE_SET_SCAN_ENABLE, LE_SET_SCAN_ENABLE_CP_SIZE, &status, &scan_cp);
    ret = hci_send_req(device, &disable_adv_rq, TIMEOUT);
    if ( ret < 0 ) {
      hci_close_dev(device);
      perror("Failed to disable scan.");
			return 0;
    }
    hci_close_dev(device);
		pthread_exit(NULL);
}
/********************************************************/
int main(int argc , char *argv[])
{
	int socket_desc,client_sock,c,temp,option_value;
  char ret = '\0';
	struct sockaddr_in server,client;
  pthread_t thread_id;
	static const char *usage =
		"\nUsage :\n"
		"\tw : To Configure whitelist\n"
		"\tc : To Clear Whitelist\n"
		"\tr : To reset the HCI device\n"
		"Note:To configure whitelist store Addresses in whitelist.conf file\n";
  if ( argc > 1){
  	ret = *argv[1];
		switch (ret) {
			case 'w': wlstatus = 1;
								if ((temp = configure_whitelist()) == -1 ){
								printf("\nCouldn't configure whitelist\n" );
								exit(EXIT_FAILURE);
								}
			case 'c': whitelist_clr();
								break;
			case 'r':	system("sudo hciconfig hci0 down");
								system("sudo hciconfig hci0 up");
								perror("HCI_CONFIG reset");
								return 0;
			default:	printf("%s\n",usage );
								return 0;
		}
	}
 	//Create socket
	socket_desc = socket(AF_INET , SOCK_STREAM , 0);
  if (socket_desc == -1){
      printf("Could not create socket");
  }
  puts("Socket created");
	/* Make listening socket's port reusable */
	if (setsockopt(socket_desc, SOL_SOCKET, SO_REUSEADDR, (char *)&option_value,
							sizeof(option_value)) < 0) {
			fprintf(stderr, "setsockopt failure\n");
			exit(1);
	}
  //Prepare the sockaddr_in structure
  server.sin_family = AF_INET;
  server.sin_addr.s_addr = INADDR_ANY;
  server.sin_port = htons( PORT );
  //Bind
  if( bind(socket_desc,(struct sockaddr *)&server , sizeof(server)) < 0){
      perror("bind failed. Error");
      return 1;
  }
  puts("bind done");
  //Listen
	if (listen(socket_desc, LISTEN_QUEUE_LIMIT) < 0) {
			fprintf(stderr, "listen failed\n");
			exit(1);
	}
  //Accept and incoming connection
  puts("Waiting for incoming connections...");
  c = sizeof(struct sockaddr_in);
  while (client_sock = accept(socket_desc, (struct sockaddr *)&client, (socklen_t*)&c)){
      puts("Connection accepted");
      if( pthread_create( &thread_id , NULL ,  scan_le , (void*) &client_sock) < 0){
          perror("could not create thread");
          return 1;
      }
      puts("Handler assigned");
  }
  if (client_sock < 0){
      perror("accept failed");
      return 1;
  }
  return 0;
}
