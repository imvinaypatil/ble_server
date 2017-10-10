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
/**********************************************/
const char *READER_ID = "00:03";
/********** Device specific data ******************/

//#define EIR_FLAGS                   0x01  /* flags */
//#define EIR_UUID16_SOME             0x02  /* 16-bit UUID, more available */
//#define EIR_UUID16_ALL              0x03  /* 16-bit UUID, all listed */
//#define EIR_UUID32_SOME             0x04  /* 32-bit UUID, more available */
//#define EIR_UUID32_ALL              0x05  /* 32-bit UUID, all listed */
//#define EIR_UUID128_SOME            0x06  /* 128-bit UUID, more available */
//#define EIR_UUID128_ALL             0x07  /* 128-bit UUID, all listed */
//#define EIR_NAME_SHORT              0x08  /* shortened local name */
//#define EIR_NAME_COMPLETE           0x09  /* complete local name */
//#define EIR_TX_POWER                0x0A  /* transmit power level */
//#define EIR_DEVICE_ID               0x0d /* device ID */
//#define EIR_MANUFACTURE_SPECIFIC    0xFF

/****************************************************/

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

/**************************** BLE MAC_ID COMPARISIOPN *************************/

/*int compare_ID(char a[])
{
   int c = 0;
 // char b[] = "00:A0:50:14:27:17";
     char b[] = "D8:80:39:F0:D1:CF";


   while (a[c] == b[c]) {
      if (a[c] == '\0' || b[c] == '\0')
         break;
      c++;
   }

   if (a[c] == '\0' && b[c] == '\0')
      return 0;
   else
      return -1;
}*/

/*********************** BLE SCAN THREAD HANDLER ********************/
void *scan_le(void *socket_desc)
{
    //Get the socket descriptor
	int sock = *(int*)socket_desc;
	int read_size;
	int ret, status;
	const int device = hci_open_dev(hci_get_route(NULL));
	if ( device < 0 ) {
		perror("Failed to open HCI device.");
		return 0;
	}
	// Set BLE scan parameters.

	le_set_scan_parameters_cp scan_params_cp;
	memset(&scan_params_cp, 0, sizeof(scan_params_cp));
	scan_params_cp.type 			= 0x00;
	scan_params_cp.interval 		= htobs(0x0010);
	scan_params_cp.window 			= htobs(0x0010);
	scan_params_cp.own_bdaddr_type 	= 0x00; // Public Device Address (default).
	scan_params_cp.filter 			= 0x00; // Accept all.
	struct hci_request scan_params_rq = ble_hci_request(OCF_LE_SET_SCAN_PARAMETERS, LE_SET_SCAN_PARAMETERS_CP_SIZE, &status, &scan_params_cp);
	ret = hci_send_req(device, &scan_params_rq, 1000);
	if ( ret < 0 ) {
		hci_close_dev(device);
		perror("Failed to set scan parameters data.");
		return 0;
	}
	// Set BLE events report mask.

	le_set_event_mask_cp event_mask_cp;
	memset(&event_mask_cp, 0, sizeof(le_set_event_mask_cp));
	int i = 0;
	for ( i = 0 ; i < 8 ; i++ ) event_mask_cp.mask[i] = 0xFF;

	struct hci_request set_mask_rq = ble_hci_request(OCF_LE_SET_EVENT_MASK, LE_SET_EVENT_MASK_CP_SIZE, &status, &event_mask_cp);
	ret = hci_send_req(device, &set_mask_rq, 1000);
	if ( ret < 0 ) {
		hci_close_dev(device);
		perror("Failed to set event mask.");
		return 0;
	}
	le_set_scan_enable_cp scan_cp;
	memset(&scan_cp, 0, sizeof(scan_cp));
	scan_cp.enable 		= 0x01;	// Enable flag.
	scan_cp.filter_dup 	= 0x01; // Filtering disabled.

	struct hci_request enable_adv_rq = ble_hci_request(OCF_LE_SET_SCAN_ENABLE, LE_SET_SCAN_ENABLE_CP_SIZE, &status, &scan_cp);

	ret = hci_send_req(device, &enable_adv_rq, 1000);
	if ( ret < 0 ) {
		hci_close_dev(device);
		perror("Failed to enable scan.");
		return 0;
	}

	// Get Results.

	struct hci_filter nf;
	hci_filter_clear(&nf);
	hci_filter_set_ptype(HCI_EVENT_PKT, &nf);
	hci_filter_set_event(EVT_LE_META_EVENT, &nf);
	if ( setsockopt(device, SOL_HCI, HCI_FILTER, &nf, sizeof(nf)) < 0 ) {
		hci_close_dev(device);
		perror("Could not set socket options\n");
		return 0;
	}

	printf("Scanning....\n");

	uint8_t buf[HCI_MAX_EVENT_SIZE];
	evt_le_meta_event * meta_event;
	le_advertising_info * info;
	int len;
	/*********************************/
	while ( sock ) {
		len = read(device, buf, sizeof(buf));
		if ( len >= HCI_EVENT_HDR_SIZE ) {
			meta_event = (evt_le_meta_event*)(buf+HCI_EVENT_HDR_SIZE+1);
			if ( meta_event->subevent == EVT_LE_ADVERTISING_REPORT ) {
				uint8_t reports_count = meta_event->data[0];
				void * offset = meta_event->data + 1;
				while ( reports_count-- ) {
					info = (le_advertising_info *)offset;
					char addr[18];
					char buffer[50];
					int8_t rssi;
					int tag_type = 1;
					int tag_battery =30;
					int button_status = 0;
					int motion_status = 0;
				//	char tag_oui[2];

				//	int flag;
					ba2str(&(info->bdaddr), addr);
				//	ba2oui(&(info->bdaddr),tag_oui);
				//	const char *manufacturer = bt_compidtostr((int)tag_oui);

                                //       flag = compare_ID(addr);

                                  //     if(flag == 0)
                                    //  {
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
					//printf("\nAFTER WRITE\n");
					offset = info->data + info->length + 2;
				      // }
                                    }
			}
		}
	}
	/**************************************/
	// Disable scanning.

	memset(&scan_cp, 0, sizeof(scan_cp));
	scan_cp.enable = 0xd8;	// Disable flag.

	struct hci_request disable_adv_rq = ble_hci_request(OCF_LE_SET_SCAN_ENABLE, LE_SET_SCAN_ENABLE_CP_SIZE, &status, &scan_cp);
	ret = hci_send_req(device, &disable_adv_rq, 1000);
	if ( ret < 0 ) {
		hci_close_dev(device);
		perror("Failed to disable scan.");
		return 0;
	}

	hci_close_dev(device);
}

/*if(read_size == 0)
    {
        puts("Client disconnected");
        fflush(stdout);
    }
    else if(read_size == -1)
    {
        perror("recv failed");
    }

    return 0;
} */

/********************************************************/
int main(int argc , char *argv[])
{
    int socket_desc , client_sock , c;
    struct sockaddr_in server , client;
    pthread_t thread_id;

    //Create socket
    socket_desc = socket(AF_INET , SOCK_STREAM , 0);
    if (socket_desc == -1)
    {
        printf("Could not create socket");
    }
    puts("Socket created");

    //Prepare the sockaddr_in structure
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons( PORT );

    //Bind
    if( bind(socket_desc,(struct sockaddr *)&server , sizeof(server)) < 0)
    {
        //print the error message
        perror("bind failed. Error");
        return 1;
    }
    puts("bind done");

    //Listen
    listen(socket_desc , 3);

    //Accept and incoming connection
    puts("Waiting for incoming connections...");
    c = sizeof(struct sockaddr_in);


    while (client_sock = accept(socket_desc, (struct sockaddr *)&client, (socklen_t*)&c))
    {
        puts("Connection accepted");

        if( pthread_create( &thread_id , NULL ,  scan_le , (void*) &client_sock) < 0)
        {
            perror("could not create thread");
            return 1;
        }

        //Now join the thread , so that we dont terminate before the thread
        //pthread_join( thread_id , NULL);
        puts("Handler assigned");
    }

    if (client_sock < 0)
    {
        perror("accept failed");
        return 1;
    }

    return 0;
}
