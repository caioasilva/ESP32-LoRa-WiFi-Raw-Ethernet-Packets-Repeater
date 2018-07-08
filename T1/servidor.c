/*
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 */

#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <errno.h>
#include <unistd.h>
#include <math.h>

#define BUFFER_SIZE 1024
#define SOURCE_NAME_SIZE 10
#define DEST_NAME_SIZE 10
#define ETHER_TYPE	0x1996
#define ENCODING_DESC_SIZE 2
/**
* Allocates memory for the output variables
* 
* @param out string in binary
* @param len length of the string to be converted
* @param the length of the binary string
*
* @return 0 if succeeds or -1 in case of error
*/
int mem_alloc(char **out, int len, int str_len) {
    if(len == 0) {
        printf("Length argument is zero\n");
        return (-1);
    }

    (*out) = malloc(str_len + 1);
    if((*out) == NULL) {
        printf("Can't allocate binary string: %s\n", strerror(errno));
        return (-1);
    }

    if(memset((*out), 0, (str_len)) == NULL) {
        printf("Can't initialize memory to zero: %s\n", strerror(errno));
        return (-1);
    }

    return 0;
}

/**
* Converts a sequence of ascii characters into its correpondents binary
* 
* @param input string to be converted
* @param out string in binary
* @param len length of the string to be converted
*
* @return the length of the new binary string or -1 in case of error
*/
int32_t ascii_to_binary(char *input, char **out, uint64_t len, uint32_t size) {
    uint32_t i;
    int32_t rtn;
    uint32_t str_len = len * size;

    if((rtn = mem_alloc(out, len, str_len)) == -1){
        return -1;
    }

    for(i = 0; i < len; i++) {
        unsigned char ch = input[i];
        char *o = &(*out)[size * i];
        unsigned char b;

        for (b = pow(2,size-1); b; b >>= 1)
            *o++ = ch & b ? '1' : '0';
    }

    (*out)[str_len] = '\0';

    return (str_len);
}

int bin2dec (int num) {
    int  decimal_val = 0, base = 1, rem;

    while (num > 0) {
        rem = num % 10;
        decimal_val = decimal_val + rem * base;
        num = num / 10 ;
        base = base * 2;
    }

    return decimal_val;
}

int binary_to_ascii(char *input, char **out, int len) {
    uint32_t i;
    uint32_t j;
    int rtn;
    int str_len = len / 8;

    for(i = 0; i < str_len; i++) {
        char *o = &(*out)[i];
        char subbuff[9];
        memcpy(subbuff, &input[8 * i], 8);
        subbuff[8] = '\0';
        char character = (char) bin2dec(atoi(subbuff));

        *o++ = character;
    }

    (*out)[str_len] = '\0';

    return (str_len);
}

int32_t nrz(char* input, char **out, uint64_t len) {
    int32_t rtrn = 0;
    char *buffer = NULL;
    //printf("%s\n", input);

    if((rtrn = mem_alloc(out, len, len)) == -1){
        return -1;
    }

    if(rtrn < 0) {
        printf("Can't convert string\n");
        return (-1);
    }

    rtrn = binary_to_ascii(input, out, len);

    return len;
}

int32_t manchester(char* input, char **out, uint64_t len) {
    int32_t rtrn = 0;
    uint32_t i;
    uint32_t j;
    uint32_t str_len = len / 2;

    if((rtrn = mem_alloc(out, len, str_len)) == -1){
        return -1;
    }

    if(rtrn < 0) {
        printf("Can't convert string\n");
        return (-1);
    }

    for (i = 0; i < len; i+=2) {
        unsigned char ch = input[i];
        char *o = &(*out)[i/2];

        *o++ = ch ^ (i % 2);
    }

    rtrn = binary_to_ascii(*out, out, str_len);

    return str_len;
}

int32_t nrzi(char* input, char **out, uint64_t len) {
    int32_t rtrn = 0;
    uint32_t i;
    char current = '0';

    if((rtrn = mem_alloc(out, len, len)) == -1){
        return -1;
    }

    if(rtrn < 0) {
        printf("Can't convert string\n");
        return (-1);
    }

    for (i = 0; i < len; i++) {
        unsigned char ch = input[i];
        char *o = &(*out)[i];

        if (ch == current) {
            *o++ = '0';
        } else {
            current = current == '0' ? '1' : '0';
            *o++ = '1';
        }
    }

    rtrn = binary_to_ascii(*out, out, len);

    return len;
}

int32_t _4b5b(char* input, char **out, uint64_t len) {
    uint32_t i;
    uint32_t j;
    uint32_t rtn;
    uint32_t str_len = len - len/5;
    char encodings[80] = { '1', '1', '1', '1', '0', 
                            '0', '1', '0', '0', '1', 
                            '1', '0', '1', '0', '0', 
                            '1', '0', '1', '0', '1', 
                            '0', '1', '0', '1', '0', 
                            '0', '1', '0', '1', '1', 
                            '0', '1', '1', '1', '0', 
                            '0', '1', '1', '1', '1', 
                            '1', '0', '0', '1', '0', 
                            '1', '0', '0', '1', '1', 
                            '1', '0', '1', '1', '0', 
                            '1', '0', '1', '1', '1', 
                            '1', '1', '0', '1', '0', 
                            '1', '1', '0', '1', '1', 
                            '1', '1', '1', '0', '0', 
                            '1', '1', '1', '0', '1'};

    if((rtn = mem_alloc(out, len, str_len)) == -1){
        return -1;
    }
    char* process = *out;
    strcpy(process, input);
    for (i=0;i<16;i++){
        char n[1]={i};
        char* b;
        ascii_to_binary(n,&b,1,4);
        for (j=0; j<len/5;j++){
            if (strncmp(encodings+i*5,input+j*5,5)==0){
                memcpy(process+j*4,b,4);
            }
        }
    }

    process[str_len]='\0';
    rtn = binary_to_ascii(process, out, str_len);

    return str_len;
}

int main(int argc, char *argv[])
{
	char sender[INET6_ADDRSTRLEN];
	int sockfd, ret, i;
	int sockopt;
	ssize_t numbytes;
	struct ifreq ifopts;	/* set promiscuous mode */
	struct sockaddr_storage their_addr;
	uint8_t buf[BUFFER_SIZE];
	char interfaceName[IFNAMSIZ];
	char my_dest_name[DEST_NAME_SIZE];
	u_char MACAddr[6];
	char packet_dest_name[DEST_NAME_SIZE];
	char packet_source_name[SOURCE_NAME_SIZE];
    char packet_encoding[ENCODING_DESC_SIZE];
	char* message;
    int responseSent=0;
    int returnReceive=0;
   // struct sockaddr_ll socket_address;
	
	/* Get interface name */
	if (argc > 2){
		strcpy(interfaceName, argv[1]);
		strncpy(my_dest_name, argv[2], 10);
        if (argc > 3)
            returnReceive=1;
	}else{
		fprintf(stderr,"Invalid arguments. Example:\n./servidor interface myName\n");
		return 1;
	}

	/* Header structures */
	struct ether_header *eh = (struct ether_header *) buf;


	/* Open PF_PACKET socket, listening for EtherType ETHER_TYPE */
	if ((sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETHER_TYPE))) == -1) {
		perror("listener: socket");	
		exit(EXIT_FAILURE);
	}

	/* Set interface to promiscuous mode - do we need to do this every time? */
	strncpy(ifopts.ifr_name, interfaceName, IFNAMSIZ-1);
	ioctl(sockfd, SIOCGIFFLAGS, &ifopts);
	ifopts.ifr_flags |= IFF_PROMISC;
	ioctl(sockfd, SIOCSIFFLAGS, &ifopts);
	if (ioctl(sockfd, SIOCGIFHWADDR, &ifopts) < 0){
	    perror("SIOCGIFHWADDR");
		close(sockfd);
		exit(EXIT_FAILURE);}
	memcpy(MACAddr,ifopts.ifr_hwaddr.sa_data,6);

	/* Allow the socket to be reused - incase connection is closed prematurely */
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &sockopt, sizeof sockopt) == -1) {
		perror("setsockopt");
		close(sockfd);
		exit(EXIT_FAILURE);
	}
	/* Bind to device */
	if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, interfaceName, IFNAMSIZ-1) == -1)	{
		perror("SO_BINDTODEVICE");
		close(sockfd);
		exit(EXIT_FAILURE);
	}
	// /* Get the MAC address of the interface to send on */
	// memset(&if_mac, 0, sizeof(struct ifreq));
	// strncpy(if_mac.ifr_name, interfaceName, IFNAMSIZ-1);
	// if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0)
	//     perror("SIOCGIFHWADDR");
	printf("My MAC: %x:%x:%x:%x:%x:%x\nMy Name: %s\n\n",
							MACAddr[0],
							MACAddr[1],
							MACAddr[2],
							MACAddr[3],
							MACAddr[4],
							MACAddr[5], 
							my_dest_name);
	while(1){
		//printf("Waiting for packet...\n");
		numbytes = recvfrom(sockfd, buf, BUFFER_SIZE, 0, NULL, NULL);
        if (responseSent){
            responseSent=0;

        }else
        {
            responseSent=0;
    		printf("> Captured a packet: %lu bytes\n", numbytes);
    		if (eh->ether_dhost[0] == MACAddr[0] &&
    			eh->ether_dhost[1] == MACAddr[1] &&
    			eh->ether_dhost[2] == MACAddr[2] &&
    			eh->ether_dhost[3] == MACAddr[3] &&
    			eh->ether_dhost[4] == MACAddr[4] &&
    			eh->ether_dhost[5] == MACAddr[5]) {
    			printf("  Correct destination MAC address\n");
    		} else {

    			printf("  Wrong destination MAC: %x:%x:%x:%x:%x:%x but i will take a look into it anyway...\n",
    							eh->ether_dhost[0],
    							eh->ether_dhost[1],
    							eh->ether_dhost[2],
    							eh->ether_dhost[3],
    							eh->ether_dhost[4],
    							eh->ether_dhost[5]);
                // if(returnReceive)
                //     return 1;
    		}
    		char* ptr = buf+sizeof(struct ether_header);
    		strncpy(packet_dest_name,ptr,DEST_NAME_SIZE);
    		ptr+=DEST_NAME_SIZE;
    		strncpy(packet_source_name,ptr,SOURCE_NAME_SIZE);
    		ptr+=SOURCE_NAME_SIZE;
            strncpy(packet_encoding,ptr,ENCODING_DESC_SIZE);
            ptr+=ENCODING_DESC_SIZE;
    		int sizeMessage = numbytes - sizeof(struct ether_header) - DEST_NAME_SIZE - SOURCE_NAME_SIZE - ENCODING_DESC_SIZE;
    		message = malloc((sizeMessage+1)*sizeof(char));
    		strncpy(message,ptr,sizeMessage);
    		
    		printf("  Source: %s\n  Destination: %s\n",packet_source_name,packet_dest_name);
    		if (strcmp(my_dest_name,packet_dest_name)==0){
    			printf("  IT IS MINE!");
                if(returnReceive)
                    return 0;
                else{
                    char buffer[10] = "olá";
                    // if(sendto(sockfd,buffer,10,0)>0){
                    //     printf("Respondido\n");
                    // }
                    char command[100];
                    sprintf(command,"./cliente.app %s %x:%x:%x:%x:%x:%x %s %s %s -%c 1 > nul.out",
                                    interfaceName,
                                    eh->ether_shost[0],
                                    eh->ether_shost[1],
                                    eh->ether_shost[2],
                                    eh->ether_shost[3],
                                    eh->ether_shost[4],
                                    eh->ether_shost[5],
                                    my_dest_name,
                                    packet_source_name,
                                    buffer,
                                    packet_encoding[1]);
                    //printf("%s\n",command);
                    sleep(1);
                    if(system(command)==0){
                        responseSent=1;
                        printf(" and I answered :)\n");
                    }
                    printf("\n");
                }
    		} else {
    			printf("  Not mine :( but i don't care, i want to read what's in there\n\n");
    		}
    		char* decoded;
    		char* bin;

    		ascii_to_binary(message, &bin, strlen(message),8);
            printf("  -Message bits:\n   %s\n",bin);

            printf("  -Decoding:\n");
            if (packet_encoding == NULL){
            nrz(bin, &decoded, strlen(bin));
            printf("   NRZ: %s\n",decoded);
            } else if (strncmp(packet_encoding, "-m",ENCODING_DESC_SIZE) == 0) {
            manchester(bin, &decoded, strlen(bin));
            printf("   Manchester: %s\n",decoded);
            } else if (strncmp(packet_encoding, "-i",ENCODING_DESC_SIZE) == 0) {
            nrzi(bin, &decoded, strlen(bin));
            printf("   NRZI: %s\n",decoded);
            } else if (strncmp(packet_encoding, "-f",ENCODING_DESC_SIZE) == 0) {
            _4b5b(bin, &decoded, strlen(bin));
            printf("   4B5B: %s\n",decoded);
            } else if (strncmp(packet_encoding, "-n",ENCODING_DESC_SIZE) == 0){
            nrz(bin, &decoded, strlen(bin));
            printf("   NRZ: %s\n",decoded);
            } else {
            nrz(bin, &decoded, strlen(bin));
            printf("=  NRZ: %s\n",decoded);
            }




    		printf("\n");
    		
    		
    		// 	/* Print packet */
    		// printf("\tData:");
    		// for (i=0; i<numbytes; i++) printf("%02x:", buf[i]);
    		// printf("\n");
        }
	}


	close(sockfd);
	return 0;
}