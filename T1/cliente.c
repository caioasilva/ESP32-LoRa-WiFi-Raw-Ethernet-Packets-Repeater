#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <errno.h>

#define BUFFER_SIZE 1024
#define SOURCE_NAME_SIZE 10
#define DEST_NAME_SIZE 10
#define ENCODING_DESC_SIZE 2
#define ETHER_TYPE	0x1996

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
int ascii_to_binary(char *input, char **out, int len) {
    uint32_t i;
    int rtn;
    int str_len = len * 8;

    if((rtn = mem_alloc(out, len, str_len)) == -1){
        return -1;
    }

    for(i = 0; i < len; i++) {
        unsigned char ch = input[i];
        char *o = &(*out)[8 * i];
        unsigned char b;

        for (b = 0x80; b; b >>= 1)
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

int nrz(char* input, char **out, int len) {
    int i;
    int rtn;

    if((rtn = mem_alloc(out, len, len)) == -1){
        return -1;
    }

    for(i = 0; i < len; i++) {
        unsigned char ch = input[i];
        char *o = &(*out)[i];

        *o++ = ch;
    }

    (*out)[len] = '\0';

    return (len);    
}

int manchester(char* input, char **out, int len) {
    uint32_t i;
    uint32_t j;
    int rtn;
    int str_len = len * 2;

    if((rtn = mem_alloc(out, len, str_len)) == -1){
        return -1;
    }

    for (i = 0; i < len; i++) {
        unsigned char ch = input[i];
        char *o = &(*out)[2 * i];

        for(j = 0; j < 2; j++) {
            *o++ = ch ^ j;
        }
    }

    (*out)[str_len] = '\0';

    return (str_len);
}

int nrzi(char* input, char **out, int len) {
    uint32_t i;
    int rtn;
    char current = '0';

    if((rtn = mem_alloc(out, len, len)) == -1){
        return -1;
    }
    
    for(i = 0; i < len; i++) {
        unsigned char ch = input[i];
        char *o = &(*out)[i];

        *o++ = ch == '0' ? current : (current = current == '0' ? '1' : '0');
    }

    (*out)[len] = '\0';

    return 0;
}

int _4b5b(char* input, char **out, int len) {
    uint32_t i;
    uint32_t j;
    int rtn;
    int str_len = len + len/4;
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

    for(i = 0; i < len/4; i++) {
        char *o = &(*out)[5 * i];
        char subbuff[5];
        memcpy(subbuff, &input[4 * i], 4);
        subbuff[4] = '\0';

        int index = bin2dec(atoi(subbuff));

        for(j = 0; j < 5; j++) {
            *o++ = encodings[5 * index + j];
        }
    }

    (*out)[str_len] = '\0';

    return 0;
}

int char_to_bits(char* input, char** output, int len){
	char* bits;
	char* cursor;
	//int size=ceil(len/8);
	int size =0;
	int i,j,c,jMax;

	bits = malloc(1);
	//memset(cursor,0,size);
	for(i=0;i<len;i+=8){
		size = size + sizeof(char);
		//printf("s: %d\n so: %s\n", size,sizeof(*bits));
		bits = realloc(bits,size);
		cursor = bits+i/8;
		//printf("c: %d\n",i/8);
		memset(cursor,0,1);
		// if(len-i < 8){
		// 	jMax = len-i;
		// }else
		// 	jMax=8;

		//printf("bits: %x\ncursor: %x\n",bits,cursor);
		for(j=0;j<8;j++){
			//printf("%x\n",(char)*cursor);
			*cursor <<= 1;
			c = *(input+i+j)-48;
			//printf("d: %d\n", c);
			*cursor |= (c & 0x01);
		}
		//printf("%x\n",(char)*bits);
		//printf("%x\n",(char)*cursor);
	}
	//printf("bits: %x\ncursor: %x\n",bits,cursor);
	//printf("%x\n",(char)*(bits));]
	*output = bits;
	return size;
}

char* encodeProtocol(int* size, char* destinationName, char* sourceName, char* message, char* encoding)
{	
	char* temp;
	char* bin;
	char* encodedMessage;
	int messageSize;
	ascii_to_binary(message, &bin, strlen(message));
	if (encoding == NULL){
		printf("No encoding especified. Using NRZ Encoding\n");
		nrz(bin, &temp, strlen(bin));
		strcpy(encoding,"-n");
	} else if (strcmp(encoding, "-m") == 0) {
		printf("Using Manchester Encoding\n");
    	manchester(bin, &temp, strlen(bin));
    } else if (strcmp(encoding, "-i") == 0) {
    	printf("Using NRZI Encoding\n");
        nrzi(bin, &temp, strlen(bin));
    } else if (strcmp(encoding, "-f") == 0) {
    	printf("Using 4B5B Encoding\n");
        _4b5b(bin, &temp, strlen(bin));
	} else if (strcmp(encoding, "-n") == 0){
		printf("Using NRZ Encoding\n");
		nrz(bin, &temp, strlen(bin));
	} else {
		printf("Invalid encoding especified. Using NRZ Encoding\n");
		nrz(bin, &temp, strlen(bin));
		strcpy(encoding,"-n");
	}
	printf("Encoded message bits: \n%s\n",temp);
	messageSize = char_to_bits(temp,&encodedMessage,strlen(temp));

	//printf("%s",message);
	*size = SOURCE_NAME_SIZE  + DEST_NAME_SIZE + ENCODING_DESC_SIZE + messageSize;

	//printf("Encoded message bytes: %s\n",encodedMessage);
	//char data[size];
	char* data = calloc(*size,sizeof(char));
	char* prot_ptr = data;
	memcpy(prot_ptr,destinationName,strlen(destinationName));
	prot_ptr+=DEST_NAME_SIZE;
	memcpy(prot_ptr,sourceName,strlen(sourceName));
	prot_ptr+=SOURCE_NAME_SIZE;
	memcpy(prot_ptr,encoding,strlen(encoding));
	prot_ptr+=ENCODING_DESC_SIZE;
	memcpy(prot_ptr,encodedMessage,messageSize);
	//printf("%x\n",encodedMessage);
	return data;
}



int main(int argc, char *argv[])
{
	int sockfd;
	struct ifreq if_idx;
	struct ifreq if_mac;
	int tx_len = 0;
	char sendDataBuffer[BUFFER_SIZE];
	struct ether_header *eh = (struct ether_header *) sendDataBuffer;
	struct iphdr *iph = (struct iphdr *) (sendDataBuffer + sizeof(struct ether_header));
	struct sockaddr_ll socket_address;
	char interfaceName[IFNAMSIZ];
	unsigned int destinationMAC[6];
	char* protocol;
	int protocol_size;
	int notwait=0;
	
	/* Get interface name */
	if (argc > 5){
		strcpy(interfaceName, argv[1]);
      	sscanf(argv[2], "%02x:%02x:%02x:%02x:%02x:%02x", &destinationMAC[0], &destinationMAC[1], &destinationMAC[2], &destinationMAC[3], &destinationMAC[4], &destinationMAC[5]);
      	char* encode;
      	//strcpy(message, argv[5]);
      	if (argc > 6){
      		encode = argv[6];
      	}else{
      		encode = NULL;
      	}
      	if (argc >7)
      		notwait=1;
      	protocol = encodeProtocol(&protocol_size, argv[4],argv[3],argv[5],encode);
      	//protocol_size = sizeof(protocol);

	}else{
		fprintf(stderr,"Invalid Arguments. Example:\n./cliente interface MACaddr sourceName destinationName message encoding\n\nEncodings:\n-n: NRZ\n-m: Manchester\n-i: NRZI\n-f: 4B5B\n");
		exit(EXIT_FAILURE);
	}

	/* Open RAW socket to send on */
	if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
	    perror("socket");
	}

	/* Get the index of the interface to send on */
	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, interfaceName, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0)
	    perror("SIOCGIFINDEX");

	/* Get the MAC address of the interface to send on */
	memset(&if_mac, 0, sizeof(struct ifreq));
	strncpy(if_mac.ifr_name, interfaceName, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0)
	    perror("SIOCGIFHWADDR");

	/* Construct the Ethernet header */
	memset(sendDataBuffer, 0, BUFFER_SIZE);

	/* Ethernet header */
	eh->ether_shost[0] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[0];
	eh->ether_shost[1] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[1];
	eh->ether_shost[2] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[2];
	eh->ether_shost[3] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[3];
	eh->ether_shost[4] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[4];
	eh->ether_shost[5] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[5];
	eh->ether_dhost[0] = destinationMAC[0];
	eh->ether_dhost[1] = destinationMAC[1];
	eh->ether_dhost[2] = destinationMAC[2];
	eh->ether_dhost[3] = destinationMAC[3];
	eh->ether_dhost[4] = destinationMAC[4];
	eh->ether_dhost[5] = destinationMAC[5];

	/* Ethertype field */
	eh->ether_type = htons(ETHER_TYPE);//htons(ETH_P_IP);
	tx_len += sizeof(struct ether_header);


	/* Mounting the data to be sent by the ethernet frame */
	// Format: Destination name (10 bytes), Sender name (10 bytes), Message

	memcpy(sendDataBuffer+tx_len,protocol,protocol_size);
	tx_len+=protocol_size;

	/* Index of the network device */
	socket_address.sll_ifindex = if_idx.ifr_ifindex;
	/* Address length*/
	socket_address.sll_halen = ETH_ALEN;
	/* Destination MAC */
	memcpy (socket_address.sll_addr, eh->ether_dhost, 6);


	/* Send packet */
	if (sendto(sockfd, sendDataBuffer, tx_len, 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
	    printf("Send failed\n");
	else{
		printf("Ethernet Frame Bytes: \n");
		for (int j = 0; j < tx_len; j++)
			printf("%02x ",(unsigned char)sendDataBuffer[j]);
		printf("\n");

		if (!notwait){
			char command[100];
            sprintf(command,"./servidor.app %s %s 1 > null.out",
                            interfaceName, argv[3]);
            //printf("%s\n",command);
            if(system(command)==0){
                printf("Response Received!\n");
            }
		}
	}
	return 0;
}