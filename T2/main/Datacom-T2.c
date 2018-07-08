/* Trabalho para a disciplina de Tecnologia e Comunicação de Dados - DC UFSCar - 2018
 * Alunos:
 * - Caio Augusto Silva - 628280
 * - Luis Felipe Tomazini - 595098
*/

#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_event_loop.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "esp_wifi_internal.h"
#include "netif/wlanif.h"
#include "lora.h"

#define ESP_WIFI_SSID CONFIG_ESP_WIFI_SSID
#define MAX_STA_CONN CONFIG_MAX_STA_CONN

#define SOURCE_NAME_SIZE 10
#define DEST_NAME_SIZE 10
#define ETHER_TYPE  0x1996
#define ENCODING_DESC_SIZE 2
static const uint8_t eth_tp[2] = {0x19,0x96};
static const char *TAG = "LoRa Repeater";
static const uint8_t dest_mac[] = {0xff,0xff,0xff,0xff,0xff,0xff};

#Wifi frame struct
typedef struct {
  unsigned frame_ctrl:16;
  unsigned duration_id:16;
  uint8_t addr1[6]; /* receiver address */
  uint8_t addr2[6]; /* sender address */
  uint8_t addr3[6]; /* filtering address */
  unsigned sequence_ctrl:16;
  uint8_t addr4[6]; /* optional */
  uint8_t eth_type[2];
} wifi_ieee80211_mac_hdr_t;

typedef struct {
  wifi_ieee80211_mac_hdr_t hdr;
  uint8_t payload[0]; /* network data ended with 4 bytes csum (CRC32) */
} wifi_ieee80211_packet_t;


/* FreeRTOS event group to signal when we are connected*/
static EventGroupHandle_t wifi_event_group;

/* The event group allows multiple bits for each event,
   but we only care about one event - are we connected
   to the AP with an IP? */
const int WIFI_CONNECTED_BIT = BIT0;
static uint8_t mymac[6];
static int sent_packet_counter = 0;
static int received_packet_counter = 0;
unsigned long sent = 0;

static esp_err_t event_handler(void *ctx, system_event_t *event)
{
    switch(event->event_id) {
    case SYSTEM_EVENT_STA_START:
        esp_wifi_connect();
        break;
    case SYSTEM_EVENT_STA_GOT_IP:
        ESP_LOGI(TAG, "got ip:%s",
                 ip4addr_ntoa(&event->event_info.got_ip.ip_info.ip));
        xEventGroupSetBits(wifi_event_group, WIFI_CONNECTED_BIT);
        break;
    case SYSTEM_EVENT_AP_STACONNECTED:
        ESP_LOGI(TAG, "station:"MACSTR" join, AID=%d",
                 MAC2STR(event->event_info.sta_connected.mac),
                 event->event_info.sta_connected.aid);
        break;
    case SYSTEM_EVENT_AP_STADISCONNECTED:
        ESP_LOGI(TAG, "station:"MACSTR"leave, AID=%d",
                 MAC2STR(event->event_info.sta_disconnected.mac),
                 event->event_info.sta_disconnected.aid);
        break;
    case SYSTEM_EVENT_STA_DISCONNECTED:
        esp_wifi_connect();
        xEventGroupClearBits(wifi_event_group, WIFI_CONNECTED_BIT);
        break;
    default:
        break;
    }
    return ESP_OK;
}
/* Wifi AP initialization
 * Configures the access point
 */
void wifi_init_softap()
{
    wifi_event_group = xEventGroupCreate();

    tcpip_adapter_init();
    ESP_ERROR_CHECK(esp_event_loop_init(event_handler, NULL));

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    wifi_config_t wifi_config;
    strcpy((char*)wifi_config.sta.ssid, ESP_WIFI_SSID);   
    wifi_config.ap.authmode = WIFI_AUTH_OPEN;
    wifi_config.ap.max_connection = MAX_STA_CONN;

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_AP));
    ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_AP, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_LOGI(TAG, "wifi_init_softap finished.SSID:%s",
             ESP_WIFI_SSID);
}
/* Raw packet sending via Wi-fi 
 * This functions uses undocumented internal ESP32 functions, may not work on newer ESP-IDF versions.
*/
bool send_eth_payload(const void* buff, int len){
  int eth_packet_size = len + 6 + 6 + 2;
  uint8_t* eth_packet = malloc(eth_packet_size);
  uint8_t* ptr_eth = eth_packet;
  memcpy(ptr_eth,dest_mac,6);
  ptr_eth+=6;
  memcpy(ptr_eth,mymac,6);
  ptr_eth+=6;
  memcpy(ptr_eth,eth_tp,2);
  ptr_eth+=2;
  memcpy(ptr_eth,buff,len);

  // esp_wifi_internal_tx is an undocumented internal function. By reverse engineering i
  // figured out that it just need a valid ethernet packet (destinationMac+myMac+ethType+payload+crc)
  // and the len of the packet
  // if the sourceMac != myMac, it does not send
  // if the destMac == 0, it does not send
  if(esp_wifi_internal_tx(ESP_IF_WIFI_AP, (void*)eth_packet, eth_packet_size)<0){
    printf("[L%d]\tWiFi: Error in packet transmission: %d bytes\n",received_packet_counter, eth_packet_size);
    for(int i=0;i<eth_packet_size;i++){
      printf("%02x ",eth_packet[i]);
    }
    printf("\n");
    free(eth_packet);
    return false;
  }
    printf("\tWiFi: Packet sent: %d bytes\n", eth_packet_size);
    free(eth_packet);
    return(true);
}

/* Decodes and Print the contents of a RAW Ethernet Packet 
 * Ethertype 1996 contains a dest name, a source name, a encoding type and a message.
*/
void decode_print_1996(char* buff, int len){
    char packet_dest_name[DEST_NAME_SIZE+1];
    char packet_source_name[SOURCE_NAME_SIZE+1];
    char packet_encoding[ENCODING_DESC_SIZE+1];
    char* message;
    char* ptr = buff;

    strncpy(packet_dest_name,ptr,DEST_NAME_SIZE);
    memset(packet_dest_name+DEST_NAME_SIZE,0,1);
    ptr+=DEST_NAME_SIZE;
    strncpy(packet_source_name,ptr,SOURCE_NAME_SIZE);
    memset(packet_source_name+SOURCE_NAME_SIZE,0,1);
    ptr+=SOURCE_NAME_SIZE;
    strncpy(packet_encoding,ptr,ENCODING_DESC_SIZE);
    memset(packet_encoding+ENCODING_DESC_SIZE,0,1);
    ptr+=ENCODING_DESC_SIZE;
    int sizeMessage = len - DEST_NAME_SIZE - SOURCE_NAME_SIZE - ENCODING_DESC_SIZE;
    message = (char*)calloc(sizeMessage+1,sizeof(char));
    strncpy(message,ptr,sizeMessage);
    printf("\tData: From: %s To: %s Encoding: %s Msg: %s\n",packet_source_name,packet_dest_name,packet_encoding,message);
    free(message);
}

/* Send bytes via LoRa
*/
void loraSend(void* buff, int len){

  lora_send_packet((uint8_t*)buff, len);
  printf("\tLoRa: Sent packet\n");
  sent = esp_timer_get_time();
}

/* Loop to receive data via Lora
 * Also decode and print the 1996 packet and repeat it via Wifi
*/ 
void loraReceive(){
	int len;
	uint8_t buff[1024];
	for(;;) {
	  	lora_receive();    // put into receive mode

	  	while(lora_received()) {
	     	len = lora_receive_packet(buff, 2014);
	     	//buf[x] = 0;

			  printf("[L%d]\tLoRa: Received packet RSSI: %d SNR: %f\n",++received_packet_counter, lora_packet_rssi(), lora_packet_snr());
	     	decode_print_1996((char*)buff,len);
        if(sent!=0){
          unsigned long rtt = esp_timer_get_time() - sent; //microseconds
          printf("\tRTT: %lu ms", rtt/1000);
          sent=0;
        }
	     	send_eth_payload(buff,len);
	     	lora_receive();
	  	}
	  	vTaskDelay(1);
	}
}

/* Wifi promiscuous packet handler
 * This function is called whenever a packet is captured by the wifi if
*/
void wifi_sniffer_packet_handler(void* buff, wifi_promiscuous_pkt_type_t type)
{

  if (type != WIFI_PKT_DATA)
    return;

  const wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t *)buff; 
  const wifi_ieee80211_packet_t *ipkt = (wifi_ieee80211_packet_t *)ppkt->payload;
  const wifi_ieee80211_mac_hdr_t *hdr = &ipkt->hdr;
  const int lendata = ppkt->rx_ctrl.sig_len - sizeof(wifi_ieee80211_mac_hdr_t)-4;
  const unsigned short eth_type = htons(*((unsigned short*)(hdr->eth_type)));
  
  if(eth_type==ETHER_TYPE 	&& hdr->addr1[0]==mymac[0]
  							&& hdr->addr1[1]==mymac[1]
  							&& hdr->addr1[2]==mymac[2]
  							&& hdr->addr1[3]==mymac[3]
  							&& hdr->addr1[4]==mymac[4]
  							&& hdr->addr1[5]==mymac[5])
  {
    ++sent_packet_counter;
    printf("[W%d]\tWiFi: %x Packet RECEIVED FROM "
      "%02x:%02x:%02x:%02x:%02x:%02x"
      " TO %02x:%02x:%02x:%02x:%02x:%02x\n",
      //" INTERCEPTED BY %02x:%02x:%02x:%02x:%02x:%02x\n",
      //wifi_sniffer_packet_type2str(type),
      //ppkt->rx_ctrl.channel,
      //ppkt->rx_ctrl.rssi,
      sent_packet_counter,
      ETHER_TYPE,
      /* ADDR2 */
      hdr->addr2[0],hdr->addr2[1],hdr->addr2[2],
      hdr->addr2[3],hdr->addr2[4],hdr->addr2[5],
      /* ADDR3 */
      hdr->addr3[0],hdr->addr3[1],hdr->addr3[2],
      hdr->addr3[3],hdr->addr3[4],hdr->addr3[5]
      /* ADDR1 */
      // hdr->addr1[0],hdr->addr1[1],hdr->addr1[2],
      // hdr->addr1[3],hdr->addr1[4],hdr->addr1[5]//,

    );
    
    //print packet info  
    decode_print_1996((char*)ipkt->payload,lendata);
    //send with lora
    loraSend((void*)ipkt->payload,lendata);    
  }
}



void app_main()
{
    //Initialize NVS
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES) {
      ESP_ERROR_CHECK(nvs_flash_erase());
      ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);
    
    //Start AP
    ESP_LOGI(TAG, "ESP_WIFI_MODE_AP");
    wifi_init_softap();

    //Set Promiscuous on
    ESP_ERROR_CHECK(esp_wifi_get_mac(ESP_IF_WIFI_AP, mymac));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb(&wifi_sniffer_packet_handler));

    //Start LoRa
    lora_init();
   	lora_set_frequency(915e6);
   	lora_enable_crc();

    //Show some infos
    printf("AP started: %s\n", ESP_WIFI_SSID);
    printf("MyMAC=%02x:%02x:%02x:%02x:%02x:%02x\n",mymac[0],mymac[1],mymac[2],mymac[3],mymac[4],mymac[5]);

    //Enter LoRa Receive Loop
    loraReceive();
}
