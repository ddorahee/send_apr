#include <pcap.h>
#include <stdio.h>
#include <string.h>	//strncpy
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>	//ifreq
#include <unistd.h>	//close
#include <stdlib.h>
#include <arpa/inet.h>

#define INTERFACE "ens33"
unsigned char * Mac;

typedef struct _ether_header{
    u_char Dst_Mac[6];
    u_char Src_Mac[6];
}ether_header;

typedef struct _arp_spoofing_header{

    u_int8_t Dst_Mac[6];
    u_int8_t Src_Mac[6];
    const u_int16_t Eth_Type = 0x0806;

    const u_int16_t HW_Type = 0x01;
    const u_int16_t Proto_Type = 0x0800;
    const u_int8_t HW_Len = 0x06;
    const u_int8_t Proto_Len = 0x04;

    u_int16_t Operation;

    u_int8_t Sender_Mac[6];
    u_int8_t Sender_Ip[4];

    u_int8_t Target_Mac[6];
    u_int8_t Target_Ip[4];

}arp_spoofing_header;

unsigned char * Get_My_Mac(unsigned char * mac){
    int fd;
    struct ifreq ifr;
    char * iface = INTERFACE;


    fd = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name , iface , IFNAMSIZ-1);

    ioctl(fd, SIOCGIFHWADDR, &ifr);

    close(fd);

    return mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;
}
unsigned char * Get_My_Ip(){

}

void Get_My_Address(arp_spoofing_header * arp_packet){

}

void Get_Target_Mac(u_char * buf, unsigned char * s_mac,unsigned char * s_ip){
    for(int i = 0; i < 6; i++)
        buf[i] = 0xFF;
    for(int i = 0; i < 6; i++)    //localhost mac
        buf[6+i] = s_mac[i];

    buf[12] = 0x08;               // ethernet_header protocol type field
    buf[13] = 0x06;

    buf[14] = 0x00;
    buf[15] = 0x01;

    buf[16] = 0x08;
    buf[17] = 0x00;

    buf[18] = 0x06;
    buf[19] = 0x04;

    buf[20] = 0x00;
    buf[21] = 0x01;

    buf[22] = s_mac[0];
    buf[23] = s_mac[1];
    buf[24] = s_mac[2];
    buf[25] = s_mac[3];
    buf[26] = s_mac[4];
    buf[27] = s_mac[5];


    buf[32] = 0x00;
    buf[33] = 0x00;
    buf[34] = 0x00;
    buf[35] = 0x00;
    buf[36] = 0x00;
    buf[37] = 0x00;


}


void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}
