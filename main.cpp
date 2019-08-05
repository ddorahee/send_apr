#include "arp_h.h"

int main(int argc, char* argv[]) {
  if (argc != 4) {
    usage();
    return -1;
  }

  u_char buf[100];

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

    arp_spoofing_header arp_header;
    Get_My_Address(&arp_header);

  //Get local Mac Address
      int fd;
      struct ifreq ifr;
      char *iface = "ens33";
      unsigned char *mac;


      fd = socket(AF_INET, SOCK_DGRAM, 0);

      ifr.ifr_addr.sa_family = AF_INET;
      strncpy(ifr.ifr_name , iface , IFNAMSIZ-1);

      ioctl(fd, SIOCGIFHWADDR, &ifr);

      close(fd);

      mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;

      //display mac address
      printf("Mac : %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n" , mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);



      char * ptr = strtok(argv[3], ".");
      int i =0;

      while(ptr != NULL)
      {
          buf[38+i]=atoi(ptr);
          ptr = strtok(NULL, ".");
          i++;
      }//Store send_ip as hex (arp_head sender_IP, cmd target_IP)
        //target_ip (when I send arp_request)


    //My_ip (when I send arp_request)
      int n;
      struct ifreq ifr2;
      char array[] = "ens33";
      unsigned char *ip;

      n = socket(AF_INET, SOCK_DGRAM, 0);
      //Type of address to retrieve - IPv4 IP address
      ifr2.ifr_addr.sa_family = AF_INET;
      //Copy the interface name in the ifreq structure
      strncpy(ifr2.ifr_name , array , IFNAMSIZ - 1);
      ioctl(n, SIOCGIFADDR, &ifr2);
      close(n);
      //display result
      printf("IP Address is %s - %s\n" , array , inet_ntoa(( (struct sockaddr_in *)&ifr2.ifr_addr )->sin_addr) );
      ip = (unsigned char *)inet_ntoa(( (struct sockaddr_in *)&ifr2.ifr_addr )->sin_addr);


      char * ptr2 = strtok((char*)ip,".");
      int j = 0;
      while(ptr2 != NULL)
      {
          buf[28+j] = atoi(ptr2);
          ptr2 = strtok(NULL,".");
          j++;
      }




      Get_Target_Mac(buf,mac,ip);  //broadcast target mac FF-FF-FF-FF-FF-FF


  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    printf("%u bytes captured\n", header->caplen);


    //Arp Request to get my mac,ip address
    pcap_sendpacket(handle, buf, 60);
           printf("Arp_request success!!\n");

    if(packet[12] == 0x08 && packet[13] == 0x06)

    if(packet[21] == 0x02)
        printf("arp reply!");

  }

  pcap_close(handle);
  return 0;
}
