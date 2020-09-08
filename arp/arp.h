#define ETH_LEN	1518
#define ETHER_TYPE	0x0800
#define DEFAULT_IF	"eth0"

struct eth_hdr {
	uint8_t dst_addr[6];
	uint8_t src_addr[6];
	uint16_t eth_type;
};

struct arp_packet {
	uint16_t hw_type;		/* hardware type */
	uint16_t prot_type;		/* protocol type */
	uint8_t hlen;			/* hardware address length */
	uint8_t plen;			/* protocol address length */
	uint16_t operation;		/* ARP operation */
	uint8_t src_hwaddr[6];		/* source hardware address */
	uint8_t src_paddr[4];		/* source protocol address */
	uint8_t tgt_hwaddr[6];		/* target hardware address */
	uint8_t tgt_paddr[4];		/* target protocol address */
};

struct ip_hdr {
	uint8_t ver;			/* version, header length */
	uint8_t tos;			/* type of service */
	int16_t len;			/* total length */
	uint16_t id;			/* identification */
	int16_t off;			/* fragment offset field */
	uint8_t ttl;			/* time to live */
	uint8_t proto;			/* protocol */
	uint16_t sum;			/* checksum */
	uint8_t src[4];			/* source address */
	uint8_t dst[4];			/* destination address */
};

union packet_u {
	struct arp_packet arp;
	struct ip_hdr ip;
};

struct eth_frame_s {
	struct eth_hdr ethernet;
	union packet_u payload;
};

union eth_buffer {
	struct eth_frame_s cooked_data;
	uint8_t raw_data[ETH_LEN];
};
