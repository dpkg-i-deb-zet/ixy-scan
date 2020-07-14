#include <stdio.h>
#include <unistd.h>
#include <sys/time.h>


#include "stats.h"
#include "log.h"
#include "memory.h"
#include "driver/device.h"

// ------ settings ------

// my mac addr: de:ad:be:ef:co:fe
#define def_my_mac 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
static uint8_t my_mac[] = { def_my_mac };

// gateway mac addr: 00:00:00:00:00:00 
#define def_gw_mac 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // Gateway


#define def_my_ip    0, 0, 0, 0
static uint8_t my_ip[] = { def_my_ip };

#define def_src_port 0x12, 0x34
#define def_dst_port 0x00, 80


// constants
#define ONE_SECOND (1e9)

#define OFFSET_DST_MAC  0
#define OFFSET_SRC_MAC  6
#define OFFSET_ETH_TYPE 12
#define OFFSET_ARP_OPCODE 20
#define OFFSET_ARP_SRC_MAC 22
#define OFFSET_ARP_SRC_IP  28
#define OFFSET_ARP_DST_MAC 32
#define OFFSET_IP_PROTO    23
#define OFFSET_ARP_DST_IP  38
#define OFFSET_IP_CHKSUM   24
#define OFFSET_TCP_SRC_IP   26
#define OFFSET_TCP_CHKSUM  50
#define OFFSET_TCP_BEGIN   34
#define OFFSET_TCP_IP_DST  30
#define OFFSET_TCP_FLAGS   47


bool compare_in_packet(uint8_t* rbufs, int search_offset, uint8_t* compare_data);

// Num Buffers in mempool (must always be greater than BATCH_SIZE)
const int NUM_BUFS = 2048;

// number of packets sent simultaneously to our driver
static const uint32_t BATCH_SIZE = 64;


// default arp reply
#define PKT_ARP_SIZE 42    // excluding CRC (offloaded by default)
static const uint8_t arp_reply[] = {
	def_gw_mac,			    // dst MAC
	def_my_mac,			    // src/my MAC
	0x08, 0x06,                         // ether type: ARP
	0x00, 0x01,                         // Hardware Type Ethernet
	0x08, 0x00,                         // Protocol Type: IPv4
	0x06, 0x04,                         // Hardware size, Protocol size
	0x00, 0x02,                         // Opcode: reply; 0x00, 0x01 = request
	def_my_mac,			    // sender mac, my mac
	def_my_ip, 		            // my IP addr
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // target/dst MAC
	0x11, 0x11, 0x11, 0x11              // Target/dst IP addr
};

// default arp reply
#define PKT_SYN_SIZE 54    // excluding CRC (offloaded by default)
static const uint8_t syn_req[] = {
	// Ethernet Frame
	def_gw_mac,		// MAC Dst
	def_my_mac,		// MAC Src
	0x08, 0x00,		// ether type: IPv4
	// IP-Proto
	0x45, 0x00,		// IPv4, Header 20 bytes, DSF=0x00
	0x00, 40,		// Total Length = 40 bytes
	0xf4, 0x7c,		// Identification
	0x40, 0x00,		// Flags
	64,			// TTL = 64
	0x06,			// Proto: TCP
	0x00, 0x00,		// Header Checksum!     ====== CHECKSUM !!
	def_my_ip,		// IP-Source
	0,0,0,0,		// IP-Destination       ====== INSERT: remote IP (TBD
	// TCP
	def_src_port,		// Port-Source
	def_dst_port,		// Port-Destination
	0xcd, 0x57, 0xfa, 0x32,	// Sequence number  ## FIXME
	0x00, 0x00, 0x00, 0x00, // ACK-num
	0x50,			// Header 20 bytes
	0x02,			// Flags (SYN)
	0xfa, 0xf0,		// Window Size???
	0x00, 0x00,		// Checksum             ====== CHECKSUM !!  (Static for a specific port)
	0x00, 0x00		// Urgent Pointer
};


// calculate a IP/TCP/UDP checksum
static uint16_t calc_ip_checksum(uint8_t* data, uint32_t len) {
	if (len % 1) error("odd-sized checksums NYI"); // we don't need that
	uint32_t cs = 0;
	for (uint32_t i = 0; i < len / 2; i++) {
		cs += ((uint16_t*)data)[i];
		if (cs > 0xFFFF) {
			cs = (cs & 0xFFFF) + 1; // 16 bit one's complement
		}
	}
	return ~((uint16_t) cs);
}




/*
**************************************************************************
Function: tcp_sum_calc()
**************************************************************************
Description: 
	Calculate TCP checksum
***************************************************************************
*/

uint16_t tcp_sum_calc(uint16_t len_tcp, uint8_t src_addr[],uint8_t dst_addr[], uint8_t *buff) {
	uint16_t prot_tcp = 6;
	uint16_t padd = 0;
	uint16_t word16;
	uint32_t sum = 0;

	//printf("len=%x\n", len_tcp);
	//printf("src=%x.%x.%x.%x\n", src_addr[0], src_addr[1], src_addr[2], src_addr[3]);
	//printf("dst=%x.%x.%x.%x\n", dst_addr[0], dst_addr[1], dst_addr[2], dst_addr[3]);
	//for (int i=0; i<len_tcp; i++) {
	//	printf("%02x", buff[i]);
	//}
	//printf("\n");

	// Find out if the length of data is even or odd number. If odd,
	// add a padding byte = 0 at the end of packet
	if (len_tcp % 2 == 1){
		padd = 1;
		buff[len_tcp] = 0;
		//printf("padding\n");
	}
	

	// add the TCP pseudo header which contains:
	// the IP source and destinationn addresses,
	for (int i=0;i<4;i=i+2){
		word16 =((src_addr[i]<<8)&0xFF00)+(src_addr[i+1]&0xFF);
		sum=sum+word16;	
	}
	for (int i=0;i<4;i=i+2){
		word16 =((dst_addr[i]<<8)&0xFF00)+(dst_addr[i+1]&0xFF);
		sum=sum+word16; 	
	}
	// the protocol number and the length of the TCP packet
	sum += prot_tcp + len_tcp;
	//printf("sum(header)=%x\n", sum);

	// make 16 bit words out of every two adjacent 8 bit words and 
	// calculate the sum of all 16 vit words
	for (int i=0; i<len_tcp+padd; i=i+2){
		word16 =((buff[i]<<8)&0xFF00)+(buff[i+1]&0xFF);
		sum += (uint32_t)word16;
	}
	//printf("sum(total)=%x\n", sum);

	// keep only the last 16 bits of the 32 bit calculated sum and add the carries
    	while (sum>>16)
		sum = (sum & 0xFFFF)+(sum >> 16);
	//printf("sum(small)=%x\n", sum);
		
	// Take the one's complement of sum
	sum = ~sum;
	//printf("sum(final)=%x\n", sum);

	return ((uint16_t) sum);
}

uint32_t ip_count(uint32_t* gcnt) {
	//static const uint8_t BitReverseTable256[256] =
	//{
	//#   define R2(n)     n,     n + 2*64,     n + 1*64,     n + 3*64
	//#   define R4(n) R2(n), R2(n + 2*16), R2(n + 1*16), R2(n + 3*16)
	//#   define R6(n) R4(n), R4(n + 2*4 ), R4(n + 1*4 ), R4(n + 3*4 )
	//    R6(0), R6(2), R6(1), R6(3)
	//};
	//uint32_t c = (BitReverseTable256[*gcnt & 0xff] << 24) |
	//             (BitReverseTable256[(*gcnt >> 8) & 0xff] << 16) |
	//             (BitReverseTable256[(*gcnt >> 16) & 0xff] << 8) |
	//             (BitReverseTable256[(*gcnt >> 24) & 0xff]);
	*gcnt += 1;
	return *gcnt;
}


int main(int argc, char* argv[]) {
	if (argc < 2 || argc > 3) {
		fprintf(stderr, "Usage: %s <pci bus id> [n packets]\n", argv[0]);
		return 1;
	}

	struct mempool* mempool = memory_allocate_mempool(NUM_BUFS, 0);
	struct ixy_device* dev = ixy_init(argv[1], 1, 1, 0);

	uint32_t global_ip_cnt = 0;

	int64_t n_packets = -1;
	if (argc == 3) {
		n_packets = atol(argv[2]);
		fprintf(stderr, "Capturing %ld packets...\n", n_packets);
	} else {
		fprintf(stderr, "Capturing packets...\n");
	}

	uint64_t last_stats_printed = monotonic_time();
	uint64_t counter = 0;
	struct device_stats stats_old, stats;
	stats_init(&stats, dev);
	stats_init(&stats_old, dev);

	// array of bufs sent out in a batch
	struct pkt_buf* tbufs[BATCH_SIZE];
	struct pkt_buf* rbufs[BATCH_SIZE];

	uint64_t endtime = 0;

	// loop
	
	while (n_packets != 0) {
		//goto skip_send;
		if (endtime != 0) goto skip_send;
		// we cannot immediately recycle packets, we need to allocate new packets every time
		// the old packets might still be used by the NIC: tx is async
		pkt_buf_alloc_batch(mempool, tbufs, BATCH_SIZE);
		uint32_t newpacks = BATCH_SIZE;
		for (uint32_t i = 0; i < BATCH_SIZE; i++) {
			// packets can be modified here, make sure to update the checksum when changing the IP header
			tbufs[i]->size = PKT_SYN_SIZE;
			// DEBUG: printf("buf=%x data=%x size=%x\n", &(tbufs[i]), &(tbufs[i]->data), &(tbufs[i]->size));
			memcpy(tbufs[i]->data, syn_req, sizeof(syn_req));
			uint8_t* ip_buf_ptr = tbufs[i]->data + OFFSET_TCP_IP_DST;
			*(uint32_t*) ip_buf_ptr = ip_count(&global_ip_cnt);
			//int length = read(STDIN_FILENO, ip_buf_ptr, 4);
			if (global_ip_cnt == 0) {
				fprintf(stderr, "EOF - End of fucking (IP) file\n");
				endtime = monotonic_time();
				newpacks = i;
				break; // Break for-loop
			}
                        //printf("IP: %i.%i.%i.%i\n", *(ip_buf_ptr), *(ip_buf_ptr+1), *(ip_buf_ptr+2), *(ip_buf_ptr+3));
			//fflush(stdout);
	                *(uint16_t*) (tbufs[i]->data + OFFSET_IP_CHKSUM) = calc_ip_checksum(tbufs[i]->data + 14, 20);
			uint16_t sum = tcp_sum_calc(20, my_ip, tbufs[i]->data + OFFSET_TCP_IP_DST, tbufs[i]->data + OFFSET_TCP_BEGIN);
                        *(uint8_t*) (tbufs[i]->data + OFFSET_TCP_CHKSUM + 1) = (sum&0xFF);
                        *(uint8_t*) (tbufs[i]->data + OFFSET_TCP_CHKSUM + 0) = ((sum>>8)&0xFF);
                        //*(uint16_t*) (tbufs[i]->data + OFFSET_TCP_CHKSUM + 0) = sum;
			//for (uint32_t asdf = 0; asdf < tbufs[i]->size; asdf++) {
			//	printf("%02x", tbufs[i]->data[asdf]);
			//}
			//printf("\n");
			//printf("(%i)\n", tbufs[i]->size);
		}
		//printf("Sending %i packets...\n", newpacks);
		//fflush(stdout);
		ixy_tx_batch_busy_wait(dev, 0, tbufs, newpacks);

skip_send:
		// don't check time for every packet, this yields +10% performance :)
		if ((counter++ & 0xFFF) == 0) {
			uint64_t time = monotonic_time();
			if (time - last_stats_printed > ONE_SECOND) {
				// every second
				ixy_read_stats(dev, &stats);
				print_stats_diff(&stats, &stats_old, time - last_stats_printed);
				fprintf(stderr, "Status: %.02f%%\n", ((float) global_ip_cnt)/ ((float) 0xFFFFFFFF) *100);
				stats_old = stats;
				last_stats_printed = time;
			}
			if ((endtime != 0) && ((time - endtime) > (10*ONE_SECOND))) {
				break;
			}
		}
		// track stats

		uint32_t num_rx = ixy_rx_batch(dev, 0, rbufs, BATCH_SIZE);
		struct timeval tv;
		gettimeofday(&tv, NULL);

		for (uint32_t i = 0; i < num_rx && n_packets != 0; i++) {
			bool pkt_minebymac = true;
			bool pkt_isbroadcast = true;
			// rbufs[i]->data  // packet data
			// rbufs[i]->size  // packet size

			for (int maccur = 0; maccur < 6; maccur++) {
				if (!(rbufs[i]->data[OFFSET_DST_MAC + maccur] == my_mac[maccur])) {
					pkt_minebymac = false;
				}
			}

			for (int maccur = 0; maccur < 6; maccur++) {
                                if (!(rbufs[i]->data[OFFSET_DST_MAC + maccur] == 0xff)) {
					pkt_isbroadcast = false;
				}
                        }

			if (pkt_isbroadcast || pkt_minebymac) {


//                      for (uint32_t pcur = 0; pcur < rbufs[i]->size; pcur++) {
//                              printf("%02x", (rbufs[i]->data)[pcur]);
//                      }
//			printf("\n");

				if (rbufs[i]->data[OFFSET_ETH_TYPE] == 0x08 && 
					rbufs[i]->data[OFFSET_ETH_TYPE +1] == 0x06 &&
					rbufs[i]->data[OFFSET_ARP_OPCODE] == 0x00 &&
					rbufs[i]->data[OFFSET_ARP_OPCODE +1] == 0x01 &&
					rbufs[i]->data[OFFSET_ARP_DST_MAC] == 0x00 &&
					rbufs[i]->data[OFFSET_ARP_DST_MAC +1] == 0x00 &&
					rbufs[i]->data[OFFSET_ARP_DST_MAC +2] == 0x00 &&
					rbufs[i]->data[OFFSET_ARP_DST_MAC +3] == 0x00 &&
					rbufs[i]->data[OFFSET_ARP_DST_MAC +4] == 0x00 &&
					rbufs[i]->data[OFFSET_ARP_DST_MAC +5] == 0x00 &&
					rbufs[i]->data[OFFSET_ARP_DST_IP] == my_ip[0] &&
					rbufs[i]->data[OFFSET_ARP_DST_IP +1] == my_ip[1] &&
					rbufs[i]->data[OFFSET_ARP_DST_IP +2] == my_ip[2] &&
					rbufs[i]->data[OFFSET_ARP_DST_IP +3] == my_ip[3]
				   ) {
//                      for (uint32_t pcur = 0; pcur < rbufs[i]->size; pcur++) {
//                              printf("%02x", (rbufs[i]->data)[pcur]);
//                      }
//                      printf("\n");



                			struct pkt_buf* buf = pkt_buf_alloc(mempool);
                			buf->size = PKT_ARP_SIZE;
                			memcpy(buf->data, arp_reply, sizeof(arp_reply));
					memcpy(buf->data + OFFSET_DST_MAC, rbufs[i]->data + OFFSET_SRC_MAC, 6);  // 6 mac
					memcpy(buf->data + OFFSET_ARP_DST_MAC, rbufs[i]->data + OFFSET_ARP_SRC_MAC, 10);  // 6 mac + 4 IP

                      for (uint32_t pcur = 0; pcur < buf->size; pcur++) {
                              printf("%02x", (buf->data)[pcur]);
                      }
                      printf("\n");
					ixy_tx_batch_busy_wait(dev, 0, &buf, 1);
				   } else if (
					pkt_minebymac && 
                                        rbufs[i]->data[OFFSET_IP_PROTO] == 0x06 &&
                                        rbufs[i]->data[OFFSET_TCP_FLAGS] == 0x12
                                   ) {
                                  	printf("%03d.%03d.%03d.%03d\n", rbufs[i]->data[OFFSET_TCP_SRC_IP],
                                        rbufs[i]->data[OFFSET_TCP_SRC_IP +1],
                                        rbufs[i]->data[OFFSET_TCP_SRC_IP +2],
                                        rbufs[i]->data[OFFSET_TCP_SRC_IP+3]);

				   }
			}

//			for (uint32_t pcur = 0; pcur < rbufs[i]->size; pcur++) {
//				printf("%02x", (rbufs[i]->data)[pcur]);
//			}


//			printf("  (%d)\n", rbufs[i]-> size);
			pkt_buf_free(rbufs[i]);  // buffer space can be reused
			// n_packets == -1 indicates unbounded capture
			if (n_packets > 0) {
				n_packets--;
			}
		}

	}
	return 0;

}


