//
// Created by root on 18-8-26.
//


#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <time.h>
#include <string.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include "probe.h"

extern int raw_sock_tx,raw_sock_rx;
extern uint32_t seq_1,ack_seq_1,src_ip,dst_ip;
extern uint16_t src_port,dst_port;

//++++++++++++++++++++++++++++++++++++++++++++++++
//New IPv4 header checksum calculation
//++++++++++++++++++++++++++++++++++++++++++++++++
uint16_t i4_sum_calc(uint16_t nwords, uint16_t* buf) {
	//buffer present checksum
	uint16_t sum_buf = ( *(buf+5) );

	//set pointer to checksum on packet
	uint16_t *pt_sum =  buf+5;

	//set packet checksum to zero in order to compute checksum
	*pt_sum = htons(0);

	//initialize sum to zero
	uint32_t sum = 0;

	//sum it all up	
	int i;
	for (i=0; i<nwords; i++)
		sum += *(buf+i);
	
	//keep only the last 16 bist of the 32 bit calculated sum and add the carries
	while(sum>>16)
		sum = (sum & 0xFFFF) + (sum >> 16);

	//take the one's copliement of sum
	sum = ~sum;

	//reinstall original i4sum_buf
	*pt_sum = (uint16_t) (sum_buf);

	//reinstate prior value
	( *(buf+5) ) = sum_buf;

	return sum;
}

//++++++++++++++++++++++++++++++++++++++++++++++++
//New TCP header checksum calculation
//++++++++++++++++++++++++++++++++++++++++++++++++
uint16_t  tcp_sum_calc(
	uint16_t len_tcp, 
	uint16_t *src_addr, 
	uint16_t *dst_addr, 
	uint16_t *buf) {

	//buffer checksum
	uint16_t old_sum = buf[8];//checksum

	//pointer to tcp sum
	uint16_t *pt_sum = buf+8;

	//replace checksum with 0000
	*pt_sum = 0;

	uint16_t prot_tcp = 6;
	uint16_t padd = 0;
	uint32_t sum;

	//Find out if the length of data is even or odd number. If odd,
	//add a padding byte = 0 at the end of packet
	if( (len_tcp & 1) == 1) {
		padd = 1;
		buf[ (len_tcp-1)>>1 ] &= 0x00FF;
	}

	//initialize sum to zero
	sum = 0;

	//make 16 bit words out of every two adjacent 8 bit words and
	//calculate the sum of all 16 bit words
	int i;
	for (i=0; i<((len_tcp+padd)>>1); i++)
		sum +=  (*(buf + i));


	//add the TCP pseudo header which contains
	//the ip srouce and ip destination addresses
	sum +=  (*src_addr);
	sum +=  (*(src_addr + 1));
	sum +=  (*dst_addr);
	sum +=  (*(dst_addr + 1));

	//the protocol number and the length of the TCP packet
	sum += htons(prot_tcp);
	sum += htons(len_tcp);

	//keep only the last 16 bist of the 32 bit calculated sum and add the carries
	while (sum>>16) sum = (sum & 0xFFFF) + (sum >> 16);


	//reinstate buffered checksum
	*pt_sum = old_sum;

	return (uint16_t) sum;
}

//++++++++++++++++++++++++++++++++++++++++++++++++
//compute checksums: computes i4 & TCP checksums for new packets
// buf starts at i4 header. len_pk includes i4 header, tcp header, payload
// leni4: length of Ipv4 header in octects, lenpk: length of entire packet in octets
//++++++++++++++++++++++++++++++++++++++++++++++++
void compute_checksums(unsigned char *buf, uint16_t leni4, uint16_t lenpk) {

	//create 16-bit word pointer
	uint16_t *pt_buf16 = (uint16_t *) (buf);	

	//set checksum to 0
	*(pt_buf16 + 5) = 0;

	//update len_pk in IPv4 header
	// *(pt_buf16+1) = (uint16_t) htons(lenpk);	
	

	//update i4 checksum
	uint16_t i4sum = i4_sum_calc( (leni4>>1), pt_buf16);

	//enter fixed i4 checksum into packet
	*(pt_buf16 + 5) = i4sum;

	//compute checksum. Note: Totlen may have changed during manipulation. It is therefore updated.
	//delta method
	*(pt_buf16 + (leni4>>1) + 8) = 0;
	uint16_t new_tcp_header_checksum = tcp_sum_calc(lenpk-leni4, pt_buf16+6, pt_buf16+8, (uint16_t *) (buf + leni4));
	*(pt_buf16 + (leni4>>1) + 8) = ~( (uint16_t)(new_tcp_header_checksum));
}

void print_packet(char* buf){
    struct iphdr* ip = (struct iphdr*)buf;
	struct tcphdr* tcp = (struct tcphdr*)(buf + 20);
    FILE* f = fopen("log.txt","a+");
    fprintf(f,"\nIP header Src Addr: %x, Dst Addr: %x\n", ip->saddr, ip->daddr);
    fprintf(f,"            Len: %i   ID: %i   TTL: %i\n", htons(ip->tot_len), ip->id, ip->ttl);
    fprintf(f,"TCP header  Src port: %i   Dst port: %i   Len: %i\n", ntohs(tcp->source), ntohs(tcp->dest), tcp->doff*4);
    fclose(f);
}


int send_raw_tcp_packet(int sock, 
                        uint32_t sip,
                        uint32_t dip,
                        uint16_t sport,//network order
                        uint16_t dport,//network order
                        uint16_t ipid,
                        uint8_t ttl,
						unsigned int seq, 
						unsigned int ack_seq,
                        unsigned char flags,
                        char* payload,
                        unsigned int payload_len
 ) {
    int bytes  = 1;
    struct iphdr *ipHdr;
    struct tcphdr *tcpHdr;

    //Initial guess for the SEQ field of the TCP header
//    unsigned int initSeqGuess = rand() * UINT32_MAX;

    //Data to be appended at the end of the tcp header
    char* data;

    //Ethernet header + IP header + TCP header + data
    char packet[1514];
    
    //Address struct to sendto()
    struct sockaddr_in addr_in;

    //Allocate mem for ip and tcp headers and zero the allocation
    memset(packet, 0, sizeof(packet));
    ipHdr = (struct iphdr *) packet;
    tcpHdr = (struct tcphdr *) (packet + sizeof(struct iphdr));
    data = (char *) (packet + sizeof(struct iphdr) + sizeof(struct tcphdr));
    if(payload && payload_len) 
        memcpy(data, payload, payload_len);

    //Populate ipHdr
    ipHdr->ihl = 5; //5 x 32-bit words in the header
    ipHdr->version = 4; // ipv4
    ipHdr->tos = 0;// //tos = [0:5] DSCP + [5:7] Not used, low delay
    ipHdr->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + payload_len; //total lenght of packet. len(data) = 0
    ipHdr->id = htons(ipid); // 0x00; //16 bit id
    ipHdr->frag_off = 0x40; //16 bit field = [0:2] flags + [3:15] offset = 0x0
    ipHdr->ttl = ttl; //16 bit time to live (or maximal number of hops)
    ipHdr->protocol = IPPROTO_TCP; //TCP protocol
    ipHdr->check = 0; //16 bit checksum of IP header. Can't calculate at this point
    ipHdr->saddr = sip; //32 bit format of source address
    ipHdr->daddr = dip; //32 bit format of source address
    // ipHdr->check = i4_sum_calc(20>>1,(uint16_t*)packet);
//    memcpy(&ip->saddr, &srcaddr4->sin_addr, sizeof(unsigned int));
//    memcpy(&ip->daddr, &destaddr4->sin_addr, sizeof(unsigned int));

    //Populate tcpHdr
    tcpHdr->source = sport; //16 bit in nbp format of source port
    tcpHdr->dest = dport; //16 bit in nbp format of destination port
    tcpHdr->seq = seq;
    tcpHdr->ack_seq = ack_seq;
    tcpHdr->doff = 5; //4 bits: 5 x 32-bit words on tcp header
    tcpHdr->res1 = 0; //4 bits: Not used
    *(packet + sizeof(struct iphdr) + 13) = flags;
    // tcpHdr->cwr = 0; //Congestion control mechanism
    // tcpHdr->ece = 0; //Congestion control mechanism
    // tcpHdr->urg = 0; //Urgent flag
    // tcpHdr->psh = 0; //Push data immediately
    // tcpHdr->ack = 1; //Acknownledge
    // tcpHdr->rst = 0; //RST flag
    // tcpHdr->syn = 0; //SYN flag
    // tcpHdr->fin = 0; //Terminates the connection
    tcpHdr->window = htons(9638);//0xFFFF; //16 bit max number of databytes
    tcpHdr->check = 0; //16 bit check sum. Can't calculate at this point
    tcpHdr->urg_ptr = 0; //16 bit indicate the urgent data. Only if URG flag is set

    compute_checksums(packet,sizeof(struct iphdr),ipHdr->tot_len);

    addr_in.sin_family = AF_INET;
    addr_in.sin_port = tcpHdr->dest;
    addr_in.sin_addr.s_addr = ipHdr->daddr;

    //Finally, send packet
    if((bytes = sendto(sock, packet, ipHdr->tot_len, 0, (struct sockaddr *)&addr_in, sizeof(addr_in))) < 0) {
        // struct in_addr sin;
        // sin.s_addr = ipHdr->saddr;
        // FILE* f = fopen("log.txt","a+");
        // fprintf(f,"%s %x %x %d %d %d\n",inet_ntoa(addr_in.sin_addr),ipHdr->saddr,ipHdr->daddr,htons(ipHdr->tot_len),strlen(data),payload_len);
        // fclose(f);
        // print_packet(packet);
        perror("Error on sendto()");
        return -1;
    }

    return 0;
}

int initRawSocket(int protocol) {
    int sock, one = 1;
    //Raw socket without any protocol-header inside
    if((sock = socket(AF_INET, SOCK_RAW, protocol)) < 0) {
        perror("Error while creating socket");
        exit(-1);
    }

    //Set option IP_HDRINCL (headers are included in packet)
    if(setsockopt(sock, IPPROTO_IP, IP_HDRINCL, (char *)&one, sizeof(one)) < 0) {
        perror("Error while setting socket options");
        exit(-1);
    }

    return sock;
}

void * interceptACK(void *pVoid) {
    uint8_t recvbuf[3000];
    struct sockaddr recvaddr;
    socklen_t len0 = sizeof(struct sockaddr);
    struct sockaddr_in *server = (struct sockaddr_in*) pVoid;
    while (1) {
        recvfrom(raw_sock_rx, recvbuf, 3000, 0, &recvaddr, &len0);
        struct iphdr* ipHeader = (struct iphdr*)recvbuf;
        struct tcphdr* tcpHeader = (struct tcphdr *)(((struct iphdr*)recvbuf) + 1);
        if ( (ipHeader->saddr == server->sin_addr.s_addr) && (tcpHeader->source == server->sin_port) ) {
            if (tcpHeader->syn == 1 && tcpHeader->ack == 1) {
                struct tcphdr *ptr = (struct tcphdr *) (recvbuf + sizeof(struct iphdr));
                seq_1 = ptr->ack_seq;
                ack_seq_1 = htonl((ntohl(ptr->seq) + 1));
                break;
            }
        }
    }
    return;
}

extern int initTCP(uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport) {

    struct sockaddr_in server,client;
	int sock;
	
    srand(time(0));
    sock = socket(AF_INET, SOCK_STREAM, 0);
    raw_sock_tx = initRawSocket(IPPROTO_RAW);
    raw_sock_rx = initRawSocket(IPPROTO_TCP);
	src_ip = sip;
	dst_ip = dip;
	src_port = sport;
	dst_port = dport;

    client.sin_addr.s_addr = sip;
    client.sin_family = AF_INET;
    client.sin_port = sport;
    server.sin_addr.s_addr = dip;
    server.sin_family = AF_INET;
    server.sin_port = dport;

    pthread_t t1;
    // pthread_attr_t t2;
    pthread_create(&t1,0,interceptACK,&server);

    int reuse = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse)) < 0)
        perror("setsockopt(SO_REUSEADDR) failed");

#ifdef SO_REUSEPORT
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, (const char*)&reuse, sizeof(reuse)) < 0) 
        perror("setsockopt(SO_REUSEPORT) failed");
#endif

    //bind local port
    if(sport){
        if (bind(sock, (struct sockaddr*) &client, sizeof(struct sockaddr_in)) < 0){
            printf("Unable to bind\n"); 
            exit(-1);
        } 
    }

    if (connect (sock, (struct sockaddr *) &server, sizeof(struct sockaddr_in)))
        exit(-1);

    return sock;
}

extern int sendData(int stream_socket, uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport,
                    uint8_t ttl, uint8_t* payload, int payload_len, uint16_t ip_id) {

//    struct sockaddr_in src_addr;
//    socklen_t len = sizeof(src_addr);
//    getsockname(stream_socket, (struct sockaddr *)&src_addr, &len);

    send_raw_tcp_packet(raw_sock_tx, sip, dip, sport, dport, ip_id, ttl, seq_1, ack_seq_1, 16, payload, payload_len);

    return 0;
}

extern int sendAck(uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport,
        uint8_t ttl, uint8_t* payload, int payload_len, uint16_t ip_id) {
    raw_sock_tx = initRawSocket(IPPROTO_RAW);
    send_raw_tcp_packet(raw_sock_tx, sip, dip, sport, dport, ip_id, ttl, ((uint32_t)rand()) % 0xffffffff, ((uint32_t)rand()) % 0xffffffff, 16, payload, payload_len);
}

extern int sendSynAck(uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport,
                   uint8_t ttl, uint8_t* payload, int payload_len, uint16_t ip_id) {
    raw_sock_tx = initRawSocket(IPPROTO_RAW);
    send_raw_tcp_packet(raw_sock_tx, sip, dip, sport, dport, ip_id, ttl, ((uint32_t)rand()) % 0xffffffff, ((uint32_t)rand()) % 0xffffffff, 18, payload, payload_len);
}