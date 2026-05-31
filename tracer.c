#include "zlib.h"
#include <pcap.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <zconf-ng.h>

// structure definitions by tim carstens
/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN 6

/* Ethernet header */
struct sniff_ethernet {
  u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
  u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
  u_short ether_type;                 /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
  u_char ip_vhl;                 /* version << 4 | header length >> 2 */
  u_char ip_tos;                 /* type of service */
  u_short ip_len;                /* total length */
  u_short ip_id;                 /* identification */
  u_short ip_off;                /* fragment offset field */
#define IP_RF 0x8000             /* reserved fragment flag */
#define IP_DF 0x4000             /* don't fragment flag */
#define IP_MF 0x2000             /* more fragments flag */
#define IP_OFFMASK 0x1fff        /* mask for fragmenting bits */
  u_char ip_ttl;                 /* time to live */
  u_char ip_p;                   /* protocol */
  u_short ip_sum;                /* checksum */
  struct in_addr ip_src, ip_dst; /* source and dest address */
};
#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip) (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
  u_short th_sport; /* source port */
  u_short th_dport; /* destination port */
  tcp_seq th_seq;   /* sequence number */
  tcp_seq th_ack;   /* acknowledgement number */
  u_char th_offx2;  /* data offset, rsvd */
#define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)
  u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN | TH_SYN | TH_RST | TH_ACK | TH_URG | TH_ECE | TH_CWR)
  u_short th_win; /* window */
  u_short th_sum; /* checksum */
  u_short th_urp; /* urgent pointer */
};

/* ethernet headers are always exactly 14 bytes */
#define SIZE_ETHERNET 14

const struct sniff_ethernet *ethernet; /* The ethernet header */
const struct sniff_ip *ip;             /* The IP header */
const struct sniff_tcp *tcp;           /* The TCP header */
const char *payload;                   /* Packet payload */

u_int size_ip;
u_int size_tcp;

void decompress(const char *bodyptr, int bodylength) {
  z_stream streamy;
  streamy.zalloc = Z_NULL;
  streamy.zfree = Z_NULL;
  streamy.opaque = Z_NULL;
  streamy.next_in = (Bytef *)bodyptr;
  streamy.avail_in = bodylength;

  inflateInit2(&streamy, 16 + MAX_WBITS);

  char outbuf[65536];

  streamy.next_out = (Bytef *)outbuf;
  streamy.avail_out = sizeof(outbuf);

  inflate(&streamy, Z_FINISH);
  inflateEnd(&streamy);

  char *titlestart = strstr(outbuf, "<title>");
  titlestart += 7;
  char *titleend = strstr(outbuf, "</title>");
  int titlelen = titleend - titlestart;
  char title[titlelen + 1];
  strncpy(title, titlestart, titlelen);
  title[titlelen] = '\0';
  char filename[titlelen + 6];
  snprintf(filename, sizeof(filename), "%s.html", title);

  FILE *f = fopen(filename, "w");
  fwrite(outbuf, 1, streamy.total_out, f);
  fclose(f);
  fwrite(outbuf, 1, streamy.total_out, stdout);
}

void callback(u_char *args, const struct pcap_pkthdr *header,
              const u_char *packet) {
  printf("packet length: %d\n", header->len);
  ethernet = (struct sniff_ethernet *)(packet);
  ip = (struct sniff_ip *)(packet + SIZE_ETHERNET);
  size_ip = IP_HL(ip) * 4;
  if (size_ip < 20) {
    printf("   * Invalid IP header length: %u bytes\n", size_ip);
    return;
  }
  tcp = (struct sniff_tcp *)(packet + SIZE_ETHERNET + size_ip);
  size_tcp = TH_OFF(tcp) * 4;
  if (size_tcp < 20) {
    printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
    return;
  }
  payload = (char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
  int payload_len = header->len - (SIZE_ETHERNET + size_ip + size_tcp);

  int body_len;
  const char *body = strstr(payload, "\r\n\r\n");
  if (body && strstr(payload, "Content-Encoding: gzip")) {
    body += 4; // skip past the \r\n\r\n
    body_len = payload_len - (body - payload);
    // pass body and body_len to your decompress function
    decompress(body, body_len);
  }
}

int main(int argc, char *argv[]) {
  pcap_t *handle;
  char *dev;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "ip and (tcp port 80 or tcp port 8080 or tcp port 8880)";
  bpf_u_int32 mask;
  bpf_u_int32 net;
  struct pcap_pkthdr header;
  const u_char *packet;
  pcap_if_t *alldevs;

  printf("looking for devices\n");
  if (pcap_findalldevs(&alldevs, errbuf) != 0) {
    fprintf(stderr, "findalldevs hot verkockt error: %s\n", errbuf);
    return (2);
  };
  dev = alldevs->name;

  printf("found device %s\n", alldevs->name);
  if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
    fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
    net = 0;
    mask = 0;
  }
  printf("printing network ip: \n");
  uint8_t *bytes = (uint8_t *)&net;
  printf("%d.%d.%d.%d\n", bytes[0], bytes[1], bytes[2], bytes[3]);

  handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  printf("link type: %d\n", pcap_datalink(handle));
  if (handle == NULL) {
    fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
    return (2);
  }

  if (pcap_compile(handle, &fp, filter_exp, 0, mask) == -1) {
    fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp,
            pcap_geterr(handle));
    return (2);
  }
  if (pcap_setfilter(handle, &fp) == -1) {
    fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp,
            pcap_geterr(handle));
    return (2);
  }

  pcap_loop(handle, 0, callback, NULL);

  pcap_close(handle);
  return (0);
}
