#include "zlib.h"
#include <arpa/inet.h>
#include <pcap.h>
#include <pcap/pcap.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
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

struct tcp_stream {
  uint32_t src_ip;
  uint16_t src_port;
  uint32_t dst_ip;
  uint16_t dst_port;
  char *buffer;
  int bufferlen;
  int contentlen;
  int is_gzip;
  int active;
};

#define MAXTCPCONNECTIONS 100
struct tcp_stream tcpconnections[MAXTCPCONNECTIONS];
int connections = 0;

void writetofile(const char *input, int n, const char *src, const char *dst) {
  const char *titlestart = strstr(input, "<title>");
  const char *titleend = strstr(input, "</title>");
  char filename_buf[256];
  const char *filename;
  if (!titlestart || !titleend) {
    filename = "unknown.html";
  } else {
    titlestart += 7;
    while (*titlestart == ' ' || *titlestart == '\t' || *titlestart == '\r' ||
           *titlestart == '\n')
      titlestart++;
    while (titleend > titlestart &&
           (titleend[-1] == ' ' || titleend[-1] == '\t' ||
            titleend[-1] == '\r' || titleend[-1] == '\n'))
      titleend--;
    int titlelen = titleend - titlestart;
    if (titlelen <= 0) {
      filename = "unknown.html";
    } else {
      char title[titlelen + 1];
      strncpy(title, titlestart, titlelen);
      title[titlelen] = '\0';
      snprintf(filename_buf, sizeof(filename_buf), "%s.html", title);
      filename = filename_buf;
    }
  }
  FILE *f = fopen(filename, "w");
  if (f) {
    fwrite(input, 1, n, f);
    fclose(f);
  }
  printf("SAVED\t%s\t%s\t%s\n", filename, src, dst);
  fflush(stdout);
}

void decompress(const char *bodyptr, int bodylength, const char *src,
                const char *dst) {
  z_stream streamy = {0};
  streamy.next_in = (Bytef *)bodyptr;
  streamy.avail_in = bodylength;
  inflateInit2(&streamy, 16 + MAX_WBITS);

  char *outbuf = NULL;
  size_t outlen = 0;
  int ret;
  char chunk[65536];

  do {
    streamy.next_out = (Bytef *)chunk;
    streamy.avail_out = sizeof(chunk);
    ret = inflate(&streamy, Z_NO_FLUSH);
    size_t have = sizeof(chunk) - streamy.avail_out;
    outbuf = realloc(outbuf, outlen + have);
    memcpy(outbuf + outlen, chunk, have);
    outlen += have;
  } while (ret == Z_OK);

  inflateEnd(&streamy);

  if (ret == Z_STREAM_END)
    writetofile(outbuf, outlen, src, dst);
  else
    fprintf(stderr, "inflate failed: %d\n", ret);

  free(outbuf);
}

void flush_stream(struct tcp_stream *s) {
  char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
  struct in_addr sa, da;
  sa.s_addr = s->src_ip;
  da.s_addr = s->dst_ip;
  inet_ntop(AF_INET, &sa, src_ip, sizeof(src_ip));
  inet_ntop(AF_INET, &da, dst_ip, sizeof(dst_ip));
  char src[48], dst[48];
  snprintf(src, sizeof(src), "%s:%d", src_ip, ntohs(s->src_port));
  snprintf(dst, sizeof(dst), "%s:%d", dst_ip, ntohs(s->dst_port));
  if (s->is_gzip)
    decompress(s->buffer, s->bufferlen, src, dst);
  else
    writetofile(s->buffer, s->bufferlen, src, dst);
  free(s->buffer);
  s->buffer = NULL;
  s->bufferlen = 0;
  s->contentlen = 0;
  s->active = 0;
}

void callback(u_char *args, const struct pcap_pkthdr *header,
              const u_char *packet) {
  fprintf(stderr, "packet length: %d\n", header->len);
  ethernet = (struct sniff_ethernet *)(packet);
  ip = (struct sniff_ip *)(packet + SIZE_ETHERNET);
  size_ip = IP_HL(ip) * 4;
  if (size_ip < 20) {
    fprintf(stderr, "   * Invalid IP header length: %u bytes\n", size_ip);
    return;
  }
  tcp = (struct sniff_tcp *)(packet + SIZE_ETHERNET + size_ip);
  size_tcp = TH_OFF(tcp) * 4;
  if (size_tcp < 20) {
    fprintf(stderr, "   * Invalid TCP header length: %u bytes\n", size_tcp);
    return;
  }
  payload = (char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
  int payload_len = header->len - (SIZE_ETHERNET + size_ip + size_tcp);
  if (payload_len <= 0)
    return;

  const char *body = NULL;
  int body_len = 0;
  int is_gzip = 0;
  int is_new_stream = 0;
  const char *header_end = NULL;
  if (payload_len > 5 && memcmp(payload, "HTTP/", 5) == 0)
    header_end = strstr(payload, "\r\n\r\n");
  if (header_end) {
    if (strstr(payload, "Content-Encoding: gzip")) {
      is_gzip = 1;
      is_new_stream = 1;
    } else if (strstr(payload, "Content-Type: text/html")) {
      is_gzip = 0;
      is_new_stream = 1;
    }
    if (is_new_stream) {
      body = header_end + 4;
      body_len = payload_len - (body - payload);
    }
  } else {
    for (int i = 0; i < connections; i++) {

      if (!body || body_len <= 0)
        return;

      int found = 0;
      for (int i = 0; i < connections; i++) {
        if (ip->ip_src.s_addr == tcpconnections[i].src_ip &&
            ip->ip_dst.s_addr == tcpconnections[i].dst_ip &&
            tcp->th_sport == tcpconnections[i].src_port &&
            tcp->th_dport == tcpconnections[i].dst_port) {
          found = 1;
          free(tcpconnections[i].buffer);
          tcpconnections[i].buffer = malloc(body_len);
          memcpy(tcpconnections[i].buffer, body, body_len);
          tcpconnections[i].bufferlen = body_len;
          tcpconnections[i].is_gzip = is_gzip;
          tcpconnections[i].active = 1;
          const char *cls = strstr(payload, "Content-Length: ");
          if (cls)
            tcpconnections[i].contentlen = atoi(cls + 16);
          else
            tcpconnections[i].contentlen = body_len;
          fprintf(
              stderr,
              "new response on existing stream: bufferlen=%d contentlen=%d\n",
              tcpconnections[i].bufferlen, tcpconnections[i].contentlen);
          if (tcpconnections[i].bufferlen >= tcpconnections[i].contentlen)
            flush_stream(&tcpconnections[i]);
          break;
        }
      }

      if (!found) {
        if (connections >= MAXTCPCONNECTIONS) {
          fprintf(stderr, "too many connections, dropping\n");
          return;
        }
        tcpconnections[connections].src_ip = ip->ip_src.s_addr;
        tcpconnections[connections].dst_ip = ip->ip_dst.s_addr;
        tcpconnections[connections].src_port = tcp->th_sport;
        tcpconnections[connections].dst_port = tcp->th_dport;
        tcpconnections[connections].bufferlen = body_len;
        tcpconnections[connections].is_gzip = is_gzip;
        tcpconnections[connections].active = 1;
        tcpconnections[connections].buffer = malloc(body_len);
        memcpy(tcpconnections[connections].buffer, body, body_len);
        const char *cls = strstr(payload, "Content-Length: ");
        if (cls)
          tcpconnections[connections].contentlen = atoi(cls + 16);
        else
          tcpconnections[connections].contentlen = body_len;
        fprintf(stderr, "new stream: bufferlen=%d contentlen=%d\n",
                tcpconnections[connections].bufferlen,
                tcpconnections[connections].contentlen);
        if (tcpconnections[connections].bufferlen >=
            tcpconnections[connections].contentlen)
          flush_stream(&tcpconnections[connections]);
        connections++;
      }
    }
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

  fprintf(stderr, "looking for devices\n");
  if (pcap_findalldevs(&alldevs, errbuf) != 0) {
    fprintf(stderr, "findalldevs hot verkockt error: %s\n", errbuf);
    return (2);
  };
  dev = alldevs->name;

  fprintf(stderr, "found device %s\n", alldevs->name);
  if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
    fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
    net = 0;
    mask = 0;
  }
  fprintf(stderr, "printing network ip: \n");
  uint8_t *bytes = (uint8_t *)&net;
  fprintf(stderr, "%d.%d.%d.%d\n", bytes[0], bytes[1], bytes[2], bytes[3]);

  handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  fprintf(stderr, "link type: %d\n", pcap_datalink(handle));
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
