#include <pcap.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <sys/types.h>

void callback(u_char *args, const struct pcap_pkthdr *header,
              const u_char *packet) {
  printf("packet length: %d\n", header->len);
}

int main(int argc, char *argv[]) {
  pcap_t *handle;
  char *dev;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "port 80 or port 8080 or port 8880";
  bpf_u_int32 mask;
  bpf_u_int32 net;
  struct pcap_pkthdr header;
  const u_char *packet;
  pcap_if_t *alldevs;

  if (pcap_findalldevs(&alldevs, errbuf) != 0) {
    fprintf(stderr, "findalldevs hot verkockt error: %s\n", errbuf);
    return (2);
  };
  dev = alldevs->name;

  if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
    fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
    net = 0;
    mask = 0;
  }

  handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
    return (2);
  }

  if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
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
