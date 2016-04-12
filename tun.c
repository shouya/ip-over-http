#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <search.h>

/* https://www.kernel.org/doc/Documentation/networking/tuntap.txt */

const char dev[IFNAMSIZ] = "tun0";
const char *tun_ip = "10.45.99.1";
int mask = 24;
int mtu = 1500;

const char *fake_ip = "10.45.99.2";
const char *redsocks_ip = "10.45.99.1";
int redsocks_port = 23333;

in_addr_t nat_ip[65535];
int nat_port[65535];

const char *http_proxy_ip = "127.0.0.1";
int http_proxy_port = 16808;

int tun_alloc(const char *dev) {
  struct ifreq ifr;
  int fd;

  fd = open("/dev/net/tun", O_RDWR);
  if (fd < 0)
    return -1;

  memset(&ifr, 0, sizeof(ifr));
  ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

  strncpy(ifr.ifr_name, dev, IFNAMSIZ);

  if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0) {
    close(fd);
    return -1;
  }

  fprintf(stderr, "%s allocated: %d\n", dev, fd);
  return fd;
}

int redsocks_alloc(const char *tun_addr, int port) {
  struct sockaddr_in saddr;
  int fd;
  char buff[1025];

  memset(buff, 0, sizeof(buff));

  fd = socket(AF_INET, SOCK_STREAM, 0);

  memset(&saddr, 0, sizeof(saddr));
  saddr.sin_family = AF_INET;
  inet_aton(tun_addr, &saddr.sin_addr);
  saddr.sin_port = htons(port);

  bind(fd, (struct sockaddr *)&saddr, sizeof(saddr));
  listen(fd, 10);

  return fd;
}

int set_addr(const char *dev, const char* ip, int mask, int mtu) {
  char buf[100];

  snprintf(buf, 100, "ip addr add %s/%d dev %s", ip, mask, dev);
  system(buf);

  snprintf(buf, 100, "ip link set %s up", dev);
  system(buf);

  snprintf(buf, 100, "ip link set %s mtu %d", dev, mtu);

  fprintf(stderr, "LOG: set addr %s/%d for %s\n", ip, mask, dev);

  return 0;
}

int redsocks_accept(int fd) {
  struct sockaddr_in caddr;
  int cfd;
  socklen_t len = sizeof(caddr);

  cfd = accept(fd, (struct sockaddr *)&caddr, &len);
  fprintf(stderr, "LOG: redsocks get connection from %s:%hd\n",
          inet_ntoa(caddr.sin_addr),
          ntohs(caddr.sin_port));
  return cfd;
}

unsigned short ip_csum(const char *buf, int sz) {
  unsigned int sum = 0;
  int i;
  for (i = 0; i < sz - 1; i += 2) {
    sum += *(unsigned short *)&buf[i];
  }
  if (sz & 1) {
    sum += (unsigned char)buf[i];
  }

  sum = (sum & 0xFFFF) + (sum >> 16);
  return ~sum;
}

unsigned short tcp_csum(const char *buf, int sz) {
  /* http://locklessinc.com/articles/tcp_checksum/ */
  unsigned int sum = 0;
  int i;

  for (i = 0; i < sz - 1; i += 2) {
    sum += *(unsigned short *)&buf[i];
  }

  if (sz & 1) {
    sum += (unsigned char)buf[i];
  }

  while (sum >> 16)
    sum = (sum & 0xFFFF) + (sum >> 16);

  return ~sum;
}

int mangle_packet(struct iphdr *iph, struct tcphdr *tcph,
                  in_addr_t sip, int sport,
                  in_addr_t dip, int dport) {
  iph->saddr = sip;
  iph->daddr = dip;
  iph->check = 0;
  tcph->source = htons(sport);
  tcph->dest = htons(dport);
  tcph->check = 0;

  iph->check = ip_csum((char *)iph, sizeof(*iph));

  tcph->check = tcp_csum((char *)tcph, ntohs(iph->tot_len) - sizeof(*iph));

  fprintf(stderr,
          "MANGLE: %s:%d -> %s:%d\n",
          inet_ntoa(*(struct in_addr *)&sip), sport,
          inet_ntoa(*(struct in_addr *)&dip), dport);

  return 0;
}

int tun_forward(int fd) {
  char data[4096];
  int sport, dport;
  in_addr_t sip, dip;
  int nbytes;

  struct iphdr *iph = (struct iphdr *)data;
  struct tcphdr *tcph = (struct tcphdr *)&data[sizeof(*iph)];

  memset(data, 0, sizeof(data));

  nbytes = read(fd, &data, sizeof(data));

  fprintf(stderr, "n bytes [%d]\n", nbytes);
  fprintf(stderr, "get: %02hhx %02hhx %02hhx\n", data[1], data[2], data[3], data[4]);

  if (iph->protocol != IPPROTO_TCP) {
    fprintf(stderr,
            "LOG: non-TCP protocol pack [%d], dropping\n",
            iph->protocol);
    return -1;
  }

  sport = ntohs(tcph->source);
  dport = ntohs(tcph->dest);
  sip = iph->saddr;
  dip = iph->daddr;

  fprintf(stderr,
          "LOG: read pack %s:%d -> %s:%d from tun\n",
          inet_ntoa(*(struct in_addr *)&sip), sport,
          inet_ntoa(*(struct in_addr *)&dip), dport);

  if (sip == inet_addr(redsocks_ip) &&
      sport == redsocks_port) {
    fprintf(stderr, "FROM REDSOCKS\n");
    /* packet is from redsocks */
    if ((sip = nat_ip[dport]) == 0)
      return -1;
    sport = nat_port[dport];
    dip = inet_addr(tun_ip);
    mangle_packet(iph, tcph, sip, sport, dip, dport);
  } else {
    fprintf(stderr, "REAL PACKET\n");
    /* packet is to be forwarded */
    nat_ip[sport] = dip;
    nat_port[sport] = dport;

    sip = inet_addr(fake_ip);
    dip = inet_addr(redsocks_ip);
    dport = redsocks_port;
    mangle_packet(iph, tcph, sip, sport, dip, dport);
  }

  write(fd, &data, mtu);

  return 0;
}

void redsocks_client(int client_fd) {
  int proxy_fd;
  struct sockaddr_in proxy_addr;
  struct sockaddr_in source_addr;
  int source_port;
  char buf[2000];
  int i, buf_size, nsel;
  fd_set active_set, rd_set;

  proxy_fd = socket(AF_INET, SOCK_STREAM, 0);

  proxy_addr.sin_family = AF_INET;
  inet_aton(http_proxy_ip, &proxy_addr.sin_addr);
  proxy_addr.sin_port = htons(http_proxy_port);

  if (!connect(proxy_fd,
               (struct sockaddr *)&proxy_addr,
               sizeof(struct sockaddr_in))) {
    perror("connect");
    exit(-1);
  }

  getpeername(client_fd, (struct sockaddr *)&source_addr, NULL);
  source_port = htons(source_addr.sin_port);

  memset(buf, 0, sizeof(buf));
  snprintf(buf, 2000,
           "CONNECT %s:%d HTTP/1.1\r\n"
           "Host: %s:%d\r\n\r\n",
           inet_ntoa(*(struct in_addr *)&nat_ip[source_port]),
           source_port,
           inet_ntoa(*(struct in_addr *)&nat_ip[source_port]),
           source_port);
  fprintf(stderr, "%s", buf);


  write(proxy_fd, buf, strlen(buf));
  read(proxy_fd, buf, sizeof(buf));

  if (!strncmp(buf, "HTTP/1.1 200", strlen("HTTP/1.1 200"))) {
    fprintf(stderr,
            "ERROR: HTTP proxy server gives non-200 status [%s]\n",
            buf);
    close(proxy_fd);
  }

  FD_ZERO(&active_set);
  FD_SET(proxy_fd, &active_set);
  FD_SET(client_fd, &active_set);

  while (1) {
    rd_set = active_set;
    nsel = select(2, &rd_set, 0, 0, 0);
    if (nsel < 0) {
      close(proxy_fd);
      close(client_fd);
      break;
    } else if (nsel == 0) {
      sleep(0);
      continue;
    }

    for (i = 0; i < FD_SETSIZE; ++i) {
      if (!FD_ISSET(i, &rd_set))
        continue;

      if (i == client_fd) {
        buf_size = read(client_fd, buf, sizeof(buf));
        write(proxy_fd, buf, buf_size);
      } else {
        buf_size = read(proxy_fd, buf, sizeof(buf));
        write(client_fd, buf, buf_size);
      }
    }
  }

  close(proxy_fd);
  close(client_fd);

  exit(0);
}



int loop(int tunfd, int redsocksfd) {
  fd_set active_fd_set, read_fd_set;
  int i, nsel;

  FD_ZERO(&active_fd_set);

  FD_SET(tunfd, &active_fd_set);
  FD_SET(redsocksfd, &active_fd_set);

  while (1) {
    read_fd_set = active_fd_set;

    nsel = select(FD_SETSIZE, &read_fd_set, 0, 0, 0);

    if (nsel == 0) {
      sleep(0);
      continue;
    }

    for (i = 0; i < FD_SETSIZE; ++i) {
      if (!FD_ISSET(i, &read_fd_set))
        continue;

      if (i == tunfd) {
        tun_forward(tunfd);
      } else if (i == redsocksfd) {
        int cfd = redsocks_accept(redsocksfd);

        if (fork() == 0) {
          close(tunfd);
          close(redsocksfd);
          redsocks_client(cfd);
          exit(0);
        } else {
          close(cfd);
        }
      }
    }
  }
}


int main() {
  int tunfd, redsocksfd;

  if ((tunfd = tun_alloc(dev)) < 0) {
    perror("tun_alloc");
    exit(-1);
  }
  set_addr(dev, tun_ip, mask, mtu);

  redsocksfd = redsocks_alloc(redsocks_ip, redsocks_port);
  if (redsocksfd < 0) {
    perror("redsocks_alloc");
    exit(-1);
  }

  memset(&nat_ip, 0, sizeof(nat_ip));
  memset(&nat_port, 0, sizeof(nat_port));

  loop(tunfd, redsocksfd);

  return 0;
}
