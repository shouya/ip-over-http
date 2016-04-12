#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

/* https://www.kernel.org/doc/Documentation/networking/tuntap.txt */


int tun_alloc(const char *dev) {
  struct ifreq ifr;
  int fd;

  fd = open("/dev/net/tun", O_RDWR);
  if (fd < 0)
    return -1;

  memset(&ifr, 0, sizeof(ifr));
  ifr.ifr_flags = IFF_TUN;

  strncpy(ifr.ifr_name, dev, IFNAMSIZ);

  if (ioctl(fd, TUNSETIFF, (void *) &ifr) < 0) {
    close(fd);
    perror("tun_alloc");
    return errno;
  }

  return fd;
}

int set_addr(const char *dev, const char* ip, int mask) {
  char buf[100];

  snprintf(buf, 100, "ip addr add %s/%d dev %s", ip, mask, dev);
  system(buf);

  snprintf(buf, 100, "ip link set %s up", dev);
  system(buf);

  fprintf(stderr, "LOG: set addr %s/%d for %s\n", ip, mask, dev);

  return 0;
}

int main() {
  const char dev[IFNAMSIZ] = "tun0";
  const char *tun_ip = "10.45.99.1";
  const int mask = 24;

  int fd;

  fd = tun_alloc(dev);

  printf("%s allocated: %d\n", dev, fd);

  set_addr(dev, tun_ip, mask);

  while (1);

  close(fd);

  return 0;
};
