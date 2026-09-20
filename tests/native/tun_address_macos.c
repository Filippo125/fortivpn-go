/* Regression for strongSwan's macOS IPv6 ifreq overflow. No root or network
 * changes: ioctl is intercepted, but real host objects and TUN code are used. */
#include <assert.h>
#include <stdarg.h>
#include <string.h>
#include <sys/ioctl.h>
#include <netinet/in_var.h>
#include <netinet6/in6_var.h>
static int fake_ioctl(int, unsigned long, ...);
#define ioctl fake_ioctl
#include TUN_SOURCE
#undef ioctl

static int calls4, calls6;
static unsigned int expected_prefix;
static int fake_ioctl(int fd, unsigned long request, ...)
{
 va_list args;
 va_start(args, request);
 void *data = va_arg(args, void*);
 va_end(args);
 if (request == SIOCAIFADDR_IN6) {
  struct in6_aliasreq *a = data;
  assert(fd == 456);
  assert(strcmp(a->ifra_name,"utun99")==0);
  assert(a->ifra_addr.sin6_len==sizeof(struct sockaddr_in6));
  assert(a->ifra_addr.sin6_family==AF_INET6);
  assert(a->ifra_addr.sin6_addr.s6_addr[0]==0xfd);
  assert(a->ifra_addr.sin6_addr.s6_addr[15]==0x10);
  assert(memcmp(&a->ifra_addr,&a->ifra_dstaddr,sizeof(a->ifra_addr))==0);
  assert(a->ifra_lifetime.ia6t_vltime==0xffffffff);
  assert(a->ifra_lifetime.ia6t_pltime==0xffffffff);
  for (unsigned int i=0;i<16;i++) {
   assert(a->ifra_prefixmask.sin6_addr.s6_addr[i] == (i<expected_prefix/8 ? 255:0));
  }
  calls6++;
 } else if (request==SIOCAIFADDR) {
  struct in_aliasreq *a=data;
  assert(fd==123);
  assert(a->ifra_addr.sin_family==AF_INET);
  calls4++;
 } else {
  /* Old implementation reaches this IPv4 ioctl path before overflowing on v6. */
  assert(request==SIOCSIFADDR || request==SIOCSIFDSTADDR || request==SIOCSIFNETMASK);
 }
 return 0;
}
int main(void)
{
 char *addresses[]={"203.0.113.10","2001:db8:200::10","2001:db8:200::10"};
 const unsigned int prefixes[]={32,128,64};
 for (int i=0;i<3;i++) {
  private_tun_device_t device={.sock=123};
#ifndef ORIGINAL_TUN
  device.sock_v6=456;
#endif
  strcpy(device.if_name,"utun99");
  host_t *host=host_create_from_string(addresses[i],0);
  assert(host);
  expected_prefix=prefixes[i];
  assert(_set_address(&device,host,prefixes[i]));
  device.address->destroy(device.address);
  host->destroy(host);
 }
 assert(calls4==1 && calls6==2);
 return 0;
}
