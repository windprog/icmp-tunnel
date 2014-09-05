#include <stdio.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/signal.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
//gcc send.c -fPIC -shared -o s.so

int sock = -1;

int sendicmp(char ip[],char buf[],int len)
{
  if (sock==-1){sock=socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);}
  struct sockaddr_in host;
  int addrlen = sizeof(struct sockaddr);
  host.sin_family = AF_INET;
  host.sin_addr.s_addr = inet_addr(ip);
  int sendlen = sendto(sock, buf, len, 0, (struct sockaddr*)&host, addrlen);
  if (sendlen<0)
  {
     return errno*(-1);
  }
  else
  {
     return sendlen;
  }
}

int geterror(int err,char res[])
{
  strcpy(res, strerror(errno));
  return 0;
}
