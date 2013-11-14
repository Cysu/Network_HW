#include <map>
#include "sysInclude.h"

#define MAX(a, b) ((a) > (b) ? (a) : (b))

using std::map;

typedef unsigned int uint;
typedef unsigned short ushort;
typedef unsigned char uchar;

enum TcpState
{
    CLOSED,
    SYN_SENT,
    ESTABLISHED,
    FIN_WAIT_1,
    FIN_WAIT_2,
    TIME_WAIT
};

struct TcpHeader
{
    ushort srcPort;
    ushort dstPort;
    uint seqNum;
    uint ackNum;
    char offset;
    uchar flag;
    ushort winSize;
    ushort checksum;
    short urgPtr;
};

struct Tcb
{
    TcpState state;
    uint sockfd;
    uint srcAddr;
    uint dstAddr;
    ushort srcPort;
    ushort dstPort;
    uint seqNum;
    uint ackNum;
};

int gSeqNum = 1001;
int gAckNum = 0;

TcpState gState = CLOSED;

map<uint, Tcb> tcbs;

char recvBuf[1024];
int recvBufLen;

extern void tcp_DiscardPkt(char *pBuffer, int type);

extern void tcp_sendReport(int type);

extern void tcp_sendIpPkt(unsigned char *pData, UINT16 len, unsigned int srcAddr, unsigned int dstAddr, UINT8 ttl);

extern int waitIpPacket(char *pBuffer, int timeout);

extern uint getIpv4Address();

extern uint getServerIpv4Address();

void ntoh(TcpHeader *tcpHeader)
{
    tcpHeader->srcPort = ntohs(tcpHeader->srcPort);
    tcpHeader->dstPort = ntohs(tcpHeader->dstPort);
    tcpHeader->seqNum = ntohl(tcpHeader->seqNum);
    tcpHeader->ackNum = ntohl(tcpHeader->ackNum);
    tcpHeader->winSize = ntohs(tcpHeader->winSize);
    tcpHeader->urgPtr = ntohs(tcpHeader->urgPtr);
}

void hton(TcpHeader *tcpHeader)
{
    tcpHeader->srcPort = htons(tcpHeader->srcPort);
    tcpHeader->dstPort = htons(tcpHeader->dstPort);
    tcpHeader->seqNum = htonl(tcpHeader->seqNum);
    tcpHeader->ackNum = htonl(tcpHeader->ackNum);
    tcpHeader->winSize = htons(tcpHeader->winSize);
    tcpHeader->urgPtr = htons(tcpHeader->urgPtr);
}

// These addrs are network byte-order.

ushort getChecksum(char *buffer, ushort len, uint srcAddr, uint dstAddr)
{
    uint ret = 0;
    ret += (srcAddr >> 16);
    ret += (srcAddr & 0xffff);
    ret += (dstAddr >> 16);
    ret += (dstAddr & 0xffff);
    ret += (IPPROTO_TCP << 8);
    ret += htons(len);

    // Ignore the checksum field.
    for (int i = 0; i < len; i += 2) 
        if (i != 16) ret += *(ushort*)(buffer + i);

    while (ret >> 16) ret = (ret >> 16) + (ret & 0xffff);
    
    return (ushort)(~ret);
}

void setup_env(const Tcb &tcb)
{
    gState = tcb.state;
    gSeqNum = tcb.seqNum;
    gAckNum = tcb.ackNum;
}

void update_tcb(Tcb &tcb)
{
    tcb.state = gState;
    tcb.seqNum = gSeqNum;
    tcb.ackNum = gAckNum;
}

void wait_recv()
{
    memset(recvBuf, 0, sizeof(recvBuf));
    while ((recvBufLen = waitIpPacket(recvBuf, 1000)) == -1);
}

uint getFreeIdx()
{
    for (uint i = 1; ; ++i)
        if (tcbs.find(i) == tcbs.end()) return i;
}

// These addrs are network byte-order.

int stud_tcp_input(char *pBuffer, ushort len, uint srcAddr, uint dstAddr)
{
    TcpHeader *tcpHeader = (TcpHeader*)pBuffer;

    // Check checksum.
    if (getChecksum(pBuffer, len, srcAddr, dstAddr) != tcpHeader->checksum) return -1;

    // Swap byte-order.
    ntoh(tcpHeader);

    // Check sequence number.
    if (gState != SYN_SENT && tcpHeader->seqNum != gAckNum) {
        tcp_DiscardPkt(pBuffer, STUD_TCP_TEST_SEQNO_ERROR);
        return -1;
    }

    if (tcpHeader->flag & PACKET_TYPE_ACK) gSeqNum = tcpHeader->ackNum;

    // State machine processing.
    if (gState == ESTABLISHED && len > 20) {
        gAckNum = tcpHeader->seqNum + len - 20;
        stud_tcp_output(NULL, 0, PACKET_TYPE_ACK,
                        tcpHeader->dstPort, tcpHeader->srcPort,
                        ntohl(dstAddr), ntohl(srcAddr));
    } else if (gState == SYN_SENT) {
        gAckNum = tcpHeader->seqNum + 1;
        if (tcpHeader->flag == PACKET_TYPE_SYN_ACK) {
            stud_tcp_output(NULL, 0, PACKET_TYPE_ACK,
                            tcpHeader->dstPort, tcpHeader->srcPort,
                            ntohl(dstAddr), ntohl(srcAddr));
            gState = ESTABLISHED;
        }
    } else if (gState == FIN_WAIT_1) {
        if (tcpHeader->flag == PACKET_TYPE_ACK) {
            gState = FIN_WAIT_2;
        }
    } else if (gState == FIN_WAIT_2) {
        gAckNum = tcpHeader->seqNum + 1;
        if (tcpHeader->flag == PACKET_TYPE_FIN_ACK) {
            stud_tcp_output(NULL, 0, PACKET_TYPE_ACK,
                            tcpHeader->dstPort, tcpHeader->srcPort,
                            ntohl(dstAddr), ntohl(srcAddr));
            gState = TIME_WAIT;
        }
    }

    return 0;
}


// These addrs are host byte-order.
void stud_tcp_output(char *pData, ushort len, uchar flag,
                     ushort srcPort, ushort dstPort,
                     uint srcAddr, uint dstAddr)
{
    char *tcpSegment = new char[20 + len];

    // Copy ip datagram.
    memcpy(tcpSegment + 20, pData, len);

    // Build header.
    TcpHeader *tcpHeader = (TcpHeader*) tcpSegment;
    tcpHeader->srcPort = srcPort;
    tcpHeader->dstPort = dstPort;
    tcpHeader->seqNum = gSeqNum;
    tcpHeader->ackNum = gAckNum;
    tcpHeader->offset = 0x50;
    tcpHeader->flag = flag;
    tcpHeader->winSize = 1024;
    tcpHeader->checksum = 0;
    tcpHeader->urgPtr = 0;
    
    hton(tcpHeader);
    tcpHeader->checksum = getChecksum(tcpSegment, 20+len, htonl(srcAddr), htonl(dstAddr));

    tcp_sendIpPkt((uchar*)tcpSegment, 20+len, srcAddr, dstAddr, 255);

    if (flag == PACKET_TYPE_SYN) gState = SYN_SENT;
    else if (flag == PACKET_TYPE_FIN_ACK) gState = FIN_WAIT_1;

    delete[] tcpSegment;
}

int stud_tcp_socket(int domain, int type, int protocol)
{
    Tcb tcb;
    tcb.state = CLOSED;
    tcb.seqNum = 1001;
    tcb.ackNum = 0;
    tcb.sockfd = getFreeIdx();
    tcbs[tcb.sockfd] = tcb;

    return tcb.sockfd;
}

int stud_tcp_connect(int sockfd, struct sockaddr_in *addr, int addrlen)
{
    if (tcbs.find(sockfd) == tcbs.end()) return -1;

    Tcb &tcb = tcbs[sockfd];
    tcb.srcPort = 2009;
    tcb.dstPort = ntohs(addr->sin_port);
    tcb.srcAddr = getIpv4Address();
    tcb.dstAddr = ntohl(addr->sin_addr.s_addr);

    setup_env(tcb);
    stud_tcp_output(NULL, 0, PACKET_TYPE_SYN, tcb.srcPort, tcb.dstPort, tcb.srcAddr, tcb.dstAddr);
    wait_recv();
    stud_tcp_input(recvBuf, recvBufLen, htonl(tcb.dstAddr), htonl(tcb.srcAddr));
    update_tcb(tcb);

    return 0;
}

int stud_tcp_send(int sockfd, const uchar *pData, ushort datalen, int flags)
{
    if (tcbs.find(sockfd) == tcbs.end()) return -1;
    Tcb &tcb = tcbs[sockfd];
    if (tcb.state != ESTABLISHED) return -1;

    setup_env(tcb);
    stud_tcp_output((char*)pData, datalen, flags, tcb.srcPort, tcb.dstPort, tcb.srcAddr, tcb.dstAddr);
    wait_recv();
    stud_tcp_input(recvBuf, recvBufLen, htonl(tcb.dstAddr), htonl(tcb.srcAddr));
    update_tcb(tcb);

    return 0;
}

int stud_tcp_recv(int sockfd, uchar *pData, ushort datalen, int flags)
{
    if (tcbs.find(sockfd) == tcbs.end()) return -1;
    Tcb &tcb = tcbs[sockfd];
    if (tcb.state != ESTABLISHED) return -1;

    setup_env(tcb);
    wait_recv();
    int ret = stud_tcp_input(recvBuf, recvBufLen, htonl(tcb.dstAddr), htonl(tcb.srcAddr));
    if (ret != -1) memcpy(pData, recvBuf+20, recvBufLen-20);
    update_tcb(tcb);

    return 0;
}

int stud_tcp_close(int sockfd)
{
    if (tcbs.find(sockfd) == tcbs.end()) return -1;
    Tcb &tcb = tcbs[sockfd];
    if (tcb.state != ESTABLISHED) return -1;

    setup_env(tcb);
    stud_tcp_output(NULL, 0, PACKET_TYPE_FIN_ACK, tcb.srcPort, tcb.dstPort, tcb.srcAddr, tcb.dstAddr);
    wait_recv();
    stud_tcp_input(recvBuf, recvBufLen, htonl(tcb.dstAddr), htonl(tcb.srcAddr));
    wait_recv();
    stud_tcp_input(recvBuf, recvBufLen, htonl(tcb.dstAddr), htonl(tcb.srcAddr));
    update_tcb(tcb);

    tcbs.erase(tcb.sockfd);

    return 0;
}
