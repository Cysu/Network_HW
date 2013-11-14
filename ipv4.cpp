/*
* THIS FILE IS FOR IP TEST
*/
// system support
#include "sysInclude.h"

typedef unsigned int uint;
typedef unsigned short ushort;

extern void ip_DiscardPkt(char *pBuffer, int type);

extern void ip_SendtoLower(char *pBuffer, int length);

extern void ip_SendtoUp(char *pBuffer, int length);

extern uint getIpv4Address();

// implemented by students

int stud_ip_recv(char *pBuffer, ushort length)
{
    // Resolve header information.
    int version = (int)(pBuffer[0]) >> 4;
    int ihl = (int)(pBuffer[0]) & 0xf;
    int ttl = (int)(pBuffer[8]);
    int checkSum = ntohs(*(ushort *)(pBuffer + 10));
    uint dstAddr = ntohl(*(uint *)(pBuffer + 16));

    if (version != 4) {
        ip_DiscardPkt(pBuffer, STUD_IP_TEST_VERSION_ERROR);
        return 1;
    }

    if (ihl < 5) {
        ip_DiscardPkt(pBuffer, STUD_IP_TEST_HEADLEN_ERROR);
        return 1;
    }

    if (ttl == 0) {
        ip_DiscardPkt(pBuffer, STUD_IP_TEST_TTL_ERROR);
        return 1;
    }

    if (dstAddr != getIpv4Address() &&
        dstAddr != 0xffffff) {
        ip_DiscardPkt(pBuffer, STUD_IP_TEST_DESTINATION_ERROR);
        return 1;
    }

    int sum = 0;
    for (int i = 0; i < 10; ++i)
        sum += (int)(*(ushort *)(pBuffer + i*2));
    while (sum > 0xffff)
        sum = (sum & 0xffff) + (sum >> 16);
    if (sum != 0xffff) {
        ip_DiscardPkt(pBuffer, STUD_IP_TEST_CHECKSUM_ERROR);
        return 1;
    }

    ip_SendtoUp(pBuffer, length);

    return 0;
}

int stud_ip_Upsend(char *pBuffer, ushort len, uint srcAddr,
                    uint dstAddr, byte protocol, byte ttl)
{
    char header[20];
    memset(header, 0, 20);

    header[0] = 0x45;
    *(ushort *)(header + 2) = htons((ushort)(20+len));
    header[8] = ttl;
    header[9] = protocol;

    *(uint *)(header + 12) = htonl(srcAddr);
    *(uint *)(header + 16) = htonl(dstAddr);

    int sum = 0;
    for (int i = 0; i < 10; ++i)
        sum += (int)(*(ushort *)(header + i*2));
    while (sum > 0xffff)
        sum = (sum & 0xffff) + (sum >> 16);
    sum = ~((ushort)sum);

    *(ushort *)(header + 10) = (ushort)sum;

    char *msg = new char[len + 20];
    memcpy(msg, header, 20);
    memcpy(msg+20, pBuffer, len);

    ip_SendtoLower(msg, len+20);

    return 0;
}
