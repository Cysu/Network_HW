/*
* THIS FILE IS FOR IPv6 FORWARD TEST
*/
// system support

#include <cstring>
#include <vector>
#include "sysinclude.h"

using std::vector;

extern void ipv6_fwd_DiscardPkt(char *pBuffer, int type);
extern void ipv6_fwd_SendtoLower(char *pBuffer, int length, ipv6_addr *nexthop);
extern void getIpv6Address(ipv6_addr *pAddr);
extern void ipv6_fwd_LocalRcv(char *pBuffer, int length);

vector<stud_ipv6_route_msg> rTable;

void printAddr(const ipv6_addr &a)
{
    for (int i = 0; i < 16; ++i)
        printf("%x:", (unsigned char)(a.bAddr[i]));
    printf("\n");
}

bool equal(const ipv6_addr &a, const ipv6_addr &b)
{
    for (int i = 0; i < 4; ++i)
        if (a.dwAddr[i] != b.dwAddr[i]) return false;
    return true;
}

bool checkMask(const ipv6_addr &a, const ipv6_addr &b, int masklen)
{
    int nrSeg = masklen / 32;
    int nrBit = masklen % 32;

    for (int i = 0; i < nrSeg; ++i)
        if (a.dwAddr[i] != b.dwAddr[i]) return false;

    if (nrSeg > 3 || nrBit == 0) return true;

    int x = ntohl(a.dwAddr[nrSeg]), y = ntohl(b.dwAddr[nrSeg]);
    for (int i = 0; i < nrBit; ++i) {
        int mask = (1 << (31-i));
        if ((x & mask) != (y & mask)) return false;
    }

    return true;
}

void stud_ipv6_Route_Init()
{
    rTable.clear();
    return;
}

void stud_ipv6_route_add(stud_ipv6_route_msg *proute)
{
    rTable.push_back(*proute);
    return;
}

int stud_ipv6_fwd_deal(char *pBuffer, int length)
{
    // Resolve the ipv6 header.
    int hopLimit = (int)(pBuffer[7]);
    ipv6_addr dstAddr;
    memcpy(&dstAddr, pBuffer+24, 16);


    // Check if the package is for local machine.
    ipv6_addr localAddr;
    getIpv6Address(&localAddr);

    printAddr(dstAddr);
    printAddr(localAddr);

    if (equal(dstAddr, localAddr)) {
        ipv6_fwd_LocalRcv(pBuffer, length);
        return 0;
    }


    // Check the hop.
    if (hopLimit == 0) {
        ipv6_fwd_DiscardPkt(pBuffer, STUD_IPV6_FORWARD_TEST_HOPLIMIT_ERROR);
        return -1;
    }


    // Check the route table %rTable.
    int maxMask = 0, maxTid = -1;
    for (int i = 0; i < rTable.size(); ++i) {
        stud_ipv6_route_msg &rItem = rTable[i];
        if (rItem.masklen <= maxMask) continue;
        if (checkMask(dstAddr, rItem.dest, rItem.masklen)) {
            maxMask = rItem.masklen;
            maxTid = i;
        }
    }

    if (maxTid != -1) {
        char newPacket[length];
        memcpy(newPacket, pBuffer, length);
        newPacket[7] = hopLimit - 1;
        ipv6_fwd_SendtoLower(newPacket, length, &rTable[maxTid].nexthop);
        return 0;
    } else {
        ipv6_fwd_DiscardPkt(pBuffer, STUD_IPV6_FORWARD_TEST_NOROUTE);
        return -1;
    }
}
