#include "sysinclude.h"

extern void bgp_FsmTryToConnectPeer();
extern void bgp_FsmSendTcpData(char *pBuf,DWORD dwLen);

typedef unsigned int uint;
typedef unsigned short ushort;
typedef unsigned char uchar;

enum BGP_MSG_TYPE
{
    OPEN = 1,
    UPDATE = 2,
    NOTIFICATION = 3,
    KEEPALIVE = 4
};

struct BgpMsgOpen
{
    uint marker[4];
    ushort length;
    uchar type;
    uchar version;
    ushort as;
    ushort holdTime;
    uint id;
    uchar optParamLength;
    uchar *optParam;
};

struct BgpMsgKeepAlive
{
    uint marker[4];
    ushort length;
    uchar type;
};

struct BgpMsgNotification
{
    uint marker[4];
    ushort length;
    uchar type;
    uchar errCode;
    uchar errSubCode;
    uchar *data;
};

void sendBgpMsgOpen(BgpPeer *peer)
{
    BgpMsgOpen *msg = new BgpMsgOpen;
    memset(msg->marker, 0xff, sizeof(msg->marker));
    msg->length = htons(sizeof(*msg));
    msg->type = (uchar)OPEN;
    msg->version = 4;
    msg->as = htons(peer->bgp_wMyAS);
    msg->holdTime = htons(peer->bgp_dwCfgHoldtime);
    msg->id = htonl(peer->bgp_dwMyRouterID);
    msg->optParamLength = 0;
    msg->optParam = NULL;
    bgp_FsmSendTcpData((char*)msg, sizeof(BgpMsgOpen));
}

void sendBgpMsgKeepAlive()
{
    BgpMsgKeepAlive *msg = new BgpMsgKeepAlive;
    memset(msg->marker, 0xff, sizeof(msg->marker));
    msg->length = htons(sizeof(*msg));
    msg->type = (uchar)KEEPALIVE;
    bgp_FsmSendTcpData((char*)msg, sizeof(*msg));
}

void sendBgpMsgNotification(uint errCode)
{
    BgpMsgNotification *msg = new BgpMsgNotification;
    memset(msg->marker, 0xff, sizeof(msg->marker));
    msg->length = htons(sizeof(*msg));
    msg->type = (uchar)NOTIFICATION;
    msg->errCode = errCode;
    msg->errSubCode = 0;
    msg->data = NULL;
    bgp_FsmSendTcpData((char*)msg, sizeof(*msg));
}

bool checkBgpMsgOpen(BgpPeer *peer, BgpMsgOpen *msg)
{
    // Check all the fields.
    bool valid = true;

    for (int i = 0; i < 4; ++i)
        valid &= (msg->marker[i] == 0xffffffff);
    valid &= (msg->type == (uchar)OPEN);
    valid &= (msg->version == 4);
    valid &= (msg->holdTime > 0);

    return valid;
}

// IE 10
BYTE stud_bgp_FsmEventOpen(BgpPeer *pPeer,BYTE *pBuf,unsigned int len) 
{
    switch (pPeer->bgp_byState) {
        case BGP_STATE_OPENSENT:
            if (checkBgpMsgOpen(pPeer, (BgpMsgOpen*)pBuf)) {
                sendBgpMsgKeepAlive();
                pPeer->bgp_byState = BGP_STATE_OPENCONFIRM;
            } else {
                sendBgpMsgNotification(2);
                pPeer->bgp_byState = BGP_STATE_IDLE;
            }
            break;
        default:
            pPeer->bgp_byState = BGP_STATE_IDLE;
    }
    return 0;
}

// IE 11
BYTE stud_bgp_FsmEventKeepAlive(BgpPeer *pPeer,BYTE *pBuf,unsigned int len)
{
    switch (pPeer->bgp_byState) {
        case BGP_STATE_OPENCONFIRM:
        case BGP_STATE_ESTABLISHED:
            pPeer->bgp_byState = BGP_STATE_ESTABLISHED;
            break;
        default:
            pPeer->bgp_byState = BGP_STATE_IDLE;
    }
    return 0;
}

// IE 13
BYTE stud_bgp_FsmEventNotification(BgpPeer *pPeer,BYTE *pBuf,unsigned int len)
{
    switch (pPeer->bgp_byState) {
        default:
            pPeer->bgp_byState = BGP_STATE_IDLE;
    }
    return 0;
}

// IE 12
BYTE stud_bgp_FsmEventUpdate(BgpPeer *pPeer,BYTE *pBuf,unsigned int len)
{
    switch (pPeer->bgp_byState) {
        case BGP_STATE_ESTABLISHED:
            pPeer->bgp_byState = BGP_STATE_ESTABLISHED;
            break;
        default:
            pPeer->bgp_byState = BGP_STATE_IDLE;
    }
    return 0;
}

// IE 4,6,5
BYTE stud_bgp_FsmEventTcpException(BgpPeer *pPeer,BYTE msgType)           
{

    switch (msgType) {
        case 1:
            switch (pPeer->bgp_byState) {
                case BGP_STATE_OPENSENT:
                    pPeer->bgp_byState = BGP_STATE_ACTIVE;
                    break;
                default:
                    pPeer->bgp_byState = BGP_STATE_IDLE;
            }
            break;
        case 2:
            pPeer->bgp_byState = BGP_STATE_IDLE;
            break;
        case 3:
            switch (pPeer->bgp_byState) {
                case BGP_STATE_CONNECT:
                case BGP_STATE_ACTIVE:
                    pPeer->bgp_byState = BGP_STATE_ACTIVE;
                    break;
                default:
                    pPeer->bgp_byState = BGP_STATE_IDLE;
            }
            break;
    }
    return 0;
}

// IE 7,8,9 
BYTE stud_bgp_FsmEventTimerProcess(BgpPeer *pPeer,BYTE msgType)
{
    switch (msgType) {
        case BGP_CONNECTRETRY_TIMEOUT:
            switch (pPeer->bgp_byState) {
                case BGP_STATE_ACTIVE:
                    pPeer->bgp_byState = BGP_STATE_CONNECT;
                    break;
                default:
                    pPeer->bgp_byState = BGP_STATE_IDLE;
            }
            break;
        case BGP_HOLD_TIMEOUT:
            switch (pPeer->bgp_byState) {
                case BGP_STATE_OPENCONFIRM:
                case BGP_STATE_ESTABLISHED:
                    sendBgpMsgNotification(4);
                default:
                    pPeer->bgp_byState = BGP_STATE_IDLE;
            }
            break;
        case BGP_KEEPALIVE_TIMEOUT:
            switch (pPeer->bgp_byState) {
                case BGP_STATE_OPENCONFIRM:
                case BGP_STATE_ESTABLISHED:
                    sendBgpMsgKeepAlive();
                    break;
                default:
                    pPeer->bgp_byState = BGP_STATE_IDLE;
            }
            break;
    }
    return 0;
}
        
// IE 1
BYTE stud_bgp_FsmEventStart(BgpPeer *pPeer)      
{
    switch (pPeer->bgp_byState) {
        case BGP_STATE_IDLE:
            pPeer->bgp_byState = BGP_STATE_CONNECT;
            break;
    }
    bgp_FsmTryToConnectPeer();
    return 0;
}

// IE 2
BYTE stud_bgp_FsmEventStop(BgpPeer *pPeer)       
{
    switch (pPeer->bgp_byState) {
        default:
            pPeer->bgp_byState = BGP_STATE_IDLE;
    }
    return 0;
}

// IE 3
BYTE stud_bgp_FsmEventConnect(BgpPeer *pPeer)   
{
    switch (pPeer->bgp_byState) {
        case BGP_STATE_CONNECT:
        case BGP_STATE_ACTIVE:
            sendBgpMsgOpen(pPeer);
            pPeer->bgp_byState = BGP_STATE_OPENSENT;
            break;
        default:
            pPeer->bgp_byState = BGP_STATE_IDLE;
    }
    return 0;
}

