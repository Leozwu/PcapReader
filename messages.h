#ifndef _ENXT_MSG_H_
#define _ENXT_MSG_H_
#include <stdint.h>
#pragma pack(push,0)

struct ENXTPacket {
    uint64_t pkgtime;
    uint32_t psn;
    uint16_t packetflag;
    uint16_t channelid;
};
struct ENXTFrame{
    uint16_t frame;
};
struct ENXTSBEMsg{
    uint16_t blocklen;
    uint16_t tempid;
    uint16_t schemaid;
    uint16_t schemaver;
};
struct standing{
    u_char hdr[16];
    u_char inst[102];
    u_char name[18];
};
struct contract{
    u_char hdr[21];
    u_char name[60];
};
struct outright{
    u_char hdr[17];
    u_char name[12];
};

#pragma pack(pop)
#endif