/*

Sessionlist v1.0
written by rage

This program was written for the lulz. Use responsibly.
This program is freeware. I wrote this in my spare time so there may be bugs etc. I am not responsible if this program, say, eats your cat or blows up your house.
Report any bugs etc to me at rage@0xrage.com if you'd like. General feedback can be sent there as well.
*/
#ifndef SESSIONLIST_H_INCLUDED
#define SESSIONLIST_H_INCLUDED

#include <pcap.h>
#include <stdio.h>
#include <signal.h>
#include "headers.h"
#include <map>
#include <queue>
#include <list>
#include <string>
#include <cstring>
#include <unistd.h>
#include <cstdlib>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <ncurses.h>
#include <pwd.h>
#include <errno.h>

#define DEBUG 0
#define SESSION_DEBUG 0
#define SESSION_TO_FILE 1
#define NCURSES_ENABLED 0

#define MAX_SESSIONS 128

extern pcap_t *handle;			/* Session handle */
extern char *dev;			/* The device to sniff on */
extern char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
extern struct bpf_program fp;		/* The compiled filter */
extern bpf_u_int32 mask;		/* Our netmask */
extern bpf_u_int32 net;		/* Our IP */
extern struct pcap_pkthdr header;	/* The header that pcap gives us */
extern const u_char *packet;		/* The actual packet */
extern FILE *sessionFile;
extern int totalFoundSessions;

int sessionlist_init(char*,int);
void *sessionlist_startcapture(void*); //thread ver
//void sessionlist_startcapture();
void sessionlist_close(int);

void sessionlist_processPacket(const unsigned char*,int);
//
typedef struct SESSION_INFO
{
    char ether_src[32],ether_dst[32];
    char ip_src[16],ip_dst[16];
    std::list<unsigned char*> pData;
    unsigned int port;
    bool cStarted;
    bool cEnded;
    bool cFound;
    bool lWritten; //added
};

extern std::list<SESSION_INFO> SESSION_LIST;
extern volatile bool killLoop;
extern pthread_mutex_t tMutex;

void updateSessionlist(char*,char*,char*,char*,unsigned int,unsigned char*,int);
void updateSessionByIPs(char*,char*,char*,char*,unsigned int,unsigned char*,int);
void addSessionToSessionList(char*,char*,char*,char*,unsigned int,unsigned char*,int);
void addPayloadToSession(std::list<SESSION_INFO>::iterator,unsigned char*,int);
bool checkPayload(unsigned char*,std::list<SESSION_INFO>::iterator,int);
bool checkPayload(unsigned char*,SESSION_INFO,int);
void displayUsableSessionInfo();
//void *displayUsableSessionInfo(void*);
bool hasUsableSessionInfo(std::list<SESSION_INFO>::iterator,char*,char*,char*);
void extractData(const char*,char*,char*,int);
bool preCheck(unsigned char*);
std::list<SESSION_INFO>::iterator findSessionByCount(int);
void extractCookieData(std::list<unsigned char*>::iterator,std::list<unsigned char*>::iterator,char*,int);
void clearPayloadsFromlist();

//
void dropPrivs();

#endif // SESSIONHIJACK_H_INCLUDED
