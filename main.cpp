/*

Sessionlist v1.0
written by rage

This program was written for the lulz. Use responsibly.
This program is freeware. I wrote this in my spare time so there may be bugs etc. I am not responsible if this program, say, eats your cat or blows up your house.
Report any bugs etc to me at rage@0xrage.com if you'd like. General feedback can be sent there as well.
*/
#include "main.h"

void banner()
{
    printf("/*\n\tsessionlist v1.0\n\tby rage\n\trage@0xrage.com\n*/\n");
}

void usage(char *s)
{
    printf("Usage:\n%s [interface] [port]- port is optional and defaults to 80. simple eh?\n",s);
}

int main(int argc,char **argv)
{
    char dev[8];
    int nport;

    banner();
    if(argc!=2 && argc!=3) { usage(argv[0]); return 1; }
    snprintf(dev,8,"%s",argv[1]);
    if(DEBUG) printf("listening on device: %s\n",dev);

    if(argc==3)
    {
        nport=atoi(argv[2]);
        if(sessionlist_init(dev,nport)) { printf("initialization failed..\n"); return 1; }
    }
    else if(sessionlist_init(dev,80)) { printf("initialization failed..\n"); return 1; }

    pthread_create(&display_thread,NULL,displaySessionData,NULL);
    pthread_create(&session_thread,NULL,sessionlist_startcapture,NULL);

    pthread_join(display_thread,NULL);
    pthread_join(session_thread,NULL);
    //sessionlist_startcapture();

    return 0;
}

void *displaySessionData(void *ptr)
{
    //char wBuffer[128];
    //int userInput;

    while(!killLoop)
    {
        //display data
        displayUsableSessionInfo();

        //wait
        sleep(2);
    }
}


