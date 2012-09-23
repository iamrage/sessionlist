/*
 * Main module for general usage and display threading.
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
    while(!killLoop)
    {
        //display data
        displayUsableSessionInfo();

        //wait
        sleep(2);
    }
}


