/*

Sessionlist v1.0
written by rage

This program was written for the lulz. Use responsibly.
This program is freeware. I wrote this in my spare time so there may be bugs etc. I am not responsible if this program, say, eats your cat or blows up your house.
Report any bugs etc to me at rage@0xrage.com if you'd like. General feedback can be sent there as well.
*/
#ifndef MAIN_H_INCLUDED
#define MAIN_H_INCLUDED

#include <stdio.h>
#include "sessionlist.h"
#include <pthread.h>

pthread_t session_thread;
pthread_t display_thread;

void *displaySessionData(void*);

void banner(char*);


#endif // MAIN_H_INCLUDED
