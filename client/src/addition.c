// Client                         //
// Tester for server              //
// DEMO                           //
// University Work Project        //
// Technical University of Kosice //
// 22.3.2026                      //
// Nikita Kuropatkin              //

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "include/addition.h"
#include "include/error.h"
#include "include/parameters.h" //Macros are defined here

////////////////////////
/// Clearing Input   ///
////////////////////////
/*
The purpose of this function is to clear the `stdin` buffer after  
an oversized message is entered (to handle `stdin` overflow).
*/
void clear (void)
{
 int c;
 while ((c = getchar()) != '\n' && c != EOF);
}
////////////////////////
////////////////////////

///////////////////////////
/// Exit on Stop-Word   ///
///////////////////////////
/*
The purpose of this function is to terminate the program  
when a stop-word is detected in the message.  
The function returns a value of 1 if the stop-word is detected.  
After returning, the program (server or client) proceeds with  
closing the communication session as normal.
- The `side` variable is a modifier for the message that indicates  
  who ended the communication.  
- The stop-word can be configured by changing the `EXIT` macro.  
*/
int exiting (const char *side, const char *msg)
{
// Exit the loop if the message contains stop-word
 if (strncmp(msg,EXIT,strlen(EXIT)) == OK) {
    printf("%s exited...\n",side);
    return YES;
 }
 else return NO;
}
///////////////////////////
///////////////////////////

///////////////////////////
/// Checking Input IP   ///
///////////////////////////
/*
The purpose of this function is to check whether the  
user has entered a valid IP address in the correct format.  
If the entered IP address is not valid (not correctly formatted),  
the program exits.  
It takes the following parameter:  
- `ip` - contains the IP address to be validated.  

Valid format examples:  
- Dotted decimal format: 192.168.0.1  
- Each octet must have a maximum value of 255: 255.255.255.255  
  (the "maximum" IP address).
*/
void ip_check (char *ip)
{
 unsigned a, b, c, d;
 char tail;

 /* Exactly four decimal octets, each 0..255, nothing after them. */
 if (sscanf(ip, "%u.%u.%u.%u%c", &a, &b, &c, &d, &tail) != 4 ||
     a > IPEND || b > IPEND || c > IPEND || d > IPEND) {
    exit_with_error(ERROR_IP_INPUT,"Invalid IP");
 }
}
///////////////////////////
///////////////////////////

////////////////////////////////
/// Printing Help for User   ///
////////////////////////////////
/*
Prints  basic help for user 
*/
void help_print (const int port)
{
 printf("\n");
 printf("HELP! HELP! HELP! HELP! HELP!\n");
 printf("***********************************************************************\n");
 printf("# You are trying to execute server tester for server demo #\n");
 printf("# Port number: %d #\n",port);
 printf("# You must executing program with argument of IP:#\n");
 printf("#client_connect <IP> [mode]#\n");
 printf("#Example: client_connect 192.168.1.1 web#\n");
 exit_with_error(OK,"You can re-run program now"); //Normal exit
}
////////////////////////////////
////////////////////////////////



