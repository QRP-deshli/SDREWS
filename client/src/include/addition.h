// Client                         //
// Tester for server              //
// DEMO                           //
// University Work Project        //
// Technical University of Kosice //
// 22.3.2026                      //
// Nikita Kuropatkin              //

/* 
This header file declares additional functions, 
like printing help, ip validation, etc. for a 
client-server application. Function bodies
are in addition.c. 
*/
#ifndef ADDITION_H
#define ADDITION_H

////////////////////////
/// Clearing Input   ///
////////////////////////
/*
The purpose of this function is to clear the `stdin` buffer after  
an oversized message is entered (to handle `stdin` overflow).
*/
void clear (void);
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
int exiting (const char *side, const char *msg);
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
void ip_check (char *ip);
///////////////////////////
///////////////////////////


////////////////////////////////
/// Printing Help for User   ///
////////////////////////////////
/*
Prints  basic help for user 
*/
void help_print (const int port);

#endif