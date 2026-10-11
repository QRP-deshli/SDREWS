// Client                         //
// Tester for server              //
// DEMO                           //
// University Work Project        //
// Technical University of Kosice //
// 22.3.2026                      //
// Nikita Kuropatkin              //


/* 
This header file contains macros for the operation 
of the client and server programs.
Read the comments next to each macro for an explanation of its purpose.
*/
#ifndef PARAMETERS_H
#define PARAMETERS_H
#include <stdint.h>

/////////////////////
/* Can be modified */
/////////////////////

/*
Frame_t size without of the data payload
*/
#define FRAME_HEADER_SIZE offsetof(frame_t, data)


/*
Size of the session key in bytes
*/
#define SESSION_KEY_SIZE 16

/*
 * Maximum payload size for DATA frames.
 * Fixed-size buffer keeps framing simple and avoids fragmentation.
 */
#define MAX_PAYLOAD 128

/*
Macro defining the amount of time messages are recieved before token rotate
*/
#define TOKEN_ROTATE 1024 

/* Maximum number of hardware TCP sockets used by the server.
 * This limits how many clients can be connected at the same time.
 * The value must not exceed the socket count supported by the Wiznet chip.
 * Each socket has its own session state.
 */
#define MAX_SOCKETS   4

/* Application-level keepalive timeout in milliseconds.
 * If no valid frame is received within this time, the connection is closed.
 * This is independent of TCP keepalive handled by the Wiznet hardware.
 * Helps remove stalled or silent clients.
 */
#define APP_KEEPALIVE_MS   5000

/* Magic value used to identify valid protocol frames.
 * Prevents accidental parsing of unrelated or corrupted data.
 * Must match on both client and server sides.
 * Checked before any frame processing.
 */
/* Magic value used to identify outgoing protocol frames. */
#define PROTOCOL_MAGIC_SEND 0xC2A6

/* Magic value used to identify incoming protocol frames. */
#define PROTOCOL_MAGIC_RECEIVE 0xC2A5

/* Protocol version number.
 * Allows future protocol changes while maintaining backward compatibility.
 * Frames with unsupported versions are rejected.
 */
#define PROTOCOL_VER  1

/* Command identifier for authentication frames.
 * Used during session initialization and token synchronization.
 * Must be sent before any application data.
 */
#define CMD_AUTH 0x01

/* Command identifier for application data frames.
 * Carries payload data protected by token and counter checks.
 * Only accepted after successful authentication.
 */
#define CMD_DATA 0x10

/* Command identifier for application data frames.
 * Carries payload data protected by token and counter checks.
 * Only accepted after successful authentication.
 */
#define CMD_INIT 0x11

/* Command identifier for acknowledgment frames.
 * Sent in response to valid received frames.
 * Confirms successful processing and token rotation.
 */
#define CMD_ACK  0x81

/* 
Command identifier for ping frames.
*/
#define CMD_PING  0x04

/*
Command identifier for pong frames.
*/
#define CMD_PONG  0x05

#define CMD_CLOSE 0x06

/* Initial token seed used during session setup.
 * Combined with a per-connection nonce to create a unique session token.
 * Prevents reuse of static tokens across connections.
 */
#define INIT_TOKEN 0xCAFEBABE

/* Secret key used for token or HMAC-based verification.
 * Must be kept private and identical on both client and server.
 * Changing this key invalidates all existing sessions.
 */
#define HMAC_KEY   0x13579BDF


/*
Defines the port number. We trying to test port 443, so it 
*/
#ifndef PORT
#define PORT 443
#endif

/*
Client timing (milliseconds). Originally 10 s / 10 s; 1 s / 2 s turned out too tight.
- CLIENT_CONNECT_TIMEOUT_MS : give up on one TCP connect attempt after this long
  and (in "web" mode) immediately try a fresh one.
- CLIENT_IO_TIMEOUT_MS      : max wait for any single server reply once connected.
- WEB_RETRY_DELAY_*         : pause between failed "web" attempts =
                              MIN + random(0..JITTER). Do not make this too small:
                              the server counts failed handshakes per IP and bans
                              an IP after a few strikes.
- WEB_MAX_ATTEMPTS          : 0 = keep trying until the server accepts.
*/
#define CLIENT_CONNECT_TIMEOUT_MS   3000
#define CLIENT_IO_TIMEOUT_MS        5000
#define WEB_RETRY_DELAY_MIN_MS      300
#define WEB_RETRY_DELAY_JITTER_MS   300
#define WEB_MAX_ATTEMPTS            0


/*
In use: addition.c.
Defines a stop-word that terminates a conversation. You can modify 
this value. If the stop-word differs on one side, the other side will 
interpret it as an error.
*/
#define EXIT "exit"

/*
In use: server_tester.c
Structure for TCP/IP functions contains IP and port, etc., used by the client
and server to establish a connection.
Never change this value!
*/
#define SA struct sockaddr 

/*
In use: client.c
Size of IP address.
Never change the value of this macro!
*/
#define IPSZ 16  

/*
In use: addition.c
The next two macros define the allowed range 
of values for octets in IPv4 (0.0.0.0 - 255.255.255.255).
Never change the values of these macros!
*/ 
#define IPSTART 0
#define IPEND 255

/*
Size of sended and got messages 
*/
#define MSG_SIZE 32

/*
In use: server_tester.c, addition.c
Two macros define DEBUG macro options. 
Also two macros define whether a certain side has ended communication
Again, you don’t need to change these, but you can. 
(I do not recommend changing them.)
*/
#define YES 1
#define NO 0

/*
This macro defines an error that can be returned by any function in this code.  
It is used almost everywhere. If you see this macro, it means the function  
execution ended with an error.
*/
#define RETURN_ERROR -1

/*
In use: server_tester.c
Defining macro for address length
(it is needed cause it has different types on WIN and LINUX).
Do not change this value!
*/
#ifdef _WIN32 
    #define LEN int 
#else
    #define LEN socklen_t
#endif 

//////////////////////// 
////////////////////////

#endif
