// Client                         //
// Tester for server              //
// DEMO                           //
// University Work Project        //
// Technical University of Kosice //
// 22.3.2026                      //
// Nikita Kuropatkin              //


#include <stdio.h>
#include <string.h>
#include "include/network.h"
#include "include/error.h" //All errors defined + function proto

/*
 * FIX: On WAN, TCP is a stream protocol — a single recv()/send() call is NOT
 * guaranteed to transfer all requested bytes in one shot. On LAN this is rarely
 * visible because small frames fit in one segment, but over the internet
 * fragmentation and buffering mean partial transfers happen ~30-70% of the time.
 *
 * Solution: loop until all bytes are transferred (or a real error occurs).
 * This is the correct, portable way to use blocking TCP sockets.
 */
 
const char *net_err_reason = "";

/* Remember why the last transfer failed (used in the client's error messages). */
static void note_failure(int closed_by_peer)
{
    static char other[48];
#ifdef _WIN32
    int err = WSAGetLastError();
    if (closed_by_peer)                                   net_err_reason = "closed by the server";
    else if (err == WSAETIMEDOUT)                         net_err_reason = "timed out, no reply";
    else if (err == WSAECONNRESET || err == WSAECONNABORTED) net_err_reason = "reset by the server";
    else { snprintf(other, sizeof(other), "network error %d", err); net_err_reason = other; }
#else
    if (closed_by_peer)                                   net_err_reason = "closed by the server";
    else if (errno == EAGAIN || errno == EWOULDBLOCK || errno == ETIMEDOUT) net_err_reason = "timed out, no reply";
    else if (errno == ECONNRESET || errno == ECONNABORTED || errno == EPIPE) net_err_reason = "reset by the server";
    else { snprintf(other, sizeof(other), "network error: %s", strerror(errno)); net_err_reason = other; }
#endif
}

// Returns 0 = success, -1 = error (timeout, disconnect, etc.)
int read_win_lin(const int sockfd, uint8_t *msg, const uint32_t size)
{
    uint32_t total = 0;
 
    while (total < size) {
#ifdef _WIN32
        int ret = recv(sockfd, (char*)(msg + total), (int)(size - total), 0);
        if (ret == SOCKET_ERROR) {
            note_failure(0);
            return -1;   // timeout / reset / abort / anything else: caller decides (retry loop)
        }
        if (ret == 0) { note_failure(1); return -1; } // connection closed by peer
        total += (uint32_t)ret;
#else
        ssize_t ret = read(sockfd, msg + total, size - total);
        if (ret < 0) {
            if (errno == EINTR) continue;
            note_failure(0);
            return -1;   // timeout / reset / abort / anything else: caller decides (retry loop)
        }
        if (ret == 0) { note_failure(1); return -1; } // connection closed by peer
        total += (uint32_t)ret;
#endif
    }
    return 0;
}
 
// Returns 0 = success, -1 = error (timeout, disconnect, etc.)
int write_win_lin(const int sockfd, const uint8_t *msg, const uint32_t size)
{
    uint32_t total = 0;
 
    while (total < size) {
#ifdef _WIN32
        int ret = send(sockfd, (const char*)(msg + total), (int)(size - total), 0);
        if (ret == SOCKET_ERROR) {
            note_failure(0);
            return -1;
        }
        total += (uint32_t)ret;
#else
        ssize_t ret = write(sockfd, msg + total, size - total);
        if (ret < 0) {
            if (errno == EINTR) continue;
            note_failure(0);
            return -1;
        }
        total += (uint32_t)ret;
#endif
    }
    return 0;
}

//////////////////////////////////////////
/// Socket Closer ///
//////////////////////////////////////////
/*
The purpose of this function is to close existing sockets for 
Windows and Linux.  
It takes the following parameter:  
- `sockfd` - the ID of the socket to be closed.  
The program exits in case of an error.
*/
void sockct_cls(const int sockfd) {
 // Close the socket
 #ifdef _WIN32
    closesocket(sockfd);
    //WSACleanup();
 #else
    close(sockfd);
 #endif
}
///////////////////////////////////////////////////
///////////////////////////////////////////////////

///////////////////////////////
/// Socket initializer///
//////////////////////////////
/*
This function purpose is to initialize socket for Windows,
program exits in case of error.
*/
void init_sock() {
 #ifdef _WIN32
    WSADATA wsaData;
    int iResult;
    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        exit_with_error(ERROR_WSA, "WSAStartup failed");
    }
 #endif
}
//////////////////////////////
/////////////////////////////

///////////////////////////////
/// Socket Creation Checker ///
///////////////////////////////
/*
The purpose of this function is to check if a socket was successfully created.  
It takes the following parameter:  
- `sockfd` - a variable containing the ID of the socket to be checked.  
The program exits in case of an error.
*/
void sock_check(const int sockfd) {
 if (sockfd == -1) {
    #ifdef _WIN32
        WSACleanup();
    #endif
    exit_with_error(ERROR_SOCKET_CREATION, "Socket creation failed");
 } 
 else {
    printf("Socket successfully created..\n");
 }
}
//////////////////////////////
//////////////////////////////

