// Client                         //
// Tester for server              //
// DEMO                           //
// University Work Project        //
// Technical University of Kosice //
// 22.3.2026                      //
// Nikita Kuropatkin              //


/*
This header file declares macros for returning values
of error, also there is a function in config.c,
that ends program and returns error code value
(can be programmed to print error message)
*/
#ifndef ERROR_H
#define ERROR_H

//Defining errors with macros to use them in codes
#define OK 0
#define ERROR_WSA 1
#define ERROR_SOCKET_CREATION 2
#define ERROR_BINDING 3
#define ERROR_SOCKET_LISTENING 4
#define ERROR_SERVER_ACCEPT 5
#define ERROR_GETTING_INPUT 6
#define ERROR_RECEIVING_DATA 7  
#define ERROR_SENDING_DATA 8
#define ERROR_GENERATING_RANDOM 9
#define ERROR_CLIENT_CONNECTION 10
#define ERROR_PORT_INPUT 11
#define ERROR_IP_INPUT 12
#define MESSAGE_ALTERED 13
#define UNEQUAL_MAC 14
#define WRONG_PIN 15
#define WRONG_PIN_FORMAT 16
#define ALLOCATION_ERROR 17
#define TEXT_OVERFLOW 18
#define ERROR_OPENING_FILE 19
#define WRONG_TXT_FORMAT 20
#define UNSUPPORTED_SIZE 21
#define ERROR_PROTOCOL 21

//////////////////////////////////////////
/// Error printing ///
//////////////////////////////////////////
/*
The purpose of this function is to print errors defined by the variable 
error and the error message contained in the variable err_string. 
The function exits with the return value specified by error.
This function takes the following parameters:  
- `err_string` - string with error message that will be printed.  
- `error` - an error code, that program will return, while exiting
   error codes are defined in error.h  
You can choose where to print the error message — either to stderr or stdout 
— by switching the PRINT macro. 
To suppress all output, set the DEBUG macro to YES.
Change macros in include/parameters.h
*/
void exit_with_error(const int error, const char * err_string);
//////////////////////////////////////////
//////////////////////////////////////////

#endif