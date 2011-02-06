#ifndef H_PURESTG_PUREPROTOCLIENT
#define H_PURESTG_PUREPROTOCLIENT

#include <netinet/in.h>

/*
    functions to work with pureprotocol
*/
//every function return non-negative on success and negative number on error

//establish a connection to stargazer
int pureproto_connect(const char* socketpath);

//terminate connection to stargazer
int pureproto_disconnect();

//sets user's host ip
int pureproto_sethostip(const char* hostip);

//ask stg to connect user
int pureproto_connectuser(const char* login);

//ask stg to disconnect user
int pureproto_disconnectuser(const char* login);

//ping stg (timeout in seconds)
int pureproto_ping(int timeout, const char* login);

//ask stg for user's passwd
int pureproto_getpasswd(char* passwd, const char* login);

//ask stg for user's ip
int pureproto_getip(struct in_addr* userip, const char* login);

//ask stg for interface unit
int pureproto_getifunit(int* ifunit);

#endif
