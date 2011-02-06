#ifndef H_PURESTG_PUREPROTO
#define H_PURESTG_PUREPROTO

#include <sys/socket.h>
#include <netinet/in.h>

#include "stg_common.h"

// ask types

#define PUREPROTO_ASK_INVALID 		0 //illegal packet type
#define PUREPROTO_ASK_CONNECT 		1 //ask stg to connect user
#define PUREPROTO_ASK_DISCONNECT 	2 //ask stg to disconnect user
#define PUREPROTO_ASK_PASSWD 		3 //ask stg to check user and return it's passwd
#define PUREPROTO_ASK_IP		4 //ask stg for user IP
#define PUREPROTO_ASK_IFUNIT		5 //ask stg for free ifunit
#define PUREPROTO_ASK_PING		6 //ask stg to reply back

struct pureproto_packet_ask {
    int 		type;			//request type
    char 		login[LOGIN_LEN+1]; 	//user login, maybe zero if not known yet
    struct in_addr 	hostip;			//host, from which user is connected
};

// reply types

#define PUREPROTO_REPLY_INVALID		0 //illegal reply
#define PUREPROTO_REPLY_OK		1 //it rocks!
#define PUREPROTO_REPLY_ERROR		2 //bad...

struct pureproto_packet_reply {
    int			type; 			//same as pureproto_packet_ask.type
    char		login[LOGIN_LEN+1];	//same as pureproto_packet_ask.login
    int			result;			//result code
    union {					//result data (depend on request type)
	char		passwd[PASSWD_LEN+1];
	struct in_addr	userip;
	int		ifunit;
    };
};

#endif
