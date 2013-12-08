/*
 *    This program is free software; you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation; either version 2 of the License, or
 *    (at your option) any later version.
 *
 *    This program is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public License
 *    along with this program; if not, write to the Free Software
 *    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/*
 *    Author: (c) 2009-2013 Alexey Osipov <public@alexey.osipov.name>
 */

#ifndef H_PURESTG_PUREPROTO
#define H_PURESTG_PUREPROTO

#include <sys/socket.h>
#include <netinet/in.h>

#include <stg/const.h>

// ask types

#define PUREPROTO_ASK_INVALID       0 //illegal packet type
#define PUREPROTO_ASK_CONNECT       1 //ask stg to connect user
#define PUREPROTO_ASK_DISCONNECT    2 //ask stg to disconnect user
#define PUREPROTO_ASK_PASSWD        3 //ask stg to check user and return it's passwd
#define PUREPROTO_ASK_IP            4 //ask stg for user IP
#define PUREPROTO_ASK_IFUNIT        5 //ask stg for free ifunit
#define PUREPROTO_ASK_PING          6 //ask stg to reply back
#define PUREPROTO_ASK_IPPARAM       7 //ask stg to store ipparam


#define IPPARAM_LEN     50
struct pureproto_packet_ask {
    int             type;                   //request type
    char            login[LOGIN_LEN+1];     //user login, maybe zero if not known yet
    union {
        char        ipparam[IPPARAM_LEN+1]; //ipparam, given to pppd
    };
};

// reply types

#define PUREPROTO_REPLY_INVALID 0 //illegal reply
#define PUREPROTO_REPLY_OK      1 //it rocks!
#define PUREPROTO_REPLY_ERROR   2 //bad...

struct pureproto_packet_reply {
    int     type;                   //same as pureproto_packet_ask.type
    char    login[LOGIN_LEN+1];     //same as pureproto_packet_ask.login
    int     result;                 //result code
    union {                         //result data (depend on request type)
        char            passwd[PASSWD_LEN+1];
        struct in_addr  userip;
        int             ifunit;
    };
};

#endif
