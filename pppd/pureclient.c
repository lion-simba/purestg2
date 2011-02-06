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
 *    Author: (c) 2009-2011 Alexey Osipov <lion-simba@pridelands.ru>
 */
 
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/poll.h>

#include "pureclient.h"
#include "pureproto.h"

//global variables

static int 		stg_socket = -1;
static struct in_addr 	user_hostip;

//every function return non-negative on success and negative number on error

//establish a connection to stargazer
int pureproto_connect(const char* socketpath)
{
    stg_socket = socket(AF_UNIX, SOCK_STREAM, 0);
    if (stg_socket == -1)
	return -1;
	
    struct sockaddr_un stg_addr;
    stg_addr.sun_family = AF_UNIX;
    strcpy(stg_addr.sun_path, socketpath);
    if (connect(stg_socket, (struct sockaddr*)&stg_addr, sizeof(stg_addr)) == -1)
	return -1;
	
    return 0;
}

//terminate connection to stargazer
int pureproto_disconnect()
{
    if (stg_socket >= 0)
    {
	if (close(stg_socket) == -1)
	    return -1;
	    
	stg_socket = -1;
    }
    
    return 0;
}

//sets user's host ip
int pureproto_sethostip(const char* hostip)
{
    struct in_addr temp;
    if (inet_aton(hostip, &temp) == 0)
	return -1;
	
    user_hostip = temp;
	
    return 0;
}

//ask stg to connect user
int pureproto_connectuser(const char* login)
{
    struct pureproto_packet_ask ask;
    struct pureproto_packet_reply reply;
    int result;
    
    if (stg_socket < 0)
	return -1;
    
    memset(&ask, 0, sizeof(ask));
    
    ask.type = PUREPROTO_ASK_CONNECT;
    strncpy(ask.login, login, LOGIN_LEN);
    ask.hostip = user_hostip;
    
    if (send(stg_socket, &ask, sizeof(ask), 0) == -1)
	return -1;
	
    result = recv(stg_socket, &reply, sizeof(reply), MSG_WAITALL);
    if (result == -1)
	return -1;
    
    if (result != sizeof(reply))
	return -1;
	
    if (ask.type != reply.type)
	return -1;
	
    if (strncmp(ask.login, reply.login, LOGIN_LEN) != 0)
	return -1;
	
    if (reply.result != PUREPROTO_REPLY_OK)
	return -1;
	
    return 0;
}

//ask stg to disconnect user
int pureproto_disconnectuser(const char* login)
{
    struct pureproto_packet_ask ask;
    struct pureproto_packet_reply reply;
    int result;
    
    if (stg_socket < 0)
	return -1;
    
    memset(&ask, 0, sizeof(ask));
    
    ask.type = PUREPROTO_ASK_DISCONNECT;
    strncpy(ask.login, login, LOGIN_LEN);
    ask.hostip = user_hostip;
    
    if (send(stg_socket, &ask, sizeof(ask), 0) == -1)
	return -1;
	
    result = recv(stg_socket, &reply, sizeof(reply), MSG_WAITALL);
    if (result == -1)
	return -1;
    
    if (result != sizeof(reply))
	return -1;
	
    if (ask.type != reply.type)
	return -1;
	
    if (strncmp(ask.login, reply.login, LOGIN_LEN) != 0)
	return -1;
	
    if (reply.result != PUREPROTO_REPLY_OK)
	return -1;
	
    return 0;
}

//ping stg
int pureproto_ping(int timeout, const char* login)
{
    struct pureproto_packet_ask ask;
    struct pureproto_packet_reply reply;
    int result;
    
    if (stg_socket < 0)
	return -1;
    
    memset(&ask, 0, sizeof(ask));
    
    ask.type = PUREPROTO_ASK_PING;
    strncpy(ask.login, login, LOGIN_LEN);    
    ask.hostip = user_hostip;
    
    if (send(stg_socket, &ask, sizeof(ask), 0) == -1)
	return -1;

    struct pollfd pfd;
    pfd.fd = stg_socket;
    pfd.events = POLLIN;
    
    result = poll(&pfd, 1, timeout * 1000);
    if (result <= 0)
	return -1;
	
    if (!(pfd.revents & POLLIN))
	return -1;
	
    result = recv(stg_socket, &reply, sizeof(reply), MSG_WAITALL);
    if (result == -1)
	return -1;
    
    if (result != sizeof(reply))
	return -1;
	
    if (ask.type != reply.type)
	return -1;
	
    if (strncmp(ask.login, reply.login, LOGIN_LEN) != 0)
	return -1;
	
    if (reply.result != PUREPROTO_REPLY_OK)
	return -2;
	
    return 0;
}

//ask stg for user's passwd
int pureproto_getpasswd(char* passwd, const char* login)
{
    struct pureproto_packet_ask ask;
    struct pureproto_packet_reply reply;
    int result;
    
    if (stg_socket < 0)
	return -1;
    
    memset(&ask, 0, sizeof(ask));
    
    ask.type = PUREPROTO_ASK_PASSWD;
    strncpy(ask.login, login, LOGIN_LEN);
    ask.hostip = user_hostip;
    
    if (send(stg_socket, &ask, sizeof(ask), 0) == -1)
	return -1;
	
    result = recv(stg_socket, &reply, sizeof(reply), MSG_WAITALL);
    if (result == -1)
	return -1;
    
    if (result != sizeof(reply))
	return -1;
	
    if (ask.type != reply.type)
	return -1;
	
    if (strncmp(ask.login, reply.login, LOGIN_LEN) != 0)
	return -1;
	
    if (reply.result != PUREPROTO_REPLY_OK)
	return -1;
	
    strncpy(passwd, reply.passwd, PASSWD_LEN);
	
    return 0;
}

//ask stg for user's ip
int pureproto_getip(struct in_addr* userip, const char* login)
{
    struct pureproto_packet_ask ask;
    struct pureproto_packet_reply reply;
    int result;
    
    if (stg_socket < 0)
	return -1;
    
    memset(&ask, 0, sizeof(ask));
    
    ask.type = PUREPROTO_ASK_IP;
    strncpy(ask.login, login, LOGIN_LEN);
    ask.hostip = user_hostip;
    
    if (send(stg_socket, &ask, sizeof(ask), 0) == -1)
	return -1;
	
    result = recv(stg_socket, &reply, sizeof(reply), MSG_WAITALL);
    if (result == -1)
	return -1;
    
    if (result != sizeof(reply))
	return -1;
	
    if (ask.type != reply.type)
	return -1;
	
    if (strncmp(ask.login, reply.login, LOGIN_LEN) != 0)
	return -1;
	
    if (reply.result != PUREPROTO_REPLY_OK)
	return -1;

    *userip = reply.userip;
	
    return 0;
}

//ask stg for interface unit
int pureproto_getifunit(int* ifunit)
{
    struct pureproto_packet_ask ask;
    struct pureproto_packet_reply reply;
    int result;
    
    if (stg_socket < 0)
	return -1;
    
    memset(&ask, 0, sizeof(ask));
    
    ask.type = PUREPROTO_ASK_IFUNIT;
    ask.hostip = user_hostip;
    
    if (send(stg_socket, &ask, sizeof(ask), 0) == -1)
	return -1;
	
    result = recv(stg_socket, &reply, sizeof(reply), MSG_WAITALL);
    if (result == -1)
	return -1;
    
    if (result != sizeof(reply))
	return -1;
	
    if (ask.type != reply.type)
	return -1;
	
    if (strncmp(ask.login, reply.login, LOGIN_LEN) != 0)
	return -1;
	
    if (reply.result != PUREPROTO_REPLY_OK)
	return -1;

    *ifunit = reply.ifunit;
	
    return 0;
}
