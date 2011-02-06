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
 *    Author: (c) 2009 Alexey Osipov <lion-simba@pridelands.ru>
 */

#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <user.h>

#include "purestg2.h"
#include "pureproto.h"


class PURESTG2_CREATOR
{
private:
    AUTH_PURESTG2 * dc;

public:
    PURESTG2_CREATOR()
        {
    	    printfd(__FILE__, "constructor PURESTG2_CREATOR\n");
    	    dc = new AUTH_PURESTG2();
        };
    ~PURESTG2_CREATOR()
        {
    	    printfd(__FILE__, "destructor PURESTG2_CREATOR\n");
    	    if (dc)
        	delete dc;
        };

    BASE_PLUGIN * GetPlugin()
    {
        return dc;
    };
};
//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------

PURESTG2_CREATOR pstg2c;

BASE_PLUGIN * GetPlugin()
{
    return pstg2c.GetPlugin();
}
//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
const string AUTH_PURESTG2::GetVersion() const
{
    return "Linux PPPD (purestg2) authorizator v.0.1";
}
//-----------------------------------------------------------------------------
AUTH_PURESTG2::AUTH_PURESTG2()
:WriteServLog(GetStgLogger())
{
    isRunning = false;
    memset(connections, 0, sizeof(connections));
    connections_count = 0;
    minppp = 10;
    d = 0;
}
//-----------------------------------------------------------------------------
void AUTH_PURESTG2::SetUsers(USERS * u)
{
    users = u;
}
//-----------------------------------------------------------------------------
void AUTH_PURESTG2::SetSettings(const MODULE_SETTINGS & s)
{
    settings = s;
}
//-----------------------------------------------------------------------------
int AUTH_PURESTG2::ParseSettings()
{
    for(size_t i=0; i<settings.moduleParams.size(); i++)
    {
	if (settings.moduleParams[i].param == "authsocket")
	{
	    if (settings.moduleParams[i].value.size() == 0)
	    {
		errorStr = "Parameter \"authsocket\" must have a value.";
		return 1;
	    }	    
	    authsocketpath = settings.moduleParams[i].value[0];	    	
	}
	else if (settings.moduleParams[i].param == "minppp")
	{
	    if (settings.moduleParams[i].value.size() == 0)
	    {
		errorStr = "Parameter \"minppp\" must have a value.";
		return 1;
	    }
	    char* endPtr;
	    minppp = strtol(settings.moduleParams[i].value[0].c_str(), &endPtr, 10);
	    if (*endPtr != '\0' || minppp < 0)
	    {
		errorStr = "Parameter \"minppp\" must be non-negative integer.";
		return 1;
	    }
	}
	else if (settings.moduleParams[i].param == "debug")
	{
	    WriteServLog("purestg2: Debug output enabled.");
	    d = 1;
	}
	else
	{
	    errorStr = string("Unknown parameter \"") + settings.moduleParams[i].param + string("\"");
	    return 1;
	}
    }
    
    if (authsocketpath == "")
    {
	errorStr = "Parameter \"authsocket\" must have a value.";
	return 1;
    }
    
    return 0;
}
//-----------------------------------------------------------------------------
const string & AUTH_PURESTG2::GetStrError() const
{
    return errorStr;
}
//-----------------------------------------------------------------------------
int AUTH_PURESTG2::Start()
{
    if (isRunning)
	return 0;

    //prepare server
    listeningsocket = socket(AF_UNIX, SOCK_STREAM, 0);
    if (listeningsocket == -1)
    {
	errorStr = string("Can't create socket: ") + string(strerror(errno));
	return 1;
    }
    
    struct sockaddr_un server;
    server.sun_family = AF_UNIX;
    strcpy(server.sun_path, authsocketpath.c_str());
    unlink(server.sun_path);
    
    if (bind(listeningsocket, (struct sockaddr *)&server, sizeof(server)) == -1)
    {
	errorStr = string("Can't bind to path \"") + authsocketpath + string("\": ") + string(strerror(errno));
	return 1;
    }
    
    if (listen(listeningsocket, 5) == -1)
    {
	errorStr = string("Can't listen on socket: ") + string(strerror(errno));
	return 1;
    }
    
    if (addConnection(listeningsocket) == -1)
    {
	errorStr = string("Can't add listening socket to connections list");
	return 1;
    }

    WriteServLog("purestg2: listening for incoming auth connections on %s", authsocketpath.c_str());
    
    //start thread
    nonstop = true;
    
    if (pthread_create(&listeningthread, NULL, Run, this))
    {
	errorStr = "Can't create listening thread";
	return 1;
    }
	
    return 0;
}
//-----------------------------------------------------------------------------
int AUTH_PURESTG2::Stop()
{
    if (!isRunning)
	return 0;

    nonstop = false;
    
    //wait for thread finish
    if (pthread_join(listeningthread, NULL))
    {
	errorStr = "Can't join listening thread";
	return 1;
    }
    
    //shutdown server
    delConnection(listeningsocket);
    close(listeningsocket);    
    
    return 0;
}
//-----------------------------------------------------------------------------
void* AUTH_PURESTG2::Run(void * me)
{
    AUTH_PURESTG2 * auth = (AUTH_PURESTG2 *) me;
    
    auth->isRunning = true;
    
    while(auth->nonstop)
    {
	int pollresult = poll(auth->connections, auth->connections_count, 1000);
	
	if (pollresult == -1)
	{
	    auth->WriteServLog("purestg2: ERROR: can't poll connections: %s", strerror(errno));
	    usleep(500000);
	    continue;
	}
	
	if (pollresult == 0)
	    continue;
	    
	int changedsockets[MAXPURECONNECTIONS];
	int changedsockets_count = 0;
	
	int hupsockets[MAXPURECONNECTIONS];
	int hupsockets_count = 0;
	
	for(int i = 0; i < auth->connections_count; i++)
	{
	    if (auth->connections[i].revents & POLLHUP)
	    {
		hupsockets[hupsockets_count] = auth->connections[i].fd;
		hupsockets_count++;
	    }
	    else if (auth->connections[i].revents & POLLIN)
	    {
		changedsockets[changedsockets_count] = auth->connections[i].fd;
		changedsockets_count++;
	    }
	}
	
	for(int i = 0; i < changedsockets_count; i++)
	{
	    if (changedsockets[i] == auth->listeningsocket)
	    {
	        if (auth->acceptClientConnection() == -1)
		    auth->WriteServLog("purestg2: ERROR: can't accept client connection");
	    }
	    else
	    {
		if (auth->handleClientConnection(changedsockets[i]) == -1)
		    auth->WriteServLog("purestg2: ERROR: can't handle client connection for socket %d", changedsockets[i]);
	    }
	}
	
	for(int i = 0; i < hupsockets_count; i++)
	{
	    if (hupsockets[i] == auth->listeningsocket)
		auth->WriteServLog("purestg2: BUG: Our listening socket is running away!");
	    else
	    {
		if (auth->delConnection(hupsockets[i]) == -1)
		    auth->WriteServLog("purestg2: BUG: Can't del hupped connection!");
		    
		close(hupsockets[i]);
	    }
	}
    }
    
    auth->isRunning = false;
    
    return 0;
}
//-----------------------------------------------------------------------------
bool AUTH_PURESTG2::IsRunning()
{
    return isRunning;
}
//-----------------------------------------------------------------------------
uint16_t AUTH_PURESTG2::GetStartPosition() const
{
    return 70;
}
//-----------------------------------------------------------------------------
uint16_t AUTH_PURESTG2::GetStopPosition() const
{
    return 70;
}
//-----------------------------------------------------------------------------
int AUTH_PURESTG2::SendMessage(const STG_MSG & msg, uint32_t ip) const
{
    errorStr = "Authorization module \'Purestg2\' does not support sending messages";
    return -1;
}
//-----------------------------------------------------------------------------
int AUTH_PURESTG2::addConnection(int socket)
{
    if (connections_count == MAXPURECONNECTIONS)
    {
	WriteServLog("purestg2: ERROR: Max purestg2 connections reached.");
	return -1;
    }
    
    connections[connections_count].fd = socket;
    connections[connections_count].events = POLLIN | POLLHUP;
    connections_count++;
    
    return 0;
}
//-----------------------------------------------------------------------------
int AUTH_PURESTG2::delConnection(int socket)
{
    int i;
    for(i = 0; i < connections_count; i++)
    {
	if (connections[i].fd == socket)
	    break;
    }
    
    if (i == connections_count)
	return -1;
	
    int lastindex = connections_count - 1;
    
    if (i < lastindex)
	connections[i].fd = connections[lastindex].fd;

    connections_count--;
    
    return 0;
}
//-----------------------------------------------------------------------------
int AUTH_PURESTG2::acceptClientConnection()
{
    int clientsocket;

    clientsocket = accept(listeningsocket, NULL, NULL);
    if (clientsocket < 0)
    {
        WriteServLog("purestg2: ERROR: can't accept connection: %s", strerror(errno));
        usleep(100000);
	return -1;
    }
    
    if (addConnection(clientsocket) == -1)
    {
	WriteServLog("purestg2: ERROR: can't add accepted connection.");
	return -1;
    }
    
    WriteServLog("purestg2: Accepted new client connection (socket=%d)", clientsocket);
    
    return 0;
}
//-----------------------------------------------------------------------------
int AUTH_PURESTG2::handleClientConnection(int clientsocket)
{
    struct pureproto_packet_ask ask;
    
    int result = recv(clientsocket, &ask, sizeof(ask), MSG_WAITALL);
    if (result == -1)
    {
	WriteServLog("purestg2: ERROR: can't recieve from client socket %d.", clientsocket);
	return -1;
    }
    if (result != sizeof(ask))
    {
	WriteServLog("purestg2: ERROR: size of ask packet is incorrect (got: %d, expect: %d, socket: %d).", result, sizeof(ask), clientsocket);
	return -1;
    }
    
    if (d) WriteServLog("purestg2: request(socket=%d): type=%d, login=%s", clientsocket, ask.type, ask.login);
    
    USER* user = NULL;
    
    //get username from packets who have it
    switch (ask.type)
    {
    case PUREPROTO_ASK_CONNECT:
    case PUREPROTO_ASK_DISCONNECT:
    case PUREPROTO_ASK_PASSWD:
    case PUREPROTO_ASK_IP:
    case PUREPROTO_ASK_PING:
	user_iter ui;
	
	if (users->FindByName(string(ask.login), &ui) == 0)
	    user = &(*ui);
	else if (ask.type != PUREPROTO_ASK_PING)
	    WriteServLog("purestg2: ERROR: user %s not found in stargazer.", ask.login);
	    
	break;
    }
    
    //prepare reply
    struct pureproto_packet_reply reply;
    memset(&reply, 0, sizeof(reply));
    
    reply.type = ask.type;
    strncpy(reply.login, ask.login, LOGIN_LEN);
        
    switch (ask.type)
    {
    case PUREPROTO_ASK_CONNECT:	
	//check if we have user
	if (!user)
	{
	    reply.result = PUREPROTO_REPLY_ERROR;
	    break;
	}
	
	//authorize user
	if (user->Authorize((user->property.ips.Get()[0]).ip, string("purestg"), 0xffffffff, this))
	{
	    WriteServLog("purestg2: ERROR: Can't authorize user %s.", ask.login);
	    reply.result = PUREPROTO_REPLY_ERROR;
	    break;
	}
	
	WriteServLog("purestg2: User %s (socket=%d) is connected.", ask.login, clientsocket);
	
	//set hostip to userdata9
	//user->property.userdata9.Set(string(inet_ntoa(ask.hostip)), );
	
	reply.result = PUREPROTO_REPLY_OK;
	break;
	
    case PUREPROTO_ASK_DISCONNECT:
	//check if we have user
	if (!user)
	{
	    reply.result = PUREPROTO_REPLY_ERROR;
	    break;
	}
	
	//remove hostip from userdata9
	//user->property.userdata9 = string("");
	
	//unauthorize
	user->Unauthorize(this);
	
	WriteServLog("purestg2: User %s (socket=%d) is disconnected.", ask.login, clientsocket);
	
	reply.result = PUREPROTO_REPLY_OK;
	break;
	
    case PUREPROTO_ASK_PASSWD:
    	//check if we have user
	if (!user)
	{
	    reply.result = PUREPROTO_REPLY_ERROR;
	    break;
	}
	
	if (!user->IsInetable())
	{
	    WriteServLog("purestg2: User %s (socket=%d) is blocked by stargazer.", ask.login, clientsocket);
	    reply.result = PUREPROTO_REPLY_ERROR;
	    break;
	}
	
	//get user passwd
	strncpy(reply.passwd, user->property.password.Get().c_str(), PASSWD_LEN);
	
	reply.result = PUREPROTO_REPLY_OK;
	
	break;
	
    case PUREPROTO_ASK_IP:
        //check if we have user
	if (!user)
	{
	    reply.result = PUREPROTO_REPLY_ERROR;
	    break;
	}
	
	//get user ip
	reply.userip.s_addr = (user->property.ips.Get()[0]).ip;
	
	reply.result = PUREPROTO_REPLY_OK;
	break;
	
    case PUREPROTO_ASK_IFUNIT:
	reply.ifunit = getNextIfunit();
	
	reply.result = PUREPROTO_REPLY_OK;
	break;
	
    case PUREPROTO_ASK_PING:
	reply.result = PUREPROTO_REPLY_OK;	
	if (user)
	{
	    if (d) WriteServLog("purestg2: PING from user %s (socket=%d)", ask.login, clientsocket);
	    
	    if (!user->IsInetable())
	    {
		WriteServLog("purestg2: User %s (socket=%d) is disconnected by stargazer. Notifing pppd.", ask.login, clientsocket);
		reply.result = PUREPROTO_REPLY_ERROR;
	    }
	}
	break;
	
    default:
        WriteServLog("purestg2: ERROR: Unknown ask packet type: %d.", ask.type);
	return -1;
    }
    
    if (d) WriteServLog("purestg2: reply: type=%d, login=%s, result=%d", reply.type, reply.login, reply.result);
    
    //now send the reply
    if (send(clientsocket, &reply, sizeof(reply), 0) == -1)
    {
	WriteServLog("purestg2: ERROR: Can't send reply: %s", strerror(errno));
	return -1;
    }
    
    return 0;
}
//-----------------------------------------------------------------------------
int AUTH_PURESTG2::getNextIfunit()
{
    char lf[100];
    
    int ifnum = minppp;
    do
    {
	++ifnum;
	sprintf(lf, "/var/run/ppp%d.pid", ifnum);
    } while (access(lf, F_OK) == 0);

    return ifnum;    
}
//-----------------------------------------------------------------------------
