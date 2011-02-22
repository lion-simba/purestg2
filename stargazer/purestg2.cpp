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
 *    Author: (c) 2009-2011 Alexey Osipov <simba@lerlan.ru>
 */

#include <config.h>

#include <cstdlib>
#include <algorithm>

#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <stg/user.h>
#include <stg/noncopyable.h>

#include "purestg2.h"
#include "pureproto.h"

#define PURESTGNAME(_package)	 "PPPD Authorizator (" _package ")"

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

    PLUGIN * GetPlugin()
    {
        return dc;
    };
};
//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------

class CONNECTED_NOTIFIER: public PROPERTY_NOTIFIER_BASE<bool>,
                       private NONCOPYABLE
{
public:
    static CONNECTED_NOTIFIER * Create(AUTH_PURESTG2 * auth, USER * user);
    void Notify(const bool & oldVal, const bool & newVal);
        
private:
    CONNECTED_NOTIFIER(AUTH_PURESTG2 * a, USER * u);
    ~CONNECTED_NOTIFIER();

    USER * user;
    AUTH_PURESTG2 * auth;

#ifdef CONNECTED_NOTIFIER_DEBUG    
    static int notifiers_count;
#endif
};

#ifdef CONNECTED_NOTIFIER_DEBUG    
int CONNECTED_NOTIFIER::notifiers_count = 0;
#endif

CONNECTED_NOTIFIER * CONNECTED_NOTIFIER::Create(AUTH_PURESTG2 * auth, USER * user)
{
    //ensure we can't be created on stack
    return new CONNECTED_NOTIFIER(auth, user);
}

CONNECTED_NOTIFIER::CONNECTED_NOTIFIER(AUTH_PURESTG2 * a, USER * u) 
    :auth(a), user(u)
{
#ifdef CONNECTED_NOTIFIER_DEBUG
notifiers_count++;
GetStgLogger()("CONNECTED_NOTIFIER created (%d)", notifiers_count);
#endif
}

CONNECTED_NOTIFIER::~CONNECTED_NOTIFIER()
{
#ifdef CONNECTED_NOTIFIER_DEBUG
notifiers_count--;
GetStgLogger()("CONNECTED_NOTIFIER destroyed (%d)", notifiers_count);
#endif
}

void CONNECTED_NOTIFIER::Notify(const bool &, const bool &)
{
    if (auth->CheckSocket(user))
    {
        user->DelConnectedAfterNotifier(this);
        delete this; //self destruction :)
    }
}

//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------

PURESTG2_CREATOR pstg2c;

PLUGIN * GetPlugin()
{
    return pstg2c.GetPlugin();
}


void splitstring(const string &s, char delim, vector<string>& elems)
{
    stringstream ss(s);
    string item;
    while(getline(ss, item, delim))
        elems.push_back(item);
}
                            

//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
const string AUTH_PURESTG2::GetVersion() const
{
    return PURESTGNAME(PACKAGE_STRING);
}
//-----------------------------------------------------------------------------
AUTH_PURESTG2::AUTH_PURESTG2()
        :WriteServLog(GetStgLogger())
{
    isRunning = false;
    minppp = 10;
    d = 0;
    ipparamsave = -1;
    ipparamauth = -1;
    allowemptyipparam = false;
    kickprevious = false;
    unitsave = -1;
}
//-----------------------------------------------------------------------------
AUTH_PURESTG2::~AUTH_PURESTG2()
{

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
    for (size_t i=0; i<settings.moduleParams.size(); i++)
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
        else if (settings.moduleParams[i].param == "ipparamsave")
        {
            char* endPtr;
            ipparamsave = strtol(settings.moduleParams[i].value[0].c_str(), &endPtr, 10);
            if (*endPtr != '\0' || ipparamsave < 0 || ipparamsave > 9)
            {
                errorStr = "Parameter \"ipparamsave\" must have an interger value from 0 to 9.";
                return 1;
            }
        }
        else if (settings.moduleParams[i].param == "ipparamauth")
        {
            char* endPtr;
            ipparamauth = strtol(settings.moduleParams[i].value[0].c_str(), &endPtr, 10);
            if (*endPtr != '\0' || ipparamauth < 0 || ipparamauth > 9)
            {
                errorStr = "Parameter \"ipparamauth\" must have an interger value from 0 to 9.";
                return 1;
            }
        }
        else if (settings.moduleParams[i].param == "allowemptyipparam")
        {
            allowemptyipparam = true;
        }
        else if (settings.moduleParams[i].param == "kickprevious")
        {
            kickprevious = true;
        }
        else if (settings.moduleParams[i].param == "pppunitsave")
        {
            char* endPtr;
            unitsave = strtol(settings.moduleParams[i].value[0].c_str(), &endPtr, 10);
            if (*endPtr != '\0' || unitsave < 0 || unitsave > 9)
            {
                errorStr = "Parameter \"unitsave\" must have an interger value from 0 to 9.";
                return 1;
            }
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
    
    int busyuserdata_count = 0;
    set<int> busyuserdata;
    if (ipparamauth != -1)
    {
        busyuserdata.insert(ipparamauth);
        busyuserdata_count++;
    }
    if (ipparamsave != -1)
    {
        busyuserdata.insert(ipparamsave);
        busyuserdata_count++;
    }
    if (unitsave != -1)
    {
        busyuserdata.insert(unitsave);
        busyuserdata_count++;
    }
    
    if (busyuserdata.size() != busyuserdata_count)
    {
        errorStr = "Values for \"ipparamsave\", \"ipparamauth\" and \"pppunitsave\" must be different.";
        return 1;
    }
    
    if (allowemptyipparam && ipparamauth == -1)
    {
        errorStr = "Parameter \"ipparamauth\" must be set to use \"allowemptyipparam\" option.";
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
int AUTH_PURESTG2::Reload()
{
    return 0;
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
    shutdown(listeningsocket, SHUT_RDWR);
    close(listeningsocket);

    return 0;
}
//-----------------------------------------------------------------------------
void* AUTH_PURESTG2::Run(void * me)
{
    AUTH_PURESTG2 * auth = (AUTH_PURESTG2 *) me;

    auth->isRunning = true;

    vector<int> changedsockets;
    vector<int> hupsockets;

    while (auth->nonstop)
    {
        int pollresult = poll(&auth->connections.front(), auth->connections.size(), 1000);

        if (pollresult == -1)
        {
            auth->WriteServLog("purestg2: ERROR: can't poll connections: %s", strerror(errno));
            usleep(500000);
            continue;
        }

        if (pollresult == 0)
            continue;
            
        changedsockets.clear();
        hupsockets.clear();

        for (vector<struct pollfd>::iterator connection = auth->connections.begin(); connection != auth->connections.end(); ++connection)
        {
            if (connection->revents & POLLHUP)
                hupsockets.push_back(connection->fd);
            else if (connection->revents & POLLIN)
                changedsockets.push_back(connection->fd);
        }

        for (vector<int>::iterator socket = changedsockets.begin(); socket != changedsockets.end(); ++socket)
        {
            if (*socket == auth->listeningsocket)
            {
                if (auth->acceptClientConnection() == -1)
                    auth->WriteServLog("purestg2: ERROR: can't accept client connection");
            }
            else
            {
                if (auth->handleClientConnection(*socket) == -1)
                    auth->WriteServLog("purestg2: ERROR: can't handle client connection for socket %d", *socket);
            }
        }

        for (vector<int>::iterator socket = hupsockets.begin(); socket != hupsockets.end(); ++socket)
        {
            if (*socket == auth->listeningsocket)
                auth->WriteServLog("purestg2: BUG: Our listening socket is running away!");
            else
            {
                if (auth->delConnection(*socket) < 0)
                    auth->WriteServLog("purestg2: BUG: Can't del hupped connection!");

                close(*socket);
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
    connections.resize(connections.size() + 1);
    connections.back().fd = socket;
    connections.back().events = POLLIN | POLLHUP;

    return 0;
}
//-----------------------------------------------------------------------------
int AUTH_PURESTG2::delConnection(int socket)
{
    //remove socket from usersockets map
    for(map<int, int>::iterator iter = usersockets.begin(); iter != usersockets.end(); ++iter)
    {
        if (iter->second == socket)
        {
            usersockets.erase(iter);
            break;
        }
    }

    //remove connection
    vector<struct pollfd>::iterator todel;
    for (todel = connections.begin(); todel != connections.end(); ++todel)
    {
        if (todel->fd == socket)
            break;
    }

    if (todel == connections.end())
        return -1;

    connections.erase(todel);
    
    //free unit holded by this socket
    vector<int>::iterator unit;
    for(unit = busyunits.begin(); unit != busyunits.end(); ++unit)
    {
        if (*unit == socket)
            break;
    }
    
    if (unit == busyunits.end())
        return -2;
        
    *unit = -1;
    
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
    case PUREPROTO_ASK_IPPARAM:
        USER_PTR uptr;

        if (users->FindByName(string(ask.login), &uptr) == 0)
            user = uptr;
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
        
        //check if already connected and disconnect previous instance if necessary
        if (user->GetAuthorized())
        {
            if (user->IsAuthorizedBy(this) && kickprevious)
            {
                map<int, int>::iterator iter = usersockets.find(user->GetID());
                if (iter == usersockets.end())
                {
                    WriteServLog("purestg2: BUG: can't find previous user socket for user \"%s\"", ask.login);
                    break;
                }
                int oldsocket = iter->second;
                WriteServLog("purestg2: Terminating previous session (oldsocket=%d) for user \"%s\"", oldsocket, ask.login);
                user->Unauthorize(this);
                if (delConnection(oldsocket) < 0)
                    WriteServLog("purestg2: BUG: can't delConnection for oldsocket=%d for user \"%s\"", oldsocket, ask.login);
                close(oldsocket);
                
                //TODO: wait for old pppd really finish somehow.
            }
            else
            {
                WriteServLog("purestg2: \"%s\" (socket=%d) is already connected.", ask.login, clientsocket);
                reply.result = PUREPROTO_REPLY_ERROR;
                break;
            }
        }

        //authorize user
        if (user->Authorize((user->GetProperty().ips.Get()[0]).ip, 0xffffffff, this))
        {
            WriteServLog("purestg2: ERROR: Can't authorize user %s.", ask.login);
            reply.result = PUREPROTO_REPLY_ERROR;
            break;
        }
        
        usersockets[user->GetID()] = clientsocket;
        
        if (unitsave != -1)
        {
            vector<int>::iterator unit = find(busyunits.begin(), busyunits.end(), clientsocket);
            if (unit != busyunits.end())
            {
                stringstream ss;
                ss << (unit - busyunits.begin() + minppp);
                getUserData(user, unitsave) = ss.str();
            }
            else
                WriteServLog("purestg2: ERROR: Can't find unit number for user \"%s\" (socket=%d).", ask.login, clientsocket);
        }

        //create notifier on user connected state change for handling user's disconnect by STG
        user->AddConnectedAfterNotifier(CONNECTED_NOTIFIER::Create(this, user));

        WriteServLog("purestg2: User %s (socket=%d) is connected.", ask.login, clientsocket);

        reply.result = PUREPROTO_REPLY_OK;
        break;

    case PUREPROTO_ASK_DISCONNECT:
        //check if we have user
        if (!user)
        {
            reply.result = PUREPROTO_REPLY_ERROR;
            break;
        }
        
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

        //check if already connected
        if (user->GetAuthorized())
        {
            if (!user->IsAuthorizedBy(this) || !kickprevious)
            {
                WriteServLog("purestg2: User %s (socket=%d) is already connected.", ask.login, clientsocket);
                reply.result = PUREPROTO_REPLY_ERROR;
                break;
            }
        }

        //get user passwd
        strncpy(reply.passwd, user->GetProperty().password.Get().c_str(), PASSWD_LEN);

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
        reply.userip.s_addr = (user->GetProperty().ips.Get()[0]).ip;

        reply.result = PUREPROTO_REPLY_OK;
        break;

    case PUREPROTO_ASK_IFUNIT:
        reply.ifunit = -1;
        for(int i = 0; i < busyunits.size(); i++)
        {
            if (busyunits[i] == -1)
            {
                reply.ifunit = i + minppp;
                busyunits[i] = clientsocket;
                break;
            }
        }
        if (reply.ifunit == -1)
        {
            reply.ifunit = busyunits.size() + minppp;
            busyunits.push_back(clientsocket);
        }

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
        
    case PUREPROTO_ASK_IPPARAM:
        reply.result = PUREPROTO_REPLY_OK;
        if (d) WriteServLog("purestg2: Got ipparam: \"%s\"", ask.ipparam);
        if (user)
        {
            string ipparam(ask.ipparam);
            if (ipparamsave != -1)
                getUserData(user, ipparamsave) = ipparam;
        
            //check if ipparam is allowed
            if (ipparamauth != -1)
            {
                if (ipparam.empty())
                {
                    if (!allowemptyipparam)
                    {
                        WriteServLog("purestg2: Empty ipparam is disallowed.");
                        reply.result = PUREPROTO_REPLY_ERROR;
                    }
                }
                else
                {
                    string userdata = getUserData(user, ipparamauth);
                    if (!userdata.empty())
                    {
                        vector<string> allowed;
                        splitstring(userdata, ',', allowed);
                        if (find(allowed.begin(), allowed.end(), ipparam) == allowed.end())
                        {
                            //given ipparam was not found in userdata field, so reply with error
                            //and deny the authentication
                            WriteServLog("purestg2: ipparam \"%s\" was't found in userdata%d field for user \"%s\".", ask.ipparam, ipparamauth, ask.login);
                            reply.result = PUREPROTO_REPLY_ERROR;
                        }
                    }
                }
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
#define USERDATACASECONDITION(_num) \
    case _num: \
        return user->GetProperty().userdata##_num;
USER_PROPERTY<string>&  AUTH_PURESTG2::getUserData(USER* user, int dataNum)
{
    switch (dataNum)
    {
        USERDATACASECONDITION(0)
        USERDATACASECONDITION(1)
        USERDATACASECONDITION(2)
        USERDATACASECONDITION(3)
        USERDATACASECONDITION(4)
        USERDATACASECONDITION(5)
        USERDATACASECONDITION(6)
        USERDATACASECONDITION(7)
        USERDATACASECONDITION(8)
        USERDATACASECONDITION(9)
        default:
            WriteServLog("purestg2: BUG: incorrect userdata index: %d", dataNum);
            return user->GetProperty().userdata0;
    }
}
//-----------------------------------------------------------------------------
bool AUTH_PURESTG2::CheckSocket(USER * user)
{
    if (user->GetConnected())
        return false; //all is OK, nothing to do
        
    int socket = usersockets[user->GetID()];
            
    WriteServLog("purestg2: User \"%s\" is disconnected by stargazer. Closing auth socket %d.", user->GetLogin().c_str(), socket);
    
    user->Unauthorize(this);
    
    if (delConnection(socket) < 0)
        WriteServLog("purestg2: BUG: Can't del connection socket %d!", socket);
    
    shutdown(socket, SHUT_RDWR);
    close(socket);
    
    return true;
}
//-----------------------------------------------------------------------------
