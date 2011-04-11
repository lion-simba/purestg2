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
#include <sys/time.h>

#include <stg/user.h>
#include <stg/locker.h>

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
    STG_LOCKER(&auth->tobeunauth_mutex, __FILE__, __LINE__);
    auth->tobeunauth.push(user);
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
    pppdtimeout = 60*5;
    
    pthread_mutex_init(&tobeunauth_mutex, NULL);
}
//-----------------------------------------------------------------------------
AUTH_PURESTG2::~AUTH_PURESTG2()
{
    pthread_mutex_destroy(&tobeunauth_mutex);
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
                errorStr = "Parameter \"unitsave\" must have an integer value from 0 to 9.";
                return 1;
            }
        }
        else if (settings.moduleParams[i].param == "pppdtimeout")
        {
            char* endPtr;
            pppdtimeout = strtol(settings.moduleParams[i].value[0].c_str(), &endPtr, 10);
            if (*endPtr != '\0' || pppdtimeout <= 0)
            {
                errorStr = "Parameter \"pppdtimeout\" must have positive integer value.";
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
        //check if some users were disconnected by stg
        if (auth->checkStgDisconnects() < 0)
            auth->WriteServLog("purestg2: ERROR: checkStgDisconnects failed");

        //check if some user should be disconnected by timeout
        if (auth->checkUserTimeouts() < 0)
            auth->WriteServLog("purestg2: ERROR: checkUserTimeouts failed");

        //check if have some data from pppds
        int pollresult = poll(&auth->connections.front(), auth->connections.size(), 1000);

        if (pollresult == -1)
        {
            auth->WriteServLog("purestg2: ERROR: can't poll connections: %s", strerror(errno));
            usleep(500000);
            continue;
        }

        if (pollresult == 0)
            continue; //no new data
            
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
                int ret;
                if ((ret = auth->hupClientConnection(*socket)) < 0)
                    auth->WriteServLog("purestg2: ERROR: Can't hup client connection %d (ret=%d)", *socket, ret);
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
    vector<struct pollfd>::iterator todel;
    for (todel = connections.begin(); todel != connections.end(); ++todel)
    {
        if (todel->fd == socket)
            break;
    }

    if (todel == connections.end())
    {
        WriteServLog("purestg2: Can't find connection for socket %d", socket);
        return -1;
    }

    connections.erase(todel);

    return 0;
}
//-----------------------------------------------------------------------------
int AUTH_PURESTG2::finishClientConnection(int socket)
{
    //remove socket from usersockets map
    USER_PTR user = getUserBySocket(socket);
    if (user)
        usersockets.erase(user->GetID());

    //remove connection
    int ret;
    if ((ret = delConnection(socket)) < 0)
        WriteServLog("purestg2: BUG: delConnection for socket %d failed: %d", socket, ret);
    
    //free unit holded by this socket
    int unit = getUnitBySocket(socket);
    if (unit >= 0)
        busyunits[unit-minppp] = -1;
    else
        WriteServLog("purestg2: BUG: Can't find unit for socket %d", socket);
        
    //remove user timeout if any
    userstos.erase(user);
    
    //close socket
    close(socket);
    
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
int AUTH_PURESTG2::hupClientConnection(int clientsocket)
{
    USER_PTR user = getUserBySocket(clientsocket);
    
    int ret;
    if ((ret = finishClientConnection(clientsocket)) < 0)
        WriteServLog("purestg2: BUG: Can't finish hupped connection for socket %d (ret=%d)", clientsocket, ret);
    
    //if this was unexpected socket termination, unauthorize user
    if (user)
    {
        if (user->IsAuthorizedBy(this))
        {
            WriteServLog("purestg2: User \"%s\" is still authorized after socket had closed, unauthorizing...", user->GetLogin().c_str());
            deactivateNotifier(user);
            user->Unauthorize(this);
        }
    }
        
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
                deactivateNotifier(user);
                user->Unauthorize(this);
                if (finishClientConnection(oldsocket) < 0)
                    WriteServLog("purestg2: BUG: can't finishClientConnection for oldsocket=%d for user \"%s\"", oldsocket, ask.login);                
                
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
        activateNotifier(user);
        
        //create watchdog timer for this user
        if (updateUserWatchdog(user) < 0)
            WriteServLog("purestg2: ERROR: updateUserWatchdog failed (socket=%d)", clientsocket);

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
        deactivateNotifier(user);
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

            if (updateUserWatchdog(user) < 0)
                WriteServLog("purestg2: ERROR: updateUserWatchdog failed (socket=%d)", clientsocket);

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
USER_PTR AUTH_PURESTG2::getUserBySocket(int socket)
{
    USER_PTR user = NULL;
    
    map<int, int>::iterator iter;
    for(iter = usersockets.begin(); iter != usersockets.end(); ++iter)
        if (iter->second == socket)
            break;
     
    if (iter != usersockets.end())
    {
        int hSearch = users->OpenSearch();
        USER_PTR cu = NULL;
        while(users->SearchNext(hSearch, &cu) == 0)
            if (cu->GetID() == iter->first)
            {
                user = cu;
                break;
            }
        users->CloseSearch(hSearch);
    }
    
    return user;
}
//-----------------------------------------------------------------------------
int AUTH_PURESTG2::getUnitBySocket(int socket)
{
    int unit = minppp;
    vector<int>::iterator iter;
    for(iter = busyunits.begin(); iter != busyunits.end(); ++iter)
    {
        if (*iter == socket)
            break;
        unit++;
    }
    
    if (iter == busyunits.end())
        return -1;
        
    return unit;
}
//-----------------------------------------------------------------------------
int AUTH_PURESTG2::clientDisconnectByStg(USER * user)
{
    int socket = usersockets[user->GetID()];

    WriteServLog("purestg2: User \"%s\" is disconnected by stargazer. Closing auth socket %d.", user->GetLogin().c_str(), socket);
    
    deactivateNotifier(user);
    user->Unauthorize(this);
    
    if (finishClientConnection(socket) < 0)
        WriteServLog("purestg2: BUG: Can't del connection socket %d!", socket);
    
    return 0;
}
//-----------------------------------------------------------------------------
int AUTH_PURESTG2::checkUserTimeouts()
{
    struct timeval tv;
    if (gettimeofday(&tv, NULL) < 0)
    {
        WriteServLog("purestg2: BUG: gettimeofday failed: %s", strerror(errno));
        return -1;
    }
    
    while(!userswds.empty() && tv.tv_sec > userswds.front().second)
    {
        USER_PTR user = userswds.front().first;
        userswds.pop();
        
        map<USER_PTR, time_t>::iterator iter;
        iter = userstos.find(user);
        if (iter == userstos.end())
            continue;
        
        if (tv.tv_sec > iter->second)
        {
            WriteServLog("purestg2: No pings from PPPD for user \"%s\" for %d seconds, terminating connection...", user->GetLogin().c_str(), pppdtimeout);
            deactivateNotifier(user);
            user->Unauthorize(this);
            
            map<int, int>::iterator socketiter;
            socketiter = usersockets.find(user->GetID());
            if (socketiter != usersockets.end())
            {
                int ret;
                if ((ret = finishClientConnection(socketiter->second)) < 0)
                    WriteServLog("purestg2: ERROR: finishClientConnection failed: %d", ret);
            }
            else
                WriteServLog("purestg2: BUG: Can't find socket for user \"%s\"", user->GetLogin().c_str());
        }
    }
}
//-----------------------------------------------------------------------------
int AUTH_PURESTG2::checkStgDisconnects()
{
    STG_LOCKER(&tobeunauth_mutex, __FILE__, __LINE__);

    while (!tobeunauth.empty())
    {
        USER_PTR user = tobeunauth.front();
        if (clientDisconnectByStg(user) < 0)
            WriteServLog("purestg2: ERROR: clientDisconnectByStg failed for user %s", user->GetLogin().c_str());
        tobeunauth.pop();
    }

    return 0;
}
//-----------------------------------------------------------------------------
void AUTH_PURESTG2::activateNotifier(USER* user)
{
    CONNECTED_NOTIFIER* cn = CONNECTED_NOTIFIER::Create(this, user);
    notifiers[user->GetID()] = cn;
    user->AddConnectedAfterNotifier(cn);
}
//-----------------------------------------------------------------------------
void AUTH_PURESTG2::deactivateNotifier(USER* user)
{
    int uid = user->GetID();
    map<int, CONNECTED_NOTIFIER*>::iterator iter = notifiers.find(uid);
    if (iter == notifiers.end())
    {
        WriteServLog("purestg2: BUG: attempt to deactivate not activated notifier for user id %d", uid);
        return;
    }
    user->DelConnectedAfterNotifier(iter->second);
    delete iter->second;
    notifiers.erase(iter);
}
//-----------------------------------------------------------------------------
int AUTH_PURESTG2::updateUserWatchdog(USER* user)
{
    //update watchdog timer for this user
    struct timeval tv;
    if (gettimeofday(&tv, NULL) < 0)
    {
        WriteServLog("purestg2: BUG: gettimeofday failed: %s", strerror(errno));
        return -1;
    }
    
    time_t watchtime = tv.tv_sec + pppdtimeout;
    userstos[user] = watchtime;
    userswds.push(pair<USER_PTR, time_t>(user, watchtime));
    if (d)
        WriteServLog("purestg2: Watchdog timer for user \"%s\" submitted on %d", user->GetLogin().c_str(), watchtime);
    
    return 0;
}
//-----------------------------------------------------------------------------
