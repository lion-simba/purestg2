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
 
/*
 *    Server side module to use with my authorization plugin for pppd.
 */

#ifndef H_STG_PURESTG_SERVER
#define H_STG_PURESTG_SERVER

#include <string>
#include <map>
#include <vector>
#include <pthread.h>
#include <sys/poll.h>
#include <base_auth.h>
//#include "notifer.h"
//#include "user_ips.h"
#include <stg_logger.h>
#include <users.h>

using namespace std;

extern "C" BASE_PLUGIN * GetPlugin();

//-----------------------------------------------------------------------------
class AUTH_PURESTG2 :public BASE_AUTH
{
public:
    AUTH_PURESTG2();
    virtual ~AUTH_PURESTG2();

    void                SetUsers(USERS * u);
    void                SetTariffs(TARIFFS * t){};
    void                SetAdmins(ADMINS * a){};
    void                SetTraffcounter(TRAFFCOUNTER * tc){};
    void                SetStore(BASE_STORE * ){};
    void                SetStgSettings(const SETTINGS *){};

    int                 Start();
    int                 Stop();
    int                 Reload();
    bool                IsRunning();
    void                SetSettings(const MODULE_SETTINGS & s);
    int                 ParseSettings();
    const string      & GetStrError() const;
    const string        GetVersion() const;
    uint16_t            GetStartPosition() const;
    uint16_t            GetStopPosition() const;

    int                 SendMessage(const STG_MSG & msg, uint32_t ip) const;

private:
    static void*            Run(void * me);
    
    STG_LOGGER&             WriteServLog;
    
    int                     addConnection(int socket);
    int                     delConnection(int socket);
    
    int                     acceptClientConnection();
    int                     handleClientConnection(int clientsocket);
    
    USER_PROPERTY<string>&  getUserData(USER* user, int dataNum);
    
private:
    mutable string          errorStr;
    bool                    isRunning;          //running or not in fact
    bool                    nonstop;            //must run or mustn't
    string                  authsocketpath;
    int                     listeningsocket;
    pthread_t               listeningthread;
    
    vector<struct pollfd>   connections;        //connections[0] is for listeningsocket
    map<int, int>           usersockets;        //maps userid to socket it is using
    
    vector<int>             busyunits;          //busyunits[unitnum-minppp] = socket_id which holds unitnum or -1 if unitnum is free
    int                     minppp;
    
    int                     d;
    
    int                     ipparamsave;        //the userdata number to save ipparam to
    int                     ipparamauth;        //the userdata number to check ipparam against
    bool                    allowemptyipparam;
    
    bool                    kickprevious;
    
    MODULE_SETTINGS         settings;
    USERS*                  users;
    
};
//-----------------------------------------------------------------------------

#endif


