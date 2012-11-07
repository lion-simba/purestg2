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
 
/*
 *    Server side module to use with my authorization plugin for pppd.
 */

#ifndef H_STG_PURESTG_SERVER
#define H_STG_PURESTG_SERVER

#include <string>
#include <map>
#include <vector>
#include <queue>
#include <pthread.h>
#include <sys/poll.h>

#include <stg/auth.h>
#include <stg/logger.h>
#include <stg/users.h>
#include <stg/user_property.h>
#include <stg/noncopyable.h>

using namespace std;

extern "C" PLUGIN * GetPlugin();

//-----------------------------------------------------------------------------

class AUTH_PURESTG2;

class CONNECTED_NOTIFIER: public PROPERTY_NOTIFIER_BASE<bool>,
                       private NONCOPYABLE
{
public:
    static CONNECTED_NOTIFIER * Create(AUTH_PURESTG2 * auth, USER * user);
    void Notify(const bool & oldVal, const bool & newVal);

    ~CONNECTED_NOTIFIER();

private:
    CONNECTED_NOTIFIER(AUTH_PURESTG2 * a, USER * u);

    USER * user;
    AUTH_PURESTG2 * auth;

#ifdef CONNECTED_NOTIFIER_DEBUG
    static int notifiers_count;
#endif
};

//-----------------------------------------------------------------------------

class AUTH_PURESTG2: public AUTH
{
    friend class CONNECTED_NOTIFIER;

public:
    AUTH_PURESTG2();
    virtual ~AUTH_PURESTG2();

    void                SetUsers(USERS * u);
    void                SetTariffs(TARIFFS * t){};
    void                SetAdmins(ADMINS * a){};
    void                SetTraffcounter(TRAFFCOUNTER * tc){};
    void                SetStore(STORE * ){};
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
    static void*            Run(void * me); // main loop

    STG_LOGGER&             WriteServLog;

    // worker (main) functions
    int                     acceptClientConnection();
    int                     handleClientConnection(int clientsocket);
    int                     hupClientConnection(int clientsocket);
    int                     checkStgDisconnects();
    int                     checkUserTimeouts();
    // ---------------------------------------------

    // helper functions
    int                     addConnection(int socket);
    int                     delConnection(int socket);

    int                     clientDisconnectByStg(USER * user);
    int                     finishClientConnection(int socket);

    void                    activateNotifier(USER* user);
    void                    deactivateNotifier(USER* user);

    USER_PROPERTY<string>&  getUserData(USER* user, int dataNum);
    USER_PTR                getUserBySocket(int socket);
    int                     getUnitBySocket(int socket);

    int                     updateUserWatchdog(USER* user);
    // --------------------------------------------------------------

private:
    mutable string          errorStr;
    bool                    isRunning;          //running or not in fact
    bool                    nonstop;            //must run or mustn't

    int                     listeningsocket;
    pthread_t               listeningthread;

    MODULE_SETTINGS         settings;
    USERS*                  users;

    //main variables
    vector<struct pollfd>          connections; //connections[0] is for listeningsocket
    map<int, int>                  usersockets; //maps userid to socket it is using
    vector<int>                    busyunits;   //busyunits[unitnum-minppp] = socket_id which holds unitnum or -1 if unitnum is free
    map<int, CONNECTED_NOTIFIER*>  notifiers;   //connected notifier for user id

    queue<USER_PTR>                tobeunauth;  //users to be unauthenticated
    pthread_mutex_t                tobeunauth_mutex;

    queue< pair<USER_PTR, time_t> >     userswds;    //users watchdogs
    map<USER_PTR, time_t>               userstos;    //users timeouts (most later watchdog time)

    //properties
    string                  authsocketpath;
    int                     minppp;
    int                     d;
    int                     unitsave;           //the userdata number to save PPP unit number to
    int                     ipparamsave;        //the userdata number to save ipparam to
    int                     ipparamauth;        //the userdata number to check ipparam against
    bool                    allowemptyipparam;
    bool                    kickprevious;
    int                     pppdtimeout;        //timeout to kill connection if no PINGs received
    bool                    checkinetable;      //if not set, purestg2 will authorize user even if it's not IsInetable()
};
//-----------------------------------------------------------------------------

#endif


