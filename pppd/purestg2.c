/*
 * purestg2.so - Stargazer authentication plugin for pppd
 * Copyright (C) 2006-2014 Alexey Osipov <public@alexey.osipov.name>
 *
 * Based on:
 * passmysql.so - MySQL authentication plugin for pppd
 * Copyright (C) 2004, 2003 McMCC <mcmcc@mail.ru>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#include <config.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <signal.h>
#include <poll.h>
#include <signal.h>

//pppd.h defines version of pppd
#undef VERSION
#include <pppd.h>
#include <fsm.h>
#include <ipcp.h>

#include <chap-new.h>
#include <chap_ms.h>
#include <md5.h>

#include <stg/const.h>

#include "pureclient.h"

char pppd_version[] = VERSION;

/* parameters */

static int keepalivetimeout = 60;
static char authsocketpath[MAXPATHLEN+1];
static char predownscript[MAXPATHLEN+1] = "";
static char preupscript[MAXPATHLEN+1] = "";

static option_t options[] = {
    { "keepalivetimeout", o_int, &keepalivetimeout, "timeout of waiting for stargazer ALIVE packets (seconds)",
      OPT_LLIMIT, NULL, 0, 10},
    { "authsocket", o_string, authsocketpath, "Stargazer auth socket path",
      OPT_PRIV | OPT_STATIC | OPT_ULIMIT, NULL, MAXPATHLEN },
    { "predownscript", o_string, predownscript, "Script to be run before link termination",
      OPT_PRIV | OPT_STATIC | OPT_ULIMIT, NULL, MAXPATHLEN },
    { "preupscript", o_string, preupscript, "Script to be run before switching user on in Stargazer",
      OPT_PRIV | OPT_STATIC | OPT_ULIMIT, NULL, MAXPATHLEN },
    {  NULL }
};

/* global variables */

static char userlogin[LOGIN_LEN+1];
static int userconnected = 0;
pthread_t socketwatch;


/* helper function */

void run_script(char* script)
{
    char strspeed[32], strlocal[32], strremote[32];
    char *argv[8];

    slprintf(strspeed, sizeof(strspeed), "%d", baud_rate);
    slprintf(strlocal, sizeof(strlocal), "%I", ipcp_gotoptions[0].ouraddr);
    slprintf(strremote, sizeof(strremote), "%I", ipcp_hisoptions[0].hisaddr);

    argv[0] = predownscript;
    argv[1] = ifname;
    argv[2] = devnam;
    argv[3] = strspeed;
    argv[4] = strlocal;
    argv[5] = strremote;
    argv[6] = ipparam;
    argv[7] = NULL;

    run_program(script, argv, 0, NULL, NULL, 1);
}

/*
    pppd hooks and notifiers
*/

void keep_alive(void* opaque)
{
    int result;
    dbglog("purestg2: keepalive started.");

    result = pureproto_ping(keepalivetimeout, userlogin);
    if (result < 0)
    {
        if (result == -2)
        {
            error("purestg2: Error reply on ping command, disconnect and exiting.");
            pureproto_disconnectuser(userlogin);
            pureproto_disconnect();
        }
        else
            error("purestg2: No ping from stargazer, exiting.");

        if (kill(getpid(), SIGTERM) == -1)
        {
            error("purestg2: Can't gracefully kill myself, will die.");
            die(1);
        }
        return;
    }

    dbglog("purestg2: keepalive succedded.");

    timeout(&keep_alive, 0, keepalivetimeout, 0);
}

void user_on(void* opaque, int xz)
{
    //run and wait for pre-iup script if it exists
    run_script(preupscript);

    //ask stargazer to enable this user
    struct in_addr userip;
    userip.s_addr = ipcp_hisoptions[0].hisaddr;
    if (pureproto_connectuser(userlogin, &userip) == -1)
    {
        error("purestg2: Can't connect user %s with ip %I.", userlogin, userip.s_addr);
        die(1);
        return;
    }
    
    userconnected = 1;

    //start keepalive sequence
    timeout(&keep_alive, 0, keepalivetimeout, 0);

    info("purestg2: User %s connected with ip %I.", userlogin, userip.s_addr);
}

void user_off(void* opaque, int xz)
{
    if (!userconnected)
        return;

    //run and wait for pre-down script if it exists
    run_script(predownscript);

    //if user, then ask stargazer to disable this user
    if (pureproto_disconnectuser(userlogin) == -1)
    {
        error("purestg2: Can't disconnect user %s", userlogin);
        return;
    }

    info("purestg2: User %s disconnected.", userlogin);
}

#define MD5_HASH_SIZE    16
#define NEW_CHAP_FAILURE 0
#define NEW_CHAP_SUCCESS 1

int chap_stg_verify(char *user, char *ourname, int id,
                    struct chap_digest_type *digest,
                    unsigned char *challenge, unsigned char *response,
                    char *message, int message_space)
{
    info("purestg2: CHAP started.");

    int code = NEW_CHAP_FAILURE;
    char secret[PASSWD_LEN+1];

    if (strlen(user) > LOGIN_LEN)
    {
        error("purestg2: Login length of login \"%s\" is too big.", user);
        return code;
    }

    //check if Stargazer accept given ipparam
    if (pureproto_setipparam(ipparam, user) == -1)
    {
        if (ipparam)
            error("purestg2: Stargazer refuse to accept ipparam \"%s\" for user \"%s\".", ipparam, user);
        else
            error("purestg2: Stargazer refuse to accept empty ipparam for user \"%s\".", user);
        return code;
    }

    //check if Stargazer accept given calling number
    if (pureproto_setcallnumber(remote_number, user) == -1)
    {
        if (remote_number)
            error("purestg2: Stargazer refuse to accept calling number \"%s\" for user \"%s\".", remote_number, user);
        else
            error("purestg2: Stargazer refuse to accept empty calling number for user \"%s\".", user);
        return code;
    }

    //ask stg if user can be turned on
    //if ok, ask user's password
    if (pureproto_getpasswd(secret, user) == -1)
    {
        error("purestg2: Can't get passwd for user %s.", user);
        return code;
    }

    info("purestg2: Got passwd for user %s.", user);

    strncpy(userlogin, user, LOGIN_LEN);

    //verify password
    code = digest->verify_response(id, user, secret, strlen(secret), challenge,
                                   response, message, message_space);

    //check code
    if (code != NEW_CHAP_SUCCESS)
    {
        error("purestg2: CHAP failed.");
        //slprintf(message, message_space, "Access denied"); // write our cause (we still need this?)
    }

    return code;
}


int pap_stg_verify(char *user,
                   char *passwd,
                   char **msgp,
                   struct wordlist **paddrs,
                   struct wordlist **popts)
{

    info("purestg2: PAP started.");

    char secret[PASSWD_LEN+1];

    if (strlen(user) > LOGIN_LEN)
    {
        error("purestg2: Login length of login \"%s\" is too big.", user);
        return 0;
    }

    //check if Stargazer accept given ipparam
    if (pureproto_setipparam(ipparam, user) == -1)
    {
        if (ipparam)
            error("purestg2: Stargazer refuse to accept ipparam \"%s\" for user \"%s\".", ipparam, user);
        else
            error("purestg2: Stargazer refuse to accept empty ipparam for user \"%s\".", user);
        return 0;
    }

    //ask stg if user can be turned on
    //if ok, ask user's password
    if (pureproto_getpasswd(secret, user) == -1)
    {
        error("purestg2: Can't get passwd for user %s.", user);
        return 0;
    }

    info("purestg2: Got passwd for user %s.", user);

    strncpy(userlogin, user, LOGIN_LEN);

    //compare passed password with correct one
    if (strncmp(secret, passwd, PASSWD_LEN) != 0)
    {
        error("purestg2: PAP failed.");
        return 0;
    }

    return 1;
}


void choose_ip(u_int32_t *addrp)
{
    struct in_addr inpz;

    info("purestg2: IP choose started.");

    //ask IP for user from stargazer
    if (pureproto_getip(&inpz, userlogin) == -1)
    {
        error("purestg2: Can't get IP for user %s.", userlogin);
        return;
    }

    if (inpz.s_addr == 0)
    {
        info("purestg2: IP choosen: any.");
        return;
    }

    info("purestg2: IP choosen: %I.", inpz.s_addr);

    //set that ip to addrp
    *addrp = inpz.s_addr;
}

int chap_check_ok (void)
{
    info("purestg2: Chap check is allowed.");
    return 1;
}

int pap_check_ok (void)
{
    info("purestg2: Pap check is allowed.");
    return 1;
}

int allowed_address (u_int32_t addr)
{
    struct in_addr inpz;
    info("purestg2: Check that address %I is allowed...", addr);

    //ask stargazer to check the ip
    inpz.s_addr = addr;
    if (pureproto_checkip(&inpz, userlogin) == 0)
    {
        info("purestg2: Good address.");
        return 1;
    }
    else
    {
        error("purestg2: Stargazer disallowed address %I for user %s.", inpz.s_addr, userlogin);
        return 0;
    }
}



void* socketwatch_thread(void* arg)
{
    int pres;
    struct pollfd watchfd;

    watchfd.fd = stg_socket;
    watchfd.events = 0;
    watchfd.revents = 0;

    if(poll(&watchfd, 1, -1) < 0)
        error("purestg2: poll failed!");

    if (watchfd.revents & POLLHUP)
    {
        info("purestg2: stargazer socket has just been closed. Terminating connection.");
        if (kill(getpid(), SIGTERM) == -1)
        {
            error("Selfkilling failed. :( Have to die.");
            die(0);
        }
    }

    return NULL;
}

int stg_phase(int phase)
{
    if (phase == PHASE_SERIALCONN)
    {
        if (debug)
        {
            info("purestg2: parameters values:");
            info("purestg2: keepalivetimeout = %d", keepalivetimeout);
            info("purestg2: authsocket = %s", authsocketpath);
            info("purestg2: predownscript = %s", predownscript);
            info("purestg2: preupscript = %s", preupscript);
            info("purestg2: ------------------");
        }

        if (pureproto_connect(authsocketpath) == -1)
        {
            error("purestg2: Can't connect to stargazer's socket %s. Exiting.", authsocketpath);
            die(1);
        }

        //spawning socketwatch thread
        if (pthread_create(&socketwatch, NULL, socketwatch_thread) != 0)
        {
            error("purestg2: Can't create socketwatch thread. Exiting.");
            die(1);
        }

        info("purestg2: Connected to stargazer via %s.", authsocketpath);

        if (pureproto_getifunit(&req_unit) == -1)
        {
            error("purestg2: Can't get ifunit. Exiting.");
            die(1);
        }

        info("purestg2: ifunit set to %d.", req_unit);
    }
    else if (phase == PHASE_DEAD)
    {
        if (pureproto_disconnect() == -1)
        {
            error("purestg2: Can't disconnect from stargazer.");
            return;
        }

        info("purestg2: Disconnected from stargazer.");
    }
}

void plugin_init (void)
{
    add_options(options);

    userlogin[0] = '\0';

    new_phase_hook = stg_phase;

    pap_check_hook = pap_check_ok;
    chap_check_hook = chap_check_ok;

    chap_verify_hook = chap_stg_verify;
    pap_auth_hook = pap_stg_verify;

    ip_choose_hook = choose_ip;
    allowed_address_hook = allowed_address;

    add_notifier(&ip_up_notifier, user_on, 0);
    add_notifier(&ip_down_notifier, user_off, 0);

    info("Stargazer (%s) auth plugin initialized.", PACKAGE_STRING);
    if (debug)
        info("purestg2: debug is enabled.");
}
