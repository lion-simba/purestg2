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
 *    Author: (c) 2009-2014 Alexey Osipov <public@alexey.osipov.name>
 */
 
#ifndef H_PURESTG_PUREPROTOCLIENT
#define H_PURESTG_PUREPROTOCLIENT

#include <netinet/in.h>


extern int stg_socket; // socket will be initialized after call to pureproto_connect()

/*
    functions to work with pureprotocol
*/
//every function return non-negative on success and negative number on error

//establish a connection to stargazer
int pureproto_connect(const char* socketpath);

//terminate connection to stargazer
int pureproto_disconnect();

//transfer ipparam to Stargazer
int pureproto_setipparam(const char* ipparam, const char* login);

//ask stg to connect user
//userip is required only if pureproto_getip() return all-zero (0.0.0.0)
int pureproto_connectuser(const char* login, struct in_addr* userip);

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

//transfer calling number to Stargazer
int pureproto_setcallnumber(const char* callnumber, const char* login);

//ask stg to check that given userip is allowed for given user
int pureproto_checkip(struct in_addr* userip, const char* login);

#endif
