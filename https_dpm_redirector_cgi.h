/**********************************************************************
 * https_dpm_redirector_cgi.h
 * Author: Andreas-Joachim Peters CERN(2007)
 */
/*
 Copyright (c) Members of the EGEE Collaboration. 2004.
 See http://www.eu-egee.org/partners/ for details on the copyright holders.
 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at
 
     http://www.apache.org/licenses/LICENSE-2.0
 
 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
*/

#ifndef __HTTPS_DPM_REDIRECTOR_CGI_H
#define __HTTPS_DPM_REDIRECTORCGI_H

/********************************************************************** 
 * system includes
 */

#include <stdio.h>
#include <syslog.h>
#include <pwd.h>
#include <grp.h>
#include <stdarg.h>
#include <errno.h>
#include <time.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <libgen.h>

/********************************************************************** 
 * dpm includes
 */

#include <dpm/dpm_api.h>
#include <dpm/dpns_api.h>
#include <dpm/serrno.h>
#include <dpm/u64subr.h>

/********************************************************************** 
 * openssl includes
 */

#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>

#include "https_dpm_util_cgi.h"

/********************************************************************** 
 * global defines
 */

/* lifetime for issued access token */
#define TOKENLIFETIME 10
#define UPLOADTOKENLIFETIME 120
/* redirection port for http requests */
#define DEFAULTHTTPTRANSPORTPORT 777
#define DEFAULTHTTPSTRANSPORTPORT 884

#define SIXMONTHS (6*30*24*60*60)

/* default allocation size for a single file in a put request */
#define DEFAULTPUTALLOCSIZE 1024 //*1024*1024 

#define MAXPUTWAIT 20
/**********************************************************************
 * structures
 */

typedef struct gs_credentials {
  char type[9];
  long notbefore;
  long notafter;
  int delegation;
  char dn[4096];
} gs_credentials_t;


/**********************************************************************
 * global variables
 */

gs_credentials_t credentials;           /* credential information of the connected user */
gs_credentials_t vomscredentials;      /* voms credential information of the connected user */
uid_t uid;                              /* user id */
gid_t gid;                              /* groud id */


int dpmSessionActive=0;                 /* indicates open dpm session */
char redirectionurl[8192];              /* stores the redirection url for an authorized request */
int  redirectionhttpport=DEFAULTHTTPTRANSPORTPORT;   /* port of the target http redirection server */
int  redirectionhttpsport=DEFAULTHTTPSTRANSPORTPORT;   /* port of the target http redirection server */

char* dpmpath=0;                  /* dpm LFN required in the http URI */
const char* dpmse=0;                    /* dpm SE required in the http URI query */
const char* dpmreplica=0;               /* dpm replica number required in the http URI query */
int dpmrep=0;                           /* dpm replica number as int */
const char* dpmguid=0;                  /* dpm guid specified in the URI query */
const char* dpmmetacmd=0;               /* dpm meta commands e.g. mkdir/rmdir  */
      char* dpmmetaopt=0;               /* dpm meta command option */ 
const char* dpmfilesize=0;              /* dpm file size for a putdone requests */
const char* dpmtoken=0;                 /* dpm token used for get & put requests */
const char* dpmfilename=0;              /* dpm base filename - if present appended to dpmpath */
const char* dpmauthip=0;		/* ip authorized on head node for authz */
const char* keyhash = "00000000";       /* hash value of the key used to sign requests - currently ignored */
int i;

char signature[8192];                   /* signature for a request */
/* signatures are made as <path>@<client-ip>:<sfn>:<key-hash>:<expirationtime>:<client-id> */

          
char signed_signature_buff[256];        /*  buffer containing a signed signature ... this will work vor keys upto 2048 bit */

u_signed64 defaultputallocsize=DEFAULTPUTALLOCSIZE; /* allocated size in a put requested when the file size is not known */

char hostname[1024];                    /* the hostname of this main redirector */
char fqdn[1024];                        /* the FQDN of this main redirector */
/**********************************************************************
 * function prototypes
 */ 

void return_browse_directory(const char* path,int dostat);      /* browser function to provide HTML pages with directory information & http links */


/*
 * dpm session/mapping functions
 */

int  init_dpm();
void exit_dpm();

/*
 * signature creation and verification
 */

void set_signature(const char* path, const char* method, const char* sfn, time_t lifetime, const char* rtoken);
const char* sign_signature();

#endif
