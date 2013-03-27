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
#ifndef __HTTPS_DPM_UTIL_CGI_H
#define __HTTPS_DPM_UTIL_CGI_H

#include <stdio.h>
#include <syslog.h>
#include <sys/time.h>
#include <time.h>

FILE* cgiOut;                           /* file descriptor for CGI script output */
FILE* https_log;                        /* file descriptor for logging */
extern const char* https_log_name;
#define PRTBUFSZ 4096
#define PROCESS "DPM-HTTPS"


/* 
 * cgi utility functions
 */

void http_body_header(const char* header);           /* cgi header/body output */
void http_body_trailer();                            /* cgi body end */
char* get_query_option(const char* option, const char* query, const char seperator);          /* extract an option from a query string */

void return_cgi_error(int code, char* msg, ...);     /* return a full html page with an error message */
void return_cgi_success(int code, char* msg, ...);     /* return a full html page with an success message */
void cleanslash(char* path);                         /* clean all multiple slashes from path ( //data -> /data ) */

/* 
 * file logging functions
 */

void open_log();
void close_log();
void logit(const char* func, int syslog, int priority, char *msg, ...);

#endif
