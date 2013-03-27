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

#include "https_dpm_util_cgi.h"
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <stdarg.h>

const char* https_log_name = "/var/log/dpm-httpd/cgilog"; /* default log file name */

/**********************************************************************
 * print a cgi header/body
 */ 
void http_body_header(const char* header)
{
  /* Top of the page */
  fprintf(cgiOut, "<HTML><HEAD>\n");
  fprintf(cgiOut, "<TITLE>%s</TITLE></HEAD>\n",header);
  fprintf(cgiOut, "<BODY><H1>%s</H1>\n",header);
  fprintf(cgiOut,"<hr><A><img src=\"http://www.cern.ch/CommonImages/Logos/CERN36.gif\" alt=\"CERN 2007\" align=\"top\" border=\"0\"> Author: Andreas.Joachim.Peters@cern.ch 2007 - IT-GD</A><hr>");
}

/**********************************************************************
 * print a cgi body trailer
 */ 
void http_body_trailer() 
{
  /* Finish up the page */
  fprintf(cgiOut, "</BODY></HTML>\n");
}

void http_table_2c(const char* label1, const char* label2, int val1, const char* val2) {
  fprintf(cgiOut, "Content-type: text/html\r\n\r\n");
  http_body_header("DPM HTTPS BROWSER");
  fprintf(cgiOut,"<table widht=\"600\" align=\"left\" frame=\"box\" border=\"1\">\n");
  fprintf(cgiOut," <tr>\n");
  fprintf(cgiOut,"   <th>%s</th>\n",label1);
  fprintf(cgiOut,"   <th>%s</th>\n",label2);
  fprintf(cgiOut,"  </tr>\n");
  fprintf(cgiOut,"<tr><td>%d</td><td>%s</td></tr>\n",val1,val2);
  fprintf(cgiOut,"</table>\n");
  http_body_trailer();
}



/**********************************************************************
 * extract an option from a query string
 * f.e. URI= ....?path=xyz&.... -> extract path value
 */ 
char* get_query_option(const char* option,const char* query,const char separator ) {
  const char* optionstart  ;
  const char* optionend ;
  char* parsedoption = 0;
  int parsedoptionsize=0;
  int offset =0;

  /* check parameters */
  if (!option) 
    return 0;
  if ((!query) && (!getenv("QUERY_STRING")))
    return 0;

  if (!query)
    query=getenv("QUERY_STRING");

  /* start the parsing of the query string */
  if ( (optionstart = strstr(query,option) ) ) {
    /* look for the '=' */
    optionstart += (strlen(option));
    if ( (*(optionstart)) == '=') {
      optionstart++;
      /* return until the next 'separator' or the end of the string */
      if (! (optionend = strchr(optionstart,separator))) {
	optionend = query;
	optionend +=strlen(query);
      }

      parsedoptionsize = (optionend-optionstart+1);
      
      if ( (parsedoptionsize <=0) || (parsedoptionsize > 4096 ) ) {
	return 0;
      }
      parsedoption = (char*) malloc(optionend-optionstart+2);
      memset(parsedoption,0,optionend-optionstart+2);
      if (!parsedoption) {
	return 0;
      }
      /* add the heading / to the path */
      
      if (!strcmp(option,"path")) {
	*parsedoption='/';
	offset=1;
      }
      if (!strncpy(parsedoption+offset,optionstart, (optionend-optionstart) )) {
	free(parsedoption);
	return 0;
      } else {
	return parsedoption;
      }	
    }
  } 
  return 0;
}

/**********************************************************************
 * clean all multiple slashes from path ( //data -> /data )
 */ 

void cleanslash(char* path) {
  int l;
  char* ptr    = path;
  char* endptr = path+strlen(path);
  for (;;) {
    if (ptr < (endptr-2)) {
      if ( (*ptr == '/') && (*(ptr+1) == '/') ) {
	memmove(ptr, ptr+1, (endptr-ptr-1));
      }
      ptr++;
    } else {
      break;
    }
    if ( (*ptr) == 0) 
      break;
  }
}

/**********************************************************************
 * return a full html page with an error code + message 
 */ 

void return_cgi_success(int code, char *msg, ...) {
  char prtbuf[PRTBUFSZ];
  va_list args;
  va_start (args, msg);

  /* Send the content type, letting the browser know this is HTML */
  fprintf(cgiOut, "Content-type: text/html\r\n\r\n");  
  http_body_header("DPM HTTPS REDIRECTOR");

  vsprintf (prtbuf, msg, args);
  fprintf(cgiOut,"HTTPS-DPM-REDIRECTOR-CGI SUCCESS: code=%d msg=\"%s\"<br>\n",code, prtbuf);
  va_end (args);

  /* close the HTML page and return */
  http_body_trailer();

  exit(0);
}

/**********************************************************************
 * return a full html page with an error code + message 
 */ 

void return_cgi_error(int code, char *msg, ...) {
  char prtbuf[PRTBUFSZ];
  va_list args;
  va_start (args, msg);

  /* Send the content type, letting the browser know this is HTML */
  fprintf(cgiOut, "Content-type: text/html\r\n\r\n");  
  http_body_header("DPM HTTPS REDIRECTOR");

  vsprintf (prtbuf, msg, args);
  fprintf(cgiOut,"HTTPS-DPM-REDIRECTOR-CGI ERROR: code=%d msg=\"%s\"<br>\n",code, prtbuf);
  va_end (args);

  /* close the HTML page and return */
  http_body_trailer();

  exit(0);
}

/**********************************************************************
 * open log file (syslog + /var/log/dpm-http/cgilog)
 * - if /var/log/dpm-http is not accessible default to /tmp/dpm-cgilog
 */ 

void open_log(){
  char *ident  = PROCESS;
  int logopt   = LOG_PID; 
  int facility = LOG_USER;

  /* open syslog */
  openlog(ident,logopt,facility);
  
  /* open default log file */
  https_log = fopen (https_log_name,"a+");
  if (!https_log) {
    https_log = fopen ("/tmp/dpm-cgilog","a+");
  }
}

/**********************************************************************
 * close default & syslog
 */ 

void close_log() {
  if (https_log) {
    fclose(https_log);
  }
  closelog();
}

/**********************************************************************
 * write a log message to default (depending on priority also to syslog)
 */

void logit(const char* func, int tosyslog, int priority, char *msg, ...) {
  va_list args;
  char prtbuf[PRTBUFSZ];
  int save_errno;
  struct tm *tm;
  char *msgptr;
  time_t current_time;
      
  save_errno = errno;
  va_start (args, msg);
  time (&current_time);
  tm = localtime (&current_time);
  sprintf (prtbuf, "%02d/%02d %02d:%02d:%02d (%d) %s: [%s] [%s@%s/%s] ", tm->tm_mon+1,
	   tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec, getpid(), func, getenv("REQUEST_METHOD"), getenv("REMOTE_USER"),getenv("REMOTE_HOST"),getenv("REMOTE_ADDR"));
  msgptr = prtbuf+strlen(prtbuf);
  vsprintf (msgptr, msg, args);

  /* log to syslog if required */
  if (tosyslog) {
    //syslog(priority,msgptr);
  }

  va_end (args);

  if (https_log) {
    fputs(prtbuf, https_log);
    fputs("\n",https_log);
    /* flush the log */
    fflush(https_log);
  }

  errno = save_errno;
  return ;
}
