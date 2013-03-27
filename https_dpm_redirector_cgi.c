/**********************************************************************
 * https_dpm_redirector_cgi.c
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
 

#include <https_dpm_redirector_cgi.h>

/********************************************************************** 
 * main program
 */
int main() {
  cgiOut = stdout; /* fd to output http */

  /* open the logging */
  open_log();

  /* Get the requested path */
  dpmpath    = get_query_option("path",0,'&');
  dpmse      = get_query_option("se",0,'&');
  dpmreplica = get_query_option("replica",0,'&');
  dpmguid    = get_query_option("guid",0,'&');
  dpmmetacmd = get_query_option("metacmd",0,'&');
  dpmfilename= get_query_option("filename",0,'&');
  dpmauthip  = get_query_option("authip",0,'&');

  if (dpmfilename) {
    char* newdpmpath=malloc(4096);
    sprintf(newdpmpath,"%s",dpmpath);
    dpmpath= newdpmpath;
    if ((*(dpmpath+strlen(dpmpath)-1)) =='/') {
      strcat(dpmpath,dpmfilename);
    } else {
      strcat(dpmpath,"/");
      strcat(dpmpath,dpmfilename);
    }
  }

  if (!strcmp(dpmpath,"/favicon.ico")) {
    // for the moment we don't have a favicon for the browser
    exit(0);
  }

  if (!dpmmetacmd) {
    dpmmetacmd=" ";
  }
  if (dpmpath) {
    logit("Info@dpm-redirector ", 0,0, "%s",getenv("QUERY_STRING"));
    logit("Info@dpm-redirector ", 0,0, "<request> metacmd=%s path=%s se=%s rep=%s guid=%s dn=\"%s\"",dpmmetacmd,dpmpath,dpmse,dpmreplica,dpmguid,getenv("SSL_CLIENT_S_DN"));
    
    /* do the user mapping and start a DPM session */
    init_dpm();
    if ((!strcmp(getenv("REQUEST_METHOD"),"GET")) || (!strcmp(getenv("REQUEST_METHOD"),"HEAD"))) {
      /* implementation of file download redirection & meta commands*/
      int nbentries;
      struct dpns_filestat statbuf;
      struct dpns_filereplica *rep_entries;
      char* hostend=0;
      const char* signed_signature; 

      dpmmetaopt = get_query_option("metaopt",0,'&');
      if (!dpmmetaopt) {
	dpmmetaopt="755";
      } else {
	/* we force always permission 7 to avoid permission traps */
	if ((dpmmetaopt[0] != '7') && (dpmmetaopt[0] != '6')) {
	  dpmmetaopt[0] = '6';
	}
      }
      
      /* check the meta commands here */
      if (!(strcmp(dpmmetacmd,"mkdir"))) {
	int lastslash=0;
	int replaceslash=1;
	/* create a directory, we always assume -p */
	/* descend the path */

	if (!dpns_access(dpmpath, F_OK)) {
	  return_cgi_success(serrno,"file/directory exists already, path=%s",dpmpath); 
	}
	for (i=1;i<strlen(dpmpath);i++) {
	  if (dpmpath[i]=='/' || (i==(strlen(dpmpath)-1))) {	
	    if ((i==(strlen(dpmpath)-1)) && (dpmpath[i]!='/'))
	      replaceslash=0;

	    if (replaceslash) {
	      dpmpath[i]=0;
	    }

	    /* check this directory */
	    if (!dpns_access(dpmpath, F_OK)) {
	      /* this exists already ... continue */
	      if (replaceslash)
		dpmpath[i]='/';
	      lastslash=i;
	      continue;
	    } else {
	      // check the parent permissions
	      dpmpath[lastslash]=0;
	      if (!dpns_access(dpmpath, W_OK)) {
		/* we write into the parent */
		dpmpath[lastslash]='/';
		lastslash=i;

		if (dpns_mkdir(dpmpath, (int)strtol(dpmmetaopt,0,8))) {
		  return_cgi_error(serrno,"cannot create directory path=%s %d",dpmpath,i);
		} 
		if (dpns_chown(dpmpath,uid,gid)) {
		  return_cgi_error(serrno,"cannot set appropriate permissions to directory path=%s %d",dpmpath,i);
		}
	      } else {
		return_cgi_error(serrno,"cannot create parent directory path=%s %d",dpmpath,i);
	      }
	    }
	    if (replaceslash)
	      dpmpath[i]='/';
	  }
	}
	return_cgi_success(serrno,"created successfully directory path=%s,%d",dpmpath,i); 
      }

      if (!(strcmp(dpmmetacmd,"getuid"))) {
	uid_t uid;
	char uidstr[1024];
	const char* dpmuid=0;
	dpmuid = get_query_option("dpmuid",0,'&');
	if (!dpmuid) {
	  return_cgi_error(serrno,"cannot return virtual user id mapping - dpmmetaopt not specified");
	}
	uid =  atoi(dpmuid);
	if ((dpns_getusrbyuid(uid,uidstr))!=0) {
	  return_cgi_error(serrno,"cannot execute getusrbyuid for id=%d",uid);
	} else {
	  http_table_2c("Virtual User ID","FQAN",uid,uidstr);
	  exit(0);
	}
      }
	
      if (!(strcmp(dpmmetacmd,"getgid"))) {
	gid_t gid;
	char gidstr[1024];
	const char* dpmgid=0;
	dpmgid = get_query_option("dpmgid",0,'&');
	if (!dpmgid) {
	  return_cgi_error(serrno,"cannot return virtual group id mapping - dpmmetaopt not specified");
	}
	gid =  atoi(dpmgid);
	if ((dpns_getgrpbygid(gid, gidstr))!=0) {
	  return_cgi_error(serrno,"cannot execute getgrpbygid for id=%d",gid);
	} else {
	  http_table_2c("Virtual Group ID","FQAN",gid,gidstr);
	  exit(0); 
	} 
      } 

      if ((!(strcmp(dpmmetacmd,"put"))) || (!(strcmp(dpmmetacmd,"post")))) {
	/* implementation of a put command */
	char r_token[CA_MAXDPMTOKENLEN+1];
	struct dpm_putfilereq putrequest;
	const char* protocols="https";
	struct dpm_putfilestatus* filestatuses; 
	char turl[CA_MAXSFNLEN+1];
	char fulldpmpath[4096];
	char u_token[256];
	sprintf(r_token,"initial fill");
	int nstatuses=0;
	int rc;
	int status;
	int nwait=0;
	const char* hostptr;

	putrequest.to_surl  = dpmpath;
	putrequest.lifetime = 0;
	putrequest.f_lifetime=0;
	putrequest.f_type=0;
	putrequest.s_token[0]=0;
	putrequest.ret_policy=0;
	putrequest.ac_latency=0;
	putrequest.requested_size=defaultputallocsize;
	
	sprintf(u_token,"https DPM put/post request");
	if ((rc=dpm_put(1,  &putrequest, 1, (char**) &protocols, u_token,  1,  0,  r_token,  &nstatuses,  &filestatuses))== -1) {
	  return_cgi_error(serrno,"the file put request failed in dpm_put for path=%s",dpmpath);
	} 
	dpm_free_pfilest(nstatuses,filestatuses);
	nstatuses=0;

      putreq_again:
	nwait++;
	usleep(200000);
	if ((rc=dpm_getstatus_putreq(r_token, 1, &dpmpath, &nstatuses, &filestatuses)<0)) {
	  if (serrno == EINVAL && nstatuses) {
	    if (filestatuses[0].errstring != NULL)
	      return_cgi_error(serrno,"error during dpm_getstatus_putreq for path=%s token=%s errormsg=%s",dpmpath,r_token,filestatuses[0].errstring);
	  }
	  return_cgi_error(serrno,"error during dpm_getstatus_putreq for path=%s token=%s",dpmpath,r_token);
	} else {
	  if (nstatuses) {
	    status = filestatuses[0].status;
	    if (status == DPM_READY && filestatuses[0].turl != NULL) {
	      if (strlen(filestatuses[0].turl)>CA_MAXSFNLEN) {
		return_cgi_error(serrno,"error during dpm_getstatus_putreq for path=%s token=%s errormsg=%s [ENAMTOOLONG]",dpmpath,r_token,filestatuses[0].errstring);
	      } else {
		strncpy(turl,filestatuses[0].turl,CA_MAXSFNLEN+1);
		turl[CA_MAXSFNLEN]='\0';
	      }
	    } else {
	      if (nwait > MAXPUTWAIT) {
		return_cgi_error(serrno,"dpm_put didn't get READY after %d retries for path=%s",nwait, dpmpath);
	      }
	      goto putreq_again;
	    }
	  } else {
	    return_cgi_error(rc,"dpm_getstatus_putreq didn't return anything for path=%s",dpmpath);
	  }
	}

	
	if (hostend = strstr(turl,"://")) {
	  hostend = strstr(hostend+3,"/");
	  hostptr = hostend+1;
	  hostend = strstr(hostptr,":/");
	} 

	if (hostend) {
	  *hostend=0;
	} else {
	  return_cgi_error(EINVAL,"received illegal turl=%s",turl);
	}

	if ((get_query_option("protocol",0,'&') && (!strcmp(get_query_option("protocol",0,'&'),"https")))) {
	  /* construct the redirection url http://<hostname>/<dpmpath> */
	  sprintf(redirectionurl,"https://%s",hostptr);
	  sprintf(redirectionurl+strlen(redirectionurl),":%d%s",redirectionhttpsport, hostend+1);
	} else {
	  /* construct the redirection url http://<hostname>/<dpmpath> */
	  sprintf(redirectionurl,"http://%s",hostptr);
	  sprintf(redirectionurl+7+(hostend-hostptr),":%d%s",redirectionhttpport, hostend+1);
	}
	/* construct a QUERY token/signature */

	if (!(strcmp(dpmmetacmd,"put"))) {
	  set_signature(dpmpath, "PUT", hostend+1,UPLOADTOKENLIFETIME,r_token);
	} else {
	  set_signature(dpmpath, "POST", hostend+1,UPLOADTOKENLIFETIME,r_token);
	}
	
	/* try to sign the token/signature */
	if (!(signed_signature = sign_signature())) {
	  logit("Info@dpm-redirector ",1,LOG_INFO,"couldn't create a signed signature");
	  return_cgi_error(EINVAL,"couldn't create a signed signature");
	}
	
	/* replace all spaces with '%20' in the signature after signing */
	for (i=0; i< strlen(signature); i++ ) {
	  if (signature[i] == ' ') {
	    memmove(signature+i+2,signature+i, strlen(signature)-i+1);
	    signature[i++]='%';
	  signature[i++]='2';
	  signature[i++]='0';
	  }
	}

	/* Check if cert subject is a Robot and replace the encode the colon (:) after the "Robot"*/
	char *subjectHasRobot;

	if (subjectHasRobot = strstr(signature, "Robot:")) {
		memmove(subjectHasRobot+strlen("Robot")+2, subjectHasRobot+strlen("Robot"), strlen(subjectHasRobot)-strlen("Robot")+1);
		memmove(subjectHasRobot+strlen("Robot"), "%3A", 3);
	}

	logit("Info@dpm-redirector ",0,0,"Creating Signature: %s",signature);
	logit("Info@dpm-redirector ",0,0,"Signed Signature: \n%s",signed_signature);
	
	/* append the token & signature to the redirection url as httpstoken & httpsauthz option */
	strcat(redirectionurl,"?httpstoken=");
	strcat(redirectionurl,signature);
	strcat(redirectionurl,"&httpsauthz=");
	strcat(redirectionurl,signed_signature);
	
	logit("Info@dpm-redirector ",1,LOG_INFO, "redirecting client \"%s\" for path \"%s\" to \"%s\"\n",getenv("SSL_CLIENT_S_DN"), dpmpath, redirectionurl);
	fprintf(cgiOut, "Content-type: text/html\r\n\r\n");
	http_body_header("DPM HTTPS UPLOAD");
	fprintf(cgiOut, "<form method=\"POST\" enctype='multipart/form-data' action=\"%s\"> Local File to upload ...\n",redirectionurl);
	fprintf(cgiOut,"        <input type=file name=upload>\n");
	fprintf(cgiOut,"	<input type=submit name=press value=\"UPLOAD\">");
	fprintf(cgiOut,"</form>\n");

	exit(0);
      }

      if (!(strcmp(dpmmetacmd,"putdone"))) {
	int nbreplies=0;
	struct dpm_filestatus* filestatuses;

	dpmfilesize = get_query_option("dpmfilesize",0,'&');
	dpmtoken    = get_query_option("dpmtoken",0,'&');

	if (!dpmtoken) {
	  return_cgi_error(EINVAL,"'putdone' requested but no token was present");
	}
	if (dpm_putdone((char*)dpmtoken, 1, &dpmpath,&nbreplies, &filestatuses)) {
	  return_cgi_error(serrno,"dpm_putdone failed for path=%s",dpmpath);
	}

	dpmmetacmd="stat";
      }
      
     
      /* check the access permissions */ 
      if (dpns_access(dpmpath, R_OK)) {
	if ((serrno == ENOENT) || (serrno == ENOTDIR)) {
	  return_cgi_error(serrno,"file or directory does not exist for path=%s",dpmpath);
	} 
	return_cgi_error(serrno,"you have no access permissions to path=%s",dpmpath);
      }

      /* let's see if this is a directory ... */
      if (dpns_stat (dpmpath, &statbuf)) {
	return_cgi_error(EINVAL,"couldn't stat the path=%s",dpmpath);
      } 

      if (!(strcmp(dpmmetacmd,"chmod"))) {
	if (dpns_access(dpmpath, W_OK)) {
	  return_cgi_error(serrno,"you have no access permissions modify permissions on path=%s",dpmpath);
	}
	if (dpns_chmod(dpmpath,(int)strtol(dpmmetaopt,0,8))) {
	  return_cgi_error(serrno,"couldn't modify the access permissions to %s on path=%s",dpmmetaopt,dpmpath);
	} else {
	  return_cgi_success(serrno,"modified successfully permissions on path=%s to mode=%s",dpmpath,dpmmetaopt); 
	}
      }

      if ((!(statbuf.filemode & S_IFDIR)) && (!(strcmp(dpmmetacmd,"ls")))) {
	dpmmetacmd="stat";
      }

      if ((statbuf.filemode & S_IFDIR) || (!(strcmp(dpmmetacmd,"stat")))) {
	/* check the meta command 'rmdir' here */	
	if (!(strcmp(dpmmetacmd,"rm"))) {
	  if ((strcmp(dpmmetacmd,"stat")) && dpns_access(dpmpath, W_OK)) {
	    return_cgi_error(serrno,"you have no access permissions to remove path=%s",dpmpath);
	  }
	  /* delete a directory, we never do it recursive */
	  if (dpns_rmdir(dpmpath)) {
	    return_cgi_error(serrno,"cannot remove the diretory path=%s",dpmpath);
	  } else {
	    return_cgi_success(serrno,"removed directory path=%s",dpmpath);
	  }
	}

	/* check if client is allowed browse that */
	if ((strcmp(dpmmetacmd,"stat")) && dpns_access(dpmpath, X_OK)) {
	  return_cgi_error(serrno,"you have no access permissions to browse path=%s",dpmpath);
	}

	if (!(strcmp(dpmmetacmd,"stat"))) {
	  return_browse_directory(dpmpath,1 );
	} else {
	  return_browse_directory(dpmpath,0 );
	}
      } else {
	int nbreplies;
	struct dpm_filestatus* filestatuses=0;
	if (!(strcmp(dpmmetacmd,"rm"))) {
	  if (dpns_access(dpmpath, W_OK)) {
	    return_cgi_error(serrno,"you have no access permissions to delete path=%s",dpmpath);
	  }

	  /* delete a directory, we never do it recursive */
	  if (dpm_rm(1,&dpmpath,&nbreplies,&filestatuses)) {
	    return_cgi_error(serrno,"cannot remove the file path=%s",dpmpath);
	  } else {
	    return_cgi_success(serrno,"removed file path=%s",dpmpath);
	  }
	}
      }

      /* get the replicas */
      if (dpns_getreplica(dpmpath, dpmguid,  dpmse, &nbentries, &rep_entries)) {
	return_cgi_error(EINVAL,"couldn't call getreplica for path=%s guid=%s se=%s",dpmpath,dpmguid,dpmse);
      }
      
      if (nbentries == 0) {
	/* no replicas found :-( */
	return_cgi_error(EINVAL,"no replica found for path=%s guid=%s se=%s",dpmpath,dpmguid,dpmse);    
      }
      
      if (dpmreplica) {
	/* set the requested replica */
	dpmrep=atoi(dpmreplica);
      }

      if (dpmrep <=nbentries) {
	/* clean all the double // from the replica sfns - otherwise we get into troubles during signature verification */ 
	char* doubleslash;
	while ( (doubleslash = strstr(rep_entries[dpmrep].sfn,"//")) ) {
	  logit("Info@dpm-redirector",0,0,"Memmove %s",rep_entries[dpmrep].sfn);
	  memmove(doubleslash, doubleslash+1, rep_entries[dpmrep].sfn + strlen(rep_entries[dpmrep].sfn) - doubleslash );
	}
		  
	/* pick the first or the specified replica if not existing replica was asked */
	hostend = strchr(rep_entries[dpmrep].sfn,':');
      } else {
	hostend = NULL;
      }
      if (!hostend) {
	return_cgi_error(EINVAL,"internal dpm error - didn't get a correct url from getreplica for replica #%d!",dpmrep);
      }

      logit("Info@dpm-redirector",0,0,"Protocol is %s ",get_query_option("protocol",0,'&'));
      if ((get_query_option("protocol",0,'&') && (!strcmp(get_query_option("protocol",0,'&'),"https")))) {
	/* construct the redirection url http://<hostname>/<dpmpath> */
	sprintf(redirectionurl,"https://%s",rep_entries[dpmrep].sfn);
	sprintf(redirectionurl+8+(hostend-rep_entries[dpmrep].sfn),":%d%s",redirectionhttpsport, hostend+1);
      } else {
	/* construct the redirection url http://<hostname>/<dpmpath> */
	sprintf(redirectionurl,"http://%s",rep_entries[dpmrep].sfn);
	sprintf(redirectionurl+7+(hostend-rep_entries[dpmrep].sfn),":%d%s",redirectionhttpport, hostend+1);
      }
	


      /* construct a QUERY token/signature */
      set_signature(dpmpath, "GET", hostend+1,TOKENLIFETIME,"no-token");
	  
      /* try to sign the token/signature */
      if (!(signed_signature = sign_signature())) {
 	logit("Info@dpm-redirector ",1,LOG_INFO,"couldn't create a signed signature");
 	return_cgi_error(EINVAL,"couldn't create a signed signature");
      }
    	
    	
      /* replace all spaces with '%20' in the signature after signing */
      for (i=0; i< strlen(signature); i++ ) {
		if (signature[i] == ' ') {
	  		memmove(signature+i+2,signature+i, strlen(signature)-i+1);
	  		signature[i++]='%';
	  		signature[i++]='2';
	  		signature[i++]='0';
		}
      }
      

      /* append the token & signature to the redirection url as httpstoken & httpsauthz option */
      strcat(redirectionurl,"?httpstoken=");
      strcat(redirectionurl,signature);
      strcat(redirectionurl,"&httpsauthz=");
      strcat(redirectionurl,signed_signature);
     
  
		logit("Info@dpm-redirector ",1,LOG_INFO, "redirecting client \"%s\" for path \"%s\" to \"%s\"\n",getenv("SSL_CLIENT_S_DN"), dpmpath, redirectionurl);
      /* return/print the CGI redirection */
      fprintf(cgiOut, "Location: %s\r\n\r\n", redirectionurl);
      
    } else {
      /* this is a delete or post */
      if (!strcmp(getenv("REQUEST_METHOD"),"DELETE")) {
	/* check the access permissions */
	if (dpns_access(dpmpath, W_OK)) {
	  if ((serrno == ENOENT) || (serrno == ENOTDIR)) {
	    return_cgi_error(serrno,"file or directory does not exist for path=%s",dpmpath);
	  } 
	  return_cgi_error(serrno,"you have no access permissions to path=%s",dpmpath);
	}

	struct dpm_filestatus* filestatuses=0;
	int nbreplies;
	
	if (dpm_rm(1, (char**)&dpmpath, &nbreplies, &filestatuses )) {
	  /* delete failed */
	  if (filestatuses) 
	    free(filestatuses);
	  return_cgi_error(serrno,"rm for path=%s failed!",dpmpath);
	} 
	
	/* delete went ok */
	if (filestatuses) 
	  free(filestatuses); 
	return_cgi_success(0,"rm for path=%s successful!",dpmpath);
      }  else {
	return_cgi_error(EINVAL,"this action is not implemented!");
      }
    }
    
    free((void*)dpmpath);
  } else {
    /* the path was not specified */
    logit("Error@dpm-redirector", 0,0, "<request> no path dn=\"%s\"",getenv("SSL_CLIENT_S_DN"));
    return_cgi_error(EINVAL,"the path has not been specified");
  }

  /* Finish up the page */
  http_body_trailer();
  
  /* close the logging */
  close_log();
  
  /* close evt. the dpm session */
  exit_dpm();
  
  return 0;
}


/**********************************************************************
 * browser function to provide HTML pages with directory information & http links
 * - partially copied from rfio code
 */ 

void return_browse_directory(const char* dirpath, int dostat) {
  dpns_DIR* dir;
  struct dpns_direnstat* direntstat;
  time_t current_time;
  char ftype[8];
  int ftype_v[7];
  char fmode[10];
  int fmode_v[9];
  char modestr[11];
  char owner[20];
  char t_creat[14];
  char pw[1024];
  char grp[1024];
  struct tm *t_tm;
  char uidstr[30];
  char gidstr[30];
  int recursively = 0;
  int multiple = 0;
  char tmpbuf[21];
  char documentref[4096];
  char documentbase[4096];
  char documentpref[4096];
  char uidtranslationref[4096];
  char gidtranslationref[4096];
  char* dpmids;
  const char* filename=0;

  strcpy(ftype,"pcdb-ls");
  ftype_v[0] = S_IFIFO; ftype_v[1] = S_IFCHR; ftype_v[2] = S_IFDIR; 
  ftype_v[3] = S_IFBLK; ftype_v[4] = S_IFREG; ftype_v[5] = S_IFLNK;
  ftype_v[6] = S_IFSOCK;
  strcpy(fmode,"rwxrwxrwx");
  fmode_v[0] = S_IRUSR; fmode_v[1] = S_IWUSR; fmode_v[2] = S_IXUSR;
  fmode_v[3] = S_IRGRP; fmode_v[4] = S_IWGRP; fmode_v[5] = S_IXGRP;
  fmode_v[6] = S_IROTH; fmode_v[7] = S_IWOTH; fmode_v[8] = S_IXOTH;

  if (1) {
    if (!dostat) {
      if (!(dir = dpns_opendir(dirpath))) {
	return_cgi_error(serrno,"cannot open directory %s",dirpath);
      } 
    }
    /* Send the content type, letting the browser know this is HTML */
    fprintf(cgiOut, "Content-type: text/html\r\n\r\n");
    http_body_header("DPM HTTPS BROWSER");
    if (!dostat) {
      fprintf(cgiOut,"<form method=\"GET\" enctype='multipart/form-data' action=\"%s\"> New File-/Dirname ...\n",dpmpath);
      fprintf(cgiOut,"        <input type=text name=filename>\n");
      fprintf(cgiOut,"	    <input type=submit name=metacmd value=\"post\">"); 
      fprintf(cgiOut,"	    <input type=submit name=metacmd value=\"mkdir\">"); 
      fprintf(cgiOut,"        <input type=submit name=metacmd value=\"rm\">");
      fprintf(cgiOut,"        <input type=submit name=metacmd value=\"chmod\">");
      fprintf(cgiOut,"        Mode <input type=text name=metaopt value=\"755\">");
      fprintf(cgiOut,"</form>\n");
    }
    fprintf(cgiOut,"<table widht=\"600\" align=\"left\" frame=\"box\" border=\"1\">\n");
    fprintf(cgiOut," <tr>\n");
    fprintf(cgiOut,"   <th> permissions </th>\n");
    fprintf(cgiOut,"   <th> nlinks </th>\n");
    fprintf(cgiOut,"   <th> owner </th>\n");
    fprintf(cgiOut,"   <th> group </th>\n");
    fprintf(cgiOut,"   <th> size        </th>\n");
    fprintf(cgiOut,"   <th> mtime       </th>\n");
    fprintf(cgiOut,"   <th> filename    </th>\n");
    fprintf(cgiOut,"  </tr>\n");
    
    sprintf(documentpref,"%s",dpmpath);
    
    
    if ((strcmp(dpmpath,"/")) && strlen(dpmpath)) {
      fprintf(cgiOut,"<tr><td></td><td></td><td></td><td></td><td></td><td></td><td><A href=\"%s\">[parent dir] .. </A></td></tr>\n",dirname(documentpref));
    }
    
    while ( dostat || (( direntstat = dpns_readdirx(dir)))) {
      filename = direntstat->d_name;

      if (!dostat) {
	sprintf(documentref,"%s/%s\n",dpmpath,direntstat->d_name);
	cleanslash(documentref);
      } else {
	sprintf(documentref,"%s",dpmpath);
	cleanslash(documentref);
	sprintf(documentbase,"%s",dpmpath);
	filename = (const char*)basename(documentbase);
      }

      if (dostat) {
	struct dpns_filestat statbuf;
	if (dpns_stat(dpmpath,&statbuf)) {
	  return_cgi_error(serrno,"cannot stat dpm path=%s",dpmpath);
	}
	direntstat = (struct dpns_direnstat*) malloc(sizeof(struct dpns_direnstat));
	/* copy the stat information */
	direntstat->fileid    =statbuf.fileid;
	direntstat->filemode  =statbuf.filemode;
	direntstat->nlink     =statbuf.nlink;
	direntstat->uid       =statbuf.uid;
	direntstat->gid       =statbuf.gid;
	direntstat->filesize  =statbuf.filesize;
	direntstat->atime     =statbuf.atime;
	direntstat->mtime     =statbuf.mtime;
	direntstat->ctime     =statbuf.ctime;
	direntstat->fileclass =statbuf.fileclass;
      }
      fprintf(cgiOut,"<tr>\n");
      strcpy(modestr,"----------");
      
      dpmids = get_query_option("dpmids",0,'&') ;
      if ( dpmids && (strcmp(dpmids,"plain"))) {
	sprintf(uidtranslationref,"<A href=\"%s?dpmmetacmd=getuid&dpmuid=%d\"%d</A>",dpmpath,direntstat->uid);
	sprintf(gidtranslationref,"<A href=\"%s?dpmmetacmd=getgid&dpmgid=%d\"%d</A>",dpmpath,direntstat->gid);
      } else { 
	char uidtranslationref1[1024];
	char gidtranslationref1[1024];
	sprintf(uidtranslationref1,"%d",direntstat->uid);
	sprintf(gidtranslationref1,"%d",direntstat->gid);
	sprintf(uidtranslationref,"%5s",uidtranslationref1);
	sprintf(gidtranslationref,"%5s",gidtranslationref1);
	if ( dpmids && (strcmp(dpmids,"full"))) {
	  dpns_getusrbyuid(direntstat->uid,uidtranslationref1);
	  dpns_getgrpbygid(direntstat->gid,gidtranslationref1);
	  sprintf(uidtranslationref,"\"%s\"",uidtranslationref1);
	  sprintf(gidtranslationref,"\"%-24s\"",gidtranslationref1);
	}
      }

      for (i=0; i<6; i++) if ( ftype_v[i] == ( S_IFMT & direntstat->filemode ) ) break;
      
      modestr[0] = ftype[i];
      for (i=0; i<9; i++) if (fmode_v[i] & direntstat->filemode) modestr[i+1] = fmode[i];
      if ( S_ISUID & direntstat->filemode ) modestr[3] = 's';
      if ( S_ISGID & direntstat->filemode ) modestr[6] = 's';

      t_tm = localtime(&(direntstat->mtime));
      if (direntstat->mtime < current_time - SIXMONTHS || direntstat->mtime > current_time + 60)
	strftime(t_creat,13,"%b %d  %Y",t_tm);
      else
	strftime(t_creat,13,"%b %d %H:%M",t_tm);
      
      fprintf(cgiOut,"<td>%s</td><td>%3d</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td>", modestr,direntstat->nlink, uidtranslationref,gidtranslationref,u64tostr((u_signed64)direntstat->filesize,tmpbuf,20),t_creat);
      fprintf(cgiOut,"<td><A href=\"%s\">%s</A></td>\n",documentref,filename);
      fprintf(cgiOut, "<td><form method=\"GET\" enctype='multipart/form-data' action=\"%s\">",dpmpath);
      if (modestr[0] != 'd') {
	fprintf(cgiOut,"	    <input type=submit name=metacmd value=\"post\">"); 
      } else {
	fprintf(cgiOut,"	    <input type=submit disabled='disabled' name=metacmd value=\"post\">"); 
      }
      fprintf(cgiOut,"      <input type=submit name=metacmd value=\"rm\">");
      fprintf(cgiOut,"      <input type=submit name=metacmd value=\"chmod\">");
      if (!dostat)
	fprintf(cgiOut,"      <input type=hidden name=filename value=\"%s\">",filename);
      if (!dostat) 
	fprintf(cgiOut,"      <input type=submit name=metacmd value=\"stat\">");
      fprintf(cgiOut,"Mode <input type=text name=metaopt size=4 value=\"%o\">",direntstat->filemode &0xfff);
      fprintf(cgiOut,"</form></td>\n");
      
      fprintf(cgiOut,"</tr>\n");
      if (dostat) {
	break;
      }
    }
    
    
      fprintf(cgiOut,"</table>\n");
      http_body_trailer();
  }
  
  if (!dostat)
    dpns_closedir(dir);
  
  
  
  exit_dpm();
  exit(0);
}


/**********************************************************************
 * dpm initialitzation
 * - map the client
 * - create a session
 */ 

int init_dpm() {
  struct passwd *dpm_pwd;
  struct hostent *hp;
  struct passwd *pw;
  char *username=0; 
  char *fqan[1];
  fqan[0] = NULL;
  char* vo=0;
  static char *mech = "GSI";
  static int nbfqans = 0;
  char dpmsession[1024];

  /* 'null' credentials */
  *(credentials.type)=0;
  credentials.notbefore=0;
  credentials.notafter=0;
  credentials.delegation=0;
  *(credentials.dn)=0;

	logit("Info@init_dpm",0,0, "parse of the credentials passed by gridsite: %s\n",getenv("GRST_CRED_0"));

  /* GridSite returns a sequence of signed DNs -> parse it */
  /* The environment contains f.e.: 
      $GRST_CRED_0 = "X509USER 1180599540 1212135540 1 /DC=ch/DC=cern/OU=Organic Units/OU=Users/CN=apeters/CN=482353/CN=Andreas Joachim Peters" */

  /* parse the gridsite credential */

  if ((sscanf(getenv("GRST_CRED_0"),"%s %ld %ld %d %4096c", credentials.type,&credentials.notbefore, &credentials.notafter,&credentials.delegation, credentials.dn)!=5)) {
    /* error parsing the DN ... */
    logit("Error@init_dpm",1,LOG_ERR, "cannot parse the credentials passed by gridsite: %s\n",getenv("GRST_CRED_0"));
    return -1;
  }

  *(vomscredentials.type) = 0;
  /* scan for the primary VOMS role */
  for (i=10 ; i>=0; i--) {
    char credname[1024];
    sprintf(credname,"GRST_CRED_%d",i);
    if (getenv(credname)) {
      gs_credentials_t parsedcredentials;
      if ((sscanf(getenv(credname),"%s %ld %ld %d %4096c", parsedcredentials.type,&parsedcredentials.notbefore, &parsedcredentials.notafter,&parsedcredentials.delegation, \
		  parsedcredentials.dn)!=5)) {
	/* error parsing the DN ... */
	logit("Error@init_dpm",1,LOG_ERR, "cannot parse the voms credentials passed by gridsite: %s\n",getenv(credname));
	return -1;
      }
      if (!strcmp(parsedcredentials.type,"VOMS")) {
	/* this is not a VOMS FQAN ... reset the voms structure */
	memcpy(&vomscredentials,&parsedcredentials,sizeof(gs_credentials_t));
      }
    }
  }

  if (credentials.dn[strlen(credentials.dn)-1] == '\n') {
    credentials.dn[strlen(credentials.dn)-1] = 0;
  }

  logit("Info@init_dpm",0,0, "User Credentials %s %ld %ld %d |%s|", credentials.type,credentials.notbefore,credentials.notafter,credentials.delegation,credentials.dn);
  if (*vomscredentials.type) {
    logit("Info@init_dpm",0,0, "VOMS Credentials %s %ld %ld %d |%s|", vomscredentials.type,vomscredentials.notbefore,vomscredentials.notafter,vomscredentials.delegation,vomscredentials.dn);
    if (vomscredentials.dn[strlen(vomscredentials.dn)-1] == '\n') {
      vomscredentials.dn[strlen(vomscredentials.dn)-1] = 0;
    }
  }


  dpm_pwd = getpwnam("dpmmgr");

  if (!dpm_pwd) {
    logit("Error@init_dpm",1,LOG_ERR, "dpmmgr account is not defined in passwd file\n");
    return -1;
  } 

  /* set the local machine as DPNS host by default if DPNS_HOST is not specified */
  if ((!getenv("DPNS_HOST")) || (!strlen(getenv("DPNS_HOST")))) {
    if (!gethostname(hostname, sizeof(hostname))) {
      setenv("DPNS_HOST",hostname,1);
    } else {
      return_cgi_error(ENOTCONN,"Server misconfiguration - cannot get the hostname\n");
    }
  }

  { /* get the FQDN */
    struct hostent *he;
    struct in_addr a;
    he = gethostbyname (hostname);
    if (he) {
      strcpy(fqdn,he->h_name);
    } else {
      return_cgi_error(ENOTCONN,"Server misconfiguration - cannot get the FQDN of this redirector\n");
    }
  }

  sprintf(dpmsession,"HTTPSDPMREDIRECTOR:%d@%s",getpid(),hostname);

  /* set CSEC_MEC=ID */
  setenv("CSEC_MECH","ID",1);

  if (*vomscredentials.type) {
    char* voptr=0;
    fqan[0] = vomscredentials.dn;
    nbfqans = 1;
    if (fqan[0]) {
      /* get the vo tag from the fqan ... fqan:/<vo>/.... */
      vo=strdup(fqan[0]);
      if ((voptr = strchr(vo+1,'/'))) {
	vo++;
	*voptr=0;
      }
    }
  }

  if (dpns_getidmap (credentials.dn, nbfqans > 1 ? 1 : nbfqans, (const char **)fqan, &uid, &gid)) {
    logit("Error@init_dpm",LOG_INFO,1, "No virtual ID mapping for \"%s\"",credentials.dn);
    return_cgi_error(EPERM,"No virtual ID mapping for \"%s\"\n",credentials.dn);
  }

  if (uid) {
    dpns_client_setAuthorizationId (uid, gid, mech , (char*) credentials.dn);
    dpm_client_setAuthorizationId  (uid, gid, mech , (char*) credentials.dn);
    if (vo && fqan[0]) {
      dpns_client_setVOMS_data(vo,fqan, 1);
      dpm_client_setVOMS_data(vo,fqan,1);
    }
    logit("Info@init_dpm",0,0, "setting authorized id for \"%s\" to %d/%d [%d]",credentials.dn,uid,gid,nbfqans);
  }

  if (dpns_startsess((char *)getenv("DPNS_HOST"),dpmsession)) {
    return_cgi_error(ENOTCONN,"cannot establish session with dpm namserver [%s]\n",getenv("DPNS_HOST"));
  }

  dpmSessionActive=1;
  return 0;
}

/**********************************************************************
 * close dpm session
 */ 

void exit_dpm() {
  /* close dpns session */
  if (dpmSessionActive) {
    dpns_endsess();
  }
}

char* replace_colon(const char* cert_subject) {

        char *sanitized_subject;

        sanitized_subject = (char *)malloc(2048);
        strcpy(sanitized_subject, cert_subject);
        logit("Info@replace_colon",0,0, "subject length |%d|",strlen(cert_subject));
        for (i=0; i< strlen(cert_subject); i++ ) {
          if (cert_subject[i] == ':') {
            memmove(sanitized_subject+i+2,cert_subject+i, strlen(cert_subject)-i+1);
            sanitized_subject[i++]='%';
            sanitized_subject[i++]='3';
            sanitized_subject[i++]='A';
          }
        }
        logit("Info@replace_colon",0,0, "cert_subject |%s|", cert_subject);
        logit("Info@replace_colon",0,0, "sanitized_subject |%s|", sanitized_subject);
        return sanitized_subject;
}




/**********************************************************************
 * create the token/signature to be signed
 */ 

void set_signature(const char* path, const char* method, const char* sfn, time_t lifetime, const char* rtoken) {
  /* add a signature to this request */
  /* signatures are made as <path>@<client-ip>:<sfn>:<key-hash>:<expirationtime>:<client-id>:<redirector-host>:<rtoken> */
  strcpy(signature,path);
  strcat(signature,"@");
  if (dpmauthip) 
  	strcat(signature, dpmauthip);
   //	logit("Info@set_signature",0,0, "signature |%s|, dpmauthip |%s|",signature, dpmauthip);
   else 
  	strcat(signature,getenv("REMOTE_ADDR"));
  //	logit("Info@set_signature",0,0, "signature |%s|, REMOTE_ADDR |%s|",signature, getenv("REMOTE_ADDR"));
  strcat(signature,":");
  strcat(signature,method);
  strcat(signature,":");
  strcat(signature,sfn);
  strcat(signature,":");
  strcat(signature,keyhash);
  strcat(signature,":");
  sprintf(signature+strlen(signature), "%010u", time(NULL) + lifetime);
  strcat(signature,":");
  strcat(signature,getenv("SSL_CLIENT_S_DN"));
  strcat(signature,":");
  strcat(signature,fqdn);
  strcat(signature,":");
  strcat(signature,rtoken);
}

/**********************************************************************
 * sign a token with a private key
 */ 

const char* sign_signature() {
  int err;
  int sig_len;
  int cnt=0;
  unsigned char sig_buf [4096];
  static char certfile[] = "/opt/lcg/etc/dpm/https/keystore/cert.pem";
  static char keyfile[]  = "/opt/lcg/etc/dpm/https/keystore/key.pem";
  EVP_MD_CTX     md_ctx;
  EVP_PKEY *      pkey;
  FILE *          fp;
  X509 *        x509;
  int ub64len; 
  BIO *bmem, *b64;
  BUF_MEM *bptr;

  ERR_load_crypto_strings();

  /* Read private key */ 
  fp = fopen (keyfile, "r");
  if (fp == NULL) 
    return 0;

  pkey = PEM_read_PrivateKey(fp, NULL, NULL,NULL);
  fclose (fp);
  
  if (pkey == NULL) { 
    ERR_print_errors_fp (stderr);
    return 0;
  }

  /* use the envelope api to create an encode the hash value */
  EVP_SignInit   (&md_ctx, EVP_sha1());
  EVP_SignUpdate (&md_ctx, signature, strlen(signature));
  sig_len = sizeof(sig_buf);
  err = EVP_SignFinal (&md_ctx, sig_buf, &sig_len, pkey);

  /* base64 encode */
  b64 = BIO_new(BIO_f_base64());
  bmem = BIO_new(BIO_s_mem());
  b64 = BIO_push(b64, bmem);
  BIO_write(b64, sig_buf,sig_len);
  BIO_flush(b64);
  BIO_get_mem_ptr(b64, &bptr);
  
  char *buff = (char *)malloc(bptr->length);
  memcpy(buff, bptr->data, bptr->length-1);
  buff[bptr->length-1] = 0;

  /* remove the backslash from the signature buffer */
  for (i=0; i<=(bptr->length-1); i++) {
    if (buff[i] != '\n') {
      signed_signature_buff[cnt] = buff[i];
      cnt++;
    }
  }

  BIO_free_all(b64);
 
  return signed_signature_buff;
}
