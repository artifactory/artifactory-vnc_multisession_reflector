/* zrefl.c */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <netinet/in.h>
//#include <linux/if.h>
//#include <linux/sockios.h>
#include <net/if.h>
#include <sys/sockio.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <ctype.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "zrefl.h"

#define SENDMSG_ARCH 1



#define ZREFL_LOG "zrefl.log"

#define REFL_VERSION "$Revision: 1.29 $"

#define ZDSPROXY_APP "ZDsProxy"



static pid_t  pid = -1;
static int  fdSession;
struct _stSession *g_pSessions;
int volatile g_iSessionsActive = 0;

#define Z_RESPONSE_OK  "HTTP/1.1\r\n200 OK\r\n\r\n200"
#define Z_RESPONSE_NAK "HTTP/1.1\r\n"
#define RFB_VERSION_STR "RFB 003.003\n"
#define Z_POST_LAUNCH_DSPORT_URL "GET xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
#define Z_SESSION_TERMINATE_URL "GET xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
#define CERTFILE "./zmeeting.com.cert"
#define KEYFILE "./zmeeting.com.key"
#define SW_SZ_DEVREG_URL "GET xxxxxxxxxxxxxxxxxxxxxxxxx"
#define SW_DEVICELOGIN_URI "GET xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
#define SW_DEVICELOGOUT_URI  "GET xxxxxxxxxxxxxxxxxxxxxxxxxxx"
#define SW_SSL_TAG "SSL/3.1\nUser-Agent: Mozilla/4.0 (compatible; MSIE 5.5; Windows NT 5.0; Znet)3.7.2\n\n"
#define SW_USERLOGIN_URI "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
#define SW_HEARTBEAT_URL "GET xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
#define SW_HTTP_TAG "HTTP/1.0\nUser-Agent: Mozilla/4.0 (compatible; MSIE 5.5; Windows NT 5.0; Znet)3.7.2\n\n"
#define Z_DS_OP_HOST 1
#define Z_DS_OP_CLIENT 2
#define Z_DS_OP_STATUS 3
#define Z_DS_OP_INVALID 0
#define Z_DEFAULT_CLIENT_THRESHOLD 1
int logwrite(char *szString);
int logwritei(char *szString, int i);
int logwritei2(char *szString, int i, int j);
int logwrite2(char *szString, char *szTring2);
void connThreadHandler(void *arg);
void  msgThreadHandler(void *arg);
#ifdef SENDMSG_ARCH
int send_fd(int msgfd, int *fd);
/*int launchSession(int iSessionSID, int iHostSock);*/
#endif
int launchSession(int  iSessionSID, int iPort);
struct _stSession *psGetSession(int iID);
struct _stSession *psGetSessionByPID(int pid);
int piGetSessionSockets(int *piSocks, int iSessionSID);
int addHostEntry(int iSessionNum, char *szHostIP, int iSock, int iSessionSID, int iHostSID, char *szPassword/*, int  **ppiClientsInvited*/);
int addClientEntry(int iSock, char *szIP, int iSessionSID, int iClientSID);
struct _stSession *updateHostEntry(int iSessionSID, int pid);
int updateHostPort(int iSessionSID, int s_iSessionPort);
int notifySessionTerminate(int pid);
int removeHostEntry(int pid);
static void sigHandler(int);
void logSessionTable();
int parseRequest(char *buf, int bytes, int *piOperation, int *piUserSID, int *piSessionSID, char *szPassword);
int ackRequest(int sock, bool bUseSSL, SSL *ssl);
int nakRequest(int sock, char *szErr, bool bUseSSL, SSL *ssl);
int iLaunchCondition(int iSessionSID);
int sendRFB(int sock);
int callBroker(char *szURI, bool bUseSSL);
int getZSettings();
int getSessionPort();
void sslInit();
SSL_CTX *sslServerInit();
int sslClientOnetimeRequest(int sock, char *URL, char *buf, int icount);
int sslRead(SSL *ssl, char *buf, int icount);
int heartbeatThread(unsigned long );
int deviceLogin();
int GetIP(char *pBuffer);
char *GetMACAddr(char *addr);
int RegisterDevice(char *sz_alias, char *sz_pw, int iIterate);
char *CreateDeviceUID();
int deviceLogout();
int updateConfig(char *buf, int bytes);

static int s_iThreshold = Z_DEFAULT_CLIENT_THRESHOLD;
static char s_szbroker_ip[32];
static int s_ibroker_port;
static int s_ibrokerSID;
static int s_idomainSID;
static int s_ivendorSID;
static char s_szDeviceSID[12];
static char s_szDeviceUID[64];
static char s_szUserSID[12];
static char s_szUserUID[64];
static int s_iPort;
static char s_szDeviceIP[14];
static int s_iZport;
static char s_szAltports[32];
static char s_szDeviceKey[2048];
static char s_szMAC[32];
static int s_iHeartbeat;
static pthread_mutex_t loglock = PTHREAD_MUTEX_INITIALIZER;
static char s_retBuf[4096]; /* making static to access return data - kludge */

#define MAX_HOST_PORTS 4

/*
  main
*/

int main(int argc, char **argv)
{
  int zero = 0;
  int i, iNumHostPorts;
  char *szHostPort[MAX_HOST_PORTS];
  char ZHOSTPORTSTR[] = "80";
  char buf[1024];


  char *ptr;
  pthread_t connThreadID, msgThreadID;
  struct sigaction heartbeatAction;

  logwrite("\nNew session ======================================================================\nCreating session table!!");
  s_iThreshold = Z_DEFAULT_CLIENT_THRESHOLD;
  szHostPort[0] = ZHOSTPORTSTR;
  if(argc > 1) {
    iNumHostPorts = 0;
    for(i = 1; i < argc; i++) {
      ptr = argv[i];
      if(*ptr == '-') {
	if(*++ptr == 't')
	  s_iThreshold = atoi(++ptr);
	else if(*ptr == 'p') {
	  if(iNumHostPorts < MAX_HOST_PORTS)
	    szHostPort[iNumHostPorts++] = (char *)++ptr;
	  else
	    logwrite2("MAX_NUM_PORTS exceeded: won't listen on ", ++ptr);
	}
      }
    }
  }
  /* init */
  sslInit();

  if(getZSettings() < 0)
    printf("zSettings not OK; wax.ini link present?\nexiting\n");

  printf("zrefl %s\nlaunching with client threshold %d", REFL_VERSION, s_iThreshold);

  if(signal(SIGUSR1, sigHandler) == SIG_ERR)
    logwrite("can't catch SIGUSR1");
  if(signal(SIGUSR2, sigHandler) == SIG_ERR)
    logwrite("can't catch SIGUSR2");
  if(signal(SIGCHLD, sigHandler) == SIG_ERR)
    logwrite("can't catch SIGCHLD");
  if(signal(SIGTERM, sigHandler) == SIG_ERR)
    logwrite("can't catch SIGTERM");





  /* log in device so Broker knows it is online */
  deviceLogin();
 /* set up heartbeat */
  bzero(&heartbeatAction, sizeof(heartbeatAction));
  heartbeatAction.sa_handler = heartbeatThread;
  heartbeatAction.sa_flags = SA_RESTART;
  if(sigaction(SIGALRM, &heartbeatAction, 0) != 0)
    logwrite("Cannot set heartbeat alarm");
  else
    alarm(s_iHeartbeat);
  logwrite("\nCreating session table:");

  fdSession = open("ZSessionTable.dat", O_RDWR | O_CREAT | O_TRUNC, \
		     S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
  for(i=0; i <  (sizeof(struct _stSession)/sizeof(int)) * MAX_SESSION_NUM; i++)
    write(fdSession, &zero, sizeof(int));
  g_pSessions = (struct _stSession *) mmap(NULL, sizeof(struct _stSession) * MAX_SESSION_NUM, \
					   PROT_READ | PROT_WRITE, MAP_SHARED, fdSession, 0);
  logwritei("mmap: ", errno);
  errno = 0;
  g_pSessions->next = NULL;
  g_pSessions->prev = NULL; /* marker for treetop */
  for(i = 0; i < MAX_SESSION_NUM; i++)
    (g_pSessions+i)->iMsgSock = -1;
  logwritei2("SessionTable allocated: fd/addr", fdSession, (int *)g_pSessions);
  logwrite("==================================================================================\n");


  for(i = 0; i < iNumHostPorts; i++)
    pthread_create( &connThreadID, NULL, (void*)&connThreadHandler, szHostPort[i]);
  pthread_create( &msgThreadID, NULL, (void*)&msgThreadHandler, NULL);
  while(1)
    ; /* wait til they die: signal catch */
  return 0;

}

static int aiSessionPortUse[MAX_SESSION_NUM];
/* array of "in-use" flags for post-launch dsproxy listening ports.
they start at ZPROXYPORT and invrement from there, but we want to reuse released ones.
*/

int getSessionPort() {
  int i;
  for(i = 0; i < MAX_SESSION_NUM; i++) {
    if(!aiSessionPortUse[i]) {
      aiSessionPortUse[i] = 1;
      return ZPROXYPORT + i;
    }
  }
  return -1;
}
void releaseSessionPort(int iSessionPort) {
  /* check valid */
  if(iSessionPort - ZPROXYPORT >= 0)
    /* reset flag to mark as avail */
    aiSessionPortUse[iSessionPort - ZPROXYPORT] = 0;
}


/*~
  connThreadHandler
~*/


void connThreadHandler(void *arg)
{
  int len;
  int listen_fd;
  int i_sock;


  int optval = 1;
  int iret;
  int iSessionNum = 0;
  int iUserSID =  0;
  int iSessionSID = 0;
  int iOp;
  int bytes;
  int s_iSessionPort;
  int iHostPort = atoi((char *)arg);




  char *szIP;
  char buf[512];
  char szPassword[32];
  struct sockaddr_in client_addr;
  struct sockaddr_in listen_addr;
  struct in_addr s_bind_address;
  struct _stSession *pSession;

  SSL_CTX *ctx;
  SSL *ssl;

  bool bListening;
  bool bUseSSL = false;

  if(iHostPort == 443) {
    bUseSSL = true;
    ctx = sslServerInit();
  }


  pSession = NULL;
  bListening = true;

  szPassword[0] = '\0';
  printf("connThreadHandler\n");
  printf("\tZmsgport: %d\n", iHostPort);
  errno = 0;

  listen_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (listen_fd < 0){
      printf("Can't get socket, exiting\n");
      return;
  }

  if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR,
                 &optval, sizeof(int)) != 0) {
    printf("setsockopt fail\n");
    close(listen_fd);
    return;
  }

  s_bind_address.s_addr = htonl(INADDR_ANY);
  listen_addr.sin_family = AF_INET;
  listen_addr.sin_addr.s_addr = s_bind_address.s_addr;
  listen_addr.sin_port = htons((unsigned short)iHostPort);

  if ( bind(listen_fd, (struct sockaddr *)&listen_addr, sizeof(listen_addr)) != 0
       || listen(listen_fd, 5) != 0 ) {
      printf("connThreadHandler: can't bind to %d\n", iHostPort);
      logwritei("connThreadHandler: can't bind to ", iHostPort);
      close(listen_fd);
      return;
  }

  len = sizeof(client_addr);
  while(bListening) {
    printf("listening on %d\n", iHostPort); logwritei("listening on", iHostPort);
    memset(buf, 0, sizeof(buf));
    i_sock =  accept(listen_fd, (struct sockaddr *) &client_addr, (socklen_t *)&len);
    if (i_sock < 0) {
      logwritei("accept gets bad return: closed connection?", i_sock);
    }
    else{
      logwrite2("\n===>accepted connection from", szIP = inet_ntoa(client_addr.sin_addr));
      logwritei("\taccepted on port:", iHostPort);
      logwritei("\t===>socket:", i_sock);
    }

    if(bUseSSL) {
      ssl = SSL_new(ctx);  /* create new SSL connection state */

      SSL_set_fd(ssl, i_sock); /* attach the socket descriptor */
      if((iret = SSL_accept(ssl)) <= 0) {
	logwritei("!!! ssl accept fail with SSL error:", SSL_get_error(ssl, iret));
	bytes = -1;
      }
      else {
	if((bytes = SSL_read(ssl, buf, sizeof(buf))) == -1) { /* read a few more than valid max */
	  logwrite("SSL_read gets -1:");
	  close(i_sock);
	  continue;
	}
      }
    }
    else {
      if((bytes = read(i_sock, buf, sizeof(buf))) == -1) { /* read a few more than valid max */
	logwrite("read gets -1:");
	close(i_sock);
	continue;
      }
    }


    /*logwrite2("read from socket:", pbuf = buf);
      logwritei("\n\tsocket: ", i_sock);*/
    if((iret = parseRequest(buf, bytes, &iOp, &iUserSID, &iSessionSID, szPassword)))	{
      logwritei("parseRequest error:", iret);
      nakRequest(i_sock, BAD_REQUEST, bUseSSL, ssl);
      close(i_sock);
      continue;
    }

    printf("pre_thread: host sock: %d; host: %s; sessionNum: %d\n", i_sock, szIP, iSessionNum);

    switch(iOp) {
    case  Z_DS_OP_HOST:
      ackRequest(i_sock, bUseSSL, ssl);
      ++iSessionNum;
      addHostEntry(iSessionNum, szIP, i_sock, iSessionSID, iUserSID, szPassword/*, int  **ppiClientsInvited*/);
#ifdef SENDMSG_ARCH
      /*launchSession(iSessionSID, i_sock);*/
#endif
      break;
    case  Z_DS_OP_CLIENT:
      if(!(pSession = psGetSession(iSessionSID))) {
	logwritei("client attempting to join session not found:", iSessionSID);
	nakRequest(i_sock, DSSESSION_NOT_FOUND, bUseSSL, ssl);
	close(i_sock);
	continue;
      }
      /*ackRequest(i_sock);*/ /* wait til we see if the session is launched before we ack -
				 special case if two joins come before broker gets launch ack */

      logwritei("\nincoming client for session: ", pSession->iSessionSID);
      logwrite2("\tclient ip", szIP);
      logwritei("\tsock", i_sock);
      logwritei("\thostSID", pSession->iHostSID);
      addClientEntry(i_sock, szIP, iSessionSID, iUserSID);

      if(iLaunchCondition(iSessionSID) == 1) {
	ackRequest(i_sock, bUseSSL, ssl);
	s_iSessionPort = getSessionPort();
#ifndef SENDMSG_ARCH
	updateHostPort(iSessionSID, s_iSessionPort);
#endif
	launchSession(iSessionSID, s_iSessionPort);
	/*++s_iSessionPort;*/
	/* close socks here ? */
      }
      else if(iLaunchCondition(iSessionSID) == -1) {
	/* -1 means already launched */
#ifdef SENDMSG_ARCH
	ackRequest(i_sock, bUseSSL, ssl); /* since we are currently taking all reqs as manager reqs, we need to ack */
	/* send_fd method: signal process of new sock for it; doesn't work in windows */
	logwritei("client requesting to join session already launched:", iSessionSID);
	logwritei("signaling PID:",  pSession->PID);
	logwritei("  at msgfd: ",  pSession->iMsgSock);
	send_fd(pSession->iMsgSock, &i_sock);
	sleep(1);
	kill(pSession->PID, SIGUSR1);

#else
	/* in the non-SENDMSG_ARCH, we cannot signal the process, so we nak the joiner; they need to use the post-launch port to join */
	logwritei("client attempting to join session already launched:", iSessionSID);
	nakRequest(i_sock, DSSESSION_ALREADY_LAUNCHED, bUseSSL, ssl);
	close(i_sock);
#endif
	continue;
      }
      else if(iLaunchCondition(iSessionSID) == -2) {
	/* this should have been caught above - shouldn't get here */
	logwritei("!!!client attempting to join session not found:", iSessionSID);
	nakRequest(i_sock, DSSESSION_NOT_FOUND, bUseSSL, ssl);
	close(i_sock);
	continue;
      }
      else
	ackRequest(i_sock, bUseSSL, ssl);


      break;
    case  Z_DS_OP_STATUS:
      ackRequest(i_sock, bUseSSL, ssl);
      close(i_sock);
      break;
    default:
      nakRequest(i_sock, BAD_REQUEST, bUseSSL, ssl);
      break;
    }
  }
}


int iLaunchCondition(int iSessionSID)
     /* return: 1 if ready to launch
	        -1 if already launched (threshold exceeds numClients
		-2 if not found - should have been found above before this call but is here for safety
		0 if not ready to launch (threshold below numClients
     */
{

    struct _stSession *pSession = NULL;

    if(!(pSession = psGetSession(iSessionSID))) {
      logwritei("!!!bLaunchCondition gets no session for sessionSID ", iSessionSID);
      /* note: this should have been caught above, before this call */
      return -2;
    }

    logwritei("bLaunchCondition: numClients ", pSession->iNumClients);
    logwritei("\t threshold ", pSession->iNumThreshold);
/***********************************************************/

    if(pSession->iNumClients == pSession->iNumThreshold)
    /* linux test code follows: launches on initial */
    /*if(pSession->iNumClients <= pSession->iNumThreshold)*/
      return 1;
    else if(pSession->iNumClients >= pSession->iNumThreshold)
    /* linux test code follows: all after host are post-launch */
    /*else if(pSession->iNumClients > pSession->iNumThreshold)*/

/***********************************************************/
      return -1;
    else
      return 0;
}
/*#ifdef SENDMSG_ARCH
int launchSession(int iSessionSID, int iHostSock)
#else
*/
int launchSession(int iSessionSID, int iSessionPort)
/*#endif*/
{
    int i, iret = 0, iNumSocks;
    int aiSocks[MAX_EXEC_CLIENT_NUM + 1]; /* + 1 for the host socket */
    char szSocks[32], szSessionPort[8], szLogFile[64], szSessionSID[12];
    struct _stSession * current;
    /* test, to see data prior to fork: */
    /*#ifdef SENDMSG_ARCH */
    /*sprintf(szSocks, "%d", iHostSock);
    */
    /*#else*/

    /*if((iNumSocks = piGetSessionSockets(aiSocks, iSessionSID)) < 0)
	return -1;
    sprintf(szSocks, "%d", aiSocks[0]);
    for(i = 1; i < iNumSocks; i++)
	sprintf(szSocks, "%s,%d", szSocks, aiSocks[i]);
    */
    /*#endif*/
    /* end of test block */

    pid=fork();
    printf("forked %d\n", pid);

    switch(pid)
    {
    case -1:
	/* error - cannot fork */
	logwrite("Can't fork - exiting.");
	exit(-1);
	break;

    case 0:
	logwritei("   I'm the child of PID", getppid());
	logwritei("   My PID is",  pid = getpid());

	/* create table entry */
	current = updateHostEntry(iSessionSID, getpid());

	/*#ifdef SENDMSG_ARCH
	sprintf(szSocks, "%d", iHostSock);
	#else*/
	if((iNumSocks = piGetSessionSockets(aiSocks, iSessionSID)) < 0)
	    return -1;
	sprintf(szSocks, "%d", aiSocks[0]);
	for(i = 1; i < iNumSocks; i++)
	    sprintf(szSocks, "%s,%d", szSocks, aiSocks[i]);
	sprintf(szSessionPort, "%d", iSessionPort);
	sprintf(szLogFile, "reflector.%d.log", iSessionSID);
	sprintf(szSessionSID, "%d", iSessionSID);
	/*#endif*/
	logwritei("launching session instance SessionSID: ", iSessionSID);
	/*#ifndef SENDMSG_ARCH*/
	logwritei("\twill listen on : ", iSessionPort);
	/*#endif*/
	logwritei("\tcurrent active sessions: ", g_iSessionsActive);

	iret = execl(ZDSPROXY_APP, ZDSPROXY_APP,  "-t", "-f4", \
		       "-l", szSessionPort, "-e", szSocks, "-n", current->szHostIP, \
		     "-x", current->szPassword,  "-g", szLogFile, "-z", szSessionSID, "HOST_INFO_FILE", NULL);

	logwritei("child exec return", iret);
	exit(pid);
	break;

    default:
	logwrite("I'm the parent.");
	logwritei("My PID is", getpid());
	break;
    }
    return 0;
}

int addHostEntry(int iSessionNum, char *szIP, int iSock, int iSessionSID, int iHostSID, char *szPassword/*, int  **ppiClientsInvited*/)
{
    struct _stSession  *psess, *current;
    psess = current = NULL;

    logwritei("\n++++++++++++++++++++++++++++++++++++++++++++++++++addHostEntry for sessionSID:",iSessionSID);
    logwritei("\tiSessionNum:",iSessionNum);
    logwritei("\tiHostSID", iHostSID);
    /*logwritei("num ClientsInvited", sizeof (ppiClientsInvited)/sizeof(*ppiClientsInvited) - 1);*/

    current = psGetSession(0);
    /* find next empty, set as next */
    psess = current + 1;
    while(psess->PID)
      ++psess;
    current->next = psess;
    psess->prev = current;

    /* populate */
    current->iSessionNum = iSessionNum;
    current->iSessionSID = iSessionSID;
    current->iHostSID = iHostSID;
    current->iHostSock = iSock;
    strcpy(current->szHostIP, szIP);
    strcpy(current->szPassword, szPassword == NULL ? "foo" : szPassword);

    current->iNumClients = 0;
    current->iNumThreshold = s_iThreshold;
    /* ignore ppiClientsInvited for now */
    ++g_iSessionsActive;
    logwritei("\tcurrent sessionNUM:", current->iSessionNum);
    logwritei("\tcurrent next addr:", (int) current->next);
    logSessionTable();
    return 0;
}

struct _stSession *updateHostEntry(int iSessionSID, int pid)
{
    struct _stSession *current = psGetSession(iSessionSID);

    current->PID = pid;
    logwritei("Updating host entry for sessionSID ", current->iSessionSID);
    logwritei("\tpid: ", current->PID);

    return current;
}

int updateHostPort(int iSessionSID, int iNewPort)
{
  int iret;
  char buf[256];
  char *pbuf = buf;
  struct _stSession *current = psGetSession(iSessionSID);
  if(!current){
    logwritei("updateHostPort - session not found:", iSessionSID);
    return -1;
  }
  current->iNewPort = iNewPort;

  sprintf(buf, "%s%d&reflport=%d&domainSID=%d&vendorSID=%d&brokerSID=%d  HTTP/1.0\nUser-Agent: Mozilla/4.0 (compatible; MSIE 5.5; Windows NT 5.0; Znet)/3.6.0 \n\n",
	  Z_POST_LAUNCH_DSPORT_URL, current->iSessionSID, iNewPort, s_ibrokerSID, s_idomainSID, s_ivendorSID);
  logwrite2("updateHostPort - calling broker:", pbuf);
  iret = callBroker(buf, NO_SSL);
  return iret;
}

int notifySessionTerminate(int pid)
{
  int iret;
  char buf[256];
  char *pbuf = buf;
  struct _stSession *current = psGetSessionByPID(pid);
  if(!current){
    logwritei("notifySessionTerminate - session not found for pid:", pid);
    return -1;
  }

  sprintf(buf, "%s%d&deviceSID=%s&domainSID=%d&vendorSID=%d&brokerSID=%d  HTTP/1.0\nUser-Agent: Mozilla/4.0 (compatible; MSIE 5.5; Windows NT 5.0; Znet)/3.6.0 \n\n",
	  Z_SESSION_TERMINATE_URL, current->iSessionSID, s_szDeviceSID, s_ibrokerSID, s_idomainSID, s_ivendorSID);
  logwrite2("notifySessionTerminate - calling broker:", pbuf);
  iret = callBroker(buf, NO_SSL);
  return iret;

}


int addClientEntry(int iSock, char *szIP, int iSessionSID, int iClientSID)
{
  int i;
  struct _stSession  *new, *current;
  new = current = NULL;

  logwritei("\n++++++++++++++++++++++++++++++++++++++++++++++++++addClientEntry for sessionSID:", iSessionSID);
  current = psGetSession(iSessionSID);
  if(current == NULL) {
    logwritei("\n\t\tsession not found for session:", iSessionSID);
    return - 2;
  }

  /* populate */
  /* find first client slot */
  for(i = 0; i < MAX_CLIENT_NUM; i++)
    if(!current->sClients[i].bInit)
      break;

  logwritei("\n\tsClients index:", i);

  if(i < MAX_CLIENT_NUM) {
    /* current->sClients[i].iSID = */
    current->sClients[i].iClientSock = iSock;
    strcpy(current->sClients[i].szClientIP, szIP);
    current->sClients[i].iClientSID = iClientSID;
    current->sClients[i].bInit = true;
    current->iNumClients += 1;
  }

  logwritei("\tcurrent sessionNUM:", current->iSessionNum);
  logwritei("\tcurrent PID:", current->PID);
  logwritei("\tcurrent next addr:", (int) current->next);
  logwrite2("\ttable IP:", current->sClients[i].szClientIP);
  /*logSessionTable();*/
  return 0;
}


int removeHostEntry(int pid)
{
  int i;
  struct _stSession *current = psGetSessionByPID(pid);
  if(!current)
    return -1;

  logwritei("\t---------- entry for PID:", pid);
  logwritei("\t--------shareddesktopSID:",  current->iSessionSID);
  logwritei("\t  current SessionsActive:",  g_iSessionsActive);

  if(!close(current->iHostSock))
    logwrite("host sock closed");
  else
    logwrite("host sock close fail!");

  if(!close(current->iMsgSock))
    logwrite("msg sock closed");
  else
    logwrite("msg sock close fail!");

  /* deal with prev/next issues */
  if(current == g_pSessions) {     /* initial entry is root, special case */
    logwrite("\treset treetop:");
    current->next = current->prev = NULL;
  }
  else {
    /* if next is active, point prev's next to it */
    if(current->next->PID){
      current->prev->next = current->next;
      current->next->prev = current->prev;
    }
    else
      current->next = current->prev = NULL;
  }
  /* release this port */
  releaseSessionPort(current->iNewPort);

  /* reset this one to empty */
  current->iSessionNum = 0;
  current->PID = 0;
  current->iSessionSID = 0;
  current->iHostSID = 0;
  current->iHostSock = 0;
  /* ignore ppiClientsInvited for now */
  current->szHostIP[0] = '\0';
  current->szPassword[0] = '\0';
  current->iNumClients = 0;
  current->iNewPort = 0;

  /* remove client(s) for this hostSID*/
  for(i = 0; i < MAX_CLIENT_NUM && current->sClients[i].bInit; i++) {
    if(!close(current->sClients[i].iClientSock))
      logwritei("client sock closed, entry ", i);
    else
      logwritei("client sock close fail, entry ", i);
    current->sClients[i].iClientSock = 0;
    current->sClients[i].szClientIP[0] = '\0';
    current->sClients[i].iClientSID = 0;
    current->sClients[i].bInit = false;
    current->iNumClients = 0;
  }
  --g_iSessionsActive;



  logSessionTable();
  return 0;
}

int piGetSessionSockets(int *piSocks, int iSessionSID)
{
    int i, j;
    struct _stSession *current =  psGetSession(iSessionSID);
    if(current == NULL)
	return -1;

    /* get host socket first */
    if(!current->iHostSock)
	return -1;
    *piSocks = current->iHostSock;

    /* we offset i after the host sock, but the client array begins at 0 */
    for(i = 1, j = 0; i < MAX_EXEC_CLIENT_NUM && current->sClients[j].bInit; i++, j++)
	*(piSocks + 1) = current->sClients[j].iClientSock;

    return i;
}





/*~
  struct _stSession *psGetSession(int iID)
  get ptr to either
  - session by passed ID, or
  - avail session slot if ID is 0
~*/

struct _stSession *psGetSession(int iSessionSID)
{
    int i;
    struct _stSession *pSess;

    if(iSessionSID){
	for(i = 0, pSess = g_pSessions; i < MAX_SESSION_NUM; i++, pSess++)
	    if(pSess->iSessionSID == iSessionSID)
		return pSess;
    }
    else {
	for(i = 0, pSess = g_pSessions; i < MAX_SESSION_NUM; i++, pSess++)
	    if(!pSess->iSessionSID)
		return pSess;
    }

    return NULL;
}
struct _stSession *psGetSessionByPID(int pid)
{
    int i;
    struct _stSession *pSess;

    if(pid){
	for(i = 0, pSess = g_pSessions; i < MAX_SESSION_NUM; i++, pSess++)
	    if(pSess->PID == pid)
		return pSess;
    }
    else {
	for(i = 0, pSess = g_pSessions; i < MAX_SESSION_NUM; i++, pSess++)
	    if(!pSess->PID)
		return pSess;
    }

    return NULL;
}


static void sigHandler(int signo)
{
    int status = 0;
    int pid/*, tpid*/;
    /*int i;*/

    if(signo == SIGUSR1 || signo == SIGCHLD)
    {
	logwrite2("\n\t>>>>>>>>>\n\t>>>>>>>> ", signo == SIGUSR1 ? " SIGUSR1" : " SIGCHLD");
	while(1)
	    /*for(i = 0; i < g_iSessionsActive; i++)*/
	{
	    /*if((tpid = (pSessionTable + 1)->PID) != 0)
	      {*/

		pid = waitpid(0, &status, WNOHANG);
		/*pid = waitpid(tpid, &status, WNOHANG);*/
		if(pid < 0)
		{
		    /* error */
		    logwritei("waitpid err: ", pid);
		    logwritei("errno: ", errno);

		    break;
		}
		if(pid == 0)
		{
		    logwrite("no waitpid return");
		    break;
		}
		logwritei("Process signaled: ", pid);
		if(WIFEXITED(status))  /*  */
		{
		    logwritei("normal exit for pid: ", pid);
		    notifySessionTerminate(pid);
		    removeHostEntry(pid);
		}
		else if(WIFSIGNALED(status)) /* abnormal termination*/
		{
		    logwritei("abnormal exit for pid: ", pid);
		    notifySessionTerminate(pid);
		    removeHostEntry(pid);
		}
		else if(WIFSTOPPED(status)) /* stopped */
		{
		   logwritei("stopped status for pid: ", pid);
		   notifySessionTerminate(pid);
		   logwritei("WSTOPSIG: ", WSTOPSIG(status));	  /*gets stopping signal*/
		   removeHostEntry(pid);
		}
		else
		   logwrite("- no signal detail");
	       /*}*/
       }
    }
    else  if(signo == SIGUSR2)
	logwrite("\n\t!!!Received SIGUSR2");
    else  if(signo == SIGTERM) {
	logwrite("\n\t!!!Received SIGTERM");
	deviceLogout();
    }
    else
	logwritei("\n\t!!!Received other signal: ", signo);

    logwrite("\n\tsigHandler done.");
    return;
}

/*~
  int parseRequest(char *buf, int bytes, int *piOperation, int *piUserSID, int *piSessionSID, char *szPassword)
  parse the incoming z host or client request, looking for parameters

`*/
#define Z_PROLOGUE "GET ZDsProxy?operation="                /* backwards compatibility: 3.7 */
#define Z_PROLOGUE_SLASH "GET /ZDsProxy?operation="
#define MAX_ARGS 8
int parseRequest(char *buf, int bytes, int *piOperation, int *piUserSID, int *piSessionSID, char *szPassword)
{
    /* req should be
       GET xxxxxxxxxxxxxx?operation=host|join|status
       &userSID=n    - caller, be it host or joiner
       &sessionSID=n - the caller got this from the broker on  peerrequest
       &tok=n        - host only - pathetic attempt to disguise password
       &threshold=n  - host only - how many clients before launch of session
    */

    char szTemp[128];
    int iLen = strlen(Z_PROLOGUE);
    int i;
    char seps[3];
    char *ptr[MAX_ARGS], *pbuf;

    strncpy(szTemp, buf, sizeof(szTemp) -1);

    /* check prologue */
    if(strncmp(buf, Z_PROLOGUE, iLen)){
      iLen = strlen(Z_PROLOGUE_SLASH);
      if(strncmp(buf, Z_PROLOGUE_SLASH, iLen))
	{
	  logwrite2("parseRequest bad prologue:", szTemp);
	  return -1;
	}
    }
    /* check operation */
    if(!strncmp(buf + iLen, "host", 4))
	*piOperation = Z_DS_OP_HOST;
    else if(!strncmp(buf + iLen, "join", 4))
	*piOperation = Z_DS_OP_CLIENT;
    else if(!strncmp(buf + iLen, "status", 6))
	*piOperation = Z_DS_OP_STATUS;
    else
    {
	logwrite2("  operation invalid or misplaced: ", szTemp);
	*piOperation = Z_DS_OP_INVALID;
	return -1;
    }
    pbuf = (buf + iLen + (*piOperation == Z_DS_OP_STATUS ? 7 : 5));

    /* now parse out other args */
    *piUserSID = *piSessionSID = 0;

    strcpy(seps, "&");
    strcat(seps, "\n"); /* we terminate the last param w this */
    i = 0;
    ptr[i] = strtok( pbuf, seps);
    while(ptr[i] != NULL)
	ptr[++i] = strtok(NULL, seps);

    /* ptr[MAX_ARGS]  now holds &-delim args */

    for(i = 0; ptr[i] != NULL; i++)
    {
	if(!strncmp(ptr[i], "userSID", 7))
	    *piUserSID = atoi(ptr[i] + 8);
	else if(!strncmp(ptr[i], "shareddesktopSID", 16))
	    *piSessionSID = atoi(ptr[i] + 17);
	else if(!strncmp(ptr[i], "tok", 3))
	   strcpy(szPassword, ptr[i] + 4);
	else if(!strncmp(ptr[i], "threshold", 9))
	    s_iThreshold = atoi(ptr[i] + 10);
    }
    logwritei("parseRequest: operation:", *piOperation);
    logwritei("\tuserSID:", *piUserSID);
    logwritei("\tsessionSID (shareddesktopSID):", *piSessionSID);
    logwrite2("\tpassword:", szPassword);
    logwritei("\tthreshold", s_iThreshold);


    return 0;
}

int ackRequest(int sock, bool bUseSSL, SSL *ssl)
{
    int iret;
    /* temp */
    bUseSSL = 0;
    if(bUseSSL)
      iret = SSL_write(ssl, Z_RESPONSE_OK, strlen(Z_RESPONSE_OK));
    else
      iret = write(sock, Z_RESPONSE_OK, strlen(Z_RESPONSE_OK));
    return iret;
}

int nakRequest(int sock, char *szErr, bool bUseSSL, SSL *ssl)
{
    int iret;
    char errbuf[128];
    /* temp */
    bUseSSL = 0;

    sprintf(errbuf, "%s%s\r\n\r\n%s", Z_RESPONSE_NAK, szErr, szErr); /* we send response as both header and data - perhaps not the most carefully thought-out model! */
    if(bUseSSL)
      iret = SSL_write(ssl, Z_RESPONSE_OK, strlen(Z_RESPONSE_OK));
    else
      iret = write(sock, errbuf, strlen(errbuf));

    logwrite2("nakRequest:", szErr);

    return iret <= 0 ? -1 : 0; /* if we sent bytes, cool, return 0; if not, return  -1*/
}
int sendRFB(int sock)
{
    int iret;
    iret = write(sock, RFB_VERSION_STR, sizeof(RFB_VERSION_STR));
    return iret;
}


#ifdef SENDMSG_ARCH
/* from Stevens
   plz see description in ZDsProxy's async_io.c: recv_fd()
*/
/*static struct cmsghdr *cmptr = NULL;
  #define CONTROLLEN (sizeof(struct cmsghdr) + sizeof(int))*/
/* size of control buffer to send/recv one file descriptor */
/* from Stevens, heavily modified by Gray:
     added use of Linux macros, got rid of Stevens 2-byte protocol
*/

int send_fd(int msgfd, int *pfd)
{

    int ret = 0;
    int er = 0; /* no error cpde of 0; replaces Stevens 2-byte protocol data send */
    errno = 0;

    struct iovec iov[1];
    struct msghdr msg;
    struct cmsghdr *cmsg = NULL;
    /*#define CONTROLLEN (sizeof(struct cmsghdr) + sizeof(int))*/
    char buf[CMSG_SPACE(sizeof *pfd)];  /* Ancillary buffer */

    if(*pfd < 0)
    {
      return -1;      /* we don't pass a bad fd */
    }
    else
    {
      iov[0].iov_base = &er;
      iov[0].iov_len =  sizeof(er);

      msg.msg_iov = iov;
      msg.msg_iovlen = 1;
      msg.msg_name = NULL;
      msg.msg_namelen = 0;

      /*if(cmsg == NULL && (cmsg = malloc(CONTROLLEN)) == NULL)
	 return -1;
      */
      //msg.msg_control = (caddr_t) cmsg;
      msg.msg_control = buf;
      //msg.msg_controllen = CONTROLLEN;
      msg.msg_controllen = sizeof buf;

      cmsg = CMSG_FIRSTHDR(&msg);
      cmsg->cmsg_level = SOL_SOCKET;
      cmsg->cmsg_type = SCM_RIGHTS;
      //cmsg->cmsg_len = CONTROLLEN;
      cmsg->cmsg_len = CMSG_LEN(sizeof *pfd);

      *(int *)CMSG_DATA(cmsg) = *pfd;

      msg.msg_controllen = cmsg->cmsg_len;
      //buf[1] = 0;       /* 0 status means OK */
    }
    //buf[0] = 0;  /* null byte flag to recv_fd */

    do {
      ret = sendmsg(msgfd, &msg, 0);
    } while (ret == -1 && errno == EINTR);

    if(ret == -1)
      {
	logwrite2("sendmsg fail: ", strerror(errno));
	logwritei("msgfd: ", msgfd);
	return -1;
    }

    return 0;
}
#endif

void  msgThreadHandler(void *arg)
{
  int msg_fd;
  int incoming_fd;
  int incoming_pid = 0;
  int len;
  int bytes;
  char buf[32];
  bool bListening = true;
  /*struct in_addr s_bind_address;*/
  /*struct sockaddr_in msg_addr, client_addr;*/
  struct sockaddr_un msg_addr, instance_addr;
  struct _stSession *current;

  logwrite("msgThreadHandler\n");
  memset(buf, 0, sizeof(buf));
  msg_fd = socket(PF_LOCAL /*AF_INET*/, SOCK_STREAM, 0);
  if (msg_fd < 0) {
      logwrite("Can't get socket, exiting\n");
      return;
  }

  /*s_bind_address.s_addr = htonl(INADDR_ANY);*/
  msg_addr.sun_family = AF_LOCAL /*AF_INET*/;
  /*msg_addr.sin_addr.s_addr = s_bind_address.s_addr;
    msg_addr.sin_port = htons((unsigned short)ZMSGPORT);*/
    strncpy(msg_addr.sun_path, "xzMsg", sizeof msg_addr.sun_path-1);
    msg_addr.sun_path[0] = 0;



  if ( bind(msg_fd, (struct sockaddr *)&msg_addr, sizeof(msg_addr)) != 0
       || listen(msg_fd, 5) != 0 ) {
      logwritei("msgThreadHandler: can't bind to \n", ZMSGPORT);
      close(msg_fd);
      return;
  }

  len = sizeof(instance_addr);
  while(bListening) {
      logwritei("listening on", ZMSGPORT);
      incoming_fd = accept(msg_fd, (struct sockaddr *) &instance_addr, (socklen_t *)&len);
      if(incoming_fd > 0) {
	bytes = read(incoming_fd, buf, sizeof(buf));
	/* read should get op=reg&PID=xxx */
	logwrite2("\n==> zrefl got from msgListener:", buf);
	if(!strncmp(buf, "op=reg&PID=",8))  {
	  incoming_pid = atoi(buf + 11);
	  /* find session */
	  current = psGetSessionByPID(incoming_pid);
	  if(!current) {
	      logwritei("No session found for pid ", incoming_pid);
	      close(incoming_fd);
	      continue;
	  }
	  logwritei("Session found for pid ", incoming_pid);
	  logwritei("\tsessionSID ", current->iSessionSID);
	  logwritei("\t==> msgListener fd:", incoming_fd);
	  current->iMsgSock = incoming_fd;
	  /*
	    could establish reading thread;
	    dying ZDsProxy throws signal which zrefl catches for removeHostEntry, so not strictly needed
	  */
	}else if(!strncmp(buf, "op=end&PID=",8))  {
	  incoming_pid = atoi(buf + 11);

	  current = psGetSessionByPID(incoming_pid);
	  if(!current) {
	      logwritei("No session found for pid ", incoming_pid);
	      close(incoming_fd);
	      continue;
	  }
	  logwritei("End request received: session found for pid ", incoming_pid);
	  logwritei("\tremoving sessionSID ", current->iSessionSID);
	  removeHostEntry(pid);
	  close(incoming_fd);
	}else
	  logwrite("!!msgListener received invalid sock: possible instance terminate\n");
      }
  }
}

void logSessionTable()
{
  int i;
  struct _stSession *ptr = g_pSessions;
  logwrite("Session table:\nPID\tsessionSID"); /*\tMsgSock\tnumClients*/
  if(ptr->next == NULL)
    logwrite("<table empty>");
  else {
    for(i = 0; ptr->next != NULL; i++, ptr++)
      logwritei2("+", ptr->PID, ptr->iSessionSID);
  }
}

int logwrite(char *szString)
{
  static FILE *flog = NULL;
  int bytes;
  int i = 0;

  for(i = 0; i < 20; i++)
    if(!pthread_mutex_trylock(&loglock))
      break;

  if(i == 20) {  /* just can't get that lock */
    printf("\n!!! can't get mutex for logfile\n");
    return -1;
  }

  if(!flog)
  {
    if(!(flog = fopen(ZREFL_LOG, "a")))
	printf("can't open %s\n", ZREFL_LOG);
      else
	printf("opened log %s\n", ZREFL_LOG);
  }
  bytes = fwrite(szString, 1, strlen(szString), flog);
  if(bytes < strlen(szString))
     printf("\n\tERROR in logwrite\n");
  else
     fflush(flog);

  pthread_mutex_unlock(&loglock);
  return bytes;
}

int logwritei(char *szString, int i)
{
  char buf[MAX_LOG_MSG + 12];

  if((strlen(szString)) > MAX_LOG_MSG - 1)
    sprintf(buf, "logwrite: excessive msg len starting with %64s\n", szString);
  else
    sprintf(buf, "%s %d\n", szString, i);
  return logwrite(buf);
}

int logwritei2(char *szString, int i, int j)
{
  char buf[MAX_LOG_MSG + 24];

  if((strlen(szString)) > MAX_LOG_MSG - 1)
    sprintf(buf, "logwrite: excessive msg len starting with %64s\n", szString);
  else
    sprintf(buf, "%s %d, %d\n", szString, i, j);
  return logwrite(buf);
}

int logwrite2(char *szString, char *szString2)
{
  char buf[MAX_LOG_MSG];

  if((strlen(szString) + strlen(szString2)) > MAX_LOG_MSG)
    sprintf(buf, "logwrite: excessive msg len starting with %64s\n", szString);
  else
    sprintf(buf, "%s %s\n", szString, szString2);
  return logwrite(buf);
}


int callBroker(char *szURI, bool bUseSSL)
{
    int broker_fd, iret;
    char *pbuf = szURI;
    struct sockaddr_in parent_addr;

    logwrite2("\ncallBroker with URL:", pbuf);
    broker_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (broker_fd < 0)
    {
	logwrite("Can't get broker socket, exiting callBroker\n");
	return -1;
    }

    bzero(&parent_addr, sizeof(parent_addr));
    parent_addr.sin_family = AF_INET;
    if(bUseSSL)
      parent_addr.sin_port = htons(443);
    else
      parent_addr.sin_port = htons((unsigned short)s_ibroker_port);
    parent_addr.sin_addr.s_addr = inet_addr(s_szbroker_ip);

    iret = connect(broker_fd, ( struct sockaddr *) &parent_addr, sizeof (parent_addr));
    if(iret < 0){
      logwritei("callBroker connect fail:", iret);
      logwrite2(" - broker: ", s_szbroker_ip);
      logwritei("- port:", bUseSSL ? 443 : s_ibroker_port);
      close(broker_fd);
      return -1;
    }
    if(bUseSSL) {
      iret = sslClientOnetimeRequest(broker_fd, szURI, s_retBuf, sizeof s_retBuf);
    }
    else {
      iret = send(broker_fd, szURI, strlen(szURI), 0);
      if(iret < 0) {
	logwritei("callBroker fail on send: %d\n", iret);
      }
      else{
	logwrite("callBroker send OK\n");

	iret = read(broker_fd, s_retBuf, sizeof(s_retBuf));
	/*check ack */
	logwritei("callBroker bytes revd: \n", iret);
	if(iret > 0) {
	  s_retBuf[iret] = '\0';   /* null-terminate buffer */
	  logwrite2("\t: \n", pbuf = s_retBuf);
	}
      }
    }
    if(iret > 0)
      iret = atoi(&s_retBuf[sizeof("StatusCode")]);

    close(broker_fd);
    return iret;
}



define INI_MAX_LINES 100
int getZSettings()
{
  static FILE *ini = NULL;
  int bytes, i, j, ret;
  const int bufsize = 5120;
  char *buf, *buf2, *pstr;
  char seps[3];
  char *ptr[INI_MAX_LINES], *pbuf;
  char sz_temp[14], sz_alias[32], sz_pw[32];
  bool b_unreg = false;

  if(! (buf = calloc(bufsize, 1)) ) {
    logwrite("getZSettings cannot allocate memory");
    return -1;
  }
  if(! (buf2 = calloc(bufsize, 1)) ) {
    logwrite("getZSettings cannot allocate memory");
    return -1;
  }

  /*memset(buf, 0, sizeof(buf));*/
  pbuf = buf;

  if(!(ini = fopen("wax.ini", "r"))){
    logwrite("can't open wax.ini for reading");
    return -1;
  }

  bytes = fread(buf, sizeof(char), bufsize, ini);
  if(bytes <= 0) {
    logwrite("can't read wax.ini");
    fclose(ini);
    return -1;
  }

  memcpy(buf2, buf, bytes);/* un-tokenized copy for possilbe config update */
  fclose(ini);

  strcpy(seps, "\n\r");
  i = j = 0;
  ptr[i] = strtok( pbuf, seps);
  while(ptr[i] != NULL) {
    if(!strncmp(ptr[i], "BrokerIP=", j = sizeof("BrokerIP")))
      strcpy(s_szbroker_ip, ptr[i] + j);
    else if(!strncmp(ptr[i], "BrokerPort=", j = sizeof("BrokerPort")))
      s_ibroker_port = atoi(ptr[i] + j);
    else if(!strncmp(ptr[i], "BrokerSID=", j = sizeof("BrokerSID")))
       s_ibrokerSID =  atoi(ptr[i] + j);
    else if(!strncmp(ptr[i], "DomainSID=", j = sizeof("DomainSID")))
      s_idomainSID =  atoi(ptr[i] + j);
    else if(!strncmp(ptr[i], "VendorSID=", j = sizeof("VendorSID")))
      s_ivendorSID =   atoi(ptr[i] + j);
    else if(!strncmp(ptr[i], "DeviceSID=", j = sizeof("DeviceSID"))) {
      if(!strncmp(ptr[i] + j, "None", 4))
	b_unreg = true;
      else
	/*s_szDeviceSID =   atoi(ptr[i] + j);*/
	strcpy(s_szDeviceSID, ptr[i] + j);
    }
    else if(!strncmp(ptr[i], "DeviceUID=", j = sizeof("DeviceUID")))
      strcpy(s_szDeviceUID, ptr[i] + j);
    else if(!strncmp(ptr[i], "AppPort=", j = sizeof("AppPort")))
      s_iPort =   atoi(ptr[i] + j);
    /*else if(!strncmp(ptr[i], "thisIP=", j = sizeof("thisIP")))
      strcpy(s_szDeviceIP, ptr[i] + j);
    */
    else if(!strncmp(ptr[i], "zport=", j = sizeof("zport")))
      s_iZport =   atoi(ptr[i] + j);
    else if(!strncmp(ptr[i], "altports=", j = sizeof("altports")))
      strcpy(s_szAltports, ptr[i] + j);
    else if(!strncmp(ptr[i], "HeartbeatSleep=", j = sizeof("HeartbeatSleep")))
      s_iHeartbeat = (atoi(ptr[i] + j))/1000; /* convert from ms to secs */
    ptr[++i] = strtok(NULL, seps);
  }

  /* check essentials */
  GetIP(s_szDeviceIP);
  if(!strcmp(s_szDeviceUID,"0"))
    CreateDeviceUID((char **)&s_szDeviceUID);



  if(b_unreg) {
    /* need to register this device */
    puts("\a\a Unregistered\n\talias?\n\t");
    gets(sz_temp);
    if(*sz_temp == '\n') {
      puts("\tno input! \n\talias?\n\t");
      gets(sz_temp);
      if(*sz_temp == '\n') {
	puts("\n\ano input! exiting.");
	exit(-1);
      }
    }
    strcpy(sz_alias, sz_temp);
    puts("\n\tpassword?\n\t");
    gets(sz_temp);
    if(*sz_temp == '\n') {
      puts("\tno input! \n\talias?\n\t");
      gets(sz_temp);
      if(*sz_temp == '\n') {
	puts("\n\ano input! exiting.");
	exit(-1);
      }
    }
    strcpy(sz_pw, sz_temp);
    i = 0;
    while (true) {
      if((ret = RegisterDevice(sz_alias, sz_pw, i)) == 401) {
	if(pstr = strstr(s_retBuf, "suffix="))  /* broker suggests suffix */
	  i = atoi(pstr + strlen("suffix="));
	else
	  ++i;
      }
      else
	break;
    };
    if(ret == 200) {
      /* increment deviceUID as needed */
      sprintf(s_szDeviceUID, "%s-%d", s_szDeviceUID, i);
      updateConfig(buf2, bytes);
    }
  }

  free(buf);
  logwrite2("Broker IP: ", s_szbroker_ip);
  logwritei("Broker port: ", s_ibroker_port);
  return 0;
}


void sslInit()
{
  // initalize lib
  OpenSSL_add_all_algorithms();
  SSL_load_error_strings();
}


SSL_CTX *sslServerInit()
{
  SSL_METHOD *method;
  SSL_CTX *ctx = NULL;

 // initalize server SSL state
  method = (TLSv1_server_method)();
  ctx = (SSL_CTX_new)(method);

  if(!method || !ctx) {
    logwrite("ConnectRequest() SSL context fail");
    return NULL;
  }

  /* load certificate and private key files */
  SSL_CTX_use_certificate_file(ctx, CERTFILE, SSL_FILETYPE_PEM);
  /* set private key from KeyFile */
  SSL_CTX_use_PrivateKey_file(ctx, KEYFILE, SSL_FILETYPE_PEM);
  /* verify private key */
  if(!SSL_CTX_check_private_key(ctx))
     logwrite("!!! ssl: key and cert don't match.");

     return ctx;
    /* SSL_write(ssl, replybuf, sizeof replybuf); */
}
int sslRead(SSL *ssl, char *buf, int icount)
{
  icount = SSL_read(ssl, buf, icount);
  return icount;
}

int sslClientOnetimeRequest(int sock, char *szURI, char *buf, int icount)
{
  SSL_METHOD *method;
  SSL_CTX *ctx;
  SSL *ssl;
  int bytes;
  int ret;
  char *pbuf;
  /* initalize client SSL state	*/
  errno = 0;
  method = TLSv1_client_method();
  if(!(ctx = SSL_CTX_new(method))) {
    logwrite2("SSL_CTX_new() failed:" , strerror(errno));
    return -1;
  }

  /* create new SSL connection state */
  if(!(ssl = SSL_new(ctx))) {
    logwrite2("SSL_new() failed:" , strerror(errno));
    return -1;
  }

  SSL_set_fd(ssl, sock); /* attach the socket descriptor */
  if((ret = SSL_connect(ssl)) <= 0) {
    logwritei("!!! ssl connect fail with SSL error:", SSL_get_error(ssl, ret));
    close(sock);
    return -1;
  }
  else {
    if((bytes = SSL_write(ssl, szURI, strlen(szURI))) == -1) { /* write string, null-terminated */
      logwrite("SSL_write gets -1:");
      close(sock);
      return -1;
    }
    else
      logwrite2("SSL_write OK:", pbuf = szURI);
  }
  memset(buf, 0, icount);
  if((bytes = SSL_read(ssl, buf, icount)) == -1) { /* read max buf size, passed in */
    logwrite("SSL_read gets -1:");
    close(sock);
    return -1;
  }

  logwrite2("SSL_read:", bytes > 0 ? pbuf = buf : "no data");

  /*free(ctx);
  free(ssl);
  */
  return bytes;
}

int heartbeatThread(unsigned long data)
{
  char buf[1204];
  int ret;
  logwrite("heartbeatThread");

  sprintf(buf, "%sdeviceSID=%s  %s", SW_HEARTBEAT_URL, s_szDeviceSID, SW_HTTP_TAG);

  ret = callBroker(buf, NO_SSL);
  alarm(s_iHeartbeat);

  return ret;
}

int deviceLogin()
{
  char buf[1024], buf2[1024];
  int ret;

  sprintf(buf, "%s&port=%d&ip=%s&zport=%d&altports=%s&deviceUID=%s  %s",
	  SW_DEVICELOGIN_URI,
	  s_iPort,
	  s_szDeviceIP,
	  s_iZport,
	  s_szAltports,
	  s_szDeviceUID,
	  SW_SSL_TAG);

  logwrite("\nabout to callBroker Devicelogin");
  if((ret = callBroker(buf, USE_SSL)) == 401) {
    /* need to logout and login again */
    logwrite("\ndevice already logged in, about to callBroker Devicelogout");
    deviceLogout();


    logwritei("\nafter callBroker Devicelogout:", ret);
    ret = callBroker(buf, USE_SSL);
  }
  logwritei("\nafter callBroker Devicelogin: ", ret);

  return ret;


}
int deviceLogout()
{
  int ret;
  char buf[1024];
  sprintf(buf, "%sdeviceUID=%s  %s",
	  SW_DEVICELOGOUT_URI,
	  s_szDeviceUID,
	  SW_SSL_TAG);
  ret = callBroker(buf, USE_SSL);

  return ret;
}
#define TEMP_BUFFER_LEN 256

int GetIP(char *pBuffer)
{

  int iRet, i;
  struct hostent stHostent;
  struct hostent  *pHostent = &stHostent;
  char tempBuffer[TEMP_BUFFER_LEN];
  char *pszIPAddress = pBuffer;
  int iErr = 0;
  *pBuffer = '\0';

  if(iRet = gethostname(tempBuffer,TEMP_BUFFER_LEN)) {
    logwrite2("GetIP err:", strerror(errno));
    return iErr;
  }

  if(!(pHostent = gethostbyname(tempBuffer))) {
    logwrite2("GetIP err:", strerror(errno));
    return iErr;
  }

  for(i = 0; i < pHostent->h_length; i++) {
    sprintf(pszIPAddress, "%s%d%s", pszIPAddress, pHostent->h_addr_list[0][i],
	    (i+1 < pHostent->h_length ? "." : ""));
  }

  return 0;

}
char *GetMACAddr (char *addr)
{
/* implementation for Linux */
/*http://cplus.kompf.de/macaddr.html#second*/

    struct ifreq ifr;
    struct ifreq *IFR;
    struct ifconf ifc;
    unsigned char buf[1024];
    int s, i;
    int ok = 0;

    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s==-1) {
        return NULL;
    }

    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = buf;
    ioctl(s, SIOCGIFCONF, &ifc);

    IFR = ifc.ifc_req;
    for (i = ifc.ifc_len / sizeof(struct ifreq); --i >= 0; IFR++) {

      strcpy(ifr.ifr_name, IFR->ifr_name);
      if (ioctl(s, SIOCGIFFLAGS, &ifr) == 0) {
	if (! (ifr.ifr_flags & IFF_LOOPBACK)) {
	  if (ioctl(s, SIOCGIFHWADDR, &ifr) == 0) {
	    ok = 1;
	    break;
	  }
	}
      }
    }

    close(s);
    if (ok) {
        bcopy( ifr.ifr_hwaddr.sa_data, buf, 6);
	/*bcopy( ifr.ifr_ifru.ifru_hwaddr, addr, 6);*/
 	addr[0] = '\0';
	sprintf(addr, "%X", buf[0]); /* convert to ascii numeric */
	i = 1;
	do {
	  sprintf(addr, "%s%X", addr, buf[i]); /* convert to ascii numeric */
	  ++i;
	}while(buf[i+1]); /* allow one trailing 0x00 */
    }
    else {
        return NULL;
    }
    return addr;
}

char *CreateDeviceUID()
{
  /*if(s_szDeviceIP[0] == '\0' || !strcmp(s_szDeviceIP, "0"))*/

  if(s_szMAC[0] == '\0')
    GetMACAddr(s_szMAC);

  sprintf(s_szDeviceUID, "%s-%s",  s_szDeviceIP, s_szMAC);
  return s_szDeviceUID;
}

int RegisterDevice(char *sz_alias, char *sz_pw, int iIteration)
{
  char buf[4096];
  char sz_temp[32];

  sprintf(buf, "%smac=%s&ip=%s&deviceUID=%s-%d&port=%d&alias=%s&password=%s&domainSID=%d&vendorSID=%d&brokerSID=%d&linespeed=%d&altports=%s&version=%s  %s",
	  SW_SZ_DEVREG_URL,
	  s_szMAC,
	  s_szDeviceIP,
	  s_szDeviceUID,
	  iIteration,
	  s_iPort,
	  sz_alias,
	  sz_pw,
	  s_idomainSID,
	  s_ivendorSID,
	  s_ibrokerSID,
	  7,
	  s_szAltports,
	  "dsp 1.0",
	  SW_SSL_TAG);

  callBroker(buf, USE_SSL);

}
struct _elements {
  char name[16]; /* tag, like DeviceUID */
  char *value;   /* value for this device/user */
  int taglen;    /* empty len: 1 for "0", 4 for "None", etc. */
} elements[4] =  {
//removed
};

int updateConfig(char *buf, int bytes)
{
  // removed
}
