#ifndef _USERVER_DTLS_H_
#define _USERVER_DTLS_H_

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_MSG_LEN 2048

typedef struct tagUSERVER_DTLS_MSG
{
	struct sockaddr_in stMsgSrc;
	char               acMsgData[MAX_MSG_LEN];
	unsigned short     usMsgLen;
}USERVER_DTLS_MSG_S;

typedef struct tagUSERVER_DTLS_SOCK
{
	struct sockaddr_in stPeerAddr;
	int                iSockFd;
	int                uiDataLen;
	char*              pcData;
}USERVER_DTLS_SOCK_S;

typedef struct tagUSERVER_DTLS_BIODATA
{
	USERVER_DTLS_SOCK_S stSockOut;
	char*               pcMsgData;
	unsigned short      usMsgLen;
	long                lMtu;
}USERVER_DTLS_BIODATA_S;

typedef struct tagUSERVER_DTLS_SESSION
{
	pthread_mutex_t stLock;
	SSL*            pstSSL;
}USERVER_DTLS_SESSION_S;

bool USERVER_DTLS_IsDataPkt(IN const char* cpcData);
bool USERVER_DTLS_IsHandshakePkt(IN const char* cpcData);
void USERVER_DTLS_ReadInject(INOUT BIO* pstBio, IN USERVER_DTLS_MSG_S *pstMsg);
bool USERVER_DTLS_Handshake(IN SSL* pstSSL);
bool USERVER_DTLS_InitSess(IN const USERVER_DTLS_SOCK_S* pstSockout, INOUT USERVER_DTLS_SESSION_S* pstSess);
int USERVER_DTLS_Write(IN USERVER_DTLS_SESSION_S* pstSess, IN const char* cpcBuf, IN unsigned int uiLen);
int USERVER_DTLS_Read(IN USERVER_DTLS_SESSION_S* pstSess, INOUT char* pcBuf, IN unsigned int uiLen);


int _dtls_InitSslCtx(IN const char* szKeyPath, IN const char* szCaPath, IN const char* cpcPwd);



#ifdef __cplusplus
}
#endif//__cplusplus

#endif//_USERVER_DTLS_H_


