#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <pthread.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/crypto.h>

#include "common/public.h"

#include "userver_dtls.h"

#ifdef __cplusplus
extern "C" {
#endif

#define USERVER_DTLS_CERT_VERIFY_DEPTH 2
#define USERVER_DTLS_PWD_LEN           16
#define USERVER_DTLS_CIPHER_LIST       "ALL:NULL:eNULL:aNULL"

#define CREATE_BIO_SUCCEED 1
#define CREATE_BIO_FAIL    0
#define BIO_CTRL_ARG ((long)10000)
#define DTLS_BUF_SIZE 256

static char             g_acCertPwd[DTLS_BUF_SIZE];
static SSL_CTX*         g_pstSslCtx;
static pthread_mutex_t* g_apstSslLock;

static void _locking_callback(int mode, int type, const char* file, int line)
{
	IGNORE(file);
	IGNORE(line);
	assert(type >= 0);

	if (mode & CRYPTO_LOCK)
	{
		pthread_mutex_lock(&g_apstSslLock[type]);
	}
	else
	{
		pthread_mutex_unlock(&g_apstSslLock[type]);
	}
}

static void _threadid_callback(CRYPTO_THREADID* id)
{
	char acBuf[32] = {0};
	//todo: fill buf with thread id
	CRYPTO_THREADID_set_pointer(id, acBuf);
}

static int _dtls_InitLock()
{
	/* 获取锁个数 */
	int iNumLocks = CRYPTO_num_locks();
	if (iNumLocks <= 0)
	{
		return -1;
	}

	/* 分配所有锁 */
	g_apstSslLock = OPENSSL_malloc(iNumLocks * sizeof(pthread_mutex_t));
	if (NULL == g_apstSslLock)
	{
		return -1;
	}

	/* 初始化锁 */
	int i;
	for (i = 0; i < iNumLocks; i++)
	{
		pthread_mutex_init(&g_apstSslLock[i], NULL);
	}

	/* 为保证线程安全，必须注册回调函数 */
	CRYPTO_set_locking_callback(_locking_callback);
	CRYPTO_THREADID_set_callback(_threadid_callback);

	return 0;
}

static int _dtls_MemNew(INOUT BIO* pstBio)
{
	if (NULL == pstBio)
	{
		return CREATE_BIO_FAIL;
	}

	pstBio->init = 1;
	pstBio->num = 0;
	pstBio->flags = 0;	
	
	USERVER_DTLS_BIODATA_S* pstBioData = (USERVER_DTLS_BIODATA_S*)calloc(1, sizeof(USERVER_DTLS_BIODATA_S));
	if (NULL == pstBioData)
	{
		return CREATE_BIO_FAIL;
	}

	pstBio->ptr = pstBioData;
	return CREATE_BIO_SUCCEED;
}

static int _dtls_MemFree(INOUT BIO* pstBio)
{
	if (NULL != pstBio)
	{
		if (NULL != pstBio->ptr)
		{
			free(pstBio->ptr);
			pstBio->ptr = NULL;
		}
	}

	return CREATE_BIO_SUCCEED;
}

static int _dtls_MemRead(IN BIO* pstBio, OUT char* pcBuf, IN int iBufLen)
{
	assert (NULL != pstBio && NULL != pcBuf);

	int iReadLen = 0;

	USERVER_DTLS_BIODATA_S* pstBioData = (USERVER_DTLS_BIODATA_S*)pstBio->ptr;
	assert (NULL != pstBioData);

	if (pstBioData->usMsgLen > 0)
	{
		assert (NULL != pstBioData->pcMsgData);
		iReadLen = MIN(iBufLen, pstBioData->usMsgLen);
		memcpy(pcBuf, pstBioData->pcMsgData, iReadLen);

		pstBioData->pcMsgData = NULL;
		pstBioData->usMsgLen = 0;
	}

	return iReadLen;
}

static int _dtls_MemWrite(IN BIO* pstBio, IN const char* pcBuf, IN int iBufLen)
{
	assert (NULL != pstBio && NULL != pcBuf);	

	USERVER_DTLS_BIODATA_S* pstBioData = (USERVER_DTLS_BIODATA_S*)pstBio->ptr;
	assert (NULL != pstBioData);

	int iWriteLen = sendto(pstBioData->stSockOut.iSockFd, pcBuf, iBufLen, 0, 
		(const struct sockaddr*)&(pstBioData->stSockOut.stPeerAddr), sizeof(struct sockaddr));

	return iWriteLen;	
}

static long _dtls_MemCtrl(IN BIO* pstBio, IN int iCmd, IN long lNum, IN void* ptr)
{
	assert (NULL != pstBio);
	IGNORE(ptr);

	long lRet = 1;
	USERVER_DTLS_BIODATA_S* pstBioData = (USERVER_DTLS_BIODATA_S*)pstBio->ptr;

	switch (iCmd)
	{
		case BIO_CTRL_DGRAM_QUERY_MTU:		
		case BIO_CTRL_DGRAM_GET_MTU:
		{
			lRet = pstBioData->lMtu;
			break;
		}
		case BIO_CTRL_DGRAM_SET_MTU:
		{
			pstBioData->lMtu = lNum;
			lRet = lNum;
			break;
		}
		case BIO_CTRL_SET_CLOSE:
		case BIO_CTRL_DUP:
		case BIO_CTRL_FLUSH:
		{
			lRet = 1;
			break;
		}
		case BIO_CTRL_RESET:
		case BIO_CTRL_EOF:
		case BIO_CTRL_INFO:
		case BIO_CTRL_GET_CLOSE:
		case BIO_CTRL_WPENDING:
		case BIO_CTRL_PENDING:
		case BIO_CTRL_PUSH:
		case BIO_CTRL_POP:
		default:
		{
			lRet = 0;
			break;
		}
	}

	return lRet;
}

static BIO_METHOD g_stDtlsBioMethod = 
{
	BIO_TYPE_DGRAM,
	"memory buffer",
	_dtls_MemWrite,
	_dtls_MemRead, 
	NULL,
	NULL,
	_dtls_MemCtrl,
	_dtls_MemNew,
	_dtls_MemFree,
	NULL,
};

static BIO_METHOD* _dtls_BioMemory()
{
	return &g_stDtlsBioMethod;
}

static BIO* _dtls_CreateBio(INOUT const USERVER_DTLS_SOCK_S* pstSockOut)
{
	assert (NULL != pstSockOut);

	BIO* pstBio = BIO_new(_dtls_BioMemory());
	if (NULL != pstBio)
	{
		USERVER_DTLS_BIODATA_S* pstBioData = (USERVER_DTLS_BIODATA_S*)pstBio->ptr;
		memcpy(&pstBioData->stSockOut, &pstSockOut, sizeof(pstBioData->stSockOut));

		pstBioData->pcMsgData = NULL;
		pstBioData->usMsgLen = 0;
	}

	return pstBio;
}

void USERVER_DTLS_ReadInject(INOUT BIO* pstBio, IN USERVER_DTLS_MSG_S *pstMsg)
{
	if (NULL != pstBio && NULL != pstMsg)
	{
		USERVER_DTLS_BIODATA_S* pstBioData = (USERVER_DTLS_BIODATA_S*)pstBio->ptr;
		if (NULL != pstBioData)
		{
			pstBioData->pcMsgData = pstMsg->acMsgData;
			pstBioData->usMsgLen = pstMsg->usMsgLen;
		}
	}
}

static int _dtls_PwdCb(OUT char* pcBuf, IN int iBufLen, IN int iFlag, OUT void* pUserData)
{
	IGNORE(iFlag);
	IGNORE(pUserData);

	int iPwdLen = strlen(g_acCertPwd);
	if (NULL == pcBuf || iBufLen < iPwdLen)
	{
		return 0;
	}

	strncpy(pcBuf, g_acCertPwd, iBufLen);

	return iPwdLen;
}

static int _dtls_VerifyCb(IN int iOk, IN X509_STORE_CTX* pstCtx)
{
	IGNORE(iOk);
	assert (NULL != pstCtx);

	char acBuf[DTLS_BUF_SIZE];
	X509* pstErrCert = NULL;
	int iErr, iDepth;
	int iPreverifyOk = 1;

	pstErrCert = X509_STORE_CTX_get_current_cert(pstCtx);
	iErr = X509_STORE_CTX_get_error(pstCtx);
	iDepth = X509_STORE_CTX_get_error_depth(pstCtx);

	X509_NAME_oneline(X509_get_subject_name(pstErrCert), acBuf, DTLS_BUF_SIZE);

	if (iDepth > USERVER_DTLS_CERT_VERIFY_DEPTH)
	{
		iPreverifyOk = 0;
		iErr = X509_V_ERR_CERT_CHAIN_TOO_LONG;
		X509_STORE_CTX_set_error(pstCtx, iErr);
	}

	if (0 == iPreverifyOk && X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT == iErr)
	{
		X509_NAME_oneline(X509_get_issuer_name(pstCtx->current_cert), acBuf, DTLS_BUF_SIZE);
	}

	return iPreverifyOk;
}

/*static*/ int _dtls_InitSslCtx(IN const char* szKeyPath, IN const char* szCaPath, IN const char* cpcPwd)
{
	assert (NULL != szKeyPath);
	assert (NULL != szCaPath);
	assert (NULL != cpcPwd);
	
	/* 初始化OpenSSL基础设置 */
	SSL_library_init();
	OpenSSL_add_ssl_algorithms();
	SSL_load_error_strings();
	ERR_load_crypto_strings();

	SSL_CTX* pstSslCtx = SSL_CTX_new(DTLSv1_server_method());
	if (NULL == pstSslCtx)
	{
		return -1;
	}

	int iRet = SSL_CTX_use_certificate_file(pstSslCtx, szCaPath, SSL_FILETYPE_PEM);
	if (1 == iRet)
	{
		strncpy(g_acCertPwd, cpcPwd, sizeof(g_acCertPwd));
		SSL_CTX_set_default_passwd_cb(pstSslCtx, _dtls_PwdCb);

		iRet = SSL_CTX_use_PrivateKey_file(pstSslCtx, szKeyPath, SSL_FILETYPE_PEM);
	}	
	
	if (1 == iRet)
	{
		iRet = SSL_CTX_check_private_key(pstSslCtx);
	}
	
	/*if (1 == iRet)
	{
		iRet = SSL_CTX_load_verify_locations(pstSslCtx, szKeyPath, NULL);
	}*/
	
	if (1 == iRet)
	{
		iRet = SSL_CTX_set_default_verify_paths(pstSslCtx);
	}

	if (1 == iRet)
	{
		SSL_CTX_set_verify(pstSslCtx, 
					       SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
					       _dtls_VerifyCb);
		g_pstSslCtx = pstSslCtx;
		
		return 0;
	}	
	else
	{
		SSL_CTX_free(pstSslCtx);
		pstSslCtx = NULL;

		return -1;
	}	
}

bool USERVER_DTLS_IsHandshakePkt(IN const char* pcData)
{
	if (NULL != pcData)
	{
		return ((*pcData) & 0xFF) == SSL3_RT_HANDSHAKE ||
			   ((*pcData) & 0xFF) == SSL3_RT_CHANGE_CIPHER_SPEC;
	}

	return false;
}

bool USERVER_DTLS_IsDataPkt(IN const char* pcData)
{
	if (NULL != pcData)
	{
		return ((*pcData) & 0xFF) == SSL3_RT_APPLICATION_DATA;
	}

	return false;
}

bool USERVER_DTLS_Handshake(IN SSL* pstSSL)
{
	if (NULL == pstSSL)
	{
		return false;
	}	

	/* 已经握手完成，直接返回即可 */
	if (SSL_ST_OK == SSL_state(pstSSL))
	{
		return true;
	}

	int iRet = SSL_do_handshake(pstSSL);
	if (0 == iRet) 
	{
		return true;/* 正常中止，controlled shutdown */
	}
	else if (iRet < 0)
	{
		int iErr = SSL_get_error(pstSSL, iRet);
		if (SSL_ERROR_WANT_READ == iErr ||
			SSL_ERROR_WANT_WRITE == iErr)
		{
			return true; /* 正常中止，非阻塞握手 */
		}
		else
		{
			return false; /* 出错 */
		}
	}
	else
	{
		return true; /* 握手成功 */
	}

	return false;
}

bool USERVER_DTLS_InitSess(IN const USERVER_DTLS_SOCK_S* pstSockout, INOUT USERVER_DTLS_SESSION_S* pstSess)
{
	if (NULL == pstSockout || NULL == pstSess)
	{
		return false;
	}

	SSL* pstSSL = SSL_new(g_pstSslCtx);
	if (NULL == pstSSL)
	{
		return false;
	}

	BIO* pstBio = _dtls_CreateBio(pstSockout);
	if (NULL == pstBio)
	{
		SSL_free(pstSSL); /* 清理ssl */
		return false;
	}
	BIO_ctrl(pstBio, BIO_CTRL_DGRAM_SET_MTU, BIO_CTRL_ARG, NULL);

	SSL_set_read_ahead(pstSSL, 1);
	SSL_set_bio(pstSSL, pstBio, pstBio);
	SSL_set_accept_state(pstSSL);

	pthread_mutex_init(&pstSess->stLock, NULL);
	pstSess->pstSSL = pstSSL;

	return true;
}

int USERVER_DTLS_Write(IN USERVER_DTLS_SESSION_S* pstSess, IN const char* cpcBuf, IN unsigned int uiLen)
{
	if (NULL == pstSess || NULL == cpcBuf || 0 == uiLen)
	{
		return -1;
	}

	int iRet = 0;

	pthread_mutex_lock(&(pstSess->stLock));
	iRet = SSL_write(pstSess->pstSSL, cpcBuf, uiLen);	
	pthread_mutex_unlock(&(pstSess->stLock));

	return iRet;
}

int USERVER_DTLS_Read(IN USERVER_DTLS_SESSION_S* pstSess, INOUT char* pcBuf, IN unsigned int uiLen)
{
	if (NULL == pstSess || NULL == pcBuf || 0 == uiLen)
	{
		return -1;
	}

	int iRet = 0;

	pthread_mutex_lock(&(pstSess->stLock));
	iRet = SSL_read(pstSess->pstSSL, pcBuf, uiLen);	
	pthread_mutex_unlock(&(pstSess->stLock));

	return iRet;
}

#ifdef __cplusplus
}
#endif//__cplusplus