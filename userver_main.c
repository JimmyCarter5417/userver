#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <string.h>
#include <stdbool.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <errno.h>
#include "common/public.h"
#include "userver_dtls.h"



#ifdef __cplusplus
extern "C" {
#endif

int main(int argc, char* argv[])
{
	int iRet = 0;

	int iListenFd = socket(AF_INET, SOCK_DGRAM, 0);
	if (iListenFd < 0)
	{
		return -1;
	}

	struct sockaddr_in stServerAddr;
	memset(&stServerAddr, 0, sizeof(stServerAddr));
	stServerAddr.sin_family = AF_INET;
	//stServerAddr.sin_addr.s_addr = htonl(INADDR_ANY);
	stServerAddr.sin_port = htons(36002);

	int iSndBufSize = 128 * 1024;
	int iOptLen = sizeof(iSndBufSize);
	int tmp = setsockopt(iListenFd, SOL_SOCKET, SO_SNDBUF, &iSndBufSize, iOptLen);

	int iRecvBufSize = 128 * 1024;
	iOptLen = sizeof(iRecvBufSize);
	tmp = setsockopt(iListenFd, SOL_SOCKET, SO_SNDBUF, &iRecvBufSize, iOptLen);

	int iOpt = 1;
	tmp = ioctl(iListenFd, FIONBIO, &iOpt);

	if (bind(iListenFd, (struct sockaddr*)&stServerAddr, sizeof(stServerAddr)) < 0)
	{
		printf("bind fail: %d\n", errno);
		return -1;
	}

	int iEpFd = epoll_create(100);
	if (iEpFd < 0)
	{
		printf("epoll_create fail\n");
		return -1;
	}	

	struct epoll_event stEv;
	stEv.data.fd = iListenFd;
	stEv.events = (EPOLLIN | EPOLLET);
	if (0 != epoll_ctl(iEpFd, EPOLL_CTL_ADD, iListenFd, &stEv))
	{
		printf("epoll_ctl add fail\n");
		return -1;
	}
	
	_dtls_InitSslCtx("serverkey.pem", "servercert.pem", "123456");
	
	struct epoll_event astEv[100];
	SSL *ssl = NULL;
	USERVER_DTLS_SOCK_S stSock;
	USERVER_DTLS_SESSION_S stSess;
	memset(&stSess, 0, sizeof(stSess));

	while (1)
	{
		int iNum = epoll_wait(iEpFd, astEv, 100, -1);
		printf("got msg\n");

		for (int i = 0; i < iNum; i++)
		{
			char buf[1024] = {0};
			socklen_t len = sizeof(struct sockaddr_in);

			int  iRecv = recvfrom(iListenFd, buf, 1024, 0, (struct sockaddr *)&stSock.stPeerAddr, &len);
			if (iRecv <= 0)
			{
				printf("recv done\n");
				continue;
			}
			if (USERVER_DTLS_IsHandshakePkt(buf))
			{
				if (NULL == stSess.pstSSL) 
					USERVER_DTLS_InitSess(&stSock, &stSess);

				if (USERVER_DTLS_Handshake(stSess.pstSSL))
					printf("handshake done\n");
				else
					printf("handshake not done\n");
			}
			else if (USERVER_DTLS_IsDataPkt(buf))
			{
				printf("data done\n");
			}
		}
	}
}



#ifdef __cplusplus
}
#endif//__cplusplus

