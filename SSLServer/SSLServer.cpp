#include <string.h>
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/applink.c>

#pragma comment(lib, "Ws2_32.lib")

#define DEFAULT_PORT "27015"
#define FAIL -1

/**
* Returns the listen socket or 0 if there is an error.
*/
int OpenListener()
{
	int iResult;
	WSADATA wsaData;

	// Initialize Winsock
	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0) {
		printf("WSAStartup failed: %d\n", iResult);
		return 0;
	}

	struct addrinfo* result = NULL, * ptr = NULL, hints;

	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_PASSIVE;

	// Resolve the local address and port to be used by the server
	iResult = getaddrinfo(NULL, DEFAULT_PORT, &hints, &result);
	if (iResult != 0) {
		printf("getaddrinfo failed: %d\n", iResult);
		WSACleanup();
		return 0;
	}

	SOCKET ListenSocket = INVALID_SOCKET;
	// Create a SOCKET for the server to listen for client connections
	ListenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
	if (ListenSocket == INVALID_SOCKET) {
		printf("Error at socket(): %ld\n", WSAGetLastError());
		freeaddrinfo(result);
		WSACleanup();
		return 0;
	}

	// Setup the TCP listening socket
	iResult = bind(ListenSocket, result->ai_addr, (int)result->ai_addrlen);
	if (iResult == SOCKET_ERROR) {
		printf("bind failed with error: %d\n", WSAGetLastError());
		freeaddrinfo(result);
		closesocket(ListenSocket);
		WSACleanup();
		return 0;
	}

	freeaddrinfo(result);

	if (listen(ListenSocket, SOMAXCONN) == SOCKET_ERROR) {
		printf("Listen failed with error: %ld\n", WSAGetLastError());
		closesocket(ListenSocket);
		WSACleanup();
		return 0;
	}

	return ListenSocket;
}


SSL_CTX* InitServerCTX(void)
{
	const SSL_METHOD* method;
	SSL_CTX* ctx;

	OpenSSL_add_all_algorithms();  /* load & register all cryptos, etc. */
	SSL_load_error_strings();   /* load all error messages */
	method = TLS_server_method();  /* create new server-method instance */
	ctx = SSL_CTX_new(method);   /* create new context from method */
	if (ctx == NULL)
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	return ctx;
}

void LoadCertificates(SSL_CTX* ctx, const char* CertFile, const char* KeyFile)
{
	/* set the local certificate from CertFile */
	if (SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0)
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	/* set the private key from KeyFile (may be the same as CertFile) */
	if (SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0)
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	/* verify private key */
	if (!SSL_CTX_check_private_key(ctx))
	{
		fprintf(stderr, "Private key does not match the public certificate\n");
		abort();
	}
}

void ShowCerts(SSL* ssl)
{
	X509* cert;
	char* line;

	cert = SSL_get_peer_certificate(ssl); /* Get certificates (if available) */
	if (cert != NULL)
	{
		printf("Server certificates:\n");
		line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
		printf("Subject: %s\n", line);
		free(line);
		line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
		printf("Issuer: %s\n", line);
		free(line);
		X509_free(cert);
	}
	else
		printf("No certificates.\n");
}

void Servlet(SSL* ssl) /* Serve the connection -- threadable */
{
	char buf[1024];
	char reply[1024];
	int sd, bytes;
	const char* HTMLecho = "<html><body><pre>%s</pre></body></html>\n\n";

	if (SSL_accept(ssl) == FAIL)     /* do SSL-protocol accept */
		ERR_print_errors_fp(stderr);
	else
	{
		ShowCerts(ssl);        /* get any certificates */
		bytes = SSL_read(ssl, buf, sizeof(buf)); /* get request */
		if (bytes > 0)
		{
			buf[bytes] = 0;
			printf("Client msg: \"%s\"\n", buf);
			sprintf_s(reply, HTMLecho, buf);   /* construct reply */
			SSL_write(ssl, reply, strlen(reply)); /* send reply */
		}
		else
			ERR_print_errors_fp(stderr);
	}
	sd = SSL_get_fd(ssl);       /* get socket connection */
	SSL_free(ssl);         /* release SSL state */
	closesocket(sd);          /* close connection */
}

// Pour générer le certificat mycert.pem, dans le terminal:
// ...> 	Ø openssl req -conf "C:\Program Files\OpenSSL-Win64\bin\cnf\openssl.cnf" -x509 -nodes -days 365 -newkey rsa:1024 -keyout mycert.pem -out mycert.pem

int main()
{
	SSL_CTX* ctx;
	SOCKET listenSocket = INVALID_SOCKET;

	SSL_library_init();

	ctx = InitServerCTX();        /* initialize SSL */
	LoadCertificates(ctx, "E:\\Dev\\Sources\\repos\\SSLClientServerProto\\x64\\Debug\\mycert.pem", "E:\\Dev\\Sources\\repos\\SSLClientServerProto\\x64\\Debug\\mycert.pem"); /* load certs */

	
	listenSocket = OpenListener();    /* create server socket */
	while (1)
	{
		SOCKET ClientSocket = INVALID_SOCKET;
		SSL* ssl;

		// Accept a client socket
		printf("Waiting a client ...\n");
		ClientSocket = accept(listenSocket, NULL, NULL);
		if (ClientSocket == INVALID_SOCKET) {
			printf("accept failed: %d\n", WSAGetLastError());
			closesocket(listenSocket);
			WSACleanup();
			return 1;
		}

		printf("Client accepted ...\n");

		ssl = SSL_new(ctx);              /* get new SSL state with context */
		SSL_set_fd(ssl, ClientSocket);      /* set connection socket to SSL state */
		Servlet(ssl);         /* service connection */
	}

	closesocket(listenSocket);          /* close server socket */
	SSL_CTX_free(ctx);         /* release context */
}
