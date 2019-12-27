#include <WinSock2.h>
#include <WS2tcpip.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/applink.c>
#include <stdio.h>
#include <iostream>

// link with Ws2_32.lib
#pragma comment (lib, "Ws2_32.lib")

#define DEFAULT_PORT "27015"
#define FAIL -1

/**
* Returns the connect socket or 0 if there is an error.
*/
int OpenConnection()
{
	WSADATA wsaData;
	int iResult;

	// Initialize Winsock
	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0) {
		printf("WSAStartup failed: %d\n", iResult);
		return 0;
	}

	struct addrinfo* result = NULL,
		* ptr = NULL,
		hints;

	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;



	// Resolve the server address and port
	iResult = getaddrinfo("127.0.0.1", DEFAULT_PORT, &hints, &result);
	if (iResult != 0) {
		printf("getaddrinfo failed: %d\n", iResult);
		WSACleanup();
		return 0;
	}

	SOCKET ConnectSocket = INVALID_SOCKET;
	// Attempt to connect to the first address returned by
	// the call to getaddrinfo
	ptr = result;

	// Create a SOCKET for connecting to server
	ConnectSocket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
	if (ConnectSocket == INVALID_SOCKET) {
		printf("Error at socket(): %ld\n", WSAGetLastError());
		freeaddrinfo(result);
		WSACleanup();
		return 0;
	}

	// Connect to server.
	iResult = connect(ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
	if (iResult == SOCKET_ERROR) {
		closesocket(ConnectSocket);
		ConnectSocket = INVALID_SOCKET;
	}

	// Should really try the next address returned by getaddrinfo
	// if the connect call failed
	// But for this simple example we just free the resources
	// returned by getaddrinfo and print an error message

	freeaddrinfo(result);

	if (ConnectSocket == INVALID_SOCKET) {
		printf("Unable to connect to server!\n");
		WSACleanup();
		return 0;
	}

	return ConnectSocket;
}

SSL_CTX* InitCTX(void)
{
	const SSL_METHOD* method;
	SSL_CTX* ctx;

	OpenSSL_add_all_algorithms();  /* Load cryptos, et.al. */
	SSL_load_error_strings();   /* Bring in and register error messages */
	method = TLS_client_method();  /* Create new client-method instance */
	ctx = SSL_CTX_new(method);   /* Create new context */
	if (ctx == NULL)
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	return ctx;
}

void parseCert(X509* x509)
{
	std::cout << "--------------------" << std::endl;
	BIO* bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);

	long l = X509_get_version(x509);
	BIO_printf(bio_out, "Version: %ld\n", l + 1);

	ASN1_INTEGER* bs = X509_get_serialNumber(x509);
	BIO_printf(bio_out, "Serial: ");
	for (int i = 0; i < bs->length; i++) {
		BIO_printf(bio_out, "%02x", bs->data[i]);
	}
	BIO_printf(bio_out, "\n");

	BIO_printf(bio_out, "Issuer: ");
	X509_NAME_print(bio_out, X509_get_issuer_name(x509), 0);
	BIO_printf(bio_out, "\n");

	BIO_printf(bio_out, "Valid From: ");
	ASN1_TIME_print(bio_out, X509_get_notBefore(x509));
	BIO_printf(bio_out, "\n");

	BIO_printf(bio_out, "Valid Until: ");
	ASN1_TIME_print(bio_out, X509_get_notAfter(x509));
	BIO_printf(bio_out, "\n");

	BIO_printf(bio_out, "Subject: ");
	X509_NAME_print(bio_out, X509_get_subject_name(x509), 0);
	BIO_printf(bio_out, "\n");

	EVP_PKEY* pkey = X509_get_pubkey(x509);
	EVP_PKEY_print_public(bio_out, pkey, 0, NULL);
	EVP_PKEY_free(pkey);

	BIO_free(bio_out);
}

void ShowCerts(SSL* ssl)
{
	X509* cert;
	char* line;
	char* line2;

	cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
	if (cert != NULL)
	{
		parseCert(cert);
		X509_free(cert);     /* free the malloc'ed certificate copy */
	}
	else
		printf("Info: No client certificates configured.\n");
}

int main()
{
	SSL_CTX* ctx;
	SSL* ssl;
	char buf[1024];
	int bytes;
	SOCKET connectSocket = INVALID_SOCKET;

	SSL_library_init();
	ctx = InitCTX();

	connectSocket = OpenConnection();
	ssl = SSL_new(ctx);      /* create new SSL connection state */
	SSL_set_fd(ssl, connectSocket);    /* attach the socket descriptor */

	if (SSL_connect(ssl) == FAIL)   /* perform the connection */
		ERR_print_errors_fp(stderr);
	else
	{
		const char* msg = "Hello???";

		printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
		ShowCerts(ssl);        /* get any certs */
		SSL_write(ssl, msg, strlen(msg));   /* encrypt & send message */
		bytes = SSL_read(ssl, buf, sizeof(buf)); /* get reply & decrypt */
		buf[bytes] = 0;
		printf("Received: \"%s\"\n", buf);
		SSL_free(ssl);        /* release connection state */
	}

	closesocket(connectSocket);         /* close socket */
	SSL_CTX_free(ctx);        /* release context */
	return 0;
}


