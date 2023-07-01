#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

//compiled with gcc -Wall -o tls_client tls_client.c -lssl -lcrypto
//Some of the code was taken from this post: https://stackoverflow.com/questions/52727565/client-in-c-use-gethostbyname-or-getaddrinfo

const int ERROR_STATUS = -1;

SSL_CTX *InitSSL_CTX(void)
{
    const SSL_METHOD *method = TLS_client_method(); /* Create new client-method instance */
    SSL_CTX *ctx = SSL_CTX_new(method);
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    if (ctx == NULL)
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    //no ca verify
#if 0
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    if (SSL_CTX_set_default_verify_paths(ctx) != 1)
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if(SSL_CTX_load_verify_locations(ctx, ca_cert_file,ca_cert_dir) <= 0)
        ERR_print_errors_fp(stderr);
#endif
    return ctx;
}

int OpenConnection(const char *hostname, const char *port)
{
    struct hostent *host;
    if ((host = gethostbyname(hostname)) == NULL)
    {
        perror(hostname);
        exit(EXIT_FAILURE);
    }
    struct addrinfo hints = {0}, *addrs;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    const int status = getaddrinfo(hostname, port, &hints, &addrs);
    if (status != 0)
    {
        fprintf(stderr, "%s: %s\n", hostname, gai_strerror(status));
        exit(EXIT_FAILURE);
    }

    int sfd, err;
    for (struct addrinfo *addr = addrs; addr != NULL; addr = addr->ai_next)
    {
        sfd = socket(addrs->ai_family, addrs->ai_socktype, addrs->ai_protocol);
        if (sfd == ERROR_STATUS)
        {
            err = errno;
            continue;
        }
        if (connect(sfd, addr->ai_addr, addr->ai_addrlen) == 0)
        {
            break;
        }
        err = errno;
        sfd = ERROR_STATUS;
        close(sfd);
    }
    freeaddrinfo(addrs);
    if (sfd == ERROR_STATUS)
    {
        fprintf(stderr, "%s: %s\n", hostname, strerror(err));
        exit(EXIT_FAILURE);
    }
    return sfd;
}

void DisplayCerts(SSL *ssl)
{
    X509 *cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
    if (cert != NULL)
    {
        printf("Server certificates:\n");
        char *line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);
        X509_free(cert);
    }
    else
    {
        printf("Info: No client certificates configured.\n");
    }
}

int main(int argc, char const *argv[])
{
    SSL_CTX *ctx = InitSSL_CTX();
    SSL *ssl = SSL_new(ctx);
    if (ssl == NULL)
    {
        fprintf(stderr, "SSL_new() failed\n");
        exit(EXIT_FAILURE);
    }

    //print default ca file
    //puts(X509_get_default_cert_file());

    //Host is hardcoded to localhost for testing purposes
    const int sfd = OpenConnection("127.0.0.1", argv[1]);
    SSL_set_fd(ssl, sfd);

    const int status = SSL_connect(ssl);
    if (status != 1)
    {
        SSL_get_error(ssl, status);
        ERR_print_errors_fp(stderr); //High probability this doesn't do anything
        fprintf(stderr, "SSL_connect failed with SSL_get_error code %d\n", status);
        exit(EXIT_FAILURE);
    }
    printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
    DisplayCerts(ssl);
    //no verify
#if 0
    int err = SSL_get_verify_result(ssl);
    if(err != X509_V_OK)
    {
        const char *message = X509_verify_cert_error_string(err);
        fprintf(stderr, "Certificate verification error: %s (%d)\n", message, err);
    }
#endif
    const char *chars = "Client Hello !";
    SSL_write(ssl, chars, strlen(chars));
    char buf[1024];
    int bytes = SSL_read(ssl, buf, sizeof(buf));
    buf[bytes] = 0;
    printf("Received: \"%s\"\n", buf);
    SSL_free(ssl);
    close(sfd);
    SSL_CTX_free(ctx);
    return 0;
}
