#include <openssl/ssl.h>
#include <linux/if_tun.h>
#include <libnet.h>

#define BUFFER_SIZE 1024

void assert(int condition, const char *format, ...) { // substitution of C assert
    if (!condition) {
        va_list args;
        va_start(args, format);
        vprintf(format, args);
        va_end(args);
        exit(EXIT_FAILURE);
    }
}

int createTUNDevice() {
    struct ifreq ifr = {0};
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    int tun = open("/dev/net/tun", O_RDWR);
    ioctl(tun, TUNSETIFF, &ifr);
    return tun;
}

int createConnection(const char *name, int port) {
    // resolve host
    struct hostent *host = gethostbyname(name);
    assert(host != NULL, "Failed to get hostname %s: %s\n", name, strerror(errno));
    // server socket address
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = *(long *) (host->h_addr);
    // create client socket
    int sd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    assert(sd != -1, "Failed to create socket: %s\n", strerror(errno));
    // connect to server
    int status = connect(sd, (struct sockaddr *) &addr, sizeof(addr));
    assert(!status, "Failed to connect %s: %s\n", name, strerror(errno));
    return sd;
}

int verifyCallback(int status, X509_STORE_CTX *ctx) {
    // check status
    assert(status == 1, "Failed to verify: %s\n", X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx)));
    // display cert info
    X509 *cert = X509_STORE_CTX_get_current_cert(ctx);
    printf("Server certificates:\n");
    printf("Subject: %s\n", X509_NAME_oneline(X509_get_subject_name(cert), 0, 0));
    printf("Issuer: %s\n", X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0));
    return 1;
}

SSL_CTX *createSSLContext(char *ca) {
    // init OpenSSL
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    // create SSL context
    SSL_CTX *ctx = SSL_CTX_new(TLSv1_2_client_method());
    assert(ctx != NULL, "Failed to initialize SSL\n");
    // enable verification and load CA
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verifyCallback);
    assert(SSL_CTX_load_verify_locations(ctx, NULL, ca) >= 1, "Failed to locate %s\n", ca);
    return ctx;
}

void handshake(SSL *ssl, char* ip) { // inform server of client's tun0 IP
    int addr = inet_addr(ip);
    SSL_write(ssl, &addr, 4);
}

void authenticate(SSL *ssl) {
    while (1) { // loop until authenticated
        // get username and password
        char username[256];
        printf("username: ");
        scanf("%s", username);
        getchar();
        char *password = getpass("password: ");

        // concat with their length and send to server
        char data[BUFFER_SIZE] = {0};
        int len = sprintf(data, "%c%s%c%s", strlen(username), username, strlen(password), password);
        SSL_write(ssl, data, len);

        // get response
        char response[BUFFER_SIZE] = {0};
        SSL_read(ssl, response, BUFFER_SIZE);
        if (response[0]) {
            printf("Logged in as %s\n", username);
            return;
        }
        printf("Authentication failed\n");
    }
}

int main(int argc, char **argv) {
    assert(getuid() == 0, "Permission denied.\n");
    assert(argc == 4, "Usage: %s <hostname> <port> <tun_ip>\n", argv[0]);
    // preparations
    int tun = createTUNDevice();
    int connection = createConnection(argv[1], atoi(argv[2]));
    SSL_CTX *ctx = createSSLContext("./ca_client");
    // create SSL structure for connection
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, connection);
    assert(SSL_connect(ssl) != -1, "Failed to connect\n");
    // handshake with server
    handshake(ssl, argv[3]);
    // send authentication request
    authenticate(ssl);

    fd_set readFDSet;
    while (1) { // loop until server disconnected
        FD_ZERO(&readFDSet);
        FD_SET(connection, &readFDSet);
        FD_SET(tun, &readFDSet);
        select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);
        if (FD_ISSET(tun, &readFDSet)) { // data from TUN
            // TUN -> SSL
            char buf[BUFFER_SIZE] = {0};
            int len = read(tun, buf, BUFFER_SIZE);
            SSL_write(ssl, buf, len);
        } else if (FD_ISSET(connection, &readFDSet)) { // data from server
            // SSL -> TUN
            char buf[BUFFER_SIZE] = {0};
            int len = SSL_read(ssl, buf, BUFFER_SIZE);
            if (!len) { // server disconnected
                printf("Connection reset by peer\n");
                break;
            }
            write(tun, buf, len);
        }
    }
    // clean up
    SSL_shutdown(ssl);
    SSL_free(ssl);
    shutdown(connection, SHUT_RDWR);
    close(connection);
    shutdown(tun, SHUT_RDWR);
    close(tun);
}
