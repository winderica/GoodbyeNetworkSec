#include <openssl/ssl.h>
#include <linux/if_tun.h>
#include <libnet.h>
#include <shadow.h>

#define BUFFER_SIZE 1024

// struct for IP header
struct IPHeader {
    uint8_t header_length: 4, version: 4;
    uint8_t tos;
    uint16_t total_length;
    uint16_t id;
    uint16_t offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
};

// struct for client queue (doubly linked)
struct Client {
    SSL *ssl;
    uint32_t ip;
    int verified;
    struct Client *prev;
    struct Client *next;
};

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

int createServer(int port) {
    // server socket address
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    // create server socket
    int sd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    assert(sd != -1, "Failed to create socket: %s\n", strerror(errno));
    // assign address to sd
    int status = bind(sd, (struct sockaddr *) &addr, sizeof(addr));
    // OS will close sd automatically when program exits, so no cleanup is needed.
    assert(!status, "Can't bind port: %s\n", strerror(errno));
    // listen on sd, max queue size is 10
    status = listen(sd, 10);
    assert(!status, "Can't configure listening port: %s\n", strerror(errno));
    return sd;
}

SSL_CTX *createSSLContext(char *cert, char *key) {
    // init OpenSSL
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    // create SSL context
    SSL_CTX *ctx = SSL_CTX_new(TLSv1_2_server_method());
    assert(ctx != NULL, "Failed to initialize SSL\n");
    // load certificate and private key
    assert(SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) > 0, "Failed to load %s\n", cert);
    assert(SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) > 0, "Failed to load %s\n", key);
    assert(SSL_CTX_check_private_key(ctx), "%s doesn't match %s\n", key, cert);
    return ctx;
}

void authenticate(struct Client *client, SSL *ssl, const char *buf) {
    // get username and password
    // "%c%s%c%s", strlen(username), username, strlen(password), password
    char username[256] = {0};
    char password[256] = {0};
    strncpy(username, buf + 1, buf[0]);
    strncpy(password, buf + buf[0] + 2, buf[buf[0] + 1]);
    // then verify them
    struct spwd *pw = getspnam(username);
    if (pw && !strcmp(crypt(password, pw->sp_pwdp), pw->sp_pwdp)) {
        SSL_write(ssl, "\1", 1);
        client->verified = 1;
    } else {
        SSL_write(ssl, "\0", 1);
    }
}

struct Client *initQueue() {
    // create a queue pointer, whose prev node and next node are itself
    struct Client *queue = calloc(1, sizeof(struct Client));
    queue->prev = queue;
    queue->next = queue;
    return queue;
}

void newClient(struct Client *client, SSL *ssl, int ip) {
    // insert client to the tail of queue
    struct Client *tail = client->prev;
    client->prev = calloc(1, sizeof(struct Client));
    tail->next = client->prev;
    client->prev->prev = tail;
    client->prev->ssl = ssl;
    client->prev->ip = ip;
    client->prev->next = client;
}

void deleteClient(struct Client *client) {
    // remove client from queue
    client->prev->next = client->next;
    client->next->prev = client->prev;
    free(client);
}

int handshake(SSL *ssl) { // receive client's tun0 IP
    // union is useful here
    union {
        char buf[BUFFER_SIZE];
        struct in_addr in_addr;
    } data = {0};
    SSL_read(ssl, data.buf, BUFFER_SIZE);
    int ip = data.in_addr.s_addr;
    return ip;
}

int main(int argc, char **argv) {
    assert(getuid() == 0, "Permission denied.\n");
    assert(argc == 2, "Usage: %s <port>\n", argv[0]);
    // preparations
    int tun = createTUNDevice();
    SSL_CTX *ctx = createSSLContext("./cert_server/server.pem", "./cert_server/server-key.pem");
    int server = createServer(atoi(argv[1]));
    struct Client *queue = initQueue();

    fd_set readFDSet;
    while (1) {
        FD_ZERO(&readFDSet);
        FD_SET(server, &readFDSet);
        FD_SET(tun, &readFDSet);
        for (struct Client *i = queue->next; i != queue; i = i->next) {
            FD_SET(SSL_get_fd(i->ssl), &readFDSet);
        }
        select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);
        if (FD_ISSET(server, &readFDSet)) { // new connection
            // accept it
            struct sockaddr_in addr;
            socklen_t size = sizeof(addr);
            int connection = accept(server, (struct sockaddr *) &addr, &size);
            // and create SSL structure for it
            SSL *ssl = SSL_new(ctx);
            SSL_set_fd(ssl, connection);
            assert(SSL_accept(ssl) != -1, "Failed to accept\n");
            printf("Connection from %s:%d accepted\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
            // get tun0 ip of client in handshake
            int ip = handshake(ssl);
            // and create a new client
            newClient(queue, ssl, ip);
        } else if (FD_ISSET(tun, &readFDSet)) { // data from TUN
            union {
                char buf[BUFFER_SIZE];
                struct IPHeader ipHeader;
            } data = {0};
            int len = read(tun, data.buf, BUFFER_SIZE);
            for (struct Client *i = queue->next; i != queue; i = i->next) {
                if (i->ip == data.ipHeader.dst_ip) { // find the corresponding client
                    // TUN -> SSL
                    SSL_write(i->ssl, data.buf, len);
                    // no break here in case of multiple connections from one IP
                }
            }
        } else {
            for (struct Client *i = queue->next; i != queue; i = i->next) {
                SSL *ssl = i->ssl;
                int connection = SSL_get_fd(ssl);
                if (!FD_ISSET(connection, &readFDSet)) { // no data from client
                    continue;
                }
                // SSL -> TUN
                char buf[BUFFER_SIZE] = {0};
                int len = SSL_read(ssl, buf, BUFFER_SIZE);
                if (len) {
                    i->verified ? write(tun, buf, len) : authenticate(i, ssl, buf);
                } else { // client disconnected
                    struct sockaddr_in addr;
                    socklen_t size = sizeof(addr);
                    getpeername(connection, (struct sockaddr *) &addr, &size);
                    printf("Connection from %s:%d closed\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
                    // clean up
                    SSL_shutdown(ssl);
                    SSL_free(ssl);
                    shutdown(connection, SHUT_RDWR);
                    close(connection);
                    deleteClient(i);
                }
            }
        }
    }
}
