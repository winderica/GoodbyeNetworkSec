#include <linux/if_tun.h>
#include <libnet.h>

#define PORT_NUMBER 55555
#define BUFFER_SIZE 2000

struct sockaddr_in peerAddr;

int createTUNDevice() {
    struct ifreq ifr = {0};
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    int tunfd = open("/dev/net/tun", O_RDWR);
    ioctl(tunfd, TUNSETIFF, &ifr);
    return tunfd;
}

int initUDPServer() {
    struct sockaddr_in server = {0};
    char buff[100] = {0};

    server.sin_family = AF_INET;
    server.sin_addr.s_addr = htonl(INADDR_ANY);
    server.sin_port = htons(PORT_NUMBER);

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    bind(sockfd, (struct sockaddr *) &server, sizeof(server));

    // Wait for the VPN client to "connect".
    socklen_t peerAddrLen = sizeof(struct sockaddr_in);
    recvfrom(sockfd, buff, 100, 0, (struct sockaddr *) &peerAddr, &peerAddrLen);

    printf("Connected with the client: %s\n", buff);
    return sockfd;
}

void tunSelected(int tunfd, int sockfd) {
    char buff[BUFFER_SIZE] = {0};

    printf("Got a packet from TUN\n");

    int len = read(tunfd, buff, BUFFER_SIZE);
    sendto(sockfd, buff, len, 0, (struct sockaddr *) &peerAddr, sizeof(peerAddr));
}

void socketSelected(int tunfd, int sockfd) {
    char buff[BUFFER_SIZE] = {0};

    printf("Got a packet from the tunnel\n");

    int len = recvfrom(sockfd, buff, BUFFER_SIZE, 0, NULL, NULL);
    write(tunfd, buff, len);
}

int main(int argc, char *argv[]) {
    int tunfd = createTUNDevice();
    int sockfd = initUDPServer();

    // Enter the main loop
    while (1) {
        fd_set readFDSet;

        FD_ZERO(&readFDSet);
        FD_SET(sockfd, &readFDSet);
        FD_SET(tunfd, &readFDSet);
        select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);

        if (FD_ISSET(tunfd, &readFDSet)) tunSelected(tunfd, sockfd);
        if (FD_ISSET(sockfd, &readFDSet)) socketSelected(tunfd, sockfd);
    }
}
 
