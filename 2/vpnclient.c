#include <linux/if_tun.h>
#include <libnet.h>

#define BUFFER_SIZE 2000
#define PORT_NUMBER 55555
#define SERVER_IP "10.0.2.9"

struct sockaddr_in peerAddr = {0};

int createTUNDevice() {
    struct ifreq ifr = {0};
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    int tunfd = open("/dev/net/tun", O_RDWR);
    ioctl(tunfd, TUNSETIFF, &ifr);
    return tunfd;
}

int connectToUDPServer() {
    char *hello = "Hello";

    peerAddr.sin_family = AF_INET;
    peerAddr.sin_port = htons(PORT_NUMBER);
    peerAddr.sin_addr.s_addr = inet_addr(SERVER_IP);

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    // Send a hello message to "connect" with the VPN server
    sendto(sockfd, hello, strlen(hello), 0, (struct sockaddr *) &peerAddr, sizeof(peerAddr));

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

int main() {
    int tunfd = createTUNDevice();
    int sockfd = connectToUDPServer();

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
 
