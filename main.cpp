#include <iostream>
#include <fstream>
#include <string>
#include <unistd.h>
#include <vector>
#include <unordered_map>

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "funcs.hpp"

int main(int argc, char* argv[]) {
    int port = 53535;
    std::string config_file = "config.txt";
    if (argc == 2) {
        config_file = argv[1];
    } else {
        std::cout << "Defaulting to config.txt as a configuration file" << std::endl;
    }

    auto records = parse_config(config_file);

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    char buffer[512];
    if (sock < 0) {
        perror("Can't create socket");
        return 1;
    }

    struct sockaddr_in servaddr{}, cliaddr{};
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    servaddr.sin_port = htons(port);

    if (bind(sock, (struct sockaddr *) &servaddr, sizeof(servaddr)) < 0) {
        perror("Bind error");
        return 1;
    }

    std::cout << "Listening on 127.0.0.1:" << port << std::endl;

    while (true) {
        socklen_t len = sizeof(cliaddr);

        ssize_t n = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *) &cliaddr, &len);
        if (n < 0) {
            perror("Recvfrom failure");
            continue;
        }

        std::cout << "Received " << n << " bytes from "
                << inet_ntoa(cliaddr.sin_addr) << ":"
                << ntohs(cliaddr.sin_port) << "\n";


        std::vector<uint8_t> data(buffer, buffer + n);
        BytePacket pkt(data);

        try {
            InPacket query = parse_request(std::move(pkt));
            // std::cout << "ID: " << query.header.id << "\n";
            // std::cout << "QR: " << query.header.qr << " RD: " << query.header.rd
            //           << " QDCOUNT: " << query.header.qdcount << "\n";
            // std::cout << "Domain: " << query.question.domain << "\n";
            // std::cout << "Type: " << query.question.query_type
            //           << " Class: " << query.question.query_class << "\n";


            OutPacket response = resolve(std::move(query), records);

            BytePacket out_bytes = write_response(response);

            ssize_t sent = sendto(sock, out_bytes.data(), out_bytes.size(), 0,
                                  (struct sockaddr *) &cliaddr, len);
            if (sent < 0) {
                perror("Sendto failure");
            } else {
                std::cout << "Sent " << sent << " bytes back to client\n";
            }
        } catch (...) {
            std::cout << "Failed to parse DNS packet\n";
        }
    }
}
