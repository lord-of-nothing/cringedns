#include <iostream>
#include <fstream>
#include <string>
#include <unistd.h>
#include <vector>
#include <sstream>
#include <unordered_map>

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

class BytePacket {
public:
    BytePacket() : pos_(0) {
    }

    BytePacket(std::vector<uint8_t> buf) : buf_(std::move(buf)), pos_(0) {
    }

    uint8_t read_byte() {
        if (pos_ >= buf_.size()) throw std::out_of_range("");
        ++pos_;
        return buf_[pos_ - 1];
    }

    void write_byte(uint8_t value) {
        buf_.push_back(value);
        ++pos_;
    }

    uint16_t read_two_bytes() {
        uint8_t first = read_byte();
        uint8_t second = read_byte();
        return (first << 8) | second;
    }

    void write_two_bytes(uint16_t value) {
        buf_.push_back(static_cast<uint8_t>(value >> 8));
        buf_.push_back(static_cast<uint8_t>(value & 0xff));
        pos_ += 2;
    }

    void read_qname(std::string &outstr) {
        size_t pos = pos_;
        bool jumped = false;
        const int max_jumps = 5;
        int jumps_performed = 0;
        std::string delim = "";

        while (true) {
            if (jumps_performed > max_jumps) throw std::runtime_error("Too many jumps in DNS name");

            if (pos >= buf_.size()) throw std::out_of_range("Out of bounds reading domain name");
            uint8_t len = buf_[pos];

            if ((len & 0xC0) == 0xC0) {
                uint16_t b2 = buf_[pos + 1];
                uint16_t offset = (((len & 0x3F) << 8) | b2);
                pos = offset;

                if (!jumped) seek(pos_ + 2);
                jumped = true;
                jumps_performed++;
                continue;
            }

            pos += 1;
            if (len == 0) break;

            outstr += delim;

            if (pos + len > buf_.size()) throw std::out_of_range("Label out of bounds");
            for (size_t i = 0; i < len; ++i) {
                outstr += static_cast<char>(buf_[pos + i]);
            }
            std::transform(outstr.end() - len, outstr.end(), outstr.end() - len, ::tolower);

            delim = ".";
            pos += len;
        }

        if (!jumped) seek(pos);
    }

    size_t size() const { return buf_.size(); }

    auto data() {
        return buf_.data();
    }

private:
    const size_t kMaxLen = 512;
    std::vector<uint8_t> buf_;
    size_t pos_;

    void seek(size_t new_pos) {
        pos_ = new_pos;
    }
};

struct Header {
    uint16_t id = 0;
    bool qr = false;
    uint8_t opcode = 0;
    bool aa = false;
    bool tc = false;
    bool rd = false;
    bool ra = false;
    uint8_t z = 0;
    uint8_t rcode = 0;

    uint16_t qdcount = 0;
    uint16_t ancount = 0;
    uint16_t nscount = 0;
    uint16_t arcount = 0;
};

struct Question {
    std::string domain;
    uint16_t query_type;
    uint16_t query_class;
};

struct Answer {
    std::string domain;
    uint16_t query_type;
    uint16_t query_class;
    uint32_t ttl = 300;
    uint8_t rdlen = 4;
    std::vector<uint8_t> rdata;
};

struct InPacket {
    Header header;
    Question question;
};

struct OutPacket {
    Header header;
    Question question;
    Answer answer;
};

OutPacket resolve(InPacket &&query, const std::unordered_map<std::string, std::vector<uint8_t> > &records) {
    std::optional<std::vector<uint8_t> > serv_addr;
    if (records.contains(query.question.domain)) {
        serv_addr = records.at(query.question.domain);
    }

    Header header = std::move(query.header);
    header.qr = 1;
    header.aa = 1;
    header.ra = 0;
    header.rcode = serv_addr.has_value() ? 0 : 3;
    header.ancount = serv_addr.has_value();
    header.nscount = 0;
    header.arcount = 0;

    Answer answer;
    if (header.ancount) {
        answer.domain = query.question.domain;
        answer.query_type = 1;
        answer.query_class = 1;
        answer.rdata = serv_addr.value();
    }

    OutPacket packet;
    packet.header = header;
    packet.question = query.question;
    packet.answer = answer;
    return packet;
}

BytePacket write_response(const OutPacket &packet) {
    BytePacket out;

    out.write_two_bytes(packet.header.id);

    uint16_t flags = 0;
    flags |= (packet.header.qr & 0x1) << 15;
    flags |= (packet.header.opcode & 0xF) << 11;
    flags |= (packet.header.aa & 0x1) << 10;
    flags |= (packet.header.tc & 0x1) << 9;
    flags |= (packet.header.rd & 0x1) << 8;
    flags |= (packet.header.ra & 0x1) << 7;
    flags |= (packet.header.z & 0x7) << 4;
    flags |= (packet.header.rcode & 0xF);
    out.write_two_bytes(flags);

    out.write_two_bytes(packet.header.qdcount);
    out.write_two_bytes(packet.header.ancount);
    out.write_two_bytes(packet.header.nscount);
    out.write_two_bytes(packet.header.arcount);

    size_t qname_offset = out.size();
    std::string domain = packet.question.domain;
    size_t start = 0;
    while (true) {
        size_t dot = domain.find('.', start);
        size_t len = (dot == std::string::npos) ? domain.size() - start : dot - start;
        out.write_byte(static_cast<uint8_t>(len));
        for (size_t i = 0; i < len; ++i) out.write_byte(domain[start + i]);
        if (dot == std::string::npos) break;
        start = dot + 1;
    }
    out.write_byte(0);

    out.write_two_bytes(packet.question.query_type);
    out.write_two_bytes(packet.question.query_class);

    if (packet.header.ancount) {
        // out.write_byte(0xC0);
        if (qname_offset > 0x3FFF) throw std::runtime_error("QNAME offset too large for pointer");
        // out.write_byte(static_cast<uint8_t>(qname_offset));
        out.write_two_bytes(0xC000 | static_cast<uint16_t>(qname_offset));

        out.write_two_bytes(packet.answer.query_type);
        out.write_two_bytes(packet.answer.query_class);

        out.write_byte((packet.answer.ttl >> 24) & 0xFF);
        out.write_byte((packet.answer.ttl >> 16) & 0xFF);
        out.write_byte((packet.answer.ttl >> 8) & 0xFF);
        out.write_byte(packet.answer.ttl & 0xFF);

        out.write_two_bytes(static_cast<uint16_t>(packet.answer.rdata.size()));

        for (auto b: packet.answer.rdata) out.write_byte(b);
    }

    return out;
}


InPacket parse_request(BytePacket &&data) {
    Header header;

    header.id = data.read_two_bytes();

    uint16_t flags = data.read_two_bytes();
    header.qr = flags >> 15 & 0x1;
    header.opcode = flags >> 11 & 0xf;
    header.aa = flags >> 10 & 0x1;
    header.tc = flags >> 9 & 0x1;
    header.rd = flags >> 8 & 0x1;
    header.ra = flags >> 7 & 0x1;
    header.z = flags >> 4 & 0x7;
    header.rcode = flags & 0xf;

    header.qdcount = data.read_two_bytes();
    header.ancount = data.read_two_bytes();
    header.nscount = data.read_two_bytes();
    header.arcount = data.read_two_bytes();

    Question question;
    if (header.qdcount != 1) {
        throw std::runtime_error("Only single-question queries supported");
    }
    if (header.qdcount > 0) {
        // question.domain = data.read_name();
        data.read_qname(question.domain);
        question.query_type = data.read_two_bytes();
        question.query_class = data.read_two_bytes();
    }

    InPacket result;
    result.header = std::move(header);
    result.question = std::move(question);
    return result;
}

std::unordered_map<std::string, std::vector<uint8_t> > parseConfig(const std::string &filename) {
    std::ifstream file(filename);
    if (!file) {
        perror("No config found");
        exit(EXIT_FAILURE);
    }

    std::unordered_map<std::string, std::vector<uint8_t> > records;
    std::string line;
    while (std::getline(file, line)) {
        if (line.empty() || line[0] == '#') continue;

        std::istringstream iss(line);
        std::string domain, ip_str;
        if (!(iss >> domain >> ip_str)) continue;

        std::vector<uint8_t> ip_bytes(4);
        std::stringstream ss(ip_str);
        std::string octet;
        int i = 0;
        while (std::getline(ss, octet, '.') && i < 4) {
            ip_bytes[i++] = static_cast<uint8_t>(std::stoi(octet));
        }
        if (i == 4) records[domain] = ip_bytes;
    }

    return records;
}

int main() {
    auto records = parseConfig("config.txt");

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    char buffer[512];
    if (sock < 0) {
        perror("Can't create socket");
        return 1;
    }

    struct sockaddr_in servaddr{}, cliaddr{};
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    servaddr.sin_port = htons(29531);

    if (bind(sock, (struct sockaddr *) &servaddr, sizeof(servaddr)) < 0) {
        perror("Bind error");
        return 1;
    }

    std::cout << "Listening on 127.0.0.1:29531..." << std::endl;

    socklen_t len;
    int n;

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
