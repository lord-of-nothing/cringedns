#pragma once
#include <fstream>
#include <cstdint>
#include <string>
#include <vector>
#include <sstream>
#include <unordered_map>
#include <sys/types.h>
#include "objects.hpp"
#include <optional>
#include <algorithm>

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

std::unordered_map<std::string, std::vector<uint8_t> > parse_config(const std::string &filename) {
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