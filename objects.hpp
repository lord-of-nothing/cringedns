#pragma once
#include <iostream>
#include <string>
#include <cstdint>
#include <algorithm>
#include <vector>

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