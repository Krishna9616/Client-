#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <algorithm>
#include <set>
#include <iomanip>
#include <cstdint>
#include <fstream>
#include <sstream>
#include <chrono>
#include <ctime>
#include "json.hpp"

using json = nlohmann::json;

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "Ws2_32.lib")
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    typedef int SOCKET;
    const int INVALID_SOCKET = -1;
    const int SOCKET_ERROR = -1;
    #define closesocket close
#endif

const char* SERVER_HOST = "127.0.0.1";
const int SERVER_PORT = 3000;
const int PACKET_SIZE = 17;
const int REQUEST_PAYLOAD_SIZE = 2;
const char* LOG_FILE_PATH = "client.log";
const char* JSON_OUTPUT_FILE_PATH = "packets.json";

std::ofstream g_log_file_stream;

void init_logger() {
    g_log_file_stream.open(LOG_FILE_PATH, std::ios::app);
    if (!g_log_file_stream.is_open()) {
        std::cerr << "Could not open log file: " << LOG_FILE_PATH << std::endl;
    }
}

void log_message(const std::string& level, const std::string& message) {
    auto now = std::chrono::system_clock::now();
    auto in_time_t = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss_timestamp;
    std::tm t_struct;
#ifdef _WIN32
    localtime_s(&t_struct, &in_time_t);
#else
    localtime_r(&in_time_t, &t_struct);
#endif
    ss_timestamp << std::put_time(&t_struct, "%Y-%m-%d %H:%M:%S");
    std::string full_log_message = "[" + ss_timestamp.str() + "] [" + level + "] " + message;
    if (g_log_file_stream.is_open()) {
        g_log_file_stream << full_log_message << std::endl;
    }
    if (level == "INFO" || level == "DEBUG") {
        std::cout << full_log_message << std::endl;
    } else {
        std::cerr << full_log_message << std::endl;
    }
}

void close_logger() {
    if (g_log_file_stream.is_open()) {
        log_message("INFO", "Closing log file.");
        g_log_file_stream.close();
    }
}

struct MarketPacket {
    char symbol[5];
    char buySellIndicator;
    int32_t quantity;
    int32_t price;
    int32_t packetSequence;

    bool operator<(const MarketPacket& other) const {
        return packetSequence < other.packetSequence;
    }
    bool operator==(const MarketPacket& other) const {
        return packetSequence == other.packetSequence;
    }
};

void to_json(json& j, const MarketPacket& p) {
    j = json{
        {"symbol", std::string(p.symbol)},
        {"buySellIndicator", std::string(1, p.buySellIndicator)},
        {"quantity", p.quantity},
        {"price", p.price},
        {"packetSequence", p.packetSequence}
    };
}

void from_json(const json& j, MarketPacket& p) {
    std::string symbol_str = j.at("symbol").get<std::string>();
    strncpy(p.symbol, symbol_str.c_str(), 4);
    p.symbol[4] = '\0';
    std::string bs_str = j.at("buySellIndicator").get<std::string>();
    if (!bs_str.empty()) {
        p.buySellIndicator = bs_str[0];
    } else {
        p.buySellIndicator = ' ';
    }
    j.at("quantity").get_to(p.quantity);
    j.at("price").get_to(p.price);
    j.at("packetSequence").get_to(p.packetSequence);
}

std::string packet_to_string(const MarketPacket& p) {
    std::stringstream ss;
    ss << "Packet { Seq: " << p.packetSequence
       << ", Symbol: " << p.symbol
       << ", Indicator: " << p.buySellIndicator
       << ", Qty: " << p.quantity
       << ", Price: " << p.price << " }";
    return ss.str();
}

void initialize_networking() {
#ifdef _WIN32
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        log_message("ERROR", "WSAStartup failed: " + std::to_string(result));
        exit(1);
    }
#endif
    log_message("INFO", "Networking initialized.");
}

void cleanup_networking() {
#ifdef _WIN32
    WSACleanup();
#endif
    log_message("INFO", "Networking cleaned up.");
}

SOCKET connect_to_server() {
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        log_message("ERROR", "Socket creation failed.");
        return INVALID_SOCKET;
    }
    sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, SERVER_HOST, &server_addr.sin_addr);
    log_message("INFO", "Attempting to connect to server " + std::string(SERVER_HOST) + ":" + std::to_string(SERVER_PORT));
    if (connect(sock, (sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        log_message("ERROR", "Connection failed to server " + std::string(SERVER_HOST) + ":" + std::to_string(SERVER_PORT));
        closesocket(sock);
        return INVALID_SOCKET;
    }
    log_message("INFO", "Successfully connected to server.");
    return sock;
}

bool send_request(SOCKET sock, uint8_t call_type, uint8_t resend_seq) {
    char payload[REQUEST_PAYLOAD_SIZE];
    payload[0] = static_cast<char>(call_type);
    payload[1] = static_cast<char>(resend_seq);
    int bytes_sent = send(sock, payload, REQUEST_PAYLOAD_SIZE, 0);
    if (bytes_sent == SOCKET_ERROR) {
        log_message("ERROR", "Send request failed. Type=" + std::to_string(call_type) + ", Seq=" + std::to_string(resend_seq));
        return false;
    }
    if (bytes_sent < REQUEST_PAYLOAD_SIZE) {
        log_message("WARNING", "Not all request bytes sent. Sent " + std::to_string(bytes_sent) + "/" + std::to_string(REQUEST_PAYLOAD_SIZE));
    }
    return true;
}

MarketPacket parse_packet_data(const char* buffer) {
    MarketPacket packet;
    memset(packet.symbol, 0, sizeof(packet.symbol));
    memcpy(packet.symbol, buffer, 4);
    packet.buySellIndicator = buffer[4];
    memcpy(&packet.quantity, buffer + 5, sizeof(int32_t));
    packet.quantity = ntohl(packet.quantity);
    memcpy(&packet.price, buffer + 9, sizeof(int32_t));
    packet.price = ntohl(packet.price);
    memcpy(&packet.packetSequence, buffer + 13, sizeof(int32_t));
    packet.packetSequence = ntohl(packet.packetSequence);
    return packet;
}

int main() {
    init_logger();
    log_message("INFO", "ABX Client starting up.");
    initialize_networking();
    std::vector<MarketPacket> all_received_packets_vec;
    std::set<int32_t> received_sequence_numbers;
    int32_t max_sequence_seen = 0;

    log_message("INFO", "--- Phase 1: Streaming all packets ---");
    SOCKET stream_sock = connect_to_server();
    if (stream_sock == INVALID_SOCKET) {
        cleanup_networking();
        close_logger();
        return 1;
    }
    log_message("INFO", "Sending Stream All Packets request (Type 1)");
    if (!send_request(stream_sock, 1, 0)) {
        closesocket(stream_sock);
        cleanup_networking();
        close_logger();
        return 1;
    }
    char buffer[PACKET_SIZE];
    int bytes_received;
    while (true) {
        bytes_received = recv(stream_sock, buffer, PACKET_SIZE, 0);
        if (bytes_received == 0) {
            log_message("INFO", "Server closed connection (end of stream).");
            break;
        }
        if (bytes_received == SOCKET_ERROR) {
            log_message("ERROR", "Recv failed during stream.");
            break;
        }
        if (bytes_received < PACKET_SIZE) {
            log_message("WARNING", "Received partial packet data (" + std::to_string(bytes_received) + " bytes). Attempting to read more...");
            int remaining_bytes = PACKET_SIZE - bytes_received;
            int extra_bytes_received = recv(stream_sock, buffer + bytes_received, remaining_bytes, 0);
            if (extra_bytes_received <= 0) {
                 log_message("ERROR", "Failed to receive remaining part of partial packet or server closed connection.");
                 break;
            }
            bytes_received += extra_bytes_received;
            if (bytes_received < PACKET_SIZE) {
                log_message("WARNING", "Still received incomplete packet after retry (" + std::to_string(bytes_received) + " bytes). Skipping.");
                continue;
            }
        }
        MarketPacket packet = parse_packet_data(buffer);
        log_message("DEBUG", "Received streamed packet: " + packet_to_string(packet));
        all_received_packets_vec.push_back(packet);
        received_sequence_numbers.insert(packet.packetSequence);
        if (packet.packetSequence > max_sequence_seen) {
            max_sequence_seen = packet.packetSequence;
        }
    }
    closesocket(stream_sock);
    log_message("INFO", "Stream socket closed.");

    log_message("INFO", "--- Phase 2: Identifying missing packets ---");
    std::vector<int32_t> missing_sequences;
    if (max_sequence_seen > 0) {
        std::set<int32_t> expected_sequences;
        for (int32_t i = 1; i <= max_sequence_seen; ++i) {
            expected_sequences.insert(i);
        }
        std::set_difference(expected_sequences.begin(), expected_sequences.end(),
                            received_sequence_numbers.begin(), received_sequence_numbers.end(),
                            std::back_inserter(missing_sequences));
    } else if (!received_sequence_numbers.empty()) {
         log_message("WARNING", "Max sequence seen is 0, but packets were received. Check sequence numbering.");
    }

    if (missing_sequences.empty()) {
        if (max_sequence_seen > 0 || !all_received_packets_vec.empty()) {
             log_message("INFO", "No packets were missed in the initial stream.");
        } else {
            log_message("INFO", "No packets received in initial stream, and no missing sequences to request.");
        }
    } else {
        std::stringstream ss_missing;
        for (size_t i = 0; i < missing_sequences.size(); ++i) {
            ss_missing << missing_sequences[i] << (i == missing_sequences.size() - 1 ? "" : ", ");
        }
        log_message("INFO", "Identified " + std::to_string(missing_sequences.size()) + " missing packet sequences: " + ss_missing.str());
        log_message("INFO", "--- Phase 3: Requesting missing packets ---");
        for (int32_t seq_num_32 : missing_sequences) {
            if (seq_num_32 < 0 || seq_num_32 > 255) {
                log_message("ERROR", "Sequence number " + std::to_string(seq_num_32) + " is out of range for uint8_t resendSeq. Skipping.");
                continue;
            }
            uint8_t seq_num_8 = static_cast<uint8_t>(seq_num_32);
            SOCKET resend_sock = connect_to_server();
            if (resend_sock == INVALID_SOCKET) {
                log_message("ERROR", "Failed to connect for resending sequence " + std::to_string(static_cast<int>(seq_num_8)));
                continue;
            }
            log_message("INFO", "Sending Resend Packet request (Type 2) for sequence " + std::to_string(static_cast<int>(seq_num_8)));
            if (!send_request(resend_sock, 2, seq_num_8)) {
                closesocket(resend_sock);
                continue;
            }
            bytes_received = recv(resend_sock, buffer, PACKET_SIZE, 0);
            if (bytes_received == PACKET_SIZE) {
                MarketPacket packet = parse_packet_data(buffer);
                log_message("DEBUG", "Received resent packet: " + packet_to_string(packet));
                if (packet.packetSequence == seq_num_32) {
                    all_received_packets_vec.push_back(packet);
                } else {
                     log_message("WARNING", "Resent packet sequence mismatch. Expected " + std::to_string(seq_num_32)
                               + ", got " + std::to_string(packet.packetSequence));
                }
            } else if (bytes_received == 0) {
                log_message("ERROR", "Server closed connection unexpectedly for resend of sequence " + std::to_string(static_cast<int>(seq_num_8)));
            } else if (bytes_received == SOCKET_ERROR) {
                log_message("ERROR", "Recv failed for resend of sequence " + std::to_string(static_cast<int>(seq_num_8)));
            } else {
                 log_message("ERROR", "Received incomplete packet (" + std::to_string(bytes_received) + " bytes) for resend of sequence " + std::to_string(static_cast<int>(seq_num_8)));
            }
            closesocket(resend_sock);
            log_message("DEBUG", "Resend socket for sequence " + std::to_string(static_cast<int>(seq_num_8)) + " closed.");
        }
    }

    log_message("INFO", "--- Final Data Processing ---");
    if (!all_received_packets_vec.empty()) {
        std::sort(all_received_packets_vec.begin(), all_received_packets_vec.end());
        all_received_packets_vec.erase(
            std::unique(all_received_packets_vec.begin(), all_received_packets_vec.end()),
            all_received_packets_vec.end()
        );
        log_message("INFO", "Sorted and removed duplicates from collected packets.");
    }

    log_message("INFO", "Total unique packets collected: " + std::to_string(all_received_packets_vec.size()));
    if (max_sequence_seen > 0) {
        log_message("INFO", "Highest sequence seen in initial stream: " + std::to_string(max_sequence_seen));
        if (all_received_packets_vec.size() == static_cast<size_t>(max_sequence_seen)) {
            log_message("INFO", "Successfully received all packets up to max sequence.");
        } else {
            log_message("WARNING", "Still missing " + std::to_string(max_sequence_seen - all_received_packets_vec.size()) + " packets after resend attempts.");
            std::set<int32_t> final_received_seqs;
            for(const auto& p : all_received_packets_vec) {
                final_received_seqs.insert(p.packetSequence);
            }
            std::vector<int32_t> still_missing_after_resend;
            if (max_sequence_seen > 0) {
                std::set<int32_t> expected_sequences_final;
                for (int32_t i = 1; i <= max_sequence_seen; ++i) {
                    expected_sequences_final.insert(i);
                }
                std::set_difference(expected_sequences_final.begin(), expected_sequences_final.end(),
                                    final_received_seqs.begin(), final_received_seqs.end(),
                                    std::back_inserter(still_missing_after_resend));
            }
            if (!still_missing_after_resend.empty()) {
                std::stringstream ss_still_missing;
                for(size_t i=0; i < still_missing_after_resend.size(); ++i)
                    ss_still_missing << still_missing_after_resend[i] << (i == still_missing_after_resend.size()-1 ? "" : ", ");
                log_message("WARNING", "Sequences still missing: " + ss_still_missing.str());
            }
        }
    }

    log_message("INFO", "Attempting to save collected packets to JSON file: " + std::string(JSON_OUTPUT_FILE_PATH));
    json json_array = all_received_packets_vec;
    std::ofstream json_file(JSON_OUTPUT_FILE_PATH);
    if (json_file.is_open()) {
        try {
            json_file << std::setw(4) << json_array << std::endl;
            json_file.close();
            log_message("INFO", "Successfully saved packets to " + std::string(JSON_OUTPUT_FILE_PATH));
        } catch (const json::exception& e) {
            log_message("ERROR", "JSON serialization/writing exception: " + std::string(e.what()));
        }
    } else {
        log_message("ERROR", "Could not open JSON output file: " + std::string(JSON_OUTPUT_FILE_PATH));
    }

    cleanup_networking();
    log_message("INFO", "ABX Client shutting down.");
    close_logger();
    return 0;
}