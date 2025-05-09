# Client

This project is a C++ client that connects to the ABX mock exchange server over TCP, receives stock ticker packets, and saves them to a JSON file.

## 📝 Description

- Connects to `localhost:3000` (ABX Exchange Server)
- Sends a request to stream all available packets
- Parses binary responses (Big Endian format)
- Detects and stores packet information including:
  - Symbol
  - Buy/Sell indicator
  - Quantity
  - Price
  - Sequence number
- Outputs all received packets to `packets.json`

## 🛠 Technologies

- C++ (Tested on Linux)
- POSIX sockets
- [nlohmann/json](https://github.com/nlohmann/json) for JSON output

## 🚀 Getting Started

### Prerequisites

- g++ (Linux or MinGW on Windows)
- Node.js (>= 16.17.0) to run the ABX server
- Download `json.hpp` from [nlohmann/json](https://github.com/nlohmann/json/releases)

### Run ABX Exchange Server

1. Extract `abx_exchange_server.zip`
2. Start the server:
   ```bash
   node main.js
