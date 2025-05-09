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

### Prerequisites

- g++ (Linux or MinGW on Windows)
- Node.js (>= 16.17.0) to run the ABX server
- Download `json.hpp` from [nlohmann/json](https://github.com/nlohmann/json/releases)

### Run ABX Exchange Server

## Start the server:
   Go to the file where project is stored and open command prompt run the code : node main.js
## For Windows: go to the file where project is stored and open command prompt run the code :
   - g++ client.cpp -o client.exe -lws2_32 
   - it will compile the client.cpp code.
   - again run this code : client.exe  
   - it will generate a packet.json file which contain the received packet from the server.

## For Linux: go to the file where project is stored and open command prompt run the code :
   - g++ client.cpp -o client -std=c++11
   - it will compile the client.cpp code.
   - again run this code : ./abx_client  
   - it will generate a packet.json file which contain the received packet from the server.

