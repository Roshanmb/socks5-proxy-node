# SOCKS5 Proxy Server (Node.js)

**Proxy Infrastructure**

## 🎯 Goal
Demonstrate the ability to learn independently, problem-solve, and implement a working system related to proxy infrastructure.

---

## 📝 Task
This project implements a **minimal SOCKS5 proxy server** in Node.js that can:

- Accept incoming client connections  
- Forward traffic to the requested destination (basic tunneling)  
- Log each connection (source IP, destination host/port)  
- Support configuration via environment variables:  
  - **Listening port** (`PORT`)  
  - **Username** (`SOCKS_USER`)  
  - **Password** (`SOCKS_PASS`)  

---

## 🚀 How to Run

1. Clone the repo:
   ```bash
   git clone https://github.com/Roshanmb/socks5-proxy-node.git
   cd socks5-proxy-node

# Unix / macOS
PORT=1080 SOCKS_USER=alice SOCKS_PASS=secret npm start

curl --proxy "socks5h://alice:secret@127.0.0.1:1080" https://ipinfo.io/ip
curl --socks5-hostname 127.0.0.1:1080 --proxy-user alice:secret https://ipinfo.io/ip

https://drive.google.com/file/d/14d9EXrm2G8KCpBAPLiUiL4cPBIz1AZ05/view?usp=sharing
