# Project 3: Secure Webserver
Uses Websockets and C++ to make a webserver that lets users broadcast messages.

### Dependencies
* Ubuntu 18.04
* [zaphoyd/websocketpp](https://github.com/zaphoyd/websocketpp)
* sqlite3, nodejs, npm, wscat plugin
* libsqlite3-dev
* [OpenSSL 1.1.1a](https://www.openssl.org/source/)
* [Crypto++ 5.6.1](https://www.cryptopp.com/index.html)
* [Boost 1.68.0](https://dl.bintray.com/boostorg/release/1.68.0/source/)

### My Workspace
I worked on the project using on Windows Sub Linux.

#### Setup workspace
* Install WSL:  
https://docs.microsoft.com/en-us/windows/wsl/install-win10
* Update & upgrade Ubuntu:
  `sudo apt-get update && sudo apt-get upgrade -y`
* Create workspace
  ```
  mkdir cpp-secure-webserver  
  cd cpp-secure-webserver
  ```
* Download zaphoyd/websocketpp into workspace
  `git clone https://github.com/zaphoyd/websocketpp.git`
* Install nodejs
  ```
  curl -sL https://deb.nodesource.com/setup_10.x | sudo -E bash -
  sudo apt-get install -y nodejs
  ```
* Install necessary programs
  `sudo apt-get install g++ make sqlite3 libsqlite3-dev libcrypto++-dev libcrypto++-doc libcrypto++-utils -y`
* Install latest OpenSSL 1.1.1a
  ```
  wget https://www.openssl.org/source/openssl-1.1.1a.tar.gz
  tar xzvf openssl-1.1.1a.tar.gz
  cd openssl-1.1.1a
  ./config -Wl,--enable-new-dtags,-rpath,'$(LIBRPATH)'
  make
  sudo make install
  sudo ldconfig
  ```
* Install npm plugin for CLI websocket client
  `sudo npm install -g wscat`
* Install Boost 1.68.0  
[https://github.com/zaphoyd/websocketpp/wiki/Build-on-debian](https://github.com/zaphoyd/websocketpp/wiki/Build-on-debian)  
  ```
  cd /usr/local
  sudo wget https://dl.bintray.com/boostorg/release/1.68.0/source/boost_1_68_0.tar.gz
  sudo tar xvfz boost_1_68_0.tar.gz
  cd /usr/local/boost_1_68_0
  mkdir libbin
  ./bootstrap.sh --prefix=libbin
  ./b2 install
  ```  
  Add `/usr/local/boost_1_68_0/libbin/lib` in `/etc/ld.so.conf.d/local.conf`  
  Run ldconfig: `sudo ldconfig`

### Build from source
Just use the make file. It took a while for me to get it to work. I haven't tested it in an actual Linux environment, but I guess it'll work too. WSL Ubuntu is basically Ubuntu.

### Run Server & Client
To run the server, build the server executable using `make` and run the server.  
To run a client, run `wscat -c ws://localhost:8081`  
To check commands that can be used on both the server and client, use `-help`.

