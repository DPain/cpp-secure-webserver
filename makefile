CC=g++
boostdir = /usr/local/boost_1_68_0
libs = -I ~/cpp-secure-webserver/websocketpp -lboost_system -lboost_timer -lboost_chrono -lrt -lssl -lcrypto -lcrypto++ -lsqlite3 -pthread -std=c++11 -L/usr/local/boost_1_68_0/libbin/lib/

main: main.cpp;
	$(CC) -I$(boostdir) -o a.out main.cpp $(libs)

test: test.cpp;
	$(CC) -I$(boostdir) -o b.out test.cpp $(libs)

