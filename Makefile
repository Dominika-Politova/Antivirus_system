all: server client stats

server: server.cpp
	g++ -std=c++17 -o server server.cpp -lrt

client: client.cpp
	g++ -std=c++17 -o client client.cpp

stats: stats.cpp
	g++ -std=c++17 -o stats stats.cpp -lrt

clean:
	rm -f server client stats
