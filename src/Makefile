all: server client

client: client.o 
	g++ -o client client.cpp -lssl -lcrypto

server: server.o
	g++ -o server server.cpp -lssl -lcrypto

clean:
	rm *o server client 
