CXX=gcc
LIBS=-lssl -lcrypto
CFLAGS=-Wall 
LD_FLAGS=-g

tls_client.o: tls_client.c
	$(CXX) -c tls_client.c $(CFLAGS)

tls_server.o: tls_server.c
	$(CXX) -c tls_server.c $(CFLAGS)

all: tls_client.o tls_server.o
	$(CXX) -o tls_client  tls_client.o  $(LD_FLAGS) $(LIBS)
	$(CXX) -o tls_server  tls_server.o  $(LD_FLAGS) $(LIBS)

clean:
	rm *.o tls_client tls_server 
