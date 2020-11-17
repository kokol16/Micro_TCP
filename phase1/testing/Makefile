CC = gcc

server: microtcp.o server.c
	$(CC) -o server.out microtcp.o server.c

client: microtcp.o client.c
	$(CC) -o client.out microtcp.o client.c

main: microtcp.o main.c
	$(CC) -o main.out microtcp.o main.c

microtcp.o: microtcp.h microtcp.c
	$(CC) -c microtcp.c

clean:
	rm -f *.o
	rm -f *.out	

