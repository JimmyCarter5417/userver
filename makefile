all : *.c
	gcc -g *.c -lpthread -lssl -lcrypto   -o userver 
