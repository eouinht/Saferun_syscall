CC=gcc
CFLAGS=-Wall
LIBS = -lseccomp 
saferun: saferun.c 
	$(CC) $(CFLAGS) saferun.c -o run/saferun $(LIBS) 

suspected: suspected.c 
	$(CC) $(CFLAGS) suspected.c -o run/suspected  

all: saferun suspected

clean: 
	rm -f run/saferun run/suspected output.txt