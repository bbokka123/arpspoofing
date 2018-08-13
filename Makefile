all: arpspoof

arpspoof : arpspoof.o main.o
	g++ -g -o arpspoof arpspoof.o main.o -lpcap -pthread

arpspoof.o: arpspoof.cpp arpspoof.h
	g++ -g -c -o arpspoof.o arpspoof.cpp

main.o: main.cpp arpspoof.h
	g++ -g -c -o main.o main.cpp

clean:
	rm -f arpspoof
	rm -f *.o
