all: arpspoofing

		gcc -o arpspoofing arpspoofing.c -lpcap -lpthread

clean:
		rm -f arpspoofing
		
