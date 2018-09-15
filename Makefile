all : pcap_test

pcap_test: main.o
	g++ -o pcap_test main.cpp -lpcap

clean:
	rm -f pcap_test
