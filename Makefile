all : web_proxy

web_proxy: web_proxy.o pcap_handle.o http_util.o ssl_util.o
	g++ -g -o web_proxy web_proxy.o pcap_handle.o http_util.o ssl_util.o -lssl -lcrypto -lpthread

web_proxy.o: web_proxy.cpp pcap_handle.h http_util.h ssl_util.h
	g++ -g -c -o web_proxy.o web_proxy.cpp -lssl -lcrypto

ssl_util.o: ssl_util.cpp ssl_util.h
	g++ -g -c -o ssl_util.o ssl_util.cpp -lssl -lcrypto

http_util.o: http_util.cpp http_util.h
	g++ -g -c -o http_util.o http_util.cpp

pcap_handle.o: pcap_handle.cpp
	g++ -g -c -o pcap_handle.o pcap_handle.cpp

clean:
	rm -f web_proxy
	rm -f *.o


