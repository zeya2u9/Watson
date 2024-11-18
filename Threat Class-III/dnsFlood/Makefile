include /usr/local/etc/PcapPlusPlus.mk

# All Target
all:
	g++ $(PCAPPP_INCLUDES) -c -o dnsFlood.o dnsFlood.cpp -g
	g++ $(PCAPPP_LIBS_DIR) -static-libstdc++ -o dnsFlood dnsFlood.o $(PCAPPP_LIBS)

# Clean Target
clean:
	rm dnsFlood.o
	rm dnsFlood
