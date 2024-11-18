include /usr/local/etc/PcapPlusPlus.mk

# All Target
all:
	g++ $(PCAPPP_BUILD_FLAGS) -c $(PCAPPP_INCLUDES) -c -o dnsAmplification.o dnsAmplification.cpp -fpermissive -g
	g++ $(PCAPPP_LIBS_DIR) -static-libstdc++ -o dnsAmplification dnsAmplification.o $(PCAPPP_LIBS) -g

# Clean Target
clean:
	rm dnsAmplification.o
	rm dnsAmplification
