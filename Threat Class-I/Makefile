include /usr/local/etc/PcapPlusPlus.mk

# All Target
all:
	g++ $(PCAPPP_INCLUDES) -g -c -o portScan.o portScan.cpp
	g++ $(PCAPPP_LIBS_DIR) -g -static-libstdc++ -o portScan portScan.o $(PCAPPP_LIBS)

# Clean Target
clean:
	rm portScan.o
	rm portScan
