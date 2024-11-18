include /usr/local/etc/PcapPlusPlus.mk

# All Target
all:
	g++ $(PCAPPP_INCLUDES) -c -o dpdkCapture.o main.cpp -g
	g++ $(PCAPPP_LIBS_DIR) -static-libstdc++ -o dpdkCapture dpdkCapture.o $(PCAPPP_LIBS) -lboost_system

# Clean Target
clean:
	rm dpdkCapture.o
	rm dpdkCapture
