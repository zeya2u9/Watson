include /usr/local/etc/PcapPlusPlus.mk

# All Target
all:
	g++ $(PCAPPP_INCLUDES) -c -o sshBruteForce.o sshBruteForce.cpp -g
	g++ $(PCAPPP_LIBS_DIR) -static-libstdc++ -o sshBruteForce sshBruteForce.o $(PCAPPP_LIBS)

# Clean Target
clean:
	rm sshBruteForce.o
	rm sshBruteForce
