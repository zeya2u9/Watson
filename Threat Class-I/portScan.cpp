#include <iostream>
#include <sstream>
#include <fstream>
#include <unordered_map>
#include <vector>
#include <array>
#include <sstream>
#include <limits>
#include <thread>
#include <cstdlib>
#include <cstring>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include "PcapFileDevice.h"
#include "TcpLayer.h"
#include "IPv4Layer.h"
#include "Packet.h"

#define ARR_SIZE 512
#define BURST 32

struct data{
    int seq;
    char buf[1500];
    int rawDataLen;
    timespec timestamp;
    pcpp::LinkLayerType layerType;
};

static unsigned int counter = 0;
static data* msg_ptr;
uint64_t count = 0, batch_count = 0;
timespec c_time,f_time, debug_time_s, debug_time_f;
short enable = 0, firstpkt = 0;
int fd;

std::unordered_map<int,std::string> scan_types = {
	{1,"syn"},{2,"syn_closed"},{3,"ack"},{4,"ack_closed"},{5,"fin"},{6,"fin_closed"},{7,"connect"},{8,"connect_closed"},{9,"window"},{10,"window_closed"},{11,"version"},{12,"version_closed"},{13,"xmas"},{14,"xmas_closed"},{15,"maimon"},{16,"maimon_closed"},{17,"null"},{18,"null_closed"}
};

int comp(std::array<long,14> x,std::vector<std::string> y){
    int val = 0;
    for(int i = 2; i < 10; i++){val = val + (10*std::abs(x[i]-atoi(y.at(i).c_str())));}
    return val;
}

// reading the csv file
std::vector<std::vector<std::string>> read_csv(){
    std::vector<std::vector<std::string>> content;
    std::vector<std::string> row;
    std::string line, word;
    std::ifstream file ("tcp_master_2.csv");
    if(file){
        while(getline(file, line)){
            row.clear();
	       std::stringstream str(line);
	       while(getline(str, word, ','))
		   row.push_back(word);
	       content.push_back(row);
	    }
	    return content;
    }
    else{
	   std::cerr<<"CSV file doesnt exist"<<std::endl;
	   exit(-1);
    }
}

void helper2(std::vector<std::vector<std::string>> train, std::vector<std::array<long,14>> test, int start, int stop, int* score){
    int min_diff = 999999;
	for(int i  = 0; i < test.size(); i++){
        int min_diff = 999999; // min dist of this packet from all packets of this type of scan in train data
	    for(int k = start; k < stop; k++){
            if(test.at(i)[1] != atol(train.at(k).at(1).c_str())){continue;} // cannot compare packets with different directions
            int diff = comp(test.at(i),train.at(k));
            //std::cout << "mindiff = "<<min_diff<<std::endl;
            min_diff = std::min(min_diff,diff);
	    }
		*score = *score + min_diff;
    }
}

// evaluates the type of TCP port scan for a given IP and calculates the confidence, returs a vector of unique ports encountered
std::pair<int,std::vector<int>> helper(std::vector<std::vector<std::string>> train, std::vector<std::array<long,14>> test, long ip){
    std::vector<int> uniq_ports;
    int num_forward = 0; // counter for the number of forward packets
    int min_scores[] = {999999,999999,999999,999999,999999,999999,999999,999999,999999,999999,999999,999999,999999,999999,999999,999999,999999,999999}; // minimum distance from each scan type
    int arr[] = {0,3,5,7,9,11,13,17,19,21,23,33,35,37,39,41,43,45}; // indices that separate packets of each type of scan in the train data
    int scores[18] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    std::thread t1(helper2, train, test, arr[0], arr[1], &scores[0]);
    std::thread t2(helper2, train, test, arr[1], arr[2], &scores[1]);
    std::thread t3(helper2, train, test, arr[2], arr[3], &scores[2]);
    std::thread t4(helper2, train, test, arr[3], arr[4], &scores[3]);
    std::thread t5(helper2, train, test, arr[4], arr[5], &scores[4]);
    std::thread t6(helper2, train, test, arr[5], arr[6], &scores[5]);
    std::thread t7(helper2, train, test, arr[6], arr[7], &scores[6]);
    std::thread t8(helper2, train, test, arr[7], arr[8], &scores[7]);
    std::thread t9(helper2, train, test, arr[8], arr[9], &scores[8]);
    std::thread t10(helper2, train, test, arr[9], arr[10], &scores[9]);
    std::thread t11(helper2, train, test, arr[10], arr[11], &scores[10]);
    std::thread t12(helper2, train, test, arr[11], arr[12], &scores[11]);
    std::thread t13(helper2, train, test, arr[12], arr[13], &scores[12]);
    std::thread t14(helper2, train, test, arr[13], arr[14], &scores[13]);
    std::thread t15(helper2, train, test, arr[14], arr[15], &scores[14]);
    std::thread t16(helper2, train, test, arr[15], arr[16], &scores[15]);
    std::thread t17(helper2, train, test, arr[16], arr[17], &scores[16]);
    std::thread t18(helper2, train, test, arr[17], arr[18], &scores[17]);

    cpu_set_t cpuset1, cpuset2, cpuset3, cpuset4, cpuset5, cpuset6, cpuset7, cpuset8, cpuset9, cpuset10, cpuset11, cpuset12, cpuset13, cpuset14, cpuset15, cpuset16, cpuset17, cpuset18;
    CPU_ZERO(&cpuset1);CPU_ZERO(&cpuset2);CPU_ZERO(&cpuset3);CPU_ZERO(&cpuset4);CPU_ZERO(&cpuset5);CPU_ZERO(&cpuset6);CPU_ZERO(&cpuset7);CPU_ZERO(&cpuset8);CPU_ZERO(&cpuset9);CPU_ZERO(&cpuset10);CPU_ZERO(&cpuset11);CPU_ZERO(&cpuset12);CPU_ZERO(&cpuset13);CPU_ZERO(&cpuset14);CPU_ZERO(&cpuset15);CPU_ZERO(&cpuset16);CPU_ZERO(&cpuset17);CPU_ZERO(&cpuset18);
    CPU_SET(10, &cpuset1);CPU_SET(11, &cpuset2);CPU_SET(12, &cpuset3);CPU_SET(13, &cpuset4);CPU_SET(14, &cpuset5);CPU_SET(15, &cpuset6);CPU_SET(16, &cpuset7);CPU_SET(17, &cpuset8);CPU_SET(18, &cpuset9);CPU_SET(19, &cpuset10);CPU_SET(20, &cpuset11);CPU_SET(21, &cpuset12);CPU_SET(22, &cpuset13);CPU_SET(23, &cpuset14);CPU_SET(24, &cpuset15);CPU_SET(25, &cpuset16);CPU_SET(26, &cpuset17);CPU_SET(27, &cpuset18);
    if(pthread_setaffinity_np(t1.native_handle(), sizeof(cpu_set_t), &cpuset1) != 0)
	   std::cerr << "Error calling pthread_setaffinity_np on t1: " << errno << "\n";
    if(pthread_setaffinity_np(t2.native_handle(), sizeof(cpu_set_t), &cpuset2) != 0)
        std::cerr << "Error calling pthread_setaffinity_np on t2: " << errno << "\n";
    if(pthread_setaffinity_np(t3.native_handle(), sizeof(cpu_set_t), &cpuset3) != 0)
        std::cerr << "Error calling pthread_setaffinity_np on t3: " << errno << "\n";
    if(pthread_setaffinity_np(t4.native_handle(), sizeof(cpu_set_t), &cpuset4) != 0)
        std::cerr << "Error calling pthread_setaffinity_np on t4: " << errno << "\n";
    if(pthread_setaffinity_np(t5.native_handle(), sizeof(cpu_set_t), &cpuset5) != 0)
        std::cerr << "Error calling pthread_setaffinity_np on t5: " << errno << "\n";
    if(pthread_setaffinity_np(t6.native_handle(), sizeof(cpu_set_t), &cpuset6) != 0)
        std::cerr << "Error calling pthread_setaffinity_np on t6: " << errno << "\n";
    if(pthread_setaffinity_np(t7.native_handle(), sizeof(cpu_set_t), &cpuset7) != 0)
        std::cerr << "Error calling pthread_setaffinity_np on t7: " << errno << "\n";
    if(pthread_setaffinity_np(t8.native_handle(), sizeof(cpu_set_t), &cpuset8) != 0)
        std::cerr << "Error calling pthread_setaffinity_np on t8: " << errno << "\n";
    if(pthread_setaffinity_np(t9.native_handle(), sizeof(cpu_set_t), &cpuset9) != 0)
        std::cerr << "Error calling pthread_setaffinity_np on t9: " << errno << "\n";
    if(pthread_setaffinity_np(t10.native_handle(), sizeof(cpu_set_t), &cpuset10) != 0)
       std::cerr << "Error calling pthread_setaffinity_np on t10: " << errno << "\n";
    if(pthread_setaffinity_np(t11.native_handle(), sizeof(cpu_set_t), &cpuset11) != 0)
        std::cerr << "Error calling pthread_setaffinity_np on t11: " << errno << "\n";
    if(pthread_setaffinity_np(t12.native_handle(), sizeof(cpu_set_t), &cpuset12) != 0)
        std::cerr << "Error calling pthread_setaffinity_np on t12: " << errno << "\n";
    if(pthread_setaffinity_np(t13.native_handle(), sizeof(cpu_set_t), &cpuset13) != 0)
        std::cerr << "Error calling pthread_setaffinity_np on t13: " << errno << "\n";
    if(pthread_setaffinity_np(t14.native_handle(), sizeof(cpu_set_t), &cpuset14) != 0)
        std::cerr << "Error calling pthread_setaffinity_np on t14: " << errno << "\n";
    if(pthread_setaffinity_np(t15.native_handle(), sizeof(cpu_set_t), &cpuset15) != 0)
        std::cerr << "Error calling pthread_setaffinity_np on t15: " << errno << "\n";
    if(pthread_setaffinity_np(t16.native_handle(), sizeof(cpu_set_t), &cpuset16) != 0)
        std::cerr << "Error calling pthread_setaffinity_np on t16: " << errno << "\n";
    if(pthread_setaffinity_np(t17.native_handle(), sizeof(cpu_set_t), &cpuset17) != 0)
        std::cerr << "Error calling pthread_setaffinity_np on t17: " << errno << "\n";
    if(pthread_setaffinity_np(t18.native_handle(), sizeof(cpu_set_t), &cpuset18) != 0)
        std::cerr << "Error calling pthread_setaffinity_np on t18: " << errno << "\n";

    t1.join();
    t2.join();
    t3.join();
    t4.join();
    t5.join();
    t6.join();
    t7.join();
    t8.join();
    t9.join();
    t10.join();
    t11.join();
    t12.join();
    t13.join();
    t14.join();
    t15.join();
    t16.join();
    t17.join();
    t18.join();

    /*printf("Some Array = ");
    for(int i = 0; i < 18; i++){
	   printf("%d ", atoi(train.at(arr[i]).at(train.at(arr[i]).size()-3).c_str()));
    }
    printf("\n");*/

    for(int i = 0; i < 18; i++){
        /*if(scores[i] != 0){
            min_scores[i] = scores[i];
        }*/
	min_scores[i] = scores[i];
    }
    

    int min_score = *std::min_element(min_scores,min_scores+(sizeof(min_scores)/sizeof(min_scores[0]))); // overall minimum score
    std::vector<std::string> pred_classes; // stores predicted classes based on overall miminum score
    for(int i = 0; i < 18; i++){
	   if(min_scores[i] == min_score){pred_classes.push_back(scan_types[i]);}
    }
    for(int i = 0; i < test.size(); i++){
    	if(test.at(i)[1] == 1){ // to calculate number of forward packets and build a set of unique ports encountered in forward packets
    	    num_forward++;
    	    uniq_ports.push_back(test.at(i)[10]);
    	}
    }
    //printing min scores
    //printf("Min score: ");
    //for(int i = 0; i < 18; i++){
    //    printf("%d ",min_scores[i]);
    //}
    //puts("");
    // printing predicted classes
    std::cout<<"Predicted: ";
    for(auto x : pred_classes){std::cout<<x<<" ";}
    std::cout<<std::endl;

    int conf = -1;
    if(num_forward > 0){
    	conf = uniq_ports.size()/num_forward; // confidence
    	std::cout<<"Number of unique local ports: "<<uniq_ports.size()<<std::endl<<"Number of Forward Packets: "<<num_forward<<std::endl;
    	std::cout<<"Confidence: "<<conf<<std::endl;
    }
    else{std::cout<<"No Confidence";} // when there are no forward packets in sample
    std::pair<int,std::vector<int>> ret = {conf,uniq_ports}; // returning the pair
    return ret;
}

void predict(std::vector<std::vector<std::string>> train, std::vector<std::array<long,14>> test){
    std::unordered_map<long,std::vector<std::array<long,14>>> ip_grps; //stores key value pair of <IP, packets of flow pertaining to this outside IP>
    std::unordered_map<long,std::vector<int>> uniq_ports; // stores key value pair of <IP, unique ports encountered in the forward packets of the flow pertaining to this outside IP>
    std::unordered_map<long,int> conf; // stores key value pair of <IP, confidence score of the IP pertaining to this outside IP>
    // building the IP groupings
    for(int i = 0; i < test.size(); i++ ){
    	auto sample = test[i];
    	if(ip_grps.size() != 0){
    	    for(auto x : ip_grps){
        		if(sample[12] == x.first)
        		    ip_grps[sample[12]].push_back(sample);
        		else{
        		    std::vector<std::array<long,14>> v;
        		    v.push_back(sample);
        		    ip_grps[sample[12]] = v;
        		}
    	    }
    	}
    	else{
    	    std::vector<std::array<long,14>> v;
            v.push_back(sample);
            ip_grps[sample[12]] = v;
    	}
    }
    std::vector<long> l; // storing unique IPs for distributed port scan
    for(auto ip : ip_grps){
    	//printf("size: %d\n",ip_grps[ip.first].size());
    	//if(ip_grps[ip.first].size() < 10){continue;} // too less packets for analysis
    	struct in_addr ip_addr;
    	ip_addr.s_addr = ip.first;
    	std::cout<<"For IP: "<<inet_ntoa(ip_addr)<<std::endl;
    	std::pair<int,std::vector<int>> temp = helper(train,ip_grps[ip.first],ip.first); // helper function to predict type of scan
    	conf[ip.first] = temp.first; uniq_ports[ip.first] = temp.second;
    	l.push_back(ip.first);
    }
    //debug statement
    if(count>=100){clock_gettime(CLOCK_REALTIME,&debug_time_f);printf("%dth Pkt: %ld.%ld\n",count,debug_time_f.tv_sec,debug_time_f.tv_nsec);}
    std::cout<<"for batch: "<<batch_count<<std::endl;
    if(l.size() <= 1){return;}
    /*else{
	for(int i = 0; i < l.size(); i++){
	    int ip_i = l.at(i);
	    if(conf[ip_i] < 0.4){continue;} // confidence too low
	    for(int j = i+1; j < l.size(); j++){
		int ip_j = l.at(j);
		if(conf[ip_j] < 0.4){continue;} // confidence too low
		std::vector<int> temp;
		std::set_intersection(uniq_ports[ip_i].begin(), uniq_ports[ip_i].end(), uniq_ports[ip_j].begin(), uniq_ports[ip_j].end(), std::inserter(temp, temp.begin()));
		if(temp.size() >= 0)
		    std::cout<<"Possible distributed port scan "<<ip_i<<" and "<<ip_j;
	    }
	}
    }*/
}

void handler(int sig){
	clock_gettime(CLOCK_REALTIME,&f_time);
    printf("\nShutting Down... with packets = %llu and processing time = %llu.%llu\n",count,f_time.tv_sec-c_time.tv_sec,f_time.tv_nsec-c_time.tv_nsec);
    delete msg_ptr;
    exit(0);
}

void* run(void *argp){
    unsigned long long* limit = (unsigned long long *)argp;
    std::vector<std::vector<std::string>> train = read_csv();
    std::vector<std::string> my_ip;
    // my_ip.push_back("205.174.165.68");
    my_ip.push_back("192.168.2.1");
    while(1){
        std::vector<std::array<long,14>> store; //store is csv data + IP and port of attacker
    	while(1){
    	    if(enable == 0){
                enable = 1;
                clock_gettime(CLOCK_REALTIME,&c_time);
            }
    	    iovec iov = {(void *)msg_ptr,sizeof(data)*BURST};
    	    int read = vmsplice(fd, &iov, 1, SPLICE_F_NONBLOCK);
    	    //int rd = read(fd, (void *)msg_ptr, sizeof(data)*BURST);
    	    if(read < 0){
    		  if(errno == 11){continue;}
    		  std::cerr<<"Cant read on /dev/shm/portScan with errno: "<<errno<<std::endl;
    	    }
    	    if(read == 0){continue;}
	    // debug statement
            if(firstpkt == 0){firstpkt = 1;clock_gettime(CLOCK_REALTIME,&debug_time_s);printf("1st Pkt: %ld.%ld\n",debug_time_s.tv_sec,debug_time_s.tv_nsec);}
    	    count += read/sizeof(data);
    	    for(int i = 0; i < read/sizeof(data); i++){
    	    	//std::cout<<msg_ptr->seq<<std::endl;
    	    	pcpp::RawPacket rawPacket((const uint8_t*)msg_ptr[i].buf,msg_ptr[i].rawDataLen,msg_ptr[i].timestamp,0,msg_ptr[i].layerType);
    	    	pcpp::Packet parsedPacket(&rawPacket); // making parsed packet from raw packet to extract information layer by layer
                //std::cout<<parsedPacket.toString();
    	    	if(!parsedPacket.isPacketOfType(pcpp::TCP)){continue;}
    	    	if(!parsedPacket.isPacketOfType(pcpp::IPv4)){continue;}
    	    	std::array<long,14> data = {0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    	    	short valid = 0;
    	    	pcpp::IPv4Layer* IPLayer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
    	    	for(auto x : my_ip){
    	    	    if(strcmp(IPLayer->getDstIPv4Address().toString().c_str(),x.c_str()) != 0){continue;}
        		    else{
        		    	valid = 1;
        		    	pcpp::tcphdr* TCPHeader = parsedPacket.getLayerOfType<pcpp::TcpLayer>()->getTcpHeader(); // getting the tcpheader
        		    	if(strcmp(IPLayer->getDstIPv4Address().toString().c_str(),x.c_str()) == 0){ // is_fwd = inbound
                            data[1] = 1;
                            data[12] = IPLayer->getSrcIPv4Address().toInt();
                            data[13] = TCPHeader->portSrc;
                        }
                        else{
                            data[12] = IPLayer->getDstIPv4Address().toInt();
                            data[13] = TCPHeader->portDst;
                    	}
        		        break;
        		    }
    	    	}
    	    	if (valid == 1) // if the packet is of valid to be processed further
                {
        		    data[0] = rawPacket.getPacketTimeStamp().tv_nsec; // getting timestamp
        		    if(!parsedPacket.isPacketOfType(pcpp::TCP)){continue;}
        		    pcpp::tcphdr* TCPHeader = parsedPacket.getLayerOfType<pcpp::TcpLayer>()->getTcpHeader(); // getting the tcpheader
        	    	if(TCPHeader->finFlag) // if fin flag exists
        		    	data[4] = 1;
        	    	if(TCPHeader->rstFlag) // if reset flag exists
        		        data[5] = 1;
        	    	if(TCPHeader->synFlag) // if syn flag exists
                        data[2] = 1;
        	    	if(TCPHeader->ackFlag) // if ack flag exists
                        data[3] = 1;
        	    	if(TCPHeader->pshFlag) // if psh flag exists
                       	data[6] = 1;
                    if(TCPHeader->urgFlag) // if urg flag exists
                       	data[7] = 1;
                    if(TCPHeader->eceFlag) // if ece flag exists
                       	data[8] = 1;
                    if(TCPHeader->cwrFlag) // if cwr flag exists
                       	data[9] = 1;
		    //printf("data: ");
		    //for(int i = 0; i < 12; i++){printf("%d ",data[i]);}
		    //puts("");
    	    	    store.push_back(data);
        		    if(store.size()>=(*limit)){
        		        batch_count++;
        			    std::thread t(predict, train, store);
        			    t.detach();
        			     // predict(train,store);
        			     break;
        		  }
        		   //predict(train,store);
        	    }
            }
    	}
    }
}

int main(int argc, char* argv[])
{
    signal(SIGINT,handler);
    if(argc<2){std::cerr<<"Usage: "<<argv[0]<<" BatchSize"<<std::endl; return -1;}
    if(strlen(argv[1]) >= 19){
    	std::cerr<<"Too long number for Batch Size"<<std::endl;
    	std::cerr<<"18 digits Maximum"<<std::endl;
    	return -1;
    }
    char batch[18];
    char *end;
    strcpy(batch,argv[1]);

    unsigned long long batchsize = std::strtoull(batch,&end,10);

    fd = open("/dev/shm/portScan",O_RDONLY);
    msg_ptr = new data[BURST];

    pthread_t t1,t2,t3,t4,t5,t6,t7,t8;
    pthread_create(&t1,NULL,run,&batchsize);
    pthread_create(&t2,NULL,run,&batchsize);
    pthread_create(&t3,NULL,run,&batchsize);
    pthread_create(&t4,NULL,run,&batchsize);
    pthread_create(&t5,NULL,run,&batchsize);
    pthread_create(&t6,NULL,run,&batchsize);
    pthread_create(&t7,NULL,run,&batchsize);
    pthread_create(&t8,NULL,run,&batchsize);
    pthread_join(t1,NULL);
    pthread_join(t2,NULL);
    pthread_join(t3,NULL);
    pthread_join(t4,NULL);
    pthread_join(t5,NULL);
    pthread_join(t6,NULL);
    pthread_join(t7,NULL);
    pthread_join(t8,NULL);
    return 0;
}
