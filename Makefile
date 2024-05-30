HEADER_DIR = ./header/
SRC_DIR = ./source/
MAIN_DIR = ./example/
INCLUDE_DIR = ./include/


CXX = g++
CXXFLAGS = -Wall -Werror -c -g3 -O3 -I$(INCLUDE_DIR)
CXX11 = -std=c++11
CXX17 = -std=c++17


# Connect to and disconnect from a token
HDR_CONNDIS = $(addprefix $(HEADER_DIR),conn_dis_token.hpp)
SRC_CONNDIS = $(addprefix $(SRC_DIR),conn_dis_token.cpp)
MAIN_CONNDIS = $(addprefix $(MAIN_DIR),test_conn_dis_token.cpp)


# Slot and Token information
HDR_STLIST = $(addprefix $(HEADER_DIR),slots_token_list.hpp)
SRC_STLIST = $(addprefix $(SRC_DIR),slots_token_list.cpp)
MAIN_STLIST = $(addprefix $(MAIN_DIR),test_slots_token_list.cpp)


# Elliptic Curve (EC) keypair generation
HDR_ECKEYPAIR = $(addprefix $(HEADER_DIR),gen_EC_keypair.hpp)
SRC_ECKEYPAIR = $(addprefix $(SRC_DIR),gen_EC_keypair.cpp)
MAIN_ECKEYPAIR = $(addprefix $(MAIN_DIR),test_gen_EC_keypair.cpp)


# Elliptic Curve Digital Signature Algorithm (ECDSA)
HDR_ECDSA = $(addprefix $(HEADER_DIR),sign_verify_ECDSA.hpp)
SRC_ECDSA = $(addprefix $(SRC_DIR),sign_verify_ECDSA.cpp)
MAIN_ECDSA = $(addprefix $(MAIN_DIR),test_sign_verify_ECDSA.cpp)


# Advanced Encryption Standard (AES) secret key generation
HDR_AESKEYS = $(addprefix $(HEADER_DIR),gen_AES_keys.hpp)
SRC_AESKEYS = $(addprefix $(SRC_DIR),gen_AES_keys.cpp)
MAIN_AESKEYS = $(addprefix $(MAIN_DIR),test_gen_AES_keys.cpp)



#Object files
OBJS_CONNDIS = main_ConnDis.o src_ConnDis.o
OBJS_STLIST = main_STList.o src_STList.o
OBJS_ECKEYPAIR = main_ECKeypair.o src_ECKeypair.o
OBJS_ECDSA = main_ECDSA.o src_ECDSA.o
OBJS_AESKEYS = main_AESKeys.o src_AESKeys.o


# Connect to and disconnect from a token
main_ConnDis.o: $(MAIN_CONNDIS)
	$(CXX) $(CXXFLAGS) $(CXX11) $< -o $@

src_ConnDis.o: $(SRC_CONNDIS) $(HDR_CONNDIS)
	$(CXX) $(CXXFLAGS) $(CXX11) $< -o $@

test_ConnDis: $(OBJS_CONNDIS)
	$(CXX) $^ -o $@


# Slot and Token information files
main_STList.o: $(MAIN_STLIST)
	$(CXX) $(CXXFLAGS) $(CXX11) $< -o $@

src_STList.o: $(SRC_STLIST) $(HDR_STLIST)
	$(CXX) $(CXXFLAGS) $(CXX11) $< -o $@

test_STList: $(OBJS_STLIST)
	$(CXX) $^ -o $@


# EC keypair files
main_ECKeypair.o: $(MAIN_ECKEYPAIR)
	$(CXX) $(CXXFLAGS) $(CXX11) $< -o $@

src_ECKeypair.o: $(SRC_ECKEYPAIR) $(HDR_ECKEYPAIR)
	$(CXX) $(CXXFLAGS) $(CXX11) $< -o $@

test_ECKeypair: $(OBJS_ECKEYPAIR)
	$(CXX) $^ -o $@


# Elliptic Curve Digital Signature Algorithm (ECDSA) files
main_ECDSA.o: $(MAIN_ECDSA)
	$(CXX) $(CXXFLAGS) $(CXX11) $< -o $@

src_ECDSA.o: $(SRC_ECDSA) $(HDR_ECDSA)
	$(CXX) $(CXXFLAGS) $(CXX11) $< -o $@

test_ECDSA: $(OBJS_ECDSA)
	$(CXX) $^ -o $@


# Advanced Encryption Standard (AES) secret key generation
main_AESKeys.o: $(MAIN_AESKEYS)
	$(CXX) $(CXXFLAGS) $(CXX11) $< -o $@

src_AESKeys.o: $(SRC_AESKEYS) $(HDR_AESKEYS)
	$(CXX) $(CXXFLAGS) $(CXX11) $< -o $@

test_AESKeys: $(OBJS_AESKEYS)
	$(CXX) $^ -o $@



.PHONY : clean
clean_test_ConnDis:
	rm test_ConnDis $(OBJS_CONNDIS)

clean_test_STList:
	rm test_STList $(OBJS_STLIST)

clean_test_ECKeypair:
	rm test_ECKeypair $(OBJS_ECKEYPAIR)

clean_test_ECDSA:
	rm test_ECDSA $(OBJS_ECDSA)

clean_test_AESKeys:
	rm test_AESKeys $(OBJS_AESKEYS)