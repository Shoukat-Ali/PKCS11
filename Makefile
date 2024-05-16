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



#Object files
OBJS_CONNDIS = main_ConnDis.o src_ConnDis.o
OBJS_STLIST = main_STLIST.o src_STLIST.o


# Connect to and disconnect from a token
main_ConnDis.o: $(MAIN_CONNDIS)
	$(CXX) $(CXXFLAGS) $(CXX11) $< -o $@

src_ConnDis.o: $(SRC_CONNDIS) $(HDR_CONNDIS)
	$(CXX) $(CXXFLAGS) $(CXX11) $< -o $@

test_ConnDis: $(OBJS_CONNDIS)
	$(CXX) $^ -o $@


# Slot and Token information files
main_STLIST.o: $(MAIN_STLIST)
	$(CXX) $(CXXFLAGS) $(CXX11) $< -o $@

src_STLIST.o: $(SRC_STLIST) $(HDR_STLIST)
	$(CXX) $(CXXFLAGS) $(CXX11) $< -o $@

test_STList: $(OBJS_STLIST)
	$(CXX) $^ -o $@



.PHONY : clean
clean:
#	rm test_ConnDis $(OBJS_CONNDIS)
	rm test_STList $(OBJS_STLIST)