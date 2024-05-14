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


#Object files
OBJS_CONNDIS = main_ConnDis.o src_ConnDis.o


# Connect to and disconnect from a token
main_ConnDis.o: $(MAIN_CONNDIS)
	$(CXX) $(CXXFLAGS) $(CXX11) $< -o $@

src_ConnDis.o: $(SRC_CONNDIS) $(HDR_CONNDIS)
	$(CXX) $(CXXFLAGS) $(CXX11) $< -o $@

test_ConnDis: $(OBJS_CONNDIS)
	$(CXX) $^ -o $@


.PHONY : clean
clean:
	rm test_ConnDis $(OBJS_CONNDIS)