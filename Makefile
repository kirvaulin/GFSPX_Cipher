# ����������
CXX = g++

# ���� � Boost
BOOST_INCLUDE = C:/Users/honor/source/repos/GFSPX_Cipher/boost_1_87_0
BOOST_LIB = C:/Users/honor/source/repos/GFSPX_Cipher/boost_1_87_0/stage/lib

# ����� ����������
CXXFLAGS = -Wall -std=c++17 -I$(BOOST_INCLUDE) -L$(BOOST_LIB) -lboost_system

# ��� ������������ �����
TARGET = gfspx_cipher.exe

# �������� �����
SRCS = GFSPX_Cipher.cpp

# ��������� �����
OBJS = $(SRCS:.cpp=.o)

# ������� �� ��������� (������ ����� �������)
all: $(TARGET)

# ������� ��� ������ ������������ �����
$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(OBJS)

# ������� ��� ���������� .cpp ������ � .o �����
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# ������� ������� (�������� ��������� � ����������� ������)
clean:
	del $(OBJS) $(TARGET)