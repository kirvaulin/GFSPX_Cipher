# Компилятор
CXX = g++

# Пути к Boost
BOOST_INCLUDE = C:/Users/honor/source/repos/GFSPX_Cipher/boost_1_87_0
BOOST_LIB = C:/Users/honor/source/repos/GFSPX_Cipher/boost_1_87_0/stage/lib

# Флаги компиляции
CXXFLAGS = -Wall -std=c++17 -I$(BOOST_INCLUDE) -L$(BOOST_LIB) -lboost_system

# Имя исполняемого файла
TARGET = gfspx_cipher.exe

# Исходные файлы
SRCS = GFSPX_Cipher.cpp

# Объектные файлы
OBJS = $(SRCS:.cpp=.o)

# Правило по умолчанию (сборка всего проекта)
all: $(TARGET)

# Правило для сборки исполняемого файла
$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(OBJS)

# Правило для компиляции .cpp файлов в .o файлы
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Очистка проекта (удаление объектных и исполняемых файлов)
clean:
	del $(OBJS) $(TARGET)