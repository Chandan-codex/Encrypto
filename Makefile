CXX = g++
CXXFLAGS = -std=c++11 -Wall -I"E:/OpenSSL/openssl-3.0/x86/include"
LDFLAGS = "E:/OpenSSL/openssl-3.0/x86/lib/libssl.lib" "E:/OpenSSL/openssl-3.0/x86/lib/libcrypto.lib" -lws2_32 -lgdi32 -lcrypt32

TARGET = Encrypto.exe
SRCS = main.cpp HybridEncryptor.cpp
OBJS = $(SRCS:.cpp=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(OBJS) -o $(TARGET) $(LDFLAGS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean
