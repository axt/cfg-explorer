CXX = g++

CXXFLAGS = -g -Wall -Wextra -Werror -pedantic -O3

TARGET = target

SRC = hello.cpp

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRC)

.PHONY: clean

clean:
	rm -f $(TARGET)