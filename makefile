CC = g++
SRC = $(wildcard src/*.cpp)
OBJ = $(SRC:src/%.cpp=bin/%.o)
FLAGS = -Wall -pedantic -std=c++20 -DDEBUG -g

elf: init $(OBJ)
	$(CC) $(OBJ) -nostdlib -e main -o stupidelf

bin/%.o: src/%.cpp
	$(CC) $(FLAGS) -c $< -o $@

clean:
	rm -f stupidelf
	rm -f bin/*.o

init:
	mkdir -p bin

.PHONY: clean init
