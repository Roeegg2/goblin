CC = g++
SRC = $(wildcard src/*.cpp)
OBJ = $(SRC:src/%.cpp=bin/%.o)
INCLUDE = -Iinclude
FLAGS = -Wall -Wextra -pedantic -std=c++20 -nostdlib -DDEBUG -g

elf: $(OBJ)
	mkdir -p bin
	$(CC) $(OBJ) -e main -o stupidelf

bin/%.o: src/%.cpp
	$(CC) $(FLAGS) $(INCLUDE) -c $< -o $@

clean:
	rm -f stupidelf
	rm -f bin/*.o

.PHONY: clean
