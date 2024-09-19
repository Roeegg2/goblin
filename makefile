CC = g++
SRC = $(wildcard src/*.cpp)
X86_64_ASM = $(wildcard src/x86_64/*.S)
OBJ = $(SRC:src/%.cpp=bin/%.o) $(X86_64_ASM:src/x86_64/%.S=bin/%.o)
FLAGS = -g -Wall -pedantic -std=c++20 -fPIC -Werror -Wextra  # \
# -DDEBUG -g

ASMFLAGS = -g -v

elf: init $(OBJ)
	$(CC) $(OBJ) -o goblin

bin/%.o: src/x86_64/%.S
	as $(ASMFLAGS) $< -o $@

bin/%.o: src/%.cpp
	$(CC) $(FLAGS) -c $< -o $@

clean:
	rm -f stupidelf
	rm -f bin/*.o

init:
	mkdir -p bin

.PHONY: clean init
