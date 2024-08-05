#ifndef TYPES_HPP
#define TYPES_HPP

#ifdef __amd64__
using u8 = unsigned char;
using u16 = unsigned short;
using u32 = unsigned int;
using u64 = unsigned long long;

using s8 = signed char;
using s16 = signed short;
using s32 = signed int;
using s64 = signed long long;

// #define u8 unsigned char
// #define u16 unsigned short
// #define u32 unsigned int
// #define u64 unsigned long long

// #define s8 signed char
// #define s16 signed short
// #define s32 signed int
// #define s64 signed long long

#else
#error "Unsupported architecture"

#endif

#endif