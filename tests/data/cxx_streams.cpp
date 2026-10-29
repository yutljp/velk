#include <iostream>
#include <string>

extern "C" __attribute__((noinline)) int accepted() { volatile int result = 0; return result; }

extern "C" __attribute__((noinline)) int word() {
    std::string text;
    std::cin >> text;
    const bool success = text == "key";
    std::cout << (success ? "success" : "failure") << ':' << text << '\n';
    return success ? accepted() : 1;
}
extern "C" __attribute__((noinline)) int line() {
    std::string text;
    std::getline(std::cin, text);
    const bool success = text == "a key";
    std::cout << (success ? "success" : "failure") << ':' << text << std::endl;
    return success ? accepted() : 1;
}
extern "C" __attribute__((noinline)) int integer() {
    int value = 0;
    std::cin >> value;
    if (value != -123) return 1;
    std::cout << value << ':' << static_cast<unsigned int>(value) << ':'
              << static_cast<long long>(value) << std::flush << '\n';
    return accepted();
}
extern "C" __attribute__((noinline)) int integer_echo() {
    int value = 0;
    std::cin >> value;
    std::cout << value << ':' << static_cast<unsigned int>(value) << ':'
              << static_cast<long long>(value) << std::flush << '\n';
    return 0;
}
extern "C" int constants();
extern "C" int numbers();
extern "C" int unsigned_numbers();
int main(int argc, char **argv) {
    if (argc < 2) return 2;
    switch (argv[1][0]) {
    case 'w': return word();
    case 'l': return line();
    case 'i': return integer();
    case 'c': return constants();
    case 'e': return integer_echo();
    case 'n': return numbers();
    case 'u': return unsigned_numbers();
    default: return 2;
    }
}
extern "C" __attribute__((noinline)) int constants() {
    const std::string short_text("hello");
    const std::string long_text("abcdefghijklmnopqrstuvwxyz");
    std::cout << short_text << ':' << long_text << ':' << -9223372036854775807LL - 1
              << ':' << 18446744073709551615ULL << '\n';
    return 0;
}
extern "C" __attribute__((noinline)) int formatted() {
    std::cout << std::hex << 255;
    return 0;
}
extern "C" __attribute__((noinline)) int unsupported() {
    std::cout << 1.5;
    return 0;
}
extern "C" __attribute__((noinline)) int numbers() {
    long long value = 0;
    std::cin >> value;
    std::cout << value << ':' << static_cast<unsigned long long>(value) << '\n';
    return 0;
}
extern "C" __attribute__((noinline)) int unsigned_numbers() {
    unsigned long long value = 0;
    std::cin >> value;
    std::cout << value << '\n';
    return 0;
}
