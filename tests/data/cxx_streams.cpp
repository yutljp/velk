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
extern "C" int locale_characters();
extern "C" int locale_input();
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
    case 't': return locale_characters();
    case 'f': return locale_input();
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

extern "C" __attribute__((noinline)) int locale_characters() {
    const std::locale locale = std::cout.getloc();
    const auto &facet = std::use_facet<std::ctype<char>>(locale);
    const std::ctype_base::mask classes[] = {
        std::ctype_base::space, std::ctype_base::print, std::ctype_base::cntrl,
        std::ctype_base::upper, std::ctype_base::lower, std::ctype_base::alpha,
        std::ctype_base::digit, std::ctype_base::punct, std::ctype_base::xdigit,
        std::ctype_base::blank
    };
    for (unsigned int value = 0; value != 256; ++value) {
        const char character = static_cast<char>(value);
        unsigned int mask = 0;
        for (unsigned int index = 0; index != 10; ++index) {
            if (facet.is(classes[index], character)) mask |= 1U << index;
        }
        std::cout << static_cast<unsigned int>(static_cast<unsigned char>(facet.widen(character)))
                  << ':' << static_cast<unsigned int>(static_cast<unsigned char>(facet.narrow(character, '?')))
                  << ':' << mask << '\n';
    }
    return 0;
}

extern "C" __attribute__((noinline)) int locale_input() {
    std::string text;
    std::cin >> text;
    if (text.size() != 1) return 1;
    const std::locale locale = std::cin.getloc();
    const auto &facet = std::use_facet<std::ctype<char>>(locale);
    const char expected = static_cast<char>(0x80);
    return facet.widen(text[0]) == expected && facet.narrow(text[0], '?') == '?'
           && facet.narrow(text[0], text[0]) == expected ? accepted() : 1;
}
