#include <iostream>
#include <string>
#include <utility>

extern "C" __attribute__((noinline)) int accepted() { volatile int result = 0; return result; }

extern "C" __attribute__((noinline)) int word() {
    std::string text;
    std::cin >> text;
    const bool success = text == "key";
    std::cout << (success ? "success" : "failure") << ':' << text << '\n';
    return success ? accepted() : 1;
}
extern "C" __attribute__((noinline)) int access() {
    std::string text;
    std::cin >> text;
    bool valid = text.size() == text.length() && text.begin() + text.size() == text.end()
        && text.c_str() == text.data()
        && &text[text.size()] == text.data() + text.size();
    if (!text.empty()) text[0] = 'X';
    std::cout << text;
    return valid && text == "Xey" ? accepted() : 1;
}
extern "C" __attribute__((noinline)) int string_operations() {
    std::string input;
    std::cin >> input;
    std::string moved(std::move(input));
    std::string text(moved);
    std::string copy;
    copy = text;
    copy += "-";
    copy.append(text, 1, 2);
    copy.append("xyz", 2);
    copy += '!';
    copy.push_back('?');
    const std::string part = copy.substr(1, 3);
    const auto position = copy.find(text);
    const auto character = copy.find('!');
    const bool equal = text == moved;
    const bool valid = equal && copy.compare(0, text.size(), text) == 0
        && copy.compare("invalid") != 0 && copy.at(0) == text[0]
        && copy[copy.size()] == '\0' && position == 0 && character == copy.size() - 2;
    std::cout << copy << ':' << part << ':' << position << ':' << character << ':'
              << copy.size() << '\n';
    return valid ? accepted() : 1;
}
extern "C" __attribute__((noinline)) int guarded_string() {
    static const std::string text("initialized");
    std::cout << text << '\n';
    return text == "initialized" ? accepted() : 1;
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
extern "C" __attribute__((noinline)) int integer_status() {
    int value = 42;
    std::cin >> value;
    std::cout << value << ':' << std::cin.fail() << ':' << std::cin.eof() << '\n';
    return 0;
}
extern "C" __attribute__((noinline)) int character_input() {
    char value = '?';
    std::cin >> value;
    std::cout << static_cast<unsigned int>(static_cast<unsigned char>(value)) << ':'
              << std::cin.fail() << ':' << std::cin.eof() << '\n';
    return 0;
}
extern "C" __attribute__((noinline)) int raw_character_input() {
    char value = '?';
    std::cin.get(value);
    std::cout << static_cast<unsigned int>(static_cast<unsigned char>(value)) << ':'
              << std::cin.fail() << ':' << std::cin.eof() << '\n';
    return 0;
}
extern "C" __attribute__((noinline)) int cstring_input() {
    char value[32] = {};
    std::cin >> value;
    std::cout << value << ':' << std::cin.fail() << ':' << std::cin.eof() << '\n';
    return 0;
}
extern "C" int constants();
extern "C" int numbers();
extern "C" int unsigned_numbers();
extern "C" int locale_characters();
extern "C" int locale_input();
int main(int argc, char **argv) {
    if (argc < 2) return 2;
    if (argv[1][0] == 's') return string_operations();
    if (argv[1][0] == 'g') return guarded_string();
    if (argv[1][0] == 'h') return character_input();
    if (argv[1][0] == 'q') return raw_character_input();
    if (argv[1][0] == 'p') return cstring_input();
    if (argv[1][0] == 'j') return integer_status();
    switch (argv[1][0]) {
    case 'w': return word();
    case 'a': return access();
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
