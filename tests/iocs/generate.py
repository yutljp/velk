from pathlib import Path

values = [
    "http://bad.example.org/path", "https://bad.example.com/path",
    "ftp://files.example.org/a", "ws://socket.example.info/", "wss://socket.example.net/",
    "example.com", "8.8.8.8", "2001:db8::1", "analyst@example.org", "C:\\Windows\\Temp\\bad.exe",
    "/usr/local/bin/bad", "HKLM\\Software\\Bad", "Mozilla/5.0 (X11; Linux x86_64)",
    "v1.2.3.4", "1.2.3.999", "notes.example.com.txt", "Zm9vYmFyMTIzNDU2",
]
functions = "\n".join(
    'const char *plain_' + str(index) + '(void) { return "'
    + value.replace("\\", "\\\\").replace('"', '\\"')
    + '"; }'
    for index, value in enumerate(values)
)
calls = " ".join(
    "result += plain_" + str(index) + "()[0] + decode_" + str(index) + "();"
    for index in range(len(values))
)
decoded_data = "\n".join(
    "static unsigned char decoded_" + str(index) + "[] = {"
    + ", ".join(str(byte ^ 93) for byte in value.encode() + b"\0")
    + "};\n__attribute__((noinline)) unsigned int decode_"
    + str(index)
    + "(void) { xor_key(decoded_"
    + str(index)
    + ", sizeof(decoded_"
    + str(index)
    + "), 93); return decoded_"
    + str(index)
    + "[0]; }"
    for index, value in enumerate(values)
)
source = f'''typedef unsigned char u8;
typedef unsigned int u32;
__attribute__((noinline)) u32 xor_key(u8 *p, u32 n, u32 key) {{
    u32 sum = 0;
    for (u32 i = 0; i < n; ++i) {{ p[i] ^= key; sum = sum * 33 + p[i]; }}
    return sum;
}}
{functions}
{decoded_data}
int main(void) {{ unsigned int result = 0; {calls} return (int)result; }}
'''
import sys

Path(sys.argv[1]).write_text(source)
