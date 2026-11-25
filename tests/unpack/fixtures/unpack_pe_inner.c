// A program another one carries in its data and maps into memory: it
// calls an import and reads through a pointer that needs a relocation.
__declspec(dllimport) unsigned __stdcall GetTickCount(void);

static int addend = 42;
int *volatile pointer = &addend;

int inner(void) { return (int)GetTickCount() + *pointer; }
