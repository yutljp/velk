#include "runtime.h"
__attribute__((noinline)) int check(const unsigned char *s) {
    static const unsigned char program[]={1,0,70,1,1,76,1,2,65,1,3,71,0}; unsigned pc=0; for(;;){unsigned op=program[pc++]; switch(op){case 0:return 1;case 1:{unsigned index=program[pc++]; if(s[index]!=program[pc++]) return 0;break;}default:return 0;}}
}
#include "main.h"
