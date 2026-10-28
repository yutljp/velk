#include "runtime.h"
__attribute__((noinline)) int check(const unsigned char *s) {
    unsigned state=0; for(unsigned i=0;i<4;i++){switch(state){case 0:if(s[i]!=70)return 0;state=1;break;case 1:if(s[i]!=76)return 0;state=2;break;case 2:if(s[i]!=65)return 0;state=3;break;case 3:if(s[i]!=71)return 0;state=4;break;default:return 0;}} return state==4;
}
#include "main.h"
