#include <stdio.h>
#include "microtcp.h"

int main(void){
    int x = 0;
    x = x | 1 << 0;
    x = x | 1 << 1;
    printf("%d\n",x);
    return 0;
}