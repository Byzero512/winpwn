#include <stdio.h>
#include<stdlib.h>
char *a = "lewis";
char s[0x10];

int main() {
    setbuf(stdout,0);
    setbuf(stdin,0);
    printf("%p", a);
    scanf("%s", s);
    return 0;
}