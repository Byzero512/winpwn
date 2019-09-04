#include<stdio.h>
#include<stdlib.h>
int main(){
	setbuf(stdout,0);
	setbuf(stdin,0);
	setbuf(stderr,0);
	puts("please input:");
	char buf[0x30];
	read(0,buf,0x30);
	puts("content: ");
	puts(buf);
	puts("input again:");
	read(0,buf,0x30);
	puts("content: ");
	puts(buf);
	puts("bye");
}
