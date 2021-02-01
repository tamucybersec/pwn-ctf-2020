#include <stdio.h>
#include <stdlib.h>

void vuln() {
	char data[32];

	puts("This binary does nothing; good luck getting the flag now!\n");
	gets(data);
}

int main(){
	setvbuf(stdout, NULL, _IONBF, 0);
	vuln();
}