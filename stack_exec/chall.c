#include <stdio.h>
#include <stdlib.h>


int vuln() {
	char data[128];
	printf("What would you like to store in memory today (%x)?\n", &data);
	gets(data);
}

int main(){
	setvbuf(stdout, NULL, _IONBF, 0);
	vuln();
}