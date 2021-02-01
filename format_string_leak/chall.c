#include <stdio.h>
#include <stdlib.h>

int main(){
	setvbuf(stdout, NULL, _IONBF, 0);
	char* val1 = "not the flag :(";
	char* val2 = "still not the flag";
	char* val3 = "i dont think this is right";
	char* val4 = "doesn't look like it";
	char* val5 = "i dont see the flag format";
	char* val6 = "not quite there yet";
	char* val7 = "FLAG{f0rm47_57r1n6_l34k_69cd8e}";
	char* val8 = "i think you went too far";
	char* name = malloc(50);
	printf("*it sounds like this cave is echoing... what do you want to say?*");
	fgets(name, 50, stdin);
	printf(name);
	free(name);
}