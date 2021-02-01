#include <stdio.h>
#include <stdlib.h>

int main(){
	setvbuf(stdout, NULL, _IONBF, 0);
	int can_read_flag = 0;
	char name[64];

	printf("Enter your name: ");
	gets(name);
	if (can_read_flag == 0x1){
		printf("Hi %s!\n",name);
		FILE *f;
		f = fopen("flag.txt","r");
		if (f == NULL){
			printf("flag.txt doesn't exist, try again on the server");
			exit(0);
		}
		char flag[0x32];
		fgets(flag,0x32,f);
		printf("%s\n",flag);
		fflush(stdout);
	} else {
		printf("Sorry, you aren't authorized!\n");
	}
}