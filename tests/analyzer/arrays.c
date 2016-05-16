#include <stdio.h>
#include <stdio.h>

int global_array[] = {0,1,2,3,4,5,6,7,8,9};
char global_string[] = "this is a string.\n";
void *global_ptr[] = {global_array, global_string, global_string+4};

int main(int argc, char **argv) {
    int a = global_array[0];
    int b = global_array[5];
    int c = global_array[9];
    char d = global_string[7];
    void *p = global_ptr[0];

    printf("%d\n", global_array[8]);
    printf("%s\n", global_string);
    printf("%s\n", global_string + 3);

    return 0;
}
