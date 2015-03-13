#include <stdio.h>
#include <stdlib.h>

int main() {
    int i = 0, j = 0, k = 0;

    while (j < 20) {
      if (i == 0) {
          if (k == 5) {
              printf("1\n");
              goto label;
          }
      } else {
          printf("2\n");
  label:
          printf("3\n");
          j++;
      }
      j += 5;
    }

    return 0;
}





