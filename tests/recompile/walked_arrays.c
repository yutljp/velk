#include <stdint.h>

int g;

int32_t frame_array(int n) {
    int32_t a[5][5][3][4];
    int i, j, k, l;
    for (i = 0; i < 5; i++)
        for (j = 0; j < 5; j++)
            for (k = 0; k < 3; k++)
                for (l = 0; l < 4; l += 2) {
                    a[i][j][k][l] = 0xe85c1e65;
                    a[i][j][k][l + 1] = 0xe85c1e65;
                }
    return a[n % 5][g % 5][n % 3][n & 3] + g;
}

int main(void) { return frame_array(2) & 0xff; }
