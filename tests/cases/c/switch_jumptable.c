volatile int g;
int d7(int x) {
    switch (x) {
    case 0: for (int j = 0; j < 1; j++) g += j; break;
    case 1: for (int j = 0; j < 2; j++) g += j; break;
    case 2: for (int j = 0; j < 3; j++) g += j; break;
    case 3: for (int j = 0; j < 4; j++) g += j; break;
    case 4: for (int j = 0; j < 5; j++) g += j; break;
    case 5: for (int j = 0; j < 6; j++) g += j; break;
    case 6: for (int j = 0; j < 7; j++) g += j; break;
    case 7: for (int j = 0; j < 8; j++) g += j; break;
    case 8: for (int j = 0; j < 9; j++) g += j; break;
    case 9: for (int j = 0; j < 10; j++) g += j; break;
    default: g = -1; break;
    }
    return g;
}
