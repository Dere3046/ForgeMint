__attribute__((visibility("default")))
int calc_add(int a, int b) { return a + b; }

__attribute__((visibility("default")))
int calc_sub(int a, int b) { return a - b; }

__attribute__((visibility("default")))
int calc_mul(int a, int b) { return a * b; }

__attribute__((visibility("default")))
int calc_div(int a, int b) { return b == 0 ? 0 : a / b; }
