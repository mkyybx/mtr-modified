#include <cstdio>
#include <cstdlib>

int main() {
    int lineNum = 0;
    float first = 0;
    int firstLabel;
    float second = 0;
    int secondLabel;
    scanf("%d", &lineNum);
    float* data = (float*)malloc(sizeof(float) * lineNum);
    int* asnum = (int*)malloc(sizeof(int) * lineNum);
    for (int i = 0; i < lineNum; i++) {
        scanf("%d", &asnum[i]);
        scanf("%f", &data[i]);
        if (data[i] <= 10e-6 && i != 0)
            data[i] = data[i - 1];
    }
    for (int i = 1; i < lineNum; i++) {
        if (data[i] - data[i - 1] > first && asnum[i] == 4134) {
            first = data[i] - data[i - 1];
            firstLabel = i;
        }
        else if (data[i] - data[i - 1] > second && asnum[i] == 4134) {
            second = data[i] - data[i - 1];
            secondLabel = i;
        }
    }
    printf("%d\t%f\t%d\t%f\n", firstLabel + 1, first, secondLabel + 1, second);
    return 0;
}