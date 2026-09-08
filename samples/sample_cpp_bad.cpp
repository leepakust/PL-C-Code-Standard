// Deliberate MISRA C++:2023 violations for scanner demonstration.
#include <cstdio>
#include <vector>
#define DOUBLE(x) ((x) * 2)

namespace example
{
union Data
{
    int integer;
    float real;
};

void demonstrate()
{
    auto octal = 052;
    auto suffix = 1l;
    int *pointer = NULL;
    auto allocated = new int{42};
    std::vector<bool> flags;
    std::printf("Example: %d", octal);
    delete allocated;
}
}
