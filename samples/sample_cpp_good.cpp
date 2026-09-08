// C++17 examples compliant with the implemented MISRA C++:2023 subset.
// Run with --std "MISRA C++:2023"; house C style is a separate rule family.
#include <array>
#include <cstdint>

namespace example
{
constexpr std::uint32_t count = 1'000U;
constexpr std::array<bool, 2> flags{true, false};
constexpr auto message = R"text(A raw string containing "quotes" and /* text */)text";

std::int32_t convert(double value)
{
    return static_cast<std::int32_t>(value);
}
}
