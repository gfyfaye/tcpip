#include <chrono>

inline uint64_t read_cycles() {
    return std::chrono::high_resolution_clock::now().time_since_epoch().count();
}
