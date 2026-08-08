#pragma once

#include <array>
#include <atomic>
#include <optional>

template <typename T, size_t Capacity>
class SPSCQueue {

    static_assert(Capacity > 0 && (Capacity & (Capacity - 1)) == 0, "Capacity must be a power of 2");

private:
    std::array<T, Capacity> buffer;
    alignas(64) std::atomic<size_t> write{0};
    alignas(64) std::atomic<size_t> read{0};

public:
    SPSCQueue() = default;

    size_t wrap_index(size_t index) {
        return index & (Capacity - 1);
    }

    bool push(const T& item) {
        if (is_full()) {
            return false;
        }
        size_t write_idx = wrap_index(write);
        buffer[write_idx] = std::move(item);
        write++;
        return true;
    }
    
    std::optional<T> pop() {
        if (is_empty()) {
            return std::nullopt;
        }
        size_t read_idx = wrap_index(read);
        T item = std::move(buffer[read_idx]);
        read++;
        return item;
    }

    bool is_empty() {
        if (write == read) {
            return true;
        }
        return false;
    }

    bool is_full() {
        if (write - read == Capacity) {
            return true;
        }
        return false;
    }
};