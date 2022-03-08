#ifndef _ABCD_VIRTUAL_DATA_HPP
#define _ABCD_VIRTUAL_DATA_HPP

#include <iostream>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>

class VirtualData {
public:
  VirtualData() : m_data(nullptr), m_virtual_size(0), m_virtual_start(0) {
  }
  VirtualData(char *data, uint64_t virtual_start, size_t virtual_size)
      : m_data(data), m_virtual_size(virtual_size),
        m_virtual_start(virtual_start) {
  }
  VirtualData(const VirtualData &) = delete;
  VirtualData(VirtualData &&other) {
    std::cout << "Using a move constructor=.\n";
    m_data = other.m_data;
    m_virtual_size = other.m_virtual_size;
    m_virtual_start = other.m_virtual_start;
    other.m_data = nullptr;
    other.m_virtual_start = 0;
    other.m_virtual_size = 0;
  }

  VirtualData &operator=(VirtualData &) = delete;
  VirtualData &operator=(VirtualData &&other) {
    std::cout << "Using a move operator=.\n";
    m_data = other.m_data;
    m_virtual_size = other.m_virtual_size;
    m_virtual_start = other.m_virtual_start;
    other.m_data = nullptr;
    other.m_virtual_start = 0;
    other.m_virtual_size = 0;
    return *this;
  }

  char *get(uint64_t address) const {
    int64_t potentially_bad_offset = address - m_virtual_start;
    if (potentially_bad_offset < 0) {
      return nullptr;
    }
    uint64_t actual_offset = address - m_virtual_start;
    return (char *)(m_data + actual_offset);
  }
  uint64_t size() const {
    return m_virtual_size;
  };

  uint64_t start() const {
    return m_virtual_start;
  }

  ~VirtualData() {
    free(m_data);
    m_data = nullptr;
    m_virtual_size = 0;
    m_virtual_start = 0;
  }

private:
  char *m_data;
  size_t m_virtual_size;
  uint64_t m_virtual_start;
};

#endif