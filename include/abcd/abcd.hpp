#ifndef _ABCD_ABCD_HPP
#define _ABCD_ABCD_HPP
#include <iostream>
#include <string>

class ABCD {
public:
  ABCD(const std::string &filename, bool debug = false)
      : m_filename(filename), m_debug(debug) {
    if (m_debug) {
      std::cout << "Initialization of ABCD complete.\n";
    }
  }

  bool initialize() {
    return false;
  }

private:
  std::string m_filename;
  bool m_debug;
};

#endif