#ifndef _ABCD_ABCD_HPP
#define _ABCD_ABCD_HPP
#include <iostream>
#include <map>
#include <string>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <elf.h>
#include <libelf.h>

#include <abcd/virtualdata.hpp>

class ABCD {
public:
  ABCD(const std::string &filename,
       const std::string &program_section_name = ".text", bool debug = false)
      : m_filename(filename), m_program_section_name(program_section_name),
        m_debug(debug), m_initialized(false), m_disassembled(false),
        m_entry_point(){};

  bool initialize(std::string &err_message);
  bool linear_disassemble(uint64_t &bad_insn_addr);
  bool output_disassembly(std::ostream &os) const;

private:
  std::string m_filename, m_program_section_name;
  bool m_debug, m_initialized, m_disassembled;

  VirtualData m_virtual_data;
  uint64_t m_entry_point;
  std::map<uint64_t, std::string> m_decoded;
};

#endif