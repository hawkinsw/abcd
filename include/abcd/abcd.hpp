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
  /** Construct an ELF binary disassembler. Depending on the parameters,
   * the binary disassembler that is constructed will be configured to
   * disassemble the binary at the path named _filename_.
   *
   * @param filename The name of the file to disassemble.
   * @param program_section_name The name of the section that contains the
   * entry point. Optional; defaults to `.text`.
   * @param debug Set the debugging mode on this instance of the disassembler.
   * Optional; defaults to `false`
   * @post m_initialized = `false`
   * @post m_disassembled = `false`
   * @post m_entry_point = `0`
   */
  ABCD(const std::string &filename,
       const std::string &program_section_name = ".text", bool debug = false)
      : m_filename(filename), m_program_section_name(program_section_name),
        m_debug(debug), m_initialized(false), m_disassembled(false),
        m_entry_point(){};

  /** Initialize the ELF binary disassembler. Attempt to initialize the ELF
   * binary disassembler for the file named m_filename.
   *
   * @param err_message The contents of any error messages generated when
   * initializing the parser.
   * @returns true if the parser could be initialized; false otherwise.
   * @post If successful, m_initialized = true.
   * @post If unsuccessful, m_initialized = false.
   * @post If (un)successful, m_disassembled = true.
   * @post If successful, m_virtual_data is a VirtualData object containing the
   * contents of the m_program_section_name section.
   */
  virtual bool initialize(std::string &err_message);

  /** Disassemble the ELF binary . Attempt to linearly disassemble the ELF
   * binary. Must call ABCD::initialize before calling this function.
   *
   * @pre m_initialized must be true.
   * @param err_message The contents of any error messages generated when
   * initializing the parser.
   * @returns true if the linear disassembly was successful.
   * @post m_initialized is unchanged.
   * @post If successful, m_disassembled = true.
   * @post If unsuccessful, m_disassembled = false.
   */
  virtual bool disassemble(uint64_t &bad_insn_addr) = 0;

  /** Write the disassembly. Write the disassembly using the std::ostream given
   * as a parameter. Must call ABCD::linear_disassemble before this function.
   *
   * @pre m_disassembled must be true.
   * @param err_message The contents of any error messages generated when
   * initializing the parser.
   * @returns true if the disassembly was written to the output stream
   * successfully.
   * @post m_initialized is unchanged.
   * @post m_disassembled is unchanged.
   */
  virtual bool output_disassembly(std::ostream &os) const = 0;

  virtual ~ABCD() {}

protected:
  std::string m_filename, m_program_section_name;
  bool m_debug, m_initialized, m_disassembled;
  VirtualData m_virtual_data;
  uint64_t m_entry_point;
};

class LinearABCD : public ABCD {
public:
  using ABCD::ABCD;
  virtual bool disassemble(uint64_t &bad_insn_addr) override;
  virtual bool output_disassembly(std::ostream &os) const override;
  virtual ~LinearABCD() {}

private:
  std::map<uint64_t, std::string> m_decoded;
};

class RecursiveABCD : public ABCD {
public:
  using ABCD::ABCD;
  virtual bool disassemble(uint64_t &bad_insn_addr) override;
  virtual bool output_disassembly(std::ostream &os) const override;
  virtual ~RecursiveABCD() {}

private:
  std::map<uint64_t, std::string> m_decoded;
};

#endif