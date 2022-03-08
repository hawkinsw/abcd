#include <algorithm>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include <fcntl.h>
#include <memory.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <elf.h>
#include <libelf.h>

#include <Zydis/Zydis.h>
#include <abcd/abcd.hpp>

bool ABCD::initialize(std::string &err_message) {
  int elf_fd;
  Elf *elf_handle;
  Elf_Scn *scn_iterator{nullptr};
  Elf64_Ehdr *ehdr{nullptr};

  Elf_Scn *string_scn{nullptr};
  Elf_Data *string_data{nullptr};

  Elf64_Shdr *program_shdr{nullptr};
  Elf_Scn *program_scn{nullptr};
  Elf_Data *program_scn_data{nullptr};

  if ((elf_fd = open(m_filename.c_str(), O_RDONLY)) < 0) {
    std::cerr << (err_message = "Could not open the requested ELF file.");
    return false;
  }

  elf_version(EV_CURRENT);
  elf_handle = elf_begin(elf_fd, ELF_C_READ, nullptr);

  if (!elf_handle) {
    close(elf_fd);
    std::cerr << (err_message =
                      "Could not create an ELF handle for the ELF file.");
    return false;
  }

  /* Obtain the .shstrtab data buffer */
  if (((ehdr = elf64_getehdr(elf_handle)) == nullptr) ||
      ((string_scn = elf_getscn(elf_handle, ehdr->e_shstrndx)) == nullptr) ||
      ((string_data = elf_getdata(string_scn, nullptr)) == nullptr)) {
    elf_end(elf_handle);
    close(elf_fd);
    std::cerr << (err_message = "Could not find the string header.");
    return false;
  }

  m_entry_point = ehdr->e_entry;

  if (m_debug) {
    std::cout << "Discovered an entry point at 0x" << std::hex << m_entry_point
              << std::dec << "\n";
  }

  /* Traverse input filename, printing each section */
  while ((scn_iterator = elf_nextscn(elf_handle, scn_iterator))) {
    Elf64_Shdr *shdr{nullptr};
    if ((shdr = elf64_getshdr(scn_iterator)) == NULL) {
      elf_end(elf_handle);
      close(elf_fd);
      std::cerr << (err_message =
                        "Failed to iterate through the section headers.");
      return false;
    }

    char *current_section_name = (char *)string_data->d_buf + shdr->sh_name;
    if (m_program_section_name == current_section_name) {
      // We found the program section!
      program_scn = scn_iterator;
      program_shdr = shdr;
      program_scn_data = elf_getdata(program_scn, nullptr);

      if (m_debug) {
        std::cout << "Found the program section!";
      }
      break;
    }
  }

  if (!program_scn) {
    elf_end(elf_handle);
    close(elf_fd);
    std::cerr << (err_message = "Could not find the program section!");
    return false;
  }

  if (m_debug) {
    std::cout << "Initialization of ABCD complete.\n";
  }

  char *program_section_data = (char *)malloc(program_scn_data->d_size);
  memcpy(program_section_data, program_scn_data->d_buf,
         program_scn_data->d_size);

  m_virtual_data = std::move(VirtualData(
      program_section_data, program_shdr->sh_addr, program_scn_data->d_size));

  elf_end(elf_handle);
  close(elf_fd);

  m_initialized = true;
  return true;
}

bool ABCD::linear_disassemble(uint64_t &bad_insn_addr) {
  if (!m_initialized) {
    bad_insn_addr = 0;
    return false;
  }

  ZydisDecoder decoder;
  ZydisFormatter formatter;
  ZydisDecodedInstruction instruction;
  ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT_VISIBLE];

  const static int LARGEST_X86_64_INSTR = 15;
  const static int DECODED_INSTRUCTION_BUFFER_LENGTH = 256;
  char decoded_instruction_buffer[DECODED_INSTRUCTION_BUFFER_LENGTH] = {
      0,
  };

  ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
  ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);

  uint64_t rip = m_entry_point;
  uint64_t rip_max = m_virtual_data.start() + m_virtual_data.size();
  while (rip < rip_max) {

    if (ZYAN_FAILED((ZydisDecoderDecodeFull(
            &decoder, m_virtual_data.get(rip), LARGEST_X86_64_INSTR,
            &instruction, operands, ZYDIS_MAX_OPERAND_COUNT_VISIBLE,
            ZYDIS_DFLAG_VISIBLE_OPERANDS_ONLY)))) {
      bad_insn_addr = rip;
      return false;
    }

    if (ZYAN_FAILED(ZydisFormatterFormatInstruction(
            &formatter, &instruction, operands,
            instruction.operand_count_visible, decoded_instruction_buffer,
            sizeof(decoded_instruction_buffer), m_entry_point))) {
      bad_insn_addr = rip;
      return false;
    }

    m_decoded[rip] = std::string{decoded_instruction_buffer};

    rip += instruction.length;
  }
  m_disassembled = true;
  return true;
}

bool ABCD::output_disassembly(std::ostream &os) const {

  if (!m_disassembled) {
    return false;
  }
  std::vector<uint64_t> addr_locs{};
  for (auto key : m_decoded) {
    addr_locs.push_back(key.first);
  }
  std::sort(addr_locs.begin(), addr_locs.end());

  os << m_filename << "\tentry point: 0x" << std::hex << m_entry_point << "\n"
     << std::dec;
  for (auto key : addr_locs) {
    // Have to use at() here because otherwise we cannot
    // make this a const member function (because [] *may*
    // change the value of something in the map).
    os << std::hex << key << ": " << m_decoded.at(key) << "\n";
  }

  return true;
}