#include <abcd/abcd.hpp>
#include <cstdlib>
#include <fstream>
#include <ios>
#include <iostream>

#include <args.hxx>

int main(int argc, char *argv[]) {
  args::ArgumentParser parser(
      "Perform disassembly of an ELF binary.");
  args::HelpFlag help(parser, "help", "Display this help menu", {'h', "help"});
  args::Flag debug(parser, "debug", "Enable debugging.", {"d", "debug"});
  args::Flag disassemble_recursively(parser, "recursive", "Disassemble recursively.", {"r", "recursive"});
  args::ValueFlag<std::string> outfile_param(
      parser, "outfile", "Store output to a file", {"o", "outfile"});
  args::Positional<std::string> binary(
      parser, "binary", "The name of the binary file to disassemble.",
      args::Options::Required);
  try {
    parser.ParseCLI(argc, argv);
  } catch (args::Help) {
    std::cout << parser;
    return 0;
  } catch (args::ParseError e) {
    std::cerr << e.what() << std::endl;
    std::cerr << parser;
    return 1;
  } catch (args::ValidationError e) {
    std::cerr << e.what() << std::endl;
    std::cerr << parser;
    return 1;
  }

  std::ofstream outfile_stream{};
  if (outfile_param) {
    outfile_stream.open(outfile_param.Get(), std::ios::trunc);
    if (!outfile_stream.is_open()) {
      std::cerr << "Error: Could not open output file ... output will be sent "
                   "to stdout!\n";
    }
  }
  std::ostream &output_stream =
      outfile_stream.is_open() ? outfile_stream : std::cout;

  std::ifstream binary_stream{binary.Get()};
  if (!binary_stream.is_open()) {
    std::cerr << "Error: Could not open the binary for disassembly!\n";
    if (outfile_stream.is_open()) {
      outfile_stream.close();
    }
    exit(EXIT_FAILURE);
  }

  ABCD *abcd = nullptr;
  if (disassemble_recursively) {
    abcd = new RecursiveABCD{binary.Get(), ".text", debug};
  } else {
    abcd = new LinearABCD{binary.Get(), ".text", debug};
  }

  std::string initialization_error_msg{""};
  if (!abcd->initialize(initialization_error_msg)) {
    std::cerr << "Initialization failed: " << initialization_error_msg << "\n";
    if (outfile_stream.is_open()) {
      outfile_stream.close();
    }
    exit(EXIT_FAILURE);
  }

  uint64_t bad_address{0};
  if (!abcd->disassemble(bad_address)) {
    std::cerr << "Failed to disassemble instruction at 0x" << std::hex
              << bad_address << std::dec << ".\n";
    if (outfile_stream.is_open()) {
      outfile_stream.close();
    }
    exit(EXIT_FAILURE);
  }

  if (!abcd->output_disassembly(output_stream)) {
    std::cerr << "Failed to save disassembly to output!\n";
  }

  if (outfile_stream.is_open()) {
    outfile_stream.close();
  }

  delete abcd;

  return 0;
}