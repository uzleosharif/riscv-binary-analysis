

// SPDX-License-Identifier: MIT

#ifndef ELF_READER_HPP
#define ELF_READER_HPP

#include <concepts>
#include <elfio/elf_types.hpp>
#include <numeric>
#include <string_view>

#include "elfio/elfio.hpp"
#include "spdlog/spdlog.h"
#include "tl/expected.hpp"

/// @brief riscv elf analyzer / parser space
namespace rparse {

/// @brief error possibilities expected on API calls
enum class Error { kLoadElf };

/// @brief abstract API for reading ELFs
///
/// allows to work with various elf-loaders generically for analysis algorithms
///
/// Load(): loads the elf binary into memory
/// GetNumberOfInstructions(): number of instructions in the elf binary
template <class T>
concept ElfReader = requires(T reader, std::string_view file_name) {
  { reader.Load(file_name) } -> std::same_as<tl::expected<void, Error>>;
  //{ reader.GetNumberOfInstructions() } -> std::same_as<std::size_t>;
};

/// @brief concrete implementation of rparse::ElfReader
///
/// This uses `ELFIO` library under-the-hood
///
/// @tparam elf_section_t elf-section notion
class ElfioReader final {
 public:
  constexpr ElfioReader() noexcept {
    m_reader = std::make_unique<ELFIO::elfio>();
  }

  /// @brief API
  /// @see rparse::ElfReader
  [[nodiscard]] constexpr auto Load(std::string_view file_name) noexcept
      -> tl::expected<void, Error> {
    try {
      auto load_ok{m_reader->load(std::string{file_name})};
      if (not load_ok) {
        return tl::unexpected{Error::kLoadElf};
      }
    } catch (...) {
      return tl::unexpected{Error::kLoadElf};
    }

    return {};
  }

  /// @brief API
  /// @see rparse::ElfReader
  [[nodiscard]] auto GetNumberOfInstructions() const noexcept -> std::size_t {
    std::size_t num_instructions{0};
    for (const auto& sec : m_reader->sections) {
      if (sec->get_type() == SHT_PROGBITS) {
        num_instructions += sec->get_size();
      }
    }
    return num_instructions;
  }

 private:
  // NOTE: automatic allocation leads to memory leaks!!
  // possibly move-semantics for ELFIO::elfio are not implemented properly
  std::unique_ptr<ELFIO::elfio> m_reader{};
};
/*
class TestReader final {
 public:
  [[nodiscard]] constexpr auto Load(std::string_view file_name) noexcept
      -> tl::expected<void, Error> {
    m_filename = file_name;
    return {};
  }

 private:
  std::string m_filename{};
};*/

//NOTE: we stop generalizing at RISC-V but could be possible later to extend
// this module for other RISC ISAs

/// @brief provides analysis functionalities for RISCV elf
///
/// @tparam elf_reader_t elf-reader statically dependency-injected as component
template <ElfReader elf_reader_t>
class Analyzer final {
 public:
  /// @brief static factory-method to create instances
  ///
  /// i am trying to avoid exceptions, heaps, singleton instances at call-site
  ///
  /// @param elf_filename absolute path to elf file location
  /// @return a _valid_ instance
  [[nodiscard]] static constexpr auto Create(
      std::string_view elf_filename) noexcept
      -> tl::expected<Analyzer<elf_reader_t>, Error> {
    try {
      auto analyzer{Analyzer<elf_reader_t>{elf_filename}};
      return analyzer;
    } catch (...) {
      return tl::unexpected{Error::kLoadElf};
    }
  }

  constexpr ~Analyzer() noexcept = default;
  Analyzer(const Analyzer&) noexcept = delete;
  [[nodiscard]] constexpr Analyzer(Analyzer&&) noexcept = default;
  auto operator=(const Analyzer&) noexcept -> Analyzer& = delete;
  [[nodiscard]] constexpr auto operator=(Analyzer&&) noexcept
      -> Analyzer& = default;

  /// @return number of instructions
  [[nodiscard]] constexpr auto GetNumberOfInstructions() const noexcept
      -> std::size_t {
    return m_elf_reader.GetNumberOfInstructions();
  }

 private:
  elf_reader_t m_elf_reader{};

  /// @brief initializes the object properly
  ///
  /// @param elf_filename aboslute path to elf file location
  constexpr Analyzer(std::string_view elf_filename) {
    if (not m_elf_reader.Load(elf_filename)) {
      throw std::runtime_error{"ELF file could not be loaded properly"};
    }
  }
};

static_assert(not std::is_copy_assignable_v<Analyzer<ElfioReader>>);
static_assert(not std::is_copy_constructible_v<Analyzer<ElfioReader>>);
static_assert(std::is_move_assignable_v<Analyzer<ElfioReader>>);
static_assert(std::is_move_constructible_v<Analyzer<ElfioReader>>);

/// @brief Analyzer that uses ELFIO library for parsing ELF files
using ElfioAnalyzer = Analyzer<ElfioReader>;
//using TestAnalyzer = Analyzer<TestReader>;
}  // namespace rparse

#endif
