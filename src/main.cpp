
// SPDX-License-Identifier: MIT

#include "analyzer.hpp"
//
#include "spdlog/spdlog.h"

auto main() -> int {
  auto exp_analyzer{rparse::ElfioAnalyzer::Create("/code/data/test.elf")};
  if (not exp_analyzer) {
    spdlog::error("couldn't parse passed in elf file");
    return 1;
  }

  spdlog::info("elf parsed");
}
