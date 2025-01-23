Response:
The user wants a summary of the functionality of the C++ code provided, which is located in `v8/tools/wasm/module-inspector.cc`. I need to analyze the code and identify its main purpose and the different actions it can perform. The prompt also asks to:

1. **Check if it's Torque:** Based on the file extension.
2. **Relate to JavaScript:** If it interacts with JS, provide an example.
3. **Provide logic examples:**  Give hypothetical inputs and outputs.
4. **Illustrate common errors:** Show potential user mistakes.
5. **Summarize the overall function.**

Let's break down the code analysis:

- **Includes:** The included headers suggest it's a tool for inspecting WebAssembly modules. It uses V8's internal WASM APIs.
- **`PrintHelp`:** This function clearly outlines the command-line arguments and actions the tool supports. These actions will be the core functionalities I need to summarize.
- **Actions (from `PrintHelp`):** `--help`, `--list-functions`, `--list-signatures`, `--section-stats`, `--instruction-stats`, `--function-stats`, `--single-wat`, `--full-wat`, `--single-hexdump`, `--full-hexdump`, `--mjsunit`, `--strip`. These are the primary functions.
- **Options (from `PrintHelp`):** `--offsets`, `-o/--output`. These modify the output.
- **`InstructionStatistics` class:**  This class calculates and presents statistics about the instructions within the WASM module.
- **`ExtendedFunctionDis` class:** This is a disassembler that can produce a "hex dump" format of individual functions.
- **`HexDumpModuleDis` class:** This disassembles the entire module into a hex dump format.
- **`FunctionStatistics` class:** Calculates and displays the distribution of function sizes.
- **`FormatConverter` class:**  This seems to be the main driver, handling file input, WASM decoding, and coordinating the different analysis actions.

Now, I can address the specific points from the prompt:

1. **Torque:** The file extension is `.cc`, not `.tq`, so it's not a Torque file.
2. **JavaScript Relation:** The `--mjsunit` action suggests a relationship with JavaScript testing within V8. I can provide an example of how the output of this option might be used in a V8 Mjsunit test.
3. **Logic Examples:**  I can demonstrate how `--list-functions` might output the names of functions in a sample WASM module, or how `--section-stats` might show the size of different sections.
4. **Common Errors:** A common error would be providing an invalid file path or using incorrect command-line arguments.
5. **Summary:** The tool's main purpose is to provide various ways to inspect and analyze the contents of a WebAssembly module.

Planning complete. I will now generate the response based on this analysis.
```cpp
      ExtendedFunctionDis dis(&zone, module(), i,
                                 module()->is_shared_function(i), nullptr,
                                 module()->functions[i].sig,
                                 module()->functions[i].code.start(),
                                 module()->functions[i].code.end(),
                                 module()->functions[i].code.offset(),
                                 wire_bytes(), names());
      dis.CollectInstructionStats(stats);
      stats.RecordCodeSize(module()->functions[i].code.size());
    }
    stats.WriteTo(out_);
  }

  void FunctionStats(size_t bucket_size, size_t bucket_count) {
    DCHECK_EQ(status_, kModuleReady);
    FunctionStatistics stats(bucket_size, bucket_count);
    for (const auto& func : module()->functions) {
      stats.addFunction(func.code.size());
    }
    stats.WriteTo(out_);
  }

  void SingleFunctionWat(uint32_t index) {
    DCHECK_EQ(status_, kModuleReady);
    const WasmFunction* f = &module()->functions[index];
    out_ << "// Function: " << index << "\n";
    WasmDisassembler::DisassembleFunction(out_, module(), f, names());
  }

  void FullWat() {
    DCHECK_EQ(status_, kModuleReady);
    WasmDisassembler::DisassembleModule(out_, module(), names());
  }

  void SingleFunctionHexdump(uint32_t index) {
    DCHECK_EQ(status_, kModuleReady);
    MultiLineStringBuilder builder;
    Zone zone(&allocator_, "hexdump");
    WasmDetectedFeatures detected;
    const WasmFunction* func = &module()->functions[index];
    ExtendedFunctionDis dis(&zone, module(), index,
                              module()->is_shared_function(index), &detected,
                              func->sig, func->code.start(), func->code.end(),
                              func->code.offset(), wire_bytes(), names());
    dis.HexDump(builder, FunctionBodyDisassembler::kPrintHeader);
    out_ << builder.ToCString();
  }

  void FullHexdump() {
    DCHECK_EQ(status_, kModuleReady);
    MultiLineStringBuilder builder;
    AccountingAllocator allocator;
    HexDumpModuleDis dis(builder, module(), names(), wire_bytes(), &allocator);
    dis.PrintModule();
    out_ << builder.ToCString();
  }

  void MjsUnit() {
    DCHECK_EQ(status_, kModuleReady);
    MjsUnitModuleDisassembler::DisassembleModule(out_, module(), names());
  }

 private:
  bool LoadFile(const char* filename) {
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
      std::cerr << "Error opening file: " << filename << "\n";
      return false;
    }
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    raw_bytes_buffer_ = std::make_unique<std::vector<char>>(size);
    if (file.read(raw_bytes_buffer_->data(), size)) {
      return true;
    } else {
      std::cerr << "Error reading file: " << filename << "\n";
      return false;
    }
  }

  const std::vector<char>& raw_bytes() const { return *raw_bytes_buffer_; }

  std::unique_ptr<OffsetsProvider> AllocateOffsetsProvider() {
    if (print_offsets_) {
      return std::make_unique<VectorOffsetsProvider>();
    }
    return std::make_unique<NoOffsetsProvider>();
  }

  Status status_ = kNotReady;
  const std::string output_;
  FileOutput output_stream_;
  std::ostream& out_;
  bool print_offsets_;
  std::unique_ptr<std::vector<char>> raw_bytes_buffer_;
  ModuleWireBytes wire_bytes_;
  std::unique_ptr<OffsetsProvider> offsets_provider_;
  AccountingAllocator allocator_;
  ModuleResult module_result_;
  std::unique_ptr<WasmModule> module_;
  std::unique_ptr<NamesProvider> names_provider_;
};

}  // namespace v8::internal::wasm

int main(int argc, char** argv) {
  v8::InitializeICUDefaultLocation(argv[0]);
  v8::InitializeExternalStartupData(argv[0]);
  std::unique_ptr<v8::Platform> platform = v8::platform::NewDefaultPlatform();
  v8::InitializePlatform(platform.get());
  v8::V8::Initialize();

  using namespace v8::internal::wasm;

  const char* input_filename = nullptr;
  const char* output_filename = nullptr;
  const char* action = nullptr;
  bool print_offsets = false;
  int function_index = -1;
  size_t bucket_size = 16;
  size_t bucket_count = 20;

  for (int i = 1; i < argc; ++i) {
    const char* arg = argv[i];
    if (strcmp(arg, "--help") == 0) {
      return PrintHelp(argv);
    } else if (strcmp(arg, "--list-functions") == 0) {
      action = arg;
    } else if (strcmp(arg, "--list-signatures") == 0) {
      action = arg;
    } else if (strcmp(arg, "--section-stats") == 0) {
      action = arg;
    } else if (strcmp(arg, "--instruction-stats") == 0) {
      action = arg;
    } else if (strcmp(arg, "--function-stats") == 0) {
      action = arg;
      // Consume optional bucket size and count.
      if (i + 1 < argc && isdigit(argv[i + 1][0])) {
        bucket_size = strtoull(argv[++i], nullptr, 10);
        if (i + 1 < argc && isdigit(argv[i + 1][0])) {
          bucket_count = strtoull(argv[++i], nullptr, 10);
        }
      }
    } else if (strcmp(arg, "--single-wat") == 0) {
      action = arg;
      if (i + 1 < argc && isdigit(argv[i + 1][0])) {
        function_index = atoi(argv[++i]);
      } else {
        std::cerr << "Error: --single-wat requires a function index.\n";
        return PrintHelp(argv);
      }
    } else if (strcmp(arg, "--full-wat") == 0) {
      action = arg;
    } else if (strcmp(arg, "--single-hexdump") == 0) {
      action = arg;
      if (i + 1 < argc && isdigit(argv[i + 1][0])) {
        function_index = atoi(argv[++i]);
      } else {
        std::cerr << "Error: --single-hexdump requires a function index.\n";
        return PrintHelp(argv);
      }
    } else if (strcmp(arg, "--full-hexdump") == 0) {
      action = arg;
    } else if (strcmp(arg, "--mjsunit") == 0) {
      action = arg;
    } else if (strcmp(arg, "--strip") == 0) {
      action = arg;
    } else if (strcmp(arg, "--offsets") == 0) {
      print_offsets = true;
    } else if (strcmp(arg, "-o") == 0 || strcmp(arg, "--output") == 0) {
      if (i + 1 < argc) {
        output_filename = argv[++i];
      } else {
        std::cerr << "Error: -o or --output requires a filename.\n";
        return PrintHelp(argv);
      }
    } else if (input_filename == nullptr) {
      input_filename = arg;
    } else {
      std::cerr << "Error: Unknown argument: " << arg << "\n";
      return PrintHelp(argv);
    }
  }

  if (input_filename == nullptr && action != nullptr) {
    std::cerr << "Error: An input file must be specified.\n";
    return PrintHelp(argv);
  }

  if (action == nullptr && input_filename != nullptr) {
    std::cerr << "Error: An action must be specified.\n";
    return PrintHelp(argv);
  }

  if (action == nullptr && input_filename == nullptr) {
    // Just print help if no arguments are given.
    return PrintHelp(argv);
  }

  FormatConverter converter(input_filename, output_filename, print_offsets);

  if (converter.status() != FormatConverter::kModuleReady) {
    return 1;
  }

  if (strcmp(action, "--list-functions") == 0) {
    converter.ListFunctions();
  } else if (strcmp(action, "--list-signatures") == 0) {
    converter.ListSignatures();
  } else if (strcmp(action, "--section-stats") == 0) {
    converter.SectionStats();
  } else if (strcmp(action, "--instruction-stats") == 0) {
    converter.InstructionStats();
  } else if (strcmp(action, "--function-stats") == 0) {
    converter.FunctionStats(bucket_size, bucket_count);
  } else if (strcmp(action, "--single-wat") == 0) {
    converter.SingleFunctionWat(function_index);
  } else if (strcmp(action, "--full-wat") == 0) {
    converter.FullWat();
  } else if (strcmp(action, "--single-hexdump") == 0) {
    converter.SingleFunctionHexdump(function_index);
  } else if (strcmp(action, "--full-hexdump") == 0) {
    converter.FullHexdump();
  } else if (strcmp(action, "--mjsunit") == 0) {
    converter.MjsUnit();
  } else if (strcmp(action, "--strip") == 0) {
    converter.Strip();
  }

  return 0;
}
```

## 功能归纳

`v8/tools/wasm/module-inspector.cc` 是一个命令行工具，用于 **检查和分析 WebAssembly 模块**。它可以执行以下操作：

1. **显示帮助信息:**  打印工具的使用方法和可用的选项 (`--help`).
2. **列出函数:**  显示模块中所有函数的索引和名称 (`--list-functions`).
3. **列出签名:**  展示模块中使用的所有函数签名及其使用次数 (`--list-signatures`).
4. **显示段统计信息:** 提供模块中各个段（如代码段、数据段等）的大小和占比信息 (`--section-stats`).
5. **显示指令统计信息:**  展示模块中各种 WebAssembly 指令的使用频率、总大小和平均大小 (`--instruction-stats`). 还可以显示最常见的立即数值。
6. **显示函数大小分布:**  将函数按大小进行分桶，并显示每个桶内的函数数量和占比 (`--function-stats`). 可以自定义桶的大小和数量。
7. **以 WAT 格式打印单个函数:**  将指定索引的函数反汇编成 WebAssembly 文本格式 (`--single-wat FUNC_INDEX`).
8. **以 WAT 格式打印完整模块:** 将整个模块反汇编成 WebAssembly 文本格式 (`--full-wat`).
9. **以十六进制转储格式打印单个函数:**  以带注释的十六进制格式显示指定索引的函数 (`--single-hexdump FUNC_INDEX`).
10. **以十六进制转储格式打印完整模块:** 以带注释的十六进制格式显示整个模块 (`--full-hexdump`).
11. **以 mjsunit 格式打印完整模块:**  生成可以在 V8 的 JavaScript 测试框架 (mjsunit) 中使用的 WebAssembly 模块构建代码 (`--mjsunit`).
12. **去除名称段并转储模块:**  以二进制格式输出模块，但不包含名称段 (`--strip`). 需要配合 `-o` 或 `--output` 指定输出文件。

**其他选项:**

* `--offsets`: 在输出中包含模块相关的偏移量。
* `-o OUTFILE` 或 `--output OUTFILE`: 将输出重定向到指定的文件，而不是标准输出。

如果 `v8/tools/wasm/module-inspector.cc` 以 `.tq` 结尾，那它将是一个 V8 Torque 源代码文件。然而，根据提供的代码，它以 `.cc` 结尾，因此是一个 **C++ 源代码文件**。

这个工具的功能与 JavaScript 有关，特别是与 V8 引擎如何处理和测试 WebAssembly 模块相关。

**JavaScript 示例 (与 `--mjsunit` 功能相关):**

假设 `module.wasm` 是一个 WebAssembly 模块。运行命令：

```bash
./module-inspector --mjsunit module.wasm
```

可能会生成如下 JavaScript 代码：

```javascript
// Generated by module-inspector
(function() {
const builder = new WasmModuleBuilder();
builder.addMemory(16);
builder.addFunction('add', kSig_i_ii)
  .exportAs('add')
  .body([
    kExprLocalGet, 0,
    kExprLocalGet, 1,
    kExprI32Add
  ])
;
// ... more functions and module structure ...
const instance = builder.instantiate();
assertEquals(3, instance.exports.add(1, 2));
})();
```

这个 JavaScript 代码使用了 V8 的 `WasmModuleBuilder` API 来动态构建和实例化 WebAssembly 模块，这通常用于编写 V8 的 WebAssembly 功能测试。

**代码逻辑推理示例 (与 `--list-functions` 功能相关):**

**假设输入:** 一个名为 `test.wasm` 的 WebAssembly 模块，其中定义了两个函数，分别命名为 `my_function` 和 `another_function`。

**运行命令:**

```bash
./module-inspector --list-functions test.wasm
```

**预期输出:**

```
There are 2 functions (0 imported, 2 locally defined; 0% of them "small"); the following have names:
0 my_function
1 another_function
```

**用户常见的编程错误示例:**

1. **未指定输入文件:**

   ```bash
   ./module-inspector --list-functions
   ```

   **错误信息:** `Error: An input file must be specified.`

2. **指定了不存在的输入文件:**

   ```bash
   ./module-inspector --list-functions non_existent.wasm
   ```

   **错误信息:** `Error opening file: non_existent.wasm`

3. **`--single-wat` 或 `--single-hexdump` 没有提供函数索引:**

   ```bash
   ./module-inspector --single-wat my_module.wasm
   ```

   **错误信息:** `Error: --single-wat requires a function index.`

4. **使用了未知的命令行参数:**

   ```bash
   ./module-inspector --invalid-option my_module.wasm
   ```

   **错误信息:** `Error: Unknown argument: --invalid-option`

### 提示词
```
这是目录为v8/tools/wasm/module-inspector.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/tools/wasm/module-inspector.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```
// Copyright 2022 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <fstream>
#include <iomanip>
#include <iostream>
#include <optional>
#include <vector>

#include "include/libplatform/libplatform.h"
#include "include/v8-initialization.h"
#include "src/wasm/module-decoder-impl.h"
#include "src/wasm/names-provider.h"
#include "src/wasm/string-builder-multiline.h"
#include "src/wasm/wasm-disassembler-impl.h"
#include "src/wasm/wasm-opcodes-inl.h"
#include "tools/wasm/mjsunit-module-disassembler-impl.h"

#if V8_OS_POSIX
#include <unistd.h>
#endif

int PrintHelp(char** argv) {
  std::cerr
      << "Usage: Specify an action and a module in any order.\n"
      << "The action can be any of:\n"

      << " --help\n"
      << "     Print this help and exit.\n"

      << " --list-functions\n"
      << "     List functions in the given module\n"

      << " --list-signatures\n"
      << "     List signatures with their use counts in the given module\n"

      << " --section-stats\n"
      << "     Show information about sections in the given module\n"

      << " --instruction-stats\n"
      << "     Show information about instructions in the given module\n"

      << " --function-stats [bucket_size] [bucket_count]\n"
      << "    Show distribution of function sizes in the given module.\n"
      << "    An optional bucket size and bucket count can be passed.\n"

      << " --single-wat FUNC_INDEX\n"
      << "     Print function FUNC_INDEX in .wat format\n"

      << " --full-wat\n"
      << "     Print full module in .wat format\n"

      << " --single-hexdump FUNC_INDEX\n"
      << "     Print function FUNC_INDEX in annotated hex format\n"

      << " --full-hexdump\n"
      << "     Print full module in annotated hex format\n"

      << " --mjsunit\n"
      << "     Print full module in mjsunit/wasm-module-builder.js syntax\n"

      << " --strip\n"
      << "     Dump the module, in binary format, without its Name"
      << " section (requires using -o as well)\n"

      << "\n"
      << "Options:\n"
      << " --offsets\n"
      << "     Include module-relative offsets in output\n"

      << " -o OUTFILE or --output OUTFILE\n"
      << "     Send output to OUTFILE instead of <stdout>\n";
  return 1;
}

namespace v8::internal::wasm {

enum class OutputMode { kWat, kHexDump };

char* PrintHexBytesCore(char* ptr, uint32_t num_bytes, const uint8_t* start) {
  for (uint32_t i = 0; i < num_bytes; i++) {
    uint8_t b = *(start + i);
    *(ptr++) = '0';
    *(ptr++) = 'x';
    *(ptr++) = kHexChars[b >> 4];
    *(ptr++) = kHexChars[b & 0xF];
    *(ptr++) = ',';
    *(ptr++) = ' ';
  }
  return ptr;
}

class InstructionStatistics {
 public:
  void Record(WasmOpcode opcode, uint32_t size) {
    Entry& entry = entries[opcode];
    entry.opcode = opcode;
    entry.count++;
    entry.total_size += size;
  }

  void RecordImmediate(WasmOpcode opcode, int imm_value) {
    OpcodeImmediates& map = immediates[opcode];
    map[imm_value]++;
  }

  void RecordCodeSize(size_t chunk) { total_code_size_ += chunk; }

  void RecordLocals(uint32_t count, uint32_t size) {
    locals_count_ += count;
    locals_size_ += size;
  }

  void WriteTo(std::ostream& out) {
    // Sort by number of occurrences.
    std::vector<Entry> sorted;
    sorted.reserve(entries.size());
    for (const auto& e : entries) sorted.push_back(e.second);
    std::sort(sorted.begin(), sorted.end(),
              [](const Entry& a, const Entry& b) { return a.count > b.count; });

    // Prepare column widths.
    int longest_mnemo = 0;
    for (const Entry& e : sorted) {
      int s = static_cast<int>(strlen(WasmOpcodes::OpcodeName(e.opcode)));
      if (s > longest_mnemo) longest_mnemo = s;
    }
    constexpr int kSpacing = 2;
    longest_mnemo =
        std::max(longest_mnemo, static_cast<int>(strlen("Instruction"))) +
        kSpacing;
    uint32_t highest_count = sorted[0].count;
    int count_digits = GetNumDigits(highest_count);
    count_digits = std::max(count_digits, static_cast<int>(strlen("count")));

    // Print headline.
    out << std::setw(longest_mnemo) << std::left << "Instruction";
    out << std::setw(count_digits) << std::right << "count";
    out << std::setw(kSpacing) << " ";
    out << std::setw(8) << "tot.size";
    out << std::setw(kSpacing) << " ";
    out << std::setw(8) << "avg.size";
    out << std::setw(kSpacing) << " ";
    out << std::setw(8) << "% of code\n";

    // Print instruction counts.
    auto PrintLine = [&](const char* name, uint32_t count,
                         uint32_t total_size) {
      out << std::setw(longest_mnemo) << std::left << name;
      out << std::setw(count_digits) << std::right << count;
      out << std::setw(kSpacing) << " ";
      out << std::setw(8) << total_size;
      out << std::setw(kSpacing) << " ";
      out << std::fixed << std::setprecision(2) << std::setw(8)
          << static_cast<double>(total_size) / count;
      out << std::setw(kSpacing) << " ";
      out << std::fixed << std::setprecision(1) << std::setw(8)
          << 100.0 * total_size / total_code_size_ << "%\n";
    };
    for (const Entry& e : sorted) {
      PrintLine(WasmOpcodes::OpcodeName(e.opcode), e.count, e.total_size);
    }
    out << "\n";
    PrintLine("locals", locals_count_, locals_size_);

    // Print most common immediate values.
    for (const auto& imm : immediates) {
      WasmOpcode opcode = imm.first;
      out << "\nMost common immediates for " << WasmOpcodes::OpcodeName(opcode)
          << ":\n";
      std::vector<std::pair<int, int>> counts;
      counts.reserve(imm.second.size());
      for (const auto& pair : imm.second) {
        counts.push_back(std::make_pair(pair.first, pair.second));
      }
      std::sort(counts.begin(), counts.end(),
                [](const std::pair<int, uint32_t>& a,
                   const std::pair<int, uint32_t>& b) {
                  return a.second > b.second;
                });
      constexpr int kImmLen = 9;  // Length of "Immediate".
      int count_len = std::max(GetNumDigits(counts[0].second),
                               static_cast<int>(strlen("count")));
      // How many most-common values to show.
      size_t print_top = std::min(size_t{10}, counts.size());
      out << std::setw(kImmLen) << "Immediate";
      out << std::setw(kSpacing) << " ";
      out << std::setw(count_len) << "count"
          << "\n";
      for (size_t i = 0; i < print_top; i++) {
        out << std::setw(kImmLen) << counts[i].first;
        out << std::setw(kSpacing) << " ";
        out << std::setw(count_len) << counts[i].second << "\n";
      }
    }
  }

 private:
  struct Entry {
    WasmOpcode opcode;
    uint32_t count = 0;
    uint32_t total_size = 0;
  };

  // First: immediate value, second: count.
  using OpcodeImmediates = std::map<int, uint32_t>;

  std::unordered_map<WasmOpcode, Entry> entries;
  std::map<WasmOpcode, OpcodeImmediates> immediates;
  size_t total_code_size_ = 0;
  uint32_t locals_count_ = 0;
  uint32_t locals_size_ = 0;
};

// A variant of FunctionBodyDisassembler that can produce "annotated hex dump"
// format, e.g.:
//     0xfb, 0x07, 0x01,  // struct.new $type1
class ExtendedFunctionDis : public FunctionBodyDisassembler {
 public:
  ExtendedFunctionDis(Zone* zone, const WasmModule* module, uint32_t func_index,
                      bool shared, WasmDetectedFeatures* detected,
                      const FunctionSig* sig, const uint8_t* start,
                      const uint8_t* end, uint32_t offset,
                      const ModuleWireBytes wire_bytes, NamesProvider* names)
      : FunctionBodyDisassembler(zone, module, func_index, shared, detected,
                                 sig, start, end, offset, wire_bytes, names) {}

  void HexDump(MultiLineStringBuilder& out, FunctionHeader include_header) {
    out_ = &out;
    if (!more()) return;  // Fuzzers...
    // Print header.
    if (include_header == kPrintHeader) {
      out << "  // func ";
      names_->PrintFunctionName(out, func_index_, NamesProvider::kDevTools);
      PrintSignatureOneLine(out, sig_, func_index_, names_, true,
                            NamesProvider::kIndexAsComment);
      out.NextLine(pc_offset());
    }

    // Decode and print locals.
    DecodeLocals(pc_);
    if (failed()) {
      // TODO(jkummerow): Better error handling.
      out << "Failed to decode locals";
      return;
    }
    auto [entries, length] = read_u32v<ValidationTag>(pc_);
    PrintHexBytes(out, length, pc_, 4);
    out << " // " << entries << " entries in locals list";
    pc_ += length;
    out.NextLine(pc_offset());
    while (entries-- > 0) {
      auto [count, count_length] = read_u32v<ValidationTag>(pc_);
      auto [type, type_length] =
          value_type_reader::read_value_type<ValidationTag>(
              this, pc_ + count_length, WasmEnabledFeatures::All());
      PrintHexBytes(out, count_length + type_length, pc_, 4);
      out << " // " << count << (count != 1 ? " locals" : " local")
          << " of type ";
      names_->PrintValueType(out, type);
      pc_ += count_length + type_length;
      out.NextLine(pc_offset());
    }

    // Main loop.
    while (pc_ < end_ && ok()) {
      WasmOpcode opcode = GetOpcode();
      current_opcode_ = opcode;  // Some immediates need to know this.
      StringBuilder immediates;
      uint32_t length = PrintImmediatesAndGetLength(immediates);
      PrintHexBytes(out, length, pc_, 4);
      if (opcode == kExprEnd) {
        out << " // end";
        if (label_stack_.size() > 0) {
          const LabelInfo& label = label_stack_.back();
          if (label.start != nullptr) {
            out << " ";
            out.write(label.start, label.length);
          }
          label_stack_.pop_back();
        }
      } else {
        out << " // " << WasmOpcodes::OpcodeName(opcode);
      }
      out.write(immediates.start(), immediates.length());
      if (opcode == kExprBlock || opcode == kExprIf || opcode == kExprLoop ||
          opcode == kExprTry) {
        label_stack_.emplace_back(out.line_number(), out.length(),
                                  label_occurrence_index_++);
      }
      pc_ += length;
      out.NextLine(pc_offset());
    }

    if (pc_ != end_) {
      // TODO(jkummerow): Better error handling.
      out << "Beyond end of code\n";
    }
  }

  void HexdumpConstantExpression(MultiLineStringBuilder& out) {
    while (pc_ < end_ && ok()) {
      WasmOpcode opcode = GetOpcode();
      current_opcode_ = opcode;  // Some immediates need to know this.
      StringBuilder immediates;
      uint32_t length = PrintImmediatesAndGetLength(immediates);
      // Don't print the final "end" separately.
      if (pc_ + length + 1 == end_ && *(pc_ + length) == kExprEnd) {
        length++;
      }
      PrintHexBytes(out, length, pc_, 4);
      out << " // " << WasmOpcodes::OpcodeName(opcode);
      out.write(immediates.start(), immediates.length());
      pc_ += length;
      out.NextLine(pc_offset());
    }
  }

  void PrintHexBytes(StringBuilder& out, uint32_t num_bytes,
                     const uint8_t* start, uint32_t fill_to_minimum = 0) {
    constexpr int kCharsPerByte = 6;  // Length of "0xFF, ".
    uint32_t max = std::max(num_bytes, fill_to_minimum) * kCharsPerByte + 2;
    char* ptr = out.allocate(max);
    *(ptr++) = ' ';
    *(ptr++) = ' ';
    ptr = PrintHexBytesCore(ptr, num_bytes, start);
    if (fill_to_minimum > num_bytes) {
      memset(ptr, ' ', (fill_to_minimum - num_bytes) * kCharsPerByte);
    }
  }

  void CollectInstructionStats(InstructionStatistics& stats) {
    uint32_t locals_length = DecodeLocals(pc_);
    if (failed()) return;
    stats.RecordLocals(num_locals(), locals_length);
    consume_bytes(locals_length);
    while (pc_ < end_ && ok()) {
      WasmOpcode opcode = GetOpcode();
      if (opcode == kExprI32Const) {
        ImmI32Immediate imm(this, pc_ + 1, Decoder::kNoValidation);
        stats.RecordImmediate(opcode, imm.value);
      } else if (opcode == kExprLocalGet || opcode == kExprGlobalGet) {
        IndexImmediate imm(this, pc_ + 1, "", Decoder::kNoValidation);
        stats.RecordImmediate(opcode, static_cast<int>(imm.index));
      }
      uint32_t length = WasmDecoder::OpcodeLength(this, pc_);
      stats.Record(opcode, length);
      pc_ += length;
    }
  }
};

// A variant of ModuleDisassembler that produces "annotated hex dump" format,
// e.g.:
//     0x01, 0x70, 0x00,  // table count 1: funcref no maximum
class HexDumpModuleDis;
class DumpingModuleDecoder : public ModuleDecoderImpl {
 public:
  DumpingModuleDecoder(ModuleWireBytes wire_bytes,
                       HexDumpModuleDis* module_dis);

 private:
  void onFirstError() override {
    // Pretend we've reached the end of the section, but contrary to the
    // superclass implementation do so without moving {pc_}, so whatever
    // bytes caused the failure can still be dumped correctly.
    end_ = pc_;
  }

  WasmDetectedFeatures unused_detected_features_;
};

class HexDumpModuleDis : public ITracer {
 public:
  HexDumpModuleDis(MultiLineStringBuilder& out, const WasmModule* module,
                   NamesProvider* names, const ModuleWireBytes wire_bytes,
                   AccountingAllocator* allocator)
      : out_(out),
        module_(module),
        names_(names),
        wire_bytes_(wire_bytes),
        zone_(allocator, "disassembler") {}

  // Public entrypoint.
  void PrintModule() {
    DumpingModuleDecoder decoder{wire_bytes_, this};
    decoder_ = &decoder;

    // If the module failed validation, create fakes to allow us to print
    // what we can.
    std::unique_ptr<WasmModule> fake_module;
    std::unique_ptr<NamesProvider> names_provider;
    if (!names_) {
      fake_module.reset(new WasmModule(kWasmOrigin));
      names_provider.reset(
          new NamesProvider(fake_module.get(), wire_bytes_.module_bytes()));
      names_ = names_provider.get();
    }

    out_ << "[";
    out_.NextLine(0);
    constexpr bool kNoVerifyFunctions = false;
    decoder.DecodeModule(kNoVerifyFunctions);
    NextLine();
    out_ << "]";

    if (total_bytes_ != wire_bytes_.length()) {
      std::cerr << "WARNING: OUTPUT INCOMPLETE. Disassembled " << total_bytes_
                << " out of " << wire_bytes_.length() << " bytes.\n";
    }

    // For cleanliness, reset {names_} if it's pointing at a fake.
    if (names_ == names_provider.get()) {
      names_ = nullptr;
    }
  }

  // Tracer hooks.
  void Bytes(const uint8_t* start, uint32_t count) override {
    if (count > kMaxBytesPerLine) {
      DCHECK_EQ(queue_, nullptr);
      queue_ = start;
      queue_length_ = count;
      total_bytes_ += count;
      return;
    }
    if (line_bytes_ == 0 && count > 0) out_ << "  ";
    PrintHexBytes(out_, count, start);
    line_bytes_ += count;
    total_bytes_ += count;
  }

  void Description(const char* desc) override { description_ << desc; }
  void Description(const char* desc, size_t length) override {
    description_.write(desc, length);
  }
  void Description(uint32_t number) override {
    if (description_.length() != 0) description_ << " ";
    description_ << number;
  }
  void Description(uint64_t number) override {
    if (description_.length() != 0) description_ << " ";
    description_ << number;
  }
  void Description(ValueType type) override {
    if (description_.length() != 0) description_ << " ";
    names_->PrintValueType(description_, type);
  }
  void Description(HeapType type) override {
    if (description_.length() != 0) description_ << " ";
    names_->PrintHeapType(description_, type);
  }
  void Description(const FunctionSig* sig) override {
    PrintSignatureOneLine(description_, sig, 0 /* ignored */, names_, false);
  }
  void FunctionName(uint32_t func_index) override {
    description_ << func_index << " ";
    names_->PrintFunctionName(description_, func_index,
                              NamesProvider::kDevTools);
  }

  void NextLineIfFull() override {
    if (queue_ || line_bytes_ >= kPadBytes) NextLine();
  }
  void NextLineIfNonEmpty() override {
    if (queue_ || line_bytes_ > 0) NextLine();
  }
  void NextLine() override {
    if (queue_) {
      // Print queued hex bytes first, unless there have also been unqueued
      // bytes.
      if (line_bytes_ > 0) {
        // Keep the queued bytes together on the next line.
        for (; line_bytes_ < kPadBytes; line_bytes_++) {
          out_ << "      ";
        }
        out_ << " // ";
        out_.write(description_.start(), description_.length());
        out_.NextLine(pc_offset(queue_));
      }
      while (queue_length_ > kMaxBytesPerLine) {
        out_ << "  ";
        PrintHexBytes(out_, kMaxBytesPerLine, queue_);
        queue_length_ -= kMaxBytesPerLine;
        queue_ += kMaxBytesPerLine;
        out_.NextLine(pc_offset(queue_));
      }
      if (queue_length_ > 0) {
        out_ << "  ";
        PrintHexBytes(out_, queue_length_, queue_);
      }
      if (line_bytes_ == 0) {
        if (queue_length_ > kPadBytes) {
          out_.NextLine(pc_offset(queue_ + queue_length_));
          out_ << "                           // ";
        } else {
          for (uint32_t i = queue_length_; i < kPadBytes; i++) {
            out_ << "      ";
          }
          out_ << " // ";
        }
        out_.write(description_.start(), description_.length());
      }
      queue_ = nullptr;
    } else {
      // No queued bytes; just write the accumulated description.
      if (description_.length() != 0) {
        if (line_bytes_ == 0) out_ << "  ";
        for (; line_bytes_ < kPadBytes; line_bytes_++) {
          out_ << "      ";
        }
        out_ << " // ";
        out_.write(description_.start(), description_.length());
      }
    }
    out_.NextLine(pc_offset());
    line_bytes_ = 0;
    description_.rewind_to_start();
  }

  // We don't care about offsets, but we can use these hooks to provide
  // helpful indexing comments in long lists.
  void TypeOffset(uint32_t offset) override {
    if (!module_ || module_->types.size() > 3) {
      description_ << "type #" << next_type_index_ << " ";
      names_->PrintTypeName(description_, next_type_index_);
      next_type_index_++;
    }
  }
  void ImportOffset(uint32_t offset) override {
    description_ << "import #" << next_import_index_++;
    NextLine();
  }
  void ImportsDone(const WasmModule* module) override {
    next_table_index_ = static_cast<uint32_t>(module->tables.size());
    next_global_index_ = static_cast<uint32_t>(module->globals.size());
    next_tag_index_ = static_cast<uint32_t>(module->tags.size());
  }
  void TableOffset(uint32_t offset) override {
    if (!module_ || module_->tables.size() > 3) {
      description_ << "table #" << next_table_index_++;
    }
  }
  void MemoryOffset(uint32_t offset) override {}
  void TagOffset(uint32_t offset) override {
    if (!module_ || module_->tags.size() > 3) {
      description_ << "tag #" << next_tag_index_++ << ":";
    }
  }
  void GlobalOffset(uint32_t offset) override {
    description_ << "global #" << next_global_index_++ << ":";
  }
  void StartOffset(uint32_t offset) override {}
  void ElementOffset(uint32_t offset) override {
    if (!module_ || module_->elem_segments.size() > 3) {
      description_ << "segment #" << next_segment_index_++;
      NextLine();
    }
  }
  void DataOffset(uint32_t offset) override {
    if (!module_ || module_->data_segments.size() > 3) {
      description_ << "data segment #" << next_data_segment_index_++;
      NextLine();
    }
  }
  void StringOffset(uint32_t offset) override {
    if (!module_ || module_->stringref_literals.size() > 3) {
      description_ << "string literal #" << next_string_index_++;
      NextLine();
    }
  }

  // We handle recgroups via {Description()} hooks.
  void RecGroupOffset(uint32_t offset, uint32_t group_size) override {}

  // The following two hooks give us an opportunity to call the hex-dumping
  // function body disassembler for initializers and functions.
  void InitializerExpression(const uint8_t* start, const uint8_t* end,
                             ValueType expected_type) override {
    WasmDetectedFeatures detected;
    auto sig = FixedSizeSignature<ValueType>::Returns(expected_type);
    uint32_t offset = decoder_->pc_offset();
    const WasmModule* module = module_;
    if (!module) module = decoder_->shared_module().get();
    ExtendedFunctionDis d(&zone_, module, 0, false, &detected, &sig, start, end,
                          offset, wire_bytes_, names_);
    d.HexdumpConstantExpression(out_);
    total_bytes_ += static_cast<size_t>(end - start);
  }

  void FunctionBody(const WasmFunction* func, const uint8_t* start) override {
    const uint8_t* end = start + func->code.length();
    WasmDetectedFeatures detected;
    DCHECK_EQ(start - wire_bytes_.start(), pc_offset());
    uint32_t offset = pc_offset();
    const WasmModule* module = module_;
    if (!module) module = decoder_->shared_module().get();
    bool shared = module->type(func->sig_index).is_shared;
    ExtendedFunctionDis d(&zone_, module, func->func_index, shared, &detected,
                          func->sig, start, end, offset, wire_bytes_, names_);
    d.HexDump(out_, FunctionBodyDisassembler::kSkipHeader);
    total_bytes_ += func->code.length();
  }

  // We have to do extra work for the name section here, because the regular
  // decoder mostly just skips over it.
  void NameSection(const uint8_t* start, const uint8_t* end,
                   uint32_t offset) override {
    Decoder decoder(start, end, offset);
    while (decoder.ok() && decoder.more()) {
      uint8_t name_type = decoder.consume_u8("name type: ", this);
      Description(NameTypeName(name_type));
      NextLine();
      uint32_t payload_length = decoder.consume_u32v("payload length:", this);
      Description(payload_length);
      NextLine();
      if (!decoder.checkAvailable(payload_length)) break;
      switch (name_type) {
        case kModuleCode:
          consume_string(&decoder, unibrow::Utf8Variant::kLossyUtf8,
                         "module name", this);
          break;
        case kFunctionCode:
        case kTypeCode:
        case kTableCode:
        case kMemoryCode:
        case kGlobalCode:
        case kElementSegmentCode:
        case kDataSegmentCode:
        case kTagCode:
          DumpNameMap(decoder);
          break;
        case kLocalCode:
        case kLabelCode:
        case kFieldCode:
          DumpIndirectNameMap(decoder);
          break;
        default:
          Bytes(decoder.pc(), payload_length);
          NextLine();
          decoder.consume_bytes(payload_length);
          break;
      }
    }
  }

 private:
  static constexpr uint32_t kMaxBytesPerLine = 8;
  static constexpr uint32_t kPadBytes = 4;

  void PrintHexBytes(StringBuilder& out, uint32_t num_bytes,
                     const uint8_t* start) {
    char* ptr = out.allocate(num_bytes * 6);
    PrintHexBytesCore(ptr, num_bytes, start);
  }

  void DumpNameMap(Decoder& decoder) {
    uint32_t count = decoder.consume_u32v("names count", this);
    Description(count);
    NextLine();
    for (uint32_t i = 0; i < count; i++) {
      uint32_t index = decoder.consume_u32v("index", this);
      Description(index);
      Description(" ");
      consume_string(&decoder, unibrow::Utf8Variant::kLossyUtf8, "name", this);
      if (!decoder.ok()) break;
    }
  }

  void DumpIndirectNameMap(Decoder& decoder) {
    uint32_t outer_count = decoder.consume_u32v("outer count", this);
    Description(outer_count);
    NextLine();
    for (uint32_t i = 0; i < outer_count; i++) {
      uint32_t outer_index = decoder.consume_u32v("outer index", this);
      Description(outer_index);
      uint32_t inner_count = decoder.consume_u32v(" inner count", this);
      Description(inner_count);
      NextLine();
      for (uint32_t j = 0; j < inner_count; j++) {
        uint32_t inner_index = decoder.consume_u32v("inner index", this);
        Description(inner_index);
        Description(" ");
        consume_string(&decoder, unibrow::Utf8Variant::kLossyUtf8, "name",
                       this);
        if (!decoder.ok()) break;
      }
      if (!decoder.ok()) break;
    }
  }

  static constexpr const char* NameTypeName(uint8_t name_type) {
    switch (name_type) {
      // clang-format off
      case kModuleCode:         return "module";
      case kFunctionCode:       return "function";
      case kTypeCode:           return "type";
      case kTableCode:          return "table";
      case kMemoryCode:         return "memory";
      case kGlobalCode:         return "global";
      case kElementSegmentCode: return "element segment";
      case kDataSegmentCode:    return "data segment";
      case kTagCode:            return "tag";
      case kLocalCode:          return "local";
      case kLabelCode:          return "label";
      case kFieldCode:          return "field";
      default:                  return "unknown";
        // clang-format on
    }
  }

  uint32_t pc_offset() { return static_cast<uint32_t>(total_bytes_); }
  uint32_t pc_offset(const uint8_t* pc) {
    return static_cast<uint32_t>(pc - wire_bytes_.start());
  }

  MultiLineStringBuilder& out_;
  const WasmModule* module_;
  NamesProvider* names_;
  const ModuleWireBytes wire_bytes_;
  Zone zone_;

  StringBuilder description_;
  const uint8_t* queue_{nullptr};
  uint32_t queue_length_{0};
  uint32_t line_bytes_{0};
  size_t total_bytes_{0};
  DumpingModuleDecoder* decoder_{nullptr};

  uint32_t next_type_index_{0};
  uint32_t next_import_index_{0};
  uint32_t next_table_index_{0};
  uint32_t next_global_index_{0};
  uint32_t next_tag_index_{0};
  uint32_t next_segment_index_{0};
  uint32_t next_data_segment_index_{0};
  uint32_t next_string_index_{0};
};

class FunctionStatistics {
 public:
  explicit FunctionStatistics(size_t bucket_size, size_t bucket_count)
      : bucket_size_(bucket_size), buckets_(bucket_count) {}

  void addFunction(size_t size) {
    size_t index = size / bucket_size_;
    index = std::min(buckets_.size() - 1, index);
    buckets_[index] += 1;
    total_bytes_ += size;
  }

  void WriteTo(std::ostream& out) {
    size_t fct_count = std::accumulate(buckets_.begin(), buckets_.end(), 0ull);
    if (fct_count == 0) {
      out << "No functions found in module.\n";
      return;
    }
    int max_w = log10(bucket_size_ * buckets_.size() - 1) + 1;
    out << "Function distribution:\n";
    for (size_t i = 0; i < buckets_.size(); ++i) {
      size_t lower = i * bucket_size_;
      size_t upper = (i + 1) * bucket_size_ - 1;
      bool last = i + 1 == buckets_.size();
      out << std::setw(max_w) << lower << " - ";
      out << std::setw(max_w) << upper << (last ? '+' : ' ') << " bytes: ";
      size_t count = buckets_[i];
      out << std::setw(6) << count;
      double percent = 100.0 * count / fct_count;
      out << "  (" << std::fixed << std::setw(4) << std::setprecision(1)
          << percent << "%)\n";
    }
    out << "Total function count: " << fct_count << '\n';
    out << "Average size per function: " << total_bytes_ / fct_count
        << " bytes\n";
  }

 private:
  size_t bucket_size_;
  std::vector<size_t> buckets_;
  size_t total_bytes_ = 0;
};

////////////////////////////////////////////////////////////////////////////////

class FormatConverter {
 public:
  enum Status { kNotReady, kIoInitialized, kModuleReady };

  explicit FormatConverter(const char* input, const char* output,
                           bool print_offsets)
      : output_(output), out_(output_.get()), print_offsets_(print_offsets) {
    if (!output_.ok()) return;
    if (!LoadFile(input)) return;
    wire_bytes_ = ModuleWireBytes(raw_bytes());
    status_ = kIoInitialized;
    offsets_provider_ = AllocateOffsetsProvider();
    ModuleResult result =
        DecodeWasmModuleForDisassembler(raw_bytes(), offsets_provider_.get());
    if (result.failed()) {
      WasmError error = result.error();
      std::cerr << "Decoding error: " << error.message() << " at offset "
                << error.offset() << "\n";
      return;
    }
    status_ = kModuleReady;
    module_ = result.value();
    names_provider_ =
        std::make_unique<NamesProvider>(module_.get(), raw_bytes());
  }

  Status status() const { return status_; }

  void ListFunctions() {
    DCHECK_EQ(status_, kModuleReady);
    const WasmModule* m = module();
    uint32_t num_functions = static_cast<uint32_t>(m->functions.size());
    double small_function_percentage =
        module_->num_small_functions * 100.0 / module_->num_declared_functions;
    out_ << "There are " << num_functions << " functions ("
         << m->num_imported_functions << " imported, "
         << m->num_declared_functions << " locally defined; "
         << small_function_percentage
         << "% of them \"small\"); the following have names:\n";
    for (uint32_t i = 0; i < num_functions; i++) {
      StringBuilder sb;
      names()->PrintFunctionName(sb, i);
      if (sb.length() == 0) continue;
      std::string name(sb.start(), sb.length());
      out_ << i << " " << name << "\n";
    }
  }

  static bool sig_uses_vector_comparison(std::pair<uint32_t, uint32_t> left,
                                         std::pair<uint32_t, uint32_t> right) {
    return left.second > right.second;
  }

  void SortAndPrintSigUses(std::map<uint32_t, uint32_t> uses,
                           const WasmModule* module, const char* kind) {
    std::vector<std::pair<uint32_t, uint32_t>> sig_uses_vector{uses.begin(),
                                                               uses.end()};
    std::sort(sig_uses_vector.begin(), sig_uses_vector.end(),
              sig_uses_vector_comparison);

    out_ << sig_uses_vector.size() << " different signatures get used by "
         << kind << std::endl;
    for (auto sig_use : sig_uses_vector) {
      uint32_t sig_index = sig_use.first;
      uint32_t uses = sig_use.second;

      const FunctionSig* sig = module->signature(ModuleTypeIndex{sig_index});

      out_ << uses << " " << kind << " use the signature " << *sig << std::endl;
    }
  }

  void ListSignatures() {
    DCHECK_EQ(status_, kModuleReady);
    const WasmModule* m = module();
    uint32_t num_functions = static_cast<uint32_t>(m->functions.size());
    std::map<uint32_t, uint32_t> sig_uses;
    std::map<uint32_t, uint32_t> export_sig_uses;

    for (uint32_t i = 0; i < num_functions; i++) {
      const WasmFunction& f = m->functions[i];
      sig_uses[f.sig_index.index]++;
      if (f.exported) {
        export_sig_uses[f.sig_index.index]++;
      }
    }

    SortAndPrintSigUses(sig_uses, m, "functions");

    out_ << std::endl;

    SortAndPrintSigUses(export_sig_uses, m, "exported functions");
  }

  void SectionStats() {
    DCHECK_EQ(status_, kModuleReady);
    Decoder decoder(raw_bytes());
    decoder.consume_bytes(kModuleHeaderSize, "module header");

    uint32_t module_size = static_cast<uint32_t>(raw_bytes().size());
    int digits = GetNumDigits(module_size);
    size_t kMinNameLength = 8;
    // 18 = kMinNameLength + strlen(" section: ").
    out_ << std::setw(18) << std::left << "Module size: ";
    out_ << std::setw(digits) << std::right << module_size << " bytes\n";
    for (WasmSectionIterator it(&decoder, ITracer::NoTrace); it.more();
         it.advance(true)) {
      const char* name = SectionName(it.section_code());
      size_t name_len = strlen(name);
      out_ << SectionName(it.section_code()) << " section: ";
      for (; name_len < kMinNameLength; name_len++) out_ << " ";

      uint32_t length = it.section_length();
      out_ << std::setw(name_len > kMinNameLength ? 0 : digits) << length
           << " bytes / ";

      out_ << std::fixed << std::setprecision(1) << std::setw(4)
           << 100.0 * length / module_size;
      out_ << "% of total\n";
    }
  }

  void Strip() {
    DCHECK_EQ(status_, kModuleReady);
    Decoder decoder(raw_bytes());
    out_.write(reinterpret_cast<const char*>(decoder.pc()), kModuleHeaderSize);
    decoder.consume_bytes(kModuleHeaderSize);
    for (WasmSectionIterator it(&decoder, ITracer::NoTrace); it.more();
         it.advance(true)) {
      if (it.section_code() == kNameSectionCode) continue;
      out_.write(reinterpret_cast<const char*>(it.section_start()),
                 it.section_length());
    }
  }

  void InstructionStats() {
    DCHECK_EQ(status_, kModuleReady);
    Zone zone(&allocator_, "disassembler");
    InstructionStatistics stats;
    for (uint32_t i = module()->num_imported_functions;
         i < module()->functions.size(); i++) {
      co
```