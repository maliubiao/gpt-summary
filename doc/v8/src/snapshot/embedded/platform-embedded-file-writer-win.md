Response: Let's break down the thought process to arrive at the summary of `platform-embedded-file-writer-win.cc`.

1. **Understand the Goal:** The request asks for a summary of the file's functionality and its relation to JavaScript, illustrated with a JavaScript example if applicable.

2. **Identify the Core Purpose:** The filename itself is a big clue: `platform-embedded-file-writer-win.cc`. This suggests it's responsible for writing embedded files on Windows. The `platform-` part implies it's platform-specific. The `embedded-file-writer` part points to its function: writing data to be embedded.

3. **Scan the Includes:** The included headers provide context:
    * `src/snapshot/embedded/platform-embedded-file-writer-win.h`:  Its own header, indicating standard C++ class structure.
    * `<algorithm>`: Standard library, likely for utility functions.
    * `src/common/globals.h`:  V8 specific, likely containing platform definitions like `V8_OS_WIN64`.
    * Several V8-specific headers like `builtins/builtins.h`, `diagnostics/unwinding-info-win64.h`, `snapshot/embedded/embedded-data-inl.h`, and `snapshot/embedded/embedded-file-writer.h`: These strongly suggest the file is involved in creating the embedded snapshot of V8's state, which includes built-in functions and their associated metadata.

4. **Conditional Compilation (`#ifdef`) Blocks:** These are crucial for understanding platform-specific logic. The code heavily uses `#if defined(V8_OS_WIN64)` and `#if defined(V8_COMPILER_IS_MSVC)`. This highlights the file's handling of different Windows architectures (x64) and different compilers (MSVC vs. others).

5. **Key Data Structures and Functions:**
    * **`PlatformEmbeddedFileWriterWin` class:** The central entity. It inherits from something (presumably `PlatformEmbeddedFileWriterBase` mentioned later), providing the concrete Windows implementation.
    * **`EmitUnwindData` function:** This function is called conditionally based on the architecture. It deals with "unwind information" (`UNWIND_INFO`, `RUNTIME_FUNCTION`, `PDATA`, `XDATA`). This strongly connects to exception handling and stack unwinding, which is essential for robust program execution. The comments and structure within `EmitUnwindData` for both x64 and ARM64 are detailed and worth noting.
    * **`WriteUnwindInfoEntry`:** A helper for `EmitUnwindData`.
    * **`DirectiveAsString`:**  Handles the translation of data directives (like `kByte`, `kLong`) into assembly syntax specific to the compiler.
    * **Section management functions (`SectionText`, `SectionRoData`, `StartPdataSection`, `EndXdataSection`):** Indicate the file is responsible for organizing the output into different sections of an object file.
    * **Symbol declaration functions (`DeclareSymbolGlobal`, `DeclareLabel`, `DeclareExternalFunction`):** Essential for linking and referencing code and data.
    * **Alignment functions (`AlignToCodeAlignment`, `AlignToDataAlignment`):**  Crucial for performance and correctness on different architectures.

6. **Assembly Syntax Differences:** The code clearly differentiates between the assembly syntax used by MSVC (MASM/MARMASM) and other compilers (like Clang on Windows, using GAS syntax). This is evident in the different implementations within the `#if defined(V8_COMPILER_IS_MSVC)` block.

7. **Relationship to JavaScript (and V8):** The presence of "builtins," "embedded blob," and "snapshot" strongly indicates a connection to V8's internal workings. V8 pre-compiles parts of the JavaScript runtime into an "embedded blob" for faster startup. This file is involved in *writing* that blob to a file during the build process. The unwind information is crucial for handling errors within these built-in functions.

8. **Formulate the Summary:** Based on the above points, we can synthesize the summary:

    * **Core Function:**  Writes an embedded file on Windows, containing pre-compiled V8 code and data.
    * **Platform-Specific:** Handles differences between x64 and ARM64 architectures, and MSVC and other compilers.
    * **Focus on Metadata:**  A significant part deals with generating metadata for exception handling (unwind information).
    * **Assembly Generation:**  Generates assembly code in different syntaxes (MASM/MARMASM or GAS).
    * **Link to JavaScript:** Directly related to V8's startup performance by embedding pre-compiled built-in JavaScript functions.

9. **JavaScript Example:**  The connection to JavaScript is through the *built-in functions*. Provide an example of a built-in function (like `Array.prototype.map`) and explain that this code helps prepare the pre-compiled version of this function.

10. **Review and Refine:**  Read through the generated summary and the example to ensure clarity and accuracy. For instance, initially, I might not have emphasized the compiler differences as much, but the `#ifdef V8_COMPILER_IS_MSVC` block clearly shows its importance. Also, ensure the JavaScript example is simple and directly relates to the concept of built-ins.
这个C++源代码文件 `platform-embedded-file-writer-win.cc` 的主要功能是**在 Windows 平台上生成用于嵌入 V8 虚拟机快照数据的汇编代码文件**。  它负责将 V8 的内置函数和其他关键数据以特定的格式写入汇编文件，这些文件随后会被编译和链接到最终的 V8 库中。

更具体地说，它的功能包括：

1. **平台特定的汇编指令生成:**  该文件针对不同的 Windows 架构（x64 和 ARM64）和编译器（MSVC 和其他编译器如 Clang）生成相应的汇编指令。例如，它会处理不同编译器下汇编语法的差异（如数据定义的指令 `BYTE`, `DWORD`, `QWORD` vs. `.byte`, `.long`, `.quad`）。

2. **定义数据段和代码段:** 它负责定义汇编文件中的 `.text` (代码段) 和 `.rodata` (只读数据段)，以及用于异常处理的 `.pdata` 和 `.xdata` 段。

3. **声明全局符号和标签:**  它声明需要在链接时可见的全局符号（如嵌入数据的起始地址和大小），以及在代码中跳转或引用数据的标签。

4. **生成嵌入数据的汇编表示:**  它将 V8 的快照数据（例如内置函数的机器码）转换为汇编语言中的数据定义，例如使用 `BYTE` 或 `QWORD` 指令来存储字节或四字数据。

5. **生成异常处理信息 (Unwind Data):**  对于 Windows x64 和 ARM64 架构，它会生成用于栈展开（stack unwinding）的元数据（PDATA 和 XDATA）。这对于异常处理和调试至关重要。它会为每个内置函数生成 `RUNTIME_FUNCTION` (PDATA) 条目，以及对应的 `UNWIND_INFO` (XDATA) 结构，描述如何在函数调用期间恢复栈状态。

**它与 JavaScript 的功能有密切关系。**

V8 虚拟机启动时，为了提升性能，它不会从头开始解释执行所有的 JavaScript 代码。相反，它会加载一个预先生成的快照 (snapshot)，其中包含了内置的 JavaScript 函数（例如 `Array.prototype.map`, `Object.prototype.toString` 等）的编译后的机器码和其他重要的运行时数据。

`platform-embedded-file-writer-win.cc` 的作用就是在构建 V8 的过程中，将这些内置函数的机器码和其他数据以特定的格式写入汇编文件。这些汇编文件会被编译器编译成目标代码，然后链接到最终的 V8 库中。

**JavaScript 示例：**

假设 `platform-embedded-file-writer-win.cc` 生成的代码中包含了 `Array.prototype.map` 这个内置函数的机器码。当你在 JavaScript 中使用 `map` 方法时，V8 实际上执行的是这个预先编译好的机器码，而不是在运行时动态解释 `map` 方法的 JavaScript 源代码。

```javascript
const numbers = [1, 2, 3];
const doubledNumbers = numbers.map(num => num * 2);
console.log(doubledNumbers); // 输出: [2, 4, 6]
```

在这个例子中，当 JavaScript 引擎执行 `numbers.map(...)` 时，它会调用 V8 内部预先编译好的 `Array.prototype.map` 函数的机器码。而 `platform-embedded-file-writer-win.cc` 这样的文件就负责生成了这段机器码在 Windows 平台上的汇编表示。

**总结来说，`platform-embedded-file-writer-win.cc` 是 V8 构建过程中的一个关键组件，它负责将 JavaScript 的核心功能（通过内置函数实现）的预编译版本嵌入到最终的 V8 库中，从而提高 V8 的启动速度和执行效率。**  它专注于生成 Windows 平台特定的、用于嵌入的汇编代码，并处理了不同编译器和架构之间的差异。

### 提示词
```
这是目录为v8/src/snapshot/embedded/platform-embedded-file-writer-win.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
```

### 源代码
```
// Copyright 2019 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/snapshot/embedded/platform-embedded-file-writer-win.h"

#include <algorithm>

#include "src/common/globals.h"  // For V8_OS_WIN64

#if defined(V8_OS_WIN64)
#include "src/builtins/builtins.h"
#include "src/diagnostics/unwinding-info-win64.h"
#include "src/snapshot/embedded/embedded-data-inl.h"
#include "src/snapshot/embedded/embedded-file-writer.h"
#endif  // V8_OS_WIN64

// V8_CC_MSVC is true for both MSVC and clang on windows. clang can handle
// __asm__-style inline assembly but MSVC cannot, and thus we need a more
// precise compiler detection that can distinguish between the two. clang on
// windows sets both __clang__ and _MSC_VER, MSVC sets only _MSC_VER.
#if defined(_MSC_VER) && !defined(__clang__)
#define V8_COMPILER_IS_MSVC
#endif

#if defined(V8_COMPILER_IS_MSVC)
#include "src/flags/flags.h"
#endif

namespace v8 {
namespace internal {

// MSVC uses MASM for x86 and x64, while it has a ARMASM for ARM32 and
// ARMASM64 for ARM64. Since ARMASM and ARMASM64 accept a slightly tweaked
// version of ARM assembly language, they are referred to together in Visual
// Studio project files as MARMASM.
//
// ARM assembly language docs:
// http://infocenter.arm.com/help/topic/com.arm.doc.dui0802b/index.html
// Microsoft ARM assembler and assembly language docs:
// https://docs.microsoft.com/en-us/cpp/assembler/arm/arm-assembler-reference

// Name mangling.
// Symbols are prefixed with an underscore on 32-bit architectures.
#if !defined(V8_TARGET_ARCH_X64) && !defined(V8_TARGET_ARCH_ARM64)
#define SYMBOL_PREFIX "_"
#else
#define SYMBOL_PREFIX ""
#endif

// Notes:
//
// Cross-bitness builds are unsupported. It's thus safe to detect bitness
// through compile-time defines.
//
// Cross-compiler builds (e.g. with mixed use of clang / MSVC) are likewise
// unsupported and hence the compiler can also be detected through compile-time
// defines.

namespace {

#if defined(V8_OS_WIN_X64)

void WriteUnwindInfoEntry(PlatformEmbeddedFileWriterWin* w,
                          const char* unwind_info_symbol,
                          const char* embedded_blob_data_symbol,
                          uint64_t rva_start, uint64_t rva_end) {
  w->DeclareRvaToSymbol(embedded_blob_data_symbol, rva_start);
  w->DeclareRvaToSymbol(embedded_blob_data_symbol, rva_end);
  w->DeclareRvaToSymbol(unwind_info_symbol);
}

void EmitUnwindData(PlatformEmbeddedFileWriterWin* w,
                    const char* unwind_info_symbol,
                    const char* embedded_blob_data_symbol,
                    const EmbeddedData* blob,
                    const win64_unwindinfo::BuiltinUnwindInfo* unwind_infos) {
  // Emit an UNWIND_INFO (XDATA) struct, which contains the unwinding
  // information that is used for all builtin functions.
  DCHECK(win64_unwindinfo::CanEmitUnwindInfoForBuiltins());
  w->Comment("xdata for all the code in the embedded blob.");
  w->DeclareExternalFunction(CRASH_HANDLER_FUNCTION_NAME_STRING);

  w->StartXdataSection();
  {
    w->DeclareLabel(unwind_info_symbol);

    std::vector<uint8_t> xdata =
        win64_unwindinfo::GetUnwindInfoForBuiltinFunctions();
    DCHECK(!xdata.empty());

    w->IndentedDataDirective(kByte);
    for (size_t i = 0; i < xdata.size(); i++) {
      if (i > 0) fprintf(w->fp(), ",");
      w->HexLiteral(xdata[i]);
    }
    w->Newline();

    w->Comment("    ExceptionHandler");
    w->DeclareRvaToSymbol(CRASH_HANDLER_FUNCTION_NAME_STRING);
  }
  w->EndXdataSection();
  w->Newline();

  // Emit a RUNTIME_FUNCTION (PDATA) entry for each builtin function, as
  // documented here:
  // https://docs.microsoft.com/en-us/cpp/build/exception-handling-x64.
  w->Comment(
      "pdata for all the code in the embedded blob (structs of type "
      "RUNTIME_FUNCTION).");
  w->Comment("    BeginAddress");
  w->Comment("    EndAddress");
  w->Comment("    UnwindInfoAddress");
  w->StartPdataSection();
  {
    static_assert(Builtins::kAllBuiltinsAreIsolateIndependent);
    Address prev_builtin_end_offset = 0;
    for (Builtin builtin = Builtins::kFirst; builtin <= Builtins::kLast;
         ++builtin) {
      const int builtin_index = static_cast<int>(builtin);
      // Some builtins are leaf functions from the point of view of Win64 stack
      // walking: they do not move the stack pointer and do not require a PDATA
      // entry because the return address can be retrieved from [rsp].
      if (unwind_infos[builtin_index].is_leaf_function()) continue;

      uint64_t builtin_start_offset = blob->InstructionStartOf(builtin) -
                                      reinterpret_cast<Address>(blob->code());
      uint32_t builtin_size = blob->InstructionSizeOf(builtin);

      const std::vector<int>& xdata_desc =
          unwind_infos[builtin_index].fp_offsets();
      if (xdata_desc.empty()) {
        // Some builtins do not have any "push rbp - mov rbp, rsp" instructions
        // to start a stack frame. We still emit a PDATA entry as if they had,
        // relying on the fact that we can find the previous frame address from
        // rbp in most cases. Note that since the function does not really start
        // with a 'push rbp' we need to specify the start RVA in the PDATA entry
        // a few bytes before the beginning of the function, if it does not
        // overlap the end of the previous builtin.
        WriteUnwindInfoEntry(
            w, unwind_info_symbol, embedded_blob_data_symbol,
            std::max(prev_builtin_end_offset,
                     builtin_start_offset - win64_unwindinfo::kRbpPrefixLength),
            builtin_start_offset + builtin_size);
      } else {
        // Some builtins have one or more "push rbp - mov rbp, rsp" sequences,
        // but not necessarily at the beginning of the function. In this case
        // we want to yield a PDATA entry for each block of instructions that
        // emit an rbp frame. If the function does not start with 'push rbp'
        // we also emit a PDATA entry for the initial block of code up to the
        // first 'push rbp', like in the case above.
        if (xdata_desc[0] > 0) {
          WriteUnwindInfoEntry(w, unwind_info_symbol, embedded_blob_data_symbol,
                               std::max(prev_builtin_end_offset,
                                        builtin_start_offset -
                                            win64_unwindinfo::kRbpPrefixLength),
                               builtin_start_offset + xdata_desc[0]);
        }

        for (size_t j = 0; j < xdata_desc.size(); j++) {
          int chunk_start = xdata_desc[j];
          int chunk_end =
              (j < xdata_desc.size() - 1) ? xdata_desc[j + 1] : builtin_size;
          WriteUnwindInfoEntry(w, unwind_info_symbol, embedded_blob_data_symbol,
                               builtin_start_offset + chunk_start,
                               builtin_start_offset + chunk_end);
        }
      }

      prev_builtin_end_offset = builtin_start_offset + builtin_size;
      w->Newline();
    }
  }
  w->EndPdataSection();
  w->Newline();
}

#elif defined(V8_OS_WIN_ARM64)

void EmitUnwindData(PlatformEmbeddedFileWriterWin* w,
                    const char* unwind_info_symbol,
                    const char* embedded_blob_data_symbol,
                    const EmbeddedData* blob,
                    const win64_unwindinfo::BuiltinUnwindInfo* unwind_infos) {
  DCHECK(win64_unwindinfo::CanEmitUnwindInfoForBuiltins());

  // Fairly arbitrary but should fit all symbol names.
  static constexpr int kTemporaryStringLength = 256;
  base::EmbeddedVector<char, kTemporaryStringLength> unwind_info_full_symbol;

  // Emit a RUNTIME_FUNCTION (PDATA) entry for each builtin function, as
  // documented here:
  // https://docs.microsoft.com/en-us/cpp/build/arm64-exception-handling.
  w->Comment(
      "pdata for all the code in the embedded blob (structs of type "
      "RUNTIME_FUNCTION).");
  w->Comment("    BeginAddress");
  w->Comment("    UnwindInfoAddress");
  w->StartPdataSection();
  std::vector<int> code_chunks;
  std::vector<win64_unwindinfo::FrameOffsets> fp_adjustments;

  static_assert(Builtins::kAllBuiltinsAreIsolateIndependent);
  for (Builtin builtin = Builtins::kFirst; builtin <= Builtins::kLast;
       ++builtin) {
    const int builtin_index = static_cast<int>(builtin);
    if (unwind_infos[builtin_index].is_leaf_function()) continue;

    uint64_t builtin_start_offset = blob->InstructionStartOf(builtin) -
                                    reinterpret_cast<Address>(blob->code());
    uint32_t builtin_size = blob->InstructionSizeOf(builtin);

    const std::vector<int>& xdata_desc =
        unwind_infos[builtin_index].fp_offsets();
    const std::vector<win64_unwindinfo::FrameOffsets>& xdata_fp_adjustments =
        unwind_infos[builtin_index].fp_adjustments();
    DCHECK_EQ(xdata_desc.size(), xdata_fp_adjustments.size());

    for (size_t j = 0; j < xdata_desc.size(); j++) {
      int chunk_start = xdata_desc[j];
      int chunk_end =
          (j < xdata_desc.size() - 1) ? xdata_desc[j + 1] : builtin_size;
      int chunk_len = ::RoundUp(chunk_end - chunk_start, kInstrSize);

      while (chunk_len > 0) {
        int allowed_chunk_len =
            std::min(chunk_len, win64_unwindinfo::kMaxFunctionLength);
        chunk_len -= win64_unwindinfo::kMaxFunctionLength;

        // Record the chunk length and fp_adjustment for emitting UNWIND_INFO
        // later.
        code_chunks.push_back(allowed_chunk_len);
        fp_adjustments.push_back(xdata_fp_adjustments[j]);
        base::SNPrintF(unwind_info_full_symbol, "%s_%u", unwind_info_symbol,
                       code_chunks.size());
        w->DeclareRvaToSymbol(embedded_blob_data_symbol,
                              builtin_start_offset + chunk_start);
        w->DeclareRvaToSymbol(unwind_info_full_symbol.begin());
      }
    }
  }
  w->EndPdataSection();
  w->Newline();

  // Emit an UNWIND_INFO (XDATA) structs, which contains the unwinding
  // information.
  w->DeclareExternalFunction(CRASH_HANDLER_FUNCTION_NAME_STRING);
  w->StartXdataSection();
  {
    for (size_t i = 0; i < code_chunks.size(); i++) {
      base::SNPrintF(unwind_info_full_symbol, "%s_%u", unwind_info_symbol,
                     i + 1);
      w->DeclareLabel(unwind_info_full_symbol.begin());
      std::vector<uint8_t> xdata =
          win64_unwindinfo::GetUnwindInfoForBuiltinFunction(code_chunks[i],
                                                            fp_adjustments[i]);

      w->IndentedDataDirective(kByte);
      for (size_t j = 0; j < xdata.size(); j++) {
        if (j > 0) fprintf(w->fp(), ",");
        w->HexLiteral(xdata[j]);
      }
      w->Newline();
      w->DeclareRvaToSymbol(CRASH_HANDLER_FUNCTION_NAME_STRING);
    }
  }
  w->EndXdataSection();
  w->Newline();
}

#endif  // V8_OS_WIN_X64

}  // namespace

const char* PlatformEmbeddedFileWriterWin::DirectiveAsString(
    DataDirective directive) {
#if defined(V8_COMPILER_IS_MSVC)
  if (target_arch_ != EmbeddedTargetArch::kArm64) {
    switch (directive) {
      case kByte:
        return "BYTE";
      case kLong:
        return "DWORD";
      case kQuad:
        return "QWORD";
      default:
        UNREACHABLE();
    }
  } else {
    switch (directive) {
      case kByte:
        return "DCB";
      case kLong:
        return "DCDU";
      case kQuad:
        return "DCQU";
      default:
        UNREACHABLE();
    }
  }
#else
  switch (directive) {
    case kByte:
      return ".byte";
    case kLong:
      return ".long";
    case kQuad:
      return ".quad";
    case kOcta:
      return ".octa";
  }
  UNREACHABLE();
#endif
}

void PlatformEmbeddedFileWriterWin::MaybeEmitUnwindData(
    const char* unwind_info_symbol, const char* embedded_blob_data_symbol,
    const EmbeddedData* blob, const void* unwind_infos) {
// Windows ARM64 supports cross build which could require unwind info for
// host_os. Ignore this case because it is only used in build time.
#if defined(V8_OS_WIN_ARM64)
  if (target_arch_ != EmbeddedTargetArch::kArm64) {
    return;
  }
#endif  // V8_OS_WIN_ARM64

#if defined(V8_OS_WIN64)
  if (win64_unwindinfo::CanEmitUnwindInfoForBuiltins()) {
    EmitUnwindData(this, unwind_info_symbol, embedded_blob_data_symbol, blob,
                   reinterpret_cast<const win64_unwindinfo::BuiltinUnwindInfo*>(
                       unwind_infos));
  }
#endif  // V8_OS_WIN64
}

// Windows, MSVC
// -----------------------------------------------------------------------------

#if defined(V8_COMPILER_IS_MSVC)

// For x64 MSVC builds we emit assembly in MASM syntax.
// See https://docs.microsoft.com/en-us/cpp/assembler/masm/directives-reference.
// For Arm build, we emit assembly in MARMASM syntax.
// Note that the same mksnapshot has to be used to compile the host and target.

// The AARCH64 ABI requires instructions be 4-byte-aligned and Windows does
// not have a stricter alignment requirement (see the TEXTAREA macro of
// kxarm64.h in the Windows SDK), so code is 4-byte-aligned.
// The data fields in the emitted assembly tend to be accessed with 8-byte
// LDR instructions, so data is 8-byte-aligned.
//
// armasm64's warning A4228 states
//     Alignment value exceeds AREA alignment; alignment not guaranteed
// To ensure that ALIGN directives are honored, their values are defined as
// equal to their corresponding AREA's ALIGN attributes.

#define ARM64_DATA_ALIGNMENT_POWER (3)
#define ARM64_DATA_ALIGNMENT (1 << ARM64_DATA_ALIGNMENT_POWER)
#define ARM64_CODE_ALIGNMENT_POWER (2)
#define ARM64_CODE_ALIGNMENT (1 << ARM64_CODE_ALIGNMENT_POWER)

void PlatformEmbeddedFileWriterWin::SectionText() {
  if (target_arch_ == EmbeddedTargetArch::kArm64) {
    fprintf(fp_, "  AREA |.text|, CODE, ALIGN=%d, READONLY\n",
            ARM64_CODE_ALIGNMENT_POWER);
  } else {
    fprintf(fp_, ".CODE\n");
  }
}

void PlatformEmbeddedFileWriterWin::SectionRoData() {
  if (target_arch_ == EmbeddedTargetArch::kArm64) {
    fprintf(fp_, "  AREA |.rodata|, DATA, ALIGN=%d, READONLY\n",
            ARM64_DATA_ALIGNMENT_POWER);
  } else {
    fprintf(fp_, ".CONST\n");
  }
}

void PlatformEmbeddedFileWriterWin::DeclareUint32(const char* name,
                                                  uint32_t value) {
  DeclareSymbolGlobal(name);
  fprintf(fp_, "%s%s %s %d\n", SYMBOL_PREFIX, name, DirectiveAsString(kLong),
          value);
}

void PlatformEmbeddedFileWriterWin::StartPdataSection() {
  if (target_arch_ == EmbeddedTargetArch::kArm64) {
    fprintf(fp_, "  AREA |.pdata|, DATA, ALIGN=%d, READONLY\n",
            ARM64_DATA_ALIGNMENT_POWER);
  } else {
    fprintf(fp_, "OPTION DOTNAME\n");
    fprintf(fp_, ".pdata SEGMENT DWORD READ ''\n");
  }
}

void PlatformEmbeddedFileWriterWin::EndPdataSection() {
  if (target_arch_ != EmbeddedTargetArch::kArm64) {
    fprintf(fp_, ".pdata ENDS\n");
  }
}

void PlatformEmbeddedFileWriterWin::StartXdataSection() {
  if (target_arch_ == EmbeddedTargetArch::kArm64) {
    fprintf(fp_, "  AREA |.xdata|, DATA, ALIGN=%d, READONLY\n",
            ARM64_DATA_ALIGNMENT_POWER);
  } else {
    fprintf(fp_, "OPTION DOTNAME\n");
    fprintf(fp_, ".xdata SEGMENT DWORD READ ''\n");
  }
}

void PlatformEmbeddedFileWriterWin::EndXdataSection() {
  if (target_arch_ != EmbeddedTargetArch::kArm64) {
    fprintf(fp_, ".xdata ENDS\n");
  }
}

void PlatformEmbeddedFileWriterWin::DeclareExternalFunction(const char* name) {
  if (target_arch_ == EmbeddedTargetArch::kArm64) {
    fprintf(fp_, "  EXTERN %s \n", name);
  } else {
    fprintf(fp_, "EXTERN %s : PROC\n", name);
  }
}

void PlatformEmbeddedFileWriterWin::DeclareRvaToSymbol(const char* name,
                                                       uint64_t offset) {
  if (target_arch_ == EmbeddedTargetArch::kArm64) {
    if (offset > 0) {
      fprintf(fp_, "  DCD  %s + %llu\n", name, offset);
    } else {
      fprintf(fp_, "  DCD  %s\n", name);
    }
    // The default relocation entry generated by MSVC armasm64.exe for DCD
    // directive is IMAGE_REL_ARM64_ADDR64 which represents relocation for
    // 64-bit pointer instead of 32-bit RVA. Append RELOC with
    // IMAGE_REL_ARM64_ADDR32NB(2) to generate correct relocation entry for
    // 32-bit RVA.
    fprintf(fp_, "  RELOC 2\n");
  } else {
    if (offset > 0) {
      fprintf(fp_, "DD IMAGEREL %s+%llu\n", name, offset);
    } else {
      fprintf(fp_, "DD IMAGEREL %s\n", name);
    }
  }
}

void PlatformEmbeddedFileWriterWin::DeclareSymbolGlobal(const char* name) {
  if (target_arch_ == EmbeddedTargetArch::kArm64) {
    fprintf(fp_, "  EXPORT %s%s\n", SYMBOL_PREFIX, name);
  } else {
    fprintf(fp_, "PUBLIC %s%s\n", SYMBOL_PREFIX, name);
  }
}

void PlatformEmbeddedFileWriterWin::AlignToCodeAlignment() {
  if (target_arch_ == EmbeddedTargetArch::kArm64) {
    fprintf(fp_, "  ALIGN %d\n", ARM64_CODE_ALIGNMENT);
  } else {
    // Diverges from other platforms due to compile error
    // 'invalid combination with segment alignment'.
    fprintf(fp_, "ALIGN 4\n");
  }
}

void PlatformEmbeddedFileWriterWin::AlignToDataAlignment() {
  if (target_arch_ == EmbeddedTargetArch::kArm64) {
    fprintf(fp_, "  ALIGN %d\n", ARM64_DATA_ALIGNMENT);

  } else {
    fprintf(fp_, "ALIGN 4\n");
  }
}

void PlatformEmbeddedFileWriterWin::Comment(const char* string) {
  fprintf(fp_, "; %s\n", string);
}

void PlatformEmbeddedFileWriterWin::DeclareLabel(const char* name) {
  if (target_arch_ == EmbeddedTargetArch::kArm64) {
    fprintf(fp_, "%s%s\n", SYMBOL_PREFIX, name);

  } else {
    fprintf(fp_, "%s%s LABEL %s\n", SYMBOL_PREFIX, name,
            DirectiveAsString(kByte));
  }
}

void PlatformEmbeddedFileWriterWin::SourceInfo(int fileid, const char* filename,
                                               int line) {
  // TODO(mvstanton): output source information for MSVC.
  // Its syntax is #line <line> "<filename>"
}

// TODO(mmarchini): investigate emitting size annotations for Windows
void PlatformEmbeddedFileWriterWin::DeclareFunctionBegin(const char* name,
                                                         uint32_t size) {
  if (target_arch_ == EmbeddedTargetArch::kArm64) {
    fprintf(fp_, "%s%s FUNCTION\n", SYMBOL_PREFIX, name);

  } else {
    fprintf(fp_, "%s%s PROC\n", SYMBOL_PREFIX, name);
  }
}

void PlatformEmbeddedFileWriterWin::DeclareFunctionEnd(const char* name) {
  if (target_arch_ == EmbeddedTargetArch::kArm64) {
    fprintf(fp_, "  ENDFUNC\n");

  } else {
    fprintf(fp_, "%s%s ENDP\n", SYMBOL_PREFIX, name);
  }
}

int PlatformEmbeddedFileWriterWin::HexLiteral(uint64_t value) {
  if (target_arch_ == EmbeddedTargetArch::kArm64) {
    return fprintf(fp_, "0x%" PRIx64, value);

  } else {
    return fprintf(fp_, "0%" PRIx64 "h", value);
  }
}

void PlatformEmbeddedFileWriterWin::FilePrologue() {
  if (target_arch_ != EmbeddedTargetArch::kArm64 &&
      target_arch_ != EmbeddedTargetArch::kX64) {
    // x86 falls into this case
    fprintf(fp_, ".MODEL FLAT\n");
  }
}

void PlatformEmbeddedFileWriterWin::DeclareExternalFilename(
    int fileid, const char* filename) {}

void PlatformEmbeddedFileWriterWin::FileEpilogue() {
  if (target_arch_ == EmbeddedTargetArch::kArm64) {
    fprintf(fp_, "  END\n");
  } else {
    fprintf(fp_, "END\n");
  }
}

int PlatformEmbeddedFileWriterWin::IndentedDataDirective(
    DataDirective directive) {
  return fprintf(fp_, "  %s ", DirectiveAsString(directive));
}

#undef ARM64_DATA_ALIGNMENT_POWER
#undef ARM64_DATA_ALIGNMENT
#undef ARM64_CODE_ALIGNMENT_POWER
#undef ARM64_CODE_ALIGNMENT

// All Windows builds without MSVC.
// -----------------------------------------------------------------------------

#else

// The directives for text section prefix come from the COFF
// (Common Object File Format) standards:
// https://llvm.org/docs/Extensions.html
//
// .text$hot means this section contains hot code.
// x means executable section.
// r means read-only section.
void PlatformEmbeddedFileWriterWin::SectionText() {
  fprintf(fp_, ".section .text$hot,\"xr\"\n");
}

void PlatformEmbeddedFileWriterWin::SectionRoData() {
  fprintf(fp_, ".section .rdata\n");
}

void PlatformEmbeddedFileWriterWin::DeclareUint32(const char* name,
                                                  uint32_t value) {
  DeclareSymbolGlobal(name);
  DeclareLabel(name);
  IndentedDataDirective(kLong);
  fprintf(fp_, "%d", value);
  Newline();
}

void PlatformEmbeddedFileWriterWin::StartPdataSection() {
  fprintf(fp_, ".section .pdata\n");
}

void PlatformEmbeddedFileWriterWin::EndPdataSection() {}

void PlatformEmbeddedFileWriterWin::StartXdataSection() {
  fprintf(fp_, ".section .xdata\n");
}

void PlatformEmbeddedFileWriterWin::EndXdataSection() {}

void PlatformEmbeddedFileWriterWin::DeclareExternalFunction(const char* name) {}

void PlatformEmbeddedFileWriterWin::DeclareRvaToSymbol(const char* name,
                                                       uint64_t offset) {
  if (offset > 0) {
    fprintf(fp_, ".rva %s + %" PRIu64 "\n", name, offset);
  } else {
    fprintf(fp_, ".rva %s\n", name);
  }
}

void PlatformEmbeddedFileWriterWin::DeclareSymbolGlobal(const char* name) {
  fprintf(fp_, ".global %s%s\n", SYMBOL_PREFIX, name);
}

void PlatformEmbeddedFileWriterWin::AlignToCodeAlignment() {
#if V8_TARGET_ARCH_X64
  // On x64 use 64-bytes code alignment to allow 64-bytes loop header alignment.
  static_assert(64 >= kCodeAlignment);
  fprintf(fp_, ".balign 64\n");
#elif V8_TARGET_ARCH_PPC64
  // 64 byte alignment is needed on ppc64 to make sure p10 prefixed instructions
  // don't cross 64-byte boundaries.
  static_assert(64 >= kCodeAlignment);
  fprintf(fp_, ".balign 64\n");
#else
  static_assert(32 >= kCodeAlignment);
  fprintf(fp_, ".balign 32\n");
#endif
}

void PlatformEmbeddedFileWriterWin::AlignToDataAlignment() {
  // On Windows ARM64, s390, PPC and possibly more platforms, aligned load
  // instructions are used to retrieve v8_Default_embedded_blob_ and/or
  // v8_Default_embedded_blob_size_. The generated instructions require the
  // load target to be aligned at 8 bytes (2^3).
  fprintf(fp_, ".balign 8\n");
}

void PlatformEmbeddedFileWriterWin::Comment(const char* string) {
  fprintf(fp_, "// %s\n", string);
}

void PlatformEmbeddedFileWriterWin::DeclareLabel(const char* name) {
  fprintf(fp_, "%s%s:\n", SYMBOL_PREFIX, name);
}

void PlatformEmbeddedFileWriterWin::SourceInfo(int fileid, const char* filename,
                                               int line) {
  // BUG(9944): Use .cv_loc to ensure CodeView information is used on
  // Windows.
}

// TODO(mmarchini): investigate emitting size annotations for Windows
void PlatformEmbeddedFileWriterWin::DeclareFunctionBegin(const char* name,
                                                         uint32_t size) {
  DeclareLabel(name);

  if (target_arch_ == EmbeddedTargetArch::kArm64
#if V8_ENABLE_DRUMBRAKE
      || IsDrumBrakeInstructionHandler(name)
#endif  // V8_ENABLE_DRUMBRAKE
  ) {
    // Windows ARM64 assembly is in GAS syntax, but ".type" is invalid directive
    // in PE/COFF for Windows.
    DeclareSymbolGlobal(name);
  } else {
    // The directives for inserting debugging information on Windows come
    // from the PE (Portable Executable) and COFF (Common Object File Format)
    // standards. Documented here:
    // https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format
    //
    // .scl 2 means StorageClass external.
    // .type 32 means Type Representation Function.
    fprintf(fp_, ".def %s%s; .scl 2; .type 32; .endef;\n", SYMBOL_PREFIX, name);
  }
}

void PlatformEmbeddedFileWriterWin::DeclareFunctionEnd(const char* name) {}

int PlatformEmbeddedFileWriterWin::HexLiteral(uint64_t value) {
  return fprintf(fp_, "0x%" PRIx64, value);
}

void PlatformEmbeddedFileWriterWin::FilePrologue() {}

void PlatformEmbeddedFileWriterWin::DeclareExternalFilename(
    int fileid, const char* filename) {
  // BUG(9944): Use .cv_filename to ensure CodeView information is used on
  // Windows.
}

void PlatformEmbeddedFileWriterWin::FileEpilogue() {}

int PlatformEmbeddedFileWriterWin::IndentedDataDirective(
    DataDirective directive) {
  return fprintf(fp_, "  %s ", DirectiveAsString(directive));
}

#endif

DataDirective PlatformEmbeddedFileWriterWin::ByteChunkDataDirective() const {
#if defined(V8_COMPILER_IS_MSVC)
  // Windows MASM doesn't have an .octa directive, use QWORDs instead.
  // Note: MASM *really* does not like large data streams. It takes over 5
  // minutes to assemble the ~350K lines of embedded.S produced when using
  // BYTE directives in a debug build. QWORD produces roughly 120KLOC and
  // reduces assembly time to ~40 seconds. Still terrible, but much better
  // than before. See also: https://crbug.com/v8/8475.
  return kQuad;
#else
  return PlatformEmbeddedFileWriterBase::ByteChunkDataDirective();
#endif
}

int PlatformEmbeddedFileWriterWin::WriteByteChunk(const uint8_t* data) {
#if defined(V8_COMPILER_IS_MSVC)
  DCHECK_EQ(ByteChunkDataDirective(), kQuad);
  const uint64_t* quad_ptr = reinterpret_cast<const uint64_t*>(data);
  return HexLiteral(*quad_ptr);
#else
  return PlatformEmbeddedFileWriterBase::WriteByteChunk(data);
#endif
}

#undef SYMBOL_PREFIX
#undef V8_ASSEMBLER_IS_MASM
#undef V8_ASSEMBLER_IS_MARMASM
#undef V8_COMPILER_IS_MSVC

}  // namespace internal
}  // namespace v8
```