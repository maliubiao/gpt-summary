Response:
Let's break down the thought process to analyze the provided C++ code.

1. **Understand the Goal:** The core request is to understand the *functionality* of the given C++ file (`platform-embedded-file-writer-win.cc`). This means figuring out what it does within the larger V8 project.

2. **Initial Scan and Keywords:** Quickly read through the code, looking for key terms and patterns. Things that stand out:
    * `#include`: Indicates dependencies on other V8 components.
    * `namespace v8::internal`:  Confirms this is internal V8 code.
    * `PlatformEmbeddedFileWriterWin`:  The central class, likely responsible for writing something related to embedded files on Windows.
    * `Embedded`: This term appears frequently, suggesting dealing with embedded data.
    * `UnwindInfo`, `pdata`, `xdata`:  Keywords related to exception handling on Windows.
    * `MSVC`, `clang`:  Compiler-specific logic.
    * `ARM64`, `X64`: Architecture-specific code.
    * `fprintf`: Used for writing to a file.
    * Directives like `BYTE`, `DWORD`, `QWORD`, `.byte`, `.long`, `.quad`:  Assembly language directives.
    * `DeclareSymbolGlobal`, `DeclareLabel`, `DeclareExternalFunction`: Functions for managing symbols in the output.

3. **Inferring the Purpose from the Class Name:** "PlatformEmbeddedFileWriterWin" strongly suggests this class is responsible for writing files that will be embedded within the V8 engine on Windows. The "Platform" part indicates it's platform-specific.

4. **Focusing on Core Functionality:**  The most prominent feature seems to be the handling of "unwind data" (PDATA and XDATA). This is a critical part of exception handling on Windows. The code specifically targets x64 and ARM64 architectures.

5. **Analyzing Conditional Compilation:**  Pay close attention to `#if defined(...)` blocks. These are essential for understanding how the code behaves in different build configurations (e.g., different architectures, compilers). The code differentiates between MSVC and other compilers (like clang on Windows) and between x64 and ARM64 architectures.

6. **Deciphering Assembly Directives:** The code generates assembly language output. Understanding the assembly directives (like `BYTE`, `DWORD`, `ALIGN`, `PUBLIC`, `.section`, `.global`) is crucial to grasping what kind of output is being produced. The comments within the code are helpful here, explaining the meaning of PDATA and XDATA.

7. **Connecting to V8 Concepts:**  The code mentions `Builtins`. This connects the file writer to the built-in JavaScript functions within V8. The `EmbeddedData` structure likely holds the compiled code for these built-ins.

8. **Formulating the High-Level Functionality:** Based on the analysis so far, we can summarize the main purpose: This file writes assembly code that embeds V8's built-in functions and their exception handling information (unwind data) into a file on Windows.

9. **Addressing Specific Questions in the Prompt:**

    * **Functionality Listing:** List the key actions the code performs, drawing from the analysis above (writing assembly, handling unwind info, architecture-specific logic, etc.).
    * **`.tq` Extension:**  Recognize that `.tq` indicates Torque code, a language used within V8, and state that the current file is C++, not Torque.
    * **Relationship to JavaScript:**  Explain the link through the built-in functions. Provide a simple JavaScript example of using a built-in function to illustrate the connection.
    * **Code Logic Inference (Hypothetical Input/Output):** Focus on the unwind data emission. Hypothesize that if a builtin function requires stack unwinding, the code will emit PDATA and XDATA entries for it. The output would be assembly directives defining these structures. A concrete example with a simplified builtin would be ideal, but given the complexity of the actual code, a more conceptual example is reasonable.
    * **Common Programming Errors:** Think about errors related to assembly generation, especially platform-specific ones. Incorrect symbol naming, alignment issues, or wrong directives are good examples.

10. **Refining and Structuring the Answer:** Organize the information logically, using clear headings and bullet points. Provide explanations that are easy to understand, even for someone not deeply familiar with V8 internals. Ensure the JavaScript example is simple and relevant.

**Self-Correction/Refinement during the Process:**

* **Initial thought:**  Maybe this is just about embedding data in general.
* **Correction:** The strong focus on unwind information and builtins points to a more specific purpose related to making the embedded V8 runtime functional on Windows, including exception handling.
* **Initial thought:** Explain every single assembly directive in detail.
* **Correction:** Focus on the *purpose* of the directives (defining code, data, unwind info) rather than a detailed assembly language tutorial.
* **Initial thought:**  Provide a complex JavaScript example.
* **Correction:** A simple example demonstrating the *use* of built-in functions is sufficient to show the connection.

By following these steps, combining code analysis with an understanding of the V8 project's goals, and systematically addressing the prompt's questions, we can arrive at a comprehensive and accurate explanation of the provided C++ code.
好的，让我们来分析一下 `v8/src/snapshot/embedded/platform-embedded-file-writer-win.cc` 这个 V8 源代码文件的功能。

**主要功能：生成用于 Windows 平台的嵌入式快照文件的汇编代码**

这个 C++ 文件定义了一个名为 `PlatformEmbeddedFileWriterWin` 的类，其主要职责是生成特定于 Windows 平台的汇编代码，用于将 V8 的嵌入式快照数据写入到文件中。这个文件是构建 V8 引擎的一部分，特别是当需要创建一个包含预编译 JavaScript 代码（例如内置函数）的快照时。

**功能拆解：**

1. **平台特定性：**  文件名中的 "Win" 表明这个文件专门处理 Windows 平台。它会根据不同的 Windows 架构（x64, ARM64）和编译器（MSVC, Clang）生成不同的汇编语法。

2. **嵌入式快照：** "embedded" 指的是将 V8 的核心代码和数据嵌入到最终的可执行文件中，而不是作为单独的文件加载。这提高了启动速度。

3. **文件写入器：**  `PlatformEmbeddedFileWriterWin` 继承自一个更通用的文件写入器基类（很可能在 `v8/src/snapshot/embedded/embedded-file-writer.h` 中定义）。它扩展了基类的功能，以处理 Windows 特定的汇编语法和段定义。

4. **生成汇编代码：**  核心功能是通过 `fprintf` 函数向文件中写入各种汇编指令和数据定义。这些指令包括：
   - **段定义：**  `.CODE`, `.CONST`, `.pdata`, `.xdata` (MSVC) 或 `.section .text$hot`, `.section .rdata`, `.section .pdata`, `.section .xdata` (其他编译器)。这些定义了代码段、只读数据段以及用于异常处理的 PDATA 和 XDATA 段。
   - **数据定义：**  `BYTE`, `DWORD`, `QWORD` (MSVC) 或 `.byte`, `.long`, `.quad` (其他编译器)，用于定义字节、长字和四字大小的数据。
   - **符号定义：** `PUBLIC`, `GLOBAL`, `LABEL`，用于声明全局符号、标签等。
   - **对齐指令：** `ALIGN`, `.balign`，用于确保代码和数据在内存中的对齐。
   - **注释：**  `;` 或 `//` 开头的注释，用于提高代码可读性。
   - **外部符号声明：** `EXTERN`，声明在其他地方定义的函数或符号。
   - **相对虚拟地址 (RVA) 定义：** `DD IMAGEREL` (MSVC) 或 `.rva` (其他编译器)，用于在 PE 文件中表示相对于模块基地址的地址。
   - **函数定义：** `PROC`/`ENDP` (MSVC) 或 `.def`/`.endef` (其他编译器)，用于标记函数的开始和结束。
   - **异常处理信息 (Unwind Data)：**  `PDATA` 和 `XDATA` 段的生成是此文件的一个重要部分，用于在发生异常时进行堆栈回溯。这在 Windows 上通过 `RUNTIME_FUNCTION` 结构（PDATA）和 `UNWIND_INFO` 结构（XDATA）来实现。

5. **处理异常处理信息 (Unwind Info)：**  对于 x64 和 ARM64 架构，代码会生成必要的 PDATA (Procedure Data) 和 XDATA (Exception Data) 条目，以便 Windows 操作系统能够正确处理 V8 嵌入式代码中的异常。这涉及到：
   - **`EmitUnwindData` 函数：**  根据内置函数的特性（是否是叶子函数，是否有帧指针等）生成相应的 PDATA 和 XDATA。
   - **`WriteUnwindInfoEntry` 函数：**  辅助函数，用于生成单个 PDATA 条目。
   - **针对不同架构的实现：**  x64 和 ARM64 的 unwind info 生成方式略有不同。

6. **编译器和架构感知：**  代码中大量使用了条件编译 (`#if defined(...)`) 来处理不同编译器 (MSVC vs. others) 和架构 (x64 vs. ARM64) 的差异，确保生成的汇编代码符合目标平台的规范。

**关于 `.tq` 扩展名：**

如果 `v8/src/snapshot/embedded/platform-embedded-file-writer-win.cc` 以 `.tq` 结尾，那么它确实是一个 V8 Torque 源代码文件。Torque 是一种 V8 内部使用的领域特定语言，用于定义内置函数。然而，当前的文件名是 `.cc`，表明这是一个 C++ 源文件。因此，当前文件不是 Torque 代码。

**与 JavaScript 的关系：**

`platform-embedded-file-writer-win.cc` 生成的汇编代码最终会被编译并链接到 V8 引擎中。这些代码包含了 V8 的内置函数（例如 `Array.prototype.map`, `String.prototype.indexOf` 等）的实现。当 JavaScript 代码调用这些内置函数时，引擎会执行嵌入在快照中的机器码。

**JavaScript 示例：**

```javascript
// 这是一个简单的 JavaScript 例子，调用了内置的 Array.prototype.map 方法
const numbers = [1, 2, 3, 4, 5];
const doubledNumbers = numbers.map(function(number) {
  return number * 2;
});

console.log(doubledNumbers); // 输出: [2, 4, 6, 8, 10]
```

在这个例子中，`numbers.map()` 调用了 JavaScript 引擎内部实现的 `Array.prototype.map` 函数。在使用了嵌入式快照的 V8 版本中，`Array.prototype.map` 的机器码很可能就是通过 `platform-embedded-file-writer-win.cc` 生成的汇编代码编译而来的。

**代码逻辑推理（假设输入与输出）：**

假设输入以下信息：

- **目标架构：** x64
- **编译器：** MSVC
- **一个内置函数 `String.prototype.substring` 的相关信息：**
    - 起始地址偏移量：100
    - 大小：50 字节
    - 需要 unwind info

**可能的输出（简化）：**

```assembly
.CODE
PUBLIC _String_prototype_substring
_String_prototype_substring LABEL BYTE
  ; ... String.prototype.substring 的机器码 ...

.pdata SEGMENT DWORD READ ''
DD IMAGEREL _String_prototype_substring  ; BeginAddress
DD IMAGEREL _String_prototype_substring + 50 ; EndAddress
DD IMAGEREL unwind_info_for_substring  ; UnwindInfoAddress
.pdata ENDS

.xdata SEGMENT DWORD READ ''
unwind_info_for_substring LABEL BYTE
  ; ... unwind info 的数据 ...
.xdata ENDS
```

**解释：**

- `.CODE` 段包含 `String.prototype.substring` 的机器码。
- `.pdata` 段包含一个 `RUNTIME_FUNCTION` 结构，描述了 `String.prototype.substring` 的起始地址、结束地址以及 unwind info 的地址。
- `.xdata` 段包含实际的 unwind info 数据，用于异常处理。

**用户常见的编程错误（与此文件生成的代码相关）：**

虽然用户通常不会直接编写或修改这类底层代码，但与嵌入式快照和异常处理相关的常见错误可能包括：

1. **不正确的函数签名或调用约定：**  如果手写汇编代码或修改生成的汇编代码，可能会错误地假设函数的参数传递方式或返回方式，导致崩溃或未定义的行为。

   **示例：**  假设一个 C++ 内置函数期望两个整数参数，但错误的汇编代码只传递了一个参数。

2. **堆栈损坏：**  在汇编代码中错误地操作堆栈指针（例如，`push` 和 `pop` 不匹配）可能导致堆栈损坏，最终导致程序崩溃。

   **示例：**  在函数入口 `push rbp` 但在函数出口忘记 `pop rbp`。

3. **不正确的异常处理信息：**  如果生成的 PDATA 或 XDATA 不正确，Windows 异常处理机制可能无法正确回溯堆栈，导致错误的崩溃报告或无法捕获异常。

   **示例：**  在生成 unwind info 时，错误地计算了帧指针的偏移量。

4. **代码对齐问题：**  某些架构对代码的内存对齐有要求。如果生成的汇编代码没有正确对齐，可能会导致性能下降或在某些处理器上崩溃。

   **示例：**  在需要 16 字节对齐的位置放置了未对齐的指令。

总而言之，`v8/src/snapshot/embedded/platform-embedded-file-writer-win.cc` 是 V8 引擎构建过程中的一个关键组件，它负责生成特定于 Windows 平台的汇编代码，用于嵌入 V8 的核心功能，并确保在发生异常时能够正确处理。它涉及到对 Windows 平台特性、汇编语言和 PE 文件格式的深入理解。

Prompt: 
```
这是目录为v8/src/snapshot/embedded/platform-embedded-file-writer-win.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/snapshot/embedded/platform-embedded-file-writer-win.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
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

"""

```