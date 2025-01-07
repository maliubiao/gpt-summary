Response:
Let's break down the thought process for analyzing this C++ code and generating the descriptive answer.

1. **Understanding the Goal:** The primary goal is to understand what the provided C++ code does, specifically within the context of V8. The prompt also asks for specific considerations like Torque, JavaScript relevance, logical reasoning, and common programming errors.

2. **Initial Scan for Keywords and Concepts:** I'd first skim the code looking for familiar terms and patterns related to compilers, debugging, and architecture. Keywords like "eh_frame", "diagnostics", "unwinding", "Dwarf", "CIE", "FDE", "registers", "stack", and architecture-specific defines (like `V8_TARGET_ARCH_X64`) immediately stand out. These point towards the code being involved in exception handling and stack unwinding.

3. **Focusing on the Core Functionality:** The presence of `EhFrameWriter` and `EhFrameIterator` suggests the code is about *generating* and *processing* `eh_frame` data. The `Write...` methods in `EhFrameWriter` clearly indicate the construction of this data. The `GetNext...` methods in `EhFrameIterator` suggest reading and interpreting it.

4. **Understanding `eh_frame`:**  Based on the keywords and the context of diagnostics, I'd recall (or quickly research) that `eh_frame` is a standard mechanism (part of the DWARF debugging format) for describing how the stack frame can be unwound during exception handling. It provides information on how to restore registers and the stack pointer at various points in the code.

5. **Analyzing `EhFrameWriter`:**  I'd go through the methods of `EhFrameWriter` systematically:
    * `WriteEmptyEhFrame`:  Creates a minimal `eh_frame` header.
    * `Initialize`: Sets up the writer and starts the process with `WriteCie` and `WriteFdeHeader`.
    * `WriteCie`:  Writes the "Call Frame Information Entry" (CIE), which describes common unwinding information for a set of frames.
    * `WriteFdeHeader`: Writes the "Frame Description Entry" (FDE) header, which describes the unwinding information for a specific function.
    * `WriteEhFrameHdr`: Writes the `.eh_frame_hdr`, an index for quickly finding FDEs.
    * `AdvanceLocation`: Records the progress through the function's code (PC offsets).
    * `SetBaseAddress...`:  Defines how the stack pointer is managed.
    * `RecordRegisterSavedToStack`, `RecordRegisterNotModified`, `RecordRegisterFollowsInitialRule`:  Describe how register values are preserved (or not) during function execution.
    * `Finish`: Completes the FDE, writes the terminator, and the `eh_frame_hdr`.
    * `GetEhFrame`:  Retrieves the generated `eh_frame` data.
    * `WriteULeb128`, `WriteSLeb128`:  Helper functions for writing variable-length encoded integers (used in DWARF).

6. **Analyzing `EhFrameIterator`:**  I'd look at the methods of `EhFrameIterator`:
    * `GetNextULeb128`, `GetNextSLeb128`:  Read the variable-length encoded integers.
    * `DecodeULeb128`, `DecodeSLeb128`:  The core logic for decoding these integers.

7. **Analyzing `EhFrameDisassembler` (if enabled):**  If the `ENABLE_DISASSEMBLER` macro is defined, this section provides functionality to print a human-readable representation of the `eh_frame` data. This is crucial for debugging.

8. **Addressing Specific Prompt Questions:**

    * **Functionality:** Summarize the purpose of the code based on the analysis above (generating `eh_frame` data for stack unwinding).
    * **Torque:** Check the file extension. It's `.cc`, not `.tq`, so it's standard C++.
    * **JavaScript Relation:**  Consider how exception handling works in JavaScript. When a JavaScript exception is thrown, the V8 runtime needs to unwind the stack, which *includes* native C++ frames. `eh_frame` provides the information for unwinding these native frames, making it indirectly related to JavaScript's exception handling. Provide a simple JavaScript `try...catch` example to illustrate this.
    * **Logical Reasoning (Hypothetical Input/Output):** Think about a simple function and how its stack frame might be described. Assume a register being saved on the stack. Describe the sequence of `EhFrameWriter` calls and the resulting (simplified) `eh_frame` data.
    * **Common Programming Errors:** Consider errors related to stack management and register usage in native code that `eh_frame` helps diagnose (e.g., stack corruption due to incorrect frame setup).

9. **Architecture-Specific Considerations:** Notice the `#if !defined(...)` block. This indicates that the code provides placeholder implementations for architectures where full `eh_frame` generation isn't supported. For supported architectures (like x64, ARM), there would be architecture-specific implementations for things like register mappings.

10. **Refinement and Organization:** Organize the findings into clear sections as requested by the prompt (Functionality, Torque, JavaScript, Logical Reasoning, Common Errors). Use clear and concise language. Provide code examples where necessary.

**Self-Correction/Refinement During the Process:**

* Initially, I might just think "exception handling," but realizing the code generates and interprets data leads to a more precise description of its function.
* If unsure about the meaning of a specific DWARF term (like CIE or FDE), I'd quickly look it up to ensure accuracy.
* While considering JavaScript relevance, I'd move from a direct link (which doesn't exist) to the *indirect* link through native stack unwinding during JavaScript exception handling.
* For the hypothetical input/output, starting with a very simple case (saving one register) makes the explanation clearer before potentially adding complexity.

By following this systematic approach, combining code analysis with domain knowledge (about compilers, debugging, and exception handling), I can construct a comprehensive and accurate answer to the prompt.
这段C++源代码文件 `v8/src/diagnostics/eh-frame.cc` 的主要功能是**生成和管理用于支持 C++ 异常处理（Exception Handling）的 `.eh_frame` 数据**。

以下是更详细的功能分解：

**核心功能：生成 `.eh_frame` 数据**

* **`.eh_frame` 的作用：** `.eh_frame` 是一种标准的数据格式（属于 DWARF 调试信息的一部分），用于描述函数调用栈的结构，以及如何在发生异常时安全地展开栈帧（unwind the stack）。这对于 C++ 的异常处理机制至关重要，因为它允许程序在抛出异常时，能正确地清理资源并找到合适的 `catch` 代码块。
* **`EhFrameWriter` 类：**  这是核心的类，负责构建 `.eh_frame` 数据。它提供了一系列方法来逐步描述函数的栈帧信息，包括：
    * **CIE (Call Frame Information Entry):**  通过 `WriteCie()` 方法写入。CIE 描述了一组函数共享的通用栈帧信息，例如代码和数据的对齐方式，以及返回地址寄存器的编码。
    * **FDE (Frame Description Entry):** 通过 `WriteFdeHeader()` 和其他 `Write...` 方法写入。FDE 描述了特定函数的栈帧布局，包括：
        * 函数的起始地址和大小。
        * 如何恢复寄存器（哪些寄存器被保存到栈上，保存的位置等）。
        * 如何计算栈指针的位置。
    * **`.eh_frame_hdr`：** 通过 `WriteEhFrameHdr()` 方法写入。这是一个索引表，用于快速查找与特定程序计数器 (PC) 值对应的 FDE。
* **编码方式：** `EhFrameWriter` 使用诸如 `WriteULeb128` 和 `WriteSLeb128` 的方法，将数据以 DWARF 标准中定义的  LEB128 (Little Endian Base 128)  变长编码格式写入缓冲区。
* **架构适配：** 代码中使用了 `#if !defined(...)` 预处理指令，表明对于某些不支持的架构（例如，这里列出的非 x64, ARM, ARM64, S390X, PPC64），提供了一些占位符实现，意味着在这些架构上可能不会生成完整的 `.eh_frame` 信息。

**辅助功能：读取和解析 `.eh_frame` 数据**

* **`EhFrameIterator` 类：**  用于遍历和解析已有的 `.eh_frame` 数据。它提供 `GetNextULeb128()` 和 `GetNextSLeb128()` 方法来读取 LEB128 编码的值。
* **`EhFrameDisassembler` 类 (仅在 `ENABLE_DISASSEMBLER` 定义时)：**  提供将 `.eh_frame` 数据反汇编成人类可读格式的功能，用于调试和分析。

**关于文件后缀名和 Torque:**

你说的很对，如果 `v8/src/diagnostics/eh-frame.cc` 以 `.tq` 结尾，那么它就是一个 V8 Torque 源代码文件。Torque 是一种 V8 自研的领域特定语言，用于生成高效的 C++ 代码，特别是在实现 V8 的内置函数和运行时部分。然而，**当前提供的代码片段的文件名是 `.cc`，这意味着它是标准的 C++ 源代码。**

**与 JavaScript 的关系：**

`eh-frame.cc` 的功能与 JavaScript 的异常处理机制 **间接相关**。当 JavaScript 代码调用原生 C++ 代码（例如，通过 V8 的内置函数或扩展）并且 C++ 代码抛出异常时，V8 运行时需要能够正确地处理这个异常，包括展开 C++ 的调用栈。

`.eh_frame` 数据提供了在发生 C++ 异常时如何正确回溯栈帧的信息，这使得 V8 能够安全地清理 C++ 层的资源，并将控制权传递回 JavaScript 层面进行处理（通常是 `try...catch` 块）。

**JavaScript 示例：**

```javascript
function nativeFunctionThatMightThrow() {
  // 假设这是一个调用原生 C++ 代码的函数
  try {
    _nativeBinding.someOperationThatMightThrow();
  } catch (error) {
    console.error("Caught an error from native code:", error);
  }
}

nativeFunctionThatMightThrow();
```

在这个例子中，如果 `_nativeBinding.someOperationThatMightThrow()` 对应的 C++ 代码抛出了一个异常，V8 运行时会利用 `.eh_frame` 信息来展开 C++ 的栈帧，然后将异常包装成 JavaScript 的 `error` 对象，使得 `catch` 块能够捕获并处理它。

**代码逻辑推理（假设输入与输出）：**

假设我们有一个简单的 C++ 函数 `foo`，它保存了一个寄存器 `rax` 到栈上：

```c++
// 假设的目标架构是 x64
void foo() {
  // ... 一些代码 ...
  // 在某个时刻，保存 rax 到栈上，偏移量为 -8
  // ... 更多代码 ...
}
```

**假设的 `EhFrameWriter` 调用顺序：**

```c++
EhFrameWriter writer(zone);
writer.Initialize();
writer.AdvanceLocation(0); // 函数开始
writer.SetBaseAddressRegisterAndOffset(rbp, 0); // 设置栈基址寄存器为 rbp，偏移为 0
writer.RecordRegisterSavedToStack(/* DWARF code for rax */ 0, -8); // 记录 rax 保存到栈，偏移 -8
writer.AdvanceLocation(0x10); // 执行到偏移 0x10 的位置
writer.Finish(function_size);
```

**可能的（简化的） `.eh_frame` 输出（二进制表示，需要进一步解析）：**

输出会包含 CIE 和 FDE 的数据。FDE 部分会包含类似以下的编码指令（具体的字节码会根据 LEB128 编码和 DWARF 规范而定）：

* **Location 指令：** 表示程序计数器的偏移量变化。
* **CFA (Canonical Frame Address) 指令：**  `SetBaseAddressRegisterAndOffset` 会生成对应的 CFA 指令，指示如何计算栈帧地址。
* **Register 保存指令：** `RecordRegisterSavedToStack` 会生成指令，指示 `rax` 寄存器的值被保存在相对于 CFA 的偏移量 `-8` 的位置。

**涉及用户常见的编程错误：**

在涉及到手动管理栈帧或与 C++ 异常处理交互的场景中，常见的编程错误包括：

1. **栈溢出：**  如果函数分配了过多的栈空间，可能导致栈溢出，破坏 `.eh_frame` 数据或其他重要的内存区域，使得异常处理机制失效或导致程序崩溃。

   ```c++
   void bar() {
     char buffer[1024 * 1024 * 10]; // 分配过大的栈缓冲区
     // ... 使用 buffer ...
   }
   ```

2. **栈帧不一致：**  如果手动修改了栈指针或基址指针，但 `.eh_frame` 数据没有正确反映这些修改，那么在异常发生时，栈展开可能会出错，导致程序崩溃或数据损坏。

   ```c++
   void baz() {
     __asm__("mov %rsp, %rax"); // 手动修改栈指针，不推荐
     // ...
   }
   ```

3. **与异常规范不符的交互：**  在 C++ 中，如果一个函数声明了异常规范（例如 `throw()` 或 `noexcept`），但实际抛出了未声明的异常，会导致 `std::unexpected` 或 `std::terminate` 被调用。虽然 `.eh_frame` 仍然会尝试展开栈，但这通常意味着程序出现了严重的错误。

4. **在不支持异常处理的平台上使用异常：**  在某些嵌入式系统或旧代码中，可能禁用了异常处理。在这种情况下，`.eh_frame` 数据可能不会被生成或使用，尝试抛出异常可能会导致未定义的行为。

总之，`v8/src/diagnostics/eh-frame.cc` 是 V8 引擎中负责生成关键的 `.eh_frame` 数据的组件，它对于支持 C++ 异常处理和确保 V8 运行时与原生代码的正确交互至关重要。

Prompt: 
```
这是目录为v8/src/diagnostics/eh-frame.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/diagnostics/eh-frame.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2016 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/diagnostics/eh-frame.h"

#include <iomanip>
#include <ostream>

#include "src/codegen/code-desc.h"

#if !defined(V8_TARGET_ARCH_X64) && !defined(V8_TARGET_ARCH_ARM) &&     \
    !defined(V8_TARGET_ARCH_ARM64) && !defined(V8_TARGET_ARCH_S390X) && \
    !defined(V8_TARGET_ARCH_PPC64)

// Placeholders for unsupported architectures.

namespace v8 {
namespace internal {

const int EhFrameConstants::kCodeAlignmentFactor = 1;
const int EhFrameConstants::kDataAlignmentFactor = 1;

void EhFrameWriter::WriteReturnAddressRegisterCode() { UNIMPLEMENTED(); }

void EhFrameWriter::WriteInitialStateInCie() { UNIMPLEMENTED(); }

int EhFrameWriter::RegisterToDwarfCode(Register) {
  UNIMPLEMENTED();
}

#ifdef ENABLE_DISASSEMBLER

const char* EhFrameDisassembler::DwarfRegisterCodeToString(int) {
  UNIMPLEMENTED();
}

#endif

}  // namespace internal
}  // namespace v8

#endif

namespace v8 {
namespace internal {

STATIC_CONST_MEMBER_DEFINITION const int
    EhFrameConstants::kEhFrameTerminatorSize;
STATIC_CONST_MEMBER_DEFINITION const int EhFrameConstants::kEhFrameHdrVersion;
STATIC_CONST_MEMBER_DEFINITION const int EhFrameConstants::kEhFrameHdrSize;

STATIC_CONST_MEMBER_DEFINITION const uint32_t EhFrameWriter::kInt32Placeholder;

// static
void EhFrameWriter::WriteEmptyEhFrame(std::ostream& stream) {
  stream.put(EhFrameConstants::kEhFrameHdrVersion);

  // .eh_frame pointer encoding specifier.
  stream.put(EhFrameConstants::kSData4 | EhFrameConstants::kPcRel);

  // Lookup table size encoding.
  stream.put(EhFrameConstants::kUData4);

  // Lookup table entries encoding.
  stream.put(EhFrameConstants::kSData4 | EhFrameConstants::kDataRel);

  // Dummy pointers and 0 entries in the lookup table.
  char dummy_data[EhFrameConstants::kEhFrameHdrSize - 4] = {0};
  stream.write(&dummy_data[0], sizeof(dummy_data));
}

EhFrameWriter::EhFrameWriter(Zone* zone)
    : cie_size_(0),
      last_pc_offset_(0),
      writer_state_(InternalState::kUndefined),
      base_register_(no_reg),
      base_offset_(0),
      eh_frame_buffer_(zone) {}

void EhFrameWriter::Initialize() {
  DCHECK_EQ(writer_state_, InternalState::kUndefined);
  eh_frame_buffer_.reserve(128);
  writer_state_ = InternalState::kInitialized;
  WriteCie();
  WriteFdeHeader();
}

void EhFrameWriter::WriteCie() {
  static const int kCIEIdentifier = 0;
  static const int kCIEVersion = 3;
  static const int kAugmentationDataSize = 2;
  static const uint8_t kAugmentationString[] = {'z', 'L', 'R', 0};

  // Placeholder for the size of the CIE.
  int size_offset = eh_frame_offset();
  WriteInt32(kInt32Placeholder);

  // CIE identifier and version.
  int record_start_offset = eh_frame_offset();
  WriteInt32(kCIEIdentifier);
  WriteByte(kCIEVersion);

  // Augmentation data contents descriptor: LSDA and FDE encoding.
  WriteBytes(&kAugmentationString[0], sizeof(kAugmentationString));

  // Alignment factors.
  WriteSLeb128(EhFrameConstants::kCodeAlignmentFactor);
  WriteSLeb128(EhFrameConstants::kDataAlignmentFactor);

  WriteReturnAddressRegisterCode();

  // Augmentation data.
  WriteULeb128(kAugmentationDataSize);
  // No language-specific data area (LSDA).
  WriteByte(EhFrameConstants::kOmit);
  // FDE pointers encoding.
  WriteByte(EhFrameConstants::kSData4 | EhFrameConstants::kPcRel);

  // Write directives to build the initial state of the unwinding table.
  DCHECK_EQ(eh_frame_offset() - size_offset,
            EhFrameConstants::kInitialStateOffsetInCie);
  WriteInitialStateInCie();

  WritePaddingToAlignedSize(eh_frame_offset() - record_start_offset);

  int record_end_offset = eh_frame_offset();
  int encoded_cie_size = record_end_offset - record_start_offset;
  cie_size_ = record_end_offset - size_offset;

  // Patch the size of the CIE now that we know it.
  PatchInt32(size_offset, encoded_cie_size);
}

void EhFrameWriter::WriteFdeHeader() {
  DCHECK_NE(cie_size_, 0);

  // Placeholder for size of the FDE. Will be filled in Finish().
  DCHECK_EQ(eh_frame_offset(), fde_offset());
  WriteInt32(kInt32Placeholder);

  // Backwards offset to the CIE.
  WriteInt32(cie_size_ + kInt32Size);

  // Placeholder for pointer to procedure. Will be filled in Finish().
  DCHECK_EQ(eh_frame_offset(), GetProcedureAddressOffset());
  WriteInt32(kInt32Placeholder);

  // Placeholder for size of the procedure. Will be filled in Finish().
  DCHECK_EQ(eh_frame_offset(), GetProcedureSizeOffset());
  WriteInt32(kInt32Placeholder);

  // No augmentation data.
  WriteByte(0);
}

void EhFrameWriter::WriteEhFrameHdr(int code_size) {
  DCHECK_EQ(writer_state_, InternalState::kInitialized);

  //
  // In order to calculate offsets in the .eh_frame_hdr, we must know the layout
  // of the DSO generated by perf inject, which is assumed to be the following:
  //
  //  |      ...      |                        |
  //  +---------------+ <-- (F) ---            |  Larger offsets in file
  //  |               |           ^            |
  //  |  Instructions |           | .text      v
  //  |               |           v
  //  +---------------+ <-- (E) ---
  //  |///////////////|
  //  |////Padding////|
  //  |///////////////|
  //  +---------------+ <-- (D) ---
  //  |               |           ^
  //  |      CIE      |           |
  //  |               |           |
  //  +---------------+ <-- (C)   |
  //  |               |           | .eh_frame
  //  |      FDE      |           |
  //  |               |           |
  //  +---------------+           |
  //  |   terminator  |           v
  //  +---------------+ <-- (B) ---
  //  |    version    |           ^
  //  +---------------+           |
  //  |   encoding    |           |
  //  |  specifiers   |           |
  //  +---------------+ <---(A)   | .eh_frame_hdr
  //  |   offset to   |           |
  //  |   .eh_frame   |           |
  //  +---------------+           |
  //  |      ...      |          ...
  //
  // (F) is aligned to a 16-byte boundary.
  // (D) is aligned to a  8-byte boundary.
  // (B) is aligned to a  4-byte boundary.
  // (C), (E) and (A) have no alignment requirements.
  //
  // The distance between (A) and (B) is 4 bytes.
  //
  // The size of the FDE is required to be a multiple of the pointer size, which
  // means that (B) will be naturally aligned to a 4-byte boundary on all the
  // architectures we support.
  //
  // Because (E) has no alignment requirements, there is padding between (E) and
  // (D). (F) is aligned at a 16-byte boundary, thus to a 8-byte one as well.
  //

  int eh_frame_size = eh_frame_offset();

  WriteByte(EhFrameConstants::kEhFrameHdrVersion);

  // .eh_frame pointer encoding specifier.
  WriteByte(EhFrameConstants::kSData4 | EhFrameConstants::kPcRel);
  // Lookup table size encoding specifier.
  WriteByte(EhFrameConstants::kUData4);
  // Lookup table entries encoding specifier.
  WriteByte(EhFrameConstants::kSData4 | EhFrameConstants::kDataRel);

  // Pointer to .eh_frame, relative to this offset (A -> D in the diagram).
  WriteInt32(-(eh_frame_size + EhFrameConstants::kFdeVersionSize +
               EhFrameConstants::kFdeEncodingSpecifiersSize));

  // Number of entries in the LUT, one for the only routine.
  WriteInt32(1);

  // Pointer to the start of the routine, relative to the beginning of the
  // .eh_frame_hdr (B -> F in the diagram).
  WriteInt32(-(RoundUp(code_size, 8) + eh_frame_size));

  // Pointer to the start of the associated FDE, relative to the start of the
  // .eh_frame_hdr (B -> C  in the diagram).
  WriteInt32(-(eh_frame_size - cie_size_));

  DCHECK_EQ(eh_frame_offset() - eh_frame_size,
            EhFrameConstants::kEhFrameHdrSize);
}

void EhFrameWriter::WritePaddingToAlignedSize(int unpadded_size) {
  DCHECK_EQ(writer_state_, InternalState::kInitialized);
  DCHECK_GE(unpadded_size, 0);

  int padding_size = RoundUp(unpadded_size, kSystemPointerSize) - unpadded_size;

  uint8_t nop = static_cast<uint8_t>(EhFrameConstants::DwarfOpcodes::kNop);
  static const uint8_t kPadding[] = {nop, nop, nop, nop, nop, nop, nop, nop};
  DCHECK_LE(padding_size, static_cast<int>(sizeof(kPadding)));
  WriteBytes(&kPadding[0], padding_size);
}

void EhFrameWriter::AdvanceLocation(int pc_offset) {
  DCHECK_EQ(writer_state_, InternalState::kInitialized);
  DCHECK_GE(pc_offset, last_pc_offset_);
  uint32_t delta = pc_offset - last_pc_offset_;

  DCHECK_EQ(delta % EhFrameConstants::kCodeAlignmentFactor, 0u);
  uint32_t factored_delta = delta / EhFrameConstants::kCodeAlignmentFactor;

  if (factored_delta <= EhFrameConstants::kLocationMask) {
    WriteByte((EhFrameConstants::kLocationTag
               << EhFrameConstants::kLocationMaskSize) |
              (factored_delta & EhFrameConstants::kLocationMask));
  } else if (factored_delta <= kMaxUInt8) {
    WriteOpcode(EhFrameConstants::DwarfOpcodes::kAdvanceLoc1);
    WriteByte(factored_delta);
  } else if (factored_delta <= kMaxUInt16) {
    WriteOpcode(EhFrameConstants::DwarfOpcodes::kAdvanceLoc2);
    WriteInt16(factored_delta);
  } else {
    WriteOpcode(EhFrameConstants::DwarfOpcodes::kAdvanceLoc4);
    WriteInt32(factored_delta);
  }

  last_pc_offset_ = pc_offset;
}

void EhFrameWriter::SetBaseAddressOffset(int base_offset) {
  DCHECK_EQ(writer_state_, InternalState::kInitialized);
  DCHECK_GE(base_offset, 0);
  WriteOpcode(EhFrameConstants::DwarfOpcodes::kDefCfaOffset);
  WriteULeb128(base_offset);
  base_offset_ = base_offset;
}

void EhFrameWriter::SetBaseAddressRegister(Register base_register) {
  DCHECK_EQ(writer_state_, InternalState::kInitialized);
  int code = RegisterToDwarfCode(base_register);
  WriteOpcode(EhFrameConstants::DwarfOpcodes::kDefCfaRegister);
  WriteULeb128(code);
  base_register_ = base_register;
}

void EhFrameWriter::SetBaseAddressRegisterAndOffset(Register base_register,
                                                    int base_offset) {
  DCHECK_EQ(writer_state_, InternalState::kInitialized);
  DCHECK_GE(base_offset, 0);
  int code = RegisterToDwarfCode(base_register);
  WriteOpcode(EhFrameConstants::DwarfOpcodes::kDefCfa);
  WriteULeb128(code);
  WriteULeb128(base_offset);
  base_offset_ = base_offset;
  base_register_ = base_register;
}

void EhFrameWriter::RecordRegisterSavedToStack(int dwarf_register_code,
                                               int offset) {
  DCHECK_EQ(writer_state_, InternalState::kInitialized);
  DCHECK_EQ(offset % EhFrameConstants::kDataAlignmentFactor, 0);
  int factored_offset = offset / EhFrameConstants::kDataAlignmentFactor;
  if (factored_offset >= 0) {
    DCHECK_LE(dwarf_register_code, EhFrameConstants::kSavedRegisterMask);
    WriteByte((EhFrameConstants::kSavedRegisterTag
               << EhFrameConstants::kSavedRegisterMaskSize) |
              (dwarf_register_code & EhFrameConstants::kSavedRegisterMask));
    WriteULeb128(factored_offset);
  } else {
    WriteOpcode(EhFrameConstants::DwarfOpcodes::kOffsetExtendedSf);
    WriteULeb128(dwarf_register_code);
    WriteSLeb128(factored_offset);
  }
}

void EhFrameWriter::RecordRegisterNotModified(Register name) {
  RecordRegisterNotModified(RegisterToDwarfCode(name));
}

void EhFrameWriter::RecordRegisterNotModified(int dwarf_register_code) {
  DCHECK_EQ(writer_state_, InternalState::kInitialized);
  WriteOpcode(EhFrameConstants::DwarfOpcodes::kSameValue);
  WriteULeb128(dwarf_register_code);
}

void EhFrameWriter::RecordRegisterFollowsInitialRule(Register name) {
  RecordRegisterFollowsInitialRule(RegisterToDwarfCode(name));
}

void EhFrameWriter::RecordRegisterFollowsInitialRule(int dwarf_register_code) {
  DCHECK_EQ(writer_state_, InternalState::kInitialized);
  if (dwarf_register_code <= EhFrameConstants::kFollowInitialRuleMask) {
    WriteByte((EhFrameConstants::kFollowInitialRuleTag
               << EhFrameConstants::kFollowInitialRuleMaskSize) |
              (dwarf_register_code & EhFrameConstants::kFollowInitialRuleMask));
  } else {
    WriteOpcode(EhFrameConstants::DwarfOpcodes::kRestoreExtended);
    WriteULeb128(dwarf_register_code);
  }
}

void EhFrameWriter::Finish(int code_size) {
  DCHECK_EQ(writer_state_, InternalState::kInitialized);
  DCHECK_GE(eh_frame_offset(), cie_size_);

  DCHECK_GE(eh_frame_offset(), fde_offset() + kInt32Size);
  WritePaddingToAlignedSize(eh_frame_offset() - fde_offset() - kInt32Size);

  // Write the size of the FDE now that we know it.
  // The encoded size does not include the size field itself.
  int encoded_fde_size = eh_frame_offset() - fde_offset() - kInt32Size;
  PatchInt32(fde_offset(), encoded_fde_size);

  // Write size and offset to procedure.
  PatchInt32(GetProcedureAddressOffset(),
             -(RoundUp(code_size, 8) + GetProcedureAddressOffset()));
  PatchInt32(GetProcedureSizeOffset(), code_size);

  // Terminate the .eh_frame.
  static const uint8_t kTerminator[EhFrameConstants::kEhFrameTerminatorSize] = {
      0};
  WriteBytes(&kTerminator[0], EhFrameConstants::kEhFrameTerminatorSize);

  WriteEhFrameHdr(code_size);

  writer_state_ = InternalState::kFinalized;
}

void EhFrameWriter::GetEhFrame(CodeDesc* desc) {
  DCHECK_EQ(writer_state_, InternalState::kFinalized);
  desc->unwinding_info_size = static_cast<int>(eh_frame_buffer_.size());
  desc->unwinding_info = eh_frame_buffer_.data();
}

void EhFrameWriter::WriteULeb128(uint32_t value) {
  do {
    uint8_t chunk = value & 0x7F;
    value >>= 7;
    if (value != 0) chunk |= 0x80;
    WriteByte(chunk);
  } while (value != 0);
}

void EhFrameWriter::WriteSLeb128(int32_t value) {
  static const int kSignBitMask = 0x40;
  bool done;
  do {
    uint8_t chunk = value & 0x7F;
    value >>= 7;
    done = ((value == 0) && ((chunk & kSignBitMask) == 0)) ||
           ((value == -1) && ((chunk & kSignBitMask) != 0));
    if (!done) chunk |= 0x80;
    WriteByte(chunk);
  } while (!done);
}

uint32_t EhFrameIterator::GetNextULeb128() {
  int size = 0;
  uint32_t result = DecodeULeb128(next_, &size);
  DCHECK_LE(next_ + size, end_);
  next_ += size;
  return result;
}

int32_t EhFrameIterator::GetNextSLeb128() {
  int size = 0;
  int32_t result = DecodeSLeb128(next_, &size);
  DCHECK_LE(next_ + size, end_);
  next_ += size;
  return result;
}

// static
uint32_t EhFrameIterator::DecodeULeb128(const uint8_t* encoded,
                                        int* encoded_size) {
  const uint8_t* current = encoded;
  uint32_t result = 0;
  int shift = 0;

  do {
    DCHECK_LT(shift, 8 * static_cast<int>(sizeof(result)));
    result |= (*current & 0x7F) << shift;
    shift += 7;
  } while (*current++ >= 128);

  DCHECK_NOT_NULL(encoded_size);
  *encoded_size = static_cast<int>(current - encoded);

  return result;
}

// static
int32_t EhFrameIterator::DecodeSLeb128(const uint8_t* encoded,
                                       int* encoded_size) {
  static const uint8_t kSignBitMask = 0x40;

  const uint8_t* current = encoded;
  int32_t result = 0;
  int shift = 0;
  uint8_t chunk;

  do {
    chunk = *current++;
    DCHECK_LT(shift, 8 * static_cast<int>(sizeof(result)));
    result |= (chunk & 0x7F) << shift;
    shift += 7;
  } while (chunk >= 128);

  // Sign extend the result if the last chunk has the sign bit set.
  if (chunk & kSignBitMask) result |= (~0ull) << shift;

  DCHECK_NOT_NULL(encoded_size);
  *encoded_size = static_cast<int>(current - encoded);

  return result;
}

#ifdef ENABLE_DISASSEMBLER

namespace {

class V8_NODISCARD StreamModifiersScope final {
 public:
  explicit StreamModifiersScope(std::ostream* stream)
      : stream_(stream), flags_(stream->flags()) {}
  ~StreamModifiersScope() { stream_->flags(flags_); }

 private:
  std::ostream* stream_;
  std::ios::fmtflags flags_;
};

}  // namespace

// static
void EhFrameDisassembler::DumpDwarfDirectives(std::ostream& stream,
                                              const uint8_t* start,
                                              const uint8_t* end) {
  StreamModifiersScope modifiers_scope(&stream);

  EhFrameIterator eh_frame_iterator(start, end);
  uint32_t offset_in_procedure = 0;

  while (!eh_frame_iterator.Done()) {
    stream << eh_frame_iterator.current_address() << "  ";

    uint8_t bytecode = eh_frame_iterator.GetNextByte();

    if (((bytecode >> EhFrameConstants::kLocationMaskSize) & 0xFF) ==
        EhFrameConstants::kLocationTag) {
      int value = (bytecode & EhFrameConstants::kLocationMask) *
                  EhFrameConstants::kCodeAlignmentFactor;
      offset_in_procedure += value;
      stream << "| pc_offset=" << offset_in_procedure << " (delta=" << value
             << ")\n";
      continue;
    }

    if (((bytecode >> EhFrameConstants::kSavedRegisterMaskSize) & 0xFF) ==
        EhFrameConstants::kSavedRegisterTag) {
      int32_t decoded_offset = eh_frame_iterator.GetNextULeb128();
      stream << "| "
             << DwarfRegisterCodeToString(bytecode &
                                          EhFrameConstants::kLocationMask)
             << " saved at base" << std::showpos
             << decoded_offset * EhFrameConstants::kDataAlignmentFactor
             << std::noshowpos << '\n';
      continue;
    }

    if (((bytecode >> EhFrameConstants::kFollowInitialRuleMaskSize) & 0xFF) ==
        EhFrameConstants::kFollowInitialRuleTag) {
      stream << "| "
             << DwarfRegisterCodeToString(bytecode &
                                          EhFrameConstants::kLocationMask)
             << " follows rule in CIE\n";
      continue;
    }

    switch (static_cast<EhFrameConstants::DwarfOpcodes>(bytecode)) {
      case EhFrameConstants::DwarfOpcodes::kOffsetExtendedSf: {
        stream << "| "
               << DwarfRegisterCodeToString(eh_frame_iterator.GetNextULeb128());
        int32_t decoded_offset = eh_frame_iterator.GetNextSLeb128();
        stream << " saved at base" << std::showpos
               << decoded_offset * EhFrameConstants::kDataAlignmentFactor
               << std::noshowpos << '\n';
        break;
      }
      case EhFrameConstants::DwarfOpcodes::kAdvanceLoc1: {
        int value = eh_frame_iterator.GetNextByte() *
                    EhFrameConstants::kCodeAlignmentFactor;
        offset_in_procedure += value;
        stream << "| pc_offset=" << offset_in_procedure << " (delta=" << value
               << ")\n";
        break;
      }
      case EhFrameConstants::DwarfOpcodes::kAdvanceLoc2: {
        int value = eh_frame_iterator.GetNextUInt16() *
                    EhFrameConstants::kCodeAlignmentFactor;
        offset_in_procedure += value;
        stream << "| pc_offset=" << offset_in_procedure << " (delta=" << value
               << ")\n";
        break;
      }
      case EhFrameConstants::DwarfOpcodes::kAdvanceLoc4: {
        int value = eh_frame_iterator.GetNextUInt32() *
                    EhFrameConstants::kCodeAlignmentFactor;
        offset_in_procedure += value;
        stream << "| pc_offset=" << offset_in_procedure << " (delta=" << value
               << ")\n";
        break;
      }
      case EhFrameConstants::DwarfOpcodes::kDefCfa: {
        uint32_t base_register = eh_frame_iterator.GetNextULeb128();
        uint32_t base_offset = eh_frame_iterator.GetNextULeb128();
        stream << "| base_register=" << DwarfRegisterCodeToString(base_register)
               << ", base_offset=" << base_offset << '\n';
        break;
      }
      case EhFrameConstants::DwarfOpcodes::kDefCfaOffset: {
        stream << "| base_offset=" << eh_frame_iterator.GetNextULeb128()
               << '\n';
        break;
      }
      case EhFrameConstants::DwarfOpcodes::kDefCfaRegister: {
        stream << "| base_register="
               << DwarfRegisterCodeToString(eh_frame_iterator.GetNextULeb128())
               << '\n';
        break;
      }
      case EhFrameConstants::DwarfOpcodes::kSameValue: {
        stream << "| "
               << DwarfRegisterCodeToString(eh_frame_iterator.GetNextULeb128())
               << " not modified from previous frame\n";
        break;
      }
      case EhFrameConstants::DwarfOpcodes::kNop:
        stream << "| nop\n";
        break;
      default:
        UNREACHABLE();
    }
  }
}

void EhFrameDisassembler::DisassembleToStream(std::ostream& stream) {
  // The encoded CIE size does not include the size field itself.
  const int cie_size =
      base::ReadUnalignedValue<uint32_t>(reinterpret_cast<Address>(start_)) +
      kInt32Size;
  const int fde_offset = cie_size;

  const uint8_t* cie_directives_start =
      start_ + EhFrameConstants::kInitialStateOffsetInCie;
  const uint8_t* cie_directives_end = start_ + cie_size;
  DCHECK_LE(cie_directives_start, cie_directives_end);

  stream << reinterpret_cast<const void*>(start_) << "  .eh_frame: CIE\n";
  DumpDwarfDirectives(stream, cie_directives_start, cie_directives_end);

  Address procedure_offset_address =
      reinterpret_cast<Address>(start_) + fde_offset +
      EhFrameConstants::kProcedureAddressOffsetInFde;
  int32_t procedure_offset =
      base::ReadUnalignedValue<int32_t>(procedure_offset_address);

  Address procedure_size_address = reinterpret_cast<Address>(start_) +
                                   fde_offset +
                                   EhFrameConstants::kProcedureSizeOffsetInFde;
  uint32_t procedure_size =
      base::ReadUnalignedValue<uint32_t>(procedure_size_address);

  const uint8_t* fde_start = start_ + fde_offset;
  stream << reinterpret_cast<const void*>(fde_start) << "  .eh_frame: FDE\n"
         << reinterpret_cast<const void*>(procedure_offset_address)
         << "  | procedure_offset=" << procedure_offset << '\n'
         << reinterpret_cast<const void*>(procedure_size_address)
         << "  | procedure_size=" << procedure_size << '\n';

  const int fde_directives_offset = fde_offset + 4 * kInt32Size + 1;

  const uint8_t* fde_directives_start = start_ + fde_directives_offset;
  const uint8_t* fde_directives_end = end_ - EhFrameConstants::kEhFrameHdrSize -
                                      EhFrameConstants::kEhFrameTerminatorSize;
  DCHECK_LE(fde_directives_start, fde_directives_end);

  DumpDwarfDirectives(stream, fde_directives_start, fde_directives_end);

  const uint8_t* fde_terminator_start = fde_directives_end;
  stream << reinterpret_cast<const void*>(fde_terminator_start)
         << "  .eh_frame: terminator\n";

  const uint8_t* eh_frame_hdr_start =
      fde_terminator_start + EhFrameConstants::kEhFrameTerminatorSize;
  stream << reinterpret_cast<const void*>(eh_frame_hdr_start)
         << "  .eh_frame_hdr\n";
}

#endif

}  // namespace internal
}  // namespace v8

"""

```