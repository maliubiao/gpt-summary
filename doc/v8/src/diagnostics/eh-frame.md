Response: Let's break down the thought process for analyzing this C++ code and relating it to JavaScript.

1. **Understand the Goal:** The request asks for the functionality of `eh-frame.cc` and its relationship to JavaScript. This means identifying what the code *does* and how that relates to the *behavior* of JavaScript.

2. **Initial Scan and Keywords:** Quickly scan the code for key terms. "eh_frame", "CIE", "FDE", "Dwarf", "unwinding", "stack", "registers", "pc_offset", "CodeDesc". These immediately point towards debugging and exception handling.

3. **Focus on the Core Concepts:** The terms CIE (Common Information Entry) and FDE (Frame Description Entry) are crucial. They're part of the DWARF debugging format, specifically for exception handling. The code seems to be *writing* this information.

4. **Identify the "Why":**  Why would V8 need to write EH-frame information?  Exception handling in native code requires a way to unwind the stack and find appropriate catch blocks. This information is platform-specific and needs to be generated.

5. **Connect to JavaScript:**  How does this low-level C++ relate to JavaScript? JavaScript has `try...catch` blocks for handling exceptions. When a JavaScript exception occurs, the V8 engine needs to unwind the call stack to find the nearest `catch`. *This is the direct link.* The EH-frame data generated by this code is used by the operating system or a debugger to perform this unwinding process, even for code that's been JIT-compiled.

6. **Look for Key Functions:** Analyze the major functions:
    * `EhFrameWriter::WriteCie()` and `WriteFdeHeader()`: These are responsible for structuring the DWARF information.
    * `EhFrameWriter::AdvanceLocation()`, `SetBaseAddressOffset()`, `RecordRegisterSavedToStack()`: These functions write the specific rules for how to unwind the stack at different points in the generated code. They record how registers are saved and where the stack pointer is.
    * `EhFrameWriter::Finish()`:  Finalizes the EH-frame data.
    * `EhFrameWriter::GetEhFrame()`: Makes the generated data available.
    * `EhFrameIterator`: This is for *reading* or parsing existing EH-frame data, likely for debugging purposes.
    * `EhFrameDisassembler`: For human-readable output of the EH-frame information.

7. **Architectural Considerations:** Notice the `#if !defined(...)` block. This indicates that the code is platform-specific. The core logic for generating EH-frames is only implemented for certain architectures (x64, ARM, ARM64, S390X, PPC64). For other platforms, it provides placeholder implementations. This reinforces the idea that EH-frames are an OS/platform-level concept.

8. **Illustrative JavaScript Example:**  The request specifically asks for a JavaScript example. A simple `try...catch` block demonstrates the functionality that relies on the EH-frame data. When an error is thrown within the `try` block, the engine uses the EH-frame information to find the `catch` block and execute its code.

9. **Refine the Explanation:**  Organize the findings into a clear explanation:
    * Start with the core purpose: generating EH-frame data.
    * Explain what EH-frame data is for: stack unwinding and exception handling.
    * Connect it to JavaScript's `try...catch`.
    * Mention the key components and their roles (CIE, FDE, the different `Write` functions).
    * Explain the purpose of the `EhFrameIterator` and `EhFrameDisassembler`.
    * Emphasize the platform-specific nature.

10. **Review and Improve:** Read through the explanation to ensure it's accurate, concise, and easy to understand. Check if the JavaScript example clearly illustrates the connection. For example, initially, I might have just said "exception handling," but specifying "stack unwinding" provides more technical detail directly related to the EH-frame's purpose. Also, explicitly mentioning that this is needed even for *JIT-compiled* code is an important detail.
这个C++源代码文件 `eh-frame.cc` 的主要功能是**生成用于支持 C++ 异常处理的 `.eh_frame` 数据**。`.eh_frame` 是一种标准化的数据格式，用于描述如何在程序执行过程中进行栈回溯（stack unwinding），这对于异常处理和调试至关重要。

更具体地说，这个文件中的 `EhFrameWriter` 类负责构建 `.eh_frame` 节（section）的内容。这个节包含了 Call Frame Information (CFI)，它描述了在程序的不同执行点上，如何恢复调用者的状态，例如恢复寄存器值和栈指针。

以下是该文件功能的更详细归纳：

1. **生成 Common Information Entry (CIE):**  CIE 包含了关于如何解释 Frame Description Entry (FDE) 的通用信息，例如代码和数据的对齐方式，返回地址寄存器等。`EhFrameWriter::WriteCie()` 方法负责生成 CIE。

2. **生成 Frame Description Entry (FDE):** FDE 描述了特定代码区域（通常是一个函数）的栈帧布局和寄存器保存信息。当异常发生时，异常处理机制会查找与当前程序计数器（PC）相关的 FDE，以确定如何安全地回溯栈。`EhFrameWriter` 类中的方法，如 `WriteFdeHeader()`, `AdvanceLocation()`, `SetBaseAddressOffset()`, `RecordRegisterSavedToStack()` 等，用于构建 FDE 的内容。

3. **记录栈帧变化信息:**  通过 `AdvanceLocation()` 记录程序计数器的变化，通过 `SetBaseAddressOffset()` 和 `SetBaseAddressRegister()` 设置栈基址信息，并通过 `RecordRegisterSavedToStack()` 记录哪些寄存器被保存到了栈上以及它们的位置。这些信息是栈回溯的关键。

4. **生成 `.eh_frame_hdr`:**  `.eh_frame_hdr` 是一个可选的头，用于加速查找与给定程序计数器相关的 FDE。`EhFrameWriter::WriteEhFrameHdr()` 方法负责生成这个头。

5. **处理不支持的架构:**  文件中有一个 `#if` 块，针对一些不支持生成 `.eh_frame` 的架构提供了占位符实现。这意味着在这些架构上，V8 可能依赖其他的异常处理机制或者不提供完整的异常处理调试信息。

6. **提供迭代器和反汇编器:** `EhFrameIterator` 类用于解析已有的 `.eh_frame` 数据，而 `EhFrameDisassembler` 类则可以将 `.eh_frame` 的内容以更易读的方式输出，这对于调试和理解生成的 `.eh_frame` 数据很有帮助。

**与 JavaScript 功能的关系：**

虽然 `eh-frame.cc` 是 C++ 代码，但它直接支持了 V8 (用于执行 JavaScript 的引擎) 的异常处理能力。当 JavaScript 代码中发生错误（例如 `TypeError`, `ReferenceError`）时，V8 引擎需要能够安全地回溯调用栈，找到合适的错误处理代码（例如 `try...catch` 块）。

`.eh_frame` 数据提供了必要的信息，使得操作系统或调试器能够理解 V8 生成的机器码的栈帧结构。这使得以下功能成为可能：

* **JavaScript 的 `try...catch` 机制:** 当 JavaScript 代码抛出异常时，V8 引擎需要使用栈回溯来找到对应的 `catch` 块。`.eh_frame` 数据确保了这个过程能够正确进行。
* **调试器支持:** 调试器（如 Chrome DevTools）在调试 JavaScript 代码时，需要能够正确地显示调用栈信息。这依赖于 `.eh_frame` 数据提供的信息。
* **错误报告:** 当未捕获的 JavaScript 异常发生时，V8 引擎可以使用栈回溯信息来生成更详细的错误报告。

**JavaScript 示例：**

```javascript
function foo() {
  bar();
}

function bar() {
  throw new Error("Something went wrong!");
}

function main() {
  try {
    foo();
  } catch (e) {
    console.error("Caught an error:", e);
    // 在这里，V8 引擎使用了栈回溯来找到这个 catch 块
  }
}

main();
```

在这个例子中，当 `bar()` 函数抛出错误时，JavaScript 引擎（由 V8 实现）会执行以下步骤：

1. 错误被抛出，开始查找能够处理该错误的 `catch` 块。
2. V8 引擎会进行栈回溯，从 `bar()` 的调用点回溯到 `foo()` 的调用点，再到 `main()` 函数内的 `try` 块。
3. `.eh_frame` 数据提供了关于如何在机器码层面进行栈回溯的信息，例如每个函数的栈帧布局、寄存器保存情况等。
4. 最终，引擎找到 `main()` 函数的 `catch` 块，并执行其中的代码。

总结来说，`eh-frame.cc` 这个 C++ 文件虽然不直接包含 JavaScript 代码，但它是 V8 引擎支持 JavaScript 异常处理和调试能力的关键组成部分。它生成的 `.eh_frame` 数据使得 V8 能够与操作系统和调试器协同工作，正确地处理和报告 JavaScript 运行时错误。

### 提示词
```
这是目录为v8/src/diagnostics/eh-frame.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
```

### 源代码
```
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
```