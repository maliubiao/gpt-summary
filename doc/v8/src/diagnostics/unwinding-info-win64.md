Response: Let's break down the thought process to analyze this C++ code and connect it to JavaScript.

1. **Understand the Core Problem:** The file name `unwinding-info-win64.cc` immediately suggests it's about *stack unwinding* on Windows 64-bit systems. Stack unwinding is the process of going back up the call stack during exceptions or debugging. The key here is "info" – this file likely deals with providing information to the operating system about how to unwind the stack correctly.

2. **Identify Key Concepts:**  Skimming the code reveals important terms:
    * `UNWIND_INFO`, `UNWIND_CODE`: These are Windows structures related to unwinding.
    * `RUNTIME_FUNCTION`: Another Windows structure, likely mapping code ranges to unwinding info.
    * `RtlAddGrowableFunctionTable`, `RtlDeleteGrowableFunctionTable`, `RtlAddFunctionTable`, `RtlDeleteFunctionTable`: These are Windows API functions for registering unwinding information.
    * `EXCEPTION_RECORD`, `CONTEXT`: Structures related to exception handling.
    * `CRASH_HANDLER_FUNCTION_NAME`:  Suggests a custom handler for V8 crashes.
    * `#if defined(V8_OS_WIN_X64)` and `#elif defined(V8_OS_WIN_ARM64)`: The code is platform-specific.
    * `v8_flags`:  V8 runtime flags influencing behavior.
    * `jitless`:  A V8 flag related to disabling JIT compilation.

3. **Determine the File's Purpose:** Based on these concepts, the file's primary function is to generate and register metadata that tells the Windows operating system how to unwind the stack when an exception occurs within V8's generated code (both JIT-compiled and potentially other code). This is crucial for debugging, crash reporting, and exception handling in general.

4. **Analyze Key Functions:**
    * `CanEmitUnwindInfoForBuiltins()`:  Determines if unwinding info should be emitted for built-in V8 functions.
    * `CanRegisterUnwindInfoForNonABICompliantCodeRange()`: Checks if unwinding info can be registered for code that doesn't follow standard ABI conventions (like JIT-compiled code).
    * `RegisterUnwindInfoForExceptionHandlingOnly()`:  Decides if only minimal exception handling unwinding info should be registered. This is often for compatibility with older systems or when full unwinding isn't needed.
    * `SetUnhandledExceptionCallback()`:  Allows setting a custom callback for unhandled exceptions within V8.
    * `CRASH_HANDLER_FUNCTION_NAME`: This is the crucial crash handler. When an exception occurs in V8 code, Windows will use the registered unwinding info to find this function.
    * `RegisterNonABICompliantCodeRange()`: This is where the unwinding information is actually registered with Windows using the `RtlAdd...` functions. It handles different scenarios based on flags and OS version.
    * `UnregisterNonABICompliantCodeRange()`:  The counterpart to `RegisterNonABICompliantCodeRange()`, removing the registered information.
    * `XdataEncoder`: This seems to be a helper class for collecting information about the generated code to create the `UNWIND_INFO`. The `onPushRbp` and `onMovRbpRsp` (for x64) and `onSaveFpLr` and `onFramePointerAdjustment` (for ARM64) methods suggest it's tracking how the stack frame is set up.

5. **Connect to JavaScript (The Key Insight):** The most important connection to JavaScript is that *V8 executes JavaScript code*. V8 compiles JavaScript into machine code (JIT compilation). This machine code needs to be able to interact with the operating system, including during exceptions. If an error occurs in the *JavaScript* code, and V8's generated machine code crashes, Windows needs to know how to unwind the stack to report the error or allow debugging. This file provides that "how to unwind" information *for the machine code generated from JavaScript*.

6. **Craft the JavaScript Example:** The goal is to illustrate a scenario where this unwinding information is relevant. A simple way to do this is to cause a runtime error in JavaScript. A `TypeError` (like calling a non-function) or a `ReferenceError` (using an undefined variable) will trigger an exception in the V8 engine, potentially leading to the crash handler being invoked if something goes wrong at a lower level or if a debugger is attached. The example should show the connection – the JavaScript error triggers something that relies on the C++ code.

7. **Refine and Explain:**  After drafting the initial explanation and example, review it for clarity and accuracy. Emphasize the role of JIT compilation, the purpose of stack unwinding, and how this C++ code bridges the gap between V8's internal workings and the Windows operating system's exception handling mechanisms. Explain the significance of the `CRASH_HANDLER_FUNCTION_NAME` and how it can be used to customize error reporting or integrate with tools like Crashpad.

8. **Consider Edge Cases and Nuances:** Think about why there are different code paths (e.g., the `jitless` flag, Windows version checks). These are often related to performance optimizations, compatibility requirements, or specific features. Briefly mentioning these adds depth to the explanation.

By following these steps, you can systematically analyze the C++ code and connect it to the higher-level concepts of JavaScript execution and error handling. The key is to understand the *problem* the code is solving and how it fits into the larger V8 architecture and the operating system environment.
这个C++源代码文件 `v8/src/diagnostics/unwinding-info-win64.cc` 的主要功能是**为V8引擎在Windows 64位平台上生成的代码提供栈回溯（stack unwinding）信息**。这使得Windows操作系统能够正确地处理V8代码中发生的异常，并允许调试器和性能分析工具遍历V8的调用栈。

更具体地说，该文件负责：

1. **生成 Unwind Info 数据结构:**  定义了用于描述函数序言（prologue）和栈帧布局的结构体，例如 `UNWIND_INFO` 和 `UNWIND_CODE` (在 x64 架构下)。这些结构体包含了在异常发生时如何恢复调用者栈帧的关键信息，例如如何找到返回地址、保存的寄存器等。对于 ARM64 架构，定义了类似的结构和枚举，例如 `UnwindOp8Bit` 和 `UNWIND_INFO`。

2. **注册 Unwind Info:**  使用 Windows API 函数（如 `RtlAddGrowableFunctionTable` 和 `RtlAddFunctionTable`）将生成的 Unwind Info 数据与 V8 生成的代码地址范围关联起来。这样，当这些代码中发生异常时，Windows 操作系统可以查找到相应的 Unwind Info 并进行栈回溯。

3. **处理异常回调:** 定义了一个名为 `CRASH_HANDLER_FUNCTION_NAME` 的全局函数，这个函数被注册为 V8 代码的异常处理入口点。当 V8 生成的代码中发生未处理的异常时，Windows 会调用这个函数。该函数会将异常信息传递给用户自定义的回调函数（通过 `SetUnhandledExceptionCallback` 设置），允许 V8 的使用者捕获和处理这些异常。

4. **针对不同场景提供支持:**  根据 V8 的配置选项（例如 `v8_flags.win64_unwinding_info` 和 `v8_flags.jitless`）以及 Windows 版本，选择不同的注册 Unwind Info 的策略。例如，可以为整个代码范围注册详细的 unwind 信息，也可以仅注册用于异常处理的最小信息。

**与 JavaScript 的关系:**

V8 引擎负责执行 JavaScript 代码。为了提高性能，V8 会将 JavaScript 代码编译成机器码（通过 Just-In-Time 编译，即 JIT）。  `unwinding-info-win64.cc` 这个文件就是为了让 Windows 操作系统能够理解和处理 **V8 编译生成的这些机器码** 中发生的异常。

当 JavaScript 代码运行时发生错误（例如 `TypeError`, `ReferenceError` 等），V8 内部会进行异常处理。然而，如果 V8 自身生成的机器码出现更底层的错误，或者需要在调试器中查看调用栈，就需要依赖操作系统的栈回溯机制。

**JavaScript 示例:**

虽然这个 C++ 文件本身不包含 JavaScript 代码，但它的功能直接影响到 JavaScript 运行时的行为。 考虑以下 JavaScript 代码：

```javascript
function a() {
  b();
}

function b() {
  throw new Error("Something went wrong!");
}

try {
  a();
} catch (e) {
  console.error("Caught an error:", e.stack);
}
```

在这个例子中，当 `b()` 函数抛出错误时，JavaScript 引擎会沿着调用栈向上查找 `catch` 语句。  但是，在 V8 内部，这个过程涉及到执行由 V8 生成的机器码。

如果 V8 没有正确地注册 Unwind Info，当在调试器中暂停执行或发生更严重的错误导致程序崩溃时，操作系统可能无法正确地回溯到 `a()` 和 `b()` 函数的调用位置，导致调试信息不完整或崩溃报告不准确。

**更深层次的联系（不直接体现在 JavaScript 代码中）:**

* **调试器支持:**  像 Chrome DevTools 这样的调试器，在断点命中或程序抛出异常时，需要依赖操作系统的栈回溯功能来展示 JavaScript 的调用栈。  `unwinding-info-win64.cc` 确保了在 Windows 上，调试器能够正确地理解 V8 生成的代码的栈结构。

* **性能分析:**  性能分析工具也需要依赖栈回溯来确定代码的执行路径和热点。正确的 Unwind Info 可以帮助性能分析工具准确地分析 V8 代码的性能瓶颈。

* **错误报告:** 当 V8 应用程序崩溃时，操作系统会生成错误报告。  如果 Unwind Info 注册正确，错误报告中就能包含更详细的 V8 调用栈信息，这对于诊断和修复 bug 非常重要。

**总结:**

`v8/src/diagnostics/unwinding-info-win64.cc` 是 V8 引擎在 Windows 平台上的一个关键组成部分，它确保了操作系统能够理解 V8 生成的机器码的栈结构，从而支持异常处理、调试和性能分析等功能。虽然 JavaScript 开发者通常不需要直接与这个文件交互，但它的正确运行对于 JavaScript 代码在 Windows 上的稳定性和可调试性至关重要。

### 提示词
```
这是目录为v8/src/diagnostics/unwinding-info-win64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
```

### 源代码
```
// Copyright 2019 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/diagnostics/unwinding-info-win64.h"

#include "src/codegen/macro-assembler.h"
#include "src/utils/allocation.h"

#if defined(V8_OS_WIN_X64)
#include "src/codegen/x64/assembler-x64.h"
#elif defined(V8_OS_WIN_ARM64)
#include "src/codegen/arm64/assembler-arm64-inl.h"
#include "src/codegen/arm64/macro-assembler-arm64-inl.h"
#else
#error "Unsupported OS"
#endif  // V8_OS_WIN_X64

#include <windows.h>

// This has to come after windows.h.
#include <versionhelpers.h>  // For IsWindows8OrGreater().

namespace v8 {
namespace internal {
namespace win64_unwindinfo {

bool CanEmitUnwindInfoForBuiltins() { return v8_flags.win64_unwinding_info; }

bool CanRegisterUnwindInfoForNonABICompliantCodeRange() {
  return !v8_flags.jitless;
}

bool RegisterUnwindInfoForExceptionHandlingOnly() {
  DCHECK(CanRegisterUnwindInfoForNonABICompliantCodeRange());
#if defined(V8_OS_WIN_ARM64)
  return !v8_flags.win64_unwinding_info;
#else
  return !IsWindows8OrGreater() || !v8_flags.win64_unwinding_info;
#endif
}

v8::UnhandledExceptionCallback unhandled_exception_callback_g = nullptr;

void SetUnhandledExceptionCallback(
    v8::UnhandledExceptionCallback unhandled_exception_callback) {
  unhandled_exception_callback_g = unhandled_exception_callback;
}

// This function is registered as exception handler for V8-generated code as
// part of the registration of unwinding info. It is referenced by
// RegisterNonABICompliantCodeRange(), below, and by the unwinding info for
// builtins declared in the embedded blob.
extern "C" __declspec(dllexport) int CRASH_HANDLER_FUNCTION_NAME(
    PEXCEPTION_RECORD ExceptionRecord, ULONG64 EstablisherFrame,
    PCONTEXT ContextRecord, PDISPATCHER_CONTEXT DispatcherContext) {
  if (unhandled_exception_callback_g != nullptr) {
    EXCEPTION_POINTERS info = {ExceptionRecord, ContextRecord};
    return unhandled_exception_callback_g(&info);
  }
  return ExceptionContinueSearch;
}

#if defined(V8_OS_WIN_X64)

#pragma pack(push, 1)

/*
 * From Windows SDK ehdata.h, which does not compile with Clang.
 * See https://msdn.microsoft.com/en-us/library/ddssxxy8.aspx.
 */
union UNWIND_CODE {
  struct {
    unsigned char CodeOffset;
    unsigned char UnwindOp : 4;
    unsigned char OpInfo : 4;
  };
  uint16_t FrameOffset;
};

struct UNWIND_INFO {
  unsigned char Version : 3;
  unsigned char Flags : 5;
  unsigned char SizeOfProlog;
  unsigned char CountOfCodes;
  unsigned char FrameRegister : 4;
  unsigned char FrameOffset : 4;
};

static constexpr int kNumberOfUnwindCodes = 2;
static constexpr int kMaxExceptionThunkSize = 12;

struct V8UnwindData {
  UNWIND_INFO unwind_info;
  UNWIND_CODE unwind_codes[kNumberOfUnwindCodes];

  V8UnwindData() {
    static constexpr int kOpPushNonvol = 0;
    static constexpr int kOpSetFPReg = 3;

    unwind_info.Version = 1;
    unwind_info.Flags = UNW_FLAG_EHANDLER;
    unwind_info.SizeOfProlog = kRbpPrefixLength;
    unwind_info.CountOfCodes = kRbpPrefixCodes;
    unwind_info.FrameRegister = rbp.code();
    unwind_info.FrameOffset = 0;

    unwind_codes[0].CodeOffset = kRbpPrefixLength;  // movq rbp, rsp
    unwind_codes[0].UnwindOp = kOpSetFPReg;
    unwind_codes[0].OpInfo = 0;

    unwind_codes[1].CodeOffset = kPushRbpInstructionLength;  // push rbp
    unwind_codes[1].UnwindOp = kOpPushNonvol;
    unwind_codes[1].OpInfo = rbp.code();
  }
};

struct ExceptionHandlerUnwindData {
  UNWIND_INFO unwind_info;

  ExceptionHandlerUnwindData() {
    unwind_info.Version = 1;
    unwind_info.Flags = UNW_FLAG_EHANDLER;
    unwind_info.SizeOfProlog = 0;
    unwind_info.CountOfCodes = 0;
    unwind_info.FrameRegister = 0;
    unwind_info.FrameOffset = 0;
  }
};

struct CodeRangeUnwindingRecord {
  void* dynamic_table;
  uint32_t runtime_function_count;
  V8UnwindData unwind_info;
  uint32_t exception_handler;
  uint8_t exception_thunk[kMaxExceptionThunkSize];
  RUNTIME_FUNCTION runtime_function[kDefaultRuntimeFunctionCount];
};

struct ExceptionHandlerRecord {
  uint32_t runtime_function_count;
  RUNTIME_FUNCTION runtime_function[kDefaultRuntimeFunctionCount];
  ExceptionHandlerUnwindData unwind_info;
  uint32_t exception_handler;
  uint8_t exception_thunk[kMaxExceptionThunkSize];
};

#pragma pack(pop)

std::vector<uint8_t> GetUnwindInfoForBuiltinFunctions() {
  V8UnwindData xdata;
  return std::vector<uint8_t>(
      reinterpret_cast<uint8_t*>(&xdata),
      reinterpret_cast<uint8_t*>(&xdata) + sizeof(xdata));
}

template <typename Record>
void InitUnwindingRecord(Record* record, size_t code_size_in_bytes) {
  // We assume that the first page of the code range is executable and
  // committed and reserved to contain PDATA/XDATA.

  // All addresses are 32bit relative offsets to start.
  record->runtime_function[0].BeginAddress = 0;
  record->runtime_function[0].EndAddress =
      static_cast<DWORD>(code_size_in_bytes);
  record->runtime_function[0].UnwindData = offsetof(Record, unwind_info);
  record->runtime_function_count = 1;
  record->exception_handler = offsetof(Record, exception_thunk);

  // Hardcoded thunk.
  AccountingAllocator allocator;
  AssemblerOptions options;
  options.record_reloc_info_for_serialization = false;
  MacroAssembler masm(&allocator, options, CodeObjectRequired::kNo,
                      NewAssemblerBuffer(64));
  masm.movq(rax, reinterpret_cast<uint64_t>(&CRASH_HANDLER_FUNCTION_NAME));
  masm.jmp(rax);
  DCHECK_LE(masm.instruction_size(), sizeof(record->exception_thunk));
  memcpy(&record->exception_thunk[0], masm.buffer_start(),
         masm.instruction_size());
}

#elif defined(V8_OS_WIN_ARM64)

#pragma pack(push, 1)

// ARM64 unwind codes are defined in below doc.
// https://docs.microsoft.com/en-us/cpp/build/arm64-exception-handling#unwind-codes
enum UnwindOp8Bit {
  OpNop = 0xE3,
  OpAllocS = 0x00,
  OpSaveFpLr = 0x40,
  OpSaveFpLrX = 0x80,
  OpSetFp = 0xE1,
  OpAddFp = 0xE2,
  OpEnd = 0xE4,
};

typedef uint32_t UNWIND_CODE;

constexpr UNWIND_CODE Combine8BitUnwindCodes(uint8_t code0 = OpNop,
                                             uint8_t code1 = OpNop,
                                             uint8_t code2 = OpNop,
                                             uint8_t code3 = OpNop) {
  return static_cast<uint32_t>(code0) | (static_cast<uint32_t>(code1) << 8) |
         (static_cast<uint32_t>(code2) << 16) |
         (static_cast<uint32_t>(code3) << 24);
}

// UNWIND_INFO defines the static part (first 32-bit) of the .xdata record in
// below doc.
// https://docs.microsoft.com/en-us/cpp/build/arm64-exception-handling#xdata-records
struct UNWIND_INFO {
  uint32_t FunctionLength : 18;
  uint32_t Version : 2;
  uint32_t X : 1;
  uint32_t E : 1;
  uint32_t EpilogCount : 5;
  uint32_t CodeWords : 5;
};

static constexpr int kDefaultNumberOfUnwindCodeWords = 1;
static constexpr int kMaxExceptionThunkSize = 16;
static constexpr int kFunctionLengthShiftSize = 2;
static constexpr int kFunctionLengthMask = (1 << kFunctionLengthShiftSize) - 1;
static constexpr int kAllocStackShiftSize = 4;
static constexpr int kAllocStackShiftMask = (1 << kAllocStackShiftSize) - 1;

// Generate an unwind code for "stp fp, lr, [sp, #pre_index_offset]!".
uint8_t MakeOpSaveFpLrX(int pre_index_offset) {
  // See unwind code save_fplr_x in
  // https://docs.microsoft.com/en-us/cpp/build/arm64-exception-handling#unwind-codes
  DCHECK_LE(pre_index_offset, -8);
  DCHECK_GE(pre_index_offset, -512);
  constexpr int kShiftSize = 3;
  constexpr int kShiftMask = (1 << kShiftSize) - 1;
  DCHECK_EQ(pre_index_offset & kShiftMask, 0);
  USE(kShiftMask);
  // Solve for Z where -(Z+1)*8 = pre_index_offset.
  int encoded_value = (-pre_index_offset >> kShiftSize) - 1;
  return OpSaveFpLrX | encoded_value;
}

// Generate an unwind code for "sub sp, sp, #stack_space".
uint8_t MakeOpAllocS(int stack_space) {
  // See unwind code alloc_s in
  // https://docs.microsoft.com/en-us/cpp/build/arm64-exception-handling#unwind-codes
  DCHECK_GE(stack_space, 0);
  DCHECK_LT(stack_space, 512);
  DCHECK_EQ(stack_space & kAllocStackShiftMask, 0);
  return OpAllocS | (stack_space >> kAllocStackShiftSize);
}

// Generate the second byte of the unwind code for "add fp, sp, #offset".
uint8_t MakeOpAddFpArgument(int offset) {
  // See unwind code add_fp in
  // https://docs.microsoft.com/en-us/cpp/build/arm64-exception-handling#unwind-codes
  DCHECK_GE(offset, 0);
  constexpr int kShiftSize = 3;
  constexpr int kShiftMask = (1 << kShiftSize) - 1;
  DCHECK_EQ(offset & kShiftMask, 0);
  USE(kShiftMask);
  int encoded_value = offset >> kShiftSize;
  // Encoded value must fit in 8 bits.
  DCHECK_LE(encoded_value, 0xff);
  return encoded_value;
}

template <int kNumberOfUnwindCodeWords = kDefaultNumberOfUnwindCodeWords>
struct V8UnwindData {
  UNWIND_INFO unwind_info;
  UNWIND_CODE unwind_codes[kNumberOfUnwindCodeWords];

  V8UnwindData() {
    memset(&unwind_info, 0, sizeof(UNWIND_INFO));
    unwind_info.X = 1;  // has exception handler after unwind-codes.
    unwind_info.CodeWords = kNumberOfUnwindCodeWords;

    // Generate unwind codes for the following prolog:
    //
    // stp fp, lr, [sp, #-kCallerSPOffset]!
    // mov fp, sp
    //
    // This is a very rough approximation of the actual function prologs used in
    // V8. In particular, we often push other data before the (fp, lr) pair,
    // meaning the stack pointer computed for the caller frame is wrong. That
    // error is acceptable when the unwinding info for the caller frame also
    // depends on fp rather than sp, as is the case for V8 builtins and runtime-
    // generated code.
    static_assert(kNumberOfUnwindCodeWords >= 1);
    unwind_codes[0] = Combine8BitUnwindCodes(
        OpSetFp, MakeOpSaveFpLrX(-CommonFrameConstants::kCallerSPOffset),
        OpEnd);

    // Fill the rest with nops.
    for (int i = 1; i < kNumberOfUnwindCodeWords; ++i) {
      unwind_codes[i] = Combine8BitUnwindCodes();
    }
  }
};

struct CodeRangeUnwindingRecord {
  void* dynamic_table;
  uint32_t runtime_function_count;
  V8UnwindData<> unwind_info;
  uint32_t exception_handler;

  // For Windows ARM64 unwinding, register 2 unwind_info for each code range,
  // unwind_info for all full size ranges (1MB - 4 bytes) and unwind_info1 for
  // the remaining non full size range. There is at most 1 range which is less
  // than full size.
  V8UnwindData<> unwind_info1;
  uint32_t exception_handler1;
  uint8_t exception_thunk[kMaxExceptionThunkSize];

  // More RUNTIME_FUNCTION structs could follow below array because the number
  // of RUNTIME_FUNCTION needed to cover given code range is computed at
  // runtime.
  RUNTIME_FUNCTION runtime_function[kDefaultRuntimeFunctionCount];
};

#pragma pack(pop)

FrameOffsets::FrameOffsets()
    : fp_to_saved_caller_fp(CommonFrameConstants::kCallerFPOffset),
      fp_to_caller_sp(CommonFrameConstants::kCallerSPOffset) {}
bool FrameOffsets::IsDefault() const {
  FrameOffsets other;
  return fp_to_saved_caller_fp == other.fp_to_saved_caller_fp &&
         fp_to_caller_sp == other.fp_to_caller_sp;
}

std::vector<uint8_t> GetUnwindInfoForBuiltinFunction(
    uint32_t func_len, FrameOffsets fp_adjustment) {
  DCHECK_LE(func_len, kMaxFunctionLength);
  DCHECK_EQ((func_len & kFunctionLengthMask), 0);
  USE(kFunctionLengthMask);

  // The largest size of unwind data required for all options below.
  constexpr int kMaxNumberOfUnwindCodeWords = 2;

  V8UnwindData<kMaxNumberOfUnwindCodeWords> xdata;
  // FunctionLength is ensured to be aligned at instruction size and Windows
  // ARM64 doesn't encoding its 2 LSB.
  xdata.unwind_info.FunctionLength = func_len >> kFunctionLengthShiftSize;

  if (fp_adjustment.IsDefault()) {
    // One code word is plenty.
    static_assert(kDefaultNumberOfUnwindCodeWords <
                  kMaxNumberOfUnwindCodeWords);
    xdata.unwind_info.CodeWords = kDefaultNumberOfUnwindCodeWords;
  } else {
    // We want to convey the following facts:
    // 1. The caller's fp is found at [fp + fp_to_saved_caller_fp].
    // 2. The caller's pc is found at [fp + fp_to_saved_caller_fp + 8].
    // 3. The caller's sp is equal to fp + fp_to_caller_sp.
    //
    // An imaginary prolog that would establish those relationships might look
    // like the following, with appropriate values for the various constants:
    //
    // stp fp, lr, [sp, #pre_index_amount]!
    // sub sp, sp, #stack_space
    // add fp, sp, offset_from_stack_top
    //
    // Why do we need offset_from_stack_top? The unwinding encoding for
    // allocating stack space has 16-byte granularity, and the frame pointer has
    // only 8-byte alignment.
    int pre_index_amount =
        fp_adjustment.fp_to_saved_caller_fp - fp_adjustment.fp_to_caller_sp;
    int stack_space = fp_adjustment.fp_to_saved_caller_fp;
    int offset_from_stack_top = stack_space & kAllocStackShiftMask;
    stack_space += offset_from_stack_top;

    xdata.unwind_codes[0] = Combine8BitUnwindCodes(
        OpAddFp, MakeOpAddFpArgument(offset_from_stack_top),
        MakeOpAllocS(stack_space), MakeOpSaveFpLrX(pre_index_amount));
    xdata.unwind_codes[1] = Combine8BitUnwindCodes(OpEnd);
  }

  return std::vector<uint8_t>(
      reinterpret_cast<uint8_t*>(&xdata),
      reinterpret_cast<uint8_t*>(
          &xdata.unwind_codes[xdata.unwind_info.CodeWords]));
}

template <typename Record>
void InitUnwindingRecord(Record* record, size_t code_size_in_bytes) {
  // We assume that the first page of the code range is executable and
  // committed and reserved to contain multiple PDATA/XDATA to cover the whole
  // range. All addresses are 32bit relative offsets to start.

  // Maximum RUNTIME_FUNCTION count available in reserved memory, this includes
  // static part in Record as kDefaultRuntimeFunctionCount plus dynamic part in
  // the remaining reserved memory.
  constexpr uint32_t max_runtime_function_count = static_cast<uint32_t>(
      (kOSPageSize - sizeof(Record)) / sizeof(RUNTIME_FUNCTION) +
      kDefaultRuntimeFunctionCount);

  uint32_t runtime_function_index = 0;
  uint32_t current_unwind_start_address = 0;
  int64_t remaining_size_in_bytes = static_cast<int64_t>(code_size_in_bytes);

  // Divide the code range into chunks in size kMaxFunctionLength and create a
  // RUNTIME_FUNCTION for each of them. All the chunks in the same size can
  // share 1 unwind_info struct, but a separate unwind_info is needed for the
  // last chunk if it is smaller than kMaxFunctionLength, because unlike X64,
  // unwind_info encodes the function/chunk length.
  while (remaining_size_in_bytes >= kMaxFunctionLength &&
         runtime_function_index < max_runtime_function_count) {
    record->runtime_function[runtime_function_index].BeginAddress =
        current_unwind_start_address;
    record->runtime_function[runtime_function_index].UnwindData =
        static_cast<DWORD>(offsetof(Record, unwind_info));

    runtime_function_index++;
    current_unwind_start_address += kMaxFunctionLength;
    remaining_size_in_bytes -= kMaxFunctionLength;
  }
  // FunctionLength is ensured to be aligned at instruction size and Windows
  // ARM64 doesn't encoding 2 LSB.
  record->unwind_info.unwind_info.FunctionLength = kMaxFunctionLength >> 2;

  if (remaining_size_in_bytes > 0 &&
      runtime_function_index < max_runtime_function_count) {
    DCHECK_EQ(remaining_size_in_bytes % kInstrSize, 0);

    record->unwind_info1.unwind_info.FunctionLength = static_cast<uint32_t>(
        remaining_size_in_bytes >> kFunctionLengthShiftSize);
    record->runtime_function[runtime_function_index].BeginAddress =
        current_unwind_start_address;
    record->runtime_function[runtime_function_index].UnwindData =
        static_cast<DWORD>(offsetof(Record, unwind_info1));

    remaining_size_in_bytes -= kMaxFunctionLength;
    record->exception_handler1 = offsetof(Record, exception_thunk);
    record->runtime_function_count = runtime_function_index + 1;
  } else {
    record->runtime_function_count = runtime_function_index;
  }

  // 1 page can cover kMaximalCodeRangeSize for ARM64 (128MB). If
  // kMaximalCodeRangeSize is changed for ARM64 and makes 1 page insufficient to
  // cover it, more pages will need to reserved for unwind data.
  DCHECK_LE(remaining_size_in_bytes, 0);

  record->exception_handler = offsetof(Record, exception_thunk);

  // Hardcoded thunk.
  AccountingAllocator allocator;
  AssemblerOptions options;
  options.record_reloc_info_for_serialization = false;
  MacroAssembler masm(&allocator, options, CodeObjectRequired::kNo,
                      NewAssemblerBuffer(64));
  masm.Mov(x16,
           Operand(reinterpret_cast<uint64_t>(&CRASH_HANDLER_FUNCTION_NAME)));
  masm.Br(x16);
  DCHECK_LE(masm.instruction_size(), sizeof(record->exception_thunk));
  memcpy(&record->exception_thunk[0], masm.buffer_start(),
         masm.instruction_size());
}

#endif  // V8_OS_WIN_X64

namespace {

V8_DECLARE_ONCE(load_ntdll_unwinding_functions_once);
static decltype(
    &::RtlAddGrowableFunctionTable) add_growable_function_table_func = nullptr;
static decltype(
    &::RtlDeleteGrowableFunctionTable) delete_growable_function_table_func =
    nullptr;

void LoadNtdllUnwindingFunctionsOnce() {
  // Load functions from the ntdll.dll module.
  HMODULE ntdll_module =
      LoadLibraryEx(L"ntdll.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
  DCHECK_NOT_NULL(ntdll_module);

  // This fails on Windows 7.
  add_growable_function_table_func =
      reinterpret_cast<decltype(&::RtlAddGrowableFunctionTable)>(
          ::GetProcAddress(ntdll_module, "RtlAddGrowableFunctionTable"));
  DCHECK_IMPLIES(IsWindows8OrGreater(), add_growable_function_table_func);

  delete_growable_function_table_func =
      reinterpret_cast<decltype(&::RtlDeleteGrowableFunctionTable)>(
          ::GetProcAddress(ntdll_module, "RtlDeleteGrowableFunctionTable"));
  DCHECK_IMPLIES(IsWindows8OrGreater(), delete_growable_function_table_func);
}

void LoadNtdllUnwindingFunctions() {
  base::CallOnce(&load_ntdll_unwinding_functions_once,
                 &LoadNtdllUnwindingFunctionsOnce);
}

bool AddGrowableFunctionTable(PVOID* DynamicTable,
                              PRUNTIME_FUNCTION FunctionTable, DWORD EntryCount,
                              DWORD MaximumEntryCount, ULONG_PTR RangeBase,
                              ULONG_PTR RangeEnd) {
  DCHECK(::IsWindows8OrGreater());

  LoadNtdllUnwindingFunctions();
  DCHECK_NOT_NULL(add_growable_function_table_func);

  *DynamicTable = nullptr;
  DWORD status =
      add_growable_function_table_func(DynamicTable, FunctionTable, EntryCount,
                                       MaximumEntryCount, RangeBase, RangeEnd);
  DCHECK((status == 0 && *DynamicTable != nullptr) ||
         status == 0xC000009A);  // STATUS_INSUFFICIENT_RESOURCES
  return (status == 0);
}

void DeleteGrowableFunctionTable(PVOID dynamic_table) {
  DCHECK(::IsWindows8OrGreater());

  LoadNtdllUnwindingFunctions();
  DCHECK_NOT_NULL(delete_growable_function_table_func);

  delete_growable_function_table_func(dynamic_table);
}

}  // namespace

void RegisterNonABICompliantCodeRange(void* start, size_t size_in_bytes) {
  DCHECK(CanRegisterUnwindInfoForNonABICompliantCodeRange());

  // When the --win64-unwinding-info flag is set, we call
  // RtlAddGrowableFunctionTable to register unwinding info for the whole code
  // range of an isolate or Wasm module. This enables the Windows OS stack
  // unwinder to work correctly with V8-generated code, enabling stack walking
  // in Windows debuggers and performance tools. However, the
  // RtlAddGrowableFunctionTable API is only supported on Windows 8 and above.
  //
  // On Windows 7, or when --win64-unwinding-info is not set, we may still need
  // to call RtlAddFunctionTable to register a custom exception handler passed
  // by the embedder (like Crashpad).

  if (RegisterUnwindInfoForExceptionHandlingOnly()) {
#if defined(V8_OS_WIN_X64)
    // Windows ARM64 starts since 1709 Windows build, no need to have exception
    // handling only unwind info for compatibility.
    if (unhandled_exception_callback_g) {
      ExceptionHandlerRecord* record = new (start) ExceptionHandlerRecord();
      InitUnwindingRecord(record, size_in_bytes);

      CHECK(::RtlAddFunctionTable(record->runtime_function,
                                  kDefaultRuntimeFunctionCount,
                                  reinterpret_cast<DWORD64>(start)));

      // Protect reserved page against modifications.
      DWORD old_protect;
      CHECK(VirtualProtect(start, sizeof(ExceptionHandlerRecord),
                           PAGE_EXECUTE_READ, &old_protect));
    }
#endif  // V8_OS_WIN_X64
  } else {
    CodeRangeUnwindingRecord* record = new (start) CodeRangeUnwindingRecord();
    InitUnwindingRecord(record, size_in_bytes);

    CHECK(AddGrowableFunctionTable(
        &record->dynamic_table, record->runtime_function,
        record->runtime_function_count, record->runtime_function_count,
        reinterpret_cast<DWORD64>(start),
        reinterpret_cast<DWORD64>(reinterpret_cast<uint8_t*>(start) +
                                  size_in_bytes)));

    // Protect reserved page against modifications.
    DWORD old_protect;
    CHECK(VirtualProtect(start, sizeof(CodeRangeUnwindingRecord),
                         PAGE_EXECUTE_READ, &old_protect));
  }
}

void UnregisterNonABICompliantCodeRange(void* start) {
  DCHECK(CanRegisterUnwindInfoForNonABICompliantCodeRange());

  if (RegisterUnwindInfoForExceptionHandlingOnly()) {
#if defined(V8_OS_WIN_X64)
    // Windows ARM64 starts since 1709 Windows build, no need to have exception
    // handling only unwind info for compatibility.
    if (unhandled_exception_callback_g) {
      ExceptionHandlerRecord* record =
          reinterpret_cast<ExceptionHandlerRecord*>(start);
      CHECK(::RtlDeleteFunctionTable(record->runtime_function));

      // Unprotect reserved page.
      DWORD old_protect;
      CHECK(VirtualProtect(start, sizeof(ExceptionHandlerRecord),
                           PAGE_READWRITE, &old_protect));
    }
#endif  // V8_OS_WIN_X64
  } else {
    CodeRangeUnwindingRecord* record =
        reinterpret_cast<CodeRangeUnwindingRecord*>(start);
    if (record->dynamic_table) {
      DeleteGrowableFunctionTable(record->dynamic_table);
    }

    // Unprotect reserved page.
    DWORD old_protect;
    CHECK(VirtualProtect(start, sizeof(CodeRangeUnwindingRecord),
                         PAGE_READWRITE, &old_protect));
  }
}

#if defined(V8_OS_WIN_X64)

void XdataEncoder::onPushRbp() {
  current_frame_code_offset_ =
      assembler_.pc_offset() - kPushRbpInstructionLength;
}

void XdataEncoder::onMovRbpRsp() {
  if (current_frame_code_offset_ >= 0 &&
      current_frame_code_offset_ == assembler_.pc_offset() - kRbpPrefixLength) {
    fp_offsets_.push_back(current_frame_code_offset_);
  }
}

#elif defined(V8_OS_WIN_ARM64)

void XdataEncoder::onSaveFpLr() {
  current_frame_code_offset_ = assembler_.pc_offset() - 4;
  fp_offsets_.push_back(current_frame_code_offset_);
  fp_adjustments_.push_back(current_frame_adjustment_);
  current_frame_adjustment_ = FrameOffsets();
}

void XdataEncoder::onFramePointerAdjustment(int fp_to_saved_caller_fp,
                                            int fp_to_caller_sp) {
  current_frame_adjustment_.fp_to_saved_caller_fp = fp_to_saved_caller_fp;
  current_frame_adjustment_.fp_to_caller_sp = fp_to_caller_sp;
}

#endif  // V8_OS_WIN_X64

}  // namespace win64_unwindinfo
}  // namespace internal
}  // namespace v8
```