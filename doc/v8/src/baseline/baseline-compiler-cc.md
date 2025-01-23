Response:
The user wants to understand the functionality of the `v8/src/baseline/baseline-compiler.cc` file.

Here's a breakdown of the thought process:

1. **Identify the file type:** The prompt explicitly mentions the `.cc` extension, indicating a C++ source file. It also provides a conditional statement about a `.tq` extension, which is irrelevant for this specific file.

2. **High-level purpose:** The file name "baseline-compiler.cc" strongly suggests it's responsible for compiling to "baseline" code. In the context of V8, "baseline" usually refers to a simpler, faster-to-compile code tier compared to the optimizing compiler (TurboFan).

3. **Analyze includes:**  The included header files provide clues about the functionalities involved:
    * `<algorithm>`, `<optional>`, `<type_traits>`: Standard C++ utilities.
    * `"src/baseline/*"`:  Indicates interactions within the baseline compilation system itself. `baseline-assembler` is likely used for generating machine code.
    * `"src/builtins/*"`: Suggests interactions with built-in functions.
    * `"src/codegen/*"`:  Points to code generation related components like `assembler`, `compiler`, and interface descriptors.
    * `"src/execution/*"`:  Deals with runtime execution aspects, like frames.
    * `"src/heap/*"`:  Relates to memory management (the heap).
    * `"src/interpreter/*"`: Indicates interaction with the V8 interpreter, particularly bytecode.
    * `"src/logging/*"`:  For performance monitoring and debugging.
    * `"src/objects/*"`: Defines the structure of JavaScript objects in memory.
    * `"src/roots/*"`:  References special objects known to the VM.
    * Platform-specific headers (`"src/baseline/x64/..."`, etc.): Suggests architecture-specific code generation.

4. **Key classes and structures:** Scanning the code reveals key classes:
    * `BaselineCompiler`: The main class responsible for the compilation process.
    * `BaselineAssembler`: Likely provides an interface for emitting machine instructions.
    * `BytecodeOffsetTableBuilder`:  Used for mapping bytecode offsets to machine code offsets.
    * `Iterator`:  Iterating through the bytecode.

5. **Core functionalities (deduced from code structure and includes):**
    * **Bytecode Processing:**  The compiler takes bytecode as input (`Handle<BytecodeArray> bytecode`).
    * **Code Generation:** It uses `BaselineAssembler` to generate machine code. The platform-specific includes suggest conditional compilation for different architectures.
    * **Compilation Phases:** The `GenerateCode()` function hints at a two-pass approach: `PreVisit` and `Visit`.
    * **Handling Bytecode Instructions:** The `VisitSingleBytecode()` function and the `BYTECODE_LIST` macro suggest handling different bytecode opcodes.
    * **Interaction with Builtins:** `CallBuiltin` and `TailCallBuiltin` indicate calling predefined V8 functions.
    * **Interaction with the Runtime:** `CallRuntime` indicates calls to more complex runtime functions.
    * **Context and Scope Management:** The `PushContext` and `PopContext` methods suggest handling execution contexts.
    * **Memory Access:**  Operations like `LdaContextSlot`, `StaContextSlot` show how the generated code accesses variables in different scopes.
    * **Feedback Vectors:** The use of `FeedbackVector` suggests incorporating runtime feedback for potential future optimizations.
    * **Deoptimization Support:** Mentions of "deoptimization" suggest the ability to revert from baseline code to the interpreter if necessary.
    * **Interrupt Handling:**  `UpdateInterruptBudgetAndJumpToLabel` indicates a mechanism for periodically checking for interrupts.

6. **Addressing specific points from the prompt:**
    * **`.tq` extension:** The code confirms it's a `.cc` file, so the Torque statement is not applicable.
    * **Relationship to JavaScript:**  The file compiles *JavaScript bytecode* into machine code. The examples should illustrate common JavaScript constructs and how they might be translated into baseline code (though low-level details aren't necessary for a functional summary).
    * **Code Logic and I/O:**  Consider a simple bytecode sequence and the expected generated code flow. This can be simplified for the summary.
    * **Common Programming Errors:** Think about errors that might be caught or handled during the baseline compilation or execution of baseline code.
    * **Summarization:** Condense the findings into a concise description of the file's role.

7. **Structuring the answer:** Organize the information logically with clear headings and bullet points. Start with a high-level summary and then delve into more specific functionalities. Provide JavaScript examples where relevant.

**Self-Correction/Refinement:**

* Initially, I might focus too much on low-level assembler details. For this summary, it's more important to convey the *purpose* and *main functionalities* at a higher level.
* The provided code doesn't contain `.tq` code, so the conditional statement about Torque should be addressed but not dwelled upon.
* When giving JavaScript examples, ensure they relate directly to the concepts discussed in the C++ code (e.g., variable access, function calls). Avoid overly complex examples.
* For the "common programming errors" section, focus on errors that the baseline compiler or its output might encounter, rather than general JavaScript errors.
* The "assumptions and I/O" part can be simplified by focusing on a typical bytecode input and the expected outcome (execution of the corresponding JavaScript).

By following these steps and refining the understanding iteratively, I can generate a comprehensive and accurate summary of the `baseline-compiler.cc` file's functionality.
好的，我们来分析一下 `v8/src/baseline/baseline-compiler.cc` 这个文件的功能。

**功能归纳:**

`v8/src/baseline/baseline-compiler.cc` 是 V8 JavaScript 引擎中 **Baseline 编译器** 的主要实现文件。它的核心功能是将 **字节码 (bytecode)** 编译成 **机器码 (machine code)**，以便 CPU 可以执行。Baseline 编译器是 V8 中一个轻量级的、快速的编译器，它生成的代码虽然不如优化编译器 (TurboFan) 生成的代码那样性能高，但编译速度快，适用于快速启动和执行不频繁的代码。

**具体功能点:**

* **接收输入:**  它接收 `SharedFunctionInfo` (包含函数的元信息) 和 `BytecodeArray` (包含函数的字节码) 作为输入。
* **代码生成:** 它使用 `BaselineAssembler` (及其平台相关的子类，例如 `BaselineAssemblerX64` 等) 来生成特定架构的机器码指令。
* **字节码遍历:**  它遍历 `BytecodeArray` 中的每一条字节码指令。
* **为字节码生成机器码:**  针对不同的字节码指令，生成相应的机器码指令序列。这包括：
    * **加载和存储数据:**  例如 `LdaZero` (加载 0), `LdaSmi` (加载小整数), `LdaGlobal` (加载全局变量), `StaContextSlot` (存储到上下文槽) 等。
    * **算术和逻辑运算:**  尽管在这个文件中没有直接展示，但相关的 `Visit...` 函数 (例如 `VisitAdd`, `VisitSub`) 会调用 `BaselineAssembler` 来生成这些操作的机器码。
    * **控制流:**  例如 `Jump`, `JumpIfTrue`, `JumpIfFalse`, `JumpLoop` 等字节码会被转换成相应的跳转指令。
    * **函数调用:** `CallBuiltin` 用于调用内置函数，`CallRuntime` 用于调用运行时函数。
    * **对象操作:**  例如属性加载和存储 (虽然在这个文件中可能不直接处理复杂的对象操作，但 Baseline 编译器会处理一些基本情况)。
* **维护字节码偏移表:**  `BytecodeOffsetTableBuilder` 用于建立字节码偏移量到生成机器码偏移量的映射，这对于调试和性能分析非常重要。
* **处理异常:**  标记异常处理器的目标地址。
* **生成 Code 对象:**  最终将生成的机器码封装成 `Code` 对象，供 V8 执行。

**关于 .tq 扩展名:**

你提到如果文件以 `.tq` 结尾，那么它是一个 V8 Torque 源代码。这是正确的。Torque 是一种 V8 内部使用的类型化的中间语言，用于定义内置函数和一些核心的运行时代码。`v8/src/baseline/baseline-compiler.cc` 是 C++ 文件，因此它不是 Torque 源代码。

**与 JavaScript 功能的关系及 JavaScript 示例:**

`v8/src/baseline/baseline-compiler.cc` 的核心作用是将 JavaScript 代码编译成机器码。它处理的每一条字节码指令都对应着一个或多个 JavaScript 操作。

以下是一些 JavaScript 示例以及它们可能对应的 Baseline 编译器处理方式 (简化说明):

**1. 变量声明和赋值:**

```javascript
let x = 10;
```

* **对应字节码 (Simplified):** `LdaSmi [10]`, `Star [local 0]`
* **Baseline 编译器处理:**
    * `VisitLdaSmi`: 生成机器码将小整数 10 加载到累加器寄存器 (kInterpreterAccumulatorRegister)。
    * `VisitStar`: 生成机器码将累加器寄存器的值存储到局部变量槽 (local 0) 中。

**2. 函数调用:**

```javascript
function add(a, b) {
  return a + b;
}
let result = add(5, 3);
```

* **对应字节码 (Simplified):**
    * 调用 `add`: `PushConstant [add function]`, `LdaSmi [5]`, `PushReg [acc]`, `LdaSmi [3]`, `Call [2 arguments]`
* **Baseline 编译器处理:**
    * `VisitPushConstant`: 将 `add` 函数对象压入栈。
    * `VisitLdaSmi`: 加载参数 5 和 3 到寄存器或栈。
    * `VisitCall`: 生成机器码来执行函数调用，这可能涉及设置函数调用帧，跳转到 `add` 函数的入口点等。如果 `add` 是内置函数，则会调用 `CallBuiltin`。

**3. 全局变量访问:**

```javascript
console.log("Hello");
```

* **对应字节码 (Simplified):** `LdaGlobal [console]`, `LdaNamedProperty [log]`, `LdaConstant ["Hello"]`, `CallMethod [1 argument]`
* **Baseline 编译器处理:**
    * `VisitLdaGlobal`: 生成机器码查找并加载全局对象 `console`。
    * `VisitLdaNamedProperty`: 生成机器码访问 `console` 对象的 `log` 属性。
    * `VisitLdaConstant`: 加载字符串 "Hello"。
    * `VisitCallMethod`: 生成机器码调用 `log` 方法。

**代码逻辑推理和假设输入输出:**

假设我们有以下简单的 JavaScript 函数：

```javascript
function simpleAdd(x) {
  return x + 1;
}
```

并且 V8 的解释器将其转换成如下 (简化的) 字节码序列：

```
00 Ldar a0          // Load argument 0 (x) to accumulator
01 LdaSmi [1]       // Load small integer 1 to accumulator
02 Add              // Add accumulator with register operand
03 Return           // Return accumulator
```

**Baseline 编译器处理过程 (假设):**

* **输入:**  包含上述字节码的 `BytecodeArray`。
* **处理 `Ldar a0` (假设 `a0` 映射到某个寄存器 `reg1`):** 生成机器码 `mov rax, [rbp + offset_of_argument_0]` (x64 架构示例，将栈帧中参数 `x` 的值加载到 `rax` 寄存器，这里假设累加器映射到 `rax`)。
* **处理 `LdaSmi [1]`:** 生成机器码 `mov rbx, 1` (将小整数 1 加载到 `rbx` 寄存器)。
* **处理 `Add`:** 生成机器码 `add rax, rbx` (将 `rbx` 的值加到 `rax` 上)。
* **处理 `Return`:** 生成机器码来执行函数返回，例如 `mov rsp, rbp; pop rbp; ret`。

**假设输入输出:**

* **假设输入 (字节码偏移和指令):**
    * 00: `Ldar a0`
    * 01: `LdaSmi [1]`
    * 02: `Add`
    * 03: `Return`
* **假设输出 (生成的机器码 - x64 架构简化):**
    * `mov rax, [rbp + offset_of_argument_0]`
    * `mov rbx, 1`
    * `add rax, rbx`
    * `mov rsp, rbp`
    * `pop rbp`
    * `ret`

**用户常见的编程错误:**

Baseline 编译器本身不直接捕获 JavaScript 语法错误或类型错误 (这些通常在解析和解释阶段处理)。然而，一些与性能相关的常见编程错误，可能会让代码停留在 Baseline 阶段而无法被优化编译器进一步优化。

* **频繁的类型变化:** 如果一个变量的类型在运行时频繁变化，Baseline 代码可能需要进行更多的类型检查，这会降低性能。
    ```javascript
    let count = 0;
    for (let i = 0; i < 10; i++) {
      if (i % 2 === 0) {
        count = "even"; // 类型从 number 变为 string
      } else {
        count = i;
      }
      console.log(count);
    }
    ```
* **访问未初始化的变量 (在某些情况下):** 虽然现代 JavaScript 有暂时性死区，但在某些旧的代码模式中，可能会遇到访问未初始化变量的情况，这可能导致 Baseline 代码执行时出现意外行为。
* **过度使用 `arguments` 对象:**  在非严格模式下使用 `arguments` 对象可能会导致一些性能损耗，Baseline 代码可能需要处理这种动态参数访问。
* **在循环中进行昂贵的操作:**  如果在循环中执行耗时的操作，Baseline 代码的性能瓶颈会更加明显。

**总结 `v8/src/baseline/baseline-compiler.cc` 的功能 (针对第 1 部分):**

`v8/src/baseline/baseline-compiler.cc` 的主要功能是作为 V8 引擎的 **Baseline 编译器**，负责将 JavaScript 函数的 **字节码** 快速转换为 **机器码**。它遍历字节码指令，并使用 `BaselineAssembler` 生成针对目标架构的机器指令。这个过程是 V8 执行 JavaScript 代码的第一步编译阶段，旨在提供快速的初始执行，为后续的优化编译提供基础。文件中涉及了字节码处理、机器码生成、内置函数和运行时函数的调用，以及维护字节码偏移表等关键功能。

### 提示词
```
这是目录为v8/src/baseline/baseline-compiler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/baseline/baseline-compiler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2021 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/baseline/baseline-compiler.h"

#include <algorithm>
#include <optional>
#include <type_traits>

#include "src/base/bits.h"
#include "src/baseline/baseline-assembler-inl.h"
#include "src/baseline/baseline-assembler.h"
#include "src/builtins/builtins-constructor.h"
#include "src/builtins/builtins-descriptors.h"
#include "src/builtins/builtins.h"
#include "src/codegen/assembler.h"
#include "src/codegen/compiler.h"
#include "src/codegen/interface-descriptors-inl.h"
#include "src/codegen/machine-type.h"
#include "src/codegen/macro-assembler-inl.h"
#include "src/common/globals.h"
#include "src/execution/frame-constants.h"
#include "src/heap/local-factory-inl.h"
#include "src/interpreter/bytecode-array-iterator.h"
#include "src/interpreter/bytecode-flags-and-tokens.h"
#include "src/logging/runtime-call-stats-scope.h"
#include "src/objects/code.h"
#include "src/objects/heap-object.h"
#include "src/objects/instance-type.h"
#include "src/objects/literal-objects-inl.h"
#include "src/objects/shared-function-info-inl.h"
#include "src/roots/roots.h"

#if V8_TARGET_ARCH_X64
#include "src/baseline/x64/baseline-compiler-x64-inl.h"
#elif V8_TARGET_ARCH_ARM64
#include "src/baseline/arm64/baseline-compiler-arm64-inl.h"
#elif V8_TARGET_ARCH_IA32
#include "src/baseline/ia32/baseline-compiler-ia32-inl.h"
#elif V8_TARGET_ARCH_ARM
#include "src/baseline/arm/baseline-compiler-arm-inl.h"
#elif V8_TARGET_ARCH_PPC64
#include "src/baseline/ppc/baseline-compiler-ppc-inl.h"
#elif V8_TARGET_ARCH_S390X
#include "src/baseline/s390/baseline-compiler-s390-inl.h"
#elif V8_TARGET_ARCH_RISCV64
#include "src/baseline/riscv/baseline-compiler-riscv-inl.h"
#elif V8_TARGET_ARCH_RISCV32
#include "src/baseline/riscv/baseline-compiler-riscv-inl.h"
#elif V8_TARGET_ARCH_MIPS64
#include "src/baseline/mips64/baseline-compiler-mips64-inl.h"
#elif V8_TARGET_ARCH_LOONG64
#include "src/baseline/loong64/baseline-compiler-loong64-inl.h"
#else
#error Unsupported target architecture.
#endif

namespace v8 {
namespace internal {
namespace baseline {

#define __ basm_.

#define RCS_BASELINE_SCOPE(rcs)                               \
  RCS_SCOPE(stats_,                                           \
            local_isolate_->is_main_thread()                  \
                ? RuntimeCallCounterId::kCompileBaseline##rcs \
                : RuntimeCallCounterId::kCompileBackgroundBaseline##rcs)

template <typename IsolateT>
Handle<TrustedByteArray> BytecodeOffsetTableBuilder::ToBytecodeOffsetTable(
    IsolateT* isolate) {
  if (bytes_.empty()) return isolate->factory()->empty_trusted_byte_array();
  Handle<TrustedByteArray> table =
      isolate->factory()->NewTrustedByteArray(static_cast<int>(bytes_.size()));
  MemCopy(table->begin(), bytes_.data(), bytes_.size());
  return table;
}

namespace detail {

#ifdef DEBUG
bool Clobbers(Register target, Register reg) { return target == reg; }
bool Clobbers(Register target, DirectHandle<Object> handle) { return false; }
bool Clobbers(Register target, Tagged<Smi> smi) { return false; }
bool Clobbers(Register target, Tagged<TaggedIndex> index) { return false; }
bool Clobbers(Register target, int32_t imm) { return false; }
bool Clobbers(Register target, RootIndex index) { return false; }
bool Clobbers(Register target, interpreter::Register reg) { return false; }
bool Clobbers(Register target, interpreter::RegisterList list) { return false; }

// We don't know what's inside machine registers or operands, so assume they
// match.
bool MachineTypeMatches(MachineType type, Register reg) { return true; }
bool MachineTypeMatches(MachineType type, MemOperand reg) { return true; }
bool MachineTypeMatches(MachineType type, DirectHandle<HeapObject> handle) {
  return type.IsTagged() && !type.IsTaggedSigned();
}
bool MachineTypeMatches(MachineType type, Tagged<Smi> handle) {
  return type.IsTagged() && !type.IsTaggedPointer();
}
bool MachineTypeMatches(MachineType type, Tagged<TaggedIndex> handle) {
  // Tagged<TaggedIndex> doesn't have a separate type, so check for the same
  // type as for Smis.
  return type.IsTagged() && !type.IsTaggedPointer();
}
bool MachineTypeMatches(MachineType type, int32_t imm) {
  // 32-bit immediates can be used for 64-bit params -- they'll be
  // zero-extended.
  return type.representation() == MachineRepresentation::kWord32 ||
         type.representation() == MachineRepresentation::kWord64;
}
bool MachineTypeMatches(MachineType type, RootIndex index) {
  return type.IsTagged() && !type.IsTaggedSigned();
}
bool MachineTypeMatches(MachineType type, interpreter::Register reg) {
  return type.IsTagged();
}

template <typename Descriptor, typename... Args>
struct CheckArgsHelper;

template <typename Descriptor>
struct CheckArgsHelper<Descriptor> {
  static void Check(BaselineAssembler* masm, int i) {
    if (Descriptor::AllowVarArgs()) {
      CHECK_GE(i, Descriptor::GetParameterCount());
    } else {
      CHECK_EQ(i, Descriptor::GetParameterCount());
    }
  }
};

template <typename Descriptor, typename Arg, typename... Args>
struct CheckArgsHelper<Descriptor, Arg, Args...> {
  static void Check(BaselineAssembler* masm, int i, Arg arg, Args... args) {
    if (i >= Descriptor::GetParameterCount()) {
      CHECK(Descriptor::AllowVarArgs());
      return;
    }
    CHECK(MachineTypeMatches(Descriptor().GetParameterType(i), arg));
    CheckArgsHelper<Descriptor, Args...>::Check(masm, i + 1, args...);
  }
};

template <typename Descriptor, typename... Args>
struct CheckArgsHelper<Descriptor, interpreter::RegisterList, Args...> {
  static void Check(BaselineAssembler* masm, int i,
                    interpreter::RegisterList list, Args... args) {
    for (int reg_index = 0; reg_index < list.register_count();
         ++reg_index, ++i) {
      if (i >= Descriptor::GetParameterCount()) {
        CHECK(Descriptor::AllowVarArgs());
        return;
      }
      CHECK(MachineTypeMatches(Descriptor().GetParameterType(i),
                               list[reg_index]));
    }
    CheckArgsHelper<Descriptor, Args...>::Check(masm, i, args...);
  }
};

template <typename Descriptor, typename... Args>
void CheckArgs(BaselineAssembler* masm, Args... args) {
  CheckArgsHelper<Descriptor, Args...>::Check(masm, 0, args...);
}

void CheckSettingDoesntClobber(Register target) {}
template <typename Arg, typename... Args>
void CheckSettingDoesntClobber(Register target, Arg arg, Args... args) {
  DCHECK(!Clobbers(target, arg));
  CheckSettingDoesntClobber(target, args...);
}

#else  // DEBUG

template <typename Descriptor, typename... Args>
void CheckArgs(Args... args) {}

template <typename... Args>
void CheckSettingDoesntClobber(Register target, Args... args) {}

#endif  // DEBUG

template <typename Descriptor, int ArgIndex, bool kIsRegister, typename... Args>
struct ArgumentSettingHelper;

template <typename Descriptor, int ArgIndex, bool kIsRegister>
struct ArgumentSettingHelper<Descriptor, ArgIndex, kIsRegister> {
  static void Set(BaselineAssembler* masm) {
    // Should only ever be called for the end of register arguments.
    static_assert(ArgIndex == Descriptor::GetRegisterParameterCount());
  }
};

template <typename Descriptor, int ArgIndex, typename Arg, typename... Args>
struct ArgumentSettingHelper<Descriptor, ArgIndex, true, Arg, Args...> {
  static void Set(BaselineAssembler* masm, Arg arg, Args... args) {
    static_assert(ArgIndex < Descriptor::GetRegisterParameterCount());
    Register target = Descriptor::GetRegisterParameter(ArgIndex);
    CheckSettingDoesntClobber(target, args...);
    masm->Move(target, arg);
    ArgumentSettingHelper<Descriptor, ArgIndex + 1,
                          (ArgIndex + 1 <
                           Descriptor::GetRegisterParameterCount()),
                          Args...>::Set(masm, args...);
  }
};

template <typename Descriptor, int ArgIndex>
struct ArgumentSettingHelper<Descriptor, ArgIndex, true,
                             interpreter::RegisterList> {
  static void Set(BaselineAssembler* masm, interpreter::RegisterList list) {
    static_assert(ArgIndex < Descriptor::GetRegisterParameterCount());
    DCHECK_EQ(ArgIndex + list.register_count(),
              Descriptor::GetRegisterParameterCount());
    for (int i = 0; ArgIndex + i < Descriptor::GetRegisterParameterCount();
         ++i) {
      Register target = Descriptor::GetRegisterParameter(ArgIndex + i);
      masm->Move(target, masm->RegisterFrameOperand(list[i]));
    }
  }
};

template <typename Descriptor, int ArgIndex, typename Arg, typename... Args>
struct ArgumentSettingHelper<Descriptor, ArgIndex, false, Arg, Args...> {
  static void Set(BaselineAssembler* masm, Arg arg, Args... args) {
    if (Descriptor::kStackArgumentOrder == StackArgumentOrder::kDefault) {
      masm->Push(arg, args...);
    } else {
      masm->PushReverse(arg, args...);
    }
  }
};

template <Builtin kBuiltin, typename... Args>
void MoveArgumentsForBuiltin(BaselineAssembler* masm, Args... args) {
  using Descriptor = typename CallInterfaceDescriptorFor<kBuiltin>::type;
  CheckArgs<Descriptor>(masm, args...);
  ArgumentSettingHelper<Descriptor, 0,
                        (0 < Descriptor::GetRegisterParameterCount()),
                        Args...>::Set(masm, args...);
  if (Descriptor::HasContextParameter()) {
    masm->LoadContext(Descriptor::ContextRegister());
  }
}

}  // namespace detail

namespace {

AssemblerOptions BaselineAssemblerOptions(Isolate* isolate) {
  AssemblerOptions options = AssemblerOptions::Default(isolate);
  options.builtin_call_jump_mode =
      isolate->is_short_builtin_calls_enabled()
          ? BuiltinCallJumpMode::kPCRelative
          : kFallbackBuiltinCallJumpModeForBaseline;
  return options;
}

// Rough upper-bound estimate. Copying the data is most likely more expensive
// than pre-allocating a large enough buffer.
#ifdef V8_TARGET_ARCH_IA32
const int kAverageBytecodeToInstructionRatio = 5;
#else
const int kAverageBytecodeToInstructionRatio = 7;
#endif
std::unique_ptr<AssemblerBuffer> AllocateBuffer(
    DirectHandle<BytecodeArray> bytecodes) {
  int estimated_size;
  {
    DisallowHeapAllocation no_gc;
    estimated_size = BaselineCompiler::EstimateInstructionSize(*bytecodes);
  }
  return NewAssemblerBuffer(RoundUp(estimated_size, 4 * KB));
}
}  // namespace

BaselineCompiler::BaselineCompiler(
    LocalIsolate* local_isolate,
    Handle<SharedFunctionInfo> shared_function_info,
    Handle<BytecodeArray> bytecode)
    : local_isolate_(local_isolate),
      stats_(local_isolate->runtime_call_stats()),
      shared_function_info_(shared_function_info),
      bytecode_(bytecode),
      zone_(local_isolate->allocator(), ZONE_NAME),
      masm_(
          local_isolate->GetMainThreadIsolateUnsafe(), &zone_,
          BaselineAssemblerOptions(local_isolate->GetMainThreadIsolateUnsafe()),
          CodeObjectRequired::kNo, AllocateBuffer(bytecode)),
      basm_(&masm_),
      iterator_(bytecode_),
      labels_(zone_.AllocateArray<Label>(bytecode_->length())),
      label_tags_(2 * bytecode_->length(), &zone_) {
  // Empirically determined expected size of the offset table at the 95th %ile,
  // based on the size of the bytecode, to be:
  //
  //   16 + (bytecode size) / 4
  bytecode_offset_table_builder_.Reserve(
      base::bits::RoundUpToPowerOfTwo(16 + bytecode_->Size() / 4));
}

void BaselineCompiler::GenerateCode() {
  {
    RCS_BASELINE_SCOPE(PreVisit);
    // Mark exception handlers as valid indirect jump targets. This is required
    // when CFI is enabled, to allow indirect jumps into baseline code.
    HandlerTable table(*bytecode_);
    for (int i = 0; i < table.NumberOfRangeEntries(); ++i) {
      MarkIndirectJumpTarget(table.GetRangeHandler(i));
    }
    for (; !iterator_.done(); iterator_.Advance()) {
      PreVisitSingleBytecode();
    }
    iterator_.Reset();
  }

  // No code generated yet.
  DCHECK_EQ(__ pc_offset(), 0);
  __ CodeEntry();

  {
    RCS_BASELINE_SCOPE(Visit);
    Prologue();
    AddPosition();
    for (; !iterator_.done(); iterator_.Advance()) {
      VisitSingleBytecode();
      AddPosition();
    }
  }
}

MaybeHandle<Code> BaselineCompiler::Build() {
  RCS_BASELINE_SCOPE(Build);
  CodeDesc desc;
  __ GetCode(local_isolate_, &desc);

  // Allocate the bytecode offset table.
  Handle<TrustedByteArray> bytecode_offset_table =
      bytecode_offset_table_builder_.ToBytecodeOffsetTable(local_isolate_);

  Factory::CodeBuilder code_builder(local_isolate_, desc, CodeKind::BASELINE);
  code_builder.set_bytecode_offset_table(bytecode_offset_table);
  if (shared_function_info_->HasInterpreterData(local_isolate_)) {
    code_builder.set_interpreter_data(
        handle(shared_function_info_->interpreter_data(local_isolate_),
               local_isolate_));
  } else {
    code_builder.set_interpreter_data(bytecode_);
  }
  code_builder.set_parameter_count(bytecode_->parameter_count());
  return code_builder.TryBuild();
}

int BaselineCompiler::EstimateInstructionSize(Tagged<BytecodeArray> bytecode) {
  return bytecode->length() * kAverageBytecodeToInstructionRatio;
}

interpreter::Register BaselineCompiler::RegisterOperand(int operand_index) {
  return iterator().GetRegisterOperand(operand_index);
}

void BaselineCompiler::LoadRegister(Register output, int operand_index) {
  __ LoadRegister(output, RegisterOperand(operand_index));
}

void BaselineCompiler::StoreRegister(int operand_index, Register value) {
#ifdef DEBUG
  effect_state_.CheckEffect();
#endif
  __ Move(RegisterOperand(operand_index), value);
}

void BaselineCompiler::StoreRegisterPair(int operand_index, Register val0,
                                         Register val1) {
#ifdef DEBUG
  effect_state_.CheckEffect();
#endif
  interpreter::Register reg0, reg1;
  std::tie(reg0, reg1) = iterator().GetRegisterPairOperand(operand_index);
  __ StoreRegister(reg0, val0);
  __ StoreRegister(reg1, val1);
}
template <typename Type>
Handle<Type> BaselineCompiler::Constant(int operand_index) {
  return Cast<Type>(
      iterator().GetConstantForIndexOperand(operand_index, local_isolate_));
}
Tagged<Smi> BaselineCompiler::ConstantSmi(int operand_index) {
  return iterator().GetConstantAtIndexAsSmi(operand_index);
}
template <typename Type>
void BaselineCompiler::LoadConstant(Register output, int operand_index) {
  __ Move(output, Constant<Type>(operand_index));
}
uint32_t BaselineCompiler::Uint(int operand_index) {
  return iterator().GetUnsignedImmediateOperand(operand_index);
}
int32_t BaselineCompiler::Int(int operand_index) {
  return iterator().GetImmediateOperand(operand_index);
}
uint32_t BaselineCompiler::Index(int operand_index) {
  return iterator().GetIndexOperand(operand_index);
}
uint32_t BaselineCompiler::Flag8(int operand_index) {
  return iterator().GetFlag8Operand(operand_index);
}
uint32_t BaselineCompiler::Flag16(int operand_index) {
  return iterator().GetFlag16Operand(operand_index);
}
uint32_t BaselineCompiler::RegisterCount(int operand_index) {
  return iterator().GetRegisterCountOperand(operand_index);
}
Tagged<TaggedIndex> BaselineCompiler::IndexAsTagged(int operand_index) {
  return TaggedIndex::FromIntptr(Index(operand_index));
}
Tagged<TaggedIndex> BaselineCompiler::UintAsTagged(int operand_index) {
  return TaggedIndex::FromIntptr(Uint(operand_index));
}
Tagged<Smi> BaselineCompiler::IndexAsSmi(int operand_index) {
  return Smi::FromInt(Index(operand_index));
}
Tagged<Smi> BaselineCompiler::IntAsSmi(int operand_index) {
  return Smi::FromInt(Int(operand_index));
}
Tagged<Smi> BaselineCompiler::UintAsSmi(int operand_index) {
  return Smi::FromInt(Uint(operand_index));
}
Tagged<Smi> BaselineCompiler::Flag8AsSmi(int operand_index) {
  return Smi::FromInt(Flag8(operand_index));
}
Tagged<Smi> BaselineCompiler::Flag16AsSmi(int operand_index) {
  return Smi::FromInt(Flag16(operand_index));
}

MemOperand BaselineCompiler::FeedbackVector() {
  return __ FeedbackVectorOperand();
}

void BaselineCompiler::LoadFeedbackVector(Register output) {
  ASM_CODE_COMMENT(&masm_);
  __ Move(output, __ FeedbackVectorOperand());
}

void BaselineCompiler::LoadClosureFeedbackArray(Register output) {
  LoadFeedbackVector(output);
  __ LoadTaggedField(output, output,
                     FeedbackVector::kClosureFeedbackCellArrayOffset);
}

void BaselineCompiler::SelectBooleanConstant(
    Register output, std::function<void(Label*, Label::Distance)> jump_func) {
  Label done, set_true;
  jump_func(&set_true, Label::kNear);
  __ LoadRoot(output, RootIndex::kFalseValue);
  __ Jump(&done, Label::kNear);
  __ Bind(&set_true);
  __ LoadRoot(output, RootIndex::kTrueValue);
  __ Bind(&done);
}

void BaselineCompiler::AddPosition() {
  bytecode_offset_table_builder_.AddPosition(__ pc_offset());
}

void BaselineCompiler::PreVisitSingleBytecode() {
  switch (iterator().current_bytecode()) {
    case interpreter::Bytecode::kJumpLoop:
      EnsureLabel(iterator().GetJumpTargetOffset(),
                  MarkAsIndirectJumpTarget::kYes);
      break;
    default:
      break;
  }
}

void BaselineCompiler::VisitSingleBytecode() {
#ifdef DEBUG
  effect_state_.clear();
#endif
  int offset = iterator().current_offset();
  if (IsJumpTarget(offset)) __ Bind(&labels_[offset]);
  // Mark position as valid jump target unconditionnaly when the deoptimizer can
  // jump to baseline code. This is required when CFI is enabled.
  if (v8_flags.deopt_to_baseline || IsIndirectJumpTarget(offset)) {
    __ JumpTarget();
  }

  ASM_CODE_COMMENT_STRING(&masm_, [&]() {
    std::ostringstream str;
    iterator().PrintTo(str);
    return str.str();
  });

  VerifyFrame();

#ifdef V8_TRACE_UNOPTIMIZED
  TraceBytecode(Runtime::kTraceUnoptimizedBytecodeEntry);
#endif

  {
    interpreter::Bytecode bytecode = iterator().current_bytecode();

#ifdef DEBUG
    std::optional<EnsureAccumulatorPreservedScope> accumulator_preserved_scope;
    // We should make sure to preserve the accumulator whenever the bytecode
    // isn't registered as writing to it. We can't do this for jumps or switches
    // though, since the control flow would not match the control flow of this
    // scope.
    if (v8_flags.debug_code &&
        !interpreter::Bytecodes::WritesOrClobbersAccumulator(bytecode) &&
        !interpreter::Bytecodes::IsJump(bytecode) &&
        !interpreter::Bytecodes::IsSwitch(bytecode)) {
      accumulator_preserved_scope.emplace(&basm_);
    }
#endif  // DEBUG

    switch (bytecode) {
#define BYTECODE_CASE(name, ...)       \
  case interpreter::Bytecode::k##name: \
    Visit##name();                     \
    break;
      BYTECODE_LIST(BYTECODE_CASE, BYTECODE_CASE)
#undef BYTECODE_CASE
    }
  }

#ifdef V8_TRACE_UNOPTIMIZED
  TraceBytecode(Runtime::kTraceUnoptimizedBytecodeExit);
#endif
}

void BaselineCompiler::VerifyFrame() {
  if (v8_flags.debug_code) {
    ASM_CODE_COMMENT(&masm_);
    __ RecordComment(" -- Verify frame size");
    VerifyFrameSize();

    __ RecordComment(" -- Verify feedback vector");
    {
      BaselineAssembler::ScratchRegisterScope temps(&basm_);
      Register scratch = temps.AcquireScratch();
      __ Move(scratch, __ FeedbackVectorOperand());
      Label is_smi, is_ok;
      __ JumpIfSmi(scratch, &is_smi);
      __ JumpIfObjectTypeFast(kEqual, scratch, FEEDBACK_VECTOR_TYPE, &is_ok);
      __ Bind(&is_smi);
      __ masm()->Abort(AbortReason::kExpectedFeedbackVector);
      __ Bind(&is_ok);
    }

    // TODO(leszeks): More verification.
  }
}

#ifdef V8_TRACE_UNOPTIMIZED
void BaselineCompiler::TraceBytecode(Runtime::FunctionId function_id) {
  if (!v8_flags.trace_baseline_exec) return;
  ASM_CODE_COMMENT_STRING(&masm_,
                          function_id == Runtime::kTraceUnoptimizedBytecodeEntry
                              ? "Trace bytecode entry"
                              : "Trace bytecode exit");
  SaveAccumulatorScope accumulator_scope(this, &basm_);
  CallRuntime(function_id, bytecode_,
              Smi::FromInt(BytecodeArray::kHeaderSize - kHeapObjectTag +
                           iterator().current_offset()),
              kInterpreterAccumulatorRegister);
}
#endif

#define DECLARE_VISITOR(name, ...) void Visit##name();
BYTECODE_LIST(DECLARE_VISITOR, DECLARE_VISITOR)
#undef DECLARE_VISITOR

#define DECLARE_VISITOR(name, ...) \
  void VisitIntrinsic##name(interpreter::RegisterList args);
INTRINSICS_LIST(DECLARE_VISITOR)
#undef DECLARE_VISITOR

void BaselineCompiler::UpdateInterruptBudgetAndJumpToLabel(
    int weight, Label* label, Label* skip_interrupt_label,
    StackCheckBehavior stack_check_behavior) {
  if (weight != 0) {
    ASM_CODE_COMMENT(&masm_);
    __ AddToInterruptBudgetAndJumpIfNotExceeded(weight, skip_interrupt_label);

    DCHECK_LT(weight, 0);
    CallRuntime(stack_check_behavior == kEnableStackCheck
                    ? Runtime::kBytecodeBudgetInterruptWithStackCheck_Sparkplug
                    : Runtime::kBytecodeBudgetInterrupt_Sparkplug,
                __ FunctionOperand());
  }
  if (label) __ Jump(label);
}

void BaselineCompiler::JumpIfRoot(RootIndex root) {
  Label dont_jump;
  __ JumpIfNotRoot(kInterpreterAccumulatorRegister, root, &dont_jump,
                   Label::kNear);
  __ Jump(BuildForwardJumpLabel());
  __ Bind(&dont_jump);
}

void BaselineCompiler::JumpIfNotRoot(RootIndex root) {
  Label dont_jump;
  __ JumpIfRoot(kInterpreterAccumulatorRegister, root, &dont_jump,
                Label::kNear);
  __ Jump(BuildForwardJumpLabel());
  __ Bind(&dont_jump);
}

Label* BaselineCompiler::BuildForwardJumpLabel() {
  int target_offset = iterator().GetJumpTargetOffset();
  return EnsureLabel(target_offset);
}

#ifdef DEBUG
// Allowlist to mark builtin calls during which it is impossible that the
// sparkplug frame would have to be deoptimized. Either because they don't
// execute any user code, or because they would anyway replace the current
// frame, e.g., due to OSR.
constexpr static bool BuiltinMayDeopt(Builtin id) {
  switch (id) {
    case Builtin::kSuspendGeneratorBaseline:
    case Builtin::kBaselineOutOfLinePrologue:
    case Builtin::kIncBlockCounter:
    case Builtin::kToObject:
    case Builtin::kStoreScriptContextSlotBaseline:
    case Builtin::kStoreCurrentScriptContextSlotBaseline:
    // This one explicitly skips the construct if the debugger is enabled.
    case Builtin::kFindNonDefaultConstructorOrConstruct:
      return false;
    default:
      return true;
  }
}
#endif  // DEBUG

template <Builtin kBuiltin, typename... Args>
void BaselineCompiler::CallBuiltin(Args... args) {
#ifdef DEBUG
  effect_state_.CheckEffect();
  if (BuiltinMayDeopt(kBuiltin)) {
    effect_state_.MayDeopt();
  }
#endif
  ASM_CODE_COMMENT(&masm_);
  detail::MoveArgumentsForBuiltin<kBuiltin>(&basm_, args...);
  __ CallBuiltin(kBuiltin);
}

template <Builtin kBuiltin, typename... Args>
void BaselineCompiler::TailCallBuiltin(Args... args) {
#ifdef DEBUG
  effect_state_.CheckEffect();
#endif
  detail::MoveArgumentsForBuiltin<kBuiltin>(&basm_, args...);
  __ TailCallBuiltin(kBuiltin);
}

template <typename... Args>
void BaselineCompiler::CallRuntime(Runtime::FunctionId function, Args... args) {
#ifdef DEBUG
  effect_state_.CheckEffect();
  effect_state_.MayDeopt();
#endif
  __ LoadContext(kContextRegister);
  int nargs = __ Push(args...);
  __ CallRuntime(function, nargs);
}

// Returns into kInterpreterAccumulatorRegister
void BaselineCompiler::JumpIfToBoolean(bool do_jump_if_true, Label* label,
                                       Label::Distance distance) {
  CallBuiltin<Builtin::kToBooleanForBaselineJump>(
      kInterpreterAccumulatorRegister);
  // ToBooleanForBaselineJump returns the ToBoolean value into return reg 1, and
  // the original value into kInterpreterAccumulatorRegister, so we don't have
  // to worry about it getting clobbered.
  static_assert(kReturnRegister0 == kInterpreterAccumulatorRegister);
  __ JumpIfSmi(do_jump_if_true ? kNotEqual : kEqual, kReturnRegister1,
               Smi::FromInt(0), label, distance);
}

void BaselineCompiler::VisitLdaZero() {
  __ Move(kInterpreterAccumulatorRegister, Smi::FromInt(0));
}

void BaselineCompiler::VisitLdaSmi() {
  Tagged<Smi> constant = Smi::FromInt(iterator().GetImmediateOperand(0));
  __ Move(kInterpreterAccumulatorRegister, constant);
}

void BaselineCompiler::VisitLdaUndefined() {
  __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kUndefinedValue);
}

void BaselineCompiler::VisitLdaNull() {
  __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kNullValue);
}

void BaselineCompiler::VisitLdaTheHole() {
  __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kTheHoleValue);
}

void BaselineCompiler::VisitLdaTrue() {
  __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kTrueValue);
}

void BaselineCompiler::VisitLdaFalse() {
  __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kFalseValue);
}

void BaselineCompiler::VisitLdaConstant() {
  LoadConstant<HeapObject>(kInterpreterAccumulatorRegister, 0);
}

void BaselineCompiler::VisitLdaGlobal() {
  CallBuiltin<Builtin::kLoadGlobalICBaseline>(Constant<Name>(0),  // name
                                              IndexAsTagged(1));  // slot
}

void BaselineCompiler::VisitLdaGlobalInsideTypeof() {
  CallBuiltin<Builtin::kLoadGlobalICInsideTypeofBaseline>(
      Constant<Name>(0),  // name
      IndexAsTagged(1));  // slot
}

void BaselineCompiler::VisitStaGlobal() {
  CallBuiltin<Builtin::kStoreGlobalICBaseline>(
      Constant<Name>(0),                // name
      kInterpreterAccumulatorRegister,  // value
      IndexAsTagged(1));                // slot
}

void BaselineCompiler::VisitPushContext() {
  BaselineAssembler::ScratchRegisterScope scratch_scope(&basm_);
  Register context = scratch_scope.AcquireScratch();
  __ LoadContext(context);
  __ StoreContext(kInterpreterAccumulatorRegister);
  StoreRegister(0, context);
}

void BaselineCompiler::VisitPopContext() {
  BaselineAssembler::ScratchRegisterScope scratch_scope(&basm_);
  Register context = scratch_scope.AcquireScratch();
  LoadRegister(context, 0);
  __ StoreContext(context);
}

void BaselineCompiler::VisitLdaContextSlot() {
  BaselineAssembler::ScratchRegisterScope scratch_scope(&basm_);
  Register context = scratch_scope.AcquireScratch();
  LoadRegister(context, 0);
  uint32_t index = Index(1);
  uint32_t depth = Uint(2);
  __ LdaContextSlot(context, index, depth);
}

void BaselineCompiler::VisitLdaScriptContextSlot() {
  BaselineAssembler::ScratchRegisterScope scratch_scope(&basm_);
  Register context = scratch_scope.AcquireScratch();
  Label done;
  LoadRegister(context, 0);
  uint32_t index = Index(1);
  uint32_t depth = Uint(2);
  __ LdaContextSlot(context, index, depth,
                    BaselineAssembler::CompressionMode::kForceDecompression);
  __ JumpIfSmi(kInterpreterAccumulatorRegister, &done);
  __ JumpIfObjectTypeFast(kNotEqual, kInterpreterAccumulatorRegister,
                          HEAP_NUMBER_TYPE, &done, Label::kNear);
  CallBuiltin<Builtin::kAllocateIfMutableHeapNumberScriptContextSlot>(
      kInterpreterAccumulatorRegister,  // heap number
      context,                          // context
      Smi::FromInt(index));             // slot
  __ Bind(&done);
}

void BaselineCompiler::VisitLdaImmutableContextSlot() { VisitLdaContextSlot(); }

void BaselineCompiler::VisitLdaCurrentContextSlot() {
  BaselineAssembler::ScratchRegisterScope scratch_scope(&basm_);
  Register context = scratch_scope.AcquireScratch();
  __ LoadContext(context);
  __ LoadTaggedField(kInterpreterAccumulatorRegister, context,
                     Context::OffsetOfElementAt(Index(0)));
}

void BaselineCompiler::VisitLdaCurrentScriptContextSlot() {
  BaselineAssembler::ScratchRegisterScope scratch_scope(&basm_);
  Register context = scratch_scope.AcquireScratch();
  Label done;
  uint32_t index = Index(0);
  __ LoadContext(context);
  __ LoadTaggedField(kInterpreterAccumulatorRegister, context,
                     Context::OffsetOfElementAt(index));
  __ JumpIfSmi(kInterpreterAccumulatorRegister, &done);
  __ JumpIfObjectTypeFast(kNotEqual, kInterpreterAccumulatorRegister,
                          HEAP_NUMBER_TYPE, &done, Label::kNear);
  CallBuiltin<Builtin::kAllocateIfMutableHeapNumberScriptContextSlot>(
      kInterpreterAccumulatorRegister,  // heap number
      context,                          // context
      Smi::FromInt(index));             // slot
  __ Bind(&done);
}

void BaselineCompiler::VisitLdaImmutableCurrentContextSlot() {
  VisitLdaCurrentContextSlot();
}

void BaselineCompiler::VisitStaContextSlot() {
  Register value = WriteBarrierDescriptor::ValueRegister();
  Register context = WriteBarrierDescriptor::ObjectRegister();
  DCHECK(!AreAliased(value, context, kInterpreterAccumulatorRegister));
  __ Move(value, kInterpreterAccumulatorRegister);
  LoadRegister(context, 0);
  uint32_t index = Index(1);
  uint32_t depth = Uint(2);
  __ StaContextSlot(context, value, index, depth);
}

void BaselineCompiler::VisitStaCurrentContextSlot() {
  Register value = WriteBarrierDescriptor::ValueRegister();
  Register context = WriteBarrierDescriptor::ObjectRegister();
  DCHECK(!AreAliased(value, context, kInterpreterAccumulatorRegister));
  __ Move(value, kInterpreterAccumulatorRegister);
  __ LoadContext(context);
  __ StoreTaggedFieldWithWriteBarrier(
      context, Context::OffsetOfElementAt(Index(0)), value);
}

void BaselineCompiler::VisitStaScriptContextSlot() {
  Register value = WriteBarrierDescriptor::ValueRegister();
  Register context = WriteBarrierDescriptor::ObjectRegister();
  DCHECK(!AreAliased(value, context, kInterpreterAccumulatorRegister));
  __ Move(value, kInterpreterAccumulatorRegister);
  LoadRegister(context, 0);
  SaveAccumulatorScope accumulator_scope(this, &basm_);
  CallBuiltin<Builtin::kStoreScriptContextSlotBaseline>(
      context,           // context
      value,             // value
      IndexAsSmi(1),     // slot
      UintAsTagged(2));  // depth
}

void BaselineCompiler::VisitStaCurrentScriptContextSlot() {
  Register value = WriteBarrierDescriptor::ValueRegister();
  DCHECK(!AreAliased(value, kInterpreterAccumulatorRegister));
  SaveAccumulatorScope accumulator_scope(this, &basm_);
  __ Move(value, kInterpreterAccumulatorRegister);
  CallBuiltin<Builtin::kStoreCurrentScriptContextSlotBaseline>(
      value,           // value
      IndexAsSmi(0));  // slot
}

void BaselineCompiler::VisitLdaLookupSlot() {
  CallRuntime(Runtime::kLoadLookupSlot, Constant<Name>(0));
}

void BaselineCompiler::VisitLdaLookupContextSlot() {
  CallBuiltin<Builtin::kLookupContextBaseline>(
      Constant<Name>(0), UintAsTagged(2), IndexAsTagged(1));
}

void BaselineCompiler::VisitLdaLookupScriptContextSlot() {
  CallBuiltin<Builtin::kLookupScriptContextBaseline>(
      Constant<Name>(0), UintAsTagged(2), IndexAsTagged(1));
}

void BaselineCompiler::VisitLdaLookupGlobalSlot() {
  CallBuiltin<Builtin::kLookupGlobalICBaseline>(
      Constant<Name>(0), UintAsTagged(2), IndexAsTagged(1));
}

void BaselineCompiler::VisitLdaLookupSlotInsideTypeof() {
  CallRuntime(Runtime::kLoadLookupSlotInsideTypeof, Constant<Name>(0));
}

void BaselineCompiler::VisitLdaLookupContextSlotInsideTypeof() {
  CallBuiltin<Builtin::kLookupContextInsideTypeofBaseline>(
      Constant<Name>(0), UintAsTagged(2), IndexAsTagged(1));
}

void BaselineCompiler::VisitLdaLookupScriptContextSlotInsideTypeof() {
  CallBuiltin<Builtin::kLookupScriptContextInsideTypeofBaseline>(
      Constant<Name>(0), UintAsTagged(2), IndexAsTagged(1));
}

void BaselineCompiler::VisitLdaLookupGlobalSlotInsideTypeof() {
  CallBuiltin<Builtin::kLookupGlobalICInsideTypeofBaseline>(
      Constant<Name>(0), UintAsTagged(2), IndexAsTagged(1));
}

void BaselineCompiler::VisitStaLookupSlot() {
  uint32_t flags = Flag8(1);
  Runtime::FunctionId function_id;
  if (flags & interpreter::StoreLookupSlotFlags::LanguageModeBit::kMask) {
    function_id = Runtime::kStoreLookupSlot_Strict;
  } else if (flags &
             interpreter::StoreLookupSlotFlags::LookupHoistingModeBit::kMask) {
    function_id = Runtime::kStoreLookupSlot_SloppyHoisting;
  } else {
    function_id = Runtime::kStoreLookupSlot_Sloppy;
  }
  CallRuntime(function_id, Constant<Name>(0),    // name
              kInterpreterAccumulatorRegister);  // value
}

void BaselineCompiler::VisitLdar() {
  LoadRegister(kInterpreterAccumulatorRegister, 0);
}

void BaselineCompiler::VisitStar() {
  StoreRegister(0, kInterpreterAccumulatorRegister);
}

#define SHORT_STAR_VISITOR(Name, ...)                                         \
  void BaselineCompiler::Visit##Name() {                                      \
    __ StoreRegister(
```