Response:
Let's break down the thought process for analyzing this V8 C++ code snippet.

1. **Understanding the Goal:** The request asks for a functional summary of the provided C++ code, along with examples, error scenarios, and specific handling of Torque files. It's important to remember this is the *first part* of a larger set.

2. **Initial Scan and Keywords:**  A quick scan reveals several important keywords and concepts:
    * `builtins-ppc.cc`:  This immediately tells us it's related to built-in functions for the PPC architecture within V8.
    * `#include`:  Indicates dependencies on other V8 components like API arguments, code generation, debugging, deoptimization, execution frames, heap management, logging, objects, and runtime. The inclusion of WASM headers suggests some involvement with WebAssembly.
    * `namespace v8 { namespace internal {`:  Confirms this is internal V8 code, not part of the public API.
    * `MacroAssembler`: A key V8 class for emitting machine code. This suggests the code is about low-level function implementations.
    * `Register`:  References to CPU registers (like `r3`, `r4`, `ip`, `fp`, `sp`).
    * `Operand`:  Represents operands for machine instructions.
    * `Label`:  Used for branching within the generated code.
    * `Builtins::Generate_*`:  A common pattern in V8 for defining entry points for built-in JavaScript functions.
    * `TailCallBuiltin`, `CallBuiltin`, `CallRuntime`:  Mechanisms for invoking other built-in functions or runtime functions.
    * `StackFrame`:  Deals with managing the call stack.
    * `JSFunction`, `SharedFunctionInfo`, `FeedbackVector`, `BytecodeArray`: V8's internal representations of JavaScript functions and their associated data.
    * `OSREntry`, `BaselineOrInterpreterEntry`:  Keywords related to optimizing code execution at runtime.

3. **Section-by-Section Analysis (and Hypothesis Formation):**

    * **Headers and Namespaces:**  Recognize the purpose of including necessary V8 components. The namespace structure is standard.
    * **Helper Functions (within the anonymous namespace):**
        * `AssertCodeIsBaseline`: Likely a debug-only assertion to ensure a code object is marked as baseline (an optimization tier).
        * `CheckSharedFunctionInfoBytecodeOrBaseline`:  Seems to determine if a function's data is either bytecode (interpreter) or baseline code. The `v8_flags.debug_code` check suggests conditional behavior.
        * `GetSharedFunctionInfoBytecodeOrBaseline`:  A more complex version of the above, loading data and handling potential "unavailable" cases.
        * `Generate_OSREntry`:  Focuses on "On-Stack Replacement," a key optimization technique where execution switches from interpreter/baseline to optimized code. The `mtlr(ip)` suggests setting the link register for a return.
        * `ResetSharedFunctionInfoAge`, `ResetJSFunctionAge`, `ResetFeedbackVectorOsrUrgency`: These appear to be related to managing optimization state and potentially triggering re-optimization.
        * `Generate_BaselineOrInterpreterEntry`: This looks crucial. It determines whether to enter a function using baseline code or the interpreter, possibly performing On-Stack Replacement (OSR). The `is_osr` flag is important.
        * **Hypothesis:** These helper functions are the building blocks for implementing built-in function logic, especially around optimization and execution tiers.

    * **`Builtins::Generate_Adaptor`:**  This pattern is common for creating "adaptor" functions, which often handle transitions between different calling conventions or execution environments.
        * **Hypothesis:** It prepares for calling a C++ function from JavaScript.

    * **More Helper Functions (within the anonymous namespace):**
        * `Generate_PushArguments`:  A utility function for copying arguments onto the stack. The `ArgumentsElementType` enum suggests handling both raw values and handles (pointers).
        * `Generate_JSBuiltinsConstructStubHelper`:  This strongly suggests the implementation of the `new` operator in JavaScript for built-in constructors. The stack manipulation and `InvokeFunctionWithNewTarget` are key indicators.
        * `OnStackReplacement`:  Further confirms the importance of OSR. It describes the process of switching to optimized code. The `source` parameter suggests distinguishing between interpreter and baseline OSR.
        * **Hypothesis:** These functions implement fundamental JavaScript mechanisms like function calls and object construction.

    * **`Builtins::Generate_JSConstructStubGeneric`:** Another variation of the constructor stub, likely handling more general cases or specific types of constructors. The logic for handling derived classes is apparent.
    * **`Builtins::Generate_JSBuiltinsConstructStub`:**  A specific entry point for the built-in constructor stub, likely calling the `Helper` function.
    * **`Builtins::Generate_ResumeGeneratorTrampoline`:** This clearly deals with the implementation of JavaScript generators (`function*`). The manipulation of the generator object's state and the handling of stepping/debugging are evident.
    * **`Builtins::Generate_ConstructedNonConstructable`:**  Handles the error case where a non-constructor is called with `new`.
    * **`Generate_JSEntryVariant`:**  A very important function!  The "JSEntry" name signifies the entry point from C++ into the JavaScript VM. The handling of stack frames, callee-saved registers, and the `type` parameter suggest different entry scenarios. The microtask queue mention points to event loop integration.
        * **Hypothesis:** This function sets up the environment for executing JavaScript code called from native code.

4. **Torque Consideration:** The request specifically asks about `.tq` files. The code doesn't directly show `.tq` usage. The thought should be: "This file is C++, and it seems to implement low-level built-in functionality. Torque is a higher-level language for *defining* built-ins. Therefore, this `.cc` file likely *implements* built-ins that *might* be defined in `.tq` files elsewhere."

5. **JavaScript Examples:** Based on the function names and the underlying operations, it's possible to construct JavaScript examples. For instance, `JSConstructStubGeneric` clearly relates to the `new` operator. `ResumeGeneratorTrampoline` relates to generator function execution.

6. **Error Scenarios:** Think about what could go wrong in the implemented logic. Stack overflow is explicitly checked. Calling a non-constructor with `new` is handled. The code also includes assertions, which indicate potential internal errors.

7. **Input/Output (Code Logic):** Focus on the functions that perform computations. `Generate_BaselineOrInterpreterEntry` takes the current execution state and decides where to jump next. `Generate_OSREntry` takes an entry address and offset and sets up a jump.

8. **Summarization:** Combine the understanding of individual functions into a coherent description of the file's overall purpose. Emphasize the role in implementing built-in functions, handling optimization, and managing the execution environment.

9. **Refinement:** Review the analysis, ensuring that the explanations are clear, concise, and address all aspects of the request. For instance, explicitly state the lack of direct `.tq` code in this file.

This systematic approach, moving from high-level understanding to detailed analysis, helps in dissecting and explaining complex code like this V8 built-ins file.
好的，让我们来分析一下 `v8/src/builtins/ppc/builtins-ppc.cc` 这个文件的功能。

**文件功能归纳：**

`v8/src/builtins/ppc/builtins-ppc.cc` 文件是 V8 JavaScript 引擎中针对 **PPC64 (PowerPC 64-bit)** 架构的 **内置函数 (Built-ins)** 的实现代码。它包含了使用汇编语言（通过 `MacroAssembler`）编写的、在 JavaScript 运行时环境中被频繁调用的核心功能的实现。

**具体功能分解：**

1. **架构特定优化:**  由于文件路径中包含 `ppc`，很明显这些内置函数是为 PPC64 架构特别优化的，可能会利用该架构的特定指令和特性来提升性能。

2. **实现 JavaScript 核心功能:**  文件中包含了许多用于实现 JavaScript 关键特性的内置函数，例如：
   * **函数调用和构造:** `Generate_Adaptor`, `Generate_JSBuiltinsConstructStubHelper`, `Generate_JSConstructStubGeneric`, `Generate_JSBuiltinsConstructStub` 等函数处理 JavaScript 函数的调用，特别是构造函数 (`new` 关键字) 的调用过程。
   * **生成器 (Generators):** `Generate_ResumeGeneratorTrampoline` 负责恢复执行被暂停的生成器函数。
   * **异常处理:**  虽然代码中没有明显的异常抛出，但其参与了构建异常处理框架。
   * **优化执行:**  `Generate_OSREntry` (On-Stack Replacement) 和 `Generate_BaselineOrInterpreterEntry` 与代码的优化执行密切相关，实现了从解释执行到更高效的基线或优化代码的切换。
   * **堆栈管理:**  代码中使用了 `StackFrame` 相关的类，说明它负责管理 JavaScript 函数调用时的堆栈帧。
   * **参数处理:** `Generate_PushArguments` 用于将参数推送到堆栈上。

3. **与解释器和编译器交互:**  代码中涉及 `InterpreterData` 和 `Code` 对象，这表明内置函数需要与 V8 的解释器 (Ignition) 和编译器 (TurboFan) 进行交互，以便在不同的执行阶段进行切换和优化。

4. **调试支持:**  代码中包含对调试的支持，例如在 `Generate_ResumeGeneratorTrampoline` 中检查调试状态并调用相应的运行时函数。

5. **C++ 与 JavaScript 的桥梁:**  `Generate_JSEntryVariant` 充当了从 C++ 代码进入 JavaScript 代码的入口点。

**关于 .tq 结尾：**

你提到如果文件以 `.tq` 结尾，那么它是 V8 Torque 源代码。Torque 是 V8 用于定义内置函数的一种高级类型化的领域特定语言。

* **如果 `v8/src/builtins/ppc/builtins-ppc.cc` 以 `.tq` 结尾，那么它的内容将会是用 Torque 语言编写的内置函数定义。** Torque 代码会被编译成 C++ 代码，最终链接到 V8 引擎中。

**与 JavaScript 功能的关系及示例：**

由于 `v8/src/builtins/ppc/builtins-ppc.cc` 实现了 JavaScript 的核心功能，它与你每天编写的 JavaScript 代码息息相关。以下是一些与代码片段中功能相关的 JavaScript 示例：

1. **函数调用和构造：**

   ```javascript
   function greet(name) {
     console.log("Hello, " + name + "!");
   }

   greet("World"); // 调用普通函数

   function Person(name) {
     this.name = name;
   }

   const person = new Person("Alice"); // 调用构造函数
   ```

   `Generate_Adaptor`, `Generate_JSBuiltinsConstructStubHelper` 等函数就参与了上述两种函数调用过程的底层实现。

2. **生成器：**

   ```javascript
   function* numberGenerator() {
     yield 1;
     yield 2;
     yield 3;
   }

   const generator = numberGenerator();
   console.log(generator.next()); // { value: 1, done: false }
   console.log(generator.next()); // { value: 2, done: false }
   ```

   `Generate_ResumeGeneratorTrampoline` 负责在每次调用 `generator.next()` 时恢复生成器的执行。

3. **`new` 关键字的行为：**

   ```javascript
   class MyClass {
     constructor(value) {
       this.value = value;
     }
   }

   const instance = new MyClass(10);
   console.log(instance.value); // 10
   ```

   `Generate_JSConstructStubGeneric` 和相关的函数实现了 `new` 关键字背后的对象创建和构造过程。

**代码逻辑推理（假设输入与输出）：**

让我们以 `Generate_BaselineOrInterpreterEntry` 函数为例进行逻辑推理。

**假设输入：**

* 当前执行处于一个解释器框架 (interpreter frame)。
* `next_bytecode` 为 `false`，表示要从当前字节码开始执行。
* SharedFunctionInfo 中存在基线代码 (baseline code)。

**代码逻辑：**

1. 加载当前函数的 `JSFunction` 对象。
2. 从 `JSFunction` 对象中获取 `SharedFunctionInfo`。
3. 检查 `SharedFunctionInfo` 中是否存在基线代码。
4. 如果存在基线代码：
   * 从堆栈帧中获取字节码偏移量 (bytecode offset)。
   * 将字节码偏移量转换为基线代码中的 PC 值 (程序计数器)。
   * 将当前的解释器框架转换为基线框架。
   * 跳转到基线代码中计算出的 PC 值继续执行。
5. 如果不存在基线代码：
   * 调用 `TailCallBuiltin(Builtin::kInterpreterEnterAtBytecode)`，继续在解释器中执行。

**假设输出：**

* 如果存在基线代码，程序的执行流程将切换到基线代码，从与当前字节码偏移量对应的位置开始执行。
* 如果不存在基线代码，程序将继续在解释器中执行。

**用户常见的编程错误举例说明：**

1. **尝试 `new` 一个非构造函数：**

   ```javascript
   function notAConstructor() {
     return 10;
   }

   try {
     const obj = new notAConstructor(); // TypeError: notAConstructor is not a constructor
   } catch (e) {
     console.error(e);
   }
   ```

   `Builtins::Generate_ConstructedNonConstructable` 函数就负责处理这种错误情况，抛出一个 `TypeError`。

2. **在生成器函数中使用 `new`：**

   ```javascript
   function* myGenerator() {
     yield 1;
   }

   try {
     const gen = new myGenerator(); // TypeError: myGenerator is not a constructor
   } catch (e) {
     console.error(e);
   }
   ```

   生成器函数是不可构造的，V8 的内置函数会强制执行这个规则。

**总结 `v8/src/builtins/ppc/builtins-ppc.cc` 的功能 (第 1 部分):**

这部分代码主要负责实现 PPC64 架构下 JavaScript 引擎的核心内置函数，特别是与函数调用、构造函数、代码优化执行 (基线代码和 OSR) 相关的底层机制。它体现了 V8 引擎为了提高性能而进行的架构特定优化，并展示了 C++ 代码如何与 JavaScript 运行时环境紧密结合。 其中 `Generate_BaselineOrInterpreterEntry` 负责决定代码执行的入口点，根据是否存在基线代码选择进入解释器还是基线代码执行。 `Generate_JSConstructStubGeneric` 实现了 `new` 关键字的基本行为。

### 提示词
```
这是目录为v8/src/builtins/ppc/builtins-ppc.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/ppc/builtins-ppc.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#if V8_TARGET_ARCH_PPC64

#include "src/api/api-arguments.h"
#include "src/builtins/builtins-inl.h"
#include "src/codegen/code-factory.h"
#include "src/codegen/interface-descriptors-inl.h"
// For interpreter_entry_return_pc_offset. TODO(jkummerow): Drop.
#include "src/codegen/macro-assembler-inl.h"
#include "src/codegen/register-configuration.h"
#include "src/debug/debug.h"
#include "src/deoptimizer/deoptimizer.h"
#include "src/execution/frame-constants.h"
#include "src/execution/frames.h"
#include "src/heap/heap-inl.h"
#include "src/logging/counters.h"
#include "src/objects/cell.h"
#include "src/objects/foreign.h"
#include "src/objects/heap-number.h"
#include "src/objects/js-generator.h"
#include "src/objects/smi.h"
#include "src/runtime/runtime.h"

#if V8_ENABLE_WEBASSEMBLY
#include "src/wasm/baseline/liftoff-assembler-defs.h"
#include "src/wasm/wasm-linkage.h"
#include "src/wasm/wasm-objects.h"
#endif  // V8_ENABLE_WEBASSEMBLY

namespace v8 {
namespace internal {

#define __ ACCESS_MASM(masm)
namespace {

static void AssertCodeIsBaseline(MacroAssembler* masm, Register code,
                                 Register scratch) {
  DCHECK(!AreAliased(code, scratch));
  // Verify that the code kind is baseline code via the CodeKind.
  __ LoadU32(scratch, FieldMemOperand(code, Code::kFlagsOffset));
  __ DecodeField<Code::KindField>(scratch);
  __ CmpS64(scratch, Operand(static_cast<int>(CodeKind::BASELINE)), r0);
  __ Assert(eq, AbortReason::kExpectedBaselineData);
}

static void CheckSharedFunctionInfoBytecodeOrBaseline(MacroAssembler* masm,
                                                      Register data,
                                                      Register scratch,
                                                      Label* is_baseline,
                                                      Label* is_bytecode) {
  DCHECK(!AreAliased(r0, scratch));

#if V8_STATIC_ROOTS_BOOL
  __ IsObjectTypeFast(data, scratch, CODE_TYPE, r0);
#else
  __ CompareObjectType(data, scratch, scratch, CODE_TYPE);
#endif  // V8_STATIC_ROOTS_BOOL
  if (v8_flags.debug_code) {
    Label not_baseline;
    __ b(ne, &not_baseline);
    AssertCodeIsBaseline(masm, data, scratch);
    __ b(eq, is_baseline);
    __ bind(&not_baseline);
  } else {
    __ b(eq, is_baseline);
  }

#if V8_STATIC_ROOTS_BOOL
  // scratch already contains the compressed map.
  __ CompareInstanceTypeWithUniqueCompressedMap(scratch, Register::no_reg(),
                                                INTERPRETER_DATA_TYPE);
#else
  // scratch already contains the instance type.
  __ CmpU64(scratch, Operand(INTERPRETER_DATA_TYPE), r0);
#endif  // V8_STATIC_ROOTS_BOOL
  __ b(ne, is_bytecode);
}

static void GetSharedFunctionInfoBytecodeOrBaseline(
    MacroAssembler* masm, Register sfi, Register bytecode, Register scratch1,
    Label* is_baseline, Label* is_unavailable) {
  USE(GetSharedFunctionInfoBytecodeOrBaseline);
  DCHECK(!AreAliased(bytecode, scratch1));
  ASM_CODE_COMMENT(masm);
  Label done;
  Register data = bytecode;
  __ LoadTrustedPointerField(
      data,
      FieldMemOperand(sfi, SharedFunctionInfo::kTrustedFunctionDataOffset),
      kUnknownIndirectPointerTag, r0);

  if (V8_JITLESS_BOOL) {
    __ IsObjectType(data, scratch1, scratch1, INTERPRETER_DATA_TYPE);
    __ b(ne, &done);
  } else {
    CheckSharedFunctionInfoBytecodeOrBaseline(masm, data, scratch1, is_baseline,
                                              &done);
  }

  __ LoadTrustedPointerField(
      bytecode, FieldMemOperand(data, InterpreterData::kBytecodeArrayOffset),
      kBytecodeArrayIndirectPointerTag, scratch1);

  __ bind(&done);
  __ IsObjectType(bytecode, scratch1, scratch1, BYTECODE_ARRAY_TYPE);
  __ b(ne, is_unavailable);
}

void Generate_OSREntry(MacroAssembler* masm, Register entry_address,
                       intptr_t offset) {
  __ AddS64(ip, entry_address, Operand(offset), r0);
  __ mtlr(ip);

  // "return" to the OSR entry point of the function.
  __ Ret();
}

void ResetSharedFunctionInfoAge(MacroAssembler* masm, Register sfi,
                                Register scratch) {
  DCHECK(!AreAliased(sfi, scratch));
  __ mov(scratch, Operand(0));
  __ StoreU16(scratch, FieldMemOperand(sfi, SharedFunctionInfo::kAgeOffset),
              no_reg);
}

void ResetJSFunctionAge(MacroAssembler* masm, Register js_function,
                        Register scratch1, Register scratch2) {
  __ LoadTaggedField(
      scratch1,
      FieldMemOperand(js_function, JSFunction::kSharedFunctionInfoOffset),
      scratch2);
  ResetSharedFunctionInfoAge(masm, scratch1, scratch2);
}

void ResetFeedbackVectorOsrUrgency(MacroAssembler* masm,
                                   Register feedback_vector, Register scratch1,
                                   Register scratch2) {
  DCHECK(!AreAliased(feedback_vector, scratch1));
  __ LoadU8(scratch1,
            FieldMemOperand(feedback_vector, FeedbackVector::kOsrStateOffset),
            scratch2);
  __ andi(
      scratch1, scratch1,
      Operand(static_cast<uint8_t>(~FeedbackVector::OsrUrgencyBits::kMask)));
  __ StoreU8(scratch1,
             FieldMemOperand(feedback_vector, FeedbackVector::kOsrStateOffset),
             scratch2);
}

// Restarts execution either at the current or next (in execution order)
// bytecode. If there is baseline code on the shared function info, converts an
// interpreter frame into a baseline frame and continues execution in baseline
// code. Otherwise execution continues with bytecode.
void Generate_BaselineOrInterpreterEntry(MacroAssembler* masm,
                                         bool next_bytecode,
                                         bool is_osr = false) {
  Label start;
  __ bind(&start);

  // Get function from the frame.
  Register closure = r4;
  __ LoadU64(closure, MemOperand(fp, StandardFrameConstants::kFunctionOffset),
             r0);

  // Get the InstructionStream object from the shared function info.
  Register code_obj = r9;
  __ LoadTaggedField(
      code_obj, FieldMemOperand(closure, JSFunction::kSharedFunctionInfoOffset),
      r0);

  if (is_osr) {
    ResetSharedFunctionInfoAge(masm, code_obj, r6);
  }

  __ LoadTrustedPointerField(
      code_obj,
      FieldMemOperand(code_obj, SharedFunctionInfo::kTrustedFunctionDataOffset),
      kUnknownIndirectPointerTag, r0);

  // Check if we have baseline code. For OSR entry it is safe to assume we
  // always have baseline code.
  if (!is_osr) {
    Label start_with_baseline;
    __ IsObjectType(code_obj, r6, r6, CODE_TYPE);
    __ b(eq, &start_with_baseline);

    // Start with bytecode as there is no baseline code.
    Builtin builtin = next_bytecode ? Builtin::kInterpreterEnterAtNextBytecode
                                    : Builtin::kInterpreterEnterAtBytecode;
    __ TailCallBuiltin(builtin);

    // Start with baseline code.
    __ bind(&start_with_baseline);
  } else if (v8_flags.debug_code) {
    __ IsObjectType(code_obj, r6, r6, CODE_TYPE);
    __ Assert(eq, AbortReason::kExpectedBaselineData);
  }

  if (v8_flags.debug_code) {
    AssertCodeIsBaseline(masm, code_obj, r6);
  }

  // Load the feedback cell and vector.
  Register feedback_cell = r5;
  Register feedback_vector = ip;
  __ LoadTaggedField(feedback_cell,
                     FieldMemOperand(closure, JSFunction::kFeedbackCellOffset),
                     r0);
  __ LoadTaggedField(feedback_vector,
                     FieldMemOperand(feedback_cell, FeedbackCell::kValueOffset),
                     r0);

  Label install_baseline_code;
  // Check if feedback vector is valid. If not, call prepare for baseline to
  // allocate it.
  __ IsObjectType(feedback_vector, r6, r6, FEEDBACK_VECTOR_TYPE);
  __ b(ne, &install_baseline_code);

  // Save BytecodeOffset from the stack frame.
  __ LoadU64(kInterpreterBytecodeOffsetRegister,
             MemOperand(fp, InterpreterFrameConstants::kBytecodeOffsetFromFp));
  __ SmiUntag(kInterpreterBytecodeOffsetRegister);
  // Replace bytecode offset with feedback cell.
  static_assert(InterpreterFrameConstants::kBytecodeOffsetFromFp ==
                BaselineFrameConstants::kFeedbackCellFromFp);
  __ StoreU64(feedback_cell,
              MemOperand(fp, BaselineFrameConstants::kFeedbackCellFromFp));
  feedback_cell = no_reg;
  // Update feedback vector cache.
  static_assert(InterpreterFrameConstants::kFeedbackVectorFromFp ==
                BaselineFrameConstants::kFeedbackVectorFromFp);
  __ StoreU64(feedback_vector,
              MemOperand(fp, InterpreterFrameConstants::kFeedbackVectorFromFp));
  feedback_vector = no_reg;

  // Compute baseline pc for bytecode offset.
  ExternalReference get_baseline_pc_extref;
  if (next_bytecode || is_osr) {
    get_baseline_pc_extref =
        ExternalReference::baseline_pc_for_next_executed_bytecode();
  } else {
    get_baseline_pc_extref =
        ExternalReference::baseline_pc_for_bytecode_offset();
  }
  Register get_baseline_pc = r6;
  __ Move(get_baseline_pc, get_baseline_pc_extref);

  // If the code deoptimizes during the implicit function entry stack interrupt
  // check, it will have a bailout ID of kFunctionEntryBytecodeOffset, which is
  // not a valid bytecode offset.
  // TODO(pthier): Investigate if it is feasible to handle this special case
  // in TurboFan instead of here.
  Label valid_bytecode_offset, function_entry_bytecode;
  if (!is_osr) {
    __ CmpS64(kInterpreterBytecodeOffsetRegister,
              Operand(BytecodeArray::kHeaderSize - kHeapObjectTag +
                      kFunctionEntryBytecodeOffset),
              r0);
    __ b(eq, &function_entry_bytecode);
  }

  __ SubS64(kInterpreterBytecodeOffsetRegister,
            kInterpreterBytecodeOffsetRegister,
            Operand(BytecodeArray::kHeaderSize - kHeapObjectTag));

  __ bind(&valid_bytecode_offset);
  // Get bytecode array from the stack frame.
  __ LoadU64(kInterpreterBytecodeArrayRegister,
             MemOperand(fp, InterpreterFrameConstants::kBytecodeArrayFromFp));
  // Save the accumulator register, since it's clobbered by the below call.
  __ Push(kInterpreterAccumulatorRegister);
  __ Push(code_obj);
  {
    __ mr(kCArgRegs[0], code_obj);
    __ mr(kCArgRegs[1], kInterpreterBytecodeOffsetRegister);
    __ mr(kCArgRegs[2], kInterpreterBytecodeArrayRegister);
    FrameScope scope(masm, StackFrame::INTERNAL);
    __ PrepareCallCFunction(4, 0, ip);
    __ CallCFunction(get_baseline_pc, 3, 0);
  }
  __ Pop(code_obj);
  __ LoadCodeInstructionStart(code_obj, code_obj);
  __ AddS64(code_obj, code_obj, kReturnRegister0);
  __ Pop(kInterpreterAccumulatorRegister);

  if (is_osr) {
    Generate_OSREntry(masm, code_obj, 0);
  } else {
    __ Jump(code_obj);
  }
  __ Trap();  // Unreachable.

  if (!is_osr) {
    __ bind(&function_entry_bytecode);
    // If the bytecode offset is kFunctionEntryOffset, get the start address of
    // the first bytecode.
    __ mov(kInterpreterBytecodeOffsetRegister, Operand(0));
    if (next_bytecode) {
      __ Move(get_baseline_pc,
              ExternalReference::baseline_pc_for_bytecode_offset());
    }
    __ b(&valid_bytecode_offset);
  }

  __ bind(&install_baseline_code);
  {
    FrameScope scope(masm, StackFrame::INTERNAL);
    __ Push(kInterpreterAccumulatorRegister);
    __ Push(closure);
    __ CallRuntime(Runtime::kInstallBaselineCode, 1);
    __ Pop(kInterpreterAccumulatorRegister);
  }
  // Retry from the start after installing baseline code.
  __ b(&start);
}

}  // namespace

void Builtins::Generate_Adaptor(MacroAssembler* masm,
                                int formal_parameter_count, Address address) {
  __ Move(kJavaScriptCallExtraArg1Register, ExternalReference::Create(address));
  __ TailCallBuiltin(
      Builtins::AdaptorWithBuiltinExitFrame(formal_parameter_count));
}

namespace {

enum class ArgumentsElementType {
  kRaw,    // Push arguments as they are.
  kHandle  // Dereference arguments before pushing.
};

void Generate_PushArguments(MacroAssembler* masm, Register array, Register argc,
                            Register scratch,
                            ArgumentsElementType element_type) {
  DCHECK(!AreAliased(array, argc, scratch));
  Label loop, done;
  __ subi(scratch, argc, Operand(kJSArgcReceiverSlots));
  __ cmpi(scratch, Operand::Zero());
  __ beq(&done);
  __ mtctr(scratch);
  __ ShiftLeftU64(scratch, scratch, Operand(kSystemPointerSizeLog2));
  __ add(scratch, array, scratch);

  __ bind(&loop);
  __ LoadU64WithUpdate(ip, MemOperand(scratch, -kSystemPointerSize));
  if (element_type == ArgumentsElementType::kHandle) {
    __ LoadU64(ip, MemOperand(ip));
  }
  __ push(ip);
  __ bdnz(&loop);
  __ bind(&done);
}

void Generate_JSBuiltinsConstructStubHelper(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- r3     : number of arguments
  //  -- r4     : constructor function
  //  -- r6     : new target
  //  -- cp     : context
  //  -- lr     : return address
  //  -- sp[...]: constructor arguments
  // -----------------------------------

  Register scratch = r5;

  Label stack_overflow;

  __ StackOverflowCheck(r3, scratch, &stack_overflow);
  // Enter a construct frame.
  {
    FrameAndConstantPoolScope scope(masm, StackFrame::CONSTRUCT);

    // Preserve the incoming parameters on the stack.

    __ Push(cp, r3);

    // TODO(victorgomes): When the arguments adaptor is completely removed, we
    // should get the formal parameter count and copy the arguments in its
    // correct position (including any undefined), instead of delaying this to
    // InvokeFunction.

    // Set up pointer to first argument (skip receiver).
    __ addi(
        r7, fp,
        Operand(StandardFrameConstants::kCallerSPOffset + kSystemPointerSize));
    // Copy arguments and receiver to the expression stack.
    // r7: Pointer to start of arguments.
    // r3: Number of arguments.
    Generate_PushArguments(masm, r7, r3, r8, ArgumentsElementType::kRaw);

    // The receiver for the builtin/api call.
    __ PushRoot(RootIndex::kTheHoleValue);

    // Call the function.
    // r3: number of arguments (untagged)
    // r4: constructor function
    // r6: new target
    {
      ConstantPoolUnavailableScope constant_pool_unavailable(masm);
      __ InvokeFunctionWithNewTarget(r4, r6, r3, InvokeType::kCall);
    }

    // Restore context from the frame.
    __ LoadU64(cp, MemOperand(fp, ConstructFrameConstants::kContextOffset));
    // Restore arguments count from the frame.
    __ LoadU64(scratch, MemOperand(fp, ConstructFrameConstants::kLengthOffset));

    // Leave construct frame.
  }
  // Remove caller arguments from the stack and return.
  __ DropArguments(scratch);
  __ blr();

  __ bind(&stack_overflow);
  {
    FrameScope scope(masm, StackFrame::INTERNAL);
    __ CallRuntime(Runtime::kThrowStackOverflow);
    __ bkpt(0);  // Unreachable code.
  }
}

enum class OsrSourceTier {
  kInterpreter,
  kBaseline,
};

void OnStackReplacement(MacroAssembler* masm, OsrSourceTier source,
                        Register maybe_target_code) {
  Label jump_to_optimized_code;
  {
    // If maybe_target_code is not null, no need to call into runtime. A
    // precondition here is: if maybe_target_code is an InstructionStream
    // object, it must NOT be marked_for_deoptimization (callers must ensure
    // this).
    __ CmpSmiLiteral(maybe_target_code, Smi::zero(), r0);
    __ bne(&jump_to_optimized_code);
  }

  ASM_CODE_COMMENT(masm);
  {
    FrameScope scope(masm, StackFrame::INTERNAL);
    __ CallRuntime(Runtime::kCompileOptimizedOSR);
  }

  // If the code object is null, just return to the caller.
  __ CmpSmiLiteral(r3, Smi::zero(), r0);
  __ bne(&jump_to_optimized_code);
  __ Ret();

  __ bind(&jump_to_optimized_code);
  DCHECK_EQ(maybe_target_code, r3);  // Already in the right spot.

  // OSR entry tracing.
  {
    Label next;
    __ Move(r4, ExternalReference::address_of_log_or_trace_osr());
    __ LoadU8(r4, MemOperand(r4));
    __ andi(r0, r4, Operand(0xFF));  // Mask to the LSB.
    __ beq(&next, cr0);

    {
      FrameAndConstantPoolScope scope(masm, StackFrame::INTERNAL);
      __ Push(r3);  // Preserve the code object.
      __ CallRuntime(Runtime::kLogOrTraceOptimizedOSREntry, 0);
      __ Pop(r3);
    }

    __ bind(&next);
  }

  if (source == OsrSourceTier::kInterpreter) {
    // Drop the handler frame that is be sitting on top of the actual
    // JavaScript frame. This is the case then OSR is triggered from bytecode.
    __ LeaveFrame(StackFrame::STUB);
  }

  // Load deoptimization data from the code object.
  // <deopt_data> = <code>[#deoptimization_data_offset]
  __ LoadTaggedField(
      r4, FieldMemOperand(r3, Code::kDeoptimizationDataOrInterpreterDataOffset),
      r0);

  {
    ConstantPoolUnavailableScope constant_pool_unavailable(masm);

    if (V8_EMBEDDED_CONSTANT_POOL_BOOL) {
      __ LoadConstantPoolPointerRegisterFromCodeTargetAddress(r3, r0, ip);
    }

    __ LoadCodeInstructionStart(r3, r3);

    // Load the OSR entrypoint offset from the deoptimization data.
    // <osr_offset> = <deopt_data>[#header_size + #osr_pc_offset]
    __ SmiUntag(r4,
                FieldMemOperand(r4, FixedArray::OffsetOfElementAt(
                                        DeoptimizationData::kOsrPcOffsetIndex)),
                LeaveRC, r0);

    // Compute the target address = code start + osr_offset
    __ add(r0, r3, r4);

    // And "return" to the OSR entry point of the function.
    __ mtlr(r0);
    __ blr();
  }
}

}  // namespace

// The construct stub for ES5 constructor functions and ES6 class constructors.
void Builtins::Generate_JSConstructStubGeneric(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  --      r3: number of arguments (untagged)
  //  --      r4: constructor function
  //  --      r6: new target
  //  --      cp: context
  //  --      lr: return address
  //  -- sp[...]: constructor arguments
  // -----------------------------------

  FrameScope scope(masm, StackFrame::MANUAL);
  // Enter a construct frame.
  Label post_instantiation_deopt_entry, not_create_implicit_receiver;
  __ EnterFrame(StackFrame::CONSTRUCT);

  // Preserve the incoming parameters on the stack.
  __ Push(cp, r3, r4);
  __ PushRoot(RootIndex::kUndefinedValue);
  __ Push(r6);

  // ----------- S t a t e -------------
  //  --        sp[0*kSystemPointerSize]: new target
  //  --        sp[1*kSystemPointerSize]: padding
  //  -- r4 and sp[2*kSystemPointerSize]: constructor function
  //  --        sp[3*kSystemPointerSize]: number of arguments
  //  --        sp[4*kSystemPointerSize]: context
  // -----------------------------------

  __ LoadTaggedField(
      r7, FieldMemOperand(r4, JSFunction::kSharedFunctionInfoOffset), r0);
  __ lwz(r7, FieldMemOperand(r7, SharedFunctionInfo::kFlagsOffset));
  __ DecodeField<SharedFunctionInfo::FunctionKindBits>(r7);
  __ JumpIfIsInRange(
      r7, r0, static_cast<uint32_t>(FunctionKind::kDefaultDerivedConstructor),
      static_cast<uint32_t>(FunctionKind::kDerivedConstructor),
      &not_create_implicit_receiver);

  // If not derived class constructor: Allocate the new receiver object.
  __ CallBuiltin(Builtin::kFastNewObject);
  __ b(&post_instantiation_deopt_entry);

  // Else: use TheHoleValue as receiver for constructor call
  __ bind(&not_create_implicit_receiver);
  __ LoadRoot(r3, RootIndex::kTheHoleValue);

  // ----------- S t a t e -------------
  //  --                          r3: receiver
  //  -- Slot 4 / sp[0*kSystemPointerSize]: new target
  //  -- Slot 3 / sp[1*kSystemPointerSize]: padding
  //  -- Slot 2 / sp[2*kSystemPointerSize]: constructor function
  //  -- Slot 1 / sp[3*kSystemPointerSize]: number of arguments
  //  -- Slot 0 / sp[4*kSystemPointerSize]: context
  // -----------------------------------
  // Deoptimizer enters here.
  masm->isolate()->heap()->SetConstructStubCreateDeoptPCOffset(
      masm->pc_offset());
  __ bind(&post_instantiation_deopt_entry);

  // Restore new target.
  __ Pop(r6);

  // Push the allocated receiver to the stack.
  __ Push(r3);
  // We need two copies because we may have to return the original one
  // and the calling conventions dictate that the called function pops the
  // receiver. The second copy is pushed after the arguments, we saved in r6
  // since r0 needs to store the number of arguments before
  // InvokingFunction.
  __ mr(r9, r3);

  // Set up pointer to first argument (skip receiver).
  __ addi(
      r7, fp,
      Operand(StandardFrameConstants::kCallerSPOffset + kSystemPointerSize));

  // ----------- S t a t e -------------
  //  --                 r6: new target
  //  -- sp[0*kSystemPointerSize]: implicit receiver
  //  -- sp[1*kSystemPointerSize]: implicit receiver
  //  -- sp[2*kSystemPointerSize]: padding
  //  -- sp[3*kSystemPointerSize]: constructor function
  //  -- sp[4*kSystemPointerSize]: number of arguments
  //  -- sp[5*kSystemPointerSize]: context
  // -----------------------------------

  // Restore constructor function and argument count.
  __ LoadU64(r4, MemOperand(fp, ConstructFrameConstants::kConstructorOffset));
  __ LoadU64(r3, MemOperand(fp, ConstructFrameConstants::kLengthOffset));

  Label stack_overflow;
  __ StackOverflowCheck(r3, r8, &stack_overflow);

  // Copy arguments to the expression stack.
  // r7: Pointer to start of argument.
  // r3: Number of arguments.
  Generate_PushArguments(masm, r7, r3, r8, ArgumentsElementType::kRaw);

  // Push implicit receiver.
  __ Push(r9);

  // Call the function.
  {
    ConstantPoolUnavailableScope constant_pool_unavailable(masm);
    __ InvokeFunctionWithNewTarget(r4, r6, r3, InvokeType::kCall);
  }

  // If the result is an object (in the ECMA sense), we should get rid
  // of the receiver and use the result; see ECMA-262 section 13.2.2-7
  // on page 74.
  Label use_receiver, do_throw, leave_and_return, check_receiver;

  // If the result is undefined, we jump out to using the implicit receiver.
  __ JumpIfNotRoot(r3, RootIndex::kUndefinedValue, &check_receiver);

  // Otherwise we do a smi check and fall through to check if the return value
  // is a valid receiver.

  // Throw away the result of the constructor invocation and use the
  // on-stack receiver as the result.
  __ bind(&use_receiver);
  __ LoadU64(r3, MemOperand(sp));
  __ JumpIfRoot(r3, RootIndex::kTheHoleValue, &do_throw);

  __ bind(&leave_and_return);
  // Restore arguments count from the frame.
  __ LoadU64(r4, MemOperand(fp, ConstructFrameConstants::kLengthOffset));
  // Leave construct frame.
  __ LeaveFrame(StackFrame::CONSTRUCT);

  // Remove caller arguments from the stack and return.
  __ DropArguments(r4);
  __ blr();

  __ bind(&check_receiver);
  // If the result is a smi, it is *not* an object in the ECMA sense.
  __ JumpIfSmi(r3, &use_receiver);

  // If the type of the result (stored in its map) is less than
  // FIRST_JS_RECEIVER_TYPE, it is not an object in the ECMA sense.
  static_assert(LAST_JS_RECEIVER_TYPE == LAST_TYPE);
  __ CompareObjectType(r3, r7, r7, FIRST_JS_RECEIVER_TYPE);
  __ bge(&leave_and_return);
  __ b(&use_receiver);

  __ bind(&do_throw);
  // Restore the context from the frame.
  __ LoadU64(cp, MemOperand(fp, ConstructFrameConstants::kContextOffset));
  __ CallRuntime(Runtime::kThrowConstructorReturnedNonObject);
  __ bkpt(0);

  __ bind(&stack_overflow);
  // Restore the context from the frame.
  __ LoadU64(cp, MemOperand(fp, ConstructFrameConstants::kContextOffset));
  __ CallRuntime(Runtime::kThrowStackOverflow);
  // Unreachable code.
  __ bkpt(0);
}

void Builtins::Generate_JSBuiltinsConstructStub(MacroAssembler* masm) {
  Generate_JSBuiltinsConstructStubHelper(masm);
}

// static
void Builtins::Generate_ResumeGeneratorTrampoline(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- r3 : the value to pass to the generator
  //  -- r4 : the JSGeneratorObject to resume
  //  -- lr : return address
  // -----------------------------------
  // Store input value into generator object.
  __ StoreTaggedField(
      r3, FieldMemOperand(r4, JSGeneratorObject::kInputOrDebugPosOffset), r0);
  __ RecordWriteField(r4, JSGeneratorObject::kInputOrDebugPosOffset, r3, r6,
                      kLRHasNotBeenSaved, SaveFPRegsMode::kIgnore);
  // Check that r4 is still valid, RecordWrite might have clobbered it.
  __ AssertGeneratorObject(r4);

  // Load suspended function and context.
  __ LoadTaggedField(
      r7, FieldMemOperand(r4, JSGeneratorObject::kFunctionOffset), r0);
  __ LoadTaggedField(cp, FieldMemOperand(r7, JSFunction::kContextOffset), r0);

  // Flood function if we are stepping.
  Label prepare_step_in_if_stepping, prepare_step_in_suspended_generator;
  Label stepping_prepared;
  Register scratch = r8;
  ExternalReference debug_hook =
      ExternalReference::debug_hook_on_function_call_address(masm->isolate());
  __ Move(scratch, debug_hook);
  __ LoadU8(scratch, MemOperand(scratch), r0);
  __ extsb(scratch, scratch);
  __ CmpSmiLiteral(scratch, Smi::zero(), r0);
  __ bne(&prepare_step_in_if_stepping);

  // Flood function if we need to continue stepping in the suspended generator.

  ExternalReference debug_suspended_generator =
      ExternalReference::debug_suspended_generator_address(masm->isolate());

  __ Move(scratch, debug_suspended_generator);
  __ LoadU64(scratch, MemOperand(scratch));
  __ CmpS64(scratch, r4);
  __ beq(&prepare_step_in_suspended_generator);
  __ bind(&stepping_prepared);

  // Check the stack for overflow. We are not trying to catch interruptions
  // (i.e. debug break and preemption) here, so check the "real stack limit".
  Label stack_overflow;
  __ LoadStackLimit(scratch, StackLimitKind::kRealStackLimit, r0);
  __ CmpU64(sp, scratch);
  __ blt(&stack_overflow);

  // ----------- S t a t e -------------
  //  -- r4    : the JSGeneratorObject to resume
  //  -- r7    : generator function
  //  -- cp    : generator context
  //  -- lr    : return address
  // -----------------------------------

  // Copy the function arguments from the generator object's register file.
  __ LoadTaggedField(
      r6, FieldMemOperand(r7, JSFunction::kSharedFunctionInfoOffset), r0);
  __ LoadU16(
      r6, FieldMemOperand(r6, SharedFunctionInfo::kFormalParameterCountOffset));
  __ subi(r6, r6, Operand(kJSArgcReceiverSlots));
  __ LoadTaggedField(
      r5, FieldMemOperand(r4, JSGeneratorObject::kParametersAndRegistersOffset),
      r0);
  {
    Label done_loop, loop;
    __ bind(&loop);
    __ subi(r6, r6, Operand(1));
    __ cmpi(r6, Operand::Zero());
    __ blt(&done_loop);
    __ ShiftLeftU64(r10, r6, Operand(kTaggedSizeLog2));
    __ add(scratch, r5, r10);
    __ LoadTaggedField(
        scratch, FieldMemOperand(scratch, OFFSET_OF_DATA_START(FixedArray)),
        r0);
    __ Push(scratch);
    __ b(&loop);
    __ bind(&done_loop);

    // Push receiver.
    __ LoadTaggedField(
        scratch, FieldMemOperand(r4, JSGeneratorObject::kReceiverOffset), r0);
    __ Push(scratch);
  }

  // Underlying function needs to have bytecode available.
  if (v8_flags.debug_code) {
    Label ok, is_baseline, is_unavailable;
    Register sfi = r6;
    Register bytecode = r6;
    __ LoadTaggedField(
        sfi, FieldMemOperand(r7, JSFunction::kSharedFunctionInfoOffset), r0);
    GetSharedFunctionInfoBytecodeOrBaseline(masm, sfi, bytecode, ip,
                                            &is_baseline, &is_unavailable);
    __ b(&ok);

    __ bind(&is_unavailable);
    __ Abort(AbortReason::kMissingBytecodeArray);

    __ bind(&is_baseline);
    __ IsObjectType(bytecode, ip, ip, CODE_TYPE);
    __ Assert(eq, AbortReason::kMissingBytecodeArray);

    __ bind(&ok);
  }

  // Resume (Ignition/TurboFan) generator object.
  {
    __ LoadTaggedField(
        r3, FieldMemOperand(r7, JSFunction::kSharedFunctionInfoOffset), r0);
    __ LoadU16(r3, FieldMemOperand(
                       r3, SharedFunctionInfo::kFormalParameterCountOffset));
    // We abuse new.target both to indicate that this is a resume call and to
    // pass in the generator object.  In ordinary calls, new.target is always
    // undefined because generator functions are non-constructable.
    __ mr(r6, r4);
    __ mr(r4, r7);
    __ JumpJSFunction(r4, r0);
  }

  __ bind(&prepare_step_in_if_stepping);
  {
    FrameAndConstantPoolScope scope(masm, StackFrame::INTERNAL);
    __ Push(r4, r7);
    // Push hole as receiver since we do not use it for stepping.
    __ PushRoot(RootIndex::kTheHoleValue);
    __ CallRuntime(Runtime::kDebugOnFunctionCall);
    __ Pop(r4);
    __ LoadTaggedField(
        r7, FieldMemOperand(r4, JSGeneratorObject::kFunctionOffset), r0);
  }
  __ b(&stepping_prepared);

  __ bind(&prepare_step_in_suspended_generator);
  {
    FrameAndConstantPoolScope scope(masm, StackFrame::INTERNAL);
    __ Push(r4);
    __ CallRuntime(Runtime::kDebugPrepareStepInSuspendedGenerator);
    __ Pop(r4);
    __ LoadTaggedField(
        r7, FieldMemOperand(r4, JSGeneratorObject::kFunctionOffset), r0);
  }
  __ b(&stepping_prepared);

  __ bind(&stack_overflow);
  {
    FrameScope scope(masm, StackFrame::INTERNAL);
    __ CallRuntime(Runtime::kThrowStackOverflow);
    __ bkpt(0);  // This should be unreachable.
  }
}

void Builtins::Generate_ConstructedNonConstructable(MacroAssembler* masm) {
  FrameAndConstantPoolScope scope(masm, StackFrame::INTERNAL);
  __ push(r4);
  __ CallRuntime(Runtime::kThrowConstructedNonConstructable);
  __ Trap();  // Unreachable.
}

namespace {

// Called with the native C calling convention. The corresponding function
// signature is either:
//
//   using JSEntryFunction = GeneratedCode<Address(
//       Address root_register_value, Address new_target, Address target,
//       Address receiver, intptr_t argc, Address** args)>;
// or
//   using JSEntryFunction = GeneratedCode<Address(
//       Address root_register_value, MicrotaskQueue* microtask_queue)>;
void Generate_JSEntryVariant(MacroAssembler* masm, StackFrame::Type type,
                             Builtin entry_trampoline) {
  // The register state is either:
  //   r3: root_register_value
  //   r4: code entry
  //   r5: function
  //   r6: receiver
  //   r7: argc
  //   r8: argv
  // or
  //   r3: root_register_value
  //   r4: microtask_queue

  Label invoke, handler_entry, exit;

  {
    NoRootArrayScope no_root_array(masm);

    // PPC LINUX ABI:
    // preserve LR in pre-reserved slot in caller's frame
    __ mflr(r0);
    __ StoreU64(r0, MemOperand(sp, kStackFrameLRSlot * kSystemPointerSize));

    // Save callee saved registers on the stack.
    __ MultiPush(kCalleeSaved);

    // Save callee-saved double registers.
    __ MultiPushDoubles(kCalleeSavedDoubles);
    // Set up the reserved register for 0.0.
    __ LoadDoubleLiteral(kDoubleRegZero, base::Double(0.0), r0);

    // Initialize the root register.
    // C calling convention. The first argument is passed in r3.
    __ mr(kRootRegister, r3);

#ifdef V8_COMPRESS_POINTERS
    // Initialize the pointer cage base register.
    __ LoadRootRelative(kPtrComprCageBaseRegister,
                        IsolateData::cage_base_offset());
#endif
  }

  // Push a frame with special values setup to mark it as an entry frame.
  // r4: code entry
  // r5: function
  // r6: receiver
  // r7: argc
  // r8: argv
  // Clear c_entry_fp, now we've pushed its previous value to the stack.
  // If the c_entry_fp is not already zero and we don't clear it, the
  // StackFrameIteratorForProfiler will assume we are executing C++ and miss the
  // JS frames on top.
  __ li(r0, Operand(-1));  // Push a bad frame pointer to fail if it is used.
  __ push(r0);
  if (V8_EMBEDDED_CONSTANT_POOL_BOOL) {
    __ li(kConstantPoolRegister, Operand::Zero());
    __ push(kConstantPoolRegister);
  }
  __ mov(r0, Operand(StackFrame::TypeToMarker(type)));
  __ push(r0);
  __ push(r0);

  __ mov(r0, Operand::Zero());
  __ Move(ip, ExternalReference::Create(IsolateAddressId::kCEntryFPAddress,
                                        masm->isolate()));
  __ LoadU64(r3, MemOperand(ip));
  __ StoreU64(r0, MemOperand(ip));
  __ push(r3);

  __ LoadIsolateField(ip, IsolateFieldId::kFastCCallCallerFP);
  __ LoadU64(r3, MemOperand(ip));
  __ StoreU64(r0, MemOperand(ip));
  __ push(r3);

  __ LoadIsolateField(ip, IsolateFieldId::kFastCCallCallerPC);
  __ LoadU64(r3, MemOperand(ip));
  __ StoreU64(r0, MemOperand(ip));
  __ push(r3);

  Register scratch = r9;
  // Set up frame pointer for the frame to be pushed.
  __ addi(fp, sp, Operand(-EntryFrameConstants::kNextFastCallFramePCOffset));

  // If this is the outermost JS call, set js_entry_sp value.
  Label non_outermost_js;
  ExternalReference js
```