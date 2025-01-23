Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/src/builtins/s390/builtins-s390.cc`.

Here's a breakdown of how to address the request:

1. **Identify the core purpose:** The file contains architecture-specific (s390) implementations of built-in functions and runtime stubs for the V8 JavaScript engine. These builtins handle low-level operations and transitions between different execution states (JavaScript, C++, interpreter, compiler).

2. **List key functionalities based on included headers and code:**  Scan the `#include` directives and function definitions for clues about the file's responsibilities. Keywords like "Builtins", "MacroAssembler", "Frame", "OSR", "Generator", "Adaptor", and "JSEntry" are strong indicators.

3. **Check for Torque usage:**  The prompt explicitly asks about `.tq` files. Since the filename is `.cc`, this part of the condition is not met.

4. **Illustrate with JavaScript examples:**  Connect the C++ builtins to their corresponding JavaScript functionalities. For instance, `JSConstructStubGeneric` relates to `new` operator, `ResumeGeneratorTrampoline` to `yield` and `next()` in generators, and `Adaptor` to calling C++ functions from JavaScript.

5. **Provide code logic reasoning (if applicable):**  Analyze functions like `GetSharedFunctionInfoBytecodeOrBaseline` or `Generate_BaselineOrInterpreterEntry` to explain their conditional logic and how they transition between bytecode and compiled code. Create simple hypothetical inputs and expected outputs.

6. **Highlight common programming errors:** Think about JavaScript errors that might trigger these builtins. For example, stack overflow in recursive functions, calling non-constructable objects with `new`, etc.

7. **Summarize the overall function:**  Provide a concise summary capturing the main role of the file.

**Pre-computation/Pre-analysis:**

* **Architecture Specificity:** Recognize that this code is specific to the s390 architecture.
* **Builtins:** Understand that builtins are highly optimized, low-level functions within V8.
* **Execution States:** Be aware of the different execution modes in V8 (interpreter, baseline compiler, optimizing compiler).
* **Frames:**  Understand the concept of stack frames and their role in managing function calls.
* **OSR (On-Stack Replacement):** Know what OSR is and its purpose in optimizing long-running functions.
* **Generators:** Recall how JavaScript generators work and the operations involved.
* **Adaptors:**  Understand how V8 bridges the gap between JavaScript and native C++ code.
* **JSEntry:** Recognize the role of the JSEntry stub in setting up the environment for executing JavaScript code called from C++.

By following these steps, I can generate a comprehensive and accurate summary of the provided V8 source code.
`v8/src/builtins/s390/builtins-s390.cc` 是 V8 JavaScript 引擎中针对 s390 架构（IBM System z）的内置函数（builtins）的实现文件。它包含了一系列用汇编语言编写的函数，这些函数是 V8 运行时环境的核心组成部分，用于执行各种底层的操作和实现 JavaScript 的语言特性。

以下是 `v8/src/builtins/s390/builtins-s390.cc` 的主要功能归纳：

1. **架构特定的优化：**  由于文件名包含 "s390"， 很明显这些代码是专门为 IBM System z 架构优化的。这意味着它利用了 s390 的指令集和架构特性来实现高效的 JavaScript 执行。

2. **内置函数的实现：** 该文件实现了许多 JavaScript 的内置函数和操作。这些内置函数是 JavaScript 语言的基础，例如对象创建、函数调用、类型转换、算术运算等。由于性能关键性，许多内置函数都用汇编语言编写。

3. **运行时支持：**  它提供了 V8 运行时环境所需的底层支持，包括：
    * **栈帧管理：**  创建和管理 JavaScript 函数调用时的栈帧。
    * **异常处理：**  处理 JavaScript 运行时发生的错误和异常。
    * **内存管理接口：**  与 V8 的垃圾回收器和堆内存管理系统交互。
    * **调试支持：**  为 JavaScript 代码的调试提供必要的支持。
    * **性能分析：**  可能包含用于性能分析和优化的代码。

4. **代码执行入口点：**  它定义了一些代码执行的入口点，例如从解释器到编译代码的转换，以及从 C++ 代码调用 JavaScript 代码的入口。

5. **解释器和编译器之间的桥梁：**  该文件包含了在解释器（Ignition）和编译器（TurboFan/Crankshaft）之间切换执行的代码。例如，`Generate_BaselineOrInterpreterEntry` 就负责在没有优化代码的情况下进入解释器，或者在有 Baseline 代码的情况下进入 Baseline 代码。

6. **OSR (On-Stack Replacement) 支持：**  `OnStackReplacement` 函数是实现 OSR 的关键部分。OSR 允许在函数执行过程中，从解释执行或低级优化的代码切换到更高级优化的代码，从而提升性能。

7. **生成器（Generator）支持：**  `Generate_ResumeGeneratorTrampoline` 函数处理 JavaScript 生成器函数的恢复执行，这是 `yield` 和 `next()` 语法的底层实现。

8. **构造函数调用：** `Generate_JSConstructStubGeneric` 和 `Generate_JSBuiltinsConstructStub` 实现了 JavaScript 构造函数的调用过程，包括创建新对象和执行构造函数体。

9. **调用适配器（Adaptor）：** `Generate_Adaptor` 用于在 JavaScript 代码和 C++ 代码之间进行调用转换，允许从 JavaScript 调用 C++ 函数。

**如果 `v8/src/builtins/s390/builtins-s390.cc` 以 `.tq` 结尾，那它是个 v8 torque 源代码**

当前文件以 `.cc` 结尾，所以它不是 Torque 源代码。 Torque 是一种 V8 内部使用的领域特定语言，用于生成高效的汇编代码。如果文件以 `.tq` 结尾，则表示其中的内置函数是用 Torque 语言编写的，V8 会将其编译成汇编代码。

**如果它与 javascript 的功能有关系，请用 javascript 举例说明**

是的，`v8/src/builtins/s390/builtins-s390.cc` 中定义的都是与 JavaScript 功能直接相关的底层实现。

* **对象创建 (`Generate_JSConstructStubGeneric`, `Generate_JSBuiltinsConstructStub`)：**

```javascript
// JavaScript 中使用 'new' 关键字调用构造函数
function MyClass(value) {
  this.value = value;
}
const instance = new MyClass(10);
```
在底层，V8 会调用类似 `Generate_JSConstructStubGeneric` 或 `Generate_JSBuiltinsConstructStub` 这样的内置函数来创建 `instance` 对象并执行 `MyClass` 的构造函数。

* **生成器函数 (`Generate_ResumeGeneratorTrampoline`)：**

```javascript
function* myGenerator() {
  yield 1;
  yield 2;
  return 3;
}

const gen = myGenerator();
console.log(gen.next()); // { value: 1, done: false }
console.log(gen.next()); // { value: 2, done: false }
console.log(gen.next()); // { value: 3, done: true }
```
当调用 `gen.next()` 时，如果生成器函数暂停在 `yield` 语句，V8 会使用类似 `Generate_ResumeGeneratorTrampoline` 的内置函数来恢复生成器的执行。

* **调用 C++ 函数 (`Generate_Adaptor`)：**

虽然用户通常不会直接接触到 `Generate_Adaptor`，但在 V8 的内部实现中，以及在 Node.js 的原生模块中，会使用类似的机制来调用 C++ 函数。

```javascript
// 假设有一个 C++ 函数被暴露给 JavaScript
// 这只是一个概念性的例子，实际过程涉及 Native 模块的绑定
function nativeFunction(arg) {
  // ... 内部会调用通过 Adaptor 注册的 C++ 代码
}

nativeFunction("hello");
```
当 JavaScript 调用 `nativeFunction` 时，V8 会通过适配器（Adaptor）将调用转发到对应的 C++ 代码。

**如果有代码逻辑推理，请给出假设输入与输出**

考虑 `GetSharedFunctionInfoBytecodeOrBaseline` 函数。

**假设输入：**

* `sfi` 寄存器包含一个 `SharedFunctionInfo` 对象的地址。这个对象代表一个 JavaScript 函数的共享信息。

**代码逻辑推理：**

1. 加载 `SharedFunctionInfo` 的 `trusted_function_data` 字段到 `data` 寄存器。这个字段可能指向 `Code` 对象（已编译的 Baseline 代码）、`BytecodeArray` 对象（字节码）或 `InterpreterData` 对象。
2. 加载 `data` 对象的 Map，并检查其 `instance_type`。
3. 如果 `instance_type` 是 `CODE_TYPE`，则说明存在 Baseline 代码，跳转到 `is_baseline` 标签。
4. 如果 `instance_type` 是 `BYTECODE_ARRAY_TYPE`，则说明存在字节码，跳转到 `done` 标签。
5. 如果 `instance_type` 是 `INTERPRETER_DATA_TYPE`，则加载 `InterpreterData` 对象的 `bytecode_array` 字段到 `data` 寄存器，然后跳转到 `done` 标签。
6. 如果以上都不是，则跳转到 `is_unavailable` 标签。

**假设输出：**

* 如果 `SharedFunctionInfo` 对应的函数有 Baseline 代码，则跳转到 `is_baseline` 标签。
* 如果 `SharedFunctionInfo` 对应的函数只有字节码，则 `bytecode` 寄存器将包含 `BytecodeArray` 对象的地址，并跳转到 `done` 标签。
* 如果 `SharedFunctionInfo` 对应的函数没有可用的代码（这种情况比较少见），则跳转到 `is_unavailable` 标签。

**如果涉及用户常见的编程错误，请举例说明**

虽然这个 C++ 文件本身不直接处理用户编写的 JavaScript 代码，但其中实现的内置函数是 JavaScript 运行时错误的基础。

* **栈溢出 (`StackOverflowCheck` 和 `Generate_JSEntryVariant`)：**

```javascript
function recursiveFunction() {
  recursiveFunction(); // 无终止条件的递归调用
}

try {
  recursiveFunction();
} catch (e) {
  console.error(e); // 可能抛出 "RangeError: Maximum call stack size exceeded"
}
```
当 JavaScript 代码进行过多的函数调用（例如无限递归）时，会导致栈溢出。V8 的内置函数（例如 `Generate_JSEntryVariant` 中的栈限制检查）会检测到这种情况并抛出错误。

* **尝试 `new` 一个非构造函数 (`Builtins::Generate_ConstructedNonConstructable`)：**

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
当尝试使用 `new` 关键字调用一个不是构造函数的对象时，V8 会调用 `Builtins::Generate_ConstructedNonConstructable` 抛出 `TypeError`。

* **构造函数返回非对象 (`Builtins::Generate_JSConstructStubGeneric`)：**

```javascript
function BadConstructor() {
  return 10; // 返回一个原始值
}

try {
  const obj = new BadConstructor();
  console.log(obj); // 返回的是构造函数内部隐式创建的 'this' 对象，而不是 10
} catch (e) {
  // 在某些严格模式或特定情况下，可能会抛出错误
}
```
虽然 JavaScript 允许构造函数返回原始值，但这种情况下 `new` 运算符会忽略返回值并返回构造函数内部创建的 `this` 对象。在某些情况下，V8 的构造函数存根（如 `Builtins::Generate_JSConstructStubGeneric`）可能会涉及到对此类行为的处理。

**总结一下它的功能**

总而言之，`v8/src/builtins/s390/builtins-s390.cc` 是 V8 JavaScript 引擎中针对 s390 架构的关键组成部分，它包含了用汇编语言编写的底层内置函数，用于实现 JavaScript 语言的核心功能，管理运行时环境，并在解释器和编译器之间进行协调，从而确保 JavaScript 代码在 s390 平台上的高效执行。

### 提示词
```
这是目录为v8/src/builtins/s390/builtins-s390.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/s390/builtins-s390.cc以.tq结尾，那它是个v8 torque源代码，
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

#if V8_TARGET_ARCH_S390X

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
  __ CmpS64(scratch, Operand(static_cast<int>(CodeKind::BASELINE)));
  __ Assert(eq, AbortReason::kExpectedBaselineData);
}

static void GetSharedFunctionInfoBytecodeOrBaseline(
    MacroAssembler* masm, Register sfi, Register bytecode, Register scratch1,
    Label* is_baseline, Label* is_unavailable) {
  USE(GetSharedFunctionInfoBytecodeOrBaseline);
  ASM_CODE_COMMENT(masm);
  Label done;

  Register data = bytecode;
  __ LoadTaggedField(
      data,
      FieldMemOperand(sfi, SharedFunctionInfo::kTrustedFunctionDataOffset));

  __ LoadMap(scratch1, data);
  __ LoadU16(scratch1, FieldMemOperand(scratch1, Map::kInstanceTypeOffset));

#ifndef V8_JITLESS
  __ CmpS32(scratch1, Operand(CODE_TYPE));
  if (v8_flags.debug_code) {
    Label not_baseline;
    __ b(ne, &not_baseline);
    AssertCodeIsBaseline(masm, data, scratch1);
    __ beq(is_baseline);
    __ bind(&not_baseline);
  } else {
    __ beq(is_baseline);
  }
#endif  // !V8_JITLESS

  __ CmpS32(scratch1, Operand(BYTECODE_ARRAY_TYPE));
  __ b(eq, &done);

  __ CmpS32(scratch1, Operand(INTERPRETER_DATA_TYPE));
  __ b(ne, is_unavailable);
  __ LoadTaggedField(
      data, FieldMemOperand(data, InterpreterData::kBytecodeArrayOffset));

  __ bind(&done);
}

void Generate_OSREntry(MacroAssembler* masm, Register entry_address,
                       Operand offset) {
  if (!offset.is_reg() && is_int20(offset.immediate())) {
    __ lay(r14, MemOperand(entry_address, offset.immediate()));
  } else {
    DCHECK(offset.is_reg());
    __ AddS64(r14, entry_address, offset.rm());
  }

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
      FieldMemOperand(js_function, JSFunction::kSharedFunctionInfoOffset));
  ResetSharedFunctionInfoAge(masm, scratch1, scratch2);
}

void ResetFeedbackVectorOsrUrgency(MacroAssembler* masm,
                                   Register feedback_vector, Register scratch) {
  DCHECK(!AreAliased(feedback_vector, scratch));
  __ LoadU8(scratch,
            FieldMemOperand(feedback_vector, FeedbackVector::kOsrStateOffset));
  __ AndP(scratch, scratch, Operand(~FeedbackVector::OsrUrgencyBits::kMask));
  __ StoreU8(scratch,
             FieldMemOperand(feedback_vector, FeedbackVector::kOsrStateOffset));
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
  Register closure = r3;
  __ LoadU64(closure, MemOperand(fp, StandardFrameConstants::kFunctionOffset));

  // Get the InstructionStream object from the shared function info.
  Register code_obj = r8;
  __ LoadTaggedField(
      code_obj,
      FieldMemOperand(closure, JSFunction::kSharedFunctionInfoOffset));

  if (is_osr) {
    ResetSharedFunctionInfoAge(masm, code_obj, r5);
  }

  __ LoadTaggedField(
      code_obj, FieldMemOperand(
                    code_obj, SharedFunctionInfo::kTrustedFunctionDataOffset));

  // Check if we have baseline code. For OSR entry it is safe to assume we
  // always have baseline code.
  if (!is_osr) {
    Label start_with_baseline;
    __ CompareObjectType(code_obj, r5, r5, CODE_TYPE);
    __ b(eq, &start_with_baseline);

    // Start with bytecode as there is no baseline code.
    Builtin builtin = next_bytecode ? Builtin::kInterpreterEnterAtNextBytecode
                                    : Builtin::kInterpreterEnterAtBytecode;
    __ TailCallBuiltin(builtin);

    // Start with baseline code.
    __ bind(&start_with_baseline);
  } else if (v8_flags.debug_code) {
    __ CompareObjectType(code_obj, r5, r5, CODE_TYPE);
    __ Assert(eq, AbortReason::kExpectedBaselineData);
  }

  if (v8_flags.debug_code) {
    AssertCodeIsBaseline(masm, code_obj, r5);
  }

  // Load the feedback cell and vector.
  Register feedback_cell = r4;
  Register feedback_vector = r1;
  __ LoadTaggedField(feedback_cell,
                     FieldMemOperand(closure, JSFunction::kFeedbackCellOffset));
  __ LoadTaggedField(
      feedback_vector,
      FieldMemOperand(feedback_cell, FeedbackCell::kValueOffset));

  Label install_baseline_code;
  // Check if feedback vector is valid. If not, call prepare for baseline to
  // allocate it.
  __ CompareObjectType(feedback_vector, r5, r5, FEEDBACK_VECTOR_TYPE);
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
  Register get_baseline_pc = r5;
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
                      kFunctionEntryBytecodeOffset));
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
  {
    __ mov(kCArgRegs[0], code_obj);
    __ mov(kCArgRegs[1], kInterpreterBytecodeOffsetRegister);
    __ mov(kCArgRegs[2], kInterpreterBytecodeArrayRegister);
    FrameScope scope(masm, StackFrame::INTERNAL);
    __ PrepareCallCFunction(3, 0, r1);
    __ CallCFunction(get_baseline_pc, 3, 0);
  }
  __ LoadCodeInstructionStart(code_obj, code_obj);
  __ AddS64(code_obj, code_obj, kReturnRegister0);
  __ Pop(kInterpreterAccumulatorRegister);

  if (is_osr) {
    // TODO(pthier): Separate baseline Sparkplug from TF arming and don't
    // disarm Sparkplug here.
    Generate_OSREntry(masm, code_obj, Operand(0));
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
  __ CmpSmiLiteral(r2, Smi::zero(), r0);
  __ bne(&jump_to_optimized_code);
  __ Ret();

  __ bind(&jump_to_optimized_code);
  DCHECK_EQ(maybe_target_code, r2);  // Already in the right spot.

  // OSR entry tracing.
  {
    Label next;
    __ Move(r3, ExternalReference::address_of_log_or_trace_osr());
    __ LoadU8(r3, MemOperand(r3));
    __ tmll(r3, Operand(0xFF));  // Mask to the LSB.
    __ beq(&next);

    {
      FrameAndConstantPoolScope scope(masm, StackFrame::INTERNAL);
      __ Push(r2);  // Preserve the code object.
      __ CallRuntime(Runtime::kLogOrTraceOptimizedOSREntry, 0);
      __ Pop(r2);
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
      r3,
      FieldMemOperand(r2, Code::kDeoptimizationDataOrInterpreterDataOffset));

  // Load the OSR entrypoint offset from the deoptimization data.
  // <osr_offset> = <deopt_data>[#header_size + #osr_pc_offset]
  __ SmiUntagField(
      r3, FieldMemOperand(r3, FixedArray::OffsetOfElementAt(
                                  DeoptimizationData::kOsrPcOffsetIndex)));

  __ LoadCodeInstructionStart(r2, r2);

  // Compute the target address = code_entry + osr_offset
  // <entry_addr> = <code_entry> + <osr_offset>
  Generate_OSREntry(masm, r2, Operand(r3));
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
  Register counter = scratch;
  Register value = ip;
  Label loop, entry;
  __ SubS64(counter, argc, Operand(kJSArgcReceiverSlots));
  __ b(&entry);
  __ bind(&loop);
  __ ShiftLeftU64(value, counter, Operand(kSystemPointerSizeLog2));
  __ LoadU64(value, MemOperand(array, value));
  if (element_type == ArgumentsElementType::kHandle) {
    __ LoadU64(value, MemOperand(value));
  }
  __ push(value);
  __ bind(&entry);
  __ SubS64(counter, counter, Operand(1));
  __ bge(&loop);
}

void Generate_JSBuiltinsConstructStubHelper(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- r2     : number of arguments
  //  -- r3     : constructor function
  //  -- r5     : new target
  //  -- cp     : context
  //  -- lr     : return address
  //  -- sp[...]: constructor arguments
  // -----------------------------------

  Register scratch = r4;
  Label stack_overflow;

  __ StackOverflowCheck(r2, scratch, &stack_overflow);

  // Enter a construct frame.
  {
    FrameAndConstantPoolScope scope(masm, StackFrame::CONSTRUCT);

    // Preserve the incoming parameters on the stack.
    __ Push(cp, r2);

    // TODO(victorgomes): When the arguments adaptor is completely removed, we
    // should get the formal parameter count and copy the arguments in its
    // correct position (including any undefined), instead of delaying this to
    // InvokeFunction.

    // Set up pointer to first argument (skip receiver).
    __ la(r6, MemOperand(fp, StandardFrameConstants::kCallerSPOffset +
                                 kSystemPointerSize));
    // Copy arguments and receiver to the expression stack.
    // r6: Pointer to start of arguments.
    // r2: Number of arguments.
    Generate_PushArguments(masm, r6, r2, r1, ArgumentsElementType::kRaw);

    // The receiver for the builtin/api call.
    __ PushRoot(RootIndex::kTheHoleValue);

    // Call the function.
    // r2: number of arguments
    // r3: constructor function
    // r5: new target

    __ InvokeFunctionWithNewTarget(r3, r5, r2, InvokeType::kCall);

    // Restore context from the frame.
    __ LoadU64(cp, MemOperand(fp, ConstructFrameConstants::kContextOffset));
    // Restore arguments count from the frame.
    __ LoadU64(scratch, MemOperand(fp, ConstructFrameConstants::kLengthOffset));

    // Leave construct frame.
  }
  // Remove caller arguments from the stack and return.
  __ DropArguments(scratch);
  __ Ret();

  __ bind(&stack_overflow);
  {
    FrameScope scope(masm, StackFrame::INTERNAL);
    __ CallRuntime(Runtime::kThrowStackOverflow);
    __ bkpt(0);  // Unreachable code.
  }
}

}  // namespace

// The construct stub for ES5 constructor functions and ES6 class constructors.
void Builtins::Generate_JSConstructStubGeneric(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  --      r2: number of arguments (untagged)
  //  --      r3: constructor function
  //  --      r5: new target
  //  --      cp: context
  //  --      lr: return address
  //  -- sp[...]: constructor arguments
  // -----------------------------------

  FrameScope scope(masm, StackFrame::MANUAL);
  // Enter a construct frame.
  Label post_instantiation_deopt_entry, not_create_implicit_receiver;
  __ EnterFrame(StackFrame::CONSTRUCT);

  // Preserve the incoming parameters on the stack.
  __ Push(cp, r2, r3);
  __ PushRoot(RootIndex::kUndefinedValue);
  __ Push(r5);

  // ----------- S t a t e -------------
  //  --        sp[0*kSystemPointerSize]: new target
  //  --        sp[1*kSystemPointerSize]: padding
  //  -- r3 and sp[2*kSystemPointerSize]: constructor function
  //  --        sp[3*kSystemPointerSize]: number of arguments
  //  --        sp[4*kSystemPointerSize]: context
  // -----------------------------------

  __ LoadTaggedField(
      r6, FieldMemOperand(r3, JSFunction::kSharedFunctionInfoOffset));
  __ LoadU32(r6, FieldMemOperand(r6, SharedFunctionInfo::kFlagsOffset));
  __ DecodeField<SharedFunctionInfo::FunctionKindBits>(r6);
  __ JumpIfIsInRange(
      r6, r6, static_cast<uint8_t>(FunctionKind::kDefaultDerivedConstructor),
      static_cast<uint8_t>(FunctionKind::kDerivedConstructor),
      &not_create_implicit_receiver);

  // If not derived class constructor: Allocate the new receiver object.
  __ CallBuiltin(Builtin::kFastNewObject);
  __ b(&post_instantiation_deopt_entry);

  // Else: use TheHoleValue as receiver for constructor call
  __ bind(&not_create_implicit_receiver);
  __ LoadRoot(r2, RootIndex::kTheHoleValue);

  // ----------- S t a t e -------------
  //  --                          r2: receiver
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
  __ Pop(r5);

  // Push the allocated receiver to the stack.
  __ Push(r2);
  // We need two copies because we may have to return the original one
  // and the calling conventions dictate that the called function pops the
  // receiver. The second copy is pushed after the arguments, we saved in r6
  // since r0 needs to store the number of arguments before
  // InvokingFunction.
  __ mov(r8, r2);

  // Set up pointer to first argument (skip receiver).
  __ la(r6, MemOperand(fp, StandardFrameConstants::kCallerSPOffset +
                               kSystemPointerSize));

  // ----------- S t a t e -------------
  //  --                 r5: new target
  //  -- sp[0*kSystemPointerSize]: implicit receiver
  //  -- sp[1*kSystemPointerSize]: implicit receiver
  //  -- sp[2*kSystemPointerSize]: padding
  //  -- sp[3*kSystemPointerSize]: constructor function
  //  -- sp[4*kSystemPointerSize]: number of arguments
  //  -- sp[5*kSystemPointerSize]: context
  // -----------------------------------

  // Restore constructor function and argument count.
  __ LoadU64(r3, MemOperand(fp, ConstructFrameConstants::kConstructorOffset));
  __ LoadU64(r2, MemOperand(fp, ConstructFrameConstants::kLengthOffset));

  Label stack_overflow;
  __ StackOverflowCheck(r2, r7, &stack_overflow);

  // Copy arguments and receiver to the expression stack.
  // r6: Pointer to start of argument.
  // r2: Number of arguments.
  Generate_PushArguments(masm, r6, r2, r1, ArgumentsElementType::kRaw);

  // Push implicit receiver.
  __ Push(r8);

  // Call the function.
  __ InvokeFunctionWithNewTarget(r3, r5, r2, InvokeType::kCall);

  // If the result is an object (in the ECMA sense), we should get rid
  // of the receiver and use the result; see ECMA-262 section 13.2.2-7
  // on page 74.
  Label use_receiver, do_throw, leave_and_return, check_receiver;

  // If the result is undefined, we jump out to using the implicit receiver.
  __ JumpIfNotRoot(r2, RootIndex::kUndefinedValue, &check_receiver);

  // Otherwise we do a smi check and fall through to check if the return value
  // is a valid receiver.

  // Throw away the result of the constructor invocation and use the
  // on-stack receiver as the result.
  __ bind(&use_receiver);
  __ LoadU64(r2, MemOperand(sp));
  __ JumpIfRoot(r2, RootIndex::kTheHoleValue, &do_throw);

  __ bind(&leave_and_return);
  // Restore arguments count from the frame.
  __ LoadU64(r3, MemOperand(fp, ConstructFrameConstants::kLengthOffset));
  // Leave construct frame.
  __ LeaveFrame(StackFrame::CONSTRUCT);

  // Remove caller arguments from the stack and return.
  __ DropArguments(r3);
  __ Ret();

  __ bind(&check_receiver);
  // If the result is a smi, it is *not* an object in the ECMA sense.
  __ JumpIfSmi(r2, &use_receiver);

  // If the type of the result (stored in its map) is less than
  // FIRST_JS_RECEIVER_TYPE, it is not an object in the ECMA sense.
  static_assert(LAST_JS_RECEIVER_TYPE == LAST_TYPE);
  __ CompareObjectType(r2, r6, r6, FIRST_JS_RECEIVER_TYPE);
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
  //  -- r2 : the value to pass to the generator
  //  -- r3 : the JSGeneratorObject to resume
  //  -- lr : return address
  // -----------------------------------
  // Store input value into generator object.
  __ StoreTaggedField(
      r2, FieldMemOperand(r3, JSGeneratorObject::kInputOrDebugPosOffset), r0);
  __ RecordWriteField(r3, JSGeneratorObject::kInputOrDebugPosOffset, r2, r5,
                      kLRHasNotBeenSaved, SaveFPRegsMode::kIgnore);
  // Check that r3 is still valid, RecordWrite might have clobbered it.
  __ AssertGeneratorObject(r3);

  // Load suspended function and context.
  __ LoadTaggedField(r6,
                     FieldMemOperand(r3, JSGeneratorObject::kFunctionOffset));
  __ LoadTaggedField(cp, FieldMemOperand(r6, JSFunction::kContextOffset));

  // Flood function if we are stepping.
  Label prepare_step_in_if_stepping, prepare_step_in_suspended_generator;
  Label stepping_prepared;
  Register scratch = r7;

  ExternalReference debug_hook =
      ExternalReference::debug_hook_on_function_call_address(masm->isolate());
  __ Move(scratch, debug_hook);
  __ LoadS8(scratch, MemOperand(scratch));
  __ CmpSmiLiteral(scratch, Smi::zero(), r0);
  __ bne(&prepare_step_in_if_stepping);

  // Flood function if we need to continue stepping in the suspended generator.

  ExternalReference debug_suspended_generator =
      ExternalReference::debug_suspended_generator_address(masm->isolate());

  __ Move(scratch, debug_suspended_generator);
  __ LoadU64(scratch, MemOperand(scratch));
  __ CmpS64(scratch, r3);
  __ beq(&prepare_step_in_suspended_generator);
  __ bind(&stepping_prepared);

  // Check the stack for overflow. We are not trying to catch interruptions
  // (i.e. debug break and preemption) here, so check the "real stack limit".
  Label stack_overflow;
  __ LoadU64(scratch,
             __ StackLimitAsMemOperand(StackLimitKind::kRealStackLimit));
  __ CmpU64(sp, scratch);
  __ blt(&stack_overflow);

  // ----------- S t a t e -------------
  //  -- r3    : the JSGeneratorObject to resume
  //  -- r6    : generator function
  //  -- cp    : generator context
  //  -- lr    : return address
  // -----------------------------------

  // Copy the function arguments from the generator object's register file.
  __ LoadTaggedField(
      r5, FieldMemOperand(r6, JSFunction::kSharedFunctionInfoOffset));
  __ LoadU16(
      r5, FieldMemOperand(r5, SharedFunctionInfo::kFormalParameterCountOffset));
  __ SubS64(r5, r5, Operand(kJSArgcReceiverSlots));
  __ LoadTaggedField(
      r4,
      FieldMemOperand(r3, JSGeneratorObject::kParametersAndRegistersOffset));
  {
    Label done_loop, loop;
    __ bind(&loop);
    __ SubS64(r5, r5, Operand(1));
    __ blt(&done_loop);
    __ ShiftLeftU64(r1, r5, Operand(kTaggedSizeLog2));
    __ la(scratch, MemOperand(r4, r1));
    __ LoadTaggedField(
        scratch, FieldMemOperand(scratch, OFFSET_OF_DATA_START(FixedArray)));
    __ Push(scratch);
    __ b(&loop);
    __ bind(&done_loop);

    // Push receiver.
    __ LoadTaggedField(scratch,
                       FieldMemOperand(r3, JSGeneratorObject::kReceiverOffset));
    __ Push(scratch);
  }

  // Underlying function needs to have bytecode available.
  if (v8_flags.debug_code) {
    Label is_baseline, is_unavailable, ok;
    __ LoadTaggedField(
        r5, FieldMemOperand(r6, JSFunction::kSharedFunctionInfoOffset));
    GetSharedFunctionInfoBytecodeOrBaseline(masm, r5, r5, ip, &is_baseline,
                                            &is_unavailable);
    __ jmp(&ok);

    __ bind(&is_unavailable);
    __ Abort(AbortReason::kMissingBytecodeArray);

    __ bind(&is_baseline);
    __ CompareObjectType(r5, r5, r5, CODE_TYPE);
    __ Assert(eq, AbortReason::kMissingBytecodeArray);

    __ bind(&ok);
  }

  // Resume (Ignition/TurboFan) generator object.
  {
    __ LoadTaggedField(
        r2, FieldMemOperand(r6, JSFunction::kSharedFunctionInfoOffset));
    __ LoadS16(r2, FieldMemOperand(
                       r2, SharedFunctionInfo::kFormalParameterCountOffset));
    // We abuse new.target both to indicate that this is a resume call and to
    // pass in the generator object.  In ordinary calls, new.target is always
    // undefined because generator functions are non-constructable.
    __ mov(r5, r3);
    __ mov(r3, r6);
    __ JumpJSFunction(r3);
  }

  __ bind(&prepare_step_in_if_stepping);
  {
    FrameAndConstantPoolScope scope(masm, StackFrame::INTERNAL);
    __ Push(r3, r6);
    // Push hole as receiver since we do not use it for stepping.
    __ PushRoot(RootIndex::kTheHoleValue);
    __ CallRuntime(Runtime::kDebugOnFunctionCall);
    __ Pop(r3);
    __ LoadTaggedField(r6,
                       FieldMemOperand(r3, JSGeneratorObject::kFunctionOffset));
  }
  __ b(&stepping_prepared);

  __ bind(&prepare_step_in_suspended_generator);
  {
    FrameAndConstantPoolScope scope(masm, StackFrame::INTERNAL);
    __ Push(r3);
    __ CallRuntime(Runtime::kDebugPrepareStepInSuspendedGenerator);
    __ Pop(r3);
    __ LoadTaggedField(r6,
                       FieldMemOperand(r3, JSGeneratorObject::kFunctionOffset));
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
  __ push(r3);
  __ CallRuntime(Runtime::kThrowConstructedNonConstructable);
  __ Trap();  // Unreachable.
}

namespace {

constexpr int kPushedStackSpace =
    (kNumCalleeSaved + 2) * kSystemPointerSize +
    kNumCalleeSavedDoubles * kDoubleSize + 7 * kSystemPointerSize +
    EntryFrameConstants::kNextFastCallFramePCOffset - kSystemPointerSize;

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
  //   r2:                             root register value
  //   r3:                             code entry
  //   r4:                             function
  //   r5:                             receiver
  //   r6:                             argc
  //   [sp + 20 * kSystemPointerSize]: argv
  // or
  //   r2: root_register_value
  //   r3: microtask_queue

  Label invoke, handler_entry, exit;

#if V8_OS_ZOS
  const int stack_space = 12 * kSystemPointerSize;

  // Store r4 - r15 to Stack
  __ StoreMultipleP(r4, sp, MemOperand(r4, kStackPointerBias - stack_space));
  // Grow stack
  __ lay(r4, MemOperand(r4, -stack_space));

  // Shuffle input XPLINK register arguments to match LoZ
  __ mov(sp, r4);
  __ mov(r4, r3);
  __ mov(r3, r2);
  __ mov(r2, r1);

  // Load args 4 and 5 from XPLINK extra frame slots in r5 and r6
  __ LoadMultipleP(
      r5, r6,
      MemOperand(sp, kStackPointerBias +
                         kXPLINKStackFrameExtraParamSlot * kSystemPointerSize +
                         stack_space));

  // Load arg 6 from XPLINK extra arg slot
  __ LoadU64(r0, MemOperand(sp, kStackPointerBias +
                                    kXPLINKStackFrameExtraParamSlot *
                                        kSystemPointerSize +
                                    stack_space + 2 * kSystemPointerSize));

  // Store arg 6 to expected LoZ save area
  __ StoreU64(r0, MemOperand(sp, kCalleeRegisterSaveAreaSize));
#endif

  int pushed_stack_space = 0;
  {
    NoRootArrayScope no_root_array(masm);

    // saving floating point registers
    // 64bit ABI requires f8 to f15 be saved
    // http://refspecs.linuxbase.org/ELF/zSeries/lzsabi0_zSeries.html
    __ lay(sp, MemOperand(sp, -8 * kDoubleSize));
    __ std(d8, MemOperand(sp));
    __ std(d9, MemOperand(sp, 1 * kDoubleSize));
    __ std(d10, MemOperand(sp, 2 * kDoubleSize));
    __ std(d11, MemOperand(sp, 3 * kDoubleSize));
    __ std(d12, MemOperand(sp, 4 * kDoubleSize));
    __ std(d13, MemOperand(sp, 5 * kDoubleSize));
    __ std(d14, MemOperand(sp, 6 * kDoubleSize));
    __ std(d15, MemOperand(sp, 7 * kDoubleSize));
    pushed_stack_space += kNumCalleeSavedDoubles * kDoubleSize;

    // zLinux ABI
    //    Incoming parameters:
    //          r2: root register value
    //          r3: code entry
    //          r4: function
    //          r5: receiver
    //          r6: argc
    // [sp + 20 * kSystemPointerSize]: argv
    //    Requires us to save the callee-preserved registers r6-r13
    //    General convention is to also save r14 (return addr) and
    //    sp/r15 as well in a single STM/STMG
    __ lay(sp, MemOperand(sp, -10 * kSystemPointerSize));
    __ StoreMultipleP(r6, sp, MemOperand(sp, 0));
    pushed_stack_space += (kNumCalleeSaved + 2) * kSystemPointerSize;

    // Initialize the root register.
    // C calling convention. The first argument is passed in r2.
    __ mov(kRootRegister, r2);
  }

  // Push a frame with special values setup to mark it as an entry frame.
  //   Bad FP (-1)
  //   SMI Marker
  //   SMI Marker
  //   kCEntryFPAddress
  //   Frame type
  // Clear c_entry_fp, now we've pushed its previous value to the stack.
  // If the c_entry_fp is not already zero and we don't clear it, the
  // StackFrameIteratorForProfiler will assume we are executing C++ and miss the
  // JS frames on top.
  pushed_stack_space += 7 * kSystemPointerSize;

  // Push a bad frame pointer to fail if it is used.
  __ mov(r0, Operand(-1));
  __ push(r0);

  __ mov(r0, Operand(StackFrame::TypeToMarker(type)));
  __ push(r0);
  __ push(r0);

  __ mov(r0, Operand::Zero());
  __ Move(ip, ExternalReference::Create(IsolateAddressId::kCEntryFPAddress,
                                        masm->isolate()));
  __ LoadU64(r9, MemOperand(ip));
  __ StoreU64(r0, MemOperand(ip));
  __ push(r9);

  __ LoadIsolateField(ip, IsolateFieldId::kFastCCallCallerFP);
  __ LoadU64(r9, MemOperand(ip));
  __ StoreU64(r0, MemOperand(ip));
  __ push(r9);

  __ LoadIsolateField(ip, IsolateFieldId::kFastCCallCallerPC);
  __ LoadU64(r9, MemOperand(ip));
```