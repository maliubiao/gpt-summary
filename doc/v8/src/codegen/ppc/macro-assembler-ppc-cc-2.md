Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/codegen/ppc/macro-assembler-ppc.cc`.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the core purpose:** The file name suggests it's part of the PowerPC (ppc) architecture support within V8's code generation (`codegen`) and specifically deals with the `MacroAssembler`. `MacroAssembler` is a class that provides an interface to generate machine code instructions in a more abstract and convenient way than directly writing assembly.

2. **Analyze the function names:**  The provided code is a collection of member functions of the `MacroAssembler` class. The function names are highly indicative of their purpose. Group thematically:
    * **Type Checking:** `CompareObjectType`, `CompareObjectTypeRange`, `CompareInstanceType`, `CompareInstanceTypeRange` - these are clearly related to verifying the type of JavaScript objects.
    * **Root Comparison:** `CompareTaggedRoot`, `CompareRoot` - these are about comparing objects against known "root" values within V8.
    * **Arithmetic with Overflow Checking:** `AddAndCheckForOverflow`, `SubAndCheckForOverflow` - these perform arithmetic operations and detect potential overflows.
    * **Floating-Point Operations:** `MinF64`, `MaxF64`, `TruncateDoubleToI`, `TryInlineTruncateDoubleToI` - these deal with double-precision floating-point numbers.
    * **Optimized Code Handling:** `TailCallOptimizedCodeSlot`, `ReplaceClosureCodeWithOptimizedCode`, `GenerateTailCallToReturnedCode`, `LoadFeedbackVectorFlagsAndJumpIfNeedsProcessing`, `OptimizeCodeOrTailCallOptimizedCodeSlot` - these are related to how V8 handles optimized (TurboFan/Maglev) code.
    * **Runtime Calls:** `CallRuntime`, `TailCallRuntime`, `JumpToExternalReference` - these functions are for calling V8's runtime functions (implemented in C++).
    * **Weak References:** `LoadWeakValue` - this deals with weak references, a mechanism for referencing objects without preventing their garbage collection.
    * **Counters:** `EmitIncrementCounter`, `EmitDecrementCounter` - these are for updating performance counters.
    * **Assertions and Aborting:** `Check`, `Abort`, `Assert...` - these are for debugging and ensuring the correctness of the generated code.
    * **Object Loading:** `LoadMap`, `LoadFeedbackVector`, `LoadCompressedMap`, `LoadNativeContextSlot` - these are for retrieving information from JavaScript objects.
    * **C Function Calls:** `PrepareCallCFunction`, `CallCFunction` - these are for calling external C functions.

3. **Infer the overall functionality:** Based on the function groupings, it's clear this part of `MacroAssembler` provides functionalities for:
    * Performing type checks on JavaScript objects.
    * Comparing objects with special V8 internal objects (roots).
    * Performing arithmetic operations with overflow detection.
    * Handling floating-point number conversions and comparisons.
    * Managing the execution of optimized code.
    * Interacting with the V8 runtime system.
    * Handling weak references.
    * Tracking performance metrics.
    * Providing debugging and assertion capabilities.
    * Loading object properties.
    * Facilitating calls to external C functions.

4. **Address specific instructions:**
    * **`.tq` extension:** The code is in `.cc`, so it's C++, not Torque.
    * **JavaScript relationship:**  Many of the functions are directly related to JavaScript concepts like object types, function calls, and optimized code. The example demonstrates type checking, a fundamental part of JavaScript's dynamic nature.
    * **Code logic reasoning:**  The `CompareRange` function is a good example. Provide a simple input and output to illustrate its behavior.
    * **Common programming errors:**  Overflow during arithmetic is a common error. The `AddAndCheckForOverflow` functions are designed to catch this. Provide a C++ example that highlights the potential issue.

5. **Structure the summary:** Organize the findings into a clear and concise summary, addressing all the user's requests. Use bullet points for readability.

6. **Review and refine:** Ensure the summary accurately reflects the code's functionality and addresses all aspects of the prompt. Check for clarity and conciseness. For instance, initially, I might have just listed function names, but then refined it to group thematically for better understanding. Also, ensure the JavaScript and C++ examples are relevant and easy to understand.
这是 `v8/src/codegen/ppc/macro-assembler-ppc.cc` 文件的第三部分，它定义了 `MacroAssembler` 类的一些成员函数，这些函数用于生成 PowerPC (ppc) 架构的机器码指令。

**功能归纳：**

这部分代码主要提供了以下功能，用于在 PowerPC 架构上生成用于 V8 引擎的代码：

* **对象类型比较：** 提供了一系列函数 (`CompareObjectType`, `CompareObjectTypeRange`, `CompareInstanceType`, `CompareInstanceTypeRange`)，用于比较 JavaScript 对象的类型，判断对象是否属于特定的类型或类型范围。这些比较通常基于对象的 `map` 属性中的 `InstanceType` 信息。
* **根对象比较：** 提供了函数 (`CompareTaggedRoot`, `CompareRoot`)，用于将对象与 V8 引擎预定义的“根”对象进行比较。这些根对象包含特殊的值，例如 `undefined`，`null`，`true`，`false` 等。
* **带溢出检查的算术运算：** 提供了函数 (`AddAndCheckForOverflow`, `SubAndCheckForOverflow`)，用于执行加法和减法运算，并检查是否发生溢出。这对于处理可能超出 JavaScript Number 安全范围的数值非常重要。
* **浮点数运算：** 提供了函数 (`MinF64`, `MaxF64`) 用于计算两个双精度浮点数的最小值和最大值，并处理 NaN 的情况。还提供了将双精度浮点数截断为整数的函数 (`TruncateDoubleToI`, `TryInlineTruncateDoubleToI`)。
* **跳转到指定范围：**  提供了 `JumpIfIsInRange` 函数，用于判断一个值是否在给定的范围内，并在范围内时跳转到指定的标签。
* **尾调用优化代码槽：** 提供了 `TailCallOptimizedCodeSlot` 函数，用于处理尾调用优化后的代码。它会检查优化后的代码是否可用，如果可用则跳转到优化后的代码执行。
* **替换闭包代码：** 提供了 `ReplaceClosureCodeWithOptimizedCode` 函数，用于将闭包对象的代码替换为优化后的代码。
* **生成到返回代码的尾调用：** 提供了 `GenerateTailCallToReturnedCode` 函数，用于生成尾调用到 V8 运行时函数的代码。
* **加载反馈向量标志并检查是否需要处理：** 提供了 `LoadFeedbackVectorFlagsAndJumpIfNeedsProcessing` 函数，用于加载反馈向量中的标志位，并根据标志位判断是否需要进行进一步的处理，例如触发优化编译。
* **优化代码或尾调用优化代码槽：** 提供了 `OptimizeCodeOrTailCallOptimizedCodeSlot` 函数，根据反馈向量的标志位，决定是触发优化编译还是尾调用已经存在的优化代码。
* **调用运行时函数：** 提供了 `CallRuntime` 函数，用于调用 V8 引擎的运行时 (C++) 函数。
* **尾调用运行时函数：** 提供了 `TailCallRuntime` 函数，用于尾调用 V8 引擎的运行时函数。
* **跳转到外部引用：** 提供了 `JumpToExternalReference` 函数，用于跳转到外部 (C++) 函数的地址。
* **加载弱引用值：** 提供了 `LoadWeakValue` 函数，用于加载弱引用的值，如果弱引用已被清除，则跳转到指定标签。
* **发射计数器增减指令：** 提供了 `EmitIncrementCounter` 和 `EmitDecrementCounter` 函数，用于增加或减少性能计数器的值。
* **条件检查和中止：** 提供了 `Check` 和 `Abort` 函数，用于在满足特定条件时中止程序执行，通常用于断言和错误处理。
* **加载对象属性：** 提供了 `LoadMap`，`LoadFeedbackVector`，`LoadCompressedMap`，`LoadNativeContextSlot` 等函数，用于加载对象的 `map`、反馈向量、压缩 map 和本地上下文槽等信息。
* **断言（Debug 代码）：**  在 `V8_ENABLE_DEBUG_CODE` 宏开启的情况下，提供了一系列 `Assert...` 函数，用于在开发和调试阶段进行各种断言检查，例如断言对象不是 Smi，是特定类型的对象等。
* **准备和调用 C 函数：** 提供了 `PrepareCallCFunction` 和 `CallCFunction` 函数，用于准备调用外部 C 函数的栈帧，并执行调用。

**如果 `v8/src/codegen/ppc/macro-assembler-ppc.cc` 以 `.tq` 结尾，那它是个 v8 torque 源代码。**

但根据你提供的信息，该文件以 `.cc` 结尾，因此它是 **C++ 源代码**，而不是 Torque 源代码。 Torque 是一种 V8 自研的用于生成高效的内置函数的领域特定语言。

**如果它与 javascript 的功能有关系，请用 javascript 举例说明:**

`CompareObjectType` 函数直接关联到 JavaScript 的类型检查。例如，在 JavaScript 中，我们经常需要判断一个变量的类型：

```javascript
function processObject(obj) {
  if (typeof obj === 'string') {
    console.log("It's a string:", obj);
  } else if (Array.isArray(obj)) {
    console.log("It's an array:", obj);
  } else if (obj instanceof Date) {
    console.log("It's a Date object:", obj);
  } else {
    console.log("It's some other object:", obj);
  }
}

processObject("hello");
processObject([1, 2, 3]);
processObject(new Date());
processObject({ a: 1 });
```

在 V8 引擎的底层，当执行这些类型检查时，`CompareObjectType` 或类似的函数会被调用，比较 `obj` 的内部 `InstanceType` 与预定义的类型（例如 `STRING_TYPE`, `JS_ARRAY_TYPE`, `JS_DATE_TYPE` 等）。

**如果有代码逻辑推理，请给出假设输入与输出:**

考虑 `CompareRange` 函数：

```c++
void MacroAssembler::CompareRange(Register value, Register scratch,
                                  unsigned lower_limit, unsigned higher_limit) {
  ASM_CODE_COMMENT(this);
  DCHECK_LT(lower_limit, higher_limit);
  if (lower_limit != 0) {
    mov(scratch, Operand(lower_limit));
    sub(scratch, value, scratch);
    cmpli(scratch, Operand(higher_limit - lower_limit));
  } else {
    mov(scratch, Operand(higher_limit));
    CmpU64(value, scratch);
  }
}
```

**假设输入：**

* `value` 寄存器包含值 `5`
* `scratch` 寄存器可以是任意值，会被覆盖
* `lower_limit` 为 `2`
* `higher_limit` 为 `8`

**代码逻辑推理：**

1. `lower_limit` (2) 不等于 0，进入 `if` 分支。
2. 将 `lower_limit` (2) 移动到 `scratch` 寄存器。
3. 执行 `sub(scratch, value, scratch)`，等价于 `scratch = value - scratch`，即 `scratch = 5 - 2 = 3`。
4. 执行 `cmpli(scratch, Operand(higher_limit - lower_limit))`，即比较 `scratch` (3) 与 `higher_limit - lower_limit` (8 - 2 = 6)。

**输出（根据比较结果）：**

比较指令会设置处理器的标志位，后续的条件跳转指令可以根据这些标志位来决定是否跳转。在这个例子中，因为 `3 < 6`，所以 `cmpli` 指令会设置相应的标志位，表示值在范围内。

**如果涉及用户常见的编程错误，请举例说明:**

`AddAndCheckForOverflow` 和 `SubAndCheckForOverflow` 函数旨在捕获算术溢出，这在 JavaScript 中也是一个需要注意的问题。虽然 JavaScript 的 `Number` 类型是双精度浮点数，可以表示很大的数值，但在进行位运算或特定场景下，仍然可能发生溢出。

**C++ 示例（模拟溢出）：**

```c++
#include <iostream>
#include <limits>

int main() {
  int max_int = std::numeric_limits<int>::max();
  int a = max_int;
  int b = 1;
  int sum = a + b; // 发生溢出，结果是未定义的行为

  std::cout << "Sum: " << sum << std::endl; // 输出可能会是负数

  return 0;
}
```

在上述 C++ 代码中，将 `int` 类型的最大值加 1 会导致溢出，结果通常会回绕到最小值。`AddAndCheckForOverflow` 函数在 V8 的代码生成过程中，会生成指令来检测这种溢出情况，并可能触发异常或采取其他处理措施，以保证 JavaScript 的语义正确性。

**总结一下它的功能 (针对提供的代码片段):**

这段代码是 `MacroAssembler` 类的一部分，专注于提供用于生成 PowerPC 架构机器码的底层操作，特别是在以下方面：

* **类型检查和比较：** 比较 JavaScript 对象的类型和与特定根对象的相等性。
* **算术运算与溢出检测：** 执行基本的算术运算，并显式地检查是否发生溢出。
* **浮点数处理：** 提供浮点数的比较、最值计算和截断操作。
* **优化代码管理：** 负责处理优化后的代码的加载、链接和尾调用。
* **运行时交互：** 提供调用和尾调用 V8 运行时函数的能力。
* **底层工具函数：** 提供加载弱引用、更新计数器、进行断言和中止执行等辅助功能。
* **C 函数调用：**  支持调用外部 C 函数。

这些功能是 V8 引擎在 PowerPC 架构上生成高效、正确的 JavaScript 执行代码的基础构建块。

Prompt: 
```
这是目录为v8/src/codegen/ppc/macro-assembler-ppc.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/ppc/macro-assembler-ppc.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共7部分，请归纳一下它的功能

"""
 InstanceType type) {
  ASM_CODE_COMMENT(this);

#if V8_STATIC_ROOTS_BOOL
  if (InstanceTypeChecker::UniqueMapOfInstanceType(type)) {
    DCHECK((scratch1 != scratch2) || (scratch1 != r0));
    LoadCompressedMap(scratch1, object, scratch1 != scratch2 ? scratch2 : r0);
    CompareInstanceTypeWithUniqueCompressedMap(
        scratch1, scratch1 != scratch2 ? scratch2 : r0, type);
    return;
  }
#endif  // V8_STATIC_ROOTS_BOOL

  CompareObjectType(object, scratch1, scratch2, type);
}

void MacroAssembler::CompareObjectType(Register object, Register map,
                                       Register type_reg, InstanceType type) {
  const Register temp = type_reg == no_reg ? r0 : type_reg;

  LoadMap(map, object);
  CompareInstanceType(map, temp, type);
}

void MacroAssembler::CompareObjectTypeRange(Register object, Register map,
                                            Register type_reg, Register scratch,
                                            InstanceType lower_limit,
                                            InstanceType upper_limit) {
  ASM_CODE_COMMENT(this);
  LoadMap(map, object);
  CompareInstanceTypeRange(map, type_reg, scratch, lower_limit, upper_limit);
}

void MacroAssembler::CompareInstanceType(Register map, Register type_reg,
                                         InstanceType type) {
  static_assert(Map::kInstanceTypeOffset < 4096);
  static_assert(LAST_TYPE <= 0xFFFF);
  lhz(type_reg, FieldMemOperand(map, Map::kInstanceTypeOffset));
  cmpi(type_reg, Operand(type));
}

void MacroAssembler::CompareRange(Register value, Register scratch,
                                  unsigned lower_limit, unsigned higher_limit) {
  ASM_CODE_COMMENT(this);
  DCHECK_LT(lower_limit, higher_limit);
  if (lower_limit != 0) {
    mov(scratch, Operand(lower_limit));
    sub(scratch, value, scratch);
    cmpli(scratch, Operand(higher_limit - lower_limit));
  } else {
    mov(scratch, Operand(higher_limit));
    CmpU64(value, scratch);
  }
}

void MacroAssembler::CompareInstanceTypeRange(Register map, Register type_reg,
                                              Register scratch,
                                              InstanceType lower_limit,
                                              InstanceType higher_limit) {
  DCHECK_LT(lower_limit, higher_limit);
  LoadU16(type_reg, FieldMemOperand(map, Map::kInstanceTypeOffset));
  CompareRange(type_reg, scratch, lower_limit, higher_limit);
}

void MacroAssembler::CompareTaggedRoot(const Register& obj, RootIndex index) {
  ASM_CODE_COMMENT(this);
  // Use r0 as a safe scratch register here, since temps.Acquire() tends
  // to spit back the register being passed as an argument in obj...
  Register temp = r0;
  DCHECK(!AreAliased(obj, temp));

  if (V8_STATIC_ROOTS_BOOL && RootsTable::IsReadOnly(index)) {
    mov(temp, Operand(ReadOnlyRootPtr(index)));
    CompareTagged(obj, temp);
    return;
  }
  // Some smi roots contain system pointer size values like stack limits.
  DCHECK(base::IsInRange(index, RootIndex::kFirstStrongOrReadOnlyRoot,
                         RootIndex::kLastStrongOrReadOnlyRoot));
  LoadRoot(temp, index);
  CompareTagged(obj, temp);
}

void MacroAssembler::CompareRoot(Register obj, RootIndex index) {
  ASM_CODE_COMMENT(this);
  // Use r0 as a safe scratch register here, since temps.Acquire() tends
  // to spit back the register being passed as an argument in obj...
  Register temp = r0;
  if (!base::IsInRange(index, RootIndex::kFirstStrongOrReadOnlyRoot,
                       RootIndex::kLastStrongOrReadOnlyRoot)) {
    // Some smi roots contain system pointer size values like stack limits.
    DCHECK(!AreAliased(obj, temp));
    LoadRoot(temp, index);
    CmpU64(obj, temp);
    return;
  }
  CompareTaggedRoot(obj, index);
}

void MacroAssembler::AddAndCheckForOverflow(Register dst, Register left,
                                            Register right,
                                            Register overflow_dst,
                                            Register scratch) {
  DCHECK(dst != overflow_dst);
  DCHECK(dst != scratch);
  DCHECK(overflow_dst != scratch);
  DCHECK(overflow_dst != left);
  DCHECK(overflow_dst != right);

  bool left_is_right = left == right;
  RCBit xorRC = left_is_right ? SetRC : LeaveRC;

  // C = A+B; C overflows if A/B have same sign and C has diff sign than A
  if (dst == left) {
    mr(scratch, left);                        // Preserve left.
    add(dst, left, right);                    // Left is overwritten.
    xor_(overflow_dst, dst, scratch, xorRC);  // Original left.
    if (!left_is_right) xor_(scratch, dst, right);
  } else if (dst == right) {
    mr(scratch, right);     // Preserve right.
    add(dst, left, right);  // Right is overwritten.
    xor_(overflow_dst, dst, left, xorRC);
    if (!left_is_right) xor_(scratch, dst, scratch);  // Original right.
  } else {
    add(dst, left, right);
    xor_(overflow_dst, dst, left, xorRC);
    if (!left_is_right) xor_(scratch, dst, right);
  }
  if (!left_is_right) and_(overflow_dst, scratch, overflow_dst, SetRC);
}

void MacroAssembler::AddAndCheckForOverflow(Register dst, Register left,
                                            intptr_t right,
                                            Register overflow_dst,
                                            Register scratch) {
  Register original_left = left;
  DCHECK(dst != overflow_dst);
  DCHECK(dst != scratch);
  DCHECK(overflow_dst != scratch);
  DCHECK(overflow_dst != left);

  // C = A+B; C overflows if A/B have same sign and C has diff sign than A
  if (dst == left) {
    // Preserve left.
    original_left = overflow_dst;
    mr(original_left, left);
  }
  AddS64(dst, left, Operand(right), scratch);
  xor_(overflow_dst, dst, original_left);
  if (right >= 0) {
    and_(overflow_dst, overflow_dst, dst, SetRC);
  } else {
    andc(overflow_dst, overflow_dst, dst, SetRC);
  }
}

void MacroAssembler::SubAndCheckForOverflow(Register dst, Register left,
                                            Register right,
                                            Register overflow_dst,
                                            Register scratch) {
  DCHECK(dst != overflow_dst);
  DCHECK(dst != scratch);
  DCHECK(overflow_dst != scratch);
  DCHECK(overflow_dst != left);
  DCHECK(overflow_dst != right);

  // C = A-B; C overflows if A/B have diff signs and C has diff sign than A
  if (dst == left) {
    mr(scratch, left);      // Preserve left.
    sub(dst, left, right);  // Left is overwritten.
    xor_(overflow_dst, dst, scratch);
    xor_(scratch, scratch, right);
    and_(overflow_dst, overflow_dst, scratch, SetRC);
  } else if (dst == right) {
    mr(scratch, right);     // Preserve right.
    sub(dst, left, right);  // Right is overwritten.
    xor_(overflow_dst, dst, left);
    xor_(scratch, left, scratch);
    and_(overflow_dst, overflow_dst, scratch, SetRC);
  } else {
    sub(dst, left, right);
    xor_(overflow_dst, dst, left);
    xor_(scratch, left, right);
    and_(overflow_dst, scratch, overflow_dst, SetRC);
  }
}

void MacroAssembler::MinF64(DoubleRegister dst, DoubleRegister lhs,
                            DoubleRegister rhs, DoubleRegister scratch) {
  Label return_nan, done;
  fcmpu(lhs, rhs);
  bunordered(&return_nan);
  xsmindp(dst, lhs, rhs);
  b(&done);
  bind(&return_nan);
  /* If left or right are NaN, fadd propagates the appropriate one.*/
  fadd(dst, lhs, rhs);
  bind(&done);
}

void MacroAssembler::MaxF64(DoubleRegister dst, DoubleRegister lhs,
                            DoubleRegister rhs, DoubleRegister scratch) {
  Label return_nan, done;
  fcmpu(lhs, rhs);
  bunordered(&return_nan);
  xsmaxdp(dst, lhs, rhs);
  b(&done);
  bind(&return_nan);
  /* If left or right are NaN, fadd propagates the appropriate one.*/
  fadd(dst, lhs, rhs);
  bind(&done);
}

void MacroAssembler::JumpIfIsInRange(Register value, Register scratch,
                                     unsigned lower_limit,
                                     unsigned higher_limit,
                                     Label* on_in_range) {
  CompareRange(value, scratch, lower_limit, higher_limit);
  ble(on_in_range);
}

void MacroAssembler::TruncateDoubleToI(Isolate* isolate, Zone* zone,
                                       Register result,
                                       DoubleRegister double_input,
                                       StubCallMode stub_mode) {
  Label done;

  TryInlineTruncateDoubleToI(result, double_input, &done);

  // If we fell through then inline version didn't succeed - call stub instead.
  mflr(r0);
  push(r0);
  // Put input on stack.
  stfdu(double_input, MemOperand(sp, -kDoubleSize));

#if V8_ENABLE_WEBASSEMBLY
  if (stub_mode == StubCallMode::kCallWasmRuntimeStub) {
    Call(static_cast<Address>(Builtin::kDoubleToI), RelocInfo::WASM_STUB_CALL);
#else
  // For balance.
  if (false) {
#endif  // V8_ENABLE_WEBASSEMBLY
  } else {
    CallBuiltin(Builtin::kDoubleToI);
  }

  LoadU64(result, MemOperand(sp));
  addi(sp, sp, Operand(kDoubleSize));
  pop(r0);
  mtlr(r0);

  bind(&done);
}

void MacroAssembler::TryInlineTruncateDoubleToI(Register result,
                                                DoubleRegister double_input,
                                                Label* done) {
  DoubleRegister double_scratch = kScratchDoubleReg;
  ConvertDoubleToInt64(double_input,
                       result, double_scratch);

// Test for overflow
  TestIfInt32(result, r0);
  beq(done);
}

namespace {

void TailCallOptimizedCodeSlot(MacroAssembler* masm,
                               Register optimized_code_entry,
                               Register scratch) {
  // ----------- S t a t e -------------
  //  -- r3 : actual argument count
  //  -- r6 : new target (preserved for callee if needed, and caller)
  //  -- r4 : target function (preserved for callee if needed, and caller)
  // -----------------------------------
  DCHECK(!AreAliased(r4, r6, optimized_code_entry, scratch));

  Register closure = r4;
  Label heal_optimized_code_slot;

  // If the optimized code is cleared, go to runtime to update the optimization
  // marker field.
  __ LoadWeakValue(optimized_code_entry, optimized_code_entry,
                   &heal_optimized_code_slot);

  // The entry references a CodeWrapper object. Unwrap it now.
  __ LoadCodePointerField(
      optimized_code_entry,
      FieldMemOperand(optimized_code_entry, CodeWrapper::kCodeOffset), scratch);

  // Check if the optimized code is marked for deopt. If it is, call the
  // runtime to clear it.
  {
    UseScratchRegisterScope temps(masm);
    __ TestCodeIsMarkedForDeoptimization(optimized_code_entry, temps.Acquire(),
                                         scratch);
    __ bne(&heal_optimized_code_slot, cr0);
  }

  // Optimized code is good, get it into the closure and link the closure
  // into the optimized functions list, then tail call the optimized code.
  __ ReplaceClosureCodeWithOptimizedCode(optimized_code_entry, closure, scratch,
                                         r8);
  static_assert(kJavaScriptCallCodeStartRegister == r5, "ABI mismatch");
  __ LoadCodeInstructionStart(r5, optimized_code_entry);
  __ Jump(r5);

  // Optimized code slot contains deoptimized code or code is cleared and
  // optimized code marker isn't updated. Evict the code, update the marker
  // and re-enter the closure's code.
  __ bind(&heal_optimized_code_slot);
  __ GenerateTailCallToReturnedCode(Runtime::kHealOptimizedCodeSlot);
}

}  // namespace

#ifdef V8_ENABLE_DEBUG_CODE
void MacroAssembler::AssertFeedbackCell(Register object, Register scratch) {
  if (v8_flags.debug_code) {
    CompareObjectType(object, scratch, scratch, FEEDBACK_CELL_TYPE);
    Assert(eq, AbortReason::kExpectedFeedbackCell);
  }
}
void MacroAssembler::AssertFeedbackVector(Register object, Register scratch) {
  if (v8_flags.debug_code) {
    CompareObjectType(object, scratch, scratch, FEEDBACK_VECTOR_TYPE);
    Assert(eq, AbortReason::kExpectedFeedbackVector);
  }
}
#endif  // V8_ENABLE_DEBUG_CODE

// Optimized code is good, get it into the closure and link the closure
// into the optimized functions list, then tail call the optimized code.
void MacroAssembler::ReplaceClosureCodeWithOptimizedCode(
    Register optimized_code, Register closure, Register scratch1,
    Register slot_address) {
  DCHECK(!AreAliased(optimized_code, closure, scratch1, slot_address));
  DCHECK_EQ(closure, kJSFunctionRegister);
  DCHECK(!AreAliased(optimized_code, closure));
  // Store code entry in the closure.
  StoreCodePointerField(optimized_code,
                        FieldMemOperand(closure, JSFunction::kCodeOffset), r0);
  // Write barrier clobbers scratch1 below.
  Register value = scratch1;
  mr(value, optimized_code);

  RecordWriteField(closure, JSFunction::kCodeOffset, value, slot_address,
                   kLRHasNotBeenSaved, SaveFPRegsMode::kIgnore, SmiCheck::kOmit,
                   SlotDescriptor::ForCodePointerSlot());
}

void MacroAssembler::GenerateTailCallToReturnedCode(
    Runtime::FunctionId function_id) {
  // ----------- S t a t e -------------
  //  -- r3 : actual argument count
  //  -- r4 : target function (preserved for callee)
  //  -- r6 : new target (preserved for callee)
  // -----------------------------------
  {
    FrameAndConstantPoolScope scope(this, StackFrame::INTERNAL);
    // Push a copy of the target function, the new target and the actual
    // argument count.
    // Push function as parameter to the runtime call.
    SmiTag(kJavaScriptCallArgCountRegister);
    Push(kJavaScriptCallTargetRegister, kJavaScriptCallNewTargetRegister,
         kJavaScriptCallArgCountRegister, kJavaScriptCallTargetRegister);

    CallRuntime(function_id, 1);
    mr(r5, r3);

    // Restore target function, new target and actual argument count.
    Pop(kJavaScriptCallTargetRegister, kJavaScriptCallNewTargetRegister,
        kJavaScriptCallArgCountRegister);
    SmiUntag(kJavaScriptCallArgCountRegister);
  }
  static_assert(kJavaScriptCallCodeStartRegister == r5, "ABI mismatch");
  JumpCodeObject(r5);
}

// Read off the flags in the feedback vector and check if there
// is optimized code or a tiering state that needs to be processed.
void MacroAssembler::LoadFeedbackVectorFlagsAndJumpIfNeedsProcessing(
    Register flags, Register feedback_vector, CodeKind current_code_kind,
    Label* flags_need_processing) {
  ASM_CODE_COMMENT(this);
  DCHECK(!AreAliased(flags, feedback_vector));
  DCHECK(CodeKindCanTierUp(current_code_kind));
  LoadU16(flags,
          FieldMemOperand(feedback_vector, FeedbackVector::kFlagsOffset));
  uint32_t kFlagsMask = FeedbackVector::kFlagsTieringStateIsAnyRequested |
                        FeedbackVector::kFlagsMaybeHasTurbofanCode |
                        FeedbackVector::kFlagsLogNextExecution;
  if (current_code_kind != CodeKind::MAGLEV) {
    kFlagsMask |= FeedbackVector::kFlagsMaybeHasMaglevCode;
  }
  CHECK(is_uint16(kFlagsMask));
  mov(r0, Operand(kFlagsMask));
  AndU32(r0, flags, r0, SetRC);
  bne(flags_need_processing, cr0);
}

void MacroAssembler::OptimizeCodeOrTailCallOptimizedCodeSlot(
    Register flags, Register feedback_vector) {
  DCHECK(!AreAliased(flags, feedback_vector));
  Label maybe_has_optimized_code, maybe_needs_logging;
  // Check if optimized code is available
  TestBitMask(flags, FeedbackVector::kFlagsTieringStateIsAnyRequested, r0);
  beq(&maybe_needs_logging, cr0);

  GenerateTailCallToReturnedCode(Runtime::kCompileOptimized);

  bind(&maybe_needs_logging);
  TestBitMask(flags, FeedbackVector::LogNextExecutionBit::kMask, r0);
  beq(&maybe_has_optimized_code, cr0);
  GenerateTailCallToReturnedCode(Runtime::kFunctionLogNextExecution);

  bind(&maybe_has_optimized_code);
  Register optimized_code_entry = flags;
  LoadTaggedField(optimized_code_entry,
                  FieldMemOperand(feedback_vector,
                                  FeedbackVector::kMaybeOptimizedCodeOffset),
                  r0);
  TailCallOptimizedCodeSlot(this, optimized_code_entry, r9);
}

void MacroAssembler::CallRuntime(const Runtime::Function* f,
                                 int num_arguments) {
  // All parameters are on the stack.  r3 has the return value after call.

  // If the expected number of arguments of the runtime function is
  // constant, we check that the actual number of arguments match the
  // expectation.
  CHECK(f->nargs < 0 || f->nargs == num_arguments);

  // TODO(1236192): Most runtime routines don't need the number of
  // arguments passed in because it is constant. At some point we
  // should remove this need and make the runtime routine entry code
  // smarter.
  mov(r3, Operand(num_arguments));
  Move(r4, ExternalReference::Create(f));
  CallBuiltin(Builtins::RuntimeCEntry(f->result_size));
}

void MacroAssembler::TailCallRuntime(Runtime::FunctionId fid) {
  const Runtime::Function* function = Runtime::FunctionForId(fid);
  DCHECK_EQ(1, function->result_size);
  if (function->nargs >= 0) {
    mov(r3, Operand(function->nargs));
  }
  JumpToExternalReference(ExternalReference::Create(fid));
}

void MacroAssembler::JumpToExternalReference(const ExternalReference& builtin,
                                             bool builtin_exit_frame) {
  Move(r4, builtin);
  TailCallBuiltin(Builtins::CEntry(1, ArgvMode::kStack, builtin_exit_frame));
}

void MacroAssembler::LoadWeakValue(Register out, Register in,
                                   Label* target_if_cleared) {
  CmpS32(in, Operand(kClearedWeakHeapObjectLower32), r0);
  beq(target_if_cleared);

  mov(r0, Operand(~kWeakHeapObjectMask));
  and_(out, in, r0);
}

void MacroAssembler::EmitIncrementCounter(StatsCounter* counter, int value,
                                          Register scratch1,
                                          Register scratch2) {
  DCHECK_GT(value, 0);
  if (v8_flags.native_code_counters && counter->Enabled()) {
    // This operation has to be exactly 32-bit wide in case the external
    // reference table redirects the counter to a uint32_t dummy_stats_counter_
    // field.
    Move(scratch2, ExternalReference::Create(counter));
    lwz(scratch1, MemOperand(scratch2));
    addi(scratch1, scratch1, Operand(value));
    stw(scratch1, MemOperand(scratch2));
  }
}

void MacroAssembler::EmitDecrementCounter(StatsCounter* counter, int value,
                                          Register scratch1,
                                          Register scratch2) {
  DCHECK_GT(value, 0);
  if (v8_flags.native_code_counters && counter->Enabled()) {
    // This operation has to be exactly 32-bit wide in case the external
    // reference table redirects the counter to a uint32_t dummy_stats_counter_
    // field.
    Move(scratch2, ExternalReference::Create(counter));
    lwz(scratch1, MemOperand(scratch2));
    subi(scratch1, scratch1, Operand(value));
    stw(scratch1, MemOperand(scratch2));
  }
}

void MacroAssembler::Check(Condition cond, AbortReason reason, CRegister cr) {
  Label L;
  b(cond, &L, cr);
  Abort(reason);
  // will not return here
  bind(&L);
}

void MacroAssembler::Abort(AbortReason reason) {
  Label abort_start;
  bind(&abort_start);
  if (v8_flags.code_comments) {
    const char* msg = GetAbortReason(reason);
    RecordComment("Abort message: ");
    RecordComment(msg);
  }

  // Avoid emitting call to builtin if requested.
  if (trap_on_abort()) {
    stop();
    return;
  }

  if (should_abort_hard()) {
    // We don't care if we constructed a frame. Just pretend we did.
    FrameScope assume_frame(this, StackFrame::NO_FRAME_TYPE);
    mov(r3, Operand(static_cast<int>(reason)));
    PrepareCallCFunction(1, 0, r4);
    Register dst = ip;
    if (!ABI_CALL_VIA_IP) {
      dst = r4;
    }
    Move(dst, ExternalReference::abort_with_reason());
    // Use Call directly to avoid any unneeded overhead. The function won't
    // return anyway.
    Call(dst);
    return;
  }

  LoadSmiLiteral(r4, Smi::FromInt(static_cast<int>(reason)));

  {
    // We don't actually want to generate a pile of code for this, so just
    // claim there is a stack frame, without generating one.
    FrameScope scope(this, StackFrame::NO_FRAME_TYPE);
    if (root_array_available()) {
      // Generate an indirect call via builtins entry table here in order to
      // ensure that the interpreter_entry_return_pc_offset is the same for
      // InterpreterEntryTrampoline and InterpreterEntryTrampolineForProfiling
      // when v8_flags.debug_code is enabled.
      LoadEntryFromBuiltin(Builtin::kAbort, ip);
      Call(ip);
    } else {
      CallBuiltin(Builtin::kAbort);
    }
  }
  // will not return here
}

void MacroAssembler::LoadMap(Register destination, Register object) {
  LoadTaggedField(destination, FieldMemOperand(object, HeapObject::kMapOffset),
                  r0);
}

void MacroAssembler::LoadFeedbackVector(Register dst, Register closure,
                                        Register scratch, Label* fbv_undef) {
  Label done;

  // Load the feedback vector from the closure.
  LoadTaggedField(
      dst, FieldMemOperand(closure, JSFunction::kFeedbackCellOffset), r0);
  LoadTaggedField(dst, FieldMemOperand(dst, FeedbackCell::kValueOffset), r0);

  // Check if feedback vector is valid.
  LoadTaggedField(scratch, FieldMemOperand(dst, HeapObject::kMapOffset), r0);
  LoadU16(scratch, FieldMemOperand(scratch, Map::kInstanceTypeOffset));
  CmpS32(scratch, Operand(FEEDBACK_VECTOR_TYPE), r0);
  b(eq, &done);

  // Not valid, load undefined.
  LoadRoot(dst, RootIndex::kUndefinedValue);
  b(fbv_undef);

  bind(&done);
}

void MacroAssembler::LoadCompressedMap(Register dst, Register object,
                                       Register scratch) {
  ASM_CODE_COMMENT(this);
  LoadU32(dst, FieldMemOperand(object, HeapObject::kMapOffset), scratch);
}

void MacroAssembler::LoadNativeContextSlot(Register dst, int index) {
  LoadMap(dst, cp);
  LoadTaggedField(
      dst,
      FieldMemOperand(dst, Map::kConstructorOrBackPointerOrNativeContextOffset),
      r0);
  LoadTaggedField(dst, MemOperand(dst, Context::SlotOffset(index)), r0);
}

#ifdef V8_ENABLE_DEBUG_CODE
void MacroAssembler::Assert(Condition cond, AbortReason reason, CRegister cr) {
  if (v8_flags.debug_code) Check(cond, reason, cr);
}

void MacroAssembler::AssertNotSmi(Register object) {
  if (v8_flags.debug_code) {
    static_assert(kSmiTag == 0);
    TestIfSmi(object, r0);
    Check(ne, AbortReason::kOperandIsASmi, cr0);
  }
}

void MacroAssembler::AssertSmi(Register object) {
  if (v8_flags.debug_code) {
    static_assert(kSmiTag == 0);
    TestIfSmi(object, r0);
    Check(eq, AbortReason::kOperandIsNotASmi, cr0);
  }
}

void MacroAssembler::AssertConstructor(Register object) {
  if (v8_flags.debug_code) {
    static_assert(kSmiTag == 0);
    TestIfSmi(object, r0);
    Check(ne, AbortReason::kOperandIsASmiAndNotAConstructor, cr0);
    push(object);
    LoadMap(object, object);
    lbz(object, FieldMemOperand(object, Map::kBitFieldOffset));
    andi(object, object, Operand(Map::Bits1::IsConstructorBit::kMask));
    pop(object);
    Check(ne, AbortReason::kOperandIsNotAConstructor, cr0);
  }
}

void MacroAssembler::AssertFunction(Register object) {
  if (v8_flags.debug_code) {
    static_assert(kSmiTag == 0);
    TestIfSmi(object, r0);
    Check(ne, AbortReason::kOperandIsASmiAndNotAFunction, cr0);
    push(object);
    LoadMap(object, object);
    CompareInstanceTypeRange(object, object, r0, FIRST_JS_FUNCTION_TYPE,
                             LAST_JS_FUNCTION_TYPE);
    pop(object);
    Check(le, AbortReason::kOperandIsNotAFunction);
  }
}

void MacroAssembler::AssertCallableFunction(Register object) {
  if (!v8_flags.debug_code) return;
  ASM_CODE_COMMENT(this);
  static_assert(kSmiTag == 0);
  TestIfSmi(object, r0);
  Check(ne, AbortReason::kOperandIsASmiAndNotAFunction, cr0);
  push(object);
  LoadMap(object, object);
  CompareInstanceTypeRange(object, object, r0, FIRST_CALLABLE_JS_FUNCTION_TYPE,
                           LAST_CALLABLE_JS_FUNCTION_TYPE);
  pop(object);
  Check(le, AbortReason::kOperandIsNotACallableFunction);
}

void MacroAssembler::AssertBoundFunction(Register object) {
  if (v8_flags.debug_code) {
    static_assert(kSmiTag == 0);
    TestIfSmi(object, r0);
    Check(ne, AbortReason::kOperandIsASmiAndNotABoundFunction, cr0);
    push(object);
    CompareObjectType(object, object, object, JS_BOUND_FUNCTION_TYPE);
    pop(object);
    Check(eq, AbortReason::kOperandIsNotABoundFunction);
  }
}

void MacroAssembler::AssertGeneratorObject(Register object) {
  if (!v8_flags.debug_code) return;
  TestIfSmi(object, r0);
  Check(ne, AbortReason::kOperandIsASmiAndNotAGeneratorObject, cr0);

  // Load map
  Register map = object;
  push(object);
  LoadMap(map, object);

  // Check if JSGeneratorObject
  Register instance_type = object;
  CompareInstanceTypeRange(map, instance_type, r0,
                           FIRST_JS_GENERATOR_OBJECT_TYPE,
                           LAST_JS_GENERATOR_OBJECT_TYPE);
  // Restore generator object to register and perform assertion
  pop(object);
  Check(le, AbortReason::kOperandIsNotAGeneratorObject);
}

void MacroAssembler::AssertUndefinedOrAllocationSite(Register object,
                                                     Register scratch) {
  if (v8_flags.debug_code) {
    Label done_checking;
    AssertNotSmi(object);
    CompareRoot(object, RootIndex::kUndefinedValue);
    beq(&done_checking);
    LoadMap(scratch, object);
    CompareInstanceType(scratch, scratch, ALLOCATION_SITE_TYPE);
    Assert(eq, AbortReason::kExpectedUndefinedOrCell);
    bind(&done_checking);
  }
}

void MacroAssembler::AssertJSAny(Register object, Register map_tmp,
                                 Register tmp, AbortReason abort_reason) {
  if (!v8_flags.debug_code) return;

  ASM_CODE_COMMENT(this);
  DCHECK(!AreAliased(object, map_tmp, tmp));
  Label ok;

  JumpIfSmi(object, &ok);

  LoadMap(map_tmp, object);
  CompareInstanceType(map_tmp, tmp, LAST_NAME_TYPE);
  ble(&ok);

  CompareInstanceType(map_tmp, tmp, FIRST_JS_RECEIVER_TYPE);
  bge(&ok);

  CompareRoot(map_tmp, RootIndex::kHeapNumberMap);
  beq(&ok);

  CompareRoot(map_tmp, RootIndex::kBigIntMap);
  beq(&ok);

  CompareRoot(object, RootIndex::kUndefinedValue);
  beq(&ok);

  CompareRoot(object, RootIndex::kTrueValue);
  beq(&ok);

  CompareRoot(object, RootIndex::kFalseValue);
  beq(&ok);

  CompareRoot(object, RootIndex::kNullValue);
  beq(&ok);

  Abort(abort_reason);

  bind(&ok);
}

#endif  // V8_ENABLE_DEBUG_CODE

int MacroAssembler::CalculateStackPassedWords(int num_reg_arguments,
                                              int num_double_arguments) {
  int stack_passed_words = 0;
  if (num_double_arguments > DoubleRegister::kNumRegisters) {
    stack_passed_words +=
        2 * (num_double_arguments - DoubleRegister::kNumRegisters);
  }
  // Up to 8 simple arguments are passed in registers r3..r10.
  if (num_reg_arguments > kRegisterPassedArguments) {
    stack_passed_words += num_reg_arguments - kRegisterPassedArguments;
  }
  return stack_passed_words;
}

void MacroAssembler::PrepareCallCFunction(int num_reg_arguments,
                                          int num_double_arguments,
                                          Register scratch) {
  int frame_alignment = ActivationFrameAlignment();
  int stack_passed_arguments =
      CalculateStackPassedWords(num_reg_arguments, num_double_arguments);
  int stack_space = kNumRequiredStackFrameSlots;

  if (frame_alignment > kSystemPointerSize) {
    // Make stack end at alignment and make room for stack arguments
    // -- preserving original value of sp.
    mr(scratch, sp);
    AddS64(sp, sp, Operand(-(stack_passed_arguments + 1) * kSystemPointerSize),
           scratch);
    DCHECK(base::bits::IsPowerOfTwo(frame_alignment));
    ClearRightImm(sp, sp,
                  Operand(base::bits::WhichPowerOfTwo(frame_alignment)));
    StoreU64(scratch,
             MemOperand(sp, stack_passed_arguments * kSystemPointerSize));
  } else {
    // Make room for stack arguments
    stack_space += stack_passed_arguments;
  }

  // Allocate frame with required slots to make ABI work.
  li(r0, Operand::Zero());
  StoreU64WithUpdate(r0, MemOperand(sp, -stack_space * kSystemPointerSize));
}

void MacroAssembler::PrepareCallCFunction(int num_reg_arguments,
                                          Register scratch) {
  PrepareCallCFunction(num_reg_arguments, 0, scratch);
}

void MacroAssembler::MovToFloatParameter(DoubleRegister src) { Move(d1, src); }

void MacroAssembler::MovToFloatResult(DoubleRegister src) { Move(d1, src); }

void MacroAssembler::MovToFloatParameters(DoubleRegister src1,
                                          DoubleRegister src2) {
  if (src2 == d1) {
    DCHECK(src1 != d2);
    Move(d2, src2);
    Move(d1, src1);
  } else {
    Move(d1, src1);
    Move(d2, src2);
  }
}

int MacroAssembler::CallCFunction(ExternalReference function,
                                  int num_reg_arguments,
                                  int num_double_arguments,
                                  SetIsolateDataSlots set_isolate_data_slots,
                                  bool has_function_descriptor) {
  Move(ip, function);
  return CallCFunction(ip, num_reg_arguments, num_double_arguments,
                       set_isolate_data_slots, has_function_descriptor);
}

int MacroAssembler::CallCFunction(Register function, int num_reg_arguments,
                                  int num_double_arguments,
                                  SetIsolateDataSlots set_isolate_data_slots,
                                  bool has_function_descriptor) {
  ASM_CODE_COMMENT(this);
  DCHECK_LE(num_reg_arguments + num_double_arguments, kMaxCParameters);
  DCHECK(has_frame());

  Label start_call;
  Register pc_scratch = r11;
  DCHECK(!AreAliased(pc_scratch, function));
  LoadPC(pc_scratch);
  bind(&start_call);
  int start_pc_offset = pc_offset();
  // We are going to patch this instruction after emitting
  // Call, using a zero offset here as placeholder for now.
  // patch_pc_address assumes `addi` is used here to
  // add the offset to pc.
  addi(pc_scratch, pc_scratch, Operand::Zero());

  if (set_isolate_data_slots == SetIsolateDataSlots::kYes) {
    // Save the frame pointer and PC so that the stack layout remains iterable,
    // even without an ExitFrame which normally exists between JS and C frames.
    Register scratch = r8;
    Push(scratch);
    mflr(scratch);
    CHECK(root_array_available());
    StoreU64(pc_scratch,
             ExternalReferenceAsOperand(IsolateFieldId::kFastCCallCallerPC));
    StoreU64(fp,
             ExternalReferenceAsOperand(IsolateFieldId::kFastCCallCallerFP));
    mtlr(scratch);
    Pop(scratch);
  }

  // Just call directly. The function called cannot cause a GC, or
  // allow preemption, so the return address in the link register
  // stays correct.
  Register dest = function;
  if (ABI_USES_FUNCTION_DESCRIPTORS && has_function_descriptor) {
    // AIX/PPC64BE Linux uses a function descriptor. When calling C code be
    // aware of this descriptor and pick up values from it
    LoadU64(ToRegister(ABI_TOC_REGISTER),
            MemOperand(function, kSystemPointerSize));
    LoadU64(ip, MemOperand(function, 0));
    dest = ip;
  } else if (ABI_CALL_VIA_IP) {
    // pLinux and Simualtor, not AIX
    Move(ip, function);
    dest = ip;
  }

  Call(dest);
  int call_pc_offset = pc_offset();
  int offset_since_start_call = SizeOfCodeGeneratedSince(&start_call);
  // Here we are going to patch the `addi` instruction above to use the
  // correct offset.
  // LoadPC emits two instructions and pc is the address of its second emitted
  // instruction. Add one more to the offset to point to after the Call.
  offset_since_start_call += kInstrSize;
  patch_pc_address(pc_scratch, start_pc_offset, offset_since_start_call);

  if (set_isolate_data_slots == SetIsolateDataSlots::kYes) {
    // We don't unset the PC; the FP is the source of truth.
    Register zero_scratch = r0;
    mov(zero_scratch, Operand::Zero());

    StoreU64(zero_scratch,
             ExternalReferenceAsOperand(IsolateFieldId::kFastCCallCallerFP));
  }

  // Remove frame bought in PrepareCallCFunction
  int stack_passed_arguments =
      CalculateStackPassedWords(num_reg_arguments, num_double_arguments);
  int stack_space = kNumRequiredStackFrameSlots + stack_passed_arguments;
  if (ActivationFrameAlignment() > kSystemPointerSize) {
    LoadU64(sp, MemOperand(sp, stack_space * kSystemPointerSize), r0);
  } else {
    AddS64(sp, sp, Operand(stack_space * kSystemPointerSize), r0);
  }

  return call_pc_offset;
}

int MacroAssembler::CallCFunction(ExternalReference function, int num_arguments,

"""


```