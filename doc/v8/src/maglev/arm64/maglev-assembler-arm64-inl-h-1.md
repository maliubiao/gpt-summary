Response:
The user wants me to analyze a C++ header file for the V8 JavaScript engine, specifically `v8/src/maglev/arm64/maglev-assembler-arm64-inl.h`.

Here's a breakdown of the thought process to answer the request:

1. **Identify the core purpose:** The file name includes "assembler" which strongly suggests it's related to generating machine code. The "arm64" part specifies the target architecture. The ".inl.h" suffix typically indicates inline function definitions within a header. Combined with the "maglev" directory, it's clear this is part of the Maglev compiler pipeline in V8, specifically for ARM64.

2. **Examine the provided code snippets:**  The snippets are mostly inline function definitions within the `MaglevAssembler` class. These functions perform various low-level operations:
    * **Type checking:** `IsObjectType`, `IsObjectTypeInRange`, `BranchOnObjectTypeInRange`. These functions check the type of a heap object.
    * **Range checks:** `JumpIfObjectInRange`, `JumpIfObjectNotInRange`, `AssertObjectInRange`. These check if an object falls within a specific memory range, often used for checking against read-only roots.
    * **Primitive checks:** `JumpIfJSAnyIsNotPrimitive`. Checks if a value is a primitive type.
    * **Map comparisons:** `CompareMapWithRoot`, `CompareInstanceType`, `CompareInstanceTypeRange`. These functions compare the map or instance type of an object.
    * **Floating-point comparisons:** `CompareFloat64AndJumpIf`, `CompareFloat64AndBranch`. These handle comparisons of double-precision floating-point numbers, including handling NaN.
    * **Control flow:** `PrepareCallCFunction`, `CallSelf`, `Jump`, `JumpToDeopt`, `JumpIf`, `JumpIfRoot`, `JumpIfNotRoot`, `JumpIfSmi`, `JumpIfNotSmi`, `JumpIfByte`. These manage the flow of execution with jumps and branches based on conditions.
    * **NaN checks:** `JumpIfHoleNan`, `JumpIfNotHoleNan`, `JumpIfNan`, `JumpIfNotNan`. Specific checks for NaN and the "hole NaN" value used in V8.
    * **Integer comparisons:** `CompareInt32AndJumpIf`, `CompareIntPtrAndJumpIf`, `CompareInt32AndAssert`, `CompareInt32AndBranch`. Comparisons for integer values.
    * **Smi comparisons:** `CompareSmiAndJumpIf`, `CompareSmiAndAssert`. Comparisons specifically for Smis (Small Integers).
    * **Byte comparisons:** `CompareByteAndJumpIf`. Comparison of individual bytes in memory.
    * **Tagged value comparisons:** `CompareTaggedAndJumpIf`. Comparisons for tagged values (which can be Smis or HeapObjects).
    * **Double comparisons (zero/NaN):** `CompareDoubleAndJumpIfZeroOrNaN`. Checks if a double is zero or NaN.
    * **Bitwise tests:** `TestInt32AndJumpIfAnySet`, `TestInt32AndJumpIfAllClear`, `TestUint8AndJumpIfAnySet`, `TestUint8AndJumpIfAllClear`. Checks for specific bits being set or clear.
    * **Loading values:** `LoadHeapNumberValue`. Loads the value from a HeapNumber object.
    * **Type conversions:** `Int32ToDouble`, `Uint32ToDouble`. Converts integers to doubles.
    * **Stack manipulation:** `Pop`, `AssertStackSizeCorrect`, `FunctionEntryStackCheck`. Manages the stack.
    * **Code finalization:** `FinishCode`.
    * **Deoptimization:** `EmitEagerDeoptIfNotEqual`, `MaybeEmitPlaceHolderForDeopt`. Handles scenarios where the optimized code needs to fall back to less optimized code.
    * **Data movement:** `MoveRepr`. Moves data between registers and memory, handling different data representations.

3. **Address specific questions from the prompt:**

    * **Function listing:**  Simply enumerate the identified functions with a brief description.
    * **.tq suffix:**  The prompt explicitly states that if the file ended with `.tq`, it would be a Torque source file. Since it ends with `.h`, it's a C++ header.
    * **Relationship to JavaScript:**  These assembler functions directly implement the logic of JavaScript operations. Provide examples of JavaScript code that would trigger these underlying operations (e.g., type checks, comparisons, arithmetic).
    * **Code logic inference:** Choose a relatively straightforward function like `IsObjectTypeInRange` or a branching function and provide a concrete example with input values and expected output (whether a branch is taken or not).
    * **Common programming errors:** Think about scenarios where the assumptions made by these low-level functions might be violated due to errors in the JavaScript code or the compiler. Type errors and incorrect assumptions about object structure are good examples.
    * **Part 2 summarization:** This part builds on the previous functions. Summarize the overarching theme and common functionalities.

4. **Structure the answer:**  Organize the information logically, addressing each part of the prompt clearly. Use headings and bullet points for readability. Provide clear and concise explanations.

5. **Refine and review:** Ensure the answer is accurate, comprehensive, and easy to understand. Check for any inconsistencies or areas where more detail might be needed. For example, initially, I might just say "it does comparisons," but refining that to specific types of comparisons (integer, float, tagged, etc.) is more helpful. Also, clarify the role of "scratch" registers.
这是目录为`v8/src/maglev/arm64/maglev-assembler-arm64-inl.h` 的 V8 源代码的第二部分，延续了第一部分的功能定义。 基于提供的代码片段，我们可以归纳一下这部分的功能：

**总体功能归纳：**

这部分代码继续定义了 `MaglevAssembler` 类在 ARM64 架构下的内联函数，这些函数提供了构建 Maglev 编译后的机器码所需的各种指令和操作。 它们主要围绕以下几个方面展开：

1. **对象类型和范围检查及分支/断言:**
   - 提供了一系列用于检查堆对象的类型是否在指定范围内的函数 (`IsObjectTypeInRange`, `BranchOnObjectTypeInRange`, `AssertObjectTypeInRange`)。
   - 提供了用于检查对象是否在特定内存地址范围内的函数 (`JumpIfObjectInRange`, `JumpIfObjectNotInRange`, `AssertObjectInRange`)，这通常用于与 V8 的只读根对象进行比较。

2. **非原始类型检查:**
   - 提供了检查对象是否为非原始类型 (object) 的函数 (`JumpIfJSAnyIsNotPrimitive`)。

3. **对象 Map 和 InstanceType 比较:**
   - 提供了比较对象的 Map 和根对象 (`CompareMapWithRoot`) 或特定 InstanceType (`CompareInstanceType`, `CompareInstanceTypeRange`) 的函数。

4. **浮点数比较和分支:**
   - 提供了比较两个双精度浮点数并根据比较结果跳转或分支的函数 (`CompareFloat64AndJumpIf`, `CompareFloat64AndBranch`)，并考虑了 NaN (Not-a-Number) 的情况。

5. **函数调用准备和调用自身:**
   - 提供了为 C 函数调用做准备的函数 (`PrepareCallCFunction`)。
   - 提供了调用当前 Maglev 代码入口点的函数 (`CallSelf`)。

6. **无条件跳转和跳转到 Deopt:**
   - 提供了无条件跳转到指定标签的函数 (`Jump`, `JumpToDeopt`)，其中 `JumpToDeopt` 专门用于跳转到反优化 (deoptimization) 的代码。
   - 提供了模拟压力测试下强制反优化的函数 (`EmitEagerDeoptStress`)，尽管在 ARM 架构上可能未完全实现。

7. **条件跳转:**
   - 提供了根据条件码跳转到指定标签的函数 (`JumpIf`)。
   - 提供了根据对象是否为特定根对象进行跳转的函数 (`JumpIfRoot`, `JumpIfNotRoot`)。
   - 提供了根据值是否为 Smi (Small Integer) 进行跳转的函数 (`JumpIfSmi`, `JumpIfNotSmi`)。
   - 提供了根据特定字节值进行跳转的函数 (`JumpIfByte`)。

8. **NaN 和 Hole NaN 检查和跳转:**
   - 提供了检查双精度浮点数是否为 NaN 或 Hole NaN 并跳转的函数 (`JumpIfHoleNan`, `JumpIfNotHoleNan`, `JumpIfNan`, `JumpIfNotNan`)。 Hole NaN 是 V8 中用于表示未初始化或删除的属性的特殊 NaN 值。

9. **整数比较和跳转/断言/分支:**
   - 提供了比较两个整数或整数与立即数，并根据比较结果跳转、断言或分支的函数 (`CompareInt32AndJumpIf`, `CompareIntPtrAndJumpIf`, `CompareInt32AndAssert`, `CompareInt32AndBranch`)。

10. **Smi 比较和断言:**
    - 提供了比较寄存器中的值是否为特定 Smi，并根据比较结果跳转或断言的函数 (`CompareSmiAndJumpIf`, `CompareSmiAndAssert`)。

11. **字节比较和跳转:**
    - 提供了比较内存中的字节与立即数，并根据比较结果跳转的函数 (`CompareByteAndJumpIf`)。

12. **Tagged 值比较和跳转:**
    - 提供了比较寄存器中的 Tagged 值 (可以是 Smi 或 HeapObject) 与 Smi 或 HeapObject，并根据比较结果跳转的函数 (`CompareTaggedAndJumpIf`)。

13. **浮点数零或 NaN 检查和跳转:**
    - 提供了检查双精度浮点数是否为零或 NaN 并跳转的函数 (`CompareDoubleAndJumpIfZeroOrNaN`)。

14. **位测试和跳转:**
    - 提供了测试整数的某些位是否设置或清除，并根据结果跳转的函数 (`TestInt32AndJumpIfAnySet`, `TestInt32AndJumpIfAllClear`, `TestUint8AndJumpIfAnySet`, `TestUint8AndJumpIfAllClear`)。

15. **加载 HeapNumber 的值:**
    - 提供了从 HeapNumber 对象中加载双精度浮点数值的函数 (`LoadHeapNumberValue`)。

16. **类型转换:**
    - 提供了将 32 位整数转换为双精度浮点数的函数 (`Int32ToDouble`, `Uint32ToDouble`)。

17. **栈操作:**
    - 提供了从栈中弹出值的函数 (`Pop`)。
    - 提供了断言栈大小是否正确的函数 (`AssertStackSizeCorrect`)，用于调试。
    - 提供了函数入口时检查栈空间的函数 (`FunctionEntryStackCheck`)。

18. **代码完成:**
    - 提供了完成代码生成的函数 (`FinishCode`)。

19. **基于条件的反优化 (Deoptimization):**
    - 提供了当条件不满足时触发反优化的函数模板 (`EmitEagerDeoptIfNotEqual`)。

20. **数据移动:**
    - 提供了根据不同的机器表示 (MachineRepresentation) 在寄存器和内存之间移动数据的函数模板 (`MoveRepr`)。

21. **反优化占位符:**
    - 提供了可能为反优化代码预留占位符的函数 (`MaybeEmitPlaceHolderForDeopt`)，这在 ARM64 架构上可能没有具体实现。

**总结:**

这部分 `maglev-assembler-arm64-inl.h` 文件定义了一系列用于在 ARM64 架构上生成 Maglev 编译器所需机器码的内联函数。 这些函数涵盖了对象类型检查、比较、分支、跳转、算术运算、类型转换、内存访问和栈操作等底层操作，是 Maglev 编译器将 JavaScript 代码转换为高效机器码的关键组成部分。 它们为 Maglev 编译器提供了精细的控制，使其能够针对 ARM64 架构进行优化。

**关于 .tq 结尾：**

正如您在问题中指出的，如果文件以 `.tq` 结尾，则它会是一个 Torque 源代码文件。 Torque 是一种 V8 内部使用的类型化的中间语言，用于定义 V8 的内置函数和运行时代码。 由于这个文件以 `.h` 结尾，它是一个 C++ 头文件，包含了内联函数的定义。

**与 JavaScript 的关系及示例：**

这些汇编器函数直接对应着 JavaScript 的各种操作。以下是一些 JavaScript 代码示例以及可能触发的 `MaglevAssembler` 函数：

1. **类型检查:**
   ```javascript
   function foo(x) {
     if (typeof x === 'number') {
       // ...
     }
   }
   ```
   这可能会触发 `IsObjectType` 或 `BranchOnObjectTypeInRange` 来检查 `x` 的类型。

2. **比较操作:**
   ```javascript
   function bar(a, b) {
     if (a > b) {
       return a;
     } else {
       return b;
     }
   }
   ```
   对于数字 `a` 和 `b`，这可能会触发 `CompareFloat64AndJumpIf` 或 `CompareInt32AndJumpIf`。

3. **对象属性访问:**
   ```javascript
   const obj = { value: 10 };
   console.log(obj.value);
   ```
   在 Maglev 中，访问 `obj.value` 可能涉及加载对象属性的操作，虽然这里没有直接对应的函数，但会用到加载内存的指令。

4. **函数调用:**
   ```javascript
   function add(x, y) {
     return x + y;
   }
   add(5, 3);
   ```
   函数调用 `add(5, 3)` 会涉及到调用约定和参数传递，可能会触发 `PrepareCallCFunction` (如果调用的是内置函数或运行时函数) 或其他与函数调用相关的汇编指令。

**代码逻辑推理（以 `IsObjectTypeInRange` 为例）：**

**假设输入：**

- `heap_object` 寄存器包含一个指向堆对象的指针。
- `lower_limit` 为 `FIRST_NONSTRING_TYPE`（假设值为 8）。
- `higher_limit` 为 `LAST_NONSTRING_TYPE`（假设值为 15）。

**输出：**

- 如果 `heap_object` 的 InstanceType（可以通过偏移量获取）的值在 8 到 15 之间（包含 8 和 15），则 `scratch` 寄存器中的值会被设置为一个非零值（表示条件为真）。
- 否则，`scratch` 寄存器中的值会被设置为零。

**推理过程：**

`IsObjectTypeInRange` 函数首先会检查 `heap_object` 是否为 Smi（小整数）。如果不是，它会从 `heap_object` 指向的内存中加载 InstanceType 的值，并将其与 `lower_limit` 和 `higher_limit` 进行比较。 `kUnsignedLessThanEqual` 条件码会根据比较结果设置处理器的标志位。

**用户常见的编程错误（可能导致这些汇编器函数相关的错误）：**

1. **类型错误：** JavaScript 是一门动态类型语言，但错误地假设变量的类型会导致类型检查失败或出现意外行为。例如，假设一个变量总是数字，但在运行时它可能是字符串。
   ```javascript
   function processNumber(x) {
     if (typeof x === 'number') {
       console.log(x * 2);
     } else {
       // 假设这里永远不会执行，但实际可能发生
       console.log("Error: Not a number");
     }
   }
   processNumber("hello"); // 触发 else 分支，与假设不符
   ```
   这可能导致 `IsObjectType` 或相关函数的结果与预期不符。

2. **错误的假设导致 NaN 相关的错误：** 在进行浮点数运算时，没有正确处理 NaN 的情况。
   ```javascript
   function calculate(a, b) {
     if (a > 0 && b > 0) {
       return Math.sqrt(a) + Math.sqrt(b);
     }
     // 错误地假设如果 a 或 b 不是正数，就不会产生 NaN
     return 0;
   }
   console.log(calculate(-1, 4)); // 实际会产生 NaN
   ```
   这可能导致与 `CompareFloat64AndJumpIf` 等函数相关的分支预测错误或逻辑错误。

3. **对对象结构的错误假设：** 假设对象的属性总是存在或具有特定的类型，但实际情况并非如此。
   ```javascript
   function printValue(obj) {
     console.log(obj.value.toUpperCase()); // 假设 obj.value 是字符串
   }
   printValue({ value: 10 }); // 运行时错误，因为数字没有 toUpperCase 方法
   ```
   这可能导致与对象属性访问相关的汇编指令执行错误，或者在类型检查阶段就失败。

总而言之，这部分代码是 V8 Maglev 编译器的核心组成部分，它定义了用于生成高效 ARM64 机器码的底层操作，直接支撑着 JavaScript 代码的执行。理解这些函数的行为有助于深入理解 V8 的内部工作原理。

Prompt: 
```
这是目录为v8/src/maglev/arm64/maglev-assembler-arm64-inl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/maglev/arm64/maglev-assembler-arm64-inl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""
cratch = temps.AcquireScratch();
  AssertNotSmi(heap_object);
  IsObjectTypeInRange(heap_object, scratch, lower_limit, higher_limit);
  Assert(kUnsignedLessThanEqual, reason);
}

inline void MaglevAssembler::BranchOnObjectTypeInRange(
    Register heap_object, InstanceType lower_limit, InstanceType higher_limit,
    Label* if_true, Label::Distance true_distance, bool fallthrough_when_true,
    Label* if_false, Label::Distance false_distance,
    bool fallthrough_when_false) {
  TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  IsObjectTypeInRange(heap_object, scratch, lower_limit, higher_limit);
  Branch(kUnsignedLessThanEqual, if_true, true_distance, fallthrough_when_true,
         if_false, false_distance, fallthrough_when_false);
}

#if V8_STATIC_ROOTS_BOOL
inline void MaglevAssembler::JumpIfObjectInRange(Register heap_object,
                                                 Tagged_t lower_limit,
                                                 Tagged_t higher_limit,
                                                 Label* target,
                                                 Label::Distance distance) {
  // Only allowed for comparisons against RORoots.
  DCHECK_LE(lower_limit, StaticReadOnlyRoot::kLastAllocatedRoot);
  DCHECK_LE(higher_limit, StaticReadOnlyRoot::kLastAllocatedRoot);
  TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  AssertNotSmi(heap_object);
  CompareRange(heap_object, scratch, lower_limit, higher_limit);
  JumpIf(kUnsignedLessThanEqual, target, distance);
}

inline void MaglevAssembler::JumpIfObjectNotInRange(Register heap_object,
                                                    Tagged_t lower_limit,
                                                    Tagged_t higher_limit,
                                                    Label* target,
                                                    Label::Distance distance) {
  // Only allowed for comparisons against RORoots.
  DCHECK_LE(lower_limit, StaticReadOnlyRoot::kLastAllocatedRoot);
  DCHECK_LE(higher_limit, StaticReadOnlyRoot::kLastAllocatedRoot);
  TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  AssertNotSmi(heap_object);
  CompareRange(heap_object, scratch, lower_limit, higher_limit);
  JumpIf(kUnsignedGreaterThan, target, distance);
}

inline void MaglevAssembler::AssertObjectInRange(Register heap_object,
                                                 Tagged_t lower_limit,
                                                 Tagged_t higher_limit,
                                                 AbortReason reason) {
  // Only allowed for comparisons against RORoots.
  DCHECK_LE(lower_limit, StaticReadOnlyRoot::kLastAllocatedRoot);
  DCHECK_LE(higher_limit, StaticReadOnlyRoot::kLastAllocatedRoot);
  TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  AssertNotSmi(heap_object);
  CompareRange(heap_object, scratch, lower_limit, higher_limit);
  Assert(kUnsignedLessThanEqual, reason);
}
#endif

inline void MaglevAssembler::JumpIfJSAnyIsNotPrimitive(
    Register heap_object, Label* target, Label::Distance distance) {
  TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  MacroAssembler::JumpIfJSAnyIsNotPrimitive(heap_object, scratch, target,
                                            distance);
}

inline void MaglevAssembler::CompareMapWithRoot(Register object,
                                                RootIndex index,
                                                Register scratch) {
  if (V8_STATIC_ROOTS_BOOL && RootsTable::IsReadOnly(index)) {
    LoadCompressedMap(scratch, object);
    CmpTagged(scratch, Immediate(ReadOnlyRootPtr(index)));
    return;
  }
  LoadMap(scratch, object);
  CompareRoot(scratch, index);
}

inline void MaglevAssembler::CompareInstanceType(Register map,
                                                 InstanceType instance_type) {
  TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  MacroAssembler::CompareInstanceType(map, scratch, instance_type);
}

inline Condition MaglevAssembler::CompareInstanceTypeRange(
    Register map, Register instance_type_out, InstanceType lower_limit,
    InstanceType higher_limit) {
  MacroAssembler::CompareInstanceTypeRange(map, instance_type_out, lower_limit,
                                           higher_limit);
  return kUnsignedLessThanEqual;
}

inline void MaglevAssembler::CompareFloat64AndJumpIf(
    DoubleRegister src1, DoubleRegister src2, Condition cond, Label* target,
    Label* nan_failed, Label::Distance distance) {
  Fcmp(src1, src2);
  JumpIf(ConditionForNaN(), nan_failed);
  JumpIf(cond, target, distance);
}

inline void MaglevAssembler::CompareFloat64AndBranch(
    DoubleRegister src1, DoubleRegister src2, Condition cond,
    BasicBlock* if_true, BasicBlock* if_false, BasicBlock* next_block,
    BasicBlock* nan_failed) {
  Fcmp(src1, src2);
  JumpIf(ConditionForNaN(), nan_failed->label());
  Branch(cond, if_true, if_false, next_block);
}

inline void MaglevAssembler::PrepareCallCFunction(int num_reg_arguments,
                                                  int num_double_registers) {}

inline void MaglevAssembler::CallSelf() {
  DCHECK(allow_call());
  DCHECK(code_gen_state()->entry_label()->is_bound());
  Bl(code_gen_state()->entry_label());
}

inline void MaglevAssembler::Jump(Label* target, Label::Distance) {
  // Any eager deopts should go through JumpIf to enable us to support the
  // `--deopt-every-n-times` stress mode. See EmitEagerDeoptStress.
  DCHECK(!IsDeoptLabel(target));
  B(target);
}

inline void MaglevAssembler::JumpToDeopt(Label* target) {
  DCHECK(IsDeoptLabel(target));
  B(target);
}

inline void MaglevAssembler::EmitEagerDeoptStress(Label* target) {
  // TODO(olivf): On arm `--deopt-every-n-times` is currently not supported.
  // Supporting it would require to implement this method, additionally handle
  // deopt branches in Cbz, and handle all cases where we fall through to the
  // deopt branch (like Int32Divide).
}

inline void MaglevAssembler::JumpIf(Condition cond, Label* target,
                                    Label::Distance) {
  B(target, cond);
}

inline void MaglevAssembler::JumpIfRoot(Register with, RootIndex index,
                                        Label* if_equal,
                                        Label::Distance distance) {
  MacroAssembler::JumpIfRoot(with, index, if_equal);
}

inline void MaglevAssembler::JumpIfNotRoot(Register with, RootIndex index,
                                           Label* if_not_equal,
                                           Label::Distance distance) {
  MacroAssembler::JumpIfNotRoot(with, index, if_not_equal);
}

inline void MaglevAssembler::JumpIfSmi(Register src, Label* on_smi,
                                       Label::Distance distance) {
  MacroAssembler::JumpIfSmi(src, on_smi);
}

inline void MaglevAssembler::JumpIfNotSmi(Register src, Label* on_smi,
                                          Label::Distance distance) {
  MacroAssembler::JumpIfNotSmi(src, on_smi);
}

void MaglevAssembler::JumpIfByte(Condition cc, Register value, int32_t byte,
                                 Label* target, Label::Distance) {
  CompareAndBranch(value, Immediate(byte), cc, target);
}

void MaglevAssembler::JumpIfHoleNan(DoubleRegister value, Register scratch,
                                    Label* target, Label::Distance distance) {
  // TODO(leszeks): Right now this only accepts Zone-allocated target labels.
  // This works because all callsites are jumping to either a deopt, deferred
  // code, or a basic block. If we ever need to jump to an on-stack label, we
  // have to add support for it here change the caller to pass a ZoneLabelRef.
  DCHECK(compilation_info()->zone()->Contains(target));
  ZoneLabelRef is_hole = ZoneLabelRef::UnsafeFromLabelPointer(target);
  ZoneLabelRef is_not_hole(this);
  Fcmp(value, value);
  JumpIf(ConditionForNaN(),
         MakeDeferredCode(
             [](MaglevAssembler* masm, DoubleRegister value, Register scratch,
                ZoneLabelRef is_hole, ZoneLabelRef is_not_hole) {
               masm->Umov(scratch.W(), value.V2S(), 1);
               masm->CompareInt32AndJumpIf(scratch.W(), kHoleNanUpper32, kEqual,
                                           *is_hole);
               masm->Jump(*is_not_hole);
             },
             value, scratch, is_hole, is_not_hole));
  bind(*is_not_hole);
}

void MaglevAssembler::JumpIfNotHoleNan(DoubleRegister value, Register scratch,
                                       Label* target,
                                       Label::Distance distance) {
  JumpIfNotNan(value, target, distance);
  Umov(scratch.W(), value.V2S(), 1);
  CompareInt32AndJumpIf(scratch.W(), kHoleNanUpper32, kNotEqual, target,
                        distance);
}

void MaglevAssembler::JumpIfNotHoleNan(MemOperand operand, Label* target,
                                       Label::Distance distance) {
  MaglevAssembler::TemporaryRegisterScope temps(this);
  Register upper_bits = temps.AcquireScratch();
  DCHECK(operand.IsImmediateOffset() && operand.shift_amount() == 0);
  Ldr(upper_bits.W(),
      MemOperand(operand.base(), operand.offset() + (kDoubleSize / 2),
                 operand.addrmode()));
  CompareInt32AndJumpIf(upper_bits.W(), kHoleNanUpper32, kNotEqual, target,
                        distance);
}

void MaglevAssembler::JumpIfNan(DoubleRegister value, Label* target,
                                Label::Distance distance) {
  Fcmp(value, value);
  JumpIf(ConditionForNaN(), target, distance);
}

void MaglevAssembler::JumpIfNotNan(DoubleRegister value, Label* target,
                                   Label::Distance distance) {
  Fcmp(value, value);
  JumpIf(NegateCondition(ConditionForNaN()), target, distance);
}

inline void MaglevAssembler::CompareInt32AndJumpIf(Register r1, Register r2,
                                                   Condition cond,
                                                   Label* target,
                                                   Label::Distance distance) {
  CompareAndBranch(r1.W(), r2.W(), cond, target);
}

void MaglevAssembler::CompareIntPtrAndJumpIf(Register r1, Register r2,
                                             Condition cond, Label* target,
                                             Label::Distance distance) {
  CompareAndBranch(r1.X(), r2.X(), cond, target);
}

inline void MaglevAssembler::CompareInt32AndJumpIf(Register r1, int32_t value,
                                                   Condition cond,
                                                   Label* target,
                                                   Label::Distance distance) {
  CompareAndBranch(r1.W(), Immediate(value), cond, target);
}

inline void MaglevAssembler::CompareInt32AndAssert(Register r1, Register r2,
                                                   Condition cond,
                                                   AbortReason reason) {
  Cmp(r1.W(), r2.W());
  Assert(cond, reason);
}
inline void MaglevAssembler::CompareInt32AndAssert(Register r1, int32_t value,
                                                   Condition cond,
                                                   AbortReason reason) {
  Cmp(r1.W(), Immediate(value));
  Assert(cond, reason);
}

inline void MaglevAssembler::CompareInt32AndBranch(
    Register r1, int32_t value, Condition cond, Label* if_true,
    Label::Distance true_distance, bool fallthrough_when_true, Label* if_false,
    Label::Distance false_distance, bool fallthrough_when_false) {
  Cmp(r1.W(), Immediate(value));
  Branch(cond, if_true, true_distance, fallthrough_when_true, if_false,
         false_distance, fallthrough_when_false);
}

inline void MaglevAssembler::CompareInt32AndBranch(
    Register r1, Register value, Condition cond, Label* if_true,
    Label::Distance true_distance, bool fallthrough_when_true, Label* if_false,
    Label::Distance false_distance, bool fallthrough_when_false) {
  Cmp(r1.W(), value.W());
  Branch(cond, if_true, true_distance, fallthrough_when_true, if_false,
         false_distance, fallthrough_when_false);
}

inline void MaglevAssembler::CompareSmiAndJumpIf(Register r1, Tagged<Smi> value,
                                                 Condition cond, Label* target,
                                                 Label::Distance distance) {
  AssertSmi(r1);
  CompareTaggedAndBranch(r1, Immediate(value), cond, target);
}

inline void MaglevAssembler::CompareSmiAndAssert(Register r1, Tagged<Smi> value,
                                                 Condition cond,
                                                 AbortReason reason) {
  if (!v8_flags.debug_code) return;
  AssertSmi(r1);
  CmpTagged(r1, value);
  Assert(cond, reason);
}

inline void MaglevAssembler::CompareByteAndJumpIf(MemOperand left, int8_t right,
                                                  Condition cond,
                                                  Register scratch,
                                                  Label* target,
                                                  Label::Distance distance) {
  LoadByte(scratch.W(), left);
  CompareAndBranch(scratch.W(), Immediate(right), cond, target);
}

inline void MaglevAssembler::CompareTaggedAndJumpIf(Register r1,
                                                    Tagged<Smi> value,
                                                    Condition cond,
                                                    Label* target,
                                                    Label::Distance distance) {
  CompareTaggedAndBranch(r1, Immediate(value), cond, target);
}

inline void MaglevAssembler::CompareTaggedAndJumpIf(Register r1,
                                                    Handle<HeapObject> obj,
                                                    Condition cond,
                                                    Label* target,
                                                    Label::Distance distance) {
  CmpTagged(r1, Operand(obj, COMPRESS_POINTERS_BOOL
                                 ? RelocInfo::COMPRESSED_EMBEDDED_OBJECT
                                 : RelocInfo::FULL_EMBEDDED_OBJECT));
  JumpIf(cond, target, distance);
}

inline void MaglevAssembler::CompareTaggedAndJumpIf(Register src1,
                                                    Register src2,
                                                    Condition cond,
                                                    Label* target,
                                                    Label::Distance distance) {
  CmpTagged(src1, src2);
  JumpIf(cond, target, distance);
}

inline void MaglevAssembler::CompareDoubleAndJumpIfZeroOrNaN(
    DoubleRegister reg, Label* target, Label::Distance distance) {
  Fcmp(reg, 0.0);
  JumpIf(eq, target);
  JumpIf(vs, target);  // NaN check
}

inline void MaglevAssembler::CompareDoubleAndJumpIfZeroOrNaN(
    MemOperand operand, Label* target, Label::Distance distance) {
  TemporaryRegisterScope temps(this);
  DoubleRegister value_double = temps.AcquireScratchDouble();
  Ldr(value_double, operand);
  CompareDoubleAndJumpIfZeroOrNaN(value_double, target, distance);
}

inline void MaglevAssembler::TestInt32AndJumpIfAnySet(
    Register r1, int32_t mask, Label* target, Label::Distance distance) {
  TestAndBranchIfAnySet(r1.W(), mask, target);
}

inline void MaglevAssembler::TestInt32AndJumpIfAnySet(
    MemOperand operand, int32_t mask, Label* target, Label::Distance distance) {
  TemporaryRegisterScope temps(this);
  Register value = temps.AcquireScratch().W();
  Ldr(value, operand);
  TestAndBranchIfAnySet(value, mask, target);
}

inline void MaglevAssembler::TestUint8AndJumpIfAnySet(
    MemOperand operand, uint8_t mask, Label* target, Label::Distance distance) {
  TemporaryRegisterScope temps(this);
  Register value = temps.AcquireScratch().W();
  LoadByte(value, operand);
  TestAndBranchIfAnySet(value, mask, target);
}

inline void MaglevAssembler::TestInt32AndJumpIfAllClear(
    Register r1, int32_t mask, Label* target, Label::Distance distance) {
  TestAndBranchIfAllClear(r1.W(), mask, target);
}

inline void MaglevAssembler::TestInt32AndJumpIfAllClear(
    MemOperand operand, int32_t mask, Label* target, Label::Distance distance) {
  TemporaryRegisterScope temps(this);
  Register value = temps.AcquireScratch().W();
  Ldr(value, operand);
  TestAndBranchIfAllClear(value, mask, target);
}

inline void MaglevAssembler::TestUint8AndJumpIfAllClear(
    MemOperand operand, uint8_t mask, Label* target, Label::Distance distance) {
  TemporaryRegisterScope temps(this);
  Register value = temps.AcquireScratch().W();
  LoadByte(value, operand);
  TestAndBranchIfAllClear(value, mask, target);
}

inline void MaglevAssembler::LoadHeapNumberValue(DoubleRegister result,
                                                 Register heap_number) {
  Ldr(result, FieldMemOperand(heap_number, offsetof(HeapNumber, value_)));
}

inline void MaglevAssembler::Int32ToDouble(DoubleRegister result,
                                           Register src) {
  Scvtf(result, src.W());
}

inline void MaglevAssembler::Uint32ToDouble(DoubleRegister result,
                                            Register src) {
  Ucvtf(result, src.W());
}

inline void MaglevAssembler::Pop(Register dst) { Pop(dst, padreg); }

inline void MaglevAssembler::AssertStackSizeCorrect() {
  if (v8_flags.debug_code) {
    TemporaryRegisterScope temps(this);
    Register scratch = temps.AcquireScratch();
    Add(scratch, sp,
        RoundUp<2 * kSystemPointerSize>(
            code_gen_state()->stack_slots() * kSystemPointerSize +
            StandardFrameConstants::kFixedFrameSizeFromFp));
    Cmp(scratch, fp);
    Assert(eq, AbortReason::kStackAccessBelowStackPointer);
  }
}

inline Condition MaglevAssembler::FunctionEntryStackCheck(
    int stack_check_offset) {
  TemporaryRegisterScope temps(this);
  Register stack_cmp_reg = sp;
  if (stack_check_offset >= kStackLimitSlackForDeoptimizationInBytes) {
    stack_cmp_reg = temps.AcquireScratch();
    Sub(stack_cmp_reg, sp, stack_check_offset);
  }
  Register interrupt_stack_limit = temps.AcquireScratch();
  LoadStackLimit(interrupt_stack_limit, StackLimitKind::kInterruptStackLimit);
  Cmp(stack_cmp_reg, interrupt_stack_limit);
  return kUnsignedGreaterThanEqual;
}

inline void MaglevAssembler::FinishCode() {
  ForceConstantPoolEmissionWithoutJump();
}

template <typename NodeT>
inline void MaglevAssembler::EmitEagerDeoptIfNotEqual(DeoptimizeReason reason,
                                                      NodeT* node) {
  EmitEagerDeoptIf(ne, reason, node);
}

template <>
inline void MaglevAssembler::MoveRepr(MachineRepresentation repr, Register dst,
                                      Register src) {
  Mov(dst, src);
}
template <>
inline void MaglevAssembler::MoveRepr(MachineRepresentation repr, Register dst,
                                      MemOperand src) {
  switch (repr) {
    case MachineRepresentation::kWord32:
      return Ldr(dst.W(), src);
    case MachineRepresentation::kTagged:
    case MachineRepresentation::kTaggedPointer:
    case MachineRepresentation::kTaggedSigned:
    case MachineRepresentation::kWord64:
      return Ldr(dst, src);
    default:
      UNREACHABLE();
  }
}
template <>
inline void MaglevAssembler::MoveRepr(MachineRepresentation repr,
                                      MemOperand dst, Register src) {
  switch (repr) {
    case MachineRepresentation::kWord32:
      return Str(src.W(), dst);
    case MachineRepresentation::kTagged:
    case MachineRepresentation::kTaggedPointer:
    case MachineRepresentation::kTaggedSigned:
    case MachineRepresentation::kWord64:
      return Str(src, dst);
    default:
      UNREACHABLE();
  }
}
template <>
inline void MaglevAssembler::MoveRepr(MachineRepresentation repr,
                                      MemOperand dst, MemOperand src) {
  TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  MoveRepr(repr, scratch, src);
  MoveRepr(repr, dst, scratch);
}

inline void MaglevAssembler::MaybeEmitPlaceHolderForDeopt() {
  // Implemented only for x64.
}

}  // namespace maglev
}  // namespace internal
}  // namespace v8

#endif  // V8_MAGLEV_ARM64_MAGLEV_ASSEMBLER_ARM64_INL_H_

"""


```