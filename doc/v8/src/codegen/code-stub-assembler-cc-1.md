Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/codegen/code-stub-assembler.cc`.

Here's a breakdown of how to approach this:

1. **Identify the Core Class:** The code is within the `CodeStubAssembler` class. This class is a key part of V8's code generation pipeline.

2. **Group Functionalities:**  Read through the methods and try to categorize them based on what they do. Common themes emerge like:
    * Smi (Small Integer) manipulation
    * Integer arithmetic with overflow checks
    * Number operations (including handling of special cases like NaN and -0)
    * Memory allocation
    * Type checking
    * Conversions between different data types

3. **Explain Each Category:**  For each category, summarize the purpose of the functions. Mention the data types involved (Smi, IntPtrT, Int32T, Float64T, etc.).

4. **Address Specific Instructions:**
    * **`.tq` extension:** Explain that if the file ended in `.tq`, it would be Torque code, which is a higher-level language used within V8 for generating assembly code.
    * **Relationship to JavaScript:** Connect the C++ functions to their analogous JavaScript behaviors. Provide simple JavaScript examples.
    * **Code Logic Reasoning:** Choose a simple function (like `SmiTag` or `SmiUntag`) and demonstrate its input and output.
    * **Common Programming Errors:** Think about scenarios where developers might misuse these low-level operations if they were directly exposed (which they aren't in typical JavaScript). Overflow errors are a good example.
    * **Part Number:** Acknowledge that this is part 2 of 23 and state that the summary focuses on the functions within this specific part.

5. **Structure the Output:** Organize the information logically with clear headings for each point.

**Mental Walkthrough of the Code:**

* **Smi Operations:** The code has functions for tagging and untagging Smis (`SmiTag`, `SmiUntag`), converting them to other integer types (`SmiToInt32`), and performing basic arithmetic (`SmiMax`, `SmiMin`, `TrySmiAdd`, `TrySmiSub`, `TrySmiAbs`, `SmiMod`, `SmiMul`, `TrySmiDiv`, `SmiLexicographicCompare`). This suggests a focus on optimizing operations with small integers.

* **Integer Arithmetic with Overflow Handling:** The `TryIntPtrAdd`, `TryIntPtrSub`, `TryIntPtrMul`, `TryIntPtrDiv`, `TryIntPtrMod`, and `TryInt32Mul` functions indicate a concern for handling potential overflows during arithmetic operations. The use of `Label* if_overflow` parameters confirms this.

* **Number Operations:** `NumberMax`, `NumberMin`, `SmiMod`, and `SmiMul` show how the assembler handles operations that might involve different numeric types (Smi and HeapNumber) and edge cases like NaN and -0.

* **Memory Allocation:** The `AllocateRaw`, `AllocateRawUnaligned`, `AllocateRawDoubleAligned`, and `AllocateInNewSpace` functions are clearly responsible for allocating memory in the V8 heap. The flags parameter suggests different allocation strategies (e.g., double alignment, pretenuring).

* **Type Checking:** Functions like `TaggedIsSmi`, `TaggedIsNotSmi`, `TaggedIsPositiveSmi`, and `BranchIfJSReceiver` are for determining the type of JavaScript values at a low level.

* **Conversions:**  Functions like `SmiToFloat64`, `TruncateWordToInt32`, `TruncateIntPtrToInt32`, and `ChangeInt32ToTagged` handle conversions between different data representations.

* **Helper Functions:**  `GetCoverageInfo`, `WordIsAligned`, `LoadDoubleWithHoleCheck`, `GotoIfForceSlowPath`, `BranchIfToBooleanIsTrue`, `LoadSandboxedPointerFromObject`, `StoreSandboxedPointerToObject`, and `EmptyBackingStoreBufferConstant` seem to provide more specific utility functions.

By grouping and understanding these functionalities, I can construct a comprehensive summary that addresses the user's request.
这是 `v8/src/codegen/code-stub-assembler.cc` 源代码的第 2 部分，它主要提供了一组用于在 V8 的代码生成过程中进行低级操作的汇编器指令和辅助方法。这个文件是 `CodeStubAssembler` 类的实现，该类允许开发者以一种结构化的方式生成机器码。

**主要功能归纳:**

这一部分的代码主要集中在以下几个方面：

1. **Smi (Small Integer) 操作:**
   - **类型判断和转换:**  提供了判断一个值是否为 Smi (`IsSmi`, `TaggedIsSmi`, `TaggedIsNotSmi`, `TaggedIsPositiveSmi`)，以及在 Smi 和其他整数类型之间进行转换的方法 (`SmiTag`, `SmiUntag`, `SmiToInt32`, `PositiveSmiToUint32`, `PositiveSmiUntag`)。
   - **算术运算:** 提供了 Smi 的基本算术运算，如最大值 (`SmiMax`)、最小值 (`SmiMin`)、加法 (`TrySmiAdd`)、减法 (`TrySmiSub`)、绝对值 (`TrySmiAbs`)、取模 (`SmiMod`)、乘法 (`SmiMul`) 和除法 (`TrySmiDiv`)，并能处理溢出情况。
   - **比较:** 提供了 Smi 的字典序比较 (`SmiLexicographicCompare`)。

2. **整数运算 (带溢出检查):**
   - 提供了带溢出检查的 `IntPtrT` 和 `Int32T` 类型的加法 (`TryIntPtrAdd`, `TryInt32Add`)、减法 (`TryIntPtrSub`)、乘法 (`TryIntPtrMul`, `TryInt32Mul`)、除法 (`TryIntPtrDiv`) 和取模 (`TryIntPtrMod`) 运算。这些函数允许在发生溢出时跳转到指定的标签。

3. **浮点数转换:**
   - 提供了将 Smi 转换为 `Float64T` 的方法 (`SmiToFloat64`)。

4. **数字运算 (更通用的 Number 类型):**
   - 提供了处理 JavaScript 中 `Number` 类型的最大值 (`NumberMax`) 和最小值 (`NumberMin`) 操作，这些操作需要考虑 NaN 等特殊情况。

5. **内存分配:**
   - 提供了底层的内存分配函数，例如 `AllocateRaw`，允许在指定的内存区域分配原始内存块，并可以处理双字对齐。
   - 提供了更高级的内存分配函数，例如 `AllocateInNewSpace` 和 `Allocate`，用于在新生代或老生代堆中分配对象。
   - 提供了判断大小是否为常规堆对象大小的方法 (`IsRegularHeapObjectSize`)。

6. **类型检查和分支:**
   - 提供了检查对象是否为 JSReceiver 的方法 (`BranchIfJSReceiver`)。
   - 提供了根据 JavaScript 的 ToBoolean 规则进行条件分支的方法 (`BranchIfToBooleanIsTrue`)，这涉及到处理各种 JavaScript 值的真假性。

7. **其他实用工具函数:**
   - `GetCoverageInfo`: 获取共享函数信息的覆盖率数据。
   - `TruncateWordToInt32`, `TruncateIntPtrToInt32`, `TruncateWord64ToWord32`: 将不同大小的字截断为 32 位整数。
   - `WordIsAligned`: 检查一个字是否按照给定的字节数对齐。
   - `LoadDoubleWithHoleCheck`: 加载 `FixedDoubleArray` 中的元素，并检查是否为 hole (未初始化的值)。
   - `GotoIfForceSlowPath`:  根据编译选项或运行时标志跳转到慢速路径。
   - `LoadSandboxedPointerFromObject`, `StoreSandboxedPointerToObject`:  用于处理沙箱环境下的指针加载和存储。
   - `EmptyBackingStoreBufferConstant`:  获取空 `BackingStore` 缓冲区的常量。

**如果 `v8/src/codegen/code-stub-assembler.cc` 以 `.tq` 结尾:**

如果文件以 `.tq` 结尾，那么它将是 **Torque** 源代码。Torque 是 V8 使用的一种领域特定语言，用于生成高效的 C++ 代码，特别是用于实现 V8 的内置函数和运行时部分。Torque 提供了一种更高级、更易于维护的方式来编写这些底层的代码生成逻辑。

**与 JavaScript 的功能关系及示例:**

这里列举一些 C++ 代码中的功能与 JavaScript 中对应操作的例子：

- **`SmiTag(value)` (C++)  相当于 JavaScript 内部将小整数标记为 Smi 的过程。**
  ```javascript
  // JavaScript 中无法直接观察到 SmiTag 的过程，
  // 但 V8 内部会将小整数优化存储为 Smi。
  const smallNumber = 10; // V8 可能会将其存储为 Smi
  ```

- **`SmiUntag(smi)` (C++) 相当于 JavaScript 内部从 Smi 中提取原始整数值的过程。**
  ```javascript
  // 同样，JavaScript 中无法直接观察，
  // 但当对 Smi 进行运算时，V8 会先 Untag。
  const smiValue = /* 假设 V8 内部的某个 Smi */;
  const rawValue = /* V8 内部的 SmiUntag(smiValue) 的结果 */;
  ```

- **`SmiAdd(a, b)` (C++) 相当于 JavaScript 中的加法运算，特别是当操作数是小的整数时。**
  ```javascript
  const num1 = 5;
  const num2 = 7;
  const sum = num1 + num2; // 如果 num1 和 num2 都是小的整数，V8 可能会使用优化的 Smi 加法
  ```

- **`NumberMax(a, b)` (C++) 相当于 `Math.max(a, b)`。**
  ```javascript
  const a = 10;
  const b = 20;
  const max = Math.max(a, b); // V8 内部的实现可能会调用类似的低级函数
  ```

- **`BranchIfToBooleanIsTrue(value, if_true, if_false)` (C++) 相当于 JavaScript 中将值转换为布尔值并进行条件判断。**
  ```javascript
  const value = 0;
  if (value) { // V8 内部会根据 ToBoolean 规则判断 value 的真假性
    console.log("Value is truthy");
  } else {
    console.log("Value is falsy");
  }
  ```

- **`AllocateInNewSpace(size)` (C++) 相当于 JavaScript 中创建新对象，例如 `new Object()` 或字面量 `{}`。**
  ```javascript
  const obj = {}; // V8 会在堆上分配内存来存储这个对象
  ```

**代码逻辑推理示例 (假设输入与输出):**

**函数:** `SmiTag(TNode<IntPtrT> value)`

**假设输入:** `value` 是一个 `TNode<IntPtrT>`，其运行时值是整数 `10`。

**推理:**
1. `TryToInt32Constant(value, &constant_value)` 会尝试将 `value` 转换为常量整数。假设转换成功，`constant_value` 将为 `10`。
2. `Smi::IsValid(constant_value)` 会检查 `10` 是否在有效的 Smi 范围内。假设是。
3. `SmiConstant(constant_value)` 会创建一个表示 Smi 值 `10` 的 `TNode<Smi>`。

**预期输出:**  返回一个 `TNode<Smi>`，其运行时值表示 Smi `10` (在内存中通常是一个带有特定标签的整数)。

**函数:** `SmiUntag(TNode<Smi> value)`

**假设输入:** `value` 是一个 `TNode<Smi>`，其运行时值表示 Smi `10`。

**推理:**
1. `TryToIntPtrConstant(value, &constant_value)` 会尝试将 `value` 转换为常量整数。假设转换成功，`constant_value` 将是 Smi `10` 的内部表示。
2. `IntPtrConstant(constant_value >> (kSmiShiftSize + kSmiTagSize))` 会将常量整数值右移，移除 Smi 的标签，得到原始的整数值 `10`。

**预期输出:** 返回一个 `TNode<IntPtrT>`，其运行时值是整数 `10`。

**用户常见的编程错误示例:**

虽然用户通常不会直接编写 `code-stub-assembler.cc` 中的代码，但理解其功能可以帮助理解 V8 如何处理 JavaScript，并避免一些与数字类型相关的常见错误：

1. **整数溢出:**  在 JavaScript 中，整数运算可以超出 32 位或 64 位整数的范围，导致精度丢失或意外的结果。`TryIntPtrAdd` 等函数试图在底层处理溢出，但 JavaScript 的语义可能会将其转换为浮点数或其他表示。
   ```javascript
   const maxInt = 2147483647;
   const overflow = maxInt + 1; // 在某些情况下可能会导致意外结果或转换为浮点数
   ```

2. **不理解 JavaScript 的 ToBoolean 规则:**  `BranchIfToBooleanIsTrue` 实现了 JavaScript 的类型转换规则。不理解这些规则可能导致 `if` 语句或逻辑运算的行为与预期不符。
   ```javascript
   if ("") { // 空字符串是 falsy
     console.log("This won't be printed");
   }

   if ([]) { // 空数组是 truthy
     console.log("This will be printed");
   }
   ```

3. **错误地假设 Smi 的范围:**  虽然 Smi 优化了小整数的存储和操作，但它们的范围是有限的。超出 Smi 范围的整数将以其他方式表示 (例如 HeapNumber)。依赖于所有整数都是 Smi 的假设可能会导致性能问题或逻辑错误。

**总结 (针对第 2 部分):**

`v8/src/codegen/code-stub-assembler.cc` 的这一部分主要提供了用于操作 Smi、进行带溢出检查的整数运算、处理通用数字类型、进行内存分配以及执行类型检查和条件分支的底层汇编器指令和辅助函数。这些功能是 V8 执行 JavaScript 代码的关键构建块，确保了高效的数值运算、内存管理和类型处理。理解这些底层机制有助于更深入地了解 V8 的工作原理以及 JavaScript 的一些行为特性。

### 提示词
```
这是目录为v8/src/codegen/code-stub-assembler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/code-stub-assembler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共23部分，请归纳一下它的功能
```

### 源代码
```cpp
return (static_cast<uintptr_t>(constant_value) <=
            static_cast<uintptr_t>(Smi::kMaxValue))
               ? Int32TrueConstant()
               : Int32FalseConstant();
  }

  return UintPtrLessThanOrEqual(value, IntPtrConstant(Smi::kMaxValue));
}

TNode<Smi> CodeStubAssembler::SmiTag(TNode<IntPtrT> value) {
  int32_t constant_value;
  if (TryToInt32Constant(value, &constant_value) &&
      Smi::IsValid(constant_value)) {
    return SmiConstant(constant_value);
  }
  if (COMPRESS_POINTERS_BOOL) {
    return SmiFromInt32(TruncateIntPtrToInt32(value));
  }
  TNode<Smi> smi =
      BitcastWordToTaggedSigned(WordShl(value, SmiShiftBitsConstant()));
  return smi;
}

TNode<IntPtrT> CodeStubAssembler::SmiUntag(TNode<Smi> value) {
  intptr_t constant_value;
  if (TryToIntPtrConstant(value, &constant_value)) {
    return IntPtrConstant(constant_value >> (kSmiShiftSize + kSmiTagSize));
  }
  TNode<IntPtrT> raw_bits = BitcastTaggedToWordForTagAndSmiBits(value);
  if (COMPRESS_POINTERS_BOOL) {
    return ChangeInt32ToIntPtr(Word32SarShiftOutZeros(
        TruncateIntPtrToInt32(raw_bits), SmiShiftBitsConstant32()));
  }
  return Signed(WordSarShiftOutZeros(raw_bits, SmiShiftBitsConstant()));
}

TNode<Int32T> CodeStubAssembler::SmiToInt32(TNode<Smi> value) {
  if (COMPRESS_POINTERS_BOOL) {
    return Signed(Word32SarShiftOutZeros(
        TruncateIntPtrToInt32(BitcastTaggedToWordForTagAndSmiBits(value)),
        SmiShiftBitsConstant32()));
  }
  TNode<IntPtrT> result = SmiUntag(value);
  return TruncateIntPtrToInt32(result);
}

TNode<Uint32T> CodeStubAssembler::PositiveSmiToUint32(TNode<Smi> value) {
  DCHECK(SmiGreaterThanOrEqual(value, SmiConstant(0)));
  return Unsigned(SmiToInt32(value));
}

TNode<IntPtrT> CodeStubAssembler::PositiveSmiUntag(TNode<Smi> value) {
  return ChangePositiveInt32ToIntPtr(SmiToInt32(value));
}

TNode<Float64T> CodeStubAssembler::SmiToFloat64(TNode<Smi> value) {
  return ChangeInt32ToFloat64(SmiToInt32(value));
}

TNode<Smi> CodeStubAssembler::SmiMax(TNode<Smi> a, TNode<Smi> b) {
  return SelectConstant<Smi>(SmiLessThan(a, b), b, a);
}

TNode<Smi> CodeStubAssembler::SmiMin(TNode<Smi> a, TNode<Smi> b) {
  return SelectConstant<Smi>(SmiLessThan(a, b), a, b);
}

TNode<IntPtrT> CodeStubAssembler::TryIntPtrAdd(TNode<IntPtrT> a,
                                               TNode<IntPtrT> b,
                                               Label* if_overflow) {
  TNode<PairT<IntPtrT, BoolT>> pair = IntPtrAddWithOverflow(a, b);
  TNode<BoolT> overflow = Projection<1>(pair);
  GotoIf(overflow, if_overflow);
  return Projection<0>(pair);
}

TNode<IntPtrT> CodeStubAssembler::TryIntPtrSub(TNode<IntPtrT> a,
                                               TNode<IntPtrT> b,
                                               Label* if_overflow) {
  TNode<PairT<IntPtrT, BoolT>> pair = IntPtrSubWithOverflow(a, b);
  TNode<BoolT> overflow = Projection<1>(pair);
  GotoIf(overflow, if_overflow);
  return Projection<0>(pair);
}

TNode<IntPtrT> CodeStubAssembler::TryIntPtrMul(TNode<IntPtrT> a,
                                               TNode<IntPtrT> b,
                                               Label* if_overflow) {
  TNode<PairT<IntPtrT, BoolT>> pair = IntPtrMulWithOverflow(a, b);
  TNode<BoolT> overflow = Projection<1>(pair);
  GotoIf(overflow, if_overflow);
  return Projection<0>(pair);
}

TNode<IntPtrT> CodeStubAssembler::TryIntPtrDiv(TNode<IntPtrT> a,
                                               TNode<IntPtrT> b,
                                               Label* if_div_zero) {
  GotoIf(IntPtrEqual(b, IntPtrConstant(0)), if_div_zero);
  return IntPtrDiv(a, b);
}

TNode<IntPtrT> CodeStubAssembler::TryIntPtrMod(TNode<IntPtrT> a,
                                               TNode<IntPtrT> b,
                                               Label* if_div_zero) {
  GotoIf(IntPtrEqual(b, IntPtrConstant(0)), if_div_zero);
  return IntPtrMod(a, b);
}

TNode<Int32T> CodeStubAssembler::TryInt32Mul(TNode<Int32T> a, TNode<Int32T> b,
                                             Label* if_overflow) {
  TNode<PairT<Int32T, BoolT>> pair = Int32MulWithOverflow(a, b);
  TNode<BoolT> overflow = Projection<1>(pair);
  GotoIf(overflow, if_overflow);
  return Projection<0>(pair);
}

TNode<Smi> CodeStubAssembler::TrySmiAdd(TNode<Smi> lhs, TNode<Smi> rhs,
                                        Label* if_overflow) {
  if (SmiValuesAre32Bits()) {
    return BitcastWordToTaggedSigned(
        TryIntPtrAdd(BitcastTaggedToWordForTagAndSmiBits(lhs),
                     BitcastTaggedToWordForTagAndSmiBits(rhs), if_overflow));
  } else {
    DCHECK(SmiValuesAre31Bits());
    TNode<PairT<Int32T, BoolT>> pair = Int32AddWithOverflow(
        TruncateIntPtrToInt32(BitcastTaggedToWordForTagAndSmiBits(lhs)),
        TruncateIntPtrToInt32(BitcastTaggedToWordForTagAndSmiBits(rhs)));
    TNode<BoolT> overflow = Projection<1>(pair);
    GotoIf(overflow, if_overflow);
    TNode<Int32T> result = Projection<0>(pair);
    return BitcastWordToTaggedSigned(ChangeInt32ToIntPtr(result));
  }
}

TNode<Smi> CodeStubAssembler::TrySmiSub(TNode<Smi> lhs, TNode<Smi> rhs,
                                        Label* if_overflow) {
  if (SmiValuesAre32Bits()) {
    TNode<PairT<IntPtrT, BoolT>> pair =
        IntPtrSubWithOverflow(BitcastTaggedToWordForTagAndSmiBits(lhs),
                              BitcastTaggedToWordForTagAndSmiBits(rhs));
    TNode<BoolT> overflow = Projection<1>(pair);
    GotoIf(overflow, if_overflow);
    TNode<IntPtrT> result = Projection<0>(pair);
    return BitcastWordToTaggedSigned(result);
  } else {
    DCHECK(SmiValuesAre31Bits());
    TNode<PairT<Int32T, BoolT>> pair = Int32SubWithOverflow(
        TruncateIntPtrToInt32(BitcastTaggedToWordForTagAndSmiBits(lhs)),
        TruncateIntPtrToInt32(BitcastTaggedToWordForTagAndSmiBits(rhs)));
    TNode<BoolT> overflow = Projection<1>(pair);
    GotoIf(overflow, if_overflow);
    TNode<Int32T> result = Projection<0>(pair);
    return BitcastWordToTaggedSigned(ChangeInt32ToIntPtr(result));
  }
}

TNode<Smi> CodeStubAssembler::TrySmiAbs(TNode<Smi> a, Label* if_overflow) {
  if (SmiValuesAre32Bits()) {
    TNode<PairT<IntPtrT, BoolT>> pair =
        IntPtrAbsWithOverflow(BitcastTaggedToWordForTagAndSmiBits(a));
    TNode<BoolT> overflow = Projection<1>(pair);
    GotoIf(overflow, if_overflow);
    TNode<IntPtrT> result = Projection<0>(pair);
    return BitcastWordToTaggedSigned(result);
  } else {
    CHECK(SmiValuesAre31Bits());
    CHECK(IsInt32AbsWithOverflowSupported());
    TNode<PairT<Int32T, BoolT>> pair = Int32AbsWithOverflow(
        TruncateIntPtrToInt32(BitcastTaggedToWordForTagAndSmiBits(a)));
    TNode<BoolT> overflow = Projection<1>(pair);
    GotoIf(overflow, if_overflow);
    TNode<Int32T> result = Projection<0>(pair);
    return BitcastWordToTaggedSigned(ChangeInt32ToIntPtr(result));
  }
}

TNode<Number> CodeStubAssembler::NumberMax(TNode<Number> a, TNode<Number> b) {
  // TODO(danno): This could be optimized by specifically handling smi cases.
  TVARIABLE(Number, result);
  Label done(this), greater_than_equal_a(this), greater_than_equal_b(this);
  GotoIfNumberGreaterThanOrEqual(a, b, &greater_than_equal_a);
  GotoIfNumberGreaterThanOrEqual(b, a, &greater_than_equal_b);
  result = NanConstant();
  Goto(&done);
  BIND(&greater_than_equal_a);
  result = a;
  Goto(&done);
  BIND(&greater_than_equal_b);
  result = b;
  Goto(&done);
  BIND(&done);
  return result.value();
}

TNode<Number> CodeStubAssembler::NumberMin(TNode<Number> a, TNode<Number> b) {
  // TODO(danno): This could be optimized by specifically handling smi cases.
  TVARIABLE(Number, result);
  Label done(this), greater_than_equal_a(this), greater_than_equal_b(this);
  GotoIfNumberGreaterThanOrEqual(a, b, &greater_than_equal_a);
  GotoIfNumberGreaterThanOrEqual(b, a, &greater_than_equal_b);
  result = NanConstant();
  Goto(&done);
  BIND(&greater_than_equal_a);
  result = b;
  Goto(&done);
  BIND(&greater_than_equal_b);
  result = a;
  Goto(&done);
  BIND(&done);
  return result.value();
}

TNode<Number> CodeStubAssembler::SmiMod(TNode<Smi> a, TNode<Smi> b) {
  TVARIABLE(Number, var_result);
  Label return_result(this, &var_result),
      return_minuszero(this, Label::kDeferred),
      return_nan(this, Label::kDeferred);

  // Untag {a} and {b}.
  TNode<Int32T> int_a = SmiToInt32(a);
  TNode<Int32T> int_b = SmiToInt32(b);

  // Return NaN if {b} is zero.
  GotoIf(Word32Equal(int_b, Int32Constant(0)), &return_nan);

  // Check if {a} is non-negative.
  Label if_aisnotnegative(this), if_aisnegative(this, Label::kDeferred);
  Branch(Int32LessThanOrEqual(Int32Constant(0), int_a), &if_aisnotnegative,
         &if_aisnegative);

  BIND(&if_aisnotnegative);
  {
    // Fast case, don't need to check any other edge cases.
    TNode<Int32T> r = Int32Mod(int_a, int_b);
    var_result = SmiFromInt32(r);
    Goto(&return_result);
  }

  BIND(&if_aisnegative);
  {
    if (SmiValuesAre32Bits()) {
      // Check if {a} is kMinInt and {b} is -1 (only relevant if the
      // kMinInt is actually representable as a Smi).
      Label join(this);
      GotoIfNot(Word32Equal(int_a, Int32Constant(kMinInt)), &join);
      GotoIf(Word32Equal(int_b, Int32Constant(-1)), &return_minuszero);
      Goto(&join);
      BIND(&join);
    }

    // Perform the integer modulus operation.
    TNode<Int32T> r = Int32Mod(int_a, int_b);

    // Check if {r} is zero, and if so return -0, because we have to
    // take the sign of the left hand side {a}, which is negative.
    GotoIf(Word32Equal(r, Int32Constant(0)), &return_minuszero);

    // The remainder {r} can be outside the valid Smi range on 32bit
    // architectures, so we cannot just say SmiFromInt32(r) here.
    var_result = ChangeInt32ToTagged(r);
    Goto(&return_result);
  }

  BIND(&return_minuszero);
  var_result = MinusZeroConstant();
  Goto(&return_result);

  BIND(&return_nan);
  var_result = NanConstant();
  Goto(&return_result);

  BIND(&return_result);
  return var_result.value();
}

TNode<Number> CodeStubAssembler::SmiMul(TNode<Smi> a, TNode<Smi> b) {
  TVARIABLE(Number, var_result);
  TVARIABLE(Float64T, var_lhs_float64);
  TVARIABLE(Float64T, var_rhs_float64);
  Label return_result(this, &var_result);

  // Both {a} and {b} are Smis. Convert them to integers and multiply.
  TNode<Int32T> lhs32 = SmiToInt32(a);
  TNode<Int32T> rhs32 = SmiToInt32(b);
  auto pair = Int32MulWithOverflow(lhs32, rhs32);

  TNode<BoolT> overflow = Projection<1>(pair);

  // Check if the multiplication overflowed.
  Label if_overflow(this, Label::kDeferred), if_notoverflow(this);
  Branch(overflow, &if_overflow, &if_notoverflow);
  BIND(&if_notoverflow);
  {
    // If the answer is zero, we may need to return -0.0, depending on the
    // input.
    Label answer_zero(this), answer_not_zero(this);
    TNode<Int32T> answer = Projection<0>(pair);
    TNode<Int32T> zero = Int32Constant(0);
    Branch(Word32Equal(answer, zero), &answer_zero, &answer_not_zero);
    BIND(&answer_not_zero);
    {
      var_result = ChangeInt32ToTagged(answer);
      Goto(&return_result);
    }
    BIND(&answer_zero);
    {
      TNode<Int32T> or_result = Word32Or(lhs32, rhs32);
      Label if_should_be_negative_zero(this), if_should_be_zero(this);
      Branch(Int32LessThan(or_result, zero), &if_should_be_negative_zero,
             &if_should_be_zero);
      BIND(&if_should_be_negative_zero);
      {
        var_result = MinusZeroConstant();
        Goto(&return_result);
      }
      BIND(&if_should_be_zero);
      {
        var_result = SmiConstant(0);
        Goto(&return_result);
      }
    }
  }
  BIND(&if_overflow);
  {
    var_lhs_float64 = SmiToFloat64(a);
    var_rhs_float64 = SmiToFloat64(b);
    TNode<Float64T> value =
        Float64Mul(var_lhs_float64.value(), var_rhs_float64.value());
    var_result = AllocateHeapNumberWithValue(value);
    Goto(&return_result);
  }

  BIND(&return_result);
  return var_result.value();
}

TNode<Smi> CodeStubAssembler::TrySmiDiv(TNode<Smi> dividend, TNode<Smi> divisor,
                                        Label* bailout) {
  // Both {a} and {b} are Smis. Bailout to floating point division if {divisor}
  // is zero.
  GotoIf(TaggedEqual(divisor, SmiConstant(0)), bailout);

  // Do floating point division if {dividend} is zero and {divisor} is
  // negative.
  Label dividend_is_zero(this), dividend_is_not_zero(this);
  Branch(TaggedEqual(dividend, SmiConstant(0)), &dividend_is_zero,
         &dividend_is_not_zero);

  BIND(&dividend_is_zero);
  {
    GotoIf(SmiLessThan(divisor, SmiConstant(0)), bailout);
    Goto(&dividend_is_not_zero);
  }
  BIND(&dividend_is_not_zero);

  TNode<Int32T> untagged_divisor = SmiToInt32(divisor);
  TNode<Int32T> untagged_dividend = SmiToInt32(dividend);

  // Do floating point division if {dividend} is kMinInt (or kMinInt - 1
  // if the Smi size is 31) and {divisor} is -1.
  Label divisor_is_minus_one(this), divisor_is_not_minus_one(this);
  Branch(Word32Equal(untagged_divisor, Int32Constant(-1)),
         &divisor_is_minus_one, &divisor_is_not_minus_one);

  BIND(&divisor_is_minus_one);
  {
    GotoIf(Word32Equal(
               untagged_dividend,
               Int32Constant(kSmiValueSize == 32 ? kMinInt : (kMinInt >> 1))),
           bailout);
    Goto(&divisor_is_not_minus_one);
  }
  BIND(&divisor_is_not_minus_one);

  TNode<Int32T> untagged_result = Int32Div(untagged_dividend, untagged_divisor);
  TNode<Int32T> truncated = Int32Mul(untagged_result, untagged_divisor);

  // Do floating point division if the remainder is not 0.
  GotoIf(Word32NotEqual(untagged_dividend, truncated), bailout);

  return SmiFromInt32(untagged_result);
}

TNode<Smi> CodeStubAssembler::SmiLexicographicCompare(TNode<Smi> x,
                                                      TNode<Smi> y) {
  TNode<ExternalReference> smi_lexicographic_compare =
      ExternalConstant(ExternalReference::smi_lexicographic_compare_function());
  TNode<ExternalReference> isolate_ptr =
      ExternalConstant(ExternalReference::isolate_address());
  return CAST(CallCFunction(smi_lexicographic_compare, MachineType::AnyTagged(),
                            std::make_pair(MachineType::Pointer(), isolate_ptr),
                            std::make_pair(MachineType::AnyTagged(), x),
                            std::make_pair(MachineType::AnyTagged(), y)));
}

TNode<Object> CodeStubAssembler::GetCoverageInfo(
    TNode<SharedFunctionInfo> sfi) {
  TNode<ExternalReference> f =
      ExternalConstant(ExternalReference::debug_get_coverage_info_function());
  TNode<ExternalReference> isolate_ptr =
      ExternalConstant(ExternalReference::isolate_address());
  return CAST(CallCFunction(f, MachineType::AnyTagged(),
                            std::make_pair(MachineType::Pointer(), isolate_ptr),
                            std::make_pair(MachineType::TaggedPointer(), sfi)));
}

TNode<Int32T> CodeStubAssembler::TruncateWordToInt32(TNode<WordT> value) {
  if (Is64()) {
    return TruncateInt64ToInt32(ReinterpretCast<Int64T>(value));
  }
  return ReinterpretCast<Int32T>(value);
}

TNode<Int32T> CodeStubAssembler::TruncateIntPtrToInt32(TNode<IntPtrT> value) {
  if (Is64()) {
    return TruncateInt64ToInt32(ReinterpretCast<Int64T>(value));
  }
  return ReinterpretCast<Int32T>(value);
}

TNode<Word32T> CodeStubAssembler::TruncateWord64ToWord32(TNode<Word64T> value) {
  return TruncateInt64ToInt32(ReinterpretCast<Int64T>(value));
}

TNode<BoolT> CodeStubAssembler::TaggedIsSmi(TNode<MaybeObject> a) {
  static_assert(kSmiTagMask < kMaxUInt32);
  return Word32Equal(
      Word32And(TruncateIntPtrToInt32(BitcastTaggedToWordForTagAndSmiBits(a)),
                Int32Constant(kSmiTagMask)),
      Int32Constant(0));
}

TNode<BoolT> CodeStubAssembler::TaggedIsNotSmi(TNode<MaybeObject> a) {
  return Word32BinaryNot(TaggedIsSmi(a));
}

TNode<BoolT> CodeStubAssembler::TaggedIsPositiveSmi(TNode<Object> a) {
#if defined(V8_HOST_ARCH_32_BIT) || defined(V8_31BIT_SMIS_ON_64BIT_ARCH)
  return Word32Equal(
      Word32And(
          TruncateIntPtrToInt32(BitcastTaggedToWordForTagAndSmiBits(a)),
          Uint32Constant(static_cast<uint32_t>(kSmiTagMask | kSmiSignMask))),
      Int32Constant(0));
#else
  return WordEqual(WordAnd(BitcastTaggedToWordForTagAndSmiBits(a),
                           IntPtrConstant(kSmiTagMask | kSmiSignMask)),
                   IntPtrConstant(0));
#endif
}

TNode<BoolT> CodeStubAssembler::WordIsAligned(TNode<WordT> word,
                                              size_t alignment) {
  DCHECK(base::bits::IsPowerOfTwo(alignment));
  DCHECK_LE(alignment, kMaxUInt32);
  return Word32Equal(
      Int32Constant(0),
      Word32And(TruncateWordToInt32(word),
                Uint32Constant(static_cast<uint32_t>(alignment) - 1)));
}

#if DEBUG
void CodeStubAssembler::Bind(Label* label, AssemblerDebugInfo debug_info) {
  CodeAssembler::Bind(label, debug_info);
}
#endif  // DEBUG

void CodeStubAssembler::Bind(Label* label) { CodeAssembler::Bind(label); }

TNode<Float64T> CodeStubAssembler::LoadDoubleWithHoleCheck(
    TNode<FixedDoubleArray> array, TNode<IntPtrT> index, Label* if_hole) {
  return LoadFixedDoubleArrayElement(array, index, if_hole);
}

void CodeStubAssembler::BranchIfJSReceiver(TNode<Object> object, Label* if_true,
                                           Label* if_false) {
  GotoIf(TaggedIsSmi(object), if_false);
  static_assert(LAST_JS_RECEIVER_TYPE == LAST_TYPE);
  Branch(IsJSReceiver(CAST(object)), if_true, if_false);
}

void CodeStubAssembler::GotoIfForceSlowPath(Label* if_true) {
#ifdef V8_ENABLE_FORCE_SLOW_PATH
  bool enable_force_slow_path = true;
#else
  bool enable_force_slow_path = false;
#endif

  Label done(this);
  // Use UniqueInt32Constant instead of BoolConstant here in order to ensure
  // that the graph structure does not depend on the value of the predicate
  // (BoolConstant uses cached nodes).
  GotoIf(UniqueInt32Constant(!enable_force_slow_path), &done);
  {
    // This optional block is used behind a static check and we rely
    // on the dead code elimination to remove it. We generate builtins this
    // way in order to ensure that builtins PGO profiles are agnostic to
    // V8_ENABLE_FORCE_SLOW_PATH value.
    const TNode<ExternalReference> force_slow_path_addr =
        ExternalConstant(ExternalReference::force_slow_path(isolate()));
    const TNode<Uint8T> force_slow = Load<Uint8T>(force_slow_path_addr);
    Branch(force_slow, if_true, &done);
  }
  BIND(&done);
}

TNode<HeapObject> CodeStubAssembler::AllocateRaw(TNode<IntPtrT> size_in_bytes,
                                                 AllocationFlags flags,
                                                 TNode<RawPtrT> top_address,
                                                 TNode<RawPtrT> limit_address) {
  Label if_out_of_memory(this, Label::kDeferred);

  // TODO(jgruber,jkummerow): Extract the slow paths (= probably everything
  // but bump pointer allocation) into a builtin to save code space. The
  // size_in_bytes check may be moved there as well since a non-smi
  // size_in_bytes probably doesn't fit into the bump pointer region
  // (double-check that).

  intptr_t size_in_bytes_constant;
  bool size_in_bytes_is_constant = false;
  if (TryToIntPtrConstant(size_in_bytes, &size_in_bytes_constant)) {
    size_in_bytes_is_constant = true;
    CHECK(Internals::IsValidSmi(size_in_bytes_constant));
    CHECK_GT(size_in_bytes_constant, 0);
  } else {
    GotoIfNot(IsValidPositiveSmi(size_in_bytes), &if_out_of_memory);
  }

  TNode<RawPtrT> top = Load<RawPtrT>(top_address);
  TNode<RawPtrT> limit = Load<RawPtrT>(limit_address);

  // If there's not enough space, call the runtime.
  TVARIABLE(Object, result);
  Label runtime_call(this, Label::kDeferred), no_runtime_call(this), out(this);

  bool needs_double_alignment = flags & AllocationFlag::kDoubleAlignment;

  Label next(this);
  GotoIf(IsRegularHeapObjectSize(size_in_bytes), &next);

  TNode<Smi> runtime_flags = SmiConstant(
      Smi::FromInt(AllocateDoubleAlignFlag::encode(needs_double_alignment)));
  result = CallRuntime(Runtime::kAllocateInYoungGeneration, NoContextConstant(),
                       SmiTag(size_in_bytes), runtime_flags);
  Goto(&out);

  BIND(&next);

  TVARIABLE(IntPtrT, adjusted_size, size_in_bytes);

  if (needs_double_alignment) {
    Label next(this);
    GotoIfNot(WordAnd(top, IntPtrConstant(kDoubleAlignmentMask)), &next);

    adjusted_size = IntPtrAdd(size_in_bytes, IntPtrConstant(4));
    Goto(&next);

    BIND(&next);
  }

  adjusted_size = AlignToAllocationAlignment(adjusted_size.value());
  TNode<IntPtrT> new_top =
      IntPtrAdd(UncheckedCast<IntPtrT>(top), adjusted_size.value());

  Branch(UintPtrGreaterThanOrEqual(new_top, limit), &runtime_call,
         &no_runtime_call);

  BIND(&runtime_call);
  {
    TNode<Smi> runtime_flags = SmiConstant(
        Smi::FromInt(AllocateDoubleAlignFlag::encode(needs_double_alignment)));
    if (flags & AllocationFlag::kPretenured) {
      result =
          CallRuntime(Runtime::kAllocateInOldGeneration, NoContextConstant(),
                      SmiTag(size_in_bytes), runtime_flags);
    } else {
      result =
          CallRuntime(Runtime::kAllocateInYoungGeneration, NoContextConstant(),
                      SmiTag(size_in_bytes), runtime_flags);
    }
    Goto(&out);
  }

  // When there is enough space, return `top' and bump it up.
  BIND(&no_runtime_call);
  {
    StoreNoWriteBarrier(MachineType::PointerRepresentation(), top_address,
                        new_top);

    TVARIABLE(IntPtrT, address, UncheckedCast<IntPtrT>(top));

    if (needs_double_alignment) {
      Label next(this);
      GotoIf(IntPtrEqual(adjusted_size.value(), size_in_bytes), &next);

      // Store a filler and increase the address by 4.
      StoreNoWriteBarrier(MachineRepresentation::kTagged, top,
                          OnePointerFillerMapConstant());
      address = IntPtrAdd(UncheckedCast<IntPtrT>(top), IntPtrConstant(4));
      Goto(&next);

      BIND(&next);
    }

    result = BitcastWordToTagged(
        IntPtrAdd(address.value(), IntPtrConstant(kHeapObjectTag)));
    Goto(&out);
  }

  if (!size_in_bytes_is_constant) {
    BIND(&if_out_of_memory);
    CallRuntime(Runtime::kFatalProcessOutOfMemoryInAllocateRaw,
                NoContextConstant());
    Unreachable();
  }

  BIND(&out);
  if (v8_flags.sticky_mark_bits && (flags & AllocationFlag::kPretenured)) {
    CSA_DCHECK(this, IsMarked(result.value()));
  }
  return UncheckedCast<HeapObject>(result.value());
}

TNode<HeapObject> CodeStubAssembler::AllocateRawUnaligned(
    TNode<IntPtrT> size_in_bytes, AllocationFlags flags,
    TNode<RawPtrT> top_address, TNode<RawPtrT> limit_address) {
  DCHECK_EQ(flags & AllocationFlag::kDoubleAlignment, 0);
  return AllocateRaw(size_in_bytes, flags, top_address, limit_address);
}

TNode<HeapObject> CodeStubAssembler::AllocateRawDoubleAligned(
    TNode<IntPtrT> size_in_bytes, AllocationFlags flags,
    TNode<RawPtrT> top_address, TNode<RawPtrT> limit_address) {
#if defined(V8_HOST_ARCH_32_BIT)
  return AllocateRaw(size_in_bytes, flags | AllocationFlag::kDoubleAlignment,
                     top_address, limit_address);
#elif defined(V8_HOST_ARCH_64_BIT)
#ifdef V8_COMPRESS_POINTERS
// TODO(ishell, v8:8875): Consider using aligned allocations once the
// allocation alignment inconsistency is fixed. For now we keep using
// unaligned access since both x64 and arm64 architectures (where pointer
// compression is supported) allow unaligned access to doubles and full words.
#endif  // V8_COMPRESS_POINTERS
  // Allocation on 64 bit machine is naturally double aligned
  return AllocateRaw(size_in_bytes, flags & ~AllocationFlag::kDoubleAlignment,
                     top_address, limit_address);
#else
#error Architecture not supported
#endif
}

TNode<HeapObject> CodeStubAssembler::AllocateInNewSpace(
    TNode<IntPtrT> size_in_bytes, AllocationFlags flags) {
  DCHECK(flags == AllocationFlag::kNone ||
         flags == AllocationFlag::kDoubleAlignment);
  CSA_DCHECK(this, IsRegularHeapObjectSize(size_in_bytes));
  return Allocate(size_in_bytes, flags);
}

TNode<HeapObject> CodeStubAssembler::Allocate(TNode<IntPtrT> size_in_bytes,
                                              AllocationFlags flags) {
  Comment("Allocate");
  if (v8_flags.single_generation) flags |= AllocationFlag::kPretenured;
  bool const new_space = !(flags & AllocationFlag::kPretenured);
  if (!(flags & AllocationFlag::kDoubleAlignment)) {
    TNode<HeapObject> heap_object =
        OptimizedAllocate(size_in_bytes, new_space ? AllocationType::kYoung
                                                   : AllocationType::kOld);
    if (v8_flags.sticky_mark_bits && !new_space) {
      CSA_DCHECK(this, IsMarked(heap_object));
    }
    return heap_object;
  }
  TNode<ExternalReference> top_address = ExternalConstant(
      new_space
          ? ExternalReference::new_space_allocation_top_address(isolate())
          : ExternalReference::old_space_allocation_top_address(isolate()));

#ifdef DEBUG
  // New space is optional and if disabled both top and limit return
  // kNullAddress.
  if (ExternalReference::new_space_allocation_top_address(isolate())
          .address() != kNullAddress) {
    Address raw_top_address =
        ExternalReference::new_space_allocation_top_address(isolate())
            .address();
    Address raw_limit_address =
        ExternalReference::new_space_allocation_limit_address(isolate())
            .address();

    CHECK_EQ(kSystemPointerSize, raw_limit_address - raw_top_address);
  }

  DCHECK_EQ(kSystemPointerSize,
            ExternalReference::old_space_allocation_limit_address(isolate())
                    .address() -
                ExternalReference::old_space_allocation_top_address(isolate())
                    .address());
#endif

  TNode<IntPtrT> limit_address =
      IntPtrAdd(ReinterpretCast<IntPtrT>(top_address),
                IntPtrConstant(kSystemPointerSize));

  if (flags & AllocationFlag::kDoubleAlignment) {
    return AllocateRawDoubleAligned(size_in_bytes, flags,
                                    ReinterpretCast<RawPtrT>(top_address),
                                    ReinterpretCast<RawPtrT>(limit_address));
  } else {
    return AllocateRawUnaligned(size_in_bytes, flags,
                                ReinterpretCast<RawPtrT>(top_address),
                                ReinterpretCast<RawPtrT>(limit_address));
  }
}

TNode<HeapObject> CodeStubAssembler::AllocateInNewSpace(int size_in_bytes,
                                                        AllocationFlags flags) {
  CHECK(flags == AllocationFlag::kNone ||
        flags == AllocationFlag::kDoubleAlignment);
  DCHECK_LE(size_in_bytes, kMaxRegularHeapObjectSize);
  return CodeStubAssembler::Allocate(IntPtrConstant(size_in_bytes), flags);
}

TNode<HeapObject> CodeStubAssembler::Allocate(int size_in_bytes,
                                              AllocationFlags flags) {
  return CodeStubAssembler::Allocate(IntPtrConstant(size_in_bytes), flags);
}

TNode<BoolT> CodeStubAssembler::IsRegularHeapObjectSize(TNode<IntPtrT> size) {
  return UintPtrLessThanOrEqual(size,
                                IntPtrConstant(kMaxRegularHeapObjectSize));
}

void CodeStubAssembler::BranchIfToBooleanIsTrue(TNode<Object> value,
                                                Label* if_true,
                                                Label* if_false) {
  Label if_smi(this, Label::kDeferred), if_heapnumber(this, Label::kDeferred),
      if_bigint(this, Label::kDeferred);

  // Check if {value} is a Smi.
  GotoIf(TaggedIsSmi(value), &if_smi);

  TNode<HeapObject> value_heapobject = CAST(value);

#if V8_STATIC_ROOTS_BOOL
  // Check if {object} is a falsey root or the true value.
  // Undefined is the first root, so it's the smallest possible pointer
  // value, which means we don't have to subtract it for the range check.
  ReadOnlyRoots roots(isolate());
  static_assert(StaticReadOnlyRoot::kFirstAllocatedRoot ==
                StaticReadOnlyRoot::kUndefinedValue);
  static_assert(StaticReadOnlyRoot::kUndefinedValue + sizeof(Undefined) ==
                StaticReadOnlyRoot::kNullValue);
  static_assert(StaticReadOnlyRoot::kNullValue + sizeof(Null) ==
                StaticReadOnlyRoot::kempty_string);
  static_assert(StaticReadOnlyRoot::kempty_string +
                    SeqOneByteString::SizeFor(0) ==
                StaticReadOnlyRoot::kFalseValue);
  static_assert(StaticReadOnlyRoot::kFalseValue + sizeof(False) ==
                StaticReadOnlyRoot::kTrueValue);
  TNode<Word32T> object_as_word32 =
      TruncateIntPtrToInt32(BitcastTaggedToWord(value_heapobject));
  TNode<Word32T> true_as_word32 = Int32Constant(StaticReadOnlyRoot::kTrueValue);
  GotoIf(Uint32LessThan(object_as_word32, true_as_word32), if_false);
  GotoIf(Word32Equal(object_as_word32, true_as_word32), if_true);
#else
  // Rule out false {value}.
  GotoIf(TaggedEqual(value, FalseConstant()), if_false);

  // Fast path on true {value}.
  GotoIf(TaggedEqual(value, TrueConstant()), if_true);

  // Check if {value} is the empty string.
  GotoIf(IsEmptyString(value_heapobject), if_false);
#endif

  // The {value} is a HeapObject, load its map.
  TNode<Map> value_map = LoadMap(value_heapobject);

  // Only null, undefined and document.all have the undetectable bit set,
  // so we can return false immediately when that bit is set. With static roots
  // we've already checked for null and undefined, but we need to check the
  // undetectable bit for document.all anyway on the common path and it doesn't
  // help to check the undetectable object protector in builtins since we can't
  // deopt.
  GotoIf(IsUndetectableMap(value_map), if_false);

  // We still need to handle numbers specially, but all other {value}s
  // that make it here yield true.
  GotoIf(IsHeapNumberMap(value_map), &if_heapnumber);
  Branch(IsBigInt(value_heapobject), &if_bigint, if_true);

  BIND(&if_smi);
  {
    // Check if the Smi {value} is a zero.
    Branch(TaggedEqual(value, SmiConstant(0)), if_false, if_true);
  }

  BIND(&if_heapnumber);
  {
    // Load the floating point value of {value}.
    TNode<Float64T> value_value = LoadObjectField<Float64T>(
        value_heapobject, offsetof(HeapNumber, value_));

    // Check if the floating point {value} is neither 0.0, -0.0 nor NaN.
    Branch(Float64LessThan(Float64Constant(0.0), Float64Abs(value_value)),
           if_true, if_false);
  }

  BIND(&if_bigint);
  {
    TNode<BigInt> bigint = CAST(value);
    TNode<Word32T> bitfield = LoadBigIntBitfield(bigint);
    TNode<Uint32T> length = DecodeWord32<BigIntBase::LengthBits>(bitfield);
    Branch(Word32Equal(length, Int32Constant(0)), if_false, if_true);
  }
}

TNode<RawPtrT> CodeStubAssembler::LoadSandboxedPointerFromObject(
    TNode<HeapObject> object, TNode<IntPtrT> field_offset) {
#ifdef V8_ENABLE_SANDBOX
  return ReinterpretCast<RawPtrT>(
      LoadObjectField<SandboxedPtrT>(object, field_offset));
#else
  return LoadObjectField<RawPtrT>(object, field_offset);
#endif  // V8_ENABLE_SANDBOX
}

void CodeStubAssembler::StoreSandboxedPointerToObject(TNode<HeapObject> object,
                                                      TNode<IntPtrT> offset,
                                                      TNode<RawPtrT> pointer) {
#ifdef V8_ENABLE_SANDBOX
  TNode<SandboxedPtrT> sbx_ptr = ReinterpretCast<SandboxedPtrT>(pointer);

  // Ensure pointer points into the sandbox.
  TNode<ExternalReference> sandbox_base_address =
      ExternalConstant(ExternalReference::sandbox_base_address());
  TNode<ExternalReference> sandbox_end_address =
      ExternalConstant(ExternalReference::sandbox_end_address());
  TNode<UintPtrT> sandbox_base = Load<UintPtrT>(sandbox_base_address);
  TNode<UintPtrT> sandbox_end = Load<UintPtrT>(sandbox_end_address);
  CSA_CHECK(this, UintPtrGreaterThanOrEqual(sbx_ptr, sandbox_base));
  CSA_CHECK(this, UintPtrLessThan(sbx_ptr, sandbox_end));

  StoreObjectFieldNoWriteBarrier<SandboxedPtrT>(object, offset, sbx_ptr);
#else
  StoreObjectFieldNoWriteBarrier<RawPtrT>(object, offset, pointer);
#endif  // V8_ENABLE_SANDBOX
}

TNode<RawPtrT> CodeStubAssembler::EmptyBackingStoreBufferConstant() {
#ifdef V8_ENABLE_SANDBOX
  // TODO(chromium:1218005) consider creating a LoadSandboxedPointerConstant()
  // if more of these constants are required later on.
  TNode<ExternalReference> empty_backing_store_buffer =
      ExternalConstant(ExternalReference::empty_backing_store_buffer());
  return Load<RawPtrT>(empty_backing_store_buffer);
#else
  return ReinterpretCast<RawPtrT>(IntPtrConstant(0));
#endif  // V8_ENABLE_SANDBOX
}

TNode<UintPtrT> CodeStubAssembler::LoadBoundedSizeFromObject(
    TNode<Hea
```