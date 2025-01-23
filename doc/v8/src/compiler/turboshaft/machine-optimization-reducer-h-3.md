Response:
Let's break down the thought process for analyzing this C++ header file and generating the summary.

**1. Initial Scan and Keyword Identification:**

My first step is to quickly scan the file for keywords and structural elements that give clues about its purpose. I look for:

* **Class names:** `MachineOptimizationReducer` immediately stands out. "Reducer" often implies a transformation or simplification process. "Optimization" and "Machine" suggest this is related to low-level code generation.
* **Method names:**  Methods like `ReduceMemoryIndex`, `IsFloat32ConvertedToFloat64`, `UndoWord32ToWord64Conversion`, `ReduceSignedDiv`, `ReduceUnsignedDiv`, `ReduceBranchCondition`, and `MapLoadCanBeConstantFolded` clearly indicate the types of optimizations being performed.
* **Data members:**  `broker` and `matcher_` suggest interactions with a larger compilation framework. `broker` likely provides access to information about the program being compiled, while `matcher_` hints at pattern matching within the intermediate representation.
* **Templates and Generics:** The use of `V<Word>`, `OpIndex`, and `WordRepresentation` suggests a system with different data types and representations being handled.
* **Includes:**  The included header file `src/compiler/turboshaft/undef-assembler-macros.inc` (while not directly revealing functionality) reinforces the idea of this being related to a code generation process.
* **Comments and `DCHECK` statements:** These provide valuable insights into the assumptions and intended behavior of the code.

**2. Grouping Functionality by Category:**

As I identify methods, I start mentally grouping them based on the type of optimization they perform. This leads to categories like:

* **Memory Access Optimization:**  `ReduceMemoryIndex`, `TryAdjustOffset`, `TryAdjustIndex`, `TryAdjustElementScale`. These clearly deal with simplifying memory address calculations.
* **Data Type Conversion Optimization:** `IsFloat32ConvertedToFloat64`, `UndoFloat32ToFloat64Conversion`, `IsWord32ConvertedToWord64`, `UndoWord32ToWord64Conversion`, `TryRemoveWord32ToWord64Conversion`. This focuses on eliminating or simplifying unnecessary type conversions.
* **Arithmetic and Logical Operation Optimization:**  `ReduceSignedDiv`, `ReduceUnsignedDiv`, `ReduceWithTruncation`, `ReduceBranchCondition`. These methods aim to simplify arithmetic and logical expressions.
* **Type Checking and Information:** `IsBit`, `IsInt8`, `IsInt16`, `MapLoadCanBeConstantFolded`. These seem to be helper functions for checking the types or properties of values.
* **Constants:**  Methods with "Constant" in their name like `__ IntPtrConstant`, `__ WordConstant`, `__ Float32Constant` suggest the creation of constant values in the intermediate representation.

**3. Analyzing Individual Methods (with examples):**

For each method, I try to understand its purpose and how it achieves its goal. This often involves:

* **Reading the method name and parameters:**  This gives the initial context. For example, `ReduceMemoryIndex(OpIndex index, int32_t* offset, uint8_t* element_scale, bool tagged_base)` suggests it's taking an index and modifying an offset and scale.
* **Examining the logic:** I look for conditional statements, loops, and how the input parameters are manipulated.
* **Understanding the return value:** What does the method return, and what does that signify?
* **Considering edge cases and assumptions (often revealed by `DCHECK`):** For example, the `ReduceSignedDiv` method handles division by -1, 0, 1, and the minimum signed value.

**Example of analyzing `ReduceMemoryIndex`:**

* **Name:** `ReduceMemoryIndex` - suggests simplifying memory access calculations.
* **Parameters:** `index`, `offset`, `element_scale`. This hints at the components of a memory address calculation (base + index * scale + offset).
* **Logic:** The `while (index.valid())` loop suggests iterating through parts of the index calculation. The calls to `TryAdjustOffset`, `TryAdjustIndex`, and the handling of `ShiftOp` and `WordBinopOp` indicate different ways the index can be simplified.
* **Goal:** The comment "Fold away operations in the computation of `index` while preserving the value of `(index << element_scale) + offset)`" clearly states the purpose.

**4. Connecting to JavaScript (when applicable):**

When a method's functionality relates to JavaScript concepts, I try to illustrate it with a simple JavaScript example. For instance, `MapLoadCanBeConstantFolded` relates to accessing object properties, which is a fundamental JavaScript operation.

**5. Code Logic Reasoning (Hypothetical Inputs and Outputs):**

For methods performing transformations, I consider simple hypothetical inputs and what the expected output would be. This helps solidify my understanding. For example, with `ReduceMemoryIndex`, if the index is `x << 2` and the offset is initially 0, the method might update the `element_scale` to 2 and the index to `x`.

**6. Identifying Potential Programming Errors:**

I look for scenarios where a programmer might make mistakes that this reducer could potentially address. For example, unnecessarily converting between float32 and float64, or performing redundant arithmetic operations in index calculations.

**7. Summarization and Structure:**

Finally, I synthesize my understanding into a clear and organized summary. I use headings and bullet points to structure the information logically, covering the main functionalities and providing illustrative examples. I pay attention to the prompt's specific requests, like mentioning Torque and JavaScript connections.

**Self-Correction/Refinement during the Process:**

* **Initial Overgeneralization:** I might initially think a function does more or less than it actually does. Careful reading of the code and comments helps refine my understanding.
* **Missing Connections:**  I might miss the connection between two related functions initially and realize it later as I analyze more code.
* **Clarity of Explanation:** I might rephrase my explanations to make them clearer and more concise.
* **Addressing all parts of the prompt:** I double-check that I've answered all aspects of the prompt, including the Torque question and the final summarization.

By following this systematic process of scanning, categorizing, analyzing, connecting, and summarizing, I can effectively understand and explain the functionality of a complex C++ header file like the one provided.
好的，这是对 `v8/src/compiler/turboshaft/machine-optimization-reducer.h` 文件功能的总结：

**核心功能：机器码优化**

`MachineOptimizationReducer` 的主要目标是在 Turboshaft 编译管道中执行机器码级别的优化。它通过分析和转换中间表示（IR）图中的操作（Operations）来实现这一点，旨在生成更高效的目标机器码。

**具体功能分解：**

1. **内存访问优化 (`ReduceMemoryIndex`)**:
    *   该功能专注于优化内存访问的索引计算，目的是简化 `(index << element_scale) + offset` 形式的表达式。
    *   它可以将索引计算中的常量部分合并到偏移量 (`offset`) 或元素缩放因子 (`element_scale`) 中。
    *   它能识别并消除不必要的移位和加法操作。

    **代码逻辑推理 (假设输入与输出):**
    假设 `index` 是操作 `a + (b << 2)`， `offset` 是 0， `element_scale` 是 0。 `ReduceMemoryIndex` 可能会将 `element_scale` 更新为 2， 并将 `index` 更新为操作 `a + b`， `offset` 保持为 0。  最终效果是相同的内存地址计算，但操作更简化。

2. **浮点数转换优化 (`IsFloat32ConvertedToFloat64`, `UndoFloat32ToFloat64Conversion`)**:
    *   检测 `float32` 到 `float64` 的转换，并在某些情况下撤销这种转换，可能因为后续操作不需要更高的精度。
    *   它还能识别可以安全地表示为 `float32` 的 `float64` 常量。

    **JavaScript 示例:**
    ```javascript
    let float32Value = 1.5;
    let float64Value = float32Value; // 隐式转换为 float64
    // 优化器可能会尝试识别并消除这种不必要的转换
    ```

3. **整数类型转换优化 (`IsWord32ConvertedToWord64`, `UndoWord32ToWord64Conversion`, `TryRemoveWord32ToWord64Conversion`)**:
    *   识别 32 位整数到 64 位整数的转换（包括符号扩展和零扩展）。
    *   在安全的情况下，撤销或移除这些转换，例如当后续操作只需要 32 位精度时。

    **JavaScript 示例:**
    ```javascript
    let int32Value = 10;
    let int64Value = int32Value; // 隐式转换为更大的类型
    // 优化器可能会在某些情况下避免实际执行 32 位到 64 位的转换
    ```

4. **位操作优化 (`ReduceWithTruncation`)**:
    *   在已知只有某些位会被观察到的情况下，简化位操作。
    *   可以移除与已知不会影响结果的掩码进行的按位与操作。
    *   可以优化连续的左移和右移操作。

    **代码逻辑推理 (假设输入与输出):**
    假设 `value` 是 `x & 0xFFFFFFFF`， `truncation_mask` 是 `0xFF`。由于只有低 8 位会被观察到，优化器可以将 `value` 简化为 `x & 0xFF`。

5. **除法优化 (`ReduceSignedDiv`, `ReduceUnsignedDiv`)**:
    *   针对除以常数的场景进行优化，将除法操作转换为更高效的乘法和移位操作（使用魔术数字）。
    *   处理除数为 0、1、-1 以及 2 的幂次等特殊情况。

    **JavaScript 示例:**
    ```javascript
    function divideByConstant(x) {
      return x / 7; // 编译器可能会将除以 7 优化为乘法和移位
    }
    ```

6. **分支条件优化 (`ReduceBranchCondition`)**:
    *   简化分支条件表达式，例如将 `x == 0` 转换为对 `x` 的真假性判断并翻转分支。
    *   识别并简化特定的位掩码操作。
    *   优化 `Select` (三元运算符) 操作。

    **JavaScript 示例:**
    ```javascript
    let x = 10;
    if (x == 0) { // 可以被优化
      console.log("x is zero");
    } else {
      console.log("x is not zero");
    }
    ```

7. **常量折叠 (`MapLoadCanBeConstantFolded`)**:
    *   判断加载对象 Map 的操作是否可以在编译时进行常量折叠。
    *   这对于稳定 Map 的对象（例如 HeapNumber）是安全的，但不适用于 Map 可能在 GC 期间改变的对象（例如 String）。

8. **辅助功能 (`IsBit`, `IsInt8`, `IsInt16`, `MatchBoolConstant`)**:
    *   提供了一些辅助函数，用于判断操作或值的类型和属性，以便进行后续的优化判断。

**关于 .tq 后缀:**

如果 `v8/src/compiler/turboshaft/machine-optimization-reducer.h` 以 `.tq` 结尾，那么它确实是一个 **V8 Torque 源代码** 文件。Torque 是一种用于编写 V8 内部代码的领域特定语言，它更安全、更易于维护。  然而，根据你提供的文件名（`.h`），它是一个 C++ 头文件，定义了类和接口。

**用户常见的编程错误示例:**

*   **不必要的类型转换:** 用户可能会在 JavaScript 中进行不必要的类型转换，例如将数字显式转换为字符串，然后再转换回数字。优化器可以消除这些冗余的转换。
*   **复杂的内存访问模式:**  编写复杂的数组或对象访问逻辑可能会导致低效的索引计算。优化器可以简化这些计算。
*   **低效的除法操作:** 在性能敏感的代码中，频繁地进行除法运算（特别是除以非常数）可能会影响性能。优化器可以将除以常数的操作转换为更快的形式。
*   **复杂的条件判断:** 编写过于复杂的 `if` 或其他条件语句可能会导致性能下降。优化器可以简化这些条件。

**总结归纳 (第 4 部分):**

`v8/src/compiler/turboshaft/machine-optimization-reducer.h` 定义了 `MachineOptimizationReducer` 类，它是 Turboshaft 编译管道中的一个关键组件。其核心职责是在机器码层面进行优化，通过分析和转换中间表示图中的操作，提高生成代码的效率。它涵盖了内存访问、类型转换、算术运算、逻辑运算以及常量折叠等多个方面的优化，旨在减少冗余计算，提升 V8 引擎的整体性能。 尽管提供的文件是 C++ 头文件，如果存在同名的 `.tq` 文件，那将是使用 Torque 语言实现的版本，用于更安全和可维护的 V8 内部代码开发。

### 提示词
```
这是目录为v8/src/compiler/turboshaft/machine-optimization-reducer.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/turboshaft/machine-optimization-reducer.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共4部分，请归纳一下它的功能
```

### 源代码
```c
ement_scale,
                                         &new_index)) {
      *index = __ IntPtrConstant(new_index);
      return true;
    }
    return false;
  }

  bool TryAdjustElementScale(uint8_t* element_scale, OpIndex maybe_constant) {
    uint64_t diff;
    if (!matcher_.MatchIntegralWordConstant(
            maybe_constant, WordRepresentation::WordPtr(), &diff)) {
      return false;
    }
    DCHECK_LT(*element_scale, WordRepresentation::WordPtr().bit_width());
    if (diff < (WordRepresentation::WordPtr().bit_width() -
                uint64_t{*element_scale})) {
      *element_scale += diff;
      return true;
    }
    return false;
  }

  // Fold away operations in the computation of `index` while preserving the
  // value of `(index << element_scale) + offset)` by updating `offset`,
  // `element_scale` and returning the updated `index`.
  // Return `OpIndex::Invalid()` if the resulting index is zero.
  OpIndex ReduceMemoryIndex(OpIndex index, int32_t* offset,
                            uint8_t* element_scale, bool tagged_base) {
    while (index.valid()) {
      const Operation& index_op = matcher_.Get(index);
      if (TryAdjustOffset(offset, index_op, *element_scale, tagged_base)) {
        index = OpIndex::Invalid();
        *element_scale = 0;
      } else if (TryAdjustIndex(*offset, &index, index_op, *element_scale)) {
        *element_scale = 0;
        *offset = 0;
        // This function cannot optimize the index further since at this point
        // it's just a WordPtrConstant.
        return index;
      } else if (const ShiftOp* shift_op = index_op.TryCast<ShiftOp>()) {
        if (shift_op->kind == ShiftOp::Kind::kShiftLeft &&
            TryAdjustElementScale(element_scale, shift_op->right())) {
          index = shift_op->left();
          continue;
        }
      } else if (const WordBinopOp* binary_op =
                     index_op.TryCast<WordBinopOp>()) {
        // TODO(jkummerow): This doesn't trigger for wasm32 memory operations
        // on 64-bit platforms, because `index_op` is a `Change` (from uint32
        // to uint64) in that case, and that Change's input is the addition
        // we're looking for. When we fix that, we must also teach the x64
        // instruction selector to support xchg with index *and* offset.
        if (binary_op->kind == WordBinopOp::Kind::kAdd &&
            TryAdjustOffset(offset, matcher_.Get(binary_op->right()),
                            *element_scale, tagged_base)) {
          index = binary_op->left();
          continue;
        }
      }
      break;
    }
    return index;
  }

  bool IsFloat32ConvertedToFloat64(OpIndex value) {
    if (OpIndex input;
        matcher_.MatchChange(value, &input, ChangeOp::Kind::kFloatConversion,
                             RegisterRepresentation::Float32(),
                             RegisterRepresentation::Float64())) {
      return true;
    }
    if (double c;
        matcher_.MatchFloat64Constant(value, &c) && DoubleToFloat32(c) == c) {
      return true;
    }
    return false;
  }

  OpIndex UndoFloat32ToFloat64Conversion(OpIndex value) {
    if (OpIndex input;
        matcher_.MatchChange(value, &input, ChangeOp::Kind::kFloatConversion,
                             RegisterRepresentation::Float32(),
                             RegisterRepresentation::Float64())) {
      return input;
    }
    if (double c;
        matcher_.MatchFloat64Constant(value, &c) && DoubleToFloat32(c) == c) {
      return __ Float32Constant(DoubleToFloat32(c));
    }
    UNREACHABLE();
  }

  bool IsBit(OpIndex value) { return matcher_.Is<ComparisonOp>(value); }

  bool IsInt8(OpIndex value) {
    if (auto* op = matcher_.TryCast<LoadOp>(value)) {
      return op->loaded_rep == MemoryRepresentation::Int8();
    } else if (auto* op = matcher_.TryCast<LoadOp>(value)) {
      return op->loaded_rep == MemoryRepresentation::Int8();
    }
    return false;
  }

  bool IsInt16(OpIndex value) {
    if (auto* op = matcher_.TryCast<LoadOp>(value)) {
      return op->loaded_rep == any_of(MemoryRepresentation::Int16(),
                                      MemoryRepresentation::Int8());
    } else if (auto* op = matcher_.TryCast<LoadOp>(value)) {
      return op->loaded_rep == any_of(MemoryRepresentation::Int16(),
                                      MemoryRepresentation::Int8());
    }
    return false;
  }

  bool IsWord32ConvertedToWord64(OpIndex value,
                                 std::optional<bool>* sign_extended = nullptr) {
    if (const ChangeOp* change_op = matcher_.TryCast<ChangeOp>(value)) {
      if (change_op->from == WordRepresentation::Word32() &&
          change_op->to == WordRepresentation::Word64()) {
        if (change_op->kind == ChangeOp::Kind::kSignExtend) {
          if (sign_extended) *sign_extended = true;
          return true;
        } else if (change_op->kind == ChangeOp::Kind::kZeroExtend) {
          if (sign_extended) *sign_extended = false;
          return true;
        }
      }
    }
    if (int64_t c; matcher_.MatchIntegralWord64Constant(value, &c) &&
                   c >= std::numeric_limits<int32_t>::min()) {
      if (c < 0) {
        if (sign_extended) *sign_extended = true;
        return true;
      } else if (c <= std::numeric_limits<int32_t>::max()) {
        // Sign- and zero-extension produce the same result.
        if (sign_extended) *sign_extended = {};
        return true;
      } else if (c <= std::numeric_limits<uint32_t>::max()) {
        if (sign_extended) *sign_extended = false;
        return true;
      }
    }
    return false;
  }

  V<Word32> UndoWord32ToWord64Conversion(V<Word> value) {
    DCHECK(IsWord32ConvertedToWord64(value));
    if (const ChangeOp* op = matcher_.TryCast<ChangeOp>(value)) {
      return V<Word32>::Cast(op->input());
    }
    return __ Word32Constant(matcher_.Cast<ConstantOp>(value).word32());
  }

  V<Word> TryRemoveWord32ToWord64Conversion(V<Word> value) {
    if (const ChangeOp* op = matcher_.TryCast<ChangeOp>(value)) {
      if (op->from == WordRepresentation::Word32() &&
          op->to == WordRepresentation::Word64() &&
          op->kind == any_of(ChangeOp::Kind::kZeroExtend,
                             ChangeOp::Kind::kSignExtend)) {
        return V<Word32>::Cast(op->input());
      }
    }
    return value;
  }

  uint64_t TruncateWord(uint64_t value, WordRepresentation rep) {
    if (rep == WordRepresentation::Word32()) {
      return static_cast<uint32_t>(value);
    } else {
      DCHECK_EQ(rep, WordRepresentation::Word64());
      return value;
    }
  }

  // Reduce the given value under the assumption that only the bits set in
  // `truncation_mask` will be observed.
  V<Word> ReduceWithTruncation(V<Word> value, uint64_t truncation_mask,
                               WordRepresentation rep) {
    {  // Remove bitwise-and with a mask whose zero-bits are not observed.
      V<Word> input, mask;
      uint64_t mask_value;
      if (matcher_.MatchBitwiseAnd(value, &input, &mask, rep) &&
          matcher_.MatchIntegralWordConstant(mask, rep, &mask_value)) {
        if ((mask_value & truncation_mask) == truncation_mask) {
          return ReduceWithTruncation(input, truncation_mask, rep);
        }
      }
    }
    {
      int left_shift_amount;
      int right_shift_amount;
      WordRepresentation rep;
      V<Word> left_shift;
      ShiftOp::Kind right_shift_kind;
      V<Word> left_shift_input;
      if (matcher_.MatchConstantShift(value, &left_shift, &right_shift_kind,
                                      &rep, &right_shift_amount) &&
          ShiftOp::IsRightShift(right_shift_kind) &&
          matcher_.MatchConstantShift(left_shift, &left_shift_input,
                                      ShiftOp::Kind::kShiftLeft, rep,
                                      &left_shift_amount) &&
          ((rep.MaxUnsignedValue() >> right_shift_amount) & truncation_mask) ==
              truncation_mask) {
        if (left_shift_amount == right_shift_amount) {
          return left_shift_input;
        } else if (left_shift_amount < right_shift_amount) {
          OpIndex shift_amount =
              __ WordConstant(right_shift_amount - left_shift_amount, rep);
          return __ Shift(left_shift_input, shift_amount, right_shift_kind,
                          rep);
        } else if (left_shift_amount > right_shift_amount) {
          OpIndex shift_amount =
              __ WordConstant(left_shift_amount - right_shift_amount, rep);
          return __ Shift(left_shift_input, shift_amount,
                          ShiftOp::Kind::kShiftLeft, rep);
        }
      }
    }
    return value;
  }

  OpIndex ReduceSignedDiv(OpIndex left, int64_t right, WordRepresentation rep) {
    // left / -1 => 0 - left
    if (right == -1) {
      return __ WordSub(__ WordConstant(0, rep), left, rep);
    }
    // left / 0 => 0
    if (right == 0) {
      return __ WordConstant(0, rep);
    }
    // left / 1 => left
    if (right == 1) {
      return left;
    }
    // left / MinSignedValue  =>  left == MinSignedValue
    if (right == rep.MinSignedValue()) {
      OpIndex equal_op = __ Equal(left, __ WordConstant(right, rep), rep);
      return rep == WordRepresentation::Word64()
                 ? __ ChangeUint32ToUint64(equal_op)
                 : equal_op;
    }
    // left / -right  => -(left / right)
    if (right < 0) {
      DCHECK_NE(right, rep.MinSignedValue());
      return __ WordSub(__ WordConstant(0, rep),
                        ReduceSignedDiv(left, Abs(right), rep), rep);
    }

    OpIndex quotient = left;
    if (base::bits::IsPowerOfTwo(right)) {
      uint32_t shift = base::bits::WhichPowerOfTwo(right);
      DCHECK_GT(shift, 0);
      if (shift > 1) {
        quotient = __ ShiftRightArithmetic(quotient, rep.bit_width() - 1, rep);
      }
      quotient = __ ShiftRightLogical(quotient, rep.bit_width() - shift, rep);
      quotient = __ WordAdd(quotient, left, rep);
      quotient = __ ShiftRightArithmetic(quotient, shift, rep);
      return quotient;
    }
    DCHECK_GT(right, 0);
    // Compute the magic number for `right`, using a generic lambda to treat
    // 32- and 64-bit uniformly.
    auto LowerToMul = [this, left](auto right, WordRepresentation rep) {
      base::MagicNumbersForDivision<decltype(right)> magic =
          base::SignedDivisionByConstant(right);
      OpIndex quotient = __ IntMulOverflownBits(
          left, __ WordConstant(magic.multiplier, rep), rep);
      if (magic.multiplier < 0) {
        quotient = __ WordAdd(quotient, left, rep);
      }
      OpIndex sign_bit = __ ShiftRightLogical(left, rep.bit_width() - 1, rep);
      return __ WordAdd(__ ShiftRightArithmetic(quotient, magic.shift, rep),
                        sign_bit, rep);
    };
    if (rep == WordRepresentation::Word32()) {
      return LowerToMul(static_cast<int32_t>(right),
                        WordRepresentation::Word32());
    } else {
      DCHECK_EQ(rep, WordRepresentation::Word64());
      return LowerToMul(static_cast<int64_t>(right),
                        WordRepresentation::Word64());
    }
  }

  OpIndex ReduceUnsignedDiv(OpIndex left, uint64_t right,
                            WordRepresentation rep) {
    // left / 0 => 0
    if (right == 0) {
      return __ WordConstant(0, rep);
    }
    // left / 1 => left
    if (right == 1) {
      return left;
    }
    // left / 2^k  => left >> k
    if (base::bits::IsPowerOfTwo(right)) {
      return __ ShiftRightLogical(left, base::bits::WhichPowerOfTwo(right),
                                  rep);
    }
    DCHECK_GT(right, 0);
    // If `right` is even, we can avoid using the expensive fixup by
    // shifting `left` upfront.
    unsigned const shift = base::bits::CountTrailingZeros(right);
    left = __ ShiftRightLogical(left, shift, rep);
    right >>= shift;
    // Compute the magic number for `right`, using a generic lambda to treat
    // 32- and 64-bit uniformly.
    auto LowerToMul = [this, left, shift](auto right, WordRepresentation rep) {
      base::MagicNumbersForDivision<decltype(right)> const mag =
          base::UnsignedDivisionByConstant(right, shift);
      OpIndex quotient = __ UintMulOverflownBits(
          left, __ WordConstant(mag.multiplier, rep), rep);
      if (mag.add) {
        DCHECK_GE(mag.shift, 1);
        // quotient = (((left - quotient) >> 1) + quotient) >> (mag.shift -
        // 1)
        quotient = __ ShiftRightLogical(
            __ WordAdd(
                __ ShiftRightLogical(__ WordSub(left, quotient, rep), 1, rep),
                quotient, rep),
            mag.shift - 1, rep);
      } else {
        quotient = __ ShiftRightLogical(quotient, mag.shift, rep);
      }
      return quotient;
    };
    if (rep == WordRepresentation::Word32()) {
      return LowerToMul(static_cast<uint32_t>(right),
                        WordRepresentation::Word32());
    } else {
      DCHECK_EQ(rep, WordRepresentation::Word64());
      return LowerToMul(static_cast<uint64_t>(right),
                        WordRepresentation::Word64());
    }
  }

  std::optional<V<Word32>> ReduceBranchCondition(V<Word32> condition,
                                                 bool* negated) {
    // TODO(dmercadier): consider generalizing this function both Word32 and
    // Word64.
    bool reduced = false;
    while (true) {
      // x == 0  =>  x with flipped branches
      if (V<Word32> left, right;
          matcher_.MatchEqual(condition, &left, &right) &&
          matcher_.MatchZero(right)) {
        reduced = true;
        condition = left;
        *negated = !*negated;
        continue;
      }
      // x - y  =>  x == y with flipped branches
      if (V<Word32> left, right; matcher_.MatchWordSub(
              condition, &left, &right, WordRepresentation::Word32())) {
        reduced = true;
        condition = __ Word32Equal(left, right);
        *negated = !*negated;
        continue;
      }
      // x & (1 << k) == (1 << k)  =>  x & (1 << k)
      if (V<Word32> left, right;
          matcher_.MatchEqual(condition, &left, &right)) {
        V<Word32> x, mask;
        uint32_t k1, k2;
        if (matcher_.MatchBitwiseAnd(left, &x, &mask,
                                     WordRepresentation::Word32()) &&
            matcher_.MatchIntegralWord32Constant(mask, &k1) &&
            matcher_.MatchIntegralWord32Constant(right, &k2) && k1 == k2 &&
            base::bits::IsPowerOfTwo(k1)) {
          reduced = true;
          condition = left;
          continue;
        }
      }
      // (x >> k1) & k2   =>   x & (k2 << k1)
      {
        V<Word32> shift, k2_index, x;
        int k1_int;
        uint32_t k1, k2;
        if (matcher_.MatchBitwiseAnd(condition, &shift, &k2_index,
                                     WordRepresentation::Word32()) &&
            matcher_.MatchConstantRightShift(
                shift, &x, WordRepresentation::Word32(), &k1_int) &&
            matcher_.MatchIntegralWord32Constant(k2_index, &k2)) {
          k1 = static_cast<uint32_t>(k1_int);
          if (k1 <= base::bits::CountLeadingZeros(k2) &&
              (static_cast<uint64_t>(k2) << k1 <=
               std::numeric_limits<uint32_t>::max())) {
            return __ Word32BitwiseAnd(x, k2 << k1);
          }
        }
      }
      // Select(x, true, false) => x
      if (const SelectOp* select = matcher_.TryCast<SelectOp>(condition)) {
        auto left_val = MatchBoolConstant(select->vtrue());
        auto right_val = MatchBoolConstant(select->vfalse());
        if (left_val && right_val) {
          if (*left_val == *right_val) {
            // Select(x, v, v) => v
            return __ Word32Constant(*left_val);
          }
          if (*left_val == false) {
            // Select(x, false, true) => !x
            *negated = !*negated;
          }
          condition = select->cond();
          reduced = true;
          continue;
        }
      }
      break;
    }
    return reduced ? std::optional<V<Word32>>(condition) : std::nullopt;
  }

  std::optional<bool> MatchBoolConstant(OpIndex condition) {
    if (uint32_t value;
        matcher_.MatchIntegralWord32Constant(condition, &value)) {
      return value != 0;
    }
    return std::nullopt;
  }

  // Returns true if loading the map of an object with map {map} can be constant
  // folded and done at compile time or not. For instance, doing this for
  // strings is not safe, since the map of a string could change during a GC,
  // but doing this for a HeapNumber is always safe.
  bool MapLoadCanBeConstantFolded(OptionalMapRef map) {
    if (!map.has_value()) return false;

    if (map->IsJSObjectMap() && map->is_stable()) {
      broker->dependencies()->DependOnStableMap(*map);
      // For JS objects, this is only safe is the map is stable.
      return true;
    }

    if (map->instance_type() ==
        any_of(BIG_INT_BASE_TYPE, HEAP_NUMBER_TYPE, ODDBALL_TYPE)) {
      return true;
    }

    return false;
  }

  static constexpr bool IsNegativePowerOfTwo(int64_t x) {
    if (x >= 0) return false;
    if (x == std::numeric_limits<int64_t>::min()) return true;
    int64_t x_abs = -x;   // This can't overflow after the check above.
    DCHECK_GE(x_abs, 1);  // The subtraction below can't underflow.
    return (x_abs & (x_abs - 1)) == 0;
  }

  static constexpr uint16_t CountLeadingSignBits(int64_t c,
                                                 WordRepresentation rep) {
    return base::bits::CountLeadingSignBits(c) - (64 - rep.bit_width());
  }

  JSHeapBroker* broker = __ data() -> broker();
  const OperationMatcher& matcher_ = __ matcher();
#if V8_ENABLE_WEBASSEMBLY
  const bool signalling_nan_possible = __ data() -> is_wasm();
#else
  static constexpr bool signalling_nan_possible = false;
#endif  // V8_ENABLE_WEBASSEMBLY
};

#include "src/compiler/turboshaft/undef-assembler-macros.inc"

}  // namespace v8::internal::compiler::turboshaft

#endif  // V8_COMPILER_TURBOSHAFT_MACHINE_OPTIMIZATION_REDUCER_H_
```