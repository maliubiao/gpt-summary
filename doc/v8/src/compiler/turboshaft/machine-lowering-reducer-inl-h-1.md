Response:
The user wants me to analyze a C++ header file from the V8 JavaScript engine, specifically `v8/src/compiler/turboshaft/machine-lowering-reducer-inl.h`.

Here's a breakdown of the request and how I'll address it:

1. **List its functionalities:** I need to read through the provided C++ code and identify the main tasks and operations it performs. Keywords like `REDUCE`, function names (e.g., `ConvertUntaggedToJSPrimitive`, `ConvertJSPrimitiveToUntagged`), and the overall structure will be key.

2. **Check if it's Torque:** I need to examine the file extension. The prompt states that if it ends with `.tq`, it's a Torque file. Since the provided file is `.h`, it's *not* a Torque file.

3. **Relate to JavaScript and provide examples:**  If the code handles conversions between different data representations (like tagged/untagged values, SMI, HeapNumbers, etc.), it likely has a direct relationship with how JavaScript values are handled internally. I'll need to provide corresponding JavaScript examples to illustrate these concepts.

4. **Code logic inference with input/output:**  For functions performing conversions or transformations, I'll try to infer the input and output types and values based on the operations being performed (e.g., tagging/untagging, truncation). I'll provide hypothetical inputs and their corresponding outputs.

5. **Common programming errors:** I should consider what kind of errors developers might make when dealing with the concepts presented in the code, such as incorrect type assumptions, precision loss, or failing to handle edge cases like NaN.

6. **Summarize its functionality (Part 2 of 5):** Based on the analysis of the provided code snippet (which is just a portion of the file), I'll summarize its purpose within the broader context of machine code generation in V8. Since this is part 2, I need to focus on the functionality present in *this specific snippet*.

**Mental Walkthrough of the Code:**

- The code heavily uses macros like `REDUCE`, `IF`, `GOTO`, and `BIND`, indicating a code generation or compilation process.
- It deals with conversions between different internal representations of JavaScript values:
    - `ConvertUntaggedToJSPrimitiveOp`: Converts raw, untagged values into tagged JavaScript primitives (Smi, HeapNumber, Boolean, String).
    - `ConvertUntaggedToJSPrimitiveOrDeopt`: Similar to the above, but includes deoptimization paths for cases where the conversion cannot be done efficiently.
    - `ConvertJSPrimitiveToUntagged`: Converts tagged JavaScript primitives back to untagged values.
    - `ConvertJSPrimitiveToUntaggedOrDeopt`: Similar to the above, with deoptimization.
    - `TruncateJSPrimitiveToUntagged`:  Truncates JavaScript primitives to untagged integer representations.
    - `ConvertJSPrimitiveToObject`: Converts JavaScript primitives to their corresponding wrapper objects.
    - `NewConsString`: Creates a new ConsString (for string concatenation).
    - `NewArray`: Creates a new array.
- It handles different numeric types (Smi, HeapNumber, integers, floats) and string encodings.
- It uses concepts like tagging and untagging, which are core to V8's object representation.
- Deoptimization is a recurring theme, suggesting that the code is part of an optimized compilation pipeline.

**Constraint Checklist & Confidence Score:**

1. 列举一下它的功能? Yes.
2. 如果v8/src/compiler/turboshaft/machine-lowering-reducer-inl.h以.tq结尾，那它是个v8 torque源代码: Yes, I can confirm it's not a Torque file.
3. 如果它与javascript的功能有关系，请用javascript举例说明: Yes.
4. 如果有代码逻辑推理，请给出假设输入与输出: Yes.
5. 如果涉及用户常见的编程错误，请举例说明: Yes.
6. 这是第2部分，共5部分，请归纳一下它的功能: Yes, I will focus on the provided snippet.

Confidence Score: 5/5  I am confident I can address all aspects of the request based on the provided code snippet.

Strategizing complete. I will now proceed with generating the response.

好的，根据提供的代码片段，以下是`v8/src/compiler/turboshaft/machine-lowering-reducer-inl.h` 的部分功能归纳：

**功能归纳 (基于提供的代码片段):**

这段代码的主要功能是定义了一系列的 **归约 (Reduce)** 操作，用于在 Turboshaft 编译器中将高级的、与 JavaScript 语义相关的操作转换为更底层的、机器相关的操作。 这些归约操作主要集中在以下几个方面：

1. **JavaScript 值类型转换:**  代码包含了多种将 JavaScript 值在不同内部表示之间进行转换的逻辑，包括：
    * **将未标记的值转换为 JavaScript 原始类型 (Primitives):** 例如，将一个原始的 32 位或 64 位整数转换为 Smi (Small Integer)、HeapNumber（堆上的数字对象）、布尔值或字符串。
    * **将 JavaScript 原始类型转换为未标记的值:**  例如，将 Smi、Number (HeapNumber) 或 Boolean 转换为原始的 32 位或 64 位整数、浮点数或位。
    * **带 Deopt (Deoptimization) 的类型转换:**  这些操作在转换过程中会进行检查，如果无法安全地进行转换（例如，精度丢失、类型不匹配），则会触发反优化 (deoptimization)，回到解释执行。
    * **截断 (Truncate) JavaScript 原始类型为未标记的值:** 将 JavaScript 的 Number 或 BigInt 截断为底层的整数表示。

2. **JavaScript 对象操作:** 代码中包含了创建新的 JavaScript 对象的操作：
    * **创建 ConsString:** 用于连接字符串。
    * **创建 Array:** 用于创建新的数组。

3. **JavaScript 值的判断:**  提供了一些辅助函数，用于判断 JavaScript 值的类型，例如 `JSAnyIsNotPrimitiveHeapObject` 用于判断一个值是否是非原始类型的堆对象。

4. **处理 JavaScript 对象的类型转换 (ToObject):**  `ConvertJSPrimitiveToObject` 函数将 JavaScript 的原始值（null 或 undefined 除外）转换为对应的包装对象。

**关于文件类型：**

根据您的描述，`v8/src/compiler/turboshaft/machine-lowering-reducer-inl.h` 的文件名以 `.h` 结尾，这表明它是一个 C++ 头文件，而不是 Torque 源代码文件（Torque 文件的扩展名是 `.tq`）。

**与 JavaScript 功能的关联及示例：**

这段代码直接关系到 JavaScript 引擎如何执行 JavaScript 代码。它处理了 JavaScript 运行时值的内部表示转换，这是引擎执行各种 JavaScript 操作的基础。

**示例 1: `ConvertUntaggedToJSPrimitiveOp` (将未标记的值转换为 JavaScript 原始类型)**

假设我们有一个未标记的 32 位整数值 `100`，我们想在 JavaScript 中将其用作一个数字。`ConvertUntaggedToJSPrimitiveOp` 的 `kSmi` 分支就负责处理这种情况：

```c++
      case ConvertUntaggedToJSPrimitiveOp::JSPrimitiveKind::kSmi: {
        DCHECK_EQ(input_rep, RegisterRepresentation::Word32());
        DCHECK_EQ(input_interpretation,
                  ConvertUntaggedToJSPrimitiveOp::InputInterpretation::kSigned);
        return __ TagSmi(V<Word32>::Cast(input));
      }
```

在 JavaScript 中，这对应于：

```javascript
let rawValue = 100; // 假设这是引擎内部的未标记值
let jsValue = rawValue; // JavaScript 引擎会将其转换为 Smi
console.log(jsValue); // 输出 100
console.log(typeof jsValue); // 输出 "number"
```

**示例 2: `ConvertJSPrimitiveToUntaggedOrDeopt` (带 Deopt 的 JavaScript 原始类型到未标记值的转换)**

考虑将一个 JavaScript 数字转换为 32 位整数，如果数字过大或不是整数，则需要进行反优化：

```c++
      case ConvertJSPrimitiveToUntaggedOrDeoptOp::UntaggedKind::kInt32: {
        if (from_kind ==
            ConvertJSPrimitiveToUntaggedOrDeoptOp::JSPrimitiveKind::kSmi) {
          __ DeoptimizeIfNot(__ ObjectIsSmi(object), frame_state,
                             DeoptimizeReason::kNotASmi, feedback);
          return __ UntagSmi(V<Smi>::Cast(object));
        } else {
          // ... (处理 HeapNumber 的情况) ...
        }
      }
```

在 JavaScript 中，这可能发生在使用位运算符或 `parseInt` 等函数时：

```javascript
function foo(x) {
  return x | 0; // 将 x 转换为 32 位整数
}

console.log(foo(10));     // 输出 10
console.log(foo(2**31));  // 可能触发 deopt，因为超过了有符号 32 位整数的范围
console.log(foo(10.5));   // 输出 10
```

**代码逻辑推理示例：**

**假设输入:**

在 `ConvertUntaggedToJSPrimitiveOp` 的 `kBoolean` 分支中，`input` 是一个 `RegisterRepresentation::Word32()` 类型的未标记值。

* **输入 1:** `input` 的值为 `1`
* **输入 2:** `input` 的值为 `0`

**代码逻辑:**

```c++
      case ConvertUntaggedToJSPrimitiveOp::JSPrimitiveKind::kBoolean: {
        DCHECK_EQ(input_rep, RegisterRepresentation::Word32());
        DCHECK_EQ(input_interpretation,
                  ConvertUntaggedToJSPrimitiveOp::InputInterpretation::kSigned);
        Label<Boolean> done(this);

        IF (V<Word32>::Cast(input)) {
          GOTO(done, __ HeapConstant(factory_->true_value()));
        } ELSE {
          GOTO(done, __ HeapConstant(factory_->false_value()));
        }

        BIND(done, result);
        return result;
      }
```

**输出:**

* **输出 1:**  `__ HeapConstant(factory_->true_value())` (JavaScript 的 `true` 值)
* **输出 2:**  `__ HeapConstant(factory_->false_value())` (JavaScript 的 `false` 值)

**用户常见的编程错误示例：**

当 JavaScript 开发者不理解内部类型转换的机制时，可能会犯一些错误。例如：

1. **误认为所有数字都是整数:**

   ```javascript
   function processNumber(n) {
     // 假设 n 总是整数
     let result = n | 0; // 尝试转换为 32 位整数
     console.log(result);
   }

   processNumber(10.7); // 输出 10，可能不是期望的结果
   ```
   这段代码没有考虑到 `n` 可能是浮点数，使用位运算符会进行截断，导致精度丢失。

2. **依赖不精确的类型判断:**

   ```javascript
   function checkType(value) {
     if (typeof value === 'number') {
       console.log("It's a number!");
     }
   }

   checkType(NaN); // 输出 "It's a number!"，但 NaN 的特殊性可能需要特别处理
   ```
   `typeof NaN` 返回 `"number"`，但 `NaN` 在数值运算中具有特殊的行为，开发者可能需要使用 `isNaN()` 进行更精确的判断。

3. **忽视类型转换带来的性能影响:**

   频繁地在不同类型之间进行转换，尤其是在热点代码中，可能会导致性能下降，甚至触发反优化。理解 V8 的内部类型表示和转换机制有助于编写更高效的 JavaScript 代码。

**总结这段代码的功能（基于提供的片段）：**

总的来说，这段代码片段定义了 Turboshaft 编译器中用于 **降低 (Lowering)**  JavaScript 操作到机器指令级别的关键步骤。它专注于处理 JavaScript 值在不同表示形式之间的转换，包括原始类型和未标记的底层表示。同时，它也处理了诸如创建新字符串和数组等基本对象操作。  代码中大量出现的 `DeoptimizeIf` 和 `DeoptimizeIfNot` 表明，这是在优化编译的上下文中，需要在运行时根据实际情况进行类型检查和可能的反优化。这段代码是 V8 引擎将高级 JavaScript 代码高效地转换为机器码的重要组成部分。

### 提示词
```
这是目录为v8/src/compiler/turboshaft/machine-lowering-reducer-inl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/turboshaft/machine-lowering-reducer-inl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共5部分，请归纳一下它的功能
```

### 源代码
```c
if constexpr (SmiValuesAre32Bits()) {
            GOTO(done, __ TagSmi(v32));
          } else {
            TagSmiOrOverflow(v32, &outside_smi_range, &done);
          }

          if (BIND(outside_smi_range)) {
            GOTO(done, AllocateHeapNumber(input_f64));
          }

          BIND(done, result);
          return result;
        }
        UNREACHABLE();
        break;
      }
      case ConvertUntaggedToJSPrimitiveOp::JSPrimitiveKind::kHeapNumber: {
        DCHECK_EQ(input_rep, RegisterRepresentation::Float64());
        DCHECK_EQ(input_interpretation,
                  ConvertUntaggedToJSPrimitiveOp::InputInterpretation::kSigned);
        return AllocateHeapNumber(V<Float64>::Cast(input));
      }
      case ConvertUntaggedToJSPrimitiveOp::JSPrimitiveKind::
          kHeapNumberOrUndefined: {
        DCHECK_EQ(input_rep, RegisterRepresentation::Float64());
        V<Float64> input_f64 = V<Float64>::Cast(input);
        DCHECK_EQ(input_interpretation,
                  ConvertUntaggedToJSPrimitiveOp::InputInterpretation::kSigned);
        Label<Union<HeapNumber, Undefined>> done(this);
        Label<> allocate_heap_number(this);

        // First check whether {input} is a NaN at all...
        IF (UNLIKELY(__ Float64IsNaN(input_f64))) {
          // ...and only if {input} is a NaN, perform the expensive signaling
          // NaN bit check. See http://crbug.com/v8/8264 for details.
          GOTO_IF_NOT(__ Word32Equal(__ Float64ExtractHighWord32(input_f64),
                                     kHoleNanUpper32),
                      allocate_heap_number);
          GOTO(done, __ HeapConstant(factory_->undefined_value()));
        } ELSE {
          GOTO(allocate_heap_number);
        }

        if (BIND(allocate_heap_number)) {
          GOTO(done, AllocateHeapNumber(input_f64));
        }

        BIND(done, result);
        return result;
      }
      case ConvertUntaggedToJSPrimitiveOp::JSPrimitiveKind::kSmi: {
        DCHECK_EQ(input_rep, RegisterRepresentation::Word32());
        DCHECK_EQ(input_interpretation,
                  ConvertUntaggedToJSPrimitiveOp::InputInterpretation::kSigned);
        return __ TagSmi(V<Word32>::Cast(input));
      }
      case ConvertUntaggedToJSPrimitiveOp::JSPrimitiveKind::kBoolean: {
        DCHECK_EQ(input_rep, RegisterRepresentation::Word32());
        DCHECK_EQ(input_interpretation,
                  ConvertUntaggedToJSPrimitiveOp::InputInterpretation::kSigned);
        Label<Boolean> done(this);

        IF (V<Word32>::Cast(input)) {
          GOTO(done, __ HeapConstant(factory_->true_value()));
        } ELSE {
          GOTO(done, __ HeapConstant(factory_->false_value()));
        }

        BIND(done, result);
        return result;
      }
      case ConvertUntaggedToJSPrimitiveOp::JSPrimitiveKind::kString: {
        DCHECK_EQ(input_rep, RegisterRepresentation::Word32());
        V<Word32> input_w32 = V<Word32>::Cast(input);

        switch (input_interpretation) {
          case ConvertUntaggedToJSPrimitiveOp::InputInterpretation::kCharCode:
            return StringFromSingleCharCode(
                __ Word32BitwiseAnd(input_w32, 0xFFFF));
          case ConvertUntaggedToJSPrimitiveOp::InputInterpretation::
              kCodePoint: {
            return StringFromSingleCodePoint(input_w32, UnicodeEncoding::UTF32);
          }
          default:
            UNREACHABLE();
        }
      }
    }

    UNREACHABLE();
  }

  V<JSPrimitive> REDUCE(ConvertUntaggedToJSPrimitiveOrDeopt)(
      V<Untagged> input, V<FrameState> frame_state,
      ConvertUntaggedToJSPrimitiveOrDeoptOp::JSPrimitiveKind kind,
      RegisterRepresentation input_rep,
      ConvertUntaggedToJSPrimitiveOrDeoptOp::InputInterpretation
          input_interpretation,
      const FeedbackSource& feedback) {
    DCHECK_EQ(kind,
              ConvertUntaggedToJSPrimitiveOrDeoptOp::JSPrimitiveKind::kSmi);
    if (input_rep == RegisterRepresentation::Word32()) {
      V<Word32> input_w32 = V<Word32>::Cast(input);
      if (input_interpretation ==
          ConvertUntaggedToJSPrimitiveOrDeoptOp::InputInterpretation::kSigned) {
        if constexpr (SmiValuesAre32Bits()) {
          return __ TagSmi(input_w32);
        } else {
          V<Tuple<Word32, Word32>> test =
              __ Int32AddCheckOverflow(input_w32, input_w32);
          __ DeoptimizeIf(__ template Projection<1>(test), frame_state,
                          DeoptimizeReason::kLostPrecision, feedback);
          return __ BitcastWord32ToSmi(__ template Projection<0>(test));
        }
      } else {
        DCHECK_EQ(input_interpretation, ConvertUntaggedToJSPrimitiveOrDeoptOp::
                                            InputInterpretation::kUnsigned);
        V<Word32> check = __ Uint32LessThanOrEqual(input_w32, Smi::kMaxValue);
        __ DeoptimizeIfNot(check, frame_state, DeoptimizeReason::kLostPrecision,
                           feedback);
        return __ TagSmi(input_w32);
      }
    } else {
      DCHECK_EQ(input_rep, RegisterRepresentation::Word64());
      V<Word64> input_w64 = V<Word64>::Cast(input);
      if (input_interpretation ==
          ConvertUntaggedToJSPrimitiveOrDeoptOp::InputInterpretation::kSigned) {
        V<Word32> i32 = __ TruncateWord64ToWord32(input_w64);
        V<Word32> check = __ Word64Equal(__ ChangeInt32ToInt64(i32), input_w64);
        __ DeoptimizeIfNot(check, frame_state, DeoptimizeReason::kLostPrecision,
                           feedback);
        if constexpr (SmiValuesAre32Bits()) {
          return __ TagSmi(i32);
        } else {
          V<Tuple<Word32, Word32>> test = __ Int32AddCheckOverflow(i32, i32);
          __ DeoptimizeIf(__ template Projection<1>(test), frame_state,
                          DeoptimizeReason::kLostPrecision, feedback);
          return __ BitcastWord32ToSmi(__ template Projection<0>(test));
        }
      } else {
        DCHECK_EQ(input_interpretation, ConvertUntaggedToJSPrimitiveOrDeoptOp::
                                            InputInterpretation::kUnsigned);
        V<Word32> check = __ Uint64LessThanOrEqual(
            input_w64, static_cast<uint64_t>(Smi::kMaxValue));
        __ DeoptimizeIfNot(check, frame_state, DeoptimizeReason::kLostPrecision,
                           feedback);
        return __ TagSmi(__ TruncateWord64ToWord32(input_w64));
      }
    }

    UNREACHABLE();
  }

  V<Untagged> REDUCE(ConvertJSPrimitiveToUntagged)(
      V<JSPrimitive> object, ConvertJSPrimitiveToUntaggedOp::UntaggedKind kind,
      ConvertJSPrimitiveToUntaggedOp::InputAssumptions input_assumptions) {
    switch (kind) {
      case ConvertJSPrimitiveToUntaggedOp::UntaggedKind::kInt32:
        if (input_assumptions ==
            ConvertJSPrimitiveToUntaggedOp::InputAssumptions::kSmi) {
          return __ UntagSmi(V<Smi>::Cast(object));
        } else if (input_assumptions ==
                   ConvertJSPrimitiveToUntaggedOp::InputAssumptions::
                       kNumberOrOddball) {
          Label<Word32> done(this);

          IF (LIKELY(__ ObjectIsSmi(object))) {
            GOTO(done, __ UntagSmi(V<Smi>::Cast(object)));
          } ELSE {
            V<Float64> value = __ template LoadField<Float64>(
                object, AccessBuilder::ForHeapNumberOrOddballOrHoleValue());
            GOTO(done, __ ReversibleFloat64ToInt32(value));
          }

          BIND(done, result);
          return result;
        } else {
          DCHECK_EQ(input_assumptions, ConvertJSPrimitiveToUntaggedOp::
                                           InputAssumptions::kPlainPrimitive);
          Label<Word32> done(this);
          GOTO_IF(LIKELY(__ ObjectIsSmi(object)), done,
                  __ UntagSmi(V<Smi>::Cast(object)));
          V<Number> number =
              __ ConvertPlainPrimitiveToNumber(V<PlainPrimitive>::Cast(object));
          GOTO_IF(__ ObjectIsSmi(number), done,
                  __ UntagSmi(V<Smi>::Cast(number)));
          V<Float64> f64 = __ LoadHeapNumberValue(V<HeapNumber>::Cast(number));
          GOTO(done, __ JSTruncateFloat64ToWord32(f64));
          BIND(done, result);
          return result;
        }
        UNREACHABLE();
      case ConvertJSPrimitiveToUntaggedOp::UntaggedKind::kInt64:
        if (input_assumptions ==
            ConvertJSPrimitiveToUntaggedOp::InputAssumptions::kSmi) {
          return __ ChangeInt32ToInt64(__ UntagSmi(V<Smi>::Cast(object)));
        } else {
          DCHECK_EQ(input_assumptions, ConvertJSPrimitiveToUntaggedOp::
                                           InputAssumptions::kNumberOrOddball);
          Label<Word64> done(this);

          IF (LIKELY(__ ObjectIsSmi(object))) {
            GOTO(done,
                 __ ChangeInt32ToInt64(__ UntagSmi(V<Smi>::Cast(object))));
          } ELSE {
            V<Float64> value = __ template LoadField<Float64>(
                object, AccessBuilder::ForHeapNumberOrOddballOrHoleValue());
            GOTO(done, __ ReversibleFloat64ToInt64(value));
          }

          BIND(done, result);
          return result;
        }
        UNREACHABLE();
      case ConvertJSPrimitiveToUntaggedOp::UntaggedKind::kUint32: {
        DCHECK_EQ(
            input_assumptions,
            ConvertJSPrimitiveToUntaggedOp::InputAssumptions::kNumberOrOddball);
        Label<Word32> done(this);

        IF (LIKELY(__ ObjectIsSmi(object))) {
          GOTO(done, __ UntagSmi(V<Smi>::Cast(object)));
        } ELSE {
          V<Float64> value = __ template LoadField<Float64>(
              object, AccessBuilder::ForHeapNumberOrOddballOrHoleValue());
          GOTO(done, __ ReversibleFloat64ToUint32(value));
        }

        BIND(done, result);
        return result;
      }
      case ConvertJSPrimitiveToUntaggedOp::UntaggedKind::kBit:
        DCHECK_EQ(input_assumptions,
                  ConvertJSPrimitiveToUntaggedOp::InputAssumptions::kBoolean);
        return __ TaggedEqual(object, __ HeapConstant(factory_->true_value()));
      case ConvertJSPrimitiveToUntaggedOp::UntaggedKind::kFloat64: {
        if (input_assumptions == ConvertJSPrimitiveToUntaggedOp::
                                     InputAssumptions::kNumberOrOddball) {
          Label<Float64> done(this);

          IF (LIKELY(__ ObjectIsSmi(object))) {
            GOTO(done,
                 __ ChangeInt32ToFloat64(__ UntagSmi(V<Smi>::Cast(object))));
          } ELSE {
            V<Float64> value = __ template LoadField<Float64>(
                object, AccessBuilder::ForHeapNumberOrOddballOrHoleValue());
            GOTO(done, value);
          }

          BIND(done, result);
          return result;
        } else {
          DCHECK_EQ(input_assumptions, ConvertJSPrimitiveToUntaggedOp::
                                           InputAssumptions::kPlainPrimitive);
          Label<Float64> done(this);
          GOTO_IF(LIKELY(__ ObjectIsSmi(object)), done,
                  __ ChangeInt32ToFloat64(__ UntagSmi(V<Smi>::Cast(object))));
          V<Number> number =
              __ ConvertPlainPrimitiveToNumber(V<PlainPrimitive>::Cast(object));
          GOTO_IF(__ ObjectIsSmi(number), done,
                  __ ChangeInt32ToFloat64(__ UntagSmi(V<Smi>::Cast(number))));
          V<Float64> f64 = __ LoadHeapNumberValue(V<HeapNumber>::Cast(number));
          GOTO(done, f64);
          BIND(done, result);
          return result;
        }
      }
    }
    UNREACHABLE();
  }

  V<Untagged> REDUCE(ConvertJSPrimitiveToUntaggedOrDeopt)(
      V<Object> object, OpIndex frame_state,
      ConvertJSPrimitiveToUntaggedOrDeoptOp::JSPrimitiveKind from_kind,
      ConvertJSPrimitiveToUntaggedOrDeoptOp::UntaggedKind to_kind,
      CheckForMinusZeroMode minus_zero_mode, const FeedbackSource& feedback) {
    switch (to_kind) {
      case ConvertJSPrimitiveToUntaggedOrDeoptOp::UntaggedKind::kInt32: {
        if (from_kind ==
            ConvertJSPrimitiveToUntaggedOrDeoptOp::JSPrimitiveKind::kSmi) {
          __ DeoptimizeIfNot(__ ObjectIsSmi(object), frame_state,
                             DeoptimizeReason::kNotASmi, feedback);
          return __ UntagSmi(V<Smi>::Cast(object));
        } else {
          DCHECK_EQ(
              from_kind,
              ConvertJSPrimitiveToUntaggedOrDeoptOp::JSPrimitiveKind::kNumber);
          Label<Word32> done(this);

          IF (LIKELY(__ ObjectIsSmi(object))) {
            GOTO(done, __ UntagSmi(V<Smi>::Cast(object)));
          } ELSE {
            V<Map> map = __ LoadMapField(object);
            __ DeoptimizeIfNot(
                __ TaggedEqual(map,
                               __ HeapConstant(factory_->heap_number_map())),
                frame_state, DeoptimizeReason::kNotAHeapNumber, feedback);
            V<Float64> heap_number_value =
                __ LoadHeapNumberValue(V<HeapNumber>::Cast(object));

            GOTO(done,
                 __ ChangeFloat64ToInt32OrDeopt(heap_number_value, frame_state,
                                                minus_zero_mode, feedback));
          }

          BIND(done, result);
          return result;
        }
      }
      case ConvertJSPrimitiveToUntaggedOrDeoptOp::UntaggedKind::kInt64: {
        DCHECK_EQ(
            from_kind,
            ConvertJSPrimitiveToUntaggedOrDeoptOp::JSPrimitiveKind::kNumber);
        Label<Word64> done(this);

        IF (LIKELY(__ ObjectIsSmi(object))) {
          GOTO(done, __ ChangeInt32ToInt64(__ UntagSmi(V<Smi>::Cast(object))));
        } ELSE {
          V<Map> map = __ LoadMapField(object);
          __ DeoptimizeIfNot(
              __ TaggedEqual(map, __ HeapConstant(factory_->heap_number_map())),
              frame_state, DeoptimizeReason::kNotAHeapNumber, feedback);
          V<Float64> heap_number_value =
              __ LoadHeapNumberValue(V<HeapNumber>::Cast(object));
          GOTO(done,
               __ ChangeFloat64ToInt64OrDeopt(heap_number_value, frame_state,
                                              minus_zero_mode, feedback));
        }

        BIND(done, result);
        return result;
      }
      case ConvertJSPrimitiveToUntaggedOrDeoptOp::UntaggedKind::kFloat64: {
        Label<Float64> done(this);

        // In the Smi case, just convert to int32 and then float64.
        // Otherwise, check heap numberness and load the number.
        IF (__ ObjectIsSmi(object)) {
          GOTO(done,
               __ ChangeInt32ToFloat64(__ UntagSmi(V<Smi>::Cast(object))));
        } ELSE {
          GOTO(done, ConvertHeapObjectToFloat64OrDeopt(object, frame_state,
                                                       from_kind, feedback));
        }

        BIND(done, result);
        return result;
      }
      case ConvertJSPrimitiveToUntaggedOrDeoptOp::UntaggedKind::kArrayIndex: {
        DCHECK_EQ(from_kind, ConvertJSPrimitiveToUntaggedOrDeoptOp::
                                 JSPrimitiveKind::kNumberOrString);
        Label<WordPtr> done(this);

        IF (LIKELY(__ ObjectIsSmi(object))) {
          // In the Smi case, just convert to intptr_t.
          GOTO(done, __ ChangeInt32ToIntPtr(__ UntagSmi(V<Smi>::Cast(object))));
        } ELSE {
          V<Map> map = __ LoadMapField(object);
          IF (LIKELY(__ TaggedEqual(
                  map, __ HeapConstant(factory_->heap_number_map())))) {
            V<Float64> heap_number_value =
                __ LoadHeapNumberValue(V<HeapNumber>::Cast(object));
            // Perform Turbofan's "CheckedFloat64ToIndex"
            {
              if constexpr (Is64()) {
                V<Word64> i64 = __ TruncateFloat64ToInt64OverflowUndefined(
                    heap_number_value);
                // The TruncateKind above means there will be a precision loss
                // in case INT64_MAX input is passed, but that precision loss
                // would not be detected and would not lead to a deoptimization
                // from the first check. But in this case, we'll deopt anyway
                // because of the following checks.
                __ DeoptimizeIfNot(__ Float64Equal(__ ChangeInt64ToFloat64(i64),
                                                   heap_number_value),
                                   frame_state,
                                   DeoptimizeReason::kLostPrecisionOrNaN,
                                   feedback);
                __ DeoptimizeIfNot(
                    __ IntPtrLessThan(i64, kMaxSafeIntegerUint64), frame_state,
                    DeoptimizeReason::kNotAnArrayIndex, feedback);
                __ DeoptimizeIfNot(
                    __ IntPtrLessThan(-kMaxSafeIntegerUint64, i64), frame_state,
                    DeoptimizeReason::kNotAnArrayIndex, feedback);
                GOTO(done, i64);
              } else {
                V<Word32> i32 = __ TruncateFloat64ToInt32OverflowUndefined(
                    heap_number_value);
                __ DeoptimizeIfNot(__ Float64Equal(__ ChangeInt32ToFloat64(i32),
                                                   heap_number_value),
                                   frame_state,
                                   DeoptimizeReason::kLostPrecisionOrNaN,
                                   feedback);
                GOTO(done, i32);
              }
            }
          } ELSE {
#if V8_STATIC_ROOTS_BOOL
            V<Word32> is_string_map = __ Uint32LessThanOrEqual(
                __ TruncateWordPtrToWord32(__ BitcastHeapObjectToWordPtr(map)),
                __ Word32Constant(InstanceTypeChecker::kStringMapUpperBound));
#else
            V<Word32> instance_type = __ LoadInstanceTypeField(map);
            V<Word32> is_string_map =
                __ Uint32LessThan(instance_type, FIRST_NONSTRING_TYPE);
#endif
            __ DeoptimizeIfNot(is_string_map, frame_state,
                               DeoptimizeReason::kNotAString, feedback);

            // TODO(nicohartmann@): We might introduce a Turboshaft way for
            // constructing call descriptors.
            MachineSignature::Builder builder(__ graph_zone(), 1, 1);
            builder.AddReturn(MachineType::Int32());
            builder.AddParam(MachineType::TaggedPointer());
            auto desc = Linkage::GetSimplifiedCDescriptor(__ graph_zone(),
                                                          builder.Get());
            auto ts_desc = TSCallDescriptor::Create(
                desc, CanThrow::kNo, LazyDeoptOnThrow::kNo, __ graph_zone());
            OpIndex callee = __ ExternalConstant(
                ExternalReference::string_to_array_index_function());
            // NOTE: String::ToArrayIndex() currently returns int32_t.
            V<WordPtr> index = __ ChangeInt32ToIntPtr(
                V<Word32>::Cast(__ Call(callee, {object}, ts_desc)));
            __ DeoptimizeIf(__ WordPtrEqual(index, -1), frame_state,
                            DeoptimizeReason::kNotAnArrayIndex, feedback);
            GOTO(done, index);
          }
        }

        BIND(done, result);
        return result;
      }
    }
    UNREACHABLE();
  }

  V<Word> REDUCE(TruncateJSPrimitiveToUntagged)(
      V<JSPrimitive> object, TruncateJSPrimitiveToUntaggedOp::UntaggedKind kind,
      TruncateJSPrimitiveToUntaggedOp::InputAssumptions input_assumptions) {
    switch (kind) {
      case TruncateJSPrimitiveToUntaggedOp::UntaggedKind::kInt32: {
        DCHECK_EQ(input_assumptions, TruncateJSPrimitiveToUntaggedOp::
                                         InputAssumptions::kNumberOrOddball);
        Label<Word32> done(this);

        IF (LIKELY(__ ObjectIsSmi(object))) {
          GOTO(done, __ UntagSmi(V<Smi>::Cast(object)));
        } ELSE {
          V<Float64> number_value = __ template LoadField<Float64>(
              object, AccessBuilder::ForHeapNumberOrOddballOrHoleValue());
          GOTO(done, __ JSTruncateFloat64ToWord32(number_value));
        }

        BIND(done, result);
        return result;
      }
      case TruncateJSPrimitiveToUntaggedOp::UntaggedKind::kInt64: {
        DCHECK_EQ(input_assumptions,
                  TruncateJSPrimitiveToUntaggedOp::InputAssumptions::kBigInt);
        DCHECK(Is64());
        Label<Word64> done(this);

        V<Word32> bitfield = __ template LoadField<Word32>(
            object, AccessBuilder::ForBigIntBitfield());
        IF (__ Word32Equal(bitfield, 0)) {
          GOTO(done, 0);
        } ELSE {
          V<Word64> lsd = __ template LoadField<Word64>(
              object, AccessBuilder::ForBigIntLeastSignificantDigit64());
          V<Word32> sign =
              __ Word32BitwiseAnd(bitfield, BigInt::SignBits::kMask);
          IF (__ Word32Equal(sign, 1)) {
            GOTO(done, __ Word64Sub(0, lsd));
          }

          GOTO(done, lsd);
        }

        BIND(done, result);
        return result;
      }
      case TruncateJSPrimitiveToUntaggedOp::UntaggedKind::kBit: {
        Label<Word32> done(this);

        if (input_assumptions ==
            TruncateJSPrimitiveToUntaggedOp::InputAssumptions::kObject) {
          // Perform Smi check.
          IF (UNLIKELY(__ ObjectIsSmi(object))) {
            GOTO(done, __ Word32Equal(__ TaggedEqual(object, __ TagSmi(0)), 0));
          }

          // Otherwise fall through into HeapObject case.
        } else {
          DCHECK_EQ(
              input_assumptions,
              TruncateJSPrimitiveToUntaggedOp::InputAssumptions::kHeapObject);
        }

#if V8_STATIC_ROOTS_BOOL
        // Check if {object} is a falsey root or the true value.
        // Undefined is the first root, so it's the smallest possible pointer
        // value, which means we don't have to subtract it for the range check.
        ReadOnlyRoots roots(isolate_);
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
        V<Word32> object_as_word32 = __ TruncateWordPtrToWord32(
            __ BitcastHeapObjectToWordPtr(V<HeapObject>::Cast(object)));
        V<Word32> true_as_word32 =
            __ Word32Constant(StaticReadOnlyRoot::kTrueValue);
        GOTO_IF(__ Uint32LessThan(object_as_word32, true_as_word32), done, 0);
        GOTO_IF(__ Word32Equal(object_as_word32, true_as_word32), done, 1);
#else
        // Check if {object} is false.
        GOTO_IF(
            __ TaggedEqual(object, __ HeapConstant(factory_->false_value())),
            done, 0);

        // Check if {object} is true.
        GOTO_IF(__ TaggedEqual(object, __ HeapConstant(factory_->true_value())),
                done, 1);

        // Check if {object} is the empty string.
        GOTO_IF(
            __ TaggedEqual(object, __ HeapConstant(factory_->empty_string())),
            done, 0);

        // Only check null and undefined if we're not going to check the
        // undetectable bit.
        if (DependOnNoUndetectableObjectsProtector()) {
          // Check if {object} is the null value.
          GOTO_IF(
              __ TaggedEqual(object, __ HeapConstant(factory_->null_value())),
              done, 0);

          // Check if {object} is the undefined value.
          GOTO_IF(__ TaggedEqual(object,
                                 __ HeapConstant(factory_->undefined_value())),
                  done, 0);
        }
#endif

        // Load the map of {object}.
        V<Map> map = __ LoadMapField(object);

        if (!DependOnNoUndetectableObjectsProtector()) {
          // Check if the {object} is undetectable and immediately return false.
          V<Word32> bitfield = __ template LoadField<Word32>(
              map, AccessBuilder::ForMapBitField());
          GOTO_IF(__ Word32BitwiseAnd(bitfield,
                                      Map::Bits1::IsUndetectableBit::kMask),
                  done, 0);
        }

        // Check if {object} is a HeapNumber.
        IF (UNLIKELY(__ TaggedEqual(
                map, __ HeapConstant(factory_->heap_number_map())))) {
          // For HeapNumber {object}, just check that its value is not 0.0, -0.0
          // or NaN.
          V<Float64> number_value =
              __ LoadHeapNumberValue(V<HeapNumber>::Cast(object));
          GOTO(done, __ Float64LessThan(0.0, __ Float64Abs(number_value)));
        }

        // Check if {object} is a BigInt.
        IF (UNLIKELY(
                __ TaggedEqual(map, __ HeapConstant(factory_->bigint_map())))) {
          V<Word32> bitfield = __ template LoadField<Word32>(
              object, AccessBuilder::ForBigIntBitfield());
          GOTO(done, IsNonZero(__ Word32BitwiseAnd(bitfield,
                                                   BigInt::LengthBits::kMask)));
        }

        // All other values that reach here are true.
        GOTO(done, 1);

        BIND(done, result);
        return result;
      }
    }
    UNREACHABLE();
  }

  V<Word> REDUCE(TruncateJSPrimitiveToUntaggedOrDeopt)(
      V<JSPrimitive> input, V<FrameState> frame_state,
      TruncateJSPrimitiveToUntaggedOrDeoptOp::UntaggedKind kind,
      TruncateJSPrimitiveToUntaggedOrDeoptOp::InputRequirement
          input_requirement,
      const FeedbackSource& feedback) {
    DCHECK_EQ(kind,
              TruncateJSPrimitiveToUntaggedOrDeoptOp::UntaggedKind::kInt32);
    Label<Word32> done(this);
    // In the Smi case, just convert to int32.
    GOTO_IF(LIKELY(__ ObjectIsSmi(input)), done,
            __ UntagSmi(V<Smi>::Cast(input)));

    // Otherwise, check that it's a heap number or oddball and truncate the
    // value to int32.
    V<Float64> number_value = ConvertHeapObjectToFloat64OrDeopt(
        input, frame_state, input_requirement, feedback);
    GOTO(done, __ JSTruncateFloat64ToWord32(number_value));

    BIND(done, result);
    return result;
  }

  V<Word32> JSAnyIsNotPrimitiveHeapObject(V<Object> value,
                                          V<Map> value_map = OpIndex{}) {
    if (!value_map.valid()) {
      value_map = __ LoadMapField(value);
    }
#if V8_STATIC_ROOTS_BOOL
    // Assumes only primitive objects and JS_RECEIVER's are passed here. All
    // primitive object's maps are in RO space and are allocated before all
    // JS_RECEIVER maps. Thus primitive object maps have smaller (compressed)
    // addresses.
    return __ Uint32LessThan(
        InstanceTypeChecker::kNonJsReceiverMapLimit,
        __ TruncateWordPtrToWord32(__ BitcastHeapObjectToWordPtr(value_map)));
#else
    static_assert(LAST_TYPE == LAST_JS_RECEIVER_TYPE);
    V<Word32> value_instance_type = __ LoadInstanceTypeField(value_map);
    return __ Uint32LessThanOrEqual(FIRST_JS_RECEIVER_TYPE,
                                    value_instance_type);
#endif
  }

  V<Object> REDUCE(ConvertJSPrimitiveToObject)(V<JSPrimitive> value,
                                               V<Context> native_context,
                                               V<JSGlobalProxy> global_proxy,
                                               ConvertReceiverMode mode) {
    switch (mode) {
      case ConvertReceiverMode::kNullOrUndefined:
        return global_proxy;
      case ConvertReceiverMode::kNotNullOrUndefined:
      case ConvertReceiverMode::kAny: {
        Label<Object> done(this);

        // Check if {value} is already a JSReceiver (or null/undefined).
        Label<> convert_to_object(this);
        GOTO_IF(UNLIKELY(__ ObjectIsSmi(value)), convert_to_object);
        GOTO_IF_NOT(LIKELY(__ JSAnyIsNotPrimitiveHeapObject(value)),
                    convert_to_object);
        GOTO(done, value);

        // Wrap the primitive {value} into a JSPrimitiveWrapper.
        if (BIND(convert_to_object)) {
          if (mode != ConvertReceiverMode::kNotNullOrUndefined) {
            // Replace the {value} with the {global_proxy}.
            GOTO_IF(UNLIKELY(__ TaggedEqual(
                        value, __ HeapConstant(factory_->undefined_value()))),
                    done, global_proxy);
            GOTO_IF(UNLIKELY(__ TaggedEqual(
                        value, __ HeapConstant(factory_->null_value()))),
                    done, global_proxy);
          }
          GOTO(done, __ CallBuiltin_ToObject(isolate_, native_context, value));
        }

        BIND(done, result);
        return result;
      }
    }
    UNREACHABLE();
  }

  V<ConsString> REDUCE(NewConsString)(V<Word32> length, V<String> first,
                                      V<String> second) {
    // Determine the instance types of {first} and {second}.
    V<Map> first_map = __ LoadMapField(first);
    V<Word32> first_type = __ LoadInstanceTypeField(first_map);
    V<Map> second_map = __ LoadMapField(second);
    V<Word32> second_type = __ LoadInstanceTypeField(second_map);

    Label<Map> allocate_string(this);
    // Determine the proper map for the resulting ConsString.
    // If both {first} and {second} are one-byte strings, we
    // create a new ConsOneByteString, otherwise we create a
    // new ConsString instead.
    static_assert(kOneByteStringTag != 0);
    static_assert(kTwoByteStringTag == 0);
    V<Word32> instance_type = __ Word32BitwiseAnd(first_type, second_type);
    V<Word32> encoding =
        __ Word32BitwiseAnd(instance_type, kStringEncodingMask);
    IF (__ Word32Equal(encoding, kTwoByteStringTag)) {
      GOTO(allocate_string,
           __ HeapConstant(factory_->cons_two_byte_string_map()));
    } ELSE {
      GOTO(allocate_string,
           __ HeapConstant(factory_->cons_one_byte_string_map()));
    }

    // Allocate the resulting ConsString.
    BIND(allocate_string, map);
    auto string = __ template Allocate<ConsString>(
        __ IntPtrConstant(sizeof(ConsString)), AllocationType::kYoung);
    __ InitializeField(string, AccessBuilder::ForMap(), map);
    __ InitializeField(string, AccessBuilder::ForNameRawHashField(),
                       __ Word32Constant(Name::kEmptyHashField));
    __ InitializeField(string, AccessBuilder::ForStringLength(), length);
    __ InitializeField(string, AccessBuilder::ForConsStringFirst(), first);
    __ InitializeField(string, AccessBuilder::ForConsStringSecond(), second);
    return __ FinishInitialization(std::move(string));
  }

  OpIndex REDUCE(NewArray)(V<WordPtr> length, NewArrayOp::Kind kind,
                           AllocationType allocation_type) {
    Label<Object> done(this);

    GOTO_IF(__ WordPtrEqual(length, 0), done,
            __ HeapConstant(factory_->empty_fixed_array()));

    // Compute the effective size of the backing store.
    intptr_t size_log2;
    Handle<Map> array_map;
    // TODO(nicohartmann@): Replace ElementAccess by a Turboshaft replacement.
    ElementAccess access;
    V<Any> the_hole_value;
    switch (kind) {
      case NewArrayOp::Kind::kDouble: {
        size_log2 = kDoubleSizeLog2;
        array_map = factory_->fixed_double_array_map();
        access = {kTaggedBase, OFFSET_OF_DATA_START(FixedDoubleArray),
                  compiler::Type::NumberOrHole(), MachineType::Float64(),
                  kNoWriteBarrier};
        the_hole_value = __ template LoadField<Float64>(
            __ HeapConstant(factory_->the_hole_value()),
            AccessBuilder::ForHeapNumberOrOddballOrHoleValue());
        break;
      }
      case NewArrayOp::Kind::kObject: {
        size_log2 = kTaggedSizeLog2;
        array_map = factory_->fixed_array_map();
        access = {kTaggedBase, OFFSET_OF_DATA_START(FixedArray),
                  compiler::Type::Any(), MachineType::AnyTagged(),
                  kNoWriteBarrier};
        the_hole_value = __ HeapConstant(factory_->the_hole_value());
        break;
      }
    }
    V<WordPtr> size =
        __ WordPtrAdd(__ WordPtrShiftLeft(length, static_cast<int>(size_log2)),
                      access.header_size);

    // Allocate the result and initialize the header.
    auto uninitialized_array =
        __ template Allocate<FixedArray>(size, allocation_type);
    __ InitializeField(uninitialized_array, AccessBuilder::ForMap(),
                       __ HeapConstant(array_map));
    __ InitializeField(uninitialized_array,
                       AccessBuilder::ForFixedArrayLength(),
                       __ TagSmi(__ TruncateWordPtrToWord32(length)));
    // TODO(nicohartmann@): Should finish initialization only after all elements
    // have been initialized.
    auto array = __ FinishInitialization(std::move(uninitialized_array));
```