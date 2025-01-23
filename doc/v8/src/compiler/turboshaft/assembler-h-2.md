Response:
My thinking process to analyze the provided C++ code snippet went through these stages:

1. **Initial Scan and Keyword Recognition:** I quickly scanned the code looking for patterns and familiar C++ keywords. Keywords like `#define`, `#undef`, `DECL_*`, `ReduceIfReachable*`, `ConstantOp::Kind::k*`, and types like `Word32`, `Float64`, `Object`, `Smi` stood out. These immediately suggested macro-based code generation, function declarations, and operations related to different data types within the V8 engine.

2. **Identifying the Core Functionality:**  The repeated use of `DECL_*` macros strongly hinted at the code's purpose: defining a large set of functions (or methods) related to various operations. The names of these functions (e.g., `IntAddCheckOverflow`, `FloatAdd`, `ShiftLeft`, `Equal`, `FloatAbs`, `ConvertInt32ToNumber`) clearly indicate the types of operations being handled: arithmetic, bit manipulation, comparison, type conversion, etc.

3. **Dissecting the Macros:** I focused on the `DECL_*` macros, particularly `DECL_MULTI_REP_BINOP_V` and `DECL_SINGLE_REP_BINOP_V`. These seem to be the primary mechanism for defining binary operations. I observed the parameters they take: `name`, `operation`, `kind`, and `tag`. This suggested a pattern: a function name, an underlying operation type, a specific kind of that operation, and a data type. The `_V` suffix likely indicates the function returns a `V<tag>` object, hinting at a templated value representation.

4. **Understanding `ReduceIfReachable`:** The `ReduceIfReachable*` prefix in many function bodies is crucial. It strongly suggests an optimization or simplification phase within the Turboshaft compiler. The assembler isn't directly generating machine code; it's building an intermediate representation (IR) that can be further optimized. `ReduceIfReachable` likely checks if an operation can be simplified or directly represented by an existing node in the IR graph.

5. **Connecting to V8 Concepts:**  I started relating the observed patterns to my knowledge of the V8 engine:
    * **Turboshaft:** The file path `v8/src/compiler/turboshaft/assembler.h` confirms this is part of Turboshaft, V8's new optimizing compiler.
    * **Assembler (High-Level):**  This "assembler" isn't a traditional assembly code generator. It's a higher-level abstraction for constructing the IR.
    * **Representations (`rep`):** The `rep` parameters (e.g., `WordRepresentation`, `FloatRepresentation`, `RegisterRepresentation`) are fundamental in V8's compiler pipeline, specifying how values are represented in memory and registers.
    * **Tagged Values:** The presence of `Smi`, `HeapObject`, and functions like `TaggedEqual` points to V8's tagged value representation for JavaScript values.
    * **Optimizations:** The `ReduceIfReachable` calls and the various "check overflow" operations align with the goals of an optimizing compiler.

6. **Inferring Functionality:** Based on the identified patterns, I could infer the functionality of different sections:
    * **Arithmetic Operations:**  The `IntAddCheckOverflow`, `FloatAdd`, etc., functions perform arithmetic operations, with some including overflow checks.
    * **Bitwise Operations:** The `ShiftLeft`, `RotateRight`, and `WordReverseBytes` functions handle bitwise manipulations.
    * **Comparisons:** The `Equal`, `IntLessThan`, etc., functions perform comparisons between values.
    * **Type Conversions:** The `Convert*` functions handle conversions between different data types (e.g., number to string, object to boolean).
    * **Constants:** The `Word32Constant`, `Float64Constant`, `HeapConstant`, and `SmiConstant` functions create constant values of different types.
    * **Object Type Checks:** The `ObjectIs*` functions check the type of JavaScript objects.

7. **Addressing Specific Questions:** I then addressed the specific points in the prompt:
    * **File Extension:** The file ends in `.h`, so it's a C++ header file, not a Torque file.
    * **Relationship to JavaScript:**  Many operations directly correspond to JavaScript operations (addition, subtraction, type conversions, comparisons). I looked for straightforward examples.
    * **Code Logic and Assumptions:**  For the overflow checks and bitwise operations, I considered the inputs and outputs.
    * **Common Programming Errors:** I thought about errors related to integer overflow and type mismatches, which are relevant to the code's functionality.

8. **Summarization:** Finally, I synthesized the information into a concise summary of the file's purpose.

Essentially, my approach was to break down the code into smaller, manageable parts, identify recurring patterns, leverage my existing knowledge of V8, and then synthesize the findings to answer the specific questions in the prompt. The presence of macros was a major clue to the code's generative nature and purpose.
这是目录为 `v8/src/compiler/turboshaft/assembler.h` 的 V8 源代码的第三部分。根据前两部分和这部分的内容，我们可以归纳一下它的功能：

**归纳其功能：**

`v8/src/compiler/turboshaft/assembler.h` 定义了一个在 Turboshaft 编译器中使用的 **汇编器 (Assembler)** 类或相关的辅助工具。这个汇编器的作用是提供一组高级的接口，用于构建中间表示 (IR) 图，而不是直接生成机器码。它允许编译器开发者以一种更抽象的方式来描述代码的逻辑操作，这些操作随后会被 Turboshaft 的其他阶段进一步优化和最终编译成机器码。

**具体功能（基于提供的代码片段）：**

这部分代码主要关注定义了各种 **算术运算、位运算、比较运算和类型转换** 的接口，这些接口会被 Turboshaft 编译器用来构建 IR 图。  它使用大量的宏 (`DECL_MULTI_REP_BINOP_V`, `DECL_SINGLE_REP_BINOP_V`, 等) 来简化相似操作的定义，这些操作可能在不同的数据表示形式 (Representation) 上执行。

**详细功能点：**

* **二元算术运算:**  定义了各种整数和浮点数的加、减、乘、除等运算，包括带溢出检查的版本 (`IntAddCheckOverflow`) 和不带溢出检查的版本 (`IntAdd`). 支持不同的数据表示形式，例如 `Word` (机器字大小), `Word32`, `Word64`, `Float`, `Float32`, `Float64`。
* **浮点数特殊运算:**  定义了浮点数的 `Min`, `Max`, `Mod`, `Power`, `Atan2` 等特殊运算。
* **位运算:** 定义了各种移位操作 (`ShiftRightArithmetic`, `ShiftLeft`, `RotateRight`, `RotateLeft`)，并支持不同的字长 (`Word32`, `Word64`, `WordPtr`)。
* **比较运算:** 定义了相等性比较 (`Equal`, `TaggedEqual`, `RootEqual`) 和大小比较 (`IntLessThan`, `UintLessThan`, `FloatLessThan`)，同样支持不同的数据表示形式。
* **一元运算:** 定义了浮点数的绝对值、取反、舍入等运算 (`FloatAbs`, `FloatNegate`, `FloatRoundDown`)，以及字操作，例如字节反转 (`WordReverseBytes`)，计算前导零/尾随零 (`WordCountLeadingZeros`, `WordCountTrailingZeros`)，以及符号扩展 (`WordSignExtend8`, `WordSignExtend16`)。
* **带溢出检查的一元运算:** 定义了带溢出检查的一元运算，例如 `IntAbsCheckOverflow`。
* **带溢出检查并 deopt 的二元运算:**  定义了在运算溢出时触发去优化 (deoptimization) 的二元运算 (`WordBinopDeoptOnOverflow`)。
* **类型转换:** 定义了各种类型转换操作，包括原始类型之间的转换 (`BitcastWord32PairToFloat64`)，以及 JavaScript 对象类型之间的转换 (`TaggedBitcast`)，例如 Smi 和 Word32 之间的转换。
* **对象类型检查:**  定义了检查 JavaScript 对象类型的操作 (`ObjectIsArrayBufferView`, `ObjectIsSmi` 等)。
* **浮点数属性检查:** 定义了检查浮点数属性的操作 (`Float64IsNaN`, `Float64IsHole`, `Float64IsSmi`)。
* **数值类型检查:** 定义了检查对象是否为特定数值类型的操作 (`ObjectIsNumericValue`).
* **更高级的类型转换:** 定义了更高级的类型转换操作，例如将原始类型转换为 Number 或 Boolean (`ConvertPlainPrimitiveToNumber`, `ConvertToBoolean`)，以及字符串和数字之间的转换 (`ConvertNumberToString`, `ConvertStringToNumber`)。
* **Untagged 类型和 JSPrimitive 类型的转换:**  定义了 Untagged (未标记) 类型和 JSPrimitive (JavaScript 原始类型) 之间的转换操作，包括带 deopt 的版本。
* **常量创建:** 提供了创建各种类型常量的便捷方法，例如 `Word32Constant`, `Float64Constant`, `HeapConstant`, `SmiConstant`。

**关于文件类型和 JavaScript 关系：**

* `v8/src/compiler/turboshaft/assembler.h` 以 `.h` 结尾，这是一个标准的 C++ 头文件扩展名，**不是** Torque 源代码 (`.tq`)。
* 这个文件与 JavaScript 的功能有密切关系。这里定义的各种运算和类型转换，都直接对应了 JavaScript 语言中的操作。例如：
    * `IntAddCheckOverflow` 对应 JavaScript 中的 `+` 运算，可能在特定情况下触发溢出错误。
    * `Float64Add` 对应 JavaScript 中浮点数的加法。
    * `ObjectIsSmi` 对应 JavaScript 中检查一个值是否为小的整数 (Smi)。
    * `ConvertStringToNumber` 对应 JavaScript 中将字符串转换为数字的操作 (`Number("123")`)。

**JavaScript 示例：**

```javascript
let a = 10;
let b = 20;
let sum = a + b; // 对应 IntAddCheckOverflow 或类似的整数加法操作

let x = 3.14;
let y = 2.71;
let product = x * y; // 对应 Float64Mul 或类似的浮点数乘法操作

let str = "42";
let num = Number(str); // 对应 ConvertStringToNumber 操作

if (typeof a === 'number') { // 内部可能使用 ObjectIsNumber 或类似的检查
  // ...
}
```

**代码逻辑推理和假设输入/输出：**

以 `Int32AddCheckOverflow` 为例：

* **假设输入:** 两个 `ConstOrV<Word32>` 类型的参数 `left` 和 `right`，分别表示要相加的两个 32 位整数。
* **代码逻辑:** 调用 `ReduceIfReachableBinop`，传入 `resolve(left)`, `resolve(right)`, `OverflowCheckedBinop::Kind::kSignedAdd`, 和 `V<Word32>::rep`。  这表示在 IR 图中创建一个带溢出检查的 32 位有符号整数加法节点。
* **输出:** 一个 `V<Word32>` 类型的对象，代表 IR 图中的加法运算结果。  如果实际执行时发生溢出，Turboshaft 的后续阶段会处理这种情况（例如，抛出异常或进行去优化）。

**用户常见的编程错误：**

* **整数溢出:** 在 JavaScript 中，整数溢出可能会导致意外的结果，因为 JavaScript 的数字类型是双精度浮点数。但在 V8 内部，进行整数运算时仍然需要处理溢出的情况。 例如：
    ```javascript
    let maxInt = 2147483647;
    let result = maxInt + 1; // 在 V8 内部的整数运算中可能会触发溢出检查
    ```
* **类型错误:**  对类型不兼容的值进行运算会导致错误。例如，尝试将一个字符串和一个数字相加，V8 会尝试进行类型转换。
    ```javascript
    let num = 10;
    let str = "hello";
    let result = num + str; // V8 内部会进行类型转换操作
    ```
* **浮点数精度问题:** 浮点数运算可能存在精度问题。
    ```javascript
    let a = 0.1;
    let b = 0.2;
    let sum = a + b; // sum 的值可能不是精确的 0.3
    ```

总而言之，这个代码片段是 V8 Turboshaft 编译器中定义基本运算和类型转换接口的关键部分，它为后续的优化和代码生成奠定了基础，并且与 JavaScript 的语义紧密相关。

### 提示词
```
这是目录为v8/src/compiler/turboshaft/assembler.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/turboshaft/assembler.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共8部分，请归纳一下它的功能
```

### 源代码
```c
turn ReduceIfReachable##operation(resolve(left), resolve(right), \
                                        operation##Op::Kind::k##kind,  \
                                        V<tag>::rep);                  \
  }
  DECL_MULTI_REP_CHECK_BINOP_V(IntAddCheckOverflow, OverflowCheckedBinop,
                               SignedAdd, Word)
  DECL_SINGLE_REP_CHECK_BINOP_V(Int32AddCheckOverflow, OverflowCheckedBinop,
                                SignedAdd, Word32)
  DECL_SINGLE_REP_CHECK_BINOP_V(Int64AddCheckOverflow, OverflowCheckedBinop,
                                SignedAdd, Word64)
  DECL_MULTI_REP_CHECK_BINOP_V(IntSubCheckOverflow, OverflowCheckedBinop,
                               SignedSub, Word)
  DECL_SINGLE_REP_CHECK_BINOP_V(Int32SubCheckOverflow, OverflowCheckedBinop,
                                SignedSub, Word32)
  DECL_SINGLE_REP_CHECK_BINOP_V(Int64SubCheckOverflow, OverflowCheckedBinop,
                                SignedSub, Word64)
  DECL_MULTI_REP_CHECK_BINOP_V(IntMulCheckOverflow, OverflowCheckedBinop,
                               SignedMul, Word)
  DECL_SINGLE_REP_CHECK_BINOP_V(Int32MulCheckOverflow, OverflowCheckedBinop,
                                SignedMul, Word32)
  DECL_SINGLE_REP_CHECK_BINOP_V(Int64MulCheckOverflow, OverflowCheckedBinop,
                                SignedMul, Word64)
#undef DECL_MULTI_REP_CHECK_BINOP_V
#undef DECL_SINGLE_REP_CHECK_BINOP_V

  DECL_MULTI_REP_BINOP_V(FloatAdd, FloatBinop, Add, Float)
  DECL_SINGLE_REP_BINOP_V(Float32Add, FloatBinop, Add, Float32)
  DECL_SINGLE_REP_BINOP_V(Float64Add, FloatBinop, Add, Float64)
  DECL_MULTI_REP_BINOP_V(FloatMul, FloatBinop, Mul, Float)
  DECL_SINGLE_REP_BINOP_V(Float32Mul, FloatBinop, Mul, Float32)
  DECL_SINGLE_REP_BINOP_V(Float64Mul, FloatBinop, Mul, Float64)
  DECL_MULTI_REP_BINOP_V(FloatSub, FloatBinop, Sub, Float)
  DECL_SINGLE_REP_BINOP_V(Float32Sub, FloatBinop, Sub, Float32)
  DECL_SINGLE_REP_BINOP_V(Float64Sub, FloatBinop, Sub, Float64)
  DECL_MULTI_REP_BINOP_V(FloatDiv, FloatBinop, Div, Float)
  DECL_SINGLE_REP_BINOP_V(Float32Div, FloatBinop, Div, Float32)
  DECL_SINGLE_REP_BINOP_V(Float64Div, FloatBinop, Div, Float64)
  DECL_MULTI_REP_BINOP_V(FloatMin, FloatBinop, Min, Float)
  DECL_SINGLE_REP_BINOP_V(Float32Min, FloatBinop, Min, Float32)
  DECL_SINGLE_REP_BINOP_V(Float64Min, FloatBinop, Min, Float64)
  DECL_MULTI_REP_BINOP_V(FloatMax, FloatBinop, Max, Float)
  DECL_SINGLE_REP_BINOP_V(Float32Max, FloatBinop, Max, Float32)
  DECL_SINGLE_REP_BINOP_V(Float64Max, FloatBinop, Max, Float64)
  DECL_SINGLE_REP_BINOP_V(Float64Mod, FloatBinop, Mod, Float64)
  DECL_SINGLE_REP_BINOP_V(Float64Power, FloatBinop, Power, Float64)
  DECL_SINGLE_REP_BINOP_V(Float64Atan2, FloatBinop, Atan2, Float64)

  OpIndex Shift(OpIndex left, OpIndex right, ShiftOp::Kind kind,
                WordRepresentation rep) {
    return ReduceIfReachableShift(left, right, kind, rep);
  }

#define DECL_SINGLE_REP_SHIFT_V(name, kind, tag)                        \
  V<tag> name(ConstOrV<tag> left, ConstOrV<Word32> right) {             \
    return ReduceIfReachableShift(resolve(left), resolve(right),        \
                                  ShiftOp::Kind::k##kind, V<tag>::rep); \
  }

  DECL_MULTI_REP_BINOP(ShiftRightArithmeticShiftOutZeros, Shift,
                       WordRepresentation, ShiftRightArithmeticShiftOutZeros)
  DECL_SINGLE_REP_SHIFT_V(Word32ShiftRightArithmeticShiftOutZeros,
                          ShiftRightArithmeticShiftOutZeros, Word32)
  DECL_SINGLE_REP_SHIFT_V(Word64ShiftRightArithmeticShiftOutZeros,
                          ShiftRightArithmeticShiftOutZeros, Word64)
  DECL_SINGLE_REP_SHIFT_V(WordPtrShiftRightArithmeticShiftOutZeros,
                          ShiftRightArithmeticShiftOutZeros, WordPtr)
  DECL_MULTI_REP_BINOP(ShiftRightArithmetic, Shift, WordRepresentation,
                       ShiftRightArithmetic)
  DECL_SINGLE_REP_SHIFT_V(Word32ShiftRightArithmetic, ShiftRightArithmetic,
                          Word32)
  DECL_SINGLE_REP_SHIFT_V(Word64ShiftRightArithmetic, ShiftRightArithmetic,
                          Word64)
  DECL_SINGLE_REP_SHIFT_V(WordPtrShiftRightArithmetic, ShiftRightArithmetic,
                          WordPtr)
  DECL_MULTI_REP_BINOP(ShiftRightLogical, Shift, WordRepresentation,
                       ShiftRightLogical)
  DECL_SINGLE_REP_SHIFT_V(Word32ShiftRightLogical, ShiftRightLogical, Word32)
  DECL_SINGLE_REP_SHIFT_V(Word64ShiftRightLogical, ShiftRightLogical, Word64)
  DECL_SINGLE_REP_SHIFT_V(WordPtrShiftRightLogical, ShiftRightLogical, WordPtr)
  DECL_MULTI_REP_BINOP(ShiftLeft, Shift, WordRepresentation, ShiftLeft)
  DECL_SINGLE_REP_SHIFT_V(Word32ShiftLeft, ShiftLeft, Word32)
  DECL_SINGLE_REP_SHIFT_V(Word64ShiftLeft, ShiftLeft, Word64)
  DECL_SINGLE_REP_SHIFT_V(WordPtrShiftLeft, ShiftLeft, WordPtr)
  DECL_MULTI_REP_BINOP(RotateRight, Shift, WordRepresentation, RotateRight)
  DECL_SINGLE_REP_SHIFT_V(Word32RotateRight, RotateRight, Word32)
  DECL_SINGLE_REP_SHIFT_V(Word64RotateRight, RotateRight, Word64)
  DECL_MULTI_REP_BINOP(RotateLeft, Shift, WordRepresentation, RotateLeft)
  DECL_SINGLE_REP_SHIFT_V(Word32RotateLeft, RotateLeft, Word32)
  DECL_SINGLE_REP_SHIFT_V(Word64RotateLeft, RotateLeft, Word64)

  OpIndex ShiftRightLogical(OpIndex left, uint32_t right,
                            WordRepresentation rep) {
    DCHECK_GE(right, 0);
    DCHECK_LT(right, rep.bit_width());
    return ShiftRightLogical(left, this->Word32Constant(right), rep);
  }
  OpIndex ShiftRightArithmetic(OpIndex left, uint32_t right,
                               WordRepresentation rep) {
    DCHECK_GE(right, 0);
    DCHECK_LT(right, rep.bit_width());
    return ShiftRightArithmetic(left, this->Word32Constant(right), rep);
  }
  OpIndex ShiftLeft(OpIndex left, uint32_t right, WordRepresentation rep) {
    DCHECK_LT(right, rep.bit_width());
    return ShiftLeft(left, this->Word32Constant(right), rep);
  }

  V<Word32> Equal(V<Any> left, V<Any> right, RegisterRepresentation rep) {
    return Comparison(left, right, ComparisonOp::Kind::kEqual, rep);
  }

  V<Word32> TaggedEqual(V<Object> left, V<Object> right) {
    return Equal(left, right, RegisterRepresentation::Tagged());
  }

  V<Word32> RootEqual(V<Object> input, RootIndex root, Isolate* isolate) {
    return __ TaggedEqual(
        input, __ HeapConstant(Cast<HeapObject>(isolate->root_handle(root))));
  }

#define DECL_SINGLE_REP_EQUAL_V(name, tag)                            \
  V<Word32> name(ConstOrV<tag> left, ConstOrV<tag> right) {           \
    return ReduceIfReachableComparison(resolve(left), resolve(right), \
                                       ComparisonOp::Kind::kEqual,    \
                                       V<tag>::rep);                  \
  }
  DECL_SINGLE_REP_EQUAL_V(Word32Equal, Word32)
  DECL_SINGLE_REP_EQUAL_V(Word64Equal, Word64)
  DECL_SINGLE_REP_EQUAL_V(WordPtrEqual, WordPtr)
  DECL_SINGLE_REP_EQUAL_V(Float32Equal, Float32)
  DECL_SINGLE_REP_EQUAL_V(Float64Equal, Float64)
  DECL_SINGLE_REP_EQUAL_V(WasmCodePtrEqual, WasmCodePtr)
#undef DECL_SINGLE_REP_EQUAL_V

#define DECL_SINGLE_REP_COMPARISON_V(name, kind, tag)                 \
  V<Word32> name(ConstOrV<tag> left, ConstOrV<tag> right) {           \
    return ReduceIfReachableComparison(resolve(left), resolve(right), \
                                       ComparisonOp::Kind::k##kind,   \
                                       V<tag>::rep);                  \
  }

  DECL_MULTI_REP_BINOP(IntLessThan, Comparison, RegisterRepresentation,
                       SignedLessThan)
  DECL_SINGLE_REP_COMPARISON_V(Int32LessThan, SignedLessThan, Word32)
  DECL_SINGLE_REP_COMPARISON_V(Int64LessThan, SignedLessThan, Word64)
  DECL_SINGLE_REP_COMPARISON_V(IntPtrLessThan, SignedLessThan, WordPtr)

  DECL_MULTI_REP_BINOP(UintLessThan, Comparison, RegisterRepresentation,
                       UnsignedLessThan)
  DECL_SINGLE_REP_COMPARISON_V(Uint32LessThan, UnsignedLessThan, Word32)
  DECL_SINGLE_REP_COMPARISON_V(Uint64LessThan, UnsignedLessThan, Word64)
  DECL_SINGLE_REP_COMPARISON_V(UintPtrLessThan, UnsignedLessThan, WordPtr)
  DECL_MULTI_REP_BINOP(FloatLessThan, Comparison, RegisterRepresentation,
                       SignedLessThan)
  DECL_SINGLE_REP_COMPARISON_V(Float32LessThan, SignedLessThan, Float32)
  DECL_SINGLE_REP_COMPARISON_V(Float64LessThan, SignedLessThan, Float64)

  DECL_MULTI_REP_BINOP(IntLessThanOrEqual, Comparison, RegisterRepresentation,
                       SignedLessThanOrEqual)
  DECL_SINGLE_REP_COMPARISON_V(Int32LessThanOrEqual, SignedLessThanOrEqual,
                               Word32)
  DECL_SINGLE_REP_COMPARISON_V(Int64LessThanOrEqual, SignedLessThanOrEqual,
                               Word64)
  DECL_SINGLE_REP_COMPARISON_V(IntPtrLessThanOrEqual, SignedLessThanOrEqual,
                               WordPtr)
  DECL_MULTI_REP_BINOP(UintLessThanOrEqual, Comparison, RegisterRepresentation,
                       UnsignedLessThanOrEqual)
  DECL_SINGLE_REP_COMPARISON_V(Uint32LessThanOrEqual, UnsignedLessThanOrEqual,
                               Word32)
  DECL_SINGLE_REP_COMPARISON_V(Uint64LessThanOrEqual, UnsignedLessThanOrEqual,
                               Word64)
  DECL_SINGLE_REP_COMPARISON_V(UintPtrLessThanOrEqual, UnsignedLessThanOrEqual,
                               WordPtr)
  DECL_MULTI_REP_BINOP(FloatLessThanOrEqual, Comparison, RegisterRepresentation,
                       SignedLessThanOrEqual)
  DECL_SINGLE_REP_COMPARISON_V(Float32LessThanOrEqual, SignedLessThanOrEqual,
                               Float32)
  DECL_SINGLE_REP_COMPARISON_V(Float64LessThanOrEqual, SignedLessThanOrEqual,
                               Float64)
#undef DECL_SINGLE_REP_COMPARISON_V

  OpIndex Comparison(OpIndex left, OpIndex right, ComparisonOp::Kind kind,
                     RegisterRepresentation rep) {
    return ReduceIfReachableComparison(left, right, kind, rep);
  }

#undef DECL_SINGLE_REP_BINOP_V
#undef DECL_MULTI_REP_BINOP

  V<Float> FloatUnary(V<Float> input, FloatUnaryOp::Kind kind,
                      FloatRepresentation rep) {
    return ReduceIfReachableFloatUnary(input, kind, rep);
  }
  V<Float64> Float64Unary(V<Float64> input, FloatUnaryOp::Kind kind) {
    return ReduceIfReachableFloatUnary(input, kind,
                                       FloatRepresentation::Float64());
  }

#define DECL_MULTI_REP_UNARY(name, operation, rep_type, kind)                \
  OpIndex name(OpIndex input, rep_type rep) {                                \
    return ReduceIfReachable##operation(input, operation##Op::Kind::k##kind, \
                                        rep);                                \
  }
#define DECL_MULTI_REP_UNARY_V(name, operation, rep_type, kind, tag)         \
  V<tag> name(V<tag> input, rep_type rep) {                                  \
    return ReduceIfReachable##operation(input, operation##Op::Kind::k##kind, \
                                        rep);                                \
  }
#define DECL_SINGLE_REP_UNARY_V(name, operation, kind, tag)         \
  V<tag> name(ConstOrV<tag> input) {                                \
    return ReduceIfReachable##operation(                            \
        resolve(input), operation##Op::Kind::k##kind, V<tag>::rep); \
  }

  DECL_MULTI_REP_UNARY_V(FloatAbs, FloatUnary, FloatRepresentation, Abs, Float)
  DECL_SINGLE_REP_UNARY_V(Float32Abs, FloatUnary, Abs, Float32)
  DECL_SINGLE_REP_UNARY_V(Float64Abs, FloatUnary, Abs, Float64)
  DECL_MULTI_REP_UNARY_V(FloatNegate, FloatUnary, FloatRepresentation, Negate,
                         Float)
  DECL_SINGLE_REP_UNARY_V(Float32Negate, FloatUnary, Negate, Float32)
  DECL_SINGLE_REP_UNARY_V(Float64Negate, FloatUnary, Negate, Float64)
  DECL_SINGLE_REP_UNARY_V(Float64SilenceNaN, FloatUnary, SilenceNaN, Float64)
  DECL_MULTI_REP_UNARY_V(FloatRoundDown, FloatUnary, FloatRepresentation,
                         RoundDown, Float)
  DECL_SINGLE_REP_UNARY_V(Float32RoundDown, FloatUnary, RoundDown, Float32)
  DECL_SINGLE_REP_UNARY_V(Float64RoundDown, FloatUnary, RoundDown, Float64)
  DECL_MULTI_REP_UNARY_V(FloatRoundUp, FloatUnary, FloatRepresentation, RoundUp,
                         Float)
  DECL_SINGLE_REP_UNARY_V(Float32RoundUp, FloatUnary, RoundUp, Float32)
  DECL_SINGLE_REP_UNARY_V(Float64RoundUp, FloatUnary, RoundUp, Float64)
  DECL_MULTI_REP_UNARY_V(FloatRoundToZero, FloatUnary, FloatRepresentation,
                         RoundToZero, Float)
  DECL_SINGLE_REP_UNARY_V(Float32RoundToZero, FloatUnary, RoundToZero, Float32)
  DECL_SINGLE_REP_UNARY_V(Float64RoundToZero, FloatUnary, RoundToZero, Float64)
  DECL_MULTI_REP_UNARY_V(FloatRoundTiesEven, FloatUnary, FloatRepresentation,
                         RoundTiesEven, Float)
  DECL_SINGLE_REP_UNARY_V(Float32RoundTiesEven, FloatUnary, RoundTiesEven,
                          Float32)
  DECL_SINGLE_REP_UNARY_V(Float64RoundTiesEven, FloatUnary, RoundTiesEven,
                          Float64)
  DECL_SINGLE_REP_UNARY_V(Float64Log, FloatUnary, Log, Float64)
  DECL_MULTI_REP_UNARY_V(FloatSqrt, FloatUnary, FloatRepresentation, Sqrt,
                         Float)
  DECL_SINGLE_REP_UNARY_V(Float32Sqrt, FloatUnary, Sqrt, Float32)
  DECL_SINGLE_REP_UNARY_V(Float64Sqrt, FloatUnary, Sqrt, Float64)
  DECL_SINGLE_REP_UNARY_V(Float64Exp, FloatUnary, Exp, Float64)
  DECL_SINGLE_REP_UNARY_V(Float64Expm1, FloatUnary, Expm1, Float64)
  DECL_SINGLE_REP_UNARY_V(Float64Sin, FloatUnary, Sin, Float64)
  DECL_SINGLE_REP_UNARY_V(Float64Cos, FloatUnary, Cos, Float64)
  DECL_SINGLE_REP_UNARY_V(Float64Sinh, FloatUnary, Sinh, Float64)
  DECL_SINGLE_REP_UNARY_V(Float64Cosh, FloatUnary, Cosh, Float64)
  DECL_SINGLE_REP_UNARY_V(Float64Asin, FloatUnary, Asin, Float64)
  DECL_SINGLE_REP_UNARY_V(Float64Acos, FloatUnary, Acos, Float64)
  DECL_SINGLE_REP_UNARY_V(Float64Asinh, FloatUnary, Asinh, Float64)
  DECL_SINGLE_REP_UNARY_V(Float64Acosh, FloatUnary, Acosh, Float64)
  DECL_SINGLE_REP_UNARY_V(Float64Tan, FloatUnary, Tan, Float64)
  DECL_SINGLE_REP_UNARY_V(Float64Tanh, FloatUnary, Tanh, Float64)
  DECL_SINGLE_REP_UNARY_V(Float64Log2, FloatUnary, Log2, Float64)
  DECL_SINGLE_REP_UNARY_V(Float64Log10, FloatUnary, Log10, Float64)
  DECL_SINGLE_REP_UNARY_V(Float64Log1p, FloatUnary, Log1p, Float64)
  DECL_SINGLE_REP_UNARY_V(Float64Atan, FloatUnary, Atan, Float64)
  DECL_SINGLE_REP_UNARY_V(Float64Atanh, FloatUnary, Atanh, Float64)
  DECL_SINGLE_REP_UNARY_V(Float64Cbrt, FloatUnary, Cbrt, Float64)

  DECL_MULTI_REP_UNARY_V(WordReverseBytes, WordUnary, WordRepresentation,
                         ReverseBytes, Word)
  DECL_SINGLE_REP_UNARY_V(Word32ReverseBytes, WordUnary, ReverseBytes, Word32)
  DECL_SINGLE_REP_UNARY_V(Word64ReverseBytes, WordUnary, ReverseBytes, Word64)
  DECL_MULTI_REP_UNARY_V(WordCountLeadingZeros, WordUnary, WordRepresentation,
                         CountLeadingZeros, Word)
  DECL_SINGLE_REP_UNARY_V(Word32CountLeadingZeros, WordUnary, CountLeadingZeros,
                          Word32)
  DECL_SINGLE_REP_UNARY_V(Word64CountLeadingZeros, WordUnary, CountLeadingZeros,
                          Word64)
  DECL_MULTI_REP_UNARY_V(WordCountTrailingZeros, WordUnary, WordRepresentation,
                         CountTrailingZeros, Word)
  DECL_SINGLE_REP_UNARY_V(Word32CountTrailingZeros, WordUnary,
                          CountTrailingZeros, Word32)
  DECL_SINGLE_REP_UNARY_V(Word64CountTrailingZeros, WordUnary,
                          CountTrailingZeros, Word64)
  DECL_MULTI_REP_UNARY_V(WordPopCount, WordUnary, WordRepresentation, PopCount,
                         Word)
  DECL_SINGLE_REP_UNARY_V(Word32PopCount, WordUnary, PopCount, Word32)
  DECL_SINGLE_REP_UNARY_V(Word64PopCount, WordUnary, PopCount, Word64)
  DECL_MULTI_REP_UNARY_V(WordSignExtend8, WordUnary, WordRepresentation,
                         SignExtend8, Word)
  DECL_SINGLE_REP_UNARY_V(Word32SignExtend8, WordUnary, SignExtend8, Word32)
  DECL_SINGLE_REP_UNARY_V(Word64SignExtend8, WordUnary, SignExtend8, Word64)
  DECL_MULTI_REP_UNARY_V(WordSignExtend16, WordUnary, WordRepresentation,
                         SignExtend16, Word)
  DECL_SINGLE_REP_UNARY_V(Word32SignExtend16, WordUnary, SignExtend16, Word32)
  DECL_SINGLE_REP_UNARY_V(Word64SignExtend16, WordUnary, SignExtend16, Word64)

  V<turboshaft::Tuple<Word, Word32>> OverflowCheckedUnary(
      V<Word> input, OverflowCheckedUnaryOp::Kind kind,
      WordRepresentation rep) {
    return ReduceIfReachableOverflowCheckedUnary(input, kind, rep);
  }

  DECL_MULTI_REP_UNARY_V(IntAbsCheckOverflow, OverflowCheckedUnary,
                         WordRepresentation, Abs, Word)
  DECL_SINGLE_REP_UNARY_V(Int32AbsCheckOverflow, OverflowCheckedUnary, Abs,
                          Word32)
  DECL_SINGLE_REP_UNARY_V(Int64AbsCheckOverflow, OverflowCheckedUnary, Abs,
                          Word64)

#undef DECL_SINGLE_REP_UNARY_V
#undef DECL_MULTI_REP_UNARY
#undef DECL_MULTI_REP_UNARY_V

  V<Word> WordBinopDeoptOnOverflow(V<Word> left, V<Word> right,
                                   V<turboshaft::FrameState> frame_state,
                                   WordBinopDeoptOnOverflowOp::Kind kind,
                                   WordRepresentation rep,
                                   FeedbackSource feedback,
                                   CheckForMinusZeroMode mode) {
    return ReduceIfReachableWordBinopDeoptOnOverflow(left, right, frame_state,
                                                     kind, rep, feedback, mode);
  }
#define DECL_SINGLE_REP_BINOP_DEOPT_OVERFLOW(operation, rep_type)     \
  OpIndex rep_type##operation##DeoptOnOverflow(                       \
      ConstOrV<rep_type> left, ConstOrV<rep_type> right,              \
      V<turboshaft::FrameState> frame_state, FeedbackSource feedback, \
      CheckForMinusZeroMode mode =                                    \
          CheckForMinusZeroMode::kDontCheckForMinusZero) {            \
    return WordBinopDeoptOnOverflow(                                  \
        resolve(left), resolve(right), frame_state,                   \
        WordBinopDeoptOnOverflowOp::Kind::k##operation,               \
        WordRepresentation::rep_type(), feedback, mode);              \
  }

  DECL_SINGLE_REP_BINOP_DEOPT_OVERFLOW(SignedAdd, Word32)
  DECL_SINGLE_REP_BINOP_DEOPT_OVERFLOW(SignedAdd, Word64)
  DECL_SINGLE_REP_BINOP_DEOPT_OVERFLOW(SignedAdd, WordPtr)
  DECL_SINGLE_REP_BINOP_DEOPT_OVERFLOW(SignedSub, Word32)
  DECL_SINGLE_REP_BINOP_DEOPT_OVERFLOW(SignedSub, Word64)
  DECL_SINGLE_REP_BINOP_DEOPT_OVERFLOW(SignedSub, WordPtr)
  DECL_SINGLE_REP_BINOP_DEOPT_OVERFLOW(SignedMul, Word32)
  DECL_SINGLE_REP_BINOP_DEOPT_OVERFLOW(SignedMul, Word64)
  DECL_SINGLE_REP_BINOP_DEOPT_OVERFLOW(SignedMul, WordPtr)
  DECL_SINGLE_REP_BINOP_DEOPT_OVERFLOW(SignedDiv, Word32)
  DECL_SINGLE_REP_BINOP_DEOPT_OVERFLOW(SignedDiv, Word64)
  DECL_SINGLE_REP_BINOP_DEOPT_OVERFLOW(SignedDiv, WordPtr)
  DECL_SINGLE_REP_BINOP_DEOPT_OVERFLOW(SignedMod, Word32)
  DECL_SINGLE_REP_BINOP_DEOPT_OVERFLOW(SignedMod, Word64)
  DECL_SINGLE_REP_BINOP_DEOPT_OVERFLOW(SignedMod, WordPtr)
  DECL_SINGLE_REP_BINOP_DEOPT_OVERFLOW(UnsignedDiv, Word32)
  DECL_SINGLE_REP_BINOP_DEOPT_OVERFLOW(UnsignedMod, Word32)
#undef DECL_SINGLE_REP_BINOP_DEOPT_OVERFLOW

  V<Float64> BitcastWord32PairToFloat64(ConstOrV<Word32> high_word32,
                                        ConstOrV<Word32> low_word32) {
    return ReduceIfReachableBitcastWord32PairToFloat64(resolve(high_word32),
                                                       resolve(low_word32));
  }

  OpIndex TaggedBitcast(OpIndex input, RegisterRepresentation from,
                        RegisterRepresentation to, TaggedBitcastOp::Kind kind) {
    return ReduceIfReachableTaggedBitcast(input, from, to, kind);
  }

#define DECL_TAGGED_BITCAST(FromT, ToT, kind)               \
  V<ToT> Bitcast##FromT##To##ToT(V<FromT> input) {          \
    return TaggedBitcast(input, V<FromT>::rep, V<ToT>::rep, \
                         TaggedBitcastOp::Kind::kind);      \
  }
  DECL_TAGGED_BITCAST(Smi, Word32, kSmi)
  DECL_TAGGED_BITCAST(Word32, Smi, kSmi)
  DECL_TAGGED_BITCAST(Smi, WordPtr, kSmi)
  DECL_TAGGED_BITCAST(WordPtr, Smi, kSmi)
  DECL_TAGGED_BITCAST(WordPtr, HeapObject, kHeapObject)
  DECL_TAGGED_BITCAST(HeapObject, WordPtr, kHeapObject)
#undef DECL_TAGGED_BITCAST
  V<Object> BitcastWordPtrToTagged(V<WordPtr> input) {
    return TaggedBitcast(input, V<WordPtr>::rep, V<Object>::rep,
                         TaggedBitcastOp::Kind::kAny);
  }

  V<WordPtr> BitcastTaggedToWordPtr(V<Object> input) {
    return TaggedBitcast(input, V<Object>::rep, V<WordPtr>::rep,
                         TaggedBitcastOp::Kind::kAny);
  }

  V<WordPtr> BitcastTaggedToWordPtrForTagAndSmiBits(V<Object> input) {
    return TaggedBitcast(input, RegisterRepresentation::Tagged(),
                         RegisterRepresentation::WordPtr(),
                         TaggedBitcastOp::Kind::kTagAndSmiBits);
  }

  V<Word32> ObjectIs(V<Object> input, ObjectIsOp::Kind kind,
                     ObjectIsOp::InputAssumptions input_assumptions) {
    return ReduceIfReachableObjectIs(input, kind, input_assumptions);
  }
#define DECL_OBJECT_IS(kind)                              \
  V<Word32> ObjectIs##kind(V<Object> object) {            \
    return ObjectIs(object, ObjectIsOp::Kind::k##kind,    \
                    ObjectIsOp::InputAssumptions::kNone); \
  }

  DECL_OBJECT_IS(ArrayBufferView)
  DECL_OBJECT_IS(BigInt)
  DECL_OBJECT_IS(BigInt64)
  DECL_OBJECT_IS(Callable)
  DECL_OBJECT_IS(Constructor)
  DECL_OBJECT_IS(DetectableCallable)
  DECL_OBJECT_IS(InternalizedString)
  DECL_OBJECT_IS(NonCallable)
  DECL_OBJECT_IS(Number)
  DECL_OBJECT_IS(NumberOrBigInt)
  DECL_OBJECT_IS(Receiver)
  DECL_OBJECT_IS(ReceiverOrNullOrUndefined)
  DECL_OBJECT_IS(Smi)
  DECL_OBJECT_IS(String)
  DECL_OBJECT_IS(StringOrStringWrapper)
  DECL_OBJECT_IS(Symbol)
  DECL_OBJECT_IS(Undetectable)
#undef DECL_OBJECT_IS

  V<Word32> Float64Is(V<Float64> input, NumericKind kind) {
    return ReduceIfReachableFloat64Is(input, kind);
  }
  V<Word32> Float64IsNaN(V<Float64> input) {
    return Float64Is(input, NumericKind::kNaN);
  }
  V<Word32> Float64IsHole(V<Float64> input) {
    return Float64Is(input, NumericKind::kFloat64Hole);
  }
  // Float64IsSmi returns true if {input} is an integer in smi range.
  V<Word32> Float64IsSmi(V<Float64> input) {
    return Float64Is(input, NumericKind::kSmi);
  }

  V<Word32> ObjectIsNumericValue(V<Object> input, NumericKind kind,
                                 FloatRepresentation input_rep) {
    return ReduceIfReachableObjectIsNumericValue(input, kind, input_rep);
  }

  V<Object> Convert(V<Object> input, ConvertOp::Kind from, ConvertOp::Kind to) {
    return ReduceIfReachableConvert(input, from, to);
  }
  V<Number> ConvertPlainPrimitiveToNumber(V<PlainPrimitive> input) {
    return V<Number>::Cast(Convert(input, ConvertOp::Kind::kPlainPrimitive,
                                   ConvertOp::Kind::kNumber));
  }
  V<Boolean> ConvertToBoolean(V<Object> input) {
    return V<Boolean>::Cast(
        Convert(input, ConvertOp::Kind::kObject, ConvertOp::Kind::kBoolean));
  }
  V<String> ConvertNumberToString(V<Number> input) {
    return V<String>::Cast(
        Convert(input, ConvertOp::Kind::kNumber, ConvertOp::Kind::kString));
  }
  V<Number> ConvertStringToNumber(V<String> input) {
    return V<Number>::Cast(
        Convert(input, ConvertOp::Kind::kString, ConvertOp::Kind::kNumber));
  }

  V<JSPrimitive> ConvertUntaggedToJSPrimitive(
      V<Untagged> input, ConvertUntaggedToJSPrimitiveOp::JSPrimitiveKind kind,
      RegisterRepresentation input_rep,
      ConvertUntaggedToJSPrimitiveOp::InputInterpretation input_interpretation,
      CheckForMinusZeroMode minus_zero_mode) {
    return ReduceIfReachableConvertUntaggedToJSPrimitive(
        input, kind, input_rep, input_interpretation, minus_zero_mode);
  }
#define CONVERT_PRIMITIVE_TO_OBJECT(name, kind, input_rep,               \
                                    input_interpretation)                \
  V<kind> name(V<input_rep> input) {                                     \
    return V<kind>::Cast(ConvertUntaggedToJSPrimitive(                   \
        input, ConvertUntaggedToJSPrimitiveOp::JSPrimitiveKind::k##kind, \
        RegisterRepresentation::input_rep(),                             \
        ConvertUntaggedToJSPrimitiveOp::InputInterpretation::            \
            k##input_interpretation,                                     \
        CheckForMinusZeroMode::kDontCheckForMinusZero));                 \
  }
  CONVERT_PRIMITIVE_TO_OBJECT(ConvertInt32ToNumber, Number, Word32, Signed)
  CONVERT_PRIMITIVE_TO_OBJECT(ConvertUint32ToNumber, Number, Word32, Unsigned)
  CONVERT_PRIMITIVE_TO_OBJECT(ConvertWord32ToBoolean, Boolean, Word32, Signed)
  CONVERT_PRIMITIVE_TO_OBJECT(ConvertCharCodeToString, String, Word32, CharCode)
#undef CONVERT_PRIMITIVE_TO_OBJECT
  V<Number> ConvertFloat64ToNumber(V<Float64> input,
                                   CheckForMinusZeroMode minus_zero_mode) {
    return V<Number>::Cast(ConvertUntaggedToJSPrimitive(
        input, ConvertUntaggedToJSPrimitiveOp::JSPrimitiveKind::kNumber,
        RegisterRepresentation::Float64(),
        ConvertUntaggedToJSPrimitiveOp::InputInterpretation::kSigned,
        minus_zero_mode));
  }

  V<JSPrimitive> ConvertUntaggedToJSPrimitiveOrDeopt(
      V<Untagged> input, V<turboshaft::FrameState> frame_state,
      ConvertUntaggedToJSPrimitiveOrDeoptOp::JSPrimitiveKind kind,
      RegisterRepresentation input_rep,
      ConvertUntaggedToJSPrimitiveOrDeoptOp::InputInterpretation
          input_interpretation,
      const FeedbackSource& feedback) {
    return ReduceIfReachableConvertUntaggedToJSPrimitiveOrDeopt(
        input, frame_state, kind, input_rep, input_interpretation, feedback);
  }

  V<Untagged> ConvertJSPrimitiveToUntagged(
      V<JSPrimitive> primitive,
      ConvertJSPrimitiveToUntaggedOp::UntaggedKind kind,
      ConvertJSPrimitiveToUntaggedOp::InputAssumptions input_assumptions) {
    return ReduceIfReachableConvertJSPrimitiveToUntagged(primitive, kind,
                                                         input_assumptions);
  }

  V<Untagged> ConvertJSPrimitiveToUntaggedOrDeopt(
      V<Object> object, V<turboshaft::FrameState> frame_state,
      ConvertJSPrimitiveToUntaggedOrDeoptOp::JSPrimitiveKind from_kind,
      ConvertJSPrimitiveToUntaggedOrDeoptOp::UntaggedKind to_kind,
      CheckForMinusZeroMode minus_zero_mode, const FeedbackSource& feedback) {
    return ReduceIfReachableConvertJSPrimitiveToUntaggedOrDeopt(
        object, frame_state, from_kind, to_kind, minus_zero_mode, feedback);
  }
  V<Word32> CheckedSmiUntag(V<Object> object,
                            V<turboshaft::FrameState> frame_state,
                            const FeedbackSource& feedback) {
    return V<Word32>::Cast(ConvertJSPrimitiveToUntaggedOrDeopt(
        object, frame_state,
        ConvertJSPrimitiveToUntaggedOrDeoptOp::JSPrimitiveKind::kSmi,
        ConvertJSPrimitiveToUntaggedOrDeoptOp::UntaggedKind::kInt32,
        CheckForMinusZeroMode::kDontCheckForMinusZero, feedback));
  }

  V<Word> TruncateJSPrimitiveToUntagged(
      V<JSPrimitive> object, TruncateJSPrimitiveToUntaggedOp::UntaggedKind kind,
      TruncateJSPrimitiveToUntaggedOp::InputAssumptions input_assumptions) {
    return ReduceIfReachableTruncateJSPrimitiveToUntagged(object, kind,
                                                          input_assumptions);
  }

  V<Word32> TruncateNumberToInt32(V<Number> value) {
    return V<Word32>::Cast(TruncateJSPrimitiveToUntagged(
        value, TruncateJSPrimitiveToUntaggedOp::UntaggedKind::kInt32,
        TruncateJSPrimitiveToUntaggedOp::InputAssumptions::kNumberOrOddball));
  }

  V<Word> TruncateJSPrimitiveToUntaggedOrDeopt(
      V<JSPrimitive> object, V<turboshaft::FrameState> frame_state,
      TruncateJSPrimitiveToUntaggedOrDeoptOp::UntaggedKind kind,
      TruncateJSPrimitiveToUntaggedOrDeoptOp::InputRequirement
          input_requirement,
      const FeedbackSource& feedback) {
    return ReduceIfReachableTruncateJSPrimitiveToUntaggedOrDeopt(
        object, frame_state, kind, input_requirement, feedback);
  }

  V<Object> ConvertJSPrimitiveToObject(V<JSPrimitive> value,
                                       V<Context> native_context,
                                       V<JSGlobalProxy> global_proxy,
                                       ConvertReceiverMode mode) {
    return ReduceIfReachableConvertJSPrimitiveToObject(value, native_context,
                                                       global_proxy, mode);
  }

  V<Word32> Word32Constant(uint32_t value) {
    return ReduceIfReachableConstant(ConstantOp::Kind::kWord32,
                                     uint64_t{value});
  }
  V<Word32> Word32Constant(int32_t value) {
    return Word32Constant(static_cast<uint32_t>(value));
  }
  V<Word64> Word64Constant(uint64_t value) {
    return ReduceIfReachableConstant(ConstantOp::Kind::kWord64, value);
  }
  V<Word64> Word64Constant(int64_t value) {
    return Word64Constant(static_cast<uint64_t>(value));
  }
  V<WordPtr> WordPtrConstant(uintptr_t value) {
    return V<WordPtr>::Cast(WordConstant(value, WordRepresentation::WordPtr()));
  }
  V<Word> WordConstant(uint64_t value, WordRepresentation rep) {
    switch (rep.value()) {
      case WordRepresentation::Word32():
        return Word32Constant(static_cast<uint32_t>(value));
      case WordRepresentation::Word64():
        return Word64Constant(value);
    }
  }
  V<WordPtr> IntPtrConstant(intptr_t value) {
    return UintPtrConstant(static_cast<uintptr_t>(value));
  }
  V<WordPtr> UintPtrConstant(uintptr_t value) { return WordPtrConstant(value); }
  // TODO(nicohartmann): I would like to get rid of this overload as it is
  // non-obvious that this doesnt perform Smi-tagging.
  V<Smi> SmiConstant(intptr_t value) {
    return SmiConstant(i::Tagged<Smi>(value));
  }
  V<Smi> SmiConstant(i::Tagged<Smi> value) {
    return V<Smi>::Cast(
        ReduceIfReachableConstant(ConstantOp::Kind::kSmi, value));
  }
  V<Float32> Float32Constant(i::Float32 value) {
    return ReduceIfReachableConstant(ConstantOp::Kind::kFloat32, value);
  }
  V<Float32> Float32Constant(float value) {
    // Passing the NaN Hole as input is allowed, but there is no guarantee that
    // it will remain a hole (it will remain NaN though).
    if (std::isnan(value)) {
      return Float32Constant(
          i::Float32::FromBits(base::bit_cast<uint32_t>(value)));
    } else {
      return Float32Constant(i::Float32(value));
    }
  }
  V<Float64> Float64Constant(i::Float64 value) {
    return ReduceIfReachableConstant(ConstantOp::Kind::kFloat64, value);
  }
  V<Float64> Float64Constant(double value) {
    // Passing the NaN Hole as input is allowed, but there is no guarantee that
    // it will remain a hole (it will remain NaN though).
    if (std::isnan(value)) {
      return Float64Constant(
          i::Float64::FromBits(base::bit_cast<uint64_t>(value)));
    } else {
      return Float64Constant(i::Float64(value));
    }
  }
  OpIndex FloatConstant(double value, FloatRepresentation rep) {
    // Passing the NaN Hole as input is allowed, but there is no guarantee that
    // it will remain a hole (it will remain NaN though).
    switch (rep.value()) {
      case FloatRepresentation::Float32():
        return Float32Constant(static_cast<float>(value));
      case FloatRepresentation::Float64():
        return Float64Constant(value);
    }
  }
  OpIndex NumberConstant(i::Float64 value) {
    return ReduceIfReachableConstant(ConstantOp::Kind::kNumber, value);
  }
  OpIndex NumberConstant(double value) {
    // Passing the NaN Hole as input is allowed, but there is no guarantee that
    // it will remain a hole (it will remain NaN though).
    if (std::isnan(value)) {
      return NumberConstant(
          i::Float64::FromBits(base::bit_cast<uint64_t>(value)));
    } else {
      return NumberConstant(i::Float64(value));
    }
  }
  OpIndex TaggedIndexConstant(int32_t value) {
    return ReduceIfReachableConstant(ConstantOp::Kind::kTaggedIndex,
                                     uint64_t{static_cast<uint32_t>(value)});
  }
  // TODO(nicohartmann): Maybe we should replace all uses of `HeapConstant` with
  // `HeapConstant[No|Maybe]?Hole` version.
  template <typename T,
            typename = std::enable_if_t<is_subtype_v<T, HeapObject>>>
  V<T> HeapConstant(Handle<T> value) {
    return ReduceIfReachableConstant(ConstantOp::Kind::kHeapObject,
                                     ConstantOp::Storage{value});
  }
  template <typename T,
            typename = std::enable_if_t<is_subtype_v<T, HeapObject>>>
  V<T> HeapConsta
```