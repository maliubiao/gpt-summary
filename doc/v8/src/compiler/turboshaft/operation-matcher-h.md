Response:
Let's break down the thought process for analyzing the C++ header file.

1. **Identify the Core Purpose:** The filename `operation-matcher.h` strongly suggests that the primary function is to check the *type* and *properties* of operations within a larger system (likely a compiler). The namespace `v8::internal::compiler::turboshaft` confirms this context is the Turboshaft compiler pipeline within the V8 JavaScript engine.

2. **Examine the Class Structure:**  The `OperationMatcher` class takes a `Graph&` as input in its constructor. This immediately tells us it operates on a graph data structure, which is a common way to represent intermediate representations in compilers. The `graph_` member stores this reference.

3. **Analyze the Core Matching Methods:**  The first few template methods (`Is`, `TryCast`, `Cast`) are fundamental. They allow you to check if an operation at a given `OpIndex` is of a specific type (`Op`). `TryCast` provides a safe way to attempt a cast (returns a pointer or null), while `Cast` assumes the type is correct.

4. **Focus on Specific Matcher Functions:** The bulk of the file consists of `Match...` functions. The naming convention is crucial. They clearly indicate the specific type of operation or property they are trying to match (e.g., `MatchZero`, `MatchIntegralZero`, `MatchFloat32Constant`).

5. **Categorize the Matcher Functions:**  As you go through the `Match...` functions, you'll start to see patterns:
    * **Constant Matching:**  Functions like `MatchZero`, `MatchIntegralZero`, `MatchFloatConstant`, `MatchHeapConstant`, `MatchIntegralWordConstant`, `MatchExternalConstant`, `MatchWasmStubCallConstant`, `MatchPowerOfTwoWordConstant`. These are crucial for recognizing constant values.
    * **Operation Type Matching with Properties:** Functions like `MatchChange`, `MatchWordBinop`, `MatchFloatUnary`, `MatchFloatBinary`, `MatchConstantShift`, `MatchEqual`, `MatchPhi`. These check the *kind* of operation and potentially extract specific input operands and attributes.

6. **Infer the Usage Scenario:** Based on the function names and parameters, the `OperationMatcher` is clearly designed for use within compiler optimization passes. These passes often need to identify specific patterns of operations to apply transformations. For instance, knowing an operand is a constant zero allows for simplifying arithmetic.

7. **Consider Potential Torque Equivalents (Instruction #2):**  The prompt asks about `.tq` files. Knowing that Torque is V8's domain-specific language for defining built-in functions and low-level operations,  it's reasonable to assume that if similar matching logic were implemented in Torque, it would involve pattern matching constructs within the Torque language itself, possibly using predicates or specific syntax for checking operation properties.

8. **Connect to JavaScript Functionality (Instruction #3):**  This requires thinking about how the matched operations relate to JavaScript concepts. Matching constant zero is directly related to how JavaScript treats `0`, `0.0`, and potentially `null` or `undefined` in certain contexts. Matching arithmetic operations like addition, subtraction, and bitwise operations has obvious JavaScript parallels. Float operations connect to JavaScript's `Number` type and its handling of floating-point arithmetic.

9. **Develop Example Scenarios (Instructions #4 & #5):**  For code logic and common errors, think about how a compiler might use these matchers and what potential pitfalls exist.
    * **Logic:**  Consider a simple arithmetic expression and how the matcher would identify the operations and constants.
    * **Errors:** Focus on situations where a programmer might *expect* a certain optimization but it doesn't occur because the compiler can't match the pattern due to type differences or unexpected operation sequences. Integer vs. floating-point comparisons are a good example.

10. **Review and Refine:**  After drafting the initial analysis, reread the code and your explanation. Are there any details you missed? Is the language clear and concise?  Are the examples relevant and easy to understand?  For example, initially I might have just said "it matches operations," but realizing the specific *types* of matches (constants, arithmetic, shifts, etc.) makes the explanation much more useful. Also, explicitly linking the matchers back to optimization opportunities strengthens the analysis.
`v8/src/compiler/turboshaft/operation-matcher.h` 是 V8 Turboshaft 编译器的源代码文件，它定义了一个名为 `OperationMatcher` 的类。这个类的主要功能是**用于方便地检查和匹配 Turboshaft 图中的操作 (operations) 的类型和属性**。

**功能列表:**

1. **类型检查:**
   - `Is<Op>(OpIndex op_idx)`:  检查给定 `OpIndex` 处的 Operation 是否是 `Op` 类型。
   - `TryCast<Op>(OpIndex op_idx)`: 尝试将给定 `OpIndex` 处的 Operation 转换为 `Op` 类型，如果成功则返回指向该 Operation 的指针，否则返回 `nullptr`。
   - `Cast<Op>(OpIndex op_idx)`: 将给定 `OpIndex` 处的 Operation 转换为 `Op` 类型，如果类型不匹配则会触发断言失败。

2. **获取 Operation 信息:**
   - `Get(OpIndex op_idx)`: 获取给定 `OpIndex` 处的 `Operation` 对象。
   - `Index(const Operation& op)`: 获取给定 `Operation` 对象的 `OpIndex`。

3. **匹配特定类型的常量:**
   - `MatchZero(OpIndex matched)`: 检查给定的 Operation 是否是数值零的常量 (包括整数、浮点数、Smi)。
   - `MatchIntegralZero(OpIndex matched)`: 检查给定的 Operation 是否是整数零的常量。
   - `MatchSmiZero(OpIndex matched)`: 检查给定的 Operation 是否是 Smi 类型的零常量。
   - `MatchFloat32Constant(OpIndex matched, float* constant)`: 检查给定的 Operation 是否是 Float32 类型的常量，并将值存储到 `constant` 中。
   - `MatchFloat64Constant(OpIndex matched, double* constant)`: 检查给定的 Operation 是否是 Float64 类型的常量，并将值存储到 `constant` 中。
   - `MatchFloat(OpIndex matched, double* value)`: 检查给定的 Operation 是否是浮点数常量 (Float32 或 Float64)，并将值存储到 `value` 中。
   - `MatchFloat(OpIndex matched, double value)`: 检查给定的 Operation 是否是等于给定 `value` 的浮点数常量。
   - `MatchNaN(OpIndex matched)`: 检查给定的 Operation 是否是 NaN (Not-a-Number) 的浮点数常量。
   - `MatchHeapConstant(OpIndex matched, Handle<HeapObject>* tagged = nullptr)`: 检查给定的 Operation 是否是堆对象常量，并可选择将句柄存储到 `tagged` 中。
   - `MatchIntegralWordConstant(...)`: 检查给定的 Operation 是否是指定位宽的整数常量 (Word32 或 Word64)。
   - `MatchIntegralWord32Constant(...)`: 检查给定的 Operation 是否是 32 位整数常量。
   - `MatchIntegralWord64Constant(...)`: 检查给定的 Operation 是否是 64 位整数常量。
   - `MatchIntegralWordPtrConstant(...)`: 检查给定的 Operation 是否是机器字长的整数常量 (32 位或 64 位，取决于平台)。
   - `MatchSignedIntegralConstant(...)`: 检查给定的 Operation 是否是有符号整数常量。
   - `MatchUnsignedIntegralConstant(...)`: 检查给定的 Operation 是否是无符号整数常量。
   - `MatchExternalConstant(OpIndex matched, ExternalReference* reference)`: 检查给定的 Operation 是否是外部引用常量。
   - `MatchWasmStubCallConstant(OpIndex matched, uint64_t* stub_id)`: 检查给定的 Operation 是否是 Wasm Stub 调用常量。
   - `MatchPowerOfTwoWordConstant(...)`: 检查给定的 Operation 是否是 2 的幂的整数常量。
   - `MatchPowerOfTwoWord32Constant(...)`: 检查给定的 Operation 是否是 2 的幂的 32 位整数常量。

4. **匹配特定类型的操作:**
   - `MatchChange(...)`: 匹配类型转换操作 (`ChangeOp`)。
   - `MatchWordBinop(...)`: 匹配字运算操作 (`WordBinopOp`)。
   - `MatchWordAdd(...)`, `MatchWordSub(...)`, `MatchWordMul(...)`, `MatchBitwiseAnd(...)`: 匹配特定的字运算。
   - `MatchBitwiseAndWithConstant(...)`: 匹配与常量进行按位与运算。
   - `MatchEqual(...)`: 匹配相等比较操作 (`ComparisonOp`，比较结果是布尔值)。
   - `MatchFloatUnary(...)`: 匹配单目浮点数运算操作 (`FloatUnaryOp`)。
   - `MatchFloatRoundDown(...)`: 匹配向下取整的浮点数运算。
   - `MatchFloatBinary(...)`: 匹配双目浮点数运算操作 (`FloatBinopOp`)。
   - `MatchFloatSub(...)`: 匹配浮点数减法运算。
   - `MatchConstantShift(...)`: 匹配与常量进行位移操作 (`ShiftOp`)。
   - `MatchConstantRightShift(...)`: 匹配与常量进行右移操作。
   - `MatchConstantLeftShift(...)`: 匹配与常量进行左移操作。
   - `MatchConstantShiftRightArithmeticShiftOutZeros(...)`: 匹配特殊的算术右移操作。
   - `MatchPhi(...)`: 匹配 Phi 节点 (`PhiOp`)，用于表示控制流汇聚点的值。

**关于 `.tq` 文件和 JavaScript 的关系:**

如果 `v8/src/compiler/turboshaft/operation-matcher.h` 以 `.tq` 结尾，那么它才是一个 V8 Torque 源代码文件。 由于当前给定的文件名是 `.h`，它是一个 C++ 头文件，不是 Torque 文件。

虽然这个文件本身不是 Torque 代码，但它定义的功能是服务于 V8 编译器的，而编译器负责将 JavaScript 代码转换为机器码。 因此，`OperationMatcher` 的功能与 JavaScript 的执行过程密切相关。

**JavaScript 举例说明 (与功能关系):**

`OperationMatcher` 用于识别 Turboshaft 图中的各种操作模式，这有助于编译器进行优化。 例如，编译器可以使用 `MatchZero` 来识别乘以零的情况，从而直接将结果优化为零。

```javascript
function example(x) {
  return x * 0; // JavaScript 代码
}
```

在 Turboshaft 编译器内部，当编译 `example` 函数时，会生成一个表示乘法操作的节点。 `OperationMatcher` 中的 `MatchZero` 函数可以用来检查乘法的第二个操作数是否是零常量。 如果是，编译器可以应用优化规则，直接生成返回零的代码，而无需实际执行乘法运算。

类似地，`MatchIntegralWordConstant` 可以用于识别与常量进行位运算的情况，例如：

```javascript
function bitwiseAndExample(y) {
  return y & 0xFF; // JavaScript 代码
}
```

编译器可以使用 `MatchBitwiseAndWithConstant` 来识别这种模式，并可能进行进一步的优化。

**代码逻辑推理 (假设输入与输出):**

假设我们有以下 Turboshaft 图中的一个操作节点的索引 `op_index`，并且该节点表示一个常量整数 `10`。

**假设输入:**
- `op_index`: 指向一个 `ConstantOp` 类型的 Operation，其值为整数 `10`。
- `WordRepresentation::Word32()`: 表示 32 位字长。

**调用:**
```c++
OperationMatcher matcher(graph); // 假设 graph 是 Turboshaft 图对象
uint32_t constant_value;
bool is_constant = matcher.MatchIntegralWord32Constant(op_index, &constant_value);
```

**输出:**
- `is_constant`: `true` (因为该 Operation 是一个 32 位整数常量)
- `constant_value`: `10`

**假设输入 (另一个例子):**

**假设输入:**
- `op_index`: 指向一个 `WordBinopOp` 类型的 Operation，表示两个变量 `a` 和 `b` 的加法。
- `WordRepresentation::Word32()`

**调用:**
```c++
OperationMatcher matcher(graph);
OpIndex left_operand, right_operand;
WordBinopOp::Kind kind;
WordRepresentation rep;
bool is_add = matcher.MatchWordBinop<uint32_t>(op_index, &left_operand, &right_operand, &kind, &rep);
```

**输出:**
- `is_add`: `true` (假设该操作确实是加法)
- `left_operand`:  指向表示变量 `a` 的 Operation 的 `OpIndex`。
- `right_operand`: 指向表示变量 `b` 的 Operation 的 `OpIndex`。
- `kind`: `WordBinopOp::Kind::kAdd`
- `rep`: `WordRepresentation::Word32()`

**用户常见的编程错误 (与匹配功能相关):**

用户在编写 JavaScript 代码时，一些常见的错误可能会导致编译器生成的 Turboshaft 图包含特定的操作模式，而 `OperationMatcher` 可以用来识别这些模式，并可能进行优化或发出警告。

**例子 1: 类型不匹配导致的非预期行为**

```javascript
function compare(x) {
  return x == 0; // 注意这里是 == 而不是 ===
}
```

如果 `x` 是一个字符串 `"0"`，JavaScript 的 `==` 运算符会进行类型转换，使得 `"0" == 0` 为 `true`。  编译器可能会生成包含类型转换操作的 Turboshaft 图。  如果开发者期望严格比较 (`===`)，则可能会出现非预期的行为。  `OperationMatcher` 可以用来识别这种类型转换模式，并可能触发进一步的优化或静态分析。

**例子 2:  位运算的误用**

```javascript
function checkBit(flags) {
  return flags & 1 == true; // 错误的比较方式
}
```

开发者可能想检查 `flags` 的最低位是否为 1。然而，由于运算符优先级，这段代码实际上等价于 `flags & (1 == true)`，即 `flags & 1`。  如果开发者期望的是 `(flags & 1) == true`，则结果会不同。  编译器生成的 Turboshaft 图会反映这种位运算和比较的模式，`OperationMatcher` 可以帮助识别这种潜在的错误模式。

**总结:**

`v8/src/compiler/turboshaft/operation-matcher.h` 定义的 `OperationMatcher` 类是 Turboshaft 编译器进行代码分析和优化的重要工具。它提供了一系列便捷的方法来检查和匹配 Turboshaft 图中各种操作的类型和属性，从而支持各种编译器优化和分析任务。虽然它本身是 C++ 代码，但其功能直接服务于 JavaScript 代码的编译和执行过程。

Prompt: 
```
这是目录为v8/src/compiler/turboshaft/operation-matcher.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/turboshaft/operation-matcher.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2022 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_COMPILER_TURBOSHAFT_OPERATION_MATCHER_H_
#define V8_COMPILER_TURBOSHAFT_OPERATION_MATCHER_H_

#include <limits>
#include <optional>
#include <type_traits>

#include "src/compiler/turboshaft/graph.h"
#include "src/compiler/turboshaft/operations.h"
#include "src/compiler/turboshaft/representations.h"

namespace v8::internal::compiler::turboshaft {

class OperationMatcher {
 public:
  explicit OperationMatcher(const Graph& graph) : graph_(graph) {}

  template <class Op>
  bool Is(OpIndex op_idx) const {
    return graph_.Get(op_idx).Is<Op>();
  }

  template <class Op>
  const underlying_operation_t<Op>* TryCast(OpIndex op_idx) const {
    return graph_.Get(op_idx).TryCast<Op>();
  }

  template <class Op>
  const underlying_operation_t<Op>& Cast(OpIndex op_idx) const {
    return graph_.Get(op_idx).Cast<Op>();
  }

  const Operation& Get(OpIndex op_idx) const { return graph_.Get(op_idx); }

  OpIndex Index(const Operation& op) const { return graph_.Index(op); }

  bool MatchZero(OpIndex matched) const {
    const ConstantOp* op = TryCast<ConstantOp>(matched);
    if (!op) return false;
    switch (op->kind) {
      case ConstantOp::Kind::kWord32:
      case ConstantOp::Kind::kWord64:
        return op->integral() == 0;
      case ConstantOp::Kind::kFloat32:
        return op->float32().get_scalar() == 0;
      case ConstantOp::Kind::kFloat64:
        return op->float64().get_scalar() == 0;
      case ConstantOp::Kind::kSmi:
        return op->smi().value() == 0;
      default:
        return false;
    }
  }

  bool MatchIntegralZero(OpIndex matched) const {
    int64_t constant;
    return MatchSignedIntegralConstant(matched, &constant) && constant == 0;
  }

  bool MatchSmiZero(OpIndex matched) const {
    const ConstantOp* op = TryCast<ConstantOp>(matched);
    if (!op) return false;
    if (op->kind != ConstantOp::Kind::kSmi) return false;
    return op->smi().value() == 0;
  }

  bool MatchFloat32Constant(OpIndex matched, float* constant) const {
    const ConstantOp* op = TryCast<ConstantOp>(matched);
    if (!op) return false;
    if (op->kind != ConstantOp::Kind::kFloat32) return false;
    *constant = op->storage.float32.get_scalar();
    return true;
  }

  bool MatchFloat32Constant(OpIndex matched, i::Float32* constant) const {
    const ConstantOp* op = TryCast<ConstantOp>(matched);
    if (!op) return false;
    if (op->kind != ConstantOp::Kind::kFloat32) return false;
    *constant = op->storage.float32;
    return true;
  }

  bool MatchFloat64Constant(OpIndex matched, double* constant) const {
    const ConstantOp* op = TryCast<ConstantOp>(matched);
    if (!op) return false;
    if (op->kind != ConstantOp::Kind::kFloat64) return false;
    *constant = op->storage.float64.get_scalar();
    return true;
  }

  bool MatchFloat64Constant(OpIndex matched, i::Float64* constant) const {
    const ConstantOp* op = TryCast<ConstantOp>(matched);
    if (!op) return false;
    if (op->kind != ConstantOp::Kind::kFloat64) return false;
    *constant = op->storage.float64;
    return true;
  }

  bool MatchFloat(OpIndex matched, double* value) const {
    const ConstantOp* op = TryCast<ConstantOp>(matched);
    if (!op) return false;
    if (op->kind == ConstantOp::Kind::kFloat64) {
      *value = op->storage.float64.get_scalar();
      return true;
    } else if (op->kind == ConstantOp::Kind::kFloat32) {
      *value = op->storage.float32.get_scalar();
      return true;
    }
    return false;
  }

  bool MatchFloat(OpIndex matched, double value) const {
    double k;
    if (!MatchFloat(matched, &k)) return false;
    return base::bit_cast<uint64_t>(value) == base::bit_cast<uint64_t>(k) ||
           (std::isnan(k) && std::isnan(value));
  }

  bool MatchNaN(OpIndex matched) const {
    double k;
    return MatchFloat(matched, &k) && std::isnan(k);
  }

  bool MatchHeapConstant(OpIndex matched,
                         Handle<HeapObject>* tagged = nullptr) const {
    const ConstantOp* op = TryCast<ConstantOp>(matched);
    if (!op) return false;
    if (!(op->kind == any_of(ConstantOp::Kind::kHeapObject,
                             ConstantOp::Kind::kCompressedHeapObject))) {
      return false;
    }
    if (tagged) {
      *tagged = op->handle();
    }
    return true;
  }

  bool MatchIntegralWordConstant(OpIndex matched, WordRepresentation rep,
                                 uint64_t* unsigned_constant,
                                 int64_t* signed_constant = nullptr) const {
    const ConstantOp* op = TryCast<ConstantOp>(matched);
    if (!op) return false;
    switch (op->kind) {
      case ConstantOp::Kind::kWord32:
      case ConstantOp::Kind::kWord64:
      case ConstantOp::Kind::kRelocatableWasmCall:
      case ConstantOp::Kind::kRelocatableWasmStubCall:
        if (rep.value() == WordRepresentation::Word32()) {
          if (unsigned_constant) {
            *unsigned_constant = static_cast<uint32_t>(op->integral());
          }
          if (signed_constant) {
            *signed_constant = static_cast<int32_t>(op->signed_integral());
          }
          return true;
        } else if (rep.value() == WordRepresentation::Word64()) {
          if (unsigned_constant) {
            *unsigned_constant = op->integral();
          }
          if (signed_constant) {
            *signed_constant = op->signed_integral();
          }
          return true;
        }
        return false;
      default:
        return false;
    }
    UNREACHABLE();
  }

  bool MatchIntegralWordConstant(OpIndex matched, WordRepresentation rep,
                                 int64_t* signed_constant) const {
    return MatchIntegralWordConstant(matched, rep, nullptr, signed_constant);
  }

  bool MatchIntegralWord32Constant(OpIndex matched, uint32_t* constant) const {
    if (uint64_t value; MatchIntegralWordConstant(
            matched, WordRepresentation::Word32(), &value)) {
      *constant = static_cast<uint32_t>(value);
      return true;
    }
    return false;
  }

  bool MatchIntegralWord64Constant(OpIndex matched, uint64_t* constant) const {
    return MatchIntegralWordConstant(matched, WordRepresentation::Word64(),
                                     constant);
  }

  bool MatchIntegralWord32Constant(OpIndex matched, uint32_t constant) const {
    if (uint64_t value; MatchIntegralWordConstant(
            matched, WordRepresentation::Word32(), &value)) {
      return static_cast<uint32_t>(value) == constant;
    }
    return false;
  }

  bool MatchIntegralWord64Constant(OpIndex matched, int64_t* constant) const {
    return MatchIntegralWordConstant(matched, WordRepresentation::Word64(),
                                     constant);
  }

  bool MatchIntegralWord32Constant(OpIndex matched, int32_t* constant) const {
    if (int64_t value; MatchIntegralWordConstant(
            matched, WordRepresentation::Word32(), &value)) {
      *constant = static_cast<int32_t>(value);
      return true;
    }
    return false;
  }

  template <typename T = intptr_t>
  bool MatchIntegralWordPtrConstant(OpIndex matched, T* constant) const {
    if constexpr (Is64()) {
      static_assert(sizeof(T) == sizeof(int64_t));
      int64_t v;
      if (!MatchIntegralWord64Constant(matched, &v)) return false;
      *constant = static_cast<T>(v);
      return true;
    } else {
      static_assert(sizeof(T) == sizeof(int32_t));
      int32_t v;
      if (!MatchIntegralWord32Constant(matched, &v)) return false;
      *constant = static_cast<T>(v);
      return true;
    }
  }

  bool MatchSignedIntegralConstant(OpIndex matched, int64_t* constant) const {
    if (const ConstantOp* c = TryCast<ConstantOp>(matched)) {
      if (c->kind == ConstantOp::Kind::kWord32 ||
          c->kind == ConstantOp::Kind::kWord64) {
        *constant = c->signed_integral();
        return true;
      }
    }
    return false;
  }

  bool MatchUnsignedIntegralConstant(OpIndex matched,
                                     uint64_t* constant) const {
    if (const ConstantOp* c = TryCast<ConstantOp>(matched)) {
      if (c->kind == ConstantOp::Kind::kWord32 ||
          c->kind == ConstantOp::Kind::kWord64) {
        *constant = c->integral();
        return true;
      }
    }
    return false;
  }

  bool MatchExternalConstant(OpIndex matched,
                             ExternalReference* reference) const {
    const ConstantOp* op = TryCast<ConstantOp>(matched);
    if (!op) return false;
    if (op->kind != ConstantOp::Kind::kExternal) return false;
    *reference = op->storage.external;
    return true;
  }

  bool MatchWasmStubCallConstant(OpIndex matched, uint64_t* stub_id) const {
    const ConstantOp* op = TryCast<ConstantOp>(matched);
    if (!op) return false;
    if (op->kind != ConstantOp::Kind::kRelocatableWasmStubCall) {
      return false;
    }
    *stub_id = op->integral();
    return true;
  }

  bool MatchChange(OpIndex matched, OpIndex* input, ChangeOp::Kind kind,
                   RegisterRepresentation from,
                   RegisterRepresentation to) const {
    const ChangeOp* op = TryCast<ChangeOp>(matched);
    if (!op || op->kind != kind || op->from != from || op->to != to) {
      return false;
    }
    *input = op->input();
    return true;
  }

  template <class T, typename = std::enable_if_t<IsWord<T>()>>
  bool MatchWordBinop(OpIndex matched, V<T>* left, V<T>* right,
                      WordBinopOp::Kind* kind, WordRepresentation* rep) const {
    const WordBinopOp* op = TryCast<WordBinopOp>(matched);
    if (!op) return false;
    *kind = op->kind;
    *left = op->left<T>();
    *right = op->right<T>();
    if (rep) *rep = op->rep;
    return true;
  }

  template <class T, typename = std::enable_if_t<IsWord<T>()>>
  bool MatchWordBinop(OpIndex matched, V<T>* left, V<T>* right,
                      WordBinopOp::Kind kind, WordRepresentation rep) const {
    const WordBinopOp* op = TryCast<WordBinopOp>(matched);
    if (!op || kind != op->kind) {
      return false;
    }
    if (!(rep == op->rep ||
          (WordBinopOp::AllowsWord64ToWord32Truncation(kind) &&
           rep == WordRepresentation::Word32() &&
           op->rep == WordRepresentation::Word64()))) {
      return false;
    }
    *left = op->left<T>();
    *right = op->right<T>();
    return true;
  }

  template <class T, typename = std::enable_if_t<IsWord<T>()>>
  bool MatchWordAdd(OpIndex matched, V<T>* left, V<T>* right,
                    WordRepresentation rep) const {
    return MatchWordBinop(matched, left, right, WordBinopOp::Kind::kAdd, rep);
  }

  template <class T, typename = std::enable_if_t<IsWord<T>()>>
  bool MatchWordSub(OpIndex matched, V<T>* left, V<T>* right,
                    WordRepresentation rep) const {
    return MatchWordBinop(matched, left, right, WordBinopOp::Kind::kSub, rep);
  }

  template <class T, typename = std::enable_if_t<IsWord<T>()>>
  bool MatchWordMul(OpIndex matched, V<T>* left, V<T>* right,
                    WordRepresentation rep) const {
    return MatchWordBinop(matched, left, right, WordBinopOp::Kind::kMul, rep);
  }

  template <class T, typename = std::enable_if_t<IsWord<T>()>>
  bool MatchBitwiseAnd(OpIndex matched, V<T>* left, V<T>* right,
                       WordRepresentation rep) const {
    return MatchWordBinop(matched, left, right, WordBinopOp::Kind::kBitwiseAnd,
                          rep);
  }

  template <class T, typename = std::enable_if_t<IsWord<T>()>>
  bool MatchBitwiseAndWithConstant(OpIndex matched, V<T>* value,
                                   uint64_t* constant,
                                   WordRepresentation rep) const {
    V<T> left, right;
    if (!MatchBitwiseAnd(matched, &left, &right, rep)) return false;
    if (MatchIntegralWordConstant(right, rep, constant)) {
      *value = left;
      return true;
    } else if (MatchIntegralWordConstant(left, rep, constant)) {
      *value = right;
      return true;
    }
    return false;
  }

  template <typename T>
  bool MatchEqual(OpIndex matched, V<T>* left, V<T>* right) const {
    const ComparisonOp* op = TryCast<ComparisonOp>(matched);
    if (!op || op->kind != ComparisonOp::Kind::kEqual || op->rep != V<T>::rep) {
      return false;
    }
    *left = V<T>::Cast(op->left());
    *right = V<T>::Cast(op->right());
    return true;
  }

  bool MatchFloatUnary(OpIndex matched, V<Float>* input,
                       FloatUnaryOp::Kind kind, FloatRepresentation rep) const {
    const FloatUnaryOp* op = TryCast<FloatUnaryOp>(matched);
    if (!op || op->kind != kind || op->rep != rep) return false;
    *input = op->input();
    return true;
  }

  bool MatchFloatRoundDown(OpIndex matched, V<Float>* input,
                           FloatRepresentation rep) const {
    return MatchFloatUnary(matched, input, FloatUnaryOp::Kind::kRoundDown, rep);
  }

  bool MatchFloatBinary(OpIndex matched, V<Float>* left, V<Float>* right,
                        FloatBinopOp::Kind kind,
                        FloatRepresentation rep) const {
    const FloatBinopOp* op = TryCast<FloatBinopOp>(matched);
    if (!op || op->kind != kind || op->rep != rep) return false;
    *left = op->left();
    *right = op->right();
    return true;
  }

  bool MatchFloatSub(OpIndex matched, V<Float>* left, V<Float>* right,
                     FloatRepresentation rep) const {
    return MatchFloatBinary(matched, left, right, FloatBinopOp::Kind::kSub,
                            rep);
  }

  bool MatchConstantShift(OpIndex matched, OpIndex* input, ShiftOp::Kind* kind,
                          WordRepresentation* rep, int* amount) const {
    const ShiftOp* op = TryCast<ShiftOp>(matched);
    if (uint32_t rhs_constant;
        op && MatchIntegralWord32Constant(op->right(), &rhs_constant) &&
        rhs_constant < static_cast<uint64_t>(op->rep.bit_width())) {
      *input = op->left();
      *kind = op->kind;
      *rep = op->rep;
      *amount = static_cast<int>(rhs_constant);
      return true;
    }
    return false;
  }

  bool MatchConstantShift(OpIndex matched, OpIndex* input, ShiftOp::Kind kind,
                          WordRepresentation rep, int* amount) const {
    const ShiftOp* op = TryCast<ShiftOp>(matched);
    if (uint32_t rhs_constant;
        op && op->kind == kind &&
        (op->rep == rep || (ShiftOp::AllowsWord64ToWord32Truncation(kind) &&
                            rep == WordRepresentation::Word32() &&
                            op->rep == WordRepresentation::Word64())) &&
        MatchIntegralWord32Constant(op->right(), &rhs_constant) &&
        rhs_constant < static_cast<uint64_t>(rep.bit_width())) {
      *input = op->left();
      *amount = static_cast<int>(rhs_constant);
      return true;
    }
    return false;
  }

  bool MatchConstantRightShift(OpIndex matched, OpIndex* input,
                               WordRepresentation rep, int* amount) const {
    const ShiftOp* op = TryCast<ShiftOp>(matched);
    if (uint32_t rhs_constant;
        op && ShiftOp::IsRightShift(op->kind) && op->rep == rep &&
        MatchIntegralWord32Constant(op->right(), &rhs_constant) &&
        rhs_constant < static_cast<uint32_t>(rep.bit_width())) {
      *input = op->left();
      *amount = static_cast<int>(rhs_constant);
      return true;
    }
    return false;
  }

  bool MatchConstantLeftShift(OpIndex matched, OpIndex* input,
                              WordRepresentation rep, int* amount) const {
    const ShiftOp* op = TryCast<ShiftOp>(matched);
    if (uint32_t rhs_constant;
        op && op->kind == ShiftOp::Kind::kShiftLeft && op->rep == rep &&
        MatchIntegralWord32Constant(op->right(), &rhs_constant) &&
        rhs_constant < static_cast<uint32_t>(rep.bit_width())) {
      *input = op->left();
      *amount = static_cast<int>(rhs_constant);
      return true;
    }
    return false;
  }

  template <class T, typename = std::enable_if_t<IsWord<T>()>>
  bool MatchConstantShiftRightArithmeticShiftOutZeros(OpIndex matched,
                                                      V<T>* input,
                                                      WordRepresentation rep,
                                                      uint16_t* amount) const {
    const ShiftOp* op = TryCast<ShiftOp>(matched);
    if (uint32_t rhs_constant;
        op && op->kind == ShiftOp::Kind::kShiftRightArithmeticShiftOutZeros &&
        op->rep == rep &&
        MatchIntegralWord32Constant(op->right(), &rhs_constant) &&
        rhs_constant < static_cast<uint64_t>(rep.bit_width())) {
      *input = V<T>::Cast(op->left());
      *amount = static_cast<uint16_t>(rhs_constant);
      return true;
    }
    return false;
  }

  bool MatchPhi(OpIndex matched,
                std::optional<int> input_count = std::nullopt) const {
    if (const PhiOp* phi = TryCast<PhiOp>(matched)) {
      return !input_count.has_value() || phi->input_count == *input_count;
    }
    return false;
  }

  bool MatchPowerOfTwoWordConstant(OpIndex matched, int64_t* ret_cst,
                                   WordRepresentation rep) const {
    int64_t loc_cst;
    if (MatchIntegralWordConstant(matched, rep, &loc_cst)) {
      if (base::bits::IsPowerOfTwo(loc_cst)) {
        *ret_cst = loc_cst;
        return true;
      }
    }
    return false;
  }

  bool MatchPowerOfTwoWord32Constant(OpIndex matched, int32_t* divisor) const {
    int64_t cst;
    if (MatchPowerOfTwoWordConstant(matched, &cst,
                                    WordRepresentation::Word32())) {
      DCHECK_LE(cst, std::numeric_limits<int32_t>().max());
      *divisor = static_cast<int32_t>(cst);
      return true;
    }
    return false;
  }

 private:
  const Graph& graph_;
};

}  // namespace v8::internal::compiler::turboshaft

#endif  // V8_COMPILER_TURBOSHAFT_OPERATION_MATCHER_H_

"""

```