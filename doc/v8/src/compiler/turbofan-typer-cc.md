Response:
My thinking process to summarize the functionality of the provided C++ code snippet goes like this:

1. **Initial Scan and Keywords:** I first quickly scanned the code for prominent keywords and structure. I noticed:
    * `#include`: Indicating inclusion of header files, hinting at dependencies.
    * `namespace v8::internal::compiler`:  Clearly places this code within the V8 JavaScript engine's compiler.
    * `class Typer`: The central class, suggesting type analysis or assignment.
    * `Visitor`:  A nested class, likely implementing the visitor pattern for traversing the compiler's graph.
    * `Reduce(Node* node)`: A method within `Visitor`, a key aspect of graph traversal and modification.
    * `Type...`:  Many methods starting with `Type`, suggesting type determination logic for different operations.
    * Operator keywords (`IrOpcode::k...`):  Indicating the code deals with different intermediate representation (IR) operations.
    * Type-related names (`Type`, `TypeCache`, `OperationTyper`): Reinforces the focus on type analysis.

2. **Identifying the Core Purpose:** The name `Typer` is a strong clue. The code is clearly involved in determining or assigning types to nodes within the compiler's graph. The inclusion of `graph-reducer.h` and the `Visitor` class further point to a graph traversal and type inference mechanism.

3. **Dissecting the `Typer` Class:**
    * The constructor takes a `JSHeapBroker`, `Flags`, `Graph`, and `TickCounter`. This suggests interaction with the V8 heap, compiler flags, the compiler's intermediate representation, and performance tracking.
    * The `Decorator` nested class, applied to the `Graph`, hints at a mechanism for adding type information directly to the graph nodes.
    * The `Run()` methods are the entry points for the type analysis process. The version taking a `LoopVariableOptimizer` as an argument indicates consideration for loop-specific optimizations.

4. **Analyzing the `Visitor` Class:** This is where the detailed logic resides.
    * The `Reduce(Node* node)` method is the heart of the visitor pattern. It's called for each node in the graph.
    * The large `switch` statement in `TypeNode(Node* node)` is crucial. It maps different IR opcodes to specific type determination logic. The sheer number of cases indicates comprehensive handling of various compiler operations.
    * The helper methods like `Operand()`, `TypeUnaryOp()`, `TypeBinaryOp()`, and the type conversion functions (`ToPrimitive`, `ToBoolean`, `ToNumber`, etc.) show how types are extracted and manipulated.
    * The various `TypeObjectIs...` methods perform type checks, returning boolean types based on the input type.
    * The `UpdateType()` method manages the assignment or widening of types to graph nodes.

5. **Inferring High-Level Functionality:** Based on the code structure and the specific operations handled, I concluded that `turbofan-typer.cc` is responsible for:
    * **Type Inference:**  Determining the types of values produced by different operations in the Turbofan compiler's intermediate representation.
    * **Graph Decoration:**  Adding type information as annotations or properties to the nodes in the compiler's graph.
    * **Optimization:** Providing type information crucial for subsequent compiler optimizations. The interaction with `LoopVariableOptimizer` supports this.
    * **Correctness:** Ensuring that operations are performed on values of compatible types, which is fundamental for the correctness of generated code.

6. **Addressing Specific Questions (Based on the Code):**
    * **`.tq` extension:** The code explicitly uses `.cc`, so it's standard C++ and not Torque.
    * **Relationship to JavaScript:**  The code directly deals with JavaScript semantics by analyzing the types of values produced by JavaScript operations (e.g., addition, comparisons, type conversions). I looked for examples of JavaScript concepts being handled.
    * **Code Logic and Input/Output:** The `TypeNode` function with its `switch` statement provides clear examples. For instance, an input node representing an addition operation would have its output type determined by the types of its input operands. I could provide hypothetical input node types and the resulting output type.
    * **Common Programming Errors:**  Type errors are common in programming. This code helps prevent those errors at the compilation stage by ensuring type compatibility. I could give examples of JavaScript code that would lead to type errors if not handled correctly.

7. **Structuring the Summary:** Finally, I organized my findings into a concise summary that covers the key functionalities of the code, addressing the specific points raised in the prompt. I focused on the core purpose, key components, and the role it plays in the V8 compilation pipeline. I also made sure to answer the questions about file extensions, JavaScript relationship, and potential errors.
好的，根据你提供的 v8 源代码文件 `v8/src/compiler/turbofan-typer.cc` 的内容，以及你的问题，我们可以归纳一下它的功能：

**核心功能：类型推断和类型标注**

`v8/src/compiler/turbofan-typer.cc` 的主要功能是在 Turbofan 优化编译器中执行类型推断和类型标注。它遍历编译器构建的图（Graph），并为图中的每个节点（Node）确定其值的类型。

**具体功能点:**

1. **Graph 遍历和装饰 (Decoration):**
   - `Typer` 类继承自 `GraphDecorator`，这意味着它可以被添加到图的装饰器链中。
   - `Decorator::Decorate(Node* node)` 方法负责为图中的节点添加类型信息。只有在节点的输入类型已知的情况下，才会立即进行类型标注。对于其他情况，需要通过 `Run()` 方法进行固定点迭代来推断类型。

2. **类型推断核心逻辑 (`Visitor` 类):**
   - `Visitor` 类继承自 `Reducer`，实现了访问者模式，用于遍历和处理图中的节点。
   - `Reduce(Node* node)` 方法是访问者模式的核心，它针对每个节点调用 `TypeNode(node)` 来获取或更新节点的类型。
   - `TypeNode(Node* node)` 方法是一个巨大的 `switch` 语句，根据节点的操作码 (opcode) 调用不同的类型推断逻辑。这个方法涵盖了大量的 IR 操作符，包括：
     - **JavaScript 简单的一元和二元操作符 (JS_SIMPLE_UNOP_LIST, JS_SIMPLE_BINOP_LIST):**  例如 `!`, `+`, `-` 等。
     - **简化的数值和 BigInt 操作符 (SIMPLIFIED_NUMBER_UNOP_LIST, SIMPLIFIED_NUMBER_BINOP_LIST, SIMPLIFIED_BIGINT_...):** 这些是经过简化和优化的操作符。
     - **比较操作符 (SIMPLIFIED_COMPARE_BINOP_LIST):** 例如 `==`, `<`, `>` 等。
     - **对象操作符 (JS_OBJECT_OP_LIST):**  例如属性访问、对象创建等。
     - **上下文操作符 (JS_CONTEXT_OP_LIST):**  与作用域和闭包相关的操作。
     - **其他 JavaScript 操作符 (JS_OTHER_OP_LIST)。**
     - **控制流操作符 (COMMON_OP_LIST):** 例如 `Start`, `IfException`。
     - **大量被标记为 "IMPOSSIBLE" 的操作符:**  这可能意味着这些操作符的类型由其他阶段或特定的类型处理逻辑负责，或者在 `Typer` 的上下文中不直接推断其类型。

3. **类型计算辅助方法:**
   - 提供了大量的 `Type...` 方法，例如 `TypeStart`, `TypeJSAdd`, `TypeNumberAdd` 等，这些方法根据操作符的语义和输入类型来计算输出类型。
   - 提供了类型转换相关的静态方法，例如 `ToPrimitive`, `ToBoolean`, `ToNumber`, `ToString` 等，模拟 JavaScript 的类型转换行为。
   - 提供了类型检查相关的静态方法，例如 `ObjectIsArrayBufferView`, `ObjectIsBigInt`, `ObjectIsCallable` 等。

4. **与 `OperationTyper` 的交互:**
   - `Typer` 类包含一个 `OperationTyper` 实例 (`operation_typer_`)，它封装了更底层的类型操作逻辑。`Typer` 类中的许多类型计算方法会委托给 `operation_typer_` 来完成。

5. **支持循环变量优化 (`LoopVariableOptimizer`):**
   - `Run()` 方法可以接受一个 `LoopVariableOptimizer` 对象，这意味着类型推断过程可以与循环变量优化协同工作，以更精确地确定循环中变量的类型。

6. **固定点迭代 (`Run()` 方法):**
   - `Run()` 方法是启动类型推断过程的入口点。它使用 `GraphReducer` 来驱动 `Visitor` 遍历图，并重复迭代直到图中所有节点的类型都达到稳定状态（固定点）。

**关于你的问题：**

* **`.tq` 结尾：** 代码明确包含了 `#include` 和使用了 C++ 的语法，因此 `v8/src/compiler/turbofan-typer.cc` 是一个 **C++** 源代码文件，而不是 Torque (`.tq`) 文件。Torque 文件通常用于定义 V8 的内置函数和类型系统。

* **与 JavaScript 的功能关系：**  `turbofan-typer.cc` 与 JavaScript 的功能 **密切相关**。它的核心任务是理解和推断 JavaScript 代码在 Turbofan 编译器中被转换成的中间表示 (IR) 的类型。这包括：
    - 理解 JavaScript 的类型系统（包括原始类型、对象类型、特殊值如 `null` 和 `undefined`）。
    - 模拟 JavaScript 的类型转换规则。
    - 理解 JavaScript 操作符的语义，并根据操作数的类型推断结果类型。

**JavaScript 举例说明:**

假设有以下 JavaScript 代码：

```javascript
function add(a, b) {
  return a + b;
}

add(5, 10); // 调用时 a 和 b 是数字
add("hello", " world"); // 调用时 a 和 b 是字符串
```

当这段代码被 Turbofan 编译时，`turbofan-typer.cc` 会分析 `add` 函数内部 `a + b` 这个操作。

* **如果已知 `a` 和 `b` 是数字类型：** `TypeJSAdd(Type::Number(), Type::Number())` 或 `TypeNumberAdd(Type::Number(), Type::Number())` 方法会被调用，推断出结果类型是 `Type::Number()`。
* **如果已知 `a` 和 `b` 是字符串类型：** `TypeJSAdd(Type::String(), Type::String())` 方法会被调用，推断出结果类型是 `Type::String()`。
* **如果 `a` 和 `b` 的类型不确定 (可能是数字或字符串)：**  类型推断会更复杂，可能产生联合类型 (Union Type) 或者更宽泛的类型，例如 `Type::Any()` 或 `Type::Primitive()`，直到后续的优化阶段可以进一步缩小类型范围。

* **代码逻辑推理的假设输入与输出:**

   **假设输入：** 一个表示 JavaScript 加法操作的 IR 节点，其两个输入节点分别代表变量 `x` 和 `y`。假设 `x` 的类型被推断为 `Type::Number()`，`y` 的类型被推断为 `Type::Number()`。

   **输出：** `TypeNode` 方法针对该加法节点会返回 `Type::Number()`。

   **假设输入：** 一个表示 JavaScript 加法操作的 IR 节点，其两个输入节点分别代表变量 `str` 和 `num`。假设 `str` 的类型被推断为 `Type::String()`，`num` 的类型被推断为 `Type::Number()`。

   **输出：** `TypeNode` 方法针对该加法节点会调用类似 `TypeJSAdd(Type::String(), Type::Number())` 的逻辑，根据 JavaScript 的规则（数字会转换为字符串），返回 `Type::String()`。

* **涉及用户常见的编程错误举例:**

   类型推断有助于在编译时发现一些潜在的 JavaScript 编程错误，尽管 JavaScript 是一种动态类型语言。例如：

   ```javascript
   function multiply(a, b) {
     return a * b;
   }

   multiply(5, "hello"); // 运行时会得到 NaN
   ```

   在 Turbofan 的类型推断过程中，当分析 `a * b` 时，如果 `a` 的类型是 `Type::Number()`，但 `b` 的类型是 `Type::String()` (且不能确定其内容是否能转换为数字)，类型推断器可能会发出警告或者生成更保守的类型，因为 JavaScript 在这种情况下会尝试进行类型转换，结果可能不是预期的数字。虽然 `turbofan-typer.cc` 的主要职责是类型推断而不是直接报错，但它提供的类型信息对于后续的优化和代码生成阶段至关重要，这些阶段可能会插入类型检查或者采取不同的优化策略来处理这类潜在的类型不匹配。

**归纳一下 `v8/src/compiler/turbofan-typer.cc` 的功能（第 1 部分）：**

`v8/src/compiler/turbofan-typer.cc` 是 V8 引擎中 Turbofan 优化编译器的关键组件，负责对编译器构建的中间表示图进行类型推断和类型标注。它通过遍历图中的节点，并根据每个节点的语义和输入类型，计算出该节点的输出类型。这个过程对于后续的编译器优化至关重要，因为它提供了关于程序运行时值的宝贵信息，使得编译器可以生成更高效、更优化的机器代码。该文件实现了类型推断的核心逻辑，并与 V8 的类型系统和 JavaScript 的语义紧密相关。

### 提示词
```
这是目录为v8/src/compiler/turbofan-typer.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/turbofan-typer.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/compiler/turbofan-typer.h"

#include <iomanip>

#include "src/base/flags.h"
#include "src/codegen/tick-counter.h"
#include "src/compiler/common-operator.h"
#include "src/compiler/graph-reducer.h"
#include "src/compiler/js-heap-broker.h"
#include "src/compiler/js-operator.h"
#include "src/compiler/linkage.h"
#include "src/compiler/loop-variable-optimizer.h"
#include "src/compiler/node-properties.h"
#include "src/compiler/node.h"
#include "src/compiler/opcodes.h"
#include "src/compiler/operation-typer.h"
#include "src/compiler/simplified-operator.h"
#include "src/compiler/type-cache.h"
#include "src/objects/objects-inl.h"

namespace v8 {
namespace internal {
namespace compiler {

class Typer::Decorator final : public GraphDecorator {
 public:
  explicit Decorator(Typer* typer) : typer_(typer) {}
  void Decorate(Node* node) final;

 private:
  Typer* const typer_;
};

Typer::Typer(JSHeapBroker* broker, Flags flags, Graph* graph,
             TickCounter* tick_counter)
    : flags_(flags),
      graph_(graph),
      decorator_(nullptr),
      cache_(TypeCache::Get()),
      broker_(broker),
      operation_typer_(broker, zone()),
      tick_counter_(tick_counter) {
  singleton_false_ = operation_typer_.singleton_false();
  singleton_true_ = operation_typer_.singleton_true();

  decorator_ = zone()->New<Decorator>(this);
  graph_->AddDecorator(decorator_);
}

Typer::~Typer() { graph_->RemoveDecorator(decorator_); }

class Typer::Visitor : public Reducer {
 public:
  explicit Visitor(Typer* typer, LoopVariableOptimizer* induction_vars)
      : typer_(typer),
        induction_vars_(induction_vars),
        weakened_nodes_(typer->zone()) {}

  const char* reducer_name() const override { return "Typer"; }

  Reduction Reduce(Node* node) override {
    if (node->op()->ValueOutputCount() == 0) return NoChange();
    return UpdateType(node, TypeNode(node));
  }

  Type TypeNode(Node* node) {
    switch (node->opcode()) {
#define DECLARE_UNARY_CASE(x, ...) \
  case IrOpcode::k##x:             \
    return Type##x(Operand(node, 0));
      JS_SIMPLE_UNOP_LIST(DECLARE_UNARY_CASE)
      SIMPLIFIED_NUMBER_UNOP_LIST(DECLARE_UNARY_CASE)
      SIMPLIFIED_BIGINT_UNOP_LIST(DECLARE_UNARY_CASE)
      SIMPLIFIED_SPECULATIVE_NUMBER_UNOP_LIST(DECLARE_UNARY_CASE)
      SIMPLIFIED_SPECULATIVE_BIGINT_UNOP_LIST(DECLARE_UNARY_CASE)
      DECLARE_UNARY_CASE(ChangeUint32ToUint64)
#undef DECLARE_UNARY_CASE
#define DECLARE_BINARY_CASE(x, ...) \
  case IrOpcode::k##x:              \
    return Type##x(Operand(node, 0), Operand(node, 1));
      JS_SIMPLE_BINOP_LIST(DECLARE_BINARY_CASE)
      SIMPLIFIED_NUMBER_BINOP_LIST(DECLARE_BINARY_CASE)
      SIMPLIFIED_BIGINT_BINOP_LIST(DECLARE_BINARY_CASE)
      SIMPLIFIED_SPECULATIVE_NUMBER_BINOP_LIST(DECLARE_BINARY_CASE)
      SIMPLIFIED_SPECULATIVE_BIGINT_BINOP_LIST(DECLARE_BINARY_CASE)
      TYPER_SUPPORTED_MACHINE_BINOP_LIST(DECLARE_BINARY_CASE)
#undef DECLARE_BINARY_CASE
#define DECLARE_OTHER_CASE(x, ...) \
  case IrOpcode::k##x:             \
    return Type##x(node);
      DECLARE_OTHER_CASE(Start)
      DECLARE_OTHER_CASE(IfException)
      COMMON_OP_LIST(DECLARE_OTHER_CASE)
      SIMPLIFIED_COMPARE_BINOP_LIST(DECLARE_OTHER_CASE)
      SIMPLIFIED_OTHER_OP_LIST(DECLARE_OTHER_CASE)
      JS_OBJECT_OP_LIST(DECLARE_OTHER_CASE)
      JS_CONTEXT_OP_LIST(DECLARE_OTHER_CASE)
      JS_OTHER_OP_LIST(DECLARE_OTHER_CASE)
#undef DECLARE_OTHER_CASE
#define DECLARE_IMPOSSIBLE_CASE(x, ...) case IrOpcode::k##x:
      DECLARE_IMPOSSIBLE_CASE(Loop)
      DECLARE_IMPOSSIBLE_CASE(Branch)
      DECLARE_IMPOSSIBLE_CASE(IfTrue)
      DECLARE_IMPOSSIBLE_CASE(IfFalse)
      DECLARE_IMPOSSIBLE_CASE(IfSuccess)
      DECLARE_IMPOSSIBLE_CASE(Switch)
      DECLARE_IMPOSSIBLE_CASE(IfValue)
      DECLARE_IMPOSSIBLE_CASE(IfDefault)
      DECLARE_IMPOSSIBLE_CASE(Merge)
      DECLARE_IMPOSSIBLE_CASE(Deoptimize)
      DECLARE_IMPOSSIBLE_CASE(DeoptimizeIf)
      DECLARE_IMPOSSIBLE_CASE(DeoptimizeUnless)
      DECLARE_IMPOSSIBLE_CASE(TrapIf)
      DECLARE_IMPOSSIBLE_CASE(TrapUnless)
      DECLARE_IMPOSSIBLE_CASE(Assert)
      DECLARE_IMPOSSIBLE_CASE(Return)
      DECLARE_IMPOSSIBLE_CASE(TailCall)
      DECLARE_IMPOSSIBLE_CASE(Terminate)
      DECLARE_IMPOSSIBLE_CASE(Throw)
      DECLARE_IMPOSSIBLE_CASE(End)
      SIMPLIFIED_CHANGE_OP_LIST(DECLARE_IMPOSSIBLE_CASE)
      SIMPLIFIED_CHECKED_OP_LIST(DECLARE_IMPOSSIBLE_CASE)
      IF_WASM(SIMPLIFIED_WASM_OP_LIST, DECLARE_IMPOSSIBLE_CASE)
      MACHINE_SIMD128_OP_LIST(DECLARE_IMPOSSIBLE_CASE)
      IF_WASM(MACHINE_SIMD256_OP_LIST, DECLARE_IMPOSSIBLE_CASE)
      MACHINE_UNOP_32_LIST(DECLARE_IMPOSSIBLE_CASE)
      DECLARE_IMPOSSIBLE_CASE(Word32Xor)
      DECLARE_IMPOSSIBLE_CASE(Word32Sar)
      DECLARE_IMPOSSIBLE_CASE(Word32Rol)
      DECLARE_IMPOSSIBLE_CASE(Word32Ror)
      DECLARE_IMPOSSIBLE_CASE(Int32AddWithOverflow)
      DECLARE_IMPOSSIBLE_CASE(Int32SubWithOverflow)
      DECLARE_IMPOSSIBLE_CASE(Int32Mul)
      DECLARE_IMPOSSIBLE_CASE(Int32MulWithOverflow)
      DECLARE_IMPOSSIBLE_CASE(Int32MulHigh)
      DECLARE_IMPOSSIBLE_CASE(Int32Div)
      DECLARE_IMPOSSIBLE_CASE(Int32Mod)
      DECLARE_IMPOSSIBLE_CASE(Uint32Mod)
      DECLARE_IMPOSSIBLE_CASE(Uint32MulHigh)
      DECLARE_IMPOSSIBLE_CASE(Word64Or)
      DECLARE_IMPOSSIBLE_CASE(Word64Xor)
      DECLARE_IMPOSSIBLE_CASE(Word64Sar)
      DECLARE_IMPOSSIBLE_CASE(Word64Rol)
      DECLARE_IMPOSSIBLE_CASE(Word64Ror)
      DECLARE_IMPOSSIBLE_CASE(Word64RolLowerable)
      DECLARE_IMPOSSIBLE_CASE(Word64RorLowerable)
      DECLARE_IMPOSSIBLE_CASE(Int64AddWithOverflow)
      DECLARE_IMPOSSIBLE_CASE(Int64SubWithOverflow)
      DECLARE_IMPOSSIBLE_CASE(Int64Mul)
      DECLARE_IMPOSSIBLE_CASE(Int64MulHigh)
      DECLARE_IMPOSSIBLE_CASE(Int64MulWithOverflow)
      DECLARE_IMPOSSIBLE_CASE(Int64Div)
      DECLARE_IMPOSSIBLE_CASE(Int64Mod)
      DECLARE_IMPOSSIBLE_CASE(Uint64Mod)
      DECLARE_IMPOSSIBLE_CASE(Uint64MulHigh)
      DECLARE_IMPOSSIBLE_CASE(Word64Equal)
      DECLARE_IMPOSSIBLE_CASE(Int32LessThan)
      DECLARE_IMPOSSIBLE_CASE(Int64LessThan)
      DECLARE_IMPOSSIBLE_CASE(Int64LessThanOrEqual)
      DECLARE_IMPOSSIBLE_CASE(Float32Equal)
      DECLARE_IMPOSSIBLE_CASE(Float32LessThan)
      DECLARE_IMPOSSIBLE_CASE(Float32LessThanOrEqual)
      DECLARE_IMPOSSIBLE_CASE(Float64Equal)
      DECLARE_IMPOSSIBLE_CASE(Float64LessThan)
      DECLARE_IMPOSSIBLE_CASE(Float64LessThanOrEqual)
      MACHINE_FLOAT32_BINOP_LIST(DECLARE_IMPOSSIBLE_CASE)
      MACHINE_FLOAT32_UNOP_LIST(DECLARE_IMPOSSIBLE_CASE)
      MACHINE_FLOAT64_BINOP_LIST(DECLARE_IMPOSSIBLE_CASE)
      MACHINE_FLOAT64_UNOP_LIST(DECLARE_IMPOSSIBLE_CASE)
      MACHINE_ATOMIC_OP_LIST(DECLARE_IMPOSSIBLE_CASE)
      DECLARE_IMPOSSIBLE_CASE(AbortCSADcheck)
      DECLARE_IMPOSSIBLE_CASE(DebugBreak)
      DECLARE_IMPOSSIBLE_CASE(Comment)
      DECLARE_IMPOSSIBLE_CASE(LoadImmutable)
      DECLARE_IMPOSSIBLE_CASE(StorePair)
      DECLARE_IMPOSSIBLE_CASE(Store)
      DECLARE_IMPOSSIBLE_CASE(StoreIndirectPointer)
      DECLARE_IMPOSSIBLE_CASE(StackSlot)
      DECLARE_IMPOSSIBLE_CASE(Word32Popcnt)
      DECLARE_IMPOSSIBLE_CASE(Word64Popcnt)
      DECLARE_IMPOSSIBLE_CASE(Word64Clz)
      DECLARE_IMPOSSIBLE_CASE(Word64Ctz)
      DECLARE_IMPOSSIBLE_CASE(Word64ClzLowerable)
      DECLARE_IMPOSSIBLE_CASE(Word64CtzLowerable)
      DECLARE_IMPOSSIBLE_CASE(Word64ReverseBits)
      DECLARE_IMPOSSIBLE_CASE(Word64ReverseBytes)
      DECLARE_IMPOSSIBLE_CASE(Simd128ReverseBytes)
      DECLARE_IMPOSSIBLE_CASE(Int64AbsWithOverflow)
      DECLARE_IMPOSSIBLE_CASE(BitcastTaggedToWord)
      DECLARE_IMPOSSIBLE_CASE(BitcastTaggedToWordForTagAndSmiBits)
      DECLARE_IMPOSSIBLE_CASE(BitcastWordToTagged)
      DECLARE_IMPOSSIBLE_CASE(BitcastWordToTaggedSigned)
      DECLARE_IMPOSSIBLE_CASE(TruncateFloat64ToWord32)
      DECLARE_IMPOSSIBLE_CASE(ChangeFloat32ToFloat64)
      DECLARE_IMPOSSIBLE_CASE(ChangeFloat64ToInt32)
      DECLARE_IMPOSSIBLE_CASE(ChangeFloat64ToInt64)
      DECLARE_IMPOSSIBLE_CASE(ChangeFloat64ToUint32)
      DECLARE_IMPOSSIBLE_CASE(ChangeFloat64ToUint64)
      DECLARE_IMPOSSIBLE_CASE(Float64SilenceNaN)
      DECLARE_IMPOSSIBLE_CASE(TruncateFloat64ToInt64)
      DECLARE_IMPOSSIBLE_CASE(TruncateFloat64ToUint32)
      DECLARE_IMPOSSIBLE_CASE(TruncateFloat32ToInt32)
      DECLARE_IMPOSSIBLE_CASE(TruncateFloat32ToUint32)
      DECLARE_IMPOSSIBLE_CASE(TryTruncateFloat32ToInt64)
      DECLARE_IMPOSSIBLE_CASE(TryTruncateFloat64ToInt64)
      DECLARE_IMPOSSIBLE_CASE(TryTruncateFloat32ToUint64)
      DECLARE_IMPOSSIBLE_CASE(TryTruncateFloat64ToUint64)
      DECLARE_IMPOSSIBLE_CASE(TryTruncateFloat64ToInt32)
      DECLARE_IMPOSSIBLE_CASE(TryTruncateFloat64ToUint32)
      DECLARE_IMPOSSIBLE_CASE(ChangeInt32ToFloat64)
      DECLARE_IMPOSSIBLE_CASE(BitcastWord32ToWord64)
      DECLARE_IMPOSSIBLE_CASE(ChangeInt32ToInt64)
      DECLARE_IMPOSSIBLE_CASE(ChangeInt64ToFloat64)
      DECLARE_IMPOSSIBLE_CASE(ChangeUint32ToFloat64)
      DECLARE_IMPOSSIBLE_CASE(TruncateFloat64ToFloat32)
      DECLARE_IMPOSSIBLE_CASE(TruncateFloat64ToFloat16RawBits)
      DECLARE_IMPOSSIBLE_CASE(TruncateInt64ToInt32)
      DECLARE_IMPOSSIBLE_CASE(RoundFloat64ToInt32)
      DECLARE_IMPOSSIBLE_CASE(RoundInt32ToFloat32)
      DECLARE_IMPOSSIBLE_CASE(RoundInt64ToFloat32)
      DECLARE_IMPOSSIBLE_CASE(RoundInt64ToFloat64)
      DECLARE_IMPOSSIBLE_CASE(RoundUint32ToFloat32)
      DECLARE_IMPOSSIBLE_CASE(RoundUint64ToFloat32)
      DECLARE_IMPOSSIBLE_CASE(RoundUint64ToFloat64)
      DECLARE_IMPOSSIBLE_CASE(BitcastFloat32ToInt32)
      DECLARE_IMPOSSIBLE_CASE(BitcastFloat64ToInt64)
      DECLARE_IMPOSSIBLE_CASE(BitcastInt32ToFloat32)
      DECLARE_IMPOSSIBLE_CASE(BitcastInt64ToFloat64)
      DECLARE_IMPOSSIBLE_CASE(Float64ExtractLowWord32)
      DECLARE_IMPOSSIBLE_CASE(Float64ExtractHighWord32)
      DECLARE_IMPOSSIBLE_CASE(Float64InsertLowWord32)
      DECLARE_IMPOSSIBLE_CASE(Float64InsertHighWord32)
      DECLARE_IMPOSSIBLE_CASE(Word32Select)
      DECLARE_IMPOSSIBLE_CASE(Word64Select)
      DECLARE_IMPOSSIBLE_CASE(Float32Select)
      DECLARE_IMPOSSIBLE_CASE(Float64Select)
      DECLARE_IMPOSSIBLE_CASE(LoadStackCheckOffset)
      DECLARE_IMPOSSIBLE_CASE(LoadFramePointer)
      IF_WASM(DECLARE_IMPOSSIBLE_CASE, LoadStackPointer)
      IF_WASM(DECLARE_IMPOSSIBLE_CASE, SetStackPointer)
      DECLARE_IMPOSSIBLE_CASE(LoadParentFramePointer)
      DECLARE_IMPOSSIBLE_CASE(LoadRootRegister)
      DECLARE_IMPOSSIBLE_CASE(UnalignedLoad)
      DECLARE_IMPOSSIBLE_CASE(UnalignedStore)
      DECLARE_IMPOSSIBLE_CASE(Int32PairAdd)
      DECLARE_IMPOSSIBLE_CASE(Int32PairSub)
      DECLARE_IMPOSSIBLE_CASE(Int32PairMul)
      DECLARE_IMPOSSIBLE_CASE(Word32PairShl)
      DECLARE_IMPOSSIBLE_CASE(Word32PairShr)
      DECLARE_IMPOSSIBLE_CASE(Word32PairSar)
      DECLARE_IMPOSSIBLE_CASE(ProtectedLoad)
      DECLARE_IMPOSSIBLE_CASE(ProtectedStore)
      DECLARE_IMPOSSIBLE_CASE(LoadTrapOnNull)
      DECLARE_IMPOSSIBLE_CASE(StoreTrapOnNull)
      DECLARE_IMPOSSIBLE_CASE(MemoryBarrier)
      DECLARE_IMPOSSIBLE_CASE(SignExtendWord8ToInt32)
      DECLARE_IMPOSSIBLE_CASE(SignExtendWord16ToInt32)
      DECLARE_IMPOSSIBLE_CASE(SignExtendWord8ToInt64)
      DECLARE_IMPOSSIBLE_CASE(SignExtendWord16ToInt64)
      DECLARE_IMPOSSIBLE_CASE(SignExtendWord32ToInt64)
      DECLARE_IMPOSSIBLE_CASE(StackPointerGreaterThan)
      DECLARE_IMPOSSIBLE_CASE(TraceInstruction)

#undef DECLARE_IMPOSSIBLE_CASE
      UNREACHABLE();
    }
  }

  Type TypeConstant(Handle<Object> value);

  bool InductionVariablePhiTypeIsPrefixedPoint(
      InductionVariable* induction_var);

 private:
  Typer* typer_;
  LoopVariableOptimizer* induction_vars_;
  ZoneSet<NodeId> weakened_nodes_;

#define DECLARE_METHOD(x, ...) inline Type Type##x(Node* node);
  DECLARE_METHOD(Start)
  DECLARE_METHOD(IfException)
  COMMON_OP_LIST(DECLARE_METHOD)
  SIMPLIFIED_COMPARE_BINOP_LIST(DECLARE_METHOD)
  SIMPLIFIED_OTHER_OP_LIST(DECLARE_METHOD)
  JS_OBJECT_OP_LIST(DECLARE_METHOD)
  JS_CONTEXT_OP_LIST(DECLARE_METHOD)
  JS_OTHER_OP_LIST(DECLARE_METHOD)
#undef DECLARE_METHOD
#define DECLARE_METHOD(x, ...) inline Type Type##x(Type input);
  JS_SIMPLE_UNOP_LIST(DECLARE_METHOD)
#undef DECLARE_METHOD

  Type TypeOrNone(Node* node) {
    return NodeProperties::IsTyped(node) ? NodeProperties::GetType(node)
                                         : Type::None();
  }

  Type Operand(Node* node, int i) {
    Node* operand_node = NodeProperties::GetValueInput(node, i);
    return TypeOrNone(operand_node);
  }

  Type Weaken(Node* node, Type current_type, Type previous_type);

  Zone* zone() { return typer_->zone(); }
  Graph* graph() { return typer_->graph(); }
  JSHeapBroker* broker() { return typer_->broker(); }

  void SetWeakened(NodeId node_id) { weakened_nodes_.insert(node_id); }
  bool IsWeakened(NodeId node_id) {
    return weakened_nodes_.find(node_id) != weakened_nodes_.end();
  }

  using UnaryTyperFun = Type (*)(Type, Typer* t);
  using BinaryTyperFun = Type (*)(Type, Type, Typer* t);

  inline Type TypeUnaryOp(Node* node, UnaryTyperFun);
  inline Type TypeBinaryOp(Node* node, BinaryTyperFun);
  inline Type TypeUnaryOp(Type input, UnaryTyperFun);
  inline Type TypeBinaryOp(Type left, Type right, BinaryTyperFun);

  static Type BinaryNumberOpTyper(Type lhs, Type rhs, Typer* t,
                                  BinaryTyperFun f);

  enum ComparisonOutcomeFlags {
    kComparisonTrue = 1,
    kComparisonFalse = 2,
    kComparisonUndefined = 4
  };
  using ComparisonOutcome = base::Flags<ComparisonOutcomeFlags>;

  static ComparisonOutcome Invert(ComparisonOutcome, Typer*);
  static Type FalsifyUndefined(ComparisonOutcome, Typer*);

  static Type BitwiseNot(Type, Typer*);
  static Type Decrement(Type, Typer*);
  static Type Increment(Type, Typer*);
  static Type Negate(Type, Typer*);

  static Type ToPrimitive(Type, Typer*);
  static Type ToBoolean(Type, Typer*);
  static Type ToInteger(Type, Typer*);
  static Type ToLength(Type, Typer*);
  static Type ToName(Type, Typer*);
  static Type ToNumber(Type, Typer*);
  static Type ToNumberConvertBigInt(Type, Typer*);
  static Type ToBigInt(Type, Typer*);
  static Type ToBigIntConvertNumber(Type, Typer*);
  static Type ToNumeric(Type, Typer*);
  static Type ToObject(Type, Typer*);
  static Type ToString(Type, Typer*);
#define DECLARE_METHOD(Name)               \
  static Type Name(Type type, Typer* t) {  \
    return t->operation_typer_.Name(type); \
  }
  SIMPLIFIED_NUMBER_UNOP_LIST(DECLARE_METHOD)
  SIMPLIFIED_BIGINT_UNOP_LIST(DECLARE_METHOD)
  SIMPLIFIED_SPECULATIVE_NUMBER_UNOP_LIST(DECLARE_METHOD)
  SIMPLIFIED_SPECULATIVE_BIGINT_UNOP_LIST(DECLARE_METHOD)
  DECLARE_METHOD(ChangeUint32ToUint64)
#undef DECLARE_METHOD
#define DECLARE_METHOD(Name)                       \
  static Type Name(Type lhs, Type rhs, Typer* t) { \
    return t->operation_typer_.Name(lhs, rhs);     \
  }
  SIMPLIFIED_NUMBER_BINOP_LIST(DECLARE_METHOD)
  SIMPLIFIED_BIGINT_BINOP_LIST(DECLARE_METHOD)
  SIMPLIFIED_SPECULATIVE_NUMBER_BINOP_LIST(DECLARE_METHOD)
  SIMPLIFIED_SPECULATIVE_BIGINT_BINOP_LIST(DECLARE_METHOD)
  TYPER_SUPPORTED_MACHINE_BINOP_LIST(DECLARE_METHOD)
#undef DECLARE_METHOD
#define DECLARE_METHOD(Name, ...)                  \
  inline Type Type##Name(Type left, Type right) {  \
    return TypeBinaryOp(left, right, Name##Typer); \
  }
  JS_SIMPLE_BINOP_LIST(DECLARE_METHOD)
#undef DECLARE_METHOD
#define DECLARE_METHOD(Name, ...)                 \
  inline Type Type##Name(Type left, Type right) { \
    return TypeBinaryOp(left, right, Name);       \
  }
  SIMPLIFIED_NUMBER_BINOP_LIST(DECLARE_METHOD)
  SIMPLIFIED_BIGINT_BINOP_LIST(DECLARE_METHOD)
  SIMPLIFIED_SPECULATIVE_NUMBER_BINOP_LIST(DECLARE_METHOD)
  SIMPLIFIED_SPECULATIVE_BIGINT_BINOP_LIST(DECLARE_METHOD)
  TYPER_SUPPORTED_MACHINE_BINOP_LIST(DECLARE_METHOD)
#undef DECLARE_METHOD
#define DECLARE_METHOD(Name, ...) \
  inline Type Type##Name(Type input) { return TypeUnaryOp(input, Name); }
  SIMPLIFIED_NUMBER_UNOP_LIST(DECLARE_METHOD)
  SIMPLIFIED_BIGINT_UNOP_LIST(DECLARE_METHOD)
  SIMPLIFIED_SPECULATIVE_NUMBER_UNOP_LIST(DECLARE_METHOD)
  SIMPLIFIED_SPECULATIVE_BIGINT_UNOP_LIST(DECLARE_METHOD)
  DECLARE_METHOD(ChangeUint32ToUint64)
#undef DECLARE_METHOD
  static Type ObjectIsArrayBufferView(Type, Typer*);
  static Type ObjectIsBigInt(Type, Typer*);
  static Type ObjectIsCallable(Type, Typer*);
  static Type ObjectIsConstructor(Type, Typer*);
  static Type ObjectIsDetectableCallable(Type, Typer*);
  static Type ObjectIsMinusZero(Type, Typer*);
  static Type NumberIsMinusZero(Type, Typer*);
  static Type ObjectIsNaN(Type, Typer*);
  static Type NumberIsNaN(Type, Typer*);
  static Type ObjectIsNonCallable(Type, Typer*);
  static Type ObjectIsNumber(Type, Typer*);
  static Type ObjectIsReceiver(Type, Typer*);
  static Type ObjectIsSmi(Type, Typer*);
  static Type ObjectIsString(Type, Typer*);
  static Type ObjectIsSymbol(Type, Typer*);
  static Type ObjectIsUndetectable(Type, Typer*);

  static ComparisonOutcome JSCompareTyper(Type, Type, Typer*);
  static ComparisonOutcome NumberCompareTyper(Type, Type, Typer*);

#define DECLARE_METHOD(x, ...) static Type x##Typer(Type, Type, Typer*);
  JS_SIMPLE_BINOP_LIST(DECLARE_METHOD)
#undef DECLARE_METHOD

  static Type JSCallTyper(Type, Typer*);

  static Type NumberEqualTyper(Type, Type, Typer*);
  static Type NumberLessThanTyper(Type, Type, Typer*);
  static Type NumberLessThanOrEqualTyper(Type, Type, Typer*);
  static Type BigIntCompareTyper(Type, Type, Typer*);
  static Type ReferenceEqualTyper(Type, Type, Typer*);
  static Type SameValueTyper(Type, Type, Typer*);
  static Type SameValueNumbersOnlyTyper(Type, Type, Typer*);
  static Type StringFromSingleCharCodeTyper(Type, Typer*);
  static Type StringFromSingleCodePointTyper(Type, Typer*);

  Reduction UpdateType(Node* node, Type current) {
    if (NodeProperties::IsTyped(node)) {
      // Widen the type of a previously typed node.
      Type previous = NodeProperties::GetType(node);
      if (node->opcode() == IrOpcode::kPhi ||
          node->opcode() == IrOpcode::kInductionVariablePhi) {
        // Speed up termination in the presence of range types:
        current = Weaken(node, current, previous);
      }

      if (V8_UNLIKELY(!previous.Is(current))) {
        AllowHandleDereference allow;
        std::ostringstream ostream;
        node->Print(ostream);
        FATAL("UpdateType error for node %s", ostream.str().c_str());
      }

      NodeProperties::SetType(node, current);
      if (!current.Is(previous)) {
        // If something changed, revisit all uses.
        return Changed(node);
      }
      return NoChange();
    } else {
      // No previous type, simply update the type.
      NodeProperties::SetType(node, current);
      return Changed(node);
    }
  }
};

void Typer::Run() { Run(NodeVector(zone()), nullptr); }

void Typer::Run(const NodeVector& roots,
                LoopVariableOptimizer* induction_vars) {
  if (induction_vars != nullptr) {
    induction_vars->ChangeToInductionVariablePhis();
  }
  Visitor visitor(this, induction_vars);
  GraphReducer graph_reducer(zone(), graph(), tick_counter_, broker());
  graph_reducer.AddReducer(&visitor);
  for (Node* const root : roots) graph_reducer.ReduceNode(root);
  graph_reducer.ReduceGraph();

  if (induction_vars != nullptr) {
    // Validate the types computed by TypeInductionVariablePhi.
    for (auto entry : induction_vars->induction_variables()) {
      InductionVariable* induction_var = entry.second;
      if (induction_var->phi()->opcode() == IrOpcode::kInductionVariablePhi) {
        CHECK(visitor.InductionVariablePhiTypeIsPrefixedPoint(induction_var));
      }
    }

    induction_vars->ChangeToPhisAndInsertGuards();
  }
}

void Typer::Decorator::Decorate(Node* node) {
  if (node->op()->ValueOutputCount() > 0) {
    // Only eagerly type-decorate nodes with known input types.
    // Other cases will generally require a proper fixpoint iteration with Run.
    bool is_typed = NodeProperties::IsTyped(node);
    if (is_typed || NodeProperties::AllValueInputsAreTyped(node)) {
      Visitor typing(typer_, nullptr);
      Type type = typing.TypeNode(node);
      if (is_typed) {
        type = Type::Intersect(type, NodeProperties::GetType(node),
                               typer_->zone());
      }
      NodeProperties::SetType(node, type);
    }
  }
}

// -----------------------------------------------------------------------------

// Helper functions that lift a function f on types to a function on bounds,
// and uses that to type the given node.  Note that f is never called with None
// as an argument.

Type Typer::Visitor::TypeUnaryOp(Node* node, UnaryTyperFun f) {
  Type input = Operand(node, 0);
  return TypeUnaryOp(input, f);
}

Type Typer::Visitor::TypeUnaryOp(Type input, UnaryTyperFun f) {
  return input.IsNone() ? Type::None() : f(input, typer_);
}

Type Typer::Visitor::TypeBinaryOp(Node* node, BinaryTyperFun f) {
  Type left = Operand(node, 0);
  Type right = Operand(node, 1);
  return TypeBinaryOp(left, right, f);
}

Type Typer::Visitor::TypeBinaryOp(Type left, Type right, BinaryTyperFun f) {
  return left.IsNone() || right.IsNone() ? Type::None()
                                         : f(left, right, typer_);
}

Type Typer::Visitor::BinaryNumberOpTyper(Type lhs, Type rhs, Typer* t,
                                         BinaryTyperFun f) {
  lhs = ToNumeric(lhs, t);
  rhs = ToNumeric(rhs, t);
  if (lhs.IsNone() || rhs.IsNone()) return Type::None();

  bool lhs_is_number = lhs.Is(Type::Number());
  bool rhs_is_number = rhs.Is(Type::Number());
  if (lhs_is_number && rhs_is_number) {
    return f(lhs, rhs, t);
  }
  // In order to maintain monotonicity, the following two conditions are
  // intentionally asymmetric.
  if (lhs_is_number) {
    return Type::Number();
  }
  if (lhs.Is(Type::BigInt())) {
    return Type::BigInt();
  }
  return Type::Numeric();
}

Typer::Visitor::ComparisonOutcome Typer::Visitor::Invert(
    ComparisonOutcome outcome, Typer* t) {
  ComparisonOutcome result(0);
  if ((outcome & kComparisonUndefined) != 0) result |= kComparisonUndefined;
  if ((outcome & kComparisonTrue) != 0) result |= kComparisonFalse;
  if ((outcome & kComparisonFalse) != 0) result |= kComparisonTrue;
  return result;
}

Type Typer::Visitor::FalsifyUndefined(ComparisonOutcome outcome, Typer* t) {
  if (outcome == 0) return Type::None();
  if ((outcome & kComparisonFalse) != 0 ||
      (outcome & kComparisonUndefined) != 0) {
    return (outcome & kComparisonTrue) != 0 ? Type::Boolean()
                                            : t->singleton_false_;
  }
  DCHECK_NE(0, outcome & kComparisonTrue);
  return t->singleton_true_;
}

Type Typer::Visitor::BitwiseNot(Type type, Typer* t) {
  type = ToNumeric(type, t);
  if (type.Is(Type::Number())) {
    return NumberBitwiseXor(type, t->cache_->kSingletonMinusOne, t);
  }
  if (type.Is(Type::BigInt())) {
    return Type::BigInt();
  }
  return Type::Numeric();
}

Type Typer::Visitor::Decrement(Type type, Typer* t) {
  type = ToNumeric(type, t);
  if (type.Is(Type::Number())) {
    return NumberSubtract(type, t->cache_->kSingletonOne, t);
  }
  if (type.Is(Type::BigInt())) {
    return Type::BigInt();
  }
  return Type::Numeric();
}

Type Typer::Visitor::Increment(Type type, Typer* t) {
  type = ToNumeric(type, t);
  if (type.Is(Type::Number())) {
    return NumberAdd(type, t->cache_->kSingletonOne, t);
  }
  if (type.Is(Type::BigInt())) {
    return Type::BigInt();
  }
  return Type::Numeric();
}

Type Typer::Visitor::Negate(Type type, Typer* t) {
  type = ToNumeric(type, t);
  if (type.Is(Type::Number())) {
    return NumberMultiply(type, t->cache_->kSingletonMinusOne, t);
  }
  if (type.Is(Type::BigInt())) {
    return Type::BigInt();
  }
  return Type::Numeric();
}

// Type conversion.

Type Typer::Visitor::ToPrimitive(Type type, Typer* t) {
  if (type.Is(Type::Primitive()) && !type.Maybe(Type::Receiver())) {
    return type;
  }
  return Type::Primitive();
}

Type Typer::Visitor::ToBoolean(Type type, Typer* t) {
  return t->operation_typer()->ToBoolean(type);
}

// static
Type Typer::Visitor::ToInteger(Type type, Typer* t) {
  // ES6 section 7.1.4 ToInteger ( argument )
  type = ToNumber(type, t);
  if (type.Is(t->cache_->kInteger)) return type;
  if (type.Is(t->cache_->kIntegerOrMinusZeroOrNaN)) {
    return Type::Union(Type::Intersect(type, t->cache_->kInteger, t->zone()),
                       t->cache_->kSingletonZero, t->zone());
  }
  return t->cache_->kInteger;
}

// static
Type Typer::Visitor::ToLength(Type type, Typer* t) {
  // ES6 section 7.1.15 ToLength ( argument )
  type = ToInteger(type, t);
  if (type.IsNone()) return type;
  double min = type.Min();
  double max = type.Max();
  if (max <= 0.0) {
    return Type::Constant(0, t->zone());
  }
  if (min >= kMaxSafeInteger) {
    return Type::Constant(kMaxSafeInteger, t->zone());
  }
  if (min <= 0.0) min = 0.0;
  if (max >= kMaxSafeInteger) max = kMaxSafeInteger;
  return Type::Range(min, max, t->zone());
}

// static
Type Typer::Visitor::ToName(Type type, Typer* t) {
  // ES6 section 7.1.14 ToPropertyKey ( argument )
  type = ToPrimitive(type, t);
  if (type.Is(Type::Name())) return type;
  if (type.Maybe(Type::Symbol())) return Type::Name();
  return ToString(type, t);
}

// static
Type Typer::Visitor::ToNumber(Type type, Typer* t) {
  return t->operation_typer_.ToNumber(type);
}

// static
Type Typer::Visitor::ToNumberConvertBigInt(Type type, Typer* t) {
  return t->operation_typer_.ToNumberConvertBigInt(type);
}

// static
Type Typer::Visitor::ToBigInt(Type type, Typer* t) {
  return t->operation_typer_.ToBigInt(type);
}

// static
Type Typer::Visitor::ToBigIntConvertNumber(Type type, Typer* t) {
  return t->operation_typer_.ToBigIntConvertNumber(type);
}

// static
Type Typer::Visitor::ToNumeric(Type type, Typer* t) {
  return t->operation_typer_.ToNumeric(type);
}

// static
Type Typer::Visitor::ToObject(Type type, Typer* t) {
  // ES6 section 7.1.13 ToObject ( argument )
  if (type.Is(Type::Receiver())) return type;
  if (type.Is(Type::Primitive())) return Type::StringWrapperOrOtherObject();
  if (!type.Maybe(Type::OtherUndetectable())) {
    return Type::DetectableReceiver();
  }
  return Type::Receiver();
}

// static
Type Typer::Visitor::ToString(Type type, Typer* t) {
  // ES6 section 7.1.12 ToString ( argument )
  type = ToPrimitive(type, t);
  if (type.Is(Type::String())) return type;
  return Type::String();
}

// Type checks.

Type Typer::Visitor::ObjectIsArrayBufferView(Type type, Typer* t) {
  // TODO(turbofan): Introduce a Type::ArrayBufferView?
  CHECK(!type.IsNone());
  if (!type.Maybe(Type::OtherObject())) return t->singleton_false_;
  return Type::Boolean();
}

Type Typer::Visitor::ObjectIsBigInt(Type type, Typer* t) {
  CHECK(!type.IsNone());
  if (type.Is(Type::BigInt())) return t->singleton_true_;
  if (!type.Maybe(Type::BigInt())) return t->singleton_false_;
  return Type::Boolean();
}

Type Typer::Visitor::ObjectIsCallable(Type type, Typer* t) {
  CHECK(!type.IsNone());
  if (type.Is(Type::Callable())) return t->singleton_true_;
  if (!type.Maybe(Type::Callable())) return t->singleton_false_;
  return Type::Boolean();
}

Type Typer::Visitor::ObjectIsConstructor(Type type, Typer* t) {
  // TODO(turbofan): Introduce a Type::Constructor?
  CHECK(!type.IsNone());
  if (type.IsHeapConstant() &&
      type.AsHeapConstant()->Ref().map(t->broker()).is_constructor()) {
    return t->singleton_true_;
  }
  if (!type.Maybe(Type::Callable())) return t->singleton_false_;
  return Type::Boolean();
}

Type Typer::Visitor::ObjectIsDetectableCallable(Type type, Typer* t) {
  CHECK(!type.IsNone());
  if (type.Is(Type::DetectableCallable())) return t->singleton_true_;
  if (!type.Maybe(Type::DetectableCallable())) return t->singleton_false_;
  return Type::Boolean();
}

Type Typer::Visitor::ObjectIsMinusZero(Type type, Typer* t) {
  CHECK(!type.IsNone());
  if (type.Is(Type::MinusZero())) return t->singleton_true_;
  if (!type.Maybe(Type::MinusZero())) return t->singleton_false_;
  return Type::Boolean();
}

Type Typer::Visitor::NumberIsMinusZero(Type type, Typer* t) {
  CHECK(!type.IsNone());
  if (type.Is(Type::MinusZero())) return t->singleton_true_;
  if (!type.Maybe(Type::MinusZero())) return t->singleton_false_;
  return Type::Boolean();
}

Type Typer::Visitor::ObjectIsNaN(Type type, Typer* t) {
  CHECK(!type.IsNone());
  if (type.Is(Type::NaN())) return t->singleton_true_;
  if (!type.Maybe(Type::NaN())) return t->singleton_false_;
  return Type::Boolean();
}

Type Typer::Visitor::NumberIsNaN(Type type, Typer* t) {
  CHECK(!type.IsNone());
  if (type.Is(Type::NaN())) return t->singleton_true_;
  if (!type.Maybe(Type::NaN())) return t->singleton_false_;
  return Type::Boolean();
}

Type Typer::Visitor::ObjectIsNonCallable(Type type, Typer* t) {
  CHECK(!type.IsNone());
  if (type.Is(Type::NonCallable())) return t->singleton_true_;
  if (!type.Maybe(Type::NonCallable())) return t->singleton_false_;
  return Type::Boolean();
}

Type Typer::Visitor::ObjectIsNumber(Type type, Typer* t) {
  CHECK(!type.IsNone());
  if (type.Is(Type::Number())) return t->singleton_true_;
  if (!type.Maybe(Type::Number())) return t->singleton_false_;
  return Type::Boolean();
}

Type Typer::Visitor::ObjectIsReceiver(Type type, Typer* t) {
  CHECK(!type.IsNone());
  if (type.Is(Type::Receiver())) return t->singleton_true_;
  if (!type.Maybe(Type::Receiver())) return t->singleton_false_;
  return Type::Boolean();
}

Type Typer::Visitor::ObjectIsSmi(Type type, Typer* t) {
  if (!type.Maybe(Type::SignedSmall())) return t->singleton_false_;
  return Type::Boolean();
}

Type Typer::Visitor::ObjectIsString(Type type, Typer* t) {
  CHECK(!type.IsNone());
  if (type.Is(Type::String())) return t->singleton_true_;
  if (!type.Maybe(Type::String())) return t->singleton_false_;
  return Type::Boolean();
}

Type Typer::Visitor::ObjectIsSymbol(Type type, Typer* t) {
  CHECK(!type.IsNone());
  if (type.Is(Type::Symbol())) return t->singleton_true_;
  if (!type.Maybe(Type::Symbol())) return t->singleton_false_;
  return Type::Boolean();
}

Type Typer::Visitor::ObjectIsUndetectable(Type type, Typer* t) {
  CHECK(!type.IsNone());
  if (type.Is(Type::Undetectable())) return t->singleton_true_;
  if (!type.Maybe(Type::Undetectable())) return t->singleton_false_;
  return Type::Boolean();
}

// -----------------------------------------------------------------------------

// Control operators.

Type Typer::Visitor::TypeStart(Node* node) { return Type::Internal(); }

Type Typer::Visitor::TypeIfException(Node* node) { return Type::NonInternal(); }

// Common operators.

Type Typer::Visitor::TypeParameter(Node* node) {
  StartNode start{node->InputAt(0)};
  int const index = ParameterIndexOf(node->op());
  if (index == Linkage::kJSCallClosureParamIndex) {
    return Type::Function();
  } else if (index == 0) {
    if (typer_->flags() & Typer::kThisIsReceiver) {
      return Type::Receiver();
    } else {
      // Parameter[this] can be a hole type for derived class constructors.
      return Type::Union(Type::Hole(), Type::NonInternal(), typer_->zone());
    }
  } else if (index == start.NewTargetParameterIndex()) {
    if (typer_->flags() & Typer::kNewTargetIsReceiver) {
      return Type::Receiver();
    } else {
      return Type::Union(Type::Receiver(), Type::Undefined(), typer_->zone());
    }
  } else if (index == start.ArgCountParameterIndex()) {
    return Type::Range(0.0, FixedArray::kMaxLength, typer_->zone());
  } else if (index == start.ContextParameterIndex()) {
    return Type::OtherInternal();
  }
  return Type::NonInternal();
}

Type Typer::Visitor::TypeOsrValue(Node* node) {
  if (OsrValueIndexOf(node->op()) == Linkage::kOsrContextSpillSlotIndex) {
    return Type::OtherInternal();
  } else {
    return Type::Any();
  }
}

Type Typer::Visitor::TypeRetain(Node* node) { UNREACHABLE(); }

Type Typer::Visitor::TypeInt32Constant(Node* node) { return Type::Machine(); }

Type Typer::Visitor::TypeInt64Constant(Node* node) { return Type::Machine(); }

Type Typer::Visitor::TypeTaggedIndexConstant(Node* node) { UNREACHABLE(); }

Type Typer::Visitor::TypeRelocatableInt32Constant(Node* node) { UNREACHABLE(); }

Type Typer::Visitor::TypeRelocatableInt64Constant(Node* node) { UNREACHABLE(); }

Type Typer::Visitor::TypeFloat32Constant(Node* node) { UNREACHABLE(); }

Type Typer::Visitor::TypeFloat64Constant(Node* node) { UNREACHABLE(); }

Type Typer::Visitor::TypeNumberConstant(Node* node) {
  double number = OpParameter<double>(node->op());
  return Type::Constant(number, zone());
}

Type Typer::Visitor::TypeHeapConstant(Node* node) {
  return TypeConst
```