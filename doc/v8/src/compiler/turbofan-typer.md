Response: The user wants a summary of the C++ source code file `v8/src/compiler/turbofan-typer.cc`.
This is part 1 of 2.

The code seems to implement a type system for the Turbofan compiler in V8. It analyzes the intermediate representation (IR) of JavaScript code to infer the types of values produced by each operation. This information is crucial for optimization, as it allows the compiler to make assumptions and eliminate unnecessary checks.

Key functionalities that seem to be present:

1. **Type Inference:** The core functionality appears to be the `Typer::Visitor` class, which walks through the graph of operations and determines the type of each node.
2. **Type Representation:** The code uses a `Type` class (likely defined elsewhere) to represent different types of JavaScript values.
3. **Operation-Specific Typing:** The `TypeNode` method within the `Visitor` class has a large switch statement that handles type inference for various IR opcodes. It seems to differentiate between JavaScript-specific operators (`JS_...`), simplified operators (`SIMPLIFIED_...`), and machine-level operators (`MACHINE_...`).
4. **Type Weakening:**  The `Weaken` method suggests a mechanism for widening types, potentially to help the type inference process converge in loops.
5. **Integration with Loop Variable Optimization:** The `LoopVariableOptimizer` class is used, indicating that type information is used to optimize loop variables.
6. **Decorator Pattern:** The `Typer::Decorator` class suggests a way to apply type information to the graph nodes.

Relationship with JavaScript:

The `turbofan-typer.cc` file is directly related to the performance of JavaScript code. By inferring types accurately, Turbofan can generate more efficient machine code for JavaScript.

To illustrate with JavaScript, consider a simple example:

```javascript
function add(a, b) {
  return a + b;
}

add(5, 10); // Calling with numbers
add("hello", " world"); // Calling with strings
```

The `turbofan-typer.cc` code would analyze the `add` function's IR. It would try to determine the type of `a` and `b` at the point of the `+` operation. If it can determine that `a` and `b` are always numbers in a specific call site, it can generate optimized machine code for numeric addition. If they can be strings, it would need to handle string concatenation. The `Typer` helps in making these type-based decisions.
This C++ source code file (`v8/src/compiler/turbofan-typer.cc`) is a crucial component of the V8 JavaScript engine's Turbofan optimizing compiler. Its primary function is **type inference** for the intermediate representation (IR) of JavaScript code.

Here's a breakdown of its key functionalities:

1. **Type Analysis:** The code implements a `Typer` class and a `Visitor` class (nested within `Typer`). The `Visitor` traverses the graph of operations representing the JavaScript code and attempts to determine the **type** of the result produced by each operation (node in the graph).

2. **Operation-Specific Type Rules:** The `TypeNode` method within the `Visitor` class contains a large switch statement that defines how to infer the type for each different kind of operation (opcode) in the IR. This includes:
    * **JavaScript Operators:**  Operators like `+`, `-`, `<`, `typeof`, function calls, object creation, property access, etc.
    * **Simplified Operators:**  Lower-level operations used by Turbofan after initial simplification.
    * **Machine Operators:**  Operations closer to the target machine's instructions.

3. **Type Representation:** The code uses a `Type` class (defined elsewhere) to represent the inferred types. These types can be primitive types (number, string, boolean), object types, or more complex types (like ranges for numbers).

4. **Type Propagation:** As the `Visitor` traverses the graph, it propagates type information from the inputs of an operation to its output.

5. **Type Weakening (for Loops):**  The `Weaken` method suggests a strategy for widening types, particularly within loops. This helps the type inference process converge and handle cases where a variable's type might change slightly with each iteration.

6. **Integration with Loop Variable Optimization:** The code interacts with a `LoopVariableOptimizer`. This indicates that the inferred type information is used to perform optimizations specific to loop variables, such as determining if a loop counter has a predictable range.

7. **Graph Decoration:** The `Typer::Decorator` class is used to annotate the nodes in the IR graph with their inferred types.

**Relationship to JavaScript and an example:**

This code directly impacts the performance of JavaScript code. By accurately inferring types, Turbofan can:

* **Eliminate unnecessary runtime type checks:** If the compiler knows a variable is always a number, it doesn't need to check its type before performing an arithmetic operation.
* **Specialize code for specific types:**  It can generate different machine code for different types, leading to more efficient execution.
* **Perform optimizations based on type information:** For example, knowing an object has a specific structure allows for faster property access.

**JavaScript Example:**

```javascript
function add(x, y) {
  return x + y;
}

add(5, 10); // Call with numbers
```

When Turbofan compiles this code, the `turbofan-typer.cc` logic would analyze the `add` function.

* For the call `add(5, 10)`, the typer would infer that both `x` and `y` are likely numbers.
* Based on this, the compiler can generate optimized machine code for integer addition.

Now consider this:

```javascript
function concatenate(a, b) {
  return a + b;
}

concatenate("hello", "world"); // Call with strings
```

* For this call, the typer would infer that `a` and `b` are strings.
* The compiler would then generate different (but still optimized) machine code for string concatenation.

If the typer encounters a situation where the types are uncertain (e.g., a function can be called with different types), it might infer a more general type or generate code that handles multiple possibilities.

In essence, `v8/src/compiler/turbofan-typer.cc` empowers the Turbofan compiler to understand the types of data flowing through your JavaScript code, allowing it to generate significantly faster and more efficient machine code.

### 提示词
```
这是目录为v8/src/compiler/turbofan-typer.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```
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
  return TypeConstant(HeapConstantOf(node->op()));
}

Type Typer::Visitor::TypeCompressedHeapConstant(Node* node) { UNREACHABLE(); }

Type Typer::Visitor::TypeTrustedHeapConstant(Node* node) {
  return TypeConstant(HeapConstantOf(node->op()));
}

Type Typer::Visitor::TypeExternalConstant(Node* node) {
  return Type::ExternalPointer();
}

Type Typer::Visitor::TypePointerConstant(Node* node) {
  return Type::ExternalPointer();
}

Type Typer::Visitor::TypeSelect(Node* node) {
  return Type::Union(Operand(node, 1), Operand(node, 2), zone());
}

Type Typer::Visitor::TypePhi(Node* node) {
  int arity = node->op()->ValueInputCount();
  Type type = Operand(node, 0);
  for (int i = 1; i < arity; ++i) {
    type = Type::Union(type, Operand(node, i), zone());
  }
  return type;
}

Type Typer::Visitor::TypeEnterMachineGraph(Node* node) {
  return Type::Machine();
}

Type Typer::Visitor::TypeExitMachineGraph(Node* node) {
  return ExitMachineGraphParametersOf(node->op()).output_type();
}

Type Typer::Visitor::TypeInductionVariablePhi(Node* node) {
  int arity = NodeProperties::GetControlInput(node)->op()->ControlInputCount();
  DCHECK_EQ(IrOpcode::kLoop, NodeProperties::GetControlInput(node)->opcode());
  DCHECK_EQ(2, NodeProperties::GetControlInput(node)->InputCount());

  Type initial_type = Operand(node, 0);
  Type increment_type = Operand(node, 2);

  // Fallback to normal phi typing in a variety of cases:
  // - when the induction variable is not initially of type Integer, because we
  //   want to work with ranges in the algorithm below.
  // - when the increment is zero, because in that case normal phi typing will
  //   generally yield a more precise type.
  // - when the induction variable can become NaN (through addition/subtraction
  //   of opposing infinities), because the code below can't handle that case.
  if (initial_type.IsNone() ||
      increment_type.Is(typer_->cache_->kSingletonZero) ||
      !initial_type.Is(typer_->cache_->kInteger) ||
      !increment_type.Is(typer_->cache_->kInteger) ||
      increment_type.Min() == -V8_INFINITY ||
      increment_type.Max() == +V8_INFINITY) {
    // Unfortunately, without baking in the previous type, monotonicity might be
    // violated because we might not yet have retyped the incrementing operation
    // even though the increment's type might been already reflected in the
    // induction variable phi.
    Type type = NodeProperties::IsTyped(node) ? NodeProperties::GetType(node)
                                              : Type::None();
    for (int i = 0; i < arity; ++i) {
      type = Type::Union(type, Operand(node, i), zone());
    }
    return type;
  }

  auto res = induction_vars_->induction_variables().find(node->id());
  DCHECK_NE(res, induction_vars_->induction_variables().end());
  InductionVariable* induction_var = res->second;
  InductionVariable::ArithmeticType arithmetic_type = induction_var->Type();

  double min = -V8_INFINITY;
  double max = V8_INFINITY;

  double increment_min;
  double increment_max;
  if (arithmetic_type == InductionVariable::ArithmeticType::kAddition) {
    increment_min = increment_type.Min();
    increment_max = increment_type.Max();
  } else {
    DCHECK_EQ(arithmetic_type, InductionVariable::ArithmeticType::kSubtraction);
    increment_min = -increment_type.Max();
    increment_max = -increment_type.Min();
  }

  if (increment_min >= 0) {
    // Increasing sequence.
    min = initial_type.Min();
    for (auto bound : induction_var->upper_bounds()) {
      Type bound_type = TypeOrNone(bound.bound);
      // If the type is not an integer, just skip the bound.
      if (!bound_type.Is(typer_->cache_->kInteger)) continue;
      // If the type is not inhabited, then we can take the initial value.
      if (bound_type.IsNone()) {
        max = initial_type.Max();
        break;
      }
      double bound_max = bound_type.Max();
      if (bound.kind == InductionVariable::kStrict) {
        bound_max -= 1;
      }
      max = std::min(max, bound_max + increment_max);
    }
    // The upper bound must be at least the initial value's upper bound.
    max = std::max(max, initial_type.Max());
  } else if (increment_max <= 0) {
    // Decreasing sequence.
    max = initial_type.Max();
    for (auto bound : induction_var->lower_bounds()) {
      Type bound_type = TypeOrNone(bound.bound);
      // If the type is not an integer, just skip the bound.
      if (!bound_type.Is(typer_->cache_->kInteger)) continue;
      // If the type is not inhabited, then we can take the initial value.
      if (bound_type.IsNone()) {
        min = initial_type.Min();
        break;
      }
      double bound_min = bound_type.Min();
      if (bound.kind == InductionVariable::kStrict) {
        bound_min += 1;
      }
      min = std::max(min, bound_min + increment_min);
    }
    // The lower bound must be at most the initial value's lower bound.
    min = std::min(min, initial_type.Min());
  } else {
    // If the increment can be both positive and negative, the variable can go
    // arbitrarily far. Use the maximal range in that case. Note that this may
    // be less precise than what ordinary typing would produce.
    min = -V8_INFINITY;
    max = +V8_INFINITY;
  }

  if (v8_flags.trace_turbo_loop) {
    StdoutStream{} << std::setprecision(10) << "Loop ("
                   << NodeProperties::GetControlInput(node)->id()
                   << ") variable bounds in "
                   << (arithmetic_type ==
                               InductionVariable::ArithmeticType::kAddition
                           ? "addition"
                           : "subtraction")
                   << " for phi " << node->id() << ": (" << min << ", " << max
                   << ")\n";
  }

  return Type::Range(min, max, typer_->zone());
}

bool Typer::Visitor::InductionVariablePhiTypeIsPrefixedPoint(
    InductionVariable* induction_var) {
  Node* node = induction_var->phi();
  DCHECK_EQ(node->opcode(), IrOpcode::kInductionVariablePhi);
  Node* arith = node->InputAt(1);
  Type type = NodeProperties::GetType(node);
  Type initial_type = Operand(node, 0);
  Type arith_type = Operand(node, 1);
  Type increment_type = Operand(node, 2);

  // Intersect {type} with useful bounds.
  for (auto bound : induction_var->upper_bounds()) {
    Type bound_type = TypeOrNone(bound.bound);
    if (!bound_type.Is(typer_->cache_->kInteger)) continue;
    if (!bound_type.IsNone()) {
      bound_type = Type::Range(
          -V8_INFINITY,
          bound_type.Max() - (bound.kind == InductionVariable::kStrict),
          zone());
    }
    type = Type::Intersect(type, bound_type, typer_->zone());
  }
  for (auto bound : induction_var->lower_bounds()) {
    Type bound_type = TypeOrNone(bound.bound);
    if (!bound_type.Is(typer_->cache_->kInteger)) continue;
    if (!bound_type.IsNone()) {
      bound_type = Type::Range(
          bound_type.Min() + (bound.kind == InductionVariable::kStrict),
          +V8_INFINITY, typer_->zone());
    }
    type = Type::Intersect(type, bound_type, typer_->zone());
  }

  if (arith_type.IsNone()) {
    type = Type::None();
  } else {
    // We support a few additional type conversions on the lhs of the arithmetic
    // operation. This needs to be kept in sync with the corresponding code in
    // {LoopVariableOptimizer::TryGetInductionVariable}.
    Node* arith_input = arith->InputAt(0);
    switch (arith_input->opcode()) {
      case IrOpcode::kSpeculativeToNumber:
        type = typer_->operation_typer_.SpeculativeToNumber(type);
        break;
      case IrOpcode::kJSToNumber:
        type = typer_->operation_typer_.ToNumber(type);
        break;
      case IrOpcode::kJSToNumberConvertBigInt:
        type = typer_->operation_typer_.ToNumberConvertBigInt(type);
        break;
      default:
        break;
    }

    // Apply ordinary typing to the "increment" operation.
    // clang-format off
    switch (arith->opcode()) {
#define CASE(x)                             \
      case IrOpcode::k##x:                    \
        type = Type##x(type, increment_type); \
        break;
      CASE(JSAdd)
      CASE(JSSubtract)
      CASE(NumberAdd)
      CASE(NumberSubtract)
      CASE(SpeculativeNumberAdd)
      CASE(SpeculativeNumberSubtract)
      CASE(SpeculativeSafeIntegerAdd)
      CASE(SpeculativeSafeIntegerSubtract)
#undef CASE
      default:
        UNREACHABLE();
    }
    // clang-format on
  }

  type = Type::Union(initial_type, type, typer_->zone());

  return type.Is(NodeProperties::GetType(node));
}

Type Typer::Visitor::TypeEffectPhi(Node* node) { UNREACHABLE(); }

Type Typer::Visitor::TypeLoopExit(Node* node) { UNREACHABLE(); }

Type Typer::Visitor::TypeLoopExitValue(Node* node) { return Operand(node, 0); }

Type Typer::Visitor::TypeLoopExitEffect(Node* node) { UNREACHABLE(); }

Type Typer::Visitor::TypeEnsureWritableFastElements(Node* node) {
  return Operand(node, 1);
}

Type Typer::Visitor::TypeMaybeGrowFastElements(Node* node) {
  return Operand(node, 1);
}

Type Typer::Visitor::TypeTransitionElementsKind(Node* node) { UNREACHABLE(); }

Type Typer::Visitor::TypeCheckpoint(Node* node) { UNREACHABLE(); }

Type Typer::Visitor::TypeBeginRegion(Node* node) { UNREACHABLE(); }

Type Typer::Visitor::TypeFinishRegion(Node* node) { return Operand(node, 0); }

Type Typer::Visitor::TypeFrameState(Node* node) {
  // TODO(rossberg): Ideally FrameState wouldn't have a value output.
  return Type::Internal();
}

Type Typer::Visitor::TypeStateValues(Node* node) { return Type::Internal(); }

Type Typer::Visitor::TypeTypedStateValues(Node* node) {
  return Type::Internal();
}

Type Typer::Visitor::TypeObjectId(Node* node) { UNREACHABLE(); }

Type Typer::Visitor::TypeArgumentsElementsState(Node* node) {
  return Type::Internal();
}

Type Typer::Visitor::TypeArgumentsLengthState(Node* node) {
  return Type::Internal();
}

Type Typer::Visitor::TypeObjectState(Node* node) { return Type::Internal(); }

Type Typer::Visitor::TypeTypedObjectState(Node* node) {
  return Type::Internal();
}

Type Typer::Visitor::TypeCall(Node* node) { return Type::Any(); }

Type Typer::Visitor::TypeFastApiCall(Node* node) {
  FastApiCallParameters const& op_params = FastApiCallParametersOf(node->op());

  const CFunctionInfo* c_signature = op_params.c_function().signature;
  CTypeInfo return_type = c_signature->ReturnInfo();

  switch (return_type.GetType()) {
    case CTypeInfo::Type::kBool:
      return Type::Boolean();
    case CTypeInfo::Type::kFloat32:
    case CTypeInfo::Type::kFloat64:
      return Type::Number();
    case CTypeInfo::Type::kInt32:
      return Type::Signed32();
    case CTypeInfo::Type::kInt64:
      if (c_signature->GetInt64Representation() ==
          CFunctionInfo::Int64Representation::kBigInt) {
        return Type::SignedBigInt64();
      }
      DCHECK_EQ(c_signature->GetInt64Representation(),
                CFunctionInfo::Int64Representation::kNumber);
      return Type::Number();
    case CTypeInfo::Type::kSeqOneByteString:
      return Type::String();
    case CTypeInfo::Type::kUint32:
      return Type::Unsigned32();
    case CTypeInfo::Type::kUint64:
      if (c_signature->GetInt64Representation() ==
          CFunctionInfo::Int64Representation::kBigInt) {
        return Type::UnsignedBigInt64();
      }
      DCHECK_EQ(c_signature->GetInt64Representation(),
                CFunctionInfo::Int64Representation::kNumber);
      return Type::Number();
    case CTypeInfo::Type::kUint8:
      return Type::UnsignedSmall();
    case CTypeInfo::Type::kAny:
      // This type is only supposed to be used for parameters, not returns.
      UNREACHABLE();
    case CTypeInfo::Type::kPointer:
    case CTypeInfo::Type::kApiObject:
    case CTypeInfo::Type::kV8Value:
    case CTypeInfo::Type::kVoid:
      return Type::Any();
  }
}

#ifdef V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA
Type Typer::Visitor::TypeGetContinuationPreservedEmbedderData(Node* node) {
  return Type::Any();
}

Type Typer::Visitor::TypeSetContinuationPreservedEmbedderData(Node* node) {
  UNREACHABLE();
}
#endif  // V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA

#if V8_ENABLE_WEBASSEMBLY
Type Typer::Visitor::TypeJSWasmCall(Node* node) {
  const JSWasmCallParameters& op_params = JSWasmCallParametersOf(node->op());
  const wasm::CanonicalSig* wasm_signature = op_params.signature();
  if (wasm_signature->return_count() > 0) {
    return JSWasmCallNode::TypeForWasmReturnType(wasm_signature->GetReturn());
  }
  return Type::Any();
}
#endif  // V8_ENABLE_WEBASSEMBLY

Type Typer::Visitor::TypeProjection(Node* node) {
  Type const type = Operand(node, 0);
  if (type.Is(Type::None())) return Type::None();
  int const index = static_cast<int>(ProjectionIndexOf(node->op()));
  if (type.IsTuple() && index < type.AsTuple()->Arity()) {
    return type.AsTuple()->Element(index);
  }
  return Type::Any();
}

Type Typer::Visitor::TypeMapGuard(Node* node) { UNREACHABLE(); }

Type Typer::Visitor::TypeTypeGuard(Node* node) {
  Type const type = Operand(node, 0);
  return typer_->operation_typer()->TypeTypeGuard(node->op(), type);
}

Type Typer::Visitor::TypeDead(Node* node) { return Type::None(); }
Type Typer::Visitor::TypeDeadValue(Node* node) { return Type::None(); }
Type Typer::Visitor::TypeUnreachable(Node* node) { return Type::None(); }

Type Typer::Visitor::TypePlug(Node* node) { UNREACHABLE(); }
Type Typer::Visitor::TypeStaticAssert(Node* node) { UNREACHABLE(); }
Type Typer::Visitor::TypeSLVerifierHint(Node* node) { UNREACHABLE(); }

// JS comparison operators.

Type Typer::Visitor::JSEqualTyper(Type lhs, Type rhs, Typer* t) {
  if (lhs.IsNone() || rhs.IsNone()) return Type::None();
  if (lhs.Is(Type::NaN()) || rhs.Is(Type::NaN())) return t->singleton_false_;
  if (lhs.Is(Type::NullOrUndefined()) && rhs.Is(Type::NullOrUndefined())) {
    return t->singleton_true_;
  }
  if (lhs.Is(Type::Number()) && rhs.Is(Type::Number()) &&
      (lhs.Max() < rhs.Min() || lhs.Min() > rhs.Max())) {
    return t->singleton_false_;
  }
  if (lhs.IsSingleton() && rhs.Is(lhs)) {
    // Types are equal and are inhabited only by a single semantic value,
    // which is not nan due to the earlier check.
    DCHECK(lhs.Is(rhs));
    return t->singleton_true_;
  }
  return Type::Boolean();
}

Type Typer::Visitor::JSStrictEqualTyper(Type lhs, Type rhs, Typer* t) {
  return t->operation_typer()->StrictEqual(lhs, rhs);
}

// The ECMAScript specification defines the four relational comparison operators
// (<, <=, >=, >) with the help of a single abstract one.  It behaves like <
// but returns undefined when the inputs cannot be compared.
// We implement the typing analogously.
Typer::Visitor::ComparisonOutcome Typer::Visitor::JSCompareTyper(Type lhs,
                                                                 Type rhs,
                                                                 Typer* t) {
  lhs = ToPrimitive(lhs, t);
  rhs = ToPrimitive(rhs, t);
  if (lhs.Maybe(Type::String()) && rhs.Maybe(Type::String())) {
    return ComparisonOutcome(kComparisonTrue) |
           ComparisonOutcome(kComparisonFalse);
  }
  lhs = ToNumeric(lhs, t);
  rhs = ToNumeric(rhs, t);
  if (lhs.Is(Type::Number()) && rhs.Is(Type::Number())) {
    return NumberCompareTyper(lhs, rhs, t);
  }
  return ComparisonOutcome(kComparisonTrue) |
         ComparisonOutcome(kComparisonFalse) |
         ComparisonOutcome(kComparisonUndefined);
}

Typer::Visitor::ComparisonOutcome Typer::Visitor::NumberCompareTyper(Type lhs,
                                                                     Type rhs,
                                                                     Typer* t) {
  DCHECK(lhs.Is(Type::Number()));
  DCHECK(rhs.Is(Type::Number()));

  if (lhs.IsNone() || rhs.IsNone()) return {};

  // Shortcut for NaNs.
  if (lhs.Is(Type::NaN()) || rhs.Is(Type::NaN())) return kComparisonUndefined;

  ComparisonOutcome result;
  if (lhs.IsHeapConstant() && rhs.Is(lhs)) {
    // Types are equal and are inhabited only by a single semantic value.
    result = kComparisonFalse;
  } else if (lhs.Min() >= rhs.Max()) {
    result = kComparisonFalse;
  } else if (lhs.Max() < rhs.Min()) {
    result = kComparisonTrue;
  } else {
    return ComparisonOutcome(kComparisonTrue) |
           ComparisonOutcome(kComparisonFalse) |
           ComparisonOutcome(kComparisonUndefined);
  }
  // Add the undefined if we could see NaN.
  if (lhs.Maybe(Type::NaN()) || rhs.Maybe(Type::NaN())) {
    result |= kComparisonUndefined;
  }
  return result;
}

Type Typer::Visitor::JSLessThanTyper(Type lhs, Type rhs, Typer* t) {
  return FalsifyUndefined(JSCompareTyper(lhs, rhs, t), t);
}

Type Typer::Visitor::JSGreaterThanTyper(Type lhs, Type rhs, Typer* t) {
  return FalsifyUndefined(JSCompareTyper(rhs, lhs, t), t);
}

Type Typer::Visitor::JSLessThanOrEqualTyper(Type lhs, Type rhs, Typer* t) {
  return FalsifyUndefined(Invert(JSCompareTyper(rhs, lhs, t), t), t);
}

Type Typer::Visitor::JSGreaterThanOrEqualTyper(Type lhs, Type rhs, Typer* t) {
  return FalsifyUndefined(Invert(JSCompareTyper(lhs, rhs, t), t), t);
}

// JS bitwise operators.

Type Typer::Visitor::JSBitwiseOrTyper(Type lhs, Type rhs, Typer* t) {
  return BinaryNumberOpTyper(lhs, rhs, t, NumberBitwiseOr);
}

Type Typer::Visitor::JSBitwiseAndTyper(Type lhs, Type rhs, Typer* t) {
  return BinaryNumberOpTyper(lhs, rhs, t, NumberBitwiseAnd);
}

Type Typer::Visitor::JSBitwiseXorTyper(Type lhs, Type rhs, Typer* t) {
  return BinaryNumberOpTyper(lhs, rhs, t, NumberBitwiseXor);
}

Type Typer::Visitor::JSShiftLeftTyper(Type lhs, Type rhs, Typer* t) {
  return BinaryNumberOpTyper(lhs, rhs, t, NumberShiftLeft);
}

Type Typer::Visitor::JSShiftRightTyper(Type lhs, Type rhs, Typer* t) {
  return BinaryNumberOpTyper(lhs, rhs, t, NumberShiftRight);
}

Type Typer::Visitor::JSShiftRightLogicalTyper(Type lhs, Type rhs, Typer* t) {
  return NumberShiftRightLogical(ToNumber(lhs, t), ToNumber(rhs, t), t);
}

// JS arithmetic operators.

Type Typer::Visitor::JSAddTyper(Type lhs, Type rhs, Typer* t) {
  lhs = ToPrimitive(lhs, t);
  rhs = ToPrimitive(rhs, t);
  if (lhs.Maybe(Type::String()) || rhs.Maybe(Type::String())) {
    if (lhs.Is(Type::String()) || rhs.Is(Type::String())) {
      return Type::String();
    } else {
      return Type::NumericOrString();
    }
  }
  // The addition must be numeric.
  return BinaryNumberOpTyper(lhs, rhs, t, NumberAdd);
}

Type Typer::Visitor::JSSubtractTyper(Type lhs, Type rhs, Typer* t) {
  return BinaryNumberOpTyper(lhs, rhs, t, NumberSubtract);
}

Type Typer::Visitor::JSMultiplyTyper(Type lhs, Type rhs, Typer* t) {
  return BinaryNumberOpTyper(lhs, rhs, t, NumberMultiply);
}

Type Typer::Visitor::JSDivideTyper(Type lhs, Type rhs, Typer* t) {
  return BinaryNumberOpTyper(lhs, rhs, t, NumberDivide);
}

Type Typer::Visitor::JSModulusTyper(Type lhs, Type rhs, Typer* t) {
  return BinaryNumberOpTyper(lhs, rhs, t, NumberModulus);
}

Type Typer::Visitor::JSExponentiateTyper(Type lhs, Type rhs, Typer* t) {
  // TODO(neis): Refine using BinaryNumberOpTyper?
  return Type::Numeric();
}

// JS unary operators.

#define DEFINE_METHOD(Name)                       \
  Type Typer::Visitor::TypeJS##Name(Type input) { \
    return TypeUnaryOp(input, Name);              \
  }
DEFINE_METHOD(BitwiseNot)
DEFINE_METHOD(Decrement)
DEFINE_METHOD(Increment)
DEFINE_METHOD(Negate)
DEFINE_METHOD(ToLength)
DEFINE_METHOD(ToName)
DEFINE_METHOD(ToNumber)
DEFINE_METHOD(ToNumberConvertBigInt)
DEFINE_METHOD(ToBigInt)
DEFINE_METHOD(ToBigIntConvertNumber)
DEFINE_METHOD(ToNumeric)
DEFINE_METHOD(ToObject)
DEFINE_METHOD(ToString)
#undef DEFINE_METHOD

Type Typer::Visitor::TypeTypeOf(Node* node) {
  return Type::InternalizedString();
}

// JS conversion operators.

Type Typer::Visitor::TypeToBoolean(Node* node) {
  return TypeUnaryOp(node, ToBoolean);
}

// JS object operators.

Type Typer::Visitor::TypeJSCreate(Node* node) { return Type::Object(); }

Type Typer::Visitor::TypeJSCreateArguments(Node* node) {
  switch (CreateArgumentsTypeOf(node->op())) {
    case CreateArgumentsType::kRestParameter:
      return Type::Array();
    case CreateArgumentsType::kMappedArguments:
    case CreateArgumentsType::kUnmappedArguments:
      return Type::OtherObject();
  }
  UNREACHABLE();
}

Type Typer::Visitor::TypeJSCreateArray(Node* node) { return Type::Array(); }

Type Typer::Visitor::TypeJSCreateArrayIterator(Node* node) {
  return Type::OtherObject();
}

Type Typer::Visitor::TypeJSCreateAsyncFunctionObject(Node* node) {
  return Type::OtherObject();
}

Type Typer::Visitor::TypeJSCreateCollectionIterator(Node* node) {
  return Type::OtherObject();
}

Type Typer::Visitor::TypeJSCreateBoundFunction(Node* node) {
  return Type::BoundFunction();
}

Type Typer::Visitor::TypeJSCreateGeneratorObject(Node* node) {
  return Type::OtherObject();
}

Type Typer::Visitor::TypeJSCreateClosure(Node* node) {
  SharedFunctionInfoRef shared =
      JSCreateClosureNode{node}.Parameters().shared_info();
  if (IsClassConstructor(shared.kind())) {
    return Type::ClassConstructor();
  } else {
    return Type::CallableFunction();
  }
}

Type Typer::Visitor::TypeJSCreateIterResultObject(Node* node) {
  return Type::OtherObject();
}

Type Typer::Visitor::TypeJSCreateStringIterator(Node* node) {
  return Type::OtherObject();
}

Type Typer::Visitor::TypeJSCreateKeyValueArray(Node* node) {
  return Type::Array();
}

Type Typer::Visitor::TypeJSCreateObject(Node* node) {
  return Type::OtherObject();
}

Type Typer::Visitor::TypeJSCreateStringWrapper(Node* node) {
  return Type::StringWrapper();
}

Type Typer::Visitor::TypeJSCreatePromise(Node* node) {
  return Type::OtherObject();
}

Type Typer::Visitor::TypeJSCreateTypedArray(Node* node) {
  return Type::OtherObject();
}

Type Typer::Visitor::TypeJSCreateLiteralArray(Node* node) {
  return Type::Array();
}

Type Typer::Visitor::TypeJSCreateEmptyLiteralArray(Node* node) {
  return Type::Array();
}

Type Typer::Visitor::TypeJSCreateArrayFromIterable(Node* node) {
  return Type::Array();
}

Type Typer::Visitor::TypeJSCreateLiteralObject(Node* node) {
  return Type::OtherObject();
}

Type Typer::Visitor::TypeJSCreateEmptyLiteralObject(Node* node) {
  return Type::OtherObject();
}

Type Typer::Visitor::TypeJSCloneObject(Node* node) {
  return Type::OtherObject();
}

Type Typer::Visitor::TypeJSCreateLiteralRegExp(Node* node) {
  return Type::OtherObject();
}

Type Typer::Visitor::TypeJSGetTemplateObject(Node* node) {
  return Type::Array();
}

Type Typer::Visitor::TypeJSLoadProperty(Node* node) { return Type::Any(); }

Type Typer::Visitor::TypeJSLoadNamed(Node* node) {
#ifdef DEBUG
  // Loading of private methods is compiled to a named load of a BlockContext
  // via a private brand, which is an internal object. However, native context
  // specialization should always apply for those cases, so assert that the name
  // is not a private brand here. Otherwise Type::NonInternal() is wrong.
  JSLoadNamedNode n(node);
  NamedAccess const& p = n.Parameters();
  DCHECK(!p.name().object()->IsPrivateBrand());
#endif
  return Type::NonInternal();
}

Type Typer::Visitor::TypeJSLoadNamedFromSuper(Node* node) {
  return Type::NonInternal();
}

Type Typer::Visitor::TypeJSLoadGlobal(Node* node) {
  return Type::NonInternal();
}

Type Typer::Visitor::TypeJSParseInt(Type input) { return Type::Number(); }

Type Typer::Visitor::TypeJSRegExpTest(Node* node) { return Type::Boolean(); }

// Returns a somewhat larger range if we previously assigned
// a (smaller) range to this node. This is used  to speed up
// the fixpoint calculation in case there appears to be a loop
// in the graph. In the current implementation, we are
// increasing the limits to the closest power of two.
Type Typer::Visitor::Weaken(Node* node, Type current_type, Type previous_type) {
  static const double kWeakenMinLimits[] = {0.0,
                                            -1073741824.0,
                                            -2147483648.0,
                                            -4294967296.0,
                                            -8589934592.0,
                                            -17179869184.0,
                                            -34359738368.0,
                                            -68719476736.0,
                                            -137438953472.0,
                                            -274877906944.0,
                                            -549755813888.0,
                                            -1099511627776.0,
                                            -2199023255552.0,
                                            -4398046511104.0,
                                            -8796093022208.0,
                                            -17592186044416.0,
                                            -35184372088832.0,
                                            -70368744177664.0,
                                            -140737488355328.0,
                                            -281474976710656.0,
                                            -562949953421312.0};
  static const double kWeakenMaxLimits[] = {0.0,
                                            1073741823.0,
                                            2147483647.0,
                                            4294967295.0,
                                            8589934591.0,
                                            17179869183.0,
                                            34359738367.0,
                                            68719476735.0,
                                            137438953471.0,
                                            274877906943.0,
                                            549755813887.0,
                                            1099511627775.0,
                                            2199023255551.0,
                                            4398046511103.0,
                                            8796093022207.0,
                                            17592186044415.0,
                                            35184372088831.0,
                                            70368744177663.0,
                                            140737488355327.0,
                                            281474976710655.0,
                                            562949953421311.0};
  static_assert(arraysize(kWeakenMinLimits) == arraysize(kWeakenMaxLimits));

  // If the types have nothing to do with integers, return the types.
  Type const integer = typer_->cache_->kInteger;
  if (!previous_type.Maybe(integer)) {
    return current_type;
  }
  DCHECK(current_type.Maybe(integer));

  Type current_integer = Type::Intersect(current_type, integer, zone());
  Type previous_integer = Type::Intersect(previous_type, integer, zone());

  // Once we start weakening a node, we should always weaken.
  if (!IsWeakened(node->id())) {
    // Only weaken if there is range involved; we should converge quickly
    // for all other types (the exception is a union of many constants,
    // but we currently do not increase the number of constants in unions).
    Type previous = previous_integer.GetRange();
    Type current = current_integer.GetRange();
    if (current.IsInvalid() || previous.IsInvalid()) {
      return current_type;
    }
    // Range is involved => we are weakening.
    SetWeakened(node->id());
  }

  double current_min = current_integer.Min();
  double new_min = current_min;
  // Find the closest lower entry in the list of allowed
  // minima (or negative infinity if there is no such entry).
  if (current_min != previous_integer.Min()) {
    new_min = -V8_INFINITY;
    for (double const min : kWeakenMinLimits) {
      if (min <= current_min) {
        new_min = min;
        break;
      }
    }
  }

  double current_max = current_integer.Max();
  double new_max = current_max;
  // Find the closest greater entry in the list of allowed
  // maxima (or infinity if there is no such entry).
  if (current_max != previous_integer.Max()) {
    new_max = V8_INFINITY;
    for (double const max : kWeakenMaxLimits) {
      if (max >= current_max) {
        new_max = max;
        break;
      }
    }
  }

  return Type::Union(current_type,
                     Type::Range(new_min, new_max, typer_->zone()),
                     typer_->zone());
}

Type Typer::Visitor::TypeJSSetKeyedProperty(Node* node) { UNREACHABLE(); }

Type Typer::Visitor::TypeJSDefineKeyedOwnProperty(Node* node) { UNREACHABLE(); }

Type Typer::Visitor::TypeJSSetNamedProperty(Node* node) { UNREACHABLE(); }

Type Typer::Visitor::TypeJSStoreGlobal(Node* node) { UNREACHABLE(); }

Type Typer::Visitor::TypeJSDefineNamedOwnProperty(Node* node) { UNREACHABLE(); }

Type Typer::Visitor::TypeJSDefineKeyedOwnPropertyInLiteral(Node* node) {
  UNREACHABLE();
}

Type Typer::Visitor::TypeJSStoreInArrayLiteral(Node* node) { UNREACHABLE(); }

Type Typer::Visitor::TypeJSDeleteProperty(Node* node) {
  return Type::Boolean();
}

Type Typer::Visitor::TypeJSHasProperty(Node* node) { return Type::Boolean(); }

// JS instanceof operator.

Type Typer::Visitor::JSHasInPrototypeChainTyper(Type lhs, Type rhs, Typer* t) {
  return Type::Boolean();
}

Type Typer::Visitor::JSInstanceOfTyper(Type lhs, Type rhs, Typer* t) {
  return Type::Boolean();
}

Type Typer::Visitor::JSOrdinaryHasInstanceTyper(Type lhs, Type rhs, Typer* t) {
  return Type::Boolean();
}

Type Typer::Visitor::TypeJSGetSuperConstructor(Node* node) {
  return Type::NonInternal();
}

Type Typer::Visitor::TypeJSFindNonDefaultConstructorOrConstruct(Node* node) {
  return Type::Tuple(Type::Boolean(), Type::ReceiverOrNull(), zone());
}

// JS context operators.
Type Typer::Visitor::TypeJSHasContextExtension(Node* node) {
  return Type::Boolean();
}

Type Typer::Visitor::TypeJSLoadContext(Node* node) {
  ContextAccess const& access = ContextAccessOf(node->op());
  switch (access.index()) {
    case Context::PREVIOUS_INDEX:
    case Context::SCOPE_INFO_INDEX:
      return Type::OtherInternal();
    default:
      return Type::Any();
  }
}

Type Typer::Visitor::TypeJSLoadScriptContext(Node* node) {
  ContextAccess const& access = ContextAccessOf(node->op());
  switch (access.index()) {
    case Context::PREVIOUS_INDEX:
    case Context::SCOPE_INFO_INDEX:
    case Context::CONTEXT_SIDE_TABLE_PROPERTY_INDEX:
      return Type::OtherInternal();
    default:
      return Type::Any();
  }
}

Type Typer::Visitor::TypeJSStoreContext(Node* node) { UNREACHABLE(); }

Type Typer::Visitor::TypeJSStoreScriptContext(Node* node) { UNREACHABLE(); }

Type Typer::Visitor::TypeJSCreateFunctionContext(Node* node) {
  return Type::OtherInternal();
}

Type Typer::Visitor::TypeJSCreateCatchContext(Node* node) {
  return Type::OtherInternal();
}

Type Typer::Visitor::TypeJSCreateWithContext(Node* node) {
  return Type::OtherInternal();
}

Type Typer::Visitor::TypeJSCreateBlockContext(Node* node) {
  return Type::OtherInternal();
}

// JS other operators.

Type Typer::Visitor::TypeJSConstructForwardVarargs(Node* node) {
  return Type::Receiver();
}

Type Typer::Visitor::TypeJSConstructForwardAllArgs(Node* node) {
  return Type::Receiver();
}

Type Typer::Visitor::TypeJSConstruct(Node* node) { return Type::Receiver(); }

Type Typer::Visitor::TypeJSConstructWithArrayLike(Node* node) {
  return Type::Receiver();
}

Type Typer::Visitor::TypeJSConstructWithSpread(Node* node) {
  return Type::Receiver();
}

Type Typer::Visitor::TypeJSObjectIsArray(Node* node) { return Type::Boolean(); }

Type Typer::Visitor::TypeDateNow(Node* node) { return Type::Number(); }

Type Typer::Visitor::TypeDoubleArrayMin(Node* node) { return Type::Number(); }

Type Typer::Visitor::TypeDoubleArrayMax(Node* node) { return Type::Number(); }

Type Typer::Visitor::TypeUnsigned32Divide(Node* node) {
  Type lhs = Operand(node, 0);
  return Type::Range(0, lhs.Max(), zone());
}

Type Typer::Visitor::JSCallTyper(Type fun, Typer* t) {
  if (!fun.IsHeapConstant() || !fun.AsHeapConstant()->Ref().IsJSFunction()) {
    return Type::NonInternal();
  }
  JSFunctionRef function = fun.AsHeapConstant()->Ref().AsJSFunction();
  if (!function.shared(t->broker()).HasBuiltinId()) {
    return Type::NonInternal();
  }
  switch (function.shared(t->broker()).builtin_id()) {
    case Builtin::kMathRandom:
      return Type::PlainNumber();
    case Builtin::kMathFloor:
    case Builtin::kMathCeil:
    case Builtin::kMathRound:
    case Builtin::kMathTrunc:
      return t->cache_->kIntegerOrMinusZeroOrNaN;
    // Unary math functions.
    case Builtin::kMathAbs:
    case Builtin::kMathExp:
      return Type::Union(Type::PlainNumber(), Type::NaN(), t->zone());
    case Builtin::kMathAcos:
    case Builtin::kMathAcosh:
    case Builtin::kMathAsin:
    case Builtin::kMathAsinh:
    case Builtin::kMathAtan:
    case Builtin::kMathAtanh:
    case Bu
```