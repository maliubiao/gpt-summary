Response:
Let's break down the thought process for analyzing the provided V8 C++ code snippet.

**1. Initial Understanding and Context:**

* **File Path:**  `v8/src/compiler/js-generic-lowering.cc`. This immediately tells us it's part of the V8 JavaScript engine's compiler and involved in a process called "generic lowering."
* **Copyright Header:** Confirms it's V8 code.
* **Includes:**  Provides clues about what functionalities this code interacts with. We see mentions of AST (Abstract Syntax Tree), builtins, code generation, graph representation, heap interaction, operators, feedback, and objects.
* **Namespace:**  `v8::internal::compiler` further pinpoints its location within the compiler pipeline.

**2. Core Class and its Purpose:**

* **`JSGenericLowering` Class:**  This is the central element. The constructor and destructor are simple. The `Reduce` method is a strong indicator that this class is a compiler *reducer*. Reducers are responsible for transforming the intermediate representation (likely a graph) of the code.
* **`Reduce` Method's Switch Statement:**  This is the workhorse. The `JS_OP_LIST(DECLARE_CASE)` macro suggests it handles various JavaScript operations (opcodes). The `Lower##x(node)` calls inside the cases strongly imply that for each JavaScript operation, there's a specific "lowering" action.

**3. Analyzing the `Lower` Methods (The Bulk of the Logic):**

* **`REPLACE_STUB_CALL` Macro:** This is a pattern. It generates `LowerJS...` methods that call `ReplaceWithBuiltinCall`. This suggests a common pattern for many simple JavaScript operations: replacing them with calls to built-in V8 functions. The list of operations here (`ToLength`, `ToNumber`, etc.) are clearly type conversion or fundamental JS operations.
* **`ReplaceWithBuiltinCall` Functions:** These functions are crucial. They handle the actual replacement of the generic JS operation with a call to a specific V8 built-in function. They manipulate the node in the graph, adding the built-in's code as an input and changing the operator to a `Call`. The different overloads handle flags and properties.
* **`ReplaceWithRuntimeCall` Function:** Similar to `ReplaceWithBuiltinCall`, but it replaces the node with a call to a V8 runtime function (C++ implementation of more complex JS behavior).
* **`ReplaceUnaryOpWithBuiltinCall` and `ReplaceBinaryOpWithBuiltinCall`:** These methods handle unary and binary JavaScript operators. They introduce the concept of "feedback" – information collected during execution to optimize subsequent executions. The code checks for valid feedback and may choose a "_WithFeedback" variant of the built-in call.
* **Specific `LowerJS...` Methods (e.g., `LowerJSAdd`, `LowerJSLoadProperty`):** These are the concrete implementations for individual JavaScript operations. They often follow patterns seen before (using the helper functions), but some have more complex logic:
    * **Property Access (`LoadProperty`, `SetKeyedProperty`, `LoadNamed`, `SetNamedProperty`):** These are more involved. They deal with Inline Caches (ICs) for optimization and check the outer frame state. They also consider megamorphic access builtins for cases with diverse object shapes.
    * **`LoadNamedFromSuper`:**  Handles accessing properties from a superclass, requiring special handling of the prototype chain.
    * **`LoadGlobal`, `StoreGlobal`:** Deal with accessing global variables.
    * **`GetIterator`:**  Has a comment about potential future optimization.
    * **Object/Array Creation (`Create`, `CreateArray`, `CreateObject`):** Involve calls to specific built-ins or runtime functions for allocation.
    * **Closures and Contexts (`CreateClosure`, `CreateFunctionContext`):** Handle the creation of function closures and their associated contexts.
    * **Literals (`CreateLiteralArray`):** Optimization for creating array literals.
    * **`GetTemplateObject`:** Handles template literals.

**4. Identifying Key Concepts and Functionality:**

* **Generic Lowering:** The overall goal is to take high-level, generic JavaScript operations and transform them into lower-level, more specific operations that the V8 engine can execute efficiently.
* **Built-in Calls:** A central mechanism is replacing generic operations with calls to highly optimized built-in functions implemented in C++.
* **Runtime Calls:** For more complex operations, calls to V8 runtime functions are used.
* **Feedback and ICs (Inline Caches):** The code extensively uses feedback to optimize property access and other operations. It chooses different built-in variants based on the availability and nature of feedback. Megamorphic builtins are used when feedback indicates a wide variety of object shapes.
* **Frame States:** The code checks frame states, likely related to deoptimization and debugging.
* **Optimization:** The use of different built-ins and the handling of feedback are all geared towards optimizing the execution of JavaScript code.

**5. Addressing the Specific Questions:**

* **Functionality Summary:**  Combine the observations above into a concise description.
* **Torque:** Check the file extension.
* **JavaScript Relation and Examples:** Identify operations with direct JavaScript counterparts and provide simple examples.
* **Logic Reasoning (Hypothetical Input/Output):** Choose a simpler `LowerJS...` function (e.g., `LowerJSToNumber`) and explain how it transforms a node.
* **Common Programming Errors:** Think about situations where the generic operations are typically used in JavaScript and potential errors (e.g., type errors leading to `ToNumber` being called).

**Self-Correction/Refinement during the Process:**

* Initially, I might focus too much on the individual `LowerJS...` methods. Realizing the patterns (macros, helper functions) helps to understand the overall structure more efficiently.
* The comments in the code are invaluable. Pay attention to "TODO" comments or explanations about specific optimizations.
* Understanding the role of feedback requires connecting the code that checks `p.feedback().IsValid()` with the different built-in call choices.
* Recognizing that this is *lowering* implies a transformation from a higher-level representation to a lower-level one.

By following these steps, combining code analysis with an understanding of compiler principles and V8's architecture, one can effectively analyze and summarize the functionality of a V8 source code file like `js-generic-lowering.cc`.
好的，让我们来分析一下 `v8/src/compiler/js-generic-lowering.cc` 这个文件的功能。

**功能归纳：**

`v8/src/compiler/js-generic-lowering.cc` 文件的主要功能是在 V8 编译器的 **泛型降低 (Generic Lowering)** 阶段，将一些通用的、高级的 JavaScript 操作 (以 `JS` 开头的操作符，例如 `JSAdd`, `JSLoadProperty`) 转换为更具体的、更底层的操作，这些底层操作可以直接映射到 V8 的内置函数 (Builtins) 或运行时函数 (Runtime Functions)。

**详细功能点：**

1. **将通用 JavaScript 操作替换为内置函数调用：**  对于许多常见的 JavaScript 操作，例如类型转换 (`ToLength`, `ToNumber`, `ToString`)，算术运算 (`Add`, `Subtract`, `Multiply`)，位运算，比较运算等，这个文件中的代码会将对应的 `JS` 操作符节点替换为调用 V8 预先实现的、高度优化的内置函数的节点。

2. **将通用 JavaScript 操作替换为运行时函数调用：** 对于一些更复杂或者需要 V8 运行时环境支持的操作，例如创建 `arguments` 对象，访问全局属性等，代码会将 `JS` 操作符节点替换为调用 V8 运行时函数的节点。

3. **处理带反馈信息的 JavaScript 操作：** 对于一些可以进行性能优化的操作，V8 会收集运行时的反馈信息。这个文件中的代码会检查这些反馈信息，并根据反馈信息的不同，选择调用带有反馈信息的内置函数版本 (`_WithFeedback` 后缀) 或者不带反馈信息的版本。这允许 V8 在后续执行中利用这些反馈信息进行优化 (例如，内联缓存)。

4. **处理属性访问操作 (`LoadProperty`, `StoreProperty`, `HasProperty` 等)：**  针对属性的读取、写入和检查操作，代码会根据是否收集到反馈信息，以及反馈信息的具体内容，选择调用不同的内置函数，例如 `KeyedLoadIC` (用于索引属性访问), `LoadIC` (用于命名属性访问) 等。 这些 `IC` (Inline Cache) 内置函数是 V8 优化属性访问的关键。

5. **处理 `super` 关键字的属性访问：**  对于使用 `super` 关键字进行的属性访问，代码会生成特定的调用序列，以确保正确的原型链查找。

6. **处理全局变量的访问：**  针对全局变量的读取和写入，代码会调用特定的内置函数 `LoadGlobalIC` 和 `StoreGlobalIC`。

7. **处理对象和数组的创建：**  针对不同类型的对象和数组创建操作，代码会选择合适的内置函数，例如 `FastNewObject`, `CreateArrayLiteral` 等。

8. **处理闭包和上下文的创建：**  针对函数闭包和执行上下文的创建，代码会调用相应的内置函数或运行时函数。

**关于文件扩展名 `.tq`：**

如果 `v8/src/compiler/js-generic-lowering.cc` 的文件扩展名是 `.tq`，那么它将是一个 **V8 Torque** 源代码文件。Torque 是 V8 内部使用的一种类型化的领域特定语言，用于编写 V8 的内置函数和运行时函数的实现。由于当前的文件扩展名是 `.cc`，所以它是一个 C++ 源代码文件。

**与 JavaScript 功能的关系及示例：**

`v8/src/compiler/js-generic-lowering.cc` 中处理的每个 `JS` 操作符都对应着一个或多个 JavaScript 语法或 API。以下是一些示例：

* **`LowerJSAdd(Node* node)`:** 对应 JavaScript 的加法运算符 `+`。
   ```javascript
   let a = 1;
   let b = 2;
   let sum = a + b; // 对应 JSAdd 操作
   ```

* **`LowerJSToNumber(Node* node)`:** 对应 JavaScript 的 `Number()` 函数或者在特定上下文中发生的隐式类型转换到数字。
   ```javascript
   let str = "123";
   let num = Number(str); // 对应 JSToNumber 操作

   let result = "5" * 2; // 字符串 "5" 被隐式转换为数字，对应 JSToNumber 操作
   ```

* **`LowerJSLoadProperty(Node* node)`:** 对应 JavaScript 的属性访问操作，例如点号运算符 `.` 或方括号运算符 `[]`。
   ```javascript
   let obj = { x: 10 };
   let value = obj.x;   // 对应 JSLoadNamed (如果访问的是命名属性) 或 JSLoadProperty (如果反馈信息指示可能是索引属性)

   let arr = [1, 2, 3];
   let element = arr[0]; // 对应 JSLoadProperty (因为使用索引访问)
   ```

* **`LowerJSCreateArray(Node* node)`:** 对应 JavaScript 创建数组的字面量语法 `[]` 或 `new Array()`。
   ```javascript
   let myArray = [1, 2, 3]; // 对应 JSCreateArray 操作
   let anotherArray = new Array(5); // 对应 JSCreateArray 操作
   ```

**代码逻辑推理示例：**

假设输入一个 `JSAdd` 节点，代表 JavaScript 中的加法运算 `a + b`。

**假设输入：**

* `node`: 一个表示 `a + b` 操作的 `JSAdd` 节点。
* `node->InputAt(0)`: 表示变量 `a` 的值的节点。
* `node->InputAt(1)`: 表示变量 `b` 的值的节点。
* 假设当前没有收集到关于这个加法操作的反馈信息。

**输出：**

`LowerJSAdd` 方法会调用 `ReplaceBinaryOpWithBuiltinCall(node, Builtin::kAdd, Builtin::kAdd_WithFeedback)`。由于假设没有反馈信息，最终会调用 `ReplaceWithBuiltinCall(node, Builtin::kAdd)`。

该方法会将 `JSAdd` 节点替换为一个 `Call` 节点，该 `Call` 节点的输入包括：

* V8 中 `Add` 内置函数的代码。
* 表示变量 `a` 的值的节点 (`node->InputAt(0)`)。
* 表示变量 `b` 的值的节点 (`node->InputAt(1)`)。

**用户常见的编程错误示例：**

许多用户常见的编程错误会导致这里的泛型降低逻辑被触发。例如：

* **类型错误导致的隐式类型转换：**
   ```javascript
   let value = "5" + 3; //  "+" 运算符既可以做加法，也可以做字符串连接
   ```
   在这个例子中，如果 V8 无法在编译时确定操作数的类型，`JSAdd` 操作符会被降低，并且可能会调用 `JSToPrimitive`, `JSToNumber` 或 `JSToString` 等内置函数来处理类型转换。

* **访问未定义的属性：**
   ```javascript
   let obj = {};
   console.log(obj.name); // 访问未定义的属性
   ```
   这会导致 `JSLoadProperty` 操作符被降低，并最终可能调用内置函数来处理属性查找失败的情况。

* **对非对象类型使用属性访问：**
   ```javascript
   let num = 5;
   console.log(num.toString());
   ```
   虽然这段代码是合法的，但 V8 内部可能需要将原始值 `num` 包装成一个对象才能访问 `toString` 方法。这个过程会涉及到 `JSToObject` 等操作的降低。

**总结 `v8/src/compiler/js-generic-lowering.cc` 的功能 (针对第 1 部分)：**

在编译器的早期阶段，`v8/src/compiler/js-generic-lowering.cc` 的主要职责是将高级的、通用的 JavaScript 操作转换为可以直接由 V8 引擎执行的底层操作，主要通过替换为对内置函数或运行时函数的调用来实现。这个过程为后续的更具体的优化阶段奠定了基础。它还负责处理运行时反馈信息，以便在后续执行中进行性能优化。

Prompt: 
```
这是目录为v8/src/compiler/js-generic-lowering.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/js-generic-lowering.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/compiler/js-generic-lowering.h"

#include "src/ast/ast.h"
#include "src/builtins/builtins-constructor.h"
#include "src/codegen/code-factory.h"
#include "src/codegen/interface-descriptors-inl.h"
#include "src/compiler/access-builder.h"
#include "src/compiler/common-operator.h"
#include "src/compiler/js-graph.h"
#include "src/compiler/js-heap-broker.h"
#include "src/compiler/machine-operator.h"
#include "src/compiler/node-properties.h"
#include "src/compiler/operator-properties.h"
#include "src/compiler/processed-feedback.h"
#include "src/compiler/simplified-operator.h"
#include "src/objects/scope-info.h"
#include "src/objects/template-objects-inl.h"

namespace v8 {
namespace internal {
namespace compiler {

namespace {

CallDescriptor::Flags FrameStateFlagForCall(Node* node) {
  return OperatorProperties::HasFrameStateInput(node->op())
             ? CallDescriptor::kNeedsFrameState
             : CallDescriptor::kNoFlags;
}

}  // namespace

JSGenericLowering::JSGenericLowering(JSGraph* jsgraph, Editor* editor,
                                     JSHeapBroker* broker)
    : AdvancedReducer(editor), jsgraph_(jsgraph), broker_(broker) {}

JSGenericLowering::~JSGenericLowering() = default;


Reduction JSGenericLowering::Reduce(Node* node) {
  switch (node->opcode()) {
#define DECLARE_CASE(x, ...) \
  case IrOpcode::k##x:       \
    Lower##x(node);          \
    break;
    JS_OP_LIST(DECLARE_CASE)
#undef DECLARE_CASE
    default:
      // Nothing to see.
      return NoChange();
  }
  return Changed(node);
}

#define REPLACE_STUB_CALL(Name)                       \
  void JSGenericLowering::LowerJS##Name(Node* node) { \
    ReplaceWithBuiltinCall(node, Builtin::k##Name);   \
  }
REPLACE_STUB_CALL(ToLength)
REPLACE_STUB_CALL(ToNumber)
REPLACE_STUB_CALL(ToNumberConvertBigInt)
REPLACE_STUB_CALL(ToBigInt)
REPLACE_STUB_CALL(ToBigIntConvertNumber)
REPLACE_STUB_CALL(ToNumeric)
REPLACE_STUB_CALL(ToName)
REPLACE_STUB_CALL(ToObject)
REPLACE_STUB_CALL(ToString)
REPLACE_STUB_CALL(ForInEnumerate)
REPLACE_STUB_CALL(AsyncFunctionEnter)
REPLACE_STUB_CALL(AsyncFunctionReject)
REPLACE_STUB_CALL(AsyncFunctionResolve)
REPLACE_STUB_CALL(FulfillPromise)
REPLACE_STUB_CALL(PerformPromiseThen)
REPLACE_STUB_CALL(PromiseResolve)
REPLACE_STUB_CALL(RejectPromise)
REPLACE_STUB_CALL(ResolvePromise)
#undef REPLACE_STUB_CALL

void JSGenericLowering::ReplaceWithBuiltinCall(Node* node, Builtin builtin) {
  CallDescriptor::Flags flags = FrameStateFlagForCall(node);
  Callable callable = Builtins::CallableFor(isolate(), builtin);
  ReplaceWithBuiltinCall(node, callable, flags);
}

void JSGenericLowering::ReplaceWithBuiltinCall(Node* node, Callable callable,
                                               CallDescriptor::Flags flags) {
  ReplaceWithBuiltinCall(node, callable, flags, node->op()->properties());
}

void JSGenericLowering::ReplaceWithBuiltinCall(
    Node* node, Callable callable, CallDescriptor::Flags flags,
    Operator::Properties properties) {
  const CallInterfaceDescriptor& descriptor = callable.descriptor();
  auto call_descriptor = Linkage::GetStubCallDescriptor(
      zone(), descriptor, descriptor.GetStackParameterCount(), flags,
      properties);
  Node* stub_code = jsgraph()->HeapConstantNoHole(callable.code());
  node->InsertInput(zone(), 0, stub_code);
  NodeProperties::ChangeOp(node, common()->Call(call_descriptor));
}

void JSGenericLowering::ReplaceWithRuntimeCall(Node* node,
                                               Runtime::FunctionId f,
                                               int nargs_override) {
  CallDescriptor::Flags flags = FrameStateFlagForCall(node);
  Operator::Properties properties = node->op()->properties();
  const Runtime::Function* fun = Runtime::FunctionForId(f);
  int nargs = (nargs_override < 0) ? fun->nargs : nargs_override;
  auto call_descriptor =
      Linkage::GetRuntimeCallDescriptor(zone(), f, nargs, properties, flags);
  Node* ref = jsgraph()->ExternalConstant(ExternalReference::Create(f));
  Node* arity = jsgraph()->Int32Constant(nargs);
  node->InsertInput(zone(), 0, jsgraph()->CEntryStubConstant(fun->result_size));
  node->InsertInput(zone(), nargs + 1, ref);
  node->InsertInput(zone(), nargs + 2, arity);
  NodeProperties::ChangeOp(node, common()->Call(call_descriptor));
}

void JSGenericLowering::ReplaceUnaryOpWithBuiltinCall(
    Node* node, Builtin builtin_without_feedback,
    Builtin builtin_with_feedback) {
  DCHECK(JSOperator::IsUnaryWithFeedback(node->opcode()));
  const FeedbackParameter& p = FeedbackParameterOf(node->op());
  if (CollectFeedbackInGenericLowering() && p.feedback().IsValid()) {
    Callable callable = Builtins::CallableFor(isolate(), builtin_with_feedback);
    Node* slot = jsgraph()->UintPtrConstant(p.feedback().slot.ToInt());
    const CallInterfaceDescriptor& descriptor = callable.descriptor();
    CallDescriptor::Flags flags = FrameStateFlagForCall(node);
    auto call_descriptor = Linkage::GetStubCallDescriptor(
        zone(), descriptor, descriptor.GetStackParameterCount(), flags,
        node->op()->properties());
    Node* stub_code = jsgraph()->HeapConstantNoHole(callable.code());
    static_assert(JSUnaryOpNode::ValueIndex() == 0);
    static_assert(JSUnaryOpNode::FeedbackVectorIndex() == 1);
    DCHECK_EQ(node->op()->ValueInputCount(), 2);
    node->InsertInput(zone(), 0, stub_code);
    node->InsertInput(zone(), 2, slot);
    NodeProperties::ChangeOp(node, common()->Call(call_descriptor));
  } else {
    node->RemoveInput(JSUnaryOpNode::FeedbackVectorIndex());
    ReplaceWithBuiltinCall(node, builtin_without_feedback);
  }
}

#define DEF_UNARY_LOWERING(Name)                                    \
  void JSGenericLowering::LowerJS##Name(Node* node) {               \
    ReplaceUnaryOpWithBuiltinCall(node, Builtin::k##Name,           \
                                  Builtin::k##Name##_WithFeedback); \
  }
DEF_UNARY_LOWERING(BitwiseNot)
DEF_UNARY_LOWERING(Decrement)
DEF_UNARY_LOWERING(Increment)
DEF_UNARY_LOWERING(Negate)
#undef DEF_UNARY_LOWERING

void JSGenericLowering::ReplaceBinaryOpWithBuiltinCall(
    Node* node, Builtin builtin_without_feedback,
    Builtin builtin_with_feedback) {
  DCHECK(JSOperator::IsBinaryWithFeedback(node->opcode()));
  Builtin builtin;
  const FeedbackParameter& p = FeedbackParameterOf(node->op());
  if (CollectFeedbackInGenericLowering() && p.feedback().IsValid()) {
    Node* slot = jsgraph()->UintPtrConstant(p.feedback().slot.ToInt());
    static_assert(JSBinaryOpNode::LeftIndex() == 0);
    static_assert(JSBinaryOpNode::RightIndex() == 1);
    static_assert(JSBinaryOpNode::FeedbackVectorIndex() == 2);
    DCHECK_EQ(node->op()->ValueInputCount(), 3);
    node->InsertInput(zone(), 2, slot);
    builtin = builtin_with_feedback;
  } else {
    node->RemoveInput(JSBinaryOpNode::FeedbackVectorIndex());
    builtin = builtin_without_feedback;
  }

  ReplaceWithBuiltinCall(node, builtin);
}

#define DEF_BINARY_LOWERING(Name)                                    \
  void JSGenericLowering::LowerJS##Name(Node* node) {                \
    ReplaceBinaryOpWithBuiltinCall(node, Builtin::k##Name,           \
                                   Builtin::k##Name##_WithFeedback); \
  }
// Binary ops.
DEF_BINARY_LOWERING(Add)
DEF_BINARY_LOWERING(BitwiseAnd)
DEF_BINARY_LOWERING(BitwiseOr)
DEF_BINARY_LOWERING(BitwiseXor)
DEF_BINARY_LOWERING(Divide)
DEF_BINARY_LOWERING(Exponentiate)
DEF_BINARY_LOWERING(Modulus)
DEF_BINARY_LOWERING(Multiply)
DEF_BINARY_LOWERING(ShiftLeft)
DEF_BINARY_LOWERING(ShiftRight)
DEF_BINARY_LOWERING(ShiftRightLogical)
DEF_BINARY_LOWERING(Subtract)
// Compare ops.
DEF_BINARY_LOWERING(Equal)
DEF_BINARY_LOWERING(GreaterThan)
DEF_BINARY_LOWERING(GreaterThanOrEqual)
DEF_BINARY_LOWERING(InstanceOf)
DEF_BINARY_LOWERING(LessThan)
DEF_BINARY_LOWERING(LessThanOrEqual)
#undef DEF_BINARY_LOWERING

void JSGenericLowering::LowerJSStrictEqual(Node* node) {
  // The === operator doesn't need the current context.
  NodeProperties::ReplaceContextInput(node, jsgraph()->NoContextConstant());
  DCHECK_EQ(node->op()->ControlInputCount(), 1);
  node->RemoveInput(NodeProperties::FirstControlIndex(node));

  Builtin builtin;
  const FeedbackParameter& p = FeedbackParameterOf(node->op());
  if (CollectFeedbackInGenericLowering() && p.feedback().IsValid()) {
    Node* slot = jsgraph()->UintPtrConstant(p.feedback().slot.ToInt());
    static_assert(JSStrictEqualNode::LeftIndex() == 0);
    static_assert(JSStrictEqualNode::RightIndex() == 1);
    static_assert(JSStrictEqualNode::FeedbackVectorIndex() == 2);
    DCHECK_EQ(node->op()->ValueInputCount(), 3);
    node->InsertInput(zone(), 2, slot);
    builtin = Builtin::kStrictEqual_WithFeedback;
  } else {
    node->RemoveInput(JSStrictEqualNode::FeedbackVectorIndex());
    builtin = Builtin::kStrictEqual;
  }

  Callable callable = Builtins::CallableFor(isolate(), builtin);
  ReplaceWithBuiltinCall(node, callable, CallDescriptor::kNoFlags,
                         Operator::kEliminatable);
}

namespace {

// The megamorphic load/store builtin can be used as a performance optimization
// in some cases - unlike the full builtin, the megamorphic builtin does fewer
// checks and does not collect feedback.
bool ShouldUseMegamorphicAccessBuiltin(FeedbackSource const& source,
                                       OptionalNameRef name, AccessMode mode,
                                       JSHeapBroker* broker) {
  ProcessedFeedback const& feedback =
      broker->GetFeedbackForPropertyAccess(source, mode, name);

  if (feedback.kind() == ProcessedFeedback::kElementAccess) {
    return feedback.AsElementAccess().transition_groups().empty();
  } else if (feedback.kind() == ProcessedFeedback::kNamedAccess) {
    return feedback.AsNamedAccess().maps().empty();
  } else if (feedback.kind() == ProcessedFeedback::kInsufficient) {
    return false;
  }
  UNREACHABLE();
}

}  // namespace

void JSGenericLowering::LowerJSHasProperty(Node* node) {
  JSHasPropertyNode n(node);
  const PropertyAccess& p = n.Parameters();
  if (!p.feedback().IsValid()) {
    node->RemoveInput(JSHasPropertyNode::FeedbackVectorIndex());
    ReplaceWithBuiltinCall(node, Builtin::kHasProperty);
  } else {
    static_assert(n.FeedbackVectorIndex() == 2);
    n->InsertInput(zone(), 2,
                   jsgraph()->TaggedIndexConstant(p.feedback().index()));
    ReplaceWithBuiltinCall(node, Builtin::kKeyedHasIC);
  }
}

void JSGenericLowering::LowerJSLoadProperty(Node* node) {
  JSLoadPropertyNode n(node);
  const PropertyAccess& p = n.Parameters();
  FrameState frame_state = n.frame_state();
  Node* outer_state = frame_state.outer_frame_state();
  static_assert(n.FeedbackVectorIndex() == 2);
  if (outer_state->opcode() != IrOpcode::kFrameState) {
    n->RemoveInput(n.FeedbackVectorIndex());
    n->InsertInput(zone(), 2,
                   jsgraph()->TaggedIndexConstant(p.feedback().index()));
    ReplaceWithBuiltinCall(
        node, ShouldUseMegamorphicAccessBuiltin(p.feedback(), {},
                                                AccessMode::kLoad, broker())
                  ? Builtin::kKeyedLoadICTrampoline_Megamorphic
                  : Builtin::kKeyedLoadICTrampoline);
  } else {
    n->InsertInput(zone(), 2,
                   jsgraph()->TaggedIndexConstant(p.feedback().index()));
    ReplaceWithBuiltinCall(
        node, ShouldUseMegamorphicAccessBuiltin(p.feedback(), {},
                                                AccessMode::kLoad, broker())
                  ? Builtin::kKeyedLoadIC_Megamorphic
                  : Builtin::kKeyedLoadIC);
  }
}

void JSGenericLowering::LowerJSLoadNamed(Node* node) {
  JSLoadNamedNode n(node);
  NamedAccess const& p = n.Parameters();
  FrameState frame_state = n.frame_state();
  Node* outer_state = frame_state.outer_frame_state();
  static_assert(n.FeedbackVectorIndex() == 1);
  if (!p.feedback().IsValid()) {
    n->RemoveInput(n.FeedbackVectorIndex());
    node->InsertInput(zone(), 1, jsgraph()->ConstantNoHole(p.name(), broker()));
    ReplaceWithBuiltinCall(node, Builtin::kGetProperty);
  } else if (outer_state->opcode() != IrOpcode::kFrameState) {
    n->RemoveInput(n.FeedbackVectorIndex());
    node->InsertInput(zone(), 1, jsgraph()->ConstantNoHole(p.name(), broker()));
    node->InsertInput(zone(), 2,
                      jsgraph()->TaggedIndexConstant(p.feedback().index()));
    ReplaceWithBuiltinCall(
        node, ShouldUseMegamorphicAccessBuiltin(p.feedback(), p.name(),
                                                AccessMode::kLoad, broker())
                  ? Builtin::kLoadICTrampoline_Megamorphic
                  : Builtin::kLoadICTrampoline);
  } else {
    node->InsertInput(zone(), 1, jsgraph()->ConstantNoHole(p.name(), broker()));
    node->InsertInput(zone(), 2,
                      jsgraph()->TaggedIndexConstant(p.feedback().index()));
    ReplaceWithBuiltinCall(
        node, ShouldUseMegamorphicAccessBuiltin(p.feedback(), p.name(),
                                                AccessMode::kLoad, broker())
                  ? Builtin::kLoadIC_Megamorphic
                  : Builtin::kLoadIC);
  }
}

void JSGenericLowering::LowerJSLoadNamedFromSuper(Node* node) {
  JSLoadNamedFromSuperNode n(node);
  NamedAccess const& p = n.Parameters();
  Node* effect = NodeProperties::GetEffectInput(node);
  Node* control = NodeProperties::GetControlInput(node);
  // Node inputs: receiver, home object, FeedbackVector.
  // LoadSuperIC expects: receiver, lookup start object, name, slot,
  // FeedbackVector.
  Node* home_object_map = effect = graph()->NewNode(
      jsgraph()->simplified()->LoadField(AccessBuilder::ForMap()),
      n.home_object(), effect, control);
  Node* home_object_proto = effect = graph()->NewNode(
      jsgraph()->simplified()->LoadField(AccessBuilder::ForMapPrototype()),
      home_object_map, effect, control);
  n->ReplaceInput(n.HomeObjectIndex(), home_object_proto);
  NodeProperties::ReplaceEffectInput(node, effect);
  static_assert(n.FeedbackVectorIndex() == 2);
  // If the code below will be used for the invalid feedback case, it needs to
  // be double-checked that the FeedbackVector parameter will be the
  // UndefinedConstant.
  DCHECK(p.feedback().IsValid());
  node->InsertInput(zone(), 2, jsgraph()->ConstantNoHole(p.name(), broker()));
  node->InsertInput(zone(), 3,
                    jsgraph()->TaggedIndexConstant(p.feedback().index()));
  ReplaceWithBuiltinCall(node, Builtin::kLoadSuperIC);
}

void JSGenericLowering::LowerJSLoadGlobal(Node* node) {
  JSLoadGlobalNode n(node);
  const LoadGlobalParameters& p = n.Parameters();
  CallDescriptor::Flags flags = FrameStateFlagForCall(node);
  FrameState frame_state = n.frame_state();
  Node* outer_state = frame_state.outer_frame_state();
  static_assert(n.FeedbackVectorIndex() == 0);
  if (outer_state->opcode() != IrOpcode::kFrameState) {
    n->RemoveInput(n.FeedbackVectorIndex());
    node->InsertInput(zone(), 0, jsgraph()->ConstantNoHole(p.name(), broker()));
    node->InsertInput(zone(), 1,
                      jsgraph()->TaggedIndexConstant(p.feedback().index()));
    Callable callable = CodeFactory::LoadGlobalIC(isolate(), p.typeof_mode());
    ReplaceWithBuiltinCall(node, callable, flags);
  } else {
    node->InsertInput(zone(), 0, jsgraph()->ConstantNoHole(p.name(), broker()));
    node->InsertInput(zone(), 1,
                      jsgraph()->TaggedIndexConstant(p.feedback().index()));
    Callable callable =
        CodeFactory::LoadGlobalICInOptimizedCode(isolate(), p.typeof_mode());
    ReplaceWithBuiltinCall(node, callable, flags);
  }
}

void JSGenericLowering::LowerJSGetIterator(Node* node) {
  // TODO(v8:9625): Currently, the GetIterator operator is desugared in the
  // native context specialization phase. Thus, the following generic lowering
  // is not reachable unless that phase is disabled (e.g. for
  // native-context-independent code).
  // We can add a check in native context specialization to avoid desugaring
  // the GetIterator operator when feedback is megamorphic. This would reduce
  // the size of the compiled code as it would insert 1 call to the builtin
  // instead of 2 calls resulting from the generic lowering of the LoadNamed
  // and Call operators.

  JSGetIteratorNode n(node);
  GetIteratorParameters const& p = n.Parameters();
  Node* load_slot =
      jsgraph()->TaggedIndexConstant(p.loadFeedback().slot.ToInt());
  Node* call_slot =
      jsgraph()->TaggedIndexConstant(p.callFeedback().slot.ToInt());
  static_assert(n.FeedbackVectorIndex() == 1);
  node->InsertInput(zone(), 1, load_slot);
  node->InsertInput(zone(), 2, call_slot);

  ReplaceWithBuiltinCall(node, Builtin::kGetIteratorWithFeedback);
}

void JSGenericLowering::LowerJSSetKeyedProperty(Node* node) {
  JSSetKeyedPropertyNode n(node);
  const PropertyAccess& p = n.Parameters();
  FrameState frame_state = n.frame_state();
  Node* outer_state = frame_state.outer_frame_state();
  static_assert(n.FeedbackVectorIndex() == 3);
  if (outer_state->opcode() != IrOpcode::kFrameState) {
    n->RemoveInput(n.FeedbackVectorIndex());
    node->InsertInput(zone(), 3,
                      jsgraph()->TaggedIndexConstant(p.feedback().index()));

    // KeyedStoreIC is currently a base class for multiple keyed property store
    // operations and contains mixed logic for set and define operations,
    // the paths are controlled by feedback.
    // TODO(v8:12548): refactor SetKeyedIC as a subclass of KeyedStoreIC, which
    // can be called here.
    ReplaceWithBuiltinCall(
        node, ShouldUseMegamorphicAccessBuiltin(p.feedback(), {},
                                                AccessMode::kStore, broker())
                  ? Builtin::kKeyedStoreICTrampoline_Megamorphic
                  : Builtin::kKeyedStoreICTrampoline);
  } else {
    node->InsertInput(zone(), 3,
                      jsgraph()->TaggedIndexConstant(p.feedback().index()));
    ReplaceWithBuiltinCall(
        node, ShouldUseMegamorphicAccessBuiltin(p.feedback(), {},
                                                AccessMode::kStore, broker())
                  ? Builtin::kKeyedStoreIC_Megamorphic
                  : Builtin::kKeyedStoreIC);
  }
}

void JSGenericLowering::LowerJSDefineKeyedOwnProperty(Node* node) {
  JSDefineKeyedOwnPropertyNode n(node);
  const PropertyAccess& p = n.Parameters();
  FrameState frame_state = n.frame_state();
  Node* outer_state = frame_state.outer_frame_state();
  static_assert(n.FeedbackVectorIndex() == 4);
  if (outer_state->opcode() != IrOpcode::kFrameState) {
    n->RemoveInput(n.FeedbackVectorIndex());
    node->InsertInput(zone(), 4,
                      jsgraph()->TaggedIndexConstant(p.feedback().index()));
    ReplaceWithBuiltinCall(node, Builtin::kDefineKeyedOwnICTrampoline);
  } else {
    node->InsertInput(zone(), 4,
                      jsgraph()->TaggedIndexConstant(p.feedback().index()));
    ReplaceWithBuiltinCall(node, Builtin::kDefineKeyedOwnIC);
  }
}

void JSGenericLowering::LowerJSSetNamedProperty(Node* node) {
  JSSetNamedPropertyNode n(node);
  NamedAccess const& p = n.Parameters();
  FrameState frame_state = n.frame_state();
  Node* outer_state = frame_state.outer_frame_state();
  static_assert(n.FeedbackVectorIndex() == 2);
  if (!p.feedback().IsValid()) {
    n->RemoveInput(n.FeedbackVectorIndex());
    node->InsertInput(zone(), 1, jsgraph()->ConstantNoHole(p.name(), broker()));
    ReplaceWithRuntimeCall(node, Runtime::kSetNamedProperty);
  } else if (outer_state->opcode() != IrOpcode::kFrameState) {
    n->RemoveInput(n.FeedbackVectorIndex());
    node->InsertInput(zone(), 1, jsgraph()->ConstantNoHole(p.name(), broker()));
    node->InsertInput(zone(), 3,
                      jsgraph()->TaggedIndexConstant(p.feedback().index()));
    // StoreIC is currently a base class for multiple property store operations
    // and contains mixed logic for named and keyed, set and define operations,
    // the paths are controlled by feedback.
    // TODO(v8:12548): refactor SetNamedIC as a subclass of StoreIC, which can
    // be called here.
    ReplaceWithBuiltinCall(
        node, ShouldUseMegamorphicAccessBuiltin(p.feedback(), {},
                                                AccessMode::kStore, broker())
                  ? Builtin::kStoreICTrampoline_Megamorphic
                  : Builtin::kStoreICTrampoline);
  } else {
    node->InsertInput(zone(), 1, jsgraph()->ConstantNoHole(p.name(), broker()));
    node->InsertInput(zone(), 3,
                      jsgraph()->TaggedIndexConstant(p.feedback().index()));
    ReplaceWithBuiltinCall(
        node, ShouldUseMegamorphicAccessBuiltin(p.feedback(), {},
                                                AccessMode::kStore, broker())
                  ? Builtin::kStoreIC_Megamorphic
                  : Builtin::kStoreIC);
  }
}

void JSGenericLowering::LowerJSDefineNamedOwnProperty(Node* node) {
  CallDescriptor::Flags flags = FrameStateFlagForCall(node);
  JSDefineNamedOwnPropertyNode n(node);
  DefineNamedOwnPropertyParameters const& p = n.Parameters();
  FrameState frame_state = n.frame_state();
  Node* outer_state = frame_state.outer_frame_state();
  static_assert(n.FeedbackVectorIndex() == 2);
  if (outer_state->opcode() != IrOpcode::kFrameState) {
    n->RemoveInput(n.FeedbackVectorIndex());
    node->InsertInput(zone(), 1, jsgraph()->ConstantNoHole(p.name(), broker()));
    node->InsertInput(zone(), 3,
                      jsgraph()->TaggedIndexConstant(p.feedback().index()));
    Callable callable = CodeFactory::DefineNamedOwnIC(isolate());
    ReplaceWithBuiltinCall(node, callable, flags);
  } else {
    node->InsertInput(zone(), 1, jsgraph()->ConstantNoHole(p.name(), broker()));
    node->InsertInput(zone(), 3,
                      jsgraph()->TaggedIndexConstant(p.feedback().index()));
    Callable callable = CodeFactory::DefineNamedOwnICInOptimizedCode(isolate());
    ReplaceWithBuiltinCall(node, callable, flags);
  }
}

void JSGenericLowering::LowerJSStoreGlobal(Node* node) {
  JSStoreGlobalNode n(node);
  const StoreGlobalParameters& p = n.Parameters();
  FrameState frame_state = n.frame_state();
  Node* outer_state = frame_state.outer_frame_state();
  static_assert(n.FeedbackVectorIndex() == 1);
  if (outer_state->opcode() != IrOpcode::kFrameState) {
    n->RemoveInput(n.FeedbackVectorIndex());
    node->InsertInput(zone(), 0, jsgraph()->ConstantNoHole(p.name(), broker()));
    node->InsertInput(zone(), 2,
                      jsgraph()->TaggedIndexConstant(p.feedback().index()));
    ReplaceWithBuiltinCall(node, Builtin::kStoreGlobalICTrampoline);
  } else {
    node->InsertInput(zone(), 0, jsgraph()->ConstantNoHole(p.name(), broker()));
    node->InsertInput(zone(), 2,
                      jsgraph()->TaggedIndexConstant(p.feedback().index()));
    ReplaceWithBuiltinCall(node, Builtin::kStoreGlobalIC);
  }
}

void JSGenericLowering::LowerJSDefineKeyedOwnPropertyInLiteral(Node* node) {
  JSDefineKeyedOwnPropertyInLiteralNode n(node);
  FeedbackParameter const& p = n.Parameters();
  static_assert(n.FeedbackVectorIndex() == 4);
  RelaxControls(node);
  node->InsertInput(zone(), 5,
                    jsgraph()->TaggedIndexConstant(p.feedback().index()));
  ReplaceWithRuntimeCall(node, Runtime::kDefineKeyedOwnPropertyInLiteral);
}

void JSGenericLowering::LowerJSStoreInArrayLiteral(Node* node) {
  JSStoreInArrayLiteralNode n(node);
  FeedbackParameter const& p = n.Parameters();
  static_assert(n.FeedbackVectorIndex() == 3);
  RelaxControls(node);
  node->InsertInput(zone(), 3,
                    jsgraph()->TaggedIndexConstant(p.feedback().index()));
  ReplaceWithBuiltinCall(node, Builtin::kStoreInArrayLiteralIC);
}

void JSGenericLowering::LowerJSDeleteProperty(Node* node) {
  ReplaceWithBuiltinCall(node, Builtin::kDeleteProperty);
}

void JSGenericLowering::LowerJSGetSuperConstructor(Node* node) {
  Node* active_function = NodeProperties::GetValueInput(node, 0);
  Node* effect = NodeProperties::GetEffectInput(node);
  Node* control = NodeProperties::GetControlInput(node);

  Node* function_map = effect = graph()->NewNode(
      jsgraph()->simplified()->LoadField(AccessBuilder::ForMap()),
      active_function, effect, control);

  RelaxControls(node);
  node->ReplaceInput(0, function_map);
  node->ReplaceInput(1, effect);
  node->ReplaceInput(2, control);
  node->TrimInputCount(3);
  NodeProperties::ChangeOp(node, jsgraph()->simplified()->LoadField(
                                     AccessBuilder::ForMapPrototype()));
}

void JSGenericLowering::LowerJSFindNonDefaultConstructorOrConstruct(
    Node* node) {
  ReplaceWithBuiltinCall(node, Builtin::kFindNonDefaultConstructorOrConstruct);
}

void JSGenericLowering::LowerJSHasInPrototypeChain(Node* node) {
  ReplaceWithRuntimeCall(node, Runtime::kHasInPrototypeChain);
}

void JSGenericLowering::LowerJSOrdinaryHasInstance(Node* node) {
  ReplaceWithBuiltinCall(node, Builtin::kOrdinaryHasInstance);
}

void JSGenericLowering::LowerJSHasContextExtension(Node* node) {
  UNREACHABLE();  // Eliminated in typed lowering.
}

void JSGenericLowering::LowerJSLoadContext(Node* node) {
  UNREACHABLE();  // Eliminated in typed lowering.
}

void JSGenericLowering::LowerJSLoadScriptContext(Node* node) {
  UNREACHABLE();  // Eliminated in typed lowering.
}

void JSGenericLowering::LowerJSStoreContext(Node* node) {
  UNREACHABLE();  // Eliminated in typed lowering.
}

void JSGenericLowering::LowerJSStoreScriptContext(Node* node) {
  UNREACHABLE();  // Eliminated in context specialization.
}

void JSGenericLowering::LowerJSCreate(Node* node) {
  ReplaceWithBuiltinCall(node, Builtin::kFastNewObject);
}


void JSGenericLowering::LowerJSCreateArguments(Node* node) {
  CreateArgumentsType const type = CreateArgumentsTypeOf(node->op());
  switch (type) {
    case CreateArgumentsType::kMappedArguments:
      ReplaceWithRuntimeCall(node, Runtime::kNewSloppyArguments);
      break;
    case CreateArgumentsType::kUnmappedArguments:
      ReplaceWithRuntimeCall(node, Runtime::kNewStrictArguments);
      break;
    case CreateArgumentsType::kRestParameter:
      ReplaceWithRuntimeCall(node, Runtime::kNewRestParameter);
      break;
  }
}


void JSGenericLowering::LowerJSCreateArray(Node* node) {
  CreateArrayParameters const& p = CreateArrayParametersOf(node->op());
  int const arity = static_cast<int>(p.arity());
  auto interface_descriptor = ArrayConstructorDescriptor{};
  auto call_descriptor = Linkage::GetStubCallDescriptor(
      zone(), interface_descriptor, arity + 1, CallDescriptor::kNeedsFrameState,
      node->op()->properties());
  // If this fails, we might need to update the parameter reordering code
  // to ensure that the additional arguments passed via stack are pushed
  // between top of stack and JS arguments.
  DCHECK_EQ(interface_descriptor.GetStackParameterCount(), 0);
  Node* stub_code = jsgraph()->ArrayConstructorStubConstant();
  Node* stub_arity = jsgraph()->Int32Constant(JSParameterCount(arity));
  OptionalAllocationSiteRef const site = p.site();
  Node* type_info = site.has_value()
                        ? jsgraph()->ConstantNoHole(site.value(), broker())
                        : jsgraph()->UndefinedConstant();
  Node* receiver = jsgraph()->UndefinedConstant();
  node->InsertInput(zone(), 0, stub_code);
  node->InsertInput(zone(), 3, stub_arity);
  node->InsertInput(zone(), 4, type_info);
  node->InsertInput(zone(), 5, receiver);
  NodeProperties::ChangeOp(node, common()->Call(call_descriptor));
}

void JSGenericLowering::LowerJSCreateArrayIterator(Node* node) {
  UNREACHABLE();  // Eliminated in typed lowering.
}

void JSGenericLowering::LowerJSCreateAsyncFunctionObject(Node* node) {
  UNREACHABLE();  // Eliminated in typed lowering.
}

void JSGenericLowering::LowerJSCreateCollectionIterator(Node* node) {
  UNREACHABLE();  // Eliminated in typed lowering.
}

void JSGenericLowering::LowerJSCreateBoundFunction(Node* node) {
  UNREACHABLE();  // Eliminated in typed lowering.
}

void JSGenericLowering::LowerJSObjectIsArray(Node* node) {
  UNREACHABLE();  // Eliminated in typed lowering.
}

void JSGenericLowering::LowerJSCreateObject(Node* node) {
  ReplaceWithBuiltinCall(node, Builtin::kCreateObjectWithoutProperties);
}

void JSGenericLowering::LowerJSCreateStringWrapper(Node* node) {
  UNREACHABLE();  // Eliminated in typed lowering.
}

void JSGenericLowering::LowerJSParseInt(Node* node) {
  ReplaceWithBuiltinCall(node, Builtin::kParseInt);
}

void JSGenericLowering::LowerJSRegExpTest(Node* node) {
  ReplaceWithBuiltinCall(node, Builtin::kRegExpPrototypeTestFast);
}

void JSGenericLowering::LowerJSCreateClosure(Node* node) {
  JSCreateClosureNode n(node);
  CreateClosureParameters const& p = n.Parameters();
  SharedFunctionInfoRef shared_info = p.shared_info();
  static_assert(n.FeedbackCellIndex() == 0);
  node->InsertInput(zone(), 0,
                    jsgraph()->ConstantNoHole(shared_info, broker()));
  node->RemoveInput(4);  // control

  // Use the FastNewClosure builtin only for functions allocated in new space.
  if (p.allocation() == AllocationType::kYoung) {
    ReplaceWithBuiltinCall(node, Builtin::kFastNewClosure);
  } else {
    ReplaceWithRuntimeCall(node, Runtime::kNewClosure_Tenured);
  }
}

void JSGenericLowering::LowerJSCreateFunctionContext(Node* node) {
  const CreateFunctionContextParameters& parameters =
      CreateFunctionContextParametersOf(node->op());
  ScopeInfoRef scope_info = parameters.scope_info();
  int slot_count = parameters.slot_count();
  ScopeType scope_type = parameters.scope_type();
  CallDescriptor::Flags flags = FrameStateFlagForCall(node);

  if (slot_count <= ConstructorBuiltins::MaximumFunctionContextSlots()) {
    Callable callable =
        CodeFactory::FastNewFunctionContext(isolate(), scope_type);
    node->InsertInput(zone(), 0,
                      jsgraph()->ConstantNoHole(scope_info, broker()));
    node->InsertInput(zone(), 1, jsgraph()->Int32Constant(slot_count));
    ReplaceWithBuiltinCall(node, callable, flags);
  } else {
    node->InsertInput(zone(), 0,
                      jsgraph()->ConstantNoHole(scope_info, broker()));
    ReplaceWithRuntimeCall(node, Runtime::kNewFunctionContext);
  }
}

void JSGenericLowering::LowerJSCreateGeneratorObject(Node* node) {
  node->RemoveInput(4);  // control
  ReplaceWithBuiltinCall(node, Builtin::kCreateGeneratorObject);
}

void JSGenericLowering::LowerJSCreateIterResultObject(Node* node) {
  ReplaceWithBuiltinCall(node, Builtin::kCreateIterResultObject);
}

void JSGenericLowering::LowerJSCreateStringIterator(Node* node) {
  UNREACHABLE();  // Eliminated in typed lowering.
}

void JSGenericLowering::LowerJSCreateKeyValueArray(Node* node) {
  UNREACHABLE();  // Eliminated in typed lowering.
}

void JSGenericLowering::LowerJSCreatePromise(Node* node) {
  UNREACHABLE();  // Eliminated in typed lowering.
}

void JSGenericLowering::LowerJSCreateTypedArray(Node* node) {
  ReplaceWithBuiltinCall(node, Builtin::kCreateTypedArray);
}

void JSGenericLowering::LowerJSCreateLiteralArray(Node* node) {
  JSCreateLiteralArrayNode n(node);
  CreateLiteralParameters const& p = n.Parameters();
  static_assert(n.FeedbackVectorIndex() == 0);
  node->InsertInput(zone(), 1,
                    jsgraph()->TaggedIndexConstant(p.feedback().index()));
  node->InsertInput(zone(), 2,
                    jsgraph()->ConstantNoHole(p.constant(), broker()));
  node->InsertInput(zone(), 3, jsgraph()->SmiConstant(p.flags()));

  // Use the CreateShallowArrayLiteral builtin only for shallow boilerplates
  // without properties up to the number of elements that the stubs can handle.
  if ((p.flags() & AggregateLiteral::kIsShallow) != 0 &&
      p.length() < ConstructorBuiltins::kMaximumClonedShallowArrayElements) {
    ReplaceWithBuiltinCall(node, Builtin::kCreateShallowArrayLiteral);
  } else {
    ReplaceWithBuiltinCall(node, Builtin::kCreateArrayFromSlowBoilerplate);
  }
}

void JSGenericLowering::LowerJSGetTemplateObject(Node* node) {
  JSGetTemplateObjectNode n(node);
  GetTemplateObjectParameters const& p = n.Parameters();
  SharedFunctionInfoRef shared = p.shared();
  TemplateObjectDescriptionRef description = p.description();

  DCHECK_EQ(node->op()->ControlInputCount(), 1);
  node->RemoveInput(NodeProperties::FirstControlIndex(node));

  static_assert(JSGetTemplateObjectNode::FeedbackVectorIndex() == 0);
  node->InsertInput(zone(), 0, jsgraph()->ConstantNoHole(shared, broker()));
  node->InsertInput(zone(), 1,
                    jsgraph()->ConstantNoHole(description, broker()));
  node->InsertInput(zone(), 2,
                    jsgraph()->UintPtr
"""


```