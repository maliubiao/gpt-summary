Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/src/compiler/js-generic-lowering.cc`.

Here's a breakdown of the thought process to answer the request:

1. **Identify the core purpose:** The file name `js-generic-lowering.cc` suggests that this code is responsible for lowering generic JavaScript operations into more specific, lower-level operations within the V8 compiler. The presence of methods like `LowerJS...` further reinforces this idea.

2. **Analyze the individual `LowerJS...` functions:**  Each function targets a specific JavaScript operation (e.g., `JSCreateTemplateObject`, `JSCreateEmptyLiteralArray`, `JSCall`). The general pattern within these functions is:
    * Identify the specific JavaScript operation being handled.
    * Extract relevant parameters from the node representing the operation in the compiler's intermediate representation.
    * Potentially modify the inputs to the node (e.g., inserting constants, feedback vector indices).
    * Replace the generic JavaScript operation node with a call to a specific built-in function (`Builtin::k...`) or a runtime function (`Runtime::k...`).

3. **Infer the overall functionality:** Based on the individual function analysis, the overall purpose of `js-generic-lowering.cc` is to transform high-level, generic JavaScript operations into lower-level primitives that the V8 engine can execute more efficiently. This involves selecting the appropriate built-in or runtime functions based on the specific JavaScript operation.

4. **Address the `.tq` file question:** The prompt explicitly asks about the `.tq` extension. The code is C++, so it's not a Torque file. State this fact clearly.

5. **Connect to JavaScript functionality and provide examples:** For each category of lowered operations (object creation, function calls, context manipulation, etc.), provide corresponding JavaScript code snippets. This helps illustrate what the C++ code is doing at a higher level. For example:
    * `LowerJSCreateTemplateObject` relates to template literals.
    * `LowerJSCreateEmptyLiteralArray` relates to creating empty arrays.
    * `LowerJSCall` relates to function calls.

6. **Address code logic reasoning:**  The core logic revolves around mapping generic operations to specific built-ins or runtime functions. The "input" is the generic JavaScript operation node, and the "output" is the modified node representing a built-in or runtime call. Give an example like `LowerJSCreateEmptyLiteralArray`.

7. **Identify common programming errors:**  Consider what kinds of JavaScript errors might be related to the operations being lowered. For instance, incorrect arguments to function calls (`LowerJSCall`), using `new` on a non-constructor (`LowerJSConstruct`), or issues with template literals (`LowerJSCreateTemplateObject`).

8. **Summarize the functionality (as requested in Part 2):**  Consolidate the findings into a concise summary that highlights the key responsibilities of the code.

9. **Review and refine:** Ensure the explanation is clear, accurate, and addresses all aspects of the prompt. Check for any ambiguities or missing information. For example, initially, I might have missed explicitly mentioning the role of feedback vectors, so I'd go back and add that detail. Also, ensure the JavaScript examples are simple and directly relevant.
这是v8源代码文件 `v8/src/compiler/js-generic-lowering.cc` 的第二部分。结合第一部分，我们可以归纳一下它的功能：

**整体功能归纳：**

`v8/src/compiler/js-generic-lowering.cc` 文件是 V8 编译器中一个关键的组件，负责将通用的 JavaScript 操作（在编译器的中间表示中以 `JS` 开头的节点表示）降低（lowering）到更具体的、更接近底层实现的内置函数调用（`Builtin::k...`) 或运行时调用 (`Runtime::k...`)。

**具体功能点（基于第二部分的代码）：**

* **创建和操作 JavaScript 对象和数组：**
    * `LowerJSCreateTemplateObject`: 将创建模板字面量的操作降低为调用 `Builtin::kGetTemplateObject`。
    * `LowerJSCreateEmptyLiteralArray`: 将创建空数组字面量的操作降低为调用 `Builtin::kCreateEmptyArrayLiteral`。
    * `LowerJSCreateArrayFromIterable`: 将从可迭代对象创建数组的操作降低为调用 `Builtin::kIterableToListWithSymbolLookup`。
    * `LowerJSCreateLiteralObject`: 将创建对象字面量的操作降低为调用 `Builtin::kCreateShallowObjectLiteral` (对于浅层字面量) 或 `Builtin::kCreateObjectFromSlowBoilerplate`。
    * `LowerJSCloneObject`: 将克隆对象的操作降低为调用 `Builtin::kCloneObjectIC`。
    * `LowerJSCreateEmptyLiteralObject`: 将创建空对象字面量的操作降低为调用 `Builtin::kCreateEmptyLiteralObject`。
    * `LowerJSCreateLiteralRegExp`: 将创建正则表达式字面量的操作降低为调用 `Builtin::kCreateRegExpLiteral`。

* **处理作用域和上下文：**
    * `LowerJSCreateCatchContext`: 将创建 `catch` 上下文的操作降低为调用运行时函数 `Runtime::kPushCatchContext`。
    * `LowerJSCreateWithContext`: 将创建 `with` 上下文的操作降低为调用运行时函数 `Runtime::kPushWithContext`。
    * `LowerJSCreateBlockContext`: 将创建块级作用域上下文的操作降低为调用运行时函数 `Runtime::kPushBlockContext`。

* **处理函数调用和构造函数调用：**
    * `LowerJSConstructForwardVarargs`: 将转发可变参数的构造函数调用降低为调用 `CodeFactory::ConstructForwardVarargs` 生成的代码。
    * `LowerJSConstructForwardAllArgs`: 将转发所有参数的构造函数调用降低为调用内置函数 `Builtin::kConstructForwardAllArgs`。
    * `LowerJSConstruct`: 将构造函数调用降低为调用内置函数 `Builtin::kConstruct`。
    * `LowerJSConstructWithArrayLike`: 将使用类数组对象作为参数的构造函数调用降低为调用内置函数 `Builtin::kConstructWithArrayLike`。
    * `LowerJSConstructWithSpread`: 将使用扩展运算符的构造函数调用降低为调用 `CodeFactory::ConstructWithSpread` 生成的代码。
    * `LowerJSCallForwardVarargs`: 将转发可变参数的函数调用降低为调用 `CodeFactory::CallForwardVarargs` 生成的代码。
    * `LowerJSCall`: 将函数调用降低为调用 `CodeFactory::Call` 生成的代码。
    * `LowerJSCallWithArrayLike`: 将使用类数组对象作为参数的函数调用降低为调用 `CodeFactory::CallWithArrayLike` 生成的代码。
    * `LowerJSCallWithSpread`: 将使用扩展运算符的函数调用降低为调用 `CodeFactory::CallWithSpread` 生成的代码。
    * `LowerJSCallRuntime`: 将调用运行时函数的节点替换为实际的运行时调用。

* **其他操作：**
    * `LowerJSGetImportMeta`: 将获取 `import.meta` 的操作降低为调用运行时函数 `Runtime::kGetImportMetaObject`。
    * `LowerJSStackCheck`: 将堆栈检查操作降低为对特定内置函数（如函数入口的堆栈检查）或运行时函数的调用。
    * `LowerJSDebugger`: 将 `debugger` 语句降低为调用运行时函数 `Runtime::kHandleDebuggerStatement`。

**关于 `.tq` 扩展名：**

正如代码注释中指出的，如果 `v8/src/compiler/js-generic-lowering.cc` 以 `.tq` 结尾，那它才是一个 V8 Torque 源代码文件。但实际上，该文件是 `.cc` 结尾，因此它是 **C++ 源代码**。 Torque 是一种用于定义 V8 内部运行时函数的领域特定语言，它会生成 C++ 代码。

**与 JavaScript 功能的关系及示例：**

以下是一些代码段的功能与 JavaScript 代码示例的对应关系：

* **`LowerJSCreateTemplateObject`:**
  ```javascript
  const name = "World";
  const greeting = `Hello, ${name}!`;
  ```
  这段代码中的模板字面量 `` `Hello, ${name}!` `` 会触发 `LowerJSCreateTemplateObject` 的处理。

* **`LowerJSCreateEmptyLiteralArray`:**
  ```javascript
  const arr = [];
  ```
  创建一个空数组字面量 `[]` 会触发 `LowerJSCreateEmptyLiteralArray` 的处理。

* **`LowerJSCreateLiteralObject`:**
  ```javascript
  const obj = { a: 1, b: 2 };
  ```
  创建一个对象字面量 `{ a: 1, b: 2 }` 会触发 `LowerJSCreateLiteralObject` 的处理。

* **`LowerJSCall`:**
  ```javascript
  function greet(name) {
    console.log("Hello, " + name);
  }
  greet("Alice");
  ```
  调用函数 `greet("Alice")` 会触发 `LowerJSCall` 的处理。

* **`LowerJSConstruct`:**
  ```javascript
  class MyClass {}
  const instance = new MyClass();
  ```
  使用 `new` 关键字创建对象 `new MyClass()` 会触发 `LowerJSConstruct` 的处理。

* **`LowerJSCreateCatchContext`:**
  ```javascript
  try {
    // 可能会抛出错误的代码
  } catch (error) {
    console.error("An error occurred:", error);
  }
  ```
  `catch` 块的创建会触发 `LowerJSCreateCatchContext` 的处理。

* **`LowerJSCreateWithContext`:**
  ```javascript
  const obj = { x: 10 };
  with (obj) {
    console.log(x); // 访问 obj.x
  }
  ```
  `with` 语句会触发 `LowerJSCreateWithContext` 的处理。 (注意：`with` 语句在严格模式下禁用，并且通常不推荐使用)。

**代码逻辑推理的假设输入与输出：**

以 `LowerJSCreateEmptyLiteralArray` 为例：

**假设输入:** 一个表示创建空数组字面量的 `JSCreateEmptyLiteralArray` 节点，可能包含以下信息：
* 操作码：`IrOpcode::kJSCreateEmptyLiteralArray`
* 反馈向量槽的索引

**处理过程:**
1. 获取反馈向量槽的索引。
2. 创建一个表示反馈向量索引的 `TaggedIndexConstant` 节点。
3. 将该常量节点插入到原始节点的输入中。
4. 移除表示控制流的输入。
5. 将原始节点的操作码更改为 `IrOpcode::kCall`，并将其指向 `Builtin::kCreateEmptyArrayLiteral`。

**假设输出:** 原始的 `JSCreateEmptyLiteralArray` 节点被替换为一个调用内置函数 `kCreateEmptyArrayLiteral` 的 `Call` 节点，其中包含了反馈向量索引作为参数。

**涉及用户常见的编程错误：**

这些 lowering 过程通常发生在编译阶段，因此直接与用户的运行时错误关联较少。然而，它们与 V8 如何优化和执行 JavaScript 代码息息相关。一些可能间接关联的编程错误包括：

* **不规范的对象或数组字面量创建：**  虽然 lowering 过程会处理各种字面量创建，但过于复杂或动态的字面量可能会导致优化受阻，性能下降。
* **过度使用 `with` 语句：**  `LowerJSCreateWithContext` 的存在表明 V8 必须处理 `with` 语句，但由于其动态作用域的特性，它会使代码更难优化，并可能导致意外的变量访问。
* **不正确的函数调用参数：**  虽然 lowering 过程本身不直接捕获参数错误，但它为后续的调用准备了参数和调用描述符，如果 JavaScript 代码传递了错误的参数数量或类型，则会在运行时导致错误。例如，在 `LowerJSCall` 中，会设置参数数量，如果实际调用时参数不匹配，则会出错。
* **在非构造函数上使用 `new`：** `LowerJSConstruct` 负责处理构造函数调用，如果在非构造函数上使用 `new`，虽然 lowering 过程会将操作降低，但在运行时会抛出 `TypeError`。

**总结（针对第二部分）：**

第二部分的代码主要关注于将 JavaScript 中与 **创建对象、数组、正则表达式，处理作用域上下文，以及各种形式的函数和构造函数调用** 相关的通用操作转换为对 V8 内部内置函数或运行时函数的调用。这为后续的优化和代码生成阶段奠定了基础。  它体现了编译器将高级语言结构转换为更低级、更具体操作的关键步骤。

Prompt: 
```
这是目录为v8/src/compiler/js-generic-lowering.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/js-generic-lowering.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""
Constant(p.feedback().index()));

  ReplaceWithBuiltinCall(node, Builtin::kGetTemplateObject);
}

void JSGenericLowering::LowerJSCreateEmptyLiteralArray(Node* node) {
  JSCreateEmptyLiteralArrayNode n(node);
  FeedbackParameter const& p = n.Parameters();
  static_assert(n.FeedbackVectorIndex() == 0);
  node->InsertInput(zone(), 1,
                    jsgraph()->TaggedIndexConstant(p.feedback().index()));
  node->RemoveInput(4);  // control
  ReplaceWithBuiltinCall(node, Builtin::kCreateEmptyArrayLiteral);
}

void JSGenericLowering::LowerJSCreateArrayFromIterable(Node* node) {
  ReplaceWithBuiltinCall(node, Builtin::kIterableToListWithSymbolLookup);
}

void JSGenericLowering::LowerJSCreateLiteralObject(Node* node) {
  JSCreateLiteralObjectNode n(node);
  CreateLiteralParameters const& p = n.Parameters();
  static_assert(n.FeedbackVectorIndex() == 0);
  node->InsertInput(zone(), 1,
                    jsgraph()->TaggedIndexConstant(p.feedback().index()));
  node->InsertInput(zone(), 2,
                    jsgraph()->ConstantNoHole(p.constant(), broker()));
  node->InsertInput(zone(), 3, jsgraph()->SmiConstant(p.flags()));

  // Use the CreateShallowObjectLiteratal builtin only for shallow boilerplates
  // without elements up to the number of properties that the stubs can handle.
  if ((p.flags() & AggregateLiteral::kIsShallow) != 0 &&
      p.length() <=
          ConstructorBuiltins::kMaximumClonedShallowObjectProperties) {
    ReplaceWithBuiltinCall(node, Builtin::kCreateShallowObjectLiteral);
  } else {
    ReplaceWithBuiltinCall(node, Builtin::kCreateObjectFromSlowBoilerplate);
  }
}

void JSGenericLowering::LowerJSCloneObject(Node* node) {
  JSCloneObjectNode n(node);
  CloneObjectParameters const& p = n.Parameters();
  static_assert(n.FeedbackVectorIndex() == 1);
  node->InsertInput(zone(), 1, jsgraph()->SmiConstant(p.flags()));
  node->InsertInput(zone(), 2,
                    jsgraph()->TaggedIndexConstant(p.feedback().index()));
  ReplaceWithBuiltinCall(node, Builtin::kCloneObjectIC);
}

void JSGenericLowering::LowerJSCreateEmptyLiteralObject(Node* node) {
  ReplaceWithBuiltinCall(node, Builtin::kCreateEmptyLiteralObject);
}

void JSGenericLowering::LowerJSCreateLiteralRegExp(Node* node) {
  JSCreateLiteralRegExpNode n(node);
  CreateLiteralParameters const& p = n.Parameters();
  static_assert(n.FeedbackVectorIndex() == 0);
  node->InsertInput(zone(), 1,
                    jsgraph()->TaggedIndexConstant(p.feedback().index()));
  node->InsertInput(zone(), 2,
                    jsgraph()->ConstantNoHole(p.constant(), broker()));
  node->InsertInput(zone(), 3, jsgraph()->SmiConstant(p.flags()));
  ReplaceWithBuiltinCall(node, Builtin::kCreateRegExpLiteral);
}


void JSGenericLowering::LowerJSCreateCatchContext(Node* node) {
  ScopeInfoRef scope_info = ScopeInfoOf(node->op());
  node->InsertInput(zone(), 1, jsgraph()->ConstantNoHole(scope_info, broker()));
  ReplaceWithRuntimeCall(node, Runtime::kPushCatchContext);
}

void JSGenericLowering::LowerJSCreateWithContext(Node* node) {
  ScopeInfoRef scope_info = ScopeInfoOf(node->op());
  node->InsertInput(zone(), 1, jsgraph()->ConstantNoHole(scope_info, broker()));
  ReplaceWithRuntimeCall(node, Runtime::kPushWithContext);
}

void JSGenericLowering::LowerJSCreateBlockContext(Node* node) {
  ScopeInfoRef scope_info = ScopeInfoOf(node->op());
  node->InsertInput(zone(), 0, jsgraph()->ConstantNoHole(scope_info, broker()));
  ReplaceWithRuntimeCall(node, Runtime::kPushBlockContext);
}

// TODO(jgruber,v8:8888): Should this collect feedback?
void JSGenericLowering::LowerJSConstructForwardVarargs(Node* node) {
  ConstructForwardVarargsParameters p =
      ConstructForwardVarargsParametersOf(node->op());
  int const arg_count = static_cast<int>(p.arity() - 2);
  CallDescriptor::Flags flags = FrameStateFlagForCall(node);
  Callable callable = CodeFactory::ConstructForwardVarargs(isolate());
  // If this fails, we might need to update the parameter reordering code
  // to ensure that the additional arguments passed via stack are pushed
  // between top of stack and JS arguments.
  DCHECK_EQ(callable.descriptor().GetStackParameterCount(), 0);
  auto call_descriptor = Linkage::GetStubCallDescriptor(
      zone(), callable.descriptor(), arg_count + 1, flags);
  Node* stub_code = jsgraph()->HeapConstantNoHole(callable.code());
  Node* stub_arity = jsgraph()->Int32Constant(JSParameterCount(arg_count));
  Node* start_index = jsgraph()->Uint32Constant(p.start_index());
  Node* receiver = jsgraph()->UndefinedConstant();
  node->InsertInput(zone(), 0, stub_code);
  node->InsertInput(zone(), 3, stub_arity);
  node->InsertInput(zone(), 4, start_index);
  node->InsertInput(zone(), 5, receiver);
  NodeProperties::ChangeOp(node, common()->Call(call_descriptor));
}

void JSGenericLowering::LowerJSConstructForwardAllArgs(Node* node) {
  // Inlined JSConstructForwardAllArgs are reduced earlier in the pipeline in
  // JSCallReducer.
  DCHECK(FrameState{NodeProperties::GetFrameStateInput(node)}
             .outer_frame_state()
             ->opcode() != IrOpcode::kFrameState);

  JSConstructForwardAllArgsNode n(node);

  // Call a builtin for forwarding the arguments of non-inlined (i.e. outermost)
  // frames.
  Callable callable =
      Builtins::CallableFor(isolate(), Builtin::kConstructForwardAllArgs);
  DCHECK_EQ(callable.descriptor().GetStackParameterCount(), 0);
  auto call_descriptor = Linkage::GetStubCallDescriptor(
      zone(), callable.descriptor(), 0, CallDescriptor::kNeedsFrameState);

  Node* stub_code = jsgraph()->HeapConstantNoHole(callable.code());

  // Shuffling inputs.
  // Before: {target, new target, feedback vector}
  node->RemoveInput(n.FeedbackVectorIndex());
  node->InsertInput(zone(), 0, stub_code);
  // After: {code, target, new target}
  NodeProperties::ChangeOp(node, common()->Call(call_descriptor));
}

void JSGenericLowering::LowerJSConstruct(Node* node) {
  JSConstructNode n(node);
  ConstructParameters const& p = n.Parameters();
  int const arg_count = p.arity_without_implicit_args();
  CallDescriptor::Flags flags = FrameStateFlagForCall(node);

  static constexpr int kReceiver = 1;

  const int stack_argument_count = arg_count + kReceiver;
  Callable callable = Builtins::CallableFor(isolate(), Builtin::kConstruct);
  auto call_descriptor = Linkage::GetStubCallDescriptor(
      zone(), callable.descriptor(), stack_argument_count, flags);
  Node* stub_code = jsgraph()->HeapConstantNoHole(callable.code());
  Node* stub_arity = jsgraph()->Int32Constant(JSParameterCount(arg_count));
  Node* receiver = jsgraph()->UndefinedConstant();
  node->RemoveInput(n.FeedbackVectorIndex());
  node->InsertInput(zone(), 0, stub_code);
  node->InsertInput(zone(), 3, stub_arity);
  node->InsertInput(zone(), 4, receiver);

  // After: {code, target, new_target, arity, receiver, ...args}.

  NodeProperties::ChangeOp(node, common()->Call(call_descriptor));
}

void JSGenericLowering::LowerJSConstructWithArrayLike(Node* node) {
  JSConstructWithArrayLikeNode n(node);
  ConstructParameters const& p = n.Parameters();
  CallDescriptor::Flags flags = FrameStateFlagForCall(node);
  const int arg_count = p.arity_without_implicit_args();
  DCHECK_EQ(arg_count, 1);

  static constexpr int kReceiver = 1;
  static constexpr int kArgumentList = 1;

  const int stack_argument_count = arg_count - kArgumentList + kReceiver;
  Callable callable =
      Builtins::CallableFor(isolate(), Builtin::kConstructWithArrayLike);
  // If this fails, we might need to update the parameter reordering code
  // to ensure that the additional arguments passed via stack are pushed
  // between top of stack and JS arguments.
  DCHECK_EQ(callable.descriptor().GetStackParameterCount(), 0);
  auto call_descriptor = Linkage::GetStubCallDescriptor(
      zone(), callable.descriptor(), stack_argument_count, flags);
  Node* stub_code = jsgraph()->HeapConstantNoHole(callable.code());
  Node* receiver = jsgraph()->UndefinedConstant();
  node->RemoveInput(n.FeedbackVectorIndex());
  node->InsertInput(zone(), 0, stub_code);
  node->InsertInput(zone(), 4, receiver);

  // After: {code, target, new_target, arguments_list, receiver}.

  NodeProperties::ChangeOp(node, common()->Call(call_descriptor));
}

void JSGenericLowering::LowerJSConstructWithSpread(Node* node) {
  JSConstructWithSpreadNode n(node);
  ConstructParameters const& p = n.Parameters();
  int const arg_count = p.arity_without_implicit_args();
  DCHECK_GE(arg_count, 1);
  CallDescriptor::Flags flags = FrameStateFlagForCall(node);

  static constexpr int kReceiver = 1;
  static constexpr int kTheSpread = 1;  // Included in `arg_count`.

  const int stack_argument_count = arg_count + kReceiver - kTheSpread;
  Callable callable = CodeFactory::ConstructWithSpread(isolate());
  // If this fails, we might need to update the parameter reordering code
  // to ensure that the additional arguments passed via stack are pushed
  // between top of stack and JS arguments.
  DCHECK_EQ(callable.descriptor().GetStackParameterCount(), 0);
  auto call_descriptor = Linkage::GetStubCallDescriptor(
      zone(), callable.descriptor(), stack_argument_count, flags);
  Node* stub_code = jsgraph()->HeapConstantNoHole(callable.code());

  // We pass the spread in a register, not on the stack.
  Node* stub_arity =
      jsgraph()->Int32Constant(JSParameterCount(arg_count - kTheSpread));
  Node* receiver = jsgraph()->UndefinedConstant();
  DCHECK(n.FeedbackVectorIndex() > n.LastArgumentIndex());
  node->RemoveInput(n.FeedbackVectorIndex());
  Node* spread = node->RemoveInput(n.LastArgumentIndex());

  node->InsertInput(zone(), 0, stub_code);
  node->InsertInput(zone(), 3, stub_arity);
  node->InsertInput(zone(), 4, spread);
  node->InsertInput(zone(), 5, receiver);

  // After: {code, target, new_target, arity, spread, receiver, ...args}.

  NodeProperties::ChangeOp(node, common()->Call(call_descriptor));
}

void JSGenericLowering::LowerJSCallForwardVarargs(Node* node) {
  CallForwardVarargsParameters p = CallForwardVarargsParametersOf(node->op());
  int const arg_count = static_cast<int>(p.arity() - 2);
  CallDescriptor::Flags flags = FrameStateFlagForCall(node);
  Callable callable = CodeFactory::CallForwardVarargs(isolate());
  auto call_descriptor = Linkage::GetStubCallDescriptor(
      zone(), callable.descriptor(), arg_count + 1, flags);
  Node* stub_code = jsgraph()->HeapConstantNoHole(callable.code());
  Node* stub_arity = jsgraph()->Int32Constant(JSParameterCount(arg_count));
  Node* start_index = jsgraph()->Uint32Constant(p.start_index());
  node->InsertInput(zone(), 0, stub_code);
  node->InsertInput(zone(), 2, stub_arity);
  node->InsertInput(zone(), 3, start_index);
  NodeProperties::ChangeOp(node, common()->Call(call_descriptor));
}

void JSGenericLowering::LowerJSCall(Node* node) {
  JSCallNode n(node);
  CallParameters const& p = n.Parameters();
  int const arg_count = p.arity_without_implicit_args();
  ConvertReceiverMode const mode = p.convert_mode();

  node->RemoveInput(n.FeedbackVectorIndex());

  Callable callable = CodeFactory::Call(isolate(), mode);
  CallDescriptor::Flags flags = FrameStateFlagForCall(node);
  auto call_descriptor = Linkage::GetStubCallDescriptor(
      zone(), callable.descriptor(), arg_count + 1, flags);
  Node* stub_code = jsgraph()->HeapConstantNoHole(callable.code());
  Node* stub_arity = jsgraph()->Int32Constant(JSParameterCount(arg_count));
  node->InsertInput(zone(), 0, stub_code);
  node->InsertInput(zone(), 2, stub_arity);
  NodeProperties::ChangeOp(node, common()->Call(call_descriptor));
}

void JSGenericLowering::LowerJSCallWithArrayLike(Node* node) {
  JSCallWithArrayLikeNode n(node);
  CallParameters const& p = n.Parameters();
  const int arg_count = p.arity_without_implicit_args();
  DCHECK_EQ(arg_count, 1);  // The arraylike object.
  CallDescriptor::Flags flags = FrameStateFlagForCall(node);

  static constexpr int kArgumentsList = 1;
  static constexpr int kReceiver = 1;

  const int stack_argument_count = arg_count - kArgumentsList + kReceiver;
  Callable callable = CodeFactory::CallWithArrayLike(isolate());
  auto call_descriptor = Linkage::GetStubCallDescriptor(
      zone(), callable.descriptor(), stack_argument_count, flags);
  Node* stub_code = jsgraph()->HeapConstantNoHole(callable.code());
  Node* receiver = n.receiver();
  Node* arguments_list = n.Argument(0);

  // Shuffling inputs.
  // Before: {target, receiver, arguments_list, vector}.

  node->RemoveInput(n.FeedbackVectorIndex());
  node->InsertInput(zone(), 0, stub_code);
  node->ReplaceInput(2, arguments_list);
  node->ReplaceInput(3, receiver);

  // After: {code, target, arguments_list, receiver}.

  NodeProperties::ChangeOp(node, common()->Call(call_descriptor));
}

void JSGenericLowering::LowerJSCallWithSpread(Node* node) {
  JSCallWithSpreadNode n(node);
  CallParameters const& p = n.Parameters();
  int const arg_count = p.arity_without_implicit_args();
  DCHECK_GE(arg_count, 1);  // At least the spread.
  CallDescriptor::Flags flags = FrameStateFlagForCall(node);

  static constexpr int kReceiver = 1;
  static constexpr int kTheSpread = 1;

  const int stack_argument_count = arg_count - kTheSpread + kReceiver;
  Callable callable = CodeFactory::CallWithSpread(isolate());
  // If this fails, we might need to update the parameter reordering code
  // to ensure that the additional arguments passed via stack are pushed
  // between top of stack and JS arguments.
  DCHECK_EQ(callable.descriptor().GetStackParameterCount(), 0);
  auto call_descriptor = Linkage::GetStubCallDescriptor(
      zone(), callable.descriptor(), stack_argument_count, flags);
  Node* stub_code = jsgraph()->HeapConstantNoHole(callable.code());

  // We pass the spread in a register, not on the stack.
  Node* stub_arity =
      jsgraph()->Int32Constant(JSParameterCount(arg_count - kTheSpread));

  // Shuffling inputs.
  // Before: {target, receiver, ...args, spread, vector}.

  node->RemoveInput(n.FeedbackVectorIndex());
  Node* spread = node->RemoveInput(n.LastArgumentIndex());

  node->InsertInput(zone(), 0, stub_code);
  node->InsertInput(zone(), 2, stub_arity);
  node->InsertInput(zone(), 3, spread);

  // After: {code, target, arity, spread, receiver, ...args}.

  NodeProperties::ChangeOp(node, common()->Call(call_descriptor));
}

void JSGenericLowering::LowerJSCallRuntime(Node* node) {
  const CallRuntimeParameters& p = CallRuntimeParametersOf(node->op());
  ReplaceWithRuntimeCall(node, p.id(), static_cast<int>(p.arity()));
}

#if V8_ENABLE_WEBASSEMBLY
// Will be lowered in SimplifiedLowering.
void JSGenericLowering::LowerJSWasmCall(Node* node) {}
#endif  // V8_ENABLE_WEBASSEMBLY

void JSGenericLowering::LowerJSForInPrepare(Node* node) {
  UNREACHABLE();  // Eliminated in typed lowering.
}

void JSGenericLowering::LowerJSForInNext(Node* node) {
  UNREACHABLE();  // Eliminated in typed lowering.
}

void JSGenericLowering::LowerJSLoadMessage(Node* node) {
  UNREACHABLE();  // Eliminated in typed lowering.
}


void JSGenericLowering::LowerJSStoreMessage(Node* node) {
  UNREACHABLE();  // Eliminated in typed lowering.
}

void JSGenericLowering::LowerJSLoadModule(Node* node) {
  UNREACHABLE();  // Eliminated in typed lowering.
}

void JSGenericLowering::LowerJSStoreModule(Node* node) {
  UNREACHABLE();  // Eliminated in typed lowering.
}

void JSGenericLowering::LowerJSGetImportMeta(Node* node) {
  ReplaceWithRuntimeCall(node, Runtime::kGetImportMetaObject);
}

void JSGenericLowering::LowerJSGeneratorStore(Node* node) {
  UNREACHABLE();  // Eliminated in typed lowering.
}

void JSGenericLowering::LowerJSGeneratorRestoreContinuation(Node* node) {
  UNREACHABLE();  // Eliminated in typed lowering.
}

void JSGenericLowering::LowerJSGeneratorRestoreContext(Node* node) {
  UNREACHABLE();  // Eliminated in typed lowering.
}

void JSGenericLowering::LowerJSGeneratorRestoreInputOrDebugPos(Node* node) {
  UNREACHABLE();  // Eliminated in typed lowering.
}

void JSGenericLowering::LowerJSGeneratorRestoreRegister(Node* node) {
  UNREACHABLE();  // Eliminated in typed lowering.
}

namespace {

StackCheckKind StackCheckKindOfJSStackCheck(const Operator* op) {
  DCHECK(op->opcode() == IrOpcode::kJSStackCheck);
  return OpParameter<StackCheckKind>(op);
}

}  // namespace

void JSGenericLowering::LowerJSStackCheck(Node* node) {
  Node* effect = NodeProperties::GetEffectInput(node);
  Node* control = NodeProperties::GetControlInput(node);
  StackCheckKind stack_check_kind = StackCheckKindOfJSStackCheck(node->op());

  Node* check;
  if (stack_check_kind == StackCheckKind::kJSIterationBody) {
    check = effect = graph()->NewNode(
        machine()->Load(MachineType::Uint8()),
        jsgraph()->ExternalConstant(
            ExternalReference::address_of_no_heap_write_interrupt_request(
                isolate())),
        jsgraph()->IntPtrConstant(0), effect, control);
    check = graph()->NewNode(machine()->Word32Equal(), check,
                             jsgraph()->Int32Constant(0));
  } else {
    Node* limit = effect =
        graph()->NewNode(machine()->Load(MachineType::Pointer()),
                         jsgraph()->ExternalConstant(
                             ExternalReference::address_of_jslimit(isolate())),
                         jsgraph()->IntPtrConstant(0), effect, control);

    check = effect = graph()->NewNode(
        machine()->StackPointerGreaterThan(stack_check_kind), limit, effect);
  }
  Node* branch =
      graph()->NewNode(common()->Branch(BranchHint::kTrue), check, control);

  Node* if_true = graph()->NewNode(common()->IfTrue(), branch);
  Node* etrue = effect;

  Node* if_false = graph()->NewNode(common()->IfFalse(), branch);
  NodeProperties::ReplaceControlInput(node, if_false);
  NodeProperties::ReplaceEffectInput(node, effect);
  Node* efalse = if_false = node;

  Node* merge = graph()->NewNode(common()->Merge(2), if_true, if_false);
  Node* ephi = graph()->NewNode(common()->EffectPhi(2), etrue, efalse, merge);

  // Wire the new diamond into the graph, {node} can still throw.
  NodeProperties::ReplaceUses(node, node, ephi, merge, merge);
  NodeProperties::ReplaceControlInput(merge, if_false, 1);
  NodeProperties::ReplaceEffectInput(ephi, efalse, 1);

  // This iteration cuts out potential {IfSuccess} or {IfException} projection
  // uses of the original node and places them inside the diamond, so that we
  // can change the original {node} into the slow-path runtime call.
  for (Edge edge : merge->use_edges()) {
    if (!NodeProperties::IsControlEdge(edge)) continue;
    if (edge.from()->opcode() == IrOpcode::kIfSuccess) {
      NodeProperties::ReplaceUses(edge.from(), nullptr, nullptr, merge);
      NodeProperties::ReplaceControlInput(merge, edge.from(), 1);
      edge.UpdateTo(node);
    }
    if (edge.from()->opcode() == IrOpcode::kIfException) {
      NodeProperties::ReplaceEffectInput(edge.from(), node);
      edge.UpdateTo(node);
    }
  }

  // Turn the stack check into a runtime call. At function entry, the runtime
  // function takes an offset argument which is subtracted from the stack
  // pointer prior to the stack check (i.e. the check is `sp - offset >=
  // limit`).
  Runtime::FunctionId builtin = GetBuiltinForStackCheckKind(stack_check_kind);
  if (stack_check_kind == StackCheckKind::kJSFunctionEntry) {
    node->InsertInput(zone(), 0,
                      graph()->NewNode(machine()->LoadStackCheckOffset()));
  }
  ReplaceWithRuntimeCall(node, builtin);
}

void JSGenericLowering::LowerJSDebugger(Node* node) {
  ReplaceWithRuntimeCall(node, Runtime::kHandleDebuggerStatement);
}

Zone* JSGenericLowering::zone() const { return graph()->zone(); }


Isolate* JSGenericLowering::isolate() const { return jsgraph()->isolate(); }


Graph* JSGenericLowering::graph() const { return jsgraph()->graph(); }


CommonOperatorBuilder* JSGenericLowering::common() const {
  return jsgraph()->common();
}


MachineOperatorBuilder* JSGenericLowering::machine() const {
  return jsgraph()->machine();
}

}  // namespace compiler
}  // namespace internal
}  // namespace v8

"""


```