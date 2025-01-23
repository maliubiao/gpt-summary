Response:
Let's break down the thought process for analyzing the provided C++ code snippet.

1. **Identify the Core Purpose:** The filename `frame-states.cc` and the content immediately suggest this file deals with representing and manipulating the state of execution frames within the V8 compiler. Keywords like `FrameState`, `Continuation`, `Deopt`, and `Builtin` reinforce this idea.

2. **Look for Key Data Structures:** The most important structure is `FrameStateInfo`. It encapsulates information about a frame's type, bailout ID, state combine strategy, and associated function. Understanding its members is crucial.

3. **Analyze Operators and Functions:** The code defines several operators and functions that work with `FrameStateInfo` and `FrameState`. These are key to understanding the file's functionality:
    * Overloaded `operator==`, `operator!=`, `hash_value`, and `operator<<` for `FrameStateInfo` and `OutputFrameStateCombine`: These are standard C++ practices for making these structures usable in containers and for debugging. They don't represent core logic, but are important utilities.
    * `DeoptimizerParameterCountFor`:  This function clearly relates to deoptimization and how many extra parameters are added to the frame state during that process. The `ContinuationFrameStateMode` enum is important here.
    * `CreateBuiltinContinuationFrameStateCommon`: This is a central function for creating frame states for built-in functions. It takes many parameters and constructs the underlying `FrameState` node in the graph.
    * `CreateStubBuiltinContinuationFrameState`: This function builds upon the common creation function, specifically for stub builtins. It handles parameter ordering and accounts for deoptimization parameters.
    * `CreateJSWasmCallBuiltinContinuationFrameState`: A specialized function for creating frame states when calling WebAssembly from JavaScript.
    * `CreateJavaScriptBuiltinContinuationFrameState`:  Similar to the stub version, but for regular JavaScript builtins. It manages stack and register parameters.
    * `CreateGenericLazyDeoptContinuationFrameState`: Creates a frame state specifically for lazy deoptimization.
    * `CreateInlinedApiFunctionFrameState`: This function's implementation is currently trivial (returns the outer frame state), but the name suggests its intended purpose for inlined API functions.
    * `CloneFrameState`: This function allows creating a copy of an existing `FrameState` with potentially modified combine information.

4. **Identify Key Concepts:** As you analyze the functions, several key V8 compiler concepts emerge:
    * **Frame States:**  Represent the execution context at a specific point. Crucial for debugging, deoptimization, and stack walking.
    * **Continuations:**  Represent the state of execution after a call. Builtins often use continuation frame states.
    * **Deoptimization:** The process of reverting from optimized code to interpreted code. Frame states are essential for reconstructing the interpreter's state. The concept of "lazy" vs. "eager" deoptimization is apparent.
    * **Builtins:**  Core V8 functions implemented in C++.
    * **Stubs:**  Small pieces of generated code used for specific tasks.
    * **JSGraph:** The intermediate representation (IR) used by Turbofan. The functions are clearly interacting with the graph by creating `Node` objects.
    * **OutputFrameStateCombine:** This enum/structure likely controls how the frame state is combined or updated. "Ignore" and "PokeAt" are suggestive names.
    * **WebAssembly Integration:** The `#if V8_ENABLE_WEBASSEMBLY` sections indicate specific handling for WebAssembly calls.

5. **Connect to JavaScript Functionality:** Think about how these compiler concepts relate to JavaScript execution:
    * **Function Calls:**  Frame states are created for each function call.
    * **Error Handling (Try/Catch):** The `LAZY_WITH_CATCH` mode suggests frame states are used to manage exception handling during deoptimization.
    * **Debugging (Stack Traces):**  Frame states are the foundation for generating stack traces.
    * **Performance Optimization (Turbofan):**  This code is within the `compiler` namespace, indicating its role in the optimizing compiler. Deoptimization is a key aspect of optimization.

6. **Consider Potential Errors:** Based on the functionality, what could go wrong?
    * Incorrectly constructed frame states can lead to crashes or incorrect deoptimization.
    * Mismatched parameter counts in frame states can cause issues.
    * Incorrect handling of stack vs. register parameters.

7. **Illustrate with JavaScript Examples (If Applicable):**  Choose simple JavaScript snippets that demonstrate the concepts. Function calls, try/catch blocks, and potentially calls to WebAssembly (if enabled) are good candidates.

8. **Reasoning with Hypothetical Inputs/Outputs:** Pick a simple function call and imagine the state of the frame before, during, and after the call. Think about the parameters and the return value.

9. **Structure the Answer:** Organize the information logically into sections addressing the prompt's specific questions:
    * Functionality overview.
    * Torque check.
    * JavaScript relevance with examples.
    * Code logic with hypothetical input/output.
    * Common programming errors.

By following this thought process, you can systematically analyze the C++ code and derive a comprehensive understanding of its purpose and how it fits within the larger V8 architecture. The key is to identify the core concepts, understand the key data structures and functions, and connect them back to the JavaScript language and potential issues.
这个 `v8/src/compiler/frame-states.cc` 文件是 V8 JavaScript 引擎中 **Turbofan 优化编译器** 的一部分，其主要功能是 **管理和创建表示 JavaScript 函数调用帧状态的信息**。 这些帧状态信息对于以下几个方面至关重要：

1. **去优化 (Deoptimization):** 当优化后的代码需要回退到解释执行时，需要恢复之前的执行状态。`FrameState` 记录了关键的信息，例如局部变量、操作数栈和上下文，使得去优化器能够正确地恢复执行。
2. **内联 (Inlining):** 当一个函数被内联到另一个函数中时，需要创建表示被内联函数帧状态的信息。这有助于在去优化时正确地回溯到原始的调用点。
3. **调试 (Debugging):**  帧状态信息可以用于生成堆栈跟踪，帮助开发者理解程序的执行流程。
4. **异常处理 (Exception Handling):**  在 `try...catch` 语句中，帧状态信息可以帮助捕获和处理异常。

**详细功能分解:**

* **定义 `FrameStateInfo` 结构体:**  这个结构体存储了关于帧状态的关键信息，例如：
    * `type()`:  帧状态的类型（例如，未优化的函数帧，内联帧，内置函数延续帧等）。
    * `bailout_id()`:  与去优化点关联的 ID。
    * `state_combine()`:  描述如何将此帧状态与之前的帧状态组合的信息 (例如，忽略，或者从某个参数位置获取)。
    * `function_info()`: 指向与此帧状态关联的函数信息的指针。
* **定义 `OutputFrameStateCombine` 结构体:**  用于指定在创建新的帧状态时，如何从之前的帧状态中获取信息。它可以是 `Ignore`（忽略之前的状态）或 `PokeAt(index)`（从之前的状态的指定参数索引处获取）。
* **提供创建不同类型帧状态的函数:**  文件中包含多个以 `Create...FrameState` 开头的函数，用于创建不同场景下的帧状态，例如：
    * `CreateBuiltinContinuationFrameState`:  为内置函数的延续点创建帧状态。
    * `CreateJavaScriptBuiltinContinuationFrameState`: 为 JavaScript 内置函数的延续点创建帧状态。
    * `CreateGenericLazyDeoptContinuationFrameState`:  为通用的惰性去优化延续点创建帧状态。
    * `CreateInlinedApiFunctionFrameState`: 为内联的 API 函数创建帧状态。
    * `CreateStubBuiltinContinuationFrameState`: 为 Stub (一段预编译的代码) 的延续点创建帧状态。
* **提供克隆帧状态的函数:** `CloneFrameState` 函数允许创建一个现有帧状态的副本，并可以修改其 `state_combine` 信息。
* **重载操作符:**  重载了 `==`, `!=`, `hash_value`, `<<` 等操作符，方便对 `FrameStateInfo` 和 `OutputFrameStateCombine` 进行比较、哈希和输出。
* **处理 WebAssembly 特定的帧状态:**  通过 `#if V8_ENABLE_WEBASSEMBLY` 宏，文件中包含了处理 WebAssembly 相关帧状态的逻辑，例如 `kWasmInlinedIntoJS`, `kJSToWasmBuiltinContinuation`, `kLiftoffFunction`。

**与 JavaScript 的关系以及示例:**

`frame-states.cc` 中创建的帧状态信息直接关联着 JavaScript 函数的执行。每当 JavaScript 函数被调用（无论是普通的函数还是内置函数），Turbofan 编译器就需要维护其执行状态，以便在必要时进行去优化或调试。

**JavaScript 示例:**

```javascript
function add(a, b) {
  return a + b;
}

function main() {
  let x = 5;
  let y = 10;
  let result = add(x, y); // 在这里可能会创建一个 FrameState 来记录 main 函数的状态
  console.log(result);
}

main();
```

在这个例子中，当 `main` 函数调用 `add` 函数时，Turbofan 可能会创建两个 `FrameState` 对象：

1. **`main` 函数的帧状态:** 记录了 `main` 函数的局部变量 `x` 和 `y` 的值，以及当前的执行位置（在调用 `add` 之后）。
2. **`add` 函数的帧状态:** 记录了 `add` 函数的参数 `a` 和 `b` 的值，以及当前的执行位置。

如果 V8 决定对 `add` 函数进行优化，但之后由于某种原因需要去优化，那么之前创建的 `FrameState` 信息就至关重要，它可以帮助 V8 回退到 `add` 函数被调用之前的状态，并继续以解释模式执行。

**如果 `v8/src/compiler/frame-states.cc` 以 `.tq` 结尾:**

如果文件以 `.tq` 结尾，那它就是一个 **V8 Torque 源代码文件**。 Torque 是 V8 自研的一种类型化的元编程语言，用于生成 C++ 代码。这意味着原本在 `frame-states.cc` 中手写的 C++ 代码，可能会被 Torque 代码生成出来。 Torque 的目标是提高 V8 代码的可维护性和安全性。

**代码逻辑推理和假设输入输出:**

假设我们正在执行以下 JavaScript 代码，并且 V8 决定内联 `innerFunction` 到 `outerFunction` 中：

```javascript
function innerFunction(p) {
  return p * 2;
}

function outerFunction(x) {
  let y = 10;
  return innerFunction(x + y);
}

outerFunction(5);
```

在内联 `innerFunction` 时，Turbofan 会创建一个表示内联帧的 `FrameState`。

**假设输入 (在 `CreateBuiltinContinuationFrameStateCommon` 函数中):**

* `jsgraph`:  当前的 JSGraph 对象。
* `frame_type`: `FrameStateType::kInlinedExtraArguments` (假设是内联参数帧).
* `closure`: 指向 `innerFunction` 的闭包的节点。
* `context`: 当前的上下文节点。
* `parameters`:  一个包含参数的节点数组，可能包含 `x + y` 的结果。
* `parameter_count`: 参数的数量 (可能是 1)。
* `outer_frame_state`:  指向 `outerFunction` 的帧状态的节点。

**可能的输出 (`FrameState` 对象):**

创建的 `FrameState` 对象会包含以下信息：

* `type()`: `FrameStateType::kInlinedExtraArguments`.
* `bailout_id()`:  与内联点关联的 ID。
* `state_combine()`:  可能设置为 `Ignore` 或指示如何从 `outerFunction` 的帧状态中获取信息。
* `function_info()`: 指向 `innerFunction` 的 `SharedFunctionInfo`。
* 包含了 `parameters`，`context`，`closure` 和 `outer_frame_state` 的链接。

**用户常见的编程错误:**

虽然用户通常不会直接与 `frame-states.cc` 中的代码交互，但理解其背后的原理可以帮助理解某些 JavaScript 运行时错误或性能问题。一些与帧状态概念相关的常见编程错误包括：

1. **爆栈 (Stack Overflow):**  过多的函数调用会导致调用栈溢出。每个函数调用都需要分配帧，如果嵌套太深，就会超出栈的限制。  虽然 `frame-states.cc` 不直接阻止爆栈，但它参与了管理这些帧。
   ```javascript
   function recursiveFunction() {
     recursiveFunction();
   }
   recursiveFunction(); // 导致 RangeError: Maximum call stack size exceeded
   ```

2. **闭包引起的意外行为:**  闭包会捕获外部作用域的变量。如果对帧状态的理解有偏差，可能会导致对闭包行为的误解。
   ```javascript
   function createCounter() {
     let count = 0;
     return function() {
       count++;
       return count;
     }
   }

   const counter1 = createCounter();
   console.log(counter1()); // 1
   console.log(counter1()); // 2

   const counter2 = createCounter();
   console.log(counter2()); // 1
   ```
   理解 `createCounter` 函数每次调用都会创建新的帧和 `count` 变量，有助于理解为什么 `counter1` 和 `counter2` 的计数是独立的。

3. **异步操作中的上下文丢失:** 在某些异步操作中，如果不小心处理 `this` 绑定或作用域，可能会导致上下文丢失，这与帧状态和作用域链有关。

总而言之，`v8/src/compiler/frame-states.cc` 是 V8 优化编译器中一个核心的文件，它负责管理和创建表示 JavaScript 函数调用帧状态的关键信息，这对于去优化、内联、调试和异常处理等至关重要。理解其功能有助于深入理解 V8 引擎的工作原理。

### 提示词
```
这是目录为v8/src/compiler/frame-states.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/frame-states.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
// Copyright 2015 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/compiler/frame-states.h"

#include <optional>

#include "src/base/functional.h"
#include "src/codegen/callable.h"
#include "src/compiler/js-graph.h"
#include "src/compiler/node.h"
#include "src/compiler/turbofan-graph.h"
#include "src/handles/handles-inl.h"
#include "src/objects/objects-inl.h"

#if V8_ENABLE_WEBASSEMBLY
#include "src/wasm/value-type.h"
#endif  // V8_ENABLE_WEBASSEMBLY

namespace v8 {
namespace internal {
namespace compiler {

size_t hash_value(OutputFrameStateCombine const& sc) {
  return base::hash_value(sc.parameter_);
}

std::ostream& operator<<(std::ostream& os, OutputFrameStateCombine const& sc) {
  if (sc.parameter_ == OutputFrameStateCombine::kInvalidIndex)
    return os << "Ignore";
  return os << "PokeAt(" << sc.parameter_ << ")";
}

bool operator==(FrameStateInfo const& lhs, FrameStateInfo const& rhs) {
  return lhs.type() == rhs.type() && lhs.bailout_id() == rhs.bailout_id() &&
         lhs.state_combine() == rhs.state_combine() &&
         lhs.function_info() == rhs.function_info();
}

bool operator!=(FrameStateInfo const& lhs, FrameStateInfo const& rhs) {
  return !(lhs == rhs);
}

size_t hash_value(FrameStateInfo const& info) {
  return base::hash_combine(static_cast<int>(info.type()), info.bailout_id(),
                            info.state_combine());
}

std::ostream& operator<<(std::ostream& os, FrameStateType type) {
  switch (type) {
    case FrameStateType::kUnoptimizedFunction:
      os << "UNOPTIMIZED_FRAME";
      break;
    case FrameStateType::kInlinedExtraArguments:
      os << "INLINED_EXTRA_ARGUMENTS";
      break;
    case FrameStateType::kConstructCreateStub:
      os << "CONSTRUCT_CREATE_STUB";
      break;
    case FrameStateType::kConstructInvokeStub:
      os << "CONSTRUCT_INVOKE_STUB";
      break;
    case FrameStateType::kBuiltinContinuation:
      os << "BUILTIN_CONTINUATION_FRAME";
      break;
#if V8_ENABLE_WEBASSEMBLY
    case FrameStateType::kWasmInlinedIntoJS:
      os << "WASM_INLINED_INTO_JS_FRAME";
      break;
    case FrameStateType::kJSToWasmBuiltinContinuation:
      os << "JS_TO_WASM_BUILTIN_CONTINUATION_FRAME";
      break;
    case FrameStateType::kLiftoffFunction:
      os << "LIFTOFF_FRAME";
      break;
#endif  // V8_ENABLE_WEBASSEMBLY
    case FrameStateType::kJavaScriptBuiltinContinuation:
      os << "JAVASCRIPT_BUILTIN_CONTINUATION_FRAME";
      break;
    case FrameStateType::kJavaScriptBuiltinContinuationWithCatch:
      os << "JAVASCRIPT_BUILTIN_CONTINUATION_WITH_CATCH_FRAME";
      break;
  }
  return os;
}

std::ostream& operator<<(std::ostream& os, FrameStateInfo const& info) {
  os << info.type() << ", " << info.bailout_id() << ", "
     << info.state_combine();
  Handle<SharedFunctionInfo> shared_info;
  if (info.shared_info().ToHandle(&shared_info)) {
    os << ", " << Brief(*shared_info);
  }
  return os;
}

namespace {

// Lazy deopt points where the frame state is associated with a call get an
// additional parameter for the return result from the call. The return result
// is added by the deoptimizer and not explicitly specified in the frame state.
// Lazy deopt points which can catch exceptions further get an additional
// parameter, namely the exception thrown. The exception is also added by the
// deoptimizer.
uint8_t DeoptimizerParameterCountFor(ContinuationFrameStateMode mode) {
  switch (mode) {
    case ContinuationFrameStateMode::EAGER:
      return 0;
    case ContinuationFrameStateMode::LAZY:
      return 1;
    case ContinuationFrameStateMode::LAZY_WITH_CATCH:
      return 2;
  }
  UNREACHABLE();
}

FrameState CreateBuiltinContinuationFrameStateCommon(
    JSGraph* jsgraph, FrameStateType frame_type, Builtin name, Node* closure,
    Node* context, Node** parameters, int parameter_count,
    Node* outer_frame_state,
    Handle<SharedFunctionInfo> shared = Handle<SharedFunctionInfo>(),
    const wasm::CanonicalSig* signature = nullptr) {
  Graph* const graph = jsgraph->graph();
  CommonOperatorBuilder* const common = jsgraph->common();

  const Operator* op_param =
      common->StateValues(parameter_count, SparseInputMask::Dense());
  Node* params_node = graph->NewNode(op_param, parameter_count, parameters);

  BytecodeOffset bailout_id = Builtins::GetContinuationBytecodeOffset(name);
#if V8_ENABLE_WEBASSEMBLY
  const FrameStateFunctionInfo* state_info =
      signature ? common->CreateJSToWasmFrameStateFunctionInfo(
                      frame_type, parameter_count, 0, shared, signature)
                : common->CreateFrameStateFunctionInfo(
                      frame_type, parameter_count, 0, 0, shared, {});
#else
  DCHECK_NULL(signature);
  const FrameStateFunctionInfo* state_info =
      common->CreateFrameStateFunctionInfo(frame_type, parameter_count, 0, 0,
                                           shared, {});
#endif  // V8_ENABLE_WEBASSEMBLY

  const Operator* op = common->FrameState(
      bailout_id, OutputFrameStateCombine::Ignore(), state_info);
  return FrameState(graph->NewNode(op, params_node, jsgraph->EmptyStateValues(),
                                   jsgraph->EmptyStateValues(), context,
                                   closure, outer_frame_state));
}

}  // namespace

FrameState CreateStubBuiltinContinuationFrameState(
    JSGraph* jsgraph, Builtin name, Node* context, Node* const* parameters,
    int parameter_count, Node* outer_frame_state,
    ContinuationFrameStateMode mode, const wasm::CanonicalSig* signature) {
  Callable callable = Builtins::CallableFor(jsgraph->isolate(), name);
  CallInterfaceDescriptor descriptor = callable.descriptor();

  std::vector<Node*> actual_parameters;
  // Stack parameters first. Depending on {mode}, final parameters are added
  // by the deoptimizer and aren't explicitly passed in the frame state.
  int stack_parameter_count =
      descriptor.GetStackParameterCount() - DeoptimizerParameterCountFor(mode);

  // Ensure the parameters added by the deoptimizer are passed on the stack.
  // This check prevents using TFS builtins as continuations while doing the
  // lazy deopt. Use TFC or TFJ builtin as a lazy deopt continuation which
  // would pass the result parameter on the stack.
  DCHECK_GE(stack_parameter_count, 0);

  // Reserving space in the vector.
  actual_parameters.reserve(stack_parameter_count +
                            descriptor.GetRegisterParameterCount());
  for (int i = 0; i < stack_parameter_count; ++i) {
    actual_parameters.push_back(
        parameters[descriptor.GetRegisterParameterCount() + i]);
  }
  // Register parameters follow, context will be added by instruction selector
  // during FrameState translation.
  for (int i = 0; i < descriptor.GetRegisterParameterCount(); ++i) {
    actual_parameters.push_back(parameters[i]);
  }

  FrameStateType frame_state_type = FrameStateType::kBuiltinContinuation;
#if V8_ENABLE_WEBASSEMBLY
  if (name == Builtin::kJSToWasmLazyDeoptContinuation) {
    CHECK_NOT_NULL(signature);
    frame_state_type = FrameStateType::kJSToWasmBuiltinContinuation;
  }
#endif  // V8_ENABLE_WEBASSEMBLY
  return CreateBuiltinContinuationFrameStateCommon(
      jsgraph, frame_state_type, name, jsgraph->UndefinedConstant(), context,
      actual_parameters.data(), static_cast<int>(actual_parameters.size()),
      outer_frame_state, Handle<SharedFunctionInfo>(), signature);
}

#if V8_ENABLE_WEBASSEMBLY
FrameState CreateJSWasmCallBuiltinContinuationFrameState(
    JSGraph* jsgraph, Node* context, Node* outer_frame_state,
    const wasm::CanonicalSig* signature) {
  std::optional<wasm::ValueKind> wasm_return_kind =
      wasm::WasmReturnTypeFromSignature(signature);
  Node* node_return_type =
      jsgraph->SmiConstant(wasm_return_kind ? wasm_return_kind.value() : -1);
  Node* lazy_deopt_parameters[] = {node_return_type};
  return CreateStubBuiltinContinuationFrameState(
      jsgraph, Builtin::kJSToWasmLazyDeoptContinuation, context,
      lazy_deopt_parameters, arraysize(lazy_deopt_parameters),
      outer_frame_state, ContinuationFrameStateMode::LAZY, signature);
}
#endif  // V8_ENABLE_WEBASSEMBLY

FrameState CreateJavaScriptBuiltinContinuationFrameState(
    JSGraph* jsgraph, SharedFunctionInfoRef shared, Builtin name, Node* target,
    Node* context, Node* const* stack_parameters, int stack_parameter_count,
    Node* outer_frame_state, ContinuationFrameStateMode mode) {
  // Depending on {mode}, final parameters are added by the deoptimizer
  // and aren't explicitly passed in the frame state.
  DCHECK_EQ(Builtins::GetStackParameterCount(name),
            stack_parameter_count + DeoptimizerParameterCountFor(mode));

  Node* argc = jsgraph->ConstantNoHole(Builtins::GetStackParameterCount(name));

  // Stack parameters first. They must be first because the receiver is expected
  // to be the second value in the translation when creating stack crawls
  // (e.g. Error.stack) of optimized JavaScript frames.
  std::vector<Node*> actual_parameters;
  actual_parameters.reserve(stack_parameter_count);
  for (int i = 0; i < stack_parameter_count; ++i) {
    actual_parameters.push_back(stack_parameters[i]);
  }

  Node* new_target = jsgraph->UndefinedConstant();

  // Register parameters follow stack parameters. The context will be added by
  // instruction selector during FrameState translation.
  DCHECK_EQ(
      Builtins::CallInterfaceDescriptorFor(name).GetRegisterParameterCount(),
      V8_ENABLE_LEAPTIERING_BOOL ? 4 : 3);
  actual_parameters.push_back(target);      // kJavaScriptCallTargetRegister
  actual_parameters.push_back(new_target);  // kJavaScriptCallNewTargetRegister
  actual_parameters.push_back(argc);        // kJavaScriptCallArgCountRegister
#ifdef V8_ENABLE_LEAPTIERING
  // The dispatch handle isn't used by the continuation builtins.
  Node* handle = jsgraph->ConstantNoHole(kInvalidDispatchHandle);
  actual_parameters.push_back(handle);  // kJavaScriptDispatchHandleRegister
#endif

  return CreateBuiltinContinuationFrameStateCommon(
      jsgraph,
      mode == ContinuationFrameStateMode::LAZY_WITH_CATCH
          ? FrameStateType::kJavaScriptBuiltinContinuationWithCatch
          : FrameStateType::kJavaScriptBuiltinContinuation,
      name, target, context, &actual_parameters[0],
      static_cast<int>(actual_parameters.size()), outer_frame_state,
      shared.object());
}

FrameState CreateGenericLazyDeoptContinuationFrameState(
    JSGraph* graph, SharedFunctionInfoRef shared, Node* target, Node* context,
    Node* receiver, Node* outer_frame_state) {
  Node* stack_parameters[]{receiver};
  const int stack_parameter_count = arraysize(stack_parameters);
  return CreateJavaScriptBuiltinContinuationFrameState(
      graph, shared, Builtin::kGenericLazyDeoptContinuation, target, context,
      stack_parameters, stack_parameter_count, outer_frame_state,
      ContinuationFrameStateMode::LAZY);
}

Node* CreateInlinedApiFunctionFrameState(JSGraph* graph,
                                         SharedFunctionInfoRef shared,
                                         Node* target, Node* context,
                                         Node* receiver,
                                         Node* outer_frame_state) {
  return outer_frame_state;
}

FrameState CloneFrameState(JSGraph* jsgraph, FrameState frame_state,
                           OutputFrameStateCombine changed_state_combine) {
  Graph* graph = jsgraph->graph();
  CommonOperatorBuilder* common = jsgraph->common();

  DCHECK_EQ(IrOpcode::kFrameState, frame_state->op()->opcode());

  const Operator* op = common->FrameState(
      frame_state.frame_state_info().bailout_id(), changed_state_combine,
      frame_state.frame_state_info().function_info());
  return FrameState(
      graph->NewNode(op, frame_state.parameters(), frame_state.locals(),
                     frame_state.stack(), frame_state.context(),
                     frame_state.function(), frame_state.outer_frame_state()));
}

}  // namespace compiler
}  // namespace internal
}  // namespace v8
```