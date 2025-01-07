Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of the V8 JavaScript engine.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the file's purpose:** The filename `js-call-reducer.cc` strongly suggests that this code is responsible for *reducing* or optimizing JavaScript call expressions during the compilation process. The term "reducer" in compiler terminology often implies simplification or transformation of an intermediate representation.

2. **Scan the includes:**  The `#include` directives point to key V8 components:
    * `compiler/...`:  Confirms it's part of the compiler pipeline.
    * `builtins/...`: Indicates interaction with built-in JavaScript functions.
    * `codegen/...`:  Suggests code generation aspects.
    * `objects/...`:  Deals with JavaScript object representation.
    * `ic/...`: Implies interaction with the V8's Inline Caches.

3. **Analyze the namespace:**  The code is within `v8::internal::compiler`, further solidifying its role in the compiler.

4. **Examine the `JSCallReducerAssembler` class:** This is the central class in the snippet. The constructor takes a `JSCallReducer` pointer, a `Node` (likely representing the call being processed), and potentially effect and control nodes. This confirms the reduction aspect – processing call nodes.

5. **Look at the methods within `JSCallReducerAssembler`:** The method names provide clues about specific reduction capabilities:
    * `ReduceJSCallWithArrayLikeOrSpreadOfEmpty`: Handling calls involving array-like objects or spread syntax.
    * `ReduceMathUnary/Binary`: Optimizing `Math` object calls.
    * `ReduceStringPrototype...`:  Specializing reductions for `String.prototype` methods.
    * `SpeculativeToNumber`, `CheckSmi`, `CheckNumber`, `CheckString`, `CheckBounds`:  Performing type checks and conversions, which are common optimizations.
    * `TypeGuard...`:  Refining type information for optimization.
    * `JSCall3/4`:  Potentially emitting optimized call nodes.
    * `CreateArrayNoThrow`, `AllocateEmptyJSArray`: Handling array creation.
    * `TryCatchBuilder0`, `ForBuilder0/1`:  Constructing control flow structures (try-catch and loops) within the compiler's intermediate representation.

6. **Investigate the other classes:**
    * `IteratingArrayBuiltinReducerAssembler`:  Focuses on optimizing calls to array iteration methods (`forEach`, `map`, `reduce`, etc.).
    * `PromiseBuiltinReducerAssembler`:  Deals with the `Promise` constructor.
    * `FastApiCallReducerAssembler`:  Handles optimized calls to native (C++) API functions.

7. **Synthesize the functionality:** Based on the above analysis, the core function is to optimize JavaScript call expressions during compilation. This involves:
    * **Recognizing patterns:** Identifying specific call patterns (e.g., calls to `Math` functions, `String.prototype` methods, array builtins, promises).
    * **Applying specialized logic:**  Using specific reduction strategies for recognized patterns (e.g., inlining, direct computation, using faster built-in implementations).
    * **Type specialization:** Leveraging type information to generate more efficient code.
    * **Handling control flow:** Representing `try-catch` and loop structures in the compiler's intermediate representation.
    * **Integrating with built-ins:**  Knowing how to replace JavaScript calls with optimized built-in function calls.
    * **Dealing with native API calls:**  Optimizing calls that bridge JavaScript and native C++ code.

8. **Address the specific questions:**
    * **`.tq` extension:** The code snippet is `.cc`, so it's not Torque.
    * **Relationship to JavaScript:** The entire purpose is to optimize JavaScript execution. Provide concrete examples of the JavaScript functions being reduced (e.g., `Math.sqrt`, `String.prototype.substring`, array methods).
    * **Code logic inference (hypothetical input/output):** Give a simple example. If the input is a call to `Math.sqrt(x)` and `x` is known to be a number, the output could be a more direct machine-level square root operation.
    * **Common programming errors:**  Illustrate errors that might lead to less optimized code or runtime exceptions (e.g., passing non-numeric values to `Math.sqrt`, accessing array elements out of bounds).
    * **Overall function (for part 1):** Summarize the high-level goal of the file.

9. **Structure the answer:** Organize the information logically with clear headings and examples. Start with a concise summary and then elaborate on the details.

By following these steps, a comprehensive and accurate answer can be constructed, covering the various aspects of the `js-call-reducer.cc` file's functionality.
```javascript
// 假设我们有这样一个JavaScript函数调用
function myFunction(a, b) {
  return Math.sqrt(a * a + b * b);
}

let result = myFunction(3, 4);
console.log(result); // 输出 5
```

这是 V8 源代码 `v8/src/compiler/js-call-reducer.cc` 的第 1 部分，让我们来归纳一下它的功能。

**核心功能归纳:**

`v8/src/compiler/js-call-reducer.cc` 的主要功能是在 V8 编译器的优化阶段，**对 JavaScript 函数调用 (JSCall) 进行简化和优化**。它通过识别特定的调用模式，并将其替换为更高效的操作或内置函数调用，从而提升代码的执行效率。

**详细功能分解:**

1. **针对特定 JavaScript API 的优化:**
   - 提供了针对 `Math` 对象（例如 `Math.sqrt`, `Math.min`, `Math.max` 等）的优化逻辑。
   - 针对 `String.prototype` 的方法（例如 `substring`, `startsWith`, `endsWith`, `charAt`, `slice`）提供了优化路径。
   - 针对数组原型方法（例如 `forEach`, `reduce`, `map`, `filter`, `find`, `every`, `some`, `indexOf`, `includes`, `push`, `at`）提供了优化的实现。
   - 针对 `Promise` 构造函数提供了特定的优化处理。

2. **处理类似数组的对象和 Spread 语法:**
   - 具备处理包含类似数组对象或使用 Spread 语法的函数调用的能力。

3. **类型推断和检查:**
   - 使用 `SpeculativeToNumber`, `CheckSmi`, `CheckNumber`, `CheckString`, `CheckBounds` 等方法进行类型推断和检查，以便在编译时进行优化。例如，如果知道一个参数肯定是数字，可以避免运行时的类型检查。
   - 使用 `TypeGuard` 相关方法来进一步细化类型信息，例如 `TypeGuardUnsignedSmall` 可以推断一个值是无符号的小整数。

4. **控制流构建:**
   - 提供了 `TryCatchBuilder0` 和 `ForBuilder0/1` 类，用于在编译器的中间表示中构建 `try-catch` 结构和循环结构，以便进行更深入的优化。

5. **处理快速 API 调用:**
   - 包含 `FastApiCallReducerAssembler` 类，专门用于优化对 C++ 扩展 API 的调用，提高 JavaScript 与原生代码交互的效率。

6. **内置函数的集成:**
   - 代码中大量使用了 V8 的内置函数 (`Builtins`)，例如用于创建数组、执行基本操作等，说明该模块的目标是将一些 JavaScript 调用转换为对高效内置函数的调用。

**关于 `.tq` 结尾：**

根据代码注释，`v8/src/compiler/js-call-reducer.cc`  **不是**以 `.tq` 结尾，因此它不是 V8 Torque 源代码。Torque 文件通常以 `.tq` 为扩展名，用于定义 V8 的内置函数和运行时函数的类型化接口。

**与 JavaScript 功能的关系及示例:**

`js-call-reducer.cc` 的目标是优化各种常见的 JavaScript 函数调用。以下是一些与代码中提到的功能相关的 JavaScript 示例：

* **`Math.sqrt` 优化:**
   ```javascript
   let result = Math.sqrt(9); // js-call-reducer 可能会直接生成更高效的平方根计算指令
   ```

* **`String.prototype.substring` 优化:**
   ```javascript
   let str = "hello world";
   let sub = str.substring(0, 5); // js-call-reducer 可能会使用更快的字符串截取方式
   ```

* **数组原型方法优化 (`map`):**
   ```javascript
   let numbers = [1, 2, 3];
   let doubled = numbers.map(x => x * 2); // js-call-reducer 可以优化 map 的迭代过程
   ```

* **`Promise` 构造函数优化:**
   ```javascript
   let promise = new Promise((resolve, reject) => {
       setTimeout(resolve, 1000);
   }); // js-call-reducer 可能会优化 Promise 的创建和状态管理
   ```

**代码逻辑推理（假设输入与输出）：**

假设输入是一个表示 JavaScript 代码 `Math.min(a, b)` 的抽象语法树节点，其中 `a` 和 `b` 在编译时被推断为数字类型。

**假设输入:**  表示 `Math.min(a, b)` 的编译器中间表示节点，包含对 `a` 和 `b` 的引用，并且类型信息表明 `a` 和 `b` 是数字。

**可能的输出:**  编译器可能会将这个 `JSCall` 节点替换为一个更底层的、直接执行数值比较并返回较小值的操作节点，而不是实际调用 JavaScript 的 `Math.min` 函数。

**用户常见的编程错误：**

* **向 `Math.sqrt` 传递非数字类型:**
   ```javascript
   let input = "not a number";
   let result = Math.sqrt(input); // 运行时可能得到 NaN，js-call-reducer 可能会尝试在编译时发现这类问题，但通常需要运行时检查
   ```

* **字符串方法参数错误 (例如 `substring` 的索引越界):**
   ```javascript
   let str = "hello";
   let sub = str.substring(0, 10); // 运行时不会报错，但会返回超出范围的部分，js-call-reducer 可以进行边界检查优化
   ```

* **数组方法回调函数中的类型错误:**
   ```javascript
   let arr = [1, "2", 3];
   let sum = arr.reduce((acc, curr) => acc + curr, 0); // 运行时会将字符串 "2" 转换为数字，但 js-call-reducer 可能会基于类型信息进行更优的假设
   ```

**总结（针对第 1 部分）：**

`v8/src/compiler/js-call-reducer.cc` 的第 1 部分主要定义了一个基础的框架和工具类 `JSCallReducerAssembler`，用于简化和优化 JavaScript 函数调用。它提供了一系列辅助方法，用于进行类型检查、构建控制流、操作中间表示，并针对一些核心的 JavaScript API（如 `Math`, `String.prototype`）和数组原型方法提供了初步的优化能力。此外，它还涉及对 `Promise` 构造函数和快速 API 调用的优化处理。 这个部分建立了进行后续更复杂优化的基础结构。

Prompt: 
```
这是目录为v8/src/compiler/js-call-reducer.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/js-call-reducer.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共12部分，请归纳一下它的功能

"""
// Copyright 2015 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/compiler/js-call-reducer.h"

#include <functional>
#include <optional>

#include "src/base/container-utils.h"
#include "src/base/small-vector.h"
#include "src/builtins/builtins-promise.h"
#include "src/builtins/builtins-utils.h"
#include "src/codegen/code-factory.h"
#include "src/codegen/tnode.h"
#include "src/compiler/access-builder.h"
#include "src/compiler/access-info.h"
#include "src/compiler/allocation-builder-inl.h"
#include "src/compiler/allocation-builder.h"
#include "src/compiler/common-operator.h"
#include "src/compiler/compilation-dependencies.h"
#include "src/compiler/fast-api-calls.h"
#include "src/compiler/feedback-source.h"
#include "src/compiler/graph-assembler.h"
#include "src/compiler/heap-refs.h"
#include "src/compiler/js-graph.h"
#include "src/compiler/js-operator.h"
#include "src/compiler/linkage.h"
#include "src/compiler/map-inference.h"
#include "src/compiler/node-matchers.h"
#include "src/compiler/opcodes.h"
#include "src/compiler/simplified-operator.h"
#include "src/compiler/state-values-utils.h"
#include "src/compiler/type-cache.h"
#include "src/compiler/use-info.h"
#include "src/flags/flags.h"
#include "src/ic/call-optimization.h"
#include "src/objects/elements-kind.h"
#include "src/objects/instance-type.h"
#include "src/objects/js-function.h"
#include "src/objects/objects-inl.h"
#include "src/objects/ordered-hash-table.h"
#include "src/utils/utils.h"

#ifdef V8_INTL_SUPPORT
#include "src/objects/intl-objects.h"
#endif

namespace v8 {
namespace internal {
namespace compiler {

// Shorter lambda declarations with less visual clutter.
#define _ [&]()

class JSCallReducerAssembler : public JSGraphAssembler {
  static constexpr bool kMarkLoopExits = true;

 public:
  JSCallReducerAssembler(JSCallReducer* reducer, Node* node,
                         Node* effect = nullptr, Node* control = nullptr)
      : JSGraphAssembler(
            reducer->broker(), reducer->JSGraphForGraphAssembler(),
            reducer->ZoneForGraphAssembler(), BranchSemantics::kJS,
            [reducer](Node* n) { reducer->RevisitForGraphAssembler(n); },
            kMarkLoopExits),
        dependencies_(reducer->dependencies()),
        node_(node) {
    InitializeEffectControl(
        effect ? effect : NodeProperties::GetEffectInput(node),
        control ? control : NodeProperties::GetControlInput(node));

    // Finish initializing the outermost catch scope.
    bool has_handler =
        NodeProperties::IsExceptionalCall(node, &outermost_handler_);
    outermost_catch_scope_.set_has_handler(has_handler);
  }

  TNode<Object> ReduceJSCallWithArrayLikeOrSpreadOfEmpty(
      std::unordered_set<Node*>* generated_calls_with_array_like_or_spread);
  TNode<Object> ReduceMathUnary(const Operator* op);
  TNode<Object> ReduceMathBinary(const Operator* op);
  TNode<String> ReduceStringPrototypeSubstring();
  TNode<Boolean> ReduceStringPrototypeStartsWith();
  TNode<Boolean> ReduceStringPrototypeStartsWith(
      StringRef search_element_string);
  TNode<Boolean> ReduceStringPrototypeEndsWith();
  TNode<Boolean> ReduceStringPrototypeEndsWith(StringRef search_element_string);
  TNode<String> ReduceStringPrototypeCharAt();
  TNode<String> ReduceStringPrototypeCharAt(StringRef s, uint32_t index);
  TNode<String> ReduceStringPrototypeSlice();
  TNode<Object> ReduceJSCallMathMinMaxWithArrayLike(Builtin builtin);

  TNode<Object> TargetInput() const { return JSCallNode{node_ptr()}.target(); }

  template <typename T>
  TNode<T> ReceiverInputAs() const {
    return TNode<T>::UncheckedCast(JSCallNode{node_ptr()}.receiver());
  }

  TNode<Object> ReceiverInput() const { return ReceiverInputAs<Object>(); }

  Node* node_ptr() const { return node_; }

  // Simplified operators.
  TNode<Number> SpeculativeToNumber(
      TNode<Object> value,
      NumberOperationHint hint = NumberOperationHint::kNumberOrOddball);
  TNode<Smi> CheckSmi(TNode<Object> value);
  TNode<Number> CheckNumber(TNode<Object> value);
  TNode<String> CheckString(TNode<Object> value);
  TNode<Number> CheckBounds(TNode<Number> value, TNode<Number> limit,
                            CheckBoundsFlags flags = {});

  // Common operators.
  TNode<Smi> TypeGuardUnsignedSmall(TNode<Object> value);
  TNode<Object> TypeGuardNonInternal(TNode<Object> value);
  TNode<Number> TypeGuardFixedArrayLength(TNode<Object> value);
  TNode<Object> Call4(const Callable& callable, TNode<Context> context,
                      TNode<Object> arg0, TNode<Object> arg1,
                      TNode<Object> arg2, TNode<Object> arg3);

  // Javascript operators.
  TNode<Object> JSCall3(TNode<Object> function, TNode<Object> this_arg,
                        TNode<Object> arg0, TNode<Object> arg1,
                        TNode<Object> arg2, FrameState frame_state);
  TNode<Object> JSCall4(TNode<Object> function, TNode<Object> this_arg,
                        TNode<Object> arg0, TNode<Object> arg1,
                        TNode<Object> arg2, TNode<Object> arg3,
                        FrameState frame_state);

  // Emplace a copy of the call node into the graph at current effect/control.
  TNode<Object> CopyNode();

  // Used in special cases in which we are certain CreateArray does not throw.
  TNode<JSArray> CreateArrayNoThrow(TNode<Object> ctor, TNode<Number> size,
                                    FrameState frame_state);

  TNode<JSArray> AllocateEmptyJSArray(ElementsKind kind,
                                      NativeContextRef native_context);

  TNode<Number> NumberInc(TNode<Number> value) {
    return NumberAdd(value, OneConstant());
  }

  TNode<Number> LoadMapElementsKind(TNode<Map> map);

  template <typename T, typename U>
  TNode<T> EnterMachineGraph(TNode<U> input, UseInfo use_info) {
    return AddNode<T>(
        graph()->NewNode(common()->EnterMachineGraph(use_info), input));
  }

  template <typename T, typename U>
  TNode<T> ExitMachineGraph(TNode<U> input,
                            MachineRepresentation output_representation,
                            Type output_type) {
    return AddNode<T>(graph()->NewNode(
        common()->ExitMachineGraph(output_representation, output_type), input));
  }

  void MaybeInsertMapChecks(MapInference* inference,
                            bool has_stability_dependency) {
    // TODO(jgruber): Implement MapInference::InsertMapChecks in graph
    // assembler.
    if (!has_stability_dependency) {
      Effect e = effect();
      inference->InsertMapChecks(jsgraph(), &e, Control{control()}, feedback());
      InitializeEffectControl(e, control());
    }
  }

  TNode<Object> ConvertHoleToUndefined(TNode<Object> value, ElementsKind kind) {
    DCHECK(IsHoleyElementsKind(kind));
    if (kind == HOLEY_DOUBLE_ELEMENTS) {
      return AddNode<Number>(
          graph()->NewNode(simplified()->ChangeFloat64HoleToTagged(), value));
    }
    return ConvertTaggedHoleToUndefined(value);
  }

  class TryCatchBuilder0 {
   public:
    using TryFunction = VoidGenerator0;
    using CatchFunction = std::function<void(TNode<Object>)>;

    TryCatchBuilder0(JSCallReducerAssembler* gasm, const TryFunction& try_body)
        : gasm_(gasm), try_body_(try_body) {}

    void Catch(const CatchFunction& catch_body) {
      TNode<Object> handler_exception;
      Effect handler_effect{nullptr};
      Control handler_control{nullptr};

      auto continuation = gasm_->MakeLabel();

      // Try.
      {
        CatchScope catch_scope = CatchScope::Inner(gasm_->temp_zone(), gasm_);
        try_body_();
        gasm_->Goto(&continuation);

        catch_scope.MergeExceptionalPaths(&handler_exception, &handler_effect,
                                          &handler_control);
      }

      // Catch.
      {
        gasm_->InitializeEffectControl(handler_effect, handler_control);
        catch_body(handler_exception);
        gasm_->Goto(&continuation);
      }

      gasm_->Bind(&continuation);
    }

   private:
    JSCallReducerAssembler* const gasm_;
    const VoidGenerator0 try_body_;
  };

  TryCatchBuilder0 Try(const VoidGenerator0& try_body) {
    return {this, try_body};
  }

  using ConditionFunction1 = std::function<TNode<Boolean>(TNode<Number>)>;
  using StepFunction1 = std::function<TNode<Number>(TNode<Number>)>;
  class ForBuilder0 {
    using For0BodyFunction = std::function<void(TNode<Number>)>;

   public:
    ForBuilder0(JSGraphAssembler* gasm, TNode<Number> initial_value,
                const ConditionFunction1& cond, const StepFunction1& step)
        : gasm_(gasm),
          initial_value_(initial_value),
          cond_(cond),
          step_(step) {}

    void Do(const For0BodyFunction& body) {
      auto loop_exit = gasm_->MakeLabel();

      {
        GraphAssembler::LoopScope<kPhiRepresentation> loop_scope(gasm_);

        auto loop_header = loop_scope.loop_header_label();
        auto loop_body = gasm_->MakeLabel();

        gasm_->Goto(loop_header, initial_value_);

        gasm_->Bind(loop_header);
        TNode<Number> i = loop_header->PhiAt<Number>(0);

        gasm_->BranchWithHint(cond_(i), &loop_body, &loop_exit,
                              BranchHint::kTrue);

        gasm_->Bind(&loop_body);
        body(i);
        gasm_->Goto(loop_header, step_(i));
      }

      gasm_->Bind(&loop_exit);
    }

   private:
    static constexpr MachineRepresentation kPhiRepresentation =
        MachineRepresentation::kTagged;

    JSGraphAssembler* const gasm_;
    const TNode<Number> initial_value_;
    const ConditionFunction1 cond_;
    const StepFunction1 step_;
  };

  ForBuilder0 ForZeroUntil(TNode<Number> excluded_limit) {
    TNode<Number> initial_value = ZeroConstant();
    auto cond = [=, this](TNode<Number> i) {
      return NumberLessThan(i, excluded_limit);
    };
    auto step = [=, this](TNode<Number> i) {
      return NumberAdd(i, OneConstant());
    };
    return {this, initial_value, cond, step};
  }

  ForBuilder0 Forever(TNode<Number> initial_value, const StepFunction1& step) {
    return {this, initial_value,
            [=, this](TNode<Number>) { return TrueConstant(); }, step};
  }

  using For1BodyFunction = std::function<void(TNode<Number>, TNode<Object>*)>;
  class ForBuilder1 {
   public:
    ForBuilder1(JSGraphAssembler* gasm, TNode<Number> initial_value,
                const ConditionFunction1& cond, const StepFunction1& step,
                TNode<Object> initial_arg0)
        : gasm_(gasm),
          initial_value_(initial_value),
          cond_(cond),
          step_(step),
          initial_arg0_(initial_arg0) {}

    V8_WARN_UNUSED_RESULT ForBuilder1& Do(const For1BodyFunction& body) {
      body_ = body;
      return *this;
    }

    V8_WARN_UNUSED_RESULT TNode<Object> Value() {
      DCHECK(body_);
      TNode<Object> arg0 = initial_arg0_;

      auto loop_exit = gasm_->MakeDeferredLabel(kPhiRepresentation);

      {
        GraphAssembler::LoopScope<kPhiRepresentation, kPhiRepresentation>
            loop_scope(gasm_);

        auto loop_header = loop_scope.loop_header_label();
        auto loop_body = gasm_->MakeDeferredLabel(kPhiRepresentation);

        gasm_->Goto(loop_header, initial_value_, initial_arg0_);

        gasm_->Bind(loop_header);
        TNode<Number> i = loop_header->PhiAt<Number>(0);
        arg0 = loop_header->PhiAt<Object>(1);

        gasm_->BranchWithHint(cond_(i), &loop_body, &loop_exit,
                              BranchHint::kTrue, arg0);

        gasm_->Bind(&loop_body);
        body_(i, &arg0);
        gasm_->Goto(loop_header, step_(i), arg0);
      }

      gasm_->Bind(&loop_exit);
      return TNode<Object>::UncheckedCast(loop_exit.PhiAt<Object>(0));
    }

    void ValueIsUnused() { USE(Value()); }

   private:
    static constexpr MachineRepresentation kPhiRepresentation =
        MachineRepresentation::kTagged;

    JSGraphAssembler* const gasm_;
    const TNode<Number> initial_value_;
    const ConditionFunction1 cond_;
    const StepFunction1 step_;
    For1BodyFunction body_;
    const TNode<Object> initial_arg0_;
  };

  ForBuilder1 For1(TNode<Number> initial_value, const ConditionFunction1& cond,
                   const StepFunction1& step, TNode<Object> initial_arg0) {
    return {this, initial_value, cond, step, initial_arg0};
  }

  ForBuilder1 For1ZeroUntil(TNode<Number> excluded_limit,
                            TNode<Object> initial_arg0) {
    TNode<Number> initial_value = ZeroConstant();
    auto cond = [=, this](TNode<Number> i) {
      return NumberLessThan(i, excluded_limit);
    };
    auto step = [=, this](TNode<Number> i) {
      return NumberAdd(i, OneConstant());
    };
    return {this, initial_value, cond, step, initial_arg0};
  }

  void ThrowIfNotCallable(TNode<Object> maybe_callable,
                          FrameState frame_state) {
    IfNot(ObjectIsCallable(maybe_callable))
        .Then(_ {
          JSCallRuntime1(Runtime::kThrowCalledNonCallable, maybe_callable,
                         ContextInput(), frame_state);
          Unreachable();  // The runtime call throws unconditionally.
        })
        .ExpectTrue();
  }

  const FeedbackSource& feedback() const {
    CallParameters const& p = CallParametersOf(node_ptr()->op());
    return p.feedback();
  }

  int ArgumentCount() const { return JSCallNode{node_ptr()}.ArgumentCount(); }

  TNode<Object> Argument(int index) const {
    return TNode<Object>::UncheckedCast(JSCallNode{node_ptr()}.Argument(index));
  }

  template <typename T>
  TNode<T> ArgumentAs(int index) const {
    return TNode<T>::UncheckedCast(Argument(index));
  }

  TNode<Object> ArgumentOrNaN(int index) {
    return TNode<Object>::UncheckedCast(
        ArgumentCount() > index ? Argument(index) : NaNConstant());
  }

  TNode<Object> ArgumentOrUndefined(int index) {
    return TNode<Object>::UncheckedCast(
        ArgumentCount() > index ? Argument(index) : UndefinedConstant());
  }

  TNode<Number> ArgumentOrZero(int index) {
    return TNode<Number>::UncheckedCast(
        ArgumentCount() > index ? Argument(index) : ZeroConstant());
  }

  TNode<Context> ContextInput() const {
    return TNode<Context>::UncheckedCast(
        NodeProperties::GetContextInput(node_));
  }

  FrameState FrameStateInput() const {
    return FrameState(NodeProperties::GetFrameStateInput(node_));
  }

  CompilationDependencies* dependencies() const { return dependencies_; }

 private:
  CompilationDependencies* const dependencies_;
  Node* const node_;
};

enum class ArrayReduceDirection { kLeft, kRight };
enum class ArrayFindVariant { kFind, kFindIndex };
enum class ArrayEverySomeVariant { kEvery, kSome };
enum class ArrayIndexOfIncludesVariant { kIncludes, kIndexOf };

// This subclass bundles functionality specific to reducing iterating array
// builtins.
class IteratingArrayBuiltinReducerAssembler : public JSCallReducerAssembler {
 public:
  IteratingArrayBuiltinReducerAssembler(JSCallReducer* reducer, Node* node)
      : JSCallReducerAssembler(reducer, node) {
    DCHECK(v8_flags.turbo_inline_array_builtins);
  }

  TNode<Object> ReduceArrayPrototypeForEach(MapInference* inference,
                                            const bool has_stability_dependency,
                                            ElementsKind kind,
                                            SharedFunctionInfoRef shared);
  TNode<Object> ReduceArrayPrototypeReduce(MapInference* inference,
                                           const bool has_stability_dependency,
                                           ElementsKind kind,
                                           ArrayReduceDirection direction,
                                           SharedFunctionInfoRef shared);
  TNode<JSArray> ReduceArrayPrototypeMap(MapInference* inference,
                                         const bool has_stability_dependency,
                                         ElementsKind kind,
                                         SharedFunctionInfoRef shared,
                                         NativeContextRef native_context);
  TNode<JSArray> ReduceArrayPrototypeFilter(MapInference* inference,
                                            const bool has_stability_dependency,
                                            ElementsKind kind,
                                            SharedFunctionInfoRef shared,
                                            NativeContextRef native_context);
  TNode<Object> ReduceArrayPrototypeFind(MapInference* inference,
                                         const bool has_stability_dependency,
                                         ElementsKind kind,
                                         SharedFunctionInfoRef shared,
                                         NativeContextRef native_context,
                                         ArrayFindVariant variant);
  TNode<Boolean> ReduceArrayPrototypeEverySome(
      MapInference* inference, const bool has_stability_dependency,
      ElementsKind kind, SharedFunctionInfoRef shared,
      NativeContextRef native_context, ArrayEverySomeVariant variant);
  TNode<Object> ReduceArrayPrototypeAt(ZoneVector<MapRef> kinds,
                                       bool needs_fallback_builtin_call);
  TNode<Object> ReduceArrayPrototypeIndexOfIncludes(
      ElementsKind kind, ArrayIndexOfIncludesVariant variant);
  TNode<Number> ReduceArrayPrototypePush(MapInference* inference);

 private:
  // Returns {index,value}. Assumes that the map has not changed, but possibly
  // the length and backing store.
  std::pair<TNode<Number>, TNode<Object>> SafeLoadElement(ElementsKind kind,
                                                          TNode<JSArray> o,
                                                          TNode<Number> index) {
    // Make sure that the access is still in bounds, since the callback could
    // have changed the array's size.
    TNode<Number> length = LoadJSArrayLength(o, kind);
    index = CheckBounds(index, length);

    // Reload the elements pointer before calling the callback, since the
    // previous callback might have resized the array causing the elements
    // buffer to be re-allocated.
    TNode<HeapObject> elements =
        LoadField<HeapObject>(AccessBuilder::ForJSObjectElements(), o);
    TNode<Object> value = LoadElement<Object>(
        AccessBuilder::ForFixedArrayElement(kind), elements, index);
    return std::make_pair(index, value);
  }

  template <typename... Vars>
  TNode<Object> MaybeSkipHole(
      TNode<Object> o, ElementsKind kind,
      GraphAssemblerLabel<sizeof...(Vars)>* continue_label,
      TNode<Vars>... vars) {
    if (!IsHoleyElementsKind(kind)) return o;

    auto if_not_hole = MakeLabel(MachineRepresentationOf<Vars>::value...);
    BranchWithHint(HoleCheck(kind, o), continue_label, &if_not_hole,
                   BranchHint::kFalse, vars...);

    // The contract is that we don't leak "the hole" into "user JavaScript",
    // so we must rename the {element} here to explicitly exclude "the hole"
    // from the type of {element}.
    Bind(&if_not_hole);
    return TypeGuardNonInternal(o);
  }

  TNode<Smi> LoadJSArrayLength(TNode<JSArray> array, ElementsKind kind) {
    return LoadField<Smi>(AccessBuilder::ForJSArrayLength(kind), array);
  }
  void StoreJSArrayLength(TNode<JSArray> array, TNode<Number> value,
                          ElementsKind kind) {
    StoreField(AccessBuilder::ForJSArrayLength(kind), array, value);
  }
  void StoreFixedArrayBaseElement(TNode<FixedArrayBase> o, TNode<Number> index,
                                  TNode<Object> v, ElementsKind kind) {
    StoreElement(AccessBuilder::ForFixedArrayElement(kind), o, index, v);
  }

  TNode<FixedArrayBase> LoadElements(TNode<JSObject> o) {
    return LoadField<FixedArrayBase>(AccessBuilder::ForJSObjectElements(), o);
  }
  TNode<Smi> LoadFixedArrayBaseLength(TNode<FixedArrayBase> o) {
    return LoadField<Smi>(AccessBuilder::ForFixedArrayLength(), o);
  }

  TNode<Boolean> HoleCheck(ElementsKind kind, TNode<Object> v) {
    return IsDoubleElementsKind(kind)
               ? NumberIsFloat64Hole(TNode<Number>::UncheckedCast(v))
               : IsTheHole(v);
  }
};

class PromiseBuiltinReducerAssembler : public JSCallReducerAssembler {
 public:
  PromiseBuiltinReducerAssembler(JSCallReducer* reducer, Node* node)
      : JSCallReducerAssembler(reducer, node) {
    DCHECK_EQ(IrOpcode::kJSConstruct, node->opcode());
  }

  TNode<Object> ReducePromiseConstructor(NativeContextRef native_context);

  int ConstructArity() const {
    return JSConstructNode{node_ptr()}.ArgumentCount();
  }

  TNode<Object> TargetInput() const {
    return JSConstructNode{node_ptr()}.target();
  }

  TNode<Object> NewTargetInput() const {
    return JSConstructNode{node_ptr()}.new_target();
  }

 private:
  TNode<JSPromise> CreatePromise(TNode<Context> context) {
    return AddNode<JSPromise>(
        graph()->NewNode(javascript()->CreatePromise(), context, effect()));
  }

  TNode<Context> CreateFunctionContext(NativeContextRef native_context,
                                       TNode<Context> outer_context,
                                       int slot_count) {
    return AddNode<Context>(graph()->NewNode(
        javascript()->CreateFunctionContext(
            native_context.scope_info(broker()),
            slot_count - Context::MIN_CONTEXT_SLOTS, FUNCTION_SCOPE),
        outer_context, effect(), control()));
  }

  void StoreContextSlot(TNode<Context> context, size_t slot_index,
                        TNode<Object> value) {
    StoreField(AccessBuilder::ForContextSlot(slot_index), context, value);
  }

  TNode<JSFunction> CreateClosureFromBuiltinSharedFunctionInfo(
      SharedFunctionInfoRef shared, TNode<Context> context) {
    DCHECK(shared.HasBuiltinId());
    Handle<FeedbackCell> feedback_cell =
        isolate()->factory()->many_closures_cell();
    Callable const callable =
        Builtins::CallableFor(isolate(), shared.builtin_id());
    CodeRef code = MakeRef(broker(), *callable.code());
    return AddNode<JSFunction>(graph()->NewNode(
        javascript()->CreateClosure(shared, code), HeapConstant(feedback_cell),
        context, effect(), control()));
  }

  void CallPromiseExecutor(TNode<Object> executor, TNode<JSFunction> resolve,
                           TNode<JSFunction> reject, FrameState frame_state) {
    JSConstructNode n(node_ptr());
    const ConstructParameters& p = n.Parameters();
    FeedbackSource no_feedback_source{};
    Node* no_feedback = UndefinedConstant();
    MayThrow(_ {
      return AddNode<Object>(graph()->NewNode(
          javascript()->Call(JSCallNode::ArityForArgc(2), p.frequency(),
                             no_feedback_source,
                             ConvertReceiverMode::kNullOrUndefined),
          executor, UndefinedConstant(), resolve, reject, no_feedback,
          n.context(), frame_state, effect(), control()));
    });
  }

  void CallPromiseReject(TNode<JSFunction> reject, TNode<Object> exception,
                         FrameState frame_state) {
    JSConstructNode n(node_ptr());
    const ConstructParameters& p = n.Parameters();
    FeedbackSource no_feedback_source{};
    Node* no_feedback = UndefinedConstant();
    MayThrow(_ {
      return AddNode<Object>(graph()->NewNode(
          javascript()->Call(JSCallNode::ArityForArgc(1), p.frequency(),
                             no_feedback_source,
                             ConvertReceiverMode::kNullOrUndefined),
          reject, UndefinedConstant(), exception, no_feedback, n.context(),
          frame_state, effect(), control()));
    });
  }
};

class FastApiCallReducerAssembler : public JSCallReducerAssembler {
 public:
  FastApiCallReducerAssembler(
      JSCallReducer* reducer, Node* node,
      const FunctionTemplateInfoRef function_template_info,
      FastApiCallFunction c_function, Node* receiver, Node* holder,
      const SharedFunctionInfoRef shared, Node* target, const int arity,
      Node* effect)
      : JSCallReducerAssembler(reducer, node),
        c_function_(c_function),
        function_template_info_(function_template_info),
        receiver_(receiver),
        holder_(holder),
        shared_(shared),
        target_(target),
        arity_(arity) {
    DCHECK_EQ(IrOpcode::kJSCall, node->opcode());
    InitializeEffectControl(effect, NodeProperties::GetControlInput(node));
  }

  TNode<Object> ReduceFastApiCall() {
    JSCallNode n(node_ptr());

    // C arguments include the receiver at index 0. Thus C index 1 corresponds
    // to the JS argument 0, etc.
    // All functions in c_candidate_functions_ have the same number of
    // arguments, so extract c_argument_count from the first function.
    const int c_argument_count =
        static_cast<int>(c_function_.signature->ArgumentCount());
    CHECK_GE(c_argument_count, kReceiver);

    const int slow_arg_count =
        // Arguments for CallApiCallbackOptimizedXXX builtin including
        // context, see CallApiCallbackOptimizedDescriptor.
        kSlowBuiltinParams +
        // JS arguments.
        kReceiver + arity_;

    const int value_input_count =
        FastApiCallNode::ArityForArgc(c_argument_count, slow_arg_count);

    base::SmallVector<Node*, kInlineSize> inputs(value_input_count +
                                                 kEffectAndControl);
    int cursor = 0;
    inputs[cursor++] = n.receiver();

    // TODO(turbofan): Consider refactoring CFunctionInfo to distinguish
    // between receiver and arguments, simplifying this (and related) spots.
    int js_args_count = c_argument_count - kReceiver;
    for (int i = 0; i < js_args_count; ++i) {
      if (i < n.ArgumentCount()) {
        inputs[cursor++] = n.Argument(i);
      } else {
        inputs[cursor++] = UndefinedConstant();
      }
    }

    // Here we add the arguments for the slow call, which will be
    // reconstructed at a later phase. Those are effectively the same
    // arguments as for the fast call, but we want to have them as
    // separate inputs, so that SimplifiedLowering can provide the best
    // possible UseInfos for each of them. The inputs to FastApiCall
    // look like:
    // [receiver, ... C arguments, callback data,
    //  slow call code, external constant for function, argc,
    //  FunctionTemplateInfo, holder, receiver, ... JS arguments,
    //  context, new frame state].
    bool no_profiling =
        broker()->dependencies()->DependOnNoProfilingProtector();
    Callable call_api_callback = Builtins::CallableFor(
        isolate(), no_profiling ? Builtin::kCallApiCallbackOptimizedNoProfiling
                                : Builtin::kCallApiCallbackOptimized);
    CallInterfaceDescriptor cid = call_api_callback.descriptor();
    DCHECK_EQ(cid.GetParameterCount() + (cid.HasContextParameter() ? 1 : 0),
              kSlowBuiltinParams);

    CallDescriptor* call_descriptor =
        Linkage::GetStubCallDescriptor(graph()->zone(), cid, arity_ + kReceiver,
                                       CallDescriptor::kNeedsFrameState);
    ApiFunction api_function(function_template_info_.callback(broker()));
    ExternalReference function_reference = ExternalReference::Create(
        isolate(), &api_function, ExternalReference::DIRECT_API_CALL,
        function_template_info_.c_functions(broker()).data(),
        function_template_info_.c_signatures(broker()).data(),
        static_cast<unsigned>(
            function_template_info_.c_functions(broker()).size()));

    Node* continuation_frame_state = CreateInlinedApiFunctionFrameState(
        jsgraph(), shared_, target_, ContextInput(), receiver_,
        FrameStateInput());

    // Callback data value for fast Api calls. Unlike slow Api calls, the fast
    // variant passes callback data directly.
    inputs[cursor++] =
        Constant(function_template_info_.callback_data(broker()).value());

    inputs[cursor++] = HeapConstant(call_api_callback.code());
    inputs[cursor++] = ExternalConstant(function_reference);
    inputs[cursor++] = NumberConstant(arity_);
    inputs[cursor++] = HeapConstant(function_template_info_.object());
    inputs[cursor++] = holder_;
    inputs[cursor++] = receiver_;
    for (int i = 0; i < arity_; ++i) {
      inputs[cursor++] = Argument(i);
    }
    inputs[cursor++] = ContextInput();
    inputs[cursor++] = continuation_frame_state;

    inputs[cursor++] = effect();
    inputs[cursor++] = control();

    DCHECK_EQ(cursor, value_input_count + kEffectAndControl);

    return FastApiCall(call_descriptor, inputs.begin(), inputs.size());
  }

 private:
  static constexpr int kEffectAndControl = 2;

  // Api function address, argc, FunctionTemplateInfo, holder, context.
  // See CallApiCallbackOptimizedDescriptor.
  static constexpr int kSlowBuiltinParams = 5;
  static constexpr int kReceiver = 1;

  // Enough for creating FastApiCall node with two JS arguments.
  static constexpr int kInlineSize = 16;

  TNode<Object> FastApiCall(CallDescriptor* descriptor, Node** inputs,
                            size_t inputs_size) {
    return AddNode<Object>(graph()->NewNode(
        simplified()->FastApiCall(c_function_, feedback(), descriptor),
        static_cast<int>(inputs_size), inputs));
  }

  FastApiCallFunction c_function_;
  const FunctionTemplateInfoRef function_template_info_;
  Node* const receiver_;
  Node* const holder_;
  const SharedFunctionInfoRef shared_;
  Node* const target_;
  const int arity_;
};

TNode<Number> JSCallReducerAssembler::SpeculativeToNumber(
    TNode<Object> value, NumberOperationHint hint) {
  return AddNode<Number>(
      graph()->NewNode(simplified()->SpeculativeToNumber(hint, feedback()),
                       value, effect(), control()));
}

TNode<Smi> JSCallReducerAssembler::CheckSmi(TNode<Object> value) {
  return AddNode<Smi>(graph()->NewNode(simplified()->CheckSmi(feedback()),
                                       value, effect(), control()));
}

TNode<Number> JSCallReducerAssembler::CheckNumber(TNode<Object> value) {
  return AddNode<Number>(graph()->NewNode(simplified()->CheckNumber(feedback()),
                                          value, effect(), control()));
}

TNode<String> JSCallReducerAssembler::CheckString(TNode<Object> value) {
  return AddNode<String>(graph()->NewNode(simplified()->CheckString(feedback()),
                                          value, effect(), control()));
}

TNode<Number> JSCallReducerAssembler::CheckBounds(TNode<Number> value,
                                                  TNode<Number> limit,
                                                  CheckBoundsFlags flags) {
  return AddNode<Number>(
      graph()->NewNode(simplified()->CheckBounds(feedback(), flags), value,
                       limit, effect(), control()));
}

TNode<Smi> JSCallReducerAssembler::TypeGuardUnsignedSmall(TNode<Object> value) {
  return TNode<Smi>::UncheckedCast(TypeGuard(Type::UnsignedSmall(), value));
}

TNode<Object> JSCallReducerAssembler::TypeGuardNonInternal(
    TNode<Object> value) {
  return TNode<Object>::UncheckedCast(TypeGuard(Type::NonInternal(), value));
}

TNode<Number> JSCallReducerAssembler::TypeGuardFixedArrayLength(
    TNode<Object> value) {
  DCHECK(TypeCache::Get()->kFixedDoubleArrayLengthType.Is(
      TypeCache::Get()->kFixedArrayLengthType));
  return TNode<Number>::UncheckedCast(
      TypeGuard(TypeCache::Get()->kFixedArrayLengthType, value));
}

TNode<Object> JSCallReducerAssembler::Call4(
    const Callable& callable, TNode<Context> context, TNode<Object> arg0,
    TNode<Object> arg1, TNode<Object> arg2, TNode<Object> arg3) {
  // TODO(jgruber): Make this more generic. Currently it's fitted to its single
  // callsite.
  CallDescriptor* desc = Linkage::GetStubCallDescriptor(
      graph()->zone(), callable.descriptor(),
      callable.descriptor().GetStackParameterCount(), CallDescriptor::kNoFlags,
      Operator::kEliminatable);

  return TNode<Object>::UncheckedCast(Call(desc, HeapConstant(callable.code()),
                                           arg0, arg1, arg2, arg3, context));
}

TNode<Object> JSCallReducerAssembler::JSCall3(
    TNode<Object> function, TNode<Object> this_arg, TNode<Object> arg0,
    TNode<Object> arg1, TNode<Object> arg2, FrameState frame_state) {
  JSCallNode n(node_ptr());
  CallParameters const& p = n.Parameters();
  return MayThrow(_ {
    return AddNode<Object>(graph()->NewNode(
        javascript()->Call(JSCallNode::ArityForArgc(3), p.frequency(),
                           p.feedback(), ConvertReceiverMode::kAny,
                           p.speculation_mode(),
                           CallFeedbackRelation::kUnrelated),
        fun
"""


```