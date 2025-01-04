Response: The user wants a summary of the provided C++ code.
The code is the first part of a file named `js-call-reducer.cc` located in the `v8/src/compiler` directory.
This suggests it's part of the V8 JavaScript engine's compiler, specifically dealing with optimizing JavaScript calls.

The code defines a few classes:
- `JSCallReducerAssembler`: A helper class built on top of `JSGraphAssembler` to simplify the process of reducing (optimizing) JavaScript calls. It provides methods for common operations during call reduction, like type checking, calling built-in functions, and managing control flow.
- `IteratingArrayBuiltinReducerAssembler`: Inherits from `JSCallReducerAssembler` and focuses on reducing calls to built-in array methods that involve iteration (e.g., `forEach`, `map`, `reduce`).
- `PromiseBuiltinReducerAssembler`:  Inherits from `JSCallReducerAssembler` and handles the reduction of Promise constructor calls.
- `FastApiCallReducerAssembler`:  Inherits from `JSCallReducerAssembler` and deals with optimizing calls to Fast API functions (C++ functions exposed to JavaScript).

The code heavily uses an assembler-like syntax (`TNode<Type>`) for building the intermediate representation of the code being optimized. It also includes various helper functions and data structures for common tasks.

It seems the core functionality of this part of the file is to provide building blocks and specific reduction logic for various kinds of JavaScript calls during the compilation process.

To illustrate with JavaScript, let's consider the `ReduceArrayPrototypeForEach` function in `IteratingArrayBuiltinReducerAssembler`. This function likely aims to optimize calls to the `Array.prototype.forEach` method.

For example, in JavaScript:
```javascript
const arr = [1, 2, 3];
arr.forEach(item => console.log(item));
```

The `ReduceArrayPrototypeForEach` function in the C++ code would be involved in analyzing this call and potentially generating optimized machine code that avoids the overhead of a generic function call. It would check the type of the `arr`, the provided callback, and generate code that iterates over the array elements and calls the callback efficiently.
这个C++源代码文件是V8 JavaScript引擎编译器的一部分，主要功能是**提供用于优化JavaScript函数调用的基础设施和特定优化逻辑**。它是`JSCallReducer`的核心组成部分，负责在编译过程中识别和简化各种JavaScript调用，以生成更高效的机器代码。

具体来说，这部分代码定义了几个关键的辅助类，这些类都继承自 `JSGraphAssembler`，并针对不同类型的JavaScript调用提供了更便捷的操作接口：

1. **`JSCallReducerAssembler`**: 这是一个基础的汇编器类，为简化JavaScript调用的优化过程提供了构建块。它包含了很多实用的方法，例如：
    - 类型检查和转换 (`SpeculativeToNumber`, `CheckSmi`, `CheckString`等)
    - 调用内置函数 (`JSCall3`, `JSCall4`)
    - 控制流管理 (`GotoIf`, `Bind`, `ForBuilder0`, `TryCatchBuilder0`)
    - 操作数获取 (`Argument`, `ReceiverInput`)
    - 创建和操作节点 (`CopyNode`, `CreateArrayNoThrow`)
    - 辅助内联优化 (`MaybeInsertMapChecks`)

2. **`IteratingArrayBuiltinReducerAssembler`**: 这个类继承自 `JSCallReducerAssembler`，专门用于优化对数组内置迭代方法的调用，例如 `forEach`、`map`、`reduce` 等。它提供了一些针对数组操作的便捷方法，例如加载和存储数组元素、获取数组长度等。

3. **`PromiseBuiltinReducerAssembler`**:  这个类继承自 `JSCallReducerAssembler`，专注于优化 `Promise` 构造函数的调用。它提供了一些用于创建和操作Promise相关对象的方法。

4. **`FastApiCallReducerAssembler`**: 这个类继承自 `JSCallReducerAssembler`，用于优化对“快速API调用”的处理。快速API调用是指直接调用C++函数，这种优化可以显著提升性能。

**与JavaScript功能的关联和示例说明:**

这个文件中的代码直接影响V8引擎执行JavaScript代码的效率。它通过在编译时进行各种优化，将一些常见的JavaScript操作转换为更底层的、更高效的机器指令。

例如，`IteratingArrayBuiltinReducerAssembler` 中的 `ReduceArrayPrototypeForEach` 函数，它的目标是优化 JavaScript 中 `Array.prototype.forEach` 方法的调用。

**JavaScript 示例:**

```javascript
const numbers = [1, 2, 3];
numbers.forEach(function(number) {
  console.log(number * 2);
});
```

当 V8 引擎编译这段 JavaScript 代码时，`ReduceArrayPrototypeForEach` 函数可能会被调用。它的功能是：

1. **检查类型**: 确保 `numbers` 是一个数组，并且提供的回调函数是可调用的。
2. **内联迭代**:  如果条件允许（例如数组元素类型稳定），它可以生成直接访问数组元素并调用回调函数的循环代码，而无需每次都进行通用的函数调用。
3. **避免开销**:  通过内联和类型特化，减少了函数调用的开销，提升了 `forEach` 循环的执行速度。

其他的优化器类也类似，例如 `PromiseBuiltinReducerAssembler` 会尝试优化 `new Promise()` 的创建过程，而 `FastApiCallReducerAssembler` 则会优化直接调用 C++ API 的场景。

总而言之，这个文件的核心功能是作为 V8 编译器的一部分，通过在编译阶段对 JavaScript 函数调用进行分析和优化，最终提升 JavaScript 代码的执行效率。这部分代码是 V8 引擎高性能的关键组成部分。

Prompt: 
```
这是目录为v8/src/compiler/js-call-reducer.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共6部分，请归纳一下它的功能

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
        function, this_arg, arg0, arg1, arg2, n.feedback_vector(),
        ContextInput(), frame_state, effect(), control()));
  });
}

TNode<Object> JSCallReducerAssembler::JSCall4(
    TNode<Object> function, TNode<Object> this_arg, TNode<Object> arg0,
    TNode<Object> arg1, TNode<Object> arg2, TNode<Object> arg3,
    FrameState frame_state) {
  JSCallNode n(node_ptr());
  CallParameters const& p = n.Parameters();
  return MayThrow(_ {
    return AddNode<Object>(graph()->NewNode(
        javascript()->Call(JSCallNode::ArityForArgc(4), p.frequency(),
                           p.feedback(), ConvertReceiverMode::kAny,
                           p.speculation_mode(),
                           CallFeedbackRelation::kUnrelated),
        function, this_arg, arg0, arg1, arg2, arg3, n.feedback_vector(),
        ContextInput(), frame_state, effect(), control()));
  });
}

TNode<Object> JSCallReducerAssembler::CopyNode() {
  return MayThrow(_ {
    Node* copy = graph()->CloneNode(node_ptr());
    NodeProperties::ReplaceEffectInput(copy, effect());
    NodeProperties::ReplaceControlInput(copy, control());
    return AddNode<Object>(copy);
  });
}

TNode<JSArray> JSCallReducerAssembler::CreateArrayNoThrow(
    TNode<Object> ctor, TNode<Number> size, FrameState frame_state) {
  return AddNode<JSArray>(
      graph()->NewNode(javascript()->CreateArray(1, std::nullopt), ctor, ctor,
                       size, ContextInput(), frame_state, effect(), control()));
}

TNode<JSArray> JSCallReducerAssembler::AllocateEmptyJSArray(
    ElementsKind kind, NativeContextRef native_context) {
  // TODO(jgruber): Port AllocationBuilder to JSGraphAssembler.
  MapRef map = native_context.GetInitialJSArrayMap(broker(), kind);

  AllocationBuilder ab(jsgraph(), broker(), effect(), control());
  ab.Allocate(map.instance_size(), AllocationType::kYoung, Type::Array());
  ab.Store(AccessBuilder::ForMap(), map);
  Node* empty_fixed_array = jsgraph()->EmptyFixedArrayConstant();
  ab.Store(AccessBuilder::ForJSObjectPropertiesOrHashKnownPointer(),
           empty_fixed_array);
  ab.Store(AccessBuilder::ForJSObjectElements(), empty_fixed_array);
  ab.Store(AccessBuilder::ForJSArrayLength(kind), jsgraph()->ZeroConstant());
  for (int i = 0; i < map.GetInObjectProperties(); ++i) {
    ab.Store(AccessBuilder::ForJSObjectInObjectProperty(map, i),
             jsgraph()->UndefinedConstant());
  }
  Node* result = ab.Finish();
  InitializeEffectControl(result, control());
  return TNode<JSArray>::UncheckedCast(result);
}

TNode<Number> JSCallReducerAssembler::LoadMapElementsKind(TNode<Map> map) {
  TNode<Number> bit_field2 =
      LoadField<Number>(AccessBuilder::ForMapBitField2(), map);
  return NumberShiftRightLogical(
      NumberBitwiseAnd(bit_field2,
                       NumberConstant(Map::Bits2::ElementsKindBits::kMask)),
      NumberConstant(Map::Bits2::ElementsKindBits::kShift));
}

TNode<Object> JSCallReducerAssembler::ReduceMathUnary(const Operator* op) {
  TNode<Object> input = Argument(0);
  TNode<Number> input_as_number = SpeculativeToNumber(input);
  return TNode<Object>::UncheckedCast(graph()->NewNode(op, input_as_number));
}

TNode<Object> JSCallReducerAssembler::ReduceMathBinary(const Operator* op) {
  TNode<Object> left = Argument(0);
  TNode<Object> right = ArgumentOrNaN(1);
  TNode<Number> left_number = SpeculativeToNumber(left);
  TNode<Number> right_number = SpeculativeToNumber(right);
  return TNode<Object>::UncheckedCast(
      graph()->NewNode(op, left_number, right_number));
}

TNode<String> JSCallReducerAssembler::ReduceStringPrototypeSubstring() {
  TNode<Object> receiver = ReceiverInput();
  TNode<Object> start = Argument(0);
  TNode<Object> end = ArgumentOrUndefined(1);

  TNode<String> receiver_string = CheckString(receiver);
  TNode<Number> start_smi = CheckSmi(start);

  TNode<Number> length = StringLength(receiver_string);

  TNode<Number> end_smi = SelectIf<Number>(IsUndefined(end))
                              .Then(_ { return length; })
                              .Else(_ { return CheckSmi(end); })
                              .ExpectFalse()
                              .Value();

  TNode<Number> zero = TNode<Number>::UncheckedCast(ZeroConstant());
  TNode<Number> finalStart = NumberMin(NumberMax(start_smi, zero), length);
  TNode<Number> finalEnd = NumberMin(NumberMax(end_smi, zero), length);
  TNode<Number> from = NumberMin(finalStart, finalEnd);
  TNode<Number> to = NumberMax(finalStart, finalEnd);

  return StringSubstring(receiver_string, from, to);
}

TNode<Boolean> JSCallReducerAssembler::ReduceStringPrototypeStartsWith(
    StringRef search_element_string) {
  DCHECK(search_element_string.IsContentAccessible());
  TNode<Object> receiver = ReceiverInput();
  TNode<Object> start = ArgumentOrZero(1);

  TNode<String> receiver_string = CheckString(receiver);
  TNode<Smi> start_smi = CheckSmi(start);
  TNode<Number> length = StringLength(receiver_string);

  TNode<Number> zero = ZeroConstant();
  TNode<Number> clamped_start = NumberMin(NumberMax(start_smi, zero), length);

  int search_string_length = search_element_string.length();
  DCHECK(search_string_length <= JSCallReducer::kMaxInlineMatchSequence);

  auto out = MakeLabel(MachineRepresentation::kTagged);

  auto search_string_too_long =
      NumberLessThan(NumberSubtract(length, clamped_start),
                     NumberConstant(search_string_length));

  GotoIf(search_string_too_long, &out, BranchHint::kFalse, FalseConstant());

  static_assert(String::kMaxLength <= kSmiMaxValue);

  for (int i = 0; i < search_string_length; i++) {
    TNode<Number> k = NumberConstant(i);
    TNode<Number> receiver_string_position = TNode<Number>::UncheckedCast(
        TypeGuard(Type::UnsignedSmall(), NumberAdd(k, clamped_start)));
    Node* receiver_string_char =
        StringCharCodeAt(receiver_string, receiver_string_position);
    Node* search_string_char = jsgraph()->ConstantNoHole(
        search_element_string.GetChar(broker(), i).value());
    auto is_equal = graph()->NewNode(simplified()->NumberEqual(),
                                     search_string_char, receiver_string_char);
    GotoIfNot(is_equal, &out, FalseConstant());
  }

  Goto(&out, TrueConstant());

  Bind(&out);
  return out.PhiAt<Boolean>(0);
}

TNode<Boolean> JSCallReducerAssembler::ReduceStringPrototypeStartsWith() {
  TNode<Object> receiver = ReceiverInput();
  TNode<Object> search_element = ArgumentOrUndefined(0);
  TNode<Object> start = ArgumentOrZero(1);

  TNode<String> receiver_string = CheckString(receiver);
  TNode<String> search_string = CheckString(search_element);
  TNode<Smi> start_smi = CheckSmi(start);
  TNode<Number> length = StringLength(receiver_string);

  TNode<Number> zero = ZeroConstant();
  TNode<Number> clamped_start = NumberMin(NumberMax(start_smi, zero), length);

  TNode<Number> search_string_length = StringLength(search_string);

  auto out = MakeLabel(MachineRepresentation::kTagged);

  auto search_string_too_long = NumberLessThan(
      NumberSubtract(length, clamped_start), search_string_length);

  GotoIf(search_string_too_long, &out, BranchHint::kFalse, FalseConstant());

  static_assert(String::kMaxLength <= kSmiMaxValue);

  ForZeroUntil(search_string_length).Do([&](TNode<Number> k) {
    TNode<Number> receiver_string_position = TNode<Number>::UncheckedCast(
        TypeGuard(Type::UnsignedSmall(), NumberAdd(k, clamped_start)));
    Node* receiver_string_char =
        StringCharCodeAt(receiver_string, receiver_string_position);
    if (!v8_flags.turbo_loop_variable) {
      // Without loop variable analysis, Turbofan's typer is unable to derive a
      // sufficiently precise type here. This is not a soundness problem, but
      // triggers graph verification errors. So we only insert the TypeGuard if
      // necessary.
      k = TypeGuard(Type::Unsigned32(), k);
    }
    Node* search_string_char = StringCharCodeAt(search_string, k);
    auto is_equal = graph()->NewNode(simplified()->NumberEqual(),
                                     receiver_string_char, search_string_char);
    GotoIfNot(is_equal, &out, FalseConstant());
  });

  Goto(&out, TrueConstant());

  Bind(&out);
  return out.PhiAt<Boolean>(0);
}

TNode<Boolean> JSCallReducerAssembler::ReduceStringPrototypeEndsWith(
    StringRef search_element_string) {
  DCHECK(search_element_string.IsContentAccessible());
  TNode<Object> receiver = ReceiverInput();
  TNode<Object> end_position = ArgumentOrUndefined(1);
  TNode<Number> zero = ZeroConstant();

  TNode<String> receiver_string = CheckString(receiver);
  TNode<Number> length = StringLength(receiver_string);
  int search_string_length = search_element_string.length();
  DCHECK_LE(search_string_length, JSCallReducer::kMaxInlineMatchSequence);

  TNode<Number> clamped_end =
      SelectIf<Number>(IsUndefined(end_position))
          .Then(_ { return length; })
          .Else(_ {
            return NumberMin(NumberMax(CheckSmi(end_position), zero), length);
          })
          .ExpectTrue()
          .Value();

  TNode<Number> start =
      NumberSubtract(clamped_end, NumberConstant(search_string_length));

  auto out = MakeLabel(MachineRepresentation::kTagged);

  TNode<Boolean> search_string_too_long = NumberLessThan(start, zero);
  GotoIf(search_string_too_long, &out, BranchHint::kFalse, FalseConstant());

  for (int i = 0; i < search_string_length; i++) {
    TNode<Number> k = NumberConstant(i);
    TNode<Number> receiver_string_position = TNode<Number>::UncheckedCast(
        TypeGuard(Type::UnsignedSmall(), NumberAdd(k, start)));
    Node* receiver_string_char =
        StringCharCodeAt(receiver_string, receiver_string_position);
    Node* search_string_char = jsgraph()->ConstantNoHole(
        search_element_string.GetChar(broker(), i).value());
    auto is_equal = graph()->NewNode(simplified()->NumberEqual(),
                                     receiver_string_char, search_string_char);
    GotoIfNot(is_equal, &out, FalseConstant());
  }

  Goto(&out, TrueConstant());

  Bind(&out);
  return out.PhiAt<Boolean>(0);
}

TNode<Boolean> JSCallReducerAssembler::ReduceStringPrototypeEndsWith() {
  TNode<Object> receiver = ReceiverInput();
  TNode<Object> search_string = ArgumentOrUndefined(0);
  TNode<Object> end_position = ArgumentOrUndefined(1);
  TNode<Number> zero = ZeroConstant();

  TNode<String> receiver_string = CheckString(receiver);
  TNode<Number> length = StringLength(receiver_string);
  TNode<String> search_element_string = CheckString(search_string);
  TNode<Number> search_string_length = StringLength(search_element_string);

  TNode<Number> clamped_end =
      SelectIf<Number>(IsUndefined(end_position))
          .Then(_ { return length; })
          .Else(_ {
            return NumberMin(NumberMax(CheckSmi(end_position), zero), length);
          })
          .ExpectTrue()
          .Value();

  TNode<Number> start = NumberSubtract(clamped_end, search_string_length);

  auto out = MakeLabel(MachineRepresentation::kTagged);

  TNode<Boolean> search_string_too_long = NumberLessThan(start, zero);
  GotoIf(search_string_too_long, &out, BranchHint::kFalse, FalseConstant());

  ForZeroUntil(search_string_length).Do([&](TNode<Number> k) {
    TNode<Number> receiver_string_position = TNode<Number>::UncheckedCast(
        TypeGuard(Type::UnsignedSmall(), NumberAdd(k, start)));
    Node* receiver_string_char =
        StringCharCodeAt(receiver_string, receiver_string_position);
    if (!v8_flags.turbo_loop_variable) {
      // Without loop variable analysis, Turbofan's typer is unable to derive a
      // sufficiently precise type here. This is not a soundness problem, but
      // triggers graph verification errors. So we only insert the TypeGuard if
      // necessary.
      k = TypeGuard(Type::Unsigned32(), k);
    }
    Node* search_string_char = StringCharCodeAt(search_element_string, k);
    auto is_equal = graph()->NewNode(simplified()->NumberEqual(),
                                     receiver_string_char, search_string_char);
    GotoIfNot(is_equal, &out, FalseConstant());
  });

  Goto(&out, TrueConstant());

  Bind(&out);
  return out.PhiAt<Boolean>(0);
}

TNode<String> JSCallReducerAssembler::ReduceStringPrototypeCharAt(
    StringRef s, uint32_t index) {
  DCHECK(s.IsContentAccessible());
  if (s.IsOneByteRepresentation()) {
    OptionalObjectRef elem = s.GetCharAsStringOrUndefined(broker(), index);
    TNode<String> elem_string =
        elem.has_value()
            ? TNode<String>::UncheckedCast(
                  jsgraph()->ConstantNoHole(elem.value(), broker()))
            : EmptyStringConstant();
    return elem_string;
  } else {
    const uint32_t length = static_cast<uint32_t>(s.length());
    if (index >= length) return EmptyStringConstant();
    Handle<SeqTwoByteString> flat = broker()->CanonicalPersistentHandle(
        broker()
            ->local_isolate_or_isolate()
            ->factory()
            ->NewRawTwoByteString(1, AllocationType::kOld)
            .ToHandleChecked());
    flat->SeqTwoByteStringSet(0, s.GetChar(broker(), index).value());
    TNode<String> two_byte_elem =
        TNode<String>::UncheckedCast(jsgraph()->HeapConstantNoHole(flat));
    return two_byte_elem;
  }
}

TNode<String> JSCallReducerAssembler::ReduceStringPrototypeCharAt() {
  TNode<Object> receiver = ReceiverInput();
  TNode<Object> index = ArgumentOrZero(0);

  TNode<String> receiver_string = CheckString(receiver);
  TNode<Number> index_smi = CheckSmi(index);
  TNode<Number> length = StringLength(receiver_string);

  TNode<Number> bounded_index = CheckBounds(index_smi, length);

  Node* result = StringCharCodeAt(receiver_string, bounded_index);
  TNode<String> result_string =
      StringFromSingleCharCode(TNode<Number>::UncheckedCast(result));
  return result_string;
}

TNode<String> JSCallReducerAssembler::ReduceStringPrototypeSlice() {
  TNode<Object> receiver = ReceiverInput();
  TNode<Object> start = Argument(0);
  TNode<Object> end = ArgumentOrUndefined(1);

  TNode<String> receiver_string = CheckString(receiver);
  TNode<Number> start_smi = CheckSmi(start);

  TNode<Number> length = StringLength(receiver_string);

  TNode<Number> end_smi = SelectIf<Number>(IsUndefined(end))
                              .Then(_ { return length; })
                              .Else(_ { return CheckSmi(end); })
                              .ExpectFalse()
                              .Value();

  TNode<Number> zero = TNode<Number>::UncheckedCast(ZeroConstant());
  TNode<Number> from_untyped =
      SelectIf<Number>(NumberLessThan(start_smi, zero))
          .Then(_ { return NumberMax(NumberAdd(length, start_smi), zero); })
          .Else(_ { return NumberMin(start_smi, length); })
          .ExpectFalse()
          .Value();
  // {from} is always in non-negative Smi range, but our typer cannot figure
  // that out yet.
  TNode<Smi> from = TypeGuardUnsignedSmall(from_untyped);

  TNode<Number> to_untyped =
      SelectIf<Number>(NumberLessThan(end_smi, zero))
          .Then(_ { return NumberMax(NumberAdd(length, end_smi), zero); })
          .Else(_ { return NumberMin(end_smi, length); })
          .ExpectFalse()
          .Value();
  // {to} is always in non-negative Smi range, but our typer cannot figure that
  // out yet.
  TNode<Smi> to = TypeGuardUnsignedSmall(to_untyped);

  return SelectIf<String>(NumberLessThan(from, to))
      .Then(_ { return StringSubstring(receiver_string, from, to); })
      .Else(_ { return EmptyStringConstant(); })
      .ExpectTrue()
      .Value();
}

TNode<Object> JSCallReducerAssembler::ReduceJSCallMathMinMaxWithArrayLike(
    Builtin builtin) {
  JSCallWithArrayLikeNode n(node_ptr());
  TNode<Object> arguments_list = n.Argument(0);

  auto call_builtin = MakeLabel();
  auto done = MakeLabel(MachineRepresentation::kTagged);

  // Check if {arguments_list} is a JSArray.
  GotoIf(ObjectIsSmi(arguments_list), &call_builtin);
  TNode<Map> arguments_list_map =
      LoadField<Map>(AccessBuilder::ForMap(),
                     TNode<HeapObject>::UncheckedCast(arguments_list));
  TNode<Number> arguments_list_instance_type = LoadField<Number>(
      AccessBuilder::ForMapInstanceType(), arguments_list_map);
  auto check_instance_type =
      NumberEqual(arguments_list_instance_type, NumberConstant(JS_ARRAY_TYPE));
  GotoIfNot(check_instance_type, &call_builtin);

  // Check if {arguments_list} has PACKED_DOUBLE_ELEMENTS.
  TNode<Number> arguments_list_elements_kind =
      LoadMapElementsKind(arguments_list_map);

  auto check_element_kind = NumberEqual(arguments_list_elements_kind,
                                        NumberConstant(PACKED_DOUBLE_ELEMENTS));
  GotoIfNot(check_element_kind, &call_builtin);

  // If {arguments_list} is a JSArray with PACKED_DOUBLE_ELEMENTS, calculate the
  // result with inlined loop.
  TNode<JSArray> array_arguments_list =
      TNode<JSArray>::UncheckedCast(arguments_list);
  Goto(&done, builtin == Builtin::kMathMax
                  ? DoubleArrayMax(array_arguments_list)
                  : DoubleArrayMin(array_arguments_list));

  // Otherwise, call BuiltinMathMin/Max as usual.
  Bind(&call_builtin);
  TNode<Object> call = CopyNode();
  CallParameters const& p = n.Parameters();

  // Set SpeculationMode to kDisallowSpeculation to avoid infinite
  // recursion.
  NodeProperties::ChangeOp(
      call, javascript()->CallWithArrayLike(
                p.frequency(), p.feedback(),
                SpeculationMode::kDisallowSpeculation, p.feedback_relation()));
  Goto(&done, call);

  Bind(&done);
  return done.PhiAt<Object>(0);
}

TNode<Object> IteratingArrayBuiltinReducerAssembler::ReduceArrayPrototypeAt(
    ZoneVector<MapRef> maps, bool needs_fallback_builtin_call) {
  TNode<JSArray> receiver = ReceiverInputAs<JSArray>();
  TNode<Object> index = ArgumentOrZero(0);

  TNode<Number> index_num = CheckSmi(index);
  TNode<FixedArrayBase> elements = LoadElements(receiver);

  TNode<Map> receiver_map =
      TNode<Map>::UncheckedCast(LoadField(AccessBuilder::ForMap(), receiver));

  auto out = MakeLabel(MachineRepresentation::kTagged);

  for (MapRef map : maps) {
    DCHECK(map.supports_fast_array_iteration(broker()));
    auto correct_map_label = MakeLabel(), wrong_map_label = MakeLabel();
    TNode<Boolean> is_map_equal = ReferenceEqual(receiver_map, Constant(map));
    Branch(is_map_equal, &correct_map_label, &wrong_map_label);
    Bind(&correct_map_label);

    TNode<Number> length = LoadJSArrayLength(receiver, map.elements_kind());

    // If index is less than 0, then subtract from length.
    TNode<Boolean> cond = NumberLessThan(index_num, ZeroConstant());
    TNode<Number> real_index_num =
        SelectIf<Number>(cond)
            .Then(_ { return NumberAdd(length, index_num); })
            .Else(_ { return index_num; })
            .ExpectTrue()  // Most common usage should be .at(-1)
            .Value();

    // Bound checking.
    GotoIf(NumberLessThan(real_index_num, ZeroConstant()), &out,
           UndefinedConstant());
    GotoIfNot(NumberLessThan(real_index_num, length), &out,
              UndefinedConstant());
    if (v8_flags.turbo_typer_hardening) {
      real_index_num = CheckBounds(real_index_num, length,
                                   CheckBoundsFlag::kAbortOnOutOfBounds);
    }

    // Retrieving element at index.
    TNode<Object> element = LoadElement<Object>(
        AccessBuilder::ForFixedArrayElement(map.elements_kind()), elements,
        real_index_num);
    if (IsHoleyElementsKind(map.elements_kind())) {
      // This case is needed in particular for HOLEY_DOUBLE_ELEMENTS: raw
      // doubles are stored in the FixedDoubleArray, and need to be converted to
      // HeapNumber or to Smi so that this function can return an Object. The
      // automatic converstion performed by
      // RepresentationChanger::GetTaggedRepresentationFor does not handle
      // holes, so we convert manually a potential hole here.
      element = ConvertHoleToUndefined(element, map.elements_kind());
    }
    Goto(&out, element);

    Bind(&wrong_map_label);
  }

  if (needs_fallback_builtin_call) {
    JSCallNode n(node_ptr());
    CallParameters const& p = n.Parameters();

    // We set SpeculationMode to kDisallowSpeculation to avoid infinite
    // recursion on the node we're creating (since, after all, it's calling
    // Array.Prototype.at).
    const Operator* op = javascript()->Call(
        JSCallNode::ArityForArgc(1), p.frequency(), p.feedback(),
        ConvertReceiverMode::kNotNullOrUndefined,
        SpeculationMode::kDisallowSpeculation, CallFeedbackRelation::kTarget);
    Node* fallback_builtin = node_ptr()->InputAt(0);

    TNode<Object> res = AddNode<Object>(graph()->NewNode(
        op, fallback_builtin, receiver, index, n.feedback_vector(),
        ContextInput(), n.frame_state(), effect(), control()));
    Goto(&out, res);
  } else {
    Goto(&out, UndefinedConstant());
  }

  Bind(&out);
  return out.PhiAt<Object>(0);
}

TNode<Number> IteratingArrayBuiltinReducerAssembler::ReduceArrayPrototypePush(
    MapInference* inference) {
  int const num_push_arguments = ArgumentCount();
  ZoneRefSet<Map> const& receiver_maps = inference->GetMaps();

  base::SmallVector<MachineRepresentation, 4> argument_reps;
  base::SmallVector<Node*, 4> argument_nodes;

  for (int i = 0; i < num_push_arguments; ++i) {
    argument_reps.push_back(MachineRepresentation::kTagged);
    argument_nodes.push_back(Argument(i));
  }

  TNode<JSArray> receiver = ReceiverInputAs<JSArray>();
  TNode<Map> receiver_map = LoadMap(receiver);

  auto double_label = MakeLabel(argument_reps);
  auto smi_label = MakeLabel(argument_reps);
  auto object_label = MakeLabel(argument_reps);

  for (size_t i = 0; i < receiver_maps.size(); i++) {
    MapRef map = receiver_maps[i];
    ElementsKind kind = map.elements_kind();

    if (i < receiver_maps.size() - 1) {
      TNode<Boolean> is_map_equal = ReferenceEqual(receiver_map, Constant(map));
      if (IsDoubleElementsKind(kind)) {
        GotoIf(is_map_equal, &double_label, argument_nodes);
      } else if (IsSmiElementsKind(kind)) {
        GotoIf(is_map_equal, &smi_label, argument_nodes);
      } else {
        GotoIf(is_map_equal, &object_label, argument_nodes);
      }
    } else {
      if (IsDoubleElementsKind(kind)) {
        Goto(&double_label, argument_nodes);
      } else if (IsSmiElementsKind(kind)) {
        Goto(&smi_label, argument_nodes);
      } else {
        Goto(&object_label, argument_nodes);
      }
    }
  }

  auto return_label = MakeLabel(MachineRepresentation::kTagged);

  auto build_array_push = [&](ElementsKind kind,
                              base::SmallVector<Node*, 1>& push_arguments) {
    // Only support PACKED_ELEMENTS and PACKED_DOUBLE_ELEMENTS, as "markers" of
    // what the elements array is (a FixedArray or FixedDoubleArray).
    DCHECK(kind == PACKED_ELEMENTS || kind == PACKED_DOUBLE_ELEMENTS);

    // Load the "length" property of the {receiver}.
    TNode<Smi> length = LoadJSArrayLength(receiver, kind);
    TNode<Number> return_value = length;

    // Check if we have any {values} to push.
    if (num_push_arguments > 0) {
      // Compute the resulting "length" of the {receiver}.
      TNode<Number> new_length = return_value =
          NumberAdd(length, NumberConstant(num_push_arguments));

      // Load the elements backing store of the {receiver}.
      TNode<FixedArrayBase> elements = LoadElements(receiver);
      TNode<Smi> elements_length = LoadFixedArrayBaseLength(elements);

      elements = MaybeGrowFastElements(
          kind, feedback(), receiver, elements,
          NumberAdd(length, NumberConstant(num_push_arguments - 1)),
          elements_length);

      // Update the JSArray::length field. Since this is observable,
      // there must be no other check after this.
      StoreJSArrayLength(receiver, new_length, kind);

      // Append the {values} to the {elements}.
      for (int i = 0; i < num_push_arguments; ++i) {
        StoreFixedArrayBaseElement(
            elements, NumberAdd(length, NumberConstant(i)),
            TNode<Object>::UncheckedCast(push_arguments[i]), kind);
      }
    }

    Goto(&return_label, return_value);
  };

  if (double_label.IsUsed()) {
    Bind(&double_label);
    base::SmallVector<Node*, 1> push_arguments(num_push_arguments);
    for (int i = 0; i < num_push_arguments; ++i) {
      Node* value =
          CheckNumber(TNode<Object>::UncheckedCast(double_label.PhiAt(i)));
      // Make sure we do not store signaling NaNs into double arrays.
      value = AddNode<Number>(
          graph()->NewNode(simplified()->NumberSilenceNaN(), value));
      push_arguments[i] = value;
    }
    build_array_push(PACKED_DOUBLE_ELEMENTS, push_arguments);
  }

  if (smi_label.IsUsed()) {
    Bind(&smi_label);
    base::SmallVector<Node*, 4> push_arguments(num_push_arguments);
    for (int i = 0; i < num_push_arguments; ++i) {
      Node* value = CheckSmi(TNode<Object>::UncheckedCast(smi_label.PhiAt(i)));
      push_arguments[i] = value;
    }
    Goto(&object_label, push_arguments);
  }

  if (object_label.IsUsed()) {
    Bind(&object_label);
    base::SmallVector<Node*, 1> push_arguments(num_push_arguments);
    for (int i = 0; i < num_push_arguments; ++i) {
      push_arguments[i] = object_label.PhiAt(i);
    }
    build_array_push(PACKED_ELEMENTS, push_arguments);
  }

  Bind(&return_label);
  return TNode<Number>::UncheckedCast(return_label.PhiAt(0));
}

namespace {

struct ForEachFrameStateParams {
  JSGraph* jsgraph;
  SharedFunctionInfoRef shared;
  TNode<Context> context;
  TNode<Object> target;
  FrameState outer_frame_state;
  TNode<Object> receiver;
  TNode<Object> callback;
  TNode<Object> this_arg;
  TNode<Object> original_length;
};

FrameState ForEachLoopLazyFrameState(const ForEachFrameStateParams& params,
                                     TNode<Object> k) {
  Builtin builtin = Builtin::kArrayForEachLoopLazyDeoptContinuation;
  Node* checkpoint_params[] = {params.receiver, params.callback,
                               params.this_arg, k, params.original_length};
  return CreateJavaScriptBuiltinContinuationFrameState(
      params.jsgraph, params.shared, builtin, params.target, params.context,
      checkpoint_params, arraysize(checkpoint_params), params.outer_frame_state,
      ContinuationFrameStateMode::LAZY);
}

FrameState ForEachLoopEagerFrameState(const ForEachFrameStateParams& params,
                                      TNode<Object> k) {
  Builtin builtin = Builtin::kArrayForEachLoopEagerDeoptContinuation;
  Node* checkpoint_params[] = {params.receiver, params.callback,
                               params.this_arg, k, params.original_length};
  return CreateJavaScriptBuiltinContinuationFrameState(
      params.jsgraph, params.shared, builtin, params.target, params.context,
      checkpoint_params, arraysize(checkpoint_params), params.outer_frame_state,
      ContinuationFrameStateMode::EAGER);
}

}  // namespace

TNode<Object>
IteratingArrayBuiltinReducerAssembler::ReduceArrayPrototypeForEach(
    MapInference* inference, const bool has_stability_dependency,
    ElementsKind kind, SharedFunctionInfoRef shared) {
  FrameState outer_frame_state = FrameStateInput();
  TNode<Context> context = ContextInput();
  TNode<Object> target = TargetInput();
  TNode<JSArray> receiver = ReceiverInputAs<JSArray>();
  TNode<Object> fncallback = ArgumentOrUndefined(0);
  TNode<Object> this_arg = ArgumentOrUndefined(1);

  TNode<Number> original_length = LoadJSArrayLength(receiver, kind);

  ForEachFrameStateParams frame_state_params{
      jsgraph(), shared,     context,  target,         outer_frame_state,
      receiver,  fncallback, this_arg, original_length};

  ThrowIfNotCallable(fncallback, ForEachLoopLazyFrameState(frame_state_params,
                                                           ZeroConstant()));

  ForZeroUntil(original_length).Do([&](TNode<Number> k) {
    Checkpoint(ForEachLoopEagerFrameState(frame_state_params, k));

    // Deopt if the map has changed during the iteration.
    MaybeInsertMapChecks(inference, has_stability_dependency);

    TNode<Object> element;
    std::tie(k, element) = SafeLoadElement(kind, receiver, k);

    auto continue_label = MakeLabel();
    element = MaybeSkipHole(element, kind, &continue_label);

    TNode<Number> next_k = NumberAdd(k, OneConstant());
    JSCall3(fncallback, this_arg, element, k, receiver,
            ForEachLoopLazyFrameState(frame_state_params, next_k));

    Goto(&continue_label);
    Bind(&continue_label);
  });

  return UndefinedConstant();
}

namespace {

struct ReduceFrameStateParams {
  JSGraph* jsgraph;
  SharedFunctionInfoRef shared;
  ArrayReduceDirection direction;
  TNode<Context> context;
  TNode<Object> target;
  FrameState outer_frame_state;
};

FrameState ReducePreLoopLazyFrameState(const ReduceFrameStateParams& params,
                                       TNode<Object> receiver,
                                       TNode<Object> callback, TNode<Object> k,
                                       TNode<Number> original_length) {
  Builtin builtin = (params.direction == ArrayReduceDirection::kLeft)
                        ? Builtin::kArrayReduceLoopLazyDeoptContinuation
                        : Builtin::kArrayReduceRightLoopLazyDeoptContinuation;
  Node* checkpoint_params[] = {receiver, callback, k, original_length};
  return CreateJavaScriptBuiltinContinuationFrameState(
      params.jsgraph, params.shared, builtin, params.target, params.context,
      checkpoint_params, arraysize(checkpoint_params), params.outer_frame_state,
      ContinuationFrameStateMode::LAZY);
}

FrameState ReducePreLoopEagerFrameState(const ReduceFrameStateParams& params,
                                        TNode<Object> receiver,
                                        TNode<Object> callback,
                                        TNode<Number> original_length) {
  Builtin builtin =
      (params.direction == ArrayReduceDirection::kLeft)
          ? Builtin::kArrayReducePreLoopEagerDeoptContinuation
          : Builtin::kArrayReduceRightPreLoopEagerDeoptContinuation;
  Node* checkpoint_params[] = {receiver, callback, original_length};
  return CreateJavaScriptBuiltinContinuationFrameState(
      params.jsgraph, params.shared, builtin, params.target, params.context,
      checkpoint_params, arraysize(checkpoint_params), params.outer_frame_state,
      ContinuationFrameStateMode::EAGER);
}

FrameState ReduceLoopLazyFrameState(const ReduceFrameStateParams& params,
                                    TNode<Object> receiver,
                                    TNode<Object> callback, TNode<Object> k,
                                    TNode<Number> original_length) {
  Builtin builtin = (params.direction == ArrayReduceDirection::kLeft)
                        ? Builtin::kArrayReduceLoopLazyDeoptContinuation
                        : Builtin::kArrayReduceRightLoopLazyDeoptContinuation;
  Node* checkpoint_params[] = {receiver, callback, k, original_length};
  return CreateJavaScriptBuiltinContinuationFrameState(
      params.jsgraph, params.shared, builtin, params.target, params.context,
      checkpoint_params, arraysize(checkpoint_params), params.outer_frame_state,
      ContinuationFrameStateMode::LAZY);
}

FrameState ReduceLoopEagerFrameState(const ReduceFrameStateParams& params,
                                     TNode<Object> receiver,
                                     TNode<Object> callback, TNode<Object> k,
                                     TNode<Number> original_length,
                                     TNode<Object> accumulator) {
  Builtin builtin = (params.direction == ArrayReduceDirection::kLeft)
                        ? Builtin::kArrayReduceLoopEagerDeoptContinuation
                        : Builtin::kArrayReduceRightLoopEagerDeoptContinuation;
  Node* checkpoint_params[] = {receiver, callback, k, original_length,
                               accumulator};
  return CreateJavaScriptBuiltinContinuationFrameState(
      params.jsgraph, params.shared, builtin, params.target, params.context,
      checkpoint_params, arraysize(checkpoint_params), params.outer_frame_state,
      ContinuationFrameStateMode::EAGER);
}

}  // namespace

TNode<Object> IteratingArrayBuiltinReducerAssembler::ReduceArrayPrototypeReduce(
    MapInference* inference, const bool has_stability_dependency,
    ElementsKind kind, ArrayReduceDirection direction,
    SharedFunctionInfoRef shared) {
  FrameState outer_frame_state = FrameStateInput();
  TNode<Context> context = ContextInput();
  TNode<Object> target = TargetInput();
  TNode<JSArray> receiver = ReceiverInputAs<JSArray>();
  TNode<Object> fncallback = 
"""


```