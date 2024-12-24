Response: The user wants a summary of the C++ source code file `v8/src/compiler/js-call-reducer.cc`, specifically the functionality of the provided snippet. They also want to see a JavaScript example that relates to the code if such a relationship exists. This is the second part of a larger file.

The code appears to implement reductions for JavaScript built-in methods that involve iterating over arrays, such as `reduce`, `map`, `filter`, `find`, `every`, `some`, `indexOf`, and `includes`. It also includes reductions for `Promise` constructor.

Let's break down the provided snippet:

1. **`ReduceArrayPrototypeReduce`**: This function handles the reduction for `Array.prototype.reduce` and `Array.prototype.reduceRight`. It sets up the iteration logic (left or right), handles the initial accumulator value, and performs the callback function application.

2. **`ReduceArrayPrototypeMap`**:  This function implements the logic for `Array.prototype.map`. It creates a new array and applies the callback function to each element of the original array, storing the result in the new array.

3. **`ReduceArrayPrototypeFilter`**: This function implements `Array.prototype.filter`. It creates a new array containing only the elements for which the callback function returns a truthy value.

4. **`ReduceArrayPrototypeFind`**:  This implements `Array.prototype.find` and `Array.prototype.findIndex`. It iterates through the array and returns the first element (or its index) that satisfies the provided testing function.

5. **`ReduceArrayPrototypeEverySome`**: This function handles both `Array.prototype.every` and `Array.prototype.some`. `every` returns `true` if the callback returns `true` for all elements, and `some` returns `true` if the callback returns `true` for at least one element.

6. **`ReduceArrayPrototypeIndexOfIncludes`**:  This function handles `Array.prototype.indexOf` and `Array.prototype.includes`. It searches for a specific element in the array and returns its index (or `true`/`false` for `includes`). It currently reduces to a stub call, indicating this part might not be fully optimized yet within this specific code.

7. **`ReducePromiseConstructor`**: This function deals with the reduction of the `Promise` constructor. It sets up the resolving and rejecting functions and handles the execution of the promise executor.

Now, let's create JavaScript examples for some of these functions.
这个C++代码片段是V8 JavaScript引擎中`JSCallReducer`的一部分，专门负责优化和简化对JavaScript数组迭代方法（如 `reduce`, `map`, `filter`, `find`, `every`, `some`, `indexOf`, `includes`）和 `Promise` 构造函数的调用。它将这些高级的JavaScript操作转换为更底层的、更有效率的中间表示，以便后续的编译和执行。

**功能归纳:**

这个代码片段主要实现了以下功能：

1. **`ReduceArrayPrototypeReduce`**:  处理 `Array.prototype.reduce` 和 `Array.prototype.reduceRight` 的优化。它设置循环结构，处理初始值，并确保在迭代过程中正确调用回调函数。

2. **`ReduceArrayPrototypeMap`**:  处理 `Array.prototype.map` 的优化。它创建一个新的数组，并将回调函数应用于原数组的每个元素，然后将结果存入新数组。

3. **`ReduceArrayPrototypeFilter`**: 处理 `Array.prototype.filter` 的优化。它创建一个新数组，其中仅包含回调函数返回真值的元素。

4. **`ReduceArrayPrototypeFind`**: 处理 `Array.prototype.find` 和 `Array.prototype.findIndex` 的优化。它查找数组中满足回调函数条件的第一个元素（或其索引）。

5. **`ReduceArrayPrototypeEverySome`**: 处理 `Array.prototype.every` 和 `Array.prototype.some` 的优化。`every` 只有在所有元素都满足条件时返回 `true`，而 `some` 只要有一个元素满足条件就返回 `true`。

6. **`ReduceArrayPrototypeIndexOfIncludes`**: 处理 `Array.prototype.indexOf` 和 `Array.prototype.includes` 的优化。它在数组中查找特定元素并返回其索引（或 `includes` 的布尔值）。目前这部分代码似乎只是简化为一个桩调用，可能后续会有更深入的优化。

7. **`ReducePromiseConstructor`**: 处理 `Promise` 构造函数的优化。它创建 `Promise` 对象，设置 `resolve` 和 `reject` 函数，并调用 `Promise` 的执行器函数。

**与 JavaScript 功能的关系和示例:**

这些 C++ 函数对应于 JavaScript 中常用的数组迭代方法和 `Promise` API。 `JSCallReducer` 的目标是在编译时识别这些调用模式，并将其转换为更高效的底层操作，从而提高 JavaScript 代码的执行效率。

**JavaScript 示例:**

```javascript
// 对应 ReduceArrayPrototypeReduce
const numbers = [1, 2, 3, 4];
const sum = numbers.reduce((accumulator, currentValue) => accumulator + currentValue, 0);
console.log(sum); // 输出 10

// 对应 ReduceArrayPrototypeMap
const doubledNumbers = numbers.map(number => number * 2);
console.log(doubledNumbers); // 输出 [2, 4, 6, 8]

// 对应 ReduceArrayPrototypeFilter
const evenNumbers = numbers.filter(number => number % 2 === 0);
console.log(evenNumbers); // 输出 [2, 4]

// 对应 ReduceArrayPrototypeFind (和 findIndex)
const firstEven = numbers.find(number => number % 2 === 0);
console.log(firstEven); // 输出 2
const indexOfFirstEven = numbers.findIndex(number => number % 2 === 0);
console.log(indexOfFirstEven); // 输出 1

// 对应 ReduceArrayPrototypeEverySome
const allPositive = numbers.every(number => number > 0);
console.log(allPositive); // 输出 true
const hasNegative = numbers.some(number => number < 0);
console.log(hasNegative); // 输出 false

// 对应 ReduceArrayPrototypeIndexOfIncludes
const index = numbers.indexOf(3);
console.log(index); // 输出 2
const includesThree = numbers.includes(3);
console.log(includesThree); // 输出 true

// 对应 ReducePromiseConstructor
const myPromise = new Promise((resolve, reject) => {
  setTimeout(() => {
    resolve("Promise resolved!");
  }, 1000);
});

myPromise.then(result => {
  console.log(result); // 大约 1 秒后输出 "Promise resolved!"
});
```

**总结:**

这个 C++ 代码片段是 V8 引擎进行 JavaScript 性能优化的关键部分。它通过在编译阶段识别并简化对特定 JavaScript 内置函数的调用，减少了运行时的开销，使得 JavaScript 代码能够更快速地执行。它针对的是数组迭代和 `Promise` 构造这两个在现代 JavaScript 开发中非常重要的概念。

Prompt: 
```
这是目录为v8/src/compiler/js-call-reducer.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共6部分，请归纳一下它的功能

"""
ArgumentOrUndefined(0);

  ReduceFrameStateParams frame_state_params{
      jsgraph(), shared, direction, context, target, outer_frame_state};

  TNode<Number> original_length = LoadJSArrayLength(receiver, kind);

  // Set up variable behavior depending on the reduction kind (left/right).
  TNode<Number> k;
  StepFunction1 step;
  ConditionFunction1 cond;
  TNode<Number> zero = ZeroConstant();
  TNode<Number> one = OneConstant();
  if (direction == ArrayReduceDirection::kLeft) {
    k = zero;
    step = [&](TNode<Number> i) { return NumberAdd(i, one); };
    cond = [&](TNode<Number> i) { return NumberLessThan(i, original_length); };
  } else {
    k = NumberSubtract(original_length, one);
    step = [&](TNode<Number> i) { return NumberSubtract(i, one); };
    cond = [&](TNode<Number> i) { return NumberLessThanOrEqual(zero, i); };
  }

  ThrowIfNotCallable(
      fncallback, ReducePreLoopLazyFrameState(frame_state_params, receiver,
                                              fncallback, k, original_length));

  // Set initial accumulator value.
  TNode<Object> accumulator;
  if (ArgumentCount() > 1) {
    accumulator = Argument(1);  // Initial value specified by the user.
  } else {
    // The initial value was not specified by the user. In this case, the first
    // (or last in the case of reduceRight) non-holey value of the array is
    // used. Loop until we find it. If not found, trigger a deopt.
    // TODO(jgruber): The deopt does not seem necessary. Instead we could simply
    // throw the TypeError here from optimized code.
    auto found_initial_element = MakeLabel(MachineRepresentation::kTagged,
                                           MachineRepresentation::kTagged);
    Forever(k, step).Do([&](TNode<Number> k) {
      Checkpoint(ReducePreLoopEagerFrameState(frame_state_params, receiver,
                                              fncallback, original_length));
      CheckIf(cond(k), DeoptimizeReason::kNoInitialElement);

      TNode<Object> element;
      std::tie(k, element) = SafeLoadElement(kind, receiver, k);

      auto continue_label = MakeLabel();
      GotoIf(HoleCheck(kind, element), &continue_label);
      Goto(&found_initial_element, k, TypeGuardNonInternal(element));

      Bind(&continue_label);
    });
    Unreachable();  // The loop is exited either by deopt or a jump to below.

    // TODO(jgruber): This manual fiddling with blocks could be avoided by
    // implementing a `break` mechanic for loop builders.
    Bind(&found_initial_element);
    k = step(found_initial_element.PhiAt<Number>(0));
    accumulator = found_initial_element.PhiAt<Object>(1);
  }

  TNode<Object> result =
      For1(k, cond, step, accumulator)
          .Do([&](TNode<Number> k, TNode<Object>* accumulator) {
            Checkpoint(ReduceLoopEagerFrameState(frame_state_params, receiver,
                                                 fncallback, k, original_length,
                                                 *accumulator));

            // Deopt if the map has changed during the iteration.
            MaybeInsertMapChecks(inference, has_stability_dependency);

            TNode<Object> element;
            std::tie(k, element) = SafeLoadElement(kind, receiver, k);

            auto continue_label = MakeLabel(MachineRepresentation::kTagged);
            element =
                MaybeSkipHole(element, kind, &continue_label, *accumulator);

            TNode<Number> next_k = step(k);
            TNode<Object> next_accumulator = JSCall4(
                fncallback, UndefinedConstant(), *accumulator, element, k,
                receiver,
                ReduceLoopLazyFrameState(frame_state_params, receiver,
                                         fncallback, next_k, original_length));
            Goto(&continue_label, next_accumulator);

            Bind(&continue_label);
            *accumulator = continue_label.PhiAt<Object>(0);
          })
          .Value();

  return result;
}

namespace {

struct MapFrameStateParams {
  JSGraph* jsgraph;
  SharedFunctionInfoRef shared;
  TNode<Context> context;
  TNode<Object> target;
  FrameState outer_frame_state;
  TNode<Object> receiver;
  TNode<Object> callback;
  TNode<Object> this_arg;
  std::optional<TNode<JSArray>> a;
  TNode<Object> original_length;
};

FrameState MapPreLoopLazyFrameState(const MapFrameStateParams& params) {
  DCHECK(!params.a);
  Node* checkpoint_params[] = {params.receiver, params.callback,
                               params.this_arg, params.original_length};
  return CreateJavaScriptBuiltinContinuationFrameState(
      params.jsgraph, params.shared,
      Builtin::kArrayMapPreLoopLazyDeoptContinuation, params.target,
      params.context, checkpoint_params, arraysize(checkpoint_params),
      params.outer_frame_state, ContinuationFrameStateMode::LAZY);
}

FrameState MapLoopLazyFrameState(const MapFrameStateParams& params,
                                 TNode<Number> k) {
  Node* checkpoint_params[] = {
      params.receiver,       params.callback, params.this_arg, *params.a, k,
      params.original_length};
  return CreateJavaScriptBuiltinContinuationFrameState(
      params.jsgraph, params.shared,
      Builtin::kArrayMapLoopLazyDeoptContinuation, params.target,
      params.context, checkpoint_params, arraysize(checkpoint_params),
      params.outer_frame_state, ContinuationFrameStateMode::LAZY);
}

FrameState MapLoopEagerFrameState(const MapFrameStateParams& params,
                                  TNode<Number> k) {
  Node* checkpoint_params[] = {
      params.receiver,       params.callback, params.this_arg, *params.a, k,
      params.original_length};
  return CreateJavaScriptBuiltinContinuationFrameState(
      params.jsgraph, params.shared,
      Builtin::kArrayMapLoopEagerDeoptContinuation, params.target,
      params.context, checkpoint_params, arraysize(checkpoint_params),
      params.outer_frame_state, ContinuationFrameStateMode::EAGER);
}

}  // namespace

TNode<JSArray> IteratingArrayBuiltinReducerAssembler::ReduceArrayPrototypeMap(
    MapInference* inference, const bool has_stability_dependency,
    ElementsKind kind, SharedFunctionInfoRef shared,
    NativeContextRef native_context) {
  FrameState outer_frame_state = FrameStateInput();
  TNode<Context> context = ContextInput();
  TNode<Object> target = TargetInput();
  TNode<JSArray> receiver = ReceiverInputAs<JSArray>();
  TNode<Object> fncallback = ArgumentOrUndefined(0);
  TNode<Object> this_arg = ArgumentOrUndefined(1);

  TNode<Number> original_length = LoadJSArrayLength(receiver, kind);

  // If the array length >= kMaxFastArrayLength, then CreateArray
  // will create a dictionary. We should deopt in this case, and make sure
  // not to attempt inlining again.
  original_length = CheckBounds(original_length,
                                NumberConstant(JSArray::kMaxFastArrayLength));

  // Even though {JSCreateArray} is not marked as {kNoThrow}, we can elide the
  // exceptional projections because it cannot throw with the given
  // parameters.
  TNode<Object> array_ctor =
      Constant(native_context.GetInitialJSArrayMap(broker(), kind)
                   .GetConstructor(broker()));

  MapFrameStateParams frame_state_params{
      jsgraph(), shared,     context,  target,       outer_frame_state,
      receiver,  fncallback, this_arg, {} /* TBD */, original_length};

  TNode<JSArray> a =
      CreateArrayNoThrow(array_ctor, original_length,
                         MapPreLoopLazyFrameState(frame_state_params));
  frame_state_params.a = a;

  ThrowIfNotCallable(fncallback,
                     MapLoopLazyFrameState(frame_state_params, ZeroConstant()));

  ForZeroUntil(original_length).Do([&](TNode<Number> k) {
    Checkpoint(MapLoopEagerFrameState(frame_state_params, k));
    MaybeInsertMapChecks(inference, has_stability_dependency);

    TNode<Object> element;
    std::tie(k, element) = SafeLoadElement(kind, receiver, k);

    auto continue_label = MakeLabel();
    element = MaybeSkipHole(element, kind, &continue_label);

    TNode<Object> v = JSCall3(fncallback, this_arg, element, k, receiver,
                              MapLoopLazyFrameState(frame_state_params, k));

    // The array {a} should be HOLEY_SMI_ELEMENTS because we'd only come into
    // this loop if the input array length is non-zero, and "new Array({x > 0})"
    // always produces a HOLEY array.
    MapRef holey_double_map =
        native_context.GetInitialJSArrayMap(broker(), HOLEY_DOUBLE_ELEMENTS);
    MapRef holey_map =
        native_context.GetInitialJSArrayMap(broker(), HOLEY_ELEMENTS);
    TransitionAndStoreElement(holey_double_map, holey_map, a, k, v);

    Goto(&continue_label);
    Bind(&continue_label);
  });

  return a;
}

namespace {

struct FilterFrameStateParams {
  JSGraph* jsgraph;
  SharedFunctionInfoRef shared;
  TNode<Context> context;
  TNode<Object> target;
  FrameState outer_frame_state;
  TNode<Object> receiver;
  TNode<Object> callback;
  TNode<Object> this_arg;
  TNode<JSArray> a;
  TNode<Object> original_length;
};

FrameState FilterLoopLazyFrameState(const FilterFrameStateParams& params,
                                    TNode<Number> k, TNode<Number> to,
                                    TNode<Object> element) {
  Node* checkpoint_params[] = {params.receiver,
                               params.callback,
                               params.this_arg,
                               params.a,
                               k,
                               params.original_length,
                               element,
                               to};
  return CreateJavaScriptBuiltinContinuationFrameState(
      params.jsgraph, params.shared,
      Builtin::kArrayFilterLoopLazyDeoptContinuation, params.target,
      params.context, checkpoint_params, arraysize(checkpoint_params),
      params.outer_frame_state, ContinuationFrameStateMode::LAZY);
}

FrameState FilterLoopEagerPostCallbackFrameState(
    const FilterFrameStateParams& params, TNode<Number> k, TNode<Number> to,
    TNode<Object> element, TNode<Object> callback_value) {
  // Note that we are intentionally reusing the
  // Builtin::kArrayFilterLoopLazyDeoptContinuation as an *eager* entry
  // point in this case. This is safe, because re-evaluating a [ToBoolean]
  // coercion is safe.
  Node* checkpoint_params[] = {params.receiver,
                               params.callback,
                               params.this_arg,
                               params.a,
                               k,
                               params.original_length,
                               element,
                               to,
                               callback_value};
  return CreateJavaScriptBuiltinContinuationFrameState(
      params.jsgraph, params.shared,
      Builtin::kArrayFilterLoopLazyDeoptContinuation, params.target,
      params.context, checkpoint_params, arraysize(checkpoint_params),
      params.outer_frame_state, ContinuationFrameStateMode::EAGER);
}

FrameState FilterLoopEagerFrameState(const FilterFrameStateParams& params,
                                     TNode<Number> k, TNode<Number> to) {
  Node* checkpoint_params[] = {params.receiver,
                               params.callback,
                               params.this_arg,
                               params.a,
                               k,
                               params.original_length,
                               to};
  return CreateJavaScriptBuiltinContinuationFrameState(
      params.jsgraph, params.shared,
      Builtin::kArrayFilterLoopEagerDeoptContinuation, params.target,
      params.context, checkpoint_params, arraysize(checkpoint_params),
      params.outer_frame_state, ContinuationFrameStateMode::EAGER);
}

}  // namespace

TNode<JSArray>
IteratingArrayBuiltinReducerAssembler::ReduceArrayPrototypeFilter(
    MapInference* inference, const bool has_stability_dependency,
    ElementsKind kind, SharedFunctionInfoRef shared,
    NativeContextRef native_context) {
  FrameState outer_frame_state = FrameStateInput();
  TNode<Context> context = ContextInput();
  TNode<Object> target = TargetInput();
  TNode<JSArray> receiver = ReceiverInputAs<JSArray>();
  TNode<Object> fncallback = ArgumentOrUndefined(0);
  TNode<Object> this_arg = ArgumentOrUndefined(1);

  // The output array is packed (filter doesn't visit holes).
  const ElementsKind packed_kind = GetPackedElementsKind(kind);
  TNode<JSArray> a = AllocateEmptyJSArray(packed_kind, native_context);

  TNode<Number> original_length = LoadJSArrayLength(receiver, kind);

  FilterFrameStateParams frame_state_params{
      jsgraph(), shared,     context,  target, outer_frame_state,
      receiver,  fncallback, this_arg, a,      original_length};

  // This frame state doesn't ever call the deopt continuation, it's only
  // necessary to specify a continuation in order to handle the exceptional
  // case. We don't have all the values available to completely fill out
  // the checkpoint parameters yet, but that's okay because it'll never be
  // called.
  TNode<Number> zero = ZeroConstant();
  ThrowIfNotCallable(fncallback, FilterLoopLazyFrameState(frame_state_params,
                                                          zero, zero, zero));

  TNode<Number> initial_a_length = zero;
  For1ZeroUntil(original_length, initial_a_length)
      .Do([&](TNode<Number> k, TNode<Object>* a_length_object) {
        TNode<Number> a_length = TNode<Number>::UncheckedCast(*a_length_object);
        Checkpoint(FilterLoopEagerFrameState(frame_state_params, k, a_length));
        MaybeInsertMapChecks(inference, has_stability_dependency);

        TNode<Object> element;
        std::tie(k, element) = SafeLoadElement(kind, receiver, k);

        auto continue_label = MakeLabel(MachineRepresentation::kTaggedSigned);
        element = MaybeSkipHole(element, kind, &continue_label, a_length);

        TNode<Object> v = JSCall3(
            fncallback, this_arg, element, k, receiver,
            FilterLoopLazyFrameState(frame_state_params, k, a_length, element));

        // We need an eager frame state for right after the callback function
        // returned, just in case an attempt to grow the output array fails.
        Checkpoint(FilterLoopEagerPostCallbackFrameState(frame_state_params, k,
                                                         a_length, element, v));

        GotoIfNot(ToBoolean(v), &continue_label, a_length);

        // Since the callback returned a trueish value, store the element in a.
        {
          TNode<Number> a_length1 = TypeGuardFixedArrayLength(a_length);
          TNode<FixedArrayBase> elements = LoadElements(a);
          elements = MaybeGrowFastElements(kind, FeedbackSource{}, a, elements,
                                           a_length1,
                                           LoadFixedArrayBaseLength(elements));

          TNode<Number> new_a_length = NumberInc(a_length1);
          StoreJSArrayLength(a, new_a_length, kind);
          StoreFixedArrayBaseElement(elements, a_length1, element, kind);

          Goto(&continue_label, new_a_length);
        }

        Bind(&continue_label);
        *a_length_object =
            TNode<Object>::UncheckedCast(continue_label.PhiAt(0));
      })
      .ValueIsUnused();

  return a;
}

namespace {

struct FindFrameStateParams {
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

FrameState FindLoopLazyFrameState(const FindFrameStateParams& params,
                                  TNode<Number> k, ArrayFindVariant variant) {
  Builtin builtin = (variant == ArrayFindVariant::kFind)
                        ? Builtin::kArrayFindLoopLazyDeoptContinuation
                        : Builtin::kArrayFindIndexLoopLazyDeoptContinuation;
  Node* checkpoint_params[] = {params.receiver, params.callback,
                               params.this_arg, k, params.original_length};
  return CreateJavaScriptBuiltinContinuationFrameState(
      params.jsgraph, params.shared, builtin, params.target, params.context,
      checkpoint_params, arraysize(checkpoint_params), params.outer_frame_state,
      ContinuationFrameStateMode::LAZY);
}

FrameState FindLoopEagerFrameState(const FindFrameStateParams& params,
                                   TNode<Number> k, ArrayFindVariant variant) {
  Builtin builtin = (variant == ArrayFindVariant::kFind)
                        ? Builtin::kArrayFindLoopEagerDeoptContinuation
                        : Builtin::kArrayFindIndexLoopEagerDeoptContinuation;
  Node* checkpoint_params[] = {params.receiver, params.callback,
                               params.this_arg, k, params.original_length};
  return CreateJavaScriptBuiltinContinuationFrameState(
      params.jsgraph, params.shared, builtin, params.target, params.context,
      checkpoint_params, arraysize(checkpoint_params), params.outer_frame_state,
      ContinuationFrameStateMode::EAGER);
}

FrameState FindLoopAfterCallbackLazyFrameState(
    const FindFrameStateParams& params, TNode<Number> next_k,
    TNode<Object> if_found_value, ArrayFindVariant variant) {
  Builtin builtin =
      (variant == ArrayFindVariant::kFind)
          ? Builtin::kArrayFindLoopAfterCallbackLazyDeoptContinuation
          : Builtin::kArrayFindIndexLoopAfterCallbackLazyDeoptContinuation;
  Node* checkpoint_params[] = {params.receiver,        params.callback,
                               params.this_arg,        next_k,
                               params.original_length, if_found_value};
  return CreateJavaScriptBuiltinContinuationFrameState(
      params.jsgraph, params.shared, builtin, params.target, params.context,
      checkpoint_params, arraysize(checkpoint_params), params.outer_frame_state,
      ContinuationFrameStateMode::LAZY);
}

}  // namespace

TNode<Object> IteratingArrayBuiltinReducerAssembler::ReduceArrayPrototypeFind(
    MapInference* inference, const bool has_stability_dependency,
    ElementsKind kind, SharedFunctionInfoRef shared,
    NativeContextRef native_context, ArrayFindVariant variant) {
  FrameState outer_frame_state = FrameStateInput();
  TNode<Context> context = ContextInput();
  TNode<Object> target = TargetInput();
  TNode<JSArray> receiver = ReceiverInputAs<JSArray>();
  TNode<Object> fncallback = ArgumentOrUndefined(0);
  TNode<Object> this_arg = ArgumentOrUndefined(1);

  TNode<Number> original_length = LoadJSArrayLength(receiver, kind);

  FindFrameStateParams frame_state_params{
      jsgraph(), shared,     context,  target,         outer_frame_state,
      receiver,  fncallback, this_arg, original_length};

  ThrowIfNotCallable(
      fncallback,
      FindLoopLazyFrameState(frame_state_params, ZeroConstant(), variant));

  const bool is_find_variant = (variant == ArrayFindVariant::kFind);
  auto out = MakeLabel(MachineRepresentation::kTagged);

  ForZeroUntil(original_length).Do([&](TNode<Number> k) {
    Checkpoint(FindLoopEagerFrameState(frame_state_params, k, variant));
    MaybeInsertMapChecks(inference, has_stability_dependency);

    TNode<Object> element;
    std::tie(k, element) = SafeLoadElement(kind, receiver, k);

    if (IsHoleyElementsKind(kind)) {
      element = ConvertHoleToUndefined(element, kind);
    }

    TNode<Object> if_found_value = is_find_variant ? element : k;
    TNode<Number> next_k = NumberInc(k);

    // The callback result states whether the desired element was found.
    TNode<Object> v =
        JSCall3(fncallback, this_arg, element, k, receiver,
                FindLoopAfterCallbackLazyFrameState(frame_state_params, next_k,
                                                    if_found_value, variant));

    GotoIf(ToBoolean(v), &out, if_found_value);
  });

  // If the loop completed, the element was not found.
  TNode<Object> if_not_found_value =
      is_find_variant ? TNode<Object>::UncheckedCast(UndefinedConstant())
                      : TNode<Object>::UncheckedCast(MinusOneConstant());
  Goto(&out, if_not_found_value);

  Bind(&out);
  return out.PhiAt<Object>(0);
}

namespace {

struct EverySomeFrameStateParams {
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

FrameState EverySomeLoopLazyFrameState(const EverySomeFrameStateParams& params,
                                       TNode<Number> k,
                                       ArrayEverySomeVariant variant) {
  Builtin builtin = (variant == ArrayEverySomeVariant::kEvery)
                        ? Builtin::kArrayEveryLoopLazyDeoptContinuation
                        : Builtin::kArraySomeLoopLazyDeoptContinuation;
  Node* checkpoint_params[] = {params.receiver, params.callback,
                               params.this_arg, k, params.original_length};
  return CreateJavaScriptBuiltinContinuationFrameState(
      params.jsgraph, params.shared, builtin, params.target, params.context,
      checkpoint_params, arraysize(checkpoint_params), params.outer_frame_state,
      ContinuationFrameStateMode::LAZY);
}

FrameState EverySomeLoopEagerFrameState(const EverySomeFrameStateParams& params,
                                        TNode<Number> k,
                                        ArrayEverySomeVariant variant) {
  Builtin builtin = (variant == ArrayEverySomeVariant::kEvery)
                        ? Builtin::kArrayEveryLoopEagerDeoptContinuation
                        : Builtin::kArraySomeLoopEagerDeoptContinuation;
  Node* checkpoint_params[] = {params.receiver, params.callback,
                               params.this_arg, k, params.original_length};
  return CreateJavaScriptBuiltinContinuationFrameState(
      params.jsgraph, params.shared, builtin, params.target, params.context,
      checkpoint_params, arraysize(checkpoint_params), params.outer_frame_state,
      ContinuationFrameStateMode::EAGER);
}

}  // namespace

TNode<Boolean>
IteratingArrayBuiltinReducerAssembler::ReduceArrayPrototypeEverySome(
    MapInference* inference, const bool has_stability_dependency,
    ElementsKind kind, SharedFunctionInfoRef shared,
    NativeContextRef native_context, ArrayEverySomeVariant variant) {
  FrameState outer_frame_state = FrameStateInput();
  TNode<Context> context = ContextInput();
  TNode<Object> target = TargetInput();
  TNode<JSArray> receiver = ReceiverInputAs<JSArray>();
  TNode<Object> fncallback = ArgumentOrUndefined(0);
  TNode<Object> this_arg = ArgumentOrUndefined(1);

  TNode<Number> original_length = LoadJSArrayLength(receiver, kind);

  EverySomeFrameStateParams frame_state_params{
      jsgraph(), shared,     context,  target,         outer_frame_state,
      receiver,  fncallback, this_arg, original_length};

  ThrowIfNotCallable(
      fncallback,
      EverySomeLoopLazyFrameState(frame_state_params, ZeroConstant(), variant));

  auto out = MakeLabel(MachineRepresentation::kTagged);

  ForZeroUntil(original_length).Do([&](TNode<Number> k) {
    Checkpoint(EverySomeLoopEagerFrameState(frame_state_params, k, variant));
    MaybeInsertMapChecks(inference, has_stability_dependency);

    TNode<Object> element;
    std::tie(k, element) = SafeLoadElement(kind, receiver, k);

    auto continue_label = MakeLabel();
    element = MaybeSkipHole(element, kind, &continue_label);

    TNode<Object> v =
        JSCall3(fncallback, this_arg, element, k, receiver,
                EverySomeLoopLazyFrameState(frame_state_params, k, variant));

    if (variant == ArrayEverySomeVariant::kEvery) {
      GotoIfNot(ToBoolean(v), &out, FalseConstant());
    } else {
      DCHECK_EQ(variant, ArrayEverySomeVariant::kSome);
      GotoIf(ToBoolean(v), &out, TrueConstant());
    }
    Goto(&continue_label);
    Bind(&continue_label);
  });

  Goto(&out, (variant == ArrayEverySomeVariant::kEvery) ? TrueConstant()
                                                        : FalseConstant());

  Bind(&out);
  return out.PhiAt<Boolean>(0);
}

namespace {

Callable GetCallableForArrayIndexOfIncludes(ArrayIndexOfIncludesVariant variant,
                                            ElementsKind elements_kind,
                                            Isolate* isolate) {
  if (variant == ArrayIndexOfIncludesVariant::kIndexOf) {
    switch (elements_kind) {
      case PACKED_SMI_ELEMENTS:
      case HOLEY_SMI_ELEMENTS:
        return Builtins::CallableFor(isolate, Builtin::kArrayIndexOfSmi);
      case PACKED_ELEMENTS:
      case HOLEY_ELEMENTS:
        return Builtins::CallableFor(isolate,
                                     Builtin::kArrayIndexOfSmiOrObject);
      case PACKED_DOUBLE_ELEMENTS:
        return Builtins::CallableFor(isolate,
                                     Builtin::kArrayIndexOfPackedDoubles);
      default:
        DCHECK_EQ(HOLEY_DOUBLE_ELEMENTS, elements_kind);
        return Builtins::CallableFor(isolate,
                                     Builtin::kArrayIndexOfHoleyDoubles);
    }
  } else {
    DCHECK_EQ(variant, ArrayIndexOfIncludesVariant::kIncludes);
    switch (elements_kind) {
      case PACKED_SMI_ELEMENTS:
      case HOLEY_SMI_ELEMENTS:
        return Builtins::CallableFor(isolate, Builtin::kArrayIncludesSmi);
      case PACKED_ELEMENTS:
      case HOLEY_ELEMENTS:
        return Builtins::CallableFor(isolate,
                                     Builtin::kArrayIncludesSmiOrObject);
      case PACKED_DOUBLE_ELEMENTS:
        return Builtins::CallableFor(isolate,
                                     Builtin::kArrayIncludesPackedDoubles);
      default:
        DCHECK_EQ(HOLEY_DOUBLE_ELEMENTS, elements_kind);
        return Builtins::CallableFor(isolate,
                                     Builtin::kArrayIncludesHoleyDoubles);
    }
  }
  UNREACHABLE();
}

}  // namespace
TNode<Object>
IteratingArrayBuiltinReducerAssembler::ReduceArrayPrototypeIndexOfIncludes(
    ElementsKind kind, ArrayIndexOfIncludesVariant variant) {
  TNode<Context> context = ContextInput();
  TNode<JSArray> receiver = ReceiverInputAs<JSArray>();
  TNode<Object> search_element = ArgumentOrUndefined(0);
  TNode<Object> from_index = ArgumentOrZero(1);

  // TODO(jgruber): This currently only reduces to a stub call. Create a full
  // reduction (similar to other higher-order array builtins) instead of
  // lowering to a builtin call. E.g. Array.p.every and Array.p.some have almost
  // identical functionality.

  TNode<Number> length = LoadJSArrayLength(receiver, kind);
  TNode<FixedArrayBase> elements = LoadElements(receiver);

  const bool have_from_index = ArgumentCount() > 1;
  if (have_from_index) {
    TNode<Smi> from_index_smi = CheckSmi(from_index);

    // If the index is negative, it means the offset from the end and
    // therefore needs to be added to the length. If the result is still
    // negative, it needs to be clamped to 0.
    TNode<Boolean> cond = NumberLessThan(from_index_smi, ZeroConstant());
    from_index = SelectIf<Number>(cond)
                     .Then(_ {
                       return NumberMax(NumberAdd(length, from_index_smi),
                                        ZeroConstant());
                     })
                     .Else(_ { return from_index_smi; })
                     .ExpectFalse()
                     .Value();
  }

  return Call4(GetCallableForArrayIndexOfIncludes(variant, kind, isolate()),
               context, elements, search_element, length, from_index);
}
namespace {

struct PromiseCtorFrameStateParams {
  JSGraph* jsgraph;
  SharedFunctionInfoRef shared;
  Node* node_ptr;
  TNode<Context> context;
  TNode<Object> target;
  FrameState outer_frame_state;
};

// Remnant of old-style JSCallReducer code. Could be ported to graph assembler,
// but probably not worth the effort.
FrameState CreateConstructInvokeStubFrameState(
    Node* node, Node* outer_frame_state, SharedFunctionInfoRef shared,
    Node* context, CommonOperatorBuilder* common, Graph* graph) {
  const FrameStateFunctionInfo* state_info =
      common->CreateFrameStateFunctionInfo(FrameStateType::kConstructInvokeStub,
                                           1, 0, 0, shared.object(), {});

  const Operator* op = common->FrameState(
      BytecodeOffset::None(), OutputFrameStateCombine::Ignore(), state_info);
  const Operator* op0 = common->StateValues(0, SparseInputMask::Dense());
  Node* node0 = graph->NewNode(op0);

  static constexpr int kTargetInputIndex = 0;
  static constexpr int kReceiverInputIndex = 1;
  std::vector<Node*> params;
  params.push_back(node->InputAt(kReceiverInputIndex));
  const Operator* op_param = common->StateValues(
      static_cast<int>(params.size()), SparseInputMask::Dense());
  Node* params_node = graph->NewNode(op_param, static_cast<int>(params.size()),
                                     &params.front());
  DCHECK(context);
  return FrameState(graph->NewNode(op, params_node, node0, node0, context,
                                   node->InputAt(kTargetInputIndex),
                                   outer_frame_state));
}

FrameState PromiseConstructorFrameState(
    const PromiseCtorFrameStateParams& params, CommonOperatorBuilder* common,
    Graph* graph) {
  DCHECK_EQ(1,
            params.shared.internal_formal_parameter_count_without_receiver());
  return CreateConstructInvokeStubFrameState(
      params.node_ptr, params.outer_frame_state, params.shared, params.context,
      common, graph);
}

FrameState PromiseConstructorLazyFrameState(
    const PromiseCtorFrameStateParams& params,
    FrameState constructor_frame_state) {
  // The deopt continuation of this frame state is never called; the frame state
  // is only necessary to obtain the right stack trace.
  JSGraph* jsgraph = params.jsgraph;
  Node* checkpoint_params[] = {
      jsgraph->UndefinedConstant(), /* receiver */
      jsgraph->UndefinedConstant(), /* promise */
      jsgraph->UndefinedConstant(), /* reject function */
      jsgraph->TheHoleConstant()    /* exception */
  };
  return CreateJavaScriptBuiltinContinuationFrameState(
      jsgraph, params.shared, Builtin::kPromiseConstructorLazyDeoptContinuation,
      params.target, params.context, checkpoint_params,
      arraysize(checkpoint_params), constructor_frame_state,
      ContinuationFrameStateMode::LAZY);
}

FrameState PromiseConstructorLazyWithCatchFrameState(
    const PromiseCtorFrameStateParams& params,
    FrameState constructor_frame_state, TNode<JSPromise> promise,
    TNode<JSFunction> reject) {
  // This continuation just returns the created promise and takes care of
  // exceptions thrown by the executor.
  Node* checkpoint_params[] = {
      params.jsgraph->UndefinedConstant(), /* receiver */
      promise, reject};
  return CreateJavaScriptBuiltinContinuationFrameState(
      params.jsgraph, params.shared,
      Builtin::kPromiseConstructorLazyDeoptContinuation, params.target,
      params.context, checkpoint_params, arraysize(checkpoint_params),
      constructor_frame_state, ContinuationFrameStateMode::LAZY_WITH_CATCH);
}

}  // namespace

TNode<Object> PromiseBuiltinReducerAssembler::ReducePromiseConstructor(
    NativeContextRef native_context) {
  DCHECK_GE(ConstructArity(), 1);

  JSConstructNode n(node_ptr());
  FrameState outer_frame_state = FrameStateInput();
  TNode<Context> context = ContextInput();
  TNode<Object> target = TargetInput();
  TNode<Object> executor = n.Argument(0);
  DCHECK_EQ(target, NewTargetInput());

  SharedFunctionInfoRef promise_shared =
      native_context.promise_function(broker()).shared(broker());

  PromiseCtorFrameStateParams frame_state_params{jsgraph(),  promise_shared,
                                                 node_ptr(), context,
                                                 target,     outer_frame_state};

  // Insert a construct stub frame into the chain of frame states. This will
  // reconstruct the proper frame when deoptimizing within the constructor.
  // For the frame state, we only provide the executor parameter, even if more
  // arguments were passed. This is not observable from JS.
  FrameState constructor_frame_state =
      PromiseConstructorFrameState(frame_state_params, common(), graph());

  ThrowIfNotCallable(executor,
                     PromiseConstructorLazyFrameState(frame_state_params,
                                                      constructor_frame_state));

  TNode<JSPromise> promise = CreatePromise(context);

  // 8. CreatePromiseResolvingFunctions
  // Allocate a promise context for the closures below.
  TNode<Context> promise_context = CreateFunctionContext(
      native_context, context, PromiseBuiltins::kPromiseContextLength);
  StoreContextSlot(promise_context, PromiseBuiltins::kPromiseSlot, promise);
  StoreContextSlot(promise_context, PromiseBuiltins::kAlreadyResolvedSlot,
                   FalseConstant());
  StoreContextSlot(promise_context, PromiseBuiltins::kDebugEventSlot,
                   TrueConstant());

  // Allocate closures for the resolve and reject cases.
  SharedFunctionInfoRef resolve_sfi =
      MakeRef(broker(), broker()
                            ->isolate()
                            ->factory()
                            ->promise_capability_default_resolve_shared_fun());
  TNode<JSFunction> resolve =
      CreateClosureFromBuiltinSharedFunctionInfo(resolve_sfi, promise_context);

  SharedFunctionInfoRef reject_sfi =
      MakeRef(broker(), broker()
                            ->isolate()
                            ->factory()
                            ->promise_capability_default_reject_shared_fun());
  TNode<JSFunction> reject =
      CreateClosureFromBuiltinSharedFunctionInfo(reject_sfi, promise_context);

  FrameState lazy_with_catch_frame_state =
      PromiseConstructorLazyWithCatchFrameState(
          frame_state_params, constructor_frame_state, promise, reject);

  // 9. Call executor with both resolving functions.
  // 10a. Call reject if the call to executor threw.
  Try(_ {
    CallPromiseExecutor(executor, resolve, reject, lazy_with_catch_frame_state);
  }).Catch([&](TNode<Object> exception) {
    // Clear pending message since the exception is not going to be rethrown.
    ClearPendingMessage();
    CallPromiseReject(reject, exception, lazy_with_catch_frame_state);
  });

  return promise;
}

#undef _

std::pair<Node*, Node*> JSCallReducer::ReleaseEffectAndControlFromAssembler(
    JSCallReducerAssembler* gasm) {
  auto catch_scope = gasm->catch_scope();
  DCHECK(catch_scope->is_outermost());

  if (catch_scope->has_handler() &&
      catch_scope->has_exceptional_control_flow()) {
    TNode<Object> handler_exception;
    Effect handler_effect{nullptr};
    Control handler_control{nullptr};
    gasm->catch_scope()->MergeExceptionalPaths(
        &handler_exception, &handler_effect, &handler_control);

    ReplaceWithValue(gasm->outermost_handler(), handler_exception,
                     handler_effect, handler_control);
  }

  return {gasm->effect(), gasm->control()};
}

Reduction JSCallReducer::ReplaceWithSubgraph(JSCallReducerAssembler* gasm,
                                             Node* subgraph) {
  // TODO(jgruber): Consider a less fiddly way of integrating the new subgraph
  // into the outer graph. For instance, the subgraph could be created in
  // complete isolation, and then plugged into the outer graph in one go.
  // Instead of manually tracking IfException nodes, we could iterate the
  // subgraph.

  // Replace the Call node with the newly-produced subgraph.
  ReplaceWithValue(gasm->node_ptr(), subgraph, gasm->effect(), gasm->control());

  // Wire exception edges contained in the newly-produced subgraph into the
  // outer graph.
  auto catch_scope = gasm->catch_scope();
  DCHECK(catch_scope->is_outermost());

  if (catch_scope->has_handler() &&
      catch_scope->has_exceptional_control_flow()) {
    TNode<Object> handler_exception;
    Effect handler_effect{nullptr};
    Control handler_control{nullptr};
    gasm->catch_scope()->MergeExceptionalPaths(
        &handler_exception, &handler_effect, &handler_control);

    ReplaceWithValue(gasm->outermost_handler(), handler_exception,
                     handler_effect, handler_control);
  }

  return Replace(subgraph);
}

Reduction JSCallReducer::ReduceMathUnary(Node* node, const Operator* op) {
  JSCallNode n(node);
  CallParameters const& p = n.Parameters();
  if (p.speculation_mode() == SpeculationMode::kDisallowSpeculation) {
    return NoChange();
  }
  if (n.ArgumentCount() < 1) {
    Node* value = jsgraph()->NaNConstant();
    ReplaceWithValue(node, value);
    return Replace(value);
  }

  JSCallReducerAssembler a(this, node);
  Node* subgraph = a.ReduceMathUnary(op);
  return ReplaceWithSubgraph(&a, subgraph);
}

Reduction JSCallReducer::ReduceMathBinary(Node* node, const Operator* op) {
  JSCallNode n(node);
  CallParameters const& p = n.Parameters();
  if (p.speculation_mode() == SpeculationMode::kDisallowSpeculation) {
    return NoChange();
  }
  if (n.ArgumentCount() < 1) {
    Node* value = jsgraph()->NaNConstant();
    ReplaceWithValue(node, value);
    return Replace(value);
  }

  JSCallReducerAssembler a(this, node);
  Node* subgraph = a.ReduceMathBinary(op);
  return ReplaceWithSubgraph(&a, subgraph);
}

// ES6 section 20.2.2.19 Math.imul ( x, y )
Reduction JSCallReducer::ReduceMathImul(Node* node) {
  JSCallNode n(node);
  CallParameters const& p = n.Parameters();
  if (p.speculation_mode() == SpeculationMode::kDisallowSpeculation) {
    return NoChange();
  }
  if (n.ArgumentCount() < 1) {
    Node* value = jsgraph()->ZeroConstant();
    ReplaceWithValue(node, value);
    return Replace(value);
  }
  Node* left = n.Argument(0);
  Node* right = n.ArgumentOr(1, jsgraph()->ZeroConstant());
  Effect effect = n.effect();
  Control control = n.control();

  left = effect =
      graph()->NewNode(simplified()->SpeculativeToNumber(
                           NumberOperationHint::kNumberOrOddball, p.feedback()),
                       left, effect, control);
  right = effect =
      graph()->NewNode(simplified()->SpeculativeToNumber(
                           NumberOperationHint::kNumberOrOddball, p.feedback()),
                       right, effect, control);
  left = graph()->NewNode(simplified()->NumberToUint32(), left);
  right = graph()->NewNode(simplified()->NumberToUint32(), right);
  Node* value = graph()->NewNode(simplified()->NumberImul(), left, right);
  ReplaceWithValue(node, value, effect);
  return Replace(value);
}

// ES6 section 20.2.2.11 Math.clz32 ( x )
Reduction JSCallReducer::ReduceMathClz32(Node* node) {
  JSCallNode n(node);
  CallParameters const& p = n.Parameters();
  if (p.speculation_mode() == SpeculationMode::kDisallowSpeculation) {
    return NoChange();
  }
  if (n.ArgumentCount() < 1) {
    Node* value = jsgraph()->ConstantNoHole(32);
    ReplaceWithValue(node, value);
    return Replace(value);
  }
  Node* input = n.Argument(0);
  Effect effect = n.effect();
  Control control = n.control();

  input = effect =
      graph()->NewNode(simplified()->SpeculativeToNumber(
                           NumberOperationHint::kNumberOrOddball, p.feedback()),
                       input, effect, control);
  input = graph()->NewNode(simplified()->NumberToUint32(), input);
  Node* value = graph()->NewNode(simplified()->NumberClz32(), input);
  ReplaceWithValue(node, value, effect);
  return Replace(value);
}

// ES6 section 20.2.2.24 Math.max ( value1, value2, ...values )
// ES6 section 20.2.2.25 Math.min ( value1, value2, ...values )
Reduction JSCallReducer::ReduceMathMinMax(Node* node, const Operator* op,
                                          Node* empty_value) {
  JSCallNode n(node);
  CallParameters const& p = n.Parameters();
  if (p.speculation_mode() == SpeculationMode::kDisallowSpeculation) {
    return NoChange();
  }
  if (n.ArgumentCount() < 1) {
    ReplaceWithValue(node, empty_value);
    return Replace(empty_value);
  }
  Node* effect = NodeProperties::GetEffectInput(node);
  Node* control = NodeProperties::GetControlInput(node);

  Node* value = effect =
      graph()->NewNode(simplified()->SpeculativeToNumber(
                           NumberOperationHint::kNumberOrOddball, p.feedback()),
                       n.Argument(0), effect, control);
  for (int i = 1; i < n.ArgumentCount(); i++) {
    Node* input = effect = graph()->NewNode(
        simplified()->SpeculativeToNumber(NumberOperationHint::kNumberOrOddball,
                                          p.feedback()),
        n.Argument(i), effect, control);
    value = graph()->NewNode(op, value, input);
  }

  ReplaceWithValue(node, value, effect);
  return Replace(value);
}

Reduction JSCallReducer::Reduce(Node* node) {
  switch (node->opcode()) {
    case IrOpcode::kJSConstruct:
      return ReduceJSConstruct(node);
    case IrOpcode::kJSConstructWithArrayLike:
      return ReduceJSConstructWithArrayLike(node);
    case IrOpcode::kJSConstructWithSpread:
      return ReduceJSConstructWithSpread(node);
    case IrOpcode::kJSConstructForwardAllArgs:
      return ReduceJSConstructForwardAllArgs(node);
    case IrOpcode::kJSCall:
      return ReduceJSCall(node);
    case IrOpcode::kJSCallWithArrayLike:
      return ReduceJSCallWithArrayLike(node);
    case IrOpcode::kJSCallWithSpread:
      return ReduceJSCallWithSpread(node);
    default:
      break;
  }
  return NoChange();
}

void JSCallReducer::Finalize() {
  // TODO(turbofan): This is not the best solution; ideally we would be able
  // to teach the GraphReducer about arbitrary dependencies between different
  // nodes, even if they don't show up in the use list of the other node.
  std::set<Node*> const waitlist = std::move(waitlist_);
  for (Node* node : waitlist) {
    if (!node->IsDead()) {
      // Remember the max node id before reduction.
      NodeId const max_id = static_cast<NodeId>(graph()->NodeCount() - 1);
      Reduction const reduction = Reduce(node);
      if (reduction.Changed()) {
        Node* replacement = reduction.replacement();
        if (replacement != node) {
          Replace(node, replacement, max_id);
        }
      }
    }
  }
}

// ES6 section 22.1.1 The Array Constructor
Reduction JSCallReducer::ReduceArrayConstructor(Node* node) {
  JSCallNode n(node);
  Node* target = n.target();
  CallParameters const& p = n.Parameters();

  // Turn the {node} into a {JSCreateArray} call.
  size_t const arity = p.arity_without_implicit_args();
  node->RemoveInput(n.FeedbackVectorIndex());
  NodeProperties::ReplaceValueInput(node, target, 0);
  NodeProperties::ReplaceValueInput(node, target, 1);
  NodeProperties::ChangeOp(node,
                           javascript()->CreateArray(arity, std::nullopt));
  return Changed(node);
}

// ES6 section 19.3.1.1 Boolean ( value )
Reduction JSCallReducer::ReduceBooleanConstructor(Node* node) {
  // Replace the {node} with a proper {ToBoolean} operator.
  JSCallNode n(node);
  Node* value = n.ArgumentOrUndefined(0, jsgraph());
  value = graph()->NewNode(simplified()->ToBoolean(), value);
  ReplaceWithValue(node, value);
  return Replace(value);
}

// ES section #sec-object-constructor
Reduction JSCallReducer::ReduceObjectConstructor(Node* node) {
  JSCallNode n(node);
  if (n.ArgumentCount() < 1) return NoChange();
  Node* value = n.Argument(0);
  Effect effect = n.effect();

  // We can fold away the Tagged<Object>(x) call if |x| is definitely not a
  // primitive.
  if (NodeProperties::CanBePrimitive(broker(), value, effect)) {
    if (!NodeProperties::CanBeNullOrUndefined(broker(), value, effect)) {
      // Turn the {node} into a {JSToObject} call if we know that
      // the {value} cannot be null or undefined.
      NodeProperties::ReplaceValueInputs(node, value);
      NodeProperties::ChangeOp(node, javascript()->ToObject());
      return Changed(node);
    }
  } else {
    ReplaceWithValue(node, value);
    return Replace(value);
  }
  return NoChange();
}

// ES6 section 19.2.3.1 Function.prototype.apply ( thisArg, argArray )
Reduction JSCallReducer::ReduceFunctionPrototypeApply(Node* node) {
  JSCallNode n(node);
  CallParameters const& p = n.Parameters();
  CallFeedbackRelation new_feedback_relation =
      p.feedback_relation() == CallFeedbackRelation::kReceiver
          ? CallFeedbackRelation::kTarget
          : CallFeedbackRelation::kUnrelated;
  int arity = p.arity_without_implicit_args();

  if (arity < 2) {
    // Degenerate cases.
    ConvertReceiverMode convert_mode;
    if (arity == 0) {
      // Neither thisArg nor argArray was provided.
      convert_mode = ConvertReceiverMode::kNullOrUndefined;
      node->ReplaceInput(n.TargetIndex(), n.receiver());
      node->ReplaceInput(n.ReceiverIndex(), jsgraph()->UndefinedConstant());
    } else {
      DCHECK_EQ(arity, 1);
      // The argArray was not provided, just remove the {target}.
      convert_mode = ConvertReceiverMode::kAny;
      node->RemoveInput(n.TargetIndex());
      --arity;
    }
    // Change {node} to a {JSCall} and try to reduce further.
    NodeProperties::ChangeOp(
        node, javascript()->Call(JSCallNode::ArityForArgc(arity), p.frequency(),
                                 p.feedback(), convert_mode,
                                 p.speculation_mode(), new_feedback_relation));
    return Changed(node).FollowedBy(ReduceJSCall(node));
  }

  // Turn the JSCall into a JSCallWithArrayLike.
  // If {argArray} can be null or undefined, we have to generate branches since
  // JSCallWithArrayLike would throw for null or undefined.

  Node* target = n.receiver();
  Node* this_argument = n.Argument(0);
  Node* arguments_list = n.Argument(1);
  Node* context = n.context();
  FrameState frame_state = n.frame_state();
  Effect effect = n.effect();
  Control control = n.control();

  // If {arguments_list} cannot be null or undefined, we don't need
  // to expand this {node} to control-flow.
  if (!NodeProperties::CanBeNullOrUndefined(broker(), arguments_list, effect)) {
    // Massage the value inputs appropriately.
    node->ReplaceInput(n.TargetIndex(), target);
    node->ReplaceInput(n.ReceiverIndex(), this_argument);
    node->ReplaceInput(n.ArgumentIndex(0), arguments_list);
    while (arity-- > 1) node->RemoveInput(n.ArgumentIndex(1));

    // Morph the {node} to a {JSCallWithArrayLike}.
    NodeProperties::ChangeOp(
        node, javascript()->CallWithArrayLike(p.frequency(), p.feedback(),
                                              p.speculation_mode(),
                                              new_feedback_relation));
    return Changed(node).FollowedBy(ReduceJSCallWithArrayLike(node));
  }

  // Check whether {arguments_list} is null.
  Node* check_null =
      graph()->NewNode(simplified()->ReferenceEqual(), arguments_list,
                       jsgraph()->NullConstant());
  control = graph()->NewNode(common()->Branch(BranchHint::kFalse), check_null,
                             control);
  Node* if_null = graph()->NewNode(common()->IfTrue(), control);
  control = graph()->NewNode(common()->IfFalse(), control);

  // Check whether {arguments_list} is undefined.
  Node* check_undefined =
      graph()->NewNode(simplified()->ReferenceEqual(), arguments_list,
                       jsgraph()->UndefinedConstant());
  control = graph()->NewNode(common()->Branch(BranchHint::kFalse),
                             check_undefined, control);
  Node* if_undefined = graph()->NewNode(common()->IfTrue(), control);
  control = graph()->NewNode(common()->IfFalse(), control);

  // Lower to {JSCallWithArrayLike} if {arguments_list} is neither null
  // nor undefined.
  Node* effect0 = effect;
  Node* control0 = control;
  Node* value0 = effect0 = control0 = graph()->NewNode(
      javascript()->CallWithArrayLike(p.frequency(), p.feedback(),
                                      p.speculation_mode(),
                                      new_feedback_relation),
      target, this_argument, arguments_list, n.feedback_vector(), context,
      frame_state, effect0, control0);

  // Lower to {JSCall} if {arguments_list} is either null or undefined.
  Node* effect1 = effect;
  Node* control1 = graph()->NewNode(common()->Merge(2), if_null, if_undefined);
  Node* value1 = effect1 = control1 = graph()->NewNode(
      javascript()->Call(JSCallNode::ArityForArgc(0)), target, this_argument,
      n.feedback_vector(), context, frame_state, effect1, control1);

  // Rewire potential exception edges.
  Node* if_exception = nullptr;
  if (NodeProperties::IsExceptionalCall(node, &if_exception)) {
    // Create appropriate {IfException} and {IfSuccess} nodes.
    Node* if_exception0 =
        graph()->NewNode(common()->IfException(), control0, effect0);
    control0 = graph()->NewNode(common()->IfSuccess(), control0);
    Node* if_exception1 =
        graph()->NewNode(common()->IfException(), control1, effect1);
    control1 = graph()->NewNode(common()->IfSuccess(), control1);

    // Join the exception edges.
    Node* merge =
        graph()->NewNode(common()->Merge(2), if_exception0, if_exception1);
    Node* ephi = graph()->NewNode(common()->EffectPhi(2), if_exception0,
                                  if_exception1, merge);
    Node* phi =
        graph()->NewNode(common()->Phi(MachineRepresentation::kTagged, 2),
                         if_exception0, if_exception1, merge);
    ReplaceWithValue(if_exception, phi, ephi, merge);
  }

  // Join control paths.
  control = graph()->NewNode(common()->Merge(2), control0, control1);
  effect = graph()->NewNode(common()->EffectPhi(2), effect0, effect1, control);
  Node* value =
      graph()->NewNode(common()->Phi(MachineRepresentation::kTagged, 2), value0,
                       value1, control);
  ReplaceWithValue(node, value, effect, control);
  return Replace(value);
}

// ES section #sec-function.prototype.bind
Reduction JSCallReducer::ReduceFunctionPrototypeBind(Node* node) {
  JSCallNode n(node);
  CallParameters const& p = n.Parameters();
  if (p.speculation_mode() == SpeculationMode::kDisallowSpeculation) {
    return NoChange();
  }

  // Value inputs to the {node} are as follows:
  //
  //  - target, which is Function.prototype.bind JSFunction
  //  - receiver, which is the [[BoundTargetFunction]]
  //  - bound_this (optional), which is the [[BoundThis]]
  //  - and all the remaining value inputs are [[BoundArguments]]
  Node* receiver = n.receiver();
  Node* context = n.context();
  Effect effect = n.effect();
  Control control = n.control();

  // Ensure that the {receiver} is known to be a JSBoundFunction or
  // a JSFunction with the same [[Prototype]], and all maps we've
  // seen for the {receiver} so far indicate that {receiver} is
  // definitely a constructor or not a constructor.
  MapInference inference(broker(), receiver, effect);
  if (!inference.HaveMaps()) return NoChange();
  ZoneRefSet<Map> const& receiver_maps = inference.GetMaps();

  MapRef first_receiver_map = receiver_maps[0];
  bool const is_constructor = first_receiver_map.is_constructor();

  HeapObjectRef prototype = first_receiver_map.prototype(broker());

  for (MapRef receiver_map : receiver_maps) {
    HeapObjectRef map_prototype = receiver_map.prototype(broker());

    // Check for consistency among the {receiver_maps}.
    if (!map_prototype.equals(prototype) ||
        receiver_map.is_constructor() != is_constructor ||
        !InstanceTypeChecker::IsJSFunctionOrBoundFunctionOrWrappedFunction(
            receiver_map.instance_type())) {
      return inference.NoChange();
    }

    // Disallow binding of slow-mode functions. We need to figure out
    // whether the length and name property are in the original state.
    if (receiver_map.is_dictionary_map()) return inference.NoChange();

    // Check whether the length and name properties are still present
    // as AccessorInfo objects. In that case, their values can be
    // recomputed even if the actual value of the object changes.
    // This mirrors the checks done in builtins-function-gen.cc at
    // runtime otherwise.
    int minimum_nof_descriptors =
        std::max(
            {JSFunctionOrBoundFunctionOrWrappedFunction::kLengthDescriptorIndex,
             JSFunctionOrBoundFunctionOrWrappedFunction::
                 kNameDescriptorIndex}) +
        1;
    if (receiver_map.NumberOfOwnDescriptors() < minimum_nof_descriptors) {
      return inference.NoChange();
    }
    const InternalIndex kLengthIndex(
        JSFunctionOrBoundFunctionOrWrappedFunction::kLengthDescriptorIndex);
    const InternalIndex kNameIndex(
        JSFunctionOrBoundFunctionOrWrappedFunction::kNameDescriptorIndex);
    StringRef length_string = broker()->length_string();
    StringRef name_string = broker()->name_string();

    OptionalObjectRef length_value(
        receiver_map.GetStrongValue(broker(), kLengthIndex));
    OptionalObjectRef name_value(
        receiver_map.GetStrongValue(broker(), kNameIndex));
    if (!length_value || !name_value) {
      TRACE_BROKER_MISSING(
          broker(), "name or length descriptors on map " << receiver_map);
      return inference.NoChange();
    }
    if (!receiver_map.GetPropertyKey(broker(), kLengthIndex)
             .equals(length_string) ||
        !length_value->IsAccessorInfo() ||
        !receiver_map.GetPropertyKey(broker(), kNameIndex)
             .equals(name_string) ||
        !name_value->IsAccessorInfo()) {
      return inference.NoChange();
    }
  }

  // Choose the map for the resulting JSBoundFunction (but bail out in case of a
  // custom prototype).
  MapRef map =
      is_constructor
          ? native_context().bound_function_with_constructor_map(broker())
          : native_context().bound_function_without_constructor_map(broker());
  if (!map.prototype(broker()).equals(prototype)) return inference.NoChange();

  inference.RelyOnMapsPreferStability(dependencies(), jsgraph(), &effect,
                                      control, p.feedback());

  // Replace the {node} with a JSCreateBoundFunction.
  static constexpr int kBoundThis = 1;
  static constexpr int kReceiverContextEffectAndControl = 4;
  int const arity = n.ArgumentCount();

  if (arity > 0) {
    MapRef fixed_array_map = broker()->fixed_array_map();
    AllocationBuilder ab(jsgraph(), broker(), effect, control);
    if (!ab.CanAllocateArray(arity, fixed_array_map)) {
      return NoChange();
    }
  }

  int const arity_with_bound_this = std::max(arity, kBoundThis);
  int const input_count =
      arity_with_bound_this + kReceiverContextEffectAndControl;
  Node** inputs = graph()->zone()->AllocateArray<Node*>(input_count);
  int cursor = 0;
  inputs[cursor++] = receiver;
  inputs[cursor++] = n.ArgumentOrUndefined(0, jsgraph());  // bound_this.
  for (int i = 1; i < arity; ++i) {
    inputs[cursor++] = n.Argument(i);
  }
  inputs[cursor++] = context;
  inputs[cursor++] = effect;
  inputs[cursor++] = control;
  DCHECK_EQ(cursor, input_count);
  Node* value = effect =
      graph()->NewNode(javascript()->CreateBoundFunction(
                           arity_with_bound_this - kBoundThis, map),
                       input_count, inputs);
  ReplaceWithValue(node, value, effect, control);
  return Replace(value);
}

// ES6 section 19.2.3.3 Function.prototype.call (thisArg, ...args)
Reduction JSCallReducer::ReduceFunctionPrototypeCall(Node* node) {
  JSCallNode n(node);
  CallParameters const& p = n.Parameters();
  Node* target = n.target();
  Effect effect = n.effect();
  Control control = n.control();

  // Change context of {node} to the Function.prototype.call context,
  // to ensure any exception is thrown in the correct context.
  Node* context;
  HeapObjectMatcher m(target);
  if (m.HasResolvedValue() && m.Ref(broker()).IsJSFunction()) {
    JSFunctionRef function = m.Ref(broker()).AsJSFunction();
    context = jsgraph()->ConstantNoHole(function.context(broker()), broker());
  } else {
    context = effect = graph()->NewNode(
        simplified()->LoadField(AccessBuilder::ForJSFunctionContext()), target,
        effect, control);
  }
  NodeProperties::ReplaceContextInput(node, context);
  NodeProperties::ReplaceEffectInput(node, effect);

  // Remove the target from {node} and use the receiver as target instead, and
  // the thisArg becomes the new target.  If thisArg was not provided, insert
  // undefined instead.
  int arity = p.arity_without_implicit_args();
  ConvertReceiverMode convert_mode;
  if (arity == 0) {
    // The thisArg was not provided, use undefined as receiver.
    convert_mode = ConvertReceiverMode::kNullOrUndefined;
    node->ReplaceInput(n.TargetIndex(), n.receiver());
    node->ReplaceInput(n.ReceiverIndex(), jsgraph()->UndefinedConstant());
  } else {
    // Just remove the target, which is the first value input.
    convert_mode = ConvertReceiverMode::kAny;
    node->RemoveInput(n.TargetIndex());
    --arity;
  }
  NodeProperties::ChangeOp(
      node, javascript()->Call(JSCallNode::ArityForArgc(arity), p.frequency(),
                               p.feedback(), convert_mode, p.speculation_mode(),
                               CallFeedbackRelation::kUnrelated));
  // Try to further reduce the JSCall {node}.
  return Changed(node).FollowedBy(ReduceJSCall(node));
}

// ES6 section 19.2.3.6 Function.prototype [ @@hasInstance ] (V)
Reduction JSCallReducer::ReduceFunctionPrototypeHasInstance(Node* node) {
  JSCallNode n(node);
  Node* receiver = n.receiver();
  Node* object = n.ArgumentOrUndefined(0, jsgraph());
  Node* context = n.context();
  FrameState frame_state = n.frame_state();
  Effect effect = n.effect();
  Control control = n.control();

  // TODO(turbofan): If JSOrdinaryToInstance raises an exception, the
  // stack trace doesn't contain the @@hasInstance call; we have the
  // corresponding bug in the baseline case. Some massaging of the frame
  // state would be necessary here.

  // Morph this {node} into a JSOrdinaryHasInstance node.
  node->ReplaceInput(0, receiver);
  node->ReplaceInput(1, object);
  node->ReplaceInput(2, context);
  node->ReplaceInput(3, frame_state);
  node->ReplaceInput(4, effect);
  node->ReplaceInput(5, control);
  node->TrimInputCount(6);
  NodeProperties::ChangeOp(node, javascript()->OrdinaryHasInstance());
  return Changed(node);
}

Reduction JSCallReducer::ReduceObjectGetPrototype(Node* node, Node* object) {
  Effect effect{NodeProperties::GetEffectInput(node)};

  // Try to determine the {object} map.
  MapInference inference(broker(), object, effect);
  if (!inference.HaveMaps()) return NoChange();
  ZoneRefSet<Map> const& object_maps = inference.GetMaps();

  MapRef candidate_map = object_maps[0];
  HeapObjectRef candidate_prototype = candidate_map.prototype(broker());

  // Check if we can constant-fold the {candidate_prototype}.
  for (size_t i = 0; i < object_maps.size(); ++i) {
    MapRef object_map = object_maps[i];
    HeapObjectRef map_prototype = object_map.prototype(broker());
    if (IsSpecialReceiverInstanceType(object_map.instance_type()) ||
        !map_prototype.equals(candidate_prototype)) {
      // We exclude special receivers, like JSProxy or API objects that
      // might require access checks here; we also don't want to deal
      // with hidden prototypes at this point.
      return inference.NoChange();
    }
    // The above check also excludes maps for primitive values, which is
    // important because we are not applying [[ToObject]] here as expected.
    DCHECK(!object_map.IsPrimitiveMap() && object_map.IsJSReceiverMap());
  }
  if (!inference.RelyOnMapsViaStability(dependencies())) {
    return inference.NoChange();
  }
  Node* value = jsgraph()->ConstantNoHole(candidate_prototype, broker());
  ReplaceWithValue(node, value);
  return Replace(value);
}

// ES6 section 19.1.2.11 Object.getPrototypeOf ( O )
Reduction JSCallReducer::ReduceObjectGetPrototypeOf(Node* node) {
  JSCallNode n(node);
  Node* object = n.ArgumentOrUndefined(0, jsgraph());
  return ReduceObjectGetPrototype(node, object);
}

// ES section #sec-object.is
Reduction JSCallReducer::ReduceObjectIs(Node* node) {
  JSCallNode n(node);
  Node* lhs = n.ArgumentOrUndefined(0, jsgraph());
  Node* rhs = n.ArgumentOrUndefined(1, jsgraph());
  Node* value = graph()->NewNode(simplified()->SameValue(), lhs, rhs);
  ReplaceWithValue(node, value);
  return Replace(value);
}

// ES6 section B.2.2.1.1 get Object.prototype.__proto__
Reduction JSCallReducer::ReduceObjectPrototypeGetProto(Node* node) {
  JSCallNode n(node);
  return ReduceObjectGetPrototype(node, n.receiver());
}

// ES #sec-object.prototype.hasownproperty
Reduction JSCallReducer::ReduceObjectPrototypeHasOwnProperty(Node* node) {
  JSCallNode call_node(node);
  Node* receiver = call_node.receiver();
  Node* name = call_node.ArgumentOrUndefined(0, jsgraph());
  Effect effect = call_node.effect();
  Control control = call_node.control();

  // We can optimize a call to Object.prototype.hasOwnProperty if it's being
  // used inside a fast-mode for..in, so for code like this:
  //
  //   for (name in receiver) {
  //     if (receiver.hasOwnProperty(name)) {
  //        ...
  //     }
  //   }
  //
  // If the for..in is in fast-mode, we know that the {receiver} has {name}
  // as own property, otherwise the enumeration wouldn't include it. The graph
  // constructed by the BytecodeGraphBuilder in this case looks like this:

  // receiver
  //  ^    ^
  //  |    |
  //  |    +-+
  //  |      |
  //  |   JSToObject
  //  |      ^
  //  |      |
  //  |   JSForInNext
  //  |      ^
  //  +----+ |
  //       | |
  //  JSCall[hasOwnProperty]

  // We can constant-fold the {node} to True in this case, and insert
  // a (potentially redundant) map check to guard the fact that the
  // {receiver} map didn't change since the dominating JSForInNext. This
  // map check is only necessary when TurboFan cannot prove that there
  // is no observable side effect between the {JSForInNext} and the
  // {JSCall} to Object.prototype.hasOwnProperty.
  //
  // Also note that it's safe to look through the {JSToObject}, since the
  // Object.prototype.hasOwnProperty does an implicit ToObject anyway, and
  // these operations are not observable.
  if (name->opcode() == IrOpcode::kJSForInNext) {
    JSForInNextNode n(name);
    if (n.Parameters().mode() != ForInMode::kGeneric) {
      Node* object = n.receiver();
      Node* cache_type = n.cache_type();
      if (object->opcode() == IrOpcode::kJSToObject) {
        object = NodeProperties::GetValueInput(object, 0);
      }
      if (object == receiver) {
        // No need to repeat the map check if we can prove that there's no
        // observable side effect between {effect} and {name].
        if (!NodeProperties::NoObservableSideEffectBetween(effect, name)) {
          Node* receiver_map = effect =
              graph()->NewNode(simplified()->LoadField(AccessBuilder::ForMap()),
                               receiver, effect, control);
          Node* check = graph()->NewNode(simplified()->ReferenceEqual(),
                                         receiver_map, cache_type);
          effect = graph()->NewNode(
              simplified()->CheckIf(DeoptimizeReason::kWrongMap), check, effect,
              control);
        }
        Node* value = jsgraph()->TrueConstant();
        ReplaceWithValue(node, value, effect, control);
        return Replace(value);
      }

      // We can also optimize for this case below:

      // receiver(is a heap constant with fast map)
      //  ^
      //  |    object(all keys are enumerable)
      //  |      ^
      //  |      |
      //  |   JSForInNext
      //  |      ^
      //  +----+ |
      //       | |
      //  JSCall[hasOwnProperty]

      // We can replace the {JSCall} with several internalized string
      // comparisons.

      if (receiver->opcode() == IrOpcode::kHeapConstant) {
        MapInference inference(broker(), receiver, effect);
        if (!inference.HaveMaps()) {
          return inference.NoChange();
        }
        const ZoneRefSet<Map>& receiver_maps = inference.GetMaps();
        if (receiver_maps.size() == 1) {
          const MapRef receiver_map = *receiver_maps.begin();
          InstanceType instance_type = receiver_map.instance_type();
          int const nof = receiver_map.NumberOfOwnDescriptors();
          // We set a heuristic value to limit the compare instructions number.
          if (nof > 4 || instance_type <= LAST_SPECIAL_RECEIVER_TYPE ||
              receiver_map.is_dictionary_map()) {
            return inference.NoChange();
          }
          // Replace builtin call with several internalized string comparisons.
          CallParameters const& p = call_node.Parameters();
          inference.RelyOnMapsPreferStability(dependencies(), jsgraph(),
                                              &effect, control, p.feedback());
#define __ gasm.
          JSGraphAssembler gasm(broker(), jsgraph(), jsgraph()->zone(),
                                BranchSemantics::kJS);
          gasm.InitializeEffectControl(effect, control);
          auto done = __ MakeLabel(MachineRepresentation::kTagged);
          const DescriptorArrayRef descriptor_array =
              receiver_map.instance_descriptors(broker());
          for (InternalIndex key_index : InternalIndex::Range(nof)) {
            NameRef receiver_key =
                descriptor_array.GetPropertyKe
"""


```