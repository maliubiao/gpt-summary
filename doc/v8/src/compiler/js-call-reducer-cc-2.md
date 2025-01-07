Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/compiler/js-call-reducer.cc`.

Here's a breakdown of the thought process to arrive at the summary:

1. **Identify the file's purpose:** The file name `js-call-reducer.cc` suggests it's part of the V8 compiler and involved in reducing JavaScript calls. This means it's optimizing certain JavaScript built-in functions.

2. **Scan for keywords and patterns:** Look for recurring patterns, function names, and data structures that indicate specific functionalities. The code contains:
    * Functions starting with `ReduceArrayPrototype...`: This strongly suggests handling reductions of array prototype methods like `reduce`, `map`, `filter`, `find`, `every`, `some`, `indexOf`, `includes`.
    * `IteratingArrayBuiltinReducerAssembler`:  This class seems responsible for implementing the reduction logic for array built-ins.
    * `FrameState`: This is a V8 concept related to recording the state of execution, likely for deoptimization purposes. The numerous `...FrameState` functions are responsible for creating these states.
    * Loops (`ForZeroUntil`, `For1ZeroUntil`, `Forever`):  Indicates iteration over arrays.
    * `JSCall`, `ThrowIfNotCallable`, `ToBoolean`: These are common operations within JavaScript execution.
    * `SafeLoadElement`, `StoreFixedArrayBaseElement`, `MaybeSkipHole`:  Operations related to accessing and manipulating array elements, including handling sparse arrays (holes).
    * Specific array methods mentioned in function names: `Reduce`, `Map`, `Filter`, `Find`, `Every`, `Some`, `IndexOf`, `Includes`.
    * `PromiseBuiltinReducerAssembler::ReducePromiseConstructor`:  Indicates handling the `Promise` constructor.

3. **Group related functionalities:** The code clearly groups logic based on the array method being reduced. For example, there's a set of functions and logic for `ReduceArrayPrototypeReduce`, another for `ReduceArrayPrototypeMap`, and so on.

4. **Infer the purpose of FrameState functions:** The `...LazyFrameState` and `...EagerFrameState` naming convention suggests these functions create frame states for different deoptimization scenarios. "Lazy" might mean creating a frame state that's only needed if deoptimization happens, while "eager" creates it upfront. The checkpoint parameters within these functions indicate the values being captured for potential deoptimization.

5. **Connect to JavaScript:**  Recognize that the `ReduceArrayPrototype...` functions are optimizations of corresponding JavaScript array methods. Provide examples of how these methods are used in JavaScript.

6. **Identify potential errors:**  The code includes checks for non-callable functions (`ThrowIfNotCallable`) and handles potential deoptimizations (e.g., when no initial value is provided for `reduce`). This points to common JavaScript errors. The handling of holes in arrays is another area where developers might encounter unexpected behavior.

7. **Address specific instructions:**
    * **`.tq` extension:**  The code is in `.cc`, so this condition is false.
    * **JavaScript relation and examples:** Provide clear JavaScript examples for the discussed array methods.
    * **Code logic inference:**  For the `reduce` function, trace the conditional logic based on the `direction` and the presence of an initial value. Provide example inputs and expected outputs.
    * **Common programming errors:** Give examples related to using `reduce` without an initial value on an empty array or passing non-callable arguments to array methods.

8. **Structure the summary:** Organize the findings logically, starting with the overall purpose and then detailing the functionalities for each array method. Use clear headings and bullet points.

9. **Refine and clarify:** Ensure the language is clear and concise, avoiding overly technical jargon where possible. Explain the role of frame states and deoptimization in a way that's understandable without deep V8 knowledge.

By following these steps, one can effectively analyze the C++ code and generate a comprehensive summary of its functionality, relating it back to JavaScript concepts and potential developer errors.
这个文件 `v8/src/compiler/js-call-reducer.cc` 是 V8 引擎中编译器的一部分，它的主要功能是 **优化 JavaScript 内建函数的调用**。 具体来说，它通过识别特定的 JavaScript 调用模式（主要是数组和 Promise 的原型方法），并将其 **替换为更高效的内部实现**，从而提升代码的执行效率。这种替换过程就称为 "reduce" 或 "lowering"。

**主要功能归纳：**

该文件的第 3 部分主要负责 **实现以下 JavaScript 数组原型方法的优化（reduce）逻辑**：

* **`Array.prototype.reduce` 和 `Array.prototype.reduceRight`:**  这两个方法用于将数组中的元素通过回调函数聚合成单个值。代码处理了从左到右 (`reduce`) 和从右到左 (`reduceRight`) 两种遍历方向，以及是否提供初始值的情况。
* **`Array.prototype.map`:** 这个方法创建一个新数组，其结果是该数组中的每个元素都调用一个提供的函数后返回的结果。
* **`Array.prototype.filter`:** 这个方法创建一个新数组, 其包含通过所提供函数实现的测试的所有元素。
* **`Array.prototype.find` 和 `Array.prototype.findIndex`:** 这两个方法分别返回数组中满足提供的测试函数的第一个元素的值和索引。
* **`Array.prototype.every` 和 `Array.prototype.some`:**  这两个方法测试数组中的所有元素是否都通过了指定函数的测试，以及数组中是否至少有一个元素通过了指定函数的测试。
* **`Array.prototype.indexOf` 和 `Array.prototype.includes`:** 这两个方法分别返回数组中可以找到给定元素的第一个索引和判断数组是否包含一个指定的值。 代码中目前是将这两个方法简化为一个内置的调用，未来可能会进行更深度的优化。
* **`Promise` 构造函数 (`new Promise(...)`)**:  代码负责优化 `Promise` 构造函数的调用过程，包括创建 `Promise` 对象和处理传入的 `executor` 函数。

**关于源代码类型：**

`v8/src/compiler/js-call-reducer.cc` 的后缀是 `.cc`，这表明它是一个 **C++ 源代码文件**。如果后缀是 `.tq`，那才表示它是 V8 Torque 源代码。

**与 JavaScript 功能的关系及示例：**

该文件中的代码直接对应于优化 JavaScript 的数组和 Promise 的内置方法。以下是一些 JavaScript 示例，说明了这些方法的功能：

**1. `Array.prototype.reduce`:**

```javascript
const numbers = [1, 2, 3, 4];
const sum = numbers.reduce((accumulator, currentValue) => accumulator + currentValue, 0);
console.log(sum); // 输出 10
```

**代码逻辑推理（`Array.prototype.reduce`）：**

**假设输入：**

* `receiver`: `[1, 2, 3]` (一个数组)
* `fncallback`: `(acc, curr) => acc + curr` (求和的回调函数)
* `initialValue`: `10` (初始累加器值)
* `direction`: `ArrayReduceDirection::kLeft` (从左到右)

**输出：** `10 + 1 + 2 + 3 = 16`

**代码逻辑解释：**

* 如果提供了 `initialValue` (ArgumentCount() > 1)，则 `accumulator` 初始化为 `initialValue` (10)。
* 循环遍历数组，从索引 0 开始。
* 每次迭代，调用 `fncallback`，将当前的 `accumulator` 和数组元素 (`currentValue`) 作为参数传递。
* `fncallback` 的返回值成为新的 `accumulator`。
* 最终返回累加器的值。

**2. `Array.prototype.map`:**

```javascript
const numbers = [1, 2, 3];
const doubled = numbers.map(number => number * 2);
console.log(doubled); // 输出 [2, 4, 6]
```

**3. `Array.prototype.filter`:**

```javascript
const numbers = [1, 2, 3, 4, 5];
const evenNumbers = numbers.filter(number => number % 2 === 0);
console.log(evenNumbers); // 输出 [2, 4]
```

**4. `Array.prototype.find`:**

```javascript
const numbers = [10, 20, 30, 40];
const found = numbers.find(number => number > 25);
console.log(found); // 输出 30
```

**5. `Array.prototype.every`:**

```javascript
const ages = [32, 33, 16, 40];
const allAdults = ages.every(age => age >= 18);
console.log(allAdults); // 输出 false
```

**6. `Array.prototype.some`:**

```javascript
const ages = [3, 10, 18, 20];
const hasAdult = ages.some(age => age >= 18);
console.log(hasAdult); // 输出 true
```

**7. `Array.prototype.indexOf`:**

```javascript
const fruits = ['apple', 'banana', 'orange'];
const index = fruits.indexOf('banana');
console.log(index); // 输出 1
```

**8. `Array.prototype.includes`:**

```javascript
const fruits = ['apple', 'banana', 'orange'];
const includesBanana = fruits.includes('banana');
console.log(includesBanana); // 输出 true
```

**9. `Promise` 构造函数:**

```javascript
const myPromise = new Promise((resolve, reject) => {
  setTimeout(() => {
    resolve("成功！");
  }, 1000);
});

myPromise.then((message) => {
  console.log(message); // 输出 "成功！"（在 1 秒后）
});
```

**用户常见的编程错误及示例：**

* **`Array.prototype.reduce` 没有提供初始值且数组为空：**

```javascript
const emptyArray = [];
// 运行时会抛出 TypeError: Reduce of empty array with no initial value
// const sum = emptyArray.reduce((acc, curr) => acc + curr);
```

* **传递给数组高阶方法的回调函数不是函数：**

```javascript
const numbers = [1, 2, 3];
// 运行时会抛出 TypeError: undefined is not a function
// numbers.map(undefined);
```

* **在 `Array.prototype.filter` 等方法中误解回调函数的返回值：** 回调函数需要返回一个布尔值来指示是否保留当前元素。

```javascript
const numbers = [1, 2, 3, 4];
// 错误地返回一个数字，导致结果不符合预期
const filtered = numbers.filter(number => number * 2);
console.log(filtered); // 输出 [1, 2, 3, 4]，因为非零数字会被转换为 true
```

* **在 `Promise` 构造函数中忘记调用 `resolve` 或 `reject`：** 这会导致 Promise 永远处于 pending 状态。

```javascript
const myPromise = new Promise((resolve, reject) => {
  // 忘记调用 resolve 或 reject
  setTimeout(() => {
    console.log("执行了一些操作");
  }, 1000);
});

myPromise.then(() => {
  console.log("Promise 已解决"); // 不会被执行
});
```

总而言之，`v8/src/compiler/js-call-reducer.cc` 的这一部分是 V8 引擎为了提升 JavaScript 代码性能而进行的关键优化工作，它针对常见的数组和 Promise 操作进行高效的内部转换。 开发者了解这些优化有助于更好地理解 JavaScript 代码的执行原理。

Prompt: 
```
这是目录为v8/src/compiler/js-call-reducer.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/js-call-reducer.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共12部分，请归纳一下它的功能

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
  TNode<Context> promise_context = Cr
"""


```