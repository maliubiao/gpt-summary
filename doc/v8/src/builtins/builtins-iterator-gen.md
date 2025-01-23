Response: Let's break down the thought process for analyzing this C++ code and explaining its functionality in relation to JavaScript iterators.

1. **Understand the Goal:** The request asks for a summary of the C++ file's functionality and its connection to JavaScript iterators, including a JavaScript example. This means we need to identify the core purpose of the C++ code and relate it to corresponding JavaScript concepts.

2. **Identify Key Namespaces and Classes:** The code starts with namespaces `v8` and `internal`. This immediately tells us we're inside the V8 JavaScript engine's implementation. The class name `IteratorBuiltinsAssembler` is a strong indicator that this code deals with the implementation of iterator-related built-in functions in JavaScript.

3. **Scan for Core Function Names:** Look for function names that are suggestive of iterator operations. Names like `GetIteratorMethod`, `GetIterator`, `IteratorStep`, `IteratorComplete`, `IteratorValue`, `Iterate`, `IterableToList`, `IterableToFixedArray`, etc., jump out. These directly mirror the conceptual steps involved in working with JavaScript iterators.

4. **Analyze Individual Function Functionality (High-Level):**  For each key function, try to infer its purpose based on its name and parameters.
    * `GetIteratorMethod`:  Seems responsible for retrieving the `Symbol.iterator` method of an object.
    * `GetIterator`:  Likely calls the iterator method and performs checks to ensure the result is a valid iterator.
    * `IteratorStep`:  Probably calls the `next()` method of an iterator.
    * `IteratorComplete`:  Checks the `done` property of the iterator result.
    * `IteratorValue`:  Retrieves the `value` property of the iterator result.
    * `Iterate`:  Implements the core iteration loop.
    * `IterableToList`, `IterableToFixedArray`:  Convert iterables to arrays or fixed arrays.

5. **Look for Connections to JavaScript Concepts:**  As you analyze the functions, actively think about how they map to JavaScript iterator behavior.
    * `GetIteratorMethod` directly corresponds to how JavaScript resolves `obj[Symbol.iterator]`.
    * The checks in `GetIterator` relate to the JavaScript specification's requirements for what constitutes a valid iterator.
    * `IteratorStep` and `IteratorComplete` mirror the steps involved when JavaScript engines execute the `next()` method and check the `done` property.
    * `IteratorValue` corresponds to accessing the `value` property.
    * `Iterate` implements the `for...of` loop or the manual iteration pattern.

6. **Identify Helper Functions and Data Structures:** Notice things like `IteratorRecord`, `GrowableFixedArray`, and the use of `Label` and `TNode`. These are implementation details within V8. `IteratorRecord` clearly represents the state of an ongoing iteration. `GrowableFixedArray` is an optimization for building arrays. `Label` and `TNode` are part of V8's code generation infrastructure.

7. **Pay Attention to Error Handling:** Observe how the code handles cases where an object is not iterable or the iterator's `next()` method returns an invalid result. The calls to `Runtime::kThrowIteratorError`, `Runtime::kThrowSymbolIteratorInvalid`, and `Runtime::kThrowIteratorResultNotAnObject` are crucial for understanding how V8 enforces iterator semantics.

8. **Examine the `TF_BUILTIN` Macros:**  These macros indicate that the associated C++ functions are exposed as built-in JavaScript functions. This directly links the C++ implementation to JavaScript functionality. For example, `TF_BUILTIN(IterableToList, IteratorBuiltinsAssembler)` means there's a JavaScript built-in function (likely accessible internally) named `IterableToList` that is implemented by the corresponding C++ function.

9. **Consider Optimizations:**  Notice the "fast path" logic in functions like `IterableToListMayPreserveHoles` and `IterableToListConvertHoles`. This demonstrates how V8 optimizes common cases (like iterating over plain arrays) to improve performance.

10. **Formulate the Summary:** Based on the analysis, synthesize a concise description of the file's purpose. Emphasize its role in implementing core iterator operations within V8.

11. **Create a JavaScript Example:** Choose a simple JavaScript example that clearly demonstrates the iterator concepts implemented in the C++ code. The `for...of` loop is the most straightforward way to showcase iteration. Illustrate how the C++ code's functions correspond to the steps within the `for...of` loop.

12. **Refine and Organize:** Structure the explanation logically, starting with a general overview and then going into more detail about specific functions. Clearly separate the C++ functionality description from the JavaScript example.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe this file is just about creating iterator objects.
* **Correction:**  No, it's more about *using* iterators, performing the steps of iteration (getting the method, calling `next()`, checking `done`, getting `value`). The "BuiltinsAssembler" part suggests it's implementing the *behavior* of built-in iterator-related functions.
* **Initial thought:** Just list the C++ function names.
* **Refinement:** Explain *what* each function does conceptually in relation to JavaScript iterators. Connect the C++ names to JavaScript actions.
* **Initial thought:**  The JavaScript example should be complex to show all the nuances.
* **Refinement:**  Start with a simple `for...of` example to illustrate the basic concept. Then maybe briefly mention more advanced scenarios if needed. Simplicity is key for clarity.
* **Consider the audience:** The explanation should be understandable to someone with a good understanding of JavaScript iterators but perhaps less familiarity with V8 internals. Avoid overly technical V8-specific jargon unless necessary and explain it if you do use it.
这个C++源代码文件 `v8/src/builtins/builtins-iterator-gen.cc` 是 V8 JavaScript 引擎中用于实现 **迭代器 (Iterator)** 相关内置函数的代码。它定义了一些底层的操作，用于处理 JavaScript 中可迭代对象和迭代器的行为。

**主要功能归纳:**

1. **获取迭代器:**
   - 提供了 `GetIteratorMethod` 函数，用于获取给定对象的 `Symbol.iterator` 属性（方法）。
   - 提供了 `GetIterator` 函数，用于调用对象的迭代器方法，并对返回的迭代器对象进行校验，确保其是一个有效的对象并拥有 `next` 方法。

2. **迭代步骤:**
   - 实现了 `IteratorStep` 函数，模拟了调用迭代器 `next()` 方法的过程。它会调用迭代器的 `next` 属性（方法），并检查返回结果是否为对象。
   - 实现了 `IteratorComplete` 函数，用于检查迭代器返回结果的 `done` 属性，以判断迭代是否完成。它针对普通对象和特定优化过的迭代器结果（`fast_iterator_result_map`）提供了不同的处理方式。
   - 实现了 `IteratorValue` 函数，用于获取迭代器返回结果的 `value` 属性。

3. **迭代循环:**
   - 提供了 `Iterate` 函数，这是一个核心的迭代循环实现。它接收一个可迭代对象和一个回调函数，然后遍历可迭代对象的所有元素，并在每次迭代时调用回调函数处理当前元素的值。它还处理了迭代过程中的异常情况，并确保在异常发生时正确关闭迭代器。

4. **可迭代对象转换为其他数据结构:**
   - 实现了 `IterableToList` 函数，将可迭代对象转换为 JavaScript 数组 (JSArray)。
   - 实现了 `IterableToFixedArray` 函数，将可迭代对象转换为 V8 内部使用的固定数组 (FixedArray)。
   - 提供了 `FillFixedArrayFromIterable` 函数，作为 `IterableToFixedArray` 和 `IterableToList` 的底层实现，负责实际的迭代和数据填充过程。
   - 提供了 `StringListFromIterable` 函数，专门用于将可迭代对象转换为一个包含字符串的固定数组，并在迭代过程中检查元素类型是否为字符串。

5. **针对特定类型的优化:**
   - 提供了一些针对特定可迭代对象类型（例如快速数组、字符串、Map、Set）的优化路径，例如 `IterableToListMayPreserveHoles`、`IterableToListConvertHoles` 和 `FastIterableToList`。这些优化路径可以在某些情况下避免完全执行迭代器协议，从而提高性能。

6. **与其他 Built-ins 的集成:**
   - 通过 `TF_BUILTIN` 宏定义了一些可以被 JavaScript 直接调用的内置函数，例如 `IterableToList`、`IterableToFixedArray`、`StringListFromIterable` 等。
   - 涉及到一些用于优化的惰性反优化 (lazy deoptimization) 机制，例如 `GetIteratorWithFeedbackLazyDeoptContinuation` 和 `CallIteratorWithFeedbackLazyDeoptContinuation`。

**与 JavaScript 功能的关系及示例:**

这个 C++ 文件直接实现了 JavaScript 中与迭代器相关的核心功能。当你在 JavaScript 中使用 `for...of` 循环、展开运算符 (`...`)、或者调用 `Array.from()` 等方法处理可迭代对象时，V8 引擎底层就会调用这个文件中实现的 C++ 代码。

**JavaScript 示例:**

```javascript
// 使用 for...of 循环遍历数组（数组是可迭代对象）
const arr = [1, 2, 3];
for (const element of arr) {
  console.log(element);
}

// 使用展开运算符将 Set 转换为数组（Set 是可迭代对象）
const set = new Set([4, 5, 6]);
const arrayFromSet = [...set];
console.log(arrayFromSet); // 输出: [4, 5, 6]

// 使用 Array.from() 将字符串转换为数组（字符串是可迭代对象）
const str = "hello";
const arrayFromStr = Array.from(str);
console.log(arrayFromStr); // 输出: ["h", "e", "l", "l", "o"]

// 手动获取迭代器并遍历
const iterable = [7, 8, 9];
const iterator = iterable[Symbol.iterator](); // 获取迭代器
let result = iterator.next();
while (!result.done) {
  console.log(result.value);
  result = iterator.next();
}
```

**对应 C++ 代码的功能映射:**

- **`for...of` 循环:**  在 V8 引擎内部，当执行 `for (const element of arr)` 时，会调用 `GetIteratorMethod` 获取 `arr[Symbol.iterator]`，然后调用 `GetIterator` 获取迭代器对象。循环的每一次迭代会调用 `IteratorStep` 获取下一个结果，调用 `IteratorComplete` 检查是否完成，并调用 `IteratorValue` 获取当前元素的值。
- **展开运算符 (`...`) 和 `Array.from()`:** 当使用展开运算符或 `Array.from()` 处理可迭代对象时，V8 引擎可能会根据对象的类型选择不同的优化路径。对于普通数组，可能会使用 `IterableToListMayPreserveHoles` 或 `IterableToListConvertHoles` 的快速路径。对于其他可迭代对象，则会使用更通用的迭代器处理流程，最终调用 `IterableToList` 或 `IterableToFixedArray` 将其转换为数组。
- **手动获取迭代器:**  `iterable[Symbol.iterator]()` 的执行会对应 C++ 中的 `GetIteratorMethod`。调用迭代器的 `next()` 方法对应 C++ 中的 `IteratorStep`，检查 `done` 属性对应 `IteratorComplete`，获取 `value` 属性对应 `IteratorValue`。

**总结:**

`v8/src/builtins/builtins-iterator-gen.cc` 文件是 V8 引擎中实现 JavaScript 迭代器机制的关键组成部分。它定义了获取迭代器、执行迭代步骤、将可迭代对象转换为其他数据结构等核心操作的底层实现，直接支持了 JavaScript 中各种与迭代器相关的语法和 API。理解这个文件的功能有助于深入理解 JavaScript 迭代器的工作原理。

### 提示词
```
这是目录为v8/src/builtins/builtins-iterator-gen.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
```

### 源代码
```
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/builtins/builtins-iterator-gen.h"

#include <optional>

#include "src/builtins/builtins-collections-gen.h"
#include "src/builtins/builtins-string-gen.h"
#include "src/builtins/builtins-utils-gen.h"
#include "src/builtins/builtins.h"
#include "src/builtins/growable-fixed-array-gen.h"
#include "src/codegen/code-stub-assembler-inl.h"
#include "src/compiler/code-assembler.h"
#include "src/heap/factory-inl.h"

namespace v8 {
namespace internal {

#include "src/codegen/define-code-stub-assembler-macros.inc"

using IteratorRecord = TorqueStructIteratorRecord;

TNode<Object> IteratorBuiltinsAssembler::GetIteratorMethod(
    TNode<Context> context, TNode<Object> object) {
  return GetProperty(context, object, factory()->iterator_symbol());
}

IteratorRecord IteratorBuiltinsAssembler::GetIterator(TNode<Context> context,
                                                      TNode<Object> object) {
  TNode<Object> method = GetIteratorMethod(context, object);
  return GetIterator(context, object, method);
}

IteratorRecord IteratorBuiltinsAssembler::GetIterator(TNode<Context> context,
                                                      TNode<Object> object,
                                                      TNode<Object> method) {
  Label if_not_callable(this, Label::kDeferred), if_callable(this);
  GotoIf(TaggedIsSmi(method), &if_not_callable);
  Branch(IsCallable(CAST(method)), &if_callable, &if_not_callable);

  BIND(&if_not_callable);
  CallRuntime(Runtime::kThrowIteratorError, context, object);
  Unreachable();

  BIND(&if_callable);
  {
    TNode<Object> iterator = Call(context, method, object);

    Label get_next(this), if_notobject(this, Label::kDeferred);
    GotoIf(TaggedIsSmi(iterator), &if_notobject);
    Branch(JSAnyIsNotPrimitive(CAST(iterator)), &get_next, &if_notobject);

    BIND(&if_notobject);
    CallRuntime(Runtime::kThrowSymbolIteratorInvalid, context);
    Unreachable();

    BIND(&get_next);
    TNode<Object> next =
        GetProperty(context, iterator, factory()->next_string());
    return IteratorRecord{TNode<JSReceiver>::UncheckedCast(iterator), next};
  }
}

TNode<JSReceiver> IteratorBuiltinsAssembler::IteratorStep(
    TNode<Context> context, const IteratorRecord& iterator, Label* if_done,
    std::optional<TNode<Map>> fast_iterator_result_map) {
  DCHECK_NOT_NULL(if_done);
  // 1. a. Let result be ? Invoke(iterator, "next", « »).
  TNode<Object> result = Call(context, iterator.next, iterator.object);

  // 3. If Type(result) is not Object, throw a TypeError exception.
  Label if_notobject(this, Label::kDeferred), return_result(this);
  GotoIf(TaggedIsSmi(result), &if_notobject);
  TNode<HeapObject> heap_object_result = CAST(result);
  TNode<Map> result_map = LoadMap(heap_object_result);
  GotoIfNot(JSAnyIsNotPrimitiveMap(result_map), &if_notobject);

  // IteratorComplete
  // 2. Return ToBoolean(? Get(iterResult, "done")).
  IteratorComplete(context, heap_object_result, if_done,
                   fast_iterator_result_map);
  Goto(&return_result);

  BIND(&if_notobject);
  CallRuntime(Runtime::kThrowIteratorResultNotAnObject, context, result);
  Unreachable();

  BIND(&return_result);
  return CAST(heap_object_result);
}

void IteratorBuiltinsAssembler::IteratorComplete(
    TNode<Context> context, const TNode<HeapObject> iterator, Label* if_done,
    std::optional<TNode<Map>> fast_iterator_result_map) {
  DCHECK_NOT_NULL(if_done);

  Label return_result(this);

  TNode<Map> result_map = LoadMap(iterator);

  if (fast_iterator_result_map) {
    // Fast iterator result case:
    Label if_generic(this);

    // 4. Return result.
    GotoIfNot(TaggedEqual(result_map, *fast_iterator_result_map), &if_generic);

    // 2. Return ToBoolean(? Get(iterResult, "done")).
    TNode<Object> done =
        LoadObjectField(iterator, JSIteratorResult::kDoneOffset);
    BranchIfToBooleanIsTrue(done, if_done, &return_result);

    BIND(&if_generic);
  }

  // Generic iterator result case:
  {
    // 2. Return ToBoolean(? Get(iterResult, "done")).
    TNode<Object> done =
        GetProperty(context, iterator, factory()->done_string());
    BranchIfToBooleanIsTrue(done, if_done, &return_result);
  }

  BIND(&return_result);
}

TNode<Object> IteratorBuiltinsAssembler::IteratorValue(
    TNode<Context> context, TNode<JSReceiver> result,
    std::optional<TNode<Map>> fast_iterator_result_map) {
  Label exit(this);
  TVARIABLE(Object, var_value);
  if (fast_iterator_result_map) {
    // Fast iterator result case:
    Label if_generic(this);
    TNode<Map> map = LoadMap(result);
    GotoIfNot(TaggedEqual(map, *fast_iterator_result_map), &if_generic);
    var_value = LoadObjectField(result, JSIteratorResult::kValueOffset);
    Goto(&exit);

    BIND(&if_generic);
  }

  // Generic iterator result case:
  var_value = GetProperty(context, result, factory()->value_string());
  Goto(&exit);

  BIND(&exit);
  return var_value.value();
}

void IteratorBuiltinsAssembler::Iterate(
    TNode<Context> context, TNode<Object> iterable,
    std::function<void(TNode<Object>)> func,
    std::initializer_list<compiler::CodeAssemblerVariable*> merged_variables) {
  Iterate(context, iterable, GetIteratorMethod(context, iterable), func,
          merged_variables);
}

void IteratorBuiltinsAssembler::Iterate(
    TNode<Context> context, TNode<Object> iterable, TNode<Object> iterable_fn,
    std::function<void(TNode<Object>)> func,
    std::initializer_list<compiler::CodeAssemblerVariable*> merged_variables) {
  Label done(this);

  IteratorRecord iterator_record = GetIterator(context, iterable, iterable_fn);

  Label if_exception(this, Label::kDeferred);
  TVARIABLE(Object, var_exception);

  Label loop_start(this, merged_variables);
  Goto(&loop_start);

  BIND(&loop_start);
  {
    TNode<JSReceiver> next = IteratorStep(context, iterator_record, &done);
    TNode<Object> next_value = IteratorValue(context, next);

    {
      compiler::ScopedExceptionHandler handler(this, &if_exception,
                                               &var_exception);
      func(next_value);
    }

    Goto(&loop_start);
  }

  BIND(&if_exception);
  {
    TNode<HeapObject> message = GetPendingMessage();
    SetPendingMessage(TheHoleConstant());
    IteratorCloseOnException(context, iterator_record);
    CallRuntime(Runtime::kReThrowWithMessage, context, var_exception.value(),
                message);
    Unreachable();
  }

  BIND(&done);
}

TNode<JSArray> IteratorBuiltinsAssembler::IterableToList(
    TNode<Context> context, TNode<Object> iterable, TNode<Object> iterator_fn) {
  GrowableFixedArray values(state());
  FillFixedArrayFromIterable(context, iterable, iterator_fn, &values);
  return values.ToJSArray(context);
}

TNode<FixedArray> IteratorBuiltinsAssembler::IterableToFixedArray(
    TNode<Context> context, TNode<Object> iterable, TNode<Object> iterator_fn) {
  GrowableFixedArray values(state());
  FillFixedArrayFromIterable(context, iterable, iterator_fn, &values);
  TNode<FixedArray> new_array = values.ToFixedArray();
  return new_array;
}

void IteratorBuiltinsAssembler::FillFixedArrayFromIterable(
    TNode<Context> context, TNode<Object> iterable, TNode<Object> iterator_fn,
    GrowableFixedArray* values) {
  // 1. Let iteratorRecord be ? GetIterator(items, method) (handled by Iterate).

  // 2. Let values be a new empty List.

  // The GrowableFixedArray has already been created. It's ok if we do this step
  // out of order, since creating an empty List is not observable.

  // 3. Let next be true. (handled by Iterate)
  // 4. Repeat, while next is not false (handled by Iterate)
  Iterate(context, iterable, iterator_fn,
          [&values](TNode<Object> value) {
            // Handled by Iterate:
            //  a. Set next to ? IteratorStep(iteratorRecord).
            //  b. If next is not false, then
            //   i. Let nextValue be ? IteratorValue(next).

            //   ii. Append nextValue to the end of the List values.
            values->Push(value);
          },
          {values->var_array(), values->var_capacity(), values->var_length()});
}

TF_BUILTIN(IterableToList, IteratorBuiltinsAssembler) {
  auto context = Parameter<Context>(Descriptor::kContext);
  auto iterable = Parameter<Object>(Descriptor::kIterable);
  auto iterator_fn = Parameter<Object>(Descriptor::kIteratorFn);

  Return(IterableToList(context, iterable, iterator_fn));
}

TF_BUILTIN(IterableToFixedArray, IteratorBuiltinsAssembler) {
  auto context = Parameter<Context>(Descriptor::kContext);
  auto iterable = Parameter<Object>(Descriptor::kIterable);
  auto iterator_fn = Parameter<Object>(Descriptor::kIteratorFn);

  Return(IterableToFixedArray(context, iterable, iterator_fn));
}

#if V8_ENABLE_WEBASSEMBLY
TF_BUILTIN(IterableToFixedArrayForWasm, IteratorBuiltinsAssembler) {
  auto context = Parameter<Context>(Descriptor::kContext);
  auto iterable = Parameter<Object>(Descriptor::kIterable);
  auto expected_length = Parameter<Smi>(Descriptor::kExpectedLength);

  TNode<Object> iterator_fn = GetIteratorMethod(context, iterable);
  GrowableFixedArray values(state());

  Label done(this);

  FillFixedArrayFromIterable(context, iterable, iterator_fn, &values);

  GotoIf(WordEqual(PositiveSmiUntag(expected_length),
                   values.var_length()->value()),
         &done);
  Return(CallRuntime(
      Runtime::kThrowTypeError, context,
      SmiConstant(MessageTemplate::kWasmTrapMultiReturnLengthMismatch)));

  BIND(&done);
  Return(values.var_array()->value());
}
#endif  // V8_ENABLE_WEBASSEMBLY

TNode<FixedArray> IteratorBuiltinsAssembler::StringListFromIterable(
    TNode<Context> context, TNode<Object> iterable) {
  Label done(this);
  GrowableFixedArray list(state());
  // 1. If iterable is undefined, then
  //   a. Return a new empty List.
  GotoIf(IsUndefined(iterable), &done);

  // 2. Let iteratorRecord be ? GetIterator(items) (handled by Iterate).

  // 3. Let list be a new empty List.

  // 4. Let next be true (handled by Iterate).
  // 5. Repeat, while next is not false (handled by Iterate).
  Iterate(
      context, iterable,
      [&](TNode<Object> next_value) {
        // Handled by Iterate:
        //  a. Set next to ? IteratorStep(iteratorRecord).
        //  b. If next is not false, then
        //   i. Let nextValue be ? IteratorValue(next).

        //   ii. If Type(nextValue) is not String, then
        Label if_isnotstringtype(this, Label::kDeferred), loop_body_end(this);
        GotoIf(TaggedIsSmi(next_value), &if_isnotstringtype);
        TNode<Uint16T> next_value_type = LoadInstanceType(CAST(next_value));
        GotoIfNot(IsStringInstanceType(next_value_type), &if_isnotstringtype);

        //   iii. Append nextValue to the end of the List list.
        list.Push(next_value);

        Goto(&loop_body_end);

        // 5.b.ii
        BIND(&if_isnotstringtype);
        {
          // 1. Let error be ThrowCompletion(a newly created TypeError object).

          CallRuntime(Runtime::kThrowTypeError, context,
                      SmiConstant(MessageTemplate::kIterableYieldedNonString),
                      next_value);
          // 2. Return ? IteratorClose(iteratorRecord, error). (handled by
          // Iterate).
          Unreachable();
        }

        BIND(&loop_body_end);
      },
      {list.var_array(), list.var_length(), list.var_capacity()});
  Goto(&done);

  BIND(&done);
  // 6. Return list.
  return list.ToFixedArray();
}

TF_BUILTIN(StringListFromIterable, IteratorBuiltinsAssembler) {
  auto context = Parameter<Context>(Descriptor::kContext);
  auto iterable = Parameter<Object>(Descriptor::kIterable);

  Return(StringListFromIterable(context, iterable));
}

TF_BUILTIN(StringFixedArrayFromIterable, IteratorBuiltinsAssembler) {
  auto context = Parameter<Context>(Descriptor::kContext);
  auto iterable = Parameter<Object>(Descriptor::kIterable);

  Return(StringListFromIterable(context, iterable));
}

// This builtin always returns a new JSArray and is thus safe to use even in the
// presence of code that may call back into user-JS. This builtin will take the
// fast path if the iterable is a fast array and the Array prototype and the
// Symbol.iterator is untouched. The fast path skips the iterator and copies the
// backing store to the new array. Note that if the array has holes, the holes
// will be copied to the new array, which is inconsistent with the behavior of
// an actual iteration, where holes should be replaced with undefined (if the
// prototype has no elements). To maintain the correct behavior for holey
// arrays, use the builtins IterableToList or IterableToListWithSymbolLookup or
// IterableToListConvertHoles.
TF_BUILTIN(IterableToListMayPreserveHoles, IteratorBuiltinsAssembler) {
  auto context = Parameter<Context>(Descriptor::kContext);
  auto iterable = Parameter<Object>(Descriptor::kIterable);
  auto iterator_fn = Parameter<Object>(Descriptor::kIteratorFn);

  Label slow_path(this);

  GotoIfNot(IsFastJSArrayWithNoCustomIteration(context, iterable), &slow_path);

  // The fast path will copy holes to the new array.
  TailCallBuiltin(Builtin::kCloneFastJSArray, context, iterable);

  BIND(&slow_path);
  TailCallBuiltin(Builtin::kIterableToList, context, iterable, iterator_fn);
}

// This builtin always returns a new JSArray and is thus safe to use even in the
// presence of code that may call back into user-JS. This builtin will take the
// fast path if the iterable is a fast array and the Array prototype and the
// Symbol.iterator is untouched. The fast path skips the iterator and copies the
// backing store to the new array. Note that if the array has holes, the holes
// will be converted to undefined values in the new array (unlike
// IterableToListMayPreserveHoles builtin).
TF_BUILTIN(IterableToListConvertHoles, IteratorBuiltinsAssembler) {
  auto context = Parameter<Context>(Descriptor::kContext);
  auto iterable = Parameter<Object>(Descriptor::kIterable);
  auto iterator_fn = Parameter<Object>(Descriptor::kIteratorFn);

  Label slow_path(this);

  GotoIfNot(IsFastJSArrayWithNoCustomIteration(context, iterable), &slow_path);

  // The fast path will convert holes to undefined values in the new array.
  TailCallBuiltin(Builtin::kCloneFastJSArrayFillingHoles, context, iterable);

  BIND(&slow_path);
  TailCallBuiltin(Builtin::kIterableToList, context, iterable, iterator_fn);
}

void IteratorBuiltinsAssembler::FastIterableToList(
    TNode<Context> context, TNode<Object> iterable,
    TVariable<JSArray>* var_result, Label* slow) {
  Label done(this), check_string(this), check_map(this), check_set(this);

  // Always call the `next()` builtins when the debugger is
  // active, to ensure we capture side-effects correctly.
  GotoIf(IsDebugActive(), slow);

  GotoIfNot(
      Word32Or(IsFastJSArrayWithNoCustomIteration(context, iterable),
               IsFastJSArrayForReadWithNoCustomIteration(context, iterable)),
      &check_string);

  // Fast path for fast JSArray.
  *var_result = CAST(
      CallBuiltin(Builtin::kCloneFastJSArrayFillingHoles, context, iterable));
  Goto(&done);

  BIND(&check_string);
  {
    Label string_maybe_fast_call(this);
    StringBuiltinsAssembler string_assembler(state());
    string_assembler.BranchIfStringPrimitiveWithNoCustomIteration(
        iterable, context, &string_maybe_fast_call, &check_map);

    BIND(&string_maybe_fast_call);
    const TNode<Uint32T> length = LoadStringLengthAsWord32(CAST(iterable));
    // Use string length as conservative approximation of number of codepoints.
    GotoIf(
        Uint32GreaterThan(length, Uint32Constant(JSArray::kMaxFastArrayLength)),
        slow);
    *var_result = CAST(CallBuiltin(Builtin::kStringToList, context, iterable));
    Goto(&done);
  }

  BIND(&check_map);
  {
    Label map_fast_call(this);
    BranchIfIterableWithOriginalKeyOrValueMapIterator(
        state(), iterable, context, &map_fast_call, &check_set);

    BIND(&map_fast_call);
    *var_result =
        CAST(CallBuiltin(Builtin::kMapIteratorToList, context, iterable));
    Goto(&done);
  }

  BIND(&check_set);
  {
    Label set_fast_call(this);
    BranchIfIterableWithOriginalValueSetIterator(state(), iterable, context,
                                                 &set_fast_call, slow);

    BIND(&set_fast_call);
    *var_result =
        CAST(CallBuiltin(Builtin::kSetOrSetIteratorToList, context, iterable));
    Goto(&done);
  }

  BIND(&done);
}

TNode<JSArray> IteratorBuiltinsAssembler::FastIterableToList(
    TNode<Context> context, TNode<Object> iterable, Label* slow) {
  TVARIABLE(JSArray, var_fast_result);
  FastIterableToList(context, iterable, &var_fast_result, slow);
  return var_fast_result.value();
}

// This builtin loads the property Symbol.iterator as the iterator, and has fast
// paths for fast arrays, for primitive strings, for sets and set iterators, and
// for map iterators. These fast paths will only be taken if Symbol.iterator and
// the Iterator prototype are not modified in a way that changes the original
// iteration behavior.
// * In case of fast holey arrays, holes will be converted to undefined to
//   reflect iteration semantics. Note that replacement by undefined is only
//   correct when the NoElements protector is valid.
// * In case of map/set iterators, there is an additional requirement that the
//   iterator is not partially consumed. To be spec-compliant, after spreading
//   the iterator is set to be exhausted.
TF_BUILTIN(IterableToListWithSymbolLookup, IteratorBuiltinsAssembler) {
  auto context = Parameter<Context>(Descriptor::kContext);
  auto iterable = Parameter<Object>(Descriptor::kIterable);

  Label slow_path(this);

  GotoIfForceSlowPath(&slow_path);

  TVARIABLE(JSArray, var_result);
  FastIterableToList(context, iterable, &var_result, &slow_path);
  Return(var_result.value());

  BIND(&slow_path);
  {
    TNode<Object> iterator_fn = GetIteratorMethod(context, iterable);
    TailCallBuiltin(Builtin::kIterableToList, context, iterable, iterator_fn);
  }
}

TF_BUILTIN(GetIteratorWithFeedbackLazyDeoptContinuation,
           IteratorBuiltinsAssembler) {
  auto context = Parameter<Context>(Descriptor::kContext);
  auto receiver = Parameter<Object>(Descriptor::kReceiver);
  // TODO(v8:10047): Use TaggedIndex here once TurboFan supports it.
  auto call_slot_smi = Parameter<Smi>(Descriptor::kCallSlot);
  auto feedback = Parameter<FeedbackVector>(Descriptor::kFeedback);
  auto iterator_method = Parameter<Object>(Descriptor::kResult);

  // Note, that the builtin also expects the call_slot as a Smi.
  TNode<Object> result =
      CallBuiltin(Builtin::kCallIteratorWithFeedback, context, receiver,
                  iterator_method, call_slot_smi, feedback);
  Return(result);
}

TF_BUILTIN(CallIteratorWithFeedbackLazyDeoptContinuation,
           IteratorBuiltinsAssembler) {
  TNode<Context> context = Parameter<Context>(Descriptor::kContext);
  TNode<Object> iterator = Parameter<Object>(Descriptor::kArgument);

  ThrowIfNotJSReceiver(context, iterator,
                       MessageTemplate::kSymbolIteratorInvalid, "");
  Return(iterator);
}

// This builtin creates a FixedArray based on an Iterable and doesn't have a
// fast path for anything.
TF_BUILTIN(IterableToFixedArrayWithSymbolLookupSlow,
           IteratorBuiltinsAssembler) {
  auto context = Parameter<Context>(Descriptor::kContext);
  auto iterable = Parameter<Object>(Descriptor::kIterable);

  TNode<Object> iterator_fn = GetIteratorMethod(context, iterable);
  TailCallBuiltin(Builtin::kIterableToFixedArray, context, iterable,
                  iterator_fn);
}

#include "src/codegen/undef-code-stub-assembler-macros.inc"

}  // namespace internal
}  // namespace v8
```