Response:
Let's break down the thought process for analyzing this V8 source code.

1. **Understanding the Request:** The core request is to understand the functionality of the `builtins-iterator-gen.cc` file within the V8 JavaScript engine. The prompt also asks about `.tq` extensions, JavaScript relevance, code logic, and common errors.

2. **Initial Scan and Keywords:**  I'll quickly scan the code for keywords and patterns that give clues about its purpose. Keywords like "Iterator", "Iterable", "next", "done", "value", "GetIterator", "IteratorStep", "IteratorComplete", "IteratorValue", "Iterate", "IterableToList", "FixedArray", "String",  "Map", "Set", and "CallBuiltin" stand out. The `#include` directives at the top also indicate dependencies on other V8 components.

3. **File Naming Convention:** The file is named `builtins-iterator-gen.cc`. The `builtins` part strongly suggests this code implements built-in JavaScript functionalities related to iterators. The `-gen.cc` suffix usually indicates that this file might be generated, but in this case, it seems to be hand-written code implementing generic iterator functionalities used by other builtins.

4. **Core Functionality Identification:**  Based on the keywords and the overall structure, I can deduce the file's primary responsibility: **implementing the core logic for handling JavaScript iterators and iterables**. It provides building blocks and utilities for consuming iterables.

5. **Analyzing Key Functions:** I'll examine the purpose of the most prominent functions:
    * `GetIteratorMethod`: Gets the `Symbol.iterator` method of an object.
    * `GetIterator`:  Retrieves the iterator object from an iterable, handling cases where the method is not callable or the result isn't an object.
    * `IteratorStep`:  Calls the `next()` method of an iterator and checks if the result is an object.
    * `IteratorComplete`: Checks the `done` property of an iterator result to determine if iteration is complete. It has optimized paths for fast iterator results.
    * `IteratorValue`: Extracts the `value` property from an iterator result, with optimizations.
    * `Iterate`: The core looping mechanism for iterating over an iterable, handling exceptions and closing the iterator.
    * `IterableToList`, `IterableToFixedArray`: Convert iterables to arrays. These are fundamental operations.
    * `StringListFromIterable`:  Specifically handles iterables of strings.
    * `FastIterableToList`: Offers optimized paths for common iterable types like Arrays, Strings, Maps, and Sets.
    * Functions with `TF_BUILTIN`: These are entry points for built-in JavaScript functions, exposing the underlying C++ implementation. Examples like `IterableToList`, `IterableToFixedArray`, `StringListFromIterable`, `IterableToListWithSymbolLookup`.

6. **Torque Consideration:** The prompt mentions `.tq`. I'll re-scan the code. There are no `.tq` files directly included. The code uses `CodeStubAssembler` (CSA), which is a lower-level assembly-like language used within V8 builtins. While Torque might generate CSA code, this specific file appears to be using CSA directly. Thus, it's not a Torque source file.

7. **JavaScript Relevance and Examples:**  Since the file deals with iterators, it's directly related to the JavaScript iterator protocol. I'll provide basic JavaScript examples demonstrating how these builtins are used implicitly: `for...of` loops, spread syntax, `Array.from()`.

8. **Code Logic and Assumptions:** For a function like `IteratorStep`, I can analyze the flow:
    * **Input:** `context`, `iterator` record.
    * **Process:** Call `iterator.next()`, check if the result is an object, check the `done` property.
    * **Output:** The iterator result object (if not done).
    * **Assumptions:** The iterator object adheres to the iterator protocol.

9. **Common Programming Errors:** I'll think about common mistakes developers make with iterators:
    * Not checking the `done` property.
    * Modifying the iterable during iteration.
    * Assuming iterator results are always objects.

10. **Structure and Organization:**  The code is organized within the `v8::internal` namespace and uses helper classes like `IteratorBuiltinsAssembler` and `GrowableFixedArray`. The use of labels (`BIND`) and conditional jumps (`GotoIf`, `Branch`) is characteristic of CSA.

11. **Refinement and Detail:** I'll review my initial analysis and add more specific details about each function's role, the fast paths, and the error handling mechanisms. For example, noting the optimizations in `IteratorComplete` and `IteratorValue` for "fast iterator results."

12. **Final Review:** I'll read through my complete answer to ensure it's accurate, well-organized, and addresses all parts of the prompt. I'll double-check for clarity and conciseness.

This systematic approach, starting with a high-level overview and progressively diving into the details of individual functions and concepts, helps in understanding the purpose and functionality of a complex source code file like this.
The file `v8/src/builtins/builtins-iterator-gen.cc` in the V8 JavaScript engine implements **built-in functions related to the JavaScript iterator protocol**. It provides fundamental operations for working with iterables and iterators in JavaScript.

Here's a breakdown of its functionalities:

**Core Iterator Operations:**

* **`GetIteratorMethod(context, object)`:**  Retrieves the `@@iterator` method (Symbol.iterator) of a given JavaScript object. This method is responsible for returning the iterator object for the iterable.
* **`GetIterator(context, object)`:** Obtains the iterator object for a given object. It first gets the `@@iterator` method and then calls it. It also handles cases where the `@@iterator` method is not callable, throwing a `TypeError`.
* **`GetIterator(context, object, method)`:**  Similar to the above, but takes the iterator method as an argument. It ensures the method is callable and the returned iterator is an object.
* **`IteratorStep(context, iterator, if_done, fast_iterator_result_map)`:**  Advances the iterator by calling its `next()` method. It checks if the returned result is an object and then calls `IteratorComplete` to check the `done` property. If `done` is true, it jumps to the `if_done` label. It also has a fast path for optimized iterator result objects.
* **`IteratorComplete(context, iterator, if_done, fast_iterator_result_map)`:** Checks the `done` property of an iterator result object. If `done` is truthy, it jumps to the `if_done` label. It includes optimizations for known "fast" iterator result maps.
* **`IteratorValue(context, result, fast_iterator_result_map)`:** Extracts the `value` property from an iterator result object. It also has a fast path for optimized iterator result objects.
* **`Iterate(context, iterable, func, merged_variables)`:**  A core function for iterating over an iterable. It obtains the iterator, and in a loop, calls `IteratorStep` and `IteratorValue`, applying the provided function `func` to each yielded value. It handles potential exceptions during iteration and ensures the iterator is closed if an exception occurs.
* **`Iterate(context, iterable, iterable_fn, func, merged_variables)`:**  Similar to the above, but takes the iterator method as an argument.
* **`IteratorCloseOnException(context, iterator)`:**  Called when an exception occurs during iteration. It attempts to call the iterator's `return()` method (if it exists) to allow the iterator to perform cleanup.

**Conversion to Collections:**

* **`IterableToList(context, iterable, iterator_fn)`:**  Converts an iterable into a JavaScript `Array`. It iterates through the iterable and pushes each value into a growable array.
* **`IterableToFixedArray(context, iterable, iterator_fn)`:** Converts an iterable into a `FixedArray` (V8's internal representation of a non-resizable array).
* **`FillFixedArrayFromIterable(context, iterable, iterator_fn, values)`:**  A helper function used by `IterableToList` and `IterableToFixedArray` to populate a `GrowableFixedArray` with values from an iterable.
* **`StringListFromIterable(context, iterable)`:**  Converts an iterable into a `FixedArray` containing only strings. It throws a `TypeError` if a non-string value is encountered.
* **`FastIterableToList(context, iterable, var_result, slow)`:** Provides optimized paths for converting certain iterable types (like fast arrays, strings, Maps, Sets) to a JavaScript `Array`. If the iterable doesn't match the fast paths, it jumps to the `slow` label.
* **`FastIterableToList(context, iterable, slow)`:** A convenience wrapper for the above.

**Built-in Implementations (using `TF_BUILTIN`):**

The file also defines several built-in JavaScript functions using the `TF_BUILTIN` macro. These are entry points that expose the underlying C++ implementations to JavaScript:

* **`IterableToList`:**  The implementation of `Array.from(iterable)`.
* **`IterableToFixedArray`:**  Potentially used internally by other V8 components.
* **`IterableToFixedArrayForWasm`:**  A specialized version for WebAssembly, likely with length checks.
* **`StringListFromIterable`:**  Could be used internally or for specific APIs.
* **`StringFixedArrayFromIterable`:**  Another variant for creating a `FixedArray` of strings.
* **`IterableToListMayPreserveHoles`:**  An optimized version of `Array.from` that might preserve holes in sparse arrays.
* **`IterableToListConvertHoles`:**  An optimized version of `Array.from` that fills holes with `undefined`.
* **`IterableToListWithSymbolLookup`:**  Similar to `IterableToList`, but with fast paths based on the `Symbol.iterator` lookup.
* **`GetIteratorWithFeedbackLazyDeoptContinuation`:** Involved in optimized iterator retrieval with feedback for deoptimization.
* **`CallIteratorWithFeedbackLazyDeoptContinuation`:**  Part of the feedback mechanism for iterator calls.
* **`IterableToFixedArrayWithSymbolLookupSlow`:** A slower path for converting iterables to `FixedArray`.

**Is it a Torque Source File?**

The prompt asks if the file is a Torque source file if it ends with `.tq`. **`v8/src/builtins/builtins-iterator-gen.cc` is a C++ source file.**  Torque source files have the `.tq` extension. Therefore, **no, this is not a Torque source file.** It's a hand-written C++ file using V8's CodeStubAssembler (CSA) to generate optimized machine code for these built-in functions.

**Relationship to JavaScript Functionality (with examples):**

This file is directly related to how JavaScript handles iteration using the iterator protocol. Here are some JavaScript examples that rely on the functionality implemented in this file:

```javascript
// 1. Using the for...of loop (implicitly uses iterators)
const iterable = [1, 2, 3];
for (const value of iterable) {
  console.log(value);
}

// 2. Using the spread syntax (...) with iterables
const set = new Set([4, 5, 6]);
const arrayFromSet = [...set]; // Equivalent to Array.from(set)
console.log(arrayFromSet);

// 3. Using Array.from()
const map = new Map([[1, 'a'], [2, 'b']]);
const arrayFromMap = Array.from(map);
console.log(arrayFromMap);

// 4. Manually getting and using an iterator
const str = "hello";
const iterator = str[Symbol.iterator]();
console.log(iterator.next()); // { value: "h", done: false }
console.log(iterator.next()); // { value: "e", done: false }
console.log(iterator.next()); // { value: "l", done: false }
console.log(iterator.next()); // { value: "l", done: false }
console.log(iterator.next()); // { value: "o", done: false }
console.log(iterator.next()); // { value: undefined, done: true }
```

The C++ code in `builtins-iterator-gen.cc` provides the underlying implementation for these JavaScript constructs. When you use a `for...of` loop, spread syntax on an iterable, or `Array.from()`, V8 calls the built-in functions defined in this file (or similar generated code) to handle the iteration process.

**Code Logic Inference (with assumptions):**

Let's consider the `IteratorStep` function:

**Assumptions:**

* **Input:** `context` (V8 execution context), `iterator` (an object with a `next` property which is a function), `if_done` (a label to jump to if iteration is complete), `fast_iterator_result_map` (optional, a map object for optimization).
* The `iterator.next()` method adheres to the iterator protocol, returning an object with `done` and `value` properties.

**Logic:**

1. **`TNode<Object> result = Call(context, iterator.next, iterator.object);`**: Calls the `next()` method of the iterator.
2. **Type Check:** Checks if the `result` is an object. If it's a primitive (like a number or string), it throws a `TypeError`.
3. **Fast Path (if `fast_iterator_result_map` is provided):** Checks if the `result` object's map matches the expected map for fast iterator results. If it does, it directly accesses the `done` property.
4. **Generic Path:** If it's not a fast iterator result, it gets the `done` property using `GetProperty`.
5. **`BranchIfToBooleanIsTrue(done, if_done, &return_result);`**: Converts the `done` property to a boolean. If it's truthy (meaning iteration is complete), it jumps to the `if_done` label. Otherwise, it continues to the `return_result` label.
6. **`return CAST(heap_object_result);`**: Returns the iterator result object.

**Hypothetical Input and Output for `IteratorStep`:**

**Input 1 (Iteration not done):**

* `iterator`: `{ next: function() { return { value: 10, done: false }; } }`
* `context`: (Valid V8 context)
* `if_done`: (A label defined elsewhere)

**Output 1:**

* Jumps to `return_result`.
* Returns an object representing the iterator result: `{ value: 10, done: false }`.

**Input 2 (Iteration done):**

* `iterator`: `{ next: function() { return { value: undefined, done: true }; } }`
* `context`: (Valid V8 context)
* `if_done`: (A label defined elsewhere)

**Output 2:**

* Jumps to the `if_done` label.
* Does not return a value from the `IteratorStep` function itself (the control flow jumps elsewhere).

**Common Programming Errors Related to Iterators:**

This file helps prevent or handle common errors developers might make when working with iterators:

1. **Not checking the `done` property:** Developers might forget to check the `done` property of the iterator result, leading to infinite loops or errors when trying to access `value` after the iterator is exhausted. The `IteratorStep` and `IteratorComplete` functions enforce this check.

   ```javascript
   // Potential error: Not checking 'done'
   const iterator = [1, 2][Symbol.iterator]();
   let result = iterator.next();
   while (result) { // Incorrect - result can be truthy even when done is true
       console.log(result.value);
       result = iterator.next();
   }
   ```

2. **Assuming iterator methods always return objects:**  The `IteratorStep` function explicitly checks if the `next()` method returns an object and throws a `TypeError` if it doesn't.

   ```javascript
   // Potential error: Assuming next() returns an object
   const badIterator = {
       [Symbol.iterator]() {
           return {
               next: () => 123 // Incorrect - should return an object
           };
       }
   };
   try {
       for (const x of badIterator) {
           console.log(x);
       }
   } catch (e) {
       console.error(e); // TypeError: Iterator result is not an object
   }
   ```

3. **Modifying the iterable during iteration:** While this file doesn't directly prevent this, the iterator protocol itself can be sensitive to modifications. V8's implementation of iterators for built-in types might throw errors in such cases.

   ```javascript
   // Potential error: Modifying the array while iterating
   const arr = [1, 2, 3];
   for (const item of arr) {
       if (item === 2) {
           arr.push(4); // Might lead to unexpected behavior or infinite loops
       }
   }
   ```

In summary, `v8/src/builtins/builtins-iterator-gen.cc` is a crucial part of V8, providing the low-level implementation for JavaScript's iteration mechanisms, ensuring correct behavior and helping to catch common programming errors related to iterators.

Prompt: 
```
这是目录为v8/src/builtins/builtins-iterator-gen.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/builtins-iterator-gen.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
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

"""

```