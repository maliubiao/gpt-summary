Response:
Let's break down the thought process for analyzing the provided C++ code.

1. **Understanding the Context:** The first step is to recognize the file path: `v8/src/builtins/builtins-typed-array.cc`. This immediately tells us we're dealing with the implementation of built-in functions for TypedArrays in V8, the JavaScript engine. The `.cc` extension confirms it's C++ code.

2. **Initial Scan for Keywords and Structure:**  Quickly scan the code for familiar keywords and structural elements. Keywords like `BUILTIN`, `HandleScope`, `CHECK_RECEIVER`, `ASSIGN_RETURN_FAILURE_ON_EXCEPTION`, `Object::ToInteger`, `std::min`, `std::max`, `memmove`, `IsSmi`, `IsHeapNumber`, etc., provide hints about the code's functionality. Notice the namespace `v8::internal`, which is standard for V8's internal implementation.

3. **Analyzing Individual `BUILTIN` Functions:**  The core of the file seems to be a series of `BUILTIN` functions. Each `BUILTIN` likely corresponds to a specific method on the `TypedArray.prototype`. The names of the `BUILTIN` functions (e.g., `TypedArrayPrototypeBuffer`, `TypedArrayPrototypeCopyWithin`, `TypedArrayPrototypeFill`) strongly suggest their purpose.

4. **Dissecting a Single `BUILTIN` (Example: `TypedArrayPrototypeBuffer`):**

   * **`BUILTIN(TypedArrayPrototypeBuffer)`:**  This clearly relates to the `buffer` property of a TypedArray.
   * **`HandleScope scope(isolate);`:** Standard V8 pattern for managing memory.
   * **`CHECK_RECEIVER(JSTypedArray, typed_array, ...);`:**  This verifies that the `this` value is a `JSTypedArray` object.
   * **`return *typed_array->GetBuffer();`:**  This directly returns the underlying buffer of the TypedArray.

   * **JavaScript Correlation:**  This maps directly to accessing the `buffer` property in JavaScript: `const buffer = new Uint8Array(10).buffer;`.

5. **Dissecting a More Complex `BUILTIN` (Example: `TypedArrayPrototypeCopyWithin`):**

   * **`BUILTIN(TypedArrayPrototypeCopyWithin)`:**  Relates to the `copyWithin` method.
   * **Parameter Handling:** The code carefully extracts and validates arguments (`to`, `from`, `final`). Notice the `CapRelativeIndex` helper function, which handles negative indices.
   * **Error Handling:** Checks for detached buffers (`array->WasDetached()`) and out-of-bounds access for resizable array buffers (`array->is_backed_by_rab()`).
   * **Core Logic:** Calculates the `count` of bytes to copy and performs the memory copy using `std::memmove` or `base::Relaxed_Memmove` (for shared buffers).

   * **Code Logic Inference:**  If `to = 1`, `from = 3`, and the array is `[0, 1, 2, 3, 4]`, the `copyWithin` operation will copy elements starting from index 3 to the position starting at index 1. The output would be `[0, 3, 4, 3, 4]`.

   * **Common Errors:**  Passing invalid indices (e.g., negative values without understanding relative indexing), or attempting to operate on a detached buffer.

6. **Generalizing the Analysis:** Apply the same dissection process to the other `BUILTIN` functions: `Fill`, `Includes`, `IndexOf`, `LastIndexOf`, `Reverse`. Identify the core logic, parameter handling, error checks, and potential JavaScript correlations.

7. **Addressing Specific Questions:** Now that the individual function functionalities are understood, answer the specific questions from the prompt:

   * **Functionality Listing:**  Summarize the purpose of each `BUILTIN`.
   * **Torque Source:** Check the file extension. Since it's `.cc`, it's C++, not Torque.
   * **JavaScript Examples:** For each `BUILTIN`, provide a corresponding JavaScript code snippet.
   * **Code Logic Inference:** Choose a function with clear logic (like `copyWithin` or `fill`) and provide an input/output example.
   * **Common Programming Errors:**  Identify typical mistakes developers might make when using these TypedArray methods based on the code's error handling and parameter validation.

8. **Review and Refine:**  Read through the generated analysis to ensure accuracy, clarity, and completeness. Check for any missing information or areas that could be explained more effectively. For instance, initially, I might not explicitly mention the handling of resizable array buffers, but upon closer inspection of the `copyWithin` and `fill` functions, I'd add that detail.

This structured approach, moving from high-level understanding to detailed analysis of individual components, combined with connecting the C++ implementation to JavaScript behavior, is key to effectively analyzing V8 source code. The process involves pattern recognition, understanding V8's internal conventions, and relating the C++ code to the user-facing JavaScript API.
This C++ source code file, `v8/src/builtins/builtins-typed-array.cc`, implements the built-in methods of JavaScript TypedArray objects in the V8 JavaScript engine. Let's break down its functionalities:

**Core Functionality:**

This file provides the C++ implementation for various methods available on the `TypedArray.prototype`. These methods allow JavaScript developers to manipulate the contents and properties of TypedArray objects.

**Specific Functionalities (Based on the provided code):**

* **`TypedArrayPrototypeBuffer`:**
    * **Functionality:** Implements the getter for the `buffer` property of a TypedArray. It returns the underlying `ArrayBuffer` associated with the TypedArray.
    * **JavaScript Example:**
      ```javascript
      const typedArray = new Uint8Array(10);
      const buffer = typedArray.buffer;
      console.log(buffer instanceof ArrayBuffer); // Output: true
      ```

* **`TypedArrayPrototypeCopyWithin`:**
    * **Functionality:** Implements the `copyWithin()` method. This method copies a sequence of array elements within the array.
    * **Logic Inference:**
        * **Assumptions:**
            * `array`: A valid TypedArray (e.g., `Uint8Array([1, 2, 3, 4, 5])`).
            * `to`: The target index to start copying to.
            * `from`: The index to start copying elements from.
            * `end`: The index to end copying elements from (exclusive).
        * **Example:** `typedArray.copyWithin(0, 3, 4)`
        * **Input:** `typedArray = Uint8Array([1, 2, 3, 4, 5])`, `to = 0`, `from = 3`, `end = 4`
        * **Output:** `typedArray` will be modified to `Uint8Array([4, 2, 3, 4, 5])`. The element at index 3 (value 4) is copied to index 0.
        * **Handling Negative Indices:** The `CapRelativeIndex` function handles negative indices, treating them as offsets from the end of the array.
    * **JavaScript Example:**
      ```javascript
      const typedArray = new Int32Array([1, 2, 3, 4, 5]);
      typedArray.copyWithin(0, 3, 5); // Copy elements from index 3 to 4 to the start
      console.log(typedArray); // Output: Int32Array(5) [4, 5, 3, 4, 5]
      ```
    * **Common Programming Errors:**
        * **Incorrect Indices:** Providing `to`, `from`, or `end` values that are out of bounds or result in illogical copy operations.
        * **Assuming destructive behavior when `count` is zero:** If the calculated `count` is zero or negative, the array remains unchanged, which might be unexpected.

* **`TypedArrayPrototypeFill`:**
    * **Functionality:** Implements the `fill()` method. This method fills all or parts of a TypedArray with a static value.
    * **Logic Inference:**
        * **Assumptions:**
            * `array`: A valid TypedArray.
            * `value`: The value to fill the array with (will be converted to the appropriate type).
            * `start`: The starting index to fill (inclusive).
            * `end`: The ending index to fill (exclusive).
        * **Example:** `typedArray.fill(0, 2, 4)`
        * **Input:** `typedArray = Float64Array([1.5, 2.5, 3.5, 4.5, 5.5])`, `value = 0`, `start = 2`, `end = 4`
        * **Output:** `typedArray` will be modified to `Float64Array([1.5, 2.5, 0, 0, 5.5])`.
    * **JavaScript Example:**
      ```javascript
      const typedArray = new Uint16Array(5);
      typedArray.fill(10); // Fill the entire array with 10
      console.log(typedArray); // Output: Uint16Array(5) [10, 10, 10, 10, 10]

      const anotherArray = new Float32Array([1, 2, 3, 4, 5]);
      anotherArray.fill(0, 1, 3); // Fill from index 1 (inclusive) to 3 (exclusive) with 0
      console.log(anotherArray); // Output: Float32Array(5) [1, 0, 0, 4, 5]
      ```
    * **Common Programming Errors:**
        * **Type Mismatch:** Trying to fill a TypedArray with a value that cannot be implicitly converted to the element type (though V8 will attempt conversion).
        * **Incorrect Range:** Providing `start` or `end` values that lead to unintended filling ranges.

* **`TypedArrayPrototypeIncludes`:**
    * **Functionality:** Implements the `includes()` method. This method determines whether a TypedArray includes a certain element, returning `true` or `false`.
    * **Logic Inference:**
        * It iterates through the array (starting from the specified `index`) and compares each element with the `search_element`.
    * **JavaScript Example:**
      ```javascript
      const typedArray = new Int8Array([10, 20, 30, 40]);
      console.log(typedArray.includes(20)); // Output: true
      console.log(typedArray.includes(50)); // Output: false
      console.log(typedArray.includes(20, 2)); // Output: false (starts searching from index 2)
      ```

* **`TypedArrayPrototypeIndexOf`:**
    * **Functionality:** Implements the `indexOf()` method. This method returns the first index at which a given element can be found in the TypedArray, or -1 if it is not present.
    * **Logic Inference:**
        * It iterates through the array (starting from the specified `index`) and returns the index of the first matching element.
    * **JavaScript Example:**
      ```javascript
      const typedArray = new Uint32Array([5, 10, 15, 10, 20]);
      console.log(typedArray.indexOf(10));     // Output: 1
      console.log(typedArray.indexOf(10, 2));  // Output: 3 (starts searching from index 2)
      console.log(typedArray.indexOf(25));     // Output: -1
      ```

* **`TypedArrayPrototypeLastIndexOf`:**
    * **Functionality:** Implements the `lastIndexOf()` method. This method returns the last index at which a given element can be found in the TypedArray, or -1 if it is not present. It searches backward from the end of the array or a specified index.
    * **Logic Inference:**
        * It iterates backward through the array (up to the specified `index`) and returns the index of the last matching element.
    * **JavaScript Example:**
      ```javascript
      const typedArray = new Float64Array([2.5, 5.0, 7.5, 5.0, 10.0]);
      console.log(typedArray.lastIndexOf(5.0));    // Output: 3
      console.log(typedArray.lastIndexOf(5.0, 2)); // Output: 1 (searches backward up to index 2)
      console.log(typedArray.lastIndexOf(15.0));   // Output: -1
      ```

* **`TypedArrayPrototypeReverse`:**
    * **Functionality:** Implements the `reverse()` method. This method reverses the elements in a TypedArray in place.
    * **Logic Inference:**
        * It swaps elements from the beginning and end of the array, moving inwards until the middle is reached.
    * **JavaScript Example:**
      ```javascript
      const typedArray = new Uint8ClampedArray([1, 2, 3, 4, 5]);
      typedArray.reverse();
      console.log(typedArray); // Output: Uint8ClampedArray(5) [5, 4, 3, 2, 1]
      ```

**Is it a Torque Source?**

The provided code has a `.cc` extension, indicating it's a **C++ source file**, not a Torque (`.tq`) source file. Torque is a domain-specific language used within V8 for defining built-in functions in a more declarative way. While some built-ins are being migrated to Torque, this particular file is still in C++.

**Relationship to JavaScript Functionality:**

This C++ code directly implements the behavior of the corresponding JavaScript `TypedArray` prototype methods. When you call methods like `copyWithin`, `fill`, `includes`, etc., on a JavaScript TypedArray object, the V8 engine ultimately executes the C++ code defined in this file (or related files).

**Common Programming Errors (General for Typed Arrays):**

* **Operating on a Detached Buffer:** After the underlying `ArrayBuffer` of a TypedArray has been detached (e.g., through transfer), attempting to access or modify the TypedArray will result in an error. The code explicitly checks for detached buffers (`array->WasDetached()`).
* **Incorrect Element Type:** While JavaScript is dynamically typed, TypedArrays have a specific element type (e.g., `Uint8Array`, `Float64Array`). Trying to store a value that cannot be represented without loss might lead to unexpected behavior or truncation.
* **Out-of-Bounds Access:** Accessing elements outside the valid range of indices in a TypedArray will lead to `undefined` (for reads) or errors (for writes in strict mode).
* **Misunderstanding `length` vs. `byteLength`:** TypedArrays have both a `length` (number of elements) and a `byteLength` (total bytes occupied). Confusing these can lead to errors when working with the underlying buffer.

In summary, `v8/src/builtins/builtins-typed-array.cc` is a crucial part of V8, providing the low-level implementation for the fundamental operations on JavaScript TypedArrays, ensuring efficient and correct behavior as defined by the ECMAScript specification.

### 提示词
```
这是目录为v8/src/builtins/builtins-typed-array.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/builtins-typed-array.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
// Copyright 2016 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/builtins/builtins-utils-inl.h"
#include "src/builtins/builtins.h"
#include "src/logging/counters.h"
#include "src/objects/elements.h"
#include "src/objects/heap-number-inl.h"
#include "src/objects/js-array-buffer-inl.h"
#include "src/objects/objects-inl.h"

namespace v8 {
namespace internal {

// -----------------------------------------------------------------------------
// ES6 section 22.2 TypedArray Objects

// ES6 section 22.2.3.1 get %TypedArray%.prototype.buffer
BUILTIN(TypedArrayPrototypeBuffer) {
  HandleScope scope(isolate);
  CHECK_RECEIVER(JSTypedArray, typed_array,
                 "get %TypedArray%.prototype.buffer");
  return *typed_array->GetBuffer();
}

namespace {

int64_t CapRelativeIndex(DirectHandle<Object> num, int64_t minimum,
                         int64_t maximum) {
  if (V8_LIKELY(IsSmi(*num))) {
    int64_t relative = Smi::ToInt(*num);
    return relative < 0 ? std::max<int64_t>(relative + maximum, minimum)
                        : std::min<int64_t>(relative, maximum);
  } else {
    DCHECK(IsHeapNumber(*num));
    double relative = Cast<HeapNumber>(*num)->value();
    DCHECK(!std::isnan(relative));
    return static_cast<int64_t>(
        relative < 0 ? std::max<double>(relative + maximum, minimum)
                     : std::min<double>(relative, maximum));
  }
}

}  // namespace

BUILTIN(TypedArrayPrototypeCopyWithin) {
  HandleScope scope(isolate);

  Handle<JSTypedArray> array;
  const char* method_name = "%TypedArray%.prototype.copyWithin";
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, array,
      JSTypedArray::Validate(isolate, args.receiver(), method_name));

  int64_t len = array->GetLength();
  int64_t to = 0;
  int64_t from = 0;
  int64_t final = len;

  if (V8_LIKELY(args.length() > 1)) {
    Handle<Object> num;
    ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
        isolate, num, Object::ToInteger(isolate, args.at<Object>(1)));
    to = CapRelativeIndex(num, 0, len);

    if (args.length() > 2) {
      ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
          isolate, num, Object::ToInteger(isolate, args.at<Object>(2)));
      from = CapRelativeIndex(num, 0, len);

      Handle<Object> end = args.atOrUndefined(isolate, 3);
      if (!IsUndefined(*end, isolate)) {
        ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, num,
                                           Object::ToInteger(isolate, end));
        final = CapRelativeIndex(num, 0, len);
      }
    }
  }

  int64_t count = std::min<int64_t>(final - from, len - to);
  if (count <= 0) return *array;

  // TypedArray buffer may have been transferred/detached during parameter
  // processing above.
  if (V8_UNLIKELY(array->WasDetached())) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate, NewTypeError(MessageTemplate::kDetachedOperation,
                              isolate->factory()->NewStringFromAsciiChecked(
                                  method_name)));
  }

  if (V8_UNLIKELY(array->is_backed_by_rab())) {
    bool out_of_bounds = false;
    int64_t new_len = array->GetLengthOrOutOfBounds(out_of_bounds);
    if (out_of_bounds) {
      const MessageTemplate message = MessageTemplate::kDetachedOperation;
      Handle<String> operation =
          isolate->factory()->NewStringFromAsciiChecked(method_name);
      THROW_NEW_ERROR_RETURN_FAILURE(isolate, NewTypeError(message, operation));
    }
    if (new_len < len) {
      // We don't need to account for growing, since we only copy an already
      // determined number of elements and growing won't change it. If to >
      // new_len or from > new_len, the count below will be < 0, so we don't
      // need to check them separately.
      if (final > new_len) {
        final = new_len;
      }
      count = std::min<int64_t>(final - from, new_len - to);
      if (count <= 0) {
        return *array;
      }
    }
  }

  // Ensure processed indexes are within array bounds
  DCHECK_GE(from, 0);
  DCHECK_LT(from, len);
  DCHECK_GE(to, 0);
  DCHECK_LT(to, len);
  DCHECK_GE(len - count, 0);

  size_t element_size = array->element_size();
  to = to * element_size;
  from = from * element_size;
  count = count * element_size;

  uint8_t* data = static_cast<uint8_t*>(array->DataPtr());
  if (array->buffer()->is_shared()) {
    base::Relaxed_Memmove(reinterpret_cast<base::Atomic8*>(data + to),
                          reinterpret_cast<base::Atomic8*>(data + from), count);
  } else {
    std::memmove(data + to, data + from, count);
  }

  return *array;
}

BUILTIN(TypedArrayPrototypeFill) {
  HandleScope scope(isolate);

  Handle<JSTypedArray> array;
  const char* method_name = "%TypedArray%.prototype.fill";
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, array,
      JSTypedArray::Validate(isolate, args.receiver(), method_name));
  ElementsKind kind = array->GetElementsKind();

  Handle<Object> obj_value = args.atOrUndefined(isolate, 1);
  if (IsBigIntTypedArrayElementsKind(kind)) {
    ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, obj_value,
                                       BigInt::FromObject(isolate, obj_value));
  } else {
    ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, obj_value,
                                       Object::ToNumber(isolate, obj_value));
  }

  int64_t len = array->GetLength();
  int64_t start = 0;
  int64_t end = len;

  if (args.length() > 2) {
    Handle<Object> num = args.atOrUndefined(isolate, 2);
    if (!IsUndefined(*num, isolate)) {
      ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
          isolate, num, Object::ToInteger(isolate, num));
      start = CapRelativeIndex(num, 0, len);

      num = args.atOrUndefined(isolate, 3);
      if (!IsUndefined(*num, isolate)) {
        ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
            isolate, num, Object::ToInteger(isolate, num));
        end = CapRelativeIndex(num, 0, len);
      }
    }
  }

  if (V8_UNLIKELY(array->WasDetached())) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate, NewTypeError(MessageTemplate::kDetachedOperation,
                              isolate->factory()->NewStringFromAsciiChecked(
                                  method_name)));
  }

  if (V8_UNLIKELY(array->IsVariableLength())) {
    if (array->IsOutOfBounds()) {
      const MessageTemplate message = MessageTemplate::kDetachedOperation;
      Handle<String> operation =
          isolate->factory()->NewStringFromAsciiChecked(method_name);
      THROW_NEW_ERROR_RETURN_FAILURE(isolate, NewTypeError(message, operation));
    }
    end = std::min(end, static_cast<int64_t>(array->GetLength()));
  }

  int64_t count = end - start;
  if (count <= 0) return *array;

  // Ensure processed indexes are within array bounds
  DCHECK_GE(start, 0);
  DCHECK_LT(start, len);
  DCHECK_GE(end, 0);
  DCHECK_LE(end, len);
  DCHECK_LE(count, len);

  RETURN_RESULT_OR_FAILURE(isolate, ElementsAccessor::ForKind(kind)->Fill(
                                        array, obj_value, start, end));
}

BUILTIN(TypedArrayPrototypeIncludes) {
  HandleScope scope(isolate);

  Handle<JSTypedArray> array;
  const char* method_name = "%TypedArray%.prototype.includes";
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, array,
      JSTypedArray::Validate(isolate, args.receiver(), method_name));

  if (args.length() < 2) return ReadOnlyRoots(isolate).false_value();

  int64_t len = array->GetLength();
  if (len == 0) return ReadOnlyRoots(isolate).false_value();

  int64_t index = 0;
  if (args.length() > 2) {
    Handle<Object> num;
    ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
        isolate, num, Object::ToInteger(isolate, args.at<Object>(2)));
    index = CapRelativeIndex(num, 0, len);
  }

  Handle<Object> search_element = args.atOrUndefined(isolate, 1);
  ElementsAccessor* elements = array->GetElementsAccessor();
  Maybe<bool> result =
      elements->IncludesValue(isolate, array, search_element, index, len);
  MAYBE_RETURN(result, ReadOnlyRoots(isolate).exception());
  return *isolate->factory()->ToBoolean(result.FromJust());
}

BUILTIN(TypedArrayPrototypeIndexOf) {
  HandleScope scope(isolate);

  Handle<JSTypedArray> array;
  const char* method_name = "%TypedArray%.prototype.indexOf";
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, array,
      JSTypedArray::Validate(isolate, args.receiver(), method_name));

  int64_t len = array->GetLength();
  if (len == 0) return Smi::FromInt(-1);

  int64_t index = 0;
  if (args.length() > 2) {
    Handle<Object> num;
    ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
        isolate, num, Object::ToInteger(isolate, args.at<Object>(2)));
    index = CapRelativeIndex(num, 0, len);
  }

  if (V8_UNLIKELY(array->WasDetached())) return Smi::FromInt(-1);

  if (V8_UNLIKELY(array->IsVariableLength() && array->IsOutOfBounds())) {
    return Smi::FromInt(-1);
  }

  Handle<Object> search_element = args.atOrUndefined(isolate, 1);
  ElementsAccessor* elements = array->GetElementsAccessor();
  Maybe<int64_t> result =
      elements->IndexOfValue(isolate, array, search_element, index, len);
  MAYBE_RETURN(result, ReadOnlyRoots(isolate).exception());
  return *isolate->factory()->NewNumberFromInt64(result.FromJust());
}

BUILTIN(TypedArrayPrototypeLastIndexOf) {
  HandleScope scope(isolate);

  Handle<JSTypedArray> array;
  const char* method_name = "%TypedArray%.prototype.lastIndexOf";
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, array,
      JSTypedArray::Validate(isolate, args.receiver(), method_name));

  int64_t len = array->GetLength();
  if (len == 0) return Smi::FromInt(-1);

  int64_t index = len - 1;
  if (args.length() > 2) {
    Handle<Object> num;
    ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
        isolate, num, Object::ToInteger(isolate, args.at<Object>(2)));
    // Set a negative value (-1) for returning -1 if num is negative and
    // len + num is still negative. Upper bound is len - 1.
    index = std::min<int64_t>(CapRelativeIndex(num, -1, len), len - 1);
  }

  if (index < 0) return Smi::FromInt(-1);

  if (V8_UNLIKELY(array->WasDetached())) return Smi::FromInt(-1);
  if (V8_UNLIKELY(array->IsVariableLength() && array->IsOutOfBounds())) {
    return Smi::FromInt(-1);
  }

  Handle<Object> search_element = args.atOrUndefined(isolate, 1);
  ElementsAccessor* elements = array->GetElementsAccessor();
  Maybe<int64_t> result =
      elements->LastIndexOfValue(array, search_element, index);
  MAYBE_RETURN(result, ReadOnlyRoots(isolate).exception());
  return *isolate->factory()->NewNumberFromInt64(result.FromJust());
}

BUILTIN(TypedArrayPrototypeReverse) {
  HandleScope scope(isolate);

  Handle<JSTypedArray> array;
  const char* method_name = "%TypedArray%.prototype.reverse";
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, array,
      JSTypedArray::Validate(isolate, args.receiver(), method_name));

  ElementsAccessor* elements = array->GetElementsAccessor();
  elements->Reverse(*array);
  return *array;
}

}  // namespace internal
}  // namespace v8
```