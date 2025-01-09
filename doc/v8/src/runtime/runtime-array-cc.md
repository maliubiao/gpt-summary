Response:
Let's break down the thought process for analyzing the provided C++ code.

**1. Understanding the Context:**

The first thing to recognize is the directory: `v8/src/runtime/runtime-array.cc`. This tells us:

* **V8:**  We're dealing with the V8 JavaScript engine.
* **src/runtime:**  This suggests these functions are part of the core runtime, providing low-level functionalities needed by the engine. These aren't direct implementations of JavaScript built-in methods, but rather building blocks for them.
* **runtime-array.cc:** The name strongly implies this file contains runtime functions specifically related to arrays.

**2. Initial Scan for Keywords and Patterns:**

A quick scan reveals several important patterns and keywords:

* **`RUNTIME_FUNCTION`:** This is the most crucial keyword. It signifies that these are functions exposed to the V8 runtime system, callable from within the engine's execution pipeline. They take an `Arguments` object as input.
* **`HandleScope scope(isolate)`:**  This is a standard V8 pattern for managing object handles and preventing memory leaks during garbage collection. It's a good indicator of functions dealing with V8's object model.
* **`args.length()` and `args.at<...>(...)`:** These are how the runtime functions access the arguments passed to them. The number of arguments is often checked with `DCHECK_EQ`.
* **`Handle<JSObject>`, `Handle<JSArray>`, `Handle<Map>`, etc.:** These are V8's handle types, representing pointers to managed objects on the heap. This reinforces that these functions manipulate V8's internal object representation.
* **`ElementsKind`:** This term appears frequently, indicating the code deals with different internal representations of array elements (e.g., packed integers, packed doubles, holey arrays, dictionary arrays).
* **`TransitionElementsKind`:**  This suggests the ability to change the internal storage format of an array.
* **`NewArray`:** A function for creating new arrays.
* **`NormalizeElements`:** A function that likely converts an array to a more standard internal representation.
* **`GrowArrayElements`:**  A function for increasing the capacity of an array's internal storage.
* **`ArrayIsArray`, `IsArray`, `ArraySpeciesConstructor`, `ArrayIncludes_Slow`, `ArrayIndexOf`:** These function names strongly correlate with standard JavaScript `Array` methods. The `_Slow` suffix often indicates a less optimized path.

**3. Analyzing Individual `RUNTIME_FUNCTION`s:**

The next step is to go through each `RUNTIME_FUNCTION` and understand its purpose based on its name and the operations it performs:

* **`Runtime_TransitionElementsKind` and `Runtime_TransitionElementsKindWithKind`:**  These clearly handle changing an array's `ElementsKind`. The first takes a `Map` as input, while the second takes the `ElementsKind` directly as a Smi.

* **`Runtime_NewArray`:** This function is responsible for the core array creation process. It handles various cases, including the size argument, type feedback from allocation sites, and potential transitions in `ElementsKind`. The logic around `AllocationSite` is a key indicator of optimization strategies.

* **`Runtime_NormalizeElements`:**  This seems to force an array into a more "normal" state, potentially converting from specialized representations. The checks for `HasTypedArrayOrRabGsabTypedArrayElements` and `IsJSGlobalProxy` give clues about when normalization is needed.

* **`Runtime_GrowArrayElements`:**  This function deals with increasing the internal capacity of a fast-mode array. It handles both Smi and HeapNumber indices and has a check for negative indices.

* **`Runtime_ArrayIsArray` and `Runtime_IsArray`:** These are straightforward implementations of the `Array.isArray()` functionality. The difference between the two might relate to internal optimizations or specific use cases within V8.

* **`Runtime_ArraySpeciesConstructor`:**  This function is related to the `Symbol.species` mechanism in JavaScript, allowing subclasses of arrays to control the constructor used for methods like `map` and `slice`.

* **`Runtime_ArrayIncludes_Slow`:** This is the slower path for `Array.prototype.includes()`. It handles various cases, including non-array objects and non-integer `fromIndex`. The comment about "special receiver types" is important.

* **`Runtime_ArrayIndexOf`:** Similar to `ArrayIncludes_Slow`, this is the slower path for `Array.prototype.indexOf()`, with comparable logic for handling different object types and index values.

**4. Connecting to JavaScript:**

After understanding the individual runtime functions, the next step is to relate them to JavaScript. This involves:

* **Matching function names:**  Functions like `Runtime_ArrayIsArray`, `Runtime_ArrayIncludes_Slow`, and `Runtime_ArrayIndexOf` have obvious JavaScript counterparts.
* **Inferring from functionality:**  `Runtime_NewArray` is clearly involved in the `new Array()` constructor. `Runtime_TransitionElementsKind` relates to how V8 internally optimizes array storage.
* **Considering the "slow" suffix:** The `_Slow` suffix indicates that there might be faster, optimized paths for `includes` and `indexOf` in V8.

**5. Hypothesizing Inputs and Outputs:**

For functions like `Runtime_GrowArrayElements`,  it's possible to make educated guesses about inputs and outputs based on the code. For example, an array and a valid index should lead to the array's internal storage potentially being resized.

**6. Identifying Potential Programming Errors:**

Looking for error handling, assertions (`CHECK`, `DCHECK`), and conditions that lead to different behavior can reveal potential JavaScript programming errors. For instance, providing a negative or non-integer length to the `Array` constructor, or using non-numeric indices.

**7. Addressing the `.tq` Question:**

The prompt specifically asks about the `.tq` extension. Based on the provided code being `.cc`, we can confidently state it's not Torque code. Explaining what Torque is and its purpose in V8 adds valuable context.

**8. Structuring the Output:**

Finally, organize the findings logically:

* Start with a summary of the file's overall purpose.
* List the individual functions and describe their functionality.
* Provide JavaScript examples where relevant.
* Give examples of potential programming errors.
* Address the `.tq` question.
* Include hypothetical input/output examples where appropriate.

This step-by-step approach, combining code analysis with knowledge of JavaScript and V8 internals, allows for a comprehensive understanding of the given C++ source code.
这个 C++ 源代码文件 `v8/src/runtime/runtime-array.cc` 包含了 V8 JavaScript 引擎中与数组操作相关的 **运行时 (Runtime)** 函数的实现。这些运行时函数是 V8 引擎内部使用的低级函数，通常会被 JavaScript 的内置方法或操作调用。

**主要功能列表:**

1. **数组元素类型转换 (`Runtime_TransitionElementsKind`, `Runtime_TransitionElementsKindWithKind`)**:
   - 允许在数组的不同内部元素存储类型之间进行转换，例如从 `PACKED_SMI_ELEMENTS` 转换为 `PACKED_DOUBLE_ELEMENTS` 或 `DICTIONARY_ELEMENTS`。
   - 这对于优化内存使用和性能至关重要。V8 会根据数组中存储的元素的类型动态调整其内部表示。

2. **创建新数组 (`Runtime_NewArray`)**:
   - 负责处理 JavaScript 中 `new Array()` 构造函数的调用。
   - 它会根据传入的参数（长度或初始元素）以及可能的类型反馈信息（通过 `AllocationSite`）来创建合适的数组对象。
   - 其中涉及优化策略，例如判断是否可以内联数组构造，以及根据类型反馈选择合适的元素类型。

3. **规范化数组元素 (`Runtime_NormalizeElements`)**:
   - 将数组的元素存储转换为更通用的形式。
   - 这通常在某些操作需要统一的元素访问方式时发生。

4. **扩展数组元素容量 (`Runtime_GrowArrayElements`)**:
   - 当向数组添加元素且当前容量不足时，此函数负责扩展数组的内部存储空间。
   - 它只针对快速元素类型的数组 (`FastElementsKind`)。

5. **判断是否为数组 (`Runtime_ArrayIsArray`, `Runtime_IsArray`)**:
   - 实现了 `Array.isArray()` 方法的功能，用于检查一个值是否为数组。

6. **获取数组的构造器 (`Runtime_ArraySpeciesConstructor`)**:
   - 用于支持 `Symbol.species`，允许子类化的数组控制派生方法（如 `map`, `slice`）返回的数组类型。

7. **数组包含判断 (`Runtime_ArrayIncludes_Slow`)**:
   - 实现了 `Array.prototype.includes()` 方法的慢速路径。
   - 它会遍历数组元素，检查是否包含指定的元素。由于带有 `_Slow` 后缀，说明 V8 内部可能存在更优化的快速路径。

8. **查找数组元素的索引 (`Runtime_ArrayIndexOf`)**:
   - 实现了 `Array.prototype.indexOf()` 方法。
   - 它在数组中查找指定元素的第一个匹配项，并返回其索引。同样，带有 `_Slow` 后缀暗示存在优化路径。

**关于 `.tq` 结尾：**

如果 `v8/src/runtime/runtime-array.cc` 以 `.tq` 结尾，那么它将是一个 **V8 Torque** 源代码文件。Torque 是 V8 使用的一种领域特定语言 (DSL)，用于更安全、更高效地编写 V8 的内置函数和运行时代码。目前这个文件是 `.cc`，所以是用 C++ 编写的。

**与 JavaScript 功能的关系及示例：**

这些 C++ 运行时函数直接支持着 JavaScript 中数组的各种操作。以下是一些示例：

1. **`Runtime_TransitionElementsKind`**: 当你向一个最初只包含整数的数组添加一个浮点数时，V8 可能会调用这个函数来将数组的元素类型从 `PACKED_SMI_ELEMENTS` 转换为 `PACKED_DOUBLE_ELEMENTS`。

   ```javascript
   const arr = [1, 2, 3]; // 内部可能是 PACKED_SMI_ELEMENTS
   arr.push(3.14);       // 触发元素类型转换
   console.log(arr);      // 输出: [1, 2, 3, 3.14]
   ```

2. **`Runtime_NewArray`**:  当你使用 `new Array()` 或字面量 `[]` 创建数组时，V8 最终会调用这个运行时函数。

   ```javascript
   const arr1 = new Array(5); // 调用 Runtime_NewArray，长度为 5
   const arr2 = [1, 'a', true]; // 调用 Runtime_NewArray，带有初始元素
   ```

3. **`Runtime_ArrayIsArray`**:

   ```javascript
   console.log(Array.isArray([1, 2, 3]));   // 输出: true
   console.log(Array.isArray({ length: 3 })); // 输出: false
   ```

4. **`Runtime_ArrayIncludes_Slow`**:

   ```javascript
   const arr = [1, 2, 'a', 4];
   console.log(arr.includes('a')); // 输出: true
   console.log(arr.includes(3));   // 输出: false
   ```

5. **`Runtime_ArrayIndexOf`**:

   ```javascript
   const arr = [10, 20, 30, 20];
   console.log(arr.indexOf(20));  // 输出: 1
   console.log(arr.indexOf(40));  // 输出: -1
   ```

**代码逻辑推理及假设输入输出：**

以 `Runtime_GrowArrayElements` 为例：

**假设输入:**

- `object`: 一个 JavaScript 数组对象，例如 `[1, 2, 3]`。
- `key`:  一个表示要访问或设置的索引的数字或字符串，例如 `5` 或 `"5"`。

**代码逻辑推理:**

1. 函数首先检查 `key` 是否为 Smi（小整数）。
2. 如果是 Smi 且为非负数，则将其转换为 `uint32_t` 类型的索引。
3. 如果不是 Smi，则尝试将其转换为 `HeapNumber`（堆上的数字）。
4. 如果 `key` 可以转换为非负的 `uint32_t` 索引，则检查该索引是否超出了数组当前的容量。
5. 如果超出容量，则调用 `object->GetElementsAccessor()->GrowCapacity()` 来扩展数组的内部存储。
6. 如果扩展成功，则返回数组的 elements 对象。如果失败（例如，内存分配失败），则可能返回一个表示失败的特殊值（在本例中是 `Smi::zero()`）。

**假设输出:**

- 如果 `key` 是 `5`，且数组初始容量不足以容纳索引 `5` 的元素，则数组的内部存储会被扩展，函数返回扩展后的 elements 对象。
- 如果 `key` 是 `-1`，函数会直接返回 `Smi::zero()`。
- 如果 `key` 是一个非常大的数，导致无法分配足够的内存， `GrowCapacity` 可能会失败，函数返回 `Smi::zero()`。

**用户常见的编程错误：**

1. **尝试给数组赋予负数或非整数索引:**  虽然 JavaScript 允许将属性名作为字符串添加到数组（这不会触发 `Runtime_GrowArrayElements`），但尝试通过负数或非整数数字访问数组元素通常不会按预期工作，并且在某些情况下可能会抛出错误。

   ```javascript
   const arr = [1, 2];
   arr[-1] = 10; // 不会修改数组的数字索引部分
   arr['a'] = 20; // 添加一个名为 'a' 的属性
   console.log(arr[-1]); // 输出: undefined
   console.log(arr.a);   // 输出: 20
   ```

2. **假设数组的内部元素类型是固定的:**  用户可能会错误地认为数组始终以相同的内部方式存储元素。但实际上，V8 会根据存储的元素类型动态调整，这可能会影响性能。

   ```javascript
   const arr1 = [1, 2, 3]; // 可能是 PACKED_SMI_ELEMENTS
   const arr2 = [1, 2, 'a']; // 可能会转换为更通用的类型，例如 PACKED_ELEMENTS
   ```

3. **过度依赖数组的“稀疏”特性:**  创建具有很大长度但只有少量元素的稀疏数组可能会导致意外的性能问题，因为 V8 可能需要处理大量的“空洞”。

   ```javascript
   const arr = new Array(1000);
   arr[999] = 1; // 创建一个稀疏数组
   console.log(arr.length); // 输出: 1000
   ```

总而言之，`v8/src/runtime/runtime-array.cc` 是 V8 引擎中处理 JavaScript 数组操作的核心部分，它包含了用于创建、修改和查询数组的底层实现。理解这些运行时函数的功能有助于深入了解 JavaScript 引擎的工作原理以及如何编写更高效的 JavaScript 代码。

Prompt: 
```
这是目录为v8/src/runtime/runtime-array.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/runtime/runtime-array.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/execution/arguments-inl.h"
#include "src/execution/isolate-inl.h"
#include "src/execution/protectors-inl.h"
#include "src/heap/factory.h"
#include "src/heap/heap-inl.h"  // For ToBoolean. TODO(jkummerow): Drop.
#include "src/objects/allocation-site-inl.h"
#include "src/objects/elements.h"
#include "src/objects/js-array-inl.h"

namespace v8 {
namespace internal {

RUNTIME_FUNCTION(Runtime_TransitionElementsKind) {
  HandleScope scope(isolate);
  DCHECK_EQ(2, args.length());
  Handle<JSObject> object = args.at<JSObject>(0);
  Handle<Map> to_map = args.at<Map>(1);
  ElementsKind to_kind = to_map->elements_kind();
  if (ElementsAccessor::ForKind(to_kind)
          ->TransitionElementsKind(object, to_map)
          .IsNothing()) {
    // TODO(victorgomes): EffectControlLinearizer::LowerTransitionElementsKind
    // does not handle exceptions.
    FATAL(
        "Fatal JavaScript invalid size error when transitioning elements kind");
    UNREACHABLE();
  }
  return *object;
}

RUNTIME_FUNCTION(Runtime_TransitionElementsKindWithKind) {
  HandleScope scope(isolate);
  DCHECK_EQ(2, args.length());
  Handle<JSObject> object = args.at<JSObject>(0);
  ElementsKind to_kind = static_cast<ElementsKind>(args.smi_value_at(1));
  JSObject::TransitionElementsKind(object, to_kind);
  return *object;
}

RUNTIME_FUNCTION(Runtime_NewArray) {
  HandleScope scope(isolate);
  DCHECK_LE(3, args.length());
  int const argc = args.length() - 3;
  // argv points to the arguments constructed by the JavaScript call.
  JavaScriptArguments argv(argc, args.address_of_arg_at(0));
  Handle<JSFunction> constructor = args.at<JSFunction>(argc);
  Handle<JSReceiver> new_target = args.at<JSReceiver>(argc + 1);
  Handle<HeapObject> type_info = args.at<HeapObject>(argc + 2);
  // TODO(bmeurer): Use MaybeHandle to pass around the AllocationSite.
  Handle<AllocationSite> site = IsAllocationSite(*type_info)
                                    ? Cast<AllocationSite>(type_info)
                                    : Handle<AllocationSite>::null();

  Factory* factory = isolate->factory();

  // If called through new, new.target can be:
  // - a subclass of constructor,
  // - a proxy wrapper around constructor, or
  // - the constructor itself.
  // If called through Reflect.construct, it's guaranteed to be a constructor by
  // REFLECT_CONSTRUCT_PREPARE.
  DCHECK(IsConstructor(*new_target));

  bool holey = false;
  bool can_use_type_feedback = !site.is_null();
  bool can_inline_array_constructor = true;
  if (argv.length() == 1) {
    DirectHandle<Object> argument_one = argv.at<Object>(0);
    if (IsSmi(*argument_one)) {
      int value = Cast<Smi>(*argument_one).value();
      if (value < 0 ||
          JSArray::SetLengthWouldNormalize(isolate->heap(), value)) {
        // the array is a dictionary in this case.
        can_use_type_feedback = false;
      } else if (value != 0) {
        holey = true;
        if (value >= JSArray::kInitialMaxFastElementArray) {
          can_inline_array_constructor = false;
        }
      }
    } else {
      // Non-smi length argument produces a dictionary
      can_use_type_feedback = false;
    }
  }

  Handle<Map> initial_map;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, initial_map,
      JSFunction::GetDerivedMap(isolate, constructor, new_target));

  ElementsKind to_kind = can_use_type_feedback ? site->GetElementsKind()
                                               : initial_map->elements_kind();
  if (holey && !IsHoleyElementsKind(to_kind)) {
    to_kind = GetHoleyElementsKind(to_kind);
    // Update the allocation site info to reflect the advice alteration.
    if (!site.is_null()) site->SetElementsKind(to_kind);
  }

  // We should allocate with an initial map that reflects the allocation site
  // advice. Therefore we use AllocateJSObjectFromMap instead of passing
  // the constructor.
  initial_map = Map::AsElementsKind(isolate, initial_map, to_kind);

  // If we don't care to track arrays of to_kind ElementsKind, then
  // don't emit a memento for them.
  DirectHandle<AllocationSite> allocation_site;
  if (AllocationSite::ShouldTrack(to_kind)) {
    allocation_site = site;
  }

  Handle<JSArray> array = Cast<JSArray>(factory->NewJSObjectFromMap(
      initial_map, AllocationType::kYoung, allocation_site));

  factory->NewJSArrayStorage(
      array, 0, 0, ArrayStorageAllocationMode::DONT_INITIALIZE_ARRAY_ELEMENTS);

  ElementsKind old_kind = array->GetElementsKind();
  RETURN_FAILURE_ON_EXCEPTION(isolate,
                              ArrayConstructInitializeElements(array, &argv));
  if (!site.is_null()) {
    if ((old_kind != array->GetElementsKind() || !can_use_type_feedback ||
         !can_inline_array_constructor)) {
      // The arguments passed in caused a transition. This kind of complexity
      // can't be dealt with in the inlined optimized array constructor case.
      // We must mark the allocationsite as un-inlinable.
      site->SetDoNotInlineCall();
    }
  } else {
    if (old_kind != array->GetElementsKind() || !can_inline_array_constructor) {
      // We don't have an AllocationSite for this Array constructor invocation,
      // i.e. it might a call from Array#map or from an Array subclass, so we
      // just flip the bit on the global protector cell instead.
      // TODO(bmeurer): Find a better way to mark this. Global protectors
      // tend to back-fire over time...
      if (Protectors::IsArrayConstructorIntact(isolate)) {
        Protectors::InvalidateArrayConstructor(isolate);
      }
    }
  }

  return *array;
}

RUNTIME_FUNCTION(Runtime_NormalizeElements) {
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());
  Handle<JSObject> array = args.at<JSObject>(0);
  CHECK(!array->HasTypedArrayOrRabGsabTypedArrayElements());
  CHECK(!IsJSGlobalProxy(*array));
  JSObject::NormalizeElements(array);
  return *array;
}

// GrowArrayElements grows fast kind elements and returns a sentinel Smi if the
// object was normalized or if the key is negative.
RUNTIME_FUNCTION(Runtime_GrowArrayElements) {
  HandleScope scope(isolate);
  DCHECK_EQ(2, args.length());
  Handle<JSObject> object = args.at<JSObject>(0);
  DirectHandle<Object> key = args.at(1);
  ElementsKind kind = object->GetElementsKind();
  CHECK(IsFastElementsKind(kind));
  uint32_t index;
  if (IsSmi(*key)) {
    int value = Smi::ToInt(*key);
    if (value < 0) return Smi::zero();
    index = static_cast<uint32_t>(value);
  } else {
    CHECK(IsHeapNumber(*key));
    double value = Cast<HeapNumber>(*key)->value();
    if (value < 0 || value > std::numeric_limits<uint32_t>::max()) {
      return Smi::zero();
    }
    index = static_cast<uint32_t>(value);
  }

  uint32_t capacity = static_cast<uint32_t>(object->elements()->length());

  if (index >= capacity) {
    bool has_grown;
    MAYBE_ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
        isolate, has_grown,
        object->GetElementsAccessor()->GrowCapacity(object, index));
    if (!has_grown) {
      return Smi::zero();
    }
  }

  return object->elements();
}

// ES6 22.1.2.2 Array.isArray
RUNTIME_FUNCTION(Runtime_ArrayIsArray) {
  HandleScope shs(isolate);
  DCHECK_EQ(1, args.length());
  Handle<Object> object = args.at(0);
  Maybe<bool> result = Object::IsArray(object);
  MAYBE_RETURN(result, ReadOnlyRoots(isolate).exception());
  return isolate->heap()->ToBoolean(result.FromJust());
}

RUNTIME_FUNCTION(Runtime_IsArray) {
  SealHandleScope shs(isolate);
  DCHECK_EQ(1, args.length());
  Tagged<Object> obj = args[0];
  return isolate->heap()->ToBoolean(IsJSArray(obj));
}

RUNTIME_FUNCTION(Runtime_ArraySpeciesConstructor) {
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());
  Handle<JSAny> original_array = args.at<JSAny>(0);
  RETURN_RESULT_OR_FAILURE(
      isolate, Object::ArraySpeciesConstructor(isolate, original_array));
}

// ES7 22.1.3.11 Array.prototype.includes
RUNTIME_FUNCTION(Runtime_ArrayIncludes_Slow) {
  HandleScope shs(isolate);
  DCHECK_EQ(3, args.length());
  Handle<Object> search_element = args.at(1);
  Handle<Object> from_index = args.at(2);

  // Let O be ? ToObject(this value).
  Handle<JSReceiver> object;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, object,
      Object::ToObject(isolate, Handle<Object>(args[0], isolate)));

  // Let len be ? ToLength(? Get(O, "length")).
  int64_t len;
  {
    if (object->map()->instance_type() == JS_ARRAY_TYPE) {
      uint32_t len32 = 0;
      bool success =
          Object::ToArrayLength(Cast<JSArray>(*object)->length(), &len32);
      DCHECK(success);
      USE(success);
      len = len32;
    } else {
      Handle<Object> len_;
      ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
          isolate, len_,
          Object::GetProperty(isolate, object,
                              isolate->factory()->length_string()));

      ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, len_,
                                         Object::ToLength(isolate, len_));
      len = static_cast<int64_t>(Object::NumberValue(*len_));
      DCHECK_EQ(len, Object::NumberValue(*len_));
    }
  }

  if (len == 0) return ReadOnlyRoots(isolate).false_value();

  // Let n be ? ToInteger(fromIndex). (If fromIndex is undefined, this step
  // produces the value 0.)
  int64_t index = 0;
  if (!IsUndefined(*from_index, isolate)) {
    ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, from_index,
                                       Object::ToInteger(isolate, from_index));

    if (V8_LIKELY(IsSmi(*from_index))) {
      int start_from = Smi::ToInt(*from_index);
      if (start_from < 0) {
        index = std::max<int64_t>(len + start_from, 0);
      } else {
        index = start_from;
      }
    } else {
      DCHECK(IsHeapNumber(*from_index));
      double start_from = Object::NumberValue(*from_index);
      if (start_from >= len) return ReadOnlyRoots(isolate).false_value();
      if (V8_LIKELY(std::isfinite(start_from))) {
        if (start_from < 0) {
          index = static_cast<int64_t>(std::max<double>(start_from + len, 0));
        } else {
          index = start_from;
        }
      }
    }

    DCHECK_GE(index, 0);
  }

  // If the receiver is not a special receiver type, and the length is a valid
  // element index, perform fast operation tailored to specific ElementsKinds.
  if (!IsSpecialReceiverMap(object->map()) &&
      len <= JSObject::kMaxElementCount &&
      JSObject::PrototypeHasNoElements(isolate, Cast<JSObject>(*object))) {
    Handle<JSObject> obj = Cast<JSObject>(object);
    ElementsAccessor* elements = obj->GetElementsAccessor();
    Maybe<bool> result =
        elements->IncludesValue(isolate, obj, search_element, index, len);
    MAYBE_RETURN(result, ReadOnlyRoots(isolate).exception());
    return *isolate->factory()->ToBoolean(result.FromJust());
  }

  // Otherwise, perform slow lookups for special receiver types.
  for (; index < len; ++index) {
    HandleScope iteration_hs(isolate);

    // Let elementK be the result of ? Get(O, ! ToString(k)).
    Handle<Object> element_k;
    {
      PropertyKey key(isolate, static_cast<double>(index));
      LookupIterator it(isolate, object, key);
      ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, element_k,
                                         Object::GetProperty(&it));
    }

    // If SameValueZero(searchElement, elementK) is true, return true.
    if (Object::SameValueZero(*search_element, *element_k)) {
      return ReadOnlyRoots(isolate).true_value();
    }
  }
  return ReadOnlyRoots(isolate).false_value();
}

RUNTIME_FUNCTION(Runtime_ArrayIndexOf) {
  HandleScope hs(isolate);
  DCHECK_EQ(3, args.length());
  Handle<Object> search_element = args.at(1);
  Handle<Object> from_index = args.at(2);

  // Let O be ? ToObject(this value).
  Handle<JSReceiver> object;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, object,
      Object::ToObject(isolate, args.at(0), "Array.prototype.indexOf"));

  // Let len be ? ToLength(? Get(O, "length")).
  int64_t len;
  {
    if (IsJSArray(*object)) {
      uint32_t len32 = 0;
      bool success =
          Object::ToArrayLength(Cast<JSArray>(*object)->length(), &len32);
      DCHECK(success);
      USE(success);
      len = len32;
    } else {
      Handle<Object> len_;
      ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
          isolate, len_,
          Object::GetProperty(isolate, object,
                              isolate->factory()->length_string()));

      ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, len_,
                                         Object::ToLength(isolate, len_));
      len = static_cast<int64_t>(Object::NumberValue(*len_));
      DCHECK_EQ(len, Object::NumberValue(*len_));
    }
  }

  if (len == 0) return Smi::FromInt(-1);

  // Let n be ? ToInteger(fromIndex). (If fromIndex is undefined, this step
  // produces the value 0.)
  int64_t start_from;
  {
    ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, from_index,
                                       Object::ToInteger(isolate, from_index));
    double fp = Object::NumberValue(*from_index);
    if (fp > len) return Smi::FromInt(-1);
    if (V8_LIKELY(fp >=
                  static_cast<double>(std::numeric_limits<int64_t>::min()))) {
      DCHECK(fp < static_cast<double>(std::numeric_limits<int64_t>::max()));
      start_from = static_cast<int64_t>(fp);
    } else {
      start_from = std::numeric_limits<int64_t>::min();
    }
  }

  int64_t index;
  if (start_from >= 0) {
    index = start_from;
  } else {
    index = len + start_from;
    if (index < 0) {
      index = 0;
    }
  }

  // If the receiver is not a special receiver type, and the length fits
  // uint32_t, perform fast operation tailored to specific ElementsKinds.
  if (!IsSpecialReceiverMap(object->map()) && len <= kMaxUInt32 &&
      JSObject::PrototypeHasNoElements(isolate, Cast<JSObject>(*object))) {
    Handle<JSObject> obj = Cast<JSObject>(object);
    ElementsAccessor* elements = obj->GetElementsAccessor();
    Maybe<int64_t> result = elements->IndexOfValue(isolate, obj, search_element,
                                                   static_cast<uint32_t>(index),
                                                   static_cast<uint32_t>(len));
    MAYBE_RETURN(result, ReadOnlyRoots(isolate).exception());
    return *isolate->factory()->NewNumberFromInt64(result.FromJust());
  }

  // Otherwise, perform slow lookups for special receiver types.
  for (; index < len; ++index) {
    HandleScope iteration_hs(isolate);
    // Let elementK be the result of ? Get(O, ! ToString(k)).
    Handle<Object> element_k;
    {
      PropertyKey key(isolate, static_cast<double>(index));
      LookupIterator it(isolate, object, key);
      Maybe<bool> present = JSReceiver::HasProperty(&it);
      MAYBE_RETURN(present, ReadOnlyRoots(isolate).exception());
      if (!present.FromJust()) continue;
      ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, element_k,
                                         Object::GetProperty(&it));
      if (Object::StrictEquals(*search_element, *element_k)) {
        return *isolate->factory()->NewNumberFromInt64(index);
      }
    }
  }
  return Smi::FromInt(-1);
}

}  // namespace internal
}  // namespace v8

"""

```