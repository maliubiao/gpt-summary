Response: Let's break down the thought process for analyzing this C++ file.

1. **Understand the Goal:** The request is to summarize the functionality of `runtime-array.cc` and illustrate its connection to JavaScript.

2. **Initial Scan for Keywords:**  I'll quickly scan the file looking for keywords that hint at the file's purpose. I see:
    * `Runtime_...`: This is a strong indicator of runtime functions, which are C++ implementations of JavaScript built-in methods or operations.
    * `Array`, `Elements`, `JSObject`:  These directly relate to JavaScript arrays and their underlying implementation.
    * `TransitionElementsKind`, `NewArray`, `NormalizeElements`, `GrowArrayElements`, `ArrayIsArray`, `ArraySpeciesConstructor`, `ArrayIncludes_Slow`, `ArrayIndexOf`. These look like specific array-related operations.

3. **Categorize Runtime Functions:**  I'll group the runtime functions based on what they seem to be doing:

    * **Element Kind Manipulation:** `Runtime_TransitionElementsKind`, `Runtime_TransitionElementsKindWithKind`, `Runtime_NormalizeElements`, `Runtime_GrowArrayElements`. These clearly deal with how array elements are stored in memory (e.g., integers, doubles, objects, packed vs. sparse).

    * **Array Creation:** `Runtime_NewArray`. This seems to be the core function for creating new JavaScript arrays.

    * **Array Type Checking:** `Runtime_ArrayIsArray`, `Runtime_IsArray`, `Runtime_ArraySpeciesConstructor`. These are about determining if something is an array or what kind of array it is.

    * **Array Searching:** `Runtime_ArrayIncludes_Slow`, `Runtime_ArrayIndexOf`. These are implementations of `Array.prototype.includes` and `Array.prototype.indexOf`. The `_Slow` suffix suggests there might be faster, optimized versions elsewhere.

4. **Analyze Each Function's Purpose:**  For each runtime function, I'll try to understand its specific role based on its name and the C++ code (even if I don't understand all the C++ details).

    * **`TransitionElementsKind`:** Changes how elements are stored internally. This is related to JavaScript's dynamic nature and how arrays can hold different types of elements.

    * **`TransitionElementsKindWithKind`:**  Similar to the above, but takes the target element kind directly.

    * **`NewArray`:**  Handles the logic for `new Array()`, including handling the length argument and potentially optimizing the internal representation based on the provided arguments and "allocation sites."

    * **`NormalizeElements`:** Converts an array to a more standard representation (likely a "packed" array if it was sparse).

    * **`GrowArrayElements`:**  Handles increasing the internal storage capacity of an array when a new element is added beyond the current limits. The "sentinel Smi" return for normalization is an interesting detail.

    * **`ArrayIsArray` and `IsArray`:**  Implement the `Array.isArray()` check. The presence of two slightly different versions (`ArrayIsArray` calling `Object::IsArray`) suggests possible nuances or historical reasons.

    * **`ArraySpeciesConstructor`:**  Deals with the `Symbol.species` mechanism for controlling the constructor used in methods like `map` and `slice`.

    * **`ArrayIncludes_Slow` and `ArrayIndexOf`:**  Implement the core logic of these array methods, including handling `fromIndex`, `ToObject`, `ToLength`, and the actual searching using `SameValueZero` and `StrictEquals`. The "slow" suffix is important – it implies these are general implementations, and optimized versions might exist. The code comments about "special receiver types" and "fast operation tailored to specific ElementsKinds" are key.

5. **Connect to JavaScript:** For each category of functionality, I'll think of corresponding JavaScript examples that would trigger these runtime functions. This requires understanding how JavaScript array operations map to V8's internal workings.

    * **Element Kind:**  Show how adding different types of elements to an array can trigger transitions.

    * **Array Creation:** Demonstrate the different ways to create arrays (with a length, with initial values, using the `new` keyword).

    * **Array Type Checking:**  Simple examples of using `Array.isArray()`.

    * **Array Searching:**  Basic usage of `includes()` and `indexOf()`, and perhaps edge cases like searching for `NaN`.

6. **Structure the Summary:** I'll organize the information logically, starting with a general overview and then diving into the details of each category of runtime function. Using bullet points and code examples will make the explanation clearer. Emphasizing the connection between C++ code and JavaScript behavior is crucial.

7. **Refine and Clarify:** After drafting the summary, I'll review it for clarity, accuracy, and completeness. Are the JavaScript examples relevant? Is the explanation of the C++ functions understandable without deep C++ knowledge?  For instance, highlighting the performance implications of element kind transitions and the existence of optimized paths is important. Explaining the concept of "allocation sites" in the context of `NewArray` adds valuable depth.

By following these steps, I can systematically analyze the C++ code and generate a comprehensive and informative summary that addresses the user's request. The process involves understanding the purpose of the code, connecting it to JavaScript concepts, and presenting the information in a clear and organized manner.
这个C++源代码文件 `v8/src/runtime/runtime-array.cc` 实现了 V8 JavaScript 引擎中与 **数组 (Array)** 相关的 **运行时 (Runtime)** 功能。这些运行时函数是 C++ 代码，用于执行一些 JavaScript 中数组的内置方法和操作，因为某些操作在 JavaScript 中无法直接实现或在 C++ 中执行效率更高。

**主要功能归纳:**

* **数组元素类型转换 (Transitioning Elements Kind):**  
    * `Runtime_TransitionElementsKind` 和 `Runtime_TransitionElementsKindWithKind` 用于改变数组内部存储元素的类型 (ElementsKind)。JavaScript 数组是动态的，可以包含不同类型的元素。V8 内部会根据数组中元素的类型使用不同的存储方式 (例如，只包含整数、包含浮点数、包含任意对象等) 以优化性能。这两个函数负责在需要时进行这种内部存储类型的转换。
* **数组创建 (Array Creation):**
    * `Runtime_NewArray` 是创建新的 JavaScript 数组的运行时函数。它处理各种创建数组的方式，包括指定长度、传入初始元素等。这个函数会根据传入的参数和 V8 内部的优化策略来初始化数组的内部结构和元素存储。
* **数组元素规范化 (Normalizing Elements):**
    * `Runtime_NormalizeElements` 用于将数组的元素存储方式规范化。这通常发生在数组的元素变得稀疏或者类型发生变化时，需要转换为一种更通用的存储方式。
* **数组元素扩容 (Growing Array Elements):**
    * `Runtime_GrowArrayElements` 负责在需要向数组添加元素，但当前数组的内部存储空间不足时，进行扩容操作。它会根据新的索引值来扩展数组的容量。
* **判断是否为数组 (Is Array Check):**
    * `Runtime_ArrayIsArray` 和 `Runtime_IsArray` 实现了 JavaScript 中 `Array.isArray()` 方法的功能，用于判断一个对象是否为数组。
* **获取数组的构造函数 (Array Species Constructor):**
    * `Runtime_ArraySpeciesConstructor` 与 ES6 中引入的 `Symbol.species` 机制相关。它用于确定在派生数组类的方法 (如 `map`, `slice`) 中应该使用哪个构造函数来创建新的数组实例。
* **数组包含性检查 (Array Includes):**
    * `Runtime_ArrayIncludes_Slow` 实现了 `Array.prototype.includes()` 方法的功能，用于检查数组中是否包含指定的元素。函数名中的 `_Slow` 可能意味着存在更快的内部优化版本。
* **数组索引查找 (Array Index Of):**
    * `Runtime_ArrayIndexOf` 实现了 `Array.prototype.indexOf()` 方法的功能，用于查找数组中指定元素的第一个索引。

**与 JavaScript 功能的关系及示例:**

这个文件中的运行时函数是 V8 引擎为了执行 JavaScript 代码而提供的底层实现。当你在 JavaScript 中执行数组相关的操作时，V8 引擎会调用这些 C++ 运行时函数来完成具体的工作。

**JavaScript 示例:**

1. **数组元素类型转换 (`Runtime_TransitionElementsKind`)**:

   ```javascript
   const arr = [1, 2, 3]; // 初始可能是 PACKED_SMI_ELEMENTS (紧凑存储小整数)
   arr.push(3.14);      // 添加浮点数，可能触发到 PACKED_DOUBLE_ELEMENTS 的转换
   arr.push({});        // 添加对象，可能触发到 PACKED_ELEMENTS 的转换
   ```
   在这个例子中，当向数组 `arr` 添加不同类型的元素时，V8 内部可能会调用 `Runtime_TransitionElementsKind` 或 `Runtime_TransitionElementsKindWithKind` 来改变数组内部的元素存储方式。

2. **数组创建 (`Runtime_NewArray`)**:

   ```javascript
   const arr1 = [];          // 调用 Runtime_NewArray 创建空数组
   const arr2 = [1, 2, 3];   // 调用 Runtime_NewArray 创建并初始化数组
   const arr3 = new Array(5); // 调用 Runtime_NewArray 创建指定长度的数组
   const arr4 = new Array(1, 2); // 调用 Runtime_NewArray 创建并初始化数组
   ```
   所有这些创建数组的方式都会最终调用 `Runtime_NewArray` 在 V8 内部创建数组对象并分配内存。

3. **数组元素规范化 (`Runtime_NormalizeElements`)**:

   ```javascript
   const arr = [];
   arr[99] = 1; // 创建一个稀疏数组
   // 当对稀疏数组进行某些操作时，可能会触发规范化
   ```
   某些对稀疏数组的操作，例如使用 `map` 或 `filter`，可能会导致 V8 调用 `Runtime_NormalizeElements` 将数组转换为更密集的表示。

4. **数组元素扩容 (`Runtime_GrowArrayElements`)**:

   ```javascript
   const arr = [1, 2, 3];
   arr[10] = 4; // 当索引超出当前数组容量时，会调用 Runtime_GrowArrayElements
   ```
   当试图访问或设置数组超出当前长度的索引时，如果需要，V8 会调用 `Runtime_GrowArrayElements` 来增加数组的内部存储空间。

5. **判断是否为数组 (`Runtime_ArrayIsArray`, `Runtime_IsArray`)**:

   ```javascript
   const arr = [];
   Array.isArray(arr); // V8 会调用 Runtime_ArrayIsArray
   ```
   `Array.isArray()` 方法的底层实现就是 `Runtime_ArrayIsArray`。

6. **获取数组的构造函数 (`Runtime_ArraySpeciesConstructor`)**:

   ```javascript
   class MyArray extends Array {}
   const myArray = new MyArray(1, 2, 3);
   const mappedArray = myArray.map(x => x * 2); // mappedArray 的构造函数由 Symbol.species 决定，可能涉及 Runtime_ArraySpeciesConstructor
   ```
   当在派生的数组类上使用 `map` 等方法时，V8 会使用 `Runtime_ArraySpeciesConstructor` 来确定新数组的构造函数。

7. **数组包含性检查 (`Runtime_ArrayIncludes_Slow`)**:

   ```javascript
   const arr = [1, 2, 3];
   arr.includes(2); // V8 会调用 Runtime_ArrayIncludes_Slow
   ```
   `Array.prototype.includes()` 方法的实现之一是 `Runtime_ArrayIncludes_Slow`.

8. **数组索引查找 (`Runtime_ArrayIndexOf`)**:

   ```javascript
   const arr = [1, 2, 3, 2];
   arr.indexOf(2);  // V8 会调用 Runtime_ArrayIndexOf，返回 1
   arr.indexOf(2, 2); // V8 会调用 Runtime_ArrayIndexOf，从索引 2 开始查找，返回 3
   ```
   `Array.prototype.indexOf()` 方法的实现就是 `Runtime_ArrayIndexOf`.

总而言之，`v8/src/runtime/runtime-array.cc` 文件是 V8 引擎中处理 JavaScript 数组核心操作的 C++ 代码，它直接支持了 JavaScript 中各种数组相关的内置方法和语法特性。理解这些运行时函数有助于深入了解 JavaScript 数组在 V8 引擎内部是如何工作的。

Prompt: 
```
这是目录为v8/src/runtime/runtime-array.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

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