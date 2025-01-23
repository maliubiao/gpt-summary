Response:
Let's break down the thought process for analyzing this C++ code snippet from `v8/src/objects/elements.cc`.

**1. Initial Understanding and Context:**

* **File Location:** The path `v8/src/objects/elements.cc` immediately suggests this file deals with the internal representation of JavaScript object elements within the V8 engine. The `.cc` extension confirms it's C++ source code.
* **"Elements":**  The term "elements" strongly points to arrays and object properties stored in an indexed manner.
* **V8:** Knowing this is V8 code means it's part of a high-performance JavaScript engine, so efficiency and careful memory management will be important themes.
* **Classes and Templates:** The code uses C++ classes and templates extensively. This indicates a design pattern focusing on code reuse and handling different element types efficiently. The `Subclass` and `KindTraits` template parameters are key to understanding this pattern.

**2. Deconstructing the Code Snippet:**

* **`PushImpl` and `UnshiftImpl`:** These function names are immediately recognizable as JavaScript array methods. They operate on a `JSArray` and take `BuiltinArguments`. The `push_size` and `unshift_size` parameters hint at adding multiple elements. The `AT_END` and `AT_START` constants further confirm their behavior.
* **`MoveElements`:** This function appears to be a lower-level utility for shifting elements within the array's backing store. The parameters `dst_index`, `src_index`, and `len` are typical for move/copy operations. The handling of `hole_start` and `hole_end` suggests dealing with sparse arrays or optimization related to "holes."
* **`FillImpl`:** Another recognizable JavaScript array method. It takes a `receiver`, `obj_value`, `start`, and `end`, aligning perfectly with the `Array.prototype.fill()` functionality. The checks for array bounds and COW (Copy-on-Write) are V8-specific optimizations.
* **`IncludesValueImpl`:**  This clearly implements the `Array.prototype.includes()` method. The logic involves handling different element types (Smis, objects, doubles), special values like `undefined` and "the hole," and NaNs. The conditional logic based on `Subclass::kind()` is crucial for understanding how V8 optimizes for different array element types.
* **`CreateListFromArrayLikeImpl`:**  This function takes a `JSObject` and a `length`, suggesting the creation of a new array-like structure from an existing object. The loop iterates through the elements and potentially internalizes names.
* **`RemoveElement`:**  Likely related to `pop()` or `shift()`. The `remove_position` parameter clarifies whether to remove from the beginning or end.
* **`AddArguments`:**  Used by `push` and `unshift`. It handles resizing the backing store and copying arguments into the array.
* **`CopyArguments`:** A utility for efficiently copying arguments into the backing store.
* **Class Hierarchy with Templates:** The `FastElementsAccessor`, `FastSmiOrObjectElementsAccessor`, `FastDoubleElementsAccessor`, and their specialized subclasses (`FastPackedSmiElementsAccessor`, etc.) show a clear strategy for handling different element types (Smis, objects, doubles) in optimized ways. The template pattern allows sharing common logic while specializing for specific element kinds. The "Fast" prefix implies these are optimizations for common cases.
* **Non-Extensible, Sealed, and Frozen Variations:** The existence of `FastNonextensibleObjectElementsAccessor`, `FastSealedObjectElementsAccessor`, and `FastFrozenObjectElementsAccessor` indicates how V8 handles arrays with these specific properties, often by preventing certain operations or transitioning to a dictionary-based representation.

**3. Inferring Functionality and Relationships:**

* **Core Array Operations:** The presence of `push`, `unshift`, `fill`, `includes`, `pop`, and methods related to adding/removing elements clearly points to this file's role in implementing core JavaScript array functionalities.
* **Optimization by Element Kind:** The extensive use of templates and specialized classes for different element kinds (PACKED_SMI, HOLEY_DOUBLE, etc.) is a major optimization strategy in V8. It allows the engine to operate more efficiently based on the types of data stored in the array.
* **Backing Store Management:** The code interacts directly with `FixedArrayBase` and `BackingStore`, which are V8's internal representations for storing array elements. This confirms its role in low-level memory management for arrays.
* **Handling of "Holes":** The frequent mention of "the hole" indicates how V8 represents missing elements in sparse arrays, optimizing for memory usage.
* **Transitions and Normalization:**  The code in the `SetLengthImpl` methods of sealed and non-extensible arrays suggests that when these arrays are modified in ways that violate their constraints, V8 might transition them to a slower, dictionary-based representation to maintain correctness.

**4. Connecting to JavaScript and Examples:**

* **Relating C++ to JavaScript:** For each of the identified core array operations (`push`, `unshift`, `fill`, `includes`), it's straightforward to provide corresponding JavaScript examples.
* **Illustrating Element Kind Optimization:** While the C++ code directly deals with element kinds, the JavaScript examples can implicitly show how these optimizations come into play. For example, creating an array of only integers might lead V8 to use `PACKED_SMI_ELEMENTS` internally.

**5. Identifying Potential Errors:**

* **Type Mismatches:** The strict type checking in the `IncludesValueImpl` highlights potential errors if a user tries to search for a value of the wrong type in an array with a specific element kind.
* **Modifying Non-Extensible/Sealed/Frozen Arrays:** The code explicitly throws `UNREACHABLE()` in many methods of the non-extensible, sealed, and frozen accessors, demonstrating common errors users might encounter when trying to modify these types of arrays.
* **Performance Implications:**  While not a direct error, understanding the different element kinds helps explain why certain array operations might be faster or slower depending on the array's internal representation.

**6. Structuring the Output:**

The final step involves organizing the gathered information into a clear and structured output, covering the requested points: functionality, Torque (if applicable), JavaScript examples, code logic, common errors, and a summary. The key is to link the C++ code directly to its corresponding JavaScript behavior and explain the underlying mechanisms and optimizations.
好的，让我们来分析一下 `v8/src/objects/elements.cc` 的这段代码。

**功能归纳:**

这段代码是 V8 引擎中 `elements.cc` 文件的一部分，它主要负责实现 JavaScript 数组和类数组对象的元素操作。更具体地说，这段代码定义了用于处理不同元素类型（例如，Smi、Object、Double）的快速数组实现的各种操作，例如：

* **添加元素:** `PushImpl`, `UnshiftImpl`, `AddArguments` 用于在数组的末尾或开头添加元素。
* **移动元素:** `MoveElements` 用于在数组内部移动元素，这通常是 `unshift` 操作的一部分。
* **填充元素:** `FillImpl` 用于使用静态值填充数组的一部分。
* **查找元素:** `IncludesValueImpl` 用于检查数组是否包含特定的值。
* **创建列表:** `CreateListFromArrayLikeImpl` 用于将类数组对象转换为真正的数组。
* **删除元素:** `RemoveElement` 用于从数组的开头或末尾删除元素 (对应 `shift` 和 `pop`)。
* **复制元素:** `CopyArguments` 用于将参数复制到数组的存储中。
* **获取和设置元素:** 通过模板类 `FastSmiOrObjectElementsAccessor` 和 `FastDoubleElementsAccessor` 提供了针对不同元素类型的 `SetImpl` 和 `GetImpl` 方法。
* **处理不同类型的数组:** 通过模板类和继承，代码针对不同类型的数组元素（例如，只包含 Smi、包含任意对象、包含浮点数）提供了优化的实现。这些类型由 `ElementsKind` 枚举表示。
* **处理固定长度和不可扩展数组:** 代码中包含对 `PACKED_FROZEN_ELEMENTS`, `PACKED_SEALED_ELEMENTS`, `PACKED_NONEXTENSIBLE_ELEMENTS` 等类型的处理，这些类型限制了数组的修改能力。
* **原子操作:**  `SharedArrayElementsAccessor` 提供了对共享数组的原子操作支持。

**关于 Torque:**

这段代码是以 `.cc` 结尾的，所以它不是 V8 Torque 源代码。V8 Torque 源代码文件以 `.tq` 结尾。

**与 JavaScript 功能的关系及示例:**

这段 C++ 代码直接对应了 JavaScript 中数组的各种操作。以下是一些 JavaScript 示例，说明了这段 C++ 代码中实现的功能：

* **`PushImpl`:** 对应 `Array.prototype.push()`
   ```javascript
   const arr = [1, 2, 3];
   arr.push(4); // 内部会调用 PushImpl 相关的 C++ 代码
   console.log(arr); // 输出: [1, 2, 3, 4]
   ```

* **`UnshiftImpl`:** 对应 `Array.prototype.unshift()`
   ```javascript
   const arr = [2, 3, 4];
   arr.unshift(1); // 内部会调用 UnshiftImpl 相关的 C++ 代码
   console.log(arr); // 输出: [1, 2, 3, 4]
   ```

* **`FillImpl`:** 对应 `Array.prototype.fill()`
   ```javascript
   const arr = [1, 2, 3];
   arr.fill(0, 1, 3); // 内部会调用 FillImpl 相关的 C++ 代码
   console.log(arr); // 输出: [1, 0, 0]
   ```

* **`IncludesValueImpl`:** 对应 `Array.prototype.includes()`
   ```javascript
   const arr = [1, 2, 3];
   const includesTwo = arr.includes(2); // 内部会调用 IncludesValueImpl 相关的 C++ 代码
   console.log(includesTwo); // 输出: true
   ```

* **`RemoveElement` (对应 `pop`)**: 对应 `Array.prototype.pop()`
   ```javascript
   const arr = [1, 2, 3];
   const last = arr.pop(); // 内部会调用 RemoveElement 相关的 C++ 代码
   console.log(arr);    // 输出: [1, 2]
   console.log(last);   // 输出: 3
   ```

* **`RemoveElement` (对应 `shift`)**: 对应 `Array.prototype.shift()`
   ```javascript
   const arr = [1, 2, 3];
   const first = arr.shift(); // 内部会调用 RemoveElement 相关的 C++ 代码
   console.log(arr);     // 输出: [2, 3]
   console.log(first);   // 输出: 1
   ```

**代码逻辑推理 (假设输入与输出):**

**假设输入 (针对 `IncludesValueImpl`):**

* `receiver`: 一个 JavaScript 数组对象 `[1, 2, "hello", 3.14]`，其元素类型可能是 `PACKED_ELEMENTS` 或 `HOLEY_ELEMENTS`。
* `search_value`:  JavaScript 值 `2`。
* `start_from`: `0`。
* `length`: `4` (数组的长度)。

**预期输出:**

`Just(true)`，因为数组中包含值 `2`。

**假设输入 (针对 `FillImpl`):**

* `receiver`: 一个 JavaScript 数组对象 `[1, 2, 3]`。
* `obj_value`: JavaScript 值 `0`.
* `start`: `1`.
* `end`: `3`.

**预期输出:**

`MaybeHandle<Object>` 指向修改后的数组对象，其内容为 `[1, 0, 0]`。

**用户常见的编程错误及示例:**

* **尝试修改不可扩展的数组:**
   ```javascript
   const arr = [1, 2, 3];
   Object.preventExtensions(arr);
   arr.push(4); // TypeError: Cannot add property 3, object is not extensible
   // 这会在 C++ 代码中触发相应的检查或抛出异常。
   ```
   在 C++ 代码中，例如 `FastPackedNonextensibleObjectElementsAccessor::PushImpl` 中，会直接 `UNREACHABLE()`，表示这种操作不应该发生。

* **尝试修改密封的数组:**
   ```javascript
   const arr = [1, 2, 3];
   Object.seal(arr);
   arr.push(4);         // TypeError: Cannot add property 3, object is sealed.
   arr[0] = 5;          // 有效
   delete arr[1];       // TypeError: Cannot delete property '1' of #<Array>
   Object.defineProperty(arr, 'length', { value: 2 }); // TypeError: Cannot redefine property length
   // C++ 中 `FastPackedSealedObjectElementsAccessor` 的相关方法会阻止这些操作。
   ```

* **尝试修改冻结的数组:**
   ```javascript
   const arr = [1, 2, 3];
   Object.freeze(arr);
   arr.push(4);     // TypeError: Cannot add property 3, object is frozen
   arr[0] = 5;      // TypeError: Cannot assign to read only property '0' of object '#<Array>'
   delete arr[1];   // TypeError: Cannot delete property '1' of #<Array>
   // C++ 中 `FastPackedFrozenObjectElementsAccessor` 的相关方法会阻止这些操作。
   ```

* **类型错误在使用 `includes` 或其他查找方法时:**
   ```javascript
   const arr = [1, 2, "3"];
   arr.includes(3); // 返回 false，因为类型不同 (number vs string)
   // C++ 代码中 `IncludesValueImpl` 会进行严格的类型比较。
   ```

**第 4 部分功能归纳:**

这段代码是 V8 引擎中处理 JavaScript 数组元素操作的核心部分。它通过模板和继承的机制，为不同类型的数组（基于其存储的元素类型和是否可扩展、密封、冻结）提供了优化的添加、删除、移动、查找和填充元素的方法。 这段代码直接支撑了 JavaScript 中数组的各种内置方法的功能。

### 提示词
```
这是目录为v8/src/objects/elements.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/elements.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共8部分，请归纳一下它的功能
```

### 源代码
```cpp
ushImpl(Handle<JSArray> receiver,
                                  BuiltinArguments* args, uint32_t push_size) {
    Handle<FixedArrayBase> backing_store(receiver->elements(),
                                         receiver->GetIsolate());
    return Subclass::AddArguments(receiver, backing_store, args, push_size,
                                  AT_END);
  }

  static Maybe<uint32_t> UnshiftImpl(Handle<JSArray> receiver,
                                     BuiltinArguments* args,
                                     uint32_t unshift_size) {
    Handle<FixedArrayBase> backing_store(receiver->elements(),
                                         receiver->GetIsolate());
    return Subclass::AddArguments(receiver, backing_store, args, unshift_size,
                                  AT_START);
  }

  static void MoveElements(Isolate* isolate, DirectHandle<JSArray> receiver,
                           Handle<FixedArrayBase> backing_store, int dst_index,
                           int src_index, int len, int hole_start,
                           int hole_end) {
    DisallowGarbageCollection no_gc;
    Tagged<BackingStore> dst_elms = Cast<BackingStore>(*backing_store);
    if (len > JSArray::kMaxCopyElements && dst_index == 0 &&
        isolate->heap()->CanMoveObjectStart(dst_elms)) {
      dst_elms = Cast<BackingStore>(
          isolate->heap()->LeftTrimFixedArray(dst_elms, src_index));
      // Update all the copies of this backing_store handle.
      backing_store.PatchValue(dst_elms);
      receiver->set_elements(dst_elms);
      // Adjust the hole offset as the array has been shrunk.
      hole_end -= src_index;
      DCHECK_LE(hole_start, backing_store->length());
      DCHECK_LE(hole_end, backing_store->length());
    } else if (len != 0) {
      WriteBarrierMode mode =
          GetWriteBarrierMode(dst_elms, KindTraits::Kind, no_gc);
      dst_elms->MoveElements(isolate, dst_index, src_index, len, mode);
    }
    if (hole_start != hole_end) {
      dst_elms->FillWithHoles(hole_start, hole_end);
    }
  }

  static MaybeHandle<Object> FillImpl(Handle<JSObject> receiver,
                                      DirectHandle<Object> obj_value,
                                      size_t start, size_t end) {
    // Ensure indexes are within array bounds
    DCHECK_LE(0, start);
    DCHECK_LE(start, end);

    // Make sure COW arrays are copied.
    if (IsSmiOrObjectElementsKind(Subclass::kind())) {
      JSObject::EnsureWritableFastElements(receiver);
    }

    // Make sure we have enough space.
    DCHECK_LE(end, std::numeric_limits<uint32_t>::max());
    if (end > Subclass::GetCapacityImpl(*receiver, receiver->elements())) {
      MAYBE_RETURN_NULL(Subclass::GrowCapacityAndConvertImpl(
          receiver, static_cast<uint32_t>(end)));
      CHECK_EQ(Subclass::kind(), receiver->GetElementsKind());
    }
    DCHECK_LE(end, Subclass::GetCapacityImpl(*receiver, receiver->elements()));

    for (size_t index = start; index < end; ++index) {
      Subclass::SetImpl(receiver, InternalIndex(index), *obj_value);
    }
    return MaybeHandle<Object>(receiver);
  }

  static Maybe<bool> IncludesValueImpl(Isolate* isolate,
                                       DirectHandle<JSObject> receiver,
                                       DirectHandle<Object> search_value,
                                       size_t start_from, size_t length) {
    DCHECK(JSObject::PrototypeHasNoElements(isolate, *receiver));
    DisallowGarbageCollection no_gc;
    Tagged<FixedArrayBase> elements_base = receiver->elements();
    Tagged<Object> the_hole = ReadOnlyRoots(isolate).the_hole_value();
    Tagged<Object> undefined = ReadOnlyRoots(isolate).undefined_value();
    Tagged<Object> value = *search_value;

    if (start_from >= length) return Just(false);

    // Elements beyond the capacity of the backing store treated as undefined.
    size_t elements_length = static_cast<size_t>(elements_base->length());
    if (value == undefined && elements_length < length) return Just(true);
    if (elements_length == 0) {
      DCHECK_NE(value, undefined);
      return Just(false);
    }

    length = std::min(elements_length, length);
    DCHECK_LE(length, std::numeric_limits<int>::max());

    if (!IsNumber(value)) {
      if (value == undefined) {
        // Search for `undefined` or The Hole. Even in the case of
        // PACKED_DOUBLE_ELEMENTS or PACKED_SMI_ELEMENTS, we might encounter The
        // Hole here, since the {length} used here can be larger than
        // JSArray::length.
        if (IsSmiOrObjectElementsKind(Subclass::kind()) ||
            IsAnyNonextensibleElementsKind(Subclass::kind())) {
          Tagged<FixedArray> elements = Cast<FixedArray>(receiver->elements());

          for (size_t k = start_from; k < length; ++k) {
            Tagged<Object> element_k = elements->get(static_cast<int>(k));

            if (element_k == the_hole || element_k == undefined) {
              return Just(true);
            }
          }
          return Just(false);
        } else {
          // Search for The Hole in HOLEY_DOUBLE_ELEMENTS or
          // PACKED_DOUBLE_ELEMENTS.
          DCHECK(IsDoubleElementsKind(Subclass::kind()));
          Tagged<FixedDoubleArray> elements =
              Cast<FixedDoubleArray>(receiver->elements());

          for (size_t k = start_from; k < length; ++k) {
            if (elements->is_the_hole(static_cast<int>(k))) return Just(true);
          }
          return Just(false);
        }
      } else if (!IsObjectElementsKind(Subclass::kind()) &&
                 !IsAnyNonextensibleElementsKind(Subclass::kind())) {
        // Search for non-number, non-Undefined value, with either
        // PACKED_SMI_ELEMENTS, PACKED_DOUBLE_ELEMENTS, HOLEY_SMI_ELEMENTS or
        // HOLEY_DOUBLE_ELEMENTS. Guaranteed to return false, since these
        // elements kinds can only contain Number values or undefined.
        return Just(false);
      } else {
        // Search for non-number, non-Undefined value with either
        // PACKED_ELEMENTS or HOLEY_ELEMENTS.
        DCHECK(IsObjectElementsKind(Subclass::kind()) ||
               IsAnyNonextensibleElementsKind(Subclass::kind()));
        Tagged<FixedArray> elements = Cast<FixedArray>(receiver->elements());

        for (size_t k = start_from; k < length; ++k) {
          Tagged<Object> element_k = elements->get(static_cast<int>(k));
          if (element_k == the_hole) continue;
          if (Object::SameValueZero(value, element_k)) return Just(true);
        }
        return Just(false);
      }
    } else {
      if (!IsNaN(value)) {
        double search_number = Object::NumberValue(value);
        if (IsDoubleElementsKind(Subclass::kind())) {
          // Search for non-NaN Number in PACKED_DOUBLE_ELEMENTS or
          // HOLEY_DOUBLE_ELEMENTS --- Skip TheHole, and trust UCOMISD or
          // similar operation for result.
          Tagged<FixedDoubleArray> elements =
              Cast<FixedDoubleArray>(receiver->elements());

          for (size_t k = start_from; k < length; ++k) {
            if (elements->is_the_hole(static_cast<int>(k))) continue;
            if (elements->get_scalar(static_cast<int>(k)) == search_number) {
              return Just(true);
            }
          }
          return Just(false);
        } else {
          // Search for non-NaN Number in PACKED_ELEMENTS, HOLEY_ELEMENTS,
          // PACKED_SMI_ELEMENTS or HOLEY_SMI_ELEMENTS --- Skip non-Numbers,
          // and trust UCOMISD or similar operation for result
          Tagged<FixedArray> elements = Cast<FixedArray>(receiver->elements());

          for (size_t k = start_from; k < length; ++k) {
            Tagged<Object> element_k = elements->get(static_cast<int>(k));
            if (IsNumber(element_k) &&
                Object::NumberValue(element_k) == search_number) {
              return Just(true);
            }
          }
          return Just(false);
        }
      } else {
        // Search for NaN --- NaN cannot be represented with Smi elements, so
        // abort if ElementsKind is PACKED_SMI_ELEMENTS or HOLEY_SMI_ELEMENTS
        if (IsSmiElementsKind(Subclass::kind())) return Just(false);

        if (IsDoubleElementsKind(Subclass::kind())) {
          // Search for NaN in PACKED_DOUBLE_ELEMENTS or
          // HOLEY_DOUBLE_ELEMENTS --- Skip The Hole and trust
          // std::isnan(elementK) for result
          Tagged<FixedDoubleArray> elements =
              Cast<FixedDoubleArray>(receiver->elements());

          for (size_t k = start_from; k < length; ++k) {
            if (elements->is_the_hole(static_cast<int>(k))) continue;
            if (std::isnan(elements->get_scalar(static_cast<int>(k)))) {
              return Just(true);
            }
          }
          return Just(false);
        } else {
          // Search for NaN in PACKED_ELEMENTS or HOLEY_ELEMENTS. Return true
          // if elementK->IsHeapNumber() && std::isnan(elementK->Number())
          DCHECK(IsObjectElementsKind(Subclass::kind()) ||
                 IsAnyNonextensibleElementsKind(Subclass::kind()));
          Tagged<FixedArray> elements = Cast<FixedArray>(receiver->elements());

          for (size_t k = start_from; k < length; ++k) {
            if (IsNaN(elements->get(static_cast<int>(k)))) return Just(true);
          }
          return Just(false);
        }
      }
    }
  }

  static Handle<FixedArray> CreateListFromArrayLikeImpl(
      Isolate* isolate, DirectHandle<JSObject> object, uint32_t length) {
    Handle<FixedArray> result = isolate->factory()->NewFixedArray(length);
    DirectHandle<FixedArrayBase> elements(object->elements(), isolate);
    for (uint32_t i = 0; i < length; i++) {
      InternalIndex entry(i);
      if (!Subclass::HasEntryImpl(isolate, *elements, entry)) continue;
      Handle<Object> value;
      value = Subclass::GetImpl(isolate, *elements, entry);
      if (IsName(*value)) {
        value = isolate->factory()->InternalizeName(Cast<Name>(value));
      }
      result->set(i, *value);
    }
    return result;
  }

  static MaybeHandle<Object> RemoveElement(Handle<JSArray> receiver,
                                           Where remove_position) {
    Isolate* isolate = receiver->GetIsolate();
    ElementsKind kind = KindTraits::Kind;
    if (IsSmiOrObjectElementsKind(kind)) {
      HandleScope scope(isolate);
      JSObject::EnsureWritableFastElements(receiver);
    }
    Handle<FixedArrayBase> backing_store(receiver->elements(), isolate);
    uint32_t length = static_cast<uint32_t>(Smi::ToInt(receiver->length()));
    DCHECK_GT(length, 0);
    int new_length = length - 1;
    int remove_index = remove_position == AT_START ? 0 : new_length;
    Handle<Object> result =
        Subclass::GetImpl(isolate, *backing_store, InternalIndex(remove_index));
    if (remove_position == AT_START) {
      Subclass::MoveElements(isolate, receiver, backing_store, 0, 1, new_length,
                             0, 0);
    }
    MAYBE_RETURN_NULL(
        Subclass::SetLengthImpl(isolate, receiver, new_length, backing_store));

    if (IsHoleyElementsKind(kind) && IsTheHole(*result, isolate)) {
      return isolate->factory()->undefined_value();
    }
    return MaybeHandle<Object>(result);
  }

  static Maybe<uint32_t> AddArguments(Handle<JSArray> receiver,
                                      Handle<FixedArrayBase> backing_store,
                                      BuiltinArguments* args, uint32_t add_size,
                                      Where add_position) {
    uint32_t length = Smi::ToInt(receiver->length());
    DCHECK_LT(0, add_size);
    uint32_t elms_len = backing_store->length();
    // Check we do not overflow the new_length.
    DCHECK(add_size <= static_cast<uint32_t>(Smi::kMaxValue - length));
    uint32_t new_length = length + add_size;
    Isolate* isolate = receiver->GetIsolate();

    if (new_length > elms_len) {
      // New backing storage is needed.
      uint32_t capacity = JSObject::NewElementsCapacity(new_length);
      // If we add arguments to the start we have to shift the existing objects.
      int copy_dst_index = add_position == AT_START ? add_size : 0;
      // Copy over all objects to a new backing_store.
      ASSIGN_RETURN_ON_EXCEPTION_VALUE(
          isolate, backing_store,
          Subclass::ConvertElementsWithCapacity(receiver, backing_store,
                                                KindTraits::Kind, capacity, 0,
                                                copy_dst_index),
          Nothing<uint32_t>());
      receiver->set_elements(*backing_store);
    } else if (add_position == AT_START) {
      // If the backing store has enough capacity and we add elements to the
      // start we have to shift the existing objects.
      Subclass::MoveElements(isolate, receiver, backing_store, add_size, 0,
                             length, 0, 0);
    }

    int insertion_index = add_position == AT_START ? 0 : length;
    // Copy the arguments to the start.
    Subclass::CopyArguments(args, backing_store, add_size, 1, insertion_index);
    // Set the length.
    receiver->set_length(Smi::FromInt(new_length));
    return Just(new_length);
  }

  static void CopyArguments(BuiltinArguments* args,
                            DirectHandle<FixedArrayBase> dst_store,
                            uint32_t copy_size, uint32_t src_index,
                            uint32_t dst_index) {
    // Add the provided values.
    DisallowGarbageCollection no_gc;
    Tagged<FixedArrayBase> raw_backing_store = *dst_store;
    WriteBarrierMode mode = raw_backing_store->GetWriteBarrierMode(no_gc);
    for (uint32_t i = 0; i < copy_size; i++) {
      Tagged<Object> argument = (*args)[src_index + i];
      DCHECK(!IsTheHole(argument));
      Subclass::SetImpl(raw_backing_store, InternalIndex(dst_index + i),
                        argument, mode);
    }
  }
};

template <typename Subclass, typename KindTraits>
class FastSmiOrObjectElementsAccessor
    : public FastElementsAccessor<Subclass, KindTraits> {
 public:
  static inline void SetImpl(DirectHandle<JSObject> holder, InternalIndex entry,
                             Tagged<Object> value) {
    SetImpl(holder->elements(), entry, value);
  }

  static inline void SetImpl(Tagged<FixedArrayBase> backing_store,
                             InternalIndex entry, Tagged<Object> value) {
    Cast<FixedArray>(backing_store)->set(entry.as_int(), value);
  }

  static inline void SetImpl(Tagged<FixedArrayBase> backing_store,
                             InternalIndex entry, Tagged<Object> value,
                             WriteBarrierMode mode) {
    Cast<FixedArray>(backing_store)->set(entry.as_int(), value, mode);
  }

  static Tagged<Object> GetRaw(Tagged<FixedArray> backing_store,
                               InternalIndex entry) {
    return backing_store->get(entry.as_int());
  }

  // NOTE: this method violates the handlified function signature convention:
  // raw pointer parameters in the function that allocates.
  // See ElementsAccessor::CopyElements() for details.
  // This method could actually allocate if copying from double elements to
  // object elements.
  static void CopyElementsImpl(Isolate* isolate, Tagged<FixedArrayBase> from,
                               uint32_t from_start, Tagged<FixedArrayBase> to,
                               ElementsKind from_kind, uint32_t to_start,
                               int packed_size, int copy_size) {
    DisallowGarbageCollection no_gc;
    ElementsKind to_kind = KindTraits::Kind;
    switch (from_kind) {
      case PACKED_SMI_ELEMENTS:
      case HOLEY_SMI_ELEMENTS:
      case PACKED_ELEMENTS:
      case PACKED_FROZEN_ELEMENTS:
      case PACKED_SEALED_ELEMENTS:
      case PACKED_NONEXTENSIBLE_ELEMENTS:
      case HOLEY_ELEMENTS:
      case HOLEY_FROZEN_ELEMENTS:
      case HOLEY_SEALED_ELEMENTS:
      case HOLEY_NONEXTENSIBLE_ELEMENTS:
      case SHARED_ARRAY_ELEMENTS:
        CopyObjectToObjectElements(isolate, from, from_kind, from_start, to,
                                   to_kind, to_start, copy_size);
        break;
      case PACKED_DOUBLE_ELEMENTS:
      case HOLEY_DOUBLE_ELEMENTS: {
        AllowGarbageCollection allow_allocation;
        DCHECK(IsObjectElementsKind(to_kind));
        CopyDoubleToObjectElements(isolate, from, from_start, to, to_start,
                                   copy_size);
        break;
      }
      case DICTIONARY_ELEMENTS:
        CopyDictionaryToObjectElements(isolate, from, from_start, to, to_kind,
                                       to_start, copy_size);
        break;
      case FAST_SLOPPY_ARGUMENTS_ELEMENTS:
      case SLOW_SLOPPY_ARGUMENTS_ELEMENTS:
      case FAST_STRING_WRAPPER_ELEMENTS:
      case SLOW_STRING_WRAPPER_ELEMENTS:
#define TYPED_ARRAY_CASE(Type, type, TYPE, ctype) case TYPE##_ELEMENTS:
        TYPED_ARRAYS(TYPED_ARRAY_CASE)
        RAB_GSAB_TYPED_ARRAYS(TYPED_ARRAY_CASE)
#undef TYPED_ARRAY_CASE
      case WASM_ARRAY_ELEMENTS:
        // This function is currently only used for JSArrays with non-zero
        // length.
        UNREACHABLE();
      case NO_ELEMENTS:
        break;  // Nothing to do.
    }
  }

  static Maybe<bool> CollectValuesOrEntriesImpl(
      Isolate* isolate, DirectHandle<JSObject> object,
      DirectHandle<FixedArray> values_or_entries, bool get_entries,
      int* nof_items, PropertyFilter filter) {
    int count = 0;
    if (get_entries) {
      // Collecting entries needs to allocate, so this code must be handlified.
      DirectHandle<FixedArray> elements(Cast<FixedArray>(object->elements()),
                                        isolate);
      uint32_t length = elements->length();
      for (uint32_t index = 0; index < length; ++index) {
        InternalIndex entry(index);
        if (!Subclass::HasEntryImpl(isolate, *elements, entry)) continue;
        DirectHandle<Object> value =
            Subclass::GetImpl(isolate, *elements, entry);
        value = MakeEntryPair(isolate, index, value);
        values_or_entries->set(count++, *value);
      }
    } else {
      // No allocations here, so we can avoid handlification overhead.
      DisallowGarbageCollection no_gc;
      Tagged<FixedArray> elements = Cast<FixedArray>(object->elements());
      uint32_t length = elements->length();
      for (uint32_t index = 0; index < length; ++index) {
        InternalIndex entry(index);
        if (!Subclass::HasEntryImpl(isolate, elements, entry)) continue;
        Tagged<Object> value = GetRaw(elements, entry);
        values_or_entries->set(count++, value);
      }
    }
    *nof_items = count;
    return Just(true);
  }

  static Maybe<int64_t> IndexOfValueImpl(Isolate* isolate,
                                         DirectHandle<JSObject> receiver,
                                         DirectHandle<Object> search_value,
                                         size_t start_from, size_t length) {
    DCHECK(JSObject::PrototypeHasNoElements(isolate, *receiver));
    DisallowGarbageCollection no_gc;
    Tagged<FixedArrayBase> elements_base = receiver->elements();
    Tagged<Object> value = *search_value;

    if (start_from >= length) return Just<int64_t>(-1);

    length = std::min(static_cast<size_t>(elements_base->length()), length);

    // Only FAST_{,HOLEY_}ELEMENTS can store non-numbers.
    if (!IsNumber(value) && !IsObjectElementsKind(Subclass::kind()) &&
        !IsAnyNonextensibleElementsKind(Subclass::kind())) {
      return Just<int64_t>(-1);
    }
    // NaN can never be found by strict equality.
    if (IsNaN(value)) return Just<int64_t>(-1);

    // k can be greater than receiver->length() below, but it is bounded by
    // elements_base->length() so we never read out of bounds. This means that
    // elements->get(k) can return the hole, for which the StrictEquals will
    // always fail.
    Tagged<FixedArray> elements = Cast<FixedArray>(receiver->elements());
    static_assert(FixedArray::kMaxLength <=
                  std::numeric_limits<uint32_t>::max());
    for (size_t k = start_from; k < length; ++k) {
      if (Object::StrictEquals(value,
                               elements->get(static_cast<uint32_t>(k)))) {
        return Just<int64_t>(k);
      }
    }
    return Just<int64_t>(-1);
  }
};

class FastPackedSmiElementsAccessor
    : public FastSmiOrObjectElementsAccessor<
          FastPackedSmiElementsAccessor,
          ElementsKindTraits<PACKED_SMI_ELEMENTS>> {};

class FastHoleySmiElementsAccessor
    : public FastSmiOrObjectElementsAccessor<
          FastHoleySmiElementsAccessor,
          ElementsKindTraits<HOLEY_SMI_ELEMENTS>> {};

class FastPackedObjectElementsAccessor
    : public FastSmiOrObjectElementsAccessor<
          FastPackedObjectElementsAccessor,
          ElementsKindTraits<PACKED_ELEMENTS>> {};

template <typename Subclass, typename KindTraits>
class FastNonextensibleObjectElementsAccessor
    : public FastSmiOrObjectElementsAccessor<Subclass, KindTraits> {
 public:
  using BackingStore = typename KindTraits::BackingStore;

  static Maybe<uint32_t> PushImpl(DirectHandle<JSArray> receiver,
                                  BuiltinArguments* args, uint32_t push_size) {
    UNREACHABLE();
  }

  static Maybe<bool> AddImpl(DirectHandle<JSObject> object, uint32_t index,
                             DirectHandle<Object> value,
                             PropertyAttributes attributes,
                             uint32_t new_capacity) {
    UNREACHABLE();
  }

  // TODO(duongn): refactor this due to code duplication of sealed version.
  // Consider using JSObject::NormalizeElements(). Also consider follow the fast
  // element logic instead of changing to dictionary mode.
  static Maybe<bool> SetLengthImpl(Isolate* isolate, Handle<JSArray> array,
                                   uint32_t length,
                                   DirectHandle<FixedArrayBase> backing_store) {
    uint32_t old_length = 0;
    CHECK(Object::ToArrayIndex(array->length(), &old_length));
    if (length == old_length) {
      // Do nothing.
      return Just(true);
    }

    // Transition to DICTIONARY_ELEMENTS.
    // Convert to dictionary mode.
    Handle<NumberDictionary> new_element_dictionary =
        old_length == 0 ? isolate->factory()->empty_slow_element_dictionary()
                        : array->GetElementsAccessor()->Normalize(array);

    // Migrate map.
    DirectHandle<Map> new_map = Map::Copy(
        isolate, handle(array->map(), isolate), "SlowCopyForSetLengthImpl");
    new_map->set_is_extensible(false);
    new_map->set_elements_kind(DICTIONARY_ELEMENTS);
    JSObject::MigrateToMap(isolate, array, new_map);

    if (!new_element_dictionary.is_null()) {
      array->set_elements(*new_element_dictionary);
    }

    if (array->elements() !=
        ReadOnlyRoots(isolate).empty_slow_element_dictionary()) {
      Handle<NumberDictionary> dictionary(array->element_dictionary(), isolate);
      // Make sure we never go back to the fast case
      array->RequireSlowElements(*dictionary);
      JSObject::ApplyAttributesToDictionary(isolate, ReadOnlyRoots(isolate),
                                            dictionary,
                                            PropertyAttributes::NONE);
    }

    // Set length.
    Handle<FixedArrayBase> new_backing_store(array->elements(), isolate);
    return DictionaryElementsAccessor::SetLengthImpl(isolate, array, length,
                                                     new_backing_store);
  }
};

class FastPackedNonextensibleObjectElementsAccessor
    : public FastNonextensibleObjectElementsAccessor<
          FastPackedNonextensibleObjectElementsAccessor,
          ElementsKindTraits<PACKED_NONEXTENSIBLE_ELEMENTS>> {};

class FastHoleyNonextensibleObjectElementsAccessor
    : public FastNonextensibleObjectElementsAccessor<
          FastHoleyNonextensibleObjectElementsAccessor,
          ElementsKindTraits<HOLEY_NONEXTENSIBLE_ELEMENTS>> {};

template <typename Subclass, typename KindTraits>
class FastSealedObjectElementsAccessor
    : public FastSmiOrObjectElementsAccessor<Subclass, KindTraits> {
 public:
  using BackingStore = typename KindTraits::BackingStore;

  static Handle<Object> RemoveElement(DirectHandle<JSArray> receiver,
                                      Where remove_position) {
    UNREACHABLE();
  }

  static void DeleteImpl(DirectHandle<JSObject> obj, InternalIndex entry) {
    UNREACHABLE();
  }

  static void DeleteAtEnd(DirectHandle<JSObject> obj,
                          DirectHandle<BackingStore> backing_store,
                          uint32_t entry) {
    UNREACHABLE();
  }

  static void DeleteCommon(DirectHandle<JSObject> obj, uint32_t entry,
                           DirectHandle<FixedArrayBase> store) {
    UNREACHABLE();
  }

  static MaybeHandle<Object> PopImpl(DirectHandle<JSArray> receiver) {
    UNREACHABLE();
  }

  static Maybe<uint32_t> PushImpl(DirectHandle<JSArray> receiver,
                                  BuiltinArguments* args, uint32_t push_size) {
    UNREACHABLE();
  }

  static Maybe<bool> AddImpl(DirectHandle<JSObject> object, uint32_t index,
                             DirectHandle<Object> value,
                             PropertyAttributes attributes,
                             uint32_t new_capacity) {
    UNREACHABLE();
  }

  // TODO(duongn): refactor this due to code duplication of nonextensible
  // version. Consider using JSObject::NormalizeElements(). Also consider follow
  // the fast element logic instead of changing to dictionary mode.
  static Maybe<bool> SetLengthImpl(Isolate* isolate, Handle<JSArray> array,
                                   uint32_t length,
                                   DirectHandle<FixedArrayBase> backing_store) {
    uint32_t old_length = 0;
    CHECK(Object::ToArrayIndex(array->length(), &old_length));
    if (length == old_length) {
      // Do nothing.
      return Just(true);
    }

    // Transition to DICTIONARY_ELEMENTS.
    // Convert to dictionary mode
    DirectHandle<NumberDictionary> new_element_dictionary =
        old_length == 0 ? isolate->factory()->empty_slow_element_dictionary()
                        : array->GetElementsAccessor()->Normalize(array);

    // Migrate map.
    DirectHandle<Map> new_map = Map::Copy(
        isolate, handle(array->map(), isolate), "SlowCopyForSetLengthImpl");
    new_map->set_is_extensible(false);
    new_map->set_elements_kind(DICTIONARY_ELEMENTS);
    JSObject::MigrateToMap(isolate, array, new_map);

    if (!new_element_dictionary.is_null()) {
      array->set_elements(*new_element_dictionary);
    }

    if (array->elements() !=
        ReadOnlyRoots(isolate).empty_slow_element_dictionary()) {
      Handle<NumberDictionary> dictionary(array->element_dictionary(), isolate);
      // Make sure we never go back to the fast case
      array->RequireSlowElements(*dictionary);
      JSObject::ApplyAttributesToDictionary(isolate, ReadOnlyRoots(isolate),
                                            dictionary,
                                            PropertyAttributes::SEALED);
    }

    // Set length
    Handle<FixedArrayBase> new_backing_store(array->elements(), isolate);
    return DictionaryElementsAccessor::SetLengthImpl(isolate, array, length,
                                                     new_backing_store);
  }
};

class FastPackedSealedObjectElementsAccessor
    : public FastSealedObjectElementsAccessor<
          FastPackedSealedObjectElementsAccessor,
          ElementsKindTraits<PACKED_SEALED_ELEMENTS>> {};

class SharedArrayElementsAccessor
    : public FastSealedObjectElementsAccessor<
          SharedArrayElementsAccessor,
          ElementsKindTraits<SHARED_ARRAY_ELEMENTS>> {
 public:
  static Handle<Object> GetAtomicInternalImpl(
      Isolate* isolate, Tagged<FixedArrayBase> backing_store,
      InternalIndex entry, SeqCstAccessTag tag) {
    return handle(Cast<BackingStore>(backing_store)->get(entry.as_int(), tag),
                  isolate);
  }

  static void SetAtomicInternalImpl(Tagged<FixedArrayBase> backing_store,
                                    InternalIndex entry, Tagged<Object> value,
                                    SeqCstAccessTag tag) {
    Cast<BackingStore>(backing_store)->set(entry.as_int(), value, tag);
  }

  static Handle<Object> SwapAtomicInternalImpl(
      Isolate* isolate, Tagged<FixedArrayBase> backing_store,
      InternalIndex entry, Tagged<Object> value, SeqCstAccessTag tag) {
    return handle(
        Cast<BackingStore>(backing_store)->swap(entry.as_int(), value, tag),
        isolate);
  }

  static Tagged<Object> CompareAndSwapAtomicInternalImpl(
      Tagged<FixedArrayBase> backing_store, InternalIndex entry,
      Tagged<Object> expected, Tagged<Object> value, SeqCstAccessTag tag) {
    return Cast<BackingStore>(backing_store)
        ->compare_and_swap(entry.as_int(), expected, value, tag);
  }
};

class FastHoleySealedObjectElementsAccessor
    : public FastSealedObjectElementsAccessor<
          FastHoleySealedObjectElementsAccessor,
          ElementsKindTraits<HOLEY_SEALED_ELEMENTS>> {};

template <typename Subclass, typename KindTraits>
class FastFrozenObjectElementsAccessor
    : public FastSmiOrObjectElementsAccessor<Subclass, KindTraits> {
 public:
  using BackingStore = typename KindTraits::BackingStore;

  static inline void SetImpl(DirectHandle<JSObject> holder, InternalIndex entry,
                             Tagged<Object> value) {
    UNREACHABLE();
  }

  static inline void SetImpl(Tagged<FixedArrayBase> backing_store,
                             InternalIndex entry, Tagged<Object> value) {
    UNREACHABLE();
  }

  static inline void SetImpl(Tagged<FixedArrayBase> backing_store,
                             InternalIndex entry, Tagged<Object> value,
                             WriteBarrierMode mode) {
    UNREACHABLE();
  }

  static Handle<Object> RemoveElement(DirectHandle<JSArray> receiver,
                                      Where remove_position) {
    UNREACHABLE();
  }

  static void DeleteImpl(DirectHandle<JSObject> obj, InternalIndex entry) {
    UNREACHABLE();
  }

  static void DeleteAtEnd(DirectHandle<JSObject> obj,
                          DirectHandle<BackingStore> backing_store,
                          uint32_t entry) {
    UNREACHABLE();
  }

  static void DeleteCommon(DirectHandle<JSObject> obj, uint32_t entry,
                           DirectHandle<FixedArrayBase> store) {
    UNREACHABLE();
  }

  static MaybeHandle<Object> PopImpl(DirectHandle<JSArray> receiver) {
    UNREACHABLE();
  }

  static Maybe<uint32_t> PushImpl(DirectHandle<JSArray> receiver,
                                  BuiltinArguments* args, uint32_t push_size) {
    UNREACHABLE();
  }

  static Maybe<bool> AddImpl(DirectHandle<JSObject> object, uint32_t index,
                             DirectHandle<Object> value,
                             PropertyAttributes attributes,
                             uint32_t new_capacity) {
    UNREACHABLE();
  }

  static Maybe<bool> SetLengthImpl(Isolate* isolate,
                                   DirectHandle<JSArray> array, uint32_t length,
                                   DirectHandle<FixedArrayBase> backing_store) {
    UNREACHABLE();
  }

  static void ReconfigureImpl(DirectHandle<JSObject> object,
                              DirectHandle<FixedArrayBase> store,
                              InternalIndex entry, DirectHandle<Object> value,
                              PropertyAttributes attributes) {
    UNREACHABLE();
  }
};

class FastPackedFrozenObjectElementsAccessor
    : public FastFrozenObjectElementsAccessor<
          FastPackedFrozenObjectElementsAccessor,
          ElementsKindTraits<PACKED_FROZEN_ELEMENTS>> {};

class FastHoleyFrozenObjectElementsAccessor
    : public FastFrozenObjectElementsAccessor<
          FastHoleyFrozenObjectElementsAccessor,
          ElementsKindTraits<HOLEY_FROZEN_ELEMENTS>> {};

class FastHoleyObjectElementsAccessor
    : public FastSmiOrObjectElementsAccessor<
          FastHoleyObjectElementsAccessor, ElementsKindTraits<HOLEY_ELEMENTS>> {
};

// Helper templates to statically determine if our destination type can contain
// the source type.
template <ElementsKind Kind, typename ElementType, ElementsKind SourceKind,
          typename SourceElementType>
struct CopyBetweenBackingStoresImpl;

template <typename Subclass, typename KindTraits>
class FastDoubleElementsAccessor
    : public FastElementsAccessor<Subclass, KindTraits> {
 public:
  static Handle<Object> GetImpl(Isolate* isolate,
                                Tagged<FixedArrayBase> backing_store,
                                InternalIndex entry) {
    return FixedDoubleArray::get(Cast<Fixe
```