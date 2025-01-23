Response:
Let's break down the thought process to analyze this V8 header file.

1. **Understand the Goal:** The request asks for the functionality of `descriptor-array-inl.h`, its relation to Torque/JavaScript, code logic, and common errors. This means I need to go beyond just summarizing the code; I need to infer its purpose within the broader V8 context.

2. **Initial Scan and Key Identifiers:** I'll start by scanning the file for keywords and recognizable patterns. I see:

    * `#ifndef`, `#define`, `#include`: Standard C++ header guards and includes.
    * `namespace v8 { namespace internal {`:  Indicates this is internal V8 code.
    * `DescriptorArray`, `EnumCache`:  The primary data structures.
    * `kNumberOfAllDescriptorsOffset`, `kNumberOfDescriptorsOffset`, `kRawGcStateOffset`: Likely offsets within the `DescriptorArray` structure.
    * `Search`, `BinarySearch`, `LinearSearch`:  Methods for finding descriptors.
    * `GetKey`, `SetValue`, `GetDetails`, `SetDetails`:  Accessors for the `DescriptorArray`'s data.
    * `PropertyDetails`, `PropertyLocation`, `FieldType`:  Related to object properties.
    * `DescriptorLookupCache`: A cache for lookups.
    * `ObjectSlot`: Represents a memory location.
    * `WRITE_BARRIER`: A V8-specific mechanism for garbage collection.
    * `TQ_OBJECT_CONSTRUCTORS_IMPL`:  Strong indicator of Torque usage.
    * `DescriptorArrayMarkingState`: Related to garbage collection marking.

3. **Inferring Core Functionality - The Descriptor Array:** Based on the names and methods, I can infer that `DescriptorArray` is a core data structure for storing information about an object's properties (descriptors). The methods for `Search`, `GetKey`, `SetValue`, etc., confirm this. It seems like a key-value store with extra metadata (`PropertyDetails`).

4. **Torque Connection:** The presence of `#include "torque-generated/src/objects/descriptor-array-tq-inl.inc"` and `TQ_OBJECT_CONSTRUCTORS_IMPL` strongly suggests that `DescriptorArray`'s structure and some of its fundamental operations are defined in Torque, a V8-specific language. The `.inc` extension further implies this is a generated file included here. The request specifically asks about `.tq`, and while this file *includes* a generated file from Torque, *this specific file* is `.h`.

5. **JavaScript Relationship:**  Since `DescriptorArray` manages object properties, it directly relates to how JavaScript objects work. When you access a property of a JavaScript object, V8 needs to look up the corresponding information. The `DescriptorArray` is a crucial component in this process. I need to think of a simple JavaScript example that demonstrates property access and creation.

6. **Code Logic - Search Algorithms:** The code implements both linear and binary search. The choice depends on the size of the array and whether the search is concurrent. This indicates performance considerations. I should create an example showing how these searches might be triggered implicitly by JavaScript code.

7. **Code Logic - Marking State:** The `DescriptorArrayMarkingState` section clearly deals with garbage collection. The functions `TryUpdateIndicesToMark` and `AcquireDescriptorRangeToMark` suggest a mechanism for tracking which descriptors have been visited during the marking phase of GC. This is an internal optimization.

8. **Common Programming Errors:** Since this is low-level V8 code, the common "user" programming errors aren't directly related to manipulating `DescriptorArray`. Instead, the errors are more about understanding JavaScript's behavior concerning properties, which are ultimately influenced by structures like this. Examples would be accessing non-existent properties or unexpected behavior related to property enumeration.

9. **Structuring the Answer:** Now I'll organize the information:

    * **Functionality:** Start with a high-level explanation of what `DescriptorArray` and this header file are for.
    * **Torque:** Explain the connection to Torque and highlight that this specific file isn't a `.tq` file but includes generated Torque code.
    * **JavaScript Relationship:** Provide a clear JavaScript example that demonstrates the underlying functionality of the `DescriptorArray`.
    * **Code Logic:** Focus on the search algorithms and the marking state, providing examples of input and output (even if they are conceptual within V8's internal workings).
    * **Common Errors:**  Illustrate common JavaScript errors related to properties and briefly explain how `DescriptorArray` plays a role behind the scenes.

10. **Refinement and Detail:**  Go back through each section and add more specific details from the code. For example, mention the specific accessors (`RELAXED_INT16_ACCESSORS`), the purpose of the `EnumCache`, and the meaning of `PropertyDetails`. Ensure the JavaScript examples are simple and directly related to the concepts being explained. For the marking state, clarify its role in optimizing garbage collection.

11. **Review and Clarity:**  Read through the complete answer to ensure it's clear, concise, and addresses all aspects of the request. Double-check for any technical inaccuracies. For example, initially, I might have overstated that *all* of `DescriptorArray` is defined in Torque, but the `.inl.h` file contains inline methods, which are C++.

By following these steps, I can move from a basic understanding of the code to a comprehensive explanation of its role and function within the V8 JavaScript engine.
## 功能列举：v8/src/objects/descriptor-array-inl.h

这个头文件 `v8/src/objects/descriptor-array-inl.h` 定义了内联（inline）函数，用于操作 `DescriptorArray` 对象。`DescriptorArray` 是 V8 引擎中用于存储 JavaScript 对象属性描述符的关键数据结构。

以下是它的主要功能：

1. **访问和修改 `DescriptorArray` 的元数据:**
   - 提供访问器（accessors）用于获取和设置 `DescriptorArray` 的基本属性，例如：
     - `number_of_all_descriptors()`:  所有描述符的总数（包括已使用和未使用的）。
     - `number_of_descriptors()`: 当前已使用的描述符数量。
     - `raw_gc_state()`:  与垃圾回收相关的状态信息。
     - `number_of_slack_descriptors()`:  未使用的描述符数量。
     - `number_of_entries()`:  已使用的描述符数量（与 `number_of_descriptors()` 相同）。

2. **枚举缓存操作:**
   - `CopyEnumCacheFrom(Tagged<DescriptorArray> array)`: 从另一个 `DescriptorArray` 复制枚举缓存。枚举缓存用于加速对象属性的枚举操作。

3. **查找描述符:**
   - 提供多种 `Search` 方法，用于在 `DescriptorArray` 中查找特定属性的描述符：
     - `Search(Tagged<Name> name, int valid_descriptors, bool concurrent_search)`: 根据属性名查找描述符，可以指定有效描述符的范围和是否为并发搜索。
     - `BinarySearch(Tagged<Name> name, int valid_descriptors)`: 使用二分查找根据属性名查找描述符。
     - `LinearSearch(Tagged<Name> name, int valid_descriptors)`: 使用线性查找根据属性名查找描述符。
     - `Search(Tagged<Name> name, Tagged<Map> map, bool concurrent_search)`: 根据属性名和所属的 Map 对象查找描述符。
     - `Search(int field_index, int valid_descriptors)`: 根据字段索引查找描述符。
     - `Search(int field_index, Tagged<Map> map)`: 根据字段索引和所属的 Map 对象查找描述符。
     - `SearchWithCache(Isolate* isolate, Tagged<Name> name, Tagged<Map> map)`: 使用描述符查找缓存来查找描述符。

4. **访问和修改描述符的条目:**
   - 提供方法来访问和修改 `DescriptorArray` 中存储的各个描述符条目：
     - `GetFirstPointerSlot()`: 获取指向第一个指针槽的 `ObjectSlot`。
     - `GetDescriptorSlot(int descriptor)`: 获取指定索引描述符的 `ObjectSlot`。
     - `GetKey(InternalIndex descriptor_number) const`: 获取指定索引描述符的属性名（key）。
     - `SetKey(InternalIndex descriptor_number, Tagged<Name> key)`: 设置指定索引描述符的属性名。
     - `GetSortedKeyIndex(int descriptor_number)`: 获取排序后的键的索引。
     - `GetSortedKey(int descriptor_number)`: 获取排序后的键的属性名。
     - `SetSortedKey(int descriptor_number, int pointer)`: 设置排序后的键的索引。
     - `GetStrongValue(InternalIndex descriptor_number)`: 获取指定索引描述符的强引用值。
     - `SetValue(InternalIndex descriptor_number, Tagged<MaybeObject> value)`: 设置指定索引描述符的值。
     - `GetValue(InternalIndex descriptor_number)`: 获取指定索引描述符的值。
     - `GetDetails(InternalIndex descriptor_number)`: 获取指定索引描述符的详细信息 (`PropertyDetails`)。
     - `SetDetails(InternalIndex descriptor_number, PropertyDetails details)`: 设置指定索引描述符的详细信息。
     - `GetFieldIndex(InternalIndex descriptor_number)`: 获取指定索引描述符的字段索引。
     - `GetFieldType(InternalIndex descriptor_number)`: 获取指定索引描述符的字段类型。
     - `Set(InternalIndex descriptor_number, Tagged<Name> key, Tagged<MaybeObject> value, PropertyDetails details)`: 设置指定索引描述符的所有信息。
     - `Set(InternalIndex descriptor_number, Descriptor* desc)`: 使用 `Descriptor` 对象设置指定索引的描述符信息。

5. **添加描述符:**
   - `Append(Descriptor* desc)`: 向 `DescriptorArray` 的末尾添加一个新的描述符，并维护排序。

6. **交换排序后的键:**
   - `SwapSortedKeys(int first, int second)`: 交换两个排序后的键的索引。

7. **垃圾回收相关的操作:**
   - `DescriptorArrayMarkingState::TryUpdateIndicesToMark(...)`: 尝试更新需要标记的描述符索引，用于垃圾回收标记阶段。
   - `DescriptorArrayMarkingState::AcquireDescriptorRangeToMark(...)`: 获取要标记的描述符范围，用于垃圾回收标记阶段。

## 关于 .tq 结尾和 JavaScript 关系

**如果 `v8/src/objects/descriptor-array-inl.h` 以 `.tq` 结尾，那它将是一个 V8 Torque 源代码文件。** Torque 是 V8 使用的一种领域特定语言，用于生成高效的 C++ 代码，特别是对于对象操作和运行时功能。

**`v8/src/objects/descriptor-array-inl.h` 与 JavaScript 的功能有直接关系。**  `DescriptorArray` 存储了 JavaScript 对象的属性信息，包括属性名、属性值、属性类型（例如，数据属性、访问器属性）、以及属性的特性（例如，是否可枚举、是否可配置、是否可写）。

**JavaScript 举例说明:**

```javascript
const obj = {
  name: 'John',
  age: 30
};

// 当你访问属性时，V8 内部会使用 DescriptorArray 来查找属性的信息
console.log(obj.name); // V8 会在 obj 的 DescriptorArray 中查找 'name' 属性

// 当你定义新的属性时，V8 会更新 obj 的 DescriptorArray
obj.city = 'New York';

// 甚至像 Object.keys 这样的方法也会用到 DescriptorArray
console.log(Object.keys(obj)); // V8 会遍历 obj 的 DescriptorArray 来获取可枚举的属性名

// 属性的特性也存储在 DescriptorArray 中
Object.defineProperty(obj, 'gender', {
  value: 'Male',
  enumerable: false // 不可枚举
});

console.log(Object.keys(obj)); // 'gender' 不会出现在这里，因为它的 enumerable 属性为 false
```

在这个例子中，每当我们访问、定义或操作 JavaScript 对象 `obj` 的属性时，V8 引擎在底层都会与 `DescriptorArray` 进行交互，以获取或更新属性的相关信息。`DescriptorArray` 是 V8 实现 JavaScript 对象属性的关键组成部分。

## 代码逻辑推理：查找描述符

**假设输入：**

- `DescriptorArray` 对象 `descriptor_array` 存储了以下描述符（简化表示，仅包含属性名）：
  - "a" (hash: 10)
  - "b" (hash: 20)
  - "c" (hash: 15)
  - "d" (hash: 25)
- 要查找的属性名 `name` 为 "c" (hash: 15)。
- `valid_descriptors` 为 4 (表示所有描述符都有效)。
- `concurrent_search` 为 `false`。

**输出：**

- `InternalIndex`，指向描述符 "c" 在 `DescriptorArray` 中的索引。

**代码逻辑推理（基于 `DescriptorArray::Search` 和 `DescriptorArray::BinarySearch`）：**

1. `Search` 方法首先检查 `valid_descriptors` 是否为 0，这里不是。
2. 接着，它判断是否应该使用线性搜索。`kMaxElementsForLinearSearch` 通常较小（例如 8），且 `concurrent_search` 为 `false`，因此会判断是否使用线性搜索。
3. 假设 `valid_descriptors` 为 4，小于或等于 `kMaxElementsForLinearSearch`，那么会执行 `LinearSearch`。
4. `LinearSearch` 会遍历前 `valid_descriptors` 个描述符，逐个比较属性名。
5. 当遍历到属性名为 "c" 的描述符时，`GetKey(index) == name` 为真，返回该描述符的 `InternalIndex`。

**如果 `valid_descriptors` 大于 `kMaxElementsForLinearSearch`，则会执行 `BinarySearch`：**

1. `BinarySearch` 首先获取要查找的属性名的哈希值（15）。
2. 它使用 `std::ranges::lower_bound` 在排序后的键中查找第一个哈希值大于或等于 15 的键。 假设排序后的键的哈希值为 [10, 15, 20, 25]，则 `lower_bound` 会找到哈希值为 15 的键的索引。
3. 然后，它会从找到的索引开始，线性扫描具有相同哈希值的描述符，直到找到属性名完全匹配的描述符。
4. 如果找到匹配的属性名 "c"，则返回其 `InternalIndex`。

## 用户常见的编程错误

用户通常不会直接操作 `DescriptorArray`，因为它是 V8 引擎的内部实现细节。但是，用户在编写 JavaScript 代码时的一些常见错误，可能会间接地与 `DescriptorArray` 的行为相关：

1. **访问未定义的属性：**

   ```javascript
   const obj = { name: 'John' };
   console.log(obj.age); // 输出 undefined
   ```

   当访问 `obj.age` 时，V8 会在 `obj` 的 `DescriptorArray` 中查找名为 "age" 的属性。如果找不到，则返回 `undefined`。

2. **意外地覆盖属性：**

   ```javascript
   const obj = { name: 'John' };
   obj.name = 'Jane'; // 覆盖了现有的 'name' 属性
   ```

   当执行 `obj.name = 'Jane'` 时，V8 会在 `obj` 的 `DescriptorArray` 中找到 "name" 属性的描述符，并更新其值。

3. **误解属性的可枚举性：**

   ```javascript
   const obj = {};
   Object.defineProperty(obj, 'secret', {
     value: 42,
     enumerable: false
   });

   console.log(Object.keys(obj)); // 输出 []，因为 'secret' 不可枚举
   for (let key in obj) {
     console.log(key); // 不会输出 'secret'
   }
   ```

   用户可能会忘记通过 `Object.defineProperty` 设置的属性特性会影响属性在枚举操作中的可见性。`DescriptorArray` 中存储了属性的 `enumerable` 特性，这决定了属性是否会被 `Object.keys` 或 `for...in` 循环遍历。

4. **性能问题：添加大量动态属性：**

   ```javascript
   const obj = {};
   for (let i = 0; i < 1000; i++) {
     obj[`prop${i}`] = i;
   }
   ```

   动态地向对象添加大量属性可能会导致 V8 引擎频繁地调整 `DescriptorArray` 的大小，从而影响性能。虽然用户不会直接操作 `DescriptorArray`，但理解其背后的机制有助于编写更优化的 JavaScript 代码。

总而言之，`v8/src/objects/descriptor-array-inl.h` 定义了操作 `DescriptorArray` 的底层方法，而 `DescriptorArray` 是 V8 引擎管理 JavaScript 对象属性的关键数据结构。理解它的功能有助于深入理解 V8 引擎的工作原理。

### 提示词
```
这是目录为v8/src/objects/descriptor-array-inl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/descriptor-array-inl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```c
// Copyright 2018 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_OBJECTS_DESCRIPTOR_ARRAY_INL_H_
#define V8_OBJECTS_DESCRIPTOR_ARRAY_INL_H_

#include "src/execution/isolate.h"
#include "src/handles/maybe-handles-inl.h"
#include "src/heap/heap-write-barrier.h"
#include "src/heap/heap.h"
#include "src/objects/descriptor-array.h"
#include "src/objects/dictionary.h"
#include "src/objects/field-type.h"
#include "src/objects/heap-object-inl.h"
#include "src/objects/lookup-cache-inl.h"
#include "src/objects/maybe-object-inl.h"
#include "src/objects/property.h"
#include "src/objects/struct-inl.h"
#include "src/objects/tagged-field-inl.h"
#include "src/torque/runtime-macro-shims.h"
#include "src/torque/runtime-support.h"

// Has to be the last include (doesn't have include guards):
#include "src/objects/object-macros.h"

namespace v8 {
namespace internal {

#include "torque-generated/src/objects/descriptor-array-tq-inl.inc"

TQ_OBJECT_CONSTRUCTORS_IMPL(DescriptorArray)
TQ_OBJECT_CONSTRUCTORS_IMPL(EnumCache)

RELAXED_INT16_ACCESSORS(DescriptorArray, number_of_all_descriptors,
                        kNumberOfAllDescriptorsOffset)
RELAXED_INT16_ACCESSORS(DescriptorArray, number_of_descriptors,
                        kNumberOfDescriptorsOffset)
RELAXED_UINT32_ACCESSORS(DescriptorArray, raw_gc_state, kRawGcStateOffset)

inline int16_t DescriptorArray::number_of_slack_descriptors() const {
  return number_of_all_descriptors() - number_of_descriptors();
}

inline int DescriptorArray::number_of_entries() const {
  return number_of_descriptors();
}

void DescriptorArray::CopyEnumCacheFrom(Tagged<DescriptorArray> array) {
  set_enum_cache(array->enum_cache());
}

InternalIndex DescriptorArray::Search(Tagged<Name> name, int valid_descriptors,
                                      bool concurrent_search) {
  DCHECK(IsUniqueName(name));
  SLOW_DCHECK_IMPLIES(!concurrent_search, IsSortedNoDuplicates());

  if (valid_descriptors == 0) {
    return InternalIndex::NotFound();
  }

  // Do linear search for small arrays, and for searches in the background
  // thread.
  const int kMaxElementsForLinearSearch = 8;
  if (valid_descriptors <= kMaxElementsForLinearSearch || concurrent_search) {
    return LinearSearch(name, valid_descriptors);
  }

  return BinarySearch(name, valid_descriptors);
}

InternalIndex DescriptorArray::BinarySearch(Tagged<Name> name,
                                            int valid_descriptors) {
  // We have to binary search all descriptors, not just valid ones, since the
  // binary search ordering is across all descriptors.
  int end = number_of_descriptors();
  uint32_t hash = name->hash();

  // Find the first descriptor whose key's hash is greater-than-or-equal-to the
  // search hash.
  int number = *std::ranges::lower_bound(std::views::iota(0, end), hash,
                                         std::less<>(), [&](int i) {
                                           Tagged<Name> entry = GetSortedKey(i);
                                           return entry->hash();
                                         });

  // There may have been hash collisions, so search for the name from the first
  // index until the first non-matching hash.
  for (; number < end; ++number) {
    InternalIndex index(GetSortedKeyIndex(number));
    Tagged<Name> entry = GetKey(index);
    if (entry == name) {
      // If we found the entry, but it's outside the owned descriptors of the
      // caller, return not found.
      if (index.as_int() >= valid_descriptors) {
        return InternalIndex::NotFound();
      }
      return index;
    }
    if (entry->hash() != hash) {
      return InternalIndex::NotFound();
    }
  }

  return InternalIndex::NotFound();
}

InternalIndex DescriptorArray::LinearSearch(Tagged<Name> name,
                                            int valid_descriptors) {
  DCHECK_LE(valid_descriptors, number_of_descriptors());
  for (int i = 0; i < valid_descriptors; ++i) {
    InternalIndex index(i);
    if (GetKey(index) == name) return index;
  }
  return InternalIndex::NotFound();
}

InternalIndex DescriptorArray::Search(Tagged<Name> name, Tagged<Map> map,
                                      bool concurrent_search) {
  DCHECK(IsUniqueName(name));
  int number_of_own_descriptors = map->NumberOfOwnDescriptors();
  if (number_of_own_descriptors == 0) return InternalIndex::NotFound();
  return Search(name, number_of_own_descriptors, concurrent_search);
}

InternalIndex DescriptorArray::Search(int field_index, int valid_descriptors) {
  for (int desc_index = field_index; desc_index < valid_descriptors;
       ++desc_index) {
    PropertyDetails details = GetDetails(InternalIndex(desc_index));
    if (details.location() != PropertyLocation::kField) continue;
    if (field_index == details.field_index()) {
      return InternalIndex(desc_index);
    }
    DCHECK_LT(details.field_index(), field_index);
  }
  return InternalIndex::NotFound();
}

InternalIndex DescriptorArray::Search(int field_index, Tagged<Map> map) {
  int number_of_own_descriptors = map->NumberOfOwnDescriptors();
  if (number_of_own_descriptors == 0) return InternalIndex::NotFound();
  return Search(field_index, number_of_own_descriptors);
}

InternalIndex DescriptorArray::SearchWithCache(Isolate* isolate,
                                               Tagged<Name> name,
                                               Tagged<Map> map) {
  DCHECK(IsUniqueName(name));
  int number_of_own_descriptors = map->NumberOfOwnDescriptors();
  if (number_of_own_descriptors == 0) return InternalIndex::NotFound();

  DescriptorLookupCache* cache = isolate->descriptor_lookup_cache();
  int number = cache->Lookup(map, name);

  if (number == DescriptorLookupCache::kAbsent) {
    InternalIndex result = Search(name, number_of_own_descriptors);
    number = result.is_found() ? result.as_int() : DescriptorArray::kNotFound;
    cache->Update(map, name, number);
  }
  if (number == DescriptorArray::kNotFound) return InternalIndex::NotFound();
  return InternalIndex(number);
}

ObjectSlot DescriptorArray::GetFirstPointerSlot() {
  static_assert(kEndOfStrongFieldsOffset == kStartOfWeakFieldsOffset,
                "Weak and strong fields are continuous.");
  static_assert(kEndOfWeakFieldsOffset == kHeaderSize,
                "Weak fields extend up to the end of the header.");
  return RawField(DescriptorArray::kStartOfStrongFieldsOffset);
}

ObjectSlot DescriptorArray::GetDescriptorSlot(int descriptor) {
  // Allow descriptor == number_of_all_descriptors() for computing the slot
  // address that comes after the last descriptor (for iterating).
  DCHECK_LE(descriptor, number_of_all_descriptors());
  return RawField(OffsetOfDescriptorAt(descriptor));
}

Tagged<Name> DescriptorArray::GetKey(InternalIndex descriptor_number) const {
  PtrComprCageBase cage_base = GetPtrComprCageBase(*this);
  return GetKey(cage_base, descriptor_number);
}

Tagged<Name> DescriptorArray::GetKey(PtrComprCageBase cage_base,
                                     InternalIndex descriptor_number) const {
  DCHECK_LT(descriptor_number.as_int(), number_of_descriptors());
  int entry_offset = OffsetOfDescriptorAt(descriptor_number.as_int());
  return Cast<Name>(
      EntryKeyField::Relaxed_Load(cage_base, *this, entry_offset));
}

void DescriptorArray::SetKey(InternalIndex descriptor_number,
                             Tagged<Name> key) {
  DCHECK_LT(descriptor_number.as_int(), number_of_descriptors());
  int entry_offset = OffsetOfDescriptorAt(descriptor_number.as_int());
  EntryKeyField::Relaxed_Store(*this, entry_offset, key);
  WRITE_BARRIER(*this, entry_offset + kEntryKeyOffset, key);
}

int DescriptorArray::GetSortedKeyIndex(int descriptor_number) {
  return GetDetails(InternalIndex(descriptor_number)).pointer();
}

Tagged<Name> DescriptorArray::GetSortedKey(int descriptor_number) {
  PtrComprCageBase cage_base = GetPtrComprCageBase(*this);
  return GetSortedKey(cage_base, descriptor_number);
}

Tagged<Name> DescriptorArray::GetSortedKey(PtrComprCageBase cage_base,
                                           int descriptor_number) {
  return GetKey(cage_base, InternalIndex(GetSortedKeyIndex(descriptor_number)));
}

void DescriptorArray::SetSortedKey(int descriptor_number, int pointer) {
  PropertyDetails details = GetDetails(InternalIndex(descriptor_number));
  SetDetails(InternalIndex(descriptor_number), details.set_pointer(pointer));
}

Tagged<Object> DescriptorArray::GetStrongValue(
    InternalIndex descriptor_number) {
  PtrComprCageBase cage_base = GetPtrComprCageBase(*this);
  return Cast<Object>(GetStrongValue(cage_base, descriptor_number));
}

Tagged<Object> DescriptorArray::GetStrongValue(
    PtrComprCageBase cage_base, InternalIndex descriptor_number) {
  return Cast<Object>(GetValue(cage_base, descriptor_number));
}

void DescriptorArray::SetValue(InternalIndex descriptor_number,
                               Tagged<MaybeObject> value) {
  DCHECK_LT(descriptor_number.as_int(), number_of_descriptors());
  int entry_offset = OffsetOfDescriptorAt(descriptor_number.as_int());
  EntryValueField::Relaxed_Store(*this, entry_offset, value);
  WRITE_BARRIER(*this, entry_offset + kEntryValueOffset, value);
}

Tagged<MaybeObject> DescriptorArray::GetValue(InternalIndex descriptor_number) {
  PtrComprCageBase cage_base = GetPtrComprCageBase(*this);
  return GetValue(cage_base, descriptor_number);
}

Tagged<MaybeObject> DescriptorArray::GetValue(PtrComprCageBase cage_base,
                                              InternalIndex descriptor_number) {
  DCHECK_LT(descriptor_number.as_int(), number_of_descriptors());
  int entry_offset = OffsetOfDescriptorAt(descriptor_number.as_int());
  return EntryValueField::Relaxed_Load(cage_base, *this, entry_offset);
}

PropertyDetails DescriptorArray::GetDetails(InternalIndex descriptor_number) {
  DCHECK_LT(descriptor_number.as_int(), number_of_descriptors());
  int entry_offset = OffsetOfDescriptorAt(descriptor_number.as_int());
  Tagged<Smi> details = EntryDetailsField::Relaxed_Load(*this, entry_offset);
  return PropertyDetails(details);
}

void DescriptorArray::SetDetails(InternalIndex descriptor_number,
                                 PropertyDetails details) {
  DCHECK_LT(descriptor_number.as_int(), number_of_descriptors());
  int entry_offset = OffsetOfDescriptorAt(descriptor_number.as_int());
  EntryDetailsField::Relaxed_Store(*this, entry_offset, details.AsSmi());
}

int DescriptorArray::GetFieldIndex(InternalIndex descriptor_number) {
  DCHECK_EQ(GetDetails(descriptor_number).location(), PropertyLocation::kField);
  return GetDetails(descriptor_number).field_index();
}

Tagged<FieldType> DescriptorArray::GetFieldType(
    InternalIndex descriptor_number) {
  PtrComprCageBase cage_base = GetPtrComprCageBase(*this);
  return GetFieldType(cage_base, descriptor_number);
}

Tagged<FieldType> DescriptorArray::GetFieldType(
    PtrComprCageBase cage_base, InternalIndex descriptor_number) {
  DCHECK_EQ(GetDetails(descriptor_number).location(), PropertyLocation::kField);
  Tagged<MaybeObject> wrapped_type = GetValue(cage_base, descriptor_number);
  return Map::UnwrapFieldType(wrapped_type);
}

void DescriptorArray::Set(InternalIndex descriptor_number, Tagged<Name> key,
                          Tagged<MaybeObject> value, PropertyDetails details) {
  CHECK_LT(descriptor_number.as_int(), number_of_descriptors());
  SetKey(descriptor_number, key);
  SetDetails(descriptor_number, details);
  SetValue(descriptor_number, value);
}

void DescriptorArray::Set(InternalIndex descriptor_number, Descriptor* desc) {
  Tagged<Name> key = *desc->GetKey();
  Tagged<MaybeObject> value = *desc->GetValue();
  Set(descriptor_number, key, value, desc->GetDetails());
}

void DescriptorArray::Append(Descriptor* desc) {
  DisallowGarbageCollection no_gc;
  int descriptor_number = number_of_descriptors();
  DCHECK_LE(descriptor_number + 1, number_of_all_descriptors());
  set_number_of_descriptors(descriptor_number + 1);
  Set(InternalIndex(descriptor_number), desc);

  uint32_t desc_hash = desc->GetKey()->hash();
  // Hash value can't be zero, see String::ComputeAndSetHash()
  uint32_t collision_hash = 0;

  int insertion;

  for (insertion = descriptor_number; insertion > 0; --insertion) {
    Tagged<Name> key = GetSortedKey(insertion - 1);
    collision_hash = key->hash();
    if (collision_hash <= desc_hash) break;
    SetSortedKey(insertion, GetSortedKeyIndex(insertion - 1));
  }

  SetSortedKey(insertion, descriptor_number);

  if (V8_LIKELY(collision_hash != desc_hash)) return;

  CheckNameCollisionDuringInsertion(desc, desc_hash, insertion);
}

void DescriptorArray::SwapSortedKeys(int first, int second) {
  int first_key = GetSortedKeyIndex(first);
  SetSortedKey(first, GetSortedKeyIndex(second));
  SetSortedKey(second, first_key);
}

// static
bool DescriptorArrayMarkingState::TryUpdateIndicesToMark(
    unsigned gc_epoch, Tagged<DescriptorArray> array,
    DescriptorIndex index_to_mark) {
  const auto current_epoch = gc_epoch & Epoch::kMask;
  while (true) {
    const RawGCStateType raw_gc_state = array->raw_gc_state(kRelaxedLoad);
    const auto epoch_from_state = Epoch::decode(raw_gc_state);
    RawGCStateType new_raw_gc_state = 0;
    if (current_epoch != epoch_from_state) {
      // If the epochs do not match, then either the raw_gc_state is zero
      // (freshly allocated descriptor array) or the epoch from value lags
      // by 1.
      DCHECK_IMPLIES(raw_gc_state != 0,
                     Epoch::decode(epoch_from_state + 1) == current_epoch);
      new_raw_gc_state = NewState(current_epoch, 0, index_to_mark);
    } else {
      const DescriptorIndex already_marked = Marked::decode(raw_gc_state);
      const DescriptorIndex delta = Delta::decode(raw_gc_state);
      if ((already_marked + delta) >= index_to_mark) {
        return false;
      }
      new_raw_gc_state = NewState(current_epoch, already_marked,
                                  index_to_mark - already_marked);
    }
    if (SwapState(array, raw_gc_state, new_raw_gc_state)) {
      return true;
    }
  }
}

// static
std::pair<DescriptorArrayMarkingState::DescriptorIndex,
          DescriptorArrayMarkingState::DescriptorIndex>
DescriptorArrayMarkingState::AcquireDescriptorRangeToMark(
    unsigned gc_epoch, Tagged<DescriptorArray> array) {
  const auto current_epoch = gc_epoch & Epoch::kMask;
  while (true) {
    const RawGCStateType raw_gc_state = array->raw_gc_state(kRelaxedLoad);
    const DescriptorIndex marked = Marked::decode(raw_gc_state);
    const DescriptorIndex delta = Delta::decode(raw_gc_state);
    // We may encounter an array here that was merely pushed to the marker. In
    // such a case, we process all descriptors (if we succeed). The cases to
    // check are:
    // 1. Epoch mismatch: Happens when descriptors survive a GC cycle.
    // 2. Epoch matches but marked/delta is 0: Can happen when descriptors are
    //    newly allocated in the current cycle.
    if (current_epoch != Epoch::decode(raw_gc_state) || (marked + delta) == 0) {
      // In case number of descriptors is 0 and we reach the array through roots
      // marking, mark also slack to get a proper transition from 0 marked to X
      // marked. Otherwise, we would need to treat the state [0,0[ for marked
      // and delta as valid state which leads to double-accounting through the
      // marking barrier (when nof>1 in the barrier).
      const int16_t number_of_descriptors =
          array->number_of_descriptors() ? array->number_of_descriptors()
                                         : array->number_of_all_descriptors();
      DCHECK_GT(number_of_descriptors, 0);
      if (SwapState(array, raw_gc_state,
                    NewState(current_epoch, number_of_descriptors, 0))) {
        return {0, number_of_descriptors};
      }
      continue;
    }

    // The delta is 0, so everything has been processed. Return the marked
    // indices.
    if (delta == 0) {
      return {marked, marked};
    }

    if (SwapState(array, raw_gc_state,
                  NewState(current_epoch, marked + delta, 0))) {
      return {marked, marked + delta};
    }
  }
}

}  // namespace internal
}  // namespace v8

#include "src/objects/object-macros-undef.h"

#endif  // V8_OBJECTS_DESCRIPTOR_ARRAY_INL_H_
```