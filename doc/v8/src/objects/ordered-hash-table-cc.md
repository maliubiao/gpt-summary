Response:
The user wants a summary of the C++ source code file `v8/src/objects/ordered-hash-table.cc`.

Here's a breakdown of the request:
1. **List the functionalities of the code.** This involves understanding the purpose of the classes and methods defined in the file.
2. **Check if the file could be a Torque file.**  This is a simple check based on the file extension.
3. **Explain the relation to JavaScript with an example.** This requires identifying how the data structures in the C++ code are used in JavaScript.
4. **Provide code logic reasoning with input/output examples.** This involves explaining how specific methods work with concrete data.
5. **Illustrate common programming errors related to this code.**  This requires thinking about how developers might misuse the functionality provided.
6. **Summarize the overall functionality.** This should be a concise description of the file's purpose.

Based on the code, here are some initial observations:
- The file defines template classes `OrderedHashTable` and `SmallOrderedHashTable` which seem to be the foundation for different ordered hash table implementations.
- There are concrete classes like `OrderedHashSet`, `OrderedHashMap`, and `OrderedNameDictionary` that inherit from these templates.
- The code includes operations like `Allocate`, `Add`, `Delete`, `HasKey`, `FindEntry`, `Rehash`, `Shrink`, and `Clear`, which are common for hash table implementations.
- The presence of `kLoadFactor`, `kInitialCapacity`, and `MaxCapacity` suggests that the hash tables have dynamic sizing capabilities.
- The code interacts with the V8 heap and object system.

Planning the response:
- Start by listing the core functionalities based on the methods present.
- Address the Torque file question.
- Explain the JavaScript connection by focusing on how these data structures back certain JavaScript objects like `Map` and `Set`.
- For code logic reasoning, choose a simple operation like `Add` for `OrderedHashSet` and provide a step-by-step example.
- For common errors, consider issues like incorrect key types or exceeding capacity limits.
- Finally, provide a concise summary.
这是对 `v8/src/objects/ordered-hash-table.cc` 源代码的功能归纳：

**功能列表:**

1. **定义有序哈希表 (Ordered Hash Table) 的基类和实现:**
    *   提供了 `OrderedHashTable` 模板类，这是一个用于实现有序哈希表的基础框架。它使用一个 `FixedArray` 来存储哈希桶、键值对以及链表信息。
    *   定义了通用的哈希表操作，如分配内存 (`Allocate`, `AllocateEmpty`)、添加元素 (`Add`)、删除元素 (`Delete`)、查找元素 (`FindEntry`)、检查键是否存在 (`HasKey`)、调整容量 (`EnsureCapacityForAdding`, `Shrink`)、清空哈希表 (`Clear`) 和重新哈希 (`Rehash`)。
    *   使用了开放寻址法（通过链表实现）来解决哈希冲突。
    *   维护了哈希表的元素数量 (`NumberOfElements`) 和已删除元素数量 (`NumberOfDeletedElements`)。
    *   支持惰性删除，使用 `hash_table_hole` 标记已删除的条目。

2. **实现特定类型的有序哈希表:**
    *   定义了 `OrderedHashSet` 类，用于存储唯一的对象集合，类似于 JavaScript 的 `Set`。每个条目只存储键。
    *   定义了 `OrderedHashMap` 类，用于存储键值对，类似于 JavaScript 的 `Map`。每个条目存储键和值。
    *   定义了 `OrderedNameDictionary` 类，这是一种专门用于存储对象属性的有序哈希表。它除了存储键值对外，还存储属性的详细信息 (`PropertyDetails`)。

3. **实现小型有序哈希表的优化版本:**
    *   提供了 `SmallOrderedHashTable` 模板类及其子类 `SmallOrderedHashSet`, `SmallOrderedHashMap`, 和 `SmallOrderedNameDictionary`。
    *   这些小型版本可能在内存布局或操作上进行了优化，以适应存储少量元素的情况。

4. **提供哈希计算和查找的辅助方法:**
    *   `FindEntry` 方法根据键计算哈希值，并在哈希桶中查找对应的条目。
    *   利用 `Object::GetHash` 或 `Object::GetOrCreateHash` 来获取对象的哈希值。

5. **支持哈希表的扩容和收缩:**
    *   `EnsureCapacityForAdding` 方法在添加元素前检查容量，并在必要时分配更大的哈希表。
    *   `Shrink` 方法在元素数量减少时尝试缩小哈希表以节省内存。
    *   `Rehash` 方法在调整容量时重新计算所有元素的哈希值并将其放入新的哈希表中。

6. **支持哈希表的清除操作:**
    *   `Clear` 方法创建一个新的、初始容量的哈希表，并将旧表标记为已清除。

7. **提供将哈希表转换为数组的方法:**
    *   `OrderedHashSet::ConvertToKeysArray` 方法将 `OrderedHashSet` 中的键提取到一个 `FixedArray` 中。

**关于文件类型:**

`v8/src/objects/ordered-hash-table.cc` 以 `.cc` 结尾，这表明它是一个 **C++ 源代码文件**，而不是 V8 的 Torque 源代码（以 `.tq` 结尾）。

**与 JavaScript 的关系及示例:**

`OrderedHashSet` 和 `OrderedHashMap` 的功能与 JavaScript 中的 `Set` 和 `Map` 非常相似。它们都维护元素的插入顺序，并且允许快速查找。`OrderedNameDictionary` 则与 JavaScript 对象的属性存储密切相关。

**JavaScript 示例：**

```javascript
// 使用 Set (对应 OrderedHashSet)
const mySet = new Set();
mySet.add('apple');
mySet.add('banana');
console.log(mySet.has('apple')); // 输出 true
console.log(mySet.size);        // 输出 2

// 使用 Map (对应 OrderedHashMap)
const myMap = new Map();
myMap.set('a', 1);
myMap.set('b', 2);
console.log(myMap.get('a'));   // 输出 1
console.log(myMap.has('b'));   // 输出 true
console.log(myMap.size);        // 输出 2

// JavaScript 对象的属性存储在底层可能使用类似 OrderedNameDictionary 的结构
const myObject = {
  name: 'John',
  age: 30
};
console.log(myObject.name); // 访问属性
```

在 V8 引擎的内部实现中，当 JavaScript 引擎需要维护对象属性的插入顺序或者需要高效地进行键值查找时，可能会使用 `OrderedHashSet`、`OrderedHashMap` 或 `OrderedNameDictionary` 这些 C++ 类。

**代码逻辑推理 (以 `OrderedHashSet::Add` 为例):**

**假设输入:**

*   `table`: 一个已存在的 `OrderedHashSet` 实例，当前包含元素 `{'a', 'b'}`。
*   `key`: 要添加的字符串 `"c"`。

**步骤:**

1. **计算哈希值:** 计算键 `"c"` 的哈希值。
2. **查找现有键 (优化):** 如果哈希表不为空，检查 `"c"` 是否已存在于哈希表中。如果存在，则直接返回原哈希表。
3. **检查容量:** 检查哈希表是否有足够的容量来添加新元素。如果容量不足，则会触发扩容操作 (`EnsureCapacityForAdding`)，创建一个更大的新哈希表并将旧数据迁移过去。
4. **确定插入位置:** 根据键的哈希值计算出对应的哈希桶。
5. **插入新条目:**
    *   在新哈希表的末尾（未使用的槽位）创建一个新的条目。
    *   将键 `"c"` 存储在新条目的键的位置。
    *   更新新条目的链表指针，指向原来该哈希桶的第一个条目（如果存在）。
    *   更新哈希桶的指针，使其指向新插入的条目。
6. **更新元素计数:** 将哈希表的元素数量递增。

**假设输出:**

*   `table`: 更新后的 `OrderedHashSet` 实例，包含元素 `{'a', 'b', 'c'}`，并且内部结构已相应更新，`"c"` 被正确地插入到哈希表中。

**用户常见的编程错误 (与 JavaScript 的 `Set` 和 `Map` 类比):**

1. **将对象作为键时不考虑对象标识:** 在 JavaScript 中，对象作为 `Map` 或 `Set` 的键时，比较的是对象的引用，而不是对象的内容。如果用户创建了两个内容相同的对象，但它们是不同的实例，则会被视为不同的键。

    ```javascript
    const obj1 = { value: 1 };
    const obj2 = { value: 1 };
    const myMap = new Map();
    myMap.set(obj1, 'first');
    myMap.set(obj2, 'second');
    console.log(myMap.size); // 输出 2，因为 obj1 和 obj2 是不同的对象
    ```

2. **误解 `Set` 和 `Map` 的键的唯一性:**  用户可能会尝试向 `Set` 中添加相同的元素多次，或者向 `Map` 中添加相同的键多次。`Set` 会忽略重复的元素，而 `Map` 会用新的值覆盖旧的值。

    ```javascript
    const mySet = new Set();
    mySet.add('apple');
    mySet.add('apple');
    console.log(mySet.size); // 输出 1

    const myMap = new Map();
    myMap.set('a', 1);
    myMap.set('a', 2);
    console.log(myMap.get('a')); // 输出 2
    ```

3. **依赖哈希表的特定迭代顺序进行编程，但不理解其有序性:** 虽然 `OrderedHashSet` 和 `OrderedHashMap` 保持插入顺序，但在某些情况下（例如，在哈希表调整大小后），底层的内存布局可能会发生变化，虽然逻辑顺序保持不变，但直接访问底层数据结构可能会导致意想不到的结果。这在 C++ 中直接操作 V8 内部数据结构时需要注意。在 JavaScript 中，通常通过标准的 `Set` 和 `Map` 方法进行迭代，这些方法保证了插入顺序。

**功能归纳:**

`v8/src/objects/ordered-hash-table.cc` 文件定义了 V8 引擎中用于实现有序哈希表的核心数据结构和操作。它提供了通用的哈希表框架以及针对集合 (`OrderedHashSet`)、映射 (`OrderedHashMap`) 和对象属性存储 (`OrderedNameDictionary`) 的特定实现。这些数据结构在 V8 引擎内部用于高效地存储和检索数据，并为 JavaScript 中的 `Set` 和 `Map` 等内置对象提供底层支持。该文件包含了内存管理、哈希计算、冲突解决、容量调整等关键的哈希表功能。

### 提示词
```
这是目录为v8/src/objects/ordered-hash-table.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/ordered-hash-table.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2018 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/objects/ordered-hash-table.h"

#include "src/execution/isolate.h"
#include "src/heap/heap-inl.h"
#include "src/objects/internal-index.h"
#include "src/objects/js-collection-inl.h"
#include "src/objects/objects-inl.h"
#include "src/objects/ordered-hash-table-inl.h"
#include "src/roots/roots.h"

namespace v8 {
namespace internal {

template <class Derived, int entrysize>
MaybeHandle<Derived> OrderedHashTable<Derived, entrysize>::Allocate(
    Isolate* isolate, int capacity, AllocationType allocation) {
  // Capacity must be a power of two, since we depend on being able
  // to divide and multiple by 2 (kLoadFactor) to derive capacity
  // from number of buckets. If we decide to change kLoadFactor
  // to something other than 2, capacity should be stored as another
  // field of this object.
  capacity =
      base::bits::RoundUpToPowerOfTwo32(std::max({kInitialCapacity, capacity}));
  if (capacity > MaxCapacity()) {
    THROW_NEW_ERROR_RETURN_VALUE(
        isolate, NewRangeError(MessageTemplate::kTooManyProperties), {});
  }
  int num_buckets = capacity / kLoadFactor;
  Handle<FixedArray> backing_store = isolate->factory()->NewFixedArrayWithMap(
      Derived::GetMap(ReadOnlyRoots(isolate)),
      HashTableStartIndex() + num_buckets + (capacity * kEntrySize),
      allocation);
  Handle<Derived> table = Cast<Derived>(backing_store);
  DisallowGarbageCollection no_gc;
  Tagged<Derived> raw_table = *table;
  for (int i = 0; i < num_buckets; ++i) {
    raw_table->set(HashTableStartIndex() + i, Smi::FromInt(kNotFound));
  }
  raw_table->SetNumberOfBuckets(num_buckets);
  raw_table->SetNumberOfElements(0);
  raw_table->SetNumberOfDeletedElements(0);
  return table;
}

template <class Derived, int entrysize>
MaybeHandle<Derived> OrderedHashTable<Derived, entrysize>::AllocateEmpty(
    Isolate* isolate, AllocationType allocation, RootIndex root_index) {
  // This is only supposed to be used to create the canonical empty versions
  // of each ordered structure, and should not be used afterwards.
  // Requires that the map has already been set up in the roots table.
  DCHECK(!ReadOnlyRoots(isolate).is_initialized(root_index));

  Handle<FixedArray> backing_store = isolate->factory()->NewFixedArrayWithMap(
      Derived::GetMap(ReadOnlyRoots(isolate)), HashTableStartIndex(),
      allocation);
  Handle<Derived> table = Cast<Derived>(backing_store);
  DisallowHandleAllocation no_gc;
  Tagged<Derived> raw_table = *table;
  raw_table->SetNumberOfBuckets(0);
  raw_table->SetNumberOfElements(0);
  raw_table->SetNumberOfDeletedElements(0);
  return table;
}

template <class Derived, int entrysize>
MaybeHandle<Derived>
OrderedHashTable<Derived, entrysize>::EnsureCapacityForAdding(
    Isolate* isolate, Handle<Derived> table) {
  DCHECK(!table->IsObsolete());

  int nof = table->NumberOfElements();
  int nod = table->NumberOfDeletedElements();
  int capacity = table->Capacity();
  if ((nof + nod) < capacity) return table;

  int new_capacity;
  if (capacity == 0) {
    // step from empty to minimum proper size
    new_capacity = kInitialCapacity;
  } else if (nod >= (capacity >> 1)) {
    // Don't need to grow if we can simply clear out deleted entries instead.
    // Note that we can't compact in place, though, so we always allocate
    // a new table.
    new_capacity = capacity;
  } else {
    new_capacity = capacity << 1;
  }

  return Derived::Rehash(isolate, table, new_capacity);
}

template <class Derived, int entrysize>
Handle<Derived> OrderedHashTable<Derived, entrysize>::Shrink(
    Isolate* isolate, Handle<Derived> table) {
  DCHECK(!table->IsObsolete());

  int nof = table->NumberOfElements();
  int capacity = table->Capacity();
  if (nof >= (capacity >> 2)) return table;
  return Derived::Rehash(isolate, table, capacity / 2).ToHandleChecked();
}

template <class Derived, int entrysize>
Handle<Derived> OrderedHashTable<Derived, entrysize>::Clear(
    Isolate* isolate, Handle<Derived> table) {
  DCHECK(!table->IsObsolete());

  AllocationType allocation_type = HeapLayout::InYoungGeneration(*table)
                                       ? AllocationType::kYoung
                                       : AllocationType::kOld;

  Handle<Derived> new_table =
      Allocate(isolate, kInitialCapacity, allocation_type).ToHandleChecked();

  if (table->NumberOfBuckets() > 0) {
    // Don't try to modify the empty canonical table which lives in RO space.
    table->SetNextTable(*new_table);
    table->SetNumberOfDeletedElements(kClearedTableSentinel);
  }

  return new_table;
}

template <class Derived, int entrysize>
bool OrderedHashTable<Derived, entrysize>::HasKey(Isolate* isolate,
                                                  Tagged<Derived> table,
                                                  Tagged<Object> key) {
  DCHECK_IMPLIES(entrysize == 1, IsOrderedHashSet(table));
  DCHECK_IMPLIES(entrysize == 2, IsOrderedHashMap(table));
  DisallowGarbageCollection no_gc;
  InternalIndex entry = table->FindEntry(isolate, key);
  return entry.is_found();
}

template <class Derived, int entrysize>
InternalIndex OrderedHashTable<Derived, entrysize>::FindEntry(
    Isolate* isolate, Tagged<Object> key) {
  if (NumberOfElements() == 0) {
    // This is not just an optimization but also ensures that we do the right
    // thing if Capacity() == 0
    return InternalIndex::NotFound();
  }

  int raw_entry;
  // This special cases for Smi, so that we avoid the HandleScope
  // creation below.
  if (IsSmi(key)) {
    uint32_t hash = ComputeUnseededHash(Smi::ToInt(key));
    raw_entry = HashToEntryRaw(hash & Smi::kMaxValue);
  } else {
    HandleScope scope(isolate);
    Tagged<Object> hash = Object::GetHash(key);
    // If the object does not have an identity hash, it was never used as a key
    if (IsUndefined(hash, isolate)) return InternalIndex::NotFound();
    raw_entry = HashToEntryRaw(Smi::ToInt(hash));
  }

  // Walk the chain in the bucket to find the key.
  while (raw_entry != kNotFound) {
    Tagged<Object> candidate_key = KeyAt(InternalIndex(raw_entry));
    if (Object::SameValueZero(candidate_key, key))
      return InternalIndex(raw_entry);
    raw_entry = NextChainEntryRaw(raw_entry);
  }

  return InternalIndex::NotFound();
}

MaybeHandle<OrderedHashSet> OrderedHashSet::Add(Isolate* isolate,
                                                Handle<OrderedHashSet> table,
                                                DirectHandle<Object> key) {
  int hash;
  {
    DisallowGarbageCollection no_gc;
    Tagged<Object> raw_key = *key;
    Tagged<OrderedHashSet> raw_table = *table;
    hash = Object::GetOrCreateHash(raw_key, isolate).value();
    if (raw_table->NumberOfElements() > 0) {
      int raw_entry = raw_table->HashToEntryRaw(hash);
      // Walk the chain of the bucket and try finding the key.
      while (raw_entry != kNotFound) {
        Tagged<Object> candidate_key =
            raw_table->KeyAt(InternalIndex(raw_entry));
        // Do not add if we have the key already
        if (Object::SameValueZero(candidate_key, raw_key)) return table;
        raw_entry = raw_table->NextChainEntryRaw(raw_entry);
      }
    }
  }

  MaybeHandle<OrderedHashSet> table_candidate =
      OrderedHashSet::EnsureCapacityForAdding(isolate, table);
  if (!table_candidate.ToHandle(&table)) {
    CHECK(isolate->has_exception());
    return table_candidate;
  }
  DisallowGarbageCollection no_gc;
  Tagged<OrderedHashSet> raw_table = *table;
  // Read the existing bucket values.
  int bucket = raw_table->HashToBucket(hash);
  int previous_entry = raw_table->HashToEntryRaw(hash);
  int nof = raw_table->NumberOfElements();
  // Insert a new entry at the end,
  int new_entry = nof + raw_table->NumberOfDeletedElements();
  int new_index = raw_table->EntryToIndexRaw(new_entry);
  raw_table->set(new_index, *key);
  raw_table->set(new_index + kChainOffset, Smi::FromInt(previous_entry));
  // and point the bucket to the new entry.
  raw_table->set(HashTableStartIndex() + bucket, Smi::FromInt(new_entry));
  raw_table->SetNumberOfElements(nof + 1);
  return table;
}

Handle<FixedArray> OrderedHashSet::ConvertToKeysArray(
    Isolate* isolate, Handle<OrderedHashSet> table, GetKeysConversion convert) {
  int length = table->NumberOfElements();
  int nof_buckets = table->NumberOfBuckets();
  // Convert the dictionary to a linear list.
  Handle<FixedArray> result = Cast<FixedArray>(table);
  // From this point on table is no longer a valid OrderedHashSet.
  result->set_map(isolate, ReadOnlyRoots(isolate).fixed_array_map());
  int const kMaxStringTableEntries =
      isolate->heap()->MaxNumberToStringCacheSize();
  for (int i = 0; i < length; i++) {
    int index = HashTableStartIndex() + nof_buckets + (i * kEntrySize);
    Tagged<Object> key = table->get(index);
    uint32_t index_value;
    if (convert == GetKeysConversion::kConvertToString) {
      if (Object::ToArrayIndex(key, &index_value)) {
        // Avoid trashing the Number2String cache if indices get very large.
        bool use_cache = i < kMaxStringTableEntries;
        key = *isolate->factory()->Uint32ToString(index_value, use_cache);
      } else {
        CHECK(IsName(key));
      }
    } else if (convert == GetKeysConversion::kNoNumbers) {
      DCHECK(!Object::ToArrayIndex(key, &index_value));
    }
    result->set(i, key);
  }
  return FixedArray::RightTrimOrEmpty(isolate, result, length);
}

Tagged<HeapObject> OrderedHashSet::GetEmpty(ReadOnlyRoots ro_roots) {
  return ro_roots.empty_ordered_hash_set();
}

Tagged<HeapObject> OrderedHashMap::GetEmpty(ReadOnlyRoots ro_roots) {
  return ro_roots.empty_ordered_hash_map();
}

template <class Derived, int entrysize>
MaybeHandle<Derived> OrderedHashTable<Derived, entrysize>::Rehash(
    Isolate* isolate, Handle<Derived> table) {
  return OrderedHashTable<Derived, entrysize>::Rehash(isolate, table,
                                                      table->Capacity());
}

template <class Derived, int entrysize>
MaybeHandle<Derived> OrderedHashTable<Derived, entrysize>::Rehash(
    Isolate* isolate, Handle<Derived> table, int new_capacity) {
  DCHECK(!table->IsObsolete());

  MaybeHandle<Derived> new_table_candidate = Derived::Allocate(
      isolate, new_capacity,
      HeapLayout::InYoungGeneration(*table) ? AllocationType::kYoung
                                            : AllocationType::kOld);
  Handle<Derived> new_table;
  if (!new_table_candidate.ToHandle(&new_table)) {
    return new_table_candidate;
  }
  int new_buckets = new_table->NumberOfBuckets();
  int new_entry = 0;
  int removed_holes_index = 0;

  DisallowGarbageCollection no_gc;

  for (InternalIndex old_entry : table->IterateEntries()) {
    int old_entry_raw = old_entry.as_int();
    Tagged<Object> key = table->KeyAt(old_entry);
    if (IsHashTableHole(key, isolate)) {
      table->SetRemovedIndexAt(removed_holes_index++, old_entry_raw);
      continue;
    }

    Tagged<Object> hash = Object::GetHash(key);
    int bucket = Smi::ToInt(hash) & (new_buckets - 1);
    Tagged<Object> chain_entry = new_table->get(HashTableStartIndex() + bucket);
    new_table->set(HashTableStartIndex() + bucket, Smi::FromInt(new_entry));
    int new_index = new_table->EntryToIndexRaw(new_entry);
    int old_index = table->EntryToIndexRaw(old_entry_raw);
    for (int i = 0; i < entrysize; ++i) {
      Tagged<Object> value = table->get(old_index + i);
      new_table->set(new_index + i, value);
    }
    new_table->set(new_index + kChainOffset, chain_entry);
    ++new_entry;
  }

  DCHECK_EQ(table->NumberOfDeletedElements(), removed_holes_index);

  new_table->SetNumberOfElements(table->NumberOfElements());
  if (table->NumberOfBuckets() > 0) {
    // Don't try to modify the empty canonical table which lives in RO space.
    table->SetNextTable(*new_table);
  }

  return new_table_candidate;
}

MaybeHandle<OrderedHashSet> OrderedHashSet::Rehash(Isolate* isolate,
                                                   Handle<OrderedHashSet> table,
                                                   int new_capacity) {
  return Base::Rehash(isolate, table, new_capacity);
}

MaybeHandle<OrderedHashSet> OrderedHashSet::Rehash(
    Isolate* isolate, Handle<OrderedHashSet> table) {
  return Base::Rehash(isolate, table);
}

MaybeHandle<OrderedHashMap> OrderedHashMap::Rehash(
    Isolate* isolate, Handle<OrderedHashMap> table) {
  return Base::Rehash(isolate, table);
}

MaybeHandle<OrderedHashMap> OrderedHashMap::Rehash(Isolate* isolate,
                                                   Handle<OrderedHashMap> table,
                                                   int new_capacity) {
  return Base::Rehash(isolate, table, new_capacity);
}

MaybeHandle<OrderedNameDictionary> OrderedNameDictionary::Rehash(
    Isolate* isolate, Handle<OrderedNameDictionary> table, int new_capacity) {
  MaybeHandle<OrderedNameDictionary> new_table_candidate =
      Base::Rehash(isolate, table, new_capacity);
  Handle<OrderedNameDictionary> new_table;
  if (new_table_candidate.ToHandle(&new_table)) {
    new_table->SetHash(table->Hash());
  }
  return new_table_candidate;
}

template <class Derived, int entrysize>
bool OrderedHashTable<Derived, entrysize>::Delete(Isolate* isolate,
                                                  Tagged<Derived> table,
                                                  Tagged<Object> key) {
  DisallowGarbageCollection no_gc;
  InternalIndex entry = table->FindEntry(isolate, key);
  if (entry.is_not_found()) return false;

  int nof = table->NumberOfElements();
  int nod = table->NumberOfDeletedElements();
  int index = table->EntryToIndex(entry);

  Tagged<Object> hash_table_hole =
      ReadOnlyRoots(isolate).hash_table_hole_value();
  for (int i = 0; i < entrysize; ++i) {
    table->set(index + i, hash_table_hole);
  }

  table->SetNumberOfElements(nof - 1);
  table->SetNumberOfDeletedElements(nod + 1);

  return true;
}

Address OrderedHashMap::GetHash(Isolate* isolate, Address raw_key) {
  DisallowGarbageCollection no_gc;
  Tagged<Object> key(raw_key);
  Tagged<Object> hash = Object::GetHash(key);
  // If the object does not have an identity hash, it was never used as a key
  if (IsUndefined(hash, isolate)) return Smi::FromInt(-1).ptr();
  DCHECK(IsSmi(hash));
  DCHECK_GE(Cast<Smi>(hash).value(), 0);
  return hash.ptr();
}

MaybeHandle<OrderedHashMap> OrderedHashMap::Add(Isolate* isolate,
                                                Handle<OrderedHashMap> table,
                                                DirectHandle<Object> key,
                                                DirectHandle<Object> value) {
  int hash = Object::GetOrCreateHash(*key, isolate).value();
  if (table->NumberOfElements() > 0) {
    int raw_entry = table->HashToEntryRaw(hash);
    // Walk the chain of the bucket and try finding the key.
    {
      DisallowGarbageCollection no_gc;
      Tagged<Object> raw_key = *key;
      while (raw_entry != kNotFound) {
        Tagged<Object> candidate_key = table->KeyAt(InternalIndex(raw_entry));
        // Do not add if we have the key already
        if (Object::SameValueZero(candidate_key, raw_key)) return table;
        raw_entry = table->NextChainEntryRaw(raw_entry);
      }
    }
  }

  MaybeHandle<OrderedHashMap> table_candidate =
      OrderedHashMap::EnsureCapacityForAdding(isolate, table);
  if (!table_candidate.ToHandle(&table)) {
    return table_candidate;
  }
  DisallowGarbageCollection no_gc;
  Tagged<OrderedHashMap> raw_table = *table;
  // Read the existing bucket values.
  int bucket = raw_table->HashToBucket(hash);
  int previous_entry = raw_table->HashToEntryRaw(hash);
  int nof = raw_table->NumberOfElements();
  // Insert a new entry at the end,
  int new_entry = nof + raw_table->NumberOfDeletedElements();
  int new_index = raw_table->EntryToIndexRaw(new_entry);
  raw_table->set(new_index, *key);
  raw_table->set(new_index + kValueOffset, *value);
  raw_table->set(new_index + kChainOffset, Smi::FromInt(previous_entry));
  // and point the bucket to the new entry.
  raw_table->set(HashTableStartIndex() + bucket, Smi::FromInt(new_entry));
  raw_table->SetNumberOfElements(nof + 1);
  return table;
}

void OrderedHashMap::SetEntry(InternalIndex entry, Tagged<Object> key,
                              Tagged<Object> value) {
  DisallowGarbageCollection no_gc;
  int index = EntryToIndex(entry);
  this->set(index, key);
  this->set(index + kValueOffset, value);
}

template <typename IsolateT>
InternalIndex OrderedNameDictionary::FindEntry(IsolateT* isolate,
                                               Tagged<Object> key) {
  DisallowGarbageCollection no_gc;

  DCHECK(IsUniqueName(key));
  Tagged<Name> raw_key = Cast<Name>(key);

  if (NumberOfElements() == 0) {
    // This is not just an optimization but also ensures that we do the right
    // thing if Capacity() == 0
    return InternalIndex::NotFound();
  }

  int raw_entry = HashToEntryRaw(raw_key->hash());
  while (raw_entry != kNotFound) {
    InternalIndex entry(raw_entry);
    Tagged<Object> candidate_key = KeyAt(entry);
    DCHECK(IsHashTableHole(candidate_key) ||
           IsUniqueName(Cast<Name>(candidate_key)));
    if (candidate_key == raw_key) return entry;

    // TODO(gsathya): This is loading the bucket count from the hash
    // table for every iteration. This should be peeled out of the
    // loop.
    raw_entry = NextChainEntryRaw(raw_entry);
  }

  return InternalIndex::NotFound();
}

MaybeHandle<OrderedNameDictionary> OrderedNameDictionary::Add(
    Isolate* isolate, Handle<OrderedNameDictionary> table,
    DirectHandle<Name> key, DirectHandle<Object> value,
    PropertyDetails details) {
  DCHECK(IsUniqueName(*key));
  DCHECK(table->FindEntry(isolate, *key).is_not_found());

  MaybeHandle<OrderedNameDictionary> table_candidate =
      OrderedNameDictionary::EnsureCapacityForAdding(isolate, table);
  if (!table_candidate.ToHandle(&table)) {
    return table_candidate;
  }
  DisallowGarbageCollection no_gc;
  Tagged<OrderedNameDictionary> raw_table = *table;
  // Read the existing bucket values.
  int hash = key->hash();
  int bucket = raw_table->HashToBucket(hash);
  int previous_entry = raw_table->HashToEntryRaw(hash);
  int nof = raw_table->NumberOfElements();
  // Insert a new entry at the end,
  int new_entry = nof + raw_table->NumberOfDeletedElements();
  int new_index = raw_table->EntryToIndexRaw(new_entry);
  raw_table->set(new_index, *key);
  raw_table->set(new_index + kValueOffset, *value);

  // TODO(gsathya): Optimize how PropertyDetails are stored in this
  // dictionary to save memory (by reusing padding?) and performance
  // (by not doing the Smi conversion).
  raw_table->set(new_index + kPropertyDetailsOffset, details.AsSmi());

  raw_table->set(new_index + kChainOffset, Smi::FromInt(previous_entry));
  // and point the bucket to the new entry.
  raw_table->set(HashTableStartIndex() + bucket, Smi::FromInt(new_entry));
  raw_table->SetNumberOfElements(nof + 1);
  return table;
}

void OrderedNameDictionary::SetEntry(InternalIndex entry, Tagged<Object> key,
                                     Tagged<Object> value,
                                     PropertyDetails details) {
  DisallowGarbageCollection gc;
  DCHECK_IMPLIES(!IsName(key), IsHashTableHole(key));
  DisallowGarbageCollection no_gc;
  int index = EntryToIndex(entry);
  this->set(index, key);
  this->set(index + kValueOffset, value);

  // TODO(gsathya): Optimize how PropertyDetails are stored in this
  // dictionary to save memory (by reusing padding?) and performance
  // (by not doing the Smi conversion).
  this->set(index + kPropertyDetailsOffset, details.AsSmi());
}

Handle<OrderedNameDictionary> OrderedNameDictionary::DeleteEntry(
    Isolate* isolate, Handle<OrderedNameDictionary> table,
    InternalIndex entry) {
  DCHECK(entry.is_found());

  Tagged<Object> hash_table_hole =
      ReadOnlyRoots(isolate).hash_table_hole_value();
  PropertyDetails details = PropertyDetails::Empty();
  table->SetEntry(entry, hash_table_hole, hash_table_hole, details);

  int nof = table->NumberOfElements();
  table->SetNumberOfElements(nof - 1);
  int nod = table->NumberOfDeletedElements();
  table->SetNumberOfDeletedElements(nod + 1);

  return Shrink(isolate, table);
}

template <typename IsolateT>
MaybeHandle<OrderedHashSet> OrderedHashSet::Allocate(
    IsolateT* isolate, int capacity, AllocationType allocation) {
  return Base::Allocate(isolate, capacity, allocation);
}

template <typename IsolateT>
MaybeHandle<OrderedHashMap> OrderedHashMap::Allocate(
    IsolateT* isolate, int capacity, AllocationType allocation) {
  return Base::Allocate(isolate, capacity, allocation);
}

MaybeHandle<OrderedNameDictionary> OrderedNameDictionary::Allocate(
    Isolate* isolate, int capacity, AllocationType allocation) {
  MaybeHandle<OrderedNameDictionary> table_candidate =
      Base::Allocate(isolate, capacity, allocation);
  Handle<OrderedNameDictionary> table;
  if (table_candidate.ToHandle(&table)) {
    table->SetHash(PropertyArray::kNoHashSentinel);
  }
  return table_candidate;
}

MaybeHandle<OrderedHashSet> OrderedHashSet::AllocateEmpty(
    Isolate* isolate, AllocationType allocation) {
  RootIndex ri = RootIndex::kEmptyOrderedHashSet;
  return Base::AllocateEmpty(isolate, allocation, ri);
}

MaybeHandle<OrderedHashMap> OrderedHashMap::AllocateEmpty(
    Isolate* isolate, AllocationType allocation) {
  RootIndex ri = RootIndex::kEmptyOrderedHashMap;
  return Base::AllocateEmpty(isolate, allocation, ri);
}

MaybeHandle<OrderedNameDictionary> OrderedNameDictionary::AllocateEmpty(
    Isolate* isolate, AllocationType allocation) {
  RootIndex ri = RootIndex::kEmptyOrderedPropertyDictionary;
  MaybeHandle<OrderedNameDictionary> table_candidate =
      Base::AllocateEmpty(isolate, allocation, ri);
  Handle<OrderedNameDictionary> table;
  if (table_candidate.ToHandle(&table)) {
    table->SetHash(PropertyArray::kNoHashSentinel);
  }

  return table_candidate;
}

template V8_EXPORT_PRIVATE MaybeHandle<OrderedHashSet>
OrderedHashTable<OrderedHashSet, 1>::EnsureCapacityForAdding(
    Isolate* isolate, Handle<OrderedHashSet> table);

template V8_EXPORT_PRIVATE Handle<OrderedHashSet>
OrderedHashTable<OrderedHashSet, 1>::Shrink(Isolate* isolate,
                                            Handle<OrderedHashSet> table);

template V8_EXPORT_PRIVATE Handle<OrderedHashSet>
OrderedHashTable<OrderedHashSet, 1>::Clear(Isolate* isolate,
                                           Handle<OrderedHashSet> table);

template V8_EXPORT_PRIVATE MaybeHandle<OrderedHashSet> OrderedHashSet::Allocate(
    Isolate* isolate, int capacity, AllocationType allocation);

template V8_EXPORT_PRIVATE bool OrderedHashTable<OrderedHashSet, 1>::HasKey(
    Isolate* isolate, Tagged<OrderedHashSet> table, Tagged<Object> key);

template V8_EXPORT_PRIVATE bool OrderedHashTable<OrderedHashSet, 1>::Delete(
    Isolate* isolate, Tagged<OrderedHashSet> table, Tagged<Object> key);

template V8_EXPORT_PRIVATE InternalIndex
OrderedHashTable<OrderedHashSet, 1>::FindEntry(Isolate* isolate,
                                               Tagged<Object> key);

template V8_EXPORT_PRIVATE MaybeHandle<OrderedHashMap>
OrderedHashTable<OrderedHashMap, 2>::EnsureCapacityForAdding(
    Isolate* isolate, Handle<OrderedHashMap> table);

template V8_EXPORT_PRIVATE Handle<OrderedHashMap>
OrderedHashTable<OrderedHashMap, 2>::Shrink(Isolate* isolate,
                                            Handle<OrderedHashMap> table);

template V8_EXPORT_PRIVATE Handle<OrderedHashMap>
OrderedHashTable<OrderedHashMap, 2>::Clear(Isolate* isolate,
                                           Handle<OrderedHashMap> table);

template V8_EXPORT_PRIVATE MaybeHandle<OrderedHashMap> OrderedHashMap::Allocate(
    Isolate* isolate, int capacity, AllocationType allocation);

template V8_EXPORT_PRIVATE bool OrderedHashTable<OrderedHashMap, 2>::HasKey(
    Isolate* isolate, Tagged<OrderedHashMap> table, Tagged<Object> key);

template V8_EXPORT_PRIVATE bool OrderedHashTable<OrderedHashMap, 2>::Delete(
    Isolate* isolate, Tagged<OrderedHashMap> table, Tagged<Object> key);

template V8_EXPORT_PRIVATE InternalIndex
OrderedHashTable<OrderedHashMap, 2>::FindEntry(Isolate* isolate,
                                               Tagged<Object> key);

template V8_EXPORT_PRIVATE Handle<OrderedNameDictionary>
OrderedHashTable<OrderedNameDictionary, 3>::Shrink(
    Isolate* isolate, Handle<OrderedNameDictionary> table);

template MaybeHandle<OrderedNameDictionary>
OrderedHashTable<OrderedNameDictionary, 3>::EnsureCapacityForAdding(
    Isolate* isolate, Handle<OrderedNameDictionary> table);

template V8_EXPORT_PRIVATE InternalIndex
OrderedNameDictionary::FindEntry(Isolate* isolate, Tagged<Object> key);

template V8_EXPORT_PRIVATE InternalIndex
OrderedNameDictionary::FindEntry(LocalIsolate* isolate, Tagged<Object> key);

template <>
Handle<SmallOrderedHashSet>
SmallOrderedHashTable<SmallOrderedHashSet>::Allocate(
    Isolate* isolate, int capacity, AllocationType allocation) {
  return isolate->factory()->NewSmallOrderedHashSet(capacity, allocation);
}

template <>
Handle<SmallOrderedHashMap>
SmallOrderedHashTable<SmallOrderedHashMap>::Allocate(
    Isolate* isolate, int capacity, AllocationType allocation) {
  return isolate->factory()->NewSmallOrderedHashMap(capacity, allocation);
}

template <>
Handle<SmallOrderedNameDictionary>
SmallOrderedHashTable<SmallOrderedNameDictionary>::Allocate(
    Isolate* isolate, int capacity, AllocationType allocation) {
  return isolate->factory()->NewSmallOrderedNameDictionary(capacity,
                                                           allocation);
}

template <class Derived>
void SmallOrderedHashTable<Derived>::Initialize(Isolate* isolate,
                                                int capacity) {
  DisallowGarbageCollection no_gc;
  int num_buckets = capacity / kLoadFactor;
  int num_chains = capacity;

  SetNumberOfBuckets(num_buckets);
  SetNumberOfElements(0);
  SetNumberOfDeletedElements(0);
  memset(reinterpret_cast<void*>(field_address(PaddingOffset())), 0,
         PaddingSize());

  Address hashtable_start = GetHashTableStartAddress(capacity);
  memset(reinterpret_cast<uint8_t*>(hashtable_start), kNotFound,
         num_buckets + num_chains);

  MemsetTagged(RawField(DataTableStartOffset()),
               ReadOnlyRoots(isolate).the_hole_value(),
               capacity * Derived::kEntrySize);

#ifdef DEBUG
  for (int i = 0; i < num_buckets; ++i) {
    DCHECK_EQ(kNotFound, GetFirstEntry(i));
  }

  for (int i = 0; i < num_chains; ++i) {
    DCHECK_EQ(kNotFound, GetNextEntry(i));
  }

  for (int i = 0; i < capacity; ++i) {
    for (int j = 0; j < Derived::kEntrySize; j++) {
      DCHECK_EQ(ReadOnlyRoots(isolate).the_hole_value(), GetDataEntry(i, j));
    }
  }
#endif  // DEBUG
}

MaybeHandle<SmallOrderedHashSet> SmallOrderedHashSet::Add(
    Isolate* isolate, Handle<SmallOrderedHashSet> table,
    DirectHandle<Object> key) {
  if (table->HasKey(isolate, key)) return table;

  if (table->UsedCapacity() >= table->Capacity()) {
    MaybeHandle<SmallOrderedHashSet> new_table =
        SmallOrderedHashSet::Grow(isolate, table);
    if (!new_table.ToHandle(&table)) {
      return MaybeHandle<SmallOrderedHashSet>();
    }
  }

  DisallowGarbageCollection no_gc;
  Tagged<SmallOrderedHashSet> raw_table = *table;
  int hash = Object::GetOrCreateHash(*key, isolate).value();
  int nof = raw_table->NumberOfElements();

  // Read the existing bucket values.
  int bucket = raw_table->HashToBucket(hash);
  int previous_entry = raw_table->HashToFirstEntry(hash);

  // Insert a new entry at the end,
  int new_entry = nof + raw_table->NumberOfDeletedElements();

  raw_table->SetDataEntry(new_entry, SmallOrderedHashSet::kKeyIndex, *key);
  raw_table->SetFirstEntry(bucket, new_entry);
  raw_table->SetNextEntry(new_entry, previous_entry);

  // and update book keeping.
  raw_table->SetNumberOfElements(nof + 1);

  return table;
}

bool SmallOrderedHashSet::Delete(Isolate* isolate,
                                 Tagged<SmallOrderedHashSet> table,
                                 Tagged<Object> key) {
  return SmallOrderedHashTable<SmallOrderedHashSet>::Delete(isolate, table,
                                                            key);
}

bool SmallOrderedHashSet::HasKey(Isolate* isolate, DirectHandle<Object> key) {
  return SmallOrderedHashTable<SmallOrderedHashSet>::HasKey(isolate, key);
}

MaybeHandle<SmallOrderedHashMap> SmallOrderedHashMap::Add(
    Isolate* isolate, Handle<SmallOrderedHashMap> table,
    DirectHandle<Object> key, DirectHandle<Object> value) {
  if (table->HasKey(isolate, key)) return table;

  if (table->UsedCapacity() >= table->Capacity()) {
    MaybeHandle<SmallOrderedHashMap> new_table =
        SmallOrderedHashMap::Grow(isolate, table);
    if (!new_table.ToHandle(&table)) {
      return MaybeHandle<SmallOrderedHashMap>();
    }
  }
  DisallowGarbageCollection no_gc;
  Tagged<SmallOrderedHashMap> raw_table = *table;
  int hash = Object::GetOrCreateHash(*key, isolate).value();
  int nof = raw_table->NumberOfElements();

  // Read the existing bucket values.
  int bucket = raw_table->HashToBucket(hash);
  int previous_entry = raw_table->HashToFirstEntry(hash);

  // Insert a new entry at the end,
  int new_entry = nof + raw_table->NumberOfDeletedElements();

  raw_table->SetDataEntry(new_entry, SmallOrderedHashMap::kValueIndex, *value);
  raw_table->SetDataEntry(new_entry, SmallOrderedHashMap::kKeyIndex, *key);
  raw_table->SetFirstEntry(bucket, new_entry);
  raw_table->SetNextEntry(new_entry, previous_entry);

  // and update book keeping.
  raw_table->SetNumberOfElements(nof + 1);

  return table;
}

bool SmallOrderedHashMap::Delete(Isolate* isolate,
                                 Tagged<SmallOrderedHashMap> table,
                                 Tagged<Object> key) {
  return SmallOrderedHashTable<SmallOrderedHashMap>::Delete(isolate, table,
                                                            key);
}

bool SmallOrderedHashMap::HasKey(Isolate* isolate, DirectHandle<Object> key) {
  return SmallOrderedHashTable<SmallOrderedHashMap>::HasKey(isolate, key);
}

template <>
InternalIndex V8_EXPORT_PRIVATE
SmallOrderedHashTable<SmallOrderedNameDictionary>::FindEntry(
    Isolate* isolate, Tagged<Object> key) {
  DisallowGarbageCollection no_gc;
  DCHECK(IsUniqueName(key));
  Tagged<Name> raw_key = Cast<Name>(key);

  int raw_entry = HashToFirstEntry(raw_key->hash());

  // Walk the chain in the bucket to find the key.
  while (raw_entry != kNotFound) {
    InternalIndex entry(raw_entry);
    Tagged<Object> candidate_key = KeyAt(entry);
    if (candidate_key == key) return entry;
    raw_entry = GetNextEntry(raw_entry);
  }

  return InternalIndex::NotFound();
}

MaybeHandle<SmallOrderedNameDictionary> SmallOrderedNameDictionary::Add(
    Isolate* isolate, Handle<SmallOrderedNameDictionary> table,
    DirectHandle<Name> key, DirectHandle<Object> value,
    PropertyDetails details) {
  DCHECK(IsUniqueName(*key));
  DCHECK(table->FindEntry(isolate, *key).is_not_found());

  if (table->UsedCapacity() >= table->Capacity()) {
    MaybeHandle<SmallOrderedNameDictionary> new_table =
        SmallOrderedNameDictionary::Grow(isolate, table);
    if (!new_table.ToHandle(&table)) {
      return MaybeHandle<SmallOrderedNameDictionary>();
    }
  }

  int nof = table->NumberOfElements();

  // Read the existing bucket values.
  int hash = key->hash();
  int bucket = table->HashToBucket(hash);
  int previous_entry = table->HashToFirstEntry(hash);

  // Insert a new entry at the end,
  int new_entry = nof + table->NumberOfDeletedElements();

  table->SetDataEntry(new_entry, SmallOrderedNameDictionary::kValueIndex,
                      *value);
  table->SetDataEntry(new_entry, SmallOrderedNameDictionary::kKeyIndex, *key);

  // TODO(gsathya): PropertyDetails should be stored as part of the
  // data table to save more memory.
  table->SetDataEntry(new_entry,
                      SmallOrderedNameDictionary::kPropertyDetailsIndex,
                      details.AsSmi());
  table->SetFirstEntry(bucket, new_entry);
  table->SetNextEntry(new_entry, previous_entry);

  // and update book keeping.
  table->SetNumberOfElements(nof + 1);

  return table;
}

void SmallOrderedNameDictionary::SetEntry(InternalIndex entry,
                                          Tagged<Object> key,
                                          Tagged<Object> value,
                                          PropertyDetails details) {
  in
```