Response: The user wants a summary of the C++ source code file `v8/src/objects/ordered-hash-table.cc`.
The summary should cover the functionalities implemented in the file.
If there are connections to JavaScript, those should be illustrated with JavaScript examples.

**Plan:**

1. **Identify the Core Purpose:** The filename and the content suggest this file implements ordered hash tables for V8.
2. **Break Down Functionality by Class/Template:**  The file uses templates for `OrderedHashTable`, `SmallOrderedHashTable`, and a handler class `OrderedHashTableHandler`. Summarize the role of each.
3. **Highlight Key Operations:** Focus on functions like `Allocate`, `Add`, `Delete`, `HasKey`, `Rehash`, `Shrink`, `Grow`, `Clear`, `FindEntry`, and iteration.
4. **Explain the "Ordered" Aspect:** Emphasize that these hash tables maintain insertion order.
5. **Connect to JavaScript:**  Consider where ordered hash tables are used in JavaScript (e.g., `Map`, `Set`, object properties). Provide simple examples demonstrating the order preservation.
6. **Differentiate `SmallOrderedHashTable`:** Explain its purpose as an optimization for smaller collections.
7. **Explain the Handler Class:** Describe how the handler manages the transition between small and large hash tables.
8. **Address the Iteration:** Summarize the `OrderedHashTableIterator`.
这个C++源代码文件 `v8/src/objects/ordered-hash-table.cc` 实现了 V8 引擎中用于存储键值对或键的**有序哈希表**。这种哈希表与传统的哈希表不同，它会**记住元素插入的顺序**。

以下是该文件主要功能的归纳：

**核心功能：**

*   **定义了有序哈希表的结构和操作:**  它定义了 `OrderedHashTable` 模板类，可以用于实现有序的哈希集合 (`OrderedHashSet`)、有序的哈希映射 (`OrderedHashMap`) 和有序的属性字典 (`OrderedNameDictionary`)。
*   **内存管理:** 提供了分配 (`Allocate`)、释放和调整大小 (`Rehash`, `Shrink`, `EnsureCapacityForAdding`) 有序哈希表内存的机制。
*   **基本操作:** 实现了诸如添加元素 (`Add`)、删除元素 (`Delete`)、检查键是否存在 (`HasKey`)、清空哈希表 (`Clear`) 和查找条目 (`FindEntry`) 等基本操作。
*   **哈希计算和冲突处理:**  使用哈希函数计算键的哈希值，并使用链表法处理哈希冲突。
*   **迭代:** 提供了遍历哈希表条目的迭代器 (`OrderedHashTableIterator`)。
*   **支持键的唯一性:**  对于 `OrderedHashSet`，确保集合中键的唯一性。
*   **处理已删除的条目:**  在删除元素时，使用特殊的 "hole" 值标记，并提供机制来压缩哈希表以去除这些空洞。
*   **支持不同类型的键值对:**  `OrderedHashSet` 存储键，`OrderedHashMap` 存储键值对，`OrderedNameDictionary` 针对属性名做了优化，并存储属性的详细信息。
*   **优化小型哈希表:** 实现了 `SmallOrderedHashTable` 模板类，作为对小型集合的优化，减少内存占用。
*   **动态调整表示:**  `OrderedHashTableHandler` 类负责在小型哈希表容量不足时，将其转换为更大型的 `OrderedHashTable`。

**与 JavaScript 的关系以及示例：**

有序哈希表在 V8 引擎中被广泛用于实现 JavaScript 中的 `Map` 和 `Set` 对象，以及对象的属性存储。

1. **`Map` 对象:** JavaScript 的 `Map` 对象会记住键值对插入的顺序。`OrderedHashMap` 就是 V8 中实现 `Map` 的核心数据结构之一。

    ```javascript
    const map = new Map();
    map.set('b', 2);
    map.set('a', 1);
    map.set('c', 3);

    // 遍历 Map 时，会按照插入顺序输出
    for (let [key, value] of map) {
      console.log(key, value); // 输出: b 2, a 1, c 3
    }
    ```

2. **`Set` 对象:** JavaScript 的 `Set` 对象也会记住值的插入顺序。`OrderedHashSet` 就是 V8 中实现 `Set` 的核心数据结构之一。

    ```javascript
    const set = new Set();
    set.add('banana');
    set.add('apple');
    set.add('cherry');

    // 遍历 Set 时，会按照插入顺序输出
    for (let item of set) {
      console.log(item); // 输出: banana, apple, cherry
    }
    ```

3. **对象属性（部分情况下）：**  在早期的 JavaScript 规范中，对象属性的枚举顺序是不确定的。但在 ES6 之后，对于非 Symbol 类型的属性，在某些操作中（例如 `for...in` 循环，`Object.keys()`，`Object.values()`，`Object.entries()`），会按照它们添加到对象中的顺序进行枚举。`OrderedNameDictionary` 被用于高效地存储和管理这些有序的属性。

    ```javascript
    const obj = {};
    obj.b = 2;
    obj.a = 1;
    obj.c = 3;

    // 按照属性添加的顺序输出
    for (let key in obj) {
      console.log(key, obj[key]); // 输出: b 2, a 1, c 3
    }

    console.log(Object.keys(obj)); // 输出: [ 'b', 'a', 'c' ]
    ```

**总结:**

`v8/src/objects/ordered-hash-table.cc` 文件是 V8 引擎中实现有序哈希表的核心，它为 JavaScript 的 `Map`、`Set` 以及部分对象属性的有序存储提供了底层的支持。它通过精心的内存管理、哈希冲突处理以及动态调整策略，保证了这些数据结构在各种场景下的高效运行。

Prompt: 
```
这是目录为v8/src/objects/ordered-hash-table.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
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
  int raw_entry = entry.as_int();
  DCHECK_IMPLIES(!IsName(key), IsTheHole(key));
  SetDataEntry(raw_entry, SmallOrderedNameDictionary::kValueIndex, value);
  SetDataEntry(raw_entry, SmallOrderedNameDictionary::kKeyIndex, key);

  // TODO(gsathya): PropertyDetails should be stored as part of the
  // data table to save more memory.
  SetDataEntry(raw_entry, SmallOrderedNameDictionary::kPropertyDetailsIndex,
               details.AsSmi());
}

template <class Derived>
bool SmallOrderedHashTable<Derived>::HasKey(Isolate* isolate,
                                            DirectHandle<Object> key) {
  DisallowGarbageCollection no_gc;
  return FindEntry(isolate, *key).is_found();
}

template <class Derived>
bool SmallOrderedHashTable<Derived>::Delete(Isolate* isolate,
                                            Tagged<Derived> table,
                                            Tagged<Object> key) {
  DisallowGarbageCollection no_gc;
  InternalIndex entry = table->FindEntry(isolate, key);
  if (entry.is_not_found()) return false;

  int nof = table->NumberOfElements();
  int nod = table->NumberOfDeletedElements();

  Tagged<Object> the_hole = ReadOnlyRoots(isolate).the_hole_value();
  for (int j = 0; j < Derived::kEntrySize; j++) {
    table->SetDataEntry(entry.as_int(), j, the_hole);
  }

  table->SetNumberOfElements(nof - 1);
  table->SetNumberOfDeletedElements(nod + 1);

  return true;
}

Handle<SmallOrderedNameDictionary> SmallOrderedNameDictionary::DeleteEntry(
    Isolate* isolate, Handle<SmallOrderedNameDictionary> table,
    InternalIndex entry) {
  DCHECK(entry.is_found());
  {
    DisallowGarbageCollection no_gc;
    Tagged<Object> the_hole = ReadOnlyRoots(isolate).the_hole_value();
    PropertyDetails details = PropertyDetails::Empty();
    table->SetEntry(entry, the_hole, the_hole, details);

    int nof = table->NumberOfElements();
    table->SetNumberOfElements(nof - 1);
    int nod = table->NumberOfDeletedElements();
    table->SetNumberOfDeletedElements(nod + 1);
  }
  return Shrink(isolate, table);
}

template <class Derived>
Handle<Derived> SmallOrderedHashTable<Derived>::Rehash(Isolate* isolate,
                                                       Handle<Derived> table,
                                                       int new_capacity) {
  DCHECK_GE(kMaxCapacity, new_capacity);

  Handle<Derived> new_table = SmallOrderedHashTable<Derived>::Allocate(
      isolate, new_capacity,
      HeapLayout::InYoungGeneration(*table) ? AllocationType::kYoung
                                            : AllocationType::kOld);
  int new_entry = 0;

  {
    DisallowGarbageCollection no_gc;
    for (InternalIndex old_entry : table->IterateEntries()) {
      Tagged<Object> key = table->KeyAt(old_entry);
      if (IsTheHole(key, isolate)) continue;

      int hash = Smi::ToInt(Object::GetHash(key));
      int bucket = new_table->HashToBucket(hash);
      int chain = new_table->GetFirstEntry(bucket);

      new_table->SetFirstEntry(bucket, new_entry);
      new_table->SetNextEntry(new_entry, chain);

      for (int i = 0; i < Derived::kEntrySize; ++i) {
        Tagged<Object> value = table->GetDataEntry(old_entry.as_int(), i);
        new_table->SetDataEntry(new_entry, i, value);
      }

      ++new_entry;
    }

    new_table->SetNumberOfElements(table->NumberOfElements());
  }
  return new_table;
}

Handle<SmallOrderedHashSet> SmallOrderedHashSet::Rehash(
    Isolate* isolate, Handle<SmallOrderedHashSet> table, int new_capacity) {
  return SmallOrderedHashTable<SmallOrderedHashSet>::Rehash(isolate, table,
                                                            new_capacity);
}

Handle<SmallOrderedHashMap> SmallOrderedHashMap::Rehash(
    Isolate* isolate, Handle<SmallOrderedHashMap> table, int new_capacity) {
  return SmallOrderedHashTable<SmallOrderedHashMap>::Rehash(isolate, table,
                                                            new_capacity);
}

Handle<SmallOrderedNameDictionary> SmallOrderedNameDictionary::Rehash(
    Isolate* isolate, Handle<SmallOrderedNameDictionary> table,
    int new_capacity) {
  Handle<SmallOrderedNameDictionary> new_table =
      SmallOrderedHashTable<SmallOrderedNameDictionary>::Rehash(isolate, table,
                                                                new_capacity);
  new_table->SetHash(table->Hash());
  return new_table;
}

template <class Derived>
Handle<Derived> SmallOrderedHashTable<Derived>::Shrink(Isolate* isolate,
                                                       Handle<Derived> table) {
  int nof = table->NumberOfElements();
  int capacity = table->Capacity();
  if (nof >= (capacity >> 2)) return table;
  return Derived::Rehash(isolate, table, capacity / 2);
}

template <class Derived>
MaybeHandle<Derived> SmallOrderedHashTable<Derived>::Grow(
    Isolate* isolate, Handle<Derived> table) {
  int capacity = table->Capacity();
  int new_capacity = capacity;

  // Don't need to grow if we can simply clear out deleted entries instead.
  // TODO(gsathya): Compact in place, instead of allocating a new table.
  if (table->NumberOfDeletedElements() < (capacity >> 1)) {
    new_capacity = capacity << 1;

    // The max capacity of our table is 254. We special case for 256 to
    // account for our growth strategy, otherwise we would only fill up
    // to 128 entries in our table.
    if (new_capacity == kGrowthHack) {
      new_capacity = kMaxCapacity;
    }

    // We need to migrate to a bigger hash table.
    if (new_capacity > kMaxCapacity) {
      return MaybeHandle<Derived>();
    }
  }

  return Derived::Rehash(isolate, table, new_capacity);
}

template <class Derived>
InternalIndex SmallOrderedHashTable<Derived>::FindEntry(Isolate* isolate,
                                                        Tagged<Object> key) {
  DisallowGarbageCollection no_gc;
  Tagged<Object> hash = Object::GetHash(key);

  if (IsUndefined(hash, isolate)) return InternalIndex::NotFound();
  int raw_entry = HashToFirstEntry(Smi::ToInt(hash));

  // Walk the chain in the bucket to find the key.
  while (raw_entry != kNotFound) {
    InternalIndex entry(raw_entry);
    Tagged<Object> candidate_key = KeyAt(entry);
    if (Object::SameValueZero(candidate_key, key)) return entry;
    raw_entry = GetNextEntry(raw_entry);
  }
  return InternalIndex::NotFound();
}

template bool EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE)
    SmallOrderedHashTable<SmallOrderedHashSet>::HasKey(
        Isolate* isolate, DirectHandle<Object> key);
template V8_EXPORT_PRIVATE Handle<SmallOrderedHashSet>
SmallOrderedHashTable<SmallOrderedHashSet>::Rehash(
    Isolate* isolate, Handle<SmallOrderedHashSet> table, int new_capacity);
template V8_EXPORT_PRIVATE Handle<SmallOrderedHashSet>
SmallOrderedHashTable<SmallOrderedHashSet>::Shrink(
    Isolate* isolate, Handle<SmallOrderedHashSet> table);
template V8_EXPORT_PRIVATE MaybeHandle<SmallOrderedHashSet>
SmallOrderedHashTable<SmallOrderedHashSet>::Grow(
    Isolate* isolate, Handle<SmallOrderedHashSet> table);
template V8_EXPORT_PRIVATE void
SmallOrderedHashTable<SmallOrderedHashSet>::Initialize(Isolate* isolate,
                                                       int capacity);
template V8_EXPORT_PRIVATE bool
SmallOrderedHashTable<SmallOrderedHashSet>::Delete(
    Isolate* isolate, Tagged<SmallOrderedHashSet> table, Tagged<Object> key);

template EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE) bool SmallOrderedHashTable<
    SmallOrderedHashMap>::HasKey(Isolate* isolate, DirectHandle<Object> key);
template V8_EXPORT_PRIVATE Handle<SmallOrderedHashMap>
SmallOrderedHashTable<SmallOrderedHashMap>::Rehash(
    Isolate* isolate, Handle<SmallOrderedHashMap> table, int new_capacity);
template V8_EXPORT_PRIVATE Handle<SmallOrderedHashMap>
SmallOrderedHashTable<SmallOrderedHashMap>::Shrink(
    Isolate* isolate, Handle<SmallOrderedHashMap> table);
template V8_EXPORT_PRIVATE MaybeHandle<SmallOrderedHashMap>
SmallOrderedHashTable<SmallOrderedHashMap>::Grow(
    Isolate* isolate, Handle<SmallOrderedHashMap> table);
template V8_EXPORT_PRIVATE void
SmallOrderedHashTable<SmallOrderedHashMap>::Initialize(Isolate* isolate,
                                                       int capacity);

template V8_EXPORT_PRIVATE bool
SmallOrderedHashTable<SmallOrderedHashMap>::Delete(
    Isolate* isolate, Tagged<SmallOrderedHashMap> table, Tagged<Object> key);

template V8_EXPORT_PRIVATE void
SmallOrderedHashTable<SmallOrderedNameDictionary>::Initialize(Isolate* isolate,
                                                              int capacity);
template V8_EXPORT_PRIVATE Handle<SmallOrderedNameDictionary>
SmallOrderedHashTable<SmallOrderedNameDictionary>::Shrink(
    Isolate* isolate, Handle<SmallOrderedNameDictionary> table);

template <class SmallTable, class LargeTable>
MaybeHandle<HeapObject>
OrderedHashTableHandler<SmallTable, LargeTable>::Allocate(Isolate* isolate,
                                                          int capacity) {
  if (capacity < SmallTable::kMaxCapacity) {
    return SmallTable::Allocate(isolate, capacity);
  }

  return LargeTable::Allocate(isolate, capacity);
}

template V8_EXPORT_PRIVATE MaybeHandle<HeapObject>
OrderedHashTableHandler<SmallOrderedHashSet, OrderedHashSet>::Allocate(
    Isolate* isolate, int capacity);
template V8_EXPORT_PRIVATE MaybeHandle<HeapObject>
OrderedHashTableHandler<SmallOrderedHashMap, OrderedHashMap>::Allocate(
    Isolate* isolate, int capacity);
template V8_EXPORT_PRIVATE MaybeHandle<HeapObject>
OrderedHashTableHandler<SmallOrderedNameDictionary,
                        OrderedNameDictionary>::Allocate(Isolate* isolate,
                                                         int capacity);

template <class SmallTable, class LargeTable>
bool OrderedHashTableHandler<SmallTable, LargeTable>::Delete(
    Isolate* isolate, Handle<HeapObject> table, DirectHandle<Object> key) {
  if (SmallTable::Is(table)) {
    return SmallTable::Delete(isolate, *Cast<SmallTable>(table), *key);
  }

  DCHECK(LargeTable::Is(table));
  // Note: Once we migrate to the a big hash table, we never migrate
  // down to a smaller hash table.
  return LargeTable::Delete(isolate, *Cast<LargeTable>(table), *key);
}

template <class SmallTable, class LargeTable>
bool OrderedHashTableHandler<SmallTable, LargeTable>::HasKey(
    Isolate* isolate, Handle<HeapObject> table, Handle<Object> key) {
  if (SmallTable::Is(table)) {
    return Cast<SmallTable>(table)->HasKey(isolate, key);
  }

  DCHECK(LargeTable::Is(table));
  return LargeTable::HasKey(isolate, Cast<LargeTable>(*table), *key);
}

template bool
OrderedHashTableHandler<SmallOrderedHashSet, OrderedHashSet>::HasKey(
    Isolate* isolate, Handle<HeapObject> table, Handle<Object> key);
template bool
OrderedHashTableHandler<SmallOrderedHashMap, OrderedHashMap>::HasKey(
    Isolate* isolate, Handle<HeapObject> table, Handle<Object> key);

template bool
OrderedHashTableHandler<SmallOrderedHashSet, OrderedHashSet>::Delete(
    Isolate* isolate, Handle<HeapObject> table, DirectHandle<Object> key);
template bool
OrderedHashTableHandler<SmallOrderedHashMap, OrderedHashMap>::Delete(
    Isolate* isolate, Handle<HeapObject> table, DirectHandle<Object> key);
template bool OrderedHashTableHandler<
    SmallOrderedNameDictionary,
    OrderedNameDictionary>::Delete(Isolate* isolate, Handle<HeapObject> table,
                                   DirectHandle<Object> key);

MaybeHandle<OrderedHashMap> OrderedHashMapHandler::AdjustRepresentation(
    Isolate* isolate, DirectHandle<SmallOrderedHashMap> table) {
  MaybeHandle<OrderedHashMap> new_table_candidate =
      OrderedHashMap::Allocate(isolate, OrderedHashTableMinSize);
  Handle<OrderedHashMap> new_table;
  if (!new_table_candidate.ToHandle(&new_table)) {
    return new_table_candidate;
  }

  // TODO(gsathya): Optimize the lookup to not re calc offsets. Also,
  // unhandlify this code as we preallocate the new backing store with
  // the proper capacity.
  for (InternalIndex entry : table->IterateEntries()) {
    DirectHandle<Object> key(table->KeyAt(entry), isolate);
    if (IsTheHole(*key, isolate)) continue;
    DirectHandle<Object> value(
        table->GetDataEntry(entry.as_int(), SmallOrderedHashMap::kValueIndex),
        isolate);
    new_table_candidate = OrderedHashMap::Add(isolate, new_table, key, value);
    if (!new_table_candidate.ToHandle(&new_table)) {
      return new_table_candidate;
    }
  }

  return new_table_candidate;
}

MaybeHandle<OrderedHashSet> OrderedHashSetHandler::AdjustRepresentation(
    Isolate* isolate, DirectHandle<SmallOrderedHashSet> table) {
  MaybeHandle<OrderedHashSet> new_table_candidate =
      OrderedHashSet::Allocate(isolate, OrderedHashTableMinSize);
  Handle<OrderedHashSet> new_table;
  if (!new_table_candidate.ToHandle(&new_table)) {
    return new_table_candidate;
  }

  // TODO(gsathya): Optimize the lookup to not re calc offsets. Also,
  // unhandlify this code as we preallocate the new backing store with
  // the proper capacity.
  for (InternalIndex entry : table->IterateEntries()) {
    DirectHandle<Object> key(table->KeyAt(entry), isolate);
    if (IsTheHole(*key, isolate)) continue;
    new_table_candidate = OrderedHashSet::Add(isolate, new_table, key);
    if (!new_table_candidate.ToHandle(&new_table)) {
      return new_table_candidate;
    }
  }

  return new_table_candidate;
}

MaybeHandle<OrderedNameDictionary>
OrderedNameDictionaryHandler::AdjustRepresentation(
    Isolate* isolate, DirectHandle<SmallOrderedNameDictionary> table) {
  MaybeHandle<OrderedNameDictionary> new_table_candidate =
      OrderedNameDictionary::Allocate(isolate, OrderedHashTableMinSize);
  Handle<OrderedNameDictionary> new_table;
  if (!new_table_candidate.ToHandle(&new_table)) {
    return new_table_candidate;
  }

  // TODO(gsathya): Optimize the lookup to not re calc offsets. Also,
  // unhandlify this code as we preallocate the new backing store with
  // the proper capacity.
  for (InternalIndex entry : table->IterateEntries()) {
    DirectHandle<Name> key(Cast<Name>(table->KeyAt(entry)), isolate);
    if (IsTheHole(*key, isolate)) continue;
    DirectHandle<Object> value(table->ValueAt(entry), isolate);
    PropertyDetails details = table->DetailsAt(entry);
    new_table_candidate =
        OrderedNameDictionary::Add(isolate, new_table, key, value, details);
    if (!new_table_candidate.ToHandle(&new_table)) {
      return new_table_candidate;
    }
  }

  return new_table_candidate;
}

MaybeHandle<HeapObject> OrderedHashMapHandler::Add(Isolate* isolate,
                                                   Handle<HeapObject> table,
                                                   DirectHandle<Object> key,
                                                   DirectHandle<Object> value) {
  if (IsSmallOrderedHashMap(*table)) {
    Handle<SmallOrderedHashMap> small_map = Cast<SmallOrderedHashMap>(table);
    MaybeHandle<SmallOrderedHashMap> new_map =
        SmallOrderedHashMap::Add(isolate, small_map, key, value);
    if (!new_map.is_null()) return new_map.ToHandleChecked();

    // We couldn't add to the small table, let's migrate to the
    // big table.
    MaybeHandle<OrderedHashMap> table_candidate =
        OrderedHashMapHandler::AdjustRepresentation(isolate, small_map);
    if (!table_candidate.ToHandle(&table)) {
      return table_candidate;
    }
  }

  DCHECK(IsOrderedHashMap(*table));
  return OrderedHashMap::Add(isolate, Cast<OrderedHashMap>(table), key, value);
}

MaybeHandle<HeapObject> OrderedHashSetHandler::Add(Isolate* isolate,
                                                   Handle<HeapObject> table,
                                                   DirectHandle<Object> key) {
  if (IsSmallOrderedHashSet(*table)) {
    Handle<SmallOrderedHashSet> small_set = Cast<SmallOrderedHashSet>(table);
    MaybeHandle<SmallOrderedHashSet> new_set =
        SmallOrderedHashSet::Add(isolate, small_set, key);
    if (!new_set.is_null()) return new_set.ToHandleChecked();

    // We couldn't add to the small table, let's migrate to the
    // big table.
    MaybeHandle<OrderedHashSet> table_candidate =
        OrderedHashSetHandler::AdjustRepresentation(isolate, small_set);
    if (!table_candidate.ToHandle(&table)) {
      return table_candidate;
    }
  }

  DCHECK(IsOrderedHashSet(*table));
  return OrderedHashSet::Add(isolate, Cast<OrderedHashSet>(table), key);
}

MaybeHandle<HeapObject> OrderedNameDictionaryHandler::Add(
    Isolate* isolate, Handle<HeapObject> table, DirectHandle<Name> key,
    DirectHandle<Object> value, PropertyDetails details) {
  if (IsSmallOrderedNameDictionary(*table)) {
    Handle<SmallOrderedNameDictionary> small_dict =
        Cast<SmallOrderedNameDictionary>(table);
    MaybeHandle<SmallOrderedNameDictionary> new_dict =
        SmallOrderedNameDictionary::Add(isolate, small_dict, key, value,
                                        details);
    if (!new_dict.is_null()) return new_dict.ToHandleChecked();

    // We couldn't add to the small table, let's migrate to the
    // big table.
    MaybeHandle<OrderedNameDictionary> table_candidate =
        OrderedNameDictionaryHandler::AdjustRepresentation(isolate, small_dict);
    if (!table_candidate.ToHandle(&table)) {
      return table_candidate;
    }
  }

  DCHECK(IsOrderedNameDictionary(*table));
  return OrderedNameDictionary::Add(isolate, Cast<OrderedNameDictionary>(table),
                                    key, value, details);
}

void OrderedNameDictionaryHandler::SetEntry(Tagged<HeapObject> table,
                                            InternalIndex entry,
                                            Tagged<Object> key,
                                            Tagged<Object> value,
                                            PropertyDetails details) {
  DisallowGarbageCollection no_gc;
  if (IsSmallOrderedNameDictionary(table)) {
    return Cast<SmallOrderedNameDictionary>(table)->SetEntry(entry, key, value,
                                                             details);
  }

  DCHECK(IsOrderedNameDictionary(table));
  return Cast<OrderedNameDictionary>(table)->SetEntry(InternalIndex(entry), key,
                                                      value, details);
}

InternalIndex OrderedNameDictionaryHandler::FindEntry(Isolate* isolate,
                                                      Tagged<HeapObject> table,
                                                      Tagged<Name> key) {
  DisallowGarbageCollection no_gc;
  if (IsSmallOrderedNameDictionary(table)) {
    return Cast<SmallOrderedNameDictionary>(table)->FindEntry(isolate, key);
  }

  DCHECK(IsOrderedNameDictionary(table));
  return Cast<OrderedNameDictionary>(table)->FindEntry(isolate, key);
}

Tagged<Object> OrderedNameDictionaryHandler::ValueAt(Tagged<HeapObject> table,
                                                     InternalIndex entry) {
  if (IsSmallOrderedNameDictionary(table)) {
    return Cast<SmallOrderedNameDictionary>(table)->ValueAt(entry);
  }

  DCHECK(IsOrderedNameDictionary(table));
  return Cast<OrderedNameDictionary>(table)->ValueAt(entry);
}

void OrderedNameDictionaryHandler::ValueAtPut(Tagged<HeapObject> table,
                                              InternalIndex entry,
                                              Tagged<Object> value) {
  if (IsSmallOrderedNameDictionary(table)) {
    return Cast<SmallOrderedNameDictionary>(table)->ValueAtPut(entry, value);
  }

  DCHECK(IsOrderedNameDictionary(table));
  Cast<OrderedNameDictionary>(table)->ValueAtPut(entry, value);
}

PropertyDetails OrderedNameDictionaryHandler::DetailsAt(
    Tagged<HeapObject> table, InternalIndex entry) {
  if (IsSmallOrderedNameDictionary(table)) {
    return Cast<SmallOrderedNameDictionary>(table)->DetailsAt(entry);
  }

  DCHECK(IsOrderedNameDictionary(table));
  return Cast<OrderedNameDictionary>(table)->DetailsAt(entry);
}

void OrderedNameDictionaryHandler::DetailsAtPut(Tagged<HeapObject> table,
                                                InternalIndex entry,
                                                PropertyDetails details) {
  if (IsSmallOrderedNameDictionary(table)) {
    return Cast<SmallOrderedNameDictionary>(table)->DetailsAtPut(entry,
                                                                 details);
  }

  DCHECK(IsOrderedNameDictionary(table));
  Cast<OrderedNameDictionary>(table)->DetailsAtPut(entry, details);
}

int OrderedNameDictionaryHandler::Hash(Tagged<HeapObject> table) {
  if (IsSmallOrderedNameDictionary(table)) {
    return Cast<SmallOrderedNameDictionary>(table)->Hash();
  }

  DCHECK(IsOrderedNameDictionary(table));
  return Cast<OrderedNameDictionary>(table)->Hash();
}

void OrderedNameDictionaryHandler::SetHash(Tagged<HeapObject> table, int hash) {
  if (IsSmallOrderedNameDictionary(table)) {
    return Cast<SmallOrderedNameDictionary>(table)->SetHash(hash);
  }

  DCHECK(IsOrderedNameDictionary(table));
  Cast<OrderedNameDictionary>(table)->SetHash(hash);
}

Tagged<Name> OrderedNameDictionaryHandler::KeyAt(Tagged<HeapObject> table,
                                                 InternalIndex entry) {
  if (IsSmallOrderedNameDictionary(table)) {
    return Cast<Name>(Cast<SmallOrderedNameDictionary>(table)->KeyAt(entry));
  }

  return Cast<Name>(
      Cast<OrderedNameDictionary>(table)->KeyAt(InternalIndex(entry)));
}

int OrderedNameDictionaryHandler::NumberOfElements(Tagged<HeapObject> table) {
  if (IsSmallOrderedNameDictionary(table)) {
    return Cast<SmallOrderedNameDictionary>(table)->NumberOfElements();
  }

  return Cast<OrderedNameDictionary>(table)->NumberOfElements();
}

int OrderedNameDictionaryHandler::Capacity(Tagged<HeapObject> table) {
  if (IsSmallOrderedNameDictionary(table)) {
    return Cast<SmallOrderedNameDictionary>(table)->Capacity();
  }

  return Cast<OrderedNameDictionary>(table)->Capacity();
}

Handle<HeapObject> OrderedNameDictionaryHandler::Shrink(
    Isolate* isolate, Handle<HeapObject> table) {
  if (IsSmallOrderedNameDictionary(*table)) {
    Handle<SmallOrderedNameDictionary> small_dict =
        Cast<SmallOrderedNameDictionary>(table);
    return SmallOrderedNameDictionary::Shrink(isolate, small_dict);
  }

  Handle<OrderedNameDictionary> large_dict = Cast<OrderedNameDictionary>(table);
  return OrderedNameDictionary::Shrink(isolate, large_dict);
}

Handle<HeapObject> OrderedNameDictionaryHandler::DeleteEntry(
    Isolate* isolate, Handle<HeapObject> table, InternalIndex entry) {
  DisallowGarbageCollection no_gc;
  if (IsSmallOrderedNameDictionary(*table)) {
    Handle<SmallOrderedNameDictionary> small_dict =
        Cast<SmallOrderedNameDictionary>(table);
    return SmallOrderedNameDictionary::DeleteEntry(isolate, small_dict, entry);
  }

  Handle<OrderedNameDictionary> large_dict = Cast<OrderedNameDictionary>(table);
  return OrderedNameDictionary::DeleteEntry(isolate, large_dict,
                                            InternalIndex(entry));
}

template <class Derived, class TableType>
void OrderedHashTableIterator<Derived, TableType>::Transition() {
  DisallowGarbageCollection no_gc;
  Tagged<TableType> table = Cast<TableType>(this->table());
  if (!table->IsObsolete()) return;

  int index = Smi::ToInt(this->index());
  DCHECK_LE(0, index);
  while (table->IsObsolete()) {
    Tagged<TableType> next_table = table->NextTable();

    if (index > 0) {
      int nod = table->NumberOfDeletedElements();

      if (nod == TableType::kClearedTableSentinel) {
        index = 0;
      } else {
        int old_index = index;
        for (int i = 0; i < nod; ++i) {
          int removed_index = table->RemovedIndexAt(i);
          if (removed_index >= old_index) break;
          --index;
        }
      }
    }

    table = next_table;
  }

  set_table(table);
  set_index(Smi::FromInt(index));
}

template <class Derived, class TableType>
bool OrderedHashTableIterator<Derived, TableType>::HasMore() {
  DisallowGarbageCollection no_gc;
  ReadOnlyRoots ro_roots = GetReadOnlyRoots();

  Transition();

  Tagged<TableType> table = Cast<TableType>(this->table());
  int index = Smi::ToInt(this->index());
  int used_capacity = table->UsedCapacity();

  while (index < used_capacity &&
         IsHashTableHole(table->KeyAt(InternalIndex(index)), ro_roots)) {
    index++;
  }

  set_index(Smi::FromInt(index));

  if (index < used_capacity) return true;

  set_table(TableType::GetEmpty(ro_roots));
  return false;
}

template bool
OrderedHashTableIterator<JSSetIterator, OrderedHashSet>::HasMore();

template void
OrderedHashTableIterator<JSSetIterator, OrderedHashSet>::MoveNext();

template Tagged<Object>
OrderedHashTableIterator<JSSetIterator, OrderedHashSet>::CurrentKey();

template void
OrderedHashTableIterator<JSSetIterator, OrderedHashSet>::Transition();

template bool
OrderedHashTableIterator<JSMapIterator, OrderedHashMap>::HasMore();

template void
OrderedHashTableIterator<JSMapIterator, OrderedHashMap>::MoveNext();

template Tagged<Object>
OrderedHashTableIterator<JSMapIterator, OrderedHashMap>::CurrentKey();

template void
OrderedHashTableIterator<JSMapIterator, OrderedHashMap>::Transition();

}  // namespace internal
}  // namespace v8

"""

```