Response:
Let's break down the thought process for analyzing the C++ header file `ordered-hash-table.h`.

**1. Initial Scan and Keyword Spotting:**

The first step is to quickly read through the code, looking for prominent keywords and structural elements. Things that stand out are:

* `#ifndef`, `#define`, `#include`:  This immediately tells us it's a C/C++ header file with include guards.
* `namespace v8::internal`:  Indicates this is part of the V8 JavaScript engine's internal implementation.
* `class OrderedHashTable`, `class OrderedHashSet`, `class OrderedHashMap`, `class SmallOrderedHashTable`, `class SmallOrderedHashSet`, `class SmallOrderedHashMap`, `class OrderedNameDictionary`: These are the core data structures defined in the file, hinting at the different types of ordered hash tables.
* `public`, `protected`, `private`: Standard C++ access modifiers, useful for understanding the API.
* `static`:  Indicates class-level methods, often for creation or utility functions.
* `MaybeHandle`, `Handle`, `Tagged`: V8-specific smart pointers for managing garbage-collected objects.
* `Isolate`:  Represents an isolated instance of the V8 engine.
* `Object`, `Smi`, `FixedArray`, `Map`, `Name`:  V8's fundamental object types.
* Comments explaining concepts like "Deterministic Hash Table" and memory layout.
* Method names like `Add`, `Delete`, `HasKey`, `FindEntry`, `IterateEntries`, `Rehash`, `Shrink`, `Clear`, `ValueAt`, `KeyAt`, etc.: These directly point to the functionalities of the data structures.
* Constants like `kEntrySize`, `kLoadFactor`, `kInitialCapacity`, `kMaxCapacity`, etc.: These define the characteristics and limits of the hash tables.
* `template <class Derived, int entrysize>`:  Indicates that `OrderedHashTable` is a template, making it reusable for different key-value sizes.

**2. Understanding the Core Concept: Ordered Hash Table:**

The initial comments explicitly state that `OrderedHashTable` is a hash table that preserves insertion order. This is the central concept. The provided link to the "Deterministic Hash Table" further reinforces this.

**3. Deconstructing the `OrderedHashTable` Template:**

This is the most complex part. The comments about memory layout are crucial here. I'd visualize the memory structure based on the description:

```
[Prefix] [Element Count] [Deleted Count] [Bucket Count] [Hash Table (Buckets)] [Data Table]
```

Understanding the role of each part is essential:

* **Prefix:** Likely for metadata, though its exact contents aren't immediately clear from this header.
* **Element Count:**  Keeps track of the number of elements.
* **Deleted Count:**  Tracks deleted entries, which are important for maintaining order and iterator stability.
* **Bucket Count:** Determines the size of the hash table for distributing keys.
* **Hash Table (Buckets):**  An array where each entry points to the *first* element in a bucket within the Data Table.
* **Data Table:**  The main storage for key-value pairs (or just keys in the case of a set). It also includes a "chain" pointer to handle collisions.

The "obsolete table" layout is a variation for when the table is resized or cleared, and it's used for iterator consistency during these operations.

**4. Identifying Concrete Implementations: `OrderedHashSet`, `OrderedHashMap`, `OrderedNameDictionary`:**

These classes inherit from `OrderedHashTable`, specializing it for different use cases:

* **`OrderedHashSet`:**  Stores only keys (like a JavaScript `Set`).
* **`OrderedHashMap`:** Stores key-value pairs (like a JavaScript `Map`).
* **`OrderedNameDictionary`:** Seems tailored for storing property names and their attributes in V8.

The `entrysize` template parameter differentiates them (1 for `HashSet`, 2 for `HashMap`, 3 for `NameDictionary`).

**5. Recognizing the "Small" Variants:**

The `SmallOrderedHashTable`, `SmallOrderedHashSet`, and `SmallOrderedHashMap` classes represent optimized versions for smaller sizes, likely to reduce memory overhead. Their memory layout is different and more compact, using byte offsets. The transition from "Small" to the regular `OrderedHashTable` is hinted at.

**6. Functionality Summarization (Iterative Refinement):**

At this point, I'd start listing the functionalities, going through the public methods:

* **Adding Elements:**  `Add` methods in various classes.
* **Deleting Elements:** `Delete` methods.
* **Checking for Existence:** `HasKey`.
* **Retrieving Elements:** `ValueAt`, `KeyAt`.
* **Iteration:** `IterateEntries`.
* **Resizing/Rehashing:** `EnsureCapacityForAdding`, `Shrink`, `Rehash`, `Grow`.
* **Clearing:** `Clear`.
* **Obsolete Table Handling:**  Methods like `IsObsolete`, `NextTable`, `RemovedIndexAt`.
* **Internal Helpers:**  Methods like `FindEntry`, `HashToBucket`, `EntryToIndex`, etc.
* **Allocation:** `Allocate`, `AllocateEmpty`.

**7. Connecting to JavaScript (if applicable):**

The comments explicitly mention that these are meant to be used by `JSMap` and `JSSet`. This makes the JavaScript connection clear. I'd think about how the C++ methods would map to JavaScript `Map` and `Set` operations.

**8. Identifying Potential Programming Errors:**

Based on the methods and data structures, I'd consider common mistakes:

* **Incorrect Usage of Iterators:** Iterators becoming invalid after modifications.
* **Memory Management Issues (though V8 handles this mostly):**  Overrunning buffer limits (less likely in managed memory).
* **Hash Code Collisions (though the implementation aims to mitigate this):**  Understanding how collisions are handled is important.

**9. Considering `.tq` Files (Torque):**

The prompt mentions `.tq` files (Torque). Knowing that Torque is V8's internal language for generating optimized code, I'd note that if a `.tq` version existed, it would likely contain more low-level, performance-critical implementations of the same concepts.

**10. Structuring the Output:**

Finally, I'd organize the findings into a clear and structured format, as demonstrated in your example answer, covering the key aspects: general functionality, relation to Torque, JavaScript examples, logic (with assumptions), common errors, and a concise summary.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Maybe the "Prefix" stores hash seed information. (Needs more investigation, not explicitly stated).
* **Realization:** The "obsolete table" mechanism is crucial for iterator stability during resizing, a common challenge in dynamic hash tables.
* **Clarification:** The distinction between `Capacity()` and `UsedCapacity()` is important for understanding memory usage.
* **Emphasis:** The template nature of `OrderedHashTable` allows code reuse for different key/value sizes.

By following these steps, systematically analyzing the code, and connecting the pieces, it's possible to arrive at a comprehensive understanding of the `ordered-hash-table.h` file.
这是对V8源代码文件 `v8/src/objects/ordered-hash-table.h` 的第一部分分析。

**功能归纳:**

`v8/src/objects/ordered-hash-table.h` 文件定义了用于实现**有序哈希表**的C++模板类 `OrderedHashTable`，以及基于该模板实现的具体类 `OrderedHashSet`、`OrderedHashMap` 和 `OrderedNameDictionary`。  这些类在 V8 引擎中用于存储和管理键值对，并保持插入顺序。此外，它还定义了针对小规模场景优化的 `SmallOrderedHashTable` 及其子类。

**具体功能点:**

1. **有序存储:**  核心目标是创建一个哈希表，它不仅能快速查找元素，还能记住元素插入的顺序。这对于实现像 JavaScript 中的 `Map` 和 `Set` 这样的数据结构至关重要，因为它们需要保持迭代顺序。

2. **多种实现:**
   - `OrderedHashTable`:  一个模板类，定义了有序哈希表的基本结构和操作，可以根据不同的 `entrysize` (每个条目的大小) 来适应不同的需求。
   - `OrderedHashSet`: 基于 `OrderedHashTable`，用于存储不重复的键（类似于 JavaScript 的 `Set`）。
   - `OrderedHashMap`: 基于 `OrderedHashTable`，用于存储键值对（类似于 JavaScript 的 `Map`）。
   - `OrderedNameDictionary`:  基于 `OrderedHashTable`，专门用于存储属性名、属性值和属性细节，在 V8 内部用于管理对象的属性。
   - `SmallOrderedHashTable`:  针对小容量场景的优化版本，使用更紧凑的内存布局 (byte 数组而非 Smi)，但容量有限。
   - `SmallOrderedHashSet` 和 `SmallOrderedHashMap`:  `SmallOrderedHashTable` 的具体实现。

3. **哈希和查找:**  使用对象的 `SameValueZero()` 方法进行相等性比较，使用 `GetHash()` 方法计算哈希值。提供了 `HasKey` 方法用于检查键是否存在，以及 `FindEntry` 方法用于查找键对应的条目索引。

4. **动态调整大小:**  提供了 `EnsureCapacityForAdding` 用于在添加元素前确保容量足够，`Shrink` 用于缩小哈希表以节省内存，以及 `Rehash` 用于在容量变化时重新组织哈希表。

5. **删除操作:**  `Delete` 方法用于删除指定键的条目，但注意删除操作可能不会立即缩小表的大小，而是标记为已删除。

6. **迭代支持:**  `IterateEntries` 方法用于遍历哈希表中的所有有效条目。

7. **Obsolete 机制:**  当哈希表需要迁移到新版本时（例如，扩容），旧的哈希表会被标记为 obsolete，并保存一些信息以支持正在进行的迭代器。

8. **小规模优化:** `SmallOrderedHashTable` 及其子类针对小规模数据进行了优化，减少了内存开销。当容量超过一定阈值时，会迁移到 `OrderedHashTable`。

**关于 .tq 结尾的文件:**

如果 `v8/src/objects/ordered-hash-table.h` 以 `.tq` 结尾，那么它确实是 V8 的 **Torque** 源代码。 Torque 是 V8 内部使用的一种类型安全的 DSL (Domain Specific Language)，用于生成高效的 C++ 代码。Torque 代码通常用于实现性能关键的部分，例如内置函数和对象操作。

**与 JavaScript 的关系:**

`OrderedHashSet` 和 `OrderedHashMap` 直接对应于 JavaScript 中的 `Set` 和 `Map` 对象。 它们在底层实现了这些 JavaScript 数据结构的有序性。

**JavaScript 示例:**

```javascript
// JavaScript Map (对应 OrderedHashMap)
const myMap = new Map();
myMap.set('a', 1);
myMap.set('b', 2);
myMap.set('c', 3);

console.log(myMap.keys()); // 输出 MapIterator {'a', 'b', 'c'}，保持插入顺序
console.log(myMap.get('b')); // 输出 2

// JavaScript Set (对应 OrderedHashSet)
const mySet = new Set();
mySet.add('apple');
mySet.add('banana');
mySet.add('orange');

console.log(mySet.values()); // 输出 SetIterator {'apple', 'banana', 'orange'}，保持插入顺序
console.log(mySet.has('banana')); // 输出 true
```

**代码逻辑推理 (假设输入与输出):**

假设我们有一个 `OrderedHashMap`，初始容量为 4，并执行以下操作：

1. **添加 ('a', 1):**
   - 假设 'a' 的哈希值经过计算后落入某个桶。
   - `NumberOfElements` 从 0 变为 1。
   - 数据表会在对应的位置存储键 'a' 和值 1。
   - 相应的哈希桶会指向该数据表条目的起始位置。

2. **添加 ('b', 2):**
   - 假设 'b' 的哈希值落入不同的桶。
   - `NumberOfElements` 从 1 变为 2。
   - 数据表会存储键 'b' 和值 2。
   - 相应的哈希桶会指向新的数据表条目。

3. **添加 ('c', 3):**
   - 假设 'c' 的哈希值与 'a' 冲突，落入相同的桶。
   - `NumberOfElements` 从 2 变为 3。
   - 数据表会存储键 'c' 和值 3。
   - 冲突通过链式结构解决：'a' 的数据表条目中的链指针会指向 'c' 的数据表条目。

4. **查找 ('b'):**
   - 计算 'b' 的哈希值，确定桶的位置。
   - 遍历该桶的链表（如果存在），找到键为 'b' 的条目。
   - 返回对应的值 2。

**涉及用户常见的编程错误 (如果与 JavaScript 有关):**

1. **依赖哈希表的顺序 (在 ES6 之前):**  在 ES6 引入 `Map` 和 `Set` 之前，JavaScript 的普通对象 (`{}`) 的属性顺序是不保证的。程序员可能会错误地依赖对象的属性顺序，导致在不同 JavaScript 引擎或版本中行为不一致。 `OrderedHashMap` 的引入解决了这个问题，为 `Map` 提供了可靠的顺序保证。

2. **修改正在迭代的 Map 或 Set:**  如果在迭代 `Map` 或 `Set` 的过程中添加或删除元素，可能会导致迭代器失效或产生意外的结果。V8 的 `OrderedHashTable` 内部的 obsolete 机制部分是为了解决在扩容等操作时保持迭代器的一致性。

**总结:**

`v8/src/objects/ordered-hash-table.h` 定义了 V8 引擎中用于实现有序哈希表的核心数据结构，为 JavaScript 的 `Map` 和 `Set` 提供了底层支持，并保证了元素的插入顺序。它包含了多种针对不同场景的实现，并具有动态调整大小和处理哈希冲突的能力。 如果该文件以 `.tq` 结尾，则意味着它使用了 V8 的 Torque 语言进行编写，以获得更高的性能。

### 提示词
```
这是目录为v8/src/objects/ordered-hash-table.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/ordered-hash-table.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```c
// Copyright 2018 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_OBJECTS_ORDERED_HASH_TABLE_H_
#define V8_OBJECTS_ORDERED_HASH_TABLE_H_

#include "src/base/export-template.h"
#include "src/common/globals.h"
#include "src/objects/fixed-array.h"
#include "src/objects/internal-index.h"
#include "src/objects/js-objects.h"
#include "src/objects/keys.h"
#include "src/objects/smi.h"
#include "src/roots/roots.h"

// Has to be the last include (doesn't have include guards):
#include "src/objects/object-macros.h"

namespace v8 {
namespace internal {

// OrderedHashTable is a HashTable with Object keys that preserves
// insertion order. There are Map and Set interfaces (OrderedHashMap
// and OrderedHashTable, below). It is meant to be used by JSMap/JSSet.
//
// Only Object keys are supported, with Object::SameValueZero() used as the
// equality operator and Object::GetHash() for the hash function.
//
// Based on the "Deterministic Hash Table" as described by Jason Orendorff at
// https://wiki.mozilla.org/User:Jorend/Deterministic_hash_tables
// Originally attributed to Tyler Close.
//
// Memory layout:
//   [0] : Prefix
//   [kPrefixSize]: element count
//   [kPrefixSize + 1]: deleted element count
//   [kPrefixSize + 2]: bucket count
//   [kPrefixSize + 3..(kPrefixSize + 3 + NumberOfBuckets() - 1)]: "hash table",
//                            where each item is an offset into the
//                            data table (see below) where the first
//                            item in this bucket is stored.
//   [kPrefixSize + 3 + NumberOfBuckets()..length]: "data table", an
//                            array of length Capacity() * kEntrySize,
//                            where the first entrysize items are
//                            handled by the derived class and the
//                            item at kChainOffset is another entry
//                            into the data table indicating the next
//                            entry in this hash bucket.
//
// When we transition the table to a new version we obsolete it and reuse parts
// of the memory to store information how to transition an iterator to the new
// table:
//
// Memory layout for obsolete table:
//   [0] : Prefix
//   [kPrefixSize + 0]: Next newer table
//   [kPrefixSize + 1]: deleted element count or kClearedTableSentinel if
//                      the table was cleared
//   [kPrefixSize + 2]: bucket count
//   [kPrefixSize + 3..(kPrefixSize + 3 + NumberOfDeletedElements() - 1)]:
//                      The indexes of the removed holes. This part is only
//                      usable for non-cleared tables, as clearing removes the
//                      deleted elements count.
//   [kPrefixSize + 3 + NumberOfDeletedElements()..length]: Not used
template <class Derived, int entrysize>
class OrderedHashTable : public FixedArray {
 public:
  // Returns an OrderedHashTable (possibly |table|) with enough space
  // to add at least one new element.
  static MaybeHandle<Derived> EnsureCapacityForAdding(Isolate* isolate,
                                                      Handle<Derived> table);

  // Returns an OrderedHashTable (possibly |table|) that's shrunken
  // if possible.
  static Handle<Derived> Shrink(Isolate* isolate, Handle<Derived> table);

  // Returns a new empty OrderedHashTable and records the clearing so that
  // existing iterators can be updated.
  static Handle<Derived> Clear(Isolate* isolate, Handle<Derived> table);

  // Returns true if the OrderedHashTable contains the key
  static bool HasKey(Isolate* isolate, Tagged<Derived> table,
                     Tagged<Object> key);

  // Returns whether a potential key |k| returned by KeyAt is a real
  // key (meaning that it is not a hole).
  static inline bool IsKey(ReadOnlyRoots roots, Tagged<Object> k);

  // Returns a true value if the OrderedHashTable contains the key and
  // the key has been deleted. This does not shrink the table.
  static bool Delete(Isolate* isolate, Tagged<Derived> table,
                     Tagged<Object> key);

  InternalIndex FindEntry(Isolate* isolate, Tagged<Object> key);

  int NumberOfElements() const {
    return Smi::ToInt(get(NumberOfElementsIndex()));
  }

  int NumberOfDeletedElements() const {
    return Smi::ToInt(get(NumberOfDeletedElementsIndex()));
  }

  // Returns the number of contiguous entries in the data table, starting at 0,
  // that either are real entries or have been deleted.
  int UsedCapacity() const {
    return NumberOfElements() + NumberOfDeletedElements();
  }

  int Capacity() { return NumberOfBuckets() * kLoadFactor; }

  int NumberOfBuckets() const {
    return Smi::ToInt(get(NumberOfBucketsIndex()));
  }

  InternalIndex::Range IterateEntries() {
    return InternalIndex::Range(UsedCapacity());
  }

  // use IsKey to check if this is a deleted entry.
  Tagged<Object> KeyAt(InternalIndex entry) {
    DCHECK_LT(entry.as_int(), this->UsedCapacity());
    return get(EntryToIndex(entry));
  }

  // Similar to KeyAt, but indicates whether the given entry is valid
  // (not deleted one)
  inline bool ToKey(ReadOnlyRoots roots, InternalIndex entry,
                    Tagged<Object>* out_key);

  bool IsObsolete() { return !IsSmi(get(NextTableIndex())); }

  // The next newer table. This is only valid if the table is obsolete.
  Tagged<Derived> NextTable() { return Cast<Derived>(get(NextTableIndex())); }

  // When the table is obsolete we store the indexes of the removed holes.
  int RemovedIndexAt(int index) {
    return Smi::ToInt(get(RemovedHolesIndex() + index));
  }

  // The extra +1 is for linking the bucket chains together.
  static const int kEntrySize = entrysize + 1;
  static const int kEntrySizeWithoutChain = entrysize;
  static const int kChainOffset = entrysize;

  static const int kNotFound = -1;
  // The minimum capacity. Note that despite this value, 0 is also a permitted
  // capacity, indicating a table without any storage for elements.
  static const int kInitialCapacity = 4;

  static constexpr int PrefixIndex() { return 0; }

  static constexpr int NumberOfElementsIndex() { return Derived::kPrefixSize; }

  // The next table is stored at the same index as the nof elements.
  static constexpr int NextTableIndex() { return NumberOfElementsIndex(); }

  static constexpr int NumberOfDeletedElementsIndex() {
    return NumberOfElementsIndex() + 1;
  }

  static constexpr int NumberOfBucketsIndex() {
    return NumberOfDeletedElementsIndex() + 1;
  }

  static constexpr int HashTableStartIndex() {
    return NumberOfBucketsIndex() + 1;
  }

  static constexpr int RemovedHolesIndex() { return HashTableStartIndex(); }

  static constexpr int NumberOfElementsOffset() {
    return FixedArray::OffsetOfElementAt(NumberOfElementsIndex());
  }

  static constexpr int NextTableOffset() {
    return FixedArray::OffsetOfElementAt(NextTableIndex());
  }

  static constexpr int NumberOfDeletedElementsOffset() {
    return FixedArray::OffsetOfElementAt(NumberOfDeletedElementsIndex());
  }

  static constexpr int NumberOfBucketsOffset() {
    return FixedArray::OffsetOfElementAt(NumberOfBucketsIndex());
  }

  static constexpr int HashTableStartOffset() {
    return FixedArray::OffsetOfElementAt(HashTableStartIndex());
  }

  static const int kLoadFactor = 2;

  // NumberOfDeletedElements is set to kClearedTableSentinel when
  // the table is cleared, which allows iterator transitions to
  // optimize that case.
  static const int kClearedTableSentinel = -1;
  static constexpr int MaxCapacity() {
    return (FixedArray::kMaxLength - HashTableStartIndex()) /
           (1 + (kEntrySize * kLoadFactor));
  }

 protected:
  // Returns an OrderedHashTable with a capacity of at least |capacity|.
  static MaybeHandle<Derived> Allocate(
      Isolate* isolate, int capacity,
      AllocationType allocation = AllocationType::kYoung);

  static MaybeHandle<Derived> AllocateEmpty(Isolate* isolate,
                                            AllocationType allocation,
                                            RootIndex root_ndex);

  static MaybeHandle<Derived> Rehash(Isolate* isolate, Handle<Derived> table);
  static MaybeHandle<Derived> Rehash(Isolate* isolate, Handle<Derived> table,
                                     int new_capacity);

  int HashToEntryRaw(int hash) {
    int bucket = HashToBucket(hash);
    Tagged<Object> entry = this->get(HashTableStartIndex() + bucket);
    int entry_int = Smi::ToInt(entry);
    DCHECK(entry_int == kNotFound || entry_int >= 0);
    return entry_int;
  }

  int NextChainEntryRaw(int entry) {
    DCHECK_LT(entry, this->UsedCapacity());
    Tagged<Object> next_entry = get(EntryToIndexRaw(entry) + kChainOffset);
    int next_entry_int = Smi::ToInt(next_entry);
    DCHECK(next_entry_int == kNotFound || next_entry_int >= 0);
    return next_entry_int;
  }

  // Returns an index into |this| for the given entry.
  int EntryToIndexRaw(int entry) {
    return HashTableStartIndex() + NumberOfBuckets() + (entry * kEntrySize);
  }

  int EntryToIndex(InternalIndex entry) {
    return EntryToIndexRaw(entry.as_int());
  }

  int HashToBucket(int hash) { return hash & (NumberOfBuckets() - 1); }

  void SetNumberOfBuckets(int num) {
    set(NumberOfBucketsIndex(), Smi::FromInt(num));
  }

  void SetNumberOfElements(int num) {
    set(NumberOfElementsIndex(), Smi::FromInt(num));
  }

  void SetNumberOfDeletedElements(int num) {
    set(NumberOfDeletedElementsIndex(), Smi::FromInt(num));
  }

  void SetNextTable(Tagged<Derived> next_table) {
    set(NextTableIndex(), next_table);
  }

  void SetRemovedIndexAt(int index, int removed_index) {
    return set(RemovedHolesIndex() + index, Smi::FromInt(removed_index));
  }

 private:
  friend class OrderedNameDictionaryHandler;
};

class V8_EXPORT_PRIVATE OrderedHashSet
    : public OrderedHashTable<OrderedHashSet, 1> {
  using Base = OrderedHashTable<OrderedHashSet, 1>;

 public:
  DECL_PRINTER(OrderedHashSet)

  static MaybeHandle<OrderedHashSet> Add(Isolate* isolate,
                                         Handle<OrderedHashSet> table,
                                         DirectHandle<Object> value);
  static Handle<FixedArray> ConvertToKeysArray(Isolate* isolate,
                                               Handle<OrderedHashSet> table,
                                               GetKeysConversion convert);
  static MaybeHandle<OrderedHashSet> Rehash(Isolate* isolate,
                                            Handle<OrderedHashSet> table,
                                            int new_capacity);
  static MaybeHandle<OrderedHashSet> Rehash(Isolate* isolate,
                                            Handle<OrderedHashSet> table);
  template <typename IsolateT>
  static MaybeHandle<OrderedHashSet> Allocate(
      IsolateT* isolate, int capacity,
      AllocationType allocation = AllocationType::kYoung);

  static MaybeHandle<OrderedHashSet> AllocateEmpty(
      Isolate* isolate, AllocationType allocation = AllocationType::kReadOnly);

  static Tagged<HeapObject> GetEmpty(ReadOnlyRoots ro_roots);
  static inline Handle<Map> GetMap(ReadOnlyRoots roots);
  static inline bool Is(DirectHandle<HeapObject> table);
  static const int kPrefixSize = 0;
};

class V8_EXPORT_PRIVATE OrderedHashMap
    : public OrderedHashTable<OrderedHashMap, 2> {
  using Base = OrderedHashTable<OrderedHashMap, 2>;

 public:
  DECL_PRINTER(OrderedHashMap)

  // Returns a value if the OrderedHashMap contains the key, otherwise
  // returns undefined.
  static MaybeHandle<OrderedHashMap> Add(Isolate* isolate,
                                         Handle<OrderedHashMap> table,
                                         DirectHandle<Object> key,
                                         DirectHandle<Object> value);

  template <typename IsolateT>
  static MaybeHandle<OrderedHashMap> Allocate(
      IsolateT* isolate, int capacity,
      AllocationType allocation = AllocationType::kYoung);

  static MaybeHandle<OrderedHashMap> AllocateEmpty(
      Isolate* isolate, AllocationType allocation = AllocationType::kReadOnly);

  static MaybeHandle<OrderedHashMap> Rehash(Isolate* isolate,
                                            Handle<OrderedHashMap> table,
                                            int new_capacity);
  static MaybeHandle<OrderedHashMap> Rehash(Isolate* isolate,
                                            Handle<OrderedHashMap> table);

  void SetEntry(InternalIndex entry, Tagged<Object> key, Tagged<Object> value);

  Tagged<Object> ValueAt(InternalIndex entry);

  // This takes and returns raw Address values containing tagged Object
  // pointers because it is called via ExternalReference.
  static Address GetHash(Isolate* isolate, Address raw_key);

  static Tagged<HeapObject> GetEmpty(ReadOnlyRoots ro_roots);
  static inline Handle<Map> GetMap(ReadOnlyRoots roots);
  static inline bool Is(DirectHandle<HeapObject> table);

  static const int kValueOffset = 1;
  static const int kPrefixSize = 0;
};

// This is similar to the OrderedHashTable, except for the memory
// layout where we use byte instead of Smi. The max capacity of this
// is only 254, we transition to an OrderedHashTable beyond that
// limit.
//
// Each bucket and chain value is a byte long. The padding exists so
// that the DataTable entries start aligned. A bucket or chain value
// of 255 is used to denote an unknown entry.
//
// The prefix size is calculated as the kPrefixSize * kTaggedSize.
//
// Memory layout: [ Prefix ] [ Header ]  [ Padding ] [ DataTable ] [ HashTable ]
// [ Chains ]
//
// The index are represented as bytes, on a 64 bit machine with
// kEntrySize = 1, capacity = 4 and entries = 2:
//
// [ 0 ] : Prefix
//
// Note: For the sake of brevity, the following start with index 0
// but, they actually start from kPrefixSize * kTaggedSize to
// account for the the prefix.
//
// [ Header ]  :
//    [0] : Number of elements
//    [1] : Number of deleted elements
//    [2] : Number of buckets
//
// [ Padding ] :
//    [3 .. 7] : Padding
//
// [ DataTable ] :
//    [8  .. 15] : Entry 1
//    [16 .. 23] : Entry 2
//    [24 .. 31] : empty
//    [32 .. 39] : empty
//
// [ HashTable ] :
//    [40] : First chain-link for bucket 1
//    [41] : empty
//
// [ Chains ] :
//    [42] : Next chain link for bucket 1
//    [43] : empty
//    [44] : empty
//    [45] : empty
//
template <class Derived>
class SmallOrderedHashTable : public HeapObject {
 public:
  // Offset points to a relative location in the table
  using Offset = int;

  // ByteIndex points to a index in the table that needs to be
  // converted to an Offset.
  using ByteIndex = int;

  void Initialize(Isolate* isolate, int capacity);

  static Handle<Derived> Allocate(
      Isolate* isolate, int capacity,
      AllocationType allocation = AllocationType::kYoung);

  // Returns a true if the OrderedHashTable contains the key
  bool HasKey(Isolate* isolate, DirectHandle<Object> key);

  // Returns a true value if the table contains the key and
  // the key has been deleted. This does not shrink the table.
  static bool Delete(Isolate* isolate, Tagged<Derived> table,
                     Tagged<Object> key);

  // Returns an SmallOrderedHashTable (possibly |table|) with enough
  // space to add at least one new element. Returns empty handle if
  // we've already reached MaxCapacity.
  static MaybeHandle<Derived> Grow(Isolate* isolate, Handle<Derived> table);

  InternalIndex FindEntry(Isolate* isolate, Tagged<Object> key);
  static Handle<Derived> Shrink(Isolate* isolate, Handle<Derived> table);

  // Iterates only fields in the DataTable.
  class BodyDescriptor;

  // Returns total size in bytes required for a table of given
  // capacity.
  static int SizeFor(int capacity) {
    DCHECK_GE(capacity, kMinCapacity);
    DCHECK_LE(capacity, kMaxCapacity);

    int data_table_size = DataTableSizeFor(capacity);
    int hash_table_size = capacity / kLoadFactor;
    int chain_table_size = capacity;
    int total_size = DataTableStartOffset() + data_table_size +
                     hash_table_size + chain_table_size;

    return RoundUp(total_size, kTaggedSize);
  }

  // Returns the number elements that can fit into the allocated table.
  int Capacity() const {
    int capacity = NumberOfBuckets() * kLoadFactor;
    DCHECK_GE(capacity, kMinCapacity);
    DCHECK_LE(capacity, kMaxCapacity);

    return capacity;
  }

  // Returns the number elements that are present in the table.
  int NumberOfElements() const {
    int nof_elements = getByte(NumberOfElementsOffset(), 0);
    DCHECK_LE(nof_elements, Capacity());

    return nof_elements;
  }

  int NumberOfDeletedElements() const {
    int nof_deleted_elements = getByte(NumberOfDeletedElementsOffset(), 0);
    DCHECK_LE(nof_deleted_elements, Capacity());

    return nof_deleted_elements;
  }

  int NumberOfBuckets() const { return getByte(NumberOfBucketsOffset(), 0); }

  V8_INLINE Tagged<Object> KeyAt(InternalIndex entry) const;

  InternalIndex::Range IterateEntries() {
    return InternalIndex::Range(UsedCapacity());
  }

  DECL_VERIFIER(SmallOrderedHashTable)

  static const int kMinCapacity = 4;
  static const uint8_t kNotFound = 0xFF;

  // We use the value 255 to indicate kNotFound for chain and bucket
  // values, which means that this value can't be used a valid
  // index.
  static const int kMaxCapacity = 254;
  static_assert(kMaxCapacity < kNotFound);

  // The load factor is used to derive the number of buckets from
  // capacity during Allocation. We also depend on this to calaculate
  // the capacity from number of buckets after allocation. If we
  // decide to change kLoadFactor to something other than 2, capacity
  // should be stored as another field of this object.
  static const int kLoadFactor = 2;

  // Our growth strategy involves doubling the capacity until we reach
  // kMaxCapacity, but since the kMaxCapacity is always less than 256,
  // we will never fully utilize this table. We special case for 256,
  // by changing the new capacity to be kMaxCapacity in
  // SmallOrderedHashTable::Grow.
  static const int kGrowthHack = 256;

 protected:
  static Handle<Derived> Rehash(Isolate* isolate, Handle<Derived> table,
                                int new_capacity);

  void SetDataEntry(int entry, int relative_index, Tagged<Object> value);

  // TODO(gsathya): Calculate all the various possible values for this
  // at compile time since capacity can only be 4 different values.
  Offset GetBucketsStartOffset() const {
    int capacity = Capacity();
    int data_table_size = DataTableSizeFor(capacity);
    return DataTableStartOffset() + data_table_size;
  }

  Address GetHashTableStartAddress(int capacity) const {
    return field_address(DataTableStartOffset() + DataTableSizeFor(capacity));
  }

  void SetFirstEntry(int bucket, uint8_t value) {
    DCHECK_LE(static_cast<unsigned>(bucket), NumberOfBuckets());
    setByte(GetBucketsStartOffset(), bucket, value);
  }

  int GetFirstEntry(int bucket) const {
    DCHECK_LE(static_cast<unsigned>(bucket), NumberOfBuckets());
    return getByte(GetBucketsStartOffset(), bucket);
  }

  // TODO(gsathya): Calculate all the various possible values for this
  // at compile time since capacity can only be 4 different values.
  Offset GetChainTableOffset() const {
    int nof_buckets = NumberOfBuckets();
    int capacity = nof_buckets * kLoadFactor;
    DCHECK_EQ(Capacity(), capacity);

    int data_table_size = DataTableSizeFor(capacity);
    int hash_table_size = nof_buckets;
    return DataTableStartOffset() + data_table_size + hash_table_size;
  }

  void SetNextEntry(int entry, int next_entry) {
    DCHECK_LT(static_cast<unsigned>(entry), Capacity());
    DCHECK_GE(static_cast<unsigned>(next_entry), 0);
    DCHECK(next_entry <= Capacity() || next_entry == kNotFound);
    setByte(GetChainTableOffset(), entry, next_entry);
  }

  int GetNextEntry(int entry) const {
    DCHECK_LT(entry, Capacity());
    return getByte(GetChainTableOffset(), entry);
  }

  V8_INLINE Tagged<Object> GetDataEntry(int entry, int relative_index);

  int HashToBucket(int hash) const { return hash & (NumberOfBuckets() - 1); }

  int HashToFirstEntry(int hash) const {
    int bucket = HashToBucket(hash);
    int entry = GetFirstEntry(bucket);
    DCHECK(entry < Capacity() || entry == kNotFound);
    return entry;
  }

  void SetNumberOfBuckets(int num) { setByte(NumberOfBucketsOffset(), 0, num); }

  void SetNumberOfElements(int num) {
    DCHECK_LE(static_cast<unsigned>(num), Capacity());
    setByte(NumberOfElementsOffset(), 0, num);
  }

  void SetNumberOfDeletedElements(int num) {
    DCHECK_LE(static_cast<unsigned>(num), Capacity());
    setByte(NumberOfDeletedElementsOffset(), 0, num);
  }

  static constexpr Offset PrefixOffset() { return kHeaderSize; }

  static constexpr Offset NumberOfElementsOffset() {
    return PrefixOffset() + (Derived::kPrefixSize * kTaggedSize);
  }

  static constexpr Offset NumberOfDeletedElementsOffset() {
    return NumberOfElementsOffset() + kOneByteSize;
  }

  static constexpr Offset NumberOfBucketsOffset() {
    return NumberOfDeletedElementsOffset() + kOneByteSize;
  }

  static constexpr Offset PaddingOffset() {
    return NumberOfBucketsOffset() + kOneByteSize;
  }

  static constexpr size_t PaddingSize() {
    return RoundUp<kTaggedSize>(PaddingOffset()) - PaddingOffset();
  }

  static constexpr Offset DataTableStartOffset() {
    return PaddingOffset() + PaddingSize();
  }

  static constexpr int DataTableSizeFor(int capacity) {
    return capacity * Derived::kEntrySize * kTaggedSize;
  }

  // This is used for accessing the non |DataTable| part of the
  // structure.
  uint8_t getByte(Offset offset, ByteIndex index) const {
    DCHECK(offset < DataTableStartOffset() ||
           offset >= GetBucketsStartOffset());
    return ReadField<uint8_t>(offset + (index * kOneByteSize));
  }

  void setByte(Offset offset, ByteIndex index, uint8_t value) {
    DCHECK(offset < DataTableStartOffset() ||
           offset >= GetBucketsStartOffset());
    WriteField<uint8_t>(offset + (index * kOneByteSize), value);
  }

  Offset GetDataEntryOffset(int entry, int relative_index) const {
    DCHECK_LT(entry, Capacity());
    int offset_in_datatable = entry * Derived::kEntrySize * kTaggedSize;
    int offset_in_entry = relative_index * kTaggedSize;
    return DataTableStartOffset() + offset_in_datatable + offset_in_entry;
  }

  int UsedCapacity() const {
    int used = NumberOfElements() + NumberOfDeletedElements();
    DCHECK_LE(used, Capacity());

    return used;
  }

 private:
  friend class OrderedHashMapHandler;
  friend class OrderedHashSetHandler;
  friend class OrderedNameDictionaryHandler;
  friend class CodeStubAssembler;

  OBJECT_CONSTRUCTORS(SmallOrderedHashTable, HeapObject);
};

class SmallOrderedHashSet : public SmallOrderedHashTable<SmallOrderedHashSet> {
 public:
  DECL_PRINTER(SmallOrderedHashSet)
  EXPORT_DECL_VERIFIER(SmallOrderedHashSet)

  static const int kKeyIndex = 0;
  static const int kEntrySize = 1;
  static const int kPrefixSize = 0;

  // Adds |value| to |table|, if the capacity isn't enough, a new
  // table is created. The original |table| is returned if there is
  // capacity to store |value| otherwise the new table is returned.
  V8_EXPORT_PRIVATE static MaybeHandle<SmallOrderedHashSet> Add(
      Isolate* isolate, Handle<SmallOrderedHashSet> table,
      DirectHandle<Object> key);
  V8_EXPORT_PRIVATE static bool Delete(Isolate* isolate,
                                       Tagged<SmallOrderedHashSet> table,
                                       Tagged<Object> key);
  V8_EXPORT_PRIVATE bool HasKey(Isolate* isolate, DirectHandle<Object> key);

  static inline bool Is(DirectHandle<HeapObject> table);
  static inline Handle<Map> GetMap(ReadOnlyRoots roots);
  static Handle<SmallOrderedHashSet> Rehash(Isolate* isolate,
                                            Handle<SmallOrderedHashSet> table,
                                            int new_capacity);
  OBJECT_CONSTRUCTORS(SmallOrderedHashSet,
                      SmallOrderedHashTable<SmallOrderedHashSet>);
};

static_assert(kSmallOrderedHashSetMinCapacity ==
              SmallOrderedHashSet::kMinCapacity);

class SmallOrderedHashMap : public SmallOrderedHashTable<SmallOrderedHashMap> {
 public:
  DECL_PRINTER(SmallOrderedHashMap)
  EXPORT_DECL_VERIFIER(SmallOrderedHashMap)

  static const int kKeyIndex = 0;
  static const int kValueIndex = 1;
  static const int kEntrySize = 2;
  static const int kPrefixSize = 0;

  // Adds |value| to |table|, if the capacity isn't enough, a new
  // table is created. The original |table| is returned if there is
  // capacity to store |value| otherwise the new table is returned.
  V8_EXPORT_PRIVATE static MaybeHandle<SmallOrderedHashMap> Add(
      Isolate* isolate, Handle<SmallOrderedHashMap> table,
      DirectHandle<Object> key, DirectHandle<Object> value);
  V8_EXPORT_PRIVATE static bool Delete(Isolate* isolate,
                                       Tagged<SmallOrderedHashMap> table,
                                       Tagged<Object> key);
  V8_EXPORT_PRIVATE bool HasKey(Isolate* isolate, DirectHandle<Object> key);
  static inline bool Is(DirectHandle<HeapObject> table);
  static inline Handle<Map> GetMap(ReadOnlyRoots roots);

  static Handle<SmallOrderedHashMap> Rehash(Isolate* isolate,
                                            Handle<SmallOrderedHashMap> table,
                                            int new_capacity);

  OBJECT_CONSTRUCTORS(SmallOrderedHashMap,
                      SmallOrderedHashTable<SmallOrderedHashMap>);
};

static_assert(kSmallOrderedHashMapMinCapacity ==
              SmallOrderedHashMap::kMinCapacity);

// TODO(gsathya): Rename this to OrderedHashTable, after we rename
// OrderedHashTable to LargeOrderedHashTable. Also set up a
// OrderedHashSetBase class as a base class for the two tables and use
// that instead of a HeapObject here.
template <class SmallTable, class LargeTable>
class EXPORT_TEMPLATE_DECLARE(V8_EXPORT_PRIVATE) OrderedHashTableHandler {
 public:
  using Entry = int;

  static MaybeHandle<HeapObject> Allocate(Isolate* isolate, int capacity);
  static bool Delete(Isolate* isolate, Handle<HeapObject> table,
                     DirectHandle<Object> key);
  static bool HasKey(Isolate* isolate, Handle<HeapObject> table,
                     Handle<Object> key);

  // TODO(gsathya): Move this to OrderedHashTable
  static const int OrderedHashTableMinSize =
      SmallOrderedHashTable<SmallTable>::kGrowthHack << 1;
};

extern template class EXPORT_TEMPLATE_DECLARE(V8_EXPORT_PRIVATE)
    OrderedHashTableHandler<SmallOrderedHashMap, OrderedHashMap>;

class V8_EXPORT_PRIVATE OrderedHashMapHandler
    : public OrderedHashTableHandler<SmallOrderedHashMap, OrderedHashMap> {
 public:
  static MaybeHandle<HeapObject> Add(Isolate* isolate, Handle<HeapObject> table,
                                     DirectHandle<Object> key,
                                     DirectHandle<Object> value);
  static MaybeHandle<OrderedHashMap> AdjustRepresentation(
      Isolate* isolate, DirectHandle<SmallOrderedHashMap> table);
};

extern template class EXPORT_TEMPLATE_DECLARE(V8_EXPORT_PRIVATE)
    OrderedHashTableHandler<SmallOrderedHashSet, OrderedHashSet>;

class V8_EXPORT_PRIVATE OrderedHashSetHandler
    : public OrderedHashTableHandler<SmallOrderedHashSet, OrderedHashSet> {
 public:
  static MaybeHandle<HeapObject> Add(Isolate* isolate, Handle<HeapObject> table,
                                     DirectHandle<Object> key);
  static MaybeHandle<OrderedHashSet> AdjustRepresentation(
      Isolate* isolate, DirectHandle<SmallOrderedHashSet> table);
};

class V8_EXPORT_PRIVATE OrderedNameDictionary
    : public OrderedHashTable<OrderedNameDictionary, 3> {
  using Base = OrderedHashTable<OrderedNameDictionary, 3>;

 public:
  DECL_PRINTER(OrderedNameDictionary)

  static MaybeHandle<OrderedNameDictionary> Add(
      Isolate* isolate, Handle<OrderedNameDictionary> table,
      DirectHandle<Name> key, DirectHandle<Object> value,
      PropertyDetails details);

  void SetEntry(InternalIndex entry, Tagged<Object> key, Tagged<Object> value,
                PropertyDetails details);

  template <typename IsolateT>
  InternalIndex FindEntry(IsolateT* isolate, Tagged<Object> key);

  // This is to make the interfaces of NameDictionary::FindEntry and
  // OrderedNameDictionary::FindEntry compatible.
  // TODO(emrich) clean this up: NameDictionary uses Handle<Object>
  // for FindEntry keys due to its Key typedef, but that's also used
  // for adding, where we do need handles.
  template <typename IsolateT>
  InternalIndex FindEntry(IsolateT* isolate, DirectHandle<Object> key) {
    return FindEntry(isolate, *key);
  }

  static Handle<OrderedNameDictionary> DeleteEntry(
      Isolate* isolate, Handle<OrderedNameDictionary> table,
      InternalIndex entry);

  static MaybeHandle<OrderedNameDictionary> Allocate(
      Isolate* isolate, int capacity,
      AllocationType allocation = AllocationType::kYoung);

  static MaybeHandle<OrderedNameDictionary> AllocateEmpty(
      Isolate* isolate, AllocationType allocation = AllocationType::kReadOnly);

  static MaybeHandle<OrderedNameDictionary> Rehash(
      Isolate* isolate, Handle<OrderedNameDictionary> table, int new_capacity);

  // Returns the value for entry.
  inline Tagged<Object> ValueAt(InternalIndex entry);

  // Like KeyAt, but casts to Name
  inline Tagged<Name> NameAt(InternalIndex entry);

  // Set the value for entry.
  inline void ValueAtPut(InternalIndex entry, Tagged<Object> value);

  // Returns the property details for the property at entry.
  inline PropertyDetails DetailsAt(InternalIndex entry);

  // Set the details for entry.
  inline void DetailsAtPut(InternalIndex entry, PropertyDetails value);

  inline void SetHash(int hash);
  inline int Hash();

  static Tagged<HeapObject> GetEmpty(ReadOnlyRoots ro_roots);
  static inline Handle<Map> GetMap(ReadOnlyRoots roots);
  static inline bool Is(DirectHandle<HeapObject> table);

  static const int kValueOffset = 1;
  static const int kPropertyDetailsOffset = 2;
  static const int kPrefixSize = 1;

  static constexpr int HashIndex() { return PrefixIndex(); }

  static const bool kIsOrderedDictionaryType = true;
};

extern template class EXPORT_TEMPLATE_DECLARE(V8_EXPORT_PRIVATE)
    OrderedHashTableHandler<SmallOrderedNameDictionary, OrderedNameDictionary>;

class V8_EXPORT_PRIVATE OrderedNameDictionaryHandler
    : public OrderedHashTableHandler<SmallOrderedNameDictionary,
                                     OrderedNameDictionary> {
 public:
  static MaybeHandle<HeapObject> Add(Isolate* isolate, Handle<HeapObject> table,
                                     DirectHandle<Name> key,
                                     DirectHandle<Object> value,
                                     PropertyDetails details);
  static Handle<HeapObject> Shrink(Isolate* isolate, Handle<HeapObject> table);

  static Handle<HeapObject> DeleteEntry(Isolate* isolate,
                                        Handle<HeapObject> table,
                                        InternalIndex entry);
  static InternalIndex FindEntry(Isolate* isolate, Tagged<HeapObject> table,
                                 Tagged<Name> key);
  static void SetEntry(Tagged<HeapObject> table, InternalIndex entry,
                       Tagged<Object> key, Tagged<Object> value,
                       PropertyDetails details);

  // Returns the value for entry.
  static Tagged<Object> ValueAt(Tagged<HeapObject> table, InternalIndex entry);

  // Set the value for entry.
  static void ValueAtPut(Tagged<HeapObject> table, InternalIndex entry,
                         Tagged<Object> value);

  // Returns the property details for the property at entry.
  static PropertyDetails DetailsAt(Tagged<HeapObject> table,
                                   InternalIndex entry);

  // Set the details for entry.
  static void DetailsAtPut(Tagged<HeapObject> table, InternalIndex entry,
                           PropertyDetails value);

  static Tagged<Name> KeyAt(Tagged<HeapObject> table, InternalIndex entry);

  static void SetHash(Tagged<HeapObject> table, int hash);
  static int Hash(Tagged<HeapObject> table);

  static int NumberOfElements(Tagged<HeapObject> table);
  static int Capacity(Tagged<HeapObject> table);

 protected:
  static MaybeHandle<OrderedNameDictionary> AdjustRepresentation(
      Isolate* isolate, DirectHandle<SmallOrderedNameDictionary> table);
};

class SmallOrderedNameDictionary
    : public SmallOrderedHashTabl
```