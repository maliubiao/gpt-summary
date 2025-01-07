Response:
The user wants a summary of the provided C++ code snippet for `v8/src/objects/ordered-hash-table.cc`. Specifically, they're asking for the functionality of the code, mentioning aspects like Torque, JavaScript relevance, logic inference with examples, common programming errors, and a final concise summary.

Here's a breakdown of how to address each point:

1. **Functionality:**  The code implements ordered hash tables in V8. This involves operations like adding, deleting, finding, resizing, and iterating over key-value pairs (or just keys in the case of sets). The "ordered" aspect means it preserves the insertion order. It also handles transitions between "small" and "large" hash table implementations.

2. **Torque:** The prompt explicitly mentions checking for `.tq`. Since the provided code is `.cc`, it's C++, *not* Torque. This is an important distinction to highlight.

3. **JavaScript Relevance:** Ordered hash tables are the underlying data structure for JavaScript's `Map` and `Set` objects, and for the internal representation of objects to some extent (property storage). Illustrate this with basic `Map` and `Set` usage in JavaScript.

4. **Logic Inference:** Select a simple function, like `HasKey`, and trace its execution with a hypothetical input to show how it finds an element. For `Delete`, demonstrate how the "hole" mechanism works.

5. **Common Programming Errors:**  Think about how users might misuse or misunderstand hash tables in general, or specifically related to V8's implementation (though direct user interaction with these internals is rare). Examples include using non-primitive types as keys without proper `hashCode` implementation (though V8 handles this well), or assuming specific iteration order without using ordered structures. Perhaps mentioning performance implications of excessive resizing could be relevant.

6. **Final Summary:** Condense the functionality into a few sentences, emphasizing the core purpose and key characteristics.

**Mental Sandbox:**

* **Torque Check:**  Immediately identify that it's `.cc`, not `.tq`.
* **JavaScript Connection:**  Focus on `Map` and `Set` as the primary link. Briefly mention object properties.
* **Logic Example (HasKey):**  Imagine a `SmallOrderedHashMap` with a few entries. Trace the steps of `FindEntry` with a known key.
* **Logic Example (Delete):** Show how an entry is marked with "the hole" and how the element count is adjusted.
* **Programming Errors:**  Consider generic hash table issues and V8-specific context if applicable.
* **Summary:** Keep it high-level, mentioning ordering and the small/large table strategy.

Strategizing complete. Proceeding with response generation.

好的，根据你提供的代码片段，这是V8 JavaScript引擎中关于`SmallOrderedHashTable`和`OrderedHashTableHandler`的C++实现。这个代码片段是 `v8/src/objects/ordered-hash-table.cc` 文件的第二部分。

**功能归纳:**

这段代码主要实现了**小型有序哈希表 (SmallOrderedHashTable)** 及其相关的操作，并提供了一个**有序哈希表处理器 (OrderedHashTableHandler)**，用于管理小型和大型有序哈希表之间的转换。核心功能包括：

1. **小型有序哈希表的实现 (`SmallOrderedHashTable` 模板类):**
   - **添加元素 (`Add`):**  向哈希表中添加键值对（对于 `SmallOrderedHashMap` 和 `SmallOrderedNameDictionary`）或键（对于 `SmallOrderedHashSet`）。
   - **查找元素 (`FindEntry`, `HasKey`):**  根据键查找哈希表中的条目。
   - **删除元素 (`Delete`, `DeleteEntry`):**  从哈希表中删除指定的键值对或键。被删除的条目会被标记为 "hole"。
   - **调整大小 (`Rehash`, `Shrink`, `Grow`):**
     - `Rehash`: 重新分配哈希表，通常用于增加容量。
     - `Shrink`: 在元素数量过少时缩小哈希表容量。
     - `Grow`: 在容量不足时增加哈希表容量。
   - **初始化 (`Initialize`):**  创建并初始化一个指定容量的哈希表。
   - **迭代 (`IterateEntries`):**  提供一种遍历哈希表中所有有效条目的方式。

2. **有序哈希表处理器 (`OrderedHashTableHandler` 模板类):**
   - **分配 (`Allocate`):**  根据所需的容量，决定分配小型哈希表还是大型哈希表 (`OrderedHashSet`, `OrderedHashMap`, `OrderedNameDictionary`)。这是 V8 中一种优化策略，对于小容量的哈希表使用更轻量级的实现。
   - **删除 (`Delete`):**  根据哈希表类型（小型或大型）调用相应的删除方法。
   - **查找 (`HasKey`):**  根据哈希表类型调用相应的查找方法。
   - **调整表示 (`AdjustRepresentation`):**  当小型哈希表的容量不足时，将其转换为大型哈希表。这个过程会将小型哈希表中的元素复制到新的大型哈希表中。
   - **添加 (`Add`):**  尝试向小型哈希表添加元素，如果小型哈希表已满，则会触发 `AdjustRepresentation` 迁移到大型哈希表后再添加。
   - **设置条目 (`SetEntry`):**  直接设置哈希表中的键、值和属性详情。
   - **获取条目信息 (`ValueAt`, `DetailsAt`, `KeyAt`, `Hash` 等):**  提供访问哈希表中特定条目信息的接口。

3. **有序哈希表迭代器 (`OrderedHashTableIterator` 模板类):**
   - **迭代 (`HasMore`, `MoveNext`, `CurrentKey`):**  提供了一种迭代哈希表中元素的机制，并能处理哈希表在迭代过程中可能发生的迁移（从一个表变为另一个表）。

**关于代码特性的说明:**

* **模板 (`template`):**  使用了 C++ 模板，使得 `SmallOrderedHashTable` 可以用于不同类型的键值对，例如 `SmallOrderedHashSet`（只存储键）、`SmallOrderedHashMap`（存储键值对）和 `SmallOrderedNameDictionary`（用于存储属性名和属性值）。
* **`Isolate*`:**  V8 中的隔离区概念，每个隔离区都有自己的堆和执行上下文。哈希表的操作通常需要访问当前隔离区。
* **`Handle` 和 `DirectHandle`:**  V8 的垃圾回收机制使用句柄来管理堆上的对象。`Handle` 是一个智能指针，可以防止对象在操作过程中被意外回收。`DirectHandle` 提供了对句柄所指向对象的直接访问。
* **`Tagged<T>`:**  表示 V8 中带有标签的对象，用于区分不同的对象类型。
* **`InternalIndex`:**  用于表示哈希表中条目的内部索引。
* **`ReadOnlyRoots`:**  访问只读的根对象，例如 `the_hole_value`。
* **`PropertyDetails`:**  用于存储对象属性的额外信息。
* **`DisallowGarbageCollection`:**  在某些关键操作期间禁用垃圾回收，以避免对象在操作过程中被移动。
* **"The Hole" (`the_hole_value`):**  V8 中用于标记哈希表中已删除条目的特殊值。

**与 JavaScript 的关系:**

`SmallOrderedHashTable` 是 V8 引擎内部用于实现 JavaScript 中 `Set` 和 `Map` 数据结构以及对象属性存储的关键数据结构。

* **`Set`:**  `SmallOrderedHashSet` 类似于 JavaScript 的 `Set`，用于存储唯一的值，并保持插入顺序。
* **`Map`:**  `SmallOrderedHashMap` 类似于 JavaScript 的 `Map`，用于存储键值对，并保持键的插入顺序。
* **对象属性:** `SmallOrderedNameDictionary` 用于存储对象的属性名和属性值，特别是对于那些属性数量较少的对象，V8 会使用这种紧凑的哈希表来提高性能。

**JavaScript 示例:**

```javascript
// JavaScript Set (底层可能使用 SmallOrderedHashSet)
const mySet = new Set();
mySet.add('a');
mySet.add('b');
mySet.add('a'); // 重复添加无效

console.log(mySet.has('a')); // true
console.log(mySet.size);    // 2
console.log([...mySet]);    // ['a', 'b'] (保持插入顺序)

// JavaScript Map (底层可能使用 SmallOrderedHashMap)
const myMap = new Map();
myMap.set('name', 'Alice');
myMap.set('age', 30);

console.log(myMap.get('name')); // 'Alice'
console.log(myMap.has('age'));  // true
console.log([...myMap]);       // [['name', 'Alice'], ['age', 30]] (保持插入顺序)

// JavaScript 对象 (属性存储可能使用 SmallOrderedNameDictionary)
const myObject = {
  x: 10,
  y: 20
};

console.log(myObject.x); // 10
myObject.z = 30;
console.log(Object.keys(myObject)); // ['x', 'y', 'z'] (顺序可能与插入顺序一致)
```

**代码逻辑推理与假设输入输出:**

**假设场景：使用 `SmallOrderedHashMap` 添加和查找元素**

```c++
// 假设我们有一个 Isolate 实例和一个空的 SmallOrderedHashMap
Isolate* isolate = ...;
Handle<SmallOrderedHashMap> table = SmallOrderedHashMap::Allocate(isolate, 4); // 容量为 4

// 假设我们要添加键值对 "key1" -> "value1"
Handle<String> key1 = isolate->factory()->NewStringFromAsciiChecked("key1");
Handle<String> value1 = isolate->factory()->NewStringFromAsciiChecked("value1");

// 调用 SmallOrderedHashMap::Add
MaybeHandle<SmallOrderedHashMap> new_table = SmallOrderedHashMap::Add(isolate, table, Handle<Object>::cast(key1), Handle<Object>::cast(value1));

// 假设添加成功，new_table 应该指向更新后的哈希表

// 现在查找 "key1"
bool has_key = table->HasKey(isolate, Handle<Object>::cast(key1));
// 输出: has_key 应该为 true

// 查找 "key2" (不存在)
Handle<String> key2 = isolate->factory()->NewStringFromAsciiChecked("key2");
bool has_key2 = table->HasKey(isolate, Handle<Object>::cast(key2));
// 输出: has_key2 应该为 false
```

**假设场景：使用 `SmallOrderedHashMap` 删除元素**

```c++
// 假设哈希表 table 中包含 "key1" -> "value1"
// 调用 SmallOrderedHashMap::Delete
bool deleted = SmallOrderedHashMap::Delete(isolate, *table, Handle<Object>::cast(key1));
// 输出: deleted 应该为 true

// 再次查找 "key1"
bool has_key_after_delete = table->HasKey(isolate, Handle<Object>::cast(key1));
// 输出: has_key_after_delete 应该为 false
```

**用户常见的编程错误 (虽然用户通常不直接操作这些底层结构):**

1. **假设哈希表的特定内存布局:** 用户不应该依赖于哈希表在内存中的具体排列方式。V8 的内部实现可能会改变。
2. **不理解哈希冲突的影响:**  虽然 V8 的哈希表实现处理了冲突，但过度依赖于哈希表的性能而没有考虑潜在的冲突可能会导致性能问题。
3. **在迭代过程中修改哈希表:**  像许多哈希表实现一样，在迭代一个 V8 的有序哈希表时添加或删除元素可能会导致未定义的行为。V8 的迭代器尝试处理某些情况（例如通过 `Transition()`），但这仍然是潜在的错误来源。
4. **误解 "The Hole" 的概念:**  用户可能会错误地认为删除元素会立即释放内存。实际上，V8 使用 "The Hole" 来标记已删除的条目，直到下一次调整大小或垃圾回收时才可能真正清理。

**总结一下它的功能 (第2部分):**

这段代码是 V8 引擎中小型有序哈希表的核心实现，提供了添加、删除、查找、调整大小等基本操作。它还定义了一个处理器，用于在小型和大型哈希表之间进行转换，以优化内存使用和性能。这些数据结构是 JavaScript 中 `Set`、`Map` 以及对象属性存储的基础。此外，代码还包括了用于迭代这些哈希表的迭代器实现。

Prompt: 
```
这是目录为v8/src/objects/ordered-hash-table.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/ordered-hash-table.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""
t raw_entry = entry.as_int();
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