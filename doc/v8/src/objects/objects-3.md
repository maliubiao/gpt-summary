Response: The user wants a summary of the C++ source code file `v8/src/objects/objects.cc`. This is the 4th and final part of the file. The goal is to understand the functionality implemented in this specific part, and if possible, relate it to JavaScript concepts.

Based on the code snippets provided, this part seems to focus on:

1. **Promise Job Enqueueing:**  Handling the creation and enqueuing of `PromiseReactionJobTask` and its specializations (`PromiseFulfillReactionJobTask`, `PromiseRejectReactionJobTask`). This is clearly related to the asynchronous nature of JavaScript Promises.

2. **Hash Table Implementations (Templates):**  A significant portion is dedicated to the implementation of generic hash table structures (`HashTable`, `Dictionary`, `ObjectHashTableBase`, `ObjectMultiHashTableBase`). This includes:
    - Creation and resizing (`New`, `EnsureCapacity`, `Shrink`).
    - Element insertion and rehashing (`Rehash`, `FindInsertionEntry`, `AddEntry`, `Put`).
    - Element lookup (`FindEntry`, `Lookup`).
    - Element removal (`DeleteEntry`, `RemoveEntry`, `Remove`).
    - Iteration (`IteratePrefix`, `IterateElements`, `IterateEntries`).
    - Capacity management and calculations.

3. **Specific Hash Table Types:**  Specialized hash table implementations like `StringSet`, `RegisteredSymbolTable`, `NameDictionary`, `GlobalDictionary`, `SimpleNumberDictionary`, `NumberDictionary`, `ObjectHashSet`. These are likely used internally by V8 to store different kinds of data.

4. **JS Set and Map Implementation:**  Functionality related to the implementation of JavaScript `Set` and `Map` (`JSSet`, `JSMap`, `OrderedHashSet`, `OrderedHashMap`). This includes initialization, clearing, and rehashing.

5. **JSWeakCollection Implementation:**  Functionality related to the implementation of JavaScript `WeakMap` and `WeakSet` (`JSWeakCollection`, `EphemeronHashTable`). Key aspects here are the weak referencing and handling of garbage collection.

6. **JSFinalizationRegistry Implementation:**  Functions related to managing the unregister token map in `JSFinalizationRegistry`, a feature for running finalizers on objects when they are garbage collected.

7. **Property Cell Management:** Functions for handling `PropertyCell` objects, which store information about object properties. This includes invalidation, type transitions, and setting values.

8. **JSGeneratorObject:**  Functions for retrieving the bytecode offset and source position of a suspended JavaScript generator.

9. **Access Checks:**  A function to retrieve `AccessCheckInfo` for objects that require access checks.

10. **Smi Comparison:** A specific function for lexicographically comparing Small Integers (Smis).

In summary, this part of the `objects.cc` file contains core data structure implementations (primarily various forms of hash tables) and logic for managing key JavaScript language features like Promises, Sets, Maps, Weak Collections, Finalization Registries, and object properties.

To illustrate the connection with JavaScript, I will focus on the Promise and HashTable aspects.
这是 `v8/src/objects/objects.cc` 文件的第四部分，主要集中在 **V8 引擎内部对象和数据结构的实现细节**。它延续了前几部分的内容，继续定义和实现了 V8 引擎用于管理 JavaScript 对象和执行的各种内部数据结构和功能。

**主要功能归纳:**

1. **Promise 任务队列管理:**  这部分代码负责将 Promise 的 `then` 和 `catch` 方法注册的回调函数封装成任务 (`PromiseReactionJobTask`) 并加入到微任务队列中。这是 JavaScript Promise 异步执行机制的核心部分。

2. **通用哈希表 (`HashTable`) 的实现:**  定义了 `HashTable` 模板类，作为 V8 中各种哈希表的基础。包含了哈希表的创建、扩容、缩容、元素查找、插入、删除以及 Rehash (重新哈希) 等核心操作。这些哈希表用于高效地存储和检索各种内部数据。

3. **特定类型的哈希表实现:**  基于 `HashTable` 模板，实现了各种特定用途的哈希表，例如：
    - `StringSet`: 用于存储字符串集合。
    - `RegisteredSymbolTable`: 用于存储已注册的 Symbol。
    - `NameDictionary` 和 `GlobalDictionary`: 用于存储对象的属性名和属性值。
    - `SimpleNumberDictionary` 和 `NumberDictionary`:  用于存储数字索引的属性。
    - `ObjectHashSet`: 用于存储对象集合。
    - `ObjectHashTable`: 用于存储键值对，其中键是任意 JavaScript 对象。
    - `EphemeronHashTable`:  用于 `WeakMap` 和 `WeakSet` 的哈希表，键是弱引用。

4. **JS Set 和 JS Map 的实现:**  实现了 JavaScript 内置对象 `Set` 和 `Map` 的底层数据结构 (`OrderedHashSet`, `OrderedHashMap`) 和相关操作，例如 `Initialize`, `Clear`, `Rehash`。

5. **JSWeakCollection 的实现:**  实现了 JavaScript 内置对象 `WeakMap` 和 `WeakSet` 的底层数据结构 (`EphemeronHashTable`) 和相关操作，例如 `Initialize`, `Set`, `Delete`, `GetEntries`。

6. **JSFinalizationRegistry 的实现:** 实现了 JavaScript 的 `FinalizationRegistry` 功能，用于在对象被垃圾回收后执行清理操作。代码中涉及到了如何管理注册的终结器和相关的弱引用。

7. **PropertyCell 的管理:** 实现了 `PropertyCell`，用于存储对象的属性信息。包含了属性值的存储、类型转换、以及失效等操作。这是 V8 引擎管理对象属性的关键组件。

8. **JSGeneratorObject 的相关操作:**  实现了获取 `JSGeneratorObject` 当前代码偏移量和源代码位置的功能，这对于调试和理解生成器函数的执行过程非常重要。

9. **访问检查 (`AccessCheckInfo`) 的获取:**  提供了获取对象访问检查信息的函数，用于控制对特定对象的访问权限。

10. **Smi 的字典序比较:**  实现了一个特殊的字符串字典序比较函数，用于比较 Small Integer (Smi) 的字符串表示。

**与 JavaScript 功能的关系 (使用 JavaScript 举例):**

**1. Promise 任务队列管理:**

```javascript
const promise = new Promise((resolve, reject) => {
  setTimeout(() => {
    resolve("成功");
  }, 100);
});

promise.then((result) => {
  console.log(result); // "成功"
});

console.log("同步代码执行完毕");
```

在 V8 内部，当 `promise.then()` 被调用时，会创建一个 `PromiseFulfillReactionJobTask` (如果 Promise 最终是 resolved) 或 `PromiseRejectReactionJobTask` (如果 Promise 最终是 rejected)，并将与 `then` 方法关联的回调函数和相关的上下文信息存储在该任务中。然后，这个任务会被加入到微任务队列中。当同步代码执行完毕后，V8 会从微任务队列中取出这些任务并执行，从而实现 Promise 的异步回调。

**2. 哈希表 (`HashTable` 和其子类):**

```javascript
const obj = { a: 1, b: 2 };
obj.c = 3;

const map = new Map();
map.set("key1", "value1");
map.set("key2", "value2");

const set = new Set();
set.add("item1");
set.add("item2");
```

- 当你在 JavaScript 中创建一个普通对象 (`obj`) 并添加属性时，V8 内部很可能使用类似于 `NameDictionary` 的哈希表来存储属性名 (`"a"`, `"b"`, `"c"`) 和对应的属性值 (`1`, `2`, `3`)。
- 当你使用 `Map` 对象时，V8 内部会使用 `OrderedHashMap` 这样的哈希表来存储键值对。
- 当你使用 `Set` 对象时，V8 内部会使用 `OrderedHashSet` 这样的哈希表来存储唯一的元素。

**3. JSWeakCollection:**

```javascript
let key = {};
const weakMap = new WeakMap();
weakMap.set(key, "some value");

console.log(weakMap.get(key)); // "some value"

key = null; // 解除对 key 的强引用

// 稍后，当垃圾回收发生时，如果 key 没有其他强引用，
// weakMap 中与 key 相关的条目会被移除。
```

`WeakMap` 内部使用 `EphemeronHashTable`，其特性是键是弱引用。这意味着当键对象没有其他强引用指向它时，垃圾回收器可以回收该对象，并且 `WeakMap` 中对应的条目也会被移除。

**4. JSFinalizationRegistry:**

```javascript
const registry = new FinalizationRegistry(heldValue => {
  console.log("对象被回收了:", heldValue);
});

let objectToObserve = {};
registry.register(objectToObserve, "观察对象", objectToObserve);

objectToObserve = null; // 解除对 objectToObserve 的强引用

// 当垃圾回收器回收 objectToObserve 时，
// FinalizationRegistry 中注册的回调函数会被调用，并传入 "观察对象" 作为 heldValue。
```

`JSFinalizationRegistry` 的实现涉及管理一个内部的哈希表，用于存储注册的对象和对应的回调函数和 heldValue。当对象被回收时，V8 会遍历这些注册信息并执行相应的清理操作。

**总结:**

这部分 `objects.cc` 代码是 V8 引擎的核心组成部分，它实现了许多关键的内部数据结构和功能，这些结构和功能直接支撑着 JavaScript 语言的各种特性和运行机制。理解这些内部实现对于深入了解 JavaScript 引擎的工作原理至关重要。

### 提示词
```
这是目录为v8/src/objects/objects.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第4部分，共4部分，请归纳一下它的功能
```

### 源代码
```
Cast<JSReceiver>(secondary_handler))
                                .ToHandle(&handler_context);
    }
    if (!has_handler_context) handler_context = isolate->native_context();

    static_assert(
        static_cast<int>(PromiseReaction::kSize) ==
        static_cast<int>(
            PromiseReactionJobTask::kSizeOfAllPromiseReactionJobTasks));
    if (type == PromiseReaction::kFulfill) {
      task->set_map(
          isolate,
          ReadOnlyRoots(isolate).promise_fulfill_reaction_job_task_map(),
          kReleaseStore);
      Cast<PromiseFulfillReactionJobTask>(task)->set_argument(*argument);
      Cast<PromiseFulfillReactionJobTask>(task)->set_context(*handler_context);
      static_assert(
          static_cast<int>(PromiseReaction::kFulfillHandlerOffset) ==
          static_cast<int>(PromiseFulfillReactionJobTask::kHandlerOffset));
      static_assert(
          static_cast<int>(PromiseReaction::kPromiseOrCapabilityOffset) ==
          static_cast<int>(
              PromiseFulfillReactionJobTask::kPromiseOrCapabilityOffset));
#ifdef V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA
      static_assert(
          static_cast<int>(
              PromiseReaction::kContinuationPreservedEmbedderDataOffset) ==
          static_cast<int>(PromiseFulfillReactionJobTask::
                               kContinuationPreservedEmbedderDataOffset));
#endif  // V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA
    } else {
      DisallowGarbageCollection no_gc;
      task->set_map(
          isolate,
          ReadOnlyRoots(isolate).promise_reject_reaction_job_task_map(),
          kReleaseStore);
      Cast<PromiseRejectReactionJobTask>(task)->set_argument(*argument);
      Cast<PromiseRejectReactionJobTask>(task)->set_context(*handler_context);
      Cast<PromiseRejectReactionJobTask>(task)->set_handler(*primary_handler);
      static_assert(
          static_cast<int>(PromiseReaction::kPromiseOrCapabilityOffset) ==
          static_cast<int>(
              PromiseRejectReactionJobTask::kPromiseOrCapabilityOffset));
#ifdef V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA
      static_assert(
          static_cast<int>(
              PromiseReaction::kContinuationPreservedEmbedderDataOffset) ==
          static_cast<int>(PromiseRejectReactionJobTask::
                               kContinuationPreservedEmbedderDataOffset));
#endif  // V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA
    }

    MicrotaskQueue* microtask_queue = handler_context->microtask_queue();
    if (microtask_queue) {
      microtask_queue->EnqueueMicrotask(*Cast<PromiseReactionJobTask>(task));
    }
  }

  return isolate->factory()->undefined_value();
}

template <typename Derived, typename Shape>
void HashTable<Derived, Shape>::IteratePrefix(ObjectVisitor* v) {
  BodyDescriptorBase::IteratePointers(this, 0, kElementsStartOffset, v);
}

template <typename Derived, typename Shape>
void HashTable<Derived, Shape>::IterateElements(ObjectVisitor* v) {
  BodyDescriptorBase::IteratePointers(this, kElementsStartOffset,
                                      SizeFor(length()), v);
}

template <typename Derived, typename Shape>
template <typename IsolateT>
Handle<Derived> HashTable<Derived, Shape>::New(
    IsolateT* isolate, int at_least_space_for, AllocationType allocation,
    MinimumCapacity capacity_option) {
  DCHECK_LE(0, at_least_space_for);
  DCHECK_IMPLIES(capacity_option == USE_CUSTOM_MINIMUM_CAPACITY,
                 base::bits::IsPowerOfTwo(at_least_space_for));

  int capacity = (capacity_option == USE_CUSTOM_MINIMUM_CAPACITY)
                     ? at_least_space_for
                     : ComputeCapacity(at_least_space_for);
  if (capacity > HashTable::kMaxCapacity) {
    isolate->FatalProcessOutOfHeapMemory("invalid table size");
  }
  return NewInternal(isolate, capacity, allocation);
}

template <typename Derived, typename Shape>
template <typename IsolateT>
Handle<Derived> HashTable<Derived, Shape>::NewInternal(
    IsolateT* isolate, int capacity, AllocationType allocation) {
  auto* factory = isolate->factory();
  int length = EntryToIndex(InternalIndex(capacity));
  Handle<FixedArray> array = factory->NewFixedArrayWithMap(
      Derived::GetMap(ReadOnlyRoots(isolate)), length, allocation);
  Handle<Derived> table = Cast<Derived>(array);
  DisallowGarbageCollection no_gc;
  Tagged<Derived> raw_table = *table;
  raw_table->SetNumberOfElements(0);
  raw_table->SetNumberOfDeletedElements(0);
  raw_table->SetCapacity(capacity);
  return table;
}

template <typename Derived, typename Shape>
void HashTable<Derived, Shape>::Rehash(PtrComprCageBase cage_base,
                                       Tagged<Derived> new_table) {
  DisallowGarbageCollection no_gc;
  WriteBarrierMode mode = new_table->GetWriteBarrierMode(no_gc);

  DCHECK_LT(NumberOfElements(), new_table->Capacity());

  // Copy prefix to new array.
  for (int i = kPrefixStartIndex; i < kElementsStartIndex; i++) {
    new_table->set(i, get(i), mode);
  }

  // Rehash the elements.
  ReadOnlyRoots roots = GetReadOnlyRoots();
  for (InternalIndex i : this->IterateEntries()) {
    uint32_t from_index = EntryToIndex(i);
    Tagged<Object> k = this->get(from_index);
    if (!IsKey(roots, k)) continue;
    uint32_t hash = TodoShape::HashForObject(roots, k);
    uint32_t insertion_index =
        EntryToIndex(new_table->FindInsertionEntry(cage_base, roots, hash));
    new_table->set_key(insertion_index, get(from_index), mode);
    for (int j = 1; j < TodoShape::kEntrySize; j++) {
      new_table->set(insertion_index + j, get(from_index + j), mode);
    }
  }
  new_table->SetNumberOfElements(NumberOfElements());
  new_table->SetNumberOfDeletedElements(0);
}

template <typename Derived, typename Shape>
InternalIndex HashTable<Derived, Shape>::EntryForProbe(ReadOnlyRoots roots,
                                                       Tagged<Object> k,
                                                       int probe,
                                                       InternalIndex expected) {
  uint32_t hash = TodoShape::HashForObject(roots, k);
  uint32_t capacity = this->Capacity();
  InternalIndex entry = FirstProbe(hash, capacity);
  for (int i = 1; i < probe; i++) {
    if (entry == expected) return expected;
    entry = NextProbe(entry, i, capacity);
  }
  return entry;
}

template <typename Derived, typename Shape>
void HashTable<Derived, Shape>::Swap(InternalIndex entry1, InternalIndex entry2,
                                     WriteBarrierMode mode) {
  int index1 = EntryToIndex(entry1);
  int index2 = EntryToIndex(entry2);
  Tagged<Object> temp[TodoShape::kEntrySize];
  Derived* self = static_cast<Derived*>(this);
  for (int j = 0; j < TodoShape::kEntrySize; j++) {
    temp[j] = get(index1 + j);
  }
  self->set_key(index1, get(index2), mode);
  for (int j = 1; j < TodoShape::kEntrySize; j++) {
    set(index1 + j, get(index2 + j), mode);
  }
  self->set_key(index2, temp[0], mode);
  for (int j = 1; j < TodoShape::kEntrySize; j++) {
    set(index2 + j, temp[j], mode);
  }
}

template <typename Derived, typename Shape>
void HashTable<Derived, Shape>::Rehash(PtrComprCageBase cage_base) {
  DisallowGarbageCollection no_gc;
  WriteBarrierMode mode = GetWriteBarrierMode(no_gc);
  ReadOnlyRoots roots = EarlyGetReadOnlyRoots();
  uint32_t capacity = Capacity();
  bool done = false;
  for (int probe = 1; !done; probe++) {
    // All elements at entries given by one of the first _probe_ probes
    // are placed correctly. Other elements might need to be moved.
    done = true;
    for (InternalIndex current(0); current.raw_value() < capacity;
         /* {current} is advanced manually below, when appropriate.*/) {
      Tagged<Object> current_key = KeyAt(cage_base, current);
      if (!IsKey(roots, current_key)) {
        ++current;  // Advance to next entry.
        continue;
      }
      InternalIndex target = EntryForProbe(roots, current_key, probe, current);
      if (current == target) {
        ++current;  // Advance to next entry.
        continue;
      }
      Tagged<Object> target_key = KeyAt(cage_base, target);
      if (!IsKey(roots, target_key) ||
          EntryForProbe(roots, target_key, probe, target) != target) {
        // Put the current element into the correct position.
        Swap(current, target, mode);
        // The other element will be processed on the next iteration,
        // so don't advance {current} here!
      } else {
        // The place for the current element is occupied. Leave the element
        // for the next probe.
        done = false;
        ++current;  // Advance to next entry.
      }
    }
  }
  // Wipe deleted entries.
  Tagged<Object> the_hole = roots.the_hole_value();
  Tagged<HeapObject> undefined = roots.undefined_value();
  Derived* self = static_cast<Derived*>(this);
  for (InternalIndex current : InternalIndex::Range(capacity)) {
    if (KeyAt(cage_base, current) == the_hole) {
      self->set_key(EntryToIndex(current) + kEntryKeyIndex, undefined,
                    SKIP_WRITE_BARRIER);
    }
  }
  SetNumberOfDeletedElements(0);
}

template <typename Derived, typename Shape>
template <typename IsolateT>
Handle<Derived> HashTable<Derived, Shape>::EnsureCapacity(
    IsolateT* isolate, Handle<Derived> table, int n,
    AllocationType allocation) {
  if (table->HasSufficientCapacityToAdd(n)) return table;

  int capacity = table->Capacity();
  int new_nof = table->NumberOfElements() + n;

  bool should_pretenure = allocation == AllocationType::kOld ||
                          ((capacity > kMinCapacityForPretenure) &&
                           !HeapLayout::InYoungGeneration(*table));
  Handle<Derived> new_table = HashTable::New(
      isolate, new_nof,
      should_pretenure ? AllocationType::kOld : AllocationType::kYoung);

  table->Rehash(isolate, *new_table);
  return new_table;
}

template <typename Derived, typename Shape>
bool HashTable<Derived, Shape>::HasSufficientCapacityToAdd(
    int number_of_additional_elements) {
  return HasSufficientCapacityToAdd(Capacity(), NumberOfElements(),
                                    NumberOfDeletedElements(),
                                    number_of_additional_elements);
}

// static
template <typename Derived, typename Shape>
bool HashTable<Derived, Shape>::HasSufficientCapacityToAdd(
    int capacity, int number_of_elements, int number_of_deleted_elements,
    int number_of_additional_elements) {
  int nof = number_of_elements + number_of_additional_elements;
  // Return true if:
  //   50% is still free after adding number_of_additional_elements elements and
  //   at most 50% of the free elements are deleted elements.
  if ((nof < capacity) &&
      ((number_of_deleted_elements <= (capacity - nof) / 2))) {
    int needed_free = nof / 2;
    if (nof + needed_free <= capacity) return true;
  }
  return false;
}

// static
template <typename Derived, typename Shape>
int HashTable<Derived, Shape>::ComputeCapacityWithShrink(
    int current_capacity, int at_least_room_for) {
  // Shrink to fit the number of elements if only a quarter of the
  // capacity is filled with elements.
  if (at_least_room_for > (current_capacity / 4)) return current_capacity;
  // Recalculate the smaller capacity actually needed.
  int new_capacity = ComputeCapacity(at_least_room_for);
  DCHECK_GE(new_capacity, at_least_room_for);
  // Don't go lower than room for {kMinShrinkCapacity} elements.
  if (new_capacity < Derived::kMinShrinkCapacity) return current_capacity;
  return new_capacity;
}

// static
template <typename Derived, typename Shape>
Handle<Derived> HashTable<Derived, Shape>::Shrink(Isolate* isolate,
                                                  Handle<Derived> table,
                                                  int additional_capacity) {
  int new_capacity = ComputeCapacityWithShrink(
      table->Capacity(), table->NumberOfElements() + additional_capacity);
  if (new_capacity == table->Capacity()) return table;
  DCHECK_GE(new_capacity, Derived::kMinShrinkCapacity);

  bool pretenure = (new_capacity > kMinCapacityForPretenure) &&
                   !HeapLayout::InYoungGeneration(*table);
  Handle<Derived> new_table =
      HashTable::New(isolate, new_capacity,
                     pretenure ? AllocationType::kOld : AllocationType::kYoung,
                     USE_CUSTOM_MINIMUM_CAPACITY);

  table->Rehash(isolate, *new_table);
  return new_table;
}

template <typename Derived, typename Shape>
InternalIndex HashTable<Derived, Shape>::FindInsertionEntry(
    PtrComprCageBase cage_base, ReadOnlyRoots roots, uint32_t hash) {
  uint32_t capacity = Capacity();
  uint32_t count = 1;
  // EnsureCapacity will guarantee the hash table is never full.
  for (InternalIndex entry = FirstProbe(hash, capacity);;
       entry = NextProbe(entry, count++, capacity)) {
    if (!IsKey(roots, KeyAt(cage_base, entry))) return entry;
  }
}

std::optional<Tagged<PropertyCell>>
GlobalDictionary::TryFindPropertyCellForConcurrentLookupIterator(
    Isolate* isolate, DirectHandle<Name> name, RelaxedLoadTag tag) {
  // This reimplements HashTable::FindEntry for use in a concurrent setting.
  // 1) Atomic loads.
  // 2) IsPendingAllocation checks.
  // 3) Return the PropertyCell value instead of the InternalIndex to avoid a
  //   repeated load (unsafe with concurrent modifications).

  DisallowGarbageCollection no_gc;
  PtrComprCageBase cage_base{isolate};
  ReadOnlyRoots roots(isolate);
  const int32_t hash = TodoShape::Hash(roots, name);
  const uint32_t capacity = Capacity();
  uint32_t count = 1;
  Tagged<Object> undefined = roots.undefined_value();
  Tagged<Object> the_hole = roots.the_hole_value();
  // EnsureCapacity will guarantee the hash table is never full.
  for (InternalIndex entry = FirstProbe(hash, capacity);;
       entry = NextProbe(entry, count++, capacity)) {
    Tagged<Object> element = KeyAt(cage_base, entry, kRelaxedLoad);
    if (isolate->heap()->IsPendingAllocation(element)) return {};
    if (element == undefined) return {};
    if (TodoShape::kMatchNeedsHoleCheck && element == the_hole) continue;
    if (!TodoShape::IsMatch(name, element)) continue;
    CHECK(IsPropertyCell(element, cage_base));
    return Cast<PropertyCell>(element);
  }
}

Handle<StringSet> StringSet::New(Isolate* isolate) {
  return HashTable::New(isolate, 0);
}

Handle<StringSet> StringSet::Add(Isolate* isolate, Handle<StringSet> stringset,
                                 DirectHandle<String> name) {
  if (!stringset->Has(isolate, name)) {
    stringset = EnsureCapacity(isolate, stringset);
    uint32_t hash = TodoShape::Hash(ReadOnlyRoots(isolate), *name);
    InternalIndex entry = stringset->FindInsertionEntry(isolate, hash);
    stringset->set(EntryToIndex(entry), *name);
    stringset->ElementAdded();
  }
  return stringset;
}

bool StringSet::Has(Isolate* isolate, DirectHandle<String> name) {
  return FindEntry(isolate, *name).is_found();
}

Handle<RegisteredSymbolTable> RegisteredSymbolTable::Add(
    Isolate* isolate, Handle<RegisteredSymbolTable> table,
    IndirectHandle<String> key, DirectHandle<Symbol> symbol) {
  // Validate that the key is absent.
  SLOW_DCHECK(table->FindEntry(isolate, key).is_not_found());

  table = EnsureCapacity(isolate, table);
  uint32_t hash = TodoShape::Hash(ReadOnlyRoots(isolate), key);
  InternalIndex entry = table->FindInsertionEntry(isolate, hash);
  table->set(EntryToIndex(entry), *key);
  table->set(EntryToValueIndex(entry), *symbol);
  table->ElementAdded();
  return table;
}

template <typename Derived, typename Shape>
template <typename IsolateT>
Handle<Derived> BaseNameDictionary<Derived, Shape>::New(
    IsolateT* isolate, int at_least_space_for, AllocationType allocation,
    MinimumCapacity capacity_option) {
  DCHECK_LE(0, at_least_space_for);
  Handle<Derived> dict = Dictionary<Derived, Shape>::New(
      isolate, at_least_space_for, allocation, capacity_option);
  dict->SetHash(PropertyArray::kNoHashSentinel);
  dict->set_next_enumeration_index(PropertyDetails::kInitialIndex);
  return dict;
}

template <typename IsolateT>
Handle<NameDictionary> NameDictionary::New(IsolateT* isolate,
                                           int at_least_space_for,
                                           AllocationType allocation,
                                           MinimumCapacity capacity_option) {
  Handle<NameDictionary> dict =
      BaseNameDictionary<NameDictionary, NameDictionaryShape>::New(
          isolate, at_least_space_for, allocation, capacity_option);
  dict->set_flags(kFlagsDefault);
  return dict;
}

template <typename Derived, typename Shape>
int BaseNameDictionary<Derived, Shape>::NextEnumerationIndex(
    Isolate* isolate, Handle<Derived> dictionary) {
  int index = dictionary->next_enumeration_index();
  // Check whether the next enumeration index is valid.
  if (!PropertyDetails::IsValidIndex(index)) {
    // If not, we generate new indices for the properties.
    DirectHandle<FixedArray> iteration_order =
        IterationIndices(isolate, dictionary);
    int length = iteration_order->length();
    DCHECK_LE(length, dictionary->NumberOfElements());

    // Iterate over the dictionary using the enumeration order and update
    // the dictionary with new enumeration indices.
    for (int i = 0; i < length; i++) {
      InternalIndex internal_index(Smi::ToInt(iteration_order->get(i)));
      DCHECK(dictionary->IsKey(dictionary->GetReadOnlyRoots(),
                               dictionary->KeyAt(isolate, internal_index)));

      int enum_index = PropertyDetails::kInitialIndex + i;

      PropertyDetails details = dictionary->DetailsAt(internal_index);
      PropertyDetails new_details = details.set_index(enum_index);
      dictionary->DetailsAtPut(internal_index, new_details);
    }

    index = PropertyDetails::kInitialIndex + length;
  }

  // Don't update the next enumeration index here, since we might be looking at
  // an immutable empty dictionary.
  return index;
}

template <typename Derived, typename Shape>
Handle<Derived> Dictionary<Derived, Shape>::DeleteEntry(
    Isolate* isolate, Handle<Derived> dictionary, InternalIndex entry) {
  DCHECK(TodoShape::kEntrySize != 3 ||
         dictionary->DetailsAt(entry).IsConfigurable());
  dictionary->ClearEntry(entry);
  dictionary->ElementRemoved();
  return Shrink(isolate, dictionary);
}

template <typename Derived, typename Shape>
Handle<Derived> Dictionary<Derived, Shape>::AtPut(Isolate* isolate,
                                                  Handle<Derived> dictionary,
                                                  Key key, Handle<Object> value,
                                                  PropertyDetails details) {
  InternalIndex entry = dictionary->FindEntry(isolate, key);

  // If the entry is present set the value;
  if (entry.is_not_found()) {
    return Derived::Add(isolate, dictionary, key, value, details);
  }

  // We don't need to copy over the enumeration index.
  dictionary->ValueAtPut(entry, *value);
  if (TodoShape::kEntrySize == 3) dictionary->DetailsAtPut(entry, details);
  return dictionary;
}

template <typename Derived, typename Shape>
void Dictionary<Derived, Shape>::UncheckedAtPut(Isolate* isolate,
                                                Handle<Derived> dictionary,
                                                Key key, Handle<Object> value,
                                                PropertyDetails details) {
  InternalIndex entry = dictionary->FindEntry(isolate, key);

  // If the entry is present set the value;
  if (entry.is_not_found()) {
    Derived::UncheckedAdd(isolate, dictionary, key, value, details);
  } else {
    // We don't need to copy over the enumeration index.
    dictionary->ValueAtPut(entry, *value);
    if (TodoShape::kEntrySize == 3) dictionary->DetailsAtPut(entry, details);
  }
}

template <typename Derived, typename Shape>
template <typename IsolateT>
Handle<Derived>
BaseNameDictionary<Derived, Shape>::AddNoUpdateNextEnumerationIndex(
    IsolateT* isolate, Handle<Derived> dictionary, Key key,
    Handle<Object> value, PropertyDetails details, InternalIndex* entry_out) {
  // Insert element at empty or deleted entry.
  return Dictionary<Derived, Shape>::Add(isolate, dictionary, key, value,
                                         details, entry_out);
}

template <typename Derived, typename Shape>
Handle<Derived> BaseNameDictionary<Derived, Shape>::Add(
    Isolate* isolate, Handle<Derived> dictionary, Key key, Handle<Object> value,
    PropertyDetails details, InternalIndex* entry_out) {
  // Insert element at empty or deleted entry
  DCHECK_EQ(0, details.dictionary_index());
  // Assign an enumeration index to the property and update
  // SetNextEnumerationIndex.
  int index = Derived::NextEnumerationIndex(isolate, dictionary);
  details = details.set_index(index);
  dictionary = AddNoUpdateNextEnumerationIndex(isolate, dictionary, key, value,
                                               details, entry_out);
  // Update enumeration index here in order to avoid potential modification of
  // the canonical empty dictionary which lives in read only space.
  dictionary->set_next_enumeration_index(index + 1);
  return dictionary;
}

template <typename Derived, typename Shape>
template <typename IsolateT, AllocationType key_allocation>
Handle<Derived> Dictionary<Derived, Shape>::Add(IsolateT* isolate,
                                                Handle<Derived> dictionary,
                                                Key key,
                                                DirectHandle<Object> value,
                                                PropertyDetails details,
                                                InternalIndex* entry_out) {
  ReadOnlyRoots roots(isolate);
  uint32_t hash = TodoShape::Hash(roots, key);
  // Validate that the key is absent.
  SLOW_DCHECK(dictionary->FindEntry(isolate, key).is_not_found());
  // Check whether the dictionary should be extended.
  dictionary = Derived::EnsureCapacity(isolate, dictionary);

  // Compute the key object.
  DirectHandle<Object> k =
      TodoShape::template AsHandle<key_allocation>(isolate, key);

  InternalIndex entry = dictionary->FindInsertionEntry(isolate, roots, hash);
  dictionary->SetEntry(entry, *k, *value, details);
  DCHECK(IsNumber(dictionary->KeyAt(isolate, entry)) ||
         IsUniqueName(TodoShape::Unwrap(dictionary->KeyAt(isolate, entry))));
  dictionary->ElementAdded();
  if (entry_out) *entry_out = entry;
  return dictionary;
}

template <typename Derived, typename Shape>
template <typename IsolateT, AllocationType key_allocation>
void Dictionary<Derived, Shape>::UncheckedAdd(IsolateT* isolate,
                                              Handle<Derived> dictionary,
                                              Key key,
                                              DirectHandle<Object> value,
                                              PropertyDetails details) {
  ReadOnlyRoots roots(isolate);
  uint32_t hash = TodoShape::Hash(roots, key);
  // Validate that the key is absent and we capacity is sufficient.
  SLOW_DCHECK(dictionary->FindEntry(isolate, key).is_not_found());
  DCHECK(dictionary->HasSufficientCapacityToAdd(1));

  // Compute the key object.
  DirectHandle<Object> k =
      TodoShape::template AsHandle<key_allocation>(isolate, key);

  InternalIndex entry = dictionary->FindInsertionEntry(isolate, roots, hash);
  dictionary->SetEntry(entry, *k, *value, details);
  DCHECK(IsNumber(dictionary->KeyAt(isolate, entry)) ||
         IsUniqueName(TodoShape::Unwrap(dictionary->KeyAt(isolate, entry))));
}

template <typename Derived, typename Shape>
Handle<Derived> Dictionary<Derived, Shape>::ShallowCopy(
    Isolate* isolate, Handle<Derived> dictionary, AllocationType allocation) {
  return Cast<Derived>(isolate->factory()->CopyFixedArrayWithMap(
      dictionary, Derived::GetMap(ReadOnlyRoots(isolate)), allocation));
}

// static
Handle<SimpleNumberDictionary> SimpleNumberDictionary::Set(
    Isolate* isolate, Handle<SimpleNumberDictionary> dictionary, uint32_t key,
    Handle<Object> value) {
  return AtPut(isolate, dictionary, key, value, PropertyDetails::Empty());
}

void NumberDictionary::UpdateMaxNumberKey(uint32_t key,
                                          Handle<JSObject> dictionary_holder) {
  DisallowGarbageCollection no_gc;
  // If the dictionary requires slow elements an element has already
  // been added at a high index.
  if (requires_slow_elements()) return;
  // Check if this index is high enough that we should require slow
  // elements.
  if (key > kRequiresSlowElementsLimit) {
    if (!dictionary_holder.is_null()) {
      dictionary_holder->RequireSlowElements(this);
    }
    set_requires_slow_elements();
    return;
  }
  // Update max key value.
  Tagged<Object> max_index_object = get(kMaxNumberKeyIndex);
  if (!IsSmi(max_index_object) || max_number_key() < key) {
    FixedArray::set(kMaxNumberKeyIndex,
                    Smi::FromInt(key << kRequiresSlowElementsTagSize));
  }
}

Handle<NumberDictionary> NumberDictionary::Set(
    Isolate* isolate, Handle<NumberDictionary> dictionary, uint32_t key,
    Handle<Object> value, Handle<JSObject> dictionary_holder,
    PropertyDetails details) {
  // We could call Set with empty dictionaries. UpdateMaxNumberKey doesn't
  // expect empty dictionaries so make sure to call AtPut that correctly handles
  // them by creating new dictionary when required.
  Handle<NumberDictionary> new_dictionary =
      AtPut(isolate, dictionary, key, value, details);
  new_dictionary->UpdateMaxNumberKey(key, dictionary_holder);
  return new_dictionary;
}

// static
void NumberDictionary::UncheckedSet(Isolate* isolate,
                                    Handle<NumberDictionary> dictionary,
                                    uint32_t key, Handle<Object> value) {
  UncheckedAtPut(isolate, dictionary, key, value, PropertyDetails::Empty());
}

void NumberDictionary::CopyValuesTo(Tagged<FixedArray> elements) {
  ReadOnlyRoots roots = GetReadOnlyRoots();
  int pos = 0;
  DisallowGarbageCollection no_gc;
  WriteBarrierMode mode = elements->GetWriteBarrierMode(no_gc);
  for (InternalIndex i : this->IterateEntries()) {
    Tagged<Object> k;
    if (this->ToKey(roots, i, &k)) {
      elements->set(pos++, this->ValueAt(i), mode);
    }
  }
  DCHECK_EQ(pos, elements->length());
}

template <typename Derived, typename Shape>
int Dictionary<Derived, Shape>::NumberOfEnumerableProperties() {
  ReadOnlyRoots roots = this->GetReadOnlyRoots();
  int result = 0;
  for (InternalIndex i : this->IterateEntries()) {
    Tagged<Object> k;
    if (!this->ToKey(roots, i, &k)) continue;
    if (Object::FilterKey(k, ENUMERABLE_STRINGS)) continue;
    PropertyDetails details = this->DetailsAt(i);
    PropertyAttributes attr = details.attributes();
    if ((int{attr} & ONLY_ENUMERABLE) == 0) result++;
  }
  return result;
}

template <typename Derived, typename Shape>
Handle<FixedArray> BaseNameDictionary<Derived, Shape>::IterationIndices(
    Isolate* isolate, Handle<Derived> dictionary) {
  Handle<FixedArray> array =
      isolate->factory()->NewFixedArray(dictionary->NumberOfElements());
  ReadOnlyRoots roots(isolate);
  int array_size = 0;
  {
    DisallowGarbageCollection no_gc;
    Tagged<Derived> raw_dictionary = *dictionary;
    for (InternalIndex i : dictionary->IterateEntries()) {
      Tagged<Object> k;
      if (!raw_dictionary->ToKey(roots, i, &k)) continue;
      array->set(array_size++, Smi::FromInt(i.as_int()));
    }

    // The global dictionary doesn't track its deletion count, so we may iterate
    // fewer entries than the count of elements claimed by the dictionary.
    if (std::is_same<Derived, GlobalDictionary>::value) {
      DCHECK_LE(array_size, dictionary->NumberOfElements());
    } else {
      DCHECK_EQ(array_size, dictionary->NumberOfElements());
    }

    EnumIndexComparator<Derived> cmp(raw_dictionary);
    // Use AtomicSlot wrapper to ensure that std::sort uses atomic load and
    // store operations that are safe for concurrent marking.
    AtomicSlot start(array->RawFieldOfFirstElement());
    std::sort(start, start + array_size, cmp);
  }
  return FixedArray::RightTrimOrEmpty(isolate, array, array_size);
}

// Backwards lookup (slow).
template <typename Derived, typename Shape>
Tagged<Object> Dictionary<Derived, Shape>::SlowReverseLookup(
    Tagged<Object> value) {
  Tagged<Derived> dictionary = Cast<Derived>(this);
  ReadOnlyRoots roots = dictionary->GetReadOnlyRoots();
  for (InternalIndex i : dictionary->IterateEntries()) {
    Tagged<Object> k;
    if (!dictionary->ToKey(roots, i, &k)) continue;
    Tagged<Object> e = dictionary->ValueAt(i);
    if (e == value) return k;
  }
  return roots.undefined_value();
}

template <typename Derived, typename Shape>
void ObjectHashTableBase<Derived, Shape>::FillEntriesWithHoles(
    Handle<Derived> table) {
  auto roots = table->GetReadOnlyRoots();
  int length = table->length();
  for (int i = Derived::EntryToIndex(InternalIndex(0)); i < length; i++) {
    table->set_the_hole(roots, i);
  }
}

template <typename Derived, typename Shape>
Tagged<Object> ObjectHashTableBase<Derived, Shape>::Lookup(
    PtrComprCageBase cage_base, Handle<Object> key, int32_t hash) {
  DisallowGarbageCollection no_gc;
  ReadOnlyRoots roots = this->GetReadOnlyRoots();
  DCHECK(this->IsKey(roots, *key));

  InternalIndex entry = this->FindEntry(cage_base, roots, key, hash);
  if (entry.is_not_found()) return roots.the_hole_value();
  return this->get(Derived::EntryToIndex(entry) + 1);
}

// The implementation should be in sync with
// CodeStubAssembler::NameToIndexHashTableLookup.
int NameToIndexHashTable::Lookup(Handle<Name> key) {
  DisallowGarbageCollection no_gc;
  PtrComprCageBase cage_base = GetPtrComprCageBase(this);
  ReadOnlyRoots roots = this->GetReadOnlyRoots();

  InternalIndex entry = this->FindEntry(cage_base, roots, key, key->hash());
  if (entry.is_not_found()) return -1;
  return Cast<Smi>(this->get(EntryToValueIndex(entry))).value();
}

template <typename Derived, typename Shape>
Tagged<Object> ObjectHashTableBase<Derived, Shape>::Lookup(Handle<Object> key) {
  DisallowGarbageCollection no_gc;

  PtrComprCageBase cage_base = GetPtrComprCageBase(this);
  ReadOnlyRoots roots = this->GetReadOnlyRoots();
  DCHECK(this->IsKey(roots, *key));

  // If the object does not have an identity hash, it was never used as a key.
  Tagged<Object> hash = Object::GetHash(*key);
  if (IsUndefined(hash, roots)) {
    return roots.the_hole_value();
  }
  return Lookup(cage_base, key, Smi::ToInt(hash));
}

template <typename Derived, typename Shape>
Tagged<Object> ObjectHashTableBase<Derived, Shape>::Lookup(Handle<Object> key,
                                                           int32_t hash) {
  return Lookup(GetPtrComprCageBase(this), key, hash);
}

template <typename Derived, typename Shape>
Tagged<Object> ObjectHashTableBase<Derived, Shape>::ValueAt(
    InternalIndex entry) {
  return this->get(EntryToValueIndex(entry));
}

Tagged<Object> RegisteredSymbolTable::ValueAt(InternalIndex entry) {
  return this->get(EntryToValueIndex(entry));
}

Tagged<Object> NameToIndexHashTable::ValueAt(InternalIndex entry) {
  return this->get(EntryToValueIndex(entry));
}

int NameToIndexHashTable::IndexAt(InternalIndex entry) {
  Tagged<Object> value = ValueAt(entry);
  if (IsSmi(value)) {
    int index = Smi::ToInt(value);
    DCHECK_LE(0, index);
    return index;
  }
  return -1;
}

template <typename Derived, typename Shape>
Handle<Derived> ObjectHashTableBase<Derived, Shape>::Put(Handle<Derived> table,
                                                         Handle<Object> key,
                                                         Handle<Object> value) {
  Isolate* isolate = Heap::FromWritableHeapObject(*table)->isolate();
  DCHECK(table->IsKey(ReadOnlyRoots(isolate), *key));
  DCHECK(!IsTheHole(*value, ReadOnlyRoots(isolate)));

  // Make sure the key object has an identity hash code.
  int32_t hash = Object::GetOrCreateHash(*key, isolate).value();

  return ObjectHashTableBase<Derived, Shape>::Put(isolate, table, key, value,
                                                  hash);
}

namespace {

template <typename T>
void RehashObjectHashTableAndGCIfNeeded(Isolate* isolate, Handle<T> table) {
  // Rehash if more than 33% of the entries are deleted entries.
  // TODO(verwaest): Consider to shrink the fixed array in place.
  if ((table->NumberOfDeletedElements() << 1) > table->NumberOfElements()) {
    table->Rehash(isolate);
  }
  // If we're out of luck, we didn't get a GC recently, and so rehashing
  // isn't enough to avoid a crash.
  if (!table->HasSufficientCapacityToAdd(1)) {
    int nof = table->NumberOfElements() + 1;
    int capacity = T::ComputeCapacity(nof);
    if (capacity > T::kMaxCapacity) {
      for (size_t i = 0; i < 2; ++i) {
        isolate->heap()->CollectAllGarbage(
            GCFlag::kNoFlags, GarbageCollectionReason::kFullHashtable);
      }
      table->Rehash(isolate);
    }
  }
}

}  // namespace

template <typename Derived, typename Shape>
Handle<Derived> ObjectHashTableBase<Derived, Shape>::Put(
    Isolate* isolate, Handle<Derived> table, Handle<Object> key,
    DirectHandle<Object> value, int32_t hash) {
  ReadOnlyRoots roots(isolate);
  DCHECK(table->IsKey(roots, *key));
  DCHECK(!IsTheHole(*value, roots));

  InternalIndex entry = table->FindEntry(isolate, roots, key, hash);

  // Key is already in table, just overwrite value.
  if (entry.is_found()) {
    table->set(Derived::EntryToValueIndex(entry), *value);
    return table;
  }

  RehashObjectHashTableAndGCIfNeeded(isolate, table);

  // Check whether the hash table should be extended.
  table = Derived::EnsureCapacity(isolate, table);
  table->AddEntry(table->FindInsertionEntry(isolate, hash), *key, *value);
  return table;
}

template <typename Derived, typename Shape>
Handle<Derived> ObjectHashTableBase<Derived, Shape>::Remove(
    Isolate* isolate, Handle<Derived> table, Handle<Object> key,
    bool* was_present) {
  DCHECK(table->IsKey(table->GetReadOnlyRoots(), *key));

  Tagged<Object> hash = Object::GetHash(*key);
  if (IsUndefined(hash)) {
    *was_present = false;
    return table;
  }

  return Remove(isolate, table, key, was_present, Smi::ToInt(hash));
}

template <typename Derived, typename Shape>
Handle<Derived> ObjectHashTableBase<Derived, Shape>::Remove(
    Isolate* isolate, Handle<Derived> table, Handle<Object> key,
    bool* was_present, int32_t hash) {
  ReadOnlyRoots roots = table->GetReadOnlyRoots();
  DCHECK(table->IsKey(roots, *key));

  InternalIndex entry = table->FindEntry(isolate, roots, key, hash);
  if (entry.is_not_found()) {
    *was_present = false;
    return table;
  }

  *was_present = true;
  table->RemoveEntry(entry);
  return Derived::Shrink(isolate, table);
}

template <typename Derived, typename Shape>
void ObjectHashTableBase<Derived, Shape>::AddEntry(InternalIndex entry,
                                                   Tagged<Object> key,
                                                   Tagged<Object> value) {
  Derived* self = static_cast<Derived*>(this);
  self->set_key(Derived::EntryToIndex(entry), key);
  self->set(Derived::EntryToValueIndex(entry), value);
  self->ElementAdded();
}

template <typename Derived, typename Shape>
void ObjectHashTableBase<Derived, Shape>::RemoveEntry(InternalIndex entry) {
  auto roots = this->GetReadOnlyRoots();
  this->set_the_hole(roots, Derived::EntryToIndex(entry));
  this->set_the_hole(roots, Derived::EntryToValueIndex(entry));
  this->ElementRemoved();
}

template <typename Derived, int N>
std::array<Tagged<Object>, N> ObjectMultiHashTableBase<Derived, N>::Lookup(
    Handle<Object> key) {
  return Lookup(GetPtrComprCageBase(this), key);
}

template <typename Derived, int N>
std::array<Tagged<Object>, N> ObjectMultiHashTableBase<Derived, N>::Lookup(
    PtrComprCageBase cage_base, Handle<Object> key) {
  DisallowGarbageCollection no_gc;

  ReadOnlyRoots roots = this->GetReadOnlyRoots();
  DCHECK(this->IsKey(roots, *key));

  Tagged<Object> hash_obj = Object::GetHash(*key);
  if (IsUndefined(hash_obj, roots)) {
    return {roots.the_hole_value(), roots.the_hole_value()};
  }
  int32_t hash = Smi::ToInt(hash_obj);

  InternalIndex entry = this->FindEntry(cage_base, roots, key, hash);
  if (entry.is_not_found()) {
    return {roots.the_hole_value(), roots.the_hole_value()};
  }

  int start_index = this->EntryToIndex(entry) +
                    ObjectMultiHashTableShape<N>::kEntryValueIndex;
  std::array<Tagged<Object>, N> values;
  for (int i = 0; i < N; i++) {
    values[i] = this->get(start_index + i);
    DCHECK(!IsTheHole(values[i]));
  }
  return values;
}

// static
template <typename Derived, int N>
Handle<Derived> ObjectMultiHashTableBase<Derived, N>::Put(
    Isolate* isolate, Handle<Derived> table, Handle<Object> key,
    const std::array<Handle<Object>, N>& values) {
  ReadOnlyRoots roots(isolate);
  DCHECK(table->IsKey(roots, *key));

  int32_t hash = Object::GetOrCreateHash(*key, isolate).value();
  InternalIndex entry = table->FindEntry(isolate, roots, key, hash);

  // Overwrite values if entry is found.
  if (entry.is_found()) {
    table->SetEntryValues(entry, values);
    return table;
  }

  RehashObjectHashTableAndGCIfNeeded(isolate, table);

  // Check whether the hash table should be extended.
  table = Derived::EnsureCapacity(isolate, table);
  entry = table->FindInsertionEntry(isolate, hash);
  table->set(Derived::EntryToIndex(entry), *key);
  table->SetEntryValues(entry, values);
  return table;
}

template <typename Derived, int N>
void ObjectMultiHashTableBase<Derived, N>::SetEntryValues(
    InternalIndex entry, const std::array<Handle<Object>, N>& values) {
  int start_index = EntryToValueIndexStart(entry);
  for (int i = 0; i < N; i++) {
    this->set(start_index + i, *values[i]);
  }
}

Handle<ObjectHashSet> ObjectHashSet::Add(Isolate* isolate,
                                         Handle<ObjectHashSet> set,
                                         Handle<Object> key) {
  int32_t hash = Object::GetOrCreateHash(*key, isolate).value();
  if (!set->Has(isolate, key, hash)) {
    set = EnsureCapacity(isolate, set);
    InternalIndex entry = set->FindInsertionEntry(isolate, hash);
    set->set(EntryToIndex(entry), *key);
    set->ElementAdded();
  }
  return set;
}

void JSSet::Initialize(DirectHandle<JSSet> set, Isolate* isolate) {
  DirectHandle<OrderedHashSet> table = isolate->factory()->NewOrderedHashSet();
  set->set_table(*table);
}

void JSSet::Clear(Isolate* isolate, DirectHandle<JSSet> set) {
  Handle<OrderedHashSet> table(Cast<OrderedHashSet>(set->table()), isolate);
  table = OrderedHashSet::Clear(isolate, table);
  set->set_table(*table);
}

void JSSet::Rehash(Isolate* isolate) {
  Handle<OrderedHashSet> table_handle(Cast<OrderedHashSet>(table()), isolate);
  DirectHandle<OrderedHashSet> new_table =
      OrderedHashSet::Rehash(isolate, table_handle).ToHandleChecked();
  set_table(*new_table);
}

void JSMap::Initialize(DirectHandle<JSMap> map, Isolate* isolate) {
  DirectHandle<OrderedHashMap> table = isolate->factory()->NewOrderedHashMap();
  map->set_table(*table);
}

void JSMap::Clear(Isolate* isolate, DirectHandle<JSMap> map) {
  Handle<OrderedHashMap> table(Cast<OrderedHashMap>(map->table()), isolate);
  table = OrderedHashMap::Clear(isolate, table);
  map->set_table(*table);
}

void JSMap::Rehash(Isolate* isolate) {
  Handle<OrderedHashMap> table_handle(Cast<OrderedHashMap>(table()), isolate);
  DirectHandle<OrderedHashMap> new_table =
      OrderedHashMap::Rehash(isolate, table_handle).ToHandleChecked();
  set_table(*new_table);
}

void JSWeakCollection::Initialize(
    DirectHandle<JSWeakCollection> weak_collection, Isolate* isolate) {
  DirectHandle<EphemeronHashTable> table = EphemeronHashTable::New(isolate, 0);
  weak_collection->set_table(*table);
}

void JSWeakCollection::Set(DirectHandle<JSWeakCollection> weak_collection,
                           Handle<Object> key, DirectHandle<Object> value,
                           int32_t hash) {
  DCHECK(IsJSReceiver(*key) || IsSymbol(*key));
  Handle<EphemeronHashTable> table(
      Cast<EphemeronHashTable>(weak_collection->table()),
      weak_collection->GetIsolate());
  DCHECK(table->IsKey(weak_collection->GetReadOnlyRoots(), *key));
  DirectHandle<EphemeronHashTable> new_table = EphemeronHashTable::Put(
      weak_collection->GetIsolate(), table, key, value, hash);
  weak_collection->set_table(*new_table);
  if (*table != *new_table) {
    // Zap the old table since we didn't record slots for its elements.
    EphemeronHashTable::FillEntriesWithHoles(table);
  }
}

bool JSWeakCollection::Delete(DirectHandle<JSWeakCollection> weak_collection,
                              Handle<Object> key, int32_t hash) {
  DCHECK(IsJSReceiver(*key) || IsSymbol(*key));
  Handle<EphemeronHashTable> table(
      Cast<EphemeronHashTable>(weak_collection->table()),
      weak_collection->GetIsolate());
  DCHECK(table->IsKey(weak_collection->GetReadOnlyRoots(), *key));
  bool was_present = false;
  DirectHandle<EphemeronHashTable> new_table = EphemeronHashTable::Remove(
      weak_collection->GetIsolate(), table, key, &was_present, hash);
  weak_collection->set_table(*new_table);
  if (*table != *new_table) {
    // Zap the old table since we didn't record slots for its elements.
    EphemeronHashTable::FillEntriesWithHoles(table);
  }
  return was_present;
}

Handle<JSArray> JSWeakCollection::GetEntries(
    DirectHandle<JSWeakCollection> holder, int max_entries) {
  Isolate* isolate = holder->GetIsolate();
  DirectHandle<EphemeronHashTable> table(
      Cast<EphemeronHashTable>(holder->table()), isolate);
  if (max_entries == 0 || max_entries > table->NumberOfElements()) {
    max_entries = table->NumberOfElements();
  }
  int values_per_entry = IsJSWeakMap(*holder) ? 2 : 1;
  DirectHandle<FixedArray> entries =
      isolate->factory()->NewFixedArray(max_entries * values_per_entry);
  // Recompute max_values because GC could have removed elements from the table.
  if (max_entries > table->NumberOfElements()) {
    max_entries = table->NumberOfElements();
  }

  {
    DisallowGarbageCollection no_gc;
    ReadOnlyRoots roots = ReadOnlyRoots(isolate);
    int count = 0;
    for (int i = 0;
         count / values_per_entry < max_entries && i < table->Capacity(); i++) {
      Tagged<Object> key;
      if (table->ToKey(roots, InternalIndex(i), &key)) {
        entries->set(count++, key);
        if (values_per_entry > 1) {
          Tagged<Object> value = table->Lookup(handle(key, isolate));
          entries->set(count++, value);
        }
      }
    }
    DCHECK_EQ(max_entries * values_per_entry, count);
  }
  return isolate->factory()->NewJSArrayWithElements(entries);
}

void JSDisposableStackBase::InitializeJSDisposableStackBase(
    Isolate* isolate, DirectHandle<JSDisposableStackBase> disposable_stack) {
  DirectHandle<FixedArray> array = isolate->factory()->NewFixedArray(0);
  disposable_stack->set_stack(*array);
  disposable_stack->set_needs_await(false);
  disposable_stack->set_has_awaited(false);
  disposable_stack->set_suppressed_error_created(false);
  disposable_stack->set_length(0);
  disposable_stack->set_state(DisposableStackState::kPending);
  disposable_stack->set_error(*(isolate->factory()->uninitialized_value()));
  disposable_stack->set_error_message(
      *(isolate->factory()->uninitialized_value()));
}

void PropertyCell::ClearAndInvalidate(ReadOnlyRoots roots) {
  DCHECK(!IsPropertyCellHole(value(), roots));
  PropertyDetails details = property_details();
  details = details.set_cell_type(PropertyCellType::kConstant);
  Transition(details, roots.property_cell_hole_value_handle());
  // TODO(11527): pass Isolate as an argument.
  Isolate* isolate = GetIsolateFromWritableObject(*this);
  DependentCode::DeoptimizeDependencyGroups(
      isolate, *this, DependentCode::kPropertyCellChangedGroup);
}

// static
Handle<PropertyCell> PropertyCell::InvalidateAndReplaceEntry(
    Isolate* isolate, DirectHandle<GlobalDictionary> dictionary,
    InternalIndex entry, PropertyDetails new_details,
    DirectHandle<Object> new_value) {
  DirectHandle<PropertyCell> cell(dictionary->CellAt(entry), isolate);
  DirectHandle<Name> name(cell->name(), isolate);
  DCHECK(cell->property_details().IsConfigurable());
  DCHECK(!IsAnyHole(cell->value(), isolate));

  // Swap with a new property cell.
  Handle<PropertyCell> new_cell =
      isolate->factory()->NewPropertyCell(name, new_details, new_value);
  dictionary->ValueAtPut(entry, *new_cell);

  cell->ClearAndInvalidate(ReadOnlyRoots(isolate));
  return new_cell;
}

static bool RemainsConstantType(Tagged<PropertyCell> cell,
                                Tagged<Object> value) {
  DisallowGarbageCollection no_gc;
  // TODO(dcarney): double->smi and smi->double transition from kConstant
  if (IsSmi(cell->value()) && IsSmi(value)) {
    return true;
  } else if (IsHeapObject(cell->value()) && IsHeapObject(value)) {
    Tagged<Map> map = Cast<HeapObject>(value)->map();
    return Cast<HeapObject>(cell->value())->map() == map && map->is_stable();
  }
  return false;
}

// static
PropertyCellType PropertyCell::InitialType(Isolate* isolate,
                                           Tagged<Object> value) {
  return IsUndefined(value, isolate) ? PropertyCellType::kUndefined
                                     : PropertyCellType::kConstant;
}

// static
PropertyCellType PropertyCell::UpdatedType(Isolate* isolate,
                                           Tagged<PropertyCell> cell,
                                           Tagged<Object> value,
                                           PropertyDetails details) {
  DisallowGarbageCollection no_gc;
  DCHECK(!IsAnyHole(value, isolate));
  DCHECK(!IsAnyHole(cell->value(), isolate));
  switch (details.cell_type()) {
    case PropertyCellType::kUndefined:
      return PropertyCellType::kConstant;
    case PropertyCellType::kConstant:
      if (value == cell->value()) return PropertyCellType::kConstant;
      [[fallthrough]];
    case PropertyCellType::kConstantType:
      if (RemainsConstantType(cell, value)) {
        return PropertyCellType::kConstantType;
      }
      [[fallthrough]];
    case PropertyCellType::kMutable:
      return PropertyCellType::kMutable;
    case PropertyCellType::kInTransition:
      UNREACHABLE();
  }
  UNREACHABLE();
}

Handle<PropertyCell> PropertyCell::PrepareForAndSetValue(
    Isolate* isolate, DirectHandle<GlobalDictionary> dictionary,
    InternalIndex entry, DirectHandle<Object> value, PropertyDetails details) {
  DCHECK(!IsAnyHole(*value, isolate));
  Tagged<PropertyCell> raw_cell = dictionary->CellAt(entry);
  CHECK(!IsAnyHole(raw_cell->value(), isolate));
  const PropertyDetails original_details = raw_cell->property_details();
  // Data accesses could be cached in ics or optimized code.
  bool invalidate = original_details.kind() == PropertyKind::kData &&
                    details.kind() == PropertyKind::kAccessor;
  int index = original_details.dictionary_index();
  DCHECK_LT(0, index);
  details = details.set_index(index);

  PropertyCellType new_type =
      UpdatedType(isolate, raw_cell, *value, original_details);
  details = details.set_cell_type(new_type);

  Handle<PropertyCell> cell(raw_cell, isolate);

  if (invalidate) {
    cell = PropertyCell::InvalidateAndReplaceEntry(isolate, dictionary, entry,
                                                   details, value);
  } else {
    cell->Transition(details, value);
    // Deopt when transitioning from a constant type or when making a writable
    // property read-only. Making a read-only property writable again is not
    // interesting because Turbofan does not currently rely on read-only unless
    // the property is also configurable, in which case it will stay read-only
    // forever.
    if (original_details.cell_type() != new_type ||
        (!original_details.IsReadOnly() && details.IsReadOnly())) {
      DependentCode::DeoptimizeDependencyGroups(
          isolate, *cell, DependentCode::kPropertyCellChangedGroup);
    }
  }
  return cell;
}

// static
void PropertyCell::InvalidateProtector() {
  if (value() != Smi::FromInt(Protectors::kProtectorInvalid)) {
    DCHECK_EQ(value(), Smi::FromInt(Protectors::kProtectorValid));
    set_value(Smi::FromInt(Protectors::kProtectorInvalid), kReleaseStore);
    // TODO(11527): pass Isolate as an argument.
    Isolate* isolate = GetIsolateFromWritableObject(*this);
    DependentCode::DeoptimizeDependencyGroups(
        isolate, *this, DependentCode::kPropertyCellChangedGroup);
  }
}

// static
bool PropertyCell::CheckDataIsCompatible(PropertyDetails details,
                                         Tagged<Object> value) {
  DisallowGarbageCollection no_gc;
  PropertyCellType cell_type = details.cell_type();
  CHECK_NE(cell_type, PropertyCellType::kInTransition);
  if (IsPropertyCellHole(value)) {
    CHECK_EQ(cell_type, PropertyCellType::kConstant);
  } else {
    CHECK_EQ(IsAccessorInfo(value) || IsAccessorPair(value),
             details.kind() == PropertyKind::kAccessor);
    DCHECK_IMPLIES(cell_type == PropertyCellType::kUndefined,
                   IsUndefined(value));
  }
  return true;
}

#ifdef DEBUG
bool PropertyCell::CanTransitionTo(PropertyDetails new_details,
                                   Tagged<Object> new_value) const {
  // Extending the implementation of PropertyCells with additional states
  // and/or transitions likely requires changes to PropertyCellData::Serialize.
  DisallowGarbageCollection no_gc;
  DCHECK(CheckDataIsCompatible(new_details, new_value));
  switch (property_details().cell_type()) {
    case PropertyCellType::kUndefined:
      return new_details.cell_type() != PropertyCellType::kUndefined;
    case PropertyCellType::kConstant:
      return !IsPropertyCellHole(value()) &&
             new_details.cell_type() != PropertyCellType::kUndefined;
    case PropertyCellType::kConstantType:
      return new_details.cell_type() == PropertyCellType::kConstantType ||
             new_details.cell_type() == PropertyCellType::kMutable ||
             (new_details.cell_type() == PropertyCellType::kConstant &&
              IsPropertyCellHole(new_value));
    case PropertyCellType::kMutable:
      return new_details.cell_type() == PropertyCellType::kMutable ||
             (new_details.cell_type() == PropertyCellType::kConstant &&
              IsPropertyCellHole(new_value));
    case PropertyCellType::kInTransition:
      UNREACHABLE();
  }
  UNREACHABLE();
}
#endif  // DEBUG

int JSGeneratorObject::code_offset() const {
  DCHECK(IsSmi(input_or_debug_pos()));
  int code_offset = Smi::ToInt(input_or_debug_pos());

  // The stored bytecode offset is relative to a different base than what
  // is used in the source position table, hence the subtraction.
  code_offset -= BytecodeArray::kHeaderSize - kHeapObjectTag;
  return code_offset;
}

int JSGeneratorObject::source_position() const {
  CHECK(is_suspended());
  DCHECK(function()->shared()->HasBytecodeArray());
  Isolate* isolate = GetIsolate();
  DCHECK(function()
             ->shared()
             ->GetBytecodeArray(isolate)
             ->HasSourcePositionTable());
  Tagged<BytecodeArray> bytecode =
      function()->shared()->GetBytecodeArray(isolate);
  return bytecode->SourcePosition(code_offset());
}

// static
Tagged<AccessCheckInfo> AccessCheckInfo::Get(Isolate* isolate,
                                             DirectHandle<JSObject> receiver) {
  DisallowGarbageCollection no_gc;
  DCHECK(receiver->map()->is_access_check_needed());
  Tagged<Object> maybe_constructor = receiver->map()->GetConstructor();
  if (IsFunctionTemplateInfo(maybe_constructor)) {
    Tagged<Object> data_obj =
        Cast<FunctionTemplateInfo>(maybe_constructor)->GetAccessCheckInfo();
    if (IsUndefined(data_obj, isolate)) return AccessCheckInfo();
    return Cast<AccessCheckInfo>(data_obj);
  }
  // Might happen for a detached context.
  if (!IsJSFunction(maybe_constructor)) return AccessCheckInfo();
  Tagged<JSFunction> constructor = Cast<JSFunction>(maybe_constructor);
  // Might happen for the debug context.
  if (!constructor->shared()->IsApiFunction()) return AccessCheckInfo();

  Tagged<Object> data_obj =
      constructor->shared()->api_func_data()->GetAccessCheckInfo();
  if (IsUndefined(data_obj, isolate)) return AccessCheckInfo();

  return Cast<AccessCheckInfo>(data_obj);
}

Address Smi::LexicographicCompare(Isolate* isolate, Tagged<Smi> x,
                                  Tagged<Smi> y) {
  DisallowGarbageCollection no_gc;
  DisallowJavascriptExecution no_js(isolate);

  int x_value = Smi::ToInt(x);
  int y_value = Smi::ToInt(y);

  // If the integers are equal so are the string representations.
  if (x_value == y_value) return Smi::FromInt(0).ptr();

  // If one of the integers is zero the normal integer order is the
  // same as the lexicographic order of the string representations.
  if (x_value == 0 || y_value == 0) {
    return Smi::FromInt(x_value < y_value ? -1 : 1).ptr();
  }

  // If only one of the integers is negative the negative number is
  // smallest because the char code of '-' is less than the char code
  // of any digit.  Otherwise, we make both values positive.

  // Use unsigned values otherwise the logic is incorrect for -MIN_INT on
  // architectures using 32-bit Smis.
  uint32_t x_scaled = x_value;
  uint32_t y_scaled = y_value;
  if (x_value < 0) {
    if (y_value >= 0) {
      return Smi::FromInt(-1).ptr();
    } else {
      y_scaled = base::NegateWithWraparound(y_value);
    }
    x_scaled = base::NegateWithWraparound(x_value);
  } else if (y_value < 0) {
    return Smi::FromInt(1).ptr();
  }

  // clang-format off
  static const uint32_t kPowersOf10[] = {
      1,                 10,                100,         1000,
      10 * 1000,         100 * 1000,        1000 * 1000, 10 * 1000 * 1000,
      100 * 1000 * 1000, 1000 * 1000 * 1000};
  // clang-format on

  // If the integers have the same number of decimal digits they can be
  // compared directly as the numeric order is the same as the
  // lexicographic order.  If one integer has fewer digits, it is scaled
  // by some power of 10 to have the same number of digits as the longer
  // integer.  If the scaled integers are equal it means the shorter
  // integer comes first in the lexicographic order.

  // From http://graphics.stanford.edu/~seander/bithacks.html#IntegerLog10
  int x_log2 = 31 - base::bits::CountLeadingZeros(x_scaled);
  int x_log10 = ((x_log2 + 1) * 1233) >> 12;
  x_log10 -= x_scaled < kPowersOf10[x_log10];

  int y_log2 = 31 - base::bits::CountLeadingZeros(y_scaled);
  int y_log10 = ((y_log2 + 1) * 1233) >> 12;
  y_log10 -= y_scaled < kPowersOf10[y_log10];

  int tie = 0;

  if (x_log10 < y_log10) {
    // X has fewer digits.  We would like to simply scale up X but that
    // might overflow, e.g when comparing 9 with 1_000_000_000, 9 would
    // be scaled up to 9_000_000_000. So we scale up by the next
    // smallest power and scale down Y to drop one digit. It is OK to
    // drop one digit from the longer integer since the final digit is
    // past the length of the shorter integer.
    x_scaled *= kPowersOf10[y_log10 - x_log10 - 1];
    y_scaled /= 10;
    tie = -1;
  } else if (y_log10 < x_log10) {
    y_scaled *= kPowersOf10[x_log10 - y_log10 - 1];
    x_scaled /= 10;
    tie = 1;
  }

  if (x_scaled < y_scaled) return Smi::FromInt(-1).ptr();
  if (x_scaled > y_scaled) return Smi::FromInt(1).ptr();
  return Smi::FromInt(tie).ptr();
}

void JSFinalizationRegistry::RemoveCellFromUnregisterTokenMap(
    Isolate* isolate, Address raw_finalization_registry,
    Address raw_weak_cell) {
  DisallowGarbageCollection no_gc;
  Tagged<JSFinalizationRegistry> finalization_registry =
      Cast<JSFinalizationRegistry>(Tagged<Object>(raw_finalization_registry));
  Tagged<WeakCell> weak_cell = Cast<WeakCell>(Tagged<Object>(raw_weak_cell));
  DCHECK(!IsUndefined(weak_cell->unregister_token(), isolate));
  Tagged<Undefined> undefined = ReadOnlyRoots(isolate).undefined_value();

  // Remove weak_cell from the linked list of other WeakCells with the same
  // unregister token and remove its unregister token from key_map if necessary
  // without shrinking it. Since shrinking may allocate, it is performed by the
  // caller after looping, or on exception.
  if (IsUndefined(weak_cell->key_list_prev(), isolate)) {
    Tagged<SimpleNumberDictionary> key_map =
        Cast<SimpleNumberDictionary>(finalization_registry->key_map());
    Tagged<HeapObject> unregister_token = weak_cell->unregister_token();
    uint32_t key = Smi::ToInt(Object::GetHash(unregister_token));
    InternalIndex entry = key_map->FindEntry(isolate, key);
    DCHECK(entry.is_found());

    if (IsUndefined(weak_cell->key_list_next(), isolate)) {
      // weak_cell is the only one associated with its key; remove the key
      // from the hash table.
      key_map->ClearEntry(entry);
      key_map->ElementRemoved();
    } else {
      // weak_cell is the list head for its key; we need to change the value
      // of the key in the hash table.
      Tagged<WeakCell> next = Cast<WeakCell>(weak_cell->key_list_next());
      DCHECK_EQ(next->key_list_prev(), weak_cell);
      next->set_key_list_prev(undefined);
      key_map->ValueAtPut(entry, next);
    }
  } else {
    // weak_cell is somewhere in the middle of its key list.
    Tagged<WeakCell> prev = Cast<WeakCell>(weak_cell->key_list_prev());
    prev->set_key_list_next(weak_cell->key_list_next());
    if (!IsUndefined(weak_cell->key_list_next())) {
      Tagged<WeakCell> next = Cast<WeakCell>(weak_cell->key_list_next());
      next->set_key_list_prev(weak_cell->key_list_prev());
    }
  }

  // weak_cell is now removed from the unregister token map, so clear its
  // unregister token-related fields.
  weak_cell->set_unregister_token(undefined);
  weak_cell->set_key_list_prev(undefined);
  weak_cell->set_key_list_next(undefined);
}

// static
bool MapWord::IsMapOrForwarded(Tagged<Map> map) {
  MapWord map_word = map->map_word(kRelaxedLoad);
  if (map_word.IsForwardingAddress()) {
    // During GC we can't access forwarded maps without synchronization.
    return true;
  }
  // The meta map might be moved away by GC too but we can read instance
  // type from both old and new location as it can't change.
  return InstanceTypeChecker::IsMap(map_word.ToMap()->instance_type());
}

// Force instantiation of template instances class.
// Please note this list is compiler dependent.
// Keep this at the end of this file

#define EXTERN_DEFINE_HASH_TABLE(DERIVED, SHAPE)                            \
  template class EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE)                  \
      HashTable<DERIVED, SHAPE>;                                            \
                                                                            \
  template EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE) Handle<DERIVED>        \
  HashTable<DERIVED, SHAPE>::New(Isolate*, int, AllocationType,             \
                                 MinimumCapacity);                          \
  template EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE) Handle<DERIVED>        \
  HashTable<DERIVED, SHAPE>::New(LocalIsolate*, int, AllocationType,        \
                                 MinimumCapacity);                          \
                                                                            \
  template EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE) Handle<DERIVED>        \
  HashTable<DERIVED, SHAPE>::EnsureCapacity(Isolate*, Handle<DERIVED>, int, \
                                            AllocationType);                \
  template EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE) Handle<DERIVED>        \
  HashTable<DERIVED, SHAPE>::EnsureCapacity(LocalIsolate*, Handle<DERIVED>, \
                                            int, AllocationType);

#define EXTERN_DEFINE_OBJECT_BASE_HASH_TABLE(DERIVED, SHAPE) \
  EXTERN_DEFINE_HASH_TABLE(DERIVED, SHAPE)                   \
  template class EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE)   \
      ObjectHashTableBase<DERIVED, SHAPE>;

#define EXTERN_DEFINE_MULTI_OBJECT_BASE_HASH_TABLE(DERIVED, N)    \
  EXTERN_DEFINE_HASH_TABLE(DERIVED, ObjectMultiHashTableShape<N>) \
  template class EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE)        \
      ObjectMultiHashTableBase<DERIVED, N>;

#define EXTERN_DEFINE_DICTIONARY(DERIVED, SHAPE)                              \
  EXTERN_DEFINE_HASH_TABLE(DERIVED, SHAPE)                                    \
  template class EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE)                    \
      Dictionary<DERIVED, SHAPE>;                                             \
                                                                              \
  template V8_EXPORT_PRIVATE Handle<DERIVED> Dictionary<DERIVED, SHAPE>::Add( \
      Isolate* isolate, Handle<DERIVED>, Key, DirectHandle<Object>,           \
      PropertyDetails, InternalIndex*);                                       \
  template V8_EXPORT_PRIVATE Handle<DERIVED> Dictionary<DERIVED, SHAPE>::Add( \
      LocalIsolate* isolate, Handle<DERIVED>, Key, DirectHandle<Object>,      \
      PropertyDetails, InternalIndex*);

#define EXTERN_DEFINE_BASE_NAME_DICTIONARY(DERIVED, SHAPE)                     \
  EXTERN_DEFINE_DICTIONARY(DERIVED, SHAPE)                                     \
  template class EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE)                     \
      BaseNameDictionary<DERIVED, SHAPE>;                                      \
                                                                               \
  template V8_EXPORT_PRIVATE Handle<DERIVED>                                   \
  BaseNameDictionary<DERIVED, SHAPE>::New(Isolate*, int, AllocationType,       \
                                          MinimumCapacity);                    \
  template V8_EXPORT_PRIVATE Handle<DERIVED>                                   \
  BaseNameDictionary<DERIVED, SHAPE>::New(LocalIsolate*, int, AllocationType,  \
                                          MinimumCapacity);                    \
                                                                               \
  template Handle<DERIVED>                                                     \
  BaseNameDictionary<DERIVED, SHAPE>::AddNoUpdateNextEnumerationIndex(         \
      Isolate* isolate, Handle<DERIVED>, Key, Handle<Object>, PropertyDetails, \
      InternalIndex*);                                                         \
  template Handle<DERIVED>                                                     \
  BaseNameDictionary<DERIVED, SHAPE>::AddNoUpdateNextEnumerationIndex(         \
      LocalIsolate* isolate, Handle<DERIVED>, Key, Handle<Object>,             \
      PropertyDetails, InternalIndex*);

EXTERN_DEFINE_HASH_TABLE(StringSet, StringSetShape)
EXTERN_DEFINE_HASH_TABLE(CompilationCacheTable, CompilationCacheShape)
EXTERN_DEFINE_HASH_TABLE(ObjectHashSet, ObjectHashSetShape)
EXTERN_DEFINE_HASH_TABLE(NameToIndexHashTable, NameToIndexShape)
EXTERN_DEFINE_HASH_TABLE(RegisteredSymbolTable, RegisteredSymbolTableShape)

EXTERN_DEFINE_OBJECT_BASE_HASH_TABLE(ObjectHashTable, ObjectHashTableShape)
EXTERN_DEFINE_OBJECT_BASE_HASH_TABLE(EphemeronHashTable, ObjectHashTableShape)

EXTERN_DEFINE_MULTI_OBJECT_BASE_HASH_TABLE(ObjectTwoHashTable, 2)

EXTERN_DEFINE_DICTIONARY(SimpleNumberDictionary, SimpleNumberDictionaryShape)
EXTERN_DEFINE_DICTIONARY(NumberDictionary, NumberDictionaryShape)

template V8_EXPORT_PRIVATE void
Dictionary<NumberDictionary, NumberDictionaryShape>::UncheckedAdd<
    Isolate, AllocationType::kSharedOld>(Isolate*, Handle<NumberDictionary>,
                                         uint32_t, DirectHandle<Object>,
                                         PropertyDetails);

EXTERN_DEFINE_BASE_NAME_DICTIONARY(NameDictionary, NameDictionaryShape)
template V8_EXPORT_PRIVATE Handle<NameDictionary> NameDictionary::New(
    Isolate*, int, AllocationType, MinimumCapacity);
template V8_EXPORT_PRIVATE Handle<NameDictionary> NameDictionary::New(
    LocalIsolate*, int, AllocationType, MinimumCapacity);

EXTERN_DEFINE_BASE_NAME_DICTIONARY(GlobalDictionary, GlobalDictionaryShape)

#undef EXTERN_DEFINE_HASH_TABLE
#undef EXTERN_DEFINE_OBJECT_BASE_HASH_TABLE
#undef EXTERN_DEFINE_DICTIONARY
#undef EXTERN_DEFINE_BASE_NAME_DICTIONARY

}  // namespace v8::internal
```