Response:
My goal is to analyze the provided C++ code snippet from V8's `objects.cc` file and extract its functionality, relate it to JavaScript, provide examples, and summarize its purpose within the context of a larger series.

Here's a breakdown of my thought process:

1. **Identify the core data structures and operations:** The code heavily revolves around `HashTable` and its specializations like `GlobalDictionary`, `StringSet`, `RegisteredSymbolTable`, `NameDictionary`, `SimpleNumberDictionary`, `NumberDictionary`, and `ObjectHashTableBase`. These suggest the code deals with storing and retrieving data based on keys. The template nature of `HashTable` indicates a general-purpose mechanism.

2. **Focus on the `PromiseReactionJobTask` logic:** The initial part of the code explicitly handles `PromiseReactionJobTask`. I noted the creation of these tasks, the distinction between `kFulfill` and `kReject` reactions, and the enqueueing of these tasks into a `MicrotaskQueue`. This immediately connects to JavaScript's Promise implementation.

3. **Analyze `HashTable` methods:**  I scanned the various methods within the `HashTable` template:
    * `IteratePrefix`, `IterateElements`:  Clearly related to traversing the table's contents.
    * `New`, `NewInternal`: Construction of new hash tables.
    * `Rehash`:  The core mechanism for resizing and reorganizing the table.
    * `EntryForProbe`:  Part of the hash table lookup process.
    * `Swap`: Utility for rearranging elements during rehashing.
    * `EnsureCapacity`, `HasSufficientCapacityToAdd`, `ComputeCapacityWithShrink`, `Shrink`:  Managing the table's size.
    * `FindInsertionEntry`:  Locating the correct spot to insert a new element.

4. **Examine specialized hash tables:** I paid attention to how the generic `HashTable` template is used to implement specific dictionaries and sets.
    * `GlobalDictionary`:  Likely for storing global variables.
    * `StringSet`:  Storing a collection of unique strings.
    * `RegisteredSymbolTable`: Managing globally registered symbols.
    * `NameDictionary` and `BaseNameDictionary`:  Storing properties associated with names. The `NextEnumerationIndex` logic caught my eye, indicating a role in property enumeration order.
    * `SimpleNumberDictionary` and `NumberDictionary`: Optimized for numeric keys. The `UpdateMaxNumberKey` method in `NumberDictionary` suggests optimizations related to array indexing.
    * `ObjectHashTableBase`:  Handles objects as keys.

5. **Connect to JavaScript concepts:** Based on the identified data structures and operations, I started making connections to JavaScript:
    * **Promises:** The `PromiseReactionJobTask` directly maps to the asynchronous nature of Promises.
    * **Objects and Properties:** The various dictionaries are used to store object properties. `NameDictionary` is particularly relevant here.
    * **Arrays (sparse arrays):**  `NumberDictionary` with its `UpdateMaxNumberKey` and the concept of "slow elements" hints at the internal representation of sparse arrays in JavaScript.
    * **Sets:** `StringSet` directly corresponds to the JavaScript `Set` object (at least conceptually, for string values).
    * **Symbols:** `RegisteredSymbolTable` is clearly linked to JavaScript's `Symbol.for()` functionality.
    * **Property Enumeration:** The `NextEnumerationIndex` logic in `BaseNameDictionary` relates to the order in which properties are enumerated in JavaScript.

6. **Craft JavaScript examples:** For each connection I made, I tried to create a simple JavaScript code snippet illustrating the underlying C++ functionality. This involved:
    * Showing how Promises are resolved and rejected.
    * Demonstrating adding properties to objects.
    * Illustrating sparse arrays and how accessing out-of-bounds indices works.
    * Showing the usage of `Set` and `Symbol.for()`.
    * Giving an example of property enumeration order.

7. **Infer code logic and provide examples:**  For methods like `Rehash`, `FindInsertionEntry`, etc., I tried to create scenarios that would trigger these actions. For instance, showing how adding many elements to a hash table might cause a rehash. The input/output for `Rehash` was a bit more conceptual, showing the transformation of the table.

8. **Identify common programming errors:**  I considered how the underlying C++ implementation might expose potential pitfalls for JavaScript developers. This led to examples related to:
    * Forgetting to handle promise rejections.
    * Performance issues with adding non-integer keys to array-like objects.
    * Unexpected property enumeration order.

9. **Summarize the functionality:** Finally, I synthesized the information gathered into a concise summary of the code's purpose within the V8 engine, emphasizing its role in implementing core JavaScript object and data structure features.

10. **Address the "part 7 of 8" aspect:** I noted that this section focuses on the fundamental data structures used for managing objects and their properties, suggesting that the other parts likely deal with higher-level features or specific object types.

**(Self-Correction/Refinement):** Initially, I might have focused too much on the low-level details of the `HashTable` implementation. I realized that it was crucial to connect these details back to concrete JavaScript concepts and provide illustrative examples to make the explanation more accessible and relevant to the user's request. I also made sure to explicitly mention the "part 7 of 8" aspect to provide context.
好的，让我们来分析一下这段 `v8/src/objects/objects.cc` 代码的功能。

**文件功能概览**

这段代码是 V8 引擎中 `objects.cc` 文件的一部分，它主要负责实现 V8 中各种对象的基础操作，特别是与哈希表相关的操作。从代码内容来看，重点在于 `HashTable` 模板类及其派生类的实现，以及与 Promise 相关的微任务队列操作。

**核心功能点**

1. **Promise 微任务入队:**
   - 这段代码实现了将 Promise 的 `then` 或 `catch` 方法注册的回调函数封装成微任务（`PromiseReactionJobTask`）并添加到微任务队列的功能。
   - 它区分了 `PromiseFulfillReactionJobTask` (用于 `then` 的成功回调) 和 `PromiseRejectReactionJobTask` (用于 `then` 的失败回调或 `catch` 的回调)。
   - 根据 Promise 的状态 (`kFulfill` 或其他，默认为 `kReject`)，设置不同的任务类型和参数。
   - 如果存在微任务队列，则将创建的任务入队。

   **JavaScript 示例:**

   ```javascript
   const promise = new Promise((resolve, reject) => {
     // 异步操作，例如网络请求
     setTimeout(() => {
       resolve('成功'); // 或者 reject('失败');
     }, 1000);
   });

   promise.then(
     (value) => { console.log('已完成:', value); }, // 对应 PromiseFulfillReactionJobTask
     (error) => { console.log('已拒绝:', error); }  // 对应 PromiseRejectReactionJobTask
   );

   promise.catch((error) => {
     console.log('捕获错误:', error); // 对应 PromiseRejectReactionJobTask
   });
   ```

2. **`HashTable` 模板类的实现:**
   - 代码定义了一个通用的 `HashTable` 模板类，用于实现各种基于哈希表的 V8 对象，例如字典（`Dictionary`）、字符串集合（`StringSet`）等。
   - 提供了哈希表的常见操作：
     - **`IteratePrefix` 和 `IterateElements`:**  用于遍历哈希表的前缀部分和元素部分。
     - **`New` 和 `NewInternal`:**  用于创建新的哈希表实例，可以指定初始容量和分配类型。
     - **`Rehash`:**  当哈希表容量不足或元素分布不均时，重新计算元素位置，调整哈希表大小。
     - **`EntryForProbe`:**  在哈希表中查找给定键的条目。
     - **`Swap`:**  交换哈希表中两个条目的位置。
     - **`EnsureCapacity`:**  确保哈希表有足够的容量容纳新的元素。
     - **`HasSufficientCapacityToAdd`:**  检查哈希表是否有足够的容量添加指定数量的元素。
     - **`ComputeCapacityWithShrink`:**  计算缩小哈希表容量的大小。
     - **`Shrink`:**  缩小哈希表的容量。
     - **`FindInsertionEntry`:**  查找可以插入新元素的空闲或已删除的条目。

   **代码逻辑推理 (以 `Rehash` 为例):**

   **假设输入:** 一个已满或接近满的 `HashTable` 实例，其中一些元素可能被标记为已删除。

   **输出:** 一个新的 `HashTable` 实例，容量更大（或不变，如果只是重新组织），所有有效的元素都重新插入到新的位置，已删除的条目被清除。

   `Rehash` 的核心逻辑是遍历旧表中的每个有效元素，根据其哈希值计算在新表中的位置，并将其插入。

3. **特定哈希表类型的实现:**
   - 代码基于 `HashTable` 模板实现了各种特定的哈希表类型：
     - **`GlobalDictionary`:** 用于存储全局对象的属性。
     - **`StringSet`:** 用于存储一组唯一的字符串。
     - **`RegisteredSymbolTable`:** 用于存储全局注册的 Symbol。
     - **`BaseNameDictionary` 和 `NameDictionary`:** 用于存储对象的命名属性。
     - **`SimpleNumberDictionary` 和 `NumberDictionary`:**  用于存储对象的数字索引属性，`NumberDictionary` 做了额外的优化，例如 `UpdateMaxNumberKey`，用于处理稀疏数组。
     - **`ObjectHashTableBase`:**  用于存储以对象作为键的键值对。
     - **`NameToIndexHashTable`:** 用于将名称映射到索引。

4. **字典操作:**
   - 代码提供了字典的常见操作，例如 `DeleteEntry` (删除条目)、`AtPut` (添加或更新键值对)、`UncheckedAtPut` (不进行重复键检查的添加或更新)、`Add` (添加键值对并更新枚举索引) 等。
   - `NextEnumerationIndex` 用于管理属性枚举的顺序。

**与 JavaScript 功能的关系**

这段代码直接关系到 JavaScript 中对象、属性、数组、Set 和 Symbol 的实现。

- **对象属性存储:** `NameDictionary` 和 `NumberDictionary` 是 JavaScript 对象存储属性的核心数据结构。
- **数组实现:** `NumberDictionary` 的 `UpdateMaxNumberKey` 等逻辑与 JavaScript 数组（特别是稀疏数组）的内部表示密切相关。
- **Set 实现:** `StringSet` 用于实现 JavaScript 的 `Set` 对象。
- **Symbol 实现:** `RegisteredSymbolTable` 用于实现 `Symbol.for()` 创建的全局 Symbol。
- **Promise 实现:**  Promise 的 `then` 和 `catch` 方法的回调入队功能由这段代码实现。

**用户常见的编程错误**

这段代码的底层实现与用户直接接触较少，但其功能会影响用户可能遇到的问题：

- **忘记处理 Promise 拒绝:**  如果 Promise 最终被拒绝，但没有 `catch` 或第二个参数的 `then` 来处理，可能会导致未捕获的错误。
  ```javascript
  const promise = new Promise((resolve, reject) => {
    setTimeout(() => {
      reject('出错了！');
    }, 500);
  });

  promise.then((value) => {
    console.log('成功了，但是拒绝了也看不到');
  }); // 缺少 reject 处理
  ```

- **向对象添加大量属性导致性能问题:**  底层哈希表的扩容和重新哈希操作在添加大量属性时可能会有性能影响，尤其是在频繁添加和删除属性的情况下。

- **对数组使用非数字索引:**  虽然 JavaScript 允许对数组使用字符串索引，但这会导致对象属性存储，而不是数组元素的存储，可能会影响性能和数组方法的使用。

**第7部分功能归纳**

作为共 8 部分的第 7 部分，这段代码主要关注 V8 引擎中 **对象属性的存储和管理** 以及 **Promise 微任务的调度**。它定义了核心的数据结构（哈希表）和操作，为实现 JavaScript 中对象、数组、Set、Symbol 和 Promise 等重要特性提供了基础。可以推测，其他部分可能涉及更高级的对象操作、原型链、函数调用、垃圾回收等方面。

总而言之，`v8/src/objects/objects.cc` 的这一部分是 V8 引擎中至关重要的基础设施代码，它直接支撑着 JavaScript 中各种对象的创建、属性的访问和操作，以及异步编程模型 Promise 的实现。

### 提示词
```
这是目录为v8/src/objects/objects.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/objects.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第7部分，共8部分，请归纳一下它的功能
```

### 源代码
```cpp
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
  if (!ta
```