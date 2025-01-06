Response: The user wants me to summarize the functionality of the provided C++ code, which is part of V8's implementation of JavaScript collections (Map and Set). This is the second part of the file.

**Plan:**
1. **Identify the main functionalities:** Look for built-in function definitions (`TF_BUILTIN`) and helper functions that implement core operations for Map and Set.
2. **Group related functions:**  Organize the functionalities based on whether they operate on `Map` or `Set`, and distinguish between prototype methods and internal helpers.
3. **Explain the interaction with JavaScript:** For each functionality, provide a corresponding JavaScript example to illustrate its usage.
该C++源代码文件（第2部分）是V8 JavaScript引擎中关于 `Map` 和 `Set` 集合类型的内置函数的实现。它延续了第1部分的内容，主要实现了以下功能：

**1. `Map` 原型方法的实现：**

*   **`Map.prototype.delete(key)`:**  从 `Map` 中删除指定键的键值对。
    ```javascript
    const map = new Map();
    map.set('a', 1);
    map.delete('a');
    console.log(map.has('a')); // 输出: false
    ```
*   **`Map.prototype.entries()`:** 返回一个新的迭代器对象，该对象包含 `Map` 中所有元素的 `[key, value]` 对，顺序为插入顺序。
    ```javascript
    const map = new Map();
    map.set('a', 1);
    map.set('b', 2);
    for (const [key, value] of map.entries()) {
      console.log(key, value); // 输出: a 1, b 2
    }
    ```
*   **`get Map.prototype.size`:** 返回 `Map` 对象中键值对的数量。
    ```javascript
    const map = new Map();
    map.set('a', 1);
    console.log(map.size); // 输出: 1
    ```
*   **`Map.prototype.forEach(callbackFn[, thisArg])`:**  对 `Map` 中的每个键值对执行提供的 `callbackFn` 一次，`thisArg` 可指定 `callbackFn` 中 `this` 的指向。
    ```javascript
    const map = new Map();
    map.set('a', 1);
    map.set('b', 2);
    map.forEach((value, key) => {
      console.log(key, value); // 输出: a 1, b 2
    });
    ```
*   **`Map.prototype.keys()`:** 返回一个新的迭代器对象，该对象包含 `Map` 中所有的键，顺序为插入顺序。
    ```javascript
    const map = new Map();
    map.set('a', 1);
    map.set('b', 2);
    for (const key of map.keys()) {
      console.log(key); // 输出: a, b
    }
    ```
*   **`Map.prototype.values()`:** 返回一个新的迭代器对象，该对象包含 `Map` 中所有的值，顺序为插入顺序。
    ```javascript
    const map = new Map();
    map.set('a', 1);
    map.set('b', 2);
    for (const value of map.values()) {
      console.log(value); // 输出: 1, 2
    }
    ```
*   **`Map.prototype[@@iterator]()` (通过 `Map.prototype.entries()` 实现):**  使 `Map` 对象可迭代，返回的迭代器与 `Map.prototype.entries()` 返回的迭代器相同。
    ```javascript
    const map = new Map();
    map.set('a', 1);
    map.set('b', 2);
    for (const [key, value] of map) {
      console.log(key, value); // 输出: a 1, b 2
    }
    ```
*   **`Map Iterator.prototype.next()`:**  `Map` 迭代器对象的 `next()` 方法，用于遍历 `Map` 中的元素，返回一个包含 `done` 和 `value` 属性的对象。对于 `Map` 迭代器，`value` 是一个 `[key, value]` 数组。
    ```javascript
    const map = new Map();
    map.set('a', 1);
    const iterator = map.entries();
    console.log(iterator.next()); // 输出: { value: [ 'a', 1 ], done: false }
    console.log(iterator.next()); // 输出: { value: undefined, done: true } (假设 Map 只有 'a': 1)
    ```

**2. `Set` 原型方法的实现：**

*   **`Set.prototype.add(value)`:** 向 `Set` 对象中添加一个新的元素，并返回该 `Set` 对象。
    ```javascript
    const set = new Set();
    set.add('a');
    console.log(set.has('a')); // 输出: true
    ```
*   **`Set.prototype.delete(value)`:** 从 `Set` 对象中删除指定的元素。
    ```javascript
    const set = new Set();
    set.add('a');
    set.delete('a');
    console.log(set.has('a')); // 输出: false
    ```
*   **`Set.prototype.entries()`:** 返回一个新的迭代器对象，该对象包含 `Set` 中所有元素的 `[value, value]` 数组，顺序为插入顺序。
    ```javascript
    const set = new Set();
    set.add('a');
    set.add('b');
    for (const [value1, value2] of set.entries()) {
      console.log(value1, value2); // 输出: a a, b b
    }
    ```
*   **`get Set.prototype.size`:** 返回 `Set` 对象中元素的数量。
    ```javascript
    const set = new Set();
    set.add('a');
    console.log(set.size); // 输出: 1
    ```
*   **`Set.prototype.forEach(callbackFn[, thisArg])`:** 对 `Set` 中的每个元素执行提供的 `callbackFn` 一次，`thisArg` 可指定 `callbackFn` 中 `this` 的指向。
    ```javascript
    const set = new Set();
    set.add('a');
    set.add('b');
    set.forEach(value => {
      console.log(value); // 输出: a, b
    });
    ```
*   **`Set.prototype.values()`:** 返回一个新的迭代器对象，该对象包含 `Set` 中所有的值，顺序为插入顺序。
    ```javascript
    const set = new Set();
    set.add('a');
    set.add('b');
    for (const value of set.values()) {
      console.log(value); // 输出: a, b
    }
    ```
*   **`Set.prototype[@@iterator]()` (通过 `Set.prototype.values()` 实现):** 使 `Set` 对象可迭代，返回的迭代器与 `Set.prototype.values()` 返回的迭代器相同。
    ```javascript
    const set = new Set();
    set.add('a');
    set.add('b');
    for (const value of set) {
      console.log(value); // 输出: a, b
    }
    ```
*   **`Set Iterator.prototype.next()`:**  `Set` 迭代器对象的 `next()` 方法，用于遍历 `Set` 中的元素，返回一个包含 `done` 和 `value` 属性的对象。对于 `Set` 迭代器，`value` 是当前遍历到的元素。
    ```javascript
    const set = new Set();
    set.add('a');
    const iterator = set.values();
    console.log(iterator.next()); // 输出: { value: 'a', done: false }
    console.log(iterator.next()); // 输出: { value: undefined, done: true } (假设 Set 只有 'a')
    ```
*   **`Set.prototype.has(value)`:** 返回一个布尔值，表示 `Set` 中是否存在指定的元素。
    ```javascript
    const set = new Set();
    set.add('a');
    console.log(set.has('a')); // 输出: true
    console.log(set.has('b')); // 输出: false
    ```

**3. 查找辅助函数的实现:**

*   **`FindOrderedHashMapEntry`**: 用于在 `Map` 的内部哈希表中查找指定键的条目，并返回其起始位置的索引。
*   **`FindOrderedHashSetEntry`**: 用于在 `Set` 的内部哈希表中查找指定元素的条目，并返回其起始位置的索引。

**4. 分组操作的辅助函数:**

*   **`AddValueToKeyedGroup`**:  用于将值添加到以键为分组依据的集合中，常用于 `group by` 操作。

**5. `WeakMap` 和 `WeakSet` 的内置函数实现:**

*   **构造函数 (`WeakMapConstructor`, `WeakSetConstructor`)**:  创建 `WeakMap` 和 `WeakSet` 实例。
    ```javascript
    const weakMap = new WeakMap();
    const weakSet = new WeakSet();
    ```
*   **`WeakMapLookupHashIndex`**:  在 `WeakMap` 的内部哈希表中查找键的索引。
*   **`WeakMapGet`**: 获取 `WeakMap` 中指定键的值。
    ```javascript
    const weakMap = new WeakMap();
    const key = {};
    weakMap.set(key, 'value');
    console.log(weakMap.get(key)); // 输出: value
    ```
*   **`WeakMap.prototype.has(key)`**: 检查 `WeakMap` 中是否存在指定的键。
    ```javascript
    const weakMap = new WeakMap();
    const key = {};
    weakMap.set(key, 'value');
    console.log(weakMap.has(key)); // 输出: true
    ```
*   **`WeakCollectionDelete`**:  用于 `WeakMap` 和 `WeakSet` 删除元素的通用辅助函数。
*   **`WeakCollectionSet`**:  用于 `WeakMap` 和 `WeakSet` 添加元素的通用辅助函数。
*   **`WeakMap.prototype.delete(key)`**: 从 `WeakMap` 中删除指定键的键值对。
    ```javascript
    const weakMap = new WeakMap();
    const key = {};
    weakMap.set(key, 'value');
    weakMap.delete(key);
    console.log(weakMap.has(key)); // 输出: false
    ```
*   **`WeakMap.prototype.set(key, value)`**: 向 `WeakMap` 中添加或更新键值对。
    ```javascript
    const weakMap = new WeakMap();
    const key = {};
    weakMap.set(key, 'value');
    ```
*   **`WeakSet.prototype.add(value)`**: 向 `WeakSet` 中添加一个值。
    ```javascript
    const weakSet = new WeakSet();
    const obj = {};
    weakSet.add(obj);
    console.log(weakSet.has(obj)); // 输出: true
    ```
*   **`WeakSet.prototype.delete(value)`**: 从 `WeakSet` 中删除指定的值。
    ```javascript
    const weakSet = new WeakSet();
    const obj = {};
    weakSet.add(obj);
    weakSet.delete(obj);
    console.log(weakSet.has(obj)); // 输出: false
    ```
*   **`WeakSet.prototype.has(value)`**: 检查 `WeakSet` 中是否存在指定的值。
    ```javascript
    const weakSet = new WeakSet();
    const obj = {};
    weakSet.add(obj);
    console.log(weakSet.has(obj)); // 输出: true
    ```

**总结:**

这部分代码实现了 JavaScript 中 `Map` 和 `Set` 集合类型的大部分原型方法，包括添加、删除、查找、遍历元素以及获取大小等操作。同时，它也实现了 `WeakMap` 和 `WeakSet` 的构造函数和基本操作。这些 C++ 代码为 JavaScript 开发者使用的 `Map` 和 `Set` 提供了底层的实现支撑，保证了这些数据结构的性能和功能。 文件中还包含了一些用于哈希表操作和优化的辅助函数，例如扩容、收缩和查找等。这些底层的实现细节对 JavaScript 开发者是透明的，但对于理解 V8 引擎如何高效地管理集合数据至关重要。

Prompt: 
```
这是目录为v8/src/builtins/builtins-collections-gen.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""
o to runtime to compute the hash code.
    entry_start_position_or_hash = SmiUntag(CallGetOrCreateHashRaw(CAST(key)));
    Goto(&add_entry);
  }

  BIND(&add_entry);
  TVARIABLE(IntPtrT, number_of_buckets);
  TVARIABLE(IntPtrT, occupancy);
  {
    // Check we have enough space for the entry.
    number_of_buckets = PositiveSmiUntag(CAST(UnsafeLoadFixedArrayElement(
        table, CollectionType::NumberOfBucketsIndex())));

    static_assert(CollectionType::kLoadFactor == 2);
    const TNode<WordT> capacity = WordShl(number_of_buckets.value(), 1);
    const TNode<IntPtrT> number_of_elements =
        LoadAndUntagPositiveSmiObjectField(
            table, CollectionType::NumberOfElementsOffset());
    const TNode<IntPtrT> number_of_deleted =
        PositiveSmiUntag(CAST(LoadObjectField(
            table, CollectionType::NumberOfDeletedElementsOffset())));
    occupancy = IntPtrAdd(number_of_elements, number_of_deleted);
    GotoIf(IntPtrLessThan(occupancy.value(), capacity), &store_new_entry);

    // We do not have enough space, grow the table and reload the relevant
    // fields.
    table_var = grow();
    number_of_buckets = PositiveSmiUntag(CAST(UnsafeLoadFixedArrayElement(
        table_var.value(), CollectionType::NumberOfBucketsIndex())));
    const TNode<IntPtrT> new_number_of_elements =
        LoadAndUntagPositiveSmiObjectField(
            table_var.value(), CollectionType::NumberOfElementsOffset());
    const TNode<IntPtrT> new_number_of_deleted = PositiveSmiUntag(
        CAST(LoadObjectField(table_var.value(),
                             CollectionType::NumberOfDeletedElementsOffset())));
    occupancy = IntPtrAdd(new_number_of_elements, new_number_of_deleted);
    Goto(&store_new_entry);
  }

  BIND(&store_new_entry);
  {
    StoreOrderedHashTableNewEntry(
        table_var.value(), entry_start_position_or_hash.value(),
        number_of_buckets.value(), occupancy.value(), store_at_new_entry);
    Goto(&done);
  }

  BIND(&done);
  return table_var.value();
}

TF_BUILTIN(MapPrototypeSet, CollectionsBuiltinsAssembler) {
  const auto receiver = Parameter<Object>(Descriptor::kReceiver);
  auto key = Parameter<Object>(Descriptor::kKey);
  const auto value = Parameter<Object>(Descriptor::kValue);
  const auto context = Parameter<Context>(Descriptor::kContext);

  ThrowIfNotInstanceType(context, receiver, JS_MAP_TYPE, "Map.prototype.set");

  key = NormalizeNumberKey(key);

  GrowCollection<OrderedHashMap> grow = [this, context, receiver]() {
    CallRuntime(Runtime::kMapGrow, context, receiver);
    return LoadObjectField<OrderedHashMap>(CAST(receiver), JSMap::kTableOffset);
  };

  StoreAtEntry<OrderedHashMap> store_at_new_entry =
      [this, key, value](const TNode<OrderedHashMap> table,
                         const TNode<IntPtrT> entry_start) {
        UnsafeStoreKeyValueInOrderedHashMapEntry(table, key, value,
                                                 entry_start);
      };

  StoreAtEntry<OrderedHashMap> store_at_existing_entry =
      [this, value](const TNode<OrderedHashMap> table,
                    const TNode<IntPtrT> entry_start) {
        UnsafeStoreValueInOrderedHashMapEntry(table, value, entry_start);
      };

  const TNode<OrderedHashMap> table =
      LoadObjectField<OrderedHashMap>(CAST(receiver), JSMap::kTableOffset);
  AddToOrderedHashTable(table, key, grow, store_at_new_entry,
                        store_at_existing_entry);
  Return(receiver);
}

template <typename CollectionType>
void CollectionsBuiltinsAssembler::StoreOrderedHashTableNewEntry(
    const TNode<CollectionType> table, const TNode<IntPtrT> hash,
    const TNode<IntPtrT> number_of_buckets, const TNode<IntPtrT> occupancy,
    const StoreAtEntry<CollectionType>& store_at_new_entry) {
  const TNode<IntPtrT> bucket =
      WordAnd(hash, IntPtrSub(number_of_buckets, IntPtrConstant(1)));
  TNode<Smi> bucket_entry = CAST(UnsafeLoadFixedArrayElement(
      table, bucket, CollectionType::HashTableStartIndex() * kTaggedSize));

  // Store the entry elements.
  const TNode<IntPtrT> entry_start = IntPtrAdd(
      IntPtrMul(occupancy, IntPtrConstant(CollectionType::kEntrySize)),
      number_of_buckets);
  store_at_new_entry(table, entry_start);

  // Connect the element to the bucket chain.
  UnsafeStoreFixedArrayElement(
      table, entry_start, bucket_entry,
      kTaggedSize * (CollectionType::HashTableStartIndex() +
                     CollectionType::kChainOffset));

  // Update the bucket head.
  UnsafeStoreFixedArrayElement(
      table, bucket, SmiTag(occupancy),
      CollectionType::HashTableStartIndex() * kTaggedSize);

  // Bump the elements count.
  const TNode<Smi> number_of_elements =
      CAST(LoadObjectField(table, CollectionType::NumberOfElementsOffset()));
  StoreObjectFieldNoWriteBarrier(table,
                                 CollectionType::NumberOfElementsOffset(),
                                 SmiAdd(number_of_elements, SmiConstant(1)));
}

// This is a helper function to add a new entry to an ordered hash table,
// when we are adding new entries from a Set.
template <typename CollectionType>
void CollectionsBuiltinsAssembler::AddNewToOrderedHashTable(
    const TNode<CollectionType> table, const TNode<Object> normalised_key,
    const TNode<IntPtrT> number_of_buckets, const TNode<IntPtrT> occupancy,
    const StoreAtEntry<CollectionType>& store_at_new_entry) {
  Label if_key_smi(this), if_key_string(this), if_key_heap_number(this),
      if_key_bigint(this), if_key_other(this), call_store(this);
  TVARIABLE(IntPtrT, hash, IntPtrConstant(0));

  GotoIf(TaggedIsSmi(normalised_key), &if_key_smi);
  TNode<Map> key_map = LoadMap(CAST(normalised_key));
  TNode<Uint16T> key_instance_type = LoadMapInstanceType(key_map);

  GotoIf(IsStringInstanceType(key_instance_type), &if_key_string);
  GotoIf(IsHeapNumberMap(key_map), &if_key_heap_number);
  GotoIf(IsBigIntInstanceType(key_instance_type), &if_key_bigint);
  Goto(&if_key_other);

  BIND(&if_key_other);
  {
    hash = Signed(ChangeUint32ToWord(GetHash(CAST(normalised_key))));
    Goto(&call_store);
  }

  BIND(&if_key_smi);
  {
    hash = ChangeInt32ToIntPtr(
        ComputeUnseededHash(SmiUntag(CAST(normalised_key))));
    Goto(&call_store);
  }

  BIND(&if_key_string);
  {
    hash = Signed(ChangeUint32ToWord(ComputeStringHash(CAST(normalised_key))));
    Goto(&call_store);
  }

  BIND(&if_key_heap_number);
  {
    hash = Signed(ChangeUint32ToWord(GetHash(CAST(normalised_key))));
    Goto(&call_store);
  }

  BIND(&if_key_bigint);
  {
    hash = Signed(ChangeUint32ToWord(GetHash(CAST(normalised_key))));
    Goto(&call_store);
  }

  BIND(&call_store);
  StoreOrderedHashTableNewEntry(table, hash.value(), number_of_buckets,
                                occupancy, store_at_new_entry);
}

void CollectionsBuiltinsAssembler::StoreValueInOrderedHashMapEntry(
    const TNode<OrderedHashMap> table, const TNode<Object> value,
    const TNode<IntPtrT> entry_start, CheckBounds check_bounds) {
  StoreFixedArrayElement(table, entry_start, value, UPDATE_WRITE_BARRIER,
                         kTaggedSize * (OrderedHashMap::HashTableStartIndex() +
                                        OrderedHashMap::kValueOffset),
                         check_bounds);
}

void CollectionsBuiltinsAssembler::StoreKeyValueInOrderedHashMapEntry(
    const TNode<OrderedHashMap> table, const TNode<Object> key,
    const TNode<Object> value, const TNode<IntPtrT> entry_start,
    CheckBounds check_bounds) {
  StoreFixedArrayElement(table, entry_start, key, UPDATE_WRITE_BARRIER,
                         kTaggedSize * OrderedHashMap::HashTableStartIndex(),
                         check_bounds);
  StoreValueInOrderedHashMapEntry(table, value, entry_start, check_bounds);
}

TF_BUILTIN(MapPrototypeDelete, CollectionsBuiltinsAssembler) {
  const auto receiver = Parameter<Object>(Descriptor::kReceiver);
  const auto key = Parameter<Object>(Descriptor::kKey);
  const auto context = Parameter<Context>(Descriptor::kContext);

  ThrowIfNotInstanceType(context, receiver, JS_MAP_TYPE,
                         "Map.prototype.delete");

  const TNode<OrderedHashMap> table =
      LoadObjectField<OrderedHashMap>(CAST(receiver), JSMap::kTableOffset);

  TVARIABLE(IntPtrT, entry_start_position_or_hash, IntPtrConstant(0));
  Label entry_found(this), not_found(this);

  TryLookupOrderedHashTableIndex<OrderedHashMap>(
      table, key, &entry_start_position_or_hash, &entry_found, &not_found);

  BIND(&not_found);
  Return(FalseConstant());

  BIND(&entry_found);
  // If we found the entry, mark the entry as deleted.
  StoreKeyValueInOrderedHashMapEntry(table, HashTableHoleConstant(),
                                     HashTableHoleConstant(),
                                     entry_start_position_or_hash.value());

  // Decrement the number of elements, increment the number of deleted elements.
  const TNode<Smi> number_of_elements = SmiSub(
      CAST(LoadObjectField(table, OrderedHashMap::NumberOfElementsOffset())),
      SmiConstant(1));
  StoreObjectFieldNoWriteBarrier(
      table, OrderedHashMap::NumberOfElementsOffset(), number_of_elements);
  const TNode<Smi> number_of_deleted =
      SmiAdd(CAST(LoadObjectField(
                 table, OrderedHashMap::NumberOfDeletedElementsOffset())),
             SmiConstant(1));
  StoreObjectFieldNoWriteBarrier(
      table, OrderedHashMap::NumberOfDeletedElementsOffset(),
      number_of_deleted);

  const TNode<Smi> number_of_buckets = CAST(
      LoadFixedArrayElement(table, OrderedHashMap::NumberOfBucketsIndex()));

  // If there fewer elements than #buckets / 2, shrink the table.
  Label shrink(this);
  GotoIf(SmiLessThan(SmiAdd(number_of_elements, number_of_elements),
                     number_of_buckets),
         &shrink);
  Return(TrueConstant());

  BIND(&shrink);
  CallRuntime(Runtime::kMapShrink, context, receiver);
  Return(TrueConstant());
}

TF_BUILTIN(SetPrototypeAdd, CollectionsBuiltinsAssembler) {
  const auto receiver = Parameter<Object>(Descriptor::kReceiver);
  auto key = Parameter<Object>(Descriptor::kKey);
  const auto context = Parameter<Context>(Descriptor::kContext);

  ThrowIfNotInstanceType(context, receiver, JS_SET_TYPE, "Set.prototype.add");

  key = NormalizeNumberKey(key);

  GrowCollection<OrderedHashSet> grow = [this, context, receiver]() {
    CallRuntime(Runtime::kSetGrow, context, receiver);
    return LoadObjectField<OrderedHashSet>(CAST(receiver), JSSet::kTableOffset);
  };

  StoreAtEntry<OrderedHashSet> store_at_new_entry =
      [this, key](const TNode<OrderedHashSet> table,
                  const TNode<IntPtrT> entry_start) {
        UnsafeStoreKeyInOrderedHashSetEntry(table, key, entry_start);
      };

  StoreAtEntry<OrderedHashSet> store_at_existing_entry =
      [](const TNode<OrderedHashSet>, const TNode<IntPtrT>) {
        // If the entry was found, there is nothing to do.
      };

  const TNode<OrderedHashSet> table =
      LoadObjectField<OrderedHashSet>(CAST(receiver), JSSet::kTableOffset);
  AddToOrderedHashTable(table, key, grow, store_at_new_entry,
                        store_at_existing_entry);
  Return(receiver);
}

TNode<OrderedHashSet> CollectionsBuiltinsAssembler::AddToSetTable(
    const TNode<Object> context, TNode<OrderedHashSet> table, TNode<Object> key,
    TNode<String> method_name) {
  key = NormalizeNumberKey(key);

  GrowCollection<OrderedHashSet> grow = [this, context, table, method_name]() {
    TNode<OrderedHashSet> new_table = Cast(
        CallRuntime(Runtime::kOrderedHashSetGrow, context, table, method_name));
    // TODO(v8:13556): check if the table is updated and remove pointer to the
    // new table.
    return new_table;
  };

  StoreAtEntry<OrderedHashSet> store_at_new_entry =
      [this, key](const TNode<OrderedHashSet> table,
                  const TNode<IntPtrT> entry_start) {
        UnsafeStoreKeyInOrderedHashSetEntry(table, key, entry_start);
      };

  StoreAtEntry<OrderedHashSet> store_at_existing_entry =
      [](const TNode<OrderedHashSet>, const TNode<IntPtrT>) {
        // If the entry was found, there is nothing to do.
      };

  return AddToOrderedHashTable(table, key, grow, store_at_new_entry,
                               store_at_existing_entry);
}

void CollectionsBuiltinsAssembler::StoreKeyInOrderedHashSetEntry(
    const TNode<OrderedHashSet> table, const TNode<Object> key,
    const TNode<IntPtrT> entry_start, CheckBounds check_bounds) {
  StoreFixedArrayElement(table, entry_start, key, UPDATE_WRITE_BARRIER,
                         kTaggedSize * OrderedHashSet::HashTableStartIndex(),
                         check_bounds);
}

template <typename CollectionType>
TNode<Object> CollectionsBuiltinsAssembler::LoadKeyFromOrderedHashTableEntry(
    const TNode<CollectionType> table, const TNode<IntPtrT> entry,
    CheckBounds check_bounds) {
  return LoadFixedArrayElement(
      table, entry, kTaggedSize * CollectionType::HashTableStartIndex(),
      check_bounds);
}

TNode<Object> CollectionsBuiltinsAssembler::LoadValueFromOrderedHashMapEntry(
    const TNode<OrderedHashMap> table, const TNode<IntPtrT> entry,
    CheckBounds check_bounds) {
  return LoadFixedArrayElement(
      table, entry,
      kTaggedSize * (OrderedHashMap::HashTableStartIndex() +
                     OrderedHashMap::kValueOffset),
      check_bounds);
}

TF_BUILTIN(SetPrototypeDelete, CollectionsBuiltinsAssembler) {
  const auto receiver = Parameter<Object>(Descriptor::kReceiver);
  const auto key = Parameter<Object>(Descriptor::kKey);
  const auto context = Parameter<Context>(Descriptor::kContext);

  ThrowIfNotInstanceType(context, receiver, JS_SET_TYPE,
                         "Set.prototype.delete");

  // This check breaks a known exploitation technique. See crbug.com/1263462
  CSA_HOLE_SECURITY_CHECK(this, TaggedNotEqual(key, HashTableHoleConstant()));

  const TNode<OrderedHashSet> table =
      LoadObjectField<OrderedHashSet>(CAST(receiver), JSMap::kTableOffset);

  Label not_found(this);
  const TNode<Smi> number_of_elements =
      DeleteFromSetTable(context, table, key, &not_found);

  const TNode<Smi> number_of_buckets = CAST(
      LoadFixedArrayElement(table, OrderedHashSet::NumberOfBucketsIndex()));

  // If there fewer elements than #buckets / 2, shrink the table.
  Label shrink(this);
  GotoIf(SmiLessThan(SmiAdd(number_of_elements, number_of_elements),
                     number_of_buckets),
         &shrink);
  Return(TrueConstant());

  BIND(&shrink);
  CallRuntime(Runtime::kSetShrink, context, receiver);
  Return(TrueConstant());

  BIND(&not_found);
  Return(FalseConstant());
}

TNode<Smi> CollectionsBuiltinsAssembler::DeleteFromSetTable(
    const TNode<Object> context, TNode<OrderedHashSet> table, TNode<Object> key,
    Label* not_found) {
  TVARIABLE(IntPtrT, entry_start_position_or_hash, IntPtrConstant(0));
  Label entry_found(this);

  TryLookupOrderedHashTableIndex<OrderedHashSet>(
      table, key, &entry_start_position_or_hash, &entry_found, not_found);

  BIND(&entry_found);
  // If we found the entry, mark the entry as deleted.
  StoreKeyInOrderedHashSetEntry(table, HashTableHoleConstant(),
                                entry_start_position_or_hash.value());

  // Decrement the number of elements, increment the number of deleted elements.
  const TNode<Smi> number_of_elements = SmiSub(
      CAST(LoadObjectField(table, OrderedHashSet::NumberOfElementsOffset())),
      SmiConstant(1));
  StoreObjectFieldNoWriteBarrier(
      table, OrderedHashSet::NumberOfElementsOffset(), number_of_elements);
  const TNode<Smi> number_of_deleted =
      SmiAdd(CAST(LoadObjectField(
                 table, OrderedHashSet::NumberOfDeletedElementsOffset())),
             SmiConstant(1));
  StoreObjectFieldNoWriteBarrier(
      table, OrderedHashSet::NumberOfDeletedElementsOffset(),
      number_of_deleted);

  return number_of_elements;
}

TF_BUILTIN(MapPrototypeEntries, CollectionsBuiltinsAssembler) {
  const auto receiver = Parameter<Object>(Descriptor::kReceiver);
  const auto context = Parameter<Context>(Descriptor::kContext);
  ThrowIfNotInstanceType(context, receiver, JS_MAP_TYPE,
                         "Map.prototype.entries");
  Return(AllocateJSCollectionIterator<JSMapIterator>(
      context, Context::MAP_KEY_VALUE_ITERATOR_MAP_INDEX, CAST(receiver)));
}

TF_BUILTIN(MapPrototypeGetSize, CollectionsBuiltinsAssembler) {
  const auto receiver = Parameter<Object>(Descriptor::kReceiver);
  const auto context = Parameter<Context>(Descriptor::kContext);
  ThrowIfNotInstanceType(context, receiver, JS_MAP_TYPE,
                         "get Map.prototype.size");
  const TNode<OrderedHashMap> table =
      LoadObjectField<OrderedHashMap>(CAST(receiver), JSMap::kTableOffset);
  Return(LoadObjectField(table, OrderedHashMap::NumberOfElementsOffset()));
}

TF_BUILTIN(MapPrototypeForEach, CollectionsBuiltinsAssembler) {
  const char* const kMethodName = "Map.prototype.forEach";
  auto argc = UncheckedParameter<Int32T>(Descriptor::kJSActualArgumentsCount);
  const auto context = Parameter<Context>(Descriptor::kContext);
  CodeStubArguments args(this, argc);
  const TNode<Object> receiver = args.GetReceiver();
  const TNode<Object> callback = args.GetOptionalArgumentValue(0);
  const TNode<Object> this_arg = args.GetOptionalArgumentValue(1);

  ThrowIfNotInstanceType(context, receiver, JS_MAP_TYPE, kMethodName);

  // Ensure that {callback} is actually callable.
  Label callback_not_callable(this, Label::kDeferred);
  GotoIf(TaggedIsSmi(callback), &callback_not_callable);
  GotoIfNot(IsCallable(CAST(callback)), &callback_not_callable);

  TVARIABLE(IntPtrT, var_index, IntPtrConstant(0));
  TVARIABLE(OrderedHashMap, var_table,
            CAST(LoadObjectField(CAST(receiver), JSMap::kTableOffset)));
  Label loop(this, {&var_index, &var_table}), done_loop(this);
  Goto(&loop);
  BIND(&loop);
  {
    // Transition {table} and {index} if there was any modification to
    // the {receiver} while we're iterating.
    TNode<IntPtrT> index = var_index.value();
    TNode<OrderedHashMap> table = var_table.value();
    std::tie(table, index) = Transition<OrderedHashMap>(
        table, index, [](const TNode<OrderedHashMap>, const TNode<IntPtrT>) {});

    // Read the next entry from the {table}, skipping holes.
    TNode<Object> entry_key;
    TNode<IntPtrT> entry_start_position;
    std::tie(entry_key, entry_start_position, index) =
        NextSkipHashTableHoles<OrderedHashMap>(table, index, &done_loop);

    // Load the entry value as well.
    TNode<Object> entry_value =
        LoadValueFromOrderedHashMapEntry(table, entry_start_position);

    // Invoke the {callback} passing the {entry_key}, {entry_value} and the
    // {receiver}.
    Call(context, callback, this_arg, entry_value, entry_key, receiver);

    // Continue with the next entry.
    var_index = index;
    var_table = table;
    Goto(&loop);
  }

  BIND(&done_loop);
  args.PopAndReturn(UndefinedConstant());

  BIND(&callback_not_callable);
  {
    CallRuntime(Runtime::kThrowCalledNonCallable, context, callback);
    Unreachable();
  }
}

TF_BUILTIN(MapPrototypeKeys, CollectionsBuiltinsAssembler) {
  const auto receiver = Parameter<Object>(Descriptor::kReceiver);
  const auto context = Parameter<Context>(Descriptor::kContext);
  ThrowIfNotInstanceType(context, receiver, JS_MAP_TYPE, "Map.prototype.keys");
  Return(AllocateJSCollectionIterator<JSMapIterator>(
      context, Context::MAP_KEY_ITERATOR_MAP_INDEX, CAST(receiver)));
}

TF_BUILTIN(MapPrototypeValues, CollectionsBuiltinsAssembler) {
  const auto receiver = Parameter<Object>(Descriptor::kReceiver);
  const auto context = Parameter<Context>(Descriptor::kContext);
  ThrowIfNotInstanceType(context, receiver, JS_MAP_TYPE,
                         "Map.prototype.values");
  Return(AllocateJSCollectionIterator<JSMapIterator>(
      context, Context::MAP_VALUE_ITERATOR_MAP_INDEX, CAST(receiver)));
}

TF_BUILTIN(MapIteratorPrototypeNext, CollectionsBuiltinsAssembler) {
  const char* const kMethodName = "Map Iterator.prototype.next";
  const auto maybe_receiver = Parameter<Object>(Descriptor::kReceiver);
  const auto context = Parameter<Context>(Descriptor::kContext);

  // Ensure that {maybe_receiver} is actually a JSMapIterator.
  Label if_receiver_valid(this), if_receiver_invalid(this, Label::kDeferred);
  GotoIf(TaggedIsSmi(maybe_receiver), &if_receiver_invalid);
  const TNode<Uint16T> receiver_instance_type =
      LoadInstanceType(CAST(maybe_receiver));
  GotoIf(
      InstanceTypeEqual(receiver_instance_type, JS_MAP_KEY_VALUE_ITERATOR_TYPE),
      &if_receiver_valid);
  GotoIf(InstanceTypeEqual(receiver_instance_type, JS_MAP_KEY_ITERATOR_TYPE),
         &if_receiver_valid);
  Branch(InstanceTypeEqual(receiver_instance_type, JS_MAP_VALUE_ITERATOR_TYPE),
         &if_receiver_valid, &if_receiver_invalid);
  BIND(&if_receiver_invalid);
  ThrowTypeError(context, MessageTemplate::kIncompatibleMethodReceiver,
                 StringConstant(kMethodName), maybe_receiver);
  BIND(&if_receiver_valid);
  TNode<JSMapIterator> receiver = CAST(maybe_receiver);

  // Check if the {receiver} is exhausted.
  TVARIABLE(Boolean, var_done, TrueConstant());
  TVARIABLE(Object, var_value, UndefinedConstant());
  Label return_value(this, {&var_done, &var_value}), return_entry(this),
      return_end(this, Label::kDeferred);

  // Transition the {receiver} table if necessary.
  TNode<OrderedHashMap> table;
  TNode<IntPtrT> index;
  std::tie(table, index) =
      TransitionAndUpdate<JSMapIterator, OrderedHashMap>(receiver);

  // Read the next entry from the {table}, skipping holes.
  TNode<Object> entry_key;
  TNode<IntPtrT> entry_start_position;
  std::tie(entry_key, entry_start_position, index) =
      NextSkipHashTableHoles<OrderedHashMap>(table, index, &return_end);
  StoreObjectFieldNoWriteBarrier(receiver, JSMapIterator::kIndexOffset,
                                 SmiTag(index));
  var_value = entry_key;
  var_done = FalseConstant();

  // Check how to return the {key} (depending on {receiver} type).
  GotoIf(InstanceTypeEqual(receiver_instance_type, JS_MAP_KEY_ITERATOR_TYPE),
         &return_value);
  var_value = LoadValueFromOrderedHashMapEntry(table, entry_start_position);
  Branch(InstanceTypeEqual(receiver_instance_type, JS_MAP_VALUE_ITERATOR_TYPE),
         &return_value, &return_entry);

  BIND(&return_entry);
  {
    TNode<JSObject> result =
        AllocateJSIteratorResultForEntry(context, entry_key, var_value.value());
    Return(result);
  }

  BIND(&return_value);
  {
    TNode<JSObject> result =
        AllocateJSIteratorResult(context, var_value.value(), var_done.value());
    Return(result);
  }

  BIND(&return_end);
  {
    StoreObjectFieldRoot(receiver, JSMapIterator::kTableOffset,
                         RootIndex::kEmptyOrderedHashMap);
    Goto(&return_value);
  }
}

TF_BUILTIN(SetPrototypeHas, CollectionsBuiltinsAssembler) {
  const auto receiver = Parameter<Object>(Descriptor::kReceiver);
  const auto key = Parameter<Object>(Descriptor::kKey);
  const auto context = Parameter<Context>(Descriptor::kContext);

  ThrowIfNotInstanceType(context, receiver, JS_SET_TYPE, "Set.prototype.has");

  const TNode<OrderedHashSet> table =
      CAST(LoadObjectField(CAST(receiver), JSMap::kTableOffset));

  Label if_found(this), if_not_found(this);
  Branch(TableHasKey(context, table, key), &if_found, &if_not_found);

  BIND(&if_found);
  Return(TrueConstant());

  BIND(&if_not_found);
  Return(FalseConstant());
}

TNode<BoolT> CollectionsBuiltinsAssembler::TableHasKey(
    const TNode<Object> context, TNode<OrderedHashSet> table,
    TNode<Object> key) {
  TNode<Smi> index =
      CAST(CallBuiltin(Builtin::kFindOrderedHashSetEntry, context, table, key));

  return SmiGreaterThanOrEqual(index, SmiConstant(0));
}

TF_BUILTIN(SetPrototypeEntries, CollectionsBuiltinsAssembler) {
  const auto receiver = Parameter<Object>(Descriptor::kReceiver);
  const auto context = Parameter<Context>(Descriptor::kContext);
  ThrowIfNotInstanceType(context, receiver, JS_SET_TYPE,
                         "Set.prototype.entries");
  Return(AllocateJSCollectionIterator<JSSetIterator>(
      context, Context::SET_KEY_VALUE_ITERATOR_MAP_INDEX, CAST(receiver)));
}

TF_BUILTIN(SetPrototypeGetSize, CollectionsBuiltinsAssembler) {
  const auto receiver = Parameter<Object>(Descriptor::kReceiver);
  const auto context = Parameter<Context>(Descriptor::kContext);
  ThrowIfNotInstanceType(context, receiver, JS_SET_TYPE,
                         "get Set.prototype.size");
  const TNode<OrderedHashSet> table =
      LoadObjectField<OrderedHashSet>(CAST(receiver), JSSet::kTableOffset);
  Return(LoadObjectField(table, OrderedHashSet::NumberOfElementsOffset()));
}

TF_BUILTIN(SetPrototypeForEach, CollectionsBuiltinsAssembler) {
  const char* const kMethodName = "Set.prototype.forEach";
  auto argc = UncheckedParameter<Int32T>(Descriptor::kJSActualArgumentsCount);
  const auto context = Parameter<Context>(Descriptor::kContext);
  CodeStubArguments args(this, argc);
  const TNode<Object> receiver = args.GetReceiver();
  const TNode<Object> callback = args.GetOptionalArgumentValue(0);
  const TNode<Object> this_arg = args.GetOptionalArgumentValue(1);

  ThrowIfNotInstanceType(context, receiver, JS_SET_TYPE, kMethodName);

  // Ensure that {callback} is actually callable.
  Label callback_not_callable(this, Label::kDeferred);
  GotoIf(TaggedIsSmi(callback), &callback_not_callable);
  GotoIfNot(IsCallable(CAST(callback)), &callback_not_callable);

  TVARIABLE(IntPtrT, var_index, IntPtrConstant(0));
  TVARIABLE(OrderedHashSet, var_table,
            CAST(LoadObjectField(CAST(receiver), JSSet::kTableOffset)));
  Label loop(this, {&var_index, &var_table}), done_loop(this);
  Goto(&loop);
  BIND(&loop);
  {
    // Transition {table} and {index} if there was any modification to
    // the {receiver} while we're iterating.
    TNode<IntPtrT> index = var_index.value();
    TNode<OrderedHashSet> table = var_table.value();
    std::tie(table, index) = Transition<OrderedHashSet>(
        table, index, [](const TNode<OrderedHashSet>, const TNode<IntPtrT>) {});

    // Read the next entry from the {table}, skipping holes.
    TNode<Object> entry_key;
    TNode<IntPtrT> entry_start_position;
    std::tie(entry_key, entry_start_position, index) =
        NextSkipHashTableHoles<OrderedHashSet>(table, index, &done_loop);

    // Invoke the {callback} passing the {entry_key} (twice) and the {receiver}.
    Call(context, callback, this_arg, entry_key, entry_key, receiver);

    // Continue with the next entry.
    var_index = index;
    var_table = table;
    Goto(&loop);
  }

  BIND(&done_loop);
  args.PopAndReturn(UndefinedConstant());

  BIND(&callback_not_callable);
  {
    CallRuntime(Runtime::kThrowCalledNonCallable, context, callback);
    Unreachable();
  }
}

TF_BUILTIN(SetPrototypeValues, CollectionsBuiltinsAssembler) {
  const auto receiver = Parameter<Object>(Descriptor::kReceiver);
  const auto context = Parameter<Context>(Descriptor::kContext);
  ThrowIfNotInstanceType(context, receiver, JS_SET_TYPE,
                         "Set.prototype.values");
  Return(AllocateJSCollectionIterator<JSSetIterator>(
      context, Context::SET_VALUE_ITERATOR_MAP_INDEX, CAST(receiver)));
}

TF_BUILTIN(SetIteratorPrototypeNext, CollectionsBuiltinsAssembler) {
  const char* const kMethodName = "Set Iterator.prototype.next";
  const auto maybe_receiver = Parameter<Object>(Descriptor::kReceiver);
  const auto context = Parameter<Context>(Descriptor::kContext);

  // Ensure that {maybe_receiver} is actually a JSSetIterator.
  Label if_receiver_valid(this), if_receiver_invalid(this, Label::kDeferred);
  GotoIf(TaggedIsSmi(maybe_receiver), &if_receiver_invalid);
  const TNode<Uint16T> receiver_instance_type =
      LoadInstanceType(CAST(maybe_receiver));
  GotoIf(InstanceTypeEqual(receiver_instance_type, JS_SET_VALUE_ITERATOR_TYPE),
         &if_receiver_valid);
  Branch(
      InstanceTypeEqual(receiver_instance_type, JS_SET_KEY_VALUE_ITERATOR_TYPE),
      &if_receiver_valid, &if_receiver_invalid);
  BIND(&if_receiver_invalid);
  ThrowTypeError(context, MessageTemplate::kIncompatibleMethodReceiver,
                 StringConstant(kMethodName), maybe_receiver);
  BIND(&if_receiver_valid);

  TNode<JSSetIterator> receiver = CAST(maybe_receiver);

  // Check if the {receiver} is exhausted.
  TVARIABLE(Boolean, var_done, TrueConstant());
  TVARIABLE(Object, var_value, UndefinedConstant());
  Label return_value(this, {&var_done, &var_value}), return_entry(this),
      return_end(this, Label::kDeferred);

  // Transition the {receiver} table if necessary.
  TNode<OrderedHashSet> table;
  TNode<IntPtrT> index;
  std::tie(table, index) =
      TransitionAndUpdate<JSSetIterator, OrderedHashSet>(receiver);

  // Read the next entry from the {table}, skipping holes.
  TNode<Object> entry_key;
  TNode<IntPtrT> entry_start_position;
  std::tie(entry_key, entry_start_position, index) =
      NextSkipHashTableHoles<OrderedHashSet>(table, index, &return_end);
  StoreObjectFieldNoWriteBarrier(receiver, JSSetIterator::kIndexOffset,
                                 SmiTag(index));
  var_value = entry_key;
  var_done = FalseConstant();

  // Check how to return the {key} (depending on {receiver} type).
  Branch(InstanceTypeEqual(receiver_instance_type, JS_SET_VALUE_ITERATOR_TYPE),
         &return_value, &return_entry);

  BIND(&return_entry);
  {
    TNode<JSObject> result = AllocateJSIteratorResultForEntry(
        context, var_value.value(), var_value.value());
    Return(result);
  }

  BIND(&return_value);
  {
    TNode<JSObject> result =
        AllocateJSIteratorResult(context, var_value.value(), var_done.value());
    Return(result);
  }

  BIND(&return_end);
  {
    StoreObjectFieldRoot(receiver, JSSetIterator::kTableOffset,
                         RootIndex::kEmptyOrderedHashSet);
    Goto(&return_value);
  }
}

template <typename CollectionType>
void CollectionsBuiltinsAssembler::TryLookupOrderedHashTableIndex(
    const TNode<CollectionType> table, const TNode<Object> key,
    TVariable<IntPtrT>* result, Label* if_entry_found, Label* if_not_found) {
  Label if_key_smi(this), if_key_string(this), if_key_heap_number(this),
      if_key_bigint(this);

  GotoIf(TaggedIsSmi(key), &if_key_smi);

  TNode<Map> key_map = LoadMap(CAST(key));
  TNode<Uint16T> key_instance_type = LoadMapInstanceType(key_map);

  GotoIf(IsStringInstanceType(key_instance_type), &if_key_string);
  GotoIf(IsHeapNumberMap(key_map), &if_key_heap_number);
  GotoIf(IsBigIntInstanceType(key_instance_type), &if_key_bigint);

  FindOrderedHashTableEntryForOtherKey<CollectionType>(
      table, CAST(key), result, if_entry_found, if_not_found);

  BIND(&if_key_smi);
  {
    FindOrderedHashTableEntryForSmiKey<CollectionType>(
        table, CAST(key), result, if_entry_found, if_not_found);
  }

  BIND(&if_key_string);
  {
    FindOrderedHashTableEntryForStringKey<CollectionType>(
        table, CAST(key), result, if_entry_found, if_not_found);
  }

  BIND(&if_key_heap_number);
  {
    FindOrderedHashTableEntryForHeapNumberKey<CollectionType>(
        table, CAST(key), result, if_entry_found, if_not_found);
  }

  BIND(&if_key_bigint);
  {
    FindOrderedHashTableEntryForBigIntKey<CollectionType>(
        table, CAST(key), result, if_entry_found, if_not_found);
  }
}

TF_BUILTIN(FindOrderedHashMapEntry, CollectionsBuiltinsAssembler) {
  const auto table = Parameter<OrderedHashMap>(Descriptor::kTable);
  const auto key = Parameter<Object>(Descriptor::kKey);

  TVARIABLE(IntPtrT, entry_start_position, IntPtrConstant(0));
  Label entry_found(this), not_found(this);

  TryLookupOrderedHashTableIndex<OrderedHashMap>(
      table, key, &entry_start_position, &entry_found, &not_found);

  BIND(&entry_found);
  Return(SmiTag(entry_start_position.value()));

  BIND(&not_found);
  Return(SmiConstant(-1));
}

TF_BUILTIN(FindOrderedHashSetEntry, CollectionsBuiltinsAssembler) {
  const auto table = Parameter<OrderedHashSet>(Descriptor::kTable);
  const auto key = Parameter<Object>(Descriptor::kKey);

  TVARIABLE(IntPtrT, entry_start_position, IntPtrConstant(0));
  Label entry_found(this), not_found(this);

  TryLookupOrderedHashTableIndex<OrderedHashSet>(
      table, key, &entry_start_position, &entry_found, &not_found);

  BIND(&entry_found);
  Return(SmiTag(entry_start_position.value()));

  BIND(&not_found);
  Return(SmiConstant(-1));
}

const TNode<OrderedHashMap> CollectionsBuiltinsAssembler::AddValueToKeyedGroup(
    const TNode<OrderedHashMap> groups, const TNode<Object> key,
    const TNode<Object> value, const TNode<String> methodName) {
  GrowCollection<OrderedHashMap> grow = [this, groups, methodName]() {
    TNode<OrderedHashMap> new_groups = CAST(CallRuntime(
        Runtime::kOrderedHashMapGrow, NoContextConstant(), groups, methodName));
    // The groups OrderedHashMap is not escaped to user script while grouping
    // items, so there can't be live iterators. So we don't need to keep the
    // pointer from the old table to the new one.
    Label did_grow(this), done(this);
    Branch(TaggedEqual(groups, new_groups), &done, &did_grow);
    BIND(&did_grow);
    {
      StoreObjectFieldNoWriteBarrier(groups, OrderedHashMap::NextTableOffset(),
                                     SmiConstant(0));
      Goto(&done);
    }
    BIND(&done);
    return new_groups;
  };

  StoreAtEntry<OrderedHashMap> store_at_new_entry =
      [this, key, value](const TNode<OrderedHashMap> table,
                         const TNode<IntPtrT> entry_start) {
        TNode<ArrayList> array = AllocateArrayList(SmiConstant(1));
        ArrayListSet(array, SmiConstant(0), value);
        ArrayListSetLength(array, SmiConstant(1));
        StoreKeyValueInOrderedHashMapEntry(table, key, array, entry_start);
      };

  StoreAtEntry<OrderedHashMap> store_at_existing_entry =
      [this, key, value](const TNode<OrderedHashMap> table,
                         const TNode<IntPtrT> entry_start) {
        TNode<ArrayList> array =
            CAST(LoadValueFromOrderedHashMapEntry(table, entry_start));
        TNode<ArrayList> new_array = ArrayListAdd(array, value);
        StoreKeyValueInOrderedHashMapEntry(table, key, new_array, entry_start);
      };

  return AddToOrderedHashTable(groups, key, grow, store_at_new_entry,
                               store_at_existing_entry);
}

void WeakCollectionsBuiltinsAssembler::AddEntry(
    TNode<EphemeronHashTable> table, TNode<IntPtrT> key_index,
    TNode<Object> key, TNode<Object> value, TNode<Int32T> number_of_elements) {
  // See EphemeronHashTable::AddEntry().
  TNode<IntPtrT> value_index = ValueIndexFromKeyIndex(key_index);
  UnsafeStoreFixedArrayElement(table, key_index, key,
                               UPDATE_EPHEMERON_KEY_WRITE_BARRIER);
  UnsafeStoreFixedArrayElement(table, value_index, value);

  // See HashTableBase::ElementAdded().
  UnsafeStoreFixedArrayElement(table,
                               EphemeronHashTable::kNumberOfElementsIndex,
                               SmiFromInt32(number_of_elements));
}

TNode<IntPtrT> WeakCollectionsBuiltinsAssembler::GetHash(
    const TNode<HeapObject> key, Label* if_no_hash) {
  TVARIABLE(IntPtrT, var_hash);
  Label if_symbol(this);
  Label return_result(this);
  GotoIfNot(IsJSReceiver(key), &if_symbol);
  var_hash = Signed(
      ChangeUint32ToWord(LoadJSReceiverIdentityHash(CAST(key), if_no_hash)));
  Goto(&return_result);
  Bind(&if_symbol);
  CSA_DCHECK(this, IsSymbol(key));
  CSA_DCHECK(this, Word32BinaryNot(
                       Word32And(LoadSymbolFlags(CAST(key)),
                                 Symbol::IsInPublicSymbolTableBit::kMask)));
  var_hash = Signed(ChangeUint32ToWord(LoadNameHash(CAST(key), nullptr)));
  Goto(&return_result);
  Bind(&return_result);
  return var_hash.value();
}

TNode<HeapObject> WeakCollectionsBuiltinsAssembler::AllocateTable(
    Variant variant, TNode<IntPtrT> at_least_space_for) {
  // See HashTable::New().
  DCHECK(variant == kWeakSet || variant == kWeakMap);
  CSA_DCHECK(this,
             IntPtrLessThanOrEqual(IntPtrConstant(0), at_least_space_for));
  TNode<IntPtrT> capacity = HashTableComputeCapacity(at_least_space_for);

  // See HashTable::NewInternal().
  TNode<IntPtrT> length = KeyIndexFromEntry(capacity);
  TNode<FixedArray> table = CAST(AllocateFixedArray(HOLEY_ELEMENTS, length));

  TNode<Map> map =
      HeapConstantNoHole(EphemeronHashTable::GetMap(ReadOnlyRoots(isolate())));
  StoreMapNoWriteBarrier(table, map);
  StoreFixedArrayElement(table, EphemeronHashTable::kNumberOfElementsIndex,
                         SmiConstant(0), SKIP_WRITE_BARRIER);
  StoreFixedArrayElement(table,
                         EphemeronHashTable::kNumberOfDeletedElementsIndex,
                         SmiConstant(0), SKIP_WRITE_BARRIER);
  StoreFixedArrayElement(table, EphemeronHashTable::kCapacityIndex,
                         SmiFromIntPtr(capacity), SKIP_WRITE_BARRIER);

  TNode<IntPtrT> start = KeyIndexFromEntry(IntPtrConstant(0));
  FillFixedArrayWithValue(HOLEY_ELEMENTS, table, start, length,
                          RootIndex::kUndefinedValue);
  return table;
}

TNode<Smi> WeakCollectionsBuiltinsAssembler::CreateIdentityHash(
    TNode<Object> key) {
  TNode<ExternalReference> function_addr =
      ExternalConstant(ExternalReference::jsreceiver_create_identity_hash());
  TNode<ExternalReference> isolate_ptr =
      ExternalConstant(ExternalReference::isolate_address());

  MachineType type_ptr = MachineType::Pointer();
  MachineType type_tagged = MachineType::AnyTagged();

  return CAST(CallCFunction(function_addr, type_tagged,
                            std::make_pair(type_ptr, isolate_ptr),
                            std::make_pair(type_tagged, key)));
}

TNode<IntPtrT> WeakCollectionsBuiltinsAssembler::EntryMask(
    TNode<IntPtrT> capacity) {
  return IntPtrSub(capacity, IntPtrConstant(1));
}

TNode<IntPtrT> WeakCollectionsBuiltinsAssembler::Coefficient(
    TNode<IntPtrT> capacity) {
  TVARIABLE(IntPtrT, coeff, IntPtrConstant(1));
  Label done(this, &coeff);
  GotoIf(IntPtrLessThan(capacity,
                        IntPtrConstant(1 << PropertyArray::HashField::kSize)),
         &done);
  coeff = Signed(
      WordShr(capacity, IntPtrConstant(PropertyArray::HashField::kSize)));
  Goto(&done);
  BIND(&done);
  return coeff.value();
}

TNode<IntPtrT> WeakCollectionsBuiltinsAssembler::FindKeyIndex(
    TNode<HeapObject> table, TNode<IntPtrT> key_hash, TNode<IntPtrT> capacity,
    const KeyComparator& key_compare) {
  // See HashTable::FirstProbe().
  TNode<IntPtrT> entry_mask = EntryMask(capacity);
  TVARIABLE(IntPtrT, var_entry,
            WordAnd(IntPtrMul(key_hash, Coefficient(capacity)), entry_mask));
  TVARIABLE(IntPtrT, var_count, IntPtrConstant(0));

  Label loop(this, {&var_count, &var_entry}), if_found(this);
  Goto(&loop);
  BIND(&loop);
  TNode<IntPtrT> key_index;
  {
    key_index = KeyIndexFromEntry(var_entry.value());
    TNode<Object> entry_key =
        UnsafeLoadFixedArrayElement(CAST(table), key_index);

    key_compare(entry_key, &if_found);

    // See HashTable::NextProbe().
    Increment(&var_count);
    var_entry =
        WordAnd(IntPtrAdd(var_entry.value(), var_count.value()), entry_mask);
    Goto(&loop);
  }

  BIND(&if_found);
  return key_index;
}

TNode<IntPtrT> WeakCollectionsBuiltinsAssembler::FindKeyIndexForInsertion(
    TNode<HeapObject> table, TNode<IntPtrT> key_hash, TNode<IntPtrT> capacity) {
  // See HashTable::FindInsertionEntry().
  auto is_not_live = [&](TNode<Object> entry_key, Label* if_found) {
    // This is the the negative form BaseShape::IsLive().
    GotoIf(Word32Or(IsTheHole(entry_key), IsUndefined(entry_key)), if_found);
  };
  return FindKeyIndex(table, key_hash, capacity, is_not_live);
}

TNode<IntPtrT> WeakCollectionsBuiltinsAssembler::FindKeyIndexForKey(
    TNode<HeapObject> table, TNode<Object> key, TNode<IntPtrT> hash,
    TNode<IntPtrT> capacity, Label* if_not_found) {
  // See HashTable::FindEntry().
  auto match_key_or_exit_on_empty = [&](TNode<Object> entry_key,
                                        Label* if_same) {
    GotoIf(IsUndefined(entry_key), if_not_found);
    GotoIf(TaggedEqual(entry_key, key), if_same);
  };
  return FindKeyIndex(table, hash, capacity, match_key_or_exit_on_empty);
}

TNode<IntPtrT> WeakCollectionsBuiltinsAssembler::KeyIndexFromEntry(
    TNode<IntPtrT> entry) {
  // See HashTable::KeyAt().
  // (entry * kEntrySize) + kElementsStartIndex + kEntryKeyIndex
  return IntPtrAdd(
      IntPtrMul(entry, IntPtrConstant(EphemeronHashTable::kEntrySize)),
      IntPtrConstant(EphemeronHashTable::kElementsStartIndex +
                     EphemeronHashTable::kEntryKeyIndex));
}

TNode<Int32T> WeakCollectionsBuiltinsAssembler::LoadNumberOfElements(
    TNode<EphemeronHashTable> table, int offset) {
  TNode<Int32T> number_of_elements =
      SmiToInt32(CAST(UnsafeLoadFixedArrayElement(
          table, EphemeronHashTable::kNumberOfElementsIndex)));
  return Int32Add(number_of_elements, Int32Constant(offset));
}

TNode<Int32T> WeakCollectionsBuiltinsAssembler::LoadNumberOfDeleted(
    TNode<EphemeronHashTable> table, int offset) {
  TNode<Int32T> number_of_deleted = SmiToInt32(CAST(UnsafeLoadFixedArrayElement(
      table, EphemeronHashTable::kNumberOfDeletedElementsIndex)));
  return Int32Add(number_of_deleted, Int32Constant(offset));
}

TNode<EphemeronHashTable> WeakCollectionsBuiltinsAssembler::LoadTable(
    TNode<JSWeakCollection> collection) {
  return CAST(LoadObjectField(collection, JSWeakCollection::kTableOffset));
}

TNode<IntPtrT> WeakCollectionsBuiltinsAssembler::LoadTableCapacity(
    TNode<EphemeronHashTable> table) {
  return PositiveSmiUntag(CAST(
      UnsafeLoadFixedArrayElement(table, EphemeronHashTable::kCapacityIndex)));
}

TNode<Word32T> WeakCollectionsBuiltinsAssembler::InsufficientCapacityToAdd(
    TNode<Int32T> capacity, TNode<Int32T> number_of_elements,
    TNode<Int32T> number_of_deleted) {
  // This is the negative form of HashTable::HasSufficientCapacityToAdd().
  // Return true if:
  //   - more than 50% of the available space are deleted elements
  //   - less than 50% will be available
  TNode<Int32T> available = Int32Sub(capacity, number_of_elements);
  TNode<Int32T> half_available = Signed(Word32Shr(available, 1));
  TNode<Int32T> needed_available = Signed(Word32Shr(number_of_elements, 1));
  return Word32Or(
      // deleted > half
      Int32GreaterThan(number_of_deleted, half_available),
      // elements + needed available > capacity
      Int32GreaterThan(Int32Add(number_of_elements, needed_available),
                       capacity));
}

void WeakCollectionsBuiltinsAssembler::RemoveEntry(
    TNode<EphemeronHashTable> table, TNode<IntPtrT> key_index,
    TNode<IntPtrT> number_of_elements) {
  // See EphemeronHashTable::RemoveEntry().
  TNode<IntPtrT> value_index = ValueIndexFromKeyIndex(key_index);
  StoreFixedArrayElement(table, key_index, TheHoleConstant());
  StoreFixedArrayElement(table, value_index, TheHoleConstant());

  // See HashTableBase::ElementRemoved().
  TNode<Int32T> number_of_deleted = LoadNumberOfDeleted(table, 1);
  StoreFixedArrayElement(table, EphemeronHashTable::kNumberOfElementsIndex,
                         SmiFromIntPtr(number_of_elements), SKIP_WRITE_BARRIER);
  StoreFixedArrayElement(table,
                         EphemeronHashTable::kNumberOfDeletedElementsIndex,
                         SmiFromInt32(number_of_deleted), SKIP_WRITE_BARRIER);
}

TNode<BoolT> WeakCollectionsBuiltinsAssembler::ShouldRehash(
    TNode<Int32T> number_of_elements, TNode<Int32T> number_of_deleted) {
  // Rehash if more than 33% of the entries are deleted.
  return Int32GreaterThanOrEqual(Word32Shl(number_of_deleted, 1),
                                 number_of_elements);
}

TNode<Word32T> WeakCollectionsBuiltinsAssembler::ShouldShrink(
    TNode<IntPtrT> capacity, TNode<IntPtrT> number_of_elements) {
  // See HashTable::Shrink().
  TNode<IntPtrT> quarter_capacity = WordShr(capacity, 2);
  return Word32And(
      // Shrink to fit the number of elements if only a quarter of the
      // capacity is filled with elements.
      IntPtrLessThanOrEqual(number_of_elements, quarter_capacity),

      // Allocate a new dictionary with room for at least the current
      // number of elements. The allocation method will make sure that
      // there is extra room in the dictionary for additions. Don't go
      // lower than room for 16 elements.
      IntPtrGreaterThanOrEqual(number_of_elements, IntPtrConstant(16)));
}

TNode<IntPtrT> WeakCollectionsBuiltinsAssembler::ValueIndexFromKeyIndex(
    TNode<IntPtrT> key_index) {
  return IntPtrAdd(
      key_index,
      IntPtrConstant(EphemeronHashTable::TodoShape::kEntryValueIndex -
                     EphemeronHashTable::kEntryKeyIndex));
}

TF_BUILTIN(WeakMapConstructor, WeakCollectionsBuiltinsAssembler) {
  auto new_target = Parameter<Object>(Descriptor::kJSNewTarget);
  TNode<IntPtrT> argc = ChangeInt32ToIntPtr(
      UncheckedParameter<Int32T>(Descriptor::kJSActualArgumentsCount));
  auto context = Parameter<Context>(Descriptor::kContext);

  GenerateConstructor(kWeakMap, isolate()->factory()->WeakMap_string(),
                      new_target, argc, context);
}

TF_BUILTIN(WeakSetConstructor, WeakCollectionsBuiltinsAssembler) {
  auto new_target = Parameter<Object>(Descriptor::kJSNewTarget);
  TNode<IntPtrT> argc = ChangeInt32ToIntPtr(
      UncheckedParameter<Int32T>(Descriptor::kJSActualArgumentsCount));
  auto context = Parameter<Context>(Descriptor::kContext);

  GenerateConstructor(kWeakSet, isolate()->factory()->WeakSet_string(),
                      new_target, argc, context);
}

TF_BUILTIN(WeakMapLookupHashIndex, WeakCollectionsBuiltinsAssembler) {
  auto table = Parameter<EphemeronHashTable>(Descriptor::kTable);
  auto key = Parameter<Object>(Descriptor::kKey);

  Label if_cannot_be_held_weakly(this);

  GotoIfCannotBeHeldWeakly(key, &if_cannot_be_held_weakly);

  TNode<IntPtrT> hash = GetHash(CAST(key), &if_cannot_be_held_weakly);
  TNode<IntPtrT> capacity = LoadTableCapacity(table);
  TNode<IntPtrT> key_index =
      FindKeyIndexForKey(table, key, hash, capacity, &if_cannot_be_held_weakly);
  Return(SmiTag(ValueIndexFromKeyIndex(key_index)));

  BIND(&if_cannot_be_held_weakly);
  Return(SmiConstant(-1));
}

TF_BUILTIN(WeakMapGet, WeakCollectionsBuiltinsAssembler) {
  const auto receiver = Parameter<Object>(Descriptor::kReceiver);
  const auto key = Parameter<Object>(Descriptor::kKey);
  const auto context = Parameter<Context>(Descriptor::kContext);

  Label return_undefined(this);

  ThrowIfNotInstanceType(context, receiver, JS_WEAK_MAP_TYPE,
                         "WeakMap.prototype.get");

  const TNode<EphemeronHashTable> table = LoadTable(CAST(receiver));
  const TNode<Smi> index =
      CAST(CallBuiltin(Builtin::kWeakMapLookupHashIndex, context, table, key));

  GotoIf(TaggedEqual(index, SmiConstant(-1)), &return_undefined);

  Return(LoadFixedArrayElement(table, SmiUntag(index)));

  BIND(&return_undefined);
  Return(UndefinedConstant());
}

TF_BUILTIN(WeakMapPrototypeHas, WeakCollectionsBuiltinsAssembler) {
  const auto receiver = Parameter<Object>(Descriptor::kReceiver);
  const auto key = Parameter<Object>(Descriptor::kKey);
  const auto context = Parameter<Context>(Descriptor::kContext);

  Label return_false(this);

  ThrowIfNotInstanceType(context, receiver, JS_WEAK_MAP_TYPE,
                         "WeakMap.prototype.has");

  const TNode<EphemeronHashTable> table = LoadTable(CAST(receiver));
  const TNode<Object> index =
      CallBuiltin(Builtin::kWeakMapLookupHashIndex, context, table, key);

  GotoIf(TaggedEqual(index, SmiConstant(-1)), &return_false);

  Return(TrueConstant());

  BIND(&return_false);
  Return(FalseConstant());
}

// Helper that removes the entry with a given key from the backing store
// (EphemeronHashTable) of a WeakMap or WeakSet.
TF_BUILTIN(WeakCollectionDelete, WeakCollectionsBuiltinsAssembler) {
  auto context = Parameter<Context>(Descriptor::kContext);
  auto collection = Parameter<JSWeakCollection>(Descriptor::kCollection);
  auto key = Parameter<Object>(Descriptor::kKey);

  Label call_runtime(this), if_cannot_be_held_weakly(this);

  GotoIfCannotBeHeldWeakly(key, &if_cannot_be_held_weakly);

  TNode<IntPtrT> hash = GetHash(CAST(key), &if_cannot_be_held_weakly);
  TNode<EphemeronHashTable> table = LoadTable(collection);
  TNode<IntPtrT> capacity = LoadTableCapacity(table);
  TNode<IntPtrT> key_index =
      FindKeyIndexForKey(table, key, hash, capacity, &if_cannot_be_held_weakly);
  TNode<Int32T> number_of_elements = LoadNumberOfElements(table, -1);
  GotoIf(ShouldShrink(capacity, ChangeInt32ToIntPtr(number_of_elements)),
         &call_runtime);

  RemoveEntry(table, key_index, ChangeInt32ToIntPtr(number_of_elements));
  Return(TrueConstant());

  BIND(&if_cannot_be_held_weakly);
  Return(FalseConstant());

  BIND(&call_runtime);
  Return(CallRuntime(Runtime::kWeakCollectionDelete, context, collection, key,
                     SmiTag(hash)));
}

// Helper that sets the key and value to the backing store (EphemeronHashTable)
// of a WeakMap or WeakSet.
TF_BUILTIN(WeakCollectionSet, WeakCollectionsBuiltinsAssembler) {
  auto context = Parameter<Context>(Descriptor::kContext);
  auto collection = Parameter<JSWeakCollection>(Descriptor::kCollection);
  auto key = Parameter<HeapObject>(Descriptor::kKey);
  auto value = Parameter<Object>(Descriptor::kValue);

  CSA_DCHECK(this, Word32Or(IsJSReceiver(key), IsSymbol(key)));

  Label call_runtime(this), if_no_hash(this), if_not_found(this);

  TNode<EphemeronHashTable> table = LoadTable(collection);
  TNode<IntPtrT> capacity = LoadTableCapacity(table);

  TVARIABLE(IntPtrT, var_hash, GetHash(key, &if_no_hash));
  TNode<IntPtrT> key_index =
      FindKeyIndexForKey(table, key, var_hash.value(), capacity, &if_not_found);

  StoreFixedArrayElement(table, ValueIndexFromKeyIndex(key_index), value);
  Return(collection);

  BIND(&if_no_hash);
  {
    CSA_DCHECK(this, IsJSReceiver(key));
    var_hash = SmiUntag(CreateIdentityHash(key));
    Goto(&if_not_found);
  }
  BIND(&if_not_found);
  {
    TNode<Int32T> number_of_deleted = LoadNumberOfDeleted(table);
    TNode<Int32T> number_of_elements = LoadNumberOfElements(table, 1);

    CSA_DCHECK(this,
               IntPtrLessThanOrEqual(capacity, IntPtrConstant(INT32_MAX)));
    CSA_DCHECK(this,
               IntPtrGreaterThanOrEqual(capacity, IntPtrConstant(INT32_MIN)));
    // TODO(pwong): Port HashTable's Rehash() and EnsureCapacity() to CSA.
    GotoIf(Word32Or(ShouldRehash(number_of_elements, number_of_deleted),
                    InsufficientCapacityToAdd(TruncateIntPtrToInt32(capacity),
                                              number_of_elements,
                                              number_of_deleted)),
           &call_runtime);

    TNode<IntPtrT> insertion_key_index =
        FindKeyIndexForInsertion(table, var_hash.value(), capacity);
    AddEntry(table, insertion_key_index, key, value, number_of_elements);
    Return(collection);
  }
  BIND(&call_runtime);
  {
    CallRuntime(Runtime::kWeakCollectionSet, context, collection, key, value,
                SmiTag(var_hash.value()));
    Return(collection);
  }
}

TF_BUILTIN(WeakMapPrototypeDelete, CodeStubAssembler) {
  auto context = Parameter<Context>(Descriptor::kContext);
  auto receiver = Parameter<Object>(Descriptor::kReceiver);
  auto key = Parameter<Object>(Descriptor::kKey);

  ThrowIfNotInstanceType(context, receiver, JS_WEAK_MAP_TYPE,
                         "WeakMap.prototype.delete");

  // This check breaks a known exploitation technique. See crbug.com/1263462
  CSA_HOLE_SECURITY_CHECK(this, TaggedNotEqual(key, TheHoleConstant()));

  Return(CallBuiltin(Builtin::kWeakCollectionDelete, context, receiver, key));
}

TF_BUILTIN(WeakMapPrototypeSet, WeakCollectionsBuiltinsAssembler) {
  auto context = Parameter<Context>(Descriptor::kContext);
  auto receiver = Parameter<Object>(Descriptor::kReceiver);
  auto key = Parameter<Object>(Descriptor::kKey);
  auto value = Parameter<Object>(Descriptor::kValue);

  ThrowIfNotInstanceType(context, receiver, JS_WEAK_MAP_TYPE,
                         "WeakMap.prototype.set");

  Label throw_invalid_key(this);
  GotoIfCannotBeHeldWeakly(key, &throw_invalid_key);

  Return(
      CallBuiltin(Builtin::kWeakCollectionSet, context, receiver, key, value));

  BIND(&throw_invalid_key);
  ThrowTypeError(context, MessageTemplate::kInvalidWeakMapKey, key);
}

TF_BUILTIN(WeakSetPrototypeAdd, WeakCollectionsBuiltinsAssembler) {
  auto context = Parameter<Context>(Descriptor::kContext);
  auto receiver = Parameter<Object>(Descriptor::kReceiver);
  auto value = Parameter<Object>(Descriptor::kValue);

  ThrowIfNotInstanceType(context, receiver, JS_WEAK_SET_TYPE,
                         "WeakSet.prototype.add");

  Label throw_invalid_value(this);
  GotoIfCannotBeHeldWeakly(value, &throw_invalid_value);

  Return(CallBuiltin(Builtin::kWeakCollectionSet, context, receiver, value,
                     TrueConstant()));

  BIND(&throw_invalid_value);
  ThrowTypeError(context, MessageTemplate::kInvalidWeakSetValue, value);
}

TF_BUILTIN(WeakSetPrototypeDelete, CodeStubAssembler) {
  auto context = Parameter<Context>(Descriptor::kContext);
  auto receiver = Parameter<Object>(Descriptor::kReceiver);
  auto value = Parameter<Object>(Descriptor::kValue);

  ThrowIfNotInstanceType(context, receiver, JS_WEAK_SET_TYPE,
                         "WeakSet.prototype.delete");

  // This check breaks a known exploitation technique. See crbug.com/1263462
  CSA_HOLE_SECURITY_CHECK(this, TaggedNotEqual(value, TheHoleConstant()));

  Return(CallBuiltin(Builtin::kWeakCollectionDelete, context, receiver, value));
}

TF_BUILTIN(WeakSetPrototypeHas, WeakCollectionsBuiltinsAssembler) {
  const auto receiver = Parameter<Object>(Descriptor::kReceiver);
  const auto key = Parameter<Object>(Descriptor::kKey);
  const auto context = Parameter<Context>(Descriptor::kContext);

  Label return_false(this);

  ThrowIfNotInstanceType(context, receiver, JS_WEAK_SET_TYPE,
                         "WeakSet.prototype.has");

  const TNode<EphemeronHashTable> table = LoadTable(CAST(receiver));
  const TNode<Object> index =
      CallBuiltin(Builtin::kWeakMapLookupHashIndex, context, table, key);

  GotoIf(TaggedEqual(index, SmiConstant(-1)), &return_false);

  Return(TrueConstant());

  BIND(&return_false);
  Return(FalseConstant());
}

#include "src/codegen/undef-code-stub-assembler-macros.inc"

}  // namespace internal
}  // namespace v8

"""


```