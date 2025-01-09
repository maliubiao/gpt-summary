Response:
The user is asking for a summary of the functionality of the provided C++ code snippet from V8's `builtins-collections-gen.cc` file.

Here's a breakdown of the thought process:

1. **Identify the core purpose:** The file name `builtins-collections-gen.cc` strongly suggests that this code implements built-in functions for JavaScript collections like `Map` and `Set`. The code itself confirms this with function names like `MapPrototypeSet`, `SetPrototypeAdd`, etc.

2. **Analyze the code structure:** The code is structured as a series of C++ functions (using the `TF_BUILTIN` macro, indicating Torque built-ins) and helper methods within a `CollectionsBuiltinsAssembler` class. Each `TF_BUILTIN` function corresponds to a JavaScript `Map` or `Set` prototype method.

3. **Categorize the functionalities:**  Group the functions by the JavaScript collection they operate on (`Map` or `Set`) and the specific operation they perform (add, delete, has, get size, iterate, etc.).

4. **Identify key data structures and algorithms:** Notice the recurring use of `OrderedHashMap` and `OrderedHashSet`. These are likely the internal representations of `Map` and `Set` in V8. The code also uses hash tables for efficient lookups. Keywords like "hash", "bucket", and "entry" reinforce this. The logic for growing and shrinking the tables is also evident.

5. **Connect to JavaScript equivalents:** For each C++ function, determine its corresponding JavaScript method. For example, `MapPrototypeSet` clearly relates to `Map.prototype.set()`. Provide simple JavaScript examples to illustrate the functionality.

6. **Look for logic and potential edge cases:** Pay attention to the logic for adding and deleting elements, including resizing the underlying hash table. Consider scenarios like adding duplicate keys (for `Set`), handling different key types, and what happens when the table is full. The code mentions "deleted elements", indicating a soft deletion mechanism.

7. **Identify potential user errors:** Based on the function names and logic, think about common mistakes developers make when using `Map` and `Set` in JavaScript. Examples include using non-callable objects in `forEach`, assuming a specific iteration order (though these are *ordered* hash tables, it's good to mention general unordered behavior), and modifying collections during iteration.

8. **Address the ".tq" question:** The prompt specifically asks about `.tq` files. Explain that if the file ended in `.tq`, it would be a Torque source file.

9. **Synthesize the information into a concise summary:**  Combine the categorized functionalities, key data structures, JavaScript connections, and potential errors into a clear and informative summary.

10. **Address the "part 3" aspect:**  Acknowledge that this is part of a larger code base and that the focus is on the provided snippet's functionalities within the context of `Map` and `Set` built-ins.

**Self-Correction/Refinement during the process:**

* Initially, I might just list the function names. However, to be more helpful, I need to explain what each function *does*.
*  Simply saying "it uses hash tables" is not enough. Mentioning the *ordered* nature is important as it's explicitly present in the code (`OrderedHashMap`, `OrderedHashSet`).
* When giving JavaScript examples, ensure they are simple and directly illustrate the corresponding C++ function's action.
*  Don't just state potential errors; provide concrete examples of how those errors might manifest in JavaScript code.

By following this thought process, the comprehensive summary provided as the answer can be generated.
好的，这是对提供的第三部分代码的功能归纳：

**核心功能：向 Map 和 Set 添加新元素，并处理哈希表扩容**

这部分代码主要关注 `Map` 和 `Set` 的 `add` 操作，以及在哈希表空间不足时进行扩容的逻辑。它定义了向 `OrderedHashMap` (用于 `Map`) 和 `OrderedHashSet` (用于 `Set`) 添加新条目的通用方法。

**具体功能点：**

1. **`AddToOrderedHashTable` 模板函数:**
   - 这是一个核心的模板函数，用于向有序哈希表（`OrderedHashMap` 或 `OrderedHashSet`）添加新的键值对或键。
   - 它接收哈希表、要添加的键、一个用于扩容的回调函数 `grow`，以及两个用于存储条目的回调函数 `store_at_new_entry` 和 `store_at_existing_entry`。
   - **查找现有条目：** 首先尝试在哈希表中查找给定的键。如果找到现有条目，则调用 `store_at_existing_entry`（通常用于 `Map` 的 `set` 操作来更新值，而 `Set` 则不做任何操作）。
   - **计算哈希值或获取现有哈希值：** 如果没有找到现有条目，则计算键的哈希值（对于非 Smi 类型的键）。对于 Smi 类型的键，它可能直接使用该 Smi 作为哈希值或获取已存在的哈希值。
   - **检查空间并扩容：** 检查当前哈希表是否有足够的空间容纳新条目。如果空间不足，则调用 `grow` 回调函数进行哈希表扩容，并重新加载扩容后的哈希表相关字段。
   - **存储新条目：** 调用 `StoreOrderedHashTableNewEntry` 函数将新条目存储到哈希表中。

2. **`StoreOrderedHashTableNewEntry` 模板函数:**
   - 负责将新的键值对或键实际存储到有序哈希表中。
   - 它根据哈希值计算出新条目应该放置的桶（bucket）。
   - 将新条目链接到对应桶的链表中。
   - 更新桶的头部信息。
   - 增加哈希表中的元素计数。

3. **`AddNewToOrderedHashTable` 模板函数:**
   -  一个用于向有序哈希表添加新条目的辅助函数，特别是当从 `Set` 添加新条目时。
   -  它根据键的类型（Smi, String, HeapNumber, BigInt 等）计算哈希值。
   -  然后调用 `StoreOrderedHashTableNewEntry` 来存储新条目。

4. **`StoreValueInOrderedHashMapEntry` 和 `StoreKeyValueInOrderedHashMapEntry` 函数:**
   -  用于在 `OrderedHashMap` 的条目中存储值或键值对。

5. **`TF_BUILTIN(MapPrototypeSet, CollectionsBuiltinsAssembler)`:**
   -  实现了 `Map.prototype.set()` 方法。
   -  接收 `receiver` (Map 实例), `key`, `value`, 和 `context` 参数。
   -  对数字类型的键进行标准化 (`NormalizeNumberKey`)。
   -  定义了 `grow` lambda 函数，用于在需要时调用运行时函数 `Runtime::kMapGrow` 来扩容哈希表。
   -  定义了 `store_at_new_entry` lambda 函数，用于将新的键值对存储到哈希表中。
   -  定义了 `store_at_existing_entry` lambda 函数，用于更新已存在键的值。
   -  调用 `AddToOrderedHashTable` 来执行添加或更新操作。

6. **`TF_BUILTIN(SetPrototypeAdd, CollectionsBuiltinsAssembler)`:**
   -  实现了 `Set.prototype.add()` 方法。
   -  接收 `receiver` (Set 实例), `key`, 和 `context` 参数。
   -  与 `MapPrototypeSet` 类似，定义了 `grow` 和 `store_at_new_entry` lambda 函数。
   -  `store_at_existing_entry` lambda 函数对于 `Set` 来说是空的，因为 `Set` 不会因为添加已存在的键而改变。
   -  调用 `AddToOrderedHashTable` 来执行添加操作。

7. **`AddToSetTable` 函数:**
   -  一个用于向 `Set` 的哈希表添加元素的辅助函数，它允许传入方法名，可能用于错误消息或其他上下文信息。

8. **`StoreKeyInOrderedHashSetEntry` 函数:**
   -  用于在 `OrderedHashSet` 的条目中存储键。

**与 JavaScript 的关系：**

这部分代码直接实现了 JavaScript 中 `Map` 和 `Set` 的 `set` 和 `add` 方法的核心逻辑。

**JavaScript 示例：**

```javascript
// Map 的 set 操作
const map = new Map();
map.set('a', 1); // 对应 TF_BUILTIN(MapPrototypeSet, ...)

// Set 的 add 操作
const set = new Set();
set.add(1);     // 对应 TF_BUILTIN(SetPrototypeAdd, ...)
set.add(1);     // 再次添加相同的元素，Set 不会改变
```

**代码逻辑推理 (假设输入与输出)：**

**假设输入 (MapPrototypeSet):**

- `receiver`: 一个已经存在的 `Map` 实例，例如 `new Map()`
- `key`: 字符串 `'b'`
- `value`: 数字 `2`

**输出:**

- 如果 `Map` 中不存在键 `'b'`，则会在其内部的 `OrderedHashMap` 中添加一个新的键值对 `('b', 2)`，并且 `Map` 实例被修改。
- 如果 `Map` 中已经存在键 `'b'`，则会将该键对应的值更新为 `2`。

**假设输入 (SetPrototypeAdd):**

- `receiver`: 一个已经存在的 `Set` 实例，例如 `new Set([1])`
- `key`: 数字 `2`

**输出:**

- `Set` 中会添加新的元素 `2`。
- 如果 `key` 是 `1`（已经存在于 `Set` 中），则 `Set` 不会发生改变。

**用户常见的编程错误：**

- **在 `Map` 或 `Set` 的 `forEach` 循环中直接修改 `Map` 或 `Set` 的结构（添加或删除元素）：** 这可能导致迭代器失效或产生意想不到的结果。V8 的实现中会尝试处理这种情况，但仍然是不推荐的做法。

**归纳总结 (第三部分功能)：**

这部分代码主要负责实现 JavaScript `Map` 和 `Set` 的添加元素操作（`set` 和 `add` 方法）。它深入到 V8 内部的哈希表实现，包括计算哈希值、查找现有条目、检查空间以及在必要时进行哈希表扩容。 这些内置函数的实现确保了 `Map` 和 `Set` 在 JavaScript 中的高效操作。

Prompt: 
```
这是目录为v8/src/builtins/builtins-collections-gen.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/builtins-collections-gen.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共4部分，请归纳一下它的功能

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
  GrowCollection<OrderedHashMap> grow = [this, gro
"""


```