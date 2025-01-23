Response:
The user wants a summary of the provided C++ code snippet from `v8/src/builtins/builtins-collections-gen.cc`.

Here's a breakdown of the request and how to address it:

1. **Identify the language:** The user correctly identified this as V8 source code and pointed out the `.tq` extension indicates Torque.

2. **List Functionality:**  Analyze the code to determine its purpose. This involves looking at function names, variable names, and the overall control flow. Key aspects seem to involve:
    * Comparing keys (Smi, Float64)
    * Checking the validity of Map and Set iterators.
    * Verifying if iterators are of the original type (keys, values, entries).
    * Converting Map and Set iterators (or the Sets themselves) to Lists (JSArrays).
    * Computing hashes for keys.
    * Finding entries in ordered hash tables (for different key types).
    * Comparing keys for equality (SameValueZero).
    * "Healing" or adjusting indices in hash tables after deletions.
    * Transitioning between hash table states.
    * Skipping holes in hash tables during iteration.
    * Getting values from Maps.
    * Checking if a Map has a key.
    * Normalizing number keys (handling -0 and 0).
    * Adding entries to ordered hash tables.

3. **Javascript Relationship:** Determine if the C++ code relates to any JavaScript features. The functions clearly deal with `Map` and `Set` objects, their iterators, and fundamental operations like `get` and `has`.

4. **Javascript Examples:** Provide concise JavaScript examples demonstrating the functionality described in the C++ code. Focus on the core concepts being implemented.

5. **Code Logic Inference (Hypothetical Inputs/Outputs):**  Choose a specific function and illustrate its behavior with a simple input and expected output. `SameValueZeroSmi` is a good candidate for this.

6. **Common Programming Errors:** Think about typical mistakes developers make when working with Maps and Sets that the code might be addressing or preventing. Incorrect key comparisons are a likely candidate.

7. **Overall Functionality (Summarization):**  Synthesize the findings from the previous steps into a concise summary of the code's purpose within V8.

**Mental Sandbox:**

* **Function Breakdown:** Imagine each function as a building block for implementing JavaScript's `Map` and `Set` functionalities efficiently within the V8 engine.
* **Torque:** Remember Torque is used for generating optimized built-in functions. This code likely represents highly performance-sensitive parts of `Map` and `Set` implementations.
* **Hash Tables:** Recognize the heavy use of hash tables as the underlying data structure for `Map` and `Set`.
* **Iterators:**  Understand the role of iterators in traversing collections.

**Constraint Checklist & Confidence Score:**

* List functionality: Yes
* Torque source: Yes
* Javascript relationship: Yes
* Javascript examples: Yes
* Code logic inference: Yes
* Common errors: Yes
* Summarize functionality: Yes

Confidence Score: 5/5 -  The code is relatively clear in its intent, and the connection to JavaScript's `Map` and `Set` is strong.

Strategizing complete. Proceeding with response generation.
这是 `v8/src/builtins/builtins-collections-gen.cc` 源代码的第二部分，延续了第一部分的内容，主要功能是为 JavaScript 的 `Map` 和 `Set` 等集合类型提供高效的内置函数实现。

**功能归纳:**

这部分代码继续构建用于操作 `Map` 和 `Set` 的底层工具函数，主要集中在以下几个方面：

1. **迭代器相关的操作和保护:**
   - `BranchIfMapIteratorProtectorValid`: 检查 Map 迭代器的保护器是否有效，这是一种优化手段，用于判断迭代器是否处于稳定状态。
   - `BranchIfIterableWithOriginalKeyOrValueMapIterator`:  判断一个对象是否是未被部分消耗的、原始的 Map 键或值迭代器。这用于优化某些迭代操作。
   - `BranchIfSetIteratorProtectorValid`: 检查 Set 迭代器的保护器是否有效。
   - `BranchIfIterableWithOriginalValueSetIterator`: 判断一个对象是否是未被部分消耗的、原始的 Set 值迭代器或者是一个原始的 Set 对象。

2. **集合与迭代器之间的转换:**
   - `SetOrSetIteratorToSet`: 将 Set 对象或 Set 迭代器转换为其底层的 `OrderedHashSet` 数据结构，并可能将迭代器标记为已耗尽。
   - `MapIteratorToList`: 将 Map 迭代器转换为包含键或值的 JavaScript 数组。
   - `SetOrSetIteratorToList`: 将 Set 对象或 Set 迭代器转换为包含值的 JavaScript 数组。

3. **哈希计算和查找:**
   - `ComputeUnseededHash`: 计算一个无种子的哈希值，用于哈希表的查找。
   - `FindOrderedHashTableEntryForSmiKey`, `FindOrderedHashTableEntryForStringKey`, `FindOrderedHashTableEntryForHeapNumberKey`, `FindOrderedHashTableEntryForBigIntKey`, `FindOrderedHashTableEntryForOtherKey`:  在有序哈希表中查找特定类型的键的条目。
   - `ComputeStringHash`: 计算字符串的哈希值，考虑了字符串是否已经计算过哈希。
   - `SameValueZeroString`, `SameValueZeroBigInt`, `SameValueZeroHeapNumber`:  实现 JavaScript 的 `SameValueZero` 比较算法，用于比较不同类型的键。

4. **哈希表索引的修复和转换:**
   - `OrderedHashTableHealIndex`:  在哈希表被删除元素后，修复可能失效的索引。
   - `Transition`:  处理哈希表的扩容或收缩导致的转换，并更新索引。
   - `TransitionAndUpdate`: 在哈希表转换时更新迭代器的状态。
   - `TransitionOrderedHashSetNoUpdate`: 执行 `OrderedHashSet` 的转换但不更新任何外部状态。

5. **哈希表遍历的辅助函数:**
   - `NextSkipHashTableHoles`: 在哈希表中跳过空洞，获取下一个有效的键值对或键。
   - `NextKeyIndexPairUnmodifiedTable`, `NextKeyIndexPair`:  用于在哈希表中获取下一个键和索引。
   - `NextKeyValueIndexTupleUnmodifiedTable`, `NextKeyValueIndexTuple`: 用于在哈希表中获取下一个键、值和索引。

6. **`Map` 原型方法的部分实现:**
   - `MapPrototypeGet`: 实现 `Map.prototype.get()` 方法，根据键查找并返回值。
   - `MapPrototypeHas`: 实现 `Map.prototype.has()` 方法，检查 Map 中是否存在指定的键。
   - `TableHasKey`:  一个辅助函数，用于检查哈希表中是否存在指定的键。

7. **键的规范化:**
   - `NormalizeNumberKey`:  规范化数字类型的键，例如将 `0` 和 `-0` 视为相等。

8. **向哈希表添加元素:**
   - `AddToOrderedHashTable`:  向有序哈希表中添加新的键值对或键。

**JavaScript 功能关联与示例:**

这部分代码直接关联到 JavaScript 中 `Map` 和 `Set` 对象的以下功能：

* **`Map.prototype.get(key)`:**  `TF_BUILTIN(MapPrototypeGet, CollectionsBuiltinsAssembler)` 实现了这个功能。
   ```javascript
   const map = new Map();
   map.set('a', 1);
   console.log(map.get('a')); // 输出 1
   console.log(map.get('b')); // 输出 undefined
   ```

* **`Map.prototype.has(key)`:** `TF_BUILTIN(MapPrototypeHas, CollectionsBuiltinsAssembler)` 实现了这个功能。
   ```javascript
   const map = new Map();
   map.set('a', 1);
   console.log(map.has('a')); // 输出 true
   console.log(map.has('b')); // 输出 false
   ```

* **`Map` 和 `Set` 的迭代:**  `BranchIfIterableWithOriginalKeyOrValueMapIterator` 和 `BranchIfIterableWithOriginalValueSetIterator` 等函数用于优化迭代过程。
   ```javascript
   const map = new Map([['a', 1], ['b', 2]]);
   for (const key of map.keys()) {
       console.log(key); // 输出 'a', 'b'
   }

   const set = new Set([1, 2, 3]);
   for (const value of set.values()) {
       console.log(value); // 输出 1, 2, 3
   }
   ```

* **将 `Map` 或 `Set` 转换为数组:** `MapIteratorToList` 和 `SetOrSetIteratorToList` 实现了这个功能。
   ```javascript
   const map = new Map([['a', 1], ['b', 2]]);
   const mapToArray = [...map]; // 或者 Array.from(map); 输出 [['a', 1], ['b', 2]]

   const set = new Set([1, 2, 3]);
   const setToArray = [...set]; // 或者 Array.from(set); 输出 [1, 2, 3]
   ```

**代码逻辑推理 (假设输入与输出):**

以 `SameValueZeroSmi` 函数为例，假设输入如下：

* `key_smi`:  一个 Smi 值，例如 `Smi(5)`
* `candidate_key`: 一个可能是 Smi 的对象。

**假设输入 1:**

* `key_smi`: `Smi(5)`
* `candidate_key`: `Smi(5)`

**预期输出:** 跳转到 `if_same` 标签。

**假设输入 2:**

* `key_smi`: `Smi(5)`
* `candidate_key`: `Smi(10)`

**预期输出:** 跳转到 `if_not_same` 标签。

**假设输入 3:**

* `key_smi`: `Smi(5)`
* `candidate_key`: `HeapNumber(5.0)`

**预期输出:** 由于 `SmiToFloat64(key_smi)` 会将 `Smi(5)` 转换为 `Float64(5.0)`，并且 `Float64Equal(candidate_key_number, key_number)` 会比较两个浮点数，因此跳转到 `if_same` 标签。

**用户常见的编程错误:**

* **不理解 `SameValueZero` 的比较规则:** 开发者可能会认为 `NaN === NaN` 为 `false`，但在 `Map` 和 `Set` 的键比较中，`NaN` 被认为是相等的（使用 `SameValueZero` 比较）。
   ```javascript
   const map = new Map();
   map.set(NaN, 'value1');
   console.log(map.has(NaN)); // 输出 true
   ```

* **错误地比较 `0` 和 `-0`:**  在 JavaScript 中，`0 === -0` 为 `true`，但在某些情况下需要区分。`NormalizeNumberKey` 的存在表明 V8 内部需要处理这种规范化。
   ```javascript
   const map = new Map();
   map.set(0, 'positive zero');
   console.log(map.get(-0)); // 可能会返回 'positive zero'，因为键被规范化了
   ```

* **在迭代过程中修改 `Map` 或 `Set`:**  这可能导致迭代器的行为变得不可预测，而代码中的迭代器保护机制 (`BranchIfMapIteratorProtectorValid`, `BranchIfSetIteratorProtectorValid`) 就是为了在一定程度上防止或优化这种情况。

总之，这部分代码是 V8 引擎中实现 `Map` 和 `Set` 核心功能的关键组成部分，它关注于性能、准确性和对 JavaScript 语义的忠实实现。

### 提示词
```
这是目录为v8/src/builtins/builtins-collections-gen.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/builtins-collections-gen.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
TNode<Float64T> key_number = SmiToFloat64(key_smi);

  GotoIf(Float64Equal(candidate_key_number, key_number), if_same);

  Goto(if_not_same);
}

void CollectionsBuiltinsAssembler::BranchIfMapIteratorProtectorValid(
    Label* if_true, Label* if_false) {
  TNode<PropertyCell> protector_cell = MapIteratorProtectorConstant();
  DCHECK(i::IsPropertyCell(isolate()->heap()->map_iterator_protector()));
  Branch(
      TaggedEqual(LoadObjectField(protector_cell, PropertyCell::kValueOffset),
                  SmiConstant(Protectors::kProtectorValid)),
      if_true, if_false);
}

void CollectionsBuiltinsAssembler::
    BranchIfIterableWithOriginalKeyOrValueMapIterator(TNode<Object> iterator,
                                                      TNode<Context> context,
                                                      Label* if_true,
                                                      Label* if_false) {
  Label if_key_or_value_iterator(this), extra_checks(this);

  // Check if iterator is a keys or values JSMapIterator.
  GotoIf(TaggedIsSmi(iterator), if_false);
  TNode<Map> iter_map = LoadMap(CAST(iterator));
  const TNode<Uint16T> instance_type = LoadMapInstanceType(iter_map);
  GotoIf(InstanceTypeEqual(instance_type, JS_MAP_KEY_ITERATOR_TYPE),
         &if_key_or_value_iterator);
  Branch(InstanceTypeEqual(instance_type, JS_MAP_VALUE_ITERATOR_TYPE),
         &if_key_or_value_iterator, if_false);

  BIND(&if_key_or_value_iterator);
  // Check that the iterator is not partially consumed.
  const TNode<Object> index =
      LoadObjectField(CAST(iterator), JSMapIterator::kIndexOffset);
  GotoIfNot(TaggedEqual(index, SmiConstant(0)), if_false);
  BranchIfMapIteratorProtectorValid(&extra_checks, if_false);

  BIND(&extra_checks);
  // Check if the iterator object has the original %MapIteratorPrototype%.
  const TNode<NativeContext> native_context = LoadNativeContext(context);
  const TNode<Object> initial_map_iter_proto = LoadContextElement(
      native_context, Context::INITIAL_MAP_ITERATOR_PROTOTYPE_INDEX);
  const TNode<HeapObject> map_iter_proto = LoadMapPrototype(iter_map);
  GotoIfNot(TaggedEqual(map_iter_proto, initial_map_iter_proto), if_false);

  // Check if the original MapIterator prototype has the original
  // %IteratorPrototype%.
  const TNode<Object> initial_iter_proto = LoadContextElement(
      native_context, Context::INITIAL_ITERATOR_PROTOTYPE_INDEX);
  const TNode<HeapObject> iter_proto =
      LoadMapPrototype(LoadMap(map_iter_proto));
  Branch(TaggedEqual(iter_proto, initial_iter_proto), if_true, if_false);
}

void BranchIfIterableWithOriginalKeyOrValueMapIterator(
    compiler::CodeAssemblerState* state, TNode<Object> iterable,
    TNode<Context> context, compiler::CodeAssemblerLabel* if_true,
    compiler::CodeAssemblerLabel* if_false) {
  CollectionsBuiltinsAssembler assembler(state);
  assembler.BranchIfIterableWithOriginalKeyOrValueMapIterator(
      iterable, context, if_true, if_false);
}

void CollectionsBuiltinsAssembler::BranchIfSetIteratorProtectorValid(
    Label* if_true, Label* if_false) {
  const TNode<PropertyCell> protector_cell = SetIteratorProtectorConstant();
  DCHECK(i::IsPropertyCell(isolate()->heap()->set_iterator_protector()));
  Branch(
      TaggedEqual(LoadObjectField(protector_cell, PropertyCell::kValueOffset),
                  SmiConstant(Protectors::kProtectorValid)),
      if_true, if_false);
}

void CollectionsBuiltinsAssembler::BranchIfIterableWithOriginalValueSetIterator(
    TNode<Object> iterable, TNode<Context> context, Label* if_true,
    Label* if_false) {
  Label if_set(this), if_value_iterator(this), check_protector(this);
  TVARIABLE(BoolT, var_result);

  GotoIf(TaggedIsSmi(iterable), if_false);
  TNode<Map> iterable_map = LoadMap(CAST(iterable));
  const TNode<Uint16T> instance_type = LoadMapInstanceType(iterable_map);

  GotoIf(InstanceTypeEqual(instance_type, JS_SET_TYPE), &if_set);
  Branch(InstanceTypeEqual(instance_type, JS_SET_VALUE_ITERATOR_TYPE),
         &if_value_iterator, if_false);

  BIND(&if_set);
  // Check if the set object has the original Set prototype.
  const TNode<Object> initial_set_proto = LoadContextElement(
      LoadNativeContext(context), Context::INITIAL_SET_PROTOTYPE_INDEX);
  const TNode<HeapObject> set_proto = LoadMapPrototype(iterable_map);
  GotoIfNot(TaggedEqual(set_proto, initial_set_proto), if_false);
  Goto(&check_protector);

  BIND(&if_value_iterator);
  // Check that the iterator is not partially consumed.
  const TNode<Object> index =
      LoadObjectField(CAST(iterable), JSSetIterator::kIndexOffset);
  GotoIfNot(TaggedEqual(index, SmiConstant(0)), if_false);

  // Check if the iterator object has the original SetIterator prototype.
  const TNode<NativeContext> native_context = LoadNativeContext(context);
  const TNode<Object> initial_set_iter_proto = LoadContextElement(
      native_context, Context::INITIAL_SET_ITERATOR_PROTOTYPE_INDEX);
  const TNode<HeapObject> set_iter_proto = LoadMapPrototype(iterable_map);
  GotoIfNot(TaggedEqual(set_iter_proto, initial_set_iter_proto), if_false);

  // Check if the original SetIterator prototype has the original
  // %IteratorPrototype%.
  const TNode<Object> initial_iter_proto = LoadContextElement(
      native_context, Context::INITIAL_ITERATOR_PROTOTYPE_INDEX);
  const TNode<HeapObject> iter_proto =
      LoadMapPrototype(LoadMap(set_iter_proto));
  GotoIfNot(TaggedEqual(iter_proto, initial_iter_proto), if_false);
  Goto(&check_protector);

  BIND(&check_protector);
  BranchIfSetIteratorProtectorValid(if_true, if_false);
}

void BranchIfIterableWithOriginalValueSetIterator(
    compiler::CodeAssemblerState* state, TNode<Object> iterable,
    TNode<Context> context, compiler::CodeAssemblerLabel* if_true,
    compiler::CodeAssemblerLabel* if_false) {
  CollectionsBuiltinsAssembler assembler(state);
  assembler.BranchIfIterableWithOriginalValueSetIterator(iterable, context,
                                                         if_true, if_false);
}

// A helper function to help extract the {table} from either a Set or
// SetIterator. The function has a side effect of marking the
// SetIterator (if SetIterator is passed) as exhausted.
TNode<OrderedHashSet> CollectionsBuiltinsAssembler::SetOrSetIteratorToSet(
    TNode<Object> iterable) {
  TVARIABLE(OrderedHashSet, var_table);
  Label if_set(this), if_iterator(this), done(this);

  const TNode<Uint16T> instance_type = LoadInstanceType(CAST(iterable));
  Branch(InstanceTypeEqual(instance_type, JS_SET_TYPE), &if_set, &if_iterator);

  BIND(&if_set);
  {
    // {iterable} is a JSSet.
    var_table = LoadObjectField<OrderedHashSet>(CAST(iterable),
                                                GetTableOffset(Variant::kSet));
    Goto(&done);
  }

  BIND(&if_iterator);
  {
    // {iterable} is a JSSetIterator.
    // Transition the {iterable} table if necessary.
    TNode<JSSetIterator> iterator = CAST(iterable);
    TNode<OrderedHashSet> table;
    TNode<IntPtrT> index;
    std::tie(table, index) =
        TransitionAndUpdate<JSSetIterator, OrderedHashSet>(iterator);
    CSA_DCHECK(this, IntPtrEqual(index, IntPtrConstant(0)));
    var_table = table;
    // Set the {iterable} to exhausted if it's an iterator.
    StoreObjectFieldRoot(iterator, JSSetIterator::kTableOffset,
                         RootIndex::kEmptyOrderedHashSet);
    TNode<IntPtrT> number_of_elements = LoadAndUntagPositiveSmiObjectField(
        table, OrderedHashSet::NumberOfElementsOffset());
    StoreObjectFieldNoWriteBarrier(iterator, JSSetIterator::kIndexOffset,
                                   SmiTag(number_of_elements));
    Goto(&done);
  }

  BIND(&done);
  return var_table.value();
}

TNode<JSArray> CollectionsBuiltinsAssembler::MapIteratorToList(
    TNode<Context> context, TNode<JSMapIterator> iterator) {
  // Transition the {iterator} table if necessary.
  TNode<OrderedHashMap> table;
  TNode<IntPtrT> index;
  std::tie(table, index) =
      TransitionAndUpdate<JSMapIterator, OrderedHashMap>(iterator);
  CSA_DCHECK(this, IntPtrEqual(index, IntPtrConstant(0)));

  TNode<Smi> size_smi =
      LoadObjectField<Smi>(table, OrderedHashMap::NumberOfElementsOffset());
  TNode<IntPtrT> size = PositiveSmiUntag(size_smi);

  const ElementsKind kind = PACKED_ELEMENTS;
  TNode<Map> array_map =
      LoadJSArrayElementsMap(kind, LoadNativeContext(context));
  TNode<JSArray> array = AllocateJSArray(kind, array_map, size, size_smi);
  TNode<FixedArray> elements = CAST(LoadElements(array));

  const int first_element_offset =
      OFFSET_OF_DATA_START(FixedArray) - kHeapObjectTag;
  TNode<IntPtrT> first_to_element_offset =
      ElementOffsetFromIndex(IntPtrConstant(0), kind, 0);
  TVARIABLE(
      IntPtrT, var_offset,
      IntPtrAdd(first_to_element_offset, IntPtrConstant(first_element_offset)));
  TVARIABLE(IntPtrT, var_index, index);
  VariableList vars({&var_index, &var_offset}, zone());
  Label done(this, {&var_index}), loop(this, vars), continue_loop(this, vars),
      write_key(this, vars), write_value(this, vars);

  Goto(&loop);

  BIND(&loop);
  {
    // Read the next entry from the {table}, skipping holes.
    TNode<Object> entry_key;
    TNode<IntPtrT> entry_start_position;
    TNode<IntPtrT> cur_index;
    std::tie(entry_key, entry_start_position, cur_index) =
        NextSkipHashTableHoles<OrderedHashMap>(table, var_index.value(), &done);

    // Decide to write key or value.
    Branch(
        InstanceTypeEqual(LoadInstanceType(iterator), JS_MAP_KEY_ITERATOR_TYPE),
        &write_key, &write_value);

    BIND(&write_key);
    {
      Store(elements, var_offset.value(), entry_key);
      Goto(&continue_loop);
    }

    BIND(&write_value);
    {
      CSA_DCHECK(this, InstanceTypeEqual(LoadInstanceType(iterator),
                                         JS_MAP_VALUE_ITERATOR_TYPE));
      TNode<Object> entry_value =
          UnsafeLoadValueFromOrderedHashMapEntry(table, entry_start_position);

      Store(elements, var_offset.value(), entry_value);
      Goto(&continue_loop);
    }

    BIND(&continue_loop);
    {
      // Increment the array offset and continue the loop to the next entry.
      var_index = cur_index;
      var_offset = IntPtrAdd(var_offset.value(), IntPtrConstant(kTaggedSize));
      Goto(&loop);
    }
  }

  BIND(&done);
  // Set the {iterator} to exhausted.
  StoreObjectFieldRoot(iterator, JSMapIterator::kTableOffset,
                       RootIndex::kEmptyOrderedHashMap);
  StoreObjectFieldNoWriteBarrier(iterator, JSMapIterator::kIndexOffset,
                                 SmiTag(var_index.value()));
  return UncheckedCast<JSArray>(array);
}

TF_BUILTIN(MapIteratorToList, CollectionsBuiltinsAssembler) {
  auto context = Parameter<Context>(Descriptor::kContext);
  auto iterator = Parameter<JSMapIterator>(Descriptor::kSource);
  Return(MapIteratorToList(context, iterator));
}

TNode<JSArray> CollectionsBuiltinsAssembler::SetOrSetIteratorToList(
    TNode<Context> context, TNode<HeapObject> iterable) {
  TNode<OrderedHashSet> table = SetOrSetIteratorToSet(iterable);
  TNode<Smi> size_smi =
      LoadObjectField<Smi>(table, OrderedHashMap::NumberOfElementsOffset());
  TNode<IntPtrT> size = PositiveSmiUntag(size_smi);

  const ElementsKind kind = PACKED_ELEMENTS;
  TNode<Map> array_map =
      LoadJSArrayElementsMap(kind, LoadNativeContext(context));
  TNode<JSArray> array = AllocateJSArray(kind, array_map, size, size_smi);
  TNode<FixedArray> elements = CAST(LoadElements(array));

  const int first_element_offset =
      OFFSET_OF_DATA_START(FixedArray) - kHeapObjectTag;
  TNode<IntPtrT> first_to_element_offset =
      ElementOffsetFromIndex(IntPtrConstant(0), kind, 0);
  TVARIABLE(
      IntPtrT, var_offset,
      IntPtrAdd(first_to_element_offset, IntPtrConstant(first_element_offset)));
  TVARIABLE(IntPtrT, var_index, IntPtrConstant(0));
  Label done(this), loop(this, {&var_index, &var_offset});

  Goto(&loop);

  BIND(&loop);
  {
    // Read the next entry from the {table}, skipping holes.
    TNode<Object> entry_key;
    TNode<IntPtrT> entry_start_position;
    TNode<IntPtrT> cur_index;
    std::tie(entry_key, entry_start_position, cur_index) =
        NextSkipHashTableHoles<OrderedHashSet>(table, var_index.value(), &done);

    Store(elements, var_offset.value(), entry_key);

    var_index = cur_index;
    var_offset = IntPtrAdd(var_offset.value(), IntPtrConstant(kTaggedSize));
    Goto(&loop);
  }

  BIND(&done);
  return UncheckedCast<JSArray>(array);
}

TF_BUILTIN(SetOrSetIteratorToList, CollectionsBuiltinsAssembler) {
  auto context = Parameter<Context>(Descriptor::kContext);
  auto object = Parameter<HeapObject>(Descriptor::kSource);
  Return(SetOrSetIteratorToList(context, object));
}

TNode<Word32T> CollectionsBuiltinsAssembler::ComputeUnseededHash(
    TNode<IntPtrT> key) {
  // See v8::internal::ComputeUnseededHash()
  TNode<Word32T> hash = TruncateIntPtrToInt32(key);
  hash = Int32Add(Word32Xor(hash, Int32Constant(0xFFFFFFFF)),
                  Word32Shl(hash, Int32Constant(15)));
  hash = Word32Xor(hash, Word32Shr(hash, Int32Constant(12)));
  hash = Int32Add(hash, Word32Shl(hash, Int32Constant(2)));
  hash = Word32Xor(hash, Word32Shr(hash, Int32Constant(4)));
  hash = Int32Mul(hash, Int32Constant(2057));
  hash = Word32Xor(hash, Word32Shr(hash, Int32Constant(16)));
  return Word32And(hash, Int32Constant(0x3FFFFFFF));
}

template <typename CollectionType>
void CollectionsBuiltinsAssembler::FindOrderedHashTableEntryForSmiKey(
    TNode<CollectionType> table, TNode<Smi> smi_key, TVariable<IntPtrT>* result,
    Label* entry_found, Label* not_found) {
  const TNode<IntPtrT> key_untagged = SmiUntag(smi_key);
  const TNode<Uint32T> hash = Unsigned(ComputeUnseededHash(key_untagged));
  *result = Signed(ChangeUint32ToWord(hash));
  FindOrderedHashTableEntry<CollectionType>(
      table, hash,
      [&](TNode<Object> other_key, Label* if_same, Label* if_not_same) {
        SameValueZeroSmi(smi_key, other_key, if_same, if_not_same);
      },
      result, entry_found, not_found);
}

template <typename CollectionType>
void CollectionsBuiltinsAssembler::FindOrderedHashTableEntryForStringKey(
    TNode<CollectionType> table, TNode<String> key_tagged,
    TVariable<IntPtrT>* result, Label* entry_found, Label* not_found) {
  const TNode<Uint32T> hash = ComputeStringHash(key_tagged);
  *result = Signed(ChangeUint32ToWord(hash));
  FindOrderedHashTableEntry<CollectionType>(
      table, hash,
      [&](TNode<Object> other_key, Label* if_same, Label* if_not_same) {
        SameValueZeroString(key_tagged, other_key, if_same, if_not_same);
      },
      result, entry_found, not_found);
}

template <typename CollectionType>
void CollectionsBuiltinsAssembler::FindOrderedHashTableEntryForHeapNumberKey(
    TNode<CollectionType> table, TNode<HeapNumber> key_heap_number,
    TVariable<IntPtrT>* result, Label* entry_found, Label* not_found) {
  const TNode<Uint32T> hash = CallGetHashRaw(key_heap_number);
  *result = Signed(ChangeUint32ToWord(hash));
  const TNode<Float64T> key_float = LoadHeapNumberValue(key_heap_number);
  FindOrderedHashTableEntry<CollectionType>(
      table, hash,
      [&](TNode<Object> other_key, Label* if_same, Label* if_not_same) {
        SameValueZeroHeapNumber(key_float, other_key, if_same, if_not_same);
      },
      result, entry_found, not_found);
}

template <typename CollectionType>
void CollectionsBuiltinsAssembler::FindOrderedHashTableEntryForBigIntKey(
    TNode<CollectionType> table, TNode<BigInt> key_big_int,
    TVariable<IntPtrT>* result, Label* entry_found, Label* not_found) {
  const TNode<Uint32T> hash = CallGetHashRaw(key_big_int);
  *result = Signed(ChangeUint32ToWord(hash));
  FindOrderedHashTableEntry<CollectionType>(
      table, hash,
      [&](TNode<Object> other_key, Label* if_same, Label* if_not_same) {
        SameValueZeroBigInt(key_big_int, other_key, if_same, if_not_same);
      },
      result, entry_found, not_found);
}

template <typename CollectionType>
void CollectionsBuiltinsAssembler::FindOrderedHashTableEntryForOtherKey(
    TNode<CollectionType> table, TNode<HeapObject> key_heap_object,
    TVariable<IntPtrT>* result, Label* entry_found, Label* not_found) {
  const TNode<Uint32T> hash = GetHash(key_heap_object);
  *result = Signed(ChangeUint32ToWord(hash));
  FindOrderedHashTableEntry<CollectionType>(
      table, hash,
      [&](TNode<Object> other_key, Label* if_same, Label* if_not_same) {
        Branch(TaggedEqual(key_heap_object, other_key), if_same, if_not_same);
      },
      result, entry_found, not_found);
}

TNode<Uint32T> CollectionsBuiltinsAssembler::ComputeStringHash(
    TNode<String> string_key) {
  TVARIABLE(Uint32T, var_result);

  Label hash_not_computed(this), done(this, &var_result);
  const TNode<Uint32T> hash = LoadNameHash(string_key, &hash_not_computed);
  var_result = hash;
  Goto(&done);

  BIND(&hash_not_computed);
  var_result = CallGetHashRaw(string_key);
  Goto(&done);

  BIND(&done);
  return var_result.value();
}

void CollectionsBuiltinsAssembler::SameValueZeroString(
    TNode<String> key_string, TNode<Object> candidate_key, Label* if_same,
    Label* if_not_same) {
  // If the candidate is not a string, the keys are not equal.
  GotoIf(TaggedIsSmi(candidate_key), if_not_same);
  GotoIfNot(IsString(CAST(candidate_key)), if_not_same);

  GotoIf(TaggedEqual(key_string, candidate_key), if_same);
  BranchIfStringEqual(key_string, CAST(candidate_key), if_same, if_not_same);
}

void CollectionsBuiltinsAssembler::SameValueZeroBigInt(
    TNode<BigInt> key, TNode<Object> candidate_key, Label* if_same,
    Label* if_not_same) {
  GotoIf(TaggedIsSmi(candidate_key), if_not_same);
  GotoIfNot(IsBigInt(CAST(candidate_key)), if_not_same);

  Branch(TaggedEqual(CallRuntime(Runtime::kBigIntEqualToBigInt,
                                 NoContextConstant(), key, candidate_key),
                     TrueConstant()),
         if_same, if_not_same);
}

void CollectionsBuiltinsAssembler::SameValueZeroHeapNumber(
    TNode<Float64T> key_float, TNode<Object> candidate_key, Label* if_same,
    Label* if_not_same) {
  Label if_smi(this), if_keyisnan(this);

  GotoIf(TaggedIsSmi(candidate_key), &if_smi);
  GotoIfNot(IsHeapNumber(CAST(candidate_key)), if_not_same);

  {
    // {candidate_key} is a heap number.
    const TNode<Float64T> candidate_float =
        LoadHeapNumberValue(CAST(candidate_key));
    GotoIf(Float64Equal(key_float, candidate_float), if_same);

    // SameValueZero needs to treat NaNs as equal. First check if {key_float}
    // is NaN.
    BranchIfFloat64IsNaN(key_float, &if_keyisnan, if_not_same);

    BIND(&if_keyisnan);
    {
      // Return true iff {candidate_key} is NaN.
      Branch(Float64Equal(candidate_float, candidate_float), if_not_same,
             if_same);
    }
  }

  BIND(&if_smi);
  {
    const TNode<Float64T> candidate_float = SmiToFloat64(CAST(candidate_key));
    Branch(Float64Equal(key_float, candidate_float), if_same, if_not_same);
  }
}

TF_BUILTIN(OrderedHashTableHealIndex, CollectionsBuiltinsAssembler) {
  auto table = Parameter<HeapObject>(Descriptor::kTable);
  auto index = Parameter<Smi>(Descriptor::kIndex);
  Label return_index(this), return_zero(this);

  // Check if we need to update the {index}.
  GotoIfNot(SmiLessThan(SmiConstant(0), index), &return_zero);

  // Check if the {table} was cleared.
  static_assert(OrderedHashMap::NumberOfDeletedElementsOffset() ==
                OrderedHashSet::NumberOfDeletedElementsOffset());
  TNode<Int32T> number_of_deleted_elements = LoadAndUntagToWord32ObjectField(
      table, OrderedHashMap::NumberOfDeletedElementsOffset());
  static_assert(OrderedHashMap::kClearedTableSentinel ==
                OrderedHashSet::kClearedTableSentinel);
  GotoIf(Word32Equal(number_of_deleted_elements,
                     Int32Constant(OrderedHashMap::kClearedTableSentinel)),
         &return_zero);

  TVARIABLE(Int32T, var_i, Int32Constant(0));
  TVARIABLE(Smi, var_index, index);
  Label loop(this, {&var_i, &var_index});
  Goto(&loop);
  BIND(&loop);
  {
    TNode<Int32T> i = var_i.value();
    GotoIfNot(Int32LessThan(i, number_of_deleted_elements), &return_index);
    static_assert(OrderedHashMap::RemovedHolesIndex() ==
                  OrderedHashSet::RemovedHolesIndex());
    TNode<Smi> removed_index = CAST(LoadFixedArrayElement(
        CAST(table), ChangeUint32ToWord(i),
        OrderedHashMap::RemovedHolesIndex() * kTaggedSize));
    GotoIf(SmiGreaterThanOrEqual(removed_index, index), &return_index);
    Decrement(&var_index);
    var_i = Int32Add(var_i.value(), Int32Constant(1));
    Goto(&loop);
  }

  BIND(&return_index);
  Return(var_index.value());

  BIND(&return_zero);
  Return(SmiConstant(0));
}

template <typename TableType>
std::pair<TNode<TableType>, TNode<IntPtrT>>
CollectionsBuiltinsAssembler::Transition(
    const TNode<TableType> table, const TNode<IntPtrT> index,
    UpdateInTransition<TableType> const& update_in_transition) {
  TVARIABLE(IntPtrT, var_index, index);
  TVARIABLE(TableType, var_table, table);
  Label if_done(this), if_transition(this, Label::kDeferred);
  Branch(TaggedIsSmi(
             LoadObjectField(var_table.value(), TableType::NextTableOffset())),
         &if_done, &if_transition);

  BIND(&if_transition);
  {
    Label loop(this, {&var_table, &var_index}), done_loop(this);
    Goto(&loop);
    BIND(&loop);
    {
      TNode<TableType> current_table = var_table.value();
      TNode<IntPtrT> current_index = var_index.value();

      TNode<Object> next_table =
          LoadObjectField(current_table, TableType::NextTableOffset());
      GotoIf(TaggedIsSmi(next_table), &done_loop);

      var_table = CAST(next_table);
      var_index = SmiUntag(CAST(CallBuiltin(Builtin::kOrderedHashTableHealIndex,
                                            NoContextConstant(), current_table,
                                            SmiTag(current_index))));
      Goto(&loop);
    }
    BIND(&done_loop);

    // Update with the new {table} and {index}.
    update_in_transition(var_table.value(), var_index.value());
    Goto(&if_done);
  }

  BIND(&if_done);
  return {var_table.value(), var_index.value()};
}

template <typename IteratorType, typename TableType>
std::pair<TNode<TableType>, TNode<IntPtrT>>
CollectionsBuiltinsAssembler::TransitionAndUpdate(
    const TNode<IteratorType> iterator) {
  return Transition<TableType>(
      CAST(LoadObjectField(iterator, IteratorType::kTableOffset)),
      LoadAndUntagPositiveSmiObjectField(iterator, IteratorType::kIndexOffset),
      [this, iterator](const TNode<TableType> table,
                       const TNode<IntPtrT> index) {
        // Update the {iterator} with the new state.
        StoreObjectField(iterator, IteratorType::kTableOffset, table);
        StoreObjectFieldNoWriteBarrier(iterator, IteratorType::kIndexOffset,
                                       SmiTag(index));
      });
}

TorqueStructOrderedHashSetIndexPair
CollectionsBuiltinsAssembler::TransitionOrderedHashSetNoUpdate(
    const TNode<OrderedHashSet> table_arg, const TNode<IntPtrT> index_arg) {
  TNode<OrderedHashSet> table;
  TNode<IntPtrT> index;
  std::tie(table, index) = Transition<OrderedHashSet>(
      table_arg, index_arg,
      [](const TNode<OrderedHashSet>, const TNode<IntPtrT>) {});
  return TorqueStructOrderedHashSetIndexPair{table, index};
}

template <typename TableType>
std::tuple<TNode<Object>, TNode<IntPtrT>, TNode<IntPtrT>>
CollectionsBuiltinsAssembler::NextSkipHashTableHoles(TNode<TableType> table,
                                                     TNode<IntPtrT> index,
                                                     Label* if_end) {
  // Compute the used capacity for the {table}.
  TNode<Int32T> number_of_buckets = LoadAndUntagToWord32ObjectField(
      table, TableType::NumberOfBucketsOffset());
  TNode<Int32T> number_of_elements = LoadAndUntagToWord32ObjectField(
      table, TableType::NumberOfElementsOffset());
  TNode<Int32T> number_of_deleted_elements = LoadAndUntagToWord32ObjectField(
      table, TableType::NumberOfDeletedElementsOffset());
  TNode<Int32T> used_capacity =
      Int32Add(number_of_elements, number_of_deleted_elements);

  return NextSkipHashTableHoles(table, number_of_buckets, used_capacity, index,
                                if_end);
}

template <typename TableType>
std::tuple<TNode<Object>, TNode<IntPtrT>, TNode<IntPtrT>>
CollectionsBuiltinsAssembler::NextSkipHashTableHoles(
    TNode<TableType> table, TNode<Int32T> number_of_buckets,
    TNode<Int32T> used_capacity, TNode<IntPtrT> index, Label* if_end) {
  CSA_DCHECK(this, Word32Equal(number_of_buckets,
                               LoadAndUntagToWord32ObjectField(
                                   table, TableType::NumberOfBucketsOffset())));
  CSA_DCHECK(
      this,
      Word32Equal(
          used_capacity,
          Int32Add(LoadAndUntagToWord32ObjectField(
                       table, TableType::NumberOfElementsOffset()),
                   LoadAndUntagToWord32ObjectField(
                       table, TableType::NumberOfDeletedElementsOffset()))));

  TNode<Object> entry_key;
  TNode<Int32T> entry_start_position;
  TVARIABLE(Int32T, var_index, TruncateIntPtrToInt32(index));
  Label loop(this, &var_index), done_loop(this);
  Goto(&loop);
  BIND(&loop);
  {
    GotoIfNot(Int32LessThan(var_index.value(), used_capacity), if_end);
    entry_start_position = Int32Add(
        Int32Mul(var_index.value(), Int32Constant(TableType::kEntrySize)),
        number_of_buckets);
    entry_key = UnsafeLoadKeyFromOrderedHashTableEntry(
        table, ChangePositiveInt32ToIntPtr(entry_start_position));
    var_index = Int32Add(var_index.value(), Int32Constant(1));
    Branch(IsHashTableHole(entry_key), &loop, &done_loop);
  }

  BIND(&done_loop);
  return std::tuple<TNode<Object>, TNode<IntPtrT>, TNode<IntPtrT>>{
      entry_key, ChangePositiveInt32ToIntPtr(entry_start_position),
      ChangePositiveInt32ToIntPtr(var_index.value())};
}

template <typename CollectionType>
TorqueStructKeyIndexPair
CollectionsBuiltinsAssembler::NextKeyIndexPairUnmodifiedTable(
    const TNode<CollectionType> table, const TNode<Int32T> number_of_buckets,
    const TNode<Int32T> used_capacity, const TNode<IntPtrT> index,
    Label* if_end) {
  // Unmodified tables do not have transitions.
  CSA_DCHECK(this, TaggedIsSmi(LoadObjectField(
                       table, CollectionType::NextTableOffset())));

  TNode<Object> key;
  TNode<IntPtrT> entry_start_position;
  TNode<IntPtrT> next_index;

  std::tie(key, entry_start_position, next_index) = NextSkipHashTableHoles(
      table, number_of_buckets, used_capacity, index, if_end);

  return TorqueStructKeyIndexPair{key, next_index};
}

template TorqueStructKeyIndexPair
CollectionsBuiltinsAssembler::NextKeyIndexPairUnmodifiedTable(
    const TNode<OrderedHashMap> table, const TNode<Int32T> number_of_buckets,
    const TNode<Int32T> used_capacity, const TNode<IntPtrT> index,
    Label* if_end);
template TorqueStructKeyIndexPair
CollectionsBuiltinsAssembler::NextKeyIndexPairUnmodifiedTable(
    const TNode<OrderedHashSet> table, const TNode<Int32T> number_of_buckets,
    const TNode<Int32T> used_capacity, const TNode<IntPtrT> index,
    Label* if_end);

template <typename CollectionType>
TorqueStructKeyIndexPair CollectionsBuiltinsAssembler::NextKeyIndexPair(
    const TNode<CollectionType> table, const TNode<IntPtrT> index,
    Label* if_end) {
  TNode<Object> key;
  TNode<IntPtrT> entry_start_position;
  TNode<IntPtrT> next_index;

  std::tie(key, entry_start_position, next_index) =
      NextSkipHashTableHoles<CollectionType>(table, index, if_end);

  return TorqueStructKeyIndexPair{key, next_index};
}

template TorqueStructKeyIndexPair
CollectionsBuiltinsAssembler::NextKeyIndexPair(
    const TNode<OrderedHashMap> table, const TNode<IntPtrT> index,
    Label* if_end);
template TorqueStructKeyIndexPair
CollectionsBuiltinsAssembler::NextKeyIndexPair(
    const TNode<OrderedHashSet> table, const TNode<IntPtrT> index,
    Label* if_end);

TorqueStructKeyValueIndexTuple
CollectionsBuiltinsAssembler::NextKeyValueIndexTupleUnmodifiedTable(
    const TNode<OrderedHashMap> table, const TNode<Int32T> number_of_buckets,
    const TNode<Int32T> used_capacity, const TNode<IntPtrT> index,
    Label* if_end) {
  TNode<Object> key;
  TNode<IntPtrT> entry_start_position;
  TNode<IntPtrT> next_index;

  std::tie(key, entry_start_position, next_index) = NextSkipHashTableHoles(
      table, number_of_buckets, used_capacity, index, if_end);

  TNode<Object> value =
      UnsafeLoadValueFromOrderedHashMapEntry(table, entry_start_position);

  return TorqueStructKeyValueIndexTuple{key, value, next_index};
}

TorqueStructKeyValueIndexTuple
CollectionsBuiltinsAssembler::NextKeyValueIndexTuple(
    const TNode<OrderedHashMap> table, const TNode<IntPtrT> index,
    Label* if_end) {
  TNode<Object> key;
  TNode<IntPtrT> entry_start_position;
  TNode<IntPtrT> next_index;

  std::tie(key, entry_start_position, next_index) =
      NextSkipHashTableHoles(table, index, if_end);

  TNode<Object> value =
      UnsafeLoadValueFromOrderedHashMapEntry(table, entry_start_position);

  return TorqueStructKeyValueIndexTuple{key, value, next_index};
}

TF_BUILTIN(MapPrototypeGet, CollectionsBuiltinsAssembler) {
  const auto receiver = Parameter<Object>(Descriptor::kReceiver);
  const auto key = Parameter<Object>(Descriptor::kKey);
  const auto context = Parameter<Context>(Descriptor::kContext);

  ThrowIfNotInstanceType(context, receiver, JS_MAP_TYPE, "Map.prototype.get");

  const TNode<Object> table =
      LoadObjectField<Object>(CAST(receiver), JSMap::kTableOffset);
  TNode<Smi> index =
      CAST(CallBuiltin(Builtin::kFindOrderedHashMapEntry, context, table, key));

  Label if_found(this), if_not_found(this);
  Branch(SmiGreaterThanOrEqual(index, SmiConstant(0)), &if_found,
         &if_not_found);

  BIND(&if_found);
  Return(LoadValueFromOrderedHashMapEntry(CAST(table), SmiUntag(index)));

  BIND(&if_not_found);
  Return(UndefinedConstant());
}

TF_BUILTIN(MapPrototypeHas, CollectionsBuiltinsAssembler) {
  const auto receiver = Parameter<Object>(Descriptor::kReceiver);
  const auto key = Parameter<Object>(Descriptor::kKey);
  const auto context = Parameter<Context>(Descriptor::kContext);

  ThrowIfNotInstanceType(context, receiver, JS_MAP_TYPE, "Map.prototype.has");

  const TNode<OrderedHashMap> table =
      CAST(LoadObjectField(CAST(receiver), JSMap::kTableOffset));

  Label if_found(this), if_not_found(this);
  Branch(TableHasKey(context, table, key), &if_found, &if_not_found);

  BIND(&if_found);
  Return(TrueConstant());

  BIND(&if_not_found);
  Return(FalseConstant());
}

TNode<BoolT> CollectionsBuiltinsAssembler::TableHasKey(
    const TNode<Object> context, TNode<OrderedHashMap> table,
    TNode<Object> key) {
  TNode<Smi> index =
      CAST(CallBuiltin(Builtin::kFindOrderedHashMapEntry, context, table, key));

  return SmiGreaterThanOrEqual(index, SmiConstant(0));
}

const TNode<Object> CollectionsBuiltinsAssembler::NormalizeNumberKey(
    const TNode<Object> key) {
  TVARIABLE(Object, result, key);
  Label done(this);

  GotoIf(TaggedIsSmi(key), &done);
  GotoIfNot(IsHeapNumber(CAST(key)), &done);
  const TNode<Float64T> number = LoadHeapNumberValue(CAST(key));
  GotoIfNot(Float64Equal(number, Float64Constant(0.0)), &done);
  // We know the value is zero, so we take the key to be Smi 0.
  // Another option would be to normalize to Smi here.
  result = SmiConstant(0);
  Goto(&done);

  BIND(&done);
  return result.value();
}

template <typename CollectionType>
TNode<CollectionType> CollectionsBuiltinsAssembler::AddToOrderedHashTable(
    const TNode<CollectionType> table, const TNode<Object> key,
    const GrowCollection<CollectionType>& grow,
    const StoreAtEntry<CollectionType>& store_at_new_entry,
    const StoreAtEntry<CollectionType>& store_at_existing_entry) {
  TVARIABLE(CollectionType, table_var, table);
  TVARIABLE(IntPtrT, entry_start_position_or_hash, IntPtrConstant(0));
  Label entry_found(this), not_found(this), done(this);

  TryLookupOrderedHashTableIndex<CollectionType>(
      table, key, &entry_start_position_or_hash, &entry_found, &not_found);

  BIND(&entry_found);
  {
    // If we found the entry, we just store the value there.
    store_at_existing_entry(table, entry_start_position_or_hash.value());
    Goto(&done);
  }

  Label no_hash(this), add_entry(this), store_new_entry(this);
  BIND(&not_found);
  {
    // If we have a hash code, we can start adding the new entry.
    GotoIf(IntPtrGreaterThan(entry_start_position_or_hash.value(),
                             IntPtrConstant(0)),
           &add_entry);

    // Otherwise, g
```