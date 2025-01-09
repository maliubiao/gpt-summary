Response:
The user wants to understand the functionality of the provided C++ code snippet from V8's `builtins-collections-gen.cc` file. The request has several constraints:

1. **List Functionality:** Enumerate the purposes of the code.
2. **Torque Source:** Check if the file could be a Torque source based on its name.
3. **JavaScript Relation:** If related to JavaScript, provide a JavaScript example.
4. **Logic Inference:** For code with logical steps, give an example with input and output.
5. **Common Errors:** Highlight potential programming mistakes the code might prevent or handle.
6. **Part 4 of 4:** Summarize the overall function of this specific part.

Let's break down the code and address each point.

**Code Analysis:**

The code heavily uses the `CodeStubAssembler` (CSA) which is V8's internal DSL for generating machine code. It defines several helper functions and built-in functions related to `WeakMap` and `WeakSet`.

**Helper Functions:** These functions provide low-level operations on hash tables (specifically `EphemeronHashTable`) used by `WeakMap` and `WeakSet`. They handle:
    - Hash computation (`GetHash`)
    - Table allocation (`AllocateTable`)
    - Entry finding (`FindKeyIndex`, `FindKeyIndexForInsertion`)
    - Entry addition (`AddEntry`)
    - Entry removal (`RemoveEntry`)
    - Capacity management (growth, shrinking)
    - Loading table properties (capacity, element count)

**Built-in Functions (TF_BUILTIN):** These are the JavaScript-callable functions that implement the `WeakMap` and `WeakSet` API. They call the helper functions to perform their operations. The built-ins are:
    - Constructors (`WeakMapConstructor`, `WeakSetConstructor`)
    - `get` (`WeakMapGet`)
    - `has` (`WeakMapPrototypeHas`, `WeakSetPrototypeHas`)
    - `delete` (`WeakMapPrototypeDelete`, `WeakSetPrototypeDelete`, `WeakCollectionDelete`)
    - `set` (`WeakMapPrototypeSet`, `WeakCollectionSet`)
    - `add` (`WeakSetPrototypeAdd`)
    - Internal lookup (`WeakMapLookupHashIndex`)

**Constraint Checklist & Plan:**

1. **List Functionality:** I will list the purpose of each helper function and built-in.
2. **Torque Source:**  I will check the file extension condition.
3. **JavaScript Relation:** I will provide JavaScript examples for `WeakMap` and `WeakSet` methods.
4. **Logic Inference:**  I will pick a function like `FindKeyIndex` and provide a simplified scenario with inputs and the expected output.
5. **Common Errors:** I will consider typical errors when using `WeakMap` and `WeakSet` and see if the code handles them (e.g., using non-object keys for `WeakMap`).
6. **Part 4 of 4:** I will summarize the role of this code within the larger context of `WeakMap` and `WeakSet` implementation.

**Drafting the Response:**

Now I will construct the answer based on the analysis and planning. I need to be clear and concise in explaining each function and its relation to JavaScript. I'll pay attention to the specific details requested in the prompt.
```cpp
ups, methodName]() {
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
```

### 功能列举

`v8/src/builtins/builtins-collections-gen.cc` 实现了 `WeakMap` 和 `WeakSet` 的内置函数，主要功能包括：

1. **构造函数:**
    *   `WeakMapConstructor`: 创建 `WeakMap` 实例。
    *   `WeakSetConstructor`: 创建 `WeakSet` 实例。

2. **`WeakMap` 的方法:**
    *   `WeakMapGet`: 获取 `WeakMap` 中指定键对应的值。
    *   `WeakMapPrototypeHas`: 检查 `WeakMap` 中是否存在指定的键。
    *   `WeakMapPrototypeDelete`: 从 `WeakMap` 中删除指定的键值对。
    *   `WeakMapPrototypeSet`: 在 `WeakMap` 中设置指定的键值对。

3. **`WeakSet` 的方法:**
    *   `WeakSetPrototypeAdd`: 向 `WeakSet` 中添加一个值。
    *   `WeakSetPrototypeDelete`: 从 `WeakSet` 中删除一个值。
    *   `WeakSetPrototypeHas`: 检查 `WeakSet` 中是否存在指定的值。

4. **内部辅助函数:**
    *   `WeakMapLookupHashIndex`: 在 `WeakMap` 的内部哈希表中查找键的索引。
    *   `WeakCollectionDelete`:  `WeakMap` 和 `WeakSet` 共用的删除元素的逻辑。
    *   `WeakCollectionSet`: `WeakMap` 和 `WeakSet` 共用的设置元素的逻辑 (对于 `WeakSet`，value 为 `true`)。
    *   `AddEntry`: 向 `EphemeronHashTable` 中添加条目。
    *   `GetHash`: 计算对象的哈希值，用于哈希表操作。
    *   `AllocateTable`: 为 `WeakMap` 或 `WeakSet` 分配内部哈希表。
    *   `CreateIdentityHash`:  为对象创建唯一标识哈希值。
    *   `EntryMask`, `Coefficient`:  用于哈希表索引计算的辅助函数。
    *   `FindKeyIndex`, `FindKeyIndexForInsertion`, `FindKeyIndexForKey`: 在哈希表中查找键的索引。
    *   `KeyIndexFromEntry`, `ValueIndexFromKeyIndex`: 在哈希表条目中计算键和值的索引。
    *   `LoadNumberOfElements`, `LoadNumberOfDeleted`, `LoadTable`, `LoadTableCapacity`: 加载哈希表的状态信息。
    *   `InsufficientCapacityToAdd`, `ShouldRehash`, `ShouldShrink`:  判断哈希表是否需要扩容、重新哈希或收缩。
    *   `RemoveEntry`: 从 `EphemeronHashTable` 中移除条目。

### 关于 Torque 源代码

如果 `v8/src/builtins/builtins-collections-gen.cc` 以 `.tq` 结尾，那么它确实是一个 V8 Torque 源代码文件。但根据您提供的文件名，它是 `.cc` 文件，所以是用 C++ 编写的，并使用了 V8 的 `CodeStubAssembler` (CSA) 来生成机器码。 Torque 是一种更高级的类型化的 DSL，可以编译成 CSA 代码。

### 与 Javascript 的关系及举例

`v8/src/builtins/builtins-collections-gen.cc` 中的代码直接实现了 JavaScript 中 `WeakMap` 和 `WeakSet` 的功能。

**JavaScript 示例：**

```javascript
// WeakMap 示例
const wm = new WeakMap();
const key1 = {};
const key2 = {};
wm.set(key1, 'value1');
wm.set(key2, 'value2');

console.log(wm.get(key1)); // 输出: value1
console.log(wm.has(key2)); // 输出: true
wm.delete(key1);
console.log(wm.has(key1)); // 输出: false

// WeakSet 示例
const ws = new WeakSet();
const obj1 = {};
const obj2 = {};
ws.add(obj1);
ws.add(obj2);

console.log(ws.has(obj1)); // 输出: true
ws.delete(obj2);
console.log(ws.has(obj2)); // 输出: false
```

这段 C++ 代码中的 `TF_BUILTIN` 宏定义的函数（例如 `WeakMapGet`, `Weak
Prompt: 
```
这是目录为v8/src/builtins/builtins-collections-gen.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/builtins-collections-gen.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共4部分，请归纳一下它的功能

"""
ups, methodName]() {
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