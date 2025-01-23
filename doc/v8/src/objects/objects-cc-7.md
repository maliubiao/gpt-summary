Response:
My thinking process to analyze the `objects.cc` file and generate the summary went something like this:

1. **Understand the Goal:** The request asks for a functional summary of the provided C++ code snippet from V8's `objects.cc`. Key constraints are identifying its purpose, relating it to JavaScript if applicable, providing examples, and acknowledging it's part 8/8.

2. **Initial Scan for Core Functionality:** I first scanned the code for recurring patterns and keywords. I noticed a lot of template code, particularly involving `HashTable`, `ObjectHashTableBase`, `ObjectMultiHashTableBase`, and dictionaries (`SimpleNumberDictionary`, `NumberDictionary`, `NameDictionary`, `GlobalDictionary`). This immediately pointed towards the core function: **implementing various hash table and dictionary structures within V8.**

3. **Focus on Key Classes and Methods:**  I then looked at the concrete classes derived from these templates (e.g., `ObjectHashSet`, `JSSet`, `JSMap`, `JSWeakCollection`, `PropertyCell`, `JSGeneratorObject`, `AccessCheckInfo`, `Smi`, `JSFinalizationRegistry`). I analyzed the methods within these classes, paying attention to verbs like `Put`, `Remove`, `Add`, `Lookup`, `Initialize`, `Clear`, `Rehash`, `Set`, `Delete`, `GetEntries`, `Invalidate`, `Compare`. This helped me understand the specific operations supported by each structure.

4. **Identify JavaScript Relationships:**  I looked for classes and methods that clearly map to JavaScript concepts. `JSSet`, `JSMap`, and `JSWeakCollection` are direct counterparts to JavaScript's `Set`, `Map`, and `WeakMap`/`WeakSet`. The methods within them (`Initialize`, `Clear`, `Rehash`, `Set`, `Delete`, `GetEntries`) strongly suggest their role in implementing these JavaScript built-in objects. `PropertyCell` relates to how JavaScript object properties are stored and managed. `JSGeneratorObject` clearly deals with the implementation of JavaScript generators. `JSFinalizationRegistry` is for JavaScript's finalization registry feature.

5. **Construct JavaScript Examples:** Based on the identified JavaScript relationships, I created simple JavaScript code snippets demonstrating the functionality. For instance, the `JSSet` section got examples of `add`, `delete`, and `clear`. Similarly, `JSMap` received examples of `set`, `get`, and `delete`. For `JSWeakCollection`, I focused on the weak referencing aspect.

6. **Infer Code Logic and Provide Examples:** For lower-level structures like `ObjectHashTableBase` and `ObjectMultiHashTableBase`, I inferred the logic of adding, removing, and looking up entries. I provided hypothetical input and output to illustrate these operations. For example, showing how a key-value pair might be added and then retrieved from a hash table.

7. **Identify Potential Programming Errors:** I considered how developers might misuse the features implemented in the code. For example, using non-object keys in `WeakMap` or `WeakSet`, leading to unexpected behavior or errors. I also highlighted the importance of `Set` and `Map` keys having proper hash functions.

8. **Address Specific Instructions:** I made sure to explicitly address the instructions about `.tq` files (not applicable here), the connection to JavaScript, providing examples, explaining logic, mentioning common errors, and acknowledging the "part 8/8" context.

9. **Synthesize the Summary:**  Finally, I combined all the individual observations into a coherent summary, starting with the overall purpose (hash tables and dictionaries) and then diving into the specifics of each key class and its associated JavaScript functionality. I organized the summary logically, grouping related concepts together. I paid attention to using clear and concise language. The concluding summary for part 8 emphasized the comprehensive nature of the file and its role in fundamental object management.

10. **Review and Refine:** I reread the generated summary and compared it against the code snippet to ensure accuracy and completeness. I checked for any ambiguities or areas where the explanation could be improved. I also made sure the tone was appropriate for a technical explanation.
```cpp
ble->HasSufficientCapacityToAdd(1)) {
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
  // of any digit. Otherwise, we make both values positive.

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
  // lexicographic order. If one integer has fewer digits, it is scaled
  // by some power of 10 to have the same number of digits as the longer
  // integer. If the scaled integers are equal it means the shorter
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
    // X has fewer digits. We would like to simply scale up X but that
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
    // weak_cell is somewhere in the middle of its key list
### 提示词
```
这是目录为v8/src/objects/objects.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/objects.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第8部分，共8部分，请归纳一下它的功能
```

### 源代码
```cpp
ble->HasSufficientCapacityToAdd(1)) {
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