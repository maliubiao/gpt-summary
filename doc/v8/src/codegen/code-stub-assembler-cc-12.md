Response:
My thought process for analyzing the provided V8 C++ code snippet goes like this:

1. **Identify the Core Functionality:** I first look for the most prominent functions and their purpose. The names like `NameDictionaryLookupWithForwardIndex`, `NumberDictionaryLookup`, `AddToDictionary`, `LookupLinear`, `LookupBinary`, and `ForEachEnumerableOwnProperty` strongly suggest operations related to property lookup and manipulation within JavaScript objects. The use of terms like "Dictionary," "Name," "Number," and "Property" further reinforces this.

2. **Analyze Key Data Structures:**  The code mentions `NameDictionary`, `GlobalDictionary`, `NumberDictionary`, `SwissNameDictionary`, `TransitionArray`, and `DescriptorArray`. I recognize these as V8's internal data structures for efficiently storing and accessing object properties. Understanding these structures is crucial to understanding the code's function.

3. **Examine Template Usage:** The code makes extensive use of C++ templates. This indicates that the underlying logic is often the same, but the specific data structures and access methods might differ. I pay attention to template specializations, as these highlight where the behavior diverges for different dictionary types.

4. **Trace Control Flow:** The code uses `Label`s and `Goto` statements extensively. This signifies state machine-like logic or complex conditional branching within the code stubs. I try to follow the flow, especially within functions like `NumberDictionaryLookup` where there's a clear loop for probing the dictionary.

5. **Look for Interactions with JavaScript Concepts:** I search for keywords or patterns that connect the C++ code to JavaScript behavior. For instance, the `ForEachEnumerableOwnProperty` function clearly relates to the iteration of an object's properties in JavaScript. The mentions of "enumerable," "private symbols," and "accessors" further strengthen this link.

6. **Infer Functionality from External References (ER):** The code uses `ExternalReference` (ER) extensively. This suggests calls to pre-compiled C++ functions within V8. While I don't have the exact implementation of those functions, their names (e.g., `name_dictionary_lookup_forwarded_string`, `compute_integer_hash`) provide hints about their purpose.

7. **Identify Assumptions and Checks:** The `CSA_DCHECK` macros indicate internal assertions and assumptions made by the V8 developers. These can be helpful in understanding the expected state of the program at certain points.

8. **Consider Error Handling and Edge Cases:**  The presence of `bailout` labels suggests points where the code might need to fall back to a slower or more general implementation if certain conditions aren't met (e.g., dictionary is full, object shape has changed).

9. **Relate to User-Visible Errors:** I consider how the internal logic might relate to common JavaScript errors. For instance, issues with property lookup or modification could stem from the dictionary operations. The comments about potential enumeration order problems (crbug.com/41432983) also provide context.

10. **Synthesize and Summarize:** After analyzing the individual components, I try to synthesize a higher-level understanding of the code's role. I focus on its contribution to the overall process of managing and accessing object properties in V8.

**Self-Correction/Refinement during the Process:**

* Initially, I might focus too much on the low-level details of each function. I then need to step back and consider the broader picture.
* If I encounter unfamiliar data structures or external references, I might need to do some quick searches or make informed guesses based on their names and context.
* If the control flow is particularly complex, I might mentally trace through a few example scenarios to understand how the code behaves under different conditions.
* If I'm struggling to connect the C++ code to JavaScript, I might think about how a particular JavaScript operation (e.g., accessing a property, iterating over an object) is likely implemented internally.

By following these steps and iteratively refining my understanding, I can arrive at a comprehensive summary of the code's functionality, even without having the complete V8 codebase.
Based on the provided C++ code snippet from `v8/src/codegen/code-stub-assembler.cc`, which is part 13 of 23, here's a breakdown of its functionality:

**Core Functionality:**

This section of `code-stub-assembler.cc` focuses on implementing efficient **property lookup and manipulation** for JavaScript objects. It provides a set of building blocks (assembler snippets) that are used in generated code stubs for common operations involving object properties. Specifically, it deals with:

* **Dictionary-based property storage:**  JavaScript objects can store properties in dictionaries (hash tables) when the number of properties grows or when certain conditions are met. This code provides functions to interact with different dictionary implementations:
    * `NameDictionary`:  For storing string-based property names.
    * `GlobalDictionary`:  Similar to `NameDictionary`, likely used for the global object.
    * `NumberDictionary`: For storing properties accessed via array indices (numbers).
    * `SwissNameDictionary`: A more modern and efficient dictionary implementation.
* **Linear and Binary Search in Arrays:**  For objects with a smaller, fixed set of properties, the property information might be stored in sorted arrays (`TransitionArray`, `DescriptorArray`). This code provides efficient linear and binary search implementations to find property information within these arrays.
* **Iterating over enumerable properties:** The `ForEachEnumerableOwnProperty` function provides a mechanism to iterate through the enumerable properties of a JavaScript object, taking into account potential changes to the object's structure during iteration.
* **Helper functions:** It also includes utility functions for tasks like computing hash codes, accessing dictionary entries, and retrieving object metadata (like the constructor).

**Relationship to JavaScript:**

This code directly underpins how V8 implements fundamental JavaScript object operations. Here's a JavaScript example and how this C++ code might be involved:

```javascript
const obj = { a: 1, b: 2 };
console.log(obj.a); // Property lookup
obj.c = 3;         // Property addition
for (let key in obj) { // Enumerable property iteration
  console.log(key);
}
```

* **`console.log(obj.a)` (Property Lookup):**  V8 might use a code stub generated with the help of functions like `NameDictionaryLookup` (if `obj` uses a `NameDictionary`) or `LookupLinear`/`LookupBinary` (if using a `DescriptorArray`). The C++ code would efficiently find the entry associated with the key "a" in the object's internal storage.
* **`obj.c = 3` (Property Addition):** If adding 'c' causes the object to transition to a dictionary representation or if the object already uses a dictionary, functions like `AddToDictionary` and `InsertEntry` would be used to add the new property and its value to the appropriate dictionary.
* **`for (let key in obj)` (Enumerable Property Iteration):** The `ForEachEnumerableOwnProperty` function would be called to iterate over the enumerable properties of `obj`, yielding "a", "b", and "c" in this case.

**Code Logic Inference (Example: `NumberDictionaryLookup`):**

**Assumption:** We're looking for a property with the integer index `5` in a `NumberDictionary`.

**Input:**
* `dictionary`: A `TNode<NumberDictionary>` representing the dictionary.
* `intptr_index`: A `TNode<IntPtrT>` representing the integer index `5`.
* `if_found`: A `Label` to jump to if the property is found.
* `var_entry`: A `TVariable<IntPtrT>*` to store the entry index if found.
* `if_not_found`: A `Label` to jump to if the property is not found.

**Logic:**

1. **Calculate Hash and Initial Probe:**  The code calculates a hash of the `intptr_index` (5) and uses it to determine the initial position to check in the dictionary's internal array.
2. **Linear Probing:** It enters a loop, checking entries in the dictionary.
3. **Check for Empty Slot:** If an empty slot (`undefined`) is found, the property is not present, and it jumps to `if_not_found`.
4. **Check for Deleted Slot:** If a deleted slot (`the_hole`) is found, it continues to the next probe.
5. **Check for Smi:** If the current entry is a Small Integer (Smi), it compares the untagged Smi value with the `intptr_index`. If they match, it jumps to `if_found`, and the index of the entry is stored in `var_entry`.
6. **Check for HeapNumber:** If the current entry is a HeapNumber, it converts both the entry and the `intptr_index` to `Float64T` and compares them. If they match, it jumps to `if_found`, and the index is stored in `var_entry`.
7. **Next Probe:** If no match is found in the current slot, it calculates the next probe index using a linear probing strategy and continues the loop.

**Output (Possible Scenarios):**

* **Property found:** Jumps to the `if_found` label, and `var_entry` will contain the index of the entry in the `NumberDictionary` where the property with index 5 is stored.
* **Property not found:** Jumps to the `if_not_found` label.

**User-Common Programming Errors:**

While this C++ code is internal to V8, its behavior directly affects how JavaScript code executes. Here are some user-level programming errors that might surface due to issues in these low-level operations:

* **Unexpected `undefined`:** If there's a bug in the dictionary lookup or insertion logic, a user might encounter an unexpected `undefined` when trying to access a property they believe should exist. This could happen if a property was not correctly added to the dictionary.
    ```javascript
    const obj = {};
    obj.myProp = 42;
    console.log(obj.myProp); // Expected: 42, Possible Error: undefined if insertion failed
    ```
* **Performance issues with large objects:**  Inefficient dictionary implementations or lookup algorithms could lead to performance problems when working with objects that have a large number of properties. While V8's implementations are highly optimized, understanding the underlying mechanisms helps appreciate the importance of keeping objects lean when performance is critical.
* **Issues with property enumeration:** Bugs in `ForEachEnumerableOwnProperty` could lead to incorrect or incomplete iteration of an object's properties in `for...in` loops or when using methods like `Object.keys()`.

**Summary of Functionality (Part 13/23):**

This portion of `v8/src/codegen/code-stub-assembler.cc` provides the foundational code building blocks for **efficiently managing and accessing properties of JavaScript objects, particularly when those properties are stored in dictionary-like structures or sorted arrays.** It includes functions for looking up, inserting, and iterating over properties in different dictionary implementations and sorted array formats used internally by V8. This code is crucial for the performance and correctness of JavaScript object manipulation.

The ".tq" check is irrelevant here since the provided code is clearly C++ (`.cc`).

### 提示词
```
这是目录为v8/src/codegen/code-stub-assembler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/code-stub-assembler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第13部分，共23部分，请归纳一下它的功能
```

### 源代码
```cpp
ary>, TNode<Name>, Label*,
                      TVariable<IntPtrT>*, Label*, LookupMode);

template <typename Dictionary>
void CodeStubAssembler::NameDictionaryLookupWithForwardIndex(
    TNode<Dictionary> dictionary, TNode<Name> unique_name, Label* if_found,
    TVariable<IntPtrT>* var_name_index, Label* if_not_found, LookupMode mode) {
  using ER = ExternalReference;  // To avoid super long lines below.
  ER func_ref;
  if constexpr (std::is_same<Dictionary, NameDictionary>::value) {
    func_ref = mode == kFindInsertionIndex
                   ? ER::name_dictionary_find_insertion_entry_forwarded_string()
                   : ER::name_dictionary_lookup_forwarded_string();
  } else if constexpr (std::is_same<Dictionary, GlobalDictionary>::value) {
    func_ref =
        mode == kFindInsertionIndex
            ? ER::global_dictionary_find_insertion_entry_forwarded_string()
            : ER::global_dictionary_lookup_forwarded_string();
  } else {
    auto ref0 =
        ER::name_to_index_hashtable_find_insertion_entry_forwarded_string();
    auto ref1 = ER::name_to_index_hashtable_lookup_forwarded_string();
    func_ref = mode == kFindInsertionIndex ? ref0 : ref1;
  }
  const TNode<ER> function = ExternalConstant(func_ref);
  const TNode<ER> isolate_ptr = ExternalConstant(ER::isolate_address());
  TNode<IntPtrT> entry = UncheckedCast<IntPtrT>(
      CallCFunction(function, MachineType::IntPtr(),
                    std::make_pair(MachineType::Pointer(), isolate_ptr),
                    std::make_pair(MachineType::TaggedPointer(), dictionary),
                    std::make_pair(MachineType::TaggedPointer(), unique_name)));

  if (var_name_index) *var_name_index = EntryToIndex<Dictionary>(entry);
  switch (mode) {
    case kFindInsertionIndex:
      CSA_DCHECK(
          this,
          WordNotEqual(entry,
                       IntPtrConstant(InternalIndex::NotFound().raw_value())));
      Goto(if_not_found);
      break;
    case kFindExisting:
      GotoIf(IntPtrEqual(entry,
                         IntPtrConstant(InternalIndex::NotFound().raw_value())),
             if_not_found);
      Goto(if_found);
      break;
    case kFindExistingOrInsertionIndex:
      GotoIfNot(IntPtrEqual(entry, IntPtrConstant(
                                       InternalIndex::NotFound().raw_value())),
                if_found);
      NameDictionaryLookupWithForwardIndex(dictionary, unique_name, if_found,
                                           var_name_index, if_not_found,
                                           kFindInsertionIndex);
      break;
  }
}

TNode<Word32T> CodeStubAssembler::ComputeSeededHash(TNode<IntPtrT> key) {
  const TNode<ExternalReference> function_addr =
      ExternalConstant(ExternalReference::compute_integer_hash());
  const TNode<ExternalReference> isolate_ptr =
      ExternalConstant(ExternalReference::isolate_address());

  MachineType type_ptr = MachineType::Pointer();
  MachineType type_uint32 = MachineType::Uint32();
  MachineType type_int32 = MachineType::Int32();

  return UncheckedCast<Word32T>(CallCFunction(
      function_addr, type_uint32, std::make_pair(type_ptr, isolate_ptr),
      std::make_pair(type_int32, TruncateIntPtrToInt32(key))));
}

template <>
void CodeStubAssembler::NameDictionaryLookup(
    TNode<SwissNameDictionary> dictionary, TNode<Name> unique_name,
    Label* if_found, TVariable<IntPtrT>* var_name_index, Label* if_not_found,
    LookupMode mode) {
  // TODO(pthier): Support mode kFindExistingOrInsertionIndex for
  // SwissNameDictionary.
  SwissNameDictionaryFindEntry(dictionary, unique_name, if_found,
                               var_name_index, if_not_found);
}

void CodeStubAssembler::NumberDictionaryLookup(
    TNode<NumberDictionary> dictionary, TNode<IntPtrT> intptr_index,
    Label* if_found, TVariable<IntPtrT>* var_entry, Label* if_not_found) {
  CSA_DCHECK(this, IsNumberDictionary(dictionary));
  DCHECK_EQ(MachineType::PointerRepresentation(), var_entry->rep());
  Comment("NumberDictionaryLookup");

  TNode<IntPtrT> capacity =
      PositiveSmiUntag(GetCapacity<NumberDictionary>(dictionary));
  TNode<IntPtrT> mask = IntPtrSub(capacity, IntPtrConstant(1));

  TNode<UintPtrT> hash = ChangeUint32ToWord(ComputeSeededHash(intptr_index));
  TNode<Float64T> key_as_float64 = RoundIntPtrToFloat64(intptr_index);

  // See Dictionary::FirstProbe().
  TNode<IntPtrT> count = IntPtrConstant(0);
  TNode<IntPtrT> initial_entry = Signed(WordAnd(hash, mask));

  TNode<Undefined> undefined = UndefinedConstant();
  TNode<Hole> the_hole = TheHoleConstant();

  TVARIABLE(IntPtrT, var_count, count);
  Label loop(this, {&var_count, var_entry});
  *var_entry = initial_entry;
  Goto(&loop);
  BIND(&loop);
  {
    TNode<IntPtrT> entry = var_entry->value();

    TNode<IntPtrT> index = EntryToIndex<NumberDictionary>(entry);
    TNode<Object> current = UnsafeLoadFixedArrayElement(dictionary, index);
    GotoIf(TaggedEqual(current, undefined), if_not_found);
    Label next_probe(this);
    {
      Label if_currentissmi(this), if_currentisnotsmi(this);
      Branch(TaggedIsSmi(current), &if_currentissmi, &if_currentisnotsmi);
      BIND(&if_currentissmi);
      {
        TNode<IntPtrT> current_value = SmiUntag(CAST(current));
        Branch(WordEqual(current_value, intptr_index), if_found, &next_probe);
      }
      BIND(&if_currentisnotsmi);
      {
        GotoIf(TaggedEqual(current, the_hole), &next_probe);
        // Current must be the Number.
        TNode<Float64T> current_value = LoadHeapNumberValue(CAST(current));
        Branch(Float64Equal(current_value, key_as_float64), if_found,
               &next_probe);
      }
    }

    BIND(&next_probe);
    // See Dictionary::NextProbe().
    Increment(&var_count);
    entry = Signed(WordAnd(IntPtrAdd(entry, var_count.value()), mask));

    *var_entry = entry;
    Goto(&loop);
  }
}

TNode<Object> CodeStubAssembler::BasicLoadNumberDictionaryElement(
    TNode<NumberDictionary> dictionary, TNode<IntPtrT> intptr_index,
    Label* not_data, Label* if_hole) {
  TVARIABLE(IntPtrT, var_entry);
  Label if_found(this);
  NumberDictionaryLookup(dictionary, intptr_index, &if_found, &var_entry,
                         if_hole);
  BIND(&if_found);

  // Check that the value is a data property.
  TNode<IntPtrT> index = EntryToIndex<NumberDictionary>(var_entry.value());
  TNode<Uint32T> details = LoadDetailsByKeyIndex(dictionary, index);
  TNode<Uint32T> kind = DecodeWord32<PropertyDetails::KindField>(details);
  // TODO(jkummerow): Support accessors without missing?
  GotoIfNot(
      Word32Equal(kind, Int32Constant(static_cast<int>(PropertyKind::kData))),
      not_data);
  // Finally, load the value.
  return LoadValueByKeyIndex(dictionary, index);
}

template <class Dictionary>
void CodeStubAssembler::FindInsertionEntry(TNode<Dictionary> dictionary,
                                           TNode<Name> key,
                                           TVariable<IntPtrT>* var_key_index) {
  UNREACHABLE();
}

template <>
void CodeStubAssembler::FindInsertionEntry<NameDictionary>(
    TNode<NameDictionary> dictionary, TNode<Name> key,
    TVariable<IntPtrT>* var_key_index) {
  Label done(this);
  NameDictionaryLookup<NameDictionary>(dictionary, key, nullptr, var_key_index,
                                       &done, kFindInsertionIndex);
  BIND(&done);
}

template <class Dictionary>
void CodeStubAssembler::InsertEntry(TNode<Dictionary> dictionary,
                                    TNode<Name> key, TNode<Object> value,
                                    TNode<IntPtrT> index,
                                    TNode<Smi> enum_index) {
  UNREACHABLE();  // Use specializations instead.
}

template <>
void CodeStubAssembler::InsertEntry<NameDictionary>(
    TNode<NameDictionary> dictionary, TNode<Name> name, TNode<Object> value,
    TNode<IntPtrT> index, TNode<Smi> enum_index) {
  // This should only be used for adding, not updating existing mappings.
  CSA_DCHECK(this,
             Word32Or(TaggedEqual(LoadFixedArrayElement(dictionary, index),
                                  UndefinedConstant()),
                      TaggedEqual(LoadFixedArrayElement(dictionary, index),
                                  TheHoleConstant())));

  // Store name and value.
  StoreFixedArrayElement(dictionary, index, name);
  StoreValueByKeyIndex<NameDictionary>(dictionary, index, value);

  // Prepare details of the new property.
  PropertyDetails d(PropertyKind::kData, NONE,
                    PropertyDetails::kConstIfDictConstnessTracking);

  // We ignore overflow of |enum_index| here and accept potentially
  // broken enumeration order (https://crbug.com/41432983).
  enum_index = UnsignedSmiShl(enum_index,
                              PropertyDetails::DictionaryStorageField::kShift);
  // We OR over the actual index below, so we expect the initial value to be 0.
  DCHECK_EQ(0, d.dictionary_index());
  TVARIABLE(Smi, var_details, SmiOr(SmiConstant(d.AsSmi()), enum_index));

  // Private names must be marked non-enumerable.
  Label not_private(this, &var_details);
  GotoIfNot(IsPrivateSymbol(name), &not_private);
  TNode<Smi> dont_enum = UnsignedSmiShl(
      SmiConstant(DONT_ENUM), PropertyDetails::AttributesField::kShift);
  var_details = SmiOr(var_details.value(), dont_enum);
  Goto(&not_private);
  BIND(&not_private);

  // Finally, store the details.
  StoreDetailsByKeyIndex<NameDictionary>(dictionary, index,
                                         var_details.value());
}

template <>
void CodeStubAssembler::InsertEntry<GlobalDictionary>(
    TNode<GlobalDictionary> dictionary, TNode<Name> key, TNode<Object> value,
    TNode<IntPtrT> index, TNode<Smi> enum_index) {
  UNIMPLEMENTED();
}

template <class Dictionary>
void CodeStubAssembler::AddToDictionary(
    TNode<Dictionary> dictionary, TNode<Name> key, TNode<Object> value,
    Label* bailout, std::optional<TNode<IntPtrT>> insertion_index) {
  CSA_DCHECK(this, Word32BinaryNot(IsEmptyPropertyDictionary(dictionary)));
  TNode<Smi> capacity = GetCapacity<Dictionary>(dictionary);
  TNode<Smi> nof = GetNumberOfElements<Dictionary>(dictionary);
  TNode<Smi> new_nof = SmiAdd(nof, SmiConstant(1));
  // Require 33% to still be free after adding additional_elements.
  // Computing "x + (x >> 1)" on a Smi x does not return a valid Smi!
  // But that's OK here because it's only used for a comparison.
  TNode<Smi> required_capacity_pseudo_smi = SmiAdd(new_nof, SmiShr(new_nof, 1));
  GotoIf(SmiBelow(capacity, required_capacity_pseudo_smi), bailout);
  // Require rehashing if more than 50% of free elements are deleted elements.
  TNode<Smi> deleted = GetNumberOfDeletedElements<Dictionary>(dictionary);
  CSA_DCHECK(this, SmiAbove(capacity, new_nof));
  TNode<Smi> half_of_free_elements = SmiShr(SmiSub(capacity, new_nof), 1);
  GotoIf(SmiAbove(deleted, half_of_free_elements), bailout);

  TNode<Smi> enum_index = GetNextEnumerationIndex<Dictionary>(dictionary);
  TNode<Smi> new_enum_index = SmiAdd(enum_index, SmiConstant(1));
  TNode<Smi> max_enum_index =
      SmiConstant(PropertyDetails::DictionaryStorageField::kMax);
  GotoIf(SmiAbove(new_enum_index, max_enum_index), bailout);

  // No more bailouts after this point.
  // Operations from here on can have side effects.

  SetNextEnumerationIndex<Dictionary>(dictionary, new_enum_index);
  SetNumberOfElements<Dictionary>(dictionary, new_nof);

  if (insertion_index.has_value()) {
    InsertEntry<Dictionary>(dictionary, key, value, *insertion_index,
                            enum_index);
  } else {
    TVARIABLE(IntPtrT, var_key_index);
    FindInsertionEntry<Dictionary>(dictionary, key, &var_key_index);
    InsertEntry<Dictionary>(dictionary, key, value, var_key_index.value(),
                            enum_index);
  }
}

template <>
void CodeStubAssembler::AddToDictionary(
    TNode<SwissNameDictionary> dictionary, TNode<Name> key, TNode<Object> value,
    Label* bailout, std::optional<TNode<IntPtrT>> insertion_index) {
  PropertyDetails d(PropertyKind::kData, NONE,
                    PropertyDetails::kConstIfDictConstnessTracking);

  PropertyDetails d_dont_enum(PropertyKind::kData, DONT_ENUM,
                              PropertyDetails::kConstIfDictConstnessTracking);
  TNode<Uint8T> details_byte_enum =
      UncheckedCast<Uint8T>(Uint32Constant(d.ToByte()));
  TNode<Uint8T> details_byte_dont_enum =
      UncheckedCast<Uint8T>(Uint32Constant(d_dont_enum.ToByte()));

  Label not_private(this);
  TVARIABLE(Uint8T, var_details, details_byte_enum);

  GotoIfNot(IsPrivateSymbol(key), &not_private);
  var_details = details_byte_dont_enum;
  Goto(&not_private);

  BIND(&not_private);
  // TODO(pthier): Use insertion_index if it was provided.
  SwissNameDictionaryAdd(dictionary, key, value, var_details.value(), bailout);
}

template void CodeStubAssembler::AddToDictionary<NameDictionary>(
    TNode<NameDictionary>, TNode<Name>, TNode<Object>, Label*,
    std::optional<TNode<IntPtrT>>);

template <class Dictionary>
TNode<Smi> CodeStubAssembler::GetNumberOfElements(
    TNode<Dictionary> dictionary) {
  return CAST(
      LoadFixedArrayElement(dictionary, Dictionary::kNumberOfElementsIndex));
}

template <>
TNode<Smi> CodeStubAssembler::GetNumberOfElements(
    TNode<SwissNameDictionary> dictionary) {
  TNode<IntPtrT> capacity =
      ChangeInt32ToIntPtr(LoadSwissNameDictionaryCapacity(dictionary));
  return SmiFromIntPtr(
      LoadSwissNameDictionaryNumberOfElements(dictionary, capacity));
}

template TNode<Smi> CodeStubAssembler::GetNumberOfElements(
    TNode<NameDictionary> dictionary);
template TNode<Smi> CodeStubAssembler::GetNumberOfElements(
    TNode<NumberDictionary> dictionary);
template TNode<Smi> CodeStubAssembler::GetNumberOfElements(
    TNode<GlobalDictionary> dictionary);

template <>
TNode<Smi> CodeStubAssembler::GetNameDictionaryFlags(
    TNode<NameDictionary> dictionary) {
  return CAST(LoadFixedArrayElement(dictionary, NameDictionary::kFlagsIndex));
}

template <>
void CodeStubAssembler::SetNameDictionaryFlags(TNode<NameDictionary> dictionary,
                                               TNode<Smi> flags) {
  StoreFixedArrayElement(dictionary, NameDictionary::kFlagsIndex, flags,
                         SKIP_WRITE_BARRIER);
}

template <>
TNode<Smi> CodeStubAssembler::GetNameDictionaryFlags(
    TNode<SwissNameDictionary> dictionary) {
  // TODO(pthier): Add flags to swiss dictionaries.
  Unreachable();
  return SmiConstant(0);
}

template <>
void CodeStubAssembler::SetNameDictionaryFlags(
    TNode<SwissNameDictionary> dictionary, TNode<Smi> flags) {
  // TODO(pthier): Add flags to swiss dictionaries.
  Unreachable();
}

namespace {
// TODO(leszeks): Remove once both TransitionArray and DescriptorArray are
// HeapObjectLayout.
template <typename Array>
struct OffsetOfArrayDataStart;
template <>
struct OffsetOfArrayDataStart<TransitionArray> {
  static constexpr int value = OFFSET_OF_DATA_START(TransitionArray);
};
template <>
struct OffsetOfArrayDataStart<DescriptorArray> {
  static constexpr int value = DescriptorArray::kHeaderSize;
};
}  // namespace

template <typename Array>
void CodeStubAssembler::LookupLinear(TNode<Name> unique_name,
                                     TNode<Array> array,
                                     TNode<Uint32T> number_of_valid_entries,
                                     Label* if_found,
                                     TVariable<IntPtrT>* var_name_index,
                                     Label* if_not_found) {
  static_assert(std::is_base_of<FixedArray, Array>::value ||
                    std::is_base_of<WeakFixedArray, Array>::value ||
                    std::is_base_of<DescriptorArray, Array>::value,
                "T must be a descendant of FixedArray or a WeakFixedArray");
  Comment("LookupLinear");
  CSA_DCHECK(this, IsUniqueName(unique_name));
  TNode<IntPtrT> first_inclusive = IntPtrConstant(Array::ToKeyIndex(0));
  TNode<IntPtrT> factor = IntPtrConstant(Array::kEntrySize);
  TNode<IntPtrT> last_exclusive = IntPtrAdd(
      first_inclusive,
      IntPtrMul(ChangeInt32ToIntPtr(number_of_valid_entries), factor));

  BuildFastLoop<IntPtrT>(
      last_exclusive, first_inclusive,
      [=, this](TNode<IntPtrT> name_index) {
        TNode<MaybeObject> element = LoadArrayElement(
            array, OffsetOfArrayDataStart<Array>::value, name_index);
        TNode<Name> candidate_name = CAST(element);
        *var_name_index = name_index;
        GotoIf(TaggedEqual(candidate_name, unique_name), if_found);
      },
      -Array::kEntrySize, LoopUnrollingMode::kYes, IndexAdvanceMode::kPre);
  Goto(if_not_found);
}

template <>
constexpr int CodeStubAssembler::MaxNumberOfEntries<TransitionArray>() {
  return TransitionsAccessor::kMaxNumberOfTransitions;
}

template <>
constexpr int CodeStubAssembler::MaxNumberOfEntries<DescriptorArray>() {
  return kMaxNumberOfDescriptors;
}

template <>
TNode<Uint32T> CodeStubAssembler::NumberOfEntries<DescriptorArray>(
    TNode<DescriptorArray> descriptors) {
  return Unsigned(LoadNumberOfDescriptors(descriptors));
}

template <>
TNode<Uint32T> CodeStubAssembler::NumberOfEntries<TransitionArray>(
    TNode<TransitionArray> transitions) {
  TNode<Uint32T> length = LoadAndUntagWeakFixedArrayLengthAsUint32(transitions);
  return Select<Uint32T>(
      Uint32LessThan(length, Uint32Constant(TransitionArray::kFirstIndex)),
      [=, this] { return Unsigned(Int32Constant(0)); },
      [=, this] {
        return Unsigned(LoadAndUntagToWord32ArrayElement(
            transitions, OFFSET_OF_DATA_START(WeakFixedArray),
            IntPtrConstant(TransitionArray::kTransitionLengthIndex)));
      });
}

template <typename Array>
TNode<IntPtrT> CodeStubAssembler::EntryIndexToIndex(
    TNode<Uint32T> entry_index) {
  TNode<Int32T> entry_size = Int32Constant(Array::kEntrySize);
  TNode<Word32T> index = Int32Mul(entry_index, entry_size);
  return ChangeInt32ToIntPtr(index);
}

template <typename Array>
TNode<IntPtrT> CodeStubAssembler::ToKeyIndex(TNode<Uint32T> entry_index) {
  return IntPtrAdd(IntPtrConstant(Array::ToKeyIndex(0)),
                   EntryIndexToIndex<Array>(entry_index));
}

template TNode<IntPtrT> CodeStubAssembler::ToKeyIndex<DescriptorArray>(
    TNode<Uint32T>);
template TNode<IntPtrT> CodeStubAssembler::ToKeyIndex<TransitionArray>(
    TNode<Uint32T>);

template <>
TNode<Uint32T> CodeStubAssembler::GetSortedKeyIndex<DescriptorArray>(
    TNode<DescriptorArray> descriptors, TNode<Uint32T> descriptor_number) {
  TNode<Uint32T> details =
      DescriptorArrayGetDetails(descriptors, descriptor_number);
  return DecodeWord32<PropertyDetails::DescriptorPointer>(details);
}

template <>
TNode<Uint32T> CodeStubAssembler::GetSortedKeyIndex<TransitionArray>(
    TNode<TransitionArray> transitions, TNode<Uint32T> transition_number) {
  return transition_number;
}

template <typename Array>
TNode<Name> CodeStubAssembler::GetKey(TNode<Array> array,
                                      TNode<Uint32T> entry_index) {
  static_assert(std::is_base_of<TransitionArray, Array>::value ||
                    std::is_base_of<DescriptorArray, Array>::value,
                "T must be a descendant of DescriptorArray or TransitionArray");
  const int key_offset = Array::ToKeyIndex(0) * kTaggedSize;
  TNode<MaybeObject> element =
      LoadArrayElement(array, OffsetOfArrayDataStart<Array>::value,
                       EntryIndexToIndex<Array>(entry_index), key_offset);
  return CAST(element);
}

template TNode<Name> CodeStubAssembler::GetKey<DescriptorArray>(
    TNode<DescriptorArray>, TNode<Uint32T>);
template TNode<Name> CodeStubAssembler::GetKey<TransitionArray>(
    TNode<TransitionArray>, TNode<Uint32T>);

TNode<Uint32T> CodeStubAssembler::DescriptorArrayGetDetails(
    TNode<DescriptorArray> descriptors, TNode<Uint32T> descriptor_number) {
  const int details_offset = DescriptorArray::ToDetailsIndex(0) * kTaggedSize;
  return Unsigned(LoadAndUntagToWord32ArrayElement(
      descriptors, DescriptorArray::kHeaderSize,
      EntryIndexToIndex<DescriptorArray>(descriptor_number), details_offset));
}

template <typename Array>
void CodeStubAssembler::LookupBinary(TNode<Name> unique_name,
                                     TNode<Array> array,
                                     TNode<Uint32T> number_of_valid_entries,
                                     Label* if_found,
                                     TVariable<IntPtrT>* var_name_index,
                                     Label* if_not_found) {
  Comment("LookupBinary");
  TVARIABLE(Uint32T, var_low, Unsigned(Int32Constant(0)));
  TNode<Uint32T> limit =
      Unsigned(Int32Sub(NumberOfEntries<Array>(array), Int32Constant(1)));
  TVARIABLE(Uint32T, var_high, limit);
  TNode<Uint32T> hash = LoadNameHashAssumeComputed(unique_name);
  CSA_DCHECK(this, Word32NotEqual(hash, Int32Constant(0)));

  // Assume non-empty array.
  CSA_DCHECK(this, Uint32LessThanOrEqual(var_low.value(), var_high.value()));

  int max_entries = MaxNumberOfEntries<Array>();

  auto calculate_mid = [&](TNode<Uint32T> low, TNode<Uint32T> high) {
    if (max_entries < kMaxInt31) {
      // mid = (low + high) / 2.
      return Unsigned(Word32Shr(Int32Add(low, high), 1));
    } else {
      // mid = low + (high - low) / 2.
      return Unsigned(Int32Add(low, Word32Shr(Int32Sub(high, low), 1)));
    }
  };

  Label binary_loop(this, {&var_high, &var_low});
  Goto(&binary_loop);
  BIND(&binary_loop);
  {
    TNode<Uint32T> mid = calculate_mid(var_low.value(), var_high.value());
    // mid_name = array->GetSortedKey(mid).
    TNode<Uint32T> sorted_key_index = GetSortedKeyIndex<Array>(array, mid);
    TNode<Name> mid_name = GetKey<Array>(array, sorted_key_index);

    TNode<Uint32T> mid_hash = LoadNameHashAssumeComputed(mid_name);

    Label mid_greater(this), mid_less(this), merge(this);
    Branch(Uint32GreaterThanOrEqual(mid_hash, hash), &mid_greater, &mid_less);
    BIND(&mid_greater);
    {
      var_high = mid;
      Goto(&merge);
    }
    BIND(&mid_less);
    {
      var_low = Unsigned(Int32Add(mid, Int32Constant(1)));
      Goto(&merge);
    }
    BIND(&merge);
    GotoIf(Word32NotEqual(var_low.value(), var_high.value()), &binary_loop);
  }

  Label scan_loop(this, &var_low);
  Goto(&scan_loop);
  BIND(&scan_loop);
  {
    GotoIf(Int32GreaterThan(var_low.value(), limit), if_not_found);

    TNode<Uint32T> sort_index =
        GetSortedKeyIndex<Array>(array, var_low.value());
    TNode<Name> current_name = GetKey<Array>(array, sort_index);
    TNode<Uint32T> current_hash = LoadNameHashAssumeComputed(current_name);
    GotoIf(Word32NotEqual(current_hash, hash), if_not_found);
    Label next(this);
    GotoIf(TaggedNotEqual(current_name, unique_name), &next);
    GotoIf(Uint32GreaterThanOrEqual(sort_index, number_of_valid_entries),
           if_not_found);
    *var_name_index = ToKeyIndex<Array>(sort_index);
    Goto(if_found);

    BIND(&next);
    var_low = Unsigned(Int32Add(var_low.value(), Int32Constant(1)));
    Goto(&scan_loop);
  }
}

void CodeStubAssembler::ForEachEnumerableOwnProperty(
    TNode<Context> context, TNode<Map> map, TNode<JSObject> object,
    PropertiesEnumerationMode mode, const ForEachKeyValueFunction& body,
    Label* bailout) {
  TNode<Uint16T> type = LoadMapInstanceType(map);
  TNode<Uint32T> bit_field3 = EnsureOnlyHasSimpleProperties(map, type, bailout);

  TVARIABLE(DescriptorArray, var_descriptors, LoadMapDescriptors(map));
  TNode<Uint32T> nof_descriptors =
      DecodeWord32<Map::Bits3::NumberOfOwnDescriptorsBits>(bit_field3);

  TVARIABLE(BoolT, var_stable, Int32TrueConstant());

  TVARIABLE(BoolT, var_has_symbol, Int32FalseConstant());
  // false - iterate only string properties, true - iterate only symbol
  // properties
  TVARIABLE(BoolT, var_is_symbol_processing_loop, Int32FalseConstant());
  TVARIABLE(IntPtrT, var_start_key_index,
            ToKeyIndex<DescriptorArray>(Unsigned(Int32Constant(0))));
  // Note: var_end_key_index is exclusive for the loop
  TVARIABLE(IntPtrT, var_end_key_index,
            ToKeyIndex<DescriptorArray>(nof_descriptors));
  VariableList list({&var_descriptors, &var_stable, &var_has_symbol,
                     &var_is_symbol_processing_loop, &var_start_key_index,
                     &var_end_key_index},
                    zone());
  Label descriptor_array_loop(this, list);

  Goto(&descriptor_array_loop);
  BIND(&descriptor_array_loop);

  BuildFastLoop<IntPtrT>(
      list, var_start_key_index.value(), var_end_key_index.value(),
      [&](TNode<IntPtrT> descriptor_key_index) {
        TNode<Name> next_key =
            LoadKeyByKeyIndex(var_descriptors.value(), descriptor_key_index);

        TVARIABLE(Object, var_value_or_accessor, SmiConstant(0));
        Label next_iteration(this);

        if (mode == kEnumerationOrder) {
          // |next_key| is either a string or a symbol
          // Skip strings or symbols depending on
          // |var_is_symbol_processing_loop|.
          Label if_string(this), if_symbol(this), if_name_ok(this);
          Branch(IsSymbol(next_key), &if_symbol, &if_string);
          BIND(&if_symbol);
          {
            // Process symbol property when |var_is_symbol_processing_loop| is
            // true.
            GotoIf(var_is_symbol_processing_loop.value(), &if_name_ok);
            // First iteration need to calculate smaller range for processing
            // symbols
            Label if_first_symbol(this);
            // var_end_key_index is still inclusive at this point.
            var_end_key_index = descriptor_key_index;
            Branch(var_has_symbol.value(), &next_iteration, &if_first_symbol);
            BIND(&if_first_symbol);
            {
              var_start_key_index = descriptor_key_index;
              var_has_symbol = Int32TrueConstant();
              Goto(&next_iteration);
            }
          }
          BIND(&if_string);
          {
            CSA_DCHECK(this, IsString(next_key));
            // Process string property when |var_is_symbol_processing_loop| is
            // false.
            Branch(var_is_symbol_processing_loop.value(), &next_iteration,
                   &if_name_ok);
          }
          BIND(&if_name_ok);
        }
        {
          TVARIABLE(Map, var_map);
          TVARIABLE(HeapObject, var_meta_storage);
          TVARIABLE(IntPtrT, var_entry);
          TVARIABLE(Uint32T, var_details);
          Label if_found(this);

          Label if_found_fast(this), if_found_dict(this);

          Label if_stable(this), if_not_stable(this);
          Branch(var_stable.value(), &if_stable, &if_not_stable);
          BIND(&if_stable);
          {
            // Directly decode from the descriptor array if |object| did not
            // change shape.
            var_map = map;
            var_meta_storage = var_descriptors.value();
            var_entry = Signed(descriptor_key_index);
            Goto(&if_found_fast);
          }
          BIND(&if_not_stable);
          {
            // If the map did change, do a slower lookup. We are still
            // guaranteed that the object has a simple shape, and that the key
            // is a name.
            var_map = LoadMap(object);
            TryLookupPropertyInSimpleObject(object, var_map.value(), next_key,
                                            &if_found_fast, &if_found_dict,
                                            &var_meta_storage, &var_entry,
                                            &next_iteration, bailout);
          }

          BIND(&if_found_fast);
          {
            TNode<DescriptorArray> descriptors = CAST(var_meta_storage.value());
            TNode<IntPtrT> name_index = var_entry.value();

            // Skip non-enumerable properties.
            var_details = LoadDetailsByKeyIndex(descriptors, name_index);
            GotoIf(IsSetWord32(var_details.value(),
                               PropertyDetails::kAttributesDontEnumMask),
                   &next_iteration);

            LoadPropertyFromFastObject(object, var_map.value(), descriptors,
                                       name_index, var_details.value(),
                                       &var_value_or_accessor);
            Goto(&if_found);
          }
          BIND(&if_found_dict);
          {
            TNode<PropertyDictionary> dictionary =
                CAST(var_meta_storage.value());
            TNode<IntPtrT> entry = var_entry.value();

            TNode<Uint32T> details = LoadDetailsByKeyIndex(dictionary, entry);
            // Skip non-enumerable properties.
            GotoIf(
                IsSetWord32(details, PropertyDetails::kAttributesDontEnumMask),
                &next_iteration);

            var_details = details;
            var_value_or_accessor =
                LoadValueByKeyIndex<PropertyDictionary>(dictionary, entry);
            Goto(&if_found);
          }

          // Here we have details and value which could be an accessor.
          BIND(&if_found);
          {
            TNode<Object> value_or_accessor = var_value_or_accessor.value();
            body(next_key, [&]() {
              TVARIABLE(Object, var_value);
              Label value_ready(this), slow_load(this, Label::kDeferred);

              var_value = CallGetterIfAccessor(
                  value_or_accessor, object, var_details.value(), context,
                  object, next_key, &slow_load, kCallJSGetterUseCachedName);
              Goto(&value_ready);

              BIND(&slow_load);
              var_value =
                  CallRuntime(Runtime::kGetProperty, context, object, next_key);
              Goto(&value_ready);

              BIND(&value_ready);
              return var_value.value();
            });

            // Check if |object| is still stable, i.e. the descriptors in the
            // preloaded |descriptors| are still the same modulo in-place
            // representation changes.
            GotoIfNot(var_stable.value(), &next_iteration);
            var_stable = TaggedEqual(LoadMap(object), map);
            // Reload the descriptors just in case the actual array changed, and
            // any of the field representations changed in-place.
            var_descriptors = LoadMapDescriptors(map);

            Goto(&next_iteration);
          }
        }
        BIND(&next_iteration);
      },
      DescriptorArray::kEntrySize, LoopUnrollingMode::kNo,
      IndexAdvanceMode::kPost);

  if (mode == kEnumerationOrder) {
    Label done(this);
    GotoIf(var_is_symbol_processing_loop.value(), &done);
    GotoIfNot(var_has_symbol.value(), &done);
    // All string properties are processed, now process symbol properties.
    var_is_symbol_processing_loop = Int32TrueConstant();
    // Add DescriptorArray::kEntrySize to make the var_end_key_index exclusive
    // as BuildFastLoop() expects.
    Increment(&var_end_key_index, DescriptorArray::kEntrySize);
    Goto(&descriptor_array_loop);

    BIND(&done);
  }
}

TNode<Object> CodeStubAssembler::GetConstructor(TNode<Map> map) {
  TVARIABLE(HeapObject, var_maybe_constructor);
  var_maybe_constructor = map;
  Label loop(this, &var_maybe_constructor), done(this);
  GotoIfNot(IsMap(var_maybe_constructor.value()), &done);
  Goto(&loop);

  BIND(&loop);
  {
    var_maybe_constructor = CAST(
        LoadObjectField(var_maybe_constructor.value(),
                        Map::kConstructorOrBackPointerOrNativeContextOffset));
    GotoIf(IsMap(var_maybe_constructor.value()), &loop);
    Goto(&done);
  }

  BIND(&done);
  return var_maybe_constructor.value();
}

TNode<NativeContext> CodeStubAssembler::GetCreationContextFromMap(
    TNode<Map> map, Label* if_bailout) {
  TNode<Map> meta_map = LoadMap(map);
  TNode<Object> maybe_context =
      LoadMapConstructorOrBackPointerOrNativeContext(meta_map);
  GotoIf(IsNull(maybe_context), if_bailout);
  return CAST(maybe_context);
}

TNode<NativeContext> CodeStubAssembler::GetCreationContext(
    TNode<JSReceiver> receiver, Label* if_bailout) {
  return GetCreationContextFromMap(LoadMap(receiver), if_bailout);
}

TNode<NativeContext> CodeStubAssembler::GetFunctionRealm(
    TNode<Context> context, TNode<JSReceiver> receiver, Label* if_bailout) {
  TVARIABLE(JSReceiver, current);
  TVARIABLE(Map, current_map);
  Label loop(this, VariableList({&current}, zone())), if_proxy(this),
      if_simple_case(this), if_bound_function(this), if_wrapped_function(this),
      proxy_revoked(this, Label::kDeferred);
  CSA_DCHECK(this, IsCallable(receiver));
  current = receiver;
  Goto(&loop);

  BIND(&loop);
  {
    current_map = LoadMap(current.value());
    TNode<Int32T> instance_type = LoadMapInstanceType(current_map.value());
    GotoIf(IsJSFunctionInstanceType(instance_type), &if_simple_case);
```