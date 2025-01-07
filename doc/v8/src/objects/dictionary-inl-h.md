Response:
Let's break down the thought process for analyzing the provided C++ header file.

1. **Initial Scan and Purpose Identification:**  The filename `dictionary-inl.h` strongly suggests this file deals with the implementation details (inline functions) of dictionary-like data structures within V8. The `#ifndef V8_OBJECTS_DICTIONARY_INL_H_` guard confirms it's a header file. The included headers like `dictionary.h`, `hash-table-inl.h`, and `objects-inl.h` further reinforce this. The `// Copyright 2018...` gives context about the project.

2. **Key Template Structures:** The code heavily uses C++ templates: `template <typename Derived, typename Shape>`. This immediately indicates that the `Dictionary` class (and its specializations) are designed to be flexible and work with different derived dictionary types and potentially different strategies for handling entries (the `Shape` parameter). This is a common pattern for code reuse and abstraction.

3. **Core Functionality - Accessing and Modifying Dictionary Entries:**  The primary functions revolve around getting and setting values and details at specific entries within the dictionary:
    * `ValueAt`: Retrieving the value at a given internal index. The overloads with `PtrComprCageBase` and `SeqCstAccessTag` hint at memory management and thread safety considerations within V8.
    * `TryValueAt`: A safer version of `ValueAt` that checks bounds.
    * `ValueAtPut`: Setting the value at a given index.
    * `ValueAtSwap` and `ValueAtCompareAndSwap`: Atomic operations, important for concurrency.
    * `DetailsAt` and `DetailsAtPut`:  Working with additional metadata (property details) associated with dictionary entries.
    * `ClearEntry`: Removing an entry.
    * `SetEntry`: Setting both the key, value, and details.

4. **Specialized Dictionary Types:**  The presence of `BaseNameDictionary`, `NumberDictionary`, `GlobalDictionary`, and `SimpleNumberDictionary` shows that V8 has different types of dictionaries optimized for various use cases (names, numbers, global properties). The `Shape` template parameter likely allows these different dictionary types to implement their specific logic for things like hashing and key matching.

5. **Hashing and Key Matching:** Functions like `Hash`, `HashForObject`, and `IsMatch` within the `Shape` classes are crucial for dictionary functionality. These are likely used internally to efficiently locate entries based on their keys. The presence of `ComputeSeededHash` suggests a security measure to prevent hash collision attacks.

6. **Property Details:** The `PropertyDetails` class and its associated `DetailsAt` and `DetailsAtPut` functions indicate that V8 dictionaries store more than just key-value pairs. They also store metadata about the properties.

7. **Global Dictionary Specifics:** `GlobalDictionary` seems to have a special structure where values are stored in `PropertyCell` objects. This likely reflects how global variables and properties are managed.

8. **Number Dictionary Specifics:** The `NumberDictionary` has specific logic related to "slow elements" and tracking the maximum number key. This likely relates to how JavaScript arrays with large or sparse numeric indices are handled.

9. **Javascript Relevance (Conceptual at this stage):**  While the code is C++, the underlying concepts are directly related to how JavaScript objects work. JavaScript objects are essentially dictionaries (hash maps) where keys (strings or Symbols) map to values. The functions in this file are the low-level mechanisms for implementing these object properties.

10. **Error Scenarios (Initial Thoughts):**  Potential errors could involve:
    * Accessing out-of-bounds entries.
    * Incorrectly handling property details.
    * Race conditions if concurrency isn't managed properly (hence the atomic operations).
    * Issues with hash collisions (though V8 likely has mitigation).

11. **Refinement and Javascript Examples:**  Now, armed with an understanding of the C++ code, we can construct more concrete JavaScript examples. The `ValueAtPut` corresponds to setting a property on an object (`obj[key] = value`). The different dictionary types correspond to different internal representations of JavaScript objects (e.g., objects with string keys, objects with numeric keys).

12. **Code Logic Inference and Examples:**  By looking at functions like `TryValueAt`, `ValueAtPut`, and `ClearEntry`, we can infer the basic operations of a dictionary. We can then create hypothetical input/output scenarios for these functions.

13. **Common Programming Errors:** Connecting the V8 internal details to common JavaScript errors becomes clearer. "Undefined" errors arise when trying to access non-existent properties, which relates to `TryValueAt` returning nothing. Performance issues with large arrays relate to the "slow elements" handling in `NumberDictionary`.

14. **Torque Consideration:** The prompt mentions `.tq` files. Since this is a `.h` file, it's not a Torque file. The thought process here is simply to check the file extension and apply the given rule.

This detailed breakdown shows how to start with a basic understanding of the file's purpose and progressively analyze the code, connecting it to higher-level concepts and finally relating it back to the user's request for JavaScript examples and potential errors. The key is to look for patterns, understand the naming conventions, and relate the low-level C++ to the observable behavior of JavaScript.
This header file, `v8/src/objects/dictionary-inl.h`, provides **inline implementations for methods of the `Dictionary` and related classes in V8**.

Here's a breakdown of its functionalities:

**Core Functionality: Accessing and Modifying Dictionary Entries**

* **`ValueAt(InternalIndex entry)` and `ValueAt(PtrComprCageBase cage_base, InternalIndex entry)`:** These functions retrieve the **value** stored at a specific `entry` (internal index) within the dictionary. The `PtrComprCageBase` parameter likely relates to V8's compressed pointer mechanism for memory optimization.
* **`TryValueAt(InternalIndex entry)`:** This function attempts to retrieve the value at a given `entry`, but it returns an `std::optional` which will be empty if the entry is out of bounds. This provides a safer way to access values without causing crashes.
* **`ValueAtPut(InternalIndex entry, Tagged<Object> value)`:** This function **sets** the `value` at a specific `entry` in the dictionary.
* **`ValueAtSwap(InternalIndex entry, Tagged<Object> value, SeqCstAccessTag tag)`:** This function **atomically swaps** the value at a specific `entry` with the given `value`. The `SeqCstAccessTag` suggests this is for thread-safe operations.
* **`ValueAtCompareAndSwap(InternalIndex entry, Tagged<Object> expected, Tagged<Object> value, SeqCstAccessTag tag)`:** This function performs an **atomic compare-and-swap** operation on the value at a specific `entry`. It only sets the new `value` if the current value matches the `expected` value. This is also for thread safety.
* **`DetailsAt(InternalIndex entry)` and `DetailsAtPut(InternalIndex entry, PropertyDetails value)`:** These functions get and set **additional metadata** ( `PropertyDetails`) associated with an entry in the dictionary. This metadata can store information about the property, such as its attributes (e.g., writable, enumerable).
* **`ClearEntry(InternalIndex entry)`:**  This function **removes** an entry from the dictionary by setting its key and value to a special "the hole" value.
* **`SetEntry(InternalIndex entry, Tagged<Object> key, Tagged<Object> value, PropertyDetails details)`:** This function sets the **key**, **value**, and **details** for a given entry.

**Specific Dictionary Types and their Functionalities:**

* **`BaseNameDictionary`:**
    * `set_next_enumeration_index(int index)` and `next_enumeration_index()`: Manage the index for iterating over the properties of an object.
    * `SetHash(int hash)` and `Hash() const`: Get and set the hash value of the dictionary, likely used for performance optimizations.
* **`NumberDictionary`:**
    * `requires_slow_elements()`:  Checks a flag indicating if the dictionary is using a slower, more general mechanism for storing elements (likely for sparse arrays or arrays with very large indices).
    * `max_number_key()`: Returns the largest numeric index stored in the dictionary.
    * `set_requires_slow_elements()`: Sets the flag indicating that slow elements should be used.
* **`GlobalDictionary`:** This type seems to have a special structure where values are stored in `PropertyCell` objects, which hold both the value and its property details. It has specific `CellAt`, `NameAt`, and overridden `ValueAt`, `SetEntry`, and `ClearEntry` to work with these `PropertyCell`s.
* **`NameDictionary`:**  Specifically for storing properties with string or symbol keys (Names). It has functions like `NameAt` to retrieve the key (which is a `Name` object). It also manages `flags` which can indicate various properties of the dictionary.

**Helper Functions and Classes:**

* **`BaseDictionaryShape`, `NumberDictionaryBaseShape`, `BaseNameDictionaryShape`, `GlobalDictionaryShape`:** These appear to be template classes or concepts (judging by the template specializations within) that define the "shape" or structure and behavior related to different dictionary types, particularly how keys are matched and hashed. They provide `IsMatch` and `Hash`/`HashForObject` functions.
* **`ObjectSlot`:** Represents a raw memory location within the V8 heap where an object can be stored.
* **`InternalIndex`:**  Represents an index within the dictionary's internal storage.
* **`Tagged<Object>`:**  A smart pointer type used in V8 to represent objects on the heap, handling garbage collection and other memory management details.
* **`PropertyDetails`:**  A structure or class that holds metadata about a property.

**Is `v8/src/objects/dictionary-inl.h` a Torque source file?**

No, `v8/src/objects/dictionary-inl.h` is **not** a Torque source file. Torque source files have the extension `.tq`. This file has the `.h` extension, indicating it's a standard C++ header file containing inline implementations.

**Relationship to JavaScript Functionality and Examples:**

The `Dictionary` and its related classes are fundamental to how JavaScript objects are implemented in V8. JavaScript objects are essentially dictionaries (hash maps) where properties (keys) map to values.

Here's how some of the functionalities relate to JavaScript:

* **Accessing Properties:**  The `ValueAt` functions are analogous to accessing properties of a JavaScript object using bracket notation or dot notation:

   ```javascript
   const obj = { a: 10, b: "hello" };
   const valueOfA = obj.a; // or obj['a']
   ```
   Internally, V8 would use a `Dictionary` to store these properties, and accessing `obj.a` would involve looking up the value associated with the key "a" in the dictionary.

* **Setting Properties:** The `ValueAtPut` function corresponds to setting or modifying properties:

   ```javascript
   const obj = {};
   obj.name = "World"; // or obj['name'] = "World";
   ```
   This operation would use `ValueAtPut` to insert or update the entry for the key "name" in the object's internal dictionary.

* **Deleting Properties:** The `ClearEntry` function is related to the `delete` operator in JavaScript:

   ```javascript
   const obj = { x: 5, y: 10 };
   delete obj.x;
   console.log(obj.x); // Output: undefined
   ```
   Deleting a property would involve clearing the corresponding entry in the dictionary.

* **Numeric Indices in Arrays:** The `NumberDictionary` is particularly relevant to how JavaScript arrays with numeric indices are implemented:

   ```javascript
   const arr = [1, 2, 3];
   console.log(arr[1]); // Accessing element at index 1
   arr[3] = 4;          // Setting element at index 3 (sparse array)
   ```
   For arrays, especially sparse ones or those with large indices, V8 might use a `NumberDictionary` to efficiently store the elements. The `requires_slow_elements` flag relates to whether V8 is using a more optimized or a more general approach for storing these elements.

* **Global Objects:** The `GlobalDictionary` is used to store properties of the global object (like `window` in browsers or the global object in Node.js).

**Code Logic Inference with Assumptions:**

Let's take the `ValueAtPut` function as an example:

**Assumption:** We have a `Dictionary` object (let's call it `myDict`) and we want to set the value "test" at internal index 5.

**Input:**
* `entry`: An `InternalIndex` representing 5.
* `value`: A `Tagged<Object>` representing the string "test".

**Code:**

```c++
template <typename Derived, typename Shape>
void Dictionary<Derived, Shape>::ValueAtPut(InternalIndex entry,
                                            Tagged<Object> value) {
  this->set(DerivedHashTable::EntryToIndex(entry) + Derived::kEntryValueIndex,
            value);
}
```

**Logic:**
1. `DerivedHashTable::EntryToIndex(entry)`: This function likely converts the `InternalIndex` (which might be a logical entry number) to an actual index within the underlying storage array of the hash table. Let's assume for index 5, this returns 10.
2. `Derived::kEntryValueIndex`: This is likely a constant that specifies the offset within an entry where the value is stored. If each entry has a key and a value, this might be 1 (assuming the key is at offset 0).
3. `this->set(10 + 1, value)`:  This calls a lower-level `set` method (likely inherited from a base class or part of the object's memory management) to write the `value` ("test") at the calculated memory location (index 11).

**Output:** The value at the internal storage location corresponding to entry 5 will be updated to "test".

**Common Programming Errors and Examples:**

* **Accessing Non-Existent Properties (leading to `undefined`):**  In JavaScript, trying to access a property that hasn't been set returns `undefined`. This relates to the `TryValueAt` function. If `TryValueAt` doesn't find an entry for a given key, it would return an empty `std::optional`, which would translate to `undefined` in JavaScript.

   ```javascript
   const obj = { name: "Alice" };
   console.log(obj.age); // Output: undefined
   ```

* **Incorrectly Assuming Property Existence:** Programmers might try to access a property and use its value without checking if it exists, leading to errors if the property is not present.

   ```javascript
   function greet(person) {
       const nameLength = person.name.length; // Potential error if person.name is undefined
       console.log(`Hello, ${person.name}! Your name has ${nameLength} letters.`);
   }

   greet({ title: "Dr." }); // This will cause an error because 'name' is not defined.
   ```

* **Performance Issues with Large or Sparse Arrays:** If a JavaScript array has a very large size or has many empty slots (sparse array), V8 might use a `NumberDictionary` with `requires_slow_elements` set. Operations on such arrays might be slower than on densely packed arrays. Programmers might inadvertently create such arrays, leading to performance problems.

   ```javascript
   const largeArray = [];
   largeArray[1000000] = "data"; // Creating a sparse array
   console.log(largeArray.length); // Output: 1000001
   ```

* **Modifying Non-Writable Properties:**  JavaScript has the concept of non-writable properties. Trying to set a value for such a property will fail silently in non-strict mode or throw an error in strict mode. This relates to the `PropertyDetails` and how V8 manages property attributes.

   ```javascript
   "use strict";
   const obj = {};
   Object.defineProperty(obj, "constant", { value: 42, writable: false });
   obj.constant = 10; // TypeError: Cannot assign to read only property 'constant' of object '#<Object>'
   ```

In summary, `v8/src/objects/dictionary-inl.h` provides the low-level, performant mechanisms for managing key-value pairs within V8's object system, directly underpinning how JavaScript objects and arrays work. Understanding this code helps in comprehending the internal workings and performance characteristics of JavaScript.

Prompt: 
```
这是目录为v8/src/objects/dictionary-inl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/dictionary-inl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2018 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_OBJECTS_DICTIONARY_INL_H_
#define V8_OBJECTS_DICTIONARY_INL_H_

#include <optional>

#include "src/execution/isolate-utils-inl.h"
#include "src/numbers/hash-seed-inl.h"
#include "src/objects/dictionary.h"
#include "src/objects/hash-table-inl.h"
#include "src/objects/objects-inl.h"
#include "src/objects/oddball.h"
#include "src/objects/property-cell-inl.h"

// Has to be the last include (doesn't have include guards):
#include "src/objects/object-macros.h"

namespace v8::internal {

template <typename Derived, typename Shape>
Tagged<Object> Dictionary<Derived, Shape>::ValueAt(InternalIndex entry) {
  PtrComprCageBase cage_base = GetPtrComprCageBase();
  return ValueAt(cage_base, entry);
}

template <typename Derived, typename Shape>
Tagged<Object> Dictionary<Derived, Shape>::ValueAt(PtrComprCageBase cage_base,
                                                   InternalIndex entry) {
  return this->get(DerivedHashTable::EntryToIndex(entry) +
                   Derived::kEntryValueIndex);
}

template <typename Derived, typename Shape>
Tagged<Object> Dictionary<Derived, Shape>::ValueAt(InternalIndex entry,
                                                   SeqCstAccessTag tag) {
  PtrComprCageBase cage_base = GetPtrComprCageBase();
  return ValueAt(cage_base, entry, tag);
}

template <typename Derived, typename Shape>
Tagged<Object> Dictionary<Derived, Shape>::ValueAt(PtrComprCageBase cage_base,
                                                   InternalIndex entry,
                                                   SeqCstAccessTag tag) {
  return this->get(
      DerivedHashTable::EntryToIndex(entry) + Derived::kEntryValueIndex, tag);
}

template <typename Derived, typename Shape>
std::optional<Tagged<Object>> Dictionary<Derived, Shape>::TryValueAt(
    InternalIndex entry) {
#if DEBUG
  Isolate* isolate;
  GetIsolateFromHeapObject(this, &isolate);
  DCHECK_NE(isolate, nullptr);
  SLOW_DCHECK(!isolate->heap()->IsPendingAllocation(Tagged(this)));
#endif  // DEBUG
  // We can read length() in a non-atomic way since we are reading an
  // initialized object which is not pending allocation.
  if (DerivedHashTable::EntryToIndex(entry) + Derived::kEntryValueIndex >=
      this->length()) {
    return {};
  }
  return ValueAt(entry);
}

template <typename Derived, typename Shape>
void Dictionary<Derived, Shape>::ValueAtPut(InternalIndex entry,
                                            Tagged<Object> value) {
  this->set(DerivedHashTable::EntryToIndex(entry) + Derived::kEntryValueIndex,
            value);
}

template <typename Derived, typename Shape>
void Dictionary<Derived, Shape>::ValueAtPut(InternalIndex entry,
                                            Tagged<Object> value,
                                            SeqCstAccessTag tag) {
  this->set(DerivedHashTable::EntryToIndex(entry) + Derived::kEntryValueIndex,
            value, tag);
}

template <typename Derived, typename Shape>
Tagged<Object> Dictionary<Derived, Shape>::ValueAtSwap(InternalIndex entry,
                                                       Tagged<Object> value,
                                                       SeqCstAccessTag tag) {
  return this->swap(
      DerivedHashTable::EntryToIndex(entry) + Derived::kEntryValueIndex, value,
      tag);
}

template <typename Derived, typename Shape>
Tagged<Object> Dictionary<Derived, Shape>::ValueAtCompareAndSwap(
    InternalIndex entry, Tagged<Object> expected, Tagged<Object> value,
    SeqCstAccessTag tag) {
  return this->compare_and_swap(
      DerivedHashTable::EntryToIndex(entry) + Derived::kEntryValueIndex,
      expected, value, tag);
}

template <typename Derived, typename Shape>
PropertyDetails Dictionary<Derived, Shape>::DetailsAt(InternalIndex entry) {
  return Shape::DetailsAt(Cast<Derived>(this), entry);
}

template <typename Derived, typename Shape>
void Dictionary<Derived, Shape>::DetailsAtPut(InternalIndex entry,
                                              PropertyDetails value) {
  Shape::DetailsAtPut(Cast<Derived>(this), entry, value);
}

template <typename Derived, typename Shape>
void BaseNameDictionary<Derived, Shape>::set_next_enumeration_index(int index) {
  DCHECK_LT(0, index);
  this->set(kNextEnumerationIndexIndex, Smi::FromInt(index));
}

template <typename Derived, typename Shape>
int BaseNameDictionary<Derived, Shape>::next_enumeration_index() {
  return Smi::ToInt(this->get(kNextEnumerationIndexIndex));
}

template <typename Derived, typename Shape>
void BaseNameDictionary<Derived, Shape>::SetHash(int hash) {
  DCHECK(PropertyArray::HashField::is_valid(hash));
  this->set(kObjectHashIndex, Smi::FromInt(hash));
}

template <typename Derived, typename Shape>
int BaseNameDictionary<Derived, Shape>::Hash() const {
  Tagged<Object> hash_obj = this->get(kObjectHashIndex);
  int hash = Smi::ToInt(hash_obj);
  DCHECK(PropertyArray::HashField::is_valid(hash));
  return hash;
}

bool NumberDictionary::requires_slow_elements() {
  Tagged<Object> max_index_object = get(kMaxNumberKeyIndex);
  if (!IsSmi(max_index_object)) return false;
  return 0 != (Smi::ToInt(max_index_object) & kRequiresSlowElementsMask);
}

uint32_t NumberDictionary::max_number_key() {
  DCHECK(!requires_slow_elements());
  Tagged<Object> max_index_object = get(kMaxNumberKeyIndex);
  if (!IsSmi(max_index_object)) return 0;
  uint32_t value = static_cast<uint32_t>(Smi::ToInt(max_index_object));
  return value >> kRequiresSlowElementsTagSize;
}

void NumberDictionary::set_requires_slow_elements() {
  set(kMaxNumberKeyIndex, Smi::FromInt(kRequiresSlowElementsMask));
}

template <typename Derived, typename Shape>
void Dictionary<Derived, Shape>::ClearEntry(InternalIndex entry) {
  Tagged<Object> the_hole = this->GetReadOnlyRoots().the_hole_value();
  PropertyDetails details = PropertyDetails::Empty();
  Cast<Derived>(this)->SetEntry(entry, the_hole, the_hole, details);
}

template <typename Derived, typename Shape>
void Dictionary<Derived, Shape>::SetEntry(InternalIndex entry,
                                          Tagged<Object> key,
                                          Tagged<Object> value,
                                          PropertyDetails details) {
  DCHECK(Dictionary::kEntrySize == 2 || Dictionary::kEntrySize == 3);
  DCHECK(!IsName(key) || details.dictionary_index() > 0);
  int index = DerivedHashTable::EntryToIndex(entry);
  DisallowGarbageCollection no_gc;
  WriteBarrierMode mode = this->GetWriteBarrierMode(no_gc);
  this->set(index + Derived::kEntryKeyIndex, key, mode);
  this->set(index + Derived::kEntryValueIndex, value, mode);
  if (Shape::kHasDetails) DetailsAtPut(entry, details);
}

template <typename Derived, typename Shape>
ObjectSlot Dictionary<Derived, Shape>::RawFieldOfValueAt(InternalIndex entry) {
  return this->RawFieldOfElementAt(DerivedHashTable::EntryToIndex(entry) +
                                   Derived::kEntryValueIndex);
}

template <typename Key>
template <typename Dictionary>
PropertyDetails BaseDictionaryShape<Key>::DetailsAt(Tagged<Dictionary> dict,
                                                    InternalIndex entry) {
  static_assert(Dictionary::kEntrySize == 3);
  DCHECK(entry.is_found());
  return PropertyDetails(Cast<Smi>(dict->get(Dictionary::EntryToIndex(entry) +
                                             Dictionary::kEntryDetailsIndex)));
}

template <typename Key>
template <typename Dictionary>
void BaseDictionaryShape<Key>::DetailsAtPut(Tagged<Dictionary> dict,
                                            InternalIndex entry,
                                            PropertyDetails value) {
  static_assert(Dictionary::kEntrySize == 3);
  dict->set(Dictionary::EntryToIndex(entry) + Dictionary::kEntryDetailsIndex,
            value.AsSmi());
}

Tagged<Object> GlobalDictionaryShape::Unwrap(Tagged<Object> object) {
  return Cast<PropertyCell>(object)->name();
}

Handle<Map> GlobalDictionary::GetMap(ReadOnlyRoots roots) {
  return roots.global_dictionary_map_handle();
}

Tagged<Name> NameDictionary::NameAt(InternalIndex entry) {
  PtrComprCageBase cage_base = GetPtrComprCageBase();
  return NameAt(cage_base, entry);
}

Tagged<Name> NameDictionary::NameAt(PtrComprCageBase cage_base,
                                    InternalIndex entry) {
  return Cast<Name>(KeyAt(cage_base, entry));
}

Handle<Map> NameDictionary::GetMap(ReadOnlyRoots roots) {
  return roots.name_dictionary_map_handle();
}

uint32_t NameDictionary::flags() const {
  return Smi::ToInt(this->get(kFlagsIndex));
}

void NameDictionary::set_flags(uint32_t flags) {
  this->set(kFlagsIndex, Smi::FromInt(flags));
}

BIT_FIELD_ACCESSORS(NameDictionary, flags, may_have_interesting_properties,
                    NameDictionary::MayHaveInterestingPropertiesBit)

Tagged<PropertyCell> GlobalDictionary::CellAt(InternalIndex entry) {
  PtrComprCageBase cage_base = GetPtrComprCageBase();
  return CellAt(cage_base, entry);
}

Tagged<PropertyCell> GlobalDictionary::CellAt(PtrComprCageBase cage_base,
                                              InternalIndex entry) {
  DCHECK(IsPropertyCell(KeyAt(cage_base, entry), cage_base));
  return Cast<PropertyCell>(KeyAt(cage_base, entry));
}

Tagged<Name> GlobalDictionary::NameAt(InternalIndex entry) {
  PtrComprCageBase cage_base = GetPtrComprCageBase();
  return NameAt(cage_base, entry);
}

Tagged<Name> GlobalDictionary::NameAt(PtrComprCageBase cage_base,
                                      InternalIndex entry) {
  return CellAt(cage_base, entry)->name(cage_base);
}

Tagged<Object> GlobalDictionary::ValueAt(InternalIndex entry) {
  PtrComprCageBase cage_base = GetPtrComprCageBase();
  return ValueAt(cage_base, entry);
}

Tagged<Object> GlobalDictionary::ValueAt(PtrComprCageBase cage_base,
                                         InternalIndex entry) {
  return CellAt(cage_base, entry)->value(cage_base);
}

void GlobalDictionary::SetEntry(InternalIndex entry, Tagged<Object> key,
                                Tagged<Object> value, PropertyDetails details) {
  DCHECK_EQ(key, Cast<PropertyCell>(value)->name());
  set(EntryToIndex(entry) + kEntryKeyIndex, value);
  DetailsAtPut(entry, details);
}

void GlobalDictionary::ClearEntry(InternalIndex entry) {
  Tagged<Hole> the_hole = this->GetReadOnlyRoots().the_hole_value();
  set(EntryToIndex(entry) + kEntryKeyIndex, the_hole);
}

void GlobalDictionary::ValueAtPut(InternalIndex entry, Tagged<Object> value) {
  set(EntryToIndex(entry), value);
}

bool NumberDictionaryBaseShape::IsMatch(uint32_t key, Tagged<Object> other) {
  return key == static_cast<uint32_t>(Object::NumberValue(Cast<Number>(other)));
}

uint32_t NumberDictionaryBaseShape::Hash(ReadOnlyRoots roots, uint32_t key) {
  return ComputeSeededHash(key, HashSeed(roots));
}

uint32_t NumberDictionaryBaseShape::HashForObject(ReadOnlyRoots roots,
                                                  Tagged<Object> other) {
  DCHECK(IsNumber(other));
  return ComputeSeededHash(
      static_cast<uint32_t>(Object::NumberValue(Cast<Number>(other))),
      HashSeed(roots));
}

template <AllocationType allocation>
Handle<Object> NumberDictionaryBaseShape::AsHandle(Isolate* isolate,
                                                   uint32_t key) {
  return isolate->factory()->NewNumberFromUint<allocation>(key);
}

template <AllocationType allocation>
Handle<Object> NumberDictionaryBaseShape::AsHandle(LocalIsolate* isolate,
                                                   uint32_t key) {
  return isolate->factory()->NewNumberFromUint<allocation>(key);
}

Handle<Map> NumberDictionary::GetMap(ReadOnlyRoots roots) {
  return roots.number_dictionary_map_handle();
}

Handle<Map> SimpleNumberDictionary::GetMap(ReadOnlyRoots roots) {
  return roots.simple_number_dictionary_map_handle();
}

bool BaseNameDictionaryShape::IsMatch(DirectHandle<Name> key,
                                      Tagged<Object> other) {
  DCHECK(IsTheHole(other) || IsUniqueName(Cast<Name>(other)));
  DCHECK(IsUniqueName(*key));
  return *key == other;
}

uint32_t BaseNameDictionaryShape::Hash(ReadOnlyRoots roots,
                                       DirectHandle<Name> key) {
  DCHECK(IsUniqueName(*key));
  return key->hash();
}

uint32_t BaseNameDictionaryShape::HashForObject(ReadOnlyRoots roots,
                                                Tagged<Object> other) {
  DCHECK(IsUniqueName(other));
  return Cast<Name>(other)->hash();
}

bool GlobalDictionaryShape::IsMatch(DirectHandle<Name> key,
                                    Tagged<Object> other) {
  DCHECK(IsUniqueName(*key));
  DCHECK(IsUniqueName(Cast<PropertyCell>(other)->name()));
  return *key == Cast<PropertyCell>(other)->name();
}

uint32_t GlobalDictionaryShape::HashForObject(ReadOnlyRoots roots,
                                              Tagged<Object> other) {
  return Cast<PropertyCell>(other)->name()->hash();
}

template <AllocationType allocation>
Handle<Object> BaseNameDictionaryShape::AsHandle(Isolate* isolate,
                                                 Handle<Name> key) {
  DCHECK(IsUniqueName(*key));
  return key;
}

template <AllocationType allocation>
Handle<Object> BaseNameDictionaryShape::AsHandle(LocalIsolate* isolate,
                                                 Handle<Name> key) {
  DCHECK(IsUniqueName(*key));
  return key;
}

template <typename Dictionary>
PropertyDetails GlobalDictionaryShape::DetailsAt(Tagged<Dictionary> dict,
                                                 InternalIndex entry) {
  DCHECK(entry.is_found());
  return dict->CellAt(entry)->property_details();
}

template <typename Dictionary>
void GlobalDictionaryShape::DetailsAtPut(Tagged<Dictionary> dict,
                                         InternalIndex entry,
                                         PropertyDetails value) {
  DCHECK(entry.is_found());
  dict->CellAt(entry)->UpdatePropertyDetailsExceptCellType(value);
}

}  // namespace v8::internal

#include "src/objects/object-macros-undef.h"

#endif  // V8_OBJECTS_DICTIONARY_INL_H_

"""

```