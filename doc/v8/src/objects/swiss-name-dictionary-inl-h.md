Response:
Let's break down the thought process for analyzing the provided C++ header file for the `SwissNameDictionary`.

1. **Identify the Core Purpose:** The filename itself, `swiss-name-dictionary-inl.h`, strongly suggests this code defines an inlined implementation of a dictionary data structure. The "Swiss" part likely refers to the underlying hashing algorithm or data organization (Swiss Tables). The ".inl.h" suffix indicates inline function definitions within a header.

2. **Examine the Includes:**  The included headers provide valuable clues:
    * `<algorithm>`:  Likely used for standard algorithms, although not explicitly visible in this snippet.
    * `<optional>`: Suggests the possibility of operations returning no value.
    * `"src/base/macros.h"`: V8-specific macros for code generation and assertions.
    * `"src/execution/isolate-utils-inl.h"`: Hints at interaction with the V8 isolate, the core execution environment.
    * `"src/heap/heap.h"`:  Indicates this dictionary manages objects on the V8 heap, implying garbage collection considerations.
    * `"src/objects/fixed-array-inl.h"`, `"src/objects/instance-type-inl.h"`, `"src/objects/js-collection-iterator.h"`, `"src/objects/objects-inl.h"`, `"src/objects/slots-inl.h"`, `"src/objects/smi.h"`:  All point to the dictionary being deeply integrated with V8's object model. It stores V8 objects.
    * `"src/objects/swiss-name-dictionary.h"`: The corresponding header file declaring the class.
    * `"torque-generated/src/objects/swiss-name-dictionary-tq-inl.inc"`:  Crucially reveals that Torque (V8's internal language) is involved. This means some parts of the class are likely generated from Torque definitions.
    * `"src/objects/object-macros.h"`: V8 macros for defining object properties and accessors.

3. **Analyze the Class Definition (`SwissNameDictionary`):**
    * **Inheritance:** `OBJECT_CONSTRUCTORS_IMPL(SwissNameDictionary, HeapObject)` tells us it inherits from `HeapObject`, confirming its presence on the V8 heap.
    * **Data Layout:** Methods like `CtrlTable()`, `PropertyDetailsTable()`, `Capacity()`, `NumberOfElements()`, `NumberOfDeletedElements()` reveal the internal structure. It has control bytes, property details, a capacity, and tracks the number of elements (including deleted ones). This strongly suggests a hash table implementation with some form of open addressing or similar collision resolution.
    * **Capacity Management:**  `IsValidCapacity()`, `DataTableSize()`, `CtrlTableSize()`, `SizeFor()`, `MaxUsableCapacity()`, `CapacityFor()` are all related to managing the dictionary's size and growth. The use of powers of 2 for capacity is a common optimization for hash tables.
    * **Element Access:** `FindEntry()`, `LoadFromDataTable()`, `StoreToDataTable()`, `KeyAt()`, `ValueAt()`, `DetailsAt()` are the core operations for accessing and manipulating elements within the dictionary.
    * **Iteration:**  The `IndexIterator` and `IndexIterable` classes indicate support for iterating through the dictionary's entries.
    * **Meta-Table:** The presence of `meta_table()`, `SetMetaTableField()`, `GetMetaTableField()` suggests a separate area to store metadata about the dictionary, likely related to enumeration order or other internal bookkeeping.
    * **Hashing:** The `Hash()` and `SetHash()` methods indicate that the dictionary itself might store a precomputed hash value, possibly for optimization.
    * **Internal Helpers:**  `GetCtrl()`, `SetCtrl()`, `FindFirstEmpty()`, `probe()` are internal helper functions for managing the control table and searching for slots.
    * **Static Methods:** Several static methods (`IsValidCapacity`, `CapacityFor`, `EnsureGrowable`, `Add`, `Initialize`, `IsEmpty`, `IsFull`, `IsDeleted`, `IsEmptyOrDeleted`, `probe`, `MaxCapacity`) provide utility functions for working with `SwissNameDictionary` objects.

4. **Connect to JavaScript (If Applicable):** The prompt specifically asks about connections to JavaScript. Dictionaries in JavaScript are typically implemented using hash tables. The `SwissNameDictionary` is a prime candidate for being the underlying implementation for JavaScript objects or Maps. Think about how JavaScript object property access works: it involves looking up the property name (a string or symbol) and retrieving its value. This aligns perfectly with the `FindEntry()` and related methods.

5. **Torque Connection:** The inclusion of `torque-generated/...` is a strong signal. Torque is used for performance-critical parts of V8. This dictionary is likely used in scenarios where efficient name lookup is crucial.

6. **Code Logic and Examples:**
    * **Assumption:**  The dictionary stores key-value pairs, where keys are V8 `Name` objects (strings or symbols).
    * **Input/Output for `FindEntry()`:** If you insert a key "foo" with a value, calling `FindEntry()` with "foo" should return the index of that entry. Calling it with a non-existent key should return `NotFound()`.
    * **Input/Output for `Add()`:** Adding a new key-value pair should increase the number of elements and potentially rehash if the capacity is reached.

7. **Common Programming Errors:** Consider how users might misuse a dictionary-like structure. Forgetting to handle the case where a key isn't found is a classic error. Understanding the potential performance implications of frequent insertions and deletions, which might trigger rehashing, is also important.

8. **Structure the Answer:** Organize the findings logically, starting with the core functionality, then drilling down into details like Torque integration, JavaScript relevance, and potential pitfalls. Use clear headings and bullet points for readability. Provide concrete JavaScript examples to illustrate the connection.

By following these steps, you can systematically analyze the C++ header file and generate a comprehensive and informative explanation of its purpose and functionality. The key is to carefully examine the code, understand the relationships between different parts, and connect it to the broader context of the V8 JavaScript engine.
This header file, `v8/src/objects/swiss-name-dictionary-inl.h`, defines the **inline implementations** for the `SwissNameDictionary` class in V8. This class is a crucial component of V8's object system, acting as a **high-performance hash table specifically designed for storing and retrieving named properties of JavaScript objects.**  It utilizes a "Swiss Table" data structure, known for its efficiency and good performance characteristics.

Here's a breakdown of its key functionalities:

**Core Functionality:**

* **Storage of Key-Value Pairs:** It stores key-value pairs, where the **keys are typically `Name` objects (Strings or Symbols) representing property names**, and the **values can be any V8 object**.
* **Efficient Lookup:** The core purpose is to **quickly find the value associated with a given key**. The Swiss Table algorithm enables fast lookups, insertions, and deletions.
* **Dynamic Sizing:** The dictionary can **grow dynamically** as more key-value pairs are added, ensuring that it can accommodate varying numbers of properties.
* **Handling Deleted Entries:** It efficiently handles the removal of entries, often using a "deleted" marker rather than immediately reorganizing the entire table.
* **Iteration:** It provides mechanisms for **iterating through the stored key-value pairs**.
* **Metadata Storage:**  It includes a `meta_table` to store additional information, such as the order of insertion for enumeration purposes.
* **Property Details:** It stores `PropertyDetails` alongside each entry, which can hold information about the property's attributes (e.g., whether it's read-only, configurable, etc.).

**Specific Features and Implementation Details Highlighted in the Code:**

* **Swiss Table Implementation:** The code directly manipulates the underlying Swiss Table structure through methods like `CtrlTable()`, `PropertyDetailsTable()`, `GetCtrl()`, `SetCtrl()`, and the `probe()` function. This indicates a direct implementation of the Swiss Table algorithm.
* **Capacity Management:**  Functions like `Capacity()`, `SetCapacity()`, `IsValidCapacity()`, `CapacityFor()`, `MaxUsableCapacity()` are responsible for managing the size of the underlying hash table.
* **Meta-Table Management:** Functions like `SetMetaTableField()` and `GetMetaTableField()` interact with the `meta_table_` to store and retrieve metadata. The size of the metadata entry depends on the dictionary's capacity.
* **Enumeration Order:** The `EntryForEnumerationIndex()` and `SetEntryForEnumerationIndex()` functions, along with the `IndexIterator` and `IndexIterable` classes, are crucial for maintaining and iterating through the dictionary in a predictable order, which is important for JavaScript object property enumeration.
* **Inline Functions:** The `.inl.h` suffix signifies that many of these functions are defined inline, which can improve performance by reducing function call overhead.
* **Pointer Compression Awareness:** The code uses `PtrComprCageBase` in `LoadFromDataTable`, indicating awareness of V8's pointer compression techniques for memory optimization.

**Is it a Torque Source Code?**

No, `v8/src/objects/swiss-name-dictionary-inl.h` is **not a Torque source code file**. Torque source files typically have the `.tq` extension. While this file *includes* a Torque-generated file (`torque-generated/src/objects/swiss-name-dictionary-tq-inl.inc`), the main file itself is C++. The included Torque file likely contains boilerplate code for object creation, field accessors, and potentially some type checks that are automatically generated from a higher-level Torque definition.

**Relationship to JavaScript Functionality and Examples:**

The `SwissNameDictionary` is **directly related to how JavaScript objects store their properties**. When you access or modify properties of a JavaScript object, V8 internally uses a hash table (and `SwissNameDictionary` is a primary candidate for that implementation) to find the corresponding value.

**JavaScript Example:**

```javascript
const myObject = {
  name: "Alice",
  age: 30,
  city: "New York"
};

console.log(myObject.name); // Accessing the 'name' property

myObject.occupation = "Engineer"; // Adding a new property

delete myObject.age; // Deleting the 'age' property

for (const key in myObject) { // Iterating through properties
  console.log(key, myObject[key]);
}
```

**Explanation:**

* When you create `myObject`, V8 might internally use a `SwissNameDictionary` (or a similar structure) to store the properties `name`, `age`, and `city` along with their values.
* `console.log(myObject.name)` triggers a lookup in the internal dictionary using "name" as the key to retrieve the value "Alice".
* `myObject.occupation = "Engineer"` involves inserting a new key-value pair ("occupation", "Engineer") into the dictionary. If the dictionary is full, it might need to be resized (rehashing).
* `delete myObject.age` causes the entry associated with the key "age" to be marked as deleted (or potentially removed).
* The `for...in` loop iterates through the keys in the dictionary, relying on the iteration mechanisms provided by `SwissNameDictionary`.

**Code Logic Reasoning with Assumptions and Input/Output:**

**Scenario: Looking up a property using `FindEntry()`**

**Assumption:** A `SwissNameDictionary` instance `dict` exists and contains the property "name" with the value "Alice".

**Input:**
* `isolate`: A pointer to the current V8 isolate.
* `key`: A `Tagged<Name>` object representing the string "name".

**Code:**
```c++
InternalIndex index = dict->FindEntry(isolate, key);
```

**Output:**
* If the property "name" exists in `dict`, `index` will be an `InternalIndex` containing the internal index (an integer) where the entry for "name" is stored.
* If the property "name" does not exist, `index` will be `InternalIndex::NotFound()`.

**Scenario: Adding a new property using `Add()`**

**Assumption:** A `SwissNameDictionary` instance `dict` exists and does not yet contain the property "occupation".

**Input:**
* `isolate`: A pointer to the current V8 isolate.
* `dict`: A handle to the existing `SwissNameDictionary`.
* `key`: A direct handle to a `Name` object representing the string "occupation".
* `value`: A direct handle to an `Object` representing the string "Engineer".
* `details`: `PropertyDetails` for the new property.
* `entry_out`: A pointer to an `InternalIndex` where the index of the newly added entry will be stored.

**Code:**
```c++
Handle<SwissNameDictionary> new_dict = SwissNameDictionary::Add(
    isolate, dict, key, value, details, entry_out);
```

**Output:**
* `new_dict`:  A handle to the (potentially new) `SwissNameDictionary`. If the original dictionary had enough capacity, it might be the same handle. If rehashing was needed, it will be a handle to a new, larger dictionary.
* `entry_out`:  Will contain the `InternalIndex` of the newly added "occupation" entry within the dictionary.

**Common Programming Errors (Relating to how this dictionary is used internally in V8):**

While developers don't directly interact with `SwissNameDictionary` in their JavaScript code, understanding its behavior helps in understanding potential performance pitfalls or unexpected behavior in V8 itself. Here are some conceptual examples of errors *within V8's implementation* or scenarios that might lead to performance issues:

1. **Incorrect Hash Function or Collision Handling:** If the hash function used for `Name` objects is poorly designed, it could lead to many collisions in the `SwissNameDictionary`. This would degrade lookup performance, as V8 would have to probe through many entries to find the correct one. The Swiss Table algorithm is designed to mitigate collision issues, but a bad hash function can still impact performance.

2. **Excessive Rehashing:** If objects frequently have properties added and removed, the underlying `SwissNameDictionary` might need to be resized (rehashed) often. Rehashing is a relatively expensive operation, as it involves creating a new, larger table and copying all the existing entries. Frequent rehashing can lead to performance hiccups.

3. **Memory Leaks (Conceptual):**  While garbage collection handles the memory management of the dictionary itself and its contained objects, if there were logical errors in how V8 manages the association between JavaScript objects and their property dictionaries, it could conceptually lead to scenarios where dictionaries are not released when the corresponding JavaScript object is no longer needed.

4. **Incorrectly Calculating Capacity:** If the logic for calculating the initial capacity or growth factor of the `SwissNameDictionary` is flawed, it could lead to either excessive memory usage (if the initial capacity is too high) or frequent, inefficient rehashing (if the growth factor is too small).

**In summary, `v8/src/objects/swiss-name-dictionary-inl.h` defines the core implementation of a high-performance hash table used by V8 to manage the properties of JavaScript objects. It leverages the Swiss Table algorithm for efficiency and includes mechanisms for dynamic sizing, handling deleted entries, iteration, and metadata storage. While not directly written in Torque, it often works in conjunction with Torque-generated code for object management within V8.**

Prompt: 
```
这是目录为v8/src/objects/swiss-name-dictionary-inl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/swiss-name-dictionary-inl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2021 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_OBJECTS_SWISS_NAME_DICTIONARY_INL_H_
#define V8_OBJECTS_SWISS_NAME_DICTIONARY_INL_H_

#include <algorithm>
#include <optional>

#include "src/base/macros.h"
#include "src/execution/isolate-utils-inl.h"
#include "src/heap/heap.h"
#include "src/objects/fixed-array-inl.h"
#include "src/objects/instance-type-inl.h"
#include "src/objects/js-collection-iterator.h"
#include "src/objects/objects-inl.h"
#include "src/objects/slots-inl.h"
#include "src/objects/smi.h"
#include "src/objects/swiss-name-dictionary.h"

// Has to be the last include (doesn't have include guards):
#include "src/objects/object-macros.h"

namespace v8::internal {

#include "torque-generated/src/objects/swiss-name-dictionary-tq-inl.inc"

OBJECT_CONSTRUCTORS_IMPL(SwissNameDictionary, HeapObject)

swiss_table::ctrl_t* SwissNameDictionary::CtrlTable() {
  return reinterpret_cast<ctrl_t*>(
      field_address(CtrlTableStartOffset(Capacity())));
}

uint8_t* SwissNameDictionary::PropertyDetailsTable() {
  return reinterpret_cast<uint8_t*>(
      field_address(PropertyDetailsTableStartOffset(Capacity())));
}

int SwissNameDictionary::Capacity() {
  return ReadField<int32_t>(CapacityOffset());
}

void SwissNameDictionary::SetCapacity(int capacity) {
  DCHECK(IsValidCapacity(capacity));

  WriteField<int32_t>(CapacityOffset(), capacity);
}

int SwissNameDictionary::NumberOfElements() {
  return GetMetaTableField(kMetaTableElementCountFieldIndex);
}

int SwissNameDictionary::NumberOfDeletedElements() {
  return GetMetaTableField(kMetaTableDeletedElementCountFieldIndex);
}

void SwissNameDictionary::SetNumberOfElements(int elements) {
  SetMetaTableField(kMetaTableElementCountFieldIndex, elements);
}

void SwissNameDictionary::SetNumberOfDeletedElements(int deleted_elements) {
  SetMetaTableField(kMetaTableDeletedElementCountFieldIndex, deleted_elements);
}

int SwissNameDictionary::UsedCapacity() {
  return NumberOfElements() + NumberOfDeletedElements();
}

// static
constexpr bool SwissNameDictionary::IsValidCapacity(int capacity) {
  return capacity == 0 || (capacity >= kInitialCapacity &&
                           // Must be power of 2.
                           ((capacity & (capacity - 1)) == 0));
}

// static
constexpr int SwissNameDictionary::DataTableSize(int capacity) {
  return capacity * kTaggedSize * kDataTableEntryCount;
}

// static
constexpr int SwissNameDictionary::CtrlTableSize(int capacity) {
  // Doing + |kGroupWidth| due to the copy of first group at the end of control
  // table.
  return (capacity + kGroupWidth) * kOneByteSize;
}

// static
constexpr int SwissNameDictionary::SizeFor(int capacity) {
  DCHECK(IsValidCapacity(capacity));
  return PropertyDetailsTableStartOffset(capacity) + capacity;
}

// We use 7/8th as maximum load factor for non-special cases.
// For 16-wide groups, that gives an average of two empty slots per group.
// Similar to Abseil's CapacityToGrowth.
// static
constexpr int SwissNameDictionary::MaxUsableCapacity(int capacity) {
  DCHECK(IsValidCapacity(capacity));

  if (Group::kWidth == 8 && capacity == 4) {
    // If the group size is 16 we can fully utilize capacity 4: There will be
    // enough kEmpty entries in the ctrl table.
    return 3;
  }
  return capacity - capacity / 8;
}

// Returns |at_least_space_for| * 8/7 for non-special cases. Similar to Abseil's
// GrowthToLowerboundCapacity.
// static
int SwissNameDictionary::CapacityFor(int at_least_space_for) {
  if (at_least_space_for <= 4) {
    if (at_least_space_for == 0) {
      return 0;
    } else if (at_least_space_for < 4) {
      return 4;
    } else if (kGroupWidth == 16) {
      DCHECK_EQ(4, at_least_space_for);
      return 4;
    } else if (kGroupWidth == 8) {
      DCHECK_EQ(4, at_least_space_for);
      return 8;
    }
  }

  int non_normalized = at_least_space_for + at_least_space_for / 7;
  return base::bits::RoundUpToPowerOfTwo32(non_normalized);
}

int SwissNameDictionary::EntryForEnumerationIndex(int enumeration_index) {
  DCHECK_LT(enumeration_index, UsedCapacity());
  return GetMetaTableField(kMetaTableEnumerationDataStartIndex +
                           enumeration_index);
}

void SwissNameDictionary::SetEntryForEnumerationIndex(int enumeration_index,
                                                      int entry) {
  DCHECK_LT(enumeration_index, UsedCapacity());
  DCHECK_LT(static_cast<unsigned>(entry), static_cast<unsigned>(Capacity()));
  DCHECK(IsFull(GetCtrl(entry)));

  SetMetaTableField(kMetaTableEnumerationDataStartIndex + enumeration_index,
                    entry);
}

template <typename IsolateT>
InternalIndex SwissNameDictionary::FindEntry(IsolateT* isolate,
                                             Tagged<Object> key) {
  Tagged<Name> name = Cast<Name>(key);
  DCHECK(IsUniqueName(name));
  uint32_t hash = name->hash();

  // We probe the hash table in groups of |kGroupWidth| buckets. One bucket
  // corresponds to a 1-byte entry in the control table.
  // Each group can be uniquely identified by the index of its first bucket,
  // which must be a value between 0 (inclusive) and Capacity() (exclusive).
  // Note that logically, groups wrap around after index Capacity() - 1. This
  // means that probing the group starting at, for example, index Capacity() - 1
  // means probing CtrlTable()[Capacity() - 1] followed by CtrlTable()[0] to
  // CtrlTable()[6], assuming a group width of 8. However, in memory, this is
  // achieved by maintaining an additional |kGroupWidth| bytes after the first
  // Capacity() entries of the control table. These contain a copy of the first
  // max(Capacity(), kGroupWidth) entries of the control table. If Capacity() <
  // |kGroupWidth|, then the remaining |kGroupWidth| - Capacity() control bytes
  // are left as |kEmpty|.
  // This means that actually, probing the group starting
  // at index Capacity() - 1 is achieved by probing CtrlTable()[Capacity() - 1],
  // followed by CtrlTable()[Capacity()] to CtrlTable()[Capacity() + 7].

  ctrl_t* ctrl = CtrlTable();
  auto seq = probe(hash, Capacity());
  // At this point, seq.offset() denotes the index of the first bucket in the
  // first group to probe. Note that this doesn't have to be divisible by
  // |kGroupWidth|, but can have any value between 0 (inclusive) and Capacity()
  // (exclusive).
  while (true) {
    Group g{ctrl + seq.offset()};
    for (int i : g.Match(swiss_table::H2(hash))) {
      int candidate_entry = seq.offset(i);
      Tagged<Object> candidate_key = KeyAt(candidate_entry);
      // This key matching is SwissNameDictionary specific!
      if (candidate_key == key) return InternalIndex(candidate_entry);
    }
    if (g.MatchEmpty()) return InternalIndex::NotFound();

    // The following selects the next group to probe. Note that seq.offset()
    // always advances by a multiple of |kGroupWidth|, modulo Capacity(). This
    // is done in a way such that we visit Capacity() / |kGroupWidth|
    // non-overlapping (!) groups before we would visit the same group (or
    // bucket) again.
    seq.next();

    // If the following DCHECK weren't true, we would have probed all Capacity()
    // different buckets without finding one containing |kEmpty| (which would
    // haved triggered the g.MatchEmpty() check above). This must not be the
    // case because the maximum load factor of 7/8 guarantees that there must
    // always remain empty buckets.
    //
    // The only exception from this rule are small tables, where 2 * Capacity()
    // < |kGroupWidth|, in which case all Capacity() entries can be filled
    // without leaving empty buckets. The layout of the control
    // table guarantees that after the first Capacity() entries of the control
    // table, the control table contains a copy of those first Capacity()
    // entries, followed by kGroupWidth - 2 * Capacity() entries containing
    // |kEmpty|. This guarantees that the g.MatchEmpty() check above will
    // always trigger if the element wasn't found, correctly preventing us from
    // probing more than one group in this special case.
    DCHECK_LT(seq.index(), Capacity());
  }
}

template <typename IsolateT>
InternalIndex SwissNameDictionary::FindEntry(IsolateT* isolate,
                                             DirectHandle<Object> key) {
  return FindEntry(isolate, *key);
}

Tagged<Object> SwissNameDictionary::LoadFromDataTable(int entry,
                                                      int data_offset) {
  return LoadFromDataTable(GetPtrComprCageBase(*this), entry, data_offset);
}

Tagged<Object> SwissNameDictionary::LoadFromDataTable(
    PtrComprCageBase cage_base, int entry, int data_offset) {
  DCHECK_LT(static_cast<unsigned>(entry), static_cast<unsigned>(Capacity()));
  int offset = DataTableStartOffset() +
               (entry * kDataTableEntryCount + data_offset) * kTaggedSize;
  return TaggedField<Object>::Relaxed_Load(cage_base, *this, offset);
}

void SwissNameDictionary::StoreToDataTable(int entry, int data_offset,
                                           Tagged<Object> data) {
  DCHECK_LT(static_cast<unsigned>(entry), static_cast<unsigned>(Capacity()));

  int offset = DataTableStartOffset() +
               (entry * kDataTableEntryCount + data_offset) * kTaggedSize;

  RELAXED_WRITE_FIELD(*this, offset, data);
  WRITE_BARRIER(*this, offset, data);
}

void SwissNameDictionary::StoreToDataTableNoBarrier(int entry, int data_offset,
                                                    Tagged<Object> data) {
  DCHECK_LT(static_cast<unsigned>(entry), static_cast<unsigned>(Capacity()));

  int offset = DataTableStartOffset() +
               (entry * kDataTableEntryCount + data_offset) * kTaggedSize;

  RELAXED_WRITE_FIELD(*this, offset, data);
}

void SwissNameDictionary::ClearDataTableEntry(Isolate* isolate, int entry) {
  ReadOnlyRoots roots(isolate);

  StoreToDataTable(entry, kDataTableKeyEntryIndex, roots.the_hole_value());
  StoreToDataTable(entry, kDataTableValueEntryIndex, roots.the_hole_value());
}

void SwissNameDictionary::ValueAtPut(int entry, Tagged<Object> value) {
  DCHECK(!IsTheHole(value));
  StoreToDataTable(entry, kDataTableValueEntryIndex, value);
}

void SwissNameDictionary::ValueAtPut(InternalIndex entry,
                                     Tagged<Object> value) {
  ValueAtPut(entry.as_int(), value);
}

void SwissNameDictionary::SetKey(int entry, Tagged<Object> key) {
  DCHECK(!IsTheHole(key));
  StoreToDataTable(entry, kDataTableKeyEntryIndex, key);
}

void SwissNameDictionary::DetailsAtPut(int entry, PropertyDetails details) {
  DCHECK_LT(static_cast<unsigned>(entry), static_cast<unsigned>(Capacity()));
  uint8_t encoded_details = details.ToByte();
  PropertyDetailsTable()[entry] = encoded_details;
}

void SwissNameDictionary::DetailsAtPut(InternalIndex entry,
                                       PropertyDetails details) {
  DetailsAtPut(entry.as_int(), details);
}

Tagged<Object> SwissNameDictionary::KeyAt(int entry) {
  return LoadFromDataTable(entry, kDataTableKeyEntryIndex);
}

Tagged<Object> SwissNameDictionary::KeyAt(InternalIndex entry) {
  return KeyAt(entry.as_int());
}

Tagged<Name> SwissNameDictionary::NameAt(InternalIndex entry) {
  return Cast<Name>(KeyAt(entry));
}

// This version can be called on empty buckets.
Tagged<Object> SwissNameDictionary::ValueAtRaw(int entry) {
  return LoadFromDataTable(entry, kDataTableValueEntryIndex);
}

Tagged<Object> SwissNameDictionary::ValueAt(InternalIndex entry) {
  DCHECK(IsFull(GetCtrl(entry.as_int())));
  return ValueAtRaw(entry.as_int());
}

std::optional<Tagged<Object>> SwissNameDictionary::TryValueAt(
    InternalIndex entry) {
#if DEBUG
  Isolate* isolate;
  GetIsolateFromHeapObject(*this, &isolate);
  DCHECK_NE(isolate, nullptr);
  SLOW_DCHECK(!isolate->heap()->IsPendingAllocation(Tagged(*this)));
#endif  // DEBUG
  // We can read Capacity() in a non-atomic way since we are reading an
  // initialized object which is not pending allocation.
  if (static_cast<unsigned>(entry.as_int()) >=
      static_cast<unsigned>(Capacity())) {
    return {};
  }
  return ValueAtRaw(entry.as_int());
}

PropertyDetails SwissNameDictionary::DetailsAt(int entry) {
  // GetCtrl(entry) does a bounds check for |entry| value.
  DCHECK(IsFull(GetCtrl(entry)));

  uint8_t encoded_details = PropertyDetailsTable()[entry];
  return PropertyDetails::FromByte(encoded_details);
}

PropertyDetails SwissNameDictionary::DetailsAt(InternalIndex entry) {
  return DetailsAt(entry.as_int());
}

// static
template <typename IsolateT>
Handle<SwissNameDictionary> SwissNameDictionary::EnsureGrowable(
    IsolateT* isolate, Handle<SwissNameDictionary> table) {
  int capacity = table->Capacity();

  if (table->UsedCapacity() < MaxUsableCapacity(capacity)) {
    // We have room for at least one more entry, nothing to do.
    return table;
  }

  int new_capacity = capacity == 0 ? kInitialCapacity : capacity * 2;
  return Rehash(isolate, table, new_capacity);
}

swiss_table::ctrl_t SwissNameDictionary::GetCtrl(int entry) {
  DCHECK_LT(static_cast<unsigned>(entry), static_cast<unsigned>(Capacity()));

  return CtrlTable()[entry];
}

void SwissNameDictionary::SetCtrl(int entry, ctrl_t h) {
  int capacity = Capacity();
  DCHECK_LT(static_cast<unsigned>(entry), static_cast<unsigned>(capacity));

  ctrl_t* ctrl = CtrlTable();
  ctrl[entry] = h;

  // The ctrl table contains a copy of the first group (i.e., the group starting
  // at entry 0) after the first |capacity| entries of the ctrl table. This
  // means that the ctrl table always has size |capacity| + |kGroupWidth|.
  // However, note that we may have |capacity| < |kGroupWidth|. For example, if
  // Capacity() == 8 and |kGroupWidth| == 16, then ctrl[0] is copied to ctrl[8],
  // ctrl[1] to ctrl[9], etc. In this case, ctrl[16] to ctrl[23] remain unused,
  // which means that their values are always Ctrl::kEmpty.
  // We achieve the necessary copying without branching here using some bit
  // magic: We set {copy_entry = entry} in those cases where we don't actually
  // have to perform a copy (meaning that we just repeat the {ctrl[entry] = h}
  // from above). If we do need to do some actual copying, we set {copy_entry =
  // Capacity() + entry}.

  int mask = capacity - 1;
  int copy_entry =
      ((entry - Group::kWidth) & mask) + 1 + ((Group::kWidth - 1) & mask);
  DCHECK_IMPLIES(entry < static_cast<int>(Group::kWidth),
                 copy_entry == capacity + entry);
  DCHECK_IMPLIES(entry >= static_cast<int>(Group::kWidth), copy_entry == entry);
  ctrl[copy_entry] = h;
}

// static
inline int SwissNameDictionary::FindFirstEmpty(uint32_t hash) {
  // See SwissNameDictionary::FindEntry for description of probing algorithm.

  auto seq = probe(hash, Capacity());
  while (true) {
    Group g{CtrlTable() + seq.offset()};
    auto mask = g.MatchEmpty();
    if (mask) {
      // Note that picking the lowest bit set here means using the leftmost
      // empty bucket in the group. Here, "left" means smaller entry/bucket
      // index.
      return seq.offset(mask.LowestBitSet());
    }
    seq.next();
    DCHECK_LT(seq.index(), Capacity());
  }
}

void SwissNameDictionary::SetMetaTableField(int field_index, int value) {
  // See the STATIC_ASSERTs on |kMax1ByteMetaTableCapacity| and
  // |kMax2ByteMetaTableCapacity| in the .cc file for an explanation of these
  // constants.
  int capacity = Capacity();
  Tagged<ByteArray> meta_table = this->meta_table();
  if (capacity <= kMax1ByteMetaTableCapacity) {
    SetMetaTableField<uint8_t>(meta_table, field_index, value);
  } else if (capacity <= kMax2ByteMetaTableCapacity) {
    SetMetaTableField<uint16_t>(meta_table, field_index, value);
  } else {
    SetMetaTableField<uint32_t>(meta_table, field_index, value);
  }
}

int SwissNameDictionary::GetMetaTableField(int field_index) {
  // See the STATIC_ASSERTs on |kMax1ByteMetaTableCapacity| and
  // |kMax2ByteMetaTableCapacity| in the .cc file for an explanation of these
  // constants.
  int capacity = Capacity();
  Tagged<ByteArray> meta_table = this->meta_table();
  if (capacity <= kMax1ByteMetaTableCapacity) {
    return GetMetaTableField<uint8_t>(meta_table, field_index);
  } else if (capacity <= kMax2ByteMetaTableCapacity) {
    return GetMetaTableField<uint16_t>(meta_table, field_index);
  } else {
    return GetMetaTableField<uint32_t>(meta_table, field_index);
  }
}

// static
template <typename T>
void SwissNameDictionary::SetMetaTableField(Tagged<ByteArray> meta_table,
                                            int field_index, int value) {
  static_assert((std::is_same<T, uint8_t>::value) ||
                (std::is_same<T, uint16_t>::value) ||
                (std::is_same<T, uint32_t>::value));
  DCHECK_LE(value, std::numeric_limits<T>::max());
  DCHECK_LT(meta_table->begin() + field_index * sizeof(T), meta_table->end());
  T* raw_data = reinterpret_cast<T*>(meta_table->begin());
  raw_data[field_index] = value;
}

// static
template <typename T>
int SwissNameDictionary::GetMetaTableField(Tagged<ByteArray> meta_table,
                                           int field_index) {
  static_assert((std::is_same<T, uint8_t>::value) ||
                (std::is_same<T, uint16_t>::value) ||
                (std::is_same<T, uint32_t>::value));
  DCHECK_LT(meta_table->begin() + field_index * sizeof(T), meta_table->end());
  T* raw_data = reinterpret_cast<T*>(meta_table->begin());
  return raw_data[field_index];
}

constexpr int SwissNameDictionary::MetaTableSizePerEntryFor(int capacity) {
  DCHECK(IsValidCapacity(capacity));

  // See the STATIC_ASSERTs on |kMax1ByteMetaTableCapacity| and
  // |kMax2ByteMetaTableCapacity| in the .cc file for an explanation of these
  // constants.
  if (capacity <= kMax1ByteMetaTableCapacity) {
    return sizeof(uint8_t);
  } else if (capacity <= kMax2ByteMetaTableCapacity) {
    return sizeof(uint16_t);
  } else {
    return sizeof(uint32_t);
  }
}

constexpr int SwissNameDictionary::MetaTableSizeFor(int capacity) {
  DCHECK(IsValidCapacity(capacity));

  int per_entry_size = MetaTableSizePerEntryFor(capacity);

  // The enumeration table only needs to have as many slots as there can be
  // present + deleted entries in the hash table (= maximum load factor *
  // capactiy). Two more slots to store the number of present and deleted
  // entries.
  return per_entry_size * (MaxUsableCapacity(capacity) + 2);
}

bool SwissNameDictionary::IsKey(ReadOnlyRoots roots,
                                Tagged<Object> key_candidate) {
  return key_candidate != roots.the_hole_value();
}

bool SwissNameDictionary::ToKey(ReadOnlyRoots roots, int entry,
                                Tagged<Object>* out_key) {
  Tagged<Object> k = KeyAt(entry);
  if (!IsKey(roots, k)) return false;
  *out_key = k;
  return true;
}

bool SwissNameDictionary::ToKey(ReadOnlyRoots roots, InternalIndex entry,
                                Tagged<Object>* out_key) {
  return ToKey(roots, entry.as_int(), out_key);
}

// static
template <typename IsolateT>
Handle<SwissNameDictionary> SwissNameDictionary::Add(
    IsolateT* isolate, Handle<SwissNameDictionary> original_table,
    DirectHandle<Name> key, DirectHandle<Object> value, PropertyDetails details,
    InternalIndex* entry_out) {
  DCHECK(original_table->FindEntry(isolate, *key).is_not_found());

  Handle<SwissNameDictionary> table = EnsureGrowable(isolate, original_table);
  DisallowGarbageCollection no_gc;
  Tagged<SwissNameDictionary> raw_table = *table;
  int nof = raw_table->NumberOfElements();
  int nod = raw_table->NumberOfDeletedElements();
  int new_enum_index = nof + nod;

  int new_entry = raw_table->AddInternal(*key, *value, details);

  raw_table->SetNumberOfElements(nof + 1);
  raw_table->SetEntryForEnumerationIndex(new_enum_index, new_entry);

  if (entry_out) {
    *entry_out = InternalIndex(new_entry);
  }

  return table;
}

int SwissNameDictionary::AddInternal(Tagged<Name> key, Tagged<Object> value,
                                     PropertyDetails details) {
  DisallowHeapAllocation no_gc;

  DCHECK(IsUniqueName(key));
  DCHECK_LE(UsedCapacity(), MaxUsableCapacity(Capacity()));

  uint32_t hash = key->hash();

  // For now we don't re-use deleted buckets (due to enumeration table
  // complications), which is why we only look for empty buckets here, not
  // deleted ones.
  int target = FindFirstEmpty(hash);

  SetCtrl(target, swiss_table::H2(hash));
  SetKey(target, key);
  ValueAtPut(target, value);
  DetailsAtPut(target, details);

  // Note that we do not update the number of elements or the enumeration table
  // in this function.

  return target;
}

template <typename IsolateT>
void SwissNameDictionary::Initialize(IsolateT* isolate,
                                     Tagged<ByteArray> meta_table,
                                     int capacity) {
  DCHECK(IsValidCapacity(capacity));
  DisallowHeapAllocation no_gc;
  ReadOnlyRoots roots(isolate);

  SetCapacity(capacity);
  SetHash(PropertyArray::kNoHashSentinel);

  memset(CtrlTable(), Ctrl::kEmpty, CtrlTableSize(capacity));

  MemsetTagged(RawField(DataTableStartOffset()), roots.the_hole_value(),
               capacity * kDataTableEntryCount);

  set_meta_table(meta_table);

  SetNumberOfElements(0);
  SetNumberOfDeletedElements(0);

  // We leave the enumeration table PropertyDetails table and uninitialized.
}

SwissNameDictionary::IndexIterator::IndexIterator(
    Handle<SwissNameDictionary> dict, int start)
    : enum_index_{start}, dict_{dict} {
  if (dict.is_null()) {
    used_capacity_ = 0;
  } else {
    used_capacity_ = dict->UsedCapacity();
  }
}

SwissNameDictionary::IndexIterator&
SwissNameDictionary::IndexIterator::operator++() {
  DCHECK_LT(enum_index_, used_capacity_);
  ++enum_index_;
  return *this;
}

bool SwissNameDictionary::IndexIterator::operator==(
    const SwissNameDictionary::IndexIterator& b) const {
  DCHECK_LE(enum_index_, used_capacity_);
  DCHECK_LE(b.enum_index_, used_capacity_);
  DCHECK(dict_.equals(b.dict_));

  return this->enum_index_ == b.enum_index_;
}

bool SwissNameDictionary::IndexIterator::operator!=(
    const IndexIterator& b) const {
  return !(*this == b);
}

InternalIndex SwissNameDictionary::IndexIterator::operator*() {
  DCHECK_LE(enum_index_, used_capacity_);

  if (enum_index_ == used_capacity_) return InternalIndex::NotFound();

  return InternalIndex(dict_->EntryForEnumerationIndex(enum_index_));
}

SwissNameDictionary::IndexIterable::IndexIterable(
    Handle<SwissNameDictionary> dict)
    : dict_{dict} {}

SwissNameDictionary::IndexIterator SwissNameDictionary::IndexIterable::begin() {
  return IndexIterator(dict_, 0);
}

SwissNameDictionary::IndexIterator SwissNameDictionary::IndexIterable::end() {
  if (dict_.is_null()) {
    return IndexIterator(dict_, 0);
  } else {
    DCHECK(!dict_.is_null());
    return IndexIterator(dict_, dict_->UsedCapacity());
  }
}

SwissNameDictionary::IndexIterable
SwissNameDictionary::IterateEntriesOrdered() {
  // If we are supposed to iterate the empty dictionary (which is non-writable),
  // we have no simple way to get the isolate, which we would need to create a
  // handle.
  // TODO(emrich): Consider always using roots.empty_swiss_dictionary_handle()
  // in the condition once this function gets Isolate as a parameter in order to
  // avoid empty dict checks.
  if (Capacity() == 0) {
    return IndexIterable(Handle<SwissNameDictionary>::null());
  }

  Isolate* isolate;
  GetIsolateFromHeapObject(*this, &isolate);
  DCHECK_NE(isolate, nullptr);
  return IndexIterable(handle(*this, isolate));
}

SwissNameDictionary::IndexIterable SwissNameDictionary::IterateEntries() {
  return IterateEntriesOrdered();
}

void SwissNameDictionary::SetHash(int32_t hash) {
  WriteField(PrefixOffset(), hash);
}

int SwissNameDictionary::Hash() { return ReadField<int32_t>(PrefixOffset()); }

// static
constexpr int SwissNameDictionary::MaxCapacity() {
  int const_size =
      DataTableStartOffset() + sizeof(ByteArray::Header) +
      // Size for present and deleted element count at max capacity:
      2 * sizeof(uint32_t);
  int per_entry_size =
      // size of data table entries:
      kDataTableEntryCount * kTaggedSize +
      // ctrl table entry size:
      kOneByteSize +
      // PropertyDetails table entry size:
      kOneByteSize +
      // Enumeration table entry size at maximum capacity:
      sizeof(uint32_t);

  int result = (FixedArrayBase::kMaxSize - const_size) / per_entry_size;
  DCHECK_GE(Smi::kMaxValue, result);

  return result;
}

// static
constexpr int SwissNameDictionary::PrefixOffset() {
  return HeapObject::kHeaderSize;
}

// static
constexpr int SwissNameDictionary::CapacityOffset() {
  return PrefixOffset() + sizeof(uint32_t);
}

// static
constexpr int SwissNameDictionary::MetaTablePointerOffset() {
  return CapacityOffset() + sizeof(int32_t);
}

// static
constexpr int SwissNameDictionary::DataTableStartOffset() {
  return MetaTablePointerOffset() + kTaggedSize;
}

// static
constexpr int SwissNameDictionary::DataTableEndOffset(int capacity) {
  return CtrlTableStartOffset(capacity);
}

// static
constexpr int SwissNameDictionary::CtrlTableStartOffset(int capacity) {
  return DataTableStartOffset() + DataTableSize(capacity);
}

// static
constexpr int SwissNameDictionary::PropertyDetailsTableStartOffset(
    int capacity) {
  return CtrlTableStartOffset(capacity) + CtrlTableSize(capacity);
}

// static
bool SwissNameDictionary::IsEmpty(ctrl_t c) { return c == Ctrl::kEmpty; }

// static
bool SwissNameDictionary::IsFull(ctrl_t c) {
  static_assert(Ctrl::kEmpty < 0);
  static_assert(Ctrl::kDeleted < 0);
  static_assert(Ctrl::kSentinel < 0);
  return c >= 0;
}

// static
bool SwissNameDictionary::IsDeleted(ctrl_t c) { return c == Ctrl::kDeleted; }

// static
bool SwissNameDictionary::IsEmptyOrDeleted(ctrl_t c) {
  static_assert(Ctrl::kDeleted < Ctrl::kSentinel);
  static_assert(Ctrl::kEmpty < Ctrl::kSentinel);
  static_assert(Ctrl::kSentinel < 0);
  return c < Ctrl::kSentinel;
}

// static
swiss_table::ProbeSequence<SwissNameDictionary::kGroupWidth>
SwissNameDictionary::probe(uint32_t hash, int capacity) {
  // If |capacity| is 0, we must produce 1 here, such that the - 1 below
  // yields 0, which is the correct modulo mask for a table of capacity 0.
  int non_zero_capacity = capacity | (capacity == 0);
  return swiss_table::ProbeSequence<SwissNameDictionary::kGroupWidth>(
      swiss_table::H1(hash), static_cast<uint32_t>(non_zero_capacity - 1));
}

ACCESSORS_CHECKED2(SwissNameDictionary, meta_table, Tagged<ByteArray>,
                   MetaTablePointerOffset(), true,
                   value->length() >= kMetaTableEnumerationDataStartIndex)

}  // namespace v8::internal

#include "src/objects/object-macros-undef.h"

#endif  // V8_OBJECTS_SWISS_NAME_DICTIONARY_INL_H_

"""

```