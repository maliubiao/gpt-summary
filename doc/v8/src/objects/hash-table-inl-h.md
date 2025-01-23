Response:
Let's break down the thought process for analyzing this V8 header file.

**1. Initial Scan and Keyword Spotting:**

My first step is to quickly scan the file for recognizable keywords and patterns. I see:

* `#ifndef`, `#define`, `#include`:  Standard C/C++ header file guards.
* `namespace v8`, `namespace internal`:  Indicates this is part of the V8 JavaScript engine's internal implementation.
* Class names like `EphemeronHashTable`, `HashTableBase`, `HashTable`, `ObjectHashSet`, `NameToIndexHashTable`, `RegisteredSymbolTable`. These are the primary data structures being defined or manipulated.
* Function names like `set_key`, `NumberOfElements`, `Capacity`, `FindEntry`, `Add`, `GetMap`, `IsMatch`, `Hash`. These reveal the common operations performed on hash tables.
* Macros like `DCHECK`, `SLOW_DCHECK`. These are V8's internal debugging/assertion mechanisms.
* Mentions of `Smi` (Small Integer), `Object`, `String`, `Name`, `Map`. These are core V8 object types.
*  Terms like "write barrier," "garbage collection," "heap." These connect the code to memory management within V8.
* The `#include "src/objects/object-macros.h"` and `#include "src/objects/object-macros-undef.h"` pair suggests the use of C++ macros for code generation, likely for defining accessors and mutators for object fields.
* The file name `hash-table-inl.h` strongly suggests this file contains inline implementations related to hash tables. The `.inl` suffix is a common convention for this.

**2. Understanding the Core Purpose:**

Based on the class names and function names, the core purpose is clearly about implementing various types of hash tables within V8. Hash tables are fundamental data structures used for efficient key-value lookups.

**3. Identifying Different Hash Table Types:**

The presence of distinct class names like `EphemeronHashTable`, `NameToIndexHashTable`, `RegisteredSymbolTable`, and `ObjectHashSet` indicates that V8 uses different kinds of hash tables for specific purposes. I'll need to pay attention to the specific characteristics and use cases of each.

**4. Analyzing Key Functionality (by category):**

I'll go through the code section by section, focusing on the core functionalities:

* **Basic Hash Table Operations:** Functions like `NumberOfElements`, `NumberOfDeletedElements`, `Capacity`, `ElementAdded`, `ElementRemoved`, `ElementsRemoved`, and `ComputeCapacity` deal with the fundamental management of a hash table's size and occupancy.

* **Key-Value Manipulation:**  The `set_key` and `KeyAt` functions are crucial for setting and retrieving keys within the hash table. The `WriteBarrier` mentions highlight the interaction with V8's garbage collector. The different overloads of `set_key` (with and without `WriteBarrierMode`) suggest different levels of control over write barrier behavior.

* **Lookup (Finding Entries):**  The `FindEntry` and `FindInsertionEntry` functions are at the heart of hash table functionality. They implement the probing logic to locate existing keys or find suitable slots for new ones. The use of `hash` parameters is expected for hash table lookups.

* **Map Retrieval:** The `GetMap` static methods are about obtaining the "map" object associated with each hash table type. In V8, "maps" describe the structure and type of objects.

* **Key Matching and Hashing:** The `IsMatch` and `Hash` functions (often within `Shape` structs) define how keys are compared for equality and how their hash codes are calculated. The different `Shape` structs correspond to the different hash table types.

* **Specific Hash Table Types:** I need to analyze the unique aspects of each type:
    * **`EphemeronHashTable`**: The `set_key` with write barriers suggests special handling for weak references (ephemerons).
    * **`NameToIndexHashTable`**: The `Add` function explicitly mentions adding names and their associated indices, suggesting it's used for mapping names to numerical indices.
    * **`ObjectHashSet`**: The `Has` function indicates this is used to check for the presence of objects in a set.
    * **`RegisteredSymbolTable`**:  The `IsMatch` compares strings for equality, suggesting it's used to store and look up canonicalized strings (symbols).

* **Internal Details:** The `InternalIndex` and `PtrComprCageBase` are V8's internal mechanisms. I don't need to fully understand their intricacies, but I recognize they are related to memory management and addressing.

**5. Connecting to JavaScript (Conceptual):**

I need to think about how these internal hash tables relate to JavaScript concepts. JavaScript objects are essentially hash maps. Therefore:

* Standard JavaScript objects (`{}`) likely use a general-purpose hash table internally.
* `Map` and `Set` objects in JavaScript have direct correspondences to V8's `NameToIndexHashTable` or `ObjectHashSet`.
* JavaScript symbols are likely managed by the `RegisteredSymbolTable`.

**6. Considering Potential Issues (Common Programming Errors):**

I should consider common errors related to hash tables:

* **Incorrect hashing:** If the `Hash` function is poorly implemented, it can lead to many collisions and slow lookups.
* **Modifying keys:** Changing a key after it has been inserted into a hash table can break the data structure's integrity.
* **Memory leaks (less direct in this context):**  While not directly a programming error *using* the hash table, incorrect management of objects stored *within* the hash table can lead to leaks.

**7. Structure and Refine the Answer:**

Finally, I organize my findings into a clear and structured answer, addressing each part of the prompt:

* **Functionality:** Provide a high-level summary and then break down the functionality by category.
* **Torque:** Check the file extension.
* **JavaScript Relationship:**  Provide concrete JavaScript examples that illustrate the concepts.
* **Code Logic:** Select a key function (like `FindEntry`) and explain its logic with a simple example.
* **Common Errors:**  Provide relevant examples of programming mistakes.

By following this methodical process, combining code analysis with knowledge of hash table concepts and V8's architecture, I can arrive at a comprehensive and accurate understanding of the provided header file.
Let's break down the functionality of `v8/src/objects/hash-table-inl.h`.

**Core Functionality:**

This header file defines inline implementations for various hash table classes used within the V8 JavaScript engine. Hash tables are fundamental data structures for efficient key-value lookups. The key functionalities include:

1. **Basic Hash Table Management:**
   - **Capacity Management:**  Calculating and setting the initial and dynamic capacity of the hash table (`ComputeCapacity`, `SetCapacity`).
   - **Element Tracking:** Keeping track of the number of elements and deleted elements in the hash table (`NumberOfElements`, `NumberOfDeletedElements`, `ElementAdded`, `ElementRemoved`, `ElementsRemoved`).
   - **Iteration:** Providing a way to iterate over the entries in the hash table (`IterateEntries`).

2. **Key-Value Operations:**
   - **Setting Keys:**  Setting the key at a specific index in the hash table, with considerations for write barriers (important for garbage collection) and ephemeron semantics (`set_key`). Ephemeron hash tables have special handling for keys that are only weakly reachable.
   - **Getting Keys:** Retrieving the key at a specific index (`KeyAt`).

3. **Lookup Operations:**
   - **Finding Entries:**  Searching for an existing entry based on a key and its hash (`FindEntry`). This involves probing the hash table using a specific collision resolution strategy.
   - **Finding Insertion Points:** Locating an appropriate empty slot to insert a new key-value pair (`FindInsertionEntry`).

4. **Map Retrieval:**
   - Each specific hash table type (e.g., `NameToIndexHashTable`, `RegisteredSymbolTable`) has a static `GetMap` function that returns the corresponding `Map` object. In V8, `Map` objects describe the structure and type of objects.

5. **Key Matching and Hashing:**
   - Defining how to determine if a given key matches an existing entry (`IsMatch`). This is often specific to the type of keys stored in the hash table.
   - Calculating the hash value for a given key (`Hash`, `HashForObject`).

6. **Specific Hash Table Types (with specialized functionality):**
   - **`EphemeronHashTable`:**  Handles weak references as keys. If the key is only reachable through the ephemeron table, the entry can be collected by the garbage collector.
   - **`NameToIndexHashTable`:**  Used for mapping names (strings or symbols) to numerical indices. The `Add` function is specific to this type.
   - **`ObjectHashSet`:**  Used for storing a set of unique objects. The `Has` function checks if an object is present in the set.
   - **`RegisteredSymbolTable`:**  A global table for canonicalizing strings used as symbols.

**Is it a Torque file?**

No, `v8/src/objects/hash-table-inl.h` ends with `.h`, not `.tq`. Therefore, it's a standard C++ header file containing inline implementations. Torque files (`.tq`) are used for a higher-level language within V8 for code generation.

**Relationship to JavaScript and Examples:**

Hash tables are the underlying data structure for JavaScript objects and the `Map` and `Set` built-in objects.

* **JavaScript Objects:**  When you create a JavaScript object, V8 internally uses a hash table to store the object's properties (key-value pairs).

   ```javascript
   const myObject = { a: 1, b: 'hello', c: true };
   console.log(myObject.b); // Accessing a property involves a hash table lookup.
   ```

* **`Map` Objects:** The JavaScript `Map` object is a direct representation of a hash table (or a similar structure).

   ```javascript
   const myMap = new Map();
   myMap.set('key1', 'value1');
   myMap.set(2, 'value2');
   console.log(myMap.get('key1')); // Accessing a value using a key.
   ```

* **`Set` Objects:** The JavaScript `Set` object internally uses a hash table (or a similar structure) to store unique values.

   ```javascript
   const mySet = new Set();
   mySet.add(1);
   mySet.add('hello');
   console.log(mySet.has(1)); // Checking if a value exists in the set.
   ```

* **Symbols:** JavaScript symbols are often stored and retrieved using a `RegisteredSymbolTable` to ensure uniqueness.

   ```javascript
   const sym1 = Symbol('description');
   const sym2 = Symbol.for('globalSymbol'); // Uses the global symbol registry (likely a hash table).
   console.log(Symbol.keyFor(sym2));
   ```

**Code Logic Reasoning (Example: `FindEntry`):**

Let's analyze the `FindEntry` function for a general `HashTable`:

**Assumptions:**

* We have a `HashTable` instance.
* We want to find an entry with a specific `key`.
* We have the pre-calculated `hash` of the `key`.

**Input:**

* `isolate`:  The V8 isolate (representing a single JavaScript execution environment).
* `roots`: Read-only access to frequently used root objects.
* `key`: The key we're searching for (of type `Key`).
* `hash`: The hash value of the `key`.

**Logic:**

1. **Calculate Initial Probe:**  The `FirstProbe(hash, capacity)` function calculates the initial index to check in the hash table based on the hash value and the table's capacity. This is typically done using a modulo operation or a bitwise AND.
2. **Linear Probing (or similar):** The code enters a loop that continues until the entry is found or determined to be absent.
3. **Check Current Slot:** In each iteration, it examines the element at the current `entry` index (`KeyAt(cage_base, entry)`).
4. **Empty Slot:** If the slot is `undefined`, it means the key is not present in the table, and `InternalIndex::NotFound()` is returned.
5. **Deleted Slot (with Hole Check):** If the slot is `the_hole` (used to mark deleted entries without shifting other elements), and the `TodoShape::kMatchNeedsHoleCheck` is true, it skips this slot and continues probing.
6. **Match Found:** If `TodoShape::IsMatch(key, element)` returns true, it means the key in the current slot matches the search `key`, and the current `entry` index is returned.
7. **Collision Resolution:** If there's no match, `NextProbe(entry, count++, capacity)` calculates the next index to check. This implements a collision resolution strategy (e.g., linear probing, quadratic probing). The `count` variable helps in strategies like quadratic probing.

**Output:**

* `InternalIndex` representing the index of the found entry.
* `InternalIndex::NotFound()` if the key is not found.

**User-Visible Programming Errors (Related to Hash Tables):**

While users don't directly interact with these internal V8 hash tables, understanding their behavior helps understand potential performance issues and the implications of certain JavaScript operations:

1. **Poor Object Key Distribution:** Using objects with poorly distributed hash codes as keys in `Map` or properties in regular objects can lead to many collisions in the underlying hash table, degrading performance (slower lookups and insertions).

   ```javascript
   const map = new Map();
   const poorlyHashedKey1 = { toString: () => 'same' };
   const poorlyHashedKey2 = { toString: () => 'same' };

   map.set(poorlyHashedKey1, 'value1');
   map.set(poorlyHashedKey2, 'value2'); // Likely causes collisions.
   ```

2. **Excessive Property Deletion and Addition:** Repeatedly deleting and adding properties to JavaScript objects can lead to fragmentation in the underlying hash table (creation of "holes"), potentially impacting performance until the engine optimizes the object's representation.

   ```javascript
   const obj = {};
   for (let i = 0; i < 1000; i++) {
     obj[i] = i;
   }
   for (let i = 0; i < 500; i++) {
     delete obj[i];
   }
   for (let i = 1000; i < 1500; i++) {
     obj[i] = i;
   } // This kind of churn can impact performance.
   ```

3. **Relying on Property Order (in older JavaScript engines or without guaranteed order):**  While modern JavaScript engines generally preserve the insertion order of object properties, relying on this behavior in all situations (especially when iterating) can be problematic if the underlying hash table implementation changes or if you're working with older environments. `Map` objects provide a guaranteed ordered collection.

**In summary, `v8/src/objects/hash-table-inl.h` is a crucial file defining the low-level mechanisms for managing hash tables within the V8 engine. These hash tables are fundamental to the implementation of JavaScript objects, `Map`, `Set`, and symbols, and understanding their workings can provide insights into JavaScript performance and behavior.**

### 提示词
```
这是目录为v8/src/objects/hash-table-inl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/hash-table-inl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```c
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_OBJECTS_HASH_TABLE_INL_H_
#define V8_OBJECTS_HASH_TABLE_INL_H_

#include "src/execution/isolate-utils-inl.h"
#include "src/heap/heap.h"
#include "src/objects/fixed-array-inl.h"
#include "src/objects/hash-table.h"
#include "src/objects/heap-object-inl.h"
#include "src/objects/objects-inl.h"
#include "src/roots/roots-inl.h"

// Has to be the last include (doesn't have include guards):
#include "src/objects/object-macros.h"

namespace v8 {
namespace internal {

void EphemeronHashTable::set_key(int index, Tagged<Object> value) {
  DCHECK_NE(GetReadOnlyRoots().fixed_cow_array_map(), map());
  DCHECK(IsEphemeronHashTable(this));
  DCHECK_GE(index, 0);
  DCHECK_LT(index, this->length());
  objects()[index].Relaxed_Store_no_write_barrier(value);
#ifndef V8_DISABLE_WRITE_BARRIERS
  DCHECK(HeapLayout::IsOwnedByAnyHeap(this));
  WriteBarrier::ForEphemeronHashTable(
      Tagged(this), ObjectSlot(&objects()[index]), value, UPDATE_WRITE_BARRIER);
#endif
}

void EphemeronHashTable::set_key(int index, Tagged<Object> value,
                                 WriteBarrierMode mode) {
  DCHECK_NE(GetReadOnlyRoots().fixed_cow_array_map(), map());
  DCHECK(IsEphemeronHashTable(this));
  DCHECK_GE(index, 0);
  DCHECK_LT(index, this->length());
  objects()[index].Relaxed_Store_no_write_barrier(value);
#ifndef V8_DISABLE_WRITE_BARRIERS
#if V8_ENABLE_UNCONDITIONAL_WRITE_BARRIERS
  mode = UPDATE_WRITE_BARRIER;
#endif
  DCHECK(HeapLayout::IsOwnedByAnyHeap(this));
  WriteBarrier::ForEphemeronHashTable(
      Tagged(this), ObjectSlot(&objects()[index]), value, mode);
#endif
}

int HashTableBase::NumberOfElements() const {
  return Cast<Smi>(get(kNumberOfElementsIndex)).value();
}

int HashTableBase::NumberOfDeletedElements() const {
  return Cast<Smi>(get(kNumberOfDeletedElementsIndex)).value();
}

int HashTableBase::Capacity() const {
  return Cast<Smi>(get(kCapacityIndex)).value();
}

InternalIndex::Range HashTableBase::IterateEntries() const {
  return InternalIndex::Range(Capacity());
}

void HashTableBase::ElementAdded() {
  SetNumberOfElements(NumberOfElements() + 1);
}

void HashTableBase::ElementRemoved() {
  SetNumberOfElements(NumberOfElements() - 1);
  SetNumberOfDeletedElements(NumberOfDeletedElements() + 1);
}

void HashTableBase::ElementsRemoved(int n) {
  SetNumberOfElements(NumberOfElements() - n);
  SetNumberOfDeletedElements(NumberOfDeletedElements() + n);
}

// static
int HashTableBase::ComputeCapacity(int at_least_space_for) {
  // Add 50% slack to make slot collisions sufficiently unlikely.
  // See matching computation in HashTable::HasSufficientCapacityToAdd().
  // Must be kept in sync with CodeStubAssembler::HashTableComputeCapacity().
  int raw_cap = at_least_space_for + (at_least_space_for >> 1);
  int capacity = base::bits::RoundUpToPowerOfTwo32(raw_cap);
  return std::max({capacity, kMinCapacity});
}

void HashTableBase::SetInitialNumberOfElements(int nof) {
  DCHECK_EQ(NumberOfElements(), 0);
  set(kNumberOfElementsIndex, Smi::FromInt(nof));
}

void HashTableBase::SetNumberOfElements(int nof) {
  set(kNumberOfElementsIndex, Smi::FromInt(nof));
}

void HashTableBase::SetNumberOfDeletedElements(int nod) {
  set(kNumberOfDeletedElementsIndex, Smi::FromInt(nod));
}

// static
template <typename Derived, typename Shape>
Handle<Map> HashTable<Derived, Shape>::GetMap(ReadOnlyRoots roots) {
  return roots.hash_table_map_handle();
}

// static
Handle<Map> NameToIndexHashTable::GetMap(ReadOnlyRoots roots) {
  return roots.name_to_index_hash_table_map_handle();
}

// static
Handle<Map> RegisteredSymbolTable::GetMap(ReadOnlyRoots roots) {
  return roots.registered_symbol_table_map_handle();
}

// static
Handle<Map> EphemeronHashTable::GetMap(ReadOnlyRoots roots) {
  return roots.ephemeron_hash_table_map_handle();
}

template <typename Derived, typename Shape>
template <typename IsolateT>
InternalIndex HashTable<Derived, Shape>::FindEntry(IsolateT* isolate, Key key) {
  ReadOnlyRoots roots(isolate);
  return FindEntry(isolate, roots, key, TodoShape::Hash(roots, key));
}

// Find entry for key otherwise return kNotFound.
template <typename Derived, typename Shape>
InternalIndex HashTable<Derived, Shape>::FindEntry(PtrComprCageBase cage_base,
                                                   ReadOnlyRoots roots, Key key,
                                                   int32_t hash) {
  DisallowGarbageCollection no_gc;
  uint32_t capacity = Capacity();
  uint32_t count = 1;
  Tagged<Object> undefined = roots.undefined_value();
  Tagged<Object> the_hole = roots.the_hole_value();
  DCHECK_EQ(TodoShape::Hash(roots, key), static_cast<uint32_t>(hash));
  // EnsureCapacity will guarantee the hash table is never full.
  for (InternalIndex entry = FirstProbe(hash, capacity);;
       entry = NextProbe(entry, count++, capacity)) {
    Tagged<Object> element = KeyAt(cage_base, entry);
    // Empty entry. Uses raw unchecked accessors because it is called by the
    // string table during bootstrapping.
    if (element == undefined) return InternalIndex::NotFound();
    if (TodoShape::kMatchNeedsHoleCheck && element == the_hole) continue;
    if (TodoShape::IsMatch(key, element)) return entry;
  }
}

template <typename Derived, typename Shape>
template <typename IsolateT>
InternalIndex HashTable<Derived, Shape>::FindInsertionEntry(IsolateT* isolate,
                                                            uint32_t hash) {
  return FindInsertionEntry(isolate, ReadOnlyRoots(isolate), hash);
}

// static
template <typename Derived, typename Shape>
bool HashTable<Derived, Shape>::IsKey(ReadOnlyRoots roots, Tagged<Object> k) {
  // TODO(leszeks): Dictionaries that don't delete could skip the hole check.
  return k != roots.unchecked_undefined_value() &&
         k != roots.unchecked_the_hole_value();
}

template <typename Derived, typename Shape>
bool HashTable<Derived, Shape>::ToKey(ReadOnlyRoots roots, InternalIndex entry,
                                      Tagged<Object>* out_k) {
  Tagged<Object> k = KeyAt(entry);
  if (!IsKey(roots, k)) return false;
  *out_k = TodoShape::Unwrap(k);
  return true;
}

template <typename Derived, typename Shape>
bool HashTable<Derived, Shape>::ToKey(PtrComprCageBase cage_base,
                                      InternalIndex entry,
                                      Tagged<Object>* out_k) {
  Tagged<Object> k = KeyAt(cage_base, entry);
  if (!IsKey(GetReadOnlyRoots(), k)) return false;
  *out_k = TodoShape::Unwrap(k);
  return true;
}

template <typename Derived, typename Shape>
Tagged<Object> HashTable<Derived, Shape>::KeyAt(InternalIndex entry) {
  PtrComprCageBase cage_base = GetPtrComprCageBase();
  return KeyAt(cage_base, entry);
}

template <typename Derived, typename Shape>
Tagged<Object> HashTable<Derived, Shape>::KeyAt(PtrComprCageBase cage_base,
                                                InternalIndex entry) {
  return get(EntryToIndex(entry) + kEntryKeyIndex);
}

template <typename Derived, typename Shape>
Tagged<Object> HashTable<Derived, Shape>::KeyAt(InternalIndex entry,
                                                RelaxedLoadTag tag) {
  PtrComprCageBase cage_base = GetPtrComprCageBase();
  return KeyAt(cage_base, entry, tag);
}

template <typename Derived, typename Shape>
Tagged<Object> HashTable<Derived, Shape>::KeyAt(PtrComprCageBase cage_base,
                                                InternalIndex entry,
                                                RelaxedLoadTag tag) {
  return get(EntryToIndex(entry) + kEntryKeyIndex, tag);
}

template <typename Derived, typename Shape>
void HashTable<Derived, Shape>::SetKeyAt(InternalIndex entry,
                                         Tagged<Object> value,
                                         WriteBarrierMode mode) {
  set_key(EntryToIndex(entry), value, mode);
}

template <typename Derived, typename Shape>
void HashTable<Derived, Shape>::set_key(int index, Tagged<Object> value) {
  DCHECK(!IsEphemeronHashTable(this));
  FixedArray::set(index, value);
}

template <typename Derived, typename Shape>
void HashTable<Derived, Shape>::set_key(int index, Tagged<Object> value,
                                        WriteBarrierMode mode) {
  DCHECK(!IsEphemeronHashTable(this));
  FixedArray::set(index, value, mode);
}

template <typename Derived, typename Shape>
void HashTable<Derived, Shape>::SetCapacity(int capacity) {
  // To scale a computed hash code to fit within the hash table, we
  // use bit-wise AND with a mask, so the capacity must be positive
  // and non-zero.
  DCHECK_GT(capacity, 0);
  DCHECK_LE(capacity, kMaxCapacity);
  set(kCapacityIndex, Smi::FromInt(capacity));
}

bool ObjectHashSet::Has(Isolate* isolate, Handle<Object> key, int32_t hash) {
  return FindEntry(isolate, ReadOnlyRoots(isolate), key, hash).is_found();
}

bool ObjectHashSet::Has(Isolate* isolate, Handle<Object> key) {
  Tagged<Object> hash = Object::GetHash(*key);
  if (!IsSmi(hash)) return false;
  return FindEntry(isolate, ReadOnlyRoots(isolate), key, Smi::ToInt(hash))
      .is_found();
}

bool ObjectHashTableShape::IsMatch(DirectHandle<Object> key,
                                   Tagged<Object> other) {
  return Object::SameValue(*key, other);
}

bool RegisteredSymbolTableShape::IsMatch(DirectHandle<String> key,
                                         Tagged<Object> value) {
  DCHECK(IsString(value));
  return key->Equals(Cast<String>(value));
}

uint32_t RegisteredSymbolTableShape::Hash(ReadOnlyRoots roots,
                                          DirectHandle<String> key) {
  return key->EnsureHash();
}

uint32_t RegisteredSymbolTableShape::HashForObject(ReadOnlyRoots roots,
                                                   Tagged<Object> object) {
  return Cast<String>(object)->EnsureHash();
}

bool NameToIndexShape::IsMatch(DirectHandle<Name> key, Tagged<Object> other) {
  return *key == other;
}

uint32_t NameToIndexShape::HashForObject(ReadOnlyRoots roots,
                                         Tagged<Object> other) {
  return Cast<Name>(other)->hash();
}

uint32_t NameToIndexShape::Hash(ReadOnlyRoots roots, DirectHandle<Name> key) {
  return key->hash();
}

uint32_t ObjectHashTableShape::Hash(ReadOnlyRoots roots,
                                    DirectHandle<Object> key) {
  return Smi::ToInt(Object::GetHash(*key));
}

uint32_t ObjectHashTableShape::HashForObject(ReadOnlyRoots roots,
                                             Tagged<Object> other) {
  return Smi::ToInt(Object::GetHash(other));
}

template <typename IsolateT>
Handle<NameToIndexHashTable> NameToIndexHashTable::Add(
    IsolateT* isolate, Handle<NameToIndexHashTable> table,
    IndirectHandle<Name> key, int32_t index) {
  DCHECK_GE(index, 0);
  // Validate that the key is absent.
  SLOW_DCHECK(table->FindEntry(isolate, key).is_not_found());
  // Check whether the dictionary should be extended.
  table = EnsureCapacity(isolate, table);
  DisallowGarbageCollection no_gc;
  Tagged<NameToIndexHashTable> raw_table = *table;
  // Compute the key object.
  InternalIndex entry = raw_table->FindInsertionEntry(isolate, key->hash());
  raw_table->set(EntryToIndex(entry), *key);
  raw_table->set(EntryToValueIndex(entry), Smi::FromInt(index));
  raw_table->ElementAdded();
  return table;
}

}  // namespace internal
}  // namespace v8

#include "src/objects/object-macros-undef.h"

#endif  // V8_OBJECTS_HASH_TABLE_INL_H_
```