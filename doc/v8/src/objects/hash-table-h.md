Response:
Let's break down the thought process to analyze the provided C++ header file (`hash-table.h`) from V8.

1. **Initial Scan and Purpose Identification:**  The first step is to quickly scan the file for keywords and structural elements. I see `#ifndef`, `#define`, `#include`, `namespace v8`, `namespace internal`, `class`, `template`, and comments. The filename `hash-table.h` itself is a strong clue. The initial comments confirm this: "HashTable is a subclass of FixedArray that implements a hash table...". This immediately tells us the core purpose of this file.

2. **Key Data Structures and Concepts:** I look for the central data structures being defined. `HashTable`, `HashTableBase`, and various `*Shape` classes stand out. The comments about "open addressing and quadratic probing" are important algorithmic details. The mention of `FixedArray` indicates the underlying storage mechanism.

3. **Understanding the `Shape` Concept:**  The comments explicitly explain the role of the `Shape` template parameter. It defines the interface for how keys are handled (matching, hashing, conversion to objects) and provides size information. This is a key design pattern for making the hash table generic. I note the members of the `Shape` interface.

4. **Dissecting `HashTableBase`:** This class seems to handle the basic metadata and operations common to all hash tables. I look for its public methods: `NumberOfElements`, `NumberOfDeletedElements`, `Capacity`, and the static `ComputeCapacity`. These are fundamental operations for managing a hash table. The protected members like `SetNumberOfElements` and the probing functions (`FirstProbe`, `NextProbe`) hint at the internal implementation.

5. **Analyzing the `HashTable` Template:** This is the main hash table class. I see the template parameters `Derived` and `ShapeT`. The `Derived` parameter suggests a CRTP (Curiously Recurring Template Pattern) being used for polymorphism or to provide derived-class specific functionality. The public methods like `New`, `FindEntry`, `Rehash`, `IsKey`, `KeyAt`, `SetKeyAt`, and `EnsureCapacity` are the core API for interacting with the hash table. The static constants like `kElementsStartIndex`, `kEntrySize`, and `kMaxCapacity` define important implementation limits. The protected `FindInsertionEntry` and `Shrink` methods reveal internal management logic.

6. **Exploring Concrete Hash Table Implementations:** I notice subclasses like `ObjectHashTable`, `EphemeronHashTable`, `ObjectHashSet`, `NameToIndexHashTable`, and `RegisteredSymbolTable`. These represent specific uses of the generic `HashTable` with different key and value types. I pay attention to any specific behavior or data associated with them (e.g., `EphemeronHashTable`'s GC implications).

7. **Identifying Potential JavaScript Relevance:**  Hash tables are fundamental data structures in JavaScript. Objects in JavaScript are essentially hash maps. I connect the concepts: JavaScript objects use string (or symbol) keys to access values, which maps directly to the key-value pair functionality of a hash table. The concept of "the hole" and `undefined` as special values resonates with JavaScript's handling of missing or deleted properties.

8. **Considering Torque (.tq) Source:**  The prompt asks about `.tq` files. I recall that Torque is V8's domain-specific language for implementing built-in functions and runtime components. If this file *were* a `.tq` file, it would likely contain the *implementation* details of the hash table operations, potentially optimized for performance. However, since it's a `.h` file, it's primarily the *declaration* and interface.

9. **Thinking about Common Programming Errors:**  Given the nature of hash tables, I consider common issues:
    * **Hash Collisions:**  While the code uses quadratic probing to mitigate this, poor hash functions can lead to performance degradation.
    * **Incorrect Key Comparisons:**  The `IsMatch` function in the `Shape` is crucial. Incorrect implementation here would lead to lookup failures.
    * **Capacity Management:**  Not handling resizing correctly can lead to performance problems (too many rehashes) or memory issues.
    * **Using the wrong kind of hash table:**  Choosing `ObjectHashTable` when identity-based keys are needed vs. `NameToIndexHashTable` for string-based lookups.

10. **Structuring the Output:** Finally, I organize the findings into the requested categories: functionality, Torque relevance, JavaScript examples, code logic (with hypothetical input/output), and common errors. I use clear and concise language, drawing direct connections between the C++ code and the higher-level concepts. For JavaScript examples, I focus on illustrating the core hash table operations. For hypothetical input/output, I select a simple `FindEntry` scenario.

This step-by-step approach, combining code analysis, domain knowledge (hash tables, V8 internals, JavaScript), and logical reasoning, allows for a comprehensive understanding of the provided header file.
This is a C++ header file (`.h`) defining the implementation of hash tables within the V8 JavaScript engine. Let's break down its functionality:

**Core Functionality of `v8/src/objects/hash-table.h`:**

This header file defines the fundamental building blocks for various hash table implementations used within V8. Hash tables are essential for efficient key-value lookups, and V8 utilizes them extensively for:

* **JavaScript Objects:**  Storing properties of JavaScript objects.
* **Maps and Sets:** Implementing the `Map` and `Set` data structures in JavaScript.
* **Symbol Tables:**  Managing symbols within the JavaScript runtime.
* **Internal Caches and Lookups:**  Various internal optimizations and data management within the engine.

**Key Components and Concepts:**

1. **`HashTableBase`:**
   - Provides the basic structure and metadata for all hash tables.
   - Stores the number of elements, number of deleted elements, and the capacity of the table.
   - Defines methods for updating these counters (`ElementAdded`, `ElementRemoved`).
   - Implements the core probing logic (`FirstProbe`, `NextProbe`) using open addressing and quadratic probing to handle collisions.

2. **`HashTable<Derived, ShapeT>`:**
   - A template class that provides the core hash table functionality, parameterized by:
     - `Derived`: The specific type of hash table inheriting from this template (e.g., `ObjectHashTable`, `NameToIndexHashTable`). This is likely using the Curiously Recurring Template Pattern (CRTP).
     - `ShapeT`: A class defining the specific characteristics of the keys and values stored in the hash table. This includes:
       - How to compare keys (`IsMatch`).
       - How to hash keys (`Hash`).
       - How to hash existing objects (`HashForObject`).
       - How to convert a key to a handle (`AsHandle`).
       - The size of the prefix (non-element data) and each entry in the underlying storage.
   - Offers methods for:
     - Creating new hash tables (`New`).
     - Finding entries based on keys (`FindEntry`).
     - Rehashing the table to resize it (`Rehash`).
     - Checking if a value is a valid key (`IsKey`).
     - Getting and setting keys at specific entries (`KeyAt`, `SetKeyAt`).
     - Ensuring sufficient capacity (`EnsureCapacity`).
     - Shrinking the table (`Shrink`).

3. **`Shape` Classes (e.g., `ObjectHashTableShape`, `NameToIndexShape`):**
   - Define the specific behavior and layout for different types of hash tables.
   - Specify how keys are compared and hashed for that particular hash table use case.
   - Determine the `kPrefixSize` and `kEntrySize` based on the data being stored.

4. **Specific Hash Table Implementations:**
   - **`ObjectHashTable`:**  Maps arbitrary JavaScript objects to other JavaScript objects. Uses identity-based hashing for keys.
   - **`EphemeronHashTable`:** Similar to `ObjectHashTable` but used for weak references. The garbage collector treats its entries specially.
   - **`ObjectHashSet`:**  Stores a set of unique JavaScript objects.
   - **`NameToIndexHashTable`:** Maps JavaScript `Name` objects (strings and symbols) to indices. This is used for fast property lookup in objects.
   - **`RegisteredSymbolTable`:**  Stores globally registered symbols.
   - **`ObjectMultiHashTableBase`:** A template for hash tables that map to multiple values.

**If `v8/src/objects/hash-table.h` ended with `.tq`:**

If the file ended with `.tq`, it would be a **V8 Torque source file**. Torque is a domain-specific language used within V8 for implementing built-in functions and runtime components. A `.tq` version of this file would contain the actual *implementation* logic for the hash table operations (like insertion, deletion, lookup) written in Torque, which then gets compiled into C++ code.

**Relationship to JavaScript Functionality (with examples):**

Hash tables are the underlying mechanism for JavaScript objects.

**JavaScript Example:**

```javascript
const myObject = {
  name: "Alice",
  age: 30,
  city: "Wonderland"
};

console.log(myObject.name); // Accessing a property

myObject.occupation = "Magician"; // Adding a new property

delete myObject.age; // Removing a property
```

**Explanation:**

- When you create a JavaScript object like `myObject`, V8 internally uses a hash table (likely an `ObjectHashTable` or a similar structure) to store the properties (`name`, `age`, `city`, `occupation`) and their corresponding values.
- Accessing a property (`myObject.name`) involves looking up the key `"name"` in the object's internal hash table.
- Adding a new property involves inserting the key-value pair into the hash table.
- Deleting a property removes the entry from the hash table, potentially marking it as "deleted" (the "the_hole" concept mentioned in the comments).

**Code Logic Reasoning (Hypothetical Input and Output):**

Let's consider the `FindEntry` function. Assume we have an `ObjectHashTable` and we're trying to find an entry for the key `"name"` with a pre-calculated hash value.

**Hypothetical Input:**

- `table`: An `ObjectHashTable` instance.
- `roots`: Read-only access to V8's root objects.
- `key`: A JavaScript string object representing `"name"`.
- `hash`: The hash value of the `"name"` string.

**Code Logic Flow (simplified):**

1. The `FindEntry` function would calculate the initial probe index using the hash value and the table's size.
2. It would check the entry at that index:
   - If the entry is unused (`key == undefined`), the key is not found.
   - If the entry's key matches the input `key` (using `ObjectHashTableShape::IsMatch`), the entry is found, and its `InternalIndex` is returned.
   - If the entry's key is different, quadratic probing is used to calculate the next probe index.
   - This process continues until a match is found or an unused entry is encountered.
   - Deleted entries (`key == the_hole`) are skipped during probing.

**Hypothetical Output:**

- If the `"name"` property exists in the `table`, `FindEntry` would return the `InternalIndex` of the entry where `"name"` is stored.
- If the `"name"` property does not exist, `FindEntry` would return a special value indicating "not found" (likely a specific enum value like `kNotFound`).

**Common Programming Errors (from a V8 developer's perspective):**

While end-users don't directly interact with this C++ code, errors in its design or implementation could lead to issues in JavaScript execution. Here are some potential areas for errors:

1. **Incorrect `Shape` Implementation:**
   - **Flawed `IsMatch`:** If the `IsMatch` function in a `Shape` class doesn't correctly compare keys, lookups will fail, and the hash table will behave incorrectly. For example, if `ObjectHashTableShape::IsMatch` didn't perform identity comparison for objects, distinct but structurally identical objects might be treated as the same key.
   - **Bad `Hash` Function:** A poorly designed hash function in a `Shape` can lead to excessive hash collisions, degrading the performance of hash table operations.

2. **Capacity Management Issues:**
   - **Incorrect Resizing Logic:** If the `Rehash` function doesn't correctly resize the table, it could lead to memory leaks or crashes.
   - **Inefficient Resizing Strategy:**  Resizing too often or by too small an increment can negatively impact performance.

3. **Concurrency Issues (though not explicitly shown in this header):**
   - If multiple threads access and modify hash tables without proper synchronization, it can lead to data corruption. V8 has mechanisms to handle concurrency, but errors in hash table implementation could create vulnerabilities.

4. **Memory Management Errors:**
   - Failing to properly handle memory allocation and deallocation for the underlying `FixedArray` could lead to memory leaks.

**Example of a User-Facing Programming Error (related to hash tables conceptually):**

```javascript
const obj1 = { value: 1 };
const obj2 = { value: 1 };

const myMap = new Map();
myMap.set(obj1, "First Object");
myMap.set(obj2, "Second Object");

console.log(myMap.get(obj1)); // Output: "First Object"
console.log(myMap.get(obj2)); // Output: "Second Object"
```

**Explanation:**

- JavaScript `Map` uses a hash table internally.
- In this example, `obj1` and `obj2` are distinct objects, even though they have the same structure.
- `Map` uses **identity-based comparison** for object keys. Therefore, `myMap.set(obj1, ...)` and `myMap.set(obj2, ...)` create two separate entries in the map's internal hash table.
- A common mistake is to assume that `myMap.get({ value: 1 })` would retrieve either "First Object" or "Second Object". However, `{ value: 1 }` creates a *new* object instance, which has a different identity than `obj1` and `obj2`, resulting in `myMap.get({ value: 1 })` returning `undefined`.

In summary, `v8/src/objects/hash-table.h` is a crucial header file in V8, defining the core logic and structure for various hash table implementations that are fundamental to the engine's functionality and the execution of JavaScript code.

### 提示词
```
这是目录为v8/src/objects/hash-table.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/hash-table.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```c
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_OBJECTS_HASH_TABLE_H_
#define V8_OBJECTS_HASH_TABLE_H_

#include "src/base/compiler-specific.h"
#include "src/base/export-template.h"
#include "src/base/macros.h"
#include "src/common/globals.h"
#include "src/execution/isolate-utils.h"
#include "src/objects/fixed-array.h"
#include "src/objects/property-array.h"
#include "src/objects/smi.h"
#include "src/objects/tagged-field.h"
#include "src/roots/roots.h"

// Has to be the last include (doesn't have include guards):
#include "src/objects/object-macros.h"

namespace v8 {
namespace internal {

// HashTable is a subclass of FixedArray that implements a hash table
// that uses open addressing and quadratic probing.
//
// In order for the quadratic probing to work, elements that have not
// yet been used and elements that have been deleted are
// distinguished.  Probing continues when deleted elements are
// encountered and stops when unused elements are encountered.
//
// - Elements with key == undefined have not been used yet.
// - Elements with key == the_hole have been deleted.
//
// The hash table class is parameterized with a Shape.
// Shape must be a class with the following interface:
//   class ExampleShape {
//    public:
//     // Tells whether key matches other.
//     static bool IsMatch(Key key, Tagged<Object> other);
//     // Returns the hash value for key.
//     static uint32_t Hash(ReadOnlyRoots roots, Key key);
//     // Returns the hash value for object.
//     static uint32_t HashForObject(ReadOnlyRoots roots,
//                                   Tagged<Object> object);
//     // Convert key to an object.
//     static inline Handle<Object> AsHandle(Isolate* isolate, Key key);
//     // The prefix size indicates number of elements in the beginning
//     // of the backing storage.
//     static const int kPrefixSize = ..;
//     // The Element size indicates number of elements per entry.
//     static const int kEntrySize = ..;
//     // Indicates whether IsMatch can deal with other being the_hole (a
//     // deleted entry).
//     static const bool kMatchNeedsHoleCheck = ..;
//   };
// The prefix size indicates an amount of memory in the
// beginning of the backing storage that can be used for non-element
// information by subclasses.

template <typename KeyT>
class V8_EXPORT_PRIVATE BaseShape {
 public:
  using Key = KeyT;
  static Tagged<Object> Unwrap(Tagged<Object> key) { return key; }
};

class V8_EXPORT_PRIVATE HashTableBase : public NON_EXPORTED_BASE(FixedArray) {
 public:
  // Returns the number of elements in the hash table.
  inline int NumberOfElements() const;

  // Returns the number of deleted elements in the hash table.
  inline int NumberOfDeletedElements() const;

  // Returns the capacity of the hash table.
  inline int Capacity() const;

  inline InternalIndex::Range IterateEntries() const;

  // ElementAdded should be called whenever an element is added to a
  // hash table.
  inline void ElementAdded();

  // ElementRemoved should be called whenever an element is removed from
  // a hash table.
  inline void ElementRemoved();
  inline void ElementsRemoved(int n);

  // Computes the required capacity for a table holding the given
  // number of elements. May be more than HashTable::kMaxCapacity.
  static inline int ComputeCapacity(int at_least_space_for);

  static const int kNumberOfElementsIndex = 0;
  static const int kNumberOfDeletedElementsIndex = 1;
  static const int kCapacityIndex = 2;
  static const int kPrefixStartIndex = 3;

  // Minimum capacity for newly created hash tables.
  static const int kMinCapacity = 4;

  // Set the number of elements in the hash table after a bulk of elements was
  // added.
  inline void SetInitialNumberOfElements(int nof);

 protected:
  // Update the number of elements in the hash table.
  inline void SetNumberOfElements(int nof);

  // Update the number of deleted elements in the hash table.
  inline void SetNumberOfDeletedElements(int nod);

  // Returns probe entry.
  inline static InternalIndex FirstProbe(uint32_t hash, uint32_t size) {
    if (size <= (1 << PropertyArray::HashField::kSize)) {
      return InternalIndex(hash & (size - 1));
    }
    // The hash stored in JSReceiver (see PropertyArray::HashField) only has 20
    // bits. This is suboptimal, if the hash table size is larger than 1 << 20.
    // This distributes the probes more evenly even in that case.
    return InternalIndex((hash * (size >> PropertyArray::HashField::kSize)) &
                         (size - 1));
  }

  inline static InternalIndex NextProbe(InternalIndex last, uint32_t number,
                                        uint32_t size) {
    return InternalIndex((last.as_uint32() + number) & (size - 1));
  }
};

template <typename Derived, typename ShapeT>
class EXPORT_TEMPLATE_DECLARE(V8_EXPORT_PRIVATE) HashTable
    : public HashTableBase {
 public:
  // TODO(jgruber): Derive from TaggedArrayBase instead of FixedArray, and
  // merge with TaggedArraryBase's Shape class. Once the naming conflict is
  // resolved rename all TodoShape occurrences back to Shape.
  using TodoShape = ShapeT;
  using Key = typename TodoShape::Key;

  // Returns a new HashTable object.
  template <typename IsolateT>
  V8_WARN_UNUSED_RESULT static Handle<Derived> New(
      IsolateT* isolate, int at_least_space_for,
      AllocationType allocation = AllocationType::kYoung,
      MinimumCapacity capacity_option = USE_DEFAULT_MINIMUM_CAPACITY);

  static inline Handle<Map> GetMap(ReadOnlyRoots roots);

  // Garbage collection support.
  void IteratePrefix(ObjectVisitor* visitor);
  void IterateElements(ObjectVisitor* visitor);

  // Find entry for key otherwise return kNotFound.
  inline InternalIndex FindEntry(PtrComprCageBase cage_base,
                                 ReadOnlyRoots roots, Key key, int32_t hash);
  template <typename IsolateT>
  inline InternalIndex FindEntry(IsolateT* isolate, Key key);

  // Rehashes the table in-place.
  void Rehash(PtrComprCageBase cage_base);

  // Returns whether k is a real key.  The hole and undefined are not allowed as
  // keys and can be used to indicate missing or deleted elements.
  static inline bool IsKey(ReadOnlyRoots roots, Tagged<Object> k);

  inline bool ToKey(ReadOnlyRoots roots, InternalIndex entry,
                    Tagged<Object>* out_k);
  inline bool ToKey(PtrComprCageBase cage_base, InternalIndex entry,
                    Tagged<Object>* out_k);

  // Returns the key at entry.
  inline Tagged<Object> KeyAt(InternalIndex entry);
  inline Tagged<Object> KeyAt(PtrComprCageBase cage_base, InternalIndex entry);
  inline Tagged<Object> KeyAt(InternalIndex entry, RelaxedLoadTag tag);
  inline Tagged<Object> KeyAt(PtrComprCageBase cage_base, InternalIndex entry,
                              RelaxedLoadTag tag);

  inline void SetKeyAt(InternalIndex entry, Tagged<Object> value,
                       WriteBarrierMode mode = UPDATE_WRITE_BARRIER);

  static const int kElementsStartIndex =
      kPrefixStartIndex + TodoShape::kPrefixSize;
  static const int kEntrySize = TodoShape::kEntrySize;
  static_assert(kEntrySize > 0);
  static const int kEntryKeyIndex = 0;
  static const int kElementsStartOffset =
      OFFSET_OF_DATA_START(HashTableBase) + kElementsStartIndex * kTaggedSize;
  // Maximal capacity of HashTable. Based on maximal length of underlying
  // FixedArray. Staying below kMaxCapacity also ensures that EntryToIndex
  // cannot overflow.
  static const int kMaxCapacity =
      (FixedArray::kMaxLength - kElementsStartIndex) / kEntrySize;

  // Don't shrink a HashTable below this capacity.
  static const int kMinShrinkCapacity = 16;

  // Pretenure hashtables above this capacity.
  static const int kMinCapacityForPretenure = 256;

  static const int kMaxRegularCapacity = kMaxRegularHeapObjectSize / 32;

  // Returns the index for an entry (of the key)
  static constexpr inline int EntryToIndex(InternalIndex entry) {
    return (entry.as_int() * kEntrySize) + kElementsStartIndex;
  }

  // Returns the entry for an index (of the key)
  static constexpr inline InternalIndex IndexToEntry(int index) {
    return InternalIndex((index - kElementsStartIndex) / kEntrySize);
  }

  // Returns the index for a slot address in the object.
  static constexpr inline int SlotToIndex(Address object, Address slot) {
    return static_cast<int>((slot - object - sizeof(HashTableBase)) /
                            kTaggedSize);
  }

  // Ensure enough space for n additional elements.
  template <typename IsolateT>
  V8_WARN_UNUSED_RESULT static Handle<Derived> EnsureCapacity(
      IsolateT* isolate, Handle<Derived> table, int n = 1,
      AllocationType allocation = AllocationType::kYoung);

  // Returns true if this table has sufficient capacity for adding n elements.
  bool HasSufficientCapacityToAdd(int number_of_additional_elements);

  // Returns true if a table with the given parameters has sufficient capacity
  // for adding n elements. Can be used to check hypothetical capacities without
  // actually allocating a table with that capacity.
  static bool HasSufficientCapacityToAdd(int capacity, int number_of_elements,
                                         int number_of_deleted_elements,
                                         int number_of_additional_elements);

 protected:
  friend class ObjectHashTable;

  template <typename IsolateT>
  V8_WARN_UNUSED_RESULT static Handle<Derived> NewInternal(
      IsolateT* isolate, int capacity, AllocationType allocation);

  // Find the entry at which to insert element with the given key that
  // has the given hash value.
  InternalIndex FindInsertionEntry(PtrComprCageBase cage_base,
                                   ReadOnlyRoots roots, uint32_t hash);
  template <typename IsolateT>
  InternalIndex FindInsertionEntry(IsolateT* isolate, uint32_t hash);

  // Computes the capacity a table with the given capacity would need to have
  // room for the given number of elements, also allowing it to shrink.
  static int ComputeCapacityWithShrink(int current_capacity,
                                       int at_least_room_for);

  // Shrink the hash table.
  V8_WARN_UNUSED_RESULT static Handle<Derived> Shrink(
      Isolate* isolate, Handle<Derived> table, int additionalCapacity = 0);

  // Rehashes this hash-table into the new table.
  void Rehash(PtrComprCageBase cage_base, Tagged<Derived> new_table);

  inline void set_key(int index, Tagged<Object> value);
  inline void set_key(int index, Tagged<Object> value, WriteBarrierMode mode);

 private:
  // Ensure that kMaxRegularCapacity yields a non-large object dictionary.
  static_assert(EntryToIndex(InternalIndex(kMaxRegularCapacity)) <
                FixedArray::kMaxRegularLength);
  static_assert(v8::base::bits::IsPowerOfTwo(kMaxRegularCapacity));
  static const int kMaxRegularEntry = kMaxRegularCapacity / kEntrySize;
  static const int kMaxRegularIndex =
      EntryToIndex(InternalIndex(kMaxRegularEntry));
  static_assert(OffsetOfElementAt(kMaxRegularIndex) <
                kMaxRegularHeapObjectSize);

  // Sets the capacity of the hash table.
  inline void SetCapacity(int capacity);

  // Returns _expected_ if one of entries given by the first _probe_ probes is
  // equal to  _expected_. Otherwise, returns the entry given by the probe
  // number _probe_.
  InternalIndex EntryForProbe(ReadOnlyRoots roots, Tagged<Object> k, int probe,
                              InternalIndex expected);

  void Swap(InternalIndex entry1, InternalIndex entry2, WriteBarrierMode mode);
};

#define EXTERN_DECLARE_HASH_TABLE(DERIVED, SHAPE)                            \
  extern template class EXPORT_TEMPLATE_DECLARE(V8_EXPORT_PRIVATE)           \
      HashTable<class DERIVED, SHAPE>;                                       \
                                                                             \
  extern template EXPORT_TEMPLATE_DECLARE(V8_EXPORT_PRIVATE) Handle<DERIVED> \
  HashTable<DERIVED, SHAPE>::New(Isolate*, int, AllocationType,              \
                                 MinimumCapacity);                           \
  extern template EXPORT_TEMPLATE_DECLARE(V8_EXPORT_PRIVATE) Handle<DERIVED> \
  HashTable<DERIVED, SHAPE>::New(LocalIsolate*, int, AllocationType,         \
                                 MinimumCapacity);                           \
                                                                             \
  extern template EXPORT_TEMPLATE_DECLARE(V8_EXPORT_PRIVATE) Handle<DERIVED> \
  HashTable<DERIVED, SHAPE>::EnsureCapacity(Isolate*, Handle<DERIVED>, int,  \
                                            AllocationType);                 \
  extern template EXPORT_TEMPLATE_DECLARE(V8_EXPORT_PRIVATE) Handle<DERIVED> \
  HashTable<DERIVED, SHAPE>::EnsureCapacity(LocalIsolate*, Handle<DERIVED>,  \
                                            int, AllocationType);

// HashTableKey is an abstract superclass for virtual key behavior.
class HashTableKey {
 public:
  explicit HashTableKey(uint32_t hash) : hash_(hash) {}

  // Returns whether the other object matches this key.
  virtual bool IsMatch(Tagged<Object> other) = 0;
  // Returns the hash value for this key.
  // Required.
  virtual ~HashTableKey() = default;

  uint32_t Hash() const { return hash_; }

 protected:
  void set_hash(uint32_t hash) {
    DCHECK_EQ(0, hash_);
    hash_ = hash;
  }

 private:
  uint32_t hash_ = 0;
};

class ObjectHashTableShape : public BaseShape<Handle<Object>> {
 public:
  static inline bool IsMatch(DirectHandle<Object> key, Tagged<Object> other);
  static inline uint32_t Hash(ReadOnlyRoots roots, DirectHandle<Object> key);
  static inline uint32_t HashForObject(ReadOnlyRoots roots,
                                       Tagged<Object> object);
  static inline Handle<Object> AsHandle(Handle<Object> key);
  static const int kPrefixSize = 0;
  static const int kEntryValueIndex = 1;
  static const int kEntrySize = 2;
  static const bool kMatchNeedsHoleCheck = false;
};

template <typename Derived, typename Shape>
class EXPORT_TEMPLATE_DECLARE(V8_EXPORT_PRIVATE) ObjectHashTableBase
    : public HashTable<Derived, Shape> {
 public:
  // Looks up the value associated with the given key. The hole value is
  // returned in case the key is not present.
  Tagged<Object> Lookup(Handle<Object> key);
  Tagged<Object> Lookup(Handle<Object> key, int32_t hash);
  Tagged<Object> Lookup(PtrComprCageBase cage_base, Handle<Object> key,
                        int32_t hash);

  // Returns the value at entry.
  Tagged<Object> ValueAt(InternalIndex entry);

  // Overwrite all keys and values with the hole value.
  static void FillEntriesWithHoles(Handle<Derived>);

  // Adds (or overwrites) the value associated with the given key.
  static Handle<Derived> Put(Handle<Derived> table, Handle<Object> key,
                             Handle<Object> value);
  static Handle<Derived> Put(Isolate* isolate, Handle<Derived> table,
                             Handle<Object> key, DirectHandle<Object> value,
                             int32_t hash);

  // Returns an ObjectHashTable (possibly |table|) where |key| has been removed.
  static Handle<Derived> Remove(Isolate* isolate, Handle<Derived> table,
                                Handle<Object> key, bool* was_present);
  static Handle<Derived> Remove(Isolate* isolate, Handle<Derived> table,
                                Handle<Object> key, bool* was_present,
                                int32_t hash);

  // Returns the index to the value of an entry.
  static inline int EntryToValueIndex(InternalIndex entry) {
    return HashTable<Derived, Shape>::EntryToIndex(entry) +
           Shape::kEntryValueIndex;
  }

 protected:
  void AddEntry(InternalIndex entry, Tagged<Object> key, Tagged<Object> value);
  void RemoveEntry(InternalIndex entry);
};

#define EXTERN_DECLARE_OBJECT_BASE_HASH_TABLE(DERIVED, SHAPE)      \
  EXTERN_DECLARE_HASH_TABLE(DERIVED, SHAPE)                        \
  extern template class EXPORT_TEMPLATE_DECLARE(V8_EXPORT_PRIVATE) \
      ObjectHashTableBase<class DERIVED, SHAPE>;

EXTERN_DECLARE_OBJECT_BASE_HASH_TABLE(ObjectHashTable, ObjectHashTableShape)

// ObjectHashTable maps keys that are arbitrary objects to object values by
// using the identity hash of the key for hashing purposes.
class V8_EXPORT_PRIVATE ObjectHashTable
    : public ObjectHashTableBase<ObjectHashTable, ObjectHashTableShape> {
 public:
  DECL_PRINTER(ObjectHashTable)
};

EXTERN_DECLARE_OBJECT_BASE_HASH_TABLE(EphemeronHashTable, ObjectHashTableShape)

// EphemeronHashTable is similar to ObjectHashTable but gets special treatment
// by the GC. The GC treats its entries as ephemerons: both key and value are
// weak references, however if the key is strongly reachable its corresponding
// value is also kept alive.
class V8_EXPORT_PRIVATE EphemeronHashTable
    : public ObjectHashTableBase<EphemeronHashTable, ObjectHashTableShape> {
 public:
  static inline Handle<Map> GetMap(ReadOnlyRoots roots);

  DECL_PRINTER(EphemeronHashTable)
  class BodyDescriptor;

 protected:
  friend class MarkCompactCollector;
  friend class MinorMarkSweepCollector;
  friend class ScavengerCollector;
  friend class HashTable<EphemeronHashTable, ObjectHashTableShape>;
  friend class ObjectHashTableBase<EphemeronHashTable, ObjectHashTableShape>;
  inline void set_key(int index, Tagged<Object> value);
  inline void set_key(int index, Tagged<Object> value, WriteBarrierMode mode);
};

// ObjectMultihashTable is a hash table that maps Object keys to N Object
// values. The Object values are stored inline in the underlying FixedArray.
//
// This is not a generic multimap where each key can map to a variable number of
// values. Each key always maps to exactly N values.
template <int N>
class ObjectMultiHashTableShape : public ObjectHashTableShape {
 public:
  static const int kEntrySize = 1 + N;
};

template <typename Derived, int N>
class ObjectMultiHashTableBase
    : public HashTable<Derived, ObjectMultiHashTableShape<N>> {
 public:
  static_assert(N > 1, "use ObjectHashTable instead if N = 1");

  // Returns the values associated with the given key. Return an std::array of
  // holes if not found.
  std::array<Tagged<Object>, N> Lookup(Handle<Object> key);
  std::array<Tagged<Object>, N> Lookup(PtrComprCageBase cage_base,
                                       Handle<Object> key);

  // Adds or overwrites the values associated with the given key.
  static Handle<Derived> Put(Isolate* isolate, Handle<Derived> table,
                             Handle<Object> key,
                             const std::array<Handle<Object>, N>& values);

 private:
  void SetEntryValues(InternalIndex entry,
                      const std::array<Handle<Object>, N>& values);

  static constexpr inline int EntryToValueIndexStart(InternalIndex entry) {
    return HashTable<Derived, ObjectMultiHashTableShape<N>>::EntryToIndex(
               entry) +
           ObjectMultiHashTableShape<N>::kEntryValueIndex;
  }
};

class ObjectTwoHashTable
    : public ObjectMultiHashTableBase<ObjectTwoHashTable, 2> {
};

class ObjectHashSetShape : public ObjectHashTableShape {
 public:
  static const int kPrefixSize = 0;
  static const int kEntrySize = 1;
};

EXTERN_DECLARE_HASH_TABLE(ObjectHashSet, ObjectHashSetShape)

class V8_EXPORT_PRIVATE ObjectHashSet
    : public HashTable<ObjectHashSet, ObjectHashSetShape> {
 public:
  static Handle<ObjectHashSet> Add(Isolate* isolate, Handle<ObjectHashSet> set,
                                   Handle<Object> key);

  inline bool Has(Isolate* isolate, Handle<Object> key, int32_t hash);
  inline bool Has(Isolate* isolate, Handle<Object> key);
};

class NameToIndexShape : public BaseShape<Handle<Name>> {
 public:
  static inline bool IsMatch(DirectHandle<Name> key, Tagged<Object> other);
  static inline uint32_t Hash(ReadOnlyRoots roots, DirectHandle<Name> key);
  static inline uint32_t HashForObject(ReadOnlyRoots roots,
                                       Tagged<Object> object);
  static inline Handle<Object> AsHandle(Handle<Name> key);
  static const int kPrefixSize = 0;
  static const int kEntryValueIndex = 1;
  static const int kEntrySize = 2;
  static const bool kMatchNeedsHoleCheck = false;
};

class V8_EXPORT_PRIVATE NameToIndexHashTable
    : public HashTable<NameToIndexHashTable, NameToIndexShape> {
 public:
  static const int kEntryValueIndex = NameToIndexShape::kEntryValueIndex;

  inline static Handle<Map> GetMap(ReadOnlyRoots roots);
  int Lookup(Handle<Name> key);

  // Returns the value at entry.
  Tagged<Object> ValueAt(InternalIndex entry);
  int IndexAt(InternalIndex entry);

  template <typename IsolateT>
  static Handle<NameToIndexHashTable> Add(IsolateT* isolate,
                                          Handle<NameToIndexHashTable> table,
                                          IndirectHandle<Name> key,
                                          int32_t value);

  // Exposed for NameDictionaryLookupForwardedString slow path for forwarded
  // strings.
  using HashTable<NameToIndexHashTable, NameToIndexShape>::FindInsertionEntry;

  DECL_PRINTER(NameToIndexHashTable)

 private:
  static inline int EntryToValueIndex(InternalIndex entry) {
    return EntryToIndex(entry) + NameToIndexShape::kEntryValueIndex;
  }
};

class RegisteredSymbolTableShape : public BaseShape<Handle<String>> {
 public:
  static inline bool IsMatch(DirectHandle<String> key, Tagged<Object> other);
  static inline uint32_t Hash(ReadOnlyRoots roots, DirectHandle<String> key);
  static inline uint32_t HashForObject(ReadOnlyRoots roots,
                                       Tagged<Object> object);
  static const int kPrefixSize = 0;
  static const int kEntryValueIndex = 1;
  static const int kEntrySize = 2;
  static const bool kMatchNeedsHoleCheck = false;
};

class RegisteredSymbolTable
    : public HashTable<RegisteredSymbolTable, RegisteredSymbolTableShape> {
 public:
  Tagged<Object> SlowReverseLookup(Tagged<Object> value);

  // Returns the value at entry.
  Tagged<Object> ValueAt(InternalIndex entry);

  inline static Handle<Map> GetMap(ReadOnlyRoots roots);

  static Handle<RegisteredSymbolTable> Add(Isolate* isolate,
                                           Handle<RegisteredSymbolTable> table,
                                           IndirectHandle<String> key,
                                           DirectHandle<Symbol>);

  DECL_PRINTER(RegisteredSymbolTable)

 private:
  static inline int EntryToValueIndex(InternalIndex entry) {
    return EntryToIndex(entry) + RegisteredSymbolTableShape::kEntryValueIndex;
  }
};

}  // namespace internal
}  // namespace v8

#include "src/objects/object-macros-undef.h"

#endif  // V8_OBJECTS_HASH_TABLE_H_
```