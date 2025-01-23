Response:
Let's break down the thought process for analyzing the provided C++ header file for a hashmap implementation.

1. **Initial Scan & Purpose Identification:**

   - The first lines are copyright and license information – standard boilerplate.
   - The comment `// The reason we write our own hash map instead of using unordered_map in STL...` immediately tells us the *why*. This is crucial context. The key reason is to avoid mutex issues in debug builds during async signal handling. This also implies performance or specific behavior requirements might be at play.
   - `#ifndef V8_BASE_HASHMAP_H_` and `#define V8_BASE_HASHMAP_H_` are standard include guards, indicating this is a header file defining a class or set of classes.
   - The inclusion of `<stdlib.h>`, `"src/base/bits.h"`, etc., suggests this code relies on standard library functions and other V8 base utilities.
   - The `namespace v8 { namespace base { ... }}` structure clearly places this within the V8 codebase's base utilities.

   *Initial takeaway: This header defines a custom hashmap implementation within V8's base library, likely for performance and to avoid STL's mutex usage issues.*

2. **Core Class Identification & Template Nature:**

   - The `TemplateHashMapImpl` class stands out. The `template <typename Key, typename Value, class MatchFun, class AllocationPolicy>` declaration signifies its generic nature. This means it can store different key-value pairs and use custom comparison and memory allocation strategies.

   *Key takeaway: This is a highly flexible hashmap, not tied to specific data types or behaviors.*

3. **Key Features and Functionality - Method by Method:**

   - **`DefaultAllocationPolicy`:** A simple allocator using `malloc` and `free`. This establishes a default memory management strategy.
   - **`kDefaultHashMapCapacity`:**  A constant defining the initial size of the hashmap.
   - **Constructors:**
     - Default constructor (with optional capacity, match function, and allocator).
     - Deleted copy constructor and assignment operator (to prevent shallow copies, likely for memory safety).
     - A constructor that clones another hashmap.
     - Move constructor and assignment operator (for efficient resource transfer).
   - **`Lookup`:** Basic key lookup, returning the entry or `nullptr`.
   - **`LookupOrInsert` (multiple overloads):**  Crucial methods for retrieving or inserting entries. The overloads provide flexibility in how the key and value are created if an insertion is needed. Pay attention to the heterogeneous version using `LookupKey`.
   - **`InsertNew`:** Inserts a new entry, assuming it doesn't already exist (or overwriting if the probe finds an existing empty slot).
   - **`Remove`:**  Implements a removal algorithm, handling potential gaps and rehashing. The comment referencing Wikipedia's Open Addressing is a strong hint about the underlying technique.
   - **`Clear`:** Empties the hashmap.
   - **`Invalidate`:**  Destroys the map and makes it unusable.
   - **`occupancy()` and `capacity()`:** Accessors for the current number of elements and the allocated size.
   - **`Start()` and `Next()`:**  Methods for iterating through the hashmap. The comment about undefined behavior during iteration with insertions is important.
   - **`allocator()`:** Returns the allocation policy in use.
   - **`Initialize()`:**  Sets up the initial hashmap structure.
   - **`Probe()`:**  The core function for finding the correct slot for a key (or an empty slot for insertion) using the hash and collision resolution.
   - **`FillEmptyEntry()`:**  Places a new entry into an empty slot, handling potential resizing.
   - **`Resize()`:**  Handles growing the hashmap when it gets too full. This involves allocating a new array and rehashing existing elements.

4. **Helper Structs and Typedefs:**

   - **`Impl`:** A nested struct to hold the actual hashmap data and match/allocation policies. The comment about C++20 `[[no_unique_address]]` is an interesting detail about potential future improvements.
   - **`HashEqualityThenKeyMatcher`:**  An optimization that checks the hash before performing a potentially more expensive key comparison.
   - **`CustomMatcherTemplateHashMapImpl`:** A specialization of `TemplateHashMapImpl` for `void*` keys and values with a custom comparison function pointer.
   - **`PointerTemplateHashMapImpl`:** Another specialization for `void*` keys and values, comparing the pointers directly.
   - **`HashMap`:** A concrete type alias for `PointerTemplateHashMapImpl` using the default allocation policy.
   - **`TemplateHashMap`:**  Provides an STL-like interface on top of `TemplateHashMapImpl`, specifically for pointer keys and values, using a custom match function. It includes an `Iterator` class.

5. **Inferring Functionality & Relationships:**

   - The existence of different `LookupOrInsert` overloads strongly suggests flexibility in how keys and values are generated, possibly for performance reasons or when dealing with complex object creation.
   - The `Resize()` method is standard for dynamic hashmap implementations to maintain efficiency as the number of elements grows. The 80% occupancy threshold is a common strategy.
   - The different `Matcher` structs highlight the ability to customize how keys are compared (direct equality vs. using a separate comparison function).

6. **Considering JavaScript Relevance:**

   - V8 *is* the JavaScript engine. Therefore, any data structure within V8's codebase is potentially used to implement JavaScript features. Hashmaps are fundamental for:
     - **Object properties:**  JavaScript objects are essentially hashmaps.
     - **Symbol tables:**  Storing variable names and their associated data.
     - **Module resolution:**  Mapping module specifiers to loaded modules.
     - **Caches:**  Storing results of computations or lookups.

7. **Considering Common Programming Errors:**

   - **Incorrect hash function:** Leading to poor distribution and performance degradation (many collisions).
   - **Memory leaks:**  If the custom allocation policy isn't implemented correctly, especially in the destructor or `Resize`.
   - **Iterator invalidation:**  Modifying the hashmap (inserting/removing) while iterating can lead to crashes or undefined behavior.
   - **Using the wrong comparison function:** If the `MatchFun` doesn't correctly compare keys, lookups and removals will fail.
   - **Forgetting to provide a hash function:** For user-defined types, a suitable hash function needs to be provided.

8. **Torque Check:**

   - The prompt explicitly asks about the `.tq` extension. Since the file is `.h`, it's a standard C++ header, *not* a Torque file.

By following these steps, we can systematically analyze the header file, understand its purpose, functionality, and potential connections to other parts of the V8 engine and even higher-level concepts like JavaScript.
This header file `v8/src/base/hashmap.h` defines several template classes that implement a hash map data structure in C++. Let's break down its functionalities:

**Core Functionality:**

1. **Generic Hash Map Implementation:** The primary class, `TemplateHashMapImpl`, is a template, meaning it can be used with different key and value types (`Key`, `Value`), a custom matching function (`MatchFun`), and a custom allocation policy (`AllocationPolicy`). This provides a highly flexible and reusable hash map.

2. **Customizable Matching:** The `MatchFun` template parameter allows users to define how keys are compared for equality. This is crucial for handling different key types and comparison logic. V8 provides helpers like `HashEqualityThenKeyMatcher` and `KeyEqualityMatcher` for common cases.

3. **Customizable Allocation:** The `AllocationPolicy` template parameter enables users to control how memory is allocated and deallocated for the hash map's internal storage. The default `DefaultAllocationPolicy` uses `malloc` and `free`. This customization is important in environments like V8 where memory management needs to be tightly controlled.

4. **Efficient Lookup, Insertion, and Removal:** The hash map provides methods for:
   - `Lookup(const Key& key, uint32_t hash)`: Finding an existing entry based on the key and its pre-computed hash.
   - `LookupOrInsert(...)`:  Finding an entry or inserting a new one if it doesn't exist. There are several overloads to handle different scenarios for creating the key and value.
   - `InsertNew(const Key& key, uint32_t hash)`: Inserting a new entry, assuming the key doesn't already exist.
   - `Remove(const Key& key, uint32_t hash)`: Removing an entry based on its key and hash.

5. **Dynamic Resizing:** The hash map automatically resizes its internal storage when the occupancy (number of elements) reaches a certain threshold (around 80%). This ensures that lookups and insertions remain efficient even with a growing number of elements. The `Resize()` method handles this reallocation and rehashing of existing entries.

6. **Iteration:** The hash map supports iteration through its entries using `Start()` and `Next()`.

7. **Clearing and Invalidating:**
   - `Clear()`: Removes all entries from the hash map, making it empty.
   - `Invalidate()`:  Releases the allocated memory and makes the hash map unusable.

**Regarding `.tq` extension:**

The text explicitly states: "如果v8/src/base/hashmap.h以.tq结尾，那它是个v8 torque源代码"。 Since the provided file ends with `.h`, **it is a standard C++ header file, not a V8 Torque source file.** Torque files are typically used for generating C++ code within the V8 project.

**Relationship with Javascript and Examples:**

Hash maps are fundamental to the implementation of Javascript objects. Javascript objects are essentially key-value stores where keys are strings or Symbols.

**Javascript Example:**

```javascript
const myObject = {
  name: "Alice",
  age: 30,
  city: "New York"
};

// When V8 implements this Javascript object, it internally uses a hash map
// (or a similar data structure) to store these properties.

// Looking up a property is similar to the HashMap's Lookup operation:
console.log(myObject.name); // V8 would perform a hash lookup for the key "name"

// Adding a new property is similar to the HashMap's InsertNew or LookupOrInsert:
myObject.occupation = "Engineer"; // V8 would insert a new entry in its internal hash map

// Deleting a property is similar to the HashMap's Remove operation:
delete myObject.city; // V8 would remove the entry with the key "city"
```

**Code Logic Reasoning with Assumptions:**

Let's consider the `LookupOrInsert` function with the following assumptions:

* **Key Type:** `std::string`
* **Value Type:** `int`
* **MatchFun:** Default `KeyEqualityMatcher` (compares strings directly)
* **AllocationPolicy:** `DefaultAllocationPolicy`
* **Initial Capacity:** The default `kDefaultHashMapCapacity` (8)

**Hypothetical Input and Output:**

1. **Input:**
   - Hash map is initially empty.
   - Call `LookupOrInsert("apple", hash("apple"))`. Assume `hash("apple")` returns some integer value, e.g., 10.

   **Output:**
   - A new entry is inserted with key "apple" and a default-initialized integer value (0).
   - The function returns a pointer to this newly created `Entry`.

2. **Input:**
   - Hash map contains the entry {"apple", 0}.
   - Call `LookupOrInsert("apple", hash("apple"))`.

   **Output:**
   - The existing entry with key "apple" is found.
   - The function returns a pointer to this existing `Entry`.

3. **Input:**
   - Hash map is full (occupancy is close to capacity).
   - Call `LookupOrInsert("banana", hash("banana"))`.

   **Output:**
   - Since the map is near its capacity, the `Resize()` method will be triggered internally.
   - A new, larger array will be allocated.
   - Existing entries will be rehashed and moved to the new array.
   - A new entry with key "banana" and default value 0 will be inserted in the resized map.
   - The function returns a pointer to this newly created `Entry`.

**User-Common Programming Errors:**

1. **Not Providing a Suitable Hash Function:** If using custom key types, users need to ensure they provide a good hash function that distributes keys evenly across the hash table. A poor hash function leads to many collisions, degrading performance (lookups become closer to O(n) instead of O(1) on average).

   ```c++
   // Example of a custom key type without a proper hash function
   struct MyKey {
       int id;
       std::string name;
   };

   // Using this with the default hash (which might just hash the memory address)
   // will likely result in poor performance.
   // HashMap<MyKey, int> myMap;
   ```

2. **Modifying Keys After Insertion:** If the hash of a key changes after it's been inserted into the hash map, the hash map will no longer be able to find that entry. Keys should generally be immutable or their hash should remain consistent while they are in the hash map.

   ```c++
   #include <string>
   #include <iostream>
   #include "src/base/hashmap.h" // Assuming you have the necessary include paths

   struct StringHasher {
       uint32_t operator()(const std::string& str) const {
           // A simple (but not great) hash function for demonstration
           uint32_t hash = 0;
           for (char c : str) {
               hash = hash * 31 + c;
           }
           return hash;
       }
   };

   struct StringEquality {
       bool operator()(const std::string& a, const std::string& b) const {
           return a == b;
       }
   };

   using MyHashMap = v8::base::TemplateHashMapImpl<
       std::string, int,
       v8::base::HashEqualityThenKeyMatcher<std::string, StringEquality>,
       v8::base::DefaultAllocationPolicy>;

   int main() {
       MyHashMap myMap;
       std::string key = "initial";
       uint32_t initial_hash = StringHasher()(key);
       myMap.LookupOrInsert(key, initial_hash);

       // Now, modify the key AFTER insertion (BAD PRACTICE!)
       key = "modified";
       uint32_t modified_hash = StringHasher()(key);

       // Lookup with the modified key's hash will likely fail
       if (myMap.Lookup(key, modified_hash)) {
           std::cout << "Found (incorrectly)" << std::endl;
       } else {
           std::cout << "Not found (correctly)" << std::endl;
       }
       return 0;
   }
   ```

3. **Incorrectly Implementing the Match Function:** If the `MatchFun` doesn't correctly determine equality between keys, lookups, removals, and insertions will behave unexpectedly.

4. **Memory Management Issues (if using custom AllocationPolicy):** If a custom `AllocationPolicy` is used, it's crucial to ensure that memory is allocated and deallocated correctly to avoid memory leaks or double frees.

This detailed explanation covers the functionality of `v8/src/base/hashmap.h`, clarifies its nature as a C++ header, illustrates its connection to Javascript, provides logic reasoning with examples, and highlights common programming errors when using hash maps.

### 提示词
```
这是目录为v8/src/base/hashmap.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/base/hashmap.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```c
// Copyright 2012 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// The reason we write our own hash map instead of using unordered_map in STL,
// is that STL containers use a mutex pool on debug build, which will lead to
// deadlock when we are using async signal handler.

#ifndef V8_BASE_HASHMAP_H_
#define V8_BASE_HASHMAP_H_

#include <stdlib.h>

#include "src/base/bits.h"
#include "src/base/hashmap-entry.h"
#include "src/base/logging.h"
#include "src/base/platform/memory.h"

namespace v8 {
namespace base {

class DefaultAllocationPolicy {
 public:
  template <typename T, typename TypeTag = T[]>
  V8_INLINE T* AllocateArray(size_t length) {
    return static_cast<T*>(base::Malloc(length * sizeof(T)));
  }
  template <typename T, typename TypeTag = T[]>
  V8_INLINE void DeleteArray(T* p, size_t length) {
    base::Free(p);
  }
};

template <typename Key, typename Value, class MatchFun, class AllocationPolicy>
class TemplateHashMapImpl {
 public:
  using Entry = TemplateHashMapEntry<Key, Value>;

  // The default capacity.  This is used by the call sites which want
  // to pass in a non-default AllocationPolicy but want to use the
  // default value of capacity specified by the implementation.
  static const uint32_t kDefaultHashMapCapacity = 8;

  // initial_capacity is the size of the initial hash map;
  // it must be a power of 2 (and thus must not be 0).
  explicit TemplateHashMapImpl(uint32_t capacity = kDefaultHashMapCapacity,
                               MatchFun match = MatchFun(),
                               AllocationPolicy allocator = AllocationPolicy());

  TemplateHashMapImpl(const TemplateHashMapImpl&) = delete;
  TemplateHashMapImpl& operator=(const TemplateHashMapImpl&) = delete;

  // Clones the given hashmap and creates a copy with the same entries.
  explicit TemplateHashMapImpl(const TemplateHashMapImpl* original,
                               AllocationPolicy allocator = AllocationPolicy());

  TemplateHashMapImpl(TemplateHashMapImpl&& other) V8_NOEXCEPT = default;

  ~TemplateHashMapImpl();

  TemplateHashMapImpl& operator=(TemplateHashMapImpl&& other)
      V8_NOEXCEPT = default;

  // If an entry with matching key is found, returns that entry.
  // Otherwise, nullptr is returned.
  Entry* Lookup(const Key& key, uint32_t hash) const;

  // If an entry with matching key is found, returns that entry.
  // If no matching entry is found, a new entry is inserted with
  // corresponding key, key hash, and default initialized value.
  Entry* LookupOrInsert(const Key& key, uint32_t hash);

  // If an entry with matching key is found, returns that entry.
  // If no matching entry is found, a new entry is inserted with
  // corresponding key, key hash, and value created by func.
  template <typename Func>
  Entry* LookupOrInsert(const Key& key, uint32_t hash, const Func& value_func);

  // Heterogeneous version of LookupOrInsert, which allows a
  // different lookup key type than the hashmap's key type.
  // The requirement is that MatchFun has an overload:
  //
  //   operator()(const LookupKey& lookup_key, const Key& entry_key)
  //
  // If an entry with matching key is found, returns that entry.
  // If no matching entry is found, a new entry is inserted with
  // a key created by key_func, key hash, and value created by
  // value_func.
  template <typename LookupKey, typename KeyFunc, typename ValueFunc>
  Entry* LookupOrInsert(const LookupKey& lookup_key, uint32_t hash,
                        const KeyFunc& key_func, const ValueFunc& value_func);

  Entry* InsertNew(const Key& key, uint32_t hash);

  // Removes the entry with matching key.
  // It returns the value of the deleted entry
  // or null if there is no value for such key.
  Value Remove(const Key& key, uint32_t hash);

  // Empties the hash map (occupancy() == 0).
  void Clear();

  // Empties the map and makes it unusable for allocation.
  void Invalidate() {
    DCHECK_NOT_NULL(impl_.map_);
    impl_.allocator().DeleteArray(impl_.map_, capacity());
    impl_ = Impl(impl_.match(), AllocationPolicy());
  }

  // The number of (non-empty) entries in the table.
  uint32_t occupancy() const { return impl_.occupancy_; }

  // The capacity of the table. The implementation
  // makes sure that occupancy is at most 80% of
  // the table capacity.
  uint32_t capacity() const { return impl_.capacity_; }

  // Iteration
  //
  // for (Entry* p = map.Start(); p != nullptr; p = map.Next(p)) {
  //   ...
  // }
  //
  // If entries are inserted during iteration, the effect of
  // calling Next() is undefined.
  Entry* Start() const;
  Entry* Next(Entry* entry) const;

  AllocationPolicy allocator() const { return impl_.allocator(); }

 protected:
  void Initialize(uint32_t capacity);

 private:
  Entry* map_end() const { return impl_.map_ + impl_.capacity_; }
  template <typename LookupKey>
  Entry* Probe(const LookupKey& key, uint32_t hash) const;
  Entry* FillEmptyEntry(Entry* entry, const Key& key, const Value& value,
                        uint32_t hash);
  void Resize();

  // To support matcher and allocator that may not be possible to
  // default-construct, we have to store their instances. Using this to store
  // all internal state of the hash map and using private inheritance to store
  // matcher and allocator lets us take advantage of an empty base class
  // optimization to avoid extra space in the common case when MatchFun and
  // AllocationPolicy have no state.
  // TODO(ishell): Once we reach C++20, consider removing the Impl struct and
  // adding match and allocator as [[no_unique_address]] fields.
  struct Impl : private MatchFun, private AllocationPolicy {
    Impl(MatchFun match, AllocationPolicy allocator)
        : MatchFun(std::move(match)), AllocationPolicy(std::move(allocator)) {}

    Impl() = default;
    Impl(const Impl&) V8_NOEXCEPT = default;
    Impl(Impl&& other) V8_NOEXCEPT { *this = std::move(other); }

    Impl& operator=(const Impl& other) V8_NOEXCEPT = default;
    Impl& operator=(Impl&& other) V8_NOEXCEPT {
      MatchFun::operator=(std::move(other));
      AllocationPolicy::operator=(std::move(other));
      map_ = other.map_;
      capacity_ = other.capacity_;
      occupancy_ = other.occupancy_;

      other.map_ = nullptr;
      other.capacity_ = 0;
      other.occupancy_ = 0;
      return *this;
    }

    const MatchFun& match() const { return *this; }
    MatchFun& match() { return *this; }

    const AllocationPolicy& allocator() const { return *this; }
    AllocationPolicy& allocator() { return *this; }

    Entry* map_ = nullptr;
    uint32_t capacity_ = 0;
    uint32_t occupancy_ = 0;
  } impl_;
};
template <typename Key, typename Value, typename MatchFun,
          class AllocationPolicy>
TemplateHashMapImpl<Key, Value, MatchFun, AllocationPolicy>::
    TemplateHashMapImpl(uint32_t initial_capacity, MatchFun match,
                        AllocationPolicy allocator)
    : impl_(std::move(match), std::move(allocator)) {
  Initialize(initial_capacity);
}

template <typename Key, typename Value, typename MatchFun,
          class AllocationPolicy>
TemplateHashMapImpl<Key, Value, MatchFun, AllocationPolicy>::
    TemplateHashMapImpl(const TemplateHashMapImpl* original,
                        AllocationPolicy allocator)
    : impl_(original->impl_.match(), std::move(allocator)) {
  impl_.capacity_ = original->capacity();
  impl_.occupancy_ = original->occupancy();
  impl_.map_ = impl_.allocator().template AllocateArray<Entry>(capacity());
  memcpy(impl_.map_, original->impl_.map_, capacity() * sizeof(Entry));
}

template <typename Key, typename Value, typename MatchFun,
          class AllocationPolicy>
TemplateHashMapImpl<Key, Value, MatchFun,
                    AllocationPolicy>::~TemplateHashMapImpl() {
  if (impl_.map_) impl_.allocator().DeleteArray(impl_.map_, capacity());
}

template <typename Key, typename Value, typename MatchFun,
          class AllocationPolicy>
typename TemplateHashMapImpl<Key, Value, MatchFun, AllocationPolicy>::Entry*
TemplateHashMapImpl<Key, Value, MatchFun, AllocationPolicy>::Lookup(
    const Key& key, uint32_t hash) const {
  Entry* entry = Probe(key, hash);
  return entry->exists() ? entry : nullptr;
}

template <typename Key, typename Value, typename MatchFun,
          class AllocationPolicy>
typename TemplateHashMapImpl<Key, Value, MatchFun, AllocationPolicy>::Entry*
TemplateHashMapImpl<Key, Value, MatchFun, AllocationPolicy>::LookupOrInsert(
    const Key& key, uint32_t hash) {
  return LookupOrInsert(key, hash, []() { return Value(); });
}

template <typename Key, typename Value, typename MatchFun,
          class AllocationPolicy>
template <typename Func>
typename TemplateHashMapImpl<Key, Value, MatchFun, AllocationPolicy>::Entry*
TemplateHashMapImpl<Key, Value, MatchFun, AllocationPolicy>::LookupOrInsert(
    const Key& key, uint32_t hash, const Func& value_func) {
  return LookupOrInsert(
      key, hash, [&key]() { return key; }, value_func);
}

template <typename Key, typename Value, typename MatchFun,
          class AllocationPolicy>
template <typename LookupKey, typename KeyFunc, typename ValueFunc>
typename TemplateHashMapImpl<Key, Value, MatchFun, AllocationPolicy>::Entry*
TemplateHashMapImpl<Key, Value, MatchFun, AllocationPolicy>::LookupOrInsert(
    const LookupKey& lookup_key, uint32_t hash, const KeyFunc& key_func,
    const ValueFunc& value_func) {
  // Find a matching entry.
  Entry* entry = Probe(lookup_key, hash);
  if (entry->exists()) {
    return entry;
  }

  return FillEmptyEntry(entry, key_func(), value_func(), hash);
}

template <typename Key, typename Value, typename MatchFun,
          class AllocationPolicy>
typename TemplateHashMapImpl<Key, Value, MatchFun, AllocationPolicy>::Entry*
TemplateHashMapImpl<Key, Value, MatchFun, AllocationPolicy>::InsertNew(
    const Key& key, uint32_t hash) {
  Entry* entry = Probe(key, hash);
  return FillEmptyEntry(entry, key, Value(), hash);
}

template <typename Key, typename Value, typename MatchFun,
          class AllocationPolicy>
Value TemplateHashMapImpl<Key, Value, MatchFun, AllocationPolicy>::Remove(
    const Key& key, uint32_t hash) {
  // Lookup the entry for the key to remove.
  Entry* p = Probe(key, hash);
  if (!p->exists()) {
    // Key not found nothing to remove.
    return nullptr;
  }

  Value value = p->value;
  // To remove an entry we need to ensure that it does not create an empty
  // entry that will cause the search for another entry to stop too soon. If all
  // the entries between the entry to remove and the next empty slot have their
  // initial position inside this interval, clearing the entry to remove will
  // not break the search. If, while searching for the next empty entry, an
  // entry is encountered which does not have its initial position between the
  // entry to remove and the position looked at, then this entry can be moved to
  // the place of the entry to remove without breaking the search for it. The
  // entry made vacant by this move is now the entry to remove and the process
  // starts over.
  // Algorithm from http://en.wikipedia.org/wiki/Open_addressing.

  // This guarantees loop termination as there is at least one empty entry so
  // eventually the removed entry will have an empty entry after it.
  DCHECK(occupancy() < capacity());

  // p is the candidate entry to clear. q is used to scan forwards.
  Entry* q = p;  // Start at the entry to remove.
  while (true) {
    // Move q to the next entry.
    q = q + 1;
    if (q == map_end()) {
      q = impl_.map_;
    }

    // All entries between p and q have their initial position between p and q
    // and the entry p can be cleared without breaking the search for these
    // entries.
    if (!q->exists()) {
      break;
    }

    // Find the initial position for the entry at position q.
    Entry* r = impl_.map_ + (q->hash & (capacity() - 1));

    // If the entry at position q has its initial position outside the range
    // between p and q it can be moved forward to position p and will still be
    // found. There is now a new candidate entry for clearing.
    if ((q > p && (r <= p || r > q)) || (q < p && (r <= p && r > q))) {
      *p = *q;
      p = q;
    }
  }

  // Clear the entry which is allowed to en emptied.
  p->clear();
  impl_.occupancy_--;
  return value;
}

template <typename Key, typename Value, typename MatchFun,
          class AllocationPolicy>
void TemplateHashMapImpl<Key, Value, MatchFun, AllocationPolicy>::Clear() {
  // Mark all entries as empty.
  for (size_t i = 0; i < capacity(); ++i) {
    impl_.map_[i].clear();
  }
  impl_.occupancy_ = 0;
}

template <typename Key, typename Value, typename MatchFun,
          class AllocationPolicy>
typename TemplateHashMapImpl<Key, Value, MatchFun, AllocationPolicy>::Entry*
TemplateHashMapImpl<Key, Value, MatchFun, AllocationPolicy>::Start() const {
  return Next(impl_.map_ - 1);
}

template <typename Key, typename Value, typename MatchFun,
          class AllocationPolicy>
typename TemplateHashMapImpl<Key, Value, MatchFun, AllocationPolicy>::Entry*
TemplateHashMapImpl<Key, Value, MatchFun, AllocationPolicy>::Next(
    Entry* entry) const {
  const Entry* end = map_end();
  DCHECK(impl_.map_ - 1 <= entry && entry < end);
  for (entry++; entry < end; entry++) {
    if (entry->exists()) {
      return entry;
    }
  }
  return nullptr;
}

template <typename Key, typename Value, typename MatchFun,
          class AllocationPolicy>
template <typename LookupKey>
typename TemplateHashMapImpl<Key, Value, MatchFun, AllocationPolicy>::Entry*
TemplateHashMapImpl<Key, Value, MatchFun, AllocationPolicy>::Probe(
    const LookupKey& key, uint32_t hash) const {
  DCHECK(base::bits::IsPowerOfTwo(capacity()));
  size_t i = hash & (capacity() - 1);
  DCHECK(i < capacity());

  DCHECK(occupancy() < capacity());  // Guarantees loop termination.
  Entry* map = impl_.map_;
  while (map[i].exists() &&
         !impl_.match()(hash, map[i].hash, key, map[i].key)) {
    i = (i + 1) & (capacity() - 1);
  }

  return &map[i];
}

template <typename Key, typename Value, typename MatchFun,
          class AllocationPolicy>
typename TemplateHashMapImpl<Key, Value, MatchFun, AllocationPolicy>::Entry*
TemplateHashMapImpl<Key, Value, MatchFun, AllocationPolicy>::FillEmptyEntry(
    Entry* entry, const Key& key, const Value& value, uint32_t hash) {
  DCHECK(!entry->exists());

  new (entry) Entry(key, value, hash);
  impl_.occupancy_++;

  // Grow the map if we reached >= 80% occupancy.
  if (occupancy() + occupancy() / 4 >= capacity()) {
    Resize();
    entry = Probe(key, hash);
  }

  return entry;
}

template <typename Key, typename Value, typename MatchFun,
          class AllocationPolicy>
void TemplateHashMapImpl<Key, Value, MatchFun, AllocationPolicy>::Initialize(
    uint32_t capacity) {
  DCHECK(base::bits::IsPowerOfTwo(capacity));
  impl_.map_ = impl_.allocator().template AllocateArray<Entry>(capacity);
  if (impl_.map_ == nullptr) {
    FATAL("Out of memory: HashMap::Initialize");
    return;
  }
  impl_.capacity_ = capacity;
  Clear();
}

template <typename Key, typename Value, typename MatchFun,
          class AllocationPolicy>
void TemplateHashMapImpl<Key, Value, MatchFun, AllocationPolicy>::Resize() {
  Entry* old_map = impl_.map_;
  uint32_t old_capacity = capacity();
  uint32_t n = occupancy();

  // Allocate larger map.
  Initialize(capacity() * 2);

  // Rehash all current entries.
  for (Entry* entry = old_map; n > 0; entry++) {
    if (entry->exists()) {
      Entry* new_entry = Probe(entry->key, entry->hash);
      new_entry =
          FillEmptyEntry(new_entry, entry->key, entry->value, entry->hash);
      n--;
    }
  }

  // Delete old map.
  impl_.allocator().DeleteArray(old_map, old_capacity);
}

// Match function which compares hashes before executing a (potentially
// expensive) key comparison.
template <typename Key, typename MatchFun>
struct HashEqualityThenKeyMatcher {
  explicit HashEqualityThenKeyMatcher(MatchFun match) : match_(match) {}

  bool operator()(uint32_t hash1, uint32_t hash2, const Key& key1,
                  const Key& key2) const {
    return hash1 == hash2 && match_(key1, key2);
  }

 private:
  MatchFun match_;
};

// Hashmap<void*, void*> which takes a custom key comparison function pointer.
template <typename AllocationPolicy>
class CustomMatcherTemplateHashMapImpl
    : public TemplateHashMapImpl<
          void*, void*,
          HashEqualityThenKeyMatcher<void*, bool (*)(void*, void*)>,
          AllocationPolicy> {
  using Base = TemplateHashMapImpl<
      void*, void*, HashEqualityThenKeyMatcher<void*, bool (*)(void*, void*)>,
      AllocationPolicy>;

 public:
  using MatchFun = bool (*)(void*, void*);

  explicit CustomMatcherTemplateHashMapImpl(
      MatchFun match, uint32_t capacity = Base::kDefaultHashMapCapacity,
      AllocationPolicy allocator = AllocationPolicy())
      : Base(capacity, HashEqualityThenKeyMatcher<void*, MatchFun>(match),
             allocator) {}

  explicit CustomMatcherTemplateHashMapImpl(
      const CustomMatcherTemplateHashMapImpl* original,
      AllocationPolicy allocator = AllocationPolicy())
      : Base(original, allocator) {}

  CustomMatcherTemplateHashMapImpl(const CustomMatcherTemplateHashMapImpl&) =
      delete;
  CustomMatcherTemplateHashMapImpl& operator=(
      const CustomMatcherTemplateHashMapImpl&) = delete;
};

using CustomMatcherHashMap =
    CustomMatcherTemplateHashMapImpl<DefaultAllocationPolicy>;

// Match function which compares keys directly by equality.
template <typename Key>
struct KeyEqualityMatcher {
  bool operator()(uint32_t hash1, uint32_t hash2, const Key& key1,
                  const Key& key2) const {
    return key1 == key2;
  }
};

// Hashmap<void*, void*> which compares the key pointers directly.
template <typename AllocationPolicy>
class PointerTemplateHashMapImpl
    : public TemplateHashMapImpl<void*, void*, KeyEqualityMatcher<void*>,
                                 AllocationPolicy> {
  using Base = TemplateHashMapImpl<void*, void*, KeyEqualityMatcher<void*>,
                                   AllocationPolicy>;

 public:
  explicit PointerTemplateHashMapImpl(
      uint32_t capacity = Base::kDefaultHashMapCapacity,
      AllocationPolicy allocator = AllocationPolicy())
      : Base(capacity, KeyEqualityMatcher<void*>(), allocator) {}

  PointerTemplateHashMapImpl(const PointerTemplateHashMapImpl& other,
                             AllocationPolicy allocator = AllocationPolicy())
      : Base(&other, allocator) {}

  PointerTemplateHashMapImpl(PointerTemplateHashMapImpl&& other) V8_NOEXCEPT
      : Base(std::move(other)) {}

  PointerTemplateHashMapImpl& operator=(PointerTemplateHashMapImpl&& other)
      V8_NOEXCEPT {
    static_cast<Base&>(*this) = std::move(other);
    return *this;
  }
};

using HashMap = PointerTemplateHashMapImpl<DefaultAllocationPolicy>;

// A hash map for pointer keys and values with an STL-like interface.
template <class Key, class Value, class MatchFun, class AllocationPolicy>
class TemplateHashMap
    : private TemplateHashMapImpl<void*, void*,
                                  HashEqualityThenKeyMatcher<void*, MatchFun>,
                                  AllocationPolicy> {
  using Base = TemplateHashMapImpl<void*, void*,
                                   HashEqualityThenKeyMatcher<void*, MatchFun>,
                                   AllocationPolicy>;

 public:
  static_assert(sizeof(Key*) == sizeof(void*));
  static_assert(sizeof(Value*) == sizeof(void*));
  struct value_type {
    Key* first;
    Value* second;
  };

  class Iterator {
   public:
    Iterator& operator++() {
      entry_ = map_->Next(entry_);
      return *this;
    }

    value_type* operator->() { return reinterpret_cast<value_type*>(entry_); }
    bool operator!=(const Iterator& other) { return entry_ != other.entry_; }

   private:
    Iterator(const Base* map, typename Base::Entry* entry)
        : map_(map), entry_(entry) {}

    const Base* map_;
    typename Base::Entry* entry_;

    friend class TemplateHashMap;
  };

  explicit TemplateHashMap(MatchFun match,
                           AllocationPolicy allocator = AllocationPolicy())
      : Base(Base::kDefaultHashMapCapacity,
             HashEqualityThenKeyMatcher<void*, MatchFun>(match), allocator) {}

  Iterator begin() const { return Iterator(this, this->Start()); }
  Iterator end() const { return Iterator(this, nullptr); }
  Iterator find(Key* key, bool insert = false) {
    if (insert) {
      return Iterator(this, this->LookupOrInsert(key, key->Hash()));
    }
    return Iterator(this, this->Lookup(key, key->Hash()));
  }
};

}  // namespace base
}  // namespace v8

#endif  // V8_BASE_HASHMAP_H_
```