Response:
Let's break down the thought process for analyzing the provided C++ code and generating the explanation.

**1. Initial Understanding & Goal:**

The request asks for a functional description of the `IdentityMapBase` class in the provided C++ code, along with connections to JavaScript, potential errors, and logical reasoning. The core goal is to understand what this class *does* and how it might be used within the V8 engine.

**2. High-Level Overview & Identifying Key Components:**

The first step is to quickly read through the code, identifying major sections and keywords. I noticed:

* **Class Definition:** `class IdentityMapBase` – This is the central entity.
* **Data Members:** `keys_`, `values_`, `size_`, `capacity_`, `mask_`, `hasher_` –  These suggest a hash map implementation. `keys_` and `values_` are likely the storage for key-value pairs.
* **Methods:** `InsertKey`, `Lookup`, `DeleteIndex`, `Resize`, `Rehash`, `Clear`, `FindOrInsertEntry`, `FindEntry`, `DeleteEntry` – These are the standard operations of a map or dictionary.
* **Memory Management:** `NewPointerArray`, `DeletePointerArray`, `strong_roots_entry_` – Indicate the class manages its own memory, likely for performance reasons within V8. `strong_roots_entry_` suggests interaction with V8's garbage collector.
* **Hashing:** The `Hash` method and the use of `mask_` for indexing strongly point towards a hash table.
* **Resizing:** The `Resize` method and `kResizeFactor` confirm dynamic resizing of the underlying storage.
* **Iteration:** `EnableIteration`, `DisableIteration`, `KeyAtIndex`, `EntryAtIndex`, `NextIndex` suggest the map can be iterated over.
* **`ReadOnlyRoots`:** This hints at interaction with V8's internal object representation and potentially immutable values.
* **`not_mapped_symbol`:** This is a common pattern in V8 for marking empty slots in data structures.

**3. Inferring Functionality – Method by Method (and relating to data members):**

Now, go through each method and deduce its purpose:

* **Constructor/Destructor (`~IdentityMapBase`):**  The destructor has a `DCHECK_NULL(keys_)`, suggesting the subclass is responsible for calling `Clear`.
* **`Clear()`:** Deallocates memory, resets size and capacity. Important for cleanup.
* **`EnableIteration()`, `DisableIteration()`:** Control whether iteration is allowed. The checks (`CHECK(!is_iterable())`) suggest there are restrictions on operations during iteration (likely to prevent inconsistencies during modification).
* **`ScanKeysFor()`:**  A helper function for finding a key. The linear probing with wrap-around is a classic hash table collision resolution strategy.
* **`ShouldGrow()`:** Determines if the map needs to be resized based on occupancy.
* **`InsertKey()`:** Inserts a new key-value pair, handling resizing if necessary. The loop with `& mask_` is the modulo operation for wrapping around the hash table.
* **`DeleteIndex()`:** Deletes an entry at a given index. The "move any collisions" logic is crucial for maintaining the correctness of the hash table after deletion.
* **`Lookup()`:**  Finds the index of a key. The rehashing logic if `gc_counter_` has changed is interesting – it suggests handling object movement during garbage collection.
* **`LookupOrInsert()`:**  Combines lookup and insertion. Optimizations are present to avoid redundant searches.
* **`Hash()`:**  Calculates the hash code for a key. The `hasher_` suggests this is customizable.
* **`FindOrInsertEntry()`:**  Returns a pointer to the value, inserting if the key doesn't exist. The check for `!is_iterable()` reinforces the restriction on modification during iteration.
* **`FindEntry()`:**  Returns a pointer to the value if the key exists, otherwise `nullptr`.
* **`InsertEntry()`:**  Inserts a new key-value pair and returns a pointer to the new value storage. Handles initial allocation.
* **`DeleteEntry()`:**  Deletes a key-value pair.
* **`KeyAtIndex()`, `EntryAtIndex()`, `NextIndex()`:**  Provide access to elements during iteration. The `CHECK(is_iterable())` is key.
* **`Rehash()`:** Reorganizes the hash table to improve performance after garbage collection might have moved objects.
* **`Resize()`:**  Allocates new storage and reinserts all existing elements.

**4. Connecting to JavaScript (Conceptual):**

Think about how JavaScript objects and maps work. The `IdentityMapBase` stores key-value pairs where the *identity* of the key (its memory address) is important. This is different from standard JavaScript object keys, which are strings or symbols. This suggests it's likely used internally by V8 for things like:

* **Object-to-Internal-Data Mappings:**  Mapping JavaScript objects to internal V8 structures.
* **Weak Maps (Conceptually):**  While not a direct implementation of `WeakMap`, the identity-based nature has similarities. If the object is garbage collected, the entry in this map might become invalid or be cleaned up in some way.

The example of associating metadata with JavaScript objects illustrates this.

**5. Identifying Potential Errors:**

Based on common hash map pitfalls:

* **Hash Collisions:**  While the code handles collisions, excessive collisions can degrade performance.
* **Incorrect Hashing Function:**  A poor hashing function leads to more collisions.
* **Modification During Iteration:** The checks in the code highlight this as a potential issue.

**6. Logical Reasoning and Examples:**

For the `InsertKey` example, simulate the steps with a small map and a given key and hash. Trace the index calculation and the handling of empty slots. Similarly, for `DeleteIndex`, visualize the shifting of elements.

**7. Torque (if applicable):**

The prompt mentions `.tq` files. Since the provided code is `.cc`, this part is not directly relevant to *this specific file*. However, it's important to note that Torque is V8's internal language, and files ending in `.tq` would define type definitions and potentially some logic that's then translated into C++.

**8. Structuring the Output:**

Finally, organize the findings into clear sections as requested: functionality, JavaScript relation, code logic, and common errors. Use clear and concise language.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This looks like a simple hash map."
* **Correction:** "It's an *identity* map, meaning it uses object addresses as keys, which is a crucial distinction from standard hash maps."
* **Refinement:**  Emphasize the internal V8 usage and the connection to garbage collection due to the identity-based nature.

By following these steps, combining code analysis with knowledge of data structures and V8 internals, a comprehensive explanation can be generated.
`v8/src/utils/identity-map.cc` 文件实现了一个基于 **身份** 的哈希映射（Identity Map）。这意味着它使用对象的 **内存地址** 作为键，而不是对象的内容或值。

**主要功能:**

1. **存储和检索基于身份的键值对:**  `IdentityMapBase` 允许你存储和检索键值对，其中键是内存地址。这与普通的哈希表使用对象的哈希值作为键不同。
2. **高效的查找:**  它使用哈希表的数据结构来实现快速的键查找。
3. **动态调整大小:** 当存储的元素数量超过容量时，它可以动态地调整内部存储空间的大小，以保持性能。
4. **处理垃圾回收 (GC):**  它与 V8 的垃圾回收机制集成，以确保在 GC 期间对象移动后仍然能够正确地找到键值对。这通过 `Rehash()` 方法实现，该方法在 GC 后重新组织哈希表。
5. **支持迭代:**  提供了方法来启用和禁用迭代，并在启用后允许按索引访问键和值。
6. **延迟初始化:**  在首次插入元素时才分配内部存储空间。
7. **可定制的哈希函数:**  允许使用自定义的哈希函数（通过 `hasher_` 成员）。

**关于文件扩展名 `.tq`:**

如果 `v8/src/utils/identity-map.cc` 的文件扩展名是 `.tq`，那么它确实是一个 **V8 Torque 源代码** 文件。Torque 是 V8 内部使用的一种类型安全的高级语言，用于生成 C++ 代码。由于给出的代码是 `.cc`，所以它是一个标准的 C++ 源代码文件。

**与 JavaScript 的关系 (通过概念联系):**

`IdentityMapBase` 的功能与 JavaScript 中的 `WeakMap` 有一些概念上的相似之处。

* **`WeakMap` 的键是对象:**  `WeakMap` 的键必须是对象。如果键对象被垃圾回收，`WeakMap` 中的相应条目也会被移除。
* **`IdentityMapBase` 的键是地址 (对象的身份):** `IdentityMapBase` 使用对象的内存地址作为键，这本质上是对象的身份。

虽然 `IdentityMapBase` 不是直接暴露给 JavaScript 的 API，但 V8 内部可能会使用它来实现一些与对象身份相关的特性或优化。

**JavaScript 示例 (概念性):**

虽然 JavaScript 没有直接的对应物，但我们可以用一个简单的例子来理解基于身份的映射的概念：

```javascript
const obj1 = {};
const obj2 = {};

// 想象一下内部的 IdentityMap
const identityMap = new InternalIdentityMap();

identityMap.set(obj1, "value1");
identityMap.set(obj2, "value2");

console.log(identityMap.get(obj1)); // 输出 "value1"
console.log(identityMap.get(obj2)); // 输出 "value2"

// 注意：即使 obj1 和 obj2 的内容可能相同，
// 它们是不同的对象实例，因此在 IdentityMap 中被视为不同的键。

const obj3 = {};
console.log(identityMap.get(obj3)); // 输出 undefined (因为 obj3 是一个新的对象)
```

在这个概念性的例子中，`InternalIdentityMap` 使用对象的身份（内存地址）作为键。即使 `obj1` 和 `obj2` 的内容为空，它们仍然是不同的键。

**代码逻辑推理 (假设输入与输出):**

假设我们有一个 `IdentityMapBase` 实例 `map`，并且我们插入了一些元素。

**假设输入:**

1. `map` 的初始容量为 4。
2. 插入一个对象 `obj1` (内存地址为 `0x1000`)，关联的值为 `10`。假设 `Hash(0x1000)` 的结果是 `5`。
3. 插入一个对象 `obj2` (内存地址为 `0x2000`)，关联的值为 `20`。假设 `Hash(0x2000)` 的结果是 `7`。

**逻辑推理 (`InsertKey` 方法):**

* **插入 `obj1`:**
    * `hash = 5`, `mask_ = 3` (容量 - 1)
    * `start = 5 & 3 = 1`
    * 检查 `keys_[1]`，假设它是 `not_mapped`。
    * 将 `keys_[1]` 设置为 `0x1000`，`values_[1]` 设置为 `10`。
    * `size_` 增加到 1。
    * 输出: `{index: 1, found: false}`

* **插入 `obj2`:**
    * `hash = 7`, `mask_ = 3`
    * `start = 7 & 3 = 3`
    * 检查 `keys_[3]`，假设它是 `not_mapped`。
    * 将 `keys_[3]` 设置为 `0x2000`，`values_[3]` 设置为 `20`。
    * `size_` 增加到 2。
    * 输出: `{index: 3, found: false}`

**假设输入 (查找):**

查找 `obj1` (内存地址 `0x1000`)。

**逻辑推理 (`Lookup` 方法):**

* `hash = Hash(0x1000) = 5`
* `std::tie(index, found) = ScanKeysFor(0x1000, 5)`
* `start = 5 & 3 = 1`
* 检查 `keys_[1]`，发现它是 `0x1000`。
* 输出: `index = 1`

**涉及用户常见的编程错误 (与概念相关):**

虽然用户通常不会直接操作 `IdentityMapBase`，但理解其原理可以帮助避免与 JavaScript 中类似概念相关的错误，例如在使用 `WeakMap` 时：

1. **误解 `WeakMap` 的键的本质:**  用户可能会错误地认为如果两个对象的内容相同，它们就可以作为 `WeakMap` 的同一个键。实际上，`WeakMap` 依赖于对象的 **身份**。

   ```javascript
   const key1 = { value: 1 };
   const key2 = { value: 1 };
   const weakMap = new WeakMap();

   weakMap.set(key1, "data for key1");
   console.log(weakMap.get(key2)); // 输出 undefined，因为 key1 和 key2 是不同的对象

   ```

2. **忘记 `WeakMap` 的键是弱引用的:**  如果作为 `WeakMap` 键的对象没有其他强引用指向它，垃圾回收器可能会回收该对象，从而导致 `WeakMap` 中相应的条目消失。这与 `IdentityMapBase` 的 GC 处理类似。

3. **在不理解身份语义的情况下使用基于身份的比较:**  在某些场景下，开发者可能会尝试模拟基于身份的映射，但如果对对象身份的理解不正确，可能会导致逻辑错误。

**总结:**

`v8/src/utils/identity-map.cc` 实现了一个高效的、基于对象身份的哈希映射，它在 V8 内部用于管理和查找与特定对象实例关联的数据。它的设计考虑了 V8 的垃圾回收机制，并支持动态调整大小和迭代。虽然用户不会直接操作这个类，但理解其工作原理有助于理解 JavaScript 中 `WeakMap` 等相关概念的行为。

Prompt: 
```
这是目录为v8/src/utils/identity-map.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/utils/identity-map.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2015 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/utils/identity-map.h"

#include "src/base/functional.h"
#include "src/base/logging.h"
#include "src/heap/heap.h"
#include "src/roots/roots-inl.h"

namespace v8 {
namespace internal {

static const int kInitialIdentityMapSize = 4;
static const int kResizeFactor = 2;

IdentityMapBase::~IdentityMapBase() {
  // Clear must be called by the subclass to avoid calling the virtual
  // DeleteArray function from the destructor.
  DCHECK_NULL(keys_);
}

void IdentityMapBase::Clear() {
  if (keys_) {
    DCHECK(!is_iterable());
    DCHECK_NOT_NULL(strong_roots_entry_);
    heap_->UnregisterStrongRoots(strong_roots_entry_);
    DeletePointerArray(reinterpret_cast<uintptr_t*>(keys_), capacity_);
    DeletePointerArray(values_, capacity_);
    keys_ = nullptr;
    strong_roots_entry_ = nullptr;
    values_ = nullptr;
    size_ = 0;
    capacity_ = 0;
    mask_ = 0;
  }
}

void IdentityMapBase::EnableIteration() {
  CHECK(!is_iterable());
  is_iterable_ = true;
}

void IdentityMapBase::DisableIteration() {
  CHECK(is_iterable());
  is_iterable_ = false;
}

std::pair<int, bool> IdentityMapBase::ScanKeysFor(Address address,
                                                  uint32_t hash) const {
  int start = hash & mask_;
  Address not_mapped = ReadOnlyRoots(heap_).not_mapped_symbol().ptr();
  for (int index = start; index < capacity_; index++) {
    if (keys_[index] == address) return {index, true};      // Found.
    if (keys_[index] == not_mapped) return {index, false};  // Not found.
  }
  for (int index = 0; index < start; index++) {
    if (keys_[index] == address) return {index, true};      // Found.
    if (keys_[index] == not_mapped) return {index, false};  // Not found.
  }
  return {-1, false};
}

bool IdentityMapBase::ShouldGrow() const {
  // Grow the map if we reached >= 80% occupancy.
  return size_ + size_ / 4 >= capacity_;
}

std::pair<int, bool> IdentityMapBase::InsertKey(Address address,
                                                uint32_t hash) {
  DCHECK_NE(heap_->gc_state(), Heap::MARK_COMPACT);
  DCHECK_EQ(gc_counter_, heap_->gc_count());

  if (ShouldGrow()) {
    Resize(capacity_ * kResizeFactor);
  }

  Address not_mapped = ReadOnlyRoots(heap_).not_mapped_symbol().ptr();

  int start = hash & mask_;
  // Guaranteed to terminate since size_ < capacity_, there must be at least
  // one empty slot.
  int index = start;
  while (true) {
    if (keys_[index] == address) return {index, true};  // Found.
    if (keys_[index] == not_mapped) {                   // Free entry.
      size_++;
      DCHECK_LE(size_, capacity_);
      keys_[index] = address;
      return {index, false};
    }
    index = (index + 1) & mask_;
    // We should never loop back to the start.
    DCHECK_NE(index, start);
  }
}

bool IdentityMapBase::DeleteIndex(int index, uintptr_t* deleted_value) {
  DCHECK_NE(heap_->gc_state(), Heap::MARK_COMPACT);
  if (deleted_value != nullptr) *deleted_value = values_[index];
  Address not_mapped = ReadOnlyRoots(heap_).not_mapped_symbol().ptr();
  DCHECK_NE(keys_[index], not_mapped);
  keys_[index] = not_mapped;
  values_[index] = 0;
  size_--;
  DCHECK_GE(size_, 0);

  if (capacity_ > kInitialIdentityMapSize &&
      size_ * kResizeFactor < capacity_ / kResizeFactor) {
    Resize(capacity_ / kResizeFactor);
    return true;  // No need to fix collisions as resize reinserts keys.
  }

  // Move any collisions to their new correct location.
  int next_index = index;
  for (;;) {
    next_index = (next_index + 1) & mask_;
    Address key = keys_[next_index];
    if (key == not_mapped) break;

    int expected_index = Hash(key) & mask_;
    if (index < next_index) {
      if (index < expected_index && expected_index <= next_index) continue;
    } else {
      DCHECK_GT(index, next_index);
      if (index < expected_index || expected_index <= next_index) continue;
    }

    DCHECK_EQ(not_mapped, keys_[index]);
    DCHECK_EQ(values_[index], 0);
    std::swap(keys_[index], keys_[next_index]);
    std::swap(values_[index], values_[next_index]);
    index = next_index;
  }

  return true;
}

int IdentityMapBase::Lookup(Address key) const {
  DCHECK_NE(heap_->gc_state(), Heap::MARK_COMPACT);
  uint32_t hash = Hash(key);
  int index;
  bool found;
  std::tie(index, found) = ScanKeysFor(key, hash);
  if (!found && gc_counter_ != heap_->gc_count()) {
    // Miss; rehash if there was a GC, then lookup again.
    const_cast<IdentityMapBase*>(this)->Rehash();
    std::tie(index, found) = ScanKeysFor(key, hash);
  }
  return found ? index : -1;
}

std::pair<int, bool> IdentityMapBase::LookupOrInsert(Address key) {
  DCHECK_NE(heap_->gc_state(), Heap::MARK_COMPACT);
  uint32_t hash = Hash(key);
  // Perform an optimistic lookup.
  int index;
  bool already_exists;
  std::tie(index, already_exists) = ScanKeysFor(key, hash);
  if (!already_exists) {
    // Miss; rehash if there was a GC, then insert.
    if (gc_counter_ != heap_->gc_count()) {
      Rehash();
      index = -1;
    }
    if (index < 0 || ShouldGrow()) {
      std::tie(index, already_exists) = InsertKey(key, hash);
    } else {
      // If rehashing is not necessary, and the table is already big enough,
      // then avoid calling InsertKey because it would search the table again
      // and we already found an adequate location to insert the new key.
      size_++;
      DCHECK_LE(size_, capacity_);
      DCHECK_EQ(keys_[index], ReadOnlyRoots(heap_).not_mapped_symbol().ptr());
      keys_[index] = key;
    }
  }
  DCHECK_GE(index, 0);
  return {index, already_exists};
}

uint32_t IdentityMapBase::Hash(Address address) const {
  CHECK_NE(address, ReadOnlyRoots(heap_).not_mapped_symbol().ptr());
  return static_cast<uint32_t>(hasher_(address));
}

// Searches this map for the given key using the object's address
// as the identity, returning:
//    found => a pointer to the storage location for the value, true
//    not found => a pointer to a new storage location for the value, false
IdentityMapFindResult<uintptr_t> IdentityMapBase::FindOrInsertEntry(
    Address key) {
  DCHECK_NE(heap_->gc_state(), Heap::MARK_COMPACT);
  CHECK(!is_iterable());  // Don't allow insertion while iterable.
  if (capacity_ == 0) {
    return {InsertEntry(key), false};
  }
  auto lookup_result = LookupOrInsert(key);
  return {&values_[lookup_result.first], lookup_result.second};
}

// Searches this map for the given key using the object's address
// as the identity, returning:
//    found => a pointer to the storage location for the value
//    not found => {nullptr}
IdentityMapBase::RawEntry IdentityMapBase::FindEntry(Address key) const {
  DCHECK_NE(heap_->gc_state(), Heap::MARK_COMPACT);
  // Don't allow find by key while iterable (might rehash).
  CHECK(!is_iterable());
  if (size_ == 0) return nullptr;
  int index = Lookup(key);
  return index >= 0 ? &values_[index] : nullptr;
}

// Inserts the given key using the object's address as the identity, returning
// a pointer to the new storage location for the value.
IdentityMapBase::RawEntry IdentityMapBase::InsertEntry(Address key) {
  DCHECK_NE(heap_->gc_state(), Heap::MARK_COMPACT);
  // Don't allow find by key while iterable (might rehash).
  CHECK(!is_iterable());
  if (capacity_ == 0) {
    // Allocate the initial storage for keys and values.
    capacity_ = kInitialIdentityMapSize;
    mask_ = kInitialIdentityMapSize - 1;
    gc_counter_ = heap_->gc_count();

    uintptr_t not_mapped = ReadOnlyRoots(heap_).not_mapped_symbol().ptr();
    keys_ = reinterpret_cast<Address*>(NewPointerArray(capacity_, not_mapped));
    for (int i = 0; i < capacity_; i++) keys_[i] = not_mapped;
    values_ = NewPointerArray(capacity_, 0);

    strong_roots_entry_ =
        heap_->RegisterStrongRoots("IdentityMapBase", FullObjectSlot(keys_),
                                   FullObjectSlot(keys_ + capacity_));
  } else {
    // Rehash if there was a GC, then insert.
    if (gc_counter_ != heap_->gc_count()) Rehash();
  }

  int index;
  bool already_exists;
  std::tie(index, already_exists) = InsertKey(key, Hash(key));
  DCHECK(!already_exists);
  return &values_[index];
}

// Deletes the given key from the map using the object's address as the
// identity, returning true iff the key was found (in which case, the value
// argument will be set to the deleted entry's value).
bool IdentityMapBase::DeleteEntry(Address key, uintptr_t* deleted_value) {
  CHECK(!is_iterable());  // Don't allow deletion by key while iterable.
  if (size_ == 0) return false;
  int index = Lookup(key);
  if (index < 0) return false;  // No entry found.
  return DeleteIndex(index, deleted_value);
}

Address IdentityMapBase::KeyAtIndex(int index) const {
  DCHECK_LE(0, index);
  DCHECK_LT(index, capacity_);
  DCHECK_NE(keys_[index], ReadOnlyRoots(heap_).not_mapped_symbol().ptr());
  CHECK(is_iterable());  // Must be iterable to access by index;
  return keys_[index];
}

IdentityMapBase::RawEntry IdentityMapBase::EntryAtIndex(int index) const {
  DCHECK_LE(0, index);
  DCHECK_LT(index, capacity_);
  DCHECK_NE(keys_[index], ReadOnlyRoots(heap_).not_mapped_symbol().ptr());
  CHECK(is_iterable());  // Must be iterable to access by index;
  return &values_[index];
}

int IdentityMapBase::NextIndex(int index) const {
  DCHECK_LE(-1, index);
  DCHECK_LE(index, capacity_);
  CHECK(is_iterable());  // Must be iterable to access by index;
  Address not_mapped = ReadOnlyRoots(heap_).not_mapped_symbol().ptr();
  for (++index; index < capacity_; ++index) {
    if (keys_[index] != not_mapped) {
      return index;
    }
  }
  return capacity_;
}

void IdentityMapBase::Rehash() {
  DCHECK_NE(heap_->gc_state(), Heap::MARK_COMPACT);
  CHECK(!is_iterable());  // Can't rehash while iterating.
  // Record the current GC counter.
  gc_counter_ = heap_->gc_count();
  // Assume that most objects won't be moved.
  std::vector<std::pair<Address, uintptr_t>> reinsert;
  // Search the table looking for keys that wouldn't be found with their
  // current hashcode and evacuate them.
  int last_empty = -1;
  Address not_mapped = ReadOnlyRoots(heap_).not_mapped_symbol().ptr();
  for (int i = 0; i < capacity_; i++) {
    if (keys_[i] == not_mapped) {
      last_empty = i;
    } else {
      int pos = Hash(keys_[i]) & mask_;
      if (pos <= last_empty || pos > i) {
        // Evacuate an entry that is in the wrong place.
        reinsert.push_back(std::pair<Address, uintptr_t>(keys_[i], values_[i]));
        keys_[i] = not_mapped;
        values_[i] = 0;
        last_empty = i;
        size_--;
      }
    }
  }
  // Reinsert all the key/value pairs that were in the wrong place.
  for (auto pair : reinsert) {
    int index = InsertKey(pair.first, Hash(pair.first)).first;
    DCHECK_GE(index, 0);
    values_[index] = pair.second;
  }
}

void IdentityMapBase::Resize(int new_capacity) {
  DCHECK_NE(heap_->gc_state(), Heap::MARK_COMPACT);
  CHECK(!is_iterable());  // Can't resize while iterating.
  // Resize the internal storage and reinsert all the key/value pairs.
  DCHECK_GT(new_capacity, size_);
  int old_capacity = capacity_;
  Address* old_keys = keys_;
  uintptr_t* old_values = values_;

  capacity_ = new_capacity;
  mask_ = capacity_ - 1;
  gc_counter_ = heap_->gc_count();
  size_ = 0;

  Address not_mapped = ReadOnlyRoots(heap_).not_mapped_symbol().ptr();
  keys_ = reinterpret_cast<Address*>(NewPointerArray(capacity_, not_mapped));
  values_ = NewPointerArray(capacity_, 0);

  for (int i = 0; i < old_capacity; i++) {
    if (old_keys[i] == not_mapped) continue;
    int index = InsertKey(old_keys[i], Hash(old_keys[i])).first;
    DCHECK_GE(index, 0);
    values_[index] = old_values[i];
  }

  // Unregister old keys and register new keys.
  DCHECK_NOT_NULL(strong_roots_entry_);
  heap_->UpdateStrongRoots(strong_roots_entry_, FullObjectSlot(keys_),
                           FullObjectSlot(keys_ + capacity_));

  // Delete old storage;
  DeletePointerArray(reinterpret_cast<uintptr_t*>(old_keys), old_capacity);
  DeletePointerArray(old_values, old_capacity);
}

}  // namespace internal
}  // namespace v8

"""

```