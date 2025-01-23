Response:
Let's break down the thought process for analyzing the C++ header file and answering the request.

**1. Initial Scan and Identification of Core Purpose:**

The first step is a quick read-through to grasp the high-level function. Keywords like "PersistentMap", "hash trees", "persistent map datastructure", "infinite", "default value", "iterators", and complexity analysis immediately jump out. This strongly suggests the core purpose is implementing a persistent, immutable map using a hash tree structure.

**2. Deconstructing the Structure and Key Components:**

Next, I'd examine the class definition (`template <class Key, class Value, class Hasher = base::hash<Key>> class PersistentMap`). This tells me it's a template class, allowing it to store various key-value types. The `Hasher` template parameter indicates the map uses hashing.

Then, I'd look at the private members:

* `kHashBits`:  A constant defining the hash bit length (32 bits). This reinforces the hash tree nature.
* `Bit` enum: Defines `kLeft` and `kRight`, suggesting a binary tree structure.
* `HashValue` class:  Handles accessing individual bits of the hash. The comment about accessing high bits first is important.
* `KeyValue` struct:  A simple key-value pair.
* `FocusedTree` struct: This is a crucial data structure. The comments explaining its purpose (representing a hash tree with a focused path) are key to understanding the implementation. The `path_array` and the surrounding comments about flexible array members are interesting implementation details.
* Private methods: `FindHash`, `GetFocusedValue`, `GetChild`, `FindLeftmost`. These are the core operations for navigating and accessing the hash tree.
* Private data members: `tree_`, `def_value_`, `zone_`. `tree_` is the root of the persistent structure, `def_value_` is the initial default, and `zone_` indicates memory management within V8's `Zone` allocator.

**3. Analyzing Public Interface and Functionality:**

Now, I'd go through the public methods, focusing on what operations the `PersistentMap` supports:

* `last_depth()`:  Provides a size estimate.
* `Get(const Key& key)`: Retrieves a value associated with a key.
* `Set(Key key, Value value)`:  Adds or updates a key-value pair. Crucially, it mentions "overwrite," aligning with the persistent nature (creating a new version).
* `Modify(Key key, F f)`: Allows in-place modification using a function. This is likely used internally by `Set` and demonstrates flexibility.
* `operator==` and `operator!=`: Equality comparison. The comment mentioning O(n) complexity and the TODO about O(1) optimization are noteworthy.
* `iterator`:  Provides forward iteration. The comment about lexicographical order of hash value and key is important.
* `begin()` and `end()`:  Standard iterator access.
* `double_iterator` and `ZipIterable`, `Zip()`:  Enable iterating over two maps simultaneously, useful for comparisons or merging.
* Constructor:  Takes a `Zone*` and an optional `def_value`.

**4. Connecting to JavaScript (If Applicable):**

The request specifically asks about connections to JavaScript. Given that this is in the `v8/src/compiler` directory, the connection isn't direct at the JavaScript language level. Instead, it's an internal data structure used by the V8 compiler.

* **Thinking about compiler use:**  Compilers need to store mappings between various program elements (e.g., variables, function names, types) and their internal representations. The persistence aspect makes it suitable for compiler optimizations and transformations where intermediate states need to be preserved.
* **Example scenario:** Imagine the compiler is tracking the types of variables in a JavaScript function. As the compiler analyzes the code, it might need to update the type information. A `PersistentMap` could store this information. When a change occurs, a new `PersistentMap` with the updated information is created, while the old map remains accessible (due to persistence).

**5. Code Logic Inference and Examples:**

The request asks for logic inference with examples. This involves thinking about how the methods work internally, even without seeing the full implementation details.

* **Assumption:**  The hash function distributes keys reasonably well.
* **`Get()` Example:** If we `Set("a", 1)` and then `Get("a")`, the expected output is `1`. If we `Get("b")` without setting it, the expected output is the `def_value`.
* **`Set()` Example:**  Multiple `Set` calls with the same key will overwrite the value. Due to persistence, earlier versions of the map still hold the old values.
* **Iteration:**  Iterating should produce the key-value pairs in hash order, excluding entries with the default value.

**6. Identifying Common Programming Errors:**

This requires thinking about how users might misuse the `PersistentMap` *if* it were a user-facing data structure (even though it's internal).

* **Assuming mutability:**  A common error with persistent data structures is trying to modify them in place expecting the changes to be reflected in other "instances" of the map.
* **Inefficient hashing:** If the `Hasher` produces poor distributions, performance will suffer due to hash collisions. The comment about dense integers being a bad choice highlights this.
* **Ignoring persistence implications:** Not understanding that `Set` creates a new version of the map can lead to unexpected behavior if you're holding references to old versions.

**7. Addressing Specific Request Points:**

Finally, I'd review the original request and ensure all points are addressed:

* **Functionality list:** Create a clear and concise list of the map's capabilities.
* **`.tq` extension:** Explain that `.tq` signifies Torque code and this file is C++, so it's not Torque.
* **JavaScript connection:**  Provide the indirect connection through the compiler and a relevant example.
* **Logic inference:**  Give input/output examples for `Get` and `Set`.
* **Common errors:**  Illustrate potential pitfalls, even if the structure isn't directly used by end-users.

This systematic approach, combining code analysis, understanding of data structure principles, and consideration of the context within V8, leads to a comprehensive and accurate answer.看起来 `v8/src/compiler/persistent-map.h` 是一个 C++ 头文件，它定义了一个名为 `PersistentMap` 的模板类。根据你的描述，我们来分析一下它的功能：

**`PersistentMap` 的功能：**

1. **持久化 (Persistent) 的 Map 数据结构:**  这是最核心的功能。持久化意味着在更新操作时，不会直接修改原有的数据结构，而是会创建一个新的版本，同时保留旧版本。这类似于函数式编程中的不可变数据结构。

2. **基于哈希树 (Hash Trees) 实现:**  `PersistentMap` 的内部实现使用了哈希树。哈希树是一种利用键的哈希值来组织数据的树形结构，常用于高效地实现持久化数据结构。

3. **概念上无限 (Conceptually Infinite):**  所有可能的键最初都映射到一个默认值。这意味着你可以查询任何键，即使它还没有被显式地添加到 map 中，它会返回默认值。

4. **通过覆盖默认值进行添加/更新:**  向 `PersistentMap` 中添加或更新键值对，实际上是通过将该键的值设置为非默认值来实现的。

5. **通过设置为默认值进行删除:**  从 `PersistentMap` 中删除键值对，实际上是将该键的值重新设置为默认值。

6. **迭代器 (Iterators):**  提供的迭代器只会遍历那些值不是默认值的键值对。

7. **高效的操作复杂度:**
   - **复制和赋值 (Copy and assignment):** O(1)，因为持久化数据结构通常通过共享内部结构来实现高效的复制。
   - **访问 (access):** O(log n)，哈希树的典型访问复杂度。
   - **更新 (update):** O(log n) 的时间和空间，因为更新操作会创建新的节点来表示新的状态。
   - **迭代 (iteration):** 分摊 O(1) 每一步。
   - **Zip (合并):** O(n)，用于合并两个 map。
   - **相等性检查 (equality check):** O(n)，需要比较所有非默认值的键值对。

8. **快速但不完全的相等性检查 (`may_be_unequal`):**  提供了一种优化的相等性检查方式。如果 `may_be_unequal` 返回 `false`，则两个 map 肯定不相等。如果返回 `true`，则需要进行更全面的比较。这可以用于在某些情况下提前排除不相等的 map。

**关于 `.tq` 结尾：**

你提到如果文件以 `.tq` 结尾，则它是 V8 Torque 源代码。 由于 `v8/src/compiler/persistent-map.h` 以 `.h` 结尾，**它是一个 C++ 头文件，而不是 Torque 源代码。** Torque 是一种用于生成 V8 内部代码的领域特定语言。

**与 JavaScript 的关系及示例：**

`PersistentMap` 是 V8 编译器内部使用的数据结构，并不直接暴露给 JavaScript 开发者。然而，它的存在是为了支持 V8 编译器高效地进行代码优化和转换。

我们可以用一个概念性的 JavaScript 例子来理解其行为，但请记住这只是一个类比，JavaScript 中并没有直接对应的 `PersistentMap` 类。

```javascript
// 概念性的 PersistentMap 类比 (并非真实 V8 代码)
class ConceptualPersistentMap {
  constructor(defaultValue) {
    this.data = new Map();
    this.defaultValue = defaultValue;
  }

  get(key) {
    return this.data.has(key) ? this.data.get(key) : this.defaultValue;
  }

  set(key, value) {
    const newMap = new ConceptualPersistentMap(this.defaultValue);
    newMap.data = new Map(this.data); // 浅拷贝
    newMap.data.set(key, value);
    return newMap;
  }

  delete(key) {
    const newMap = new ConceptualPersistentMap(this.defaultValue);
    newMap.data = new Map(this.data); // 浅拷贝
    newMap.data.delete(key);
    return newMap;
  }

  // ... 其他方法
}

const map1 = new ConceptualPersistentMap(undefined);
console.log(map1.get("a")); // 输出: undefined

const map2 = map1.set("a", 1);
console.log(map1.get("a")); // 输出: undefined (map1 没有被修改)
console.log(map2.get("a")); // 输出: 1

const map3 = map2.set("b", 2);
console.log(map2.get("b")); // 输出: undefined
console.log(map3.get("b")); // 输出: 2

const map4 = map3.delete("a");
console.log(map3.get("a")); // 输出: 1
console.log(map4.get("a")); // 输出: undefined
```

在这个 JavaScript 例子中，`set` 和 `delete` 操作不会修改原有的 `map1`，而是返回一个新的 map (`map2`, `map3`, `map4`)，这体现了持久化的概念。 V8 编译器内部使用 `PersistentMap` 来管理编译过程中的一些状态信息，例如类型推断的结果、变量的绑定关系等。

**代码逻辑推理和示例：**

假设我们创建了一个 `PersistentMap<std::string, int>`，默认值为 0。

**假设输入：**

1. 创建一个空的 `PersistentMap<std::string, int>` `map1`。
2. 调用 `map1.Get("hello")`。
3. 调用 `map1.Set("hello", 5)`，得到新的 `map2`。
4. 调用 `map2.Get("hello")`。
5. 调用 `map1.Get("hello")`。
6. 调用 `map2.Set("world", 10)`，得到新的 `map3`。
7. 调用 `map3.Get("world")`。
8. 调用 `map2.Get("world")`。

**预期输出：**

1. `map1.Get("hello")` 输出: `0` (默认值)
2. `map2.Get("hello")` 输出: `5`
3. `map1.Get("hello")` 输出: `0` (map1 未被修改)
4. `map3.Get("world")` 输出: `10`
5. `map2.Get("world")` 输出: `0` (map2 中 "world" 仍然是默认值)

**用户常见的编程错误：**

虽然开发者不会直接使用 `PersistentMap`，但如果理解其背后的持久化概念，可以避免一些在使用类似数据结构时的常见错误：

1. **误以为 `Set` 操作会修改原有的 Map:**  这是使用持久化数据结构最常见的误解。用户可能会认为调用 `Set` 后，之前持有该 Map 引用的变量也会反映新的值。实际上，`Set` 会返回一个新的 Map。

   ```cpp
   // 假设用户错误地认为 PersistentMap 是可变的
   PersistentMap<std::string, int> map1(nullptr, 0);
   map1.Set("key", 10); // 实际上，这应该赋值给一个新的 map 变量

   // map1 仍然是空的，因为 Set 返回了新的 map
   std::cout << map1.Get("key") << std::endl; // 错误地期望输出 10
   ```

   **正确用法：**

   ```cpp
   PersistentMap<std::string, int> map1(nullptr, 0);
   PersistentMap<std::string, int> map2 = map1.Set("key", 10);
   std::cout << map2.Get("key") << std::endl; // 输出 10
   std::cout << map1.Get("key") << std::endl; // 输出 0
   ```

2. **性能问题：过度创建新的 Map 对象:**  虽然复制是 O(1)，但如果在一个循环中频繁地进行 `Set` 操作而不合理地管理这些新的 Map 对象，可能会导致不必要的内存分配和性能开销。

   ```cpp
   PersistentMap<int, int> map(nullptr, 0);
   for (int i = 0; i < 1000; ++i) {
       map.Set(i, i * 2); // 错误：每次 Set 的结果都被丢弃了
   }
   std::cout << map.Get(500) << std::endl; // 仍然是默认值 0
   ```

   **正确用法：**

   ```cpp
   PersistentMap<int, int> map(nullptr, 0);
   for (int i = 0; i < 1000; ++i) {
       map = map.Set(i, i * 2); // 正确：更新 map 变量
   }
   std::cout << map.Get(500) << std::endl; // 输出 1000
   ```

总而言之，`v8/src/compiler/persistent-map.h` 定义了一个用于 V8 编译器内部的持久化哈希 Map 数据结构，它基于哈希树实现，提供了高效的访问和更新操作，并且保持了数据的不可变性。虽然 JavaScript 开发者不会直接使用它，但理解其原理有助于理解 V8 编译器的工作方式以及持久化数据结构的概念。

### 提示词
```
这是目录为v8/src/compiler/persistent-map.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/persistent-map.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```c
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_COMPILER_PERSISTENT_MAP_H_
#define V8_COMPILER_PERSISTENT_MAP_H_

#include <array>
#include <tuple>

#include "src/base/functional.h"
#include "src/zone/zone-containers.h"

namespace v8 {
namespace internal {
namespace compiler {

// A fast and possibly incomplete equality check. If it returns false, the
// values are certainly not equal, otherwise we do not know. The template is
// intended to be specialized for types with expensive equality checks.
template <class T>
struct may_be_unequal {
  bool operator()(const T& a, const T& b) { return a != b; }
};

// PersistentMap is a persistent map datastructure based on hash trees (a binary
// tree using the bits of a hash value as addresses). The map is a conceptually
// infinite: All keys are initially mapped to a default value, values are
// deleted by overwriting them with the default value. The iterators produce
// exactly the keys that are not the default value. The hash values should have
// high variance in their high bits, so dense integers are a bad choice.
// Complexity:
// - Copy and assignment: O(1)
// - access: O(log n)
// - update: O(log n) time and space
// - iteration: amortized O(1) per step
// - Zip: O(n)
// - equality check: O(n)
// TODO(turbofan): Cache map transitions to avoid re-allocation of the same map.
// TODO(turbofan): Implement an O(1) equality check based on hash consing or
//              something similar.
template <class Key, class Value, class Hasher = base::hash<Key>>
class PersistentMap {
 public:
  using key_type = Key;
  using mapped_type = Value;
  using value_type = std::pair<Key, Value>;

 private:
  static constexpr size_t kHashBits = 32;
  enum Bit : int { kLeft = 0, kRight = 1 };

  // Access hash bits starting from the high bits and compare them according to
  // their unsigned value. This way, the order in the hash tree is compatible
  // with numeric hash comparisons.
  class HashValue;

  struct KeyValue : std::pair<Key, Value> {
    const Key& key() const { return this->first; }
    const Value& value() const { return this->second; }
    using std::pair<Key, Value>::pair;
  };

  struct FocusedTree;

  friend struct may_be_unequal<PersistentMap<Key, Value, Hasher>>;

 public:
  // Depth of the last added element. This is a cheap estimate for the size of
  // the hash tree.
  size_t last_depth() const {
    if (tree_) {
      return tree_->length;
    } else {
      return 0;
    }
  }

  const Value& Get(const Key& key) const {
    HashValue key_hash = HashValue(Hasher()(key));
    const FocusedTree* tree = FindHash(key_hash);
    return GetFocusedValue(tree, key);
  }

  // Add or overwrite an existing key-value pair.
  void Set(Key key, Value value);
  // Modify an entry in-place, avoiding repeated search.
  // `F` is a functional that expects a `Value*` parameter to modify it.
  template <class F>
  void Modify(Key key, F f);

  bool operator==(const PersistentMap& other) const {
    if (tree_ == other.tree_) return true;
    if (def_value_ != other.def_value_) return false;
    for (std::tuple<Key, Value, Value> triple : Zip(other)) {
      if (std::get<1>(triple) != std::get<2>(triple)) return false;
    }
    return true;
  }

  bool operator!=(const PersistentMap& other) const {
    return !(*this == other);
  }

  // The iterator produces key-value pairs in the lexicographical order of
  // hash value and key. It produces exactly the key-value pairs where the value
  // is not the default value.
  class iterator;

  iterator begin() const {
    if (!tree_) return end();
    return iterator::begin(tree_, def_value_);
  }
  iterator end() const { return iterator::end(def_value_); }

  // Iterator to traverse two maps in lockstep, producing matching value pairs
  // for each key where at least one value is different from the respective
  // default.
  class double_iterator;

  // An iterable to iterate over the two maps in lockstep.
  struct ZipIterable {
    PersistentMap a;
    PersistentMap b;
    double_iterator begin() { return double_iterator(a.begin(), b.begin()); }
    double_iterator end() { return double_iterator(a.end(), b.end()); }
  };

  ZipIterable Zip(const PersistentMap& other) const { return {*this, other}; }

  explicit PersistentMap(Zone* zone, Value def_value = Value())
      : PersistentMap(nullptr, zone, def_value) {}

 private:
  // Find the {FocusedTree} that contains a key-value pair with key hash {hash}.
  const FocusedTree* FindHash(HashValue hash) const;

  // Find the {FocusedTree} that contains a key-value pair with key hash {hash}.
  // Output the path to this {FocusedTree} and its length. If no such
  // {FocusedTree} exists, return {nullptr} and output the path to the last node
  // with a matching hash prefix. Note that {length} is the length of the found
  // path and may be less than the length of the found {FocusedTree}.
  const FocusedTree* FindHash(HashValue hash,
                              std::array<const FocusedTree*, kHashBits>* path,
                              int* length) const;

  // Load value from the leaf node on the focused path of {tree}.
  const Value& GetFocusedValue(const FocusedTree* tree, const Key& key) const;

  // Return the {FocusedTree} representing the left (bit==kLeft) or right
  // (bit==kRight) child of the node on the path of {tree} at tree level
  // {level}.
  static const FocusedTree* GetChild(const FocusedTree* tree, int level,
                                     Bit bit);

  // Find the leftmost path in the tree, starting at the node at tree level
  // {level} on the path of {start}. Output the level of the leaf to {level} and
  // the path to {path}.
  static const FocusedTree* FindLeftmost(
      const FocusedTree* start, int* level,
      std::array<const FocusedTree*, kHashBits>* path);

  PersistentMap(const FocusedTree* tree, Zone* zone, Value def_value)
      : tree_(tree), def_value_(def_value), zone_(zone) {}

  const FocusedTree* tree_;
  Value def_value_;
  Zone* zone_;
};

template <class Key, class Value, class Hasher>
struct may_be_unequal<PersistentMap<Key, Value, Hasher>> {
  bool operator()(const PersistentMap<Key, Value, Hasher>& a,
                  const PersistentMap<Key, Value, Hasher>& b) {
    return a.tree_ != b.tree_;
  }
};

// This structure represents a hash tree with one focused path to a specific
// leaf. For the focused leaf, it stores key, value and key hash. The path is
// defined by the hash bits of the focused leaf. In a traditional tree
// datastructure, the nodes of a path form a linked list with the values being
// the pointers outside of this path. Instead of storing all of these nodes,
// we store an array of the pointers pointing outside of the path. This is
// similar to the stack used when doing DFS traversal of a tree. The hash of
// the leaf is used to know if the pointers point to the left or the
// right of the path. As there is no explicit representation of a tree node,
// this structure also represents all the nodes on its path. The intended node
// depends on the tree depth, which is always clear from the referencing
// context. So the pointer to a {FocusedTree} stored in the
// {PersistentMap.tree_} always references the root, while a pointer from a
// focused node of another {FocusedTree} always references to one tree level
// lower than before.
template <class Key, class Value, class Hasher>
struct PersistentMap<Key, Value, Hasher>::FocusedTree {
  KeyValue key_value;
  // The depth of the focused path, that is, the number of pointers stored in
  // this structure.
  int8_t length;
  HashValue key_hash;
  // Out-of-line storage for hash collisions.
  const ZoneMap<Key, Value>* more;
  using more_iterator = typename ZoneMap<Key, Value>::const_iterator;
  // {path_array} has to be the last member: To store an array inline, we
  // over-allocate memory for this structure and access memory beyond
  // {path_array}. This corresponds to a flexible array member as defined in
  // C99.
  const FocusedTree* path_array[1];
  const FocusedTree*& path(int i) {
    DCHECK(i < length);
    return reinterpret_cast<const FocusedTree**>(
        reinterpret_cast<uint8_t*>(this) +
        offsetof(FocusedTree, path_array))[i];
  }
  const FocusedTree* path(int i) const {
    DCHECK(i < length);
    return reinterpret_cast<const FocusedTree* const*>(
        reinterpret_cast<const uint8_t*>(this) +
        offsetof(FocusedTree, path_array))[i];
  }
};

template <class Key, class Value, class Hasher>
class PersistentMap<Key, Value, Hasher>::HashValue {
 public:
  explicit HashValue(size_t hash) : bits_(static_cast<uint32_t>(hash)) {}

  Bit operator[](int pos) const {
    DCHECK_LT(pos, kHashBits);
    return bits_ & (static_cast<decltype(bits_)>(1) << (kHashBits - pos - 1))
               ? kRight
               : kLeft;
  }

  bool operator<(HashValue other) const { return bits_ < other.bits_; }
  bool operator==(HashValue other) const { return bits_ == other.bits_; }
  bool operator!=(HashValue other) const { return bits_ != other.bits_; }
  HashValue operator^(HashValue other) const {
    return HashValue(bits_ ^ other.bits_);
  }

 private:
  static_assert(sizeof(uint32_t) * 8 == kHashBits, "wrong type for bits_");
  uint32_t bits_;
};

template <class Key, class Value, class Hasher>
class PersistentMap<Key, Value, Hasher>::iterator {
 public:
  const value_type operator*() const {
    if (current_->more) {
      return *more_iter_;
    } else {
      return current_->key_value;
    }
  }

  iterator& operator++() {
    do {
      if (!current_) {
        // Iterator is past the end.
        return *this;
      }
      if (current_->more) {
        DCHECK(more_iter_ != current_->more->end());
        ++more_iter_;
        if (more_iter_ != current_->more->end()) return *this;
      }
      if (level_ == 0) {
        *this = end(def_value_);
        return *this;
      }
      --level_;
      while (current_->key_hash[level_] == kRight || path_[level_] == nullptr) {
        if (level_ == 0) {
          *this = end(def_value_);
          return *this;
        }
        --level_;
      }
      const FocusedTree* first_right_alternative = path_[level_];
      level_++;
      current_ = FindLeftmost(first_right_alternative, &level_, &path_);
      if (current_->more) {
        more_iter_ = current_->more->begin();
      }
    } while (!((**this).second != def_value()));
    return *this;
  }

  bool operator==(const iterator& other) const {
    if (is_end()) return other.is_end();
    if (other.is_end()) return false;
    if (current_->key_hash != other.current_->key_hash) {
      return false;
    } else {
      return (**this).first == (*other).first;
    }
  }
  bool operator!=(const iterator& other) const { return !(*this == other); }

  bool operator<(const iterator& other) const {
    if (is_end()) return false;
    if (other.is_end()) return true;
    if (current_->key_hash == other.current_->key_hash) {
      return (**this).first < (*other).first;
    } else {
      return current_->key_hash < other.current_->key_hash;
    }
  }

  bool is_end() const { return current_ == nullptr; }

  const Value& def_value() { return def_value_; }

  static iterator begin(const FocusedTree* tree, Value def_value) {
    iterator i(def_value);
    i.current_ = FindLeftmost(tree, &i.level_, &i.path_);
    if (i.current_->more) {
      i.more_iter_ = i.current_->more->begin();
    }
    // Skip entries with default value. PersistentMap iterators must never point
    // to a default value.
    while (!i.is_end() && !((*i).second != def_value)) ++i;
    return i;
  }

  static iterator end(Value def_value) { return iterator(def_value); }

 private:
  int level_;
  typename FocusedTree::more_iterator more_iter_;
  const FocusedTree* current_;
  std::array<const FocusedTree*, kHashBits> path_;
  Value def_value_;

  explicit iterator(Value def_value)
      : level_(0), current_(nullptr), def_value_(def_value) {}
};

template <class Key, class Value, class Hasher>
class PersistentMap<Key, Value, Hasher>::double_iterator {
 public:
  std::tuple<Key, Value, Value> operator*() {
    if (first_current_) {
      auto pair = *first_;
      return std::make_tuple(
          pair.first, pair.second,
          second_current_ ? (*second_).second : second_.def_value());
    } else {
      DCHECK(second_current_);
      auto pair = *second_;
      return std::make_tuple(pair.first, first_.def_value(), pair.second);
    }
  }

  double_iterator& operator++() {
#ifdef DEBUG
    iterator old_first = first_;
    iterator old_second = second_;
#endif
    if (first_current_) {
      ++first_;
      DCHECK(old_first < first_);
    }
    if (second_current_) {
      ++second_;
      DCHECK(old_second < second_);
    }
    return *this = double_iterator(first_, second_);
  }

  double_iterator(iterator first, iterator second)
      : first_(first), second_(second) {
    if (first_ == second_) {
      first_current_ = second_current_ = true;
    } else if (first_ < second_) {
      first_current_ = true;
      second_current_ = false;
    } else {
      DCHECK(second_ < first_);
      first_current_ = false;
      second_current_ = true;
    }
  }

  bool operator!=(const double_iterator& other) {
    return first_ != other.first_ || second_ != other.second_;
  }

  bool is_end() const { return first_.is_end() && second_.is_end(); }

 private:
  iterator first_;
  iterator second_;
  bool first_current_;
  bool second_current_;
};

template <class Key, class Value, class Hasher>
void PersistentMap<Key, Value, Hasher>::Set(Key key, Value new_value) {
  Modify(key, [&](Value* value) { *value = std::move(new_value); });
}

template <class Key, class Value, class Hasher>
template <class F>
void PersistentMap<Key, Value, Hasher>::Modify(Key key, F f) {
  static_assert(std::is_void_v<decltype(f(std::declval<Value*>()))>);
  HashValue key_hash = HashValue(Hasher()(key));
  std::array<const FocusedTree*, kHashBits> path;
  int length = 0;
  const FocusedTree* old = FindHash(key_hash, &path, &length);
  ZoneMap<Key, Value>* more = nullptr;
  const Value& old_value = GetFocusedValue(old, key);
  Value new_value = old_value;
  f(&new_value);
  if (!may_be_unequal<Value>()(old_value, new_value)) return;
  if (old && !(old->more == nullptr && old->key_value.key() == key)) {
    more = zone_->New<ZoneMap<Key, Value>>(zone_);
    if (old->more) {
      *more = *old->more;
    } else {
      more->erase(old->key_value.key());
      more->emplace(old->key_value.key(), old->key_value.value());
    }
    more->erase(key);
    more->emplace(key, new_value);
  }
  size_t size = sizeof(FocusedTree) +
                std::max(0, length - 1) * sizeof(const FocusedTree*);
  FocusedTree* tree = new (zone_->Allocate<FocusedTree>(size))
      FocusedTree{KeyValue(std::move(key), std::move(new_value)),
                  static_cast<int8_t>(length),
                  key_hash,
                  more,
                  {}};
  for (int i = 0; i < length; ++i) {
    tree->path(i) = path[i];
  }
  *this = PersistentMap(tree, zone_, def_value_);
}

template <class Key, class Value, class Hasher>
const typename PersistentMap<Key, Value, Hasher>::FocusedTree*
PersistentMap<Key, Value, Hasher>::FindHash(HashValue hash) const {
  const FocusedTree* tree = tree_;
  int level = 0;
  while (tree && hash != tree->key_hash) {
    while ((hash ^ tree->key_hash)[level] == 0) {
      ++level;
    }
    tree = level < tree->length ? tree->path(level) : nullptr;
    ++level;
  }
  return tree;
}

template <class Key, class Value, class Hasher>
const typename PersistentMap<Key, Value, Hasher>::FocusedTree*
PersistentMap<Key, Value, Hasher>::FindHash(
    HashValue hash, std::array<const FocusedTree*, kHashBits>* path,
    int* length) const {
  const FocusedTree* tree = tree_;
  int level = 0;
  while (tree && hash != tree->key_hash) {
    int map_length = tree->length;
    while ((hash ^ tree->key_hash)[level] == 0) {
      (*path)[level] = level < map_length ? tree->path(level) : nullptr;
      ++level;
    }
    (*path)[level] = tree;
    tree = level < tree->length ? tree->path(level) : nullptr;
    ++level;
  }
  if (tree) {
    while (level < tree->length) {
      (*path)[level] = tree->path(level);
      ++level;
    }
  }
  *length = level;
  return tree;
}

template <class Key, class Value, class Hasher>
const Value& PersistentMap<Key, Value, Hasher>::GetFocusedValue(
    const FocusedTree* tree, const Key& key) const {
  if (!tree) {
    return def_value_;
  }
  if (tree->more) {
    auto it = tree->more->find(key);
    if (it == tree->more->end())
      return def_value_;
    else
      return it->second;
  } else {
    if (key == tree->key_value.key()) {
      return tree->key_value.value();
    } else {
      return def_value_;
    }
  }
}

template <class Key, class Value, class Hasher>
const typename PersistentMap<Key, Value, Hasher>::FocusedTree*
PersistentMap<Key, Value, Hasher>::GetChild(const FocusedTree* tree, int level,
                                            Bit bit) {
  if (tree->key_hash[level] == bit) {
    return tree;
  } else if (level < tree->length) {
    return tree->path(level);
  } else {
    return nullptr;
  }
}

template <class Key, class Value, class Hasher>
const typename PersistentMap<Key, Value, Hasher>::FocusedTree*
PersistentMap<Key, Value, Hasher>::FindLeftmost(
    const FocusedTree* start, int* level,
    std::array<const FocusedTree*, kHashBits>* path) {
  const FocusedTree* current = start;
  while (*level < current->length) {
    if (const FocusedTree* left_child = GetChild(current, *level, kLeft)) {
      (*path)[*level] = GetChild(current, *level, kRight);
      current = left_child;
      ++*level;
    } else if (const FocusedTree* right_child =
                   GetChild(current, *level, kRight)) {
      (*path)[*level] = GetChild(current, *level, kLeft);
      current = right_child;
      ++*level;
    } else {
      UNREACHABLE();
    }
  }
  return current;
}

template <class Key, class Value, class Hasher>
std::ostream& operator<<(std::ostream& os,
                         const PersistentMap<Key, Value, Hasher>& map) {
  os << "{";
  bool first = true;
  for (auto pair : map) {
    if (!first) os << ", ";
    first = false;
    os << pair.first << ": " << pair.second;
  }
  return os << "}";
}

}  // namespace compiler
}  // namespace internal
}  // namespace v8

#endif  // V8_COMPILER_PERSISTENT_MAP_H_
```