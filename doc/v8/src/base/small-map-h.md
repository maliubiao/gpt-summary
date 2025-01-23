Response:
Let's break down the thought process to analyze the `small-map.h` file.

1. **Identify the Core Purpose:** The initial comments are crucial. They state, "SmallMap is a container with a std::map-like interface. It starts out backed by an unsorted array but switches to some other container type if it grows beyond this fixed size." This immediately tells us the central idea: optimization for small maps by avoiding heap allocation.

2. **Analyze the "PROS" and "CONS":**  These sections highlight the trade-offs. Pros: memory locality, low overhead for small maps, handles large maps. Cons: larger code size. This suggests the implementation will have two different code paths.

3. **Examine "IMPORTANT NOTES":** The invalidation of iterators across mutations is a key characteristic to understand and can lead to common programming errors.

4. **Understand the "DETAILS":**  The explanation of how the comparator is handled (especially the difference between `std::map` and `std::unordered_map`) gives insight into the template design and potential performance considerations. The example of using `std::equal_to` is also important.

5. **Deconstruct the "USAGE" section:** This is vital for understanding the template parameters: `NormalMap`, `kArraySize`, `EqualKey`, and `MapInit`. Each parameter's purpose is clearly defined. The example with `SmallMap<std::map<string, int>> days;` provides a concrete usage scenario.

6. **Dive into the `internal` namespace:**
    * **`SmallMapDefaultInit`:**  This simple functor suggests a default way to initialize the underlying `NormalMap`.
    * **`has_key_equal`:** This template metaprogramming construct is designed to detect if the `NormalMap` has a `key_equal` member. The `sml`/`big` trick is a common C++ technique for compile-time type introspection using `sizeof`.
    * **`select_equal_key`:** This template uses the result of `has_key_equal` to select the appropriate equality comparison mechanism. It handles cases where `key_equal` exists and where it doesn't (using the less-than operator for equality).

7. **Scrutinize the `SmallMap` class template:**
    * **Template Parameters:**  Confirm the understanding from the "USAGE" section.
    * **`kUsingFullMapSentinel`:** Recognize this as a flag to indicate when the `SmallMap` has switched to the full map implementation.
    * **Type Definitions:** Identify the common map-like type aliases.
    * **Constructors and Assignment Operators:** Notice the `V8_NOEXCEPT` and the handling of copying and assignment, including the optimization potential mentioned in the comments.
    * **Destructor:**  Ensure proper cleanup of either the array or the map.
    * **Iterators:** Analyze the implementation of `iterator` and `const_iterator`. Observe how they handle both the array and the map cases. The constructors, increment/decrement operators, and dereferencing are key.
    * **`find`:**  See the two versions (const and non-const) and how they switch between array linear search and the underlying map's `find`.
    * **`operator[]`:** Focus on the insertion logic, the backward search in the array, and the call to `ConvertToRealMap` when the array is full.
    * **`insert` (various overloads):**  Similar logic to `operator[]`, handling both array and map scenarios, including the `ConvertToRealMap` call.
    * **`emplace` and `try_emplace`:** Understand how they forward arguments for efficient in-place construction.
    * **`begin` and `end`:**  Implementations for both array and map cases.
    * **`clear`:**  Destruction of elements in either the array or the map.
    * **`erase`:** Handling erasure in both array and map modes, including the potential need to move elements in the array.
    * **`count`, `size`, `empty`:** Simple delegation to either the array or the map.
    * **`UsingFullMap`, `map`:** Accessors to check the internal state and get a pointer to the underlying map.
    * **Private Members:**
        * **`size_`:**  The crucial counter and flag.
        * **`functor_`:**  Stores the map initialization functor.
        * **`union`:** The clever use of a union to save space.
    * **`ConvertToRealMap`:** The core logic for transitioning from the array to the full map. Pay attention to the use of a temporary storage and placement new.
    * **`InitFrom` and `Destroy`:** Helper methods for copy/move operations.

8. **Synthesize the Information:** Based on the detailed analysis, formulate the functional description, identify potential Torque usage, relate to JavaScript, create code examples, and highlight common errors. This involves connecting the individual pieces of the code to the broader purpose and usage scenarios. For example, recognizing that iterator invalidation is a consequence of the dual-mode implementation.

9. **Refine and Organize:**  Structure the analysis logically with clear headings and examples. Ensure that the language is precise and addresses all aspects of the prompt.

**(Self-Correction during the process):**  Initially, I might have just skimmed the iterator implementation. But realizing the "Iterators are invalidated across mutations" note, I would go back and carefully analyze how the iterators work in both array and map modes to understand *why* they are invalidated during transitions. Similarly, I'd initially assume the comparison logic is simple, but the `internal` namespace section on `select_equal_key` reveals a more nuanced approach, prompting a deeper look. The union is a key optimization; recognizing its purpose is crucial. Finally, ensuring the JavaScript example directly relates to the concept of a map or dictionary is important for demonstrating the connection.
This header file `v8/src/base/small-map.h` defines a container called `SmallMap` in the `v8::base` namespace. Here's a breakdown of its functionality:

**Core Functionality of `SmallMap`:**

* **Optimized for Small Maps:** `SmallMap` is designed to be efficient for containers with a small number of elements. It achieves this by initially storing elements in a fixed-size array directly within the `SmallMap` object itself, avoiding dynamic memory allocation on the heap for these initial elements.

* **Fallback to a Full Map:** When the number of elements exceeds the fixed array size (`kArraySize`), `SmallMap` automatically transitions to using a standard map implementation (specified by the `NormalMap` template parameter, often `std::map` or `std::unordered_map`). This prevents the performance degradation that would occur if a simple array was used for a large number of elements.

* **`std::map`-like Interface:** `SmallMap` provides an interface similar to `std::map`, including methods like `insert`, `find`, `operator[]`, `erase`, `begin`, `end`, `size`, `empty`, etc. This makes it easy to use as a drop-in replacement for `std::map` in scenarios where small map sizes are common.

* **Customizable Comparator:**  It allows you to specify a custom comparator (`EqualKey`) for comparing keys. By default, it intelligently uses the `key_equal` member of the underlying `NormalMap` if available (like in `std::unordered_map`), otherwise it defaults to comparing using the less-than operator from `key_compare` (like in `std::map`).

* **Customizable Initialization:**  The `MapInit` functor allows you to customize how the underlying `NormalMap` is initialized when the `SmallMap` grows beyond the initial array size.

**If `v8/src/base/small-map.h` ended with `.tq`:**

Then it would indeed be a **V8 Torque source code file**. Torque is V8's domain-specific language for writing performance-critical parts of the JavaScript engine. Torque code is typically used for implementing built-in functions, runtime functions, and object model logic.

**Relationship with JavaScript Functionality:**

`SmallMap` is a low-level utility class within the V8 engine's codebase. While it doesn't directly correspond to a specific JavaScript language feature, it's used internally to implement various aspects of JavaScript's object model and built-in objects.

**Example Scenario:**

Imagine V8 needs to store a small, temporary mapping of string identifiers to some internal values during the compilation or execution of JavaScript code. `SmallMap` would be a suitable choice here. For instance, it could be used to store:

* **Properties of a small object:** If an object has only a few properties, V8 might use a `SmallMap` to store these properties before potentially transitioning to a more complex representation for objects with many properties.
* **Local variables in a function:**  During the execution of a function, a `SmallMap` could be used to keep track of local variable names and their corresponding memory locations.

**JavaScript Example (Illustrative, not a direct mapping):**

While `SmallMap` isn't directly exposed to JavaScript, its concept is related to how JavaScript engines internally manage objects and their properties.

```javascript
// Internally, V8 might use something conceptually similar to SmallMap
// for small objects.

const smallObject = {
  a: 10,
  b: "hello",
  c: true
};

// Accessing properties is similar to how you'd interact with a map
console.log(smallObject.a);
console.log(smallObject.b);

// Adding a new property
smallObject.d = [1, 2, 3];

// If the object remains small, the underlying implementation
// might be optimized, similar to how SmallMap works.
```

**Code Logic Reasoning with Assumptions:**

**Assumption:** We are using `SmallMap` with `std::map<std::string, int>` as `NormalMap` and `kArraySize` is 4.

**Input:**

1. `SmallMap<std::map<std::string, int>, 4> myMap;` (Creates an empty `SmallMap`)
2. `myMap["one"] = 1;`
3. `myMap["two"] = 2;`
4. `myMap["three"] = 3;`
5. `myMap["four"] = 4;`
6. `myMap["five"] = 5;`

**Output and Reasoning:**

*   **After step 4:** The `myMap` will have 4 elements ("one", "two", "three", "four") stored in its internal array. `myMap.size()` will be 4. `myMap.UsingFullMap()` will be `false`.
*   **After step 5:** When we try to insert "five", the `SmallMap` will detect that its internal array is full (`size_ == kArraySize`). It will then:
    1. Allocate memory for a `std::map<std::string, int>`.
    2. Move the existing four elements from the internal array into the newly created `std::map`.
    3. Insert the new element ("five", 5) into the `std::map`.
    4. `myMap.size()` will be 5.
    5. `myMap.UsingFullMap()` will become `true`. Subsequent operations will be delegated to the underlying `std::map`.

**Common Programming Errors Involving `SmallMap` (Conceptual, as it's an internal class):**

While developers don't directly interact with `SmallMap` in their JavaScript code, understanding its behavior can help with understanding potential performance implications in V8. If a similar pattern was exposed directly, common errors would include:

1. **Iterators Invalidated After Mutations:** The documentation explicitly states that iterators are invalidated across mutations (insert, erase, potentially `operator[]`). A common mistake would be to iterate through a `SmallMap` and modify it within the loop without taking this invalidation into account.

    ```c++
    // Potential error if SmallMap was directly used
    v8::base::SmallMap<std::map<int, int>, 4> myMap;
    // ... populate myMap ...

    for (auto it = myMap.begin(); it != myMap.end(); ++it) {
        if (it->first % 2 == 0) {
            // Inserting here might invalidate 'it'
            myMap.insert({it->first + 1, it->second * 2});
        }
    }
    ```

2. **Assuming Consistent Performance Characteristics:**  A developer might make assumptions about the performance of operations based on the initial small array behavior and be surprised by the performance characteristics after the transition to the full map. For example, lookups in the initial array are likely faster than lookups in a `std::map` due to the simpler linear search.

3. **Incorrectly Estimating `kArraySize`:** If a developer could configure `kArraySize`, choosing a value that is too small could lead to frequent transitions to the full map, potentially negating the benefits of the small array optimization. Conversely, choosing a value that is too large could waste memory for maps that remain small.

In summary, `v8/src/base/small-map.h` provides a memory-efficient container optimized for small collections, falling back to a standard map implementation when needed. It's a crucial internal building block for V8's efficient execution of JavaScript.

### 提示词
```
这是目录为v8/src/base/small-map.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/base/small-map.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```c
// Copyright 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Copyright 2023 the V8 project authors. All rights reserved.
// This file is a clone of "base/containers/small_map.h" in chromium.
// Keep in sync, especially when fixing bugs.

#ifndef V8_BASE_SMALL_MAP_H_
#define V8_BASE_SMALL_MAP_H_

#include "src/base/macros.h"

namespace v8::base {

// SmallMap is a container with a std::map-like interface. It starts out backed
// by an unsorted array but switches to some other container type if it grows
// beyond this fixed size.
//
// PROS
//
//  - Good memory locality and low overhead for smaller maps.
//  - Handles large maps without the degenerate performance of an array.
//
// CONS
//
//  - Larger code size than the alternatives.
//
// IMPORTANT NOTES
//
//  - Iterators are invalidated across mutations.
//
// DETAILS
//
// SmallMap will pick up the comparator from the underlying map type. In
// std::map only a "less" operator is defined, which requires us to do two
// comparisons per element when doing the brute-force search in the simple
// array. std::unordered_map has a key_equal function which will be used.
//
// We define default overrides for the common map types to avoid this
// double-compare, but you should be aware of this if you use your own operator<
// for your map and supply your own version of == to the SmallMap. You can use
// regular operator== by just doing:
//
//   SmallMap<std::map<MyKey, MyValue>, 4, std::equal_to<MyKey>>
//
//
// USAGE
// -----
//
// NormalMap:  The map type to fall back to. This also defines the key and value
//             types for the SmallMap.
// kArraySize:  The size of the initial array of results. This will be allocated
//              with the SmallMap object rather than separately on the heap.
//              Once the map grows beyond this size, the map type will be used
//              instead.
// EqualKey:  A functor which tests two keys for equality. If the wrapped map
//            type has a "key_equal" member (unordered_map does), then that will
//            be used by default. If the wrapped map type has a strict weak
//            ordering "key_compare" (std::map does), that will be used to
//            implement equality by default.
// MapInit: A functor that takes a NormalMap* and uses it to initialize the map.
//          This functor will be called at most once per SmallMap, when the map
//          exceeds the threshold of kArraySize and we are about to copy values
//          from the array to the map. The functor *must* initialize the
//          NormalMap* argument with placement new, since after it runs we
//          assume that the NormalMap has been initialized.
//
// Example:
//   SmallMap<std::map<string, int>> days;
//   days["sunday"   ] = 0;
//   days["monday"   ] = 1;
//   days["tuesday"  ] = 2;
//   days["wednesday"] = 3;
//   days["thursday" ] = 4;
//   days["friday"   ] = 5;
//   days["saturday" ] = 6;

namespace internal {

template <typename NormalMap>
class SmallMapDefaultInit {
 public:
  void operator()(NormalMap* map) const { new (map) NormalMap(); }
};

// has_key_equal<M>::value is true iff there exists a type M::key_equal. This is
// used to dispatch to one of the select_equal_key<> metafunctions below.
template <typename M>
struct has_key_equal {
  typedef char sml;  // "small" is sometimes #defined so we use an abbreviation.
  typedef struct {
    char dummy[2];
  } big;
  // Two functions, one accepts types that have a key_equal member, and one that
  // accepts anything. They each return a value of a different size, so we can
  // determine at compile-time which function would have been called.
  template <typename U>
  static big test(typename U::key_equal*);
  template <typename>
  static sml test(...);
  // Determines if M::key_equal exists by looking at the size of the return
  // type of the compiler-chosen test() function.
  static const bool value = (sizeof(test<M>(0)) == sizeof(big));
};
template <typename M>
const bool has_key_equal<M>::value;

// Base template used for map types that do NOT have an M::key_equal member,
// e.g., std::map<>. These maps have a strict weak ordering comparator rather
// than an equality functor, so equality will be implemented in terms of that
// comparator.
//
// There's a partial specialization of this template below for map types that do
// have an M::key_equal member.
template <typename M, bool has_key_equal_value>
struct select_equal_key {
  struct equal_key {
    bool operator()(const typename M::key_type& left,
                    const typename M::key_type& right) {
      // Implements equality in terms of a strict weak ordering comparator.
      typename M::key_compare comp;
      return !comp(left, right) && !comp(right, left);
    }
  };
};

// Partial template specialization handles case where M::key_equal exists, e.g.,
// unordered_map<>.
template <typename M>
struct select_equal_key<M, true> {
  typedef typename M::key_equal equal_key;
};

}  // namespace internal

template <typename NormalMap, size_t kArraySize = 4,
          typename EqualKey = typename internal::select_equal_key<
              NormalMap, internal::has_key_equal<NormalMap>::value>::equal_key,
          typename MapInit = internal::SmallMapDefaultInit<NormalMap>>
class SmallMap {
  static constexpr size_t kUsingFullMapSentinel =
      std::numeric_limits<size_t>::max();

  static_assert(kArraySize > 0, "Initial size must be greater than 0");
  static_assert(kArraySize != kUsingFullMapSentinel,
                "Initial size out of range");

 public:
  typedef typename NormalMap::key_type key_type;
  typedef typename NormalMap::mapped_type data_type;
  typedef typename NormalMap::mapped_type mapped_type;
  typedef typename NormalMap::value_type value_type;
  typedef EqualKey key_equal;

  SmallMap() : size_(0), functor_(MapInit()) {}

  explicit SmallMap(const MapInit& functor) : size_(0), functor_(functor) {}

  // Allow copy-constructor and assignment, since STL allows them too.
  SmallMap(const SmallMap& src) V8_NOEXCEPT {
    // size_ and functor_ are initted in InitFrom()
    InitFrom(src);
  }

  void operator=(const SmallMap& src) V8_NOEXCEPT {
    if (&src == this) return;

    // This is not optimal. If src and dest are both using the small array, we
    // could skip the teardown and reconstruct. One problem to be resolved is
    // that the value_type itself is pair<const K, V>, and const K is not
    // assignable.
    Destroy();
    InitFrom(src);
  }

  ~SmallMap() { Destroy(); }

  class const_iterator;

  class iterator {
   public:
    typedef typename NormalMap::iterator::iterator_category iterator_category;
    typedef typename NormalMap::iterator::value_type value_type;
    typedef typename NormalMap::iterator::difference_type difference_type;
    typedef typename NormalMap::iterator::pointer pointer;
    typedef typename NormalMap::iterator::reference reference;

    V8_INLINE iterator() : array_iter_(nullptr) {}

    V8_INLINE iterator& operator++() {
      if (array_iter_ != nullptr) {
        ++array_iter_;
      } else {
        ++map_iter_;
      }
      return *this;
    }

    V8_INLINE iterator operator++(int /*unused*/) {
      iterator result(*this);
      ++(*this);
      return result;
    }

    V8_INLINE iterator& operator--() {
      if (array_iter_ != nullptr) {
        --array_iter_;
      } else {
        --map_iter_;
      }
      return *this;
    }

    V8_INLINE iterator operator--(int /*unused*/) {
      iterator result(*this);
      --(*this);
      return result;
    }

    V8_INLINE value_type* operator->() const {
      return array_iter_ ? array_iter_ : map_iter_.operator->();
    }

    V8_INLINE value_type& operator*() const {
      return array_iter_ ? *array_iter_ : *map_iter_;
    }

    V8_INLINE bool operator==(const iterator& other) const {
      if (array_iter_ != nullptr) {
        return array_iter_ == other.array_iter_;
      } else {
        return other.array_iter_ == nullptr && map_iter_ == other.map_iter_;
      }
    }

    V8_INLINE bool operator!=(const iterator& other) const {
      return !(*this == other);
    }

   private:
    friend class SmallMap;
    friend class const_iterator;
    V8_INLINE explicit iterator(value_type* init) : array_iter_(init) {}
    V8_INLINE explicit iterator(const typename NormalMap::iterator& init)
        : array_iter_(nullptr), map_iter_(init) {}

    value_type* array_iter_;
    typename NormalMap::iterator map_iter_;
  };

  class const_iterator {
   public:
    typedef
        typename NormalMap::const_iterator::iterator_category iterator_category;
    typedef typename NormalMap::const_iterator::value_type value_type;
    typedef typename NormalMap::const_iterator::difference_type difference_type;
    typedef typename NormalMap::const_iterator::pointer pointer;
    typedef typename NormalMap::const_iterator::reference reference;

    V8_INLINE const_iterator() : array_iter_(nullptr) {}

    // Non-explicit constructor lets us convert regular iterators to const
    // iterators.
    V8_INLINE const_iterator(const iterator& other)
        : array_iter_(other.array_iter_), map_iter_(other.map_iter_) {}

    V8_INLINE const_iterator& operator++() {
      if (array_iter_ != nullptr) {
        ++array_iter_;
      } else {
        ++map_iter_;
      }
      return *this;
    }

    V8_INLINE const_iterator operator++(int /*unused*/) {
      const_iterator result(*this);
      ++(*this);
      return result;
    }

    V8_INLINE const_iterator& operator--() {
      if (array_iter_ != nullptr) {
        --array_iter_;
      } else {
        --map_iter_;
      }
      return *this;
    }

    V8_INLINE const_iterator operator--(int /*unused*/) {
      const_iterator result(*this);
      --(*this);
      return result;
    }

    V8_INLINE const value_type* operator->() const {
      return array_iter_ ? array_iter_ : map_iter_.operator->();
    }

    V8_INLINE const value_type& operator*() const {
      return array_iter_ ? *array_iter_ : *map_iter_;
    }

    V8_INLINE bool operator==(const const_iterator& other) const {
      if (array_iter_ != nullptr) {
        return array_iter_ == other.array_iter_;
      }
      return other.array_iter_ == nullptr && map_iter_ == other.map_iter_;
    }

    V8_INLINE bool operator!=(const const_iterator& other) const {
      return !(*this == other);
    }

   private:
    friend class SmallMap;
    V8_INLINE explicit const_iterator(const value_type* init)
        : array_iter_(init) {}
    V8_INLINE explicit const_iterator(
        const typename NormalMap::const_iterator& init)
        : array_iter_(nullptr), map_iter_(init) {}

    const value_type* array_iter_;
    typename NormalMap::const_iterator map_iter_;
  };

  iterator find(const key_type& key) {
    key_equal compare;

    if (UsingFullMap()) {
      return iterator(map()->find(key));
    }

    for (size_t i = 0; i < size_; ++i) {
      if (compare(array_[i].first, key)) {
        return iterator(array_ + i);
      }
    }
    return iterator(array_ + size_);
  }

  const_iterator find(const key_type& key) const {
    key_equal compare;

    if (UsingFullMap()) {
      return const_iterator(map()->find(key));
    }

    for (size_t i = 0; i < size_; ++i) {
      if (compare(array_[i].first, key)) {
        return const_iterator(array_ + i);
      }
    }
    return const_iterator(array_ + size_);
  }

  // Invalidates iterators.
  data_type& operator[](const key_type& key) {
    key_equal compare;

    if (UsingFullMap()) {
      return map_[key];
    }

    // Search backwards to favor recently-added elements.
    for (size_t i = size_; i > 0; --i) {
      const size_t index = i - 1;
      if (compare(array_[index].first, key)) {
        return array_[index].second;
      }
    }

    if (V8_UNLIKELY(size_ == kArraySize)) {
      ConvertToRealMap();
      return map_[key];
    }

    DCHECK(size_ < kArraySize);
    new (&array_[size_]) value_type(key, data_type());
    return array_[size_++].second;
  }

  // Invalidates iterators.
  std::pair<iterator, bool> insert(const value_type& x) {
    key_equal compare;

    if (UsingFullMap()) {
      std::pair<typename NormalMap::iterator, bool> ret = map_.insert(x);
      return std::make_pair(iterator(ret.first), ret.second);
    }

    for (size_t i = 0; i < size_; ++i) {
      if (compare(array_[i].first, x.first)) {
        return std::make_pair(iterator(array_ + i), false);
      }
    }

    if (V8_UNLIKELY(size_ == kArraySize)) {
      ConvertToRealMap();  // Invalidates all iterators!
      std::pair<typename NormalMap::iterator, bool> ret = map_.insert(x);
      return std::make_pair(iterator(ret.first), ret.second);
    }

    DCHECK(size_ < kArraySize);
    new (&array_[size_]) value_type(x);
    return std::make_pair(iterator(array_ + size_++), true);
  }

  // Invalidates iterators.
  template <class InputIterator>
  void insert(InputIterator f, InputIterator l) {
    while (f != l) {
      insert(*f);
      ++f;
    }
  }

  // Invalidates iterators.
  template <typename... Args>
  std::pair<iterator, bool> emplace(Args&&... args) {
    key_equal compare;

    if (UsingFullMap()) {
      std::pair<typename NormalMap::iterator, bool> ret =
          map_.emplace(std::forward<Args>(args)...);
      return std::make_pair(iterator(ret.first), ret.second);
    }

    value_type x(std::forward<Args>(args)...);
    for (size_t i = 0; i < size_; ++i) {
      if (compare(array_[i].first, x.first)) {
        return std::make_pair(iterator(array_ + i), false);
      }
    }

    if (V8_UNLIKELY(size_ == kArraySize)) {
      ConvertToRealMap();  // Invalidates all iterators!
      std::pair<typename NormalMap::iterator, bool> ret =
          map_.emplace(std::move(x));
      return std::make_pair(iterator(ret.first), ret.second);
    }

    DCHECK(size_ < kArraySize);
    new (&array_[size_]) value_type(std::move(x));
    return std::make_pair(iterator(array_ + size_++), true);
  }

  // Invalidates iterators.
  template <typename... Args>
  std::pair<iterator, bool> try_emplace(const key_type& key, Args&&... args) {
    key_equal compare;

    if (UsingFullMap()) {
      std::pair<typename NormalMap::iterator, bool> ret =
          map_.try_emplace(key, std::forward<Args>(args)...);
      return std::make_pair(iterator(ret.first), ret.second);
    }

    for (size_t i = 0; i < size_; ++i) {
      if (compare(array_[i].first, key)) {
        return std::make_pair(iterator(array_ + i), false);
      }
    }

    if (V8_UNLIKELY(size_ == kArraySize)) {
      ConvertToRealMap();  // Invalidates all iterators!
      std::pair<typename NormalMap::iterator, bool> ret =
          map_.try_emplace(key, std::forward<Args>(args)...);
      return std::make_pair(iterator(ret.first), ret.second);
    }

    DCHECK(size_ < kArraySize);
    new (&array_[size_]) value_type(key, std::forward<Args>(args)...);
    return std::make_pair(iterator(array_ + size_++), true);
  }

  iterator begin() {
    return UsingFullMap() ? iterator(map_.begin()) : iterator(array_);
  }

  const_iterator begin() const {
    return UsingFullMap() ? const_iterator(map_.begin())
                          : const_iterator(array_);
  }

  iterator end() {
    return UsingFullMap() ? iterator(map_.end()) : iterator(array_ + size_);
  }

  const_iterator end() const {
    return UsingFullMap() ? const_iterator(map_.end())
                          : const_iterator(array_ + size_);
  }

  void clear() {
    if (UsingFullMap()) {
      map_.~NormalMap();
    } else {
      for (size_t i = 0; i < size_; ++i) {
        array_[i].~value_type();
      }
    }
    size_ = 0;
  }

  // Invalidates iterators. Returns iterator following the last removed element.
  iterator erase(const iterator& position) {
    if (UsingFullMap()) {
      return iterator(map_.erase(position.map_iter_));
    }

    size_t i = static_cast<size_t>(position.array_iter_ - array_);
    // TODO(crbug.com/817982): When we have a checked iterator, this CHECK might
    // not be necessary.
    CHECK_LE(i, size_);
    array_[i].~value_type();
    --size_;
    if (i != size_) {
      new (&array_[i]) value_type(std::move(array_[size_]));
      array_[size_].~value_type();
      return iterator(array_ + i);
    }
    return end();
  }

  size_t erase(const key_type& key) {
    iterator iter = find(key);
    if (iter == end()) {
      return 0;
    }
    erase(iter);
    return 1;
  }

  size_t count(const key_type& key) const {
    return (find(key) == end()) ? 0 : 1;
  }

  size_t size() const { return UsingFullMap() ? map_.size() : size_; }

  bool empty() const { return UsingFullMap() ? map_.empty() : size_ == 0; }

  // Returns true if we have fallen back to using the underlying map
  // representation.
  bool UsingFullMap() const { return size_ == kUsingFullMapSentinel; }

  V8_INLINE NormalMap* map() {
    CHECK(UsingFullMap());
    return &map_;
  }

  V8_INLINE const NormalMap* map() const {
    CHECK(UsingFullMap());
    return &map_;
  }

 private:
  // When `size_ == kUsingFullMapSentinel`, we have switched storage strategies
  // from `array_[kArraySize] to `NormalMap map_`. See ConvertToRealMap and
  // UsingFullMap.
  size_t size_;

  MapInit functor_;

  // We want to call constructors and destructors manually, but we don't want
  // to allocate and deallocate the memory used for them separately. Since
  // array_ and map_ are mutually exclusive, we'll put them in a union.
  union {
    value_type array_[kArraySize];
    NormalMap map_;
  };

  V8_NOINLINE V8_PRESERVE_MOST void ConvertToRealMap() {
    // Storage for the elements in the temporary array. This is intentionally
    // declared as a union to avoid having to default-construct |kArraySize|
    // elements, only to move construct over them in the initial loop.
    union Storage {
      Storage() {}
      ~Storage() {}
      value_type array[kArraySize];
    } temp;

    // Move the current elements into a temporary array.
    for (size_t i = 0; i < kArraySize; ++i) {
      new (&temp.array[i]) value_type(std::move(array_[i]));
      array_[i].~value_type();
    }

    // Initialize the map.
    size_ = kUsingFullMapSentinel;
    functor_(&map_);

    // Insert elements into it.
    for (size_t i = 0; i < kArraySize; ++i) {
      map_.insert(std::move(temp.array[i]));
      temp.array[i].~value_type();
    }
  }

  // Helpers for constructors and destructors.
  void InitFrom(const SmallMap& src) {
    functor_ = src.functor_;
    size_ = src.size_;
    if (src.UsingFullMap()) {
      functor_(&map_);
      map_ = src.map_;
    } else {
      for (size_t i = 0; i < size_; ++i) {
        new (&array_[i]) value_type(src.array_[i]);
      }
    }
  }

  void Destroy() {
    if (UsingFullMap()) {
      map_.~NormalMap();
    } else {
      for (size_t i = 0; i < size_; ++i) {
        array_[i].~value_type();
      }
    }
  }
};

}  // namespace v8::base

#endif  // V8_BASE_SMALL_MAP_H_
```