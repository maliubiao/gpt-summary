Response:
Let's break down the thought process for analyzing the `v8/src/base/vector.h` header file.

**1. Initial Scan and High-Level Understanding:**

* **File Name and Location:**  The prompt specifies the file `v8/src/base/vector.h`. The `.h` extension immediately signals a C++ header file, likely containing class definitions and declarations. The path suggests it's a fundamental utility within the V8 codebase.
* **Copyright and License:** The standard copyright notice and BSD-style license confirm it's part of the open-source V8 project.
* **Include Guards:** The `#ifndef V8_BASE_VECTOR_H_`, `#define V8_BASE_VECTOR_H_`, and `#endif` block are standard C++ include guards, preventing multiple inclusions and potential errors.
* **Includes:**  The included headers provide clues about the class's dependencies and functionality. `<algorithm>`, `<cstring>`, `<iterator>`, `<limits>`, `<memory>`, `<type_traits>` suggest core C++ functionalities like copying, string manipulation (though minimal here), iteration, numeric limits, memory management, and type introspection. The `src/base/functional.h`, `src/base/logging.h`, and `src/base/macros.h` point to internal V8 utilities for function objects, logging, and common macros.
* **Namespaces:** The code is within `namespace v8 { namespace base { ... } }`, indicating its organizational structure within the V8 project.

**2. Analyzing the `Vector` Class Template:**

* **Template Parameter:** `template <typename T>` signifies this is a generic vector that can hold elements of any type `T`.
* **Type Aliases:** `value_type`, `iterator`, `const_iterator` are standard type aliases for clarity and consistency with standard containers.
* **Constructors:**
    * `constexpr Vector()`: Default constructor, initializes an empty vector.
    * `constexpr Vector(T* data, size_t length)`: Constructor taking existing data and length. The `DCHECK` is important – it's a debug assertion ensuring the data pointer is valid if the length is non-zero.
    * `static Vector<T> New(size_t length)`: Static factory method to create a new vector with allocated memory. This immediately suggests heap allocation.
* **`SubVector` and `SubVectorFrom`:** These methods allow creating views (not copies) of a portion of the original vector, improving efficiency. The `DCHECK_LE` calls are crucial for boundary checks.
* **`OverwriteWith`:**  Methods to copy data from another `Vector` or a `std::array`. The `DCHECK_EQ` enforces size compatibility.
* **`length()` and `size()`:**  Provide the size of the vector. The distinction (one returning `int`, the other `size_t`) is a subtle but important detail, likely for historical reasons or API compatibility, with a `DCHECK` to prevent overflow.
* **`empty()`:**  Simple check for emptiness.
* **`operator[]` and `at()`:** Element accessors. The `operator[]` has a `DCHECK_LT` for bounds checking in debug builds, while `at()` likely does the same (or could throw an exception, although this implementation doesn't).
* **`first()` and `last()`:** Convenient accessors for the first and last elements, with `DCHECK_LT` ensuring the vector isn't empty when accessing the last element.
* **`begin()`, `cbegin()`, `data()`, `end()`, `cend()`, `rbegin()`, `rend()`:** These are standard iterator accessors, providing forward and reverse iteration capabilities. The inclusion of `data()` aligns with standard container interfaces.
* **`Clone()`:** Creates a deep copy of the vector with its own allocated memory.
* **`Truncate()`:** Resizes the vector, effectively removing elements from the end.
* **`Dispose()`:** Deallocates the underlying memory. Crucial for preventing memory leaks.
* **`operator+` and `operator+=`:**  Create a new `Vector` or modify the existing one by adjusting the starting point, effectively creating a sub-vector.
* **Implicit Conversion:** The `operator Vector<const U>() const` is an important optimization that avoids unnecessary copying when converting to a read-only view, but it has a crucial safety constraint (`sizeof(U) == sizeof(T)`).
* **`cast()`:**  A more explicit and potentially dangerous way to reinterpret the underlying data as a vector of a different type. The `static_assert` and `DCHECK_EQ` calls are there to enforce strict conditions and try to prevent memory corruption.
* **`operator==` and `operator!=`:** Equality comparison operators, leveraging `std::equal`. The templated versions handle comparisons with `Vector<const T>`.

**3. Analyzing `ScopedVector` and `OwnedVector`:**

* **`ScopedVector`:**  A RAII (Resource Acquisition Is Initialization) wrapper around `Vector`. Its constructor allocates memory, and its destructor automatically frees it. This helps prevent memory leaks. The `DISALLOW_IMPLICIT_CONSTRUCTORS` macro is common in V8 to avoid unintended conversions.
* **`OwnedVector`:** Manages memory using `std::unique_ptr`, ensuring exclusive ownership. It disallows copying but allows moving, which is efficient. It provides methods for creating new vectors (`New`, `NewForOverwrite`, `Of`), releasing ownership (`ReleaseData`), and accessing the underlying data (`as_vector`).

**4. Analyzing Helper Functions and Constants:**

* **`hash_value()`:**  A function to calculate a hash of the vector's contents.
* **`StaticCharVector`, `CStrVector`, `OneByteVector`, `StaticOneByteVector`, `ArrayVector`, `VectorOf`:** These are factory functions for creating `Vector` instances in various ways, often with `const char*` or character arrays. The comments explaining null termination are important for understanding their behavior.
* **`EmbeddedVector`:** A `Vector` whose data is stored directly within the object as a fixed-size array. This can be useful for small, stack-allocated vectors.

**5. Answering the Prompt's Questions (Iterative Refinement):**

* **Functionality:**  Based on the analysis above, list the core features of each class and the helper functions.
* **Torque Source:** Check for the `.tq` extension. In this case, the file ends in `.h`, so it's not a Torque file.
* **JavaScript Relationship:** Look for functionalities that relate to how JavaScript arrays or typed arrays work. The `Vector` provides a foundation for managing sequences of data, which is fundamental to JavaScript arrays and buffers. Brainstorm concrete JavaScript examples that would internally use similar data structures.
* **Code Logic Reasoning:** Choose a relatively simple method (like `SubVector`) and illustrate its behavior with a clear example, showing input and output.
* **Common Programming Errors:** Think about how a user might misuse the `Vector` class, leading to errors like out-of-bounds access, memory leaks (if using `Vector` directly and not `ScopedVector` or `OwnedVector`), or issues with implicit conversions or casting. Provide specific code examples to demonstrate these errors.

**Self-Correction/Refinement during Analysis:**

* **Initial thought:** "Is `Vector` just like `std::vector`?"  **Correction:** While it shares similarities, it's a simpler, non-resizable vector designed for internal V8 use. It doesn't have features like `push_back`, `pop_back`, or automatic resizing.
* **Confusion about `cast()`:** "Why is there a `cast()` method? That seems dangerous." **Refinement:** Recognize that it's a low-level operation and the `static_assert` and `DCHECK_EQ` calls are safety measures to mitigate risks. It's likely used in scenarios where V8 needs to reinterpret memory.
* **Understanding the different vector types:** Pay close attention to the differences between `Vector`, `ScopedVector`, and `OwnedVector` regarding memory management. This is crucial for explaining their proper usage.
* **JavaScript examples:** Ensure the JavaScript examples are relevant and clearly illustrate the connection to the C++ `Vector`. Don't just say "arrays are related"; show *how* they are related in terms of underlying data structures.

By following these steps, combining code inspection with conceptual understanding, and iteratively refining the analysis, one can arrive at a comprehensive and accurate explanation of the `v8/src/base/vector.h` file.
This is a header file defining several vector-like data structures for internal use within the V8 JavaScript engine. Let's break down its functionality:

**Core Functionality of `v8/src/base/vector.h`:**

This header defines the `Vector` class template and related utility classes (`ScopedVector`, `OwnedVector`, `EmbeddedVector`) to provide efficient and lightweight ways to manage contiguous blocks of memory. Think of them as V8's internal, optimized versions of something similar to `std::vector` or C-style arrays, but with specific design choices tailored for V8's needs.

Here's a breakdown of the key classes and their purposes:

1. **`Vector<T>`:**
   - **Represents a non-owning view of a contiguous block of memory.** It holds a pointer (`start_`) to the beginning of the data and a length (`length_`).
   - **Does not manage the lifetime of the underlying data.** The memory must be managed elsewhere. This makes it very lightweight and efficient for passing around views of existing data.
   - **Provides various methods for accessing and manipulating the data:**
     - Constructors for creating empty vectors or vectors from existing data.
     - `SubVector`: Creates a new `Vector` that is a sub-section of the original.
     - `OverwriteWith`: Copies data from another `Vector` or `std::array`.
     - `length()`/`size()`: Returns the size of the vector.
     - `empty()`: Checks if the vector is empty.
     - `operator[]`/`at()`: Accesses elements (with bounds checking in debug mode).
     - `first()`/`last()`: Accesses the first and last elements.
     - `begin()`/`end()`/`cbegin()`/`cend()`/`rbegin()`/`rend()`: Provides iterators for traversing the data.
     - `data()`: Returns a raw pointer to the underlying data.
     - `Clone()`: Creates a copy of the vector with its own allocated memory.
     - `Truncate()`: Reduces the logical size of the vector.
     - `Dispose()`: Releases the underlying memory (important to call if the `Vector` owns the memory, although this class typically doesn't).
     - `operator+`/`operator+=`:  Creates a new `Vector` starting at an offset.
     - Implicit conversion to `Vector<const U>` (for read-only access).
     - `cast()`:  Allows reinterpreting the underlying data as a vector of a different type (use with caution!).
     - `operator==`/`operator!=`: Compares two vectors for equality.

2. **`ScopedVector<T>`:**
   - **Represents a `Vector` that owns its underlying memory.**
   - **Uses RAII (Resource Acquisition Is Initialization) to manage memory.** The constructor allocates memory, and the destructor automatically deallocates it. This prevents memory leaks.
   - Useful for temporary buffers or data that needs to be automatically cleaned up.

3. **`OwnedVector<T>`:**
   - **Also represents a `Vector` that owns its underlying memory.**
   - **Uses `std::unique_ptr` to manage the memory.** This enforces exclusive ownership and prevents double-frees.
   - Disallows copying but supports moving.
   - Provides static factory methods like `New` and `NewForOverwrite` for creating new owned vectors.
   - Offers a `ReleaseData()` method to transfer ownership of the underlying memory.

4. **`EmbeddedVector<T, kSize>`:**
   - **A `Vector` whose underlying data is stored directly within the `EmbeddedVector` object as a fixed-size array.**
   - Avoids dynamic memory allocation, making it very efficient for small, fixed-size vectors.

**Is `v8/src/base/vector.h` a Torque Source?**

No, `v8/src/base/vector.h` ends with `.h`, which is the standard extension for C++ header files. Torque source files in V8 typically have the `.tq` extension. Therefore, this is **not** a V8 Torque source file. It's a standard C++ header file.

**Relationship with JavaScript Functionality (and JavaScript Examples):**

While this header file is part of V8's internal C++ implementation, it has a strong relationship to how JavaScript handles arrays and typed arrays:

* **Underlying Storage for JavaScript Arrays:**  Internally, V8 uses efficient data structures to store the elements of JavaScript arrays. While the exact implementation is complex and optimized, concepts similar to `Vector` are used to manage the contiguous memory where array elements are stored. When a JavaScript array is created, V8 needs a way to allocate and manage memory for its elements.

   ```javascript
   // JavaScript Array
   const myArray = [1, 2, 3, 4];
   ```

   Internally, V8 might use something akin to `Vector<int>` (or a more specialized structure) to hold the numbers 1, 2, 3, and 4 in a contiguous memory block.

* **Typed Arrays:** JavaScript's Typed Arrays (e.g., `Uint8Array`, `Float32Array`) provide a way to work with raw binary data in a more structured way. These directly map to contiguous blocks of memory.

   ```javascript
   // JavaScript Typed Array
   const buffer = new ArrayBuffer(8); // 8 bytes of memory
   const uint8View = new Uint8Array(buffer);
   uint8View[0] = 10;
   uint8View[1] = 20;
   ```

   In this case, `v8::base::Vector<uint8_t>` or similar structures are highly likely to be used internally by V8 to represent the underlying buffer of the `Uint8Array`. The `Vector` provides a way to access and manipulate this raw memory efficiently.

* **String Representation:** While strings in JavaScript are more complex, the `StaticCharVector`, `CStrVector`, and `OneByteVector` functions in this header suggest that `Vector` is used to represent character data, which is fundamental to how V8 handles strings.

**Code Logic Reasoning (with Assumptions and Input/Output):**

Let's take the `SubVector` method as an example:

**Method:** `SubVector(size_t from, size_t to) const`

**Assumption:** We have a `Vector<int>` named `myVector` containing the values `{10, 20, 30, 40, 50}`.

**Input:** `myVector.SubVector(1, 4)`

**Logic:**
1. `DCHECK_LE(from, to)`: Checks if `1 <= 4` (true).
2. `DCHECK_LE(to, length_)`: Checks if `4 <= 5` (true, as `myVector.length_` is 5).
3. `return Vector<T>(begin() + from, to - from);`:
   - `begin()` returns a pointer to the start of the data (where 10 is).
   - `begin() + from` (which is `begin() + 1`) points to the element `20`.
   - `to - from` is `4 - 1 = 3`, which is the length of the sub-vector.
   - A new `Vector<int>` is created with the starting pointer pointing to `20` and a length of `3`.

**Output:** A new `Vector<int>` representing the sub-array `{20, 30, 40}`.

**Common Programming Errors and Examples:**

1. **Out-of-Bounds Access:** Trying to access an element at an index that is outside the valid range of the vector.

   ```c++
   v8::base::Vector<int> myVector(new int[3]{1, 2, 3}, 3);
   int value = myVector[5]; // Error: Index 5 is out of bounds (0, 1, 2 are valid)
   ```
   In debug builds, the `DCHECK_LT` in `operator[]` would trigger an assertion failure. In release builds, this could lead to reading garbage data or even crashes.

2. **Memory Leaks (when using `Vector` directly and not `ScopedVector` or `OwnedVector`):** If you create a `Vector` that owns the underlying memory and forget to call `Dispose()`, the memory will be leaked.

   ```c++
   v8::base::Vector<int> myVector(new int[10], 10);
   // ... use myVector ...
   // Oops! Forgot to call myVector.Dispose();
   ```
   `ScopedVector` and `OwnedVector` are designed to prevent this by automatically managing the memory.

3. **Incorrect Usage of `cast()`:** Using `cast()` to reinterpret memory without carefully considering the types and sizes involved can lead to undefined behavior and crashes.

   ```c++
   v8::base::Vector<int> intVector(new int[2]{100, 200}, 2);
   v8::base::Vector<char> charVector = v8::base::Vector<char>::cast(intVector);
   // Now charVector points to the same memory as intVector, but interprets it as characters.
   // This is likely to produce unexpected results as an integer takes up more bytes than a char.
   ```

4. **Modifying a `Vector` that doesn't own its memory after the original owner deallocates:**  If you have a `Vector` that's a sub-view of another data structure, and the original data structure is deallocated, the `Vector` will point to invalid memory.

   ```c++
   {
       std::unique_ptr<int[]> data(new int[5]{1, 2, 3, 4, 5});
       v8::base::Vector<int> subVector(data.get() + 1, 3); // Points to {2, 3, 4}
       // ... use subVector ...
   } // data is deallocated here

   // Now subVector points to freed memory. Accessing it is undefined behavior.
   // int value = subVector[0]; // Potential crash or garbage data
   ```

In summary, `v8/src/base/vector.h` provides fundamental building blocks for managing memory efficiently within the V8 engine. While not directly exposed to JavaScript developers, its concepts and implementations are crucial for the performance and functionality of JavaScript arrays and typed arrays. The different `Vector` variants offer flexibility in managing memory ownership, helping to avoid common C++ memory management pitfalls.

### 提示词
```
这是目录为v8/src/base/vector.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/base/vector.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```c
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_BASE_VECTOR_H_
#define V8_BASE_VECTOR_H_

#include <algorithm>
#include <cstring>
#include <iterator>
#include <limits>
#include <memory>
#include <type_traits>

#include "src/base/functional.h"
#include "src/base/logging.h"
#include "src/base/macros.h"

namespace v8 {
namespace base {

template <typename T>
class Vector {
 public:
  using value_type = T;
  using iterator = T*;
  using const_iterator = const T*;

  constexpr Vector() : start_(nullptr), length_(0) {}

  constexpr Vector(T* data, size_t length) : start_(data), length_(length) {
    DCHECK(length == 0 || data != nullptr);
  }

  static Vector<T> New(size_t length) {
    return Vector<T>(new T[length], length);
  }

  // Returns a vector using the same backing storage as this one,
  // spanning from and including 'from', to but not including 'to'.
  Vector<T> SubVector(size_t from, size_t to) const {
    DCHECK_LE(from, to);
    DCHECK_LE(to, length_);
    return Vector<T>(begin() + from, to - from);
  }
  Vector<T> SubVectorFrom(size_t from) const {
    return SubVector(from, length_);
  }

  template <class U>
  void OverwriteWith(Vector<U> other) {
    DCHECK_EQ(size(), other.size());
    std::copy(other.begin(), other.end(), begin());
  }

  template <class U, size_t n>
  void OverwriteWith(const std::array<U, n>& other) {
    DCHECK_EQ(size(), other.size());
    std::copy(other.begin(), other.end(), begin());
  }

  // Returns the length of the vector. Only use this if you really need an
  // integer return value. Use {size()} otherwise.
  int length() const {
    DCHECK_GE(std::numeric_limits<int>::max(), length_);
    return static_cast<int>(length_);
  }

  // Returns the length of the vector as a size_t.
  constexpr size_t size() const { return length_; }

  // Returns whether or not the vector is empty.
  constexpr bool empty() const { return length_ == 0; }

  // Access individual vector elements - checks bounds in debug mode.
  T& operator[](size_t index) const {
    DCHECK_LT(index, length_);
    return start_[index];
  }

  const T& at(size_t index) const { return operator[](index); }

  T& first() { return start_[0]; }
  const T& first() const { return start_[0]; }

  T& last() {
    DCHECK_LT(0, length_);
    return start_[length_ - 1];
  }
  const T& last() const {
    DCHECK_LT(0, length_);
    return start_[length_ - 1];
  }

  // Returns a pointer to the start of the data in the vector.
  constexpr T* begin() const { return start_; }
  constexpr const T* cbegin() const { return start_; }

  // For consistency with other containers, do also provide a {data} accessor.
  constexpr T* data() const { return start_; }

  // Returns a pointer past the end of the data in the vector.
  constexpr T* end() const { return start_ + length_; }
  constexpr const T* cend() const { return start_ + length_; }

  constexpr std::reverse_iterator<T*> rbegin() const {
    return std::make_reverse_iterator(end());
  }
  constexpr std::reverse_iterator<T*> rend() const {
    return std::make_reverse_iterator(begin());
  }

  // Returns a clone of this vector with a new backing store.
  Vector<T> Clone() const {
    T* result = new T[length_];
    for (size_t i = 0; i < length_; i++) result[i] = start_[i];
    return Vector<T>(result, length_);
  }

  void Truncate(size_t length) {
    DCHECK(length <= length_);
    length_ = length;
  }

  // Releases the array underlying this vector. Once disposed the
  // vector is empty.
  void Dispose() {
    delete[] start_;
    start_ = nullptr;
    length_ = 0;
  }

  Vector<T> operator+(size_t offset) {
    DCHECK_LE(offset, length_);
    return Vector<T>(start_ + offset, length_ - offset);
  }

  Vector<T> operator+=(size_t offset) {
    DCHECK_LE(offset, length_);
    start_ += offset;
    length_ -= offset;
    return *this;
  }

  // Implicit conversion from Vector<T> to Vector<const U> if
  // - T* is convertible to const U*, and
  // - U and T have the same size.
  // Note that this conversion is only safe for `*const* U`; writes would
  // violate covariance.
  template <typename U,
            typename = std::enable_if_t<std::is_convertible_v<T*, const U*> &&
                                        sizeof(U) == sizeof(T)>>
  operator Vector<const U>() const {
    return {start_, length_};
  }

  template <typename S>
  static Vector<T> cast(Vector<S> input) {
    // Casting is potentially dangerous, so be really restrictive here. This
    // might be lifted once we have use cases for that.
    static_assert(std::is_trivial_v<S> && std::is_standard_layout_v<S>);
    static_assert(std::is_trivial_v<T> && std::is_standard_layout_v<T>);
    DCHECK_EQ(0, (input.size() * sizeof(S)) % sizeof(T));
    DCHECK_EQ(0, reinterpret_cast<uintptr_t>(input.begin()) % alignof(T));
    return Vector<T>(reinterpret_cast<T*>(input.begin()),
                     input.size() * sizeof(S) / sizeof(T));
  }

  bool operator==(const Vector<T>& other) const {
    return std::equal(begin(), end(), other.begin(), other.end());
  }

  bool operator!=(const Vector<T>& other) const {
    return !operator==(other);
  }

  template<typename TT = T>
  std::enable_if_t<!std::is_const_v<TT>, bool> operator==(
      const Vector<const T>& other) const {
    return std::equal(begin(), end(), other.begin(), other.end());
  }

  template<typename TT = T>
  std::enable_if_t<!std::is_const_v<TT>, bool> operator!=(
      const Vector<const T>& other) const {
    return !operator==(other);
  }

 private:
  T* start_;
  size_t length_;
};

template <typename T>
V8_INLINE size_t hash_value(base::Vector<T> v) {
  return hash_range(v.begin(), v.end());
}

template <typename T>
class V8_NODISCARD ScopedVector : public Vector<T> {
 public:
  explicit ScopedVector(size_t length) : Vector<T>(new T[length], length) {}
  ~ScopedVector() { delete[] this->begin(); }

 private:
  DISALLOW_IMPLICIT_CONSTRUCTORS(ScopedVector);
};

template <typename T>
class OwnedVector {
 public:
  OwnedVector() = default;

  OwnedVector(std::unique_ptr<T[]> data, size_t length)
      : data_(std::move(data)), length_(length) {
    DCHECK_IMPLIES(length_ > 0, data_ != nullptr);
  }

  // Disallow copying.
  OwnedVector(const OwnedVector&) = delete;
  OwnedVector& operator=(const OwnedVector&) = delete;

  // Move construction and move assignment from {OwnedVector<U>} to
  // {OwnedVector<T>}, instantiable if {std::unique_ptr<U>} can be converted to
  // {std::unique_ptr<T>}. Can also be used to convert {OwnedVector<T>} to
  // {OwnedVector<const T>}.
  // These also function as the standard move construction/assignment operator.
  // {other} is left as an empty vector.
  template <typename U,
            typename = typename std::enable_if<std::is_convertible<
                std::unique_ptr<U>, std::unique_ptr<T>>::value>::type>
  OwnedVector(OwnedVector<U>&& other) V8_NOEXCEPT {
    *this = std::move(other);
  }

  template <typename U,
            typename = typename std::enable_if<std::is_convertible<
                std::unique_ptr<U>, std::unique_ptr<T>>::value>::type>
  OwnedVector& operator=(OwnedVector<U>&& other) V8_NOEXCEPT {
    static_assert(sizeof(U) == sizeof(T));
    data_ = std::move(other.data_);
    length_ = other.length_;
    DCHECK_NULL(other.data_);
    other.length_ = 0;
    return *this;
  }

  // Returns the length of the vector as a size_t.
  constexpr size_t size() const { return length_; }

  // Returns whether or not the vector is empty.
  constexpr bool empty() const { return length_ == 0; }

  constexpr T* begin() const {
    DCHECK_IMPLIES(length_ > 0, data_ != nullptr);
    return data_.get();
  }

  constexpr T* end() const { return begin() + length_; }

  // In addition to {begin}, do provide a {data()} accessor for API
  // compatibility with other sequential containers.
  constexpr T* data() const { return begin(); }

  constexpr std::reverse_iterator<T*> rbegin() const {
    return std::make_reverse_iterator(end());
  }
  constexpr std::reverse_iterator<T*> rend() const {
    return std::make_reverse_iterator(begin());
  }

  // Access individual vector elements - checks bounds in debug mode.
  T& operator[](size_t index) const {
    DCHECK_LT(index, length_);
    return data_[index];
  }

  // Returns a {Vector<T>} view of the data in this vector.
  Vector<T> as_vector() const { return {begin(), size()}; }

  // Releases the backing data from this vector and transfers ownership to the
  // caller. This vector will be empty afterwards.
  std::unique_ptr<T[]> ReleaseData() {
    length_ = 0;
    return std::move(data_);
  }

  // Allocates a new vector of the specified size via the default allocator.
  // Elements in the new vector are value-initialized.
  static OwnedVector<T> New(size_t size) {
    if (size == 0) return {};
    return OwnedVector<T>(std::make_unique<T[]>(size), size);
  }

  // Allocates a new vector of the specified size via the default allocator.
  // Elements in the new vector are default-initialized.
  static OwnedVector<T> NewForOverwrite(size_t size) {
    if (size == 0) return {};
    // TODO(v8): Use {std::make_unique_for_overwrite} once we allow C++20.
    return OwnedVector<T>(std::unique_ptr<T[]>(new T[size]), size);
  }

  // Allocates a new vector containing the specified collection of values.
  // {Iterator} is the common type of {std::begin} and {std::end} called on a
  // {const U&}. This function is only instantiable if that type exists.
  template <typename U, typename Iterator = typename std::common_type<
                            decltype(std::begin(std::declval<const U&>())),
                            decltype(std::end(std::declval<const U&>()))>::type>
  static OwnedVector<T> Of(const U& collection) {
    Iterator begin = std::begin(collection);
    Iterator end = std::end(collection);
    using non_const_t = typename std::remove_const<T>::type;
    auto vec =
        OwnedVector<non_const_t>::NewForOverwrite(std::distance(begin, end));
    std::copy(begin, end, vec.begin());
    return vec;
  }

  bool operator==(std::nullptr_t) const { return data_ == nullptr; }
  bool operator!=(std::nullptr_t) const { return data_ != nullptr; }

 private:
  template <typename U>
  friend class OwnedVector;

  std::unique_ptr<T[]> data_;
  size_t length_ = 0;
};

// The vectors returned by {StaticCharVector}, {CStrVector}, or {OneByteVector}
// do not contain a null-termination byte. If you want the null byte, use
// {ArrayVector}.

// Known length, constexpr.
template <size_t N>
constexpr Vector<const char> StaticCharVector(const char (&array)[N]) {
  return {array, N - 1};
}

// Unknown length, not constexpr.
inline Vector<const char> CStrVector(const char* data) {
  return {data, strlen(data)};
}

// OneByteVector is never constexpr because the data pointer is
// {reinterpret_cast}ed.
inline Vector<const uint8_t> OneByteVector(const char* data, size_t length) {
  return {reinterpret_cast<const uint8_t*>(data), length};
}

inline Vector<const uint8_t> OneByteVector(const char* data) {
  return OneByteVector(data, strlen(data));
}

template <size_t N>
Vector<const uint8_t> StaticOneByteVector(const char (&array)[N]) {
  return OneByteVector(array, N - 1);
}

// For string literals, ArrayVector("foo") returns a vector ['f', 'o', 'o', \0]
// with length 4 and null-termination.
// If you want ['f', 'o', 'o'], use CStrVector("foo").
template <typename T, size_t N>
inline constexpr Vector<T> ArrayVector(T (&arr)[N]) {
  return {arr, N};
}

// Construct a Vector from a start pointer and a size.
template <typename T>
inline constexpr Vector<T> VectorOf(T* start, size_t size) {
  return {start, size};
}

// Construct a Vector from anything compatible with std::data and std::size (ie,
// an array, or a container providing a {data()} and {size()} accessor).
template <typename Container>
inline constexpr auto VectorOf(Container&& c)
    -> decltype(VectorOf(std::data(c), std::size(c))) {
  return VectorOf(std::data(c), std::size(c));
}

// Construct a Vector from an initializer list. The vector can obviously only be
// used as long as the initializer list is live. Valid uses include direct use
// in parameter lists: F(VectorOf({1, 2, 3}));
template <typename T>
inline constexpr Vector<const T> VectorOf(std::initializer_list<T> list) {
  return VectorOf(list.begin(), list.size());
}

template <typename T, size_t kSize>
class EmbeddedVector : public Vector<T> {
 public:
  EmbeddedVector() : Vector<T>(buffer_, kSize) {}
  explicit EmbeddedVector(const T& initial_value) : Vector<T>(buffer_, kSize) {
    std::fill_n(buffer_, kSize, initial_value);
  }
  EmbeddedVector(const EmbeddedVector&) = delete;
  EmbeddedVector& operator=(const EmbeddedVector&) = delete;

 private:
  T buffer_[kSize];
};

}  // namespace base
}  // namespace v8

#endif  // V8_BASE_VECTOR_H_
```