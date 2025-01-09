Response:
Let's break down the thought process for analyzing this C++ header file.

**1. Initial Scan and High-Level Understanding:**

First, I'd quickly read through the comments at the top. Keywords like "hash function," "C++11," "std::hash," and "boost::hash" immediately jump out. This tells me the core purpose of this header is related to hashing in V8. The mention of "Hashing User-Defined Types in C++1y" further reinforces this and hints at a focus on making hashing easy and consistent for custom data structures.

**2. Identifying Key Components:**

Next, I'd look for the major building blocks within the code:

* **`namespace v8::base`:**  This is a standard C++ namespace, indicating this code belongs to the "base" utilities within the V8 project.
* **`template <typename> struct hash;`:**  A forward declaration of a template struct named `hash`. This is likely the main hash function object.
* **`hash_combine(size_t seed, size_t hash)`:** A function to combine two hash values. The comment mentions MurmurHash, suggesting a performance-oriented approach.
* **`class Hasher`:** A class designed to simplify the process of combining multiple values into a single hash. This seems like a key utility for users.
* **`hash_value_unsigned_impl(T v)`:** A template function implementing the actual hashing logic for unsigned integer types. The "Thomas Wang" comment is a significant clue.
* **`V8_BASE_HASH_VALUE_TRIVIAL` and related macros:** Macros are used to define `hash_value` overloads for basic types. This is a common C++ technique for reducing boilerplate.
* **Overloads of `hash_value` for various types:**  Functions like `hash_value(unsigned int v)`, `hash_value(float v)`, `hash_value(std::pair<T1, T2> const& v)`, etc. This shows the library's intention to provide hashing for common data types.
* **Specializations of the `hash` template:** `template <typename T> struct hash { ... }` and `template <typename T> struct hash<T*> { ... }`. This is standard C++ template specialization to handle different types (like pointers) differently.
* **`bit_equal_to` and `bit_hash`:** These structures hint at the ability to perform equality and hashing based on the *bitwise* representation of data, which can be useful in specific scenarios.

**3. Understanding the Functionality of Each Component:**

Now, I'd delve deeper into what each part does:

* **`hash` template:**  Acts as a function object. The `operator()` calls the appropriate `hash_value` function. This allows using `base::hash<MyType>{}(myObject)` to get the hash.
* **`hash_combine`:** Implements a specific algorithm (MurmurHash-inspired) to mix hash values effectively, reducing collisions.
* **`Hasher`:** Provides a convenient way to build up a hash from multiple inputs. The `Add()` and `AddRange()` methods make this easy to use. The static `Combine()` is a shortcut for simple cases.
* **`hash_value_unsigned_impl`:** Implements the core hashing algorithm for unsigned integers, using the Thomas Wang method. The different cases for `sizeof(T)` and `sizeof(size_t)` indicate optimizations for different architectures.
* **`hash_value` overloads:**  These provide default hashing behavior for built-in types and common containers. The handling of floating-point numbers (treating 0 and -0 the same) is noteworthy.
* **`bit_equal_to` and `bit_hash`:** These offer an alternative comparison and hashing mechanism based on the raw bit representation. This can be useful for ensuring that even if two objects are conceptually equal, they are treated as different if their underlying bit patterns differ.

**4. Connecting to JavaScript (if applicable):**

The prompt specifically asks about JavaScript relevance. Hashing is fundamental in JavaScript for:

* **`Map` and `Set`:**  These data structures rely on hashing for efficient lookups and storage.
* **Object property lookup:**  Although not directly exposed, JavaScript engines often use hash tables internally to store object properties.
* **String interning:**  To optimize memory usage, identical strings might be stored only once using a hash table.

I would then construct JavaScript examples demonstrating these connections.

**5. Code Logic and Examples:**

For the more complex parts like `Hasher` and `hash_combine`, providing concrete examples with assumed inputs and outputs is essential for clarity. This involves:

* **Choosing a simple custom struct:**  Like the `Coordinate` and `Point` examples in the comments.
* **Demonstrating the usage of `Hasher::Combine` and the free `hash_value` function.**
* **Showing how the dispatching mechanism works (calling the member `hash_value` if it exists).**

**6. Common Programming Errors:**

Thinking about potential pitfalls is crucial. Common hashing errors include:

* **Poorly distributed hash functions:** Leading to many collisions and performance degradation.
* **Not including all relevant fields in the hash:**  Causing unequal objects to have the same hash.
* **Inconsistent equality and hashing:** If two objects are equal according to `operator==`, their hashes *must* be the same.

I would then create C++ examples illustrating these mistakes.

**7. Torque Consideration:**

The prompt mentions `.tq` files (Torque). A quick search reveals that Torque is a V8-specific language for defining built-in functions. Since the file ends in `.h`, it's *not* a Torque file. I would state this clearly.

**8. Structuring the Answer:**

Finally, I'd organize the information logically:

* Start with a summary of the file's purpose.
* Detail the functionality of each key component.
* Provide JavaScript examples to connect to higher-level concepts.
* Illustrate code logic with input/output examples.
* Explain common programming errors related to hashing.
* Address the Torque question.

This systematic approach allows for a comprehensive and well-structured analysis of the provided C++ header file. It mimics how a developer would approach understanding unfamiliar code.
This header file, `v8/src/base/functional.h`, primarily provides **generic functional programming utilities** for the V8 JavaScript engine, with a strong focus on **hashing**.

Here's a breakdown of its functionalities:

**1. Hashing Infrastructure:**

* **`base::hash` template:** This is the central component for obtaining hash values of objects. It acts as a function object. It leverages argument-dependent lookup (ADL) to find the appropriate `hash_value` function for a given type. This allows for customization of hashing for specific types.
* **`hash_value` free functions:** The header defines several overloads of the free function `hash_value` for various built-in C++ types (e.g., `bool`, `int`, `float`, pointers, `std::pair`, `std::tuple`, enums, and arrays). These provide default hashing implementations for common types.
* **`hash_combine` functions:** These functions (`hash_combine(size_t seed, size_t hash)` and `hash_combine(Ts const&... vs)`) are used to combine multiple hash values into a single hash value. This is crucial when hashing objects composed of multiple members. The implementation uses a MurmurHash-inspired algorithm for good distribution.
* **`base::Hasher` class:** This class provides a convenient way to combine the hashes of multiple values. It maintains an internal hash and allows adding individual values or ranges of values. This simplifies the process of creating hash functions for complex objects.

**2. Bitwise Equality and Hashing:**

* **`base::bit_equal_to` template:**  A function object class for performing bitwise equality comparisons. This compares the raw memory representation of objects.
* **`base::bit_hash` template:** A function object class for performing hashing based on the bitwise representation of objects. This is useful when you need to hash based on the exact memory layout.

**3. Helper Macros and Utilities:**

* **`V8_INLINE`:**  A macro likely used to suggest inline expansion to the compiler for performance.
* **`V8_BASE_EXPORT`:**  A macro related to exporting symbols from a shared library (if `v8/src/base` is built as such).
* **`bits::RotateRight32`, `bits::RotateRight64`:** Functions for bitwise rotation, used in the `hash_combine` implementation.
* **`base::bit_cast`:** A utility (likely defined elsewhere) for reinterpreting the bits of one type as another.

**If `v8/src/base/functional.h` ended with `.tq`, it would be a V8 Torque source file.** Torque is a language used within V8 to define built-in functions and runtime behavior. Since it ends with `.h`, it's a standard C++ header file.

**Relationship to JavaScript and Examples:**

Hashing is fundamental in JavaScript implementations. V8 uses hash tables extensively for:

* **Object property lookup:**  Internally, JavaScript objects are often implemented as hash maps (dictionaries), where property names (strings or symbols) are keys and property values are values. The `base::hash` functionality likely plays a role in calculating hash codes for these keys.
* **`Map` and `Set` data structures:**  These ES6 data structures rely on efficient key lookup, which is typically implemented using hash tables.
* **String interning:** V8 might use hashing to efficiently store and compare strings, ensuring that identical string literals share the same memory.

**JavaScript Example (Conceptual):**

While you can't directly access the C++ `base::hash` from JavaScript, you can see the *effect* of hashing in JavaScript's built-in objects:

```javascript
const myObject = { a: 1, b: "hello" };
const key1 = "a";
const key2 = "b";

// Internally, V8 uses something similar to hashing to quickly find
// the property associated with the key.

console.log(myObject[key1]); // Accessing 'a' is fast due to hashing
console.log(myObject[key2]); // Accessing 'b' is also fast

const myMap = new Map();
myMap.set("key1", 10);
myMap.set("key2", 20);

console.log(myMap.get("key1")); // Map uses hashing for efficient retrieval

const mySet = new Set();
mySet.add("item1");
mySet.add("item2");

console.log(mySet.has("item1")); // Set uses hashing for efficient membership checking
```

**Code Logic Inference with Assumptions:**

Let's consider the `base::Hasher` class.

**Assumption:** We want to create a hash for a simple struct:

```c++
struct MyData {
  int id;
  std::string name;
};
```

**Input:**  An instance of `MyData`:

```c++
MyData data = {123, "example"};
```

**Code using `base::Hasher`:**

```c++
#include "src/base/functional.h"
#include <string>
#include <iostream>

namespace v8::base {

struct MyData {
  int id;
  std::string name;
};

size_t hash_value(const MyData& data) {
  Hasher hasher;
  hasher.Add(data.id);
  hasher.Add(data.name);
  return hasher.hash();
}

} // namespace v8::base

int main() {
  v8::base::MyData data = {123, "example"};
  size_t hash = v8::base::hash_value(data);
  std::cout << "Hash of MyData: " << hash << std::endl;
  return 0;
}
```

**Output (will vary based on the hash function implementation):**  A `size_t` value representing the hash of the `MyData` object. For example: `Hash of MyData: 1786435678` (this is just an illustrative example, the actual value will depend on the specific hash algorithm and input).

**Explanation:**

1. We define a custom `hash_value` function for `MyData`.
2. We create a `Hasher` object.
3. We use `hasher.Add()` to add the `id` and `name` members to the hasher. This internally calls `base::hash<int>{}(data.id)` and `base::hash<std::string>{}(data.name)` to get their individual hashes and combines them.
4. Finally, `hasher.hash()` returns the combined hash value.

**Common Programming Errors and Examples:**

**1. Not including all relevant fields in the hash:**

```c++
struct Point {
  int x;
  int y;
};

size_t hash_value(const Point& p) {
  // Error: Only hashing 'x', 'y' is ignored!
  return v8::base::hash_value(p.x);
}

int main() {
  Point p1 = {1, 2};
  Point p2 = {1, 3};
  std::cout << "Hash of p1: " << hash_value(p1) << std::endl;
  std::cout << "Hash of p2: " << hash_value(p2) << std::endl;
  // p1 and p2 will have the same hash, even though they are different!
  return 0;
}
```

**2. Inconsistent equality and hashing:**

If two objects are considered equal (via `operator==`), their hash values *must* be the same. Failing to do so will break hash-based data structures like `std::unordered_map` and `std::unordered_set`.

```c++
struct MyString {
  std::string str;

  bool operator==(const MyString& other) const {
    return str.length() == other.str.length(); // Inconsistent equality
  }
};

size_t hash_value(const MyString& s) {
  return v8::base::hash_value(s.str); // Hashing based on the actual string
}

int main() {
  MyString s1 = {"abc"};
  MyString s2 = {"def"}; // s1 == s2 is true because lengths are the same
  std::cout << "Hash of s1: " << hash_value(s1) << std::endl;
  std::cout << "Hash of s2: " << hash_value(s2) << std::endl;
  // s1 and s2 have different hashes, violating the equality contract!
  return 0;
}
```

**3. Using default hashing for complex objects without a custom `hash_value`:**

If you don't provide a custom `hash_value` for your class, the default hashing might only hash the memory address of the object, which is generally not what you want for comparing object content.

In summary, `v8/src/base/functional.h` provides a fundamental hashing infrastructure for V8, enabling efficient implementation of core JavaScript features and data structures. It offers tools for defining custom hash functions and combining hash values effectively. Understanding its purpose is crucial for anyone working on the internals of the V8 engine.

Prompt: 
```
这是目录为v8/src/base/functional.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/base/functional.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_BASE_FUNCTIONAL_H_
#define V8_BASE_FUNCTIONAL_H_

#include <stddef.h>
#include <stdint.h>

#include <cstddef>
#include <cstring>
#include <functional>
#include <type_traits>
#include <utility>

#include "src/base/base-export.h"
#include "src/base/bits.h"
#include "src/base/macros.h"

namespace v8::base {

// base::hash is an implementation of the hash function object specified by
// C++11. It was designed to be compatible with std::hash (in C++11) and
// boost:hash (which in turn is based on the hash function object specified by
// the Draft Technical Report on C++ Library Extensions (TR1)).
//
// base::hash is implemented by calling either the hash_value function or the
// hash_value member function. In the first case, the namespace is not specified
// so that it can detect overloads via argument dependent lookup. So if there is
// a free function hash_value in the same namespace as a custom type, it will
// get called.
//
// If users are asked to implement a hash function for their own types with no
// guidance, they generally write bad hash functions. Instead, we provide a
// base::Hasher class to pass hash-relevant member variables into, in order to
// define a decent hash function.
//
// Consider the following example:
//
//   namespace v8 {
//   namespace bar {
//     struct Coordinate {
//       int val;
//       size_t hash_value() const { return hash_value(val); }
//     };
//     struct Point {
//       Coordinate x;
//       Coordinate y;
//     };
//     size_t hash_value(Point const& p) {
//       return base::Hasher::Combine(p.x, p.y);
//     }
//   }
//
//   namespace foo {
//     void DoSomeWork(bar::Point const& p) {
//       base::hash<bar::Point> h;
//       ...
//       size_t hash = h(p);  // calls bar::hash_value(Point const&), which
//                            // calls p.x.hash_value() and p.y.hash_value().
//       ...
//     }
//   }
//   }
//
// This header also provides implementations of hash_value for basic types.
//
// Based on the "Hashing User-Defined Types in C++1y" proposal from Jeffrey
// Yasskin and Chandler Carruth, see
// http://www.open-std.org/Jtc1/sc22/wg21/docs/papers/2012/n3333.html.

template <typename>
struct hash;

// Combine two hash values together. This code was taken from MurmurHash.
V8_INLINE size_t hash_combine(size_t seed, size_t hash) {
#if V8_HOST_ARCH_32_BIT
  const uint32_t c1 = 0xCC9E2D51;
  const uint32_t c2 = 0x1B873593;

  hash *= c1;
  hash = bits::RotateRight32(hash, 15);
  hash *= c2;

  seed ^= hash;
  seed = bits::RotateRight32(seed, 13);
  seed = seed * 5 + 0xE6546B64;
#else
  const uint64_t m = uint64_t{0xC6A4A7935BD1E995};
  const uint32_t r = 47;

  hash *= m;
  hash ^= hash >> r;
  hash *= m;

  seed ^= hash;
  seed *= m;
#endif  // V8_HOST_ARCH_32_BIT
  return seed;
}

// base::Hasher makes it easier to combine multiple fields into one hash and
// avoids the ambiguity of the different {hash_combine} methods.
class Hasher {
 public:
  constexpr Hasher() = default;
  constexpr explicit Hasher(size_t seed) : hash_(seed) {}

  // Retrieve the current hash.
  constexpr size_t hash() const { return hash_; }

  // Combine an existing hash value into this hasher's hash.
  Hasher& AddHash(size_t other_hash) {
    hash_ = hash_combine(hash_, other_hash);
    return *this;
  }

  // Hash a value {t} and combine its hash into this hasher's hash.
  template <typename T>
  Hasher& Add(const T& t) {
    return AddHash(base::hash<T>{}(t));
  }

  // Hash a range of values and combine the hashes into this hasher's hash.
  template <typename Iterator>
  Hasher& AddRange(Iterator first, Iterator last) {
    // TODO(clemensb): If the iterator returns an integral or POD value smaller
    // than size_t we can combine multiple elements together to get better
    // hashing performance.
    for (; first != last; ++first) Add(*first);
    return *this;
  }

  // Hash a collection of values and combine the hashes into this hasher's hash.
  template <typename C>
  auto AddRange(C collection)
      -> decltype(AddRange(std::begin(collection), std::end(collection))) {
    return AddRange(std::begin(collection), std::end(collection));
  }

  // Hash multiple values and combine their hashes.
  template <typename... T>
  constexpr static size_t Combine(const T&... ts) {
    Hasher hasher;
    (..., hasher.Add(ts));
    return hasher.hash();
  }

 private:
  size_t hash_ = 0;
};

// Thomas Wang, Integer Hash Functions.
// https://gist.github.com/badboy/6267743
template <typename T>
V8_INLINE size_t hash_value_unsigned_impl(T v) {
  switch (sizeof(T)) {
    case 4: {
      // "32 bit Mix Functions"
      v = ~v + (v << 15);  // v = (v << 15) - v - 1;
      v = v ^ (v >> 12);
      v = v + (v << 2);
      v = v ^ (v >> 4);
      v = v * 2057;  // v = (v + (v << 3)) + (v << 11);
      v = v ^ (v >> 16);
      return static_cast<size_t>(v);
    }
    case 8: {
      switch (sizeof(size_t)) {
        case 4: {
          // "64 bit to 32 bit Hash Functions"
          v = ~v + (v << 18);  // v = (v << 18) - v - 1;
          v = v ^ (v >> 31);
          v = v * 21;  // v = (v + (v << 2)) + (v << 4);
          v = v ^ (v >> 11);
          v = v + (v << 6);
          v = v ^ (v >> 22);
          return static_cast<size_t>(v);
        }
        case 8: {
          // "64 bit Mix Functions"
          v = ~v + (v << 21);  // v = (v << 21) - v - 1;
          v = v ^ (v >> 24);
          v = (v + (v << 3)) + (v << 8);  // v * 265
          v = v ^ (v >> 14);
          v = (v + (v << 2)) + (v << 4);  // v * 21
          v = v ^ (v >> 28);
          v = v + (v << 31);
          return static_cast<size_t>(v);
        }
      }
    }
  }
  UNREACHABLE();
}

#define V8_BASE_HASH_VALUE_TRIVIAL(type) \
  V8_INLINE size_t hash_value(type v) { return static_cast<size_t>(v); }
V8_BASE_HASH_VALUE_TRIVIAL(bool)
V8_BASE_HASH_VALUE_TRIVIAL(unsigned char)
V8_BASE_HASH_VALUE_TRIVIAL(unsigned short)  // NOLINT(runtime/int)
#undef V8_BASE_HASH_VALUE_TRIVIAL

V8_INLINE size_t hash_value(unsigned int v) {
  return hash_value_unsigned_impl(v);
}

V8_INLINE size_t hash_value(unsigned long v) {  // NOLINT(runtime/int)
  return hash_value_unsigned_impl(v);
}

V8_INLINE size_t hash_value(unsigned long long v) {  // NOLINT(runtime/int)
  return hash_value_unsigned_impl(v);
}

#define V8_BASE_HASH_VALUE_SIGNED(type)                  \
  V8_INLINE size_t hash_value(signed type v) {           \
    return hash_value(base::bit_cast<unsigned type>(v)); \
  }
V8_BASE_HASH_VALUE_SIGNED(char)
V8_BASE_HASH_VALUE_SIGNED(short)      // NOLINT(runtime/int)
V8_BASE_HASH_VALUE_SIGNED(int)        // NOLINT(runtime/int)
V8_BASE_HASH_VALUE_SIGNED(long)       // NOLINT(runtime/int)
V8_BASE_HASH_VALUE_SIGNED(long long)  // NOLINT(runtime/int)
#undef V8_BASE_HASH_VALUE_SIGNED

V8_INLINE size_t hash_value(float v) {
  // 0 and -0 both hash to zero.
  return v != 0.0f ? hash_value(base::bit_cast<uint32_t>(v)) : 0;
}

V8_INLINE size_t hash_value(double v) {
  // 0 and -0 both hash to zero.
  return v != 0.0 ? hash_value(base::bit_cast<uint64_t>(v)) : 0;
}

template <typename T, size_t N>
V8_INLINE size_t hash_value(const T (&v)[N]) {
  return Hasher{}.AddRange(v, v + N).hash();
}

template <typename T, size_t N>
V8_INLINE size_t hash_value(T (&v)[N]) {
  return Hasher{}.AddRange(v, v + N).hash();
}

template <typename T>
V8_INLINE size_t hash_value(T* const& v) {
  return hash_value(reinterpret_cast<uintptr_t>(v));
}

template <typename T1, typename T2>
V8_INLINE size_t hash_value(std::pair<T1, T2> const& v) {
  return Hasher::Combine(v.first, v.second);
}

template <typename... T, size_t... I>
V8_INLINE size_t hash_value_impl(std::tuple<T...> const& v,
                                 std::index_sequence<I...>) {
  return Hasher::Combine(std::get<I>(v)...);
}

template <typename... T>
V8_INLINE size_t hash_value(std::tuple<T...> const& v) {
  return hash_value_impl(v, std::make_index_sequence<sizeof...(T)>());
}

template <typename T, typename = std::enable_if_t<std::is_enum<T>::value>>
V8_INLINE size_t hash_value(T v) {
  return hash_value(static_cast<std::underlying_type_t<T>>(v));
}

// Provide a hash_value function for each T with a hash_value member function.
template <typename T>
V8_INLINE auto hash_value(const T& v) -> decltype(v.hash_value()) {
  return v.hash_value();
}

// Define base::hash to call the hash_value function or member function.
template <typename T>
struct hash {
  V8_INLINE constexpr size_t operator()(const T& v) const {
    return hash_value(v);
  }
};

template <typename T>
struct hash<T*> {
  V8_INLINE size_t operator()(T* const v) const {
    return ::v8::base::hash_value(v);
  }
};

// TODO(clemensb): Depending on the types in this template the compiler might
// pick {hash_combine(size_t, size_t)} instead. Thus remove this template and
// switch callers to {Hasher::Combine}.
template <typename... Ts>
V8_INLINE size_t hash_combine(Ts const&... vs) {
  return Hasher{}.Combine(vs...);
}

// TODO(clemensb): Switch users to {Hasher{}.AddRange(first, last).hash()}.
template <typename Iterator>
V8_INLINE size_t hash_range(Iterator first, Iterator last) {
  return Hasher{}.AddRange(first, last).hash();
}

// base::bit_equal_to is a function object class for bitwise equality
// comparison, similar to std::equal_to, except that the comparison is performed
// on the bit representation of the operands.
//
// base::bit_hash is a function object class for bitwise hashing, similar to
// base::hash. It can be used together with base::bit_equal_to to implement a
// hash data structure based on the bitwise representation of types.

template <typename T>
struct bit_equal_to {};

template <typename T>
struct bit_hash {};

#define V8_BASE_BIT_SPECIALIZE_TRIVIAL(type)                 \
  template <>                                                \
  struct bit_equal_to<type> : public std::equal_to<type> {}; \
  template <>                                                \
  struct bit_hash<type> : public hash<type> {};
V8_BASE_BIT_SPECIALIZE_TRIVIAL(signed char)
V8_BASE_BIT_SPECIALIZE_TRIVIAL(unsigned char)
V8_BASE_BIT_SPECIALIZE_TRIVIAL(short)           // NOLINT(runtime/int)
V8_BASE_BIT_SPECIALIZE_TRIVIAL(unsigned short)  // NOLINT(runtime/int)
V8_BASE_BIT_SPECIALIZE_TRIVIAL(int)
V8_BASE_BIT_SPECIALIZE_TRIVIAL(unsigned int)
V8_BASE_BIT_SPECIALIZE_TRIVIAL(long)                // NOLINT(runtime/int)
V8_BASE_BIT_SPECIALIZE_TRIVIAL(unsigned long)       // NOLINT(runtime/int)
V8_BASE_BIT_SPECIALIZE_TRIVIAL(long long)           // NOLINT(runtime/int)
V8_BASE_BIT_SPECIALIZE_TRIVIAL(unsigned long long)  // NOLINT(runtime/int)
#undef V8_BASE_BIT_SPECIALIZE_TRIVIAL

#define V8_BASE_BIT_SPECIALIZE_BIT_CAST(type, btype)                   \
  template <>                                                          \
  struct bit_equal_to<type> {                                          \
    V8_INLINE bool operator()(type lhs, type rhs) const {              \
      return base::bit_cast<btype>(lhs) == base::bit_cast<btype>(rhs); \
    }                                                                  \
  };                                                                   \
  template <>                                                          \
  struct bit_hash<type> {                                              \
    V8_INLINE size_t operator()(type v) const {                        \
      hash<btype> h;                                                   \
      return h(base::bit_cast<btype>(v));                              \
    }                                                                  \
  };
V8_BASE_BIT_SPECIALIZE_BIT_CAST(float, uint32_t)
V8_BASE_BIT_SPECIALIZE_BIT_CAST(double, uint64_t)
#undef V8_BASE_BIT_SPECIALIZE_BIT_CAST

}  // namespace v8::base

#endif  // V8_BASE_FUNCTIONAL_H_

"""

```