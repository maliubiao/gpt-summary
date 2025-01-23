Response:
Let's break down the thought process for analyzing this C++ header file.

1. **Identify the Core Purpose:** The filename `bigint.h` strongly suggests this header defines the implementation of arbitrary-precision integers (BigInts) within the V8 JavaScript engine. The copyright notice and namespace `v8::bigint` confirm this.

2. **Scan for Key Data Structures:** Look for `class` or `struct` declarations. The prominent ones are `Digits`, `RWDigits`, `Platform`, `Processor`, and `FromStringAccumulator`. These likely represent the fundamental building blocks for BigInt operations.

3. **Analyze Individual Data Structures:**

   * **`Digits`:**  This class seems to represent a read-only view of a sequence of `digit_t`. The comments highlight that it *doesn't own* the memory and that digits are little-endian. The constructors allow creating `Digits` from raw memory, slicing existing `Digits`, and creating empty `Digits`. Methods like `operator[]`, `msd()`, `Normalize()`, `TrimOne()`, and `len()` suggest basic operations on these digit arrays. The `friend class ShiftedDigits` hint at a related class for shifted views (though not present in this file).

   * **`RWDigits`:** This inherits from `Digits` and provides *write access*. The `operator[]` is overloaded differently on 32-bit and 64-bit platforms due to alignment considerations. The `Clear()` and `set_len()` methods indicate mutability.

   * **`Platform`:** This is an abstract base class with a virtual `InterruptRequested()` method. This strongly suggests a mechanism for handling long-running BigInt operations and allowing them to be interrupted.

   * **`Processor`:** This class encapsulates the *operations* on BigInts. The methods like `Multiply`, `Divide`, `Modulo`, `ToString`, and `FromString` clearly map to common BigInt functionalities. The `Status` enum indicates whether an operation succeeded or was interrupted. The factory method `New` and `Destroy` pattern suggests manual memory management.

   * **`FromStringAccumulator`:** This class is designed for efficient parsing of BigInts from strings. The "Step 1-4" comments outline the usage pattern. The internal structure with `stack_parts_` and `heap_parts_` suggests an optimization for smaller numbers (using the stack) and a fallback to the heap for larger numbers. The `Parse` and `ParsePowerTwo` methods hint at optimized parsing for bases that are powers of 2.

4. **Examine Free Functions:** Look for functions outside of classes in the `v8::bigint` namespace. Functions like `Compare`, `Add`, `Subtract`, `BitwiseAnd_*`, `BitwiseOr_*`, `BitwiseXor_*`, `LeftShift`, `RightShift`, `AsIntN`, and `AsUintN_*` represent core BigInt arithmetic and bitwise operations. The naming conventions (e.g., `BitwiseAnd_PosPos`) suggest handling different sign combinations.

5. **Identify Constants and Type Definitions:**  Pay attention to `using` declarations (like `digit_t`, `twodigit_t`), `static constexpr` variables (like `kLog2DigitBits`, `kDigitBits`, `kBarrettThreshold`), and macros (like `BIGINT_H_DCHECK`). These define the underlying data types, constants, and debugging aids. The platform-specific definitions for `twodigit_t` are important.

6. **Connect to JavaScript:** Since this is part of V8, consider how these C++ structures and functions relate to JavaScript's `BigInt` type. The operations and functionalities are direct counterparts.

7. **Look for Performance Optimizations:** The comments about "fast" and "slow" operations, the `Platform` for interruption, the stack/heap optimization in `FromStringAccumulator`, and the special handling of power-of-two bases indicate performance considerations. The `ALWAYS_INLINE` macro further reinforces this.

8. **Consider Potential Error Scenarios:**  Think about what could go wrong when using BigInts. Overflow during parsing (handled by `kMaxSizeExceeded`), division by zero (likely handled within the `Divide` implementation, though not explicitly shown in the header), and incorrect input formats for `FromString` are all possibilities. The `BIGINT_H_DCHECK` macros suggest internal assertions for debugging.

9. **Synthesize and Organize:**  Group the identified features into logical categories (core functionality, data structures, optimizations, etc.) to present a clear and structured overview.

10. **Provide Examples:**  Illustrate the C++ concepts with corresponding JavaScript examples to make the connection clear for someone familiar with JavaScript.

11. **Consider Edge Cases and Assumptions:**  Think about the assumptions made in the code, such as the little-endian representation and the 4-byte alignment requirement. Mentioning potential user errors (like not allocating enough space for results) adds practical value.

By following these steps, we can systematically analyze the header file and extract its essential features, its relationship to JavaScript, and potential usage considerations. The key is to start with the high-level purpose and gradually drill down into the details of the code.
This C++ header file `v8/src/bigint/bigint.h` defines the core data structures and functions for implementing arbitrary-precision integers (BigInts) in the V8 JavaScript engine. Let's break down its functionality:

**Core Functionality:**

1. **Representation of BigInts:**
   - Defines `digit_t` as the fundamental unit for storing parts of a BigInt (typically `uintptr_t`).
   - Uses the `Digits` class to represent a read-only array of these `digit_t`. It does *not* own the underlying memory. Digits are stored in little-endian order.
   - Provides `RWDigits` as a writable version of `Digits`, also not owning the memory.

2. **Basic Arithmetic Operations:**
   - **Addition:** `Add`, `AddSigned`, `AddOne`.
   - **Subtraction:** `Subtract`, `SubtractSigned`, `SubtractOne`.
   - **Comparison:** `Compare`.

3. **Bitwise Operations:**
   - `BitwiseAnd_PosPos`, `BitwiseAnd_NegNeg`, `BitwiseAnd_PosNeg`.
   - `BitwiseOr_PosPos`, `BitwiseOr_NegNeg`, `BitwiseOr_PosNeg`.
   - `BitwiseXor_PosPos`, `BitwiseXor_NegNeg`, `BitwiseXor_PosNeg`.
   - `LeftShift`.
   - `RightShift`.

4. **Conversion and Truncation:**
   - `AsIntN`:  Converts to a signed N-bit integer.
   - `AsUintN_Pos`, `AsUintN_Neg`: Converts to an unsigned N-bit integer.

5. **Multiplication, Division, and Modulo (through `Processor` class):**
   - The `Processor` class encapsulates potentially long-running operations and provides a mechanism for interruption using the `Platform` interface.
   - `Multiply`.
   - `Divide`.
   - `Modulo`.

6. **String Conversion (through `Processor` class):**
   - `ToString`: Converts a BigInt to a string in a given radix.
   - `FromString` (using `FromStringAccumulator`): Parses a string into a BigInt.

7. **Memory Management:**
   - The `Digits` and `RWDigits` classes act as views on externally managed memory. The user (or other V8 components) is responsible for allocating and deallocating the underlying memory for the digit arrays.
   - The `Processor` class uses a `New` and `Destroy` pattern for its own lifecycle, suggesting manual memory management for `Processor` instances.

8. **Platform Abstraction:**
   - The `Platform` class provides an abstract interface for platform-specific functionalities, currently only supporting interruption of long-running operations via `InterruptRequested()`.

9. **Helper Functions for Result Lengths:**
   - Functions like `AddResultLength`, `MultiplyResultLength`, `DivideResultLength`, etc., help in pre-calculating the required size of the output buffer for BigInt operations, preventing buffer overflows.

10. **String Parsing Accumulator (`FromStringAccumulator`):**
    - Provides an efficient way to parse strings into BigInts, optimizing for both small and large numbers. It uses a stack-based buffer for small numbers and falls back to a heap-based buffer for larger ones.

**Is `v8/src/bigint/bigint.h` a Torque source file?**

No, `v8/src/bigint/bigint.h` is a standard C++ header file. Files ending in `.tq` are V8 Torque source files. Torque is a domain-specific language used within V8 for generating efficient machine code for certain runtime functions.

**Relationship to JavaScript and Examples:**

The functions and data structures in `bigint.h` directly implement the functionality of JavaScript's `BigInt` primitive type.

**JavaScript Examples:**

```javascript
// Addition
const a = 9007199254740991n; // Max safe integer + 1
const b = 1n;
const sum = a + b; // sum will be 9007199254740992n

// Subtraction
const difference = a - b; // difference will be 9007199254740990n

// Multiplication
const product = a * b; // product will be 9007199254740991n

// Division
const quotient = a / 2n; // quotient will be 4503599627370495n

// Modulo
const remainder = a % 3n; // remainder will be 1n

// Bitwise AND
const bitwiseAnd = 15n & 7n; // bitwiseAnd will be 7n (binary 111)

// Left Shift
const leftShift = 5n << 2n; // leftShift will be 20n (binary 10100)

// Right Shift
const rightShift = 20n >> 2n; // rightShift will be 5n (binary 101)

// String Conversion
const bigIntFromString = BigInt("123456789012345678901234567890");
const bigIntToString = a.toString(); // bigIntToString will be "9007199254740991"
```

Internally, when JavaScript code performs these `BigInt` operations, the V8 engine uses the C++ functions defined in files like `bigint.h` to perform the actual calculations on the underlying arbitrary-precision integer representation.

**Code Logic Reasoning with Assumptions:**

Let's take the `Add` function as an example:

**Assumption:** We have two `Digits` objects, `X` and `Y`, representing the addends, and an `RWDigits` object `Z` allocated with enough space to store the sum.

**Input:**
- `X`: `Digits` representing a BigInt (e.g., digits = `{1, 2, 3}`, len = 3, representing the number 321).
- `Y`: `Digits` representing another BigInt (e.g., digits = `{4, 5}`, len = 2, representing the number 54).
- `Z`: `RWDigits` with allocated memory (e.g., enough for 4 digits).

**Expected Output (after calling `Add(Z, X, Y)`):**
- `Z`: `RWDigits` will have its underlying memory updated to represent the sum (321 + 54 = 375), likely with:
    - `digits_` pointing to `{5, 7, 3, 0}` (little-endian).
    - `len_` will be set to 3 after calling `Z.Normalize()`.

**High-level logic within the `Add` function (simplified):**

1. Iterate through the digits of `X` and `Y` simultaneously, from least significant to most significant.
2. Add the corresponding digits along with any carry from the previous digit addition.
3. Store the result's digit in `Z`.
4. Update the carry for the next digit addition.
5. If one BigInt has more digits than the other, continue adding the remaining digits of the longer BigInt with the carry.
6. If there's a remaining carry after processing all digits, add it as the most significant digit in `Z`.
7. Normalize `Z` to remove leading zeros.

**User-Common Programming Errors:**

1. **Insufficient Memory Allocation:**
   - **Error:** Not allocating enough memory for the result of a BigInt operation.
   - **Example (C++ perspective):**
     ```c++
     std::vector<v8::bigint::digit_t> x_mem = {1, 0, 0, 0, 0};
     v8::bigint::Digits x(x_mem.data(), x_mem.size());
     std::vector<v8::bigint::digit_t> y_mem = {1};
     v8::bigint::Digits y(y_mem.data(), y_mem.size());

     // Incorrectly allocate only enough space for the larger input
     std::vector<v8::bigint::digit_t> z_mem(x.len());
     v8::bigint::RWDigits z(z_mem.data(), z_mem.size());

     v8::bigint::Add(z, x, y); // Potential buffer overflow if the sum has more digits
     ```
   - **JavaScript Equivalent (less direct but conceptually similar):** While JavaScript handles BigInt memory automatically, performing very large operations repeatedly without considering memory implications could lead to performance issues or even crashes in extreme cases.

2. **Incorrectly Handling Signs:**
   - **Error:** Not properly accounting for the signs of BigInts when performing operations, especially for bitwise operations where the representation of negative numbers matters.
   - **Example (C++ perspective):**  Calling `BitwiseAnd_PosPos` when one of the inputs is negative.
   - **JavaScript Equivalent:** Incorrectly assuming positive behavior for bitwise operations on negative `BigInt`s. JavaScript uses two's complement for bitwise operations on negative `BigInt`s.

3. **Misunderstanding Little-Endianness:**
   - **Error:** When directly manipulating the underlying digit arrays, not understanding that the least significant digit comes first in memory.
   - **Example (C++ perspective):**  Iterating through the digits in reverse order when performing a manual operation.

4. **Not Normalizing Results:**
   - **Error:** Forgetting to call `Normalize()` on the result `RWDigits` object, leading to incorrect length reporting and potential issues in subsequent operations.
   - **Example (C++ perspective):**
     ```c++
     // ... (BigInt addition) ...
     // Forgot to call z.Normalize();
     std::cout << "Length of result: " << z.len() << std::endl; // Might be larger than expected
     ```

This header file is a crucial component for V8's ability to handle arbitrarily large integers in JavaScript, enabling developers to work with numbers beyond the limitations of standard JavaScript numbers.

### 提示词
```
这是目录为v8/src/bigint/bigint.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/bigint/bigint.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```c
// Copyright 2021 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_BIGINT_BIGINT_H_
#define V8_BIGINT_BIGINT_H_

#include <stdint.h>

#include <algorithm>
#include <cstring>
#include <iostream>
#include <vector>

namespace v8 {
namespace bigint {

// To play nice with embedders' macros, we define our own DCHECK here.
// It's only used in this file, and undef'ed at the end.
#ifdef DEBUG
#define BIGINT_H_DCHECK(cond)                         \
  if (!(cond)) {                                      \
    std::cerr << __FILE__ << ":" << __LINE__ << ": "; \
    std::cerr << "Assertion failed: " #cond "\n";     \
    abort();                                          \
  }

extern bool kAdvancedAlgorithmsEnabledInLibrary;
#else
#define BIGINT_H_DCHECK(cond) (void(0))
#endif

// The type of a digit: a register-width unsigned integer.
using digit_t = uintptr_t;
using signed_digit_t = intptr_t;
#if UINTPTR_MAX == 0xFFFFFFFF
// 32-bit platform.
using twodigit_t = uint64_t;
#define HAVE_TWODIGIT_T 1
static constexpr int kLog2DigitBits = 5;
#elif UINTPTR_MAX == 0xFFFFFFFFFFFFFFFF
// 64-bit platform.
static constexpr int kLog2DigitBits = 6;
#if defined(__SIZEOF_INT128__)
using twodigit_t = __uint128_t;
#define HAVE_TWODIGIT_T 1
#endif  // defined(__SIZEOF_INT128__)
#else
#error Unsupported platform.
#endif
static constexpr int kDigitBits = 1 << kLog2DigitBits;
static_assert(kDigitBits == 8 * sizeof(digit_t), "inconsistent type sizes");

// Describes an array of digits, also known as a BigInt. Unsigned.
// Does not own the memory it points at, and only gives read-only access to it.
// Digits are stored in little-endian order.
class Digits {
 public:
  // This is the constructor intended for public consumption.
  Digits(const digit_t* mem, int len)
      // The const_cast here is ugly, but we need the digits field to be mutable
      // for the RWDigits subclass. We pinky swear to not mutate the memory with
      // this class.
      : Digits(const_cast<digit_t*>(mem), len) {}

  Digits(digit_t* mem, int len) : digits_(mem), len_(len) {
    // Require 4-byte alignment (even on 64-bit platforms).
    // TODO(jkummerow): See if we can tighten BigInt alignment in V8 to
    // system pointer size, and raise this requirement to that.
    BIGINT_H_DCHECK((reinterpret_cast<uintptr_t>(mem) & 3) == 0);
  }

  // Provides a "slice" view into another Digits object.
  Digits(Digits src, int offset, int len)
      : digits_(src.digits_ + offset),
        len_(std::max(0, std::min(src.len_ - offset, len))) {
    BIGINT_H_DCHECK(offset >= 0);
  }

  Digits() : Digits(static_cast<digit_t*>(nullptr), 0) {}

  // Alternative way to get a "slice" view into another Digits object.
  Digits operator+(int i) {
    BIGINT_H_DCHECK(i >= 0 && i <= len_);
    return Digits(digits_ + i, len_ - i);
  }

  // Provides access to individual digits.
  digit_t operator[](int i) {
    BIGINT_H_DCHECK(i >= 0 && i < len_);
    return read_4byte_aligned(i);
  }
  // Convenience accessor for the most significant digit.
  digit_t msd() {
    BIGINT_H_DCHECK(len_ > 0);
    return read_4byte_aligned(len_ - 1);
  }
  // Checks "pointer equality" (does not compare digits contents).
  bool operator==(const Digits& other) const {
    return digits_ == other.digits_ && len_ == other.len_;
  }

  // Decrements {len_} until there are no leading zero digits left.
  void Normalize() {
    while (len_ > 0 && msd() == 0) len_--;
  }
  // Unconditionally drops exactly one leading zero digit.
  void TrimOne() {
    BIGINT_H_DCHECK(len_ > 0 && msd() == 0);
    len_--;
  }

  int len() { return len_; }
  const digit_t* digits() const { return digits_; }

 protected:
  friend class ShiftedDigits;
  digit_t* digits_;
  int len_;

 private:
  // We require externally-provided digits arrays to be 4-byte aligned, but
  // not necessarily 8-byte aligned; so on 64-bit platforms we use memcpy
  // to allow unaligned reads.
  digit_t read_4byte_aligned(int i) {
    if (sizeof(digit_t) == 4) {
      return digits_[i];
    } else {
      digit_t result;
      memcpy(&result, static_cast<const void*>(digits_ + i), sizeof(result));
      return result;
    }
  }
};

// Writable version of a Digits array.
// Does not own the memory it points at.
class RWDigits : public Digits {
 public:
  RWDigits(digit_t* mem, int len) : Digits(mem, len) {}
  RWDigits(RWDigits src, int offset, int len) : Digits(src, offset, len) {}
  RWDigits operator+(int i) {
    BIGINT_H_DCHECK(i >= 0 && i <= len_);
    return RWDigits(digits_ + i, len_ - i);
  }

#if UINTPTR_MAX == 0xFFFFFFFF
  digit_t& operator[](int i) {
    BIGINT_H_DCHECK(i >= 0 && i < len_);
    return digits_[i];
  }
#else
  // 64-bit platform. We only require digits arrays to be 4-byte aligned,
  // so we use a wrapper class to allow regular array syntax while
  // performing unaligned memory accesses under the hood.
  class WritableDigitReference {
   public:
    // Support "X[i] = x" notation.
    void operator=(digit_t digit) { memcpy(ptr_, &digit, sizeof(digit)); }
    // Support "X[i] = Y[j]" notation.
    WritableDigitReference& operator=(const WritableDigitReference& src) {
      memcpy(ptr_, src.ptr_, sizeof(digit_t));
      return *this;
    }
    // Support "x = X[i]" notation.
    operator digit_t() {
      digit_t result;
      memcpy(&result, ptr_, sizeof(result));
      return result;
    }

   private:
    // This class is not for public consumption.
    friend class RWDigits;
    // Primary constructor.
    explicit WritableDigitReference(digit_t* ptr)
        : ptr_(reinterpret_cast<uint32_t*>(ptr)) {}
    // Required for returning WDR instances from "operator[]" below.
    WritableDigitReference(const WritableDigitReference& src) = default;

    uint32_t* ptr_;
  };

  WritableDigitReference operator[](int i) {
    BIGINT_H_DCHECK(i >= 0 && i < len_);
    return WritableDigitReference(digits_ + i);
  }
#endif

  digit_t* digits() { return digits_; }
  void set_len(int len) { len_ = len; }

  void Clear() { memset(digits_, 0, len_ * sizeof(digit_t)); }
};

class Platform {
 public:
  virtual ~Platform() = default;

  // If you want the ability to interrupt long-running operations, implement
  // a Platform subclass that overrides this method. It will be queried
  // every now and then by long-running operations.
  virtual bool InterruptRequested() { return false; }
};

// These are the operations that this library supports.
// The signatures follow the convention:
//
//   void Operation(RWDigits results, Digits inputs);
//
// You must preallocate the result; use the respective {OperationResultLength}
// function to determine its minimum required length. The actual result may
// be smaller, so you should call result.Normalize() on the result.
//
// The operations are divided into two groups: "fast" (O(n) with small
// coefficient) operations are exposed directly as free functions, "slow"
// operations are methods on a {Processor} object, which provides
// support for interrupting execution via the {Platform}'s {InterruptRequested}
// mechanism when it takes too long. These functions return a {Status} value.

// Returns r such that r < 0 if A < B; r > 0 if A > B; r == 0 if A == B.
// Defined here to be inlineable, which helps ia32 a lot (64-bit platforms
// don't care).
inline int Compare(Digits A, Digits B) {
  A.Normalize();
  B.Normalize();
  int diff = A.len() - B.len();
  if (diff != 0) return diff;
  int i = A.len() - 1;
  while (i >= 0 && A[i] == B[i]) i--;
  if (i < 0) return 0;
  return A[i] > B[i] ? 1 : -1;
}

// Z := X + Y
void Add(RWDigits Z, Digits X, Digits Y);
// Addition of signed integers. Returns true if the result is negative.
bool AddSigned(RWDigits Z, Digits X, bool x_negative, Digits Y,
               bool y_negative);
// Z := X + 1
void AddOne(RWDigits Z, Digits X);

// Z := X - Y. Requires X >= Y.
void Subtract(RWDigits Z, Digits X, Digits Y);
// Subtraction of signed integers. Returns true if the result is negative.
bool SubtractSigned(RWDigits Z, Digits X, bool x_negative, Digits Y,
                    bool y_negative);
// Z := X - 1
void SubtractOne(RWDigits Z, Digits X);

// The bitwise operations assume that negative BigInts are represented as
// sign+magnitude. Their behavior depends on the sign of the inputs: negative
// inputs perform an implicit conversion to two's complement representation.
// Z := X & Y
void BitwiseAnd_PosPos(RWDigits Z, Digits X, Digits Y);
// Call this for a BigInt x = (magnitude=X, negative=true).
void BitwiseAnd_NegNeg(RWDigits Z, Digits X, Digits Y);
// Positive X, negative Y. Callers must swap arguments as needed.
void BitwiseAnd_PosNeg(RWDigits Z, Digits X, Digits Y);
void BitwiseOr_PosPos(RWDigits Z, Digits X, Digits Y);
void BitwiseOr_NegNeg(RWDigits Z, Digits X, Digits Y);
void BitwiseOr_PosNeg(RWDigits Z, Digits X, Digits Y);
void BitwiseXor_PosPos(RWDigits Z, Digits X, Digits Y);
void BitwiseXor_NegNeg(RWDigits Z, Digits X, Digits Y);
void BitwiseXor_PosNeg(RWDigits Z, Digits X, Digits Y);
void LeftShift(RWDigits Z, Digits X, digit_t shift);
// RightShiftState is provided by RightShift_ResultLength and used by the actual
// RightShift to avoid some recomputation.
struct RightShiftState {
  bool must_round_down = false;
};
void RightShift(RWDigits Z, Digits X, digit_t shift,
                const RightShiftState& state);

// Z := (least significant n bits of X, interpreted as a signed n-bit integer).
// Returns true if the result is negative; Z will hold the absolute value.
bool AsIntN(RWDigits Z, Digits X, bool x_negative, int n);
// Z := (least significant n bits of X).
void AsUintN_Pos(RWDigits Z, Digits X, int n);
// Same, but X is the absolute value of a negative BigInt.
void AsUintN_Neg(RWDigits Z, Digits X, int n);

enum class Status { kOk, kInterrupted };

class FromStringAccumulator;

class Processor {
 public:
  // Takes ownership of {platform}.
  static Processor* New(Platform* platform);

  // Use this for any std::unique_ptr holding an instance of {Processor}.
  class Destroyer {
   public:
    void operator()(Processor* proc) { proc->Destroy(); }
  };
  // When not using std::unique_ptr, call this to delete the instance.
  void Destroy();

  // Z := X * Y
  Status Multiply(RWDigits Z, Digits X, Digits Y);
  // Q := A / B
  Status Divide(RWDigits Q, Digits A, Digits B);
  // R := A % B
  Status Modulo(RWDigits R, Digits A, Digits B);

  // {out_length} initially contains the allocated capacity of {out}, and
  // upon return will be set to the actual length of the result string.
  Status ToString(char* out, uint32_t* out_length, Digits X, int radix,
                  bool sign);

  // Z := the contents of {accumulator}.
  // Assume that this leaves {accumulator} in unusable state.
  Status FromString(RWDigits Z, FromStringAccumulator* accumulator);

 protected:
  // Use {Destroy} or {Destroyer} instead of the destructor directly.
  ~Processor() = default;
};

inline int AddResultLength(int x_length, int y_length) {
  return std::max(x_length, y_length) + 1;
}
inline int AddSignedResultLength(int x_length, int y_length, bool same_sign) {
  return same_sign ? AddResultLength(x_length, y_length)
                   : std::max(x_length, y_length);
}
inline int SubtractResultLength(int x_length, int y_length) { return x_length; }
inline int SubtractSignedResultLength(int x_length, int y_length,
                                      bool same_sign) {
  return same_sign ? std::max(x_length, y_length)
                   : AddResultLength(x_length, y_length);
}
inline int MultiplyResultLength(Digits X, Digits Y) {
  return X.len() + Y.len();
}
constexpr int kBarrettThreshold = 13310;
inline int DivideResultLength(Digits A, Digits B) {
#if V8_ADVANCED_BIGINT_ALGORITHMS
  BIGINT_H_DCHECK(kAdvancedAlgorithmsEnabledInLibrary);
  // The Barrett division algorithm needs one extra digit for temporary use.
  int kBarrettExtraScratch = B.len() >= kBarrettThreshold ? 1 : 0;
#else
  // If this fails, set -DV8_ADVANCED_BIGINT_ALGORITHMS in any compilation unit
  // that #includes this header.
  BIGINT_H_DCHECK(!kAdvancedAlgorithmsEnabledInLibrary);
  constexpr int kBarrettExtraScratch = 0;
#endif
  return A.len() - B.len() + 1 + kBarrettExtraScratch;
}
inline int ModuloResultLength(Digits B) { return B.len(); }

uint32_t ToStringResultLength(Digits X, int radix, bool sign);
// In DEBUG builds, the result of {ToString} will be initialized to this value.
constexpr char kStringZapValue = '?';

int RightShift_ResultLength(Digits X, bool x_sign, digit_t shift,
                            RightShiftState* state);

// Returns -1 if this "asIntN" operation would be a no-op.
int AsIntNResultLength(Digits X, bool x_negative, int n);
// Returns -1 if this "asUintN" operation would be a no-op.
int AsUintN_Pos_ResultLength(Digits X, int n);
inline int AsUintN_Neg_ResultLength(int n) {
  return ((n - 1) / kDigitBits) + 1;
}

// Support for parsing BigInts from Strings, using an Accumulator object
// for intermediate state.

class ProcessorImpl;

#if !defined(DEBUG) && (defined(__GNUC__) || defined(__clang__))
// Clang supports this since 3.9, GCC since 4.x.
#define ALWAYS_INLINE inline __attribute__((always_inline))
#elif !defined(DEBUG) && defined(_MSC_VER)
#define ALWAYS_INLINE __forceinline
#else
#define ALWAYS_INLINE inline
#endif

static constexpr int kStackParts = 8;

// A container object for all metadata required for parsing a BigInt from
// a string.
// Aggressively optimized not to waste instructions for small cases, while
// also scaling transparently to huge cases.
// Defined here in the header so that it can be inlined.
class FromStringAccumulator {
 public:
  enum class Result { kOk, kMaxSizeExceeded };

  // Step 1: Create a FromStringAccumulator instance. For best performance,
  // stack allocation is recommended.
  // {max_digits} is only used for refusing to grow beyond a given size
  // (see "Step 2" below). It does not cause pre-allocation, so feel free to
  // specify a large maximum.
  // TODO(jkummerow): The limit applies to the number of intermediate chunks,
  // whereas the final result will be slightly smaller (depending on {radix}).
  // So for sufficiently large N, setting max_digits=N here will not actually
  // allow parsing BigInts with N digits. We can fix that if/when anyone cares.
  explicit FromStringAccumulator(int max_digits)
      : max_digits_(std::max(max_digits, kStackParts)) {}

  // Step 2: Call this method to read all characters.
  // {CharIt} should be a forward iterator and
  // std::iterator_traits<CharIt>::value_type shall be a character type, such as
  // uint8_t or uint16_t. {end} should be one past the last character (i.e.
  // {start == end} would indicate an empty string). Returns the current
  // position when an invalid character is encountered.
  template <class CharIt>
  ALWAYS_INLINE CharIt Parse(CharIt start, CharIt end, digit_t radix);

  // Step 3: Check if a result is available, and determine its required
  // allocation size (guaranteed to be <= max_digits passed to the constructor).
  Result result() { return result_; }
  int ResultLength() {
    return std::max(stack_parts_used_, static_cast<int>(heap_parts_.size()));
  }

  // Step 4: Use BigIntProcessor::FromString() to retrieve the result into an
  // {RWDigits} struct allocated for the size returned by step 3.

 private:
  friend class ProcessorImpl;

  template <class CharIt>
  ALWAYS_INLINE CharIt ParsePowerTwo(CharIt start, CharIt end, digit_t radix);

  ALWAYS_INLINE bool AddPart(digit_t multiplier, digit_t part, bool is_last);
  ALWAYS_INLINE bool AddPart(digit_t part);

  digit_t stack_parts_[kStackParts];
  std::vector<digit_t> heap_parts_;
  digit_t max_multiplier_{0};
  digit_t last_multiplier_;
  const int max_digits_;
  Result result_{Result::kOk};
  int stack_parts_used_{0};
  bool inline_everything_{false};
  uint8_t radix_{0};
};

// The rest of this file is the inlineable implementation of
// FromStringAccumulator methods.

#if defined(__GNUC__) || defined(__clang__)
// Clang supports this since 3.9, GCC since 5.x.
#define HAVE_BUILTIN_MUL_OVERFLOW 1
#else
#define HAVE_BUILTIN_MUL_OVERFLOW 0
#endif

// Numerical value of the first 127 ASCII characters, using 255 as sentinel
// for "invalid".
static constexpr uint8_t kCharValue[] = {
    255, 255, 255, 255, 255, 255, 255, 255,  // 0..7
    255, 255, 255, 255, 255, 255, 255, 255,  // 8..15
    255, 255, 255, 255, 255, 255, 255, 255,  // 16..23
    255, 255, 255, 255, 255, 255, 255, 255,  // 24..31
    255, 255, 255, 255, 255, 255, 255, 255,  // 32..39
    255, 255, 255, 255, 255, 255, 255, 255,  // 40..47
    0,   1,   2,   3,   4,   5,   6,   7,    // 48..55    '0' == 48
    8,   9,   255, 255, 255, 255, 255, 255,  // 56..63    '9' == 57
    255, 10,  11,  12,  13,  14,  15,  16,   // 64..71    'A' == 65
    17,  18,  19,  20,  21,  22,  23,  24,   // 72..79
    25,  26,  27,  28,  29,  30,  31,  32,   // 80..87
    33,  34,  35,  255, 255, 255, 255, 255,  // 88..95    'Z' == 90
    255, 10,  11,  12,  13,  14,  15,  16,   // 96..103   'a' == 97
    17,  18,  19,  20,  21,  22,  23,  24,   // 104..111
    25,  26,  27,  28,  29,  30,  31,  32,   // 112..119
    33,  34,  35,  255, 255, 255, 255, 255,  // 120..127  'z' == 122
};

// A space- and time-efficient way to map {2,4,8,16,32} to {1,2,3,4,5}.
static constexpr uint8_t kCharBits[] = {1, 2, 3, 0, 4, 0, 0, 0, 5};

template <class CharIt>
CharIt FromStringAccumulator::ParsePowerTwo(CharIt current, CharIt end,
                                            digit_t radix) {
  radix_ = static_cast<uint8_t>(radix);
  const int char_bits = kCharBits[radix >> 2];
  int bits_left;
  bool done = false;
  do {
    digit_t part = 0;
    bits_left = kDigitBits;
    while (true) {
      digit_t d;  // Numeric value of the current character {c}.
      uint32_t c = *current;
      if (c > 127 || (d = bigint::kCharValue[c]) >= radix) {
        done = true;
        break;
      }

      if (bits_left < char_bits) break;
      bits_left -= char_bits;
      part = (part << char_bits) | d;

      ++current;
      if (current == end) {
        done = true;
        break;
      }
    }
    if (!AddPart(part)) return current;
  } while (!done);
  // We use the unused {last_multiplier_} field to
  // communicate how many bits are unused in the last part.
  last_multiplier_ = bits_left;
  return current;
}

template <class CharIt>
CharIt FromStringAccumulator::Parse(CharIt start, CharIt end, digit_t radix) {
  BIGINT_H_DCHECK(2 <= radix && radix <= 36);
  CharIt current = start;
#if !HAVE_BUILTIN_MUL_OVERFLOW
  const digit_t kMaxMultiplier = (~digit_t{0}) / radix;
#endif
#if HAVE_TWODIGIT_T  // The inlined path requires twodigit_t availability.
  // The max supported radix is 36, and Math.log2(36) == 5.169..., so we
  // need at most 5.17 bits per char.
  static constexpr int kInlineThreshold = kStackParts * kDigitBits * 100 / 517;
  inline_everything_ = (end - start) <= kInlineThreshold;
#endif
  if (!inline_everything_ && (radix & (radix - 1)) == 0) {
    return ParsePowerTwo(start, end, radix);
  }
  bool done = false;
  do {
    digit_t multiplier = 1;
    digit_t part = 0;
    while (true) {
      digit_t d;  // Numeric value of the current character {c}.
      uint32_t c = *current;
      if (c > 127 || (d = bigint::kCharValue[c]) >= radix) {
        done = true;
        break;
      }

#if HAVE_BUILTIN_MUL_OVERFLOW
      digit_t new_multiplier;
      if (__builtin_mul_overflow(multiplier, radix, &new_multiplier)) break;
      multiplier = new_multiplier;
#else
      if (multiplier > kMaxMultiplier) break;
      multiplier *= radix;
#endif
      part = part * radix + d;

      ++current;
      if (current == end) {
        done = true;
        break;
      }
    }
    if (!AddPart(multiplier, part, done)) return current;
  } while (!done);
  return current;
}

bool FromStringAccumulator::AddPart(digit_t multiplier, digit_t part,
                                    bool is_last) {
#if HAVE_TWODIGIT_T
  if (inline_everything_) {
    // Inlined version of {MultiplySingle}.
    digit_t carry = part;
    digit_t high = 0;
    for (int i = 0; i < stack_parts_used_; i++) {
      twodigit_t result = twodigit_t{stack_parts_[i]} * multiplier;
      digit_t new_high = result >> bigint::kDigitBits;
      digit_t low = static_cast<digit_t>(result);
      result = twodigit_t{low} + high + carry;
      carry = result >> bigint::kDigitBits;
      stack_parts_[i] = static_cast<digit_t>(result);
      high = new_high;
    }
    stack_parts_[stack_parts_used_++] = carry + high;
    return true;
  }
#else
  BIGINT_H_DCHECK(!inline_everything_);
#endif
  if (is_last) {
    last_multiplier_ = multiplier;
  } else {
    BIGINT_H_DCHECK(max_multiplier_ == 0 || max_multiplier_ == multiplier);
    max_multiplier_ = multiplier;
  }
  return AddPart(part);
}

bool FromStringAccumulator::AddPart(digit_t part) {
  if (stack_parts_used_ < kStackParts) {
    stack_parts_[stack_parts_used_++] = part;
    return true;
  }
  if (heap_parts_.size() == 0) {
    // Initialize heap storage. Copy the stack part to make things easier later.
    heap_parts_.reserve(kStackParts * 2);
    for (int i = 0; i < kStackParts; i++) {
      heap_parts_.push_back(stack_parts_[i]);
    }
  }
  if (static_cast<int>(heap_parts_.size()) >= max_digits_) {
    result_ = Result::kMaxSizeExceeded;
    return false;
  }
  heap_parts_.push_back(part);
  return true;
}

}  // namespace bigint
}  // namespace v8

#undef BIGINT_H_DCHECK
#undef ALWAYS_INLINE
#undef HAVE_BUILTIN_MUL_OVERFLOW

#endif  // V8_BIGINT_BIGINT_H_
```