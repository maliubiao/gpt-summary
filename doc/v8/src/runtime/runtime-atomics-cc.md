Response:
Let's break down the thought process to analyze the provided C++ code.

**1. Initial Understanding - What is this file about?**

The filename `runtime-atomics.cc` and the comment "// Implement Atomic accesses to ArrayBuffers and SharedArrayBuffers." immediately tell us the core purpose: handling atomic operations in JavaScript's typed arrays (specifically, those backed by `ArrayBuffer` and `SharedArrayBuffer`). The reference to `https://tc39.es/ecma262/#sec-atomics` confirms this is related to the JavaScript `Atomics` object.

**2. High-Level Structure Scan:**

I'll quickly scan the code for major sections and patterns:

* **Copyright and Includes:** Standard header. Nothing particularly informative about the *functionality* here.
* **Namespace:** `v8::internal`. This tells us it's internal V8 implementation, not public API.
* **Conditional Compilation (`#if`, `#elif`, `#else`):**  A large block is wrapped in conditional compilation based on target architecture (`V8_TARGET_ARCH_...`). This is a key insight – the implementation of atomic operations varies depending on the CPU.
* **Helper Functions/Templates:**  Look for reusable code blocks. I see templates like `ExchangeSeqCst`, `CompareExchangeSeqCst`, `LoadSeqCst`, `StoreSeqCst`, and `FromObject`, `ToObject`. These suggest common operations on different data types.
* **RUNTIME_FUNCTION Macros:**  These are V8-specific macros that define functions callable from JavaScript. The names like `Runtime_AtomicsLoad64`, `Runtime_AtomicsStore`, etc., strongly suggest the mapping to JavaScript `Atomics` methods.
* **Error Handling:**  Look for patterns related to error checking. The `THROW_ERROR_RETURN_FAILURE_ON_DETACHED_OR_OUT_OF_BOUNDS` macro stands out.
* **Specific Data Types:** Look for mentions of `JSTypedArray`, `SharedArrayBuffer`, `BigInt`.

**3. Deep Dive into the Conditional Compilation Block:**

This is crucial. The different implementations for different architectures highlight the platform-specific nature of low-level atomic operations.

* **Unimplemented (`UNIMPLEMENTED()`):**  Some platforms might not have optimized atomic operations available.
* **GCC/Clang (`__atomic_...`):**  Uses built-in atomic intrinsics provided by GCC and Clang.
* **MSVC (`Interlocked...`):** Uses Windows API functions for atomic operations.
* **Error for Unsupported Platforms:**  Ensures that the code doesn't accidentally compile on an architecture where atomics aren't handled.

**4. Analyzing the Helper Functions/Templates:**

* **`LoadSeqCst`, `StoreSeqCst`, etc.:** These clearly represent the fundamental atomic operations (load, store, exchange, compare-and-swap, add, subtract, etc.) with sequential consistency (`SeqCst`).
* **`FromObject`, `ToObject`:** These handle the conversion between JavaScript values (Numbers, BigInts) and their C++ counterparts. The template specialization indicates support for different data types.

**5. Connecting `RUNTIME_FUNCTION` to JavaScript:**

The names of the `RUNTIME_FUNCTION`s directly correspond to the methods of the JavaScript `Atomics` object. For example:

* `Runtime_AtomicsLoad64`  -> `Atomics.load(bigInt64Array, index)`
* `Runtime_AtomicsStore` -> `Atomics.store(typedArray, index, value)`
* `Runtime_AtomicsExchange` -> `Atomics.exchange(typedArray, index, value)`

**6. Understanding the Logic within `RUNTIME_FUNCTION`s:**

* **Argument Handling:** They receive `RuntimeArguments`. The code extracts the `JSTypedArray`, index, and value from these arguments.
* **Type Checking:**  The code checks the type of the `JSTypedArray` (e.g., `kExternalBigInt64Array`, `kExternalUint8Array`).
* **Bounds Checking/Detached Check:** The `THROW_ERROR_RETURN_FAILURE_ON_DETACHED_OR_OUT_OF_BOUNDS` macro ensures that the operations are performed on valid memory locations.
* **Core Atomic Operation:**  Inside the `switch` statements or conditional blocks, the appropriate template function (`Load`, `Store`, `Exchange`, etc.) is called to perform the actual atomic operation using the platform-specific implementation.
* **Return Value:** The result of the atomic operation is converted back to a JavaScript value using the `ToObject` helper and returned.

**7. Focusing on `Runtime_AtomicsLoadSharedStructOrArray` and related functions:**

These functions handle atomic operations on fields of shared structs and shared arrays, rather than on the raw buffer of a typed array. The `LookupIterator` and property access mechanisms are relevant here.

**8. Considering User Errors:**

By understanding the function's purpose (atomic operations) and the error handling mechanisms (detachment, out-of-bounds), I can infer common user errors. Trying to access an already detached buffer or accessing an index outside the bounds of the array are obvious candidates. Incorrect data types for the atomic operation (e.g., trying to store a non-integer value in an integer array) are also likely errors.

**9. Structuring the Output:**

Finally, I organize my findings into the requested categories: functionality, Torque, JavaScript examples, logic reasoning, and common errors. I use the insights gained from the previous steps to generate concrete examples and explanations.

**Self-Correction/Refinement:**

Initially, I might have overlooked the distinction between regular `TypedArray` and `SharedArrayBuffer`. Realizing that the code handles both (and especially the `SharedArrayBuffer` with its need for explicit atomic operations) is important. Also, the handling of `BigInt` requires separate consideration because it's not a standard number type. Paying attention to the different `RUNTIME_FUNCTION`s and their corresponding `Atomics` methods in JavaScript helped ensure I covered the key functionalities.
This C++ source code file, `v8/src/runtime/runtime-atomics.cc`, implements the runtime functionalities for the JavaScript `Atomics` object. It provides low-level atomic operations that can be performed on shared memory locations, specifically within `ArrayBuffer` and `SharedArrayBuffer` objects.

Here's a breakdown of its functions:

**Core Functionality:**

* **Atomic Operations on Typed Arrays:** The file implements various atomic operations defined in the ECMAScript specification for `Atomics`, including:
    * **`load()`:** Atomically reads a value from a specific index in a typed array.
    * **`store()`:** Atomically writes a value to a specific index in a typed array.
    * **`exchange()`:** Atomically replaces the value at a specific index with a new value and returns the original value.
    * **`compareExchange()`:** Atomically compares the value at a specific index with an expected value. If they match, it replaces the value with a new value and returns the original value. Otherwise, it returns the current value.
    * **Arithmetic and Bitwise Operations (`add()`, `sub()`, `and()`, `or()`, `xor()`):** These atomically perform the respective operations on the value at a specific index and return the original value.

* **Platform-Specific Implementations:**  The code uses conditional compilation (`#if`, `#elif`, `#else`) to provide platform-optimized implementations of the atomic operations. It leverages platform-specific atomic primitives provided by GCC/Clang (`__atomic_...`) or MSVC (`Interlocked...`) where available. For other platforms, it might fall back to less optimized or even unimplemented versions.

* **Handling of `BigInt`:**  It includes specific handling for `BigInt64Array` and `BigUint64Array`, allowing atomic operations on 64-bit big integers.

* **Error Handling:** The code includes checks for detached array buffers and out-of-bounds access, throwing appropriate `TypeError` exceptions as specified in the ECMAScript standard.

* **Atomic Operations on Shared Structs/Arrays:**  It provides runtime functions for atomic operations on properties of shared structs and shared arrays. These operations ensure that access and modification of shared object properties are done atomically.

**Relationship to JavaScript:**

This C++ code directly implements the functionality exposed by the JavaScript `Atomics` object. When you call methods like `Atomics.load()`, `Atomics.store()`, etc., in JavaScript, the V8 engine will eventually execute the corresponding runtime functions defined in this file.

**JavaScript Examples:**

```javascript
// Using Atomics with Int32Array
const buffer = new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT * 2);
const view = new Int32Array(buffer);

// Atomics.load()
console.log(Atomics.load(view, 0)); // Output: 0 (initial value)

// Atomics.store()
Atomics.store(view, 0, 10);
console.log(Atomics.load(view, 0)); // Output: 10

// Atomics.add()
Atomics.add(view, 0, 5);
console.log(Atomics.load(view, 0)); // Output: 15

// Atomics.exchange()
const oldValue = Atomics.exchange(view, 0, 20);
console.log(oldValue);          // Output: 15
console.log(Atomics.load(view, 0)); // Output: 20

// Atomics.compareExchange()
const originalValue = Atomics.compareExchange(view, 0, 20, 30);
console.log(originalValue);      // Output: 20
console.log(Atomics.load(view, 0)); // Output: 30

// Using Atomics with BigInt64Array
const bigIntBuffer = new SharedArrayBuffer(BigInt64Array.BYTES_PER_ELEMENT * 1);
const bigIntView = new BigInt64Array(bigIntBuffer);

Atomics.store(bigIntView, 0, 10n);
console.log(Atomics.load(bigIntView, 0)); // Output: 10n
```

**Is it a Torque Source File?**

Based on the provided code snippet, `v8/src/runtime/runtime-atomics.cc` does **not** end with `.tq`. Therefore, it is **not** a V8 Torque source file. It's a standard C++ source file. Torque files are used for defining built-in functions in a more declarative way.

**Code Logic Reasoning (with assumptions):**

Let's consider the `Runtime_AtomicsAdd` function as an example.

**Assumption:** We are on an architecture where atomic operations are implemented using GCC's `__atomic_fetch_add`.

**Input:**
* `args`: A `RuntimeArguments` object containing:
    * `args[0]`: A `JSTypedArray` (e.g., an `Int32Array`) pointing to a `SharedArrayBuffer`.
    * `args[1]`: A number representing the index in the typed array.
    * `args[2]`: A number representing the value to add.

**Example Input Values:**
* `args[0]`: An `Int32Array` of length 2, backed by a `SharedArrayBuffer`. Let's say the initial value at index 0 is 5.
* `args[1]`: The number `0`.
* `args[2]`: The number `3`.

**Code Logic Flow (Simplified):**

1. **Argument Extraction:** The function extracts the `JSTypedArray`, index (converted to a `size_t`), and the value to add (converted to an integer).
2. **Detached/Bounds Check:** It checks if the `SharedArrayBuffer` is detached or if the index is out of bounds. If so, it throws a `TypeError`.
3. **Pointer Calculation:** It calculates the memory address of the element at the specified index within the shared buffer.
4. **Atomic Addition:** It calls the `AddSeqCst` template function, which, in this assumed scenario, calls `__atomic_fetch_add` on the calculated memory address, adding the provided value (3) to the current value (5) atomically. `__atomic_fetch_add` returns the original value *before* the addition.
5. **Result Conversion:** The original value (5) is converted back to a JavaScript number.
6. **Return Value:** The function returns the JavaScript number representing the original value (5).

**Output:** The JavaScript code calling `Atomics.add(view, 0, 3)` would receive the number `5` as the return value. The value at `view[0]` in the shared buffer would now be `8`.

**Common User Programming Errors:**

1. **Using `Atomics` with non-shared memory:**  `Atomics` operations are designed for shared memory (`SharedArrayBuffer`). Trying to use them with a regular `ArrayBuffer` will typically result in an error or undefined behavior, as the atomicity guarantees are not relevant in a single-threaded context.

   ```javascript
   // Error: Using Atomics with a regular ArrayBuffer
   const buffer = new ArrayBuffer(4);
   const view = new Int32Array(buffer);
   try {
     Atomics.add(view, 0, 5); // This might throw an error or behave unexpectedly
   } catch (e) {
     console.error(e); // Likely a TypeError or similar
   }
   ```

2. **Incorrect data types:** Providing a value that cannot be converted to the underlying data type of the typed array can lead to errors.

   ```javascript
   const buffer = new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT);
   const view = new Int32Array(buffer);
   try {
     Atomics.store(view, 0, "hello"); // Error: "hello" cannot be directly stored in an Int32Array
   } catch (e) {
     console.error(e); // Likely a TypeError
   }
   ```

3. **Out-of-bounds access:**  Attempting to access an index outside the valid bounds of the typed array will result in a `TypeError`.

   ```javascript
   const buffer = new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT * 2);
   const view = new Int32Array(buffer);
   try {
     Atomics.load(view, 2); // Error: Index 2 is out of bounds (valid indices are 0 and 1)
   } catch (e) {
     console.error(e); // TypeError: Index is out of bounds
   }
   ```

4. **Operating on a detached buffer:**  If the underlying `SharedArrayBuffer` has been detached (though this is less common with `SharedArrayBuffer` compared to `ArrayBuffer` in older contexts), attempting to perform atomic operations will throw a `TypeError`.

5. **Misunderstanding atomicity:**  Users might incorrectly assume that non-atomic operations on shared memory are also safe. `Atomics` provides explicit control over atomicity for specific operations. Standard read/write operations on shared memory without proper synchronization can lead to race conditions.

In summary, `v8/src/runtime/runtime-atomics.cc` is a crucial part of the V8 engine that enables the functionality of the JavaScript `Atomics` object, providing low-level, thread-safe operations on shared memory. It handles platform differences and ensures correct behavior according to the ECMAScript specification.

Prompt: 
```
这是目录为v8/src/runtime/runtime-atomics.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/runtime/runtime-atomics.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2015 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/base/macros.h"
#include "src/base/platform/mutex.h"
#include "src/execution/arguments-inl.h"
#include "src/heap/factory.h"
#include "src/logging/counters.h"
#include "src/numbers/conversions-inl.h"
#include "src/objects/js-array-buffer-inl.h"
#include "src/objects/js-shared-array-inl.h"
#include "src/objects/js-struct-inl.h"
#include "src/runtime/runtime-utils.h"

// Implement Atomic accesses to ArrayBuffers and SharedArrayBuffers.
// https://tc39.es/ecma262/#sec-atomics

namespace v8 {
namespace internal {

// Other platforms have CSA support, see builtins-sharedarraybuffer-gen.h.
#if V8_TARGET_ARCH_MIPS64 || V8_TARGET_ARCH_PPC64 || V8_TARGET_ARCH_S390X || \
    V8_TARGET_ARCH_LOONG64

namespace {

#if defined(V8_OS_STARBOARD)

template <typename T>
inline T ExchangeSeqCst(T* p, T value) {
  UNIMPLEMENTED();
}

template <typename T>
inline T CompareExchangeSeqCst(T* p, T oldval, T newval) {
  UNIMPLEMENTED();
}

template <typename T>
inline T AddSeqCst(T* p, T value) {
  UNIMPLEMENTED();
}

template <typename T>
inline T SubSeqCst(T* p, T value) {
  UNIMPLEMENTED();
}

template <typename T>
inline T AndSeqCst(T* p, T value) {
  UNIMPLEMENTED();
}

template <typename T>
inline T OrSeqCst(T* p, T value) {
  UNIMPLEMENTED();
}

template <typename T>
inline T XorSeqCst(T* p, T value) {
  UNIMPLEMENTED();
}

#elif V8_CC_GNU

// GCC/Clang helpfully warn us that using 64-bit atomics on 32-bit platforms
// can be slow. Good to know, but we don't have a choice.
#ifdef V8_TARGET_ARCH_32_BIT
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpragmas"
#pragma GCC diagnostic ignored "-Watomic-alignment"
#endif  // V8_TARGET_ARCH_32_BIT

template <typename T>
inline T LoadSeqCst(T* p) {
  return __atomic_load_n(p, __ATOMIC_SEQ_CST);
}

template <typename T>
inline void StoreSeqCst(T* p, T value) {
  __atomic_store_n(p, value, __ATOMIC_SEQ_CST);
}

template <typename T>
inline T ExchangeSeqCst(T* p, T value) {
  return __atomic_exchange_n(p, value, __ATOMIC_SEQ_CST);
}

template <typename T>
inline T CompareExchangeSeqCst(T* p, T oldval, T newval) {
  (void)__atomic_compare_exchange_n(p, &oldval, newval, 0, __ATOMIC_SEQ_CST,
                                    __ATOMIC_SEQ_CST);
  return oldval;
}

template <typename T>
inline T AddSeqCst(T* p, T value) {
  return __atomic_fetch_add(p, value, __ATOMIC_SEQ_CST);
}

template <typename T>
inline T SubSeqCst(T* p, T value) {
  return __atomic_fetch_sub(p, value, __ATOMIC_SEQ_CST);
}

template <typename T>
inline T AndSeqCst(T* p, T value) {
  return __atomic_fetch_and(p, value, __ATOMIC_SEQ_CST);
}

template <typename T>
inline T OrSeqCst(T* p, T value) {
  return __atomic_fetch_or(p, value, __ATOMIC_SEQ_CST);
}

template <typename T>
inline T XorSeqCst(T* p, T value) {
  return __atomic_fetch_xor(p, value, __ATOMIC_SEQ_CST);
}

#ifdef V8_TARGET_ARCH_32_BIT
#pragma GCC diagnostic pop
#endif  // V8_TARGET_ARCH_32_BIT

#elif V8_CC_MSVC

#define InterlockedExchange32 _InterlockedExchange
#define InterlockedCompareExchange32 _InterlockedCompareExchange
#define InterlockedCompareExchange8 _InterlockedCompareExchange8
#define InterlockedExchangeAdd32 _InterlockedExchangeAdd
#define InterlockedExchangeAdd16 _InterlockedExchangeAdd16
#define InterlockedExchangeAdd8 _InterlockedExchangeAdd8
#define InterlockedAnd32 _InterlockedAnd
#define InterlockedOr64 _InterlockedOr64
#define InterlockedOr32 _InterlockedOr
#define InterlockedXor32 _InterlockedXor

#if defined(V8_HOST_ARCH_ARM64)
#define InterlockedExchange8 _InterlockedExchange8
#endif

#define ATOMIC_OPS(type, suffix, vctype)                                       \
  inline type ExchangeSeqCst(type* p, type value) {                            \
    return InterlockedExchange##suffix(reinterpret_cast<vctype*>(p),           \
                                       base::bit_cast<vctype>(value));         \
  }                                                                            \
  inline type CompareExchangeSeqCst(type* p, type oldval, type newval) {       \
    return InterlockedCompareExchange##suffix(reinterpret_cast<vctype*>(p),    \
                                              base::bit_cast<vctype>(newval),  \
                                              base::bit_cast<vctype>(oldval)); \
  }                                                                            \
  inline type AddSeqCst(type* p, type value) {                                 \
    return InterlockedExchangeAdd##suffix(reinterpret_cast<vctype*>(p),        \
                                          base::bit_cast<vctype>(value));      \
  }                                                                            \
  inline type SubSeqCst(type* p, type value) {                                 \
    return InterlockedExchangeAdd##suffix(reinterpret_cast<vctype*>(p),        \
                                          -base::bit_cast<vctype>(value));     \
  }                                                                            \
  inline type AndSeqCst(type* p, type value) {                                 \
    return InterlockedAnd##suffix(reinterpret_cast<vctype*>(p),                \
                                  base::bit_cast<vctype>(value));              \
  }                                                                            \
  inline type OrSeqCst(type* p, type value) {                                  \
    return InterlockedOr##suffix(reinterpret_cast<vctype*>(p),                 \
                                 base::bit_cast<vctype>(value));               \
  }                                                                            \
  inline type XorSeqCst(type* p, type value) {                                 \
    return InterlockedXor##suffix(reinterpret_cast<vctype*>(p),                \
                                  base::bit_cast<vctype>(value));              \
  }

ATOMIC_OPS(int8_t, 8, char)
ATOMIC_OPS(uint8_t, 8, char)
ATOMIC_OPS(int16_t, 16, short)  /* NOLINT(runtime/int) */
ATOMIC_OPS(uint16_t, 16, short) /* NOLINT(runtime/int) */
ATOMIC_OPS(int32_t, 32, long)   /* NOLINT(runtime/int) */
ATOMIC_OPS(uint32_t, 32, long)  /* NOLINT(runtime/int) */
ATOMIC_OPS(int64_t, 64, __int64)
ATOMIC_OPS(uint64_t, 64, __int64)

template <typename T>
inline T LoadSeqCst(T* p) {
  UNREACHABLE();
}

template <typename T>
inline void StoreSeqCst(T* p, T value) {
  UNREACHABLE();
}

#undef ATOMIC_OPS

#undef InterlockedExchange32
#undef InterlockedCompareExchange32
#undef InterlockedCompareExchange8
#undef InterlockedExchangeAdd32
#undef InterlockedExchangeAdd16
#undef InterlockedExchangeAdd8
#undef InterlockedAnd32
#undef InterlockedOr64
#undef InterlockedOr32
#undef InterlockedXor32

#if defined(V8_HOST_ARCH_ARM64)
#undef InterlockedExchange8
#endif

#else

#error Unsupported platform!

#endif

template <typename T>
T FromObject(Handle<Object> number);

template <>
inline uint8_t FromObject<uint8_t>(Handle<Object> number) {
  return NumberToUint32(*number);
}

template <>
inline int8_t FromObject<int8_t>(Handle<Object> number) {
  return NumberToInt32(*number);
}

template <>
inline uint16_t FromObject<uint16_t>(Handle<Object> number) {
  return NumberToUint32(*number);
}

template <>
inline int16_t FromObject<int16_t>(Handle<Object> number) {
  return NumberToInt32(*number);
}

template <>
inline uint32_t FromObject<uint32_t>(Handle<Object> number) {
  return NumberToUint32(*number);
}

template <>
inline int32_t FromObject<int32_t>(Handle<Object> number) {
  return NumberToInt32(*number);
}

template <>
inline uint64_t FromObject<uint64_t>(Handle<Object> bigint) {
  return Cast<BigInt>(bigint)->AsUint64();
}

template <>
inline int64_t FromObject<int64_t>(Handle<Object> bigint) {
  return Cast<BigInt>(bigint)->AsInt64();
}

inline Tagged<Object> ToObject(Isolate* isolate, int8_t t) {
  return Smi::FromInt(t);
}

inline Tagged<Object> ToObject(Isolate* isolate, uint8_t t) {
  return Smi::FromInt(t);
}

inline Tagged<Object> ToObject(Isolate* isolate, int16_t t) {
  return Smi::FromInt(t);
}

inline Tagged<Object> ToObject(Isolate* isolate, uint16_t t) {
  return Smi::FromInt(t);
}

inline Tagged<Object> ToObject(Isolate* isolate, int32_t t) {
  return *isolate->factory()->NewNumber(t);
}

inline Tagged<Object> ToObject(Isolate* isolate, uint32_t t) {
  return *isolate->factory()->NewNumber(t);
}

inline Tagged<Object> ToObject(Isolate* isolate, int64_t t) {
  return *BigInt::FromInt64(isolate, t);
}

inline Tagged<Object> ToObject(Isolate* isolate, uint64_t t) {
  return *BigInt::FromUint64(isolate, t);
}

template <typename T>
struct Load {
  static inline Tagged<Object> Do(Isolate* isolate, void* buffer,
                                  size_t index) {
    T result = LoadSeqCst(static_cast<T*>(buffer) + index);
    return ToObject(isolate, result);
  }
};

template <typename T>
struct Store {
  static inline void Do(Isolate* isolate, void* buffer, size_t index,
                        Handle<Object> obj) {
    T value = FromObject<T>(obj);
    StoreSeqCst(static_cast<T*>(buffer) + index, value);
  }
};

template <typename T>
struct Exchange {
  static inline Tagged<Object> Do(Isolate* isolate, void* buffer, size_t index,
                                  Handle<Object> obj) {
    T value = FromObject<T>(obj);
    T result = ExchangeSeqCst(static_cast<T*>(buffer) + index, value);
    return ToObject(isolate, result);
  }
};

template <typename T>
inline Tagged<Object> DoCompareExchange(Isolate* isolate, void* buffer,
                                        size_t index, Handle<Object> oldobj,
                                        Handle<Object> newobj) {
  T oldval = FromObject<T>(oldobj);
  T newval = FromObject<T>(newobj);
  T result =
      CompareExchangeSeqCst(static_cast<T*>(buffer) + index, oldval, newval);
  return ToObject(isolate, result);
}

template <typename T>
struct Add {
  static inline Tagged<Object> Do(Isolate* isolate, void* buffer, size_t index,
                                  Handle<Object> obj) {
    T value = FromObject<T>(obj);
    T result = AddSeqCst(static_cast<T*>(buffer) + index, value);
    return ToObject(isolate, result);
  }
};

template <typename T>
struct Sub {
  static inline Tagged<Object> Do(Isolate* isolate, void* buffer, size_t index,
                                  Handle<Object> obj) {
    T value = FromObject<T>(obj);
    T result = SubSeqCst(static_cast<T*>(buffer) + index, value);
    return ToObject(isolate, result);
  }
};

template <typename T>
struct And {
  static inline Tagged<Object> Do(Isolate* isolate, void* buffer, size_t index,
                                  Handle<Object> obj) {
    T value = FromObject<T>(obj);
    T result = AndSeqCst(static_cast<T*>(buffer) + index, value);
    return ToObject(isolate, result);
  }
};

template <typename T>
struct Or {
  static inline Tagged<Object> Do(Isolate* isolate, void* buffer, size_t index,
                                  Handle<Object> obj) {
    T value = FromObject<T>(obj);
    T result = OrSeqCst(static_cast<T*>(buffer) + index, value);
    return ToObject(isolate, result);
  }
};

template <typename T>
struct Xor {
  static inline Tagged<Object> Do(Isolate* isolate, void* buffer, size_t index,
                                  Handle<Object> obj) {
    T value = FromObject<T>(obj);
    T result = XorSeqCst(static_cast<T*>(buffer) + index, value);
    return ToObject(isolate, result);
  }
};

}  // anonymous namespace

// Duplicated from objects.h
// V has parameters (Type, type, TYPE, C type)
#define INTEGER_TYPED_ARRAYS(V)       \
  V(Uint8, uint8, UINT8, uint8_t)     \
  V(Int8, int8, INT8, int8_t)         \
  V(Uint16, uint16, UINT16, uint16_t) \
  V(Int16, int16, INT16, int16_t)     \
  V(Uint32, uint32, UINT32, uint32_t) \
  V(Int32, int32, INT32, int32_t)

#define THROW_ERROR_RETURN_FAILURE_ON_DETACHED_OR_OUT_OF_BOUNDS(               \
    isolate, sta, index, method_name)                                          \
  do {                                                                         \
    bool out_of_bounds = false;                                                \
    auto length = sta->GetLengthOrOutOfBounds(out_of_bounds);                  \
    if (V8_UNLIKELY(sta->WasDetached() || out_of_bounds || index >= length)) { \
      THROW_NEW_ERROR_RETURN_FAILURE(                                          \
          isolate, NewTypeError(MessageTemplate::kDetachedOperation,           \
                                isolate->factory()->NewStringFromAsciiChecked( \
                                    method_name)));                            \
    }                                                                          \
  } while (false)

// This is https://tc39.github.io/ecma262/#sec-getmodifysetvalueinbuffer
// but also includes the ToInteger/ToBigInt conversion that's part of
// https://tc39.github.io/ecma262/#sec-atomicreadmodifywrite
template <template <typename> class Op>
Tagged<Object> GetModifySetValueInBuffer(RuntimeArguments args,
                                         Isolate* isolate,
                                         const char* method_name) {
  HandleScope scope(isolate);
  DCHECK_EQ(3, args.length());
  Handle<JSTypedArray> sta = args.at<JSTypedArray>(0);
  size_t index = NumberToSize(args[1]);
  Handle<Object> value_obj = args.at(2);

  uint8_t* source = static_cast<uint8_t*>(sta->GetBuffer()->backing_store()) +
                    sta->byte_offset();

  if (sta->type() >= kExternalBigInt64Array) {
    Handle<BigInt> bigint;
    ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, bigint,
                                       BigInt::FromObject(isolate, value_obj));

    THROW_ERROR_RETURN_FAILURE_ON_DETACHED_OR_OUT_OF_BOUNDS(isolate, sta, index,
                                                            method_name);

    CHECK_LT(index, sta->GetLength());
    if (sta->type() == kExternalBigInt64Array) {
      return Op<int64_t>::Do(isolate, source, index, bigint);
    }
    DCHECK(sta->type() == kExternalBigUint64Array);
    return Op<uint64_t>::Do(isolate, source, index, bigint);
  }

  Handle<Object> value;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, value,
                                     Object::ToInteger(isolate, value_obj));

  THROW_ERROR_RETURN_FAILURE_ON_DETACHED_OR_OUT_OF_BOUNDS(isolate, sta, index,
                                                          method_name);

  CHECK_LT(index, sta->GetLength());

  switch (sta->type()) {
#define TYPED_ARRAY_CASE(Type, typeName, TYPE, ctype) \
  case kExternal##Type##Array:                        \
    return Op<ctype>::Do(isolate, source, index, value);

    INTEGER_TYPED_ARRAYS(TYPED_ARRAY_CASE)
#undef TYPED_ARRAY_CASE

    default:
      break;
  }

  UNREACHABLE();
}

RUNTIME_FUNCTION(Runtime_AtomicsLoad64) {
  HandleScope scope(isolate);
  DCHECK_EQ(2, args.length());
  Handle<JSTypedArray> sta = args.at<JSTypedArray>(0);
  size_t index = NumberToSize(args[1]);

  uint8_t* source = static_cast<uint8_t*>(sta->GetBuffer()->backing_store()) +
                    sta->byte_offset();

  DCHECK(sta->type() == kExternalBigInt64Array ||
         sta->type() == kExternalBigUint64Array);
  DCHECK(!sta->IsDetachedOrOutOfBounds());
  CHECK_LT(index, sta->GetLength());
  if (sta->type() == kExternalBigInt64Array) {
    return Load<int64_t>::Do(isolate, source, index);
  }
  DCHECK(sta->type() == kExternalBigUint64Array);
  return Load<uint64_t>::Do(isolate, source, index);
}

RUNTIME_FUNCTION(Runtime_AtomicsStore64) {
  HandleScope scope(isolate);
  DCHECK_EQ(3, args.length());
  Handle<JSTypedArray> sta = args.at<JSTypedArray>(0);
  size_t index = NumberToSize(args[1]);
  Handle<Object> value_obj = args.at(2);

  uint8_t* source = static_cast<uint8_t*>(sta->GetBuffer()->backing_store()) +
                    sta->byte_offset();

  Handle<BigInt> bigint;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, bigint,
                                     BigInt::FromObject(isolate, value_obj));

  THROW_ERROR_RETURN_FAILURE_ON_DETACHED_OR_OUT_OF_BOUNDS(isolate, sta, index,
                                                          "Atomics.store");

  DCHECK(sta->type() == kExternalBigInt64Array ||
         sta->type() == kExternalBigUint64Array);
  CHECK_LT(index, sta->GetLength());
  if (sta->type() == kExternalBigInt64Array) {
    Store<int64_t>::Do(isolate, source, index, bigint);
    return *bigint;
  }
  DCHECK(sta->type() == kExternalBigUint64Array);
  Store<uint64_t>::Do(isolate, source, index, bigint);
  return *bigint;
}

RUNTIME_FUNCTION(Runtime_AtomicsExchange) {
  return GetModifySetValueInBuffer<Exchange>(args, isolate, "Atomics.exchange");
}

RUNTIME_FUNCTION(Runtime_AtomicsCompareExchange) {
  HandleScope scope(isolate);
  DCHECK_EQ(4, args.length());
  Handle<JSTypedArray> sta = args.at<JSTypedArray>(0);
  size_t index = NumberToSize(args[1]);
  Handle<Object> old_value_obj = args.at(2);
  Handle<Object> new_value_obj = args.at(3);

  uint8_t* source = static_cast<uint8_t*>(sta->GetBuffer()->backing_store()) +
                    sta->byte_offset();

  if (sta->type() >= kExternalBigInt64Array) {
    Handle<BigInt> old_bigint;
    Handle<BigInt> new_bigint;
    ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
        isolate, old_bigint, BigInt::FromObject(isolate, old_value_obj));
    ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
        isolate, new_bigint, BigInt::FromObject(isolate, new_value_obj));

    THROW_ERROR_RETURN_FAILURE_ON_DETACHED_OR_OUT_OF_BOUNDS(
        isolate, sta, index, "Atomics.compareExchange");

    CHECK_LT(index, sta->GetLength());
    if (sta->type() == kExternalBigInt64Array) {
      return DoCompareExchange<int64_t>(isolate, source, index, old_bigint,
                                        new_bigint);
    }
    DCHECK(sta->type() == kExternalBigUint64Array);
    return DoCompareExchange<uint64_t>(isolate, source, index, old_bigint,
                                       new_bigint);
  }

  Handle<Object> old_value;
  Handle<Object> new_value;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, old_value,
                                     Object::ToInteger(isolate, old_value_obj));
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, new_value,
                                     Object::ToInteger(isolate, new_value_obj));

  THROW_ERROR_RETURN_FAILURE_ON_DETACHED_OR_OUT_OF_BOUNDS(
      isolate, sta, index, "Atomics.compareExchange");

  switch (sta->type()) {
#define TYPED_ARRAY_CASE(Type, typeName, TYPE, ctype)                  \
  case kExternal##Type##Array:                                         \
    return DoCompareExchange<ctype>(isolate, source, index, old_value, \
                                    new_value);

    INTEGER_TYPED_ARRAYS(TYPED_ARRAY_CASE)
#undef TYPED_ARRAY_CASE

    default:
      break;
  }

  UNREACHABLE();
}

// ES #sec-atomics.add
// Atomics.add( typedArray, index, value )
RUNTIME_FUNCTION(Runtime_AtomicsAdd) {
  return GetModifySetValueInBuffer<Add>(args, isolate, "Atomics.add");
}

// ES #sec-atomics.sub
// Atomics.sub( typedArray, index, value )
RUNTIME_FUNCTION(Runtime_AtomicsSub) {
  return GetModifySetValueInBuffer<Sub>(args, isolate, "Atomics.sub");
}

// ES #sec-atomics.and
// Atomics.and( typedArray, index, value )
RUNTIME_FUNCTION(Runtime_AtomicsAnd) {
  return GetModifySetValueInBuffer<And>(args, isolate, "Atomics.and");
}

// ES #sec-atomics.or
// Atomics.or( typedArray, index, value )
RUNTIME_FUNCTION(Runtime_AtomicsOr) {
  return GetModifySetValueInBuffer<Or>(args, isolate, "Atomics.or");
}

// ES #sec-atomics.xor
// Atomics.xor( typedArray, index, value )
RUNTIME_FUNCTION(Runtime_AtomicsXor) {
  return GetModifySetValueInBuffer<Xor>(args, isolate, "Atomics.xor");
}

#undef INTEGER_TYPED_ARRAYS

#else

RUNTIME_FUNCTION(Runtime_AtomicsLoad64) { UNREACHABLE(); }

RUNTIME_FUNCTION(Runtime_AtomicsStore64) { UNREACHABLE(); }

RUNTIME_FUNCTION(Runtime_AtomicsExchange) { UNREACHABLE(); }

RUNTIME_FUNCTION(Runtime_AtomicsCompareExchange) { UNREACHABLE(); }

RUNTIME_FUNCTION(Runtime_AtomicsAdd) { UNREACHABLE(); }

RUNTIME_FUNCTION(Runtime_AtomicsSub) { UNREACHABLE(); }

RUNTIME_FUNCTION(Runtime_AtomicsAnd) { UNREACHABLE(); }

RUNTIME_FUNCTION(Runtime_AtomicsOr) { UNREACHABLE(); }

RUNTIME_FUNCTION(Runtime_AtomicsXor) { UNREACHABLE(); }

#endif  // V8_TARGET_ARCH_MIPS64 || V8_TARGET_ARCH_PPC64
        // || V8_TARGET_ARCH_S390X || V8_TARGET_ARCH_RISCV64 ||
        // V8_TARGET_ARCH_LOONG64 || V8_TARGET_ARCH_RISCV32

RUNTIME_FUNCTION(Runtime_AtomicsLoadSharedStructOrArray) {
  HandleScope scope(isolate);
  DCHECK_EQ(2, args.length());
  Handle<JSObject> shared_struct_or_shared_array = args.at<JSObject>(0);
  Handle<Name> field_name;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, field_name,
                                     Object::ToName(isolate, args.at(1)));
  // Shared structs are prototypeless.
  LookupIterator it(isolate, shared_struct_or_shared_array,
                    PropertyKey(isolate, field_name), LookupIterator::OWN);
  if (it.IsFound()) return *it.GetDataValue(kSeqCstAccess);
  return ReadOnlyRoots(isolate).undefined_value();
}

namespace {

template <typename WriteOperation>
Tagged<Object> AtomicFieldWrite(Isolate* isolate, Handle<JSObject> object,
                                Handle<Name> field_name,
                                DirectHandle<Object> value,
                                WriteOperation write_operation) {
  LookupIterator it(isolate, object, PropertyKey(isolate, field_name),
                    LookupIterator::OWN);
  Maybe<bool> result = Nothing<bool>();
  if (it.IsFound()) {
    if (!it.IsReadOnly()) {
      return write_operation(it);
    }
    // Shared structs and arrays are non-extensible and have non-configurable,
    // writable, enumerable properties. The only exception is SharedArrays'
    // "length" property, which is non-writable.
    result = Object::WriteToReadOnlyProperty(&it, value, Just(kThrowOnError));
  } else {
    // Shared structs are non-extensible. Instead of duplicating logic, call
    // Object::AddDataProperty to handle the error case.
    result = Object::AddDataProperty(&it, value, NONE, Just(kThrowOnError),
                                     StoreOrigin::kMaybeKeyed);
  }
  // Treat as strict code and always throw an error.
  DCHECK(result.IsNothing());
  USE(result);
  return ReadOnlyRoots(isolate).exception();
}
}  // namespace

RUNTIME_FUNCTION(Runtime_AtomicsStoreSharedStructOrArray) {
  HandleScope scope(isolate);
  DCHECK_EQ(3, args.length());
  Handle<JSObject> shared_struct_or_shared_array = args.at<JSObject>(0);
  Handle<Name> field_name;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, field_name,
                                     Object::ToName(isolate, args.at(1)));
  Handle<Object> shared_value;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, shared_value, Object::Share(isolate, args.at(2), kThrowOnError));

  return AtomicFieldWrite(isolate, shared_struct_or_shared_array, field_name,
                          shared_value, [=](LookupIterator it) {
                            it.WriteDataValue(shared_value, kSeqCstAccess);
                            return *shared_value;
                          });
}

RUNTIME_FUNCTION(Runtime_AtomicsExchangeSharedStructOrArray) {
  HandleScope scope(isolate);
  DCHECK_EQ(3, args.length());
  Handle<JSObject> shared_struct_or_shared_array = args.at<JSObject>(0);
  Handle<Name> field_name;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, field_name,
                                     Object::ToName(isolate, args.at(1)));
  Handle<Object> shared_value;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, shared_value, Object::Share(isolate, args.at(2), kThrowOnError));

  return AtomicFieldWrite(isolate, shared_struct_or_shared_array, field_name,
                          shared_value, [=](LookupIterator it) {
                            return *it.SwapDataValue(shared_value,
                                                     kSeqCstAccess);
                          });
}

RUNTIME_FUNCTION(Runtime_AtomicsCompareExchangeSharedStructOrArray) {
  HandleScope scope(isolate);
  DCHECK_EQ(4, args.length());
  Handle<JSObject> shared_struct_or_shared_array = args.at<JSObject>(0);
  Handle<Name> field_name;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, field_name,
                                     Object::ToName(isolate, args.at(1)));
  Handle<Object> shared_expected;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, shared_expected,
      Object::Share(isolate, args.at(2), kThrowOnError));
  Handle<Object> shared_value;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, shared_value, Object::Share(isolate, args.at(3), kThrowOnError));

  return AtomicFieldWrite(isolate, shared_struct_or_shared_array, field_name,
                          shared_value, [=](LookupIterator it) {
                            return *it.CompareAndSwapDataValue(
                                shared_expected, shared_value, kSeqCstAccess);
                          });
}

}  // namespace internal
}  // namespace v8

"""

```