Response: The user wants to understand the functionality of the C++ source code file `v8/src/runtime/runtime-atomics.cc`. I need to:

1. **Summarize the file's purpose**:  Focus on what the code does. Keywords like "atomic operations", "shared memory", and "JavaScript integration" will be important.
2. **Explain the connection to JavaScript**: Describe how the C++ code relates to JavaScript features. The `Atomics` object in JavaScript will be key.
3. **Provide a JavaScript example**: Illustrate the connection with a concrete example of using the `Atomics` object.

Let's break down the code:

- **Includes**:  Standard V8 headers for objects, execution, and platform. This suggests the file is part of V8's core runtime.
- **Namespace**: `v8::internal` confirms it's an internal V8 component.
- **Conditional Compilation (`#if V8_TARGET_ARCH_...`)**:  This section defines platform-specific implementations for atomic operations. It handles different architectures and compilers (GCC, MSVC). This strongly indicates the file deals with low-level atomic operations.
- **Atomic Operation Templates (`ExchangeSeqCst`, `CompareExchangeSeqCst`, etc.)**: These templates encapsulate the platform-specific atomic operations. The `SeqCst` suffix suggests "Sequential Consistency", a strong memory ordering.
- **`FromObject` and `ToObject` Templates**: These functions handle conversion between JavaScript objects (Numbers, BigInts) and C++ primitive types. This is the bridge between JavaScript and the C++ implementation.
- **`Load`, `Store`, `Exchange`, `CompareExchange`, `Add`, `Sub`, `And`, `Or`, `Xor` Templates**:  These structures define the core atomic operations for different data types.
- **`INTEGER_TYPED_ARRAYS` Macro**: This macro lists the supported integer typed arrays, indicating that the atomic operations are performed on these array types.
- **`THROW_ERROR_RETURN_FAILURE_ON_DETACHED_OR_OUT_OF_BOUNDS` Macro**: This suggests error handling for operations on detached or out-of-bounds arrays.
- **`GetModifySetValueInBuffer` Function**: This is a central function that handles many of the atomic operations on typed arrays. It takes a template parameter `Op` to dispatch to the correct atomic operation.
- **`RUNTIME_FUNCTION` Macros (e.g., `Runtime_AtomicsLoad64`, `Runtime_AtomicsStore64`, etc.)**: These functions are the entry points from the JavaScript runtime into this C++ code. They correspond to methods on the JavaScript `Atomics` object.
- **Shared Struct/Array Functions (`Runtime_AtomicsLoadSharedStructOrArray`, `Runtime_AtomicsStoreSharedStructOrArray`, etc.)**: These functions handle atomic operations on shared memory regions represented by `JSObject` (likely `JSSharedStruct` and `JSSharedArray`).

**Connecting to JavaScript `Atomics`**: The naming of the `RUNTIME_FUNCTION`s (e.g., `Runtime_AtomicsLoad`, `Runtime_AtomicsStore`, `Runtime_AtomicsAdd`) directly corresponds to the methods available on the JavaScript `Atomics` object. The arguments to these functions (typed array, index, value) match the expected parameters for the JavaScript `Atomics` methods.

**JavaScript Example Idea**:  Demonstrate a simple atomic operation like `Atomics.add` on a `SharedArrayBuffer`.

**Summary Plan**:

1. State that the file implements the core logic for JavaScript's `Atomics` object, enabling atomic operations on shared memory.
2. Explain that it handles platform-specific implementations for atomicity.
3. Mention the conversion between JavaScript values and C++ types.
4. Give a JavaScript example using `SharedArrayBuffer` and `Atomics.add`.
这个C++源代码文件 `v8/src/runtime/runtime-atomics.cc` 的主要功能是**实现了 JavaScript 中 `Atomics` 对象提供的原子操作**。这些原子操作允许在共享内存（通过 `SharedArrayBuffer` 和共享的 `JSObject` 实例，例如 `SharedStruct` 或 `SharedArray`）上进行线程安全的读写和修改。

更具体地说，该文件做了以下几件事情：

1. **平台相关的原子操作实现**:  针对不同的处理器架构（如 MIPS64, PPC64, S390X, LOONG64）以及操作系统和编译器（GNU, MSVC），提供了底层的原子操作实现。 这些实现使用了平台提供的原子指令或库函数（例如 `__atomic_load_n`, `InterlockedExchange` 等），以确保操作的原子性。 对于其他平台，这些操作通常在 `builtins-sharedarraybuffer-gen.h` 中实现。

2. **JavaScript 值和 C++ 值的转换**: 提供了 `FromObject` 和 `ToObject` 模板函数，用于在 JavaScript 的 Number 或 BigInt 对象和 C++ 的基本数据类型（如 `uint8_t`, `int32_t`, `uint64_t` 等）之间进行转换。这是连接 JavaScript 和底层原子操作的关键。

3. **实现 `Atomics` 的各种操作**:  定义了用于执行 `Atomics` 对象上各种方法的 C++ 函数，例如：
    - `Atomics.load()`: 从共享数组或共享对象中原子地读取值。
    - `Atomics.store()`: 将值原子地写入共享数组或共享对象。
    - `Atomics.exchange()`: 原子地替换共享数组或共享对象中的值，并返回旧值。
    - `Atomics.compareExchange()`:  原子地比较共享数组或共享对象中的值与预期值，如果相等则替换为新值，并返回原始值。
    - `Atomics.add()`, `Atomics.sub()`, `Atomics.and()`, `Atomics.or()`, `Atomics.xor()`:  原子地执行算术和位运算，并将结果写回共享数组。

4. **处理不同类型的共享内存**:  代码区分了对 `SharedArrayBuffer` 及其各种类型的 TypedArray 视图，以及对共享的 `JSObject` (如 `SharedStruct` 和 `SharedArray`) 的原子操作。

5. **错误处理**: 包含了对分离的 `SharedArrayBuffer` 和越界访问的错误处理。

**与 JavaScript 的功能关系及举例说明:**

该文件直接实现了 JavaScript 中 `Atomics` 对象的底层功能。当你在 JavaScript 中使用 `Atomics` 对象的方法时，V8 引擎会调用此文件中相应的 C++ 函数来执行实际的原子操作。

**JavaScript 示例:**

```javascript
// 创建一个共享的 Int32Array
const sab = new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT * 1);
const view = new Int32Array(sab);

// 初始值
console.log(Atomics.load(view, 0)); // 输出: 0

// 使用 Atomics.add 原子地增加值
const oldValue = Atomics.add(view, 0, 5);
console.log(oldValue); // 输出: 0 (返回操作前的值)
console.log(Atomics.load(view, 0)); // 输出: 5

// 使用 Atomics.compareExchange 原子地比较并交换值
const originalValue = Atomics.compareExchange(view, 0, 5, 10);
console.log(originalValue); // 输出: 5 (返回操作前的值)
console.log(Atomics.load(view, 0)); // 输出: 10

// 创建一个共享的结构体 (SharedStruct - 假设 V8 实现了 SharedStruct)
// 这是一个假设的例子，SharedStruct 的具体 API 可能有所不同
// const sharedStruct = new SharedStruct({ value: 0 });
// console.log(Atomics.load(sharedStruct, "value")); // 假设的用法
// Atomics.store(sharedStruct, "value", 15); // 假设的用法
// console.log(Atomics.load(sharedStruct, "value")); // 假设的用法
```

**解释:**

- `SharedArrayBuffer` 允许在多个 worker 线程或共享的上下文中共享内存。
- `Atomics` 对象提供了一组静态方法，用于安全地操作 `SharedArrayBuffer` 中的数据，避免出现竞态条件等并发问题。
- 例如，`Atomics.add(view, 0, 5)` 会原子地将 `view[0]` 的值增加 5。这意味着即使有多个线程同时尝试修改 `view[0]`，操作也会一个接一个地完成，不会出现数据损坏的情况。
- `Atomics.compareExchange(view, 0, 5, 10)` 会检查 `view[0]` 的值是否为 5。如果是，则将其替换为 10；否则，不进行任何操作。这个操作也是原子性的。
- 代码中注释掉的 `SharedStruct` 部分展示了 `Atomics` 也被设计用于操作共享的结构体或对象，尽管 V8 中 `SharedStruct` 的具体实现和 API 可能会有所不同。

总而言之，`v8/src/runtime/runtime-atomics.cc` 是 V8 引擎中实现 JavaScript `Atomics` 核心功能的关键部分，它通过平台相关的原子操作和数据类型转换，使得在 JavaScript 中进行多线程编程成为可能。

Prompt: 
```
这是目录为v8/src/runtime/runtime-atomics.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

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