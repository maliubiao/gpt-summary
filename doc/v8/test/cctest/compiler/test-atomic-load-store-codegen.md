Response: Let's break down the thought process for analyzing this C++ code and relating it to JavaScript.

1. **Understand the Goal:** The filename `test-atomic-load-store-codegen.cc` strongly suggests the code is about testing the code generation for atomic load and store operations within the V8 JavaScript engine. The "codegen" part is a key indicator.

2. **Identify Key V8 Concepts:**  Immediately, certain V8-specific terms jump out:
    * `v8::internal::compiler`: This signifies we're dealing with the compiler part of V8, which translates JavaScript into machine code.
    * `MachineType`: This likely represents the low-level data types used in the generated machine code (e.g., `Int8`, `Uint32`, `TaggedSigned`).
    * `AtomicMemoryOrder`:  This relates to memory synchronization and how different threads see changes to shared memory. Keywords like "Acquire" and "SeqCst" (Sequential Consistency) are hints about different levels of memory ordering guarantees.
    * `Tagged<T>`:  This is a fundamental V8 concept. JavaScript values aren't simply raw integers or pointers. They're tagged to indicate their type (Smi for small integers, HeapObject for objects, etc.). This tag is crucial for V8's runtime behavior.
    * `RawMachineAssemblerTester` and `BufferedRawMachineAssemblerTester`: These are testing utilities within V8 to directly generate and execute snippets of machine code. They are used for low-level verification.
    * `Node*`:  This likely refers to nodes in V8's intermediate representation (IR) used during compilation.

3. **Analyze the Macros and Helper Functions:**
    * `LSB`:  This macro deals with endianness (byte order). It helps to access the least significant byte, which is important when dealing with potentially different architectures.
    * `TEST_ATOMIC_LOAD_INTEGER` and `TEST_ATOMIC_STORE_INTEGER`: These macros are clearly defining the structure of the tests for atomic loads and stores of various integer types. They follow a pattern:
        * Allocate a buffer.
        * Use the `RawMachineAssemblerTester` to generate code for the atomic operation.
        * Iterate through input values using `FOR_INPUTS`.
        * Perform the operation and check the result using `CHECK_EQ`.
    * `CheckEq`:  This function seems like a customized equality check, with specializations for `Tagged` values. This hints at the complexity of comparing JavaScript values at the machine level.
    * `InitBuffer`: This function initializes a buffer with tagged values, likely to simulate real JavaScript object memory. It uses `Smi::FromInt` and copies data from `isolate->roots_table()`, further emphasizing its connection to V8's internal representation.
    * `AtomicLoadTagged` and `AtomicStoreTagged`: These functions generalize the atomic load/store testing for `Tagged` values. The loop and the use of `zap_value` suggest a pattern of writing a value and then verifying it was correctly written and that other locations were not affected.

4. **Connect to JavaScript Concepts:**
    * **Atomics in JavaScript:** The core connection is the `Atomics` object in JavaScript. The C++ code is testing the *implementation* of these JavaScript features at a very low level.
    * **SharedArrayBuffer:** Atomic operations in JavaScript work on `SharedArrayBuffer` instances, which allow multiple JavaScript agents (threads or workers) to access the same underlying memory. While the C++ code doesn't directly manipulate `SharedArrayBuffer` objects, it's simulating the underlying memory operations that `Atomics` uses.
    * **Memory Ordering (Acquire/Release/SeqCst):** The `AtomicMemoryOrder` enum directly corresponds to the memory ordering modes available in JavaScript's `Atomics` API (e.g., `Atomics.load(sab, index)`, which defaults to sequential consistency).
    * **Data Types:** The C++ `MachineType` values (e.g., `Int32`, `Uint8`) map to the data types you can work with in `SharedArrayBuffer` using typed arrays (e.g., `Int32Array`, `Uint8Array`).
    * **Tagged Values:** The testing with `Tagged<T>` is critical because JavaScript's variables can hold values of different types. The atomic operations need to handle these tagged values correctly.

5. **Formulate the Explanation:**  Based on the above analysis, construct an explanation that:
    * States the purpose of the file (testing atomic load/store code generation).
    * Highlights the key V8 concepts involved.
    * Explains the testing methodology (using macros and assembler testers).
    * Clearly links the C++ code to the corresponding JavaScript `Atomics` features.
    * Provides concrete JavaScript examples that illustrate the usage of the tested functionalities.

6. **Refine the Explanation:** Review the explanation for clarity, accuracy, and completeness. Ensure the JavaScript examples are correct and directly relate to the C++ code's functionality. For instance, explicitly mention `SharedArrayBuffer` when discussing atomics.

By following these steps, we can effectively dissect the C++ code and connect it to its purpose within the V8 JavaScript engine and its corresponding features in the JavaScript language.
这个C++源代码文件 `test-atomic-load-store-codegen.cc` 的主要功能是**测试 V8 JavaScript 引擎中原子加载（load）和存储（store）操作的代码生成**。它验证了编译器在生成执行原子操作的机器码时是否正确。

具体来说，这个文件做了以下几件事：

1. **定义宏来简化测试**:  `TEST_ATOMIC_LOAD_INTEGER` 和 `TEST_ATOMIC_STORE_INTEGER` 宏定义了测试原子加载和存储整型值的通用模式。这避免了为每种整型类型重复编写相似的代码。

2. **测试不同大小和类型的原子加载**:  它针对不同大小（8位、16位、32位、64位）和有/无符号的整型数据，以及不同的内存顺序（`Acquire` 和 `SeqCst`，分别代表获取释放语义和顺序一致性语义）测试了原子加载操作。

3. **测试不同大小和类型的原子存储**:  类似地，它针对不同大小和类型的整型数据，以及不同的内存顺序（`Release` 和 `SeqCst`）测试了原子存储操作。

4. **测试原子加载和存储 `Tagged` 值**:  `Tagged` 是 V8 中用来表示 JavaScript 值的类型，它可以是小整数（Smi）、堆对象指针等等。 这部分测试确保了原子操作能够正确处理这些带标签的值，这对于 JavaScript 的并发编程至关重要。它考虑了指针压缩的情况（`COMPRESS_POINTERS_BOOL`）。

5. **测试 32 位架构下的原子对加载和存储**:  在 32 位架构下，64 位的原子操作需要特殊处理。这部分测试了原子地加载和存储 64 位整数的两个 32 位部分。

**与 JavaScript 的关系及示例**

这个文件测试的是 V8 引擎的底层实现，特别是涉及到 JavaScript 的并发和共享内存的特性。  JavaScript 中与原子操作相关的主要是 `SharedArrayBuffer` 和 `Atomics` 对象。

* **`SharedArrayBuffer`**: 允许在多个 worker 线程或者主线程之间共享内存。
* **`Atomics`**: 提供了一组静态方法用于执行原子操作，确保在多线程环境下对共享内存的访问是安全的。

这个 C++ 测试文件验证了 `Atomics` 对象背后的实现是否正确生成了机器码。

**JavaScript 示例**

假设我们在 JavaScript 中有一个 `SharedArrayBuffer` 和一个 `Int32Array` 视图：

```javascript
const sab = new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT * 2); // 创建一个共享的 ArrayBuffer
const int32Array = new Int32Array(sab);

// 在一个 worker 线程中：
// ...
Atomics.store(int32Array, 0, 123); // 原子地将 123 存储到索引 0 的位置
const value = Atomics.load(int32Array, 1); // 原子地加载索引 1 的值
// ...
```

在这个 JavaScript 示例中，`Atomics.store` 和 `Atomics.load` 就是这个 C++ 测试文件所测试的核心功能。

* **`Atomics.store(int32Array, 0, 123)`**  对应于 C++ 代码中 `TEST_ATOMIC_STORE_INTEGER` 系列的测试，特别是针对 `MachineType::Int32()` 的情况。它确保了当 JavaScript 代码执行 `Atomics.store` 时，V8 能够生成正确的机器码来原子地写入数据。

* **`Atomics.load(int32Array, 1)`** 对应于 C++ 代码中 `TEST_ATOMIC_LOAD_INTEGER` 系列的测试，同样特别是针对 `MachineType::Int32()` 的情况。它确保了当 JavaScript 代码执行 `Atomics.load` 时，V8 能够生成正确的机器码来原子地读取数据。

文件中的 `AtomicMemoryOrder::kAcqRel` 和 `AtomicMemoryOrder::kSeqCst`  对应于 `Atomics` 操作中隐含的内存顺序保证。例如，不带额外参数的 `Atomics.load` 和 `Atomics.store` 默认具有顺序一致性。

**总结**

`test-atomic-load-store-codegen.cc` 是 V8 引擎中一个非常底层的测试文件，它直接测试了编译器为 JavaScript 的原子操作生成的机器码的正确性。这对于确保 JavaScript 并发编程的正确性和安全性至关重要。它验证了当开发者在 JavaScript 中使用 `SharedArrayBuffer` 和 `Atomics` 时，底层的原子操作能够按照预期工作。

Prompt: 
```
这是目录为v8/test/cctest/compiler/test-atomic-load-store-codegen.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2021 the V8 project authors. All rights reserved. Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

#include "src/base/bits.h"
#include "src/objects/objects-inl.h"
#include "test/cctest/cctest.h"
#include "test/cctest/compiler/codegen-tester.h"
#include "test/common/value-helper.h"

namespace v8 {
namespace internal {
namespace compiler {

#if V8_TARGET_LITTLE_ENDIAN
#define LSB(addr, bytes) addr
#elif V8_TARGET_BIG_ENDIAN
#define LSB(addr, bytes) reinterpret_cast<uint8_t*>(addr + 1) - (bytes)
#else
#error "Unknown Architecture"
#endif

#define TEST_ATOMIC_LOAD_INTEGER(ctype, itype, mach_type, order) \
  do {                                                           \
    ctype buffer[1];                                             \
                                                                 \
    RawMachineAssemblerTester<ctype> m;                          \
    Node* base = m.PointerConstant(&buffer[0]);                  \
    Node* index = m.Int32Constant(0);                            \
    AtomicLoadParameters params(mach_type, order);               \
    if (mach_type.MemSize() == 8) {                              \
      m.Return(m.AtomicLoad64(params, base, index));             \
    } else {                                                     \
      m.Return(m.AtomicLoad(params, base, index));               \
    }                                                            \
                                                                 \
    FOR_INPUTS(ctype, itype, i) {                                \
      buffer[0] = i;                                             \
      CHECK_EQ(i, m.Call());                                     \
    }                                                            \
  } while (false)

TEST(AcquireLoadInteger) {
  TEST_ATOMIC_LOAD_INTEGER(int8_t, int8, MachineType::Int8(),
                           AtomicMemoryOrder::kAcqRel);
  TEST_ATOMIC_LOAD_INTEGER(uint8_t, uint8, MachineType::Uint8(),
                           AtomicMemoryOrder::kAcqRel);
  TEST_ATOMIC_LOAD_INTEGER(int16_t, int16, MachineType::Int16(),
                           AtomicMemoryOrder::kAcqRel);
  TEST_ATOMIC_LOAD_INTEGER(uint16_t, uint16, MachineType::Uint16(),
                           AtomicMemoryOrder::kAcqRel);
  TEST_ATOMIC_LOAD_INTEGER(int32_t, int32, MachineType::Int32(),
                           AtomicMemoryOrder::kAcqRel);
  TEST_ATOMIC_LOAD_INTEGER(uint32_t, uint32, MachineType::Uint32(),
                           AtomicMemoryOrder::kAcqRel);
#if V8_TARGET_ARCH_64_BIT
  TEST_ATOMIC_LOAD_INTEGER(uint64_t, uint64, MachineType::Uint64(),
                           AtomicMemoryOrder::kAcqRel);
#endif
}

TEST(SeqCstLoadInteger) {
  TEST_ATOMIC_LOAD_INTEGER(int8_t, int8, MachineType::Int8(),
                           AtomicMemoryOrder::kSeqCst);
  TEST_ATOMIC_LOAD_INTEGER(uint8_t, uint8, MachineType::Uint8(),
                           AtomicMemoryOrder::kSeqCst);
  TEST_ATOMIC_LOAD_INTEGER(int16_t, int16, MachineType::Int16(),
                           AtomicMemoryOrder::kSeqCst);
  TEST_ATOMIC_LOAD_INTEGER(uint16_t, uint16, MachineType::Uint16(),
                           AtomicMemoryOrder::kSeqCst);
  TEST_ATOMIC_LOAD_INTEGER(int32_t, int32, MachineType::Int32(),
                           AtomicMemoryOrder::kSeqCst);
  TEST_ATOMIC_LOAD_INTEGER(uint32_t, uint32, MachineType::Uint32(),
                           AtomicMemoryOrder::kSeqCst);
#if V8_TARGET_ARCH_64_BIT
  TEST_ATOMIC_LOAD_INTEGER(uint64_t, uint64, MachineType::Uint64(),
                           AtomicMemoryOrder::kSeqCst);
#endif
}

namespace {
// Mostly same as CHECK_EQ() but customized for compressed tagged values.
template <typename CType>
void CheckEq(CType in_value, CType out_value) {
  CHECK_EQ(in_value, out_value);
}

#ifdef V8_COMPRESS_POINTERS
// Specializations for checking the result of compressing store.
template <>
void CheckEq<Tagged<Object>>(Tagged<Object> in_value,
                             Tagged<Object> out_value) {
  // Compare only lower 32-bits of the value because tagged load/stores are
  // 32-bit operations anyway.
  CHECK_EQ(static_cast<Tagged_t>(in_value.ptr()),
           static_cast<Tagged_t>(out_value.ptr()));
}

template <>
void CheckEq<Tagged<HeapObject>>(Tagged<HeapObject> in_value,
                                 Tagged<HeapObject> out_value) {
  return CheckEq<Tagged<Object>>(in_value, out_value);
}

template <>
void CheckEq<Tagged<Smi>>(Tagged<Smi> in_value, Tagged<Smi> out_value) {
  return CheckEq<Tagged<Object>>(in_value, out_value);
}
#endif

template <typename T>
void InitBuffer(Tagged<T>* buffer, size_t length, MachineType type) {
  const size_t kBufferSize = sizeof(Tagged<T>) * length;

  // Tagged field loads require values to be properly tagged because of
  // pointer decompression that may be happenning during load.
  Isolate* isolate = CcTest::InitIsolateOnce();
  Tagged<Smi>* smi_view = reinterpret_cast<Tagged<Smi>*>(&buffer[0]);
  if (type.IsTaggedSigned()) {
    for (size_t i = 0; i < length; i++) {
      smi_view[i] = Smi::FromInt(static_cast<int>(i + kBufferSize) ^ 0xABCDEF0);
    }
  } else {
    memcpy(&buffer[0], &isolate->roots_table(), kBufferSize);
    if (!type.IsTaggedPointer()) {
      // Also add some Smis if we are checking AnyTagged case.
      for (size_t i = 0; i < length / 2; i++) {
        smi_view[i] =
            Smi::FromInt(static_cast<int>(i + kBufferSize) ^ 0xABCDEF0);
      }
    }
  }
}

template <typename T>
void AtomicLoadTagged(MachineType type, AtomicMemoryOrder order) {
  const int kNumElems = 16;
  Tagged<T> buffer[kNumElems];

  InitBuffer(buffer, kNumElems, type);

  for (int i = 0; i < kNumElems; i++) {
    BufferedRawMachineAssemblerTester<Tagged<T>> m;
    Tagged<T>* base_pointer = &buffer[0];
    if (COMPRESS_POINTERS_BOOL) {
      base_pointer =
          reinterpret_cast<Tagged<T>*>(LSB(base_pointer, kTaggedSize));
    }
    Node* base = m.PointerConstant(base_pointer);
    Node* index = m.Int32Constant(i * sizeof(buffer[0]));
    AtomicLoadParameters params(type, order);
    Node* load;
    if (kTaggedSize == 8) {
      load = m.AtomicLoad64(params, base, index);
    } else {
      load = m.AtomicLoad(params, base, index);
    }
    m.Return(load);
    CheckEq<Tagged<T>>(buffer[i], m.Call());
  }
}
}  // namespace

TEST(AcquireLoadTagged) {
  AtomicLoadTagged<Smi>(MachineType::TaggedSigned(),
                        AtomicMemoryOrder::kAcqRel);
  AtomicLoadTagged<HeapObject>(MachineType::TaggedPointer(),
                               AtomicMemoryOrder::kAcqRel);
  AtomicLoadTagged<Object>(MachineType::AnyTagged(),
                           AtomicMemoryOrder::kAcqRel);
}

TEST(SeqCstLoadTagged) {
  AtomicLoadTagged<Smi>(MachineType::TaggedSigned(),
                        AtomicMemoryOrder::kSeqCst);
  AtomicLoadTagged<HeapObject>(MachineType::TaggedPointer(),
                               AtomicMemoryOrder::kSeqCst);
  AtomicLoadTagged<Object>(MachineType::AnyTagged(),
                           AtomicMemoryOrder::kSeqCst);
}

#define TEST_ATOMIC_STORE_INTEGER(ctype, itype, mach_type, order)             \
  do {                                                                        \
    ctype buffer[1];                                                          \
    buffer[0] = static_cast<ctype>(-1);                                       \
                                                                              \
    BufferedRawMachineAssemblerTester<int32_t> m(mach_type);                  \
    Node* value = m.Parameter(0);                                             \
    Node* base = m.PointerConstant(&buffer[0]);                               \
    Node* index = m.Int32Constant(0);                                         \
    AtomicStoreParameters params(mach_type.representation(), kNoWriteBarrier, \
                                 order);                                      \
    if (mach_type.MemSize() == 8) {                                           \
      m.AtomicStore64(params, base, index, value, nullptr);                   \
    } else {                                                                  \
      m.AtomicStore(params, base, index, value);                              \
    }                                                                         \
                                                                              \
    int32_t OK = 0x29000;                                                     \
    m.Return(m.Int32Constant(OK));                                            \
                                                                              \
    FOR_INPUTS(ctype, itype, i) {                                             \
      CHECK_EQ(OK, m.Call(i));                                                \
      CHECK_EQ(i, buffer[0]);                                                 \
    }                                                                         \
  } while (false)

TEST(ReleaseStoreInteger) {
  TEST_ATOMIC_STORE_INTEGER(int8_t, int8, MachineType::Int8(),
                            AtomicMemoryOrder::kAcqRel);
  TEST_ATOMIC_STORE_INTEGER(uint8_t, uint8, MachineType::Uint8(),
                            AtomicMemoryOrder::kAcqRel);
  TEST_ATOMIC_STORE_INTEGER(int16_t, int16, MachineType::Int16(),
                            AtomicMemoryOrder::kAcqRel);
  TEST_ATOMIC_STORE_INTEGER(uint16_t, uint16, MachineType::Uint16(),
                            AtomicMemoryOrder::kAcqRel);
  TEST_ATOMIC_STORE_INTEGER(int32_t, int32, MachineType::Int32(),
                            AtomicMemoryOrder::kAcqRel);
  TEST_ATOMIC_STORE_INTEGER(uint32_t, uint32, MachineType::Uint32(),
                            AtomicMemoryOrder::kAcqRel);
#if V8_TARGET_ARCH_64_BIT
  TEST_ATOMIC_STORE_INTEGER(uint64_t, uint64, MachineType::Uint64(),
                            AtomicMemoryOrder::kAcqRel);
#endif
}

TEST(SeqCstStoreInteger) {
  TEST_ATOMIC_STORE_INTEGER(int8_t, int8, MachineType::Int8(),
                            AtomicMemoryOrder::kSeqCst);
  TEST_ATOMIC_STORE_INTEGER(uint8_t, uint8, MachineType::Uint8(),
                            AtomicMemoryOrder::kSeqCst);
  TEST_ATOMIC_STORE_INTEGER(int16_t, int16, MachineType::Int16(),
                            AtomicMemoryOrder::kSeqCst);
  TEST_ATOMIC_STORE_INTEGER(uint16_t, uint16, MachineType::Uint16(),
                            AtomicMemoryOrder::kSeqCst);
  TEST_ATOMIC_STORE_INTEGER(int32_t, int32, MachineType::Int32(),
                            AtomicMemoryOrder::kSeqCst);
  TEST_ATOMIC_STORE_INTEGER(uint32_t, uint32, MachineType::Uint32(),
                            AtomicMemoryOrder::kSeqCst);
#if V8_TARGET_ARCH_64_BIT
  TEST_ATOMIC_STORE_INTEGER(uint64_t, uint64, MachineType::Uint64(),
                            AtomicMemoryOrder::kSeqCst);
#endif
}

namespace {
template <typename T>
void AtomicStoreTagged(MachineType type, AtomicMemoryOrder order) {
  // This tests that tagged values are correctly transferred by atomic loads and
  // stores from in_buffer to out_buffer. For each particular element in
  // in_buffer, it is copied to a different index in out_buffer, and all other
  // indices are zapped, to test instructions of the correct width are emitted.

  const int kNumElems = 16;
  Tagged<T> in_buffer[kNumElems];
  Tagged<T> out_buffer[kNumElems];
  uintptr_t zap_data[] = {kZapValue, kZapValue};
  Tagged<T> zap_value;

  static_assert(sizeof(Tagged<T>) <= sizeof(zap_data));
  MemCopy(&zap_value, &zap_data, sizeof(Tagged<T>));
  InitBuffer(in_buffer, kNumElems, type);

#ifdef V8_TARGET_BIG_ENDIAN
  int offset = sizeof(Tagged<T>) - ElementSizeInBytes(type.representation());
#else
  int offset = 0;
#endif

  for (int32_t x = 0; x < kNumElems; x++) {
    int32_t y = kNumElems - x - 1;

    RawMachineAssemblerTester<int32_t> m;
    int32_t OK = 0x29000 + x;
    Node* in_base = m.PointerConstant(in_buffer);
    Node* in_index = m.IntPtrConstant(x * sizeof(Tagged<T>) + offset);
    Node* out_base = m.PointerConstant(out_buffer);
    Node* out_index = m.IntPtrConstant(y * sizeof(Tagged<T>) + offset);

    Node* load;
    AtomicLoadParameters load_params(type, order);
    AtomicStoreParameters store_params(type.representation(), kNoWriteBarrier,
                                       order);
    if (kTaggedSize == 4) {
      load = m.AtomicLoad(load_params, in_base, in_index);
      m.AtomicStore(store_params, out_base, out_index, load);
    } else {
      DCHECK(m.machine()->Is64());
      load = m.AtomicLoad64(load_params, in_base, in_index);
      m.AtomicStore64(store_params, out_base, out_index, load, nullptr);
    }

    m.Return(m.Int32Constant(OK));

    for (int32_t z = 0; z < kNumElems; z++) {
      out_buffer[z] = zap_value;
    }
    CHECK_NE(in_buffer[x], out_buffer[y]);
    CHECK_EQ(OK, m.Call());
    // Mostly same as CHECK_EQ() but customized for compressed tagged values.
    CheckEq<Tagged<T>>(in_buffer[x], out_buffer[y]);
    for (int32_t z = 0; z < kNumElems; z++) {
      if (z != y) CHECK_EQ(zap_value, out_buffer[z]);
    }
  }
}
}  // namespace

TEST(ReleaseStoreTagged) {
  AtomicStoreTagged<Smi>(MachineType::TaggedSigned(),
                         AtomicMemoryOrder::kAcqRel);
  AtomicStoreTagged<HeapObject>(MachineType::TaggedPointer(),
                                AtomicMemoryOrder::kAcqRel);
  AtomicStoreTagged<Object>(MachineType::AnyTagged(),
                            AtomicMemoryOrder::kAcqRel);
}

TEST(SeqCstStoreTagged) {
  AtomicStoreTagged<Smi>(MachineType::TaggedSigned(),
                         AtomicMemoryOrder::kSeqCst);
  AtomicStoreTagged<HeapObject>(MachineType::TaggedPointer(),
                                AtomicMemoryOrder::kSeqCst);
  AtomicStoreTagged<Object>(MachineType::AnyTagged(),
                            AtomicMemoryOrder::kSeqCst);
}

#if V8_TARGET_ARCH_32_BIT

namespace {
void TestAtomicPairLoadInteger(AtomicMemoryOrder order) {
  uint64_t buffer[1];
  uint32_t high;
  uint32_t low;

  BufferedRawMachineAssemblerTester<int32_t> m;
  Node* base = m.PointerConstant(&buffer[0]);
  Node* index = m.Int32Constant(0);

  Node* pair_load = m.AtomicLoad64(
      AtomicLoadParameters(MachineType::Uint64(), order), base, index);
  m.StoreToPointer(&low, MachineRepresentation::kWord32,
                   m.Projection(0, pair_load));
  m.StoreToPointer(&high, MachineRepresentation::kWord32,
                   m.Projection(1, pair_load));

  int32_t OK = 0x29000;
  m.Return(m.Int32Constant(OK));

  FOR_UINT64_INPUTS(i) {
    buffer[0] = i;
    CHECK_EQ(OK, m.Call());
    CHECK_EQ(i, make_uint64(high, low));
  }
}
}  // namespace

TEST(AcquirePairLoadInteger) {
  TestAtomicPairLoadInteger(AtomicMemoryOrder::kAcqRel);
}

TEST(SeqCstPairLoadInteger) {
  TestAtomicPairLoadInteger(AtomicMemoryOrder::kSeqCst);
}

namespace {
void TestAtomicPairStoreInteger(AtomicMemoryOrder order) {
  uint64_t buffer[1];

  BufferedRawMachineAssemblerTester<int32_t> m(MachineType::Uint32(),
                                               MachineType::Uint32());
  Node* base = m.PointerConstant(&buffer[0]);
  Node* index = m.Int32Constant(0);

  m.AtomicStore64(AtomicStoreParameters(MachineRepresentation::kWord64,
                                        kNoWriteBarrier, order),
                  base, index, m.Parameter(0), m.Parameter(1));

  int32_t OK = 0x29000;
  m.Return(m.Int32Constant(OK));

  FOR_UINT64_INPUTS(i) {
    CHECK_EQ(OK, m.Call(static_cast<uint32_t>(i & 0xFFFFFFFF),
                        static_cast<uint32_t>(i >> 32)));
    CHECK_EQ(i, buffer[0]);
  }
}
}  // namespace

TEST(ReleasePairStoreInteger) {
  TestAtomicPairStoreInteger(AtomicMemoryOrder::kAcqRel);
}

TEST(SeqCstPairStoreInteger) {
  TestAtomicPairStoreInteger(AtomicMemoryOrder::kSeqCst);
}

#endif  // V8_TARGET_ARCH_32_BIT

}  // namespace compiler
}  // namespace internal
}  // namespace v8

"""

```