Response: Let's break down the thought process for analyzing this C++ code and generating the summary and JavaScript examples.

1. **Understand the Goal:** The request asks for a summary of the C++ file's functionality and, if applicable, a JavaScript explanation with examples. This means focusing on what the code *does* and how it relates to JavaScript's memory operations.

2. **Initial Scan and Keyword Spotting:**  I'd start by quickly skimming the code, looking for repeated patterns, keywords, and recognizable structures. I see:
    * `#include` statements (standard library and V8-specific headers). This tells me it's a C++ test file within the V8 project.
    * `namespace v8`, `namespace internal`, `namespace compiler`. This indicates the code's location within the V8 codebase.
    * `enum TestAlignment { kAligned, kUnaligned };`. This suggests the code is testing memory access with different alignment requirements.
    * `RunLoadInt32`, `RunLoadFloat32Offset`, `RunLoadStore`, `RunUnalignedLoadStore`, etc. These function names are very descriptive and point to the core actions being tested: loading and storing various data types (integers, floats) with and without alignment considerations.
    * `RawMachineAssemblerTester` and `BufferedRawMachineAssemblerTester`. This strongly suggests the code is directly manipulating machine code or an intermediate representation close to it. "Assembler" is a key giveaway.
    * `m.LoadFromPointer`, `m.UnalignedLoadFromPointer`, `m.StoreToPointer`, `m.UnalignedStoreToPointer`, `m.Load`, `m.UnalignedLoad`, `m.Store`, `m.UnalignedStore`. These are the core operations being tested.
    * `CHECK_EQ`, `CHECK_DOUBLE_EQ`, `UNREACHABLE`. These are standard testing macros.
    * `FOR_INT32_INPUTS`, `FOR_FLOAT32_INPUTS`, `FOR_FLOAT64_INPUTS`, `FOR_UINT32_INPUTS`, `FOR_INT64_INPUTS`, `FOR_UINT64_INPUTS`. These macros indicate the code is testing with a range of different input values for various data types.
    * `TEST(...)`. This is a common testing framework macro.
    * `#ifdef V8_COMPRESS_POINTERS`. This indicates conditional compilation based on a V8 build flag, likely related to memory optimization.
    * Mentions of "tagged values," "Smis," and "HeapObjects." These are V8-specific data types.

3. **Focus on Core Functionality:** The repeated patterns of `RunLoad...` and `RunStore...` functions, along with the `TestAlignment` enum, are the most important clues. The code is clearly focused on testing load and store operations. The "aligned" vs. "unaligned" distinction is crucial.

4. **Understanding Alignment:** I recall that aligned memory access is generally faster and sometimes required by certain processor architectures, while unaligned access might be slower or require special handling. This context helps interpret the purpose of testing both.

5. **Connecting to JavaScript (the Key Challenge):** This is the crucial step. How do these low-level C++ tests relate to JavaScript?
    * **Memory Model:** JavaScript engines (like V8) manage memory on behalf of the JavaScript code. While JavaScript doesn't have explicit pointers like C++, the engine uses them internally.
    * **Data Types:** JavaScript has numbers (which can be integers or floating-point), and objects (which are essentially collections of properties). These need to be stored in memory.
    * **Engine Optimizations:** V8 performs various optimizations, including how data is laid out in memory. Testing aligned and unaligned access hints at potential optimizations or scenarios where unaligned access might occur (e.g., when dealing with external data or specific object layouts).
    * **Typed Arrays/Buffers:**  These JavaScript features *do* give more direct access to underlying memory. `ArrayBuffer` is a raw byte buffer, and `TypedArray` views provide typed access (e.g., `Int32Array`). This is a strong connection point.

6. **Formulating the Summary:** Based on the observations, I would draft a summary like: "This C++ file tests the functionality of loading and storing data of various types (integers, floats, pointers, tagged values) in V8's compiler. It specifically checks both aligned and unaligned memory access, covering direct loads/stores and those with offsets. The tests use `RawMachineAssemblerTester` to generate machine code snippets for these operations and compare the results."

7. **Creating JavaScript Examples:** This involves thinking about how the concepts of aligned/unaligned access manifest in JavaScript:
    * **Direct Analogy is Difficult:** JavaScript doesn't have direct control over memory alignment in the same way C++ does.
    * **Focus on Outcomes:** Instead of trying to *force* unaligned access in JS, focus on the *outcomes* that these tests ensure are handled correctly by V8. For example, when you access an element in a `TypedArray`, V8 handles the underlying memory access.
    * **`ArrayBuffer` and `TypedArray`:** These are the most relevant APIs. Demonstrate how you can create a raw buffer and then access it with different typed views, implicitly relying on V8 to handle the memory operations correctly. Illustrate reading and writing data of different sizes.
    * **Emphasize Engine Responsibility:**  Point out that the JavaScript developer doesn't usually need to worry about alignment, as V8 handles it. The tests ensure that this handling is correct.

8. **Refinement and Wording:** Review the summary and examples for clarity and accuracy. Ensure the JavaScript examples are easy to understand and demonstrate the relevant concepts.

**(Self-Correction during the process):**

* **Initial Thought:** "Maybe this is about testing different memory layouts of JavaScript objects."
* **Correction:** While related, the direct use of `RawMachineAssemblerTester` and the explicit "aligned/unaligned" testing points more towards testing the *primitives* of load and store operations at a lower level than specific object layouts. The object layout tests would likely be in a different file.
* **Initial Thought:** "Can I create truly 'unaligned' access with standard JavaScript?"
* **Correction:**  Not directly. JavaScript abstracts away this level of detail. The focus should be on how V8 ensures correctness even when dealing with potentially unaligned data internally, which these tests validate. The `TypedArray` example shows how different views can interpret the same underlying buffer.

By following these steps, combining code analysis with knowledge of V8 and JavaScript's memory model, I can arrive at a comprehensive and accurate explanation.
这个C++源代码文件 `test-run-load-store.cc` 的主要功能是**测试 V8 JavaScript 引擎中编译器生成的加载和存储指令的正确性**。

更具体地说，它涵盖了以下几个方面：

1. **测试不同数据类型的加载和存储操作：**  代码中针对 `int8_t`, `uint8_t`, `int16_t`, `uint16_t`, `int32_t`, `uint32_t`, 指针 (`void*`), 标记值 (`Tagged<Smi>`, `Tagged<HeapObject>`, `Tagged<Object>`), `float`, `double`, 以及在 64 位架构下的 `int64_t` 等多种数据类型进行了加载和存储操作的测试。

2. **测试对齐和非对齐的内存访问：** 文件中定义了一个 `TestAlignment` 枚举，用于区分对齐和非对齐的内存访问。代码针对这两种情况分别进行了测试，确保编译器生成的指令在处理对齐和非对齐的内存访问时都能正常工作。

3. **测试带有偏移量的加载和存储：**  代码中包含了测试从指定内存地址加上偏移量后进行加载和存储的功能。这模拟了访问数组元素或对象属性等场景。

4. **测试加载后进行符号扩展和零扩展：** 对于较小的数据类型（如 `int8_t`, `int16_t`）的加载，代码测试了在加载到更大的数据类型时进行符号扩展（保持符号位）和零扩展（用零填充高位）的功能。

5. **使用 `RawMachineAssemblerTester` 和 `BufferedRawMachineAssemblerTester`：**  这些测试工具允许直接生成和执行底层的机器码指令片段，以便精确地测试加载和存储操作的语义。

**与 JavaScript 的功能关系以及 JavaScript 示例：**

这个测试文件直接关系到 V8 引擎如何将 JavaScript 代码编译成高效的机器码。JavaScript 引擎需要能够正确地加载和存储各种类型的数据到内存中。

虽然 JavaScript 本身不直接暴露底层的内存地址和对齐概念，但 V8 引擎在执行 JavaScript 代码时，会在底层进行大量的内存操作。例如，访问一个 JavaScript 对象的属性，或者访问一个 `TypedArray` 的元素，都需要进行加载和存储操作。

**JavaScript 示例：**

考虑以下 JavaScript 代码片段：

```javascript
let arr = new Int32Array(2);
arr[0] = 10;
let value = arr[0];
```

在这个简单的例子中，V8 引擎在执行时，需要做以下几件事，而 `test-run-load-store.cc` 中测试的功能就与之息息相关：

1. **`new Int32Array(2)`:**  V8 需要在内存中分配一块连续的空间来存储两个 32 位的整数。
2. **`arr[0] = 10;`:** V8 需要将整数值 `10` 存储到 `arr` 指向的内存地址的起始位置（偏移量为 0）。这涉及到 **存储 (Store)** 操作。 `test-run-load-store.cc` 中的 `RunLoadStoreInt32` 等测试函数就模拟了这种场景。由于 `Int32Array` 通常是内存对齐的，所以也会测试对齐的存储。
3. **`let value = arr[0];`:** V8 需要从 `arr` 指向的内存地址的起始位置加载一个 32 位的整数值。这涉及到 **加载 (Load)** 操作。 `test-run-load-store.cc` 中的 `RunLoadInt32` 等测试函数就模拟了这种场景。

**更进一步的例子，涉及非对齐访问（在某些特定情况下，JavaScript 可能会触发非对齐访问，但这通常是 V8 内部处理的）：**

虽然 JavaScript 开发者通常不需要直接处理非对齐内存访问，但在某些底层操作或与外部数据交互时，V8 可能会遇到这种情况。例如，当 JavaScript 代码操作 `ArrayBuffer` 的视图时，如果视图的起始位置或访问的数据大小与底层内存的对齐方式不匹配，就可能涉及非对齐访问。

```javascript
let buffer = new ArrayBuffer(5);
let view1 = new Uint8Array(buffer, 1, 3); // 从偏移量 1 开始创建一个 Uint8Array
let view2 = new Uint32Array(buffer, 1, 1); // 从偏移量 1 开始尝试创建一个 Uint32Array (可能会导致非对齐访问，取决于架构)

view1[0] = 0xAA;
view1[1] = 0xBB;
view1[2] = 0xCC;

console.log(view2[0]); //  结果取决于 CPU 的架构和字节序，可能无法正确读取一个完整的 Uint32
```

在这个例子中，`view2` 尝试从偏移量 1 开始读取一个 32 位的整数。如果 CPU 架构要求 32 位整数必须在 4 字节对齐的地址上，那么这次访问就是非对齐的。`test-run-load-store.cc` 中的带有 `Unaligned` 前缀的测试函数（如 `RunUnalignedLoadInt32Offset`）就测试了 V8 引擎在处理这类非对齐访问时的正确性。

**总结:**

`test-run-load-store.cc` 是 V8 引擎的编译器测试套件的一部分，它通过生成和执行底层的机器码指令，来验证编译器生成的加载和存储指令在各种情况下的正确性，包括不同的数据类型、内存对齐方式以及偏移量。这对于确保 V8 能够正确高效地执行 JavaScript 代码至关重要。虽然 JavaScript 开发者通常不需要直接关注这些底层细节，但这些测试保证了 V8 在处理 JavaScript 的内存操作时是可靠的。

Prompt: 
```
这是目录为v8/test/cctest/compiler/test-run-load-store.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2016 the V8 project authors. All rights reserved. Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

#include <cmath>
#include <functional>
#include <limits>

#include "src/base/bits.h"
#include "src/base/overflowing-math.h"
#include "src/base/template-utils.h"
#include "src/base/utils/random-number-generator.h"
#include "src/objects/objects-inl.h"
#include "src/objects/tagged.h"
#include "test/cctest/cctest.h"
#include "test/cctest/compiler/codegen-tester.h"
#include "test/common/value-helper.h"

namespace v8 {
namespace internal {
namespace compiler {

enum TestAlignment {
  kAligned,
  kUnaligned,
};

#if V8_TARGET_LITTLE_ENDIAN
#define LSB(addr, bytes) addr
#elif V8_TARGET_BIG_ENDIAN
#define LSB(addr, bytes) reinterpret_cast<uint8_t*>(addr + 1) - (bytes)
#else
#error "Unknown Architecture"
#endif

// This is America!
#define A_BILLION 1000000000ULL
#define A_GIG (1024ULL * 1024ULL * 1024ULL)

namespace {
uint8_t* ComputeOffset(void* real_address, int32_t offset) {
  return reinterpret_cast<uint8_t*>(reinterpret_cast<Address>(real_address) -
                                    offset);
}

void RunLoadInt32(const TestAlignment t) {
  RawMachineAssemblerTester<int32_t> m;

  int32_t p1 = 0;  // loads directly from this location.

  if (t == TestAlignment::kAligned) {
    m.Return(m.LoadFromPointer(&p1, MachineType::Int32()));
  } else if (t == TestAlignment::kUnaligned) {
    m.Return(m.UnalignedLoadFromPointer(&p1, MachineType::Int32()));
  } else {
    UNREACHABLE();
  }

  FOR_INT32_INPUTS(i) {
    p1 = i;
    CHECK_EQ(p1, m.Call());
  }
}

void RunLoadInt32Offset(TestAlignment t) {
  int32_t p1 = 0;  // loads directly from this location.

  int32_t offsets[] = {-2000000, -100, -101, 1,          3,
                       7,        120,  2000, 2000000000, 0xFF};

  for (size_t i = 0; i < arraysize(offsets); i++) {
    RawMachineAssemblerTester<int32_t> m;
    int32_t offset = offsets[i];
    uint8_t* pointer = ComputeOffset(&p1, offset);

    // generate load [#base + #index]
    if (t == TestAlignment::kAligned) {
      m.Return(m.LoadFromPointer(pointer, MachineType::Int32(), offset));
    } else if (t == TestAlignment::kUnaligned) {
      m.Return(
          m.UnalignedLoadFromPointer(pointer, MachineType::Int32(), offset));
    } else {
      UNREACHABLE();
    }

    FOR_INT32_INPUTS(j) {
      p1 = j;
      CHECK_EQ(p1, m.Call());
    }
  }
}

void RunLoadStoreFloat32Offset(TestAlignment t) {
  float p1 = 0.0f;  // loads directly from this location.
  float p2 = 0.0f;  // and stores directly into this location.

  FOR_INT32_INPUTS(i) {
    int32_t magic =
        base::AddWithWraparound(0x2342AABB, base::MulWithWraparound(i, 3));
    RawMachineAssemblerTester<int32_t> m;
    int32_t offset = i;
    uint8_t* from = ComputeOffset(&p1, offset);
    uint8_t* to = ComputeOffset(&p2, offset);
    // generate load [#base + #index]
    if (t == TestAlignment::kAligned) {
      Node* load = m.Load(MachineType::Float32(), m.PointerConstant(from),
                          m.IntPtrConstant(offset));
      m.Store(MachineRepresentation::kFloat32, m.PointerConstant(to),
              m.IntPtrConstant(offset), load, kNoWriteBarrier);
    } else if (t == TestAlignment::kUnaligned) {
      Node* load =
          m.UnalignedLoad(MachineType::Float32(), m.PointerConstant(from),
                          m.IntPtrConstant(offset));
      m.UnalignedStore(MachineRepresentation::kFloat32, m.PointerConstant(to),
                       m.IntPtrConstant(offset), load);

    } else {
      UNREACHABLE();
    }
    m.Return(m.Int32Constant(magic));

    FOR_FLOAT32_INPUTS(j) {
      p1 = j;
      p2 = j - 5;
      CHECK_EQ(magic, m.Call());
      CHECK_DOUBLE_EQ(p1, p2);
    }
  }
}

void RunLoadStoreFloat64Offset(TestAlignment t) {
  double p1 = 0;  // loads directly from this location.
  double p2 = 0;  // and stores directly into this location.

  FOR_INT32_INPUTS(i) {
    int32_t magic =
        base::AddWithWraparound(0x2342AABB, base::MulWithWraparound(i, 3));
    RawMachineAssemblerTester<int32_t> m;
    int32_t offset = i;
    uint8_t* from = ComputeOffset(&p1, offset);
    uint8_t* to = ComputeOffset(&p2, offset);
    // generate load [#base + #index]
    if (t == TestAlignment::kAligned) {
      Node* load = m.Load(MachineType::Float64(), m.PointerConstant(from),
                          m.IntPtrConstant(offset));
      m.Store(MachineRepresentation::kFloat64, m.PointerConstant(to),
              m.IntPtrConstant(offset), load, kNoWriteBarrier);
    } else if (t == TestAlignment::kUnaligned) {
      Node* load =
          m.UnalignedLoad(MachineType::Float64(), m.PointerConstant(from),
                          m.IntPtrConstant(offset));
      m.UnalignedStore(MachineRepresentation::kFloat64, m.PointerConstant(to),
                       m.IntPtrConstant(offset), load);
    } else {
      UNREACHABLE();
    }
    m.Return(m.Int32Constant(magic));

    FOR_FLOAT64_INPUTS(j) {
      p1 = j;
      p2 = j - 5;
      CHECK_EQ(magic, m.Call());
      CHECK_DOUBLE_EQ(p1, p2);
    }
  }
}
}  // namespace

TEST(RunLoadInt32) { RunLoadInt32(TestAlignment::kAligned); }

TEST(RunUnalignedLoadInt32) { RunLoadInt32(TestAlignment::kUnaligned); }

TEST(RunLoadInt32Offset) { RunLoadInt32Offset(TestAlignment::kAligned); }

TEST(RunUnalignedLoadInt32Offset) {
  RunLoadInt32Offset(TestAlignment::kUnaligned);
}

TEST(RunLoadStoreFloat32Offset) {
  RunLoadStoreFloat32Offset(TestAlignment::kAligned);
}

TEST(RunUnalignedLoadStoreFloat32Offset) {
  RunLoadStoreFloat32Offset(TestAlignment::kUnaligned);
}

TEST(RunLoadStoreFloat64Offset) {
  RunLoadStoreFloat64Offset(TestAlignment::kAligned);
}

TEST(RunUnalignedLoadStoreFloat64Offset) {
  RunLoadStoreFloat64Offset(TestAlignment::kUnaligned);
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

// Initializes the buffer with some raw data respecting requested representation
// of the values.
template <typename CType>
void InitBuffer(CType* buffer, size_t length, MachineType type) {
  const size_t kBufferSize = sizeof(CType) * length;
  if (!type.IsTagged()) {
    uint8_t* raw = reinterpret_cast<uint8_t*>(buffer);
    for (size_t i = 0; i < kBufferSize; i++) {
      raw[i] = static_cast<uint8_t>((i + kBufferSize) ^ 0xAA);
    }
    return;
  }

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

template <typename CType>
void RunLoadImmIndex(MachineType type, TestAlignment t) {
  const int kNumElems = 16;
  CType buffer[kNumElems];

  InitBuffer(buffer, kNumElems, type);

  // Test with various large and small offsets.
  for (int offset = -1; offset <= 200000; offset *= -5) {
    for (int i = 0; i < kNumElems; i++) {
      BufferedRawMachineAssemblerTester<CType> m;
      CType* base_pointer = reinterpret_cast<CType*>(
          ComputeOffset(&buffer[0], offset * sizeof(CType)));
#ifdef V8_COMPRESS_POINTERS
      if (type.IsTagged()) {
        // When pointer compression is enabled then we need to access only
        // the lower 32-bit of the tagged value while the buffer contains
        // full 64-bit values.
        base_pointer = reinterpret_cast<CType*>(LSB(base_pointer, kTaggedSize));
      }
#endif

      Node* base = m.PointerConstant(base_pointer);
      Node* index = m.Int32Constant((offset + i) * sizeof(buffer[0]));
      if (t == TestAlignment::kAligned) {
        m.Return(m.Load(type, base, index));
      } else if (t == TestAlignment::kUnaligned) {
        m.Return(m.UnalignedLoad(type, base, index));
      } else {
        UNREACHABLE();
      }

      CheckEq<CType>(buffer[i], m.Call());
    }
  }
}

template <typename CType>
void RunLoadStore(MachineType type, TestAlignment t) {
  const int kNumElems = 16;
  CType in_buffer[kNumElems];
  CType out_buffer[kNumElems];
  uintptr_t zap_data[] = {kZapValue, kZapValue};
  CType zap_value;

  static_assert(sizeof(CType) <= sizeof(zap_data));
  MemCopy(&zap_value, &zap_data, sizeof(CType));
  InitBuffer(in_buffer, kNumElems, type);

#ifdef V8_TARGET_BIG_ENDIAN
  int offset = sizeof(CType) - ElementSizeInBytes(type.representation());
#else
  int offset = 0;
#endif

  for (int32_t x = 0; x < kNumElems; x++) {
    int32_t y = kNumElems - x - 1;

    RawMachineAssemblerTester<int32_t> m;
    int32_t OK = 0x29000 + x;
    Node* in_base = m.PointerConstant(in_buffer);
    Node* in_index = m.IntPtrConstant(x * sizeof(CType) + offset);
    Node* out_base = m.PointerConstant(out_buffer);
    Node* out_index = m.IntPtrConstant(y * sizeof(CType) + offset);
    if (t == TestAlignment::kAligned) {
      Node* load = m.Load(type, in_base, in_index);
      m.Store(type.representation(), out_base, out_index, load,
              kNoWriteBarrier);
    } else if (t == TestAlignment::kUnaligned) {
      Node* load = m.UnalignedLoad(type, in_base, in_index);
      m.UnalignedStore(type.representation(), out_base, out_index, load);
    }

    m.Return(m.Int32Constant(OK));

    for (int32_t z = 0; z < kNumElems; z++) {
      out_buffer[z] = zap_value;
    }
    CHECK_NE(in_buffer[x], out_buffer[y]);
    CHECK_EQ(OK, m.Call());
    // Mostly same as CHECK_EQ() but customized for compressed tagged values.
    CheckEq<CType>(in_buffer[x], out_buffer[y]);
    for (int32_t z = 0; z < kNumElems; z++) {
      if (z != y) CHECK_EQ(zap_value, out_buffer[z]);
    }
  }
}

template <typename CType>
void RunUnalignedLoadStoreUnalignedAccess(MachineType type) {
  CType in, out;
  uint8_t in_buffer[2 * sizeof(CType)];
  uint8_t out_buffer[2 * sizeof(CType)];

  InitBuffer(&in, 1, type);

  for (int x = 0; x < static_cast<int>(sizeof(CType)); x++) {
    // Direct write to &in_buffer[x] may cause unaligned access in C++ code so
    // we use MemCopy() to handle that.
    MemCopy(&in_buffer[x], &in, sizeof(CType));

    for (int y = 0; y < static_cast<int>(sizeof(CType)); y++) {
      RawMachineAssemblerTester<int32_t> m;
      int32_t OK = 0x29000 + x;

      Node* in_base = m.PointerConstant(in_buffer);
      Node* in_index = m.IntPtrConstant(x);
      Node* load = m.UnalignedLoad(type, in_base, in_index);

      Node* out_base = m.PointerConstant(out_buffer);
      Node* out_index = m.IntPtrConstant(y);
      m.UnalignedStore(type.representation(), out_base, out_index, load);

      m.Return(m.Int32Constant(OK));

      CHECK_EQ(OK, m.Call());
      // Direct read of &out_buffer[y] may cause unaligned access in C++ code
      // so we use MemCopy() to handle that.
      MemCopy(&out, &out_buffer[y], sizeof(CType));
      // Mostly same as CHECK_EQ() but customized for compressed tagged values.
      CheckEq<CType>(in, out);
    }
  }
}
}  // namespace

TEST(RunLoadImmIndex) {
  RunLoadImmIndex<int8_t>(MachineType::Int8(), TestAlignment::kAligned);
  RunLoadImmIndex<uint8_t>(MachineType::Uint8(), TestAlignment::kAligned);
  RunLoadImmIndex<int16_t>(MachineType::Int16(), TestAlignment::kAligned);
  RunLoadImmIndex<uint16_t>(MachineType::Uint16(), TestAlignment::kAligned);
  RunLoadImmIndex<int32_t>(MachineType::Int32(), TestAlignment::kAligned);
  RunLoadImmIndex<uint32_t>(MachineType::Uint32(), TestAlignment::kAligned);
  RunLoadImmIndex<void*>(MachineType::Pointer(), TestAlignment::kAligned);
  RunLoadImmIndex<Tagged<Smi>>(MachineType::TaggedSigned(),
                               TestAlignment::kAligned);
  RunLoadImmIndex<Tagged<HeapObject>>(MachineType::TaggedPointer(),
                                      TestAlignment::kAligned);
  RunLoadImmIndex<Tagged<Object>>(MachineType::AnyTagged(),
                                  TestAlignment::kAligned);
  RunLoadImmIndex<float>(MachineType::Float32(), TestAlignment::kAligned);
  RunLoadImmIndex<double>(MachineType::Float64(), TestAlignment::kAligned);
#if V8_TARGET_ARCH_64_BIT
  RunLoadImmIndex<int64_t>(MachineType::Int64(), TestAlignment::kAligned);
#endif
  // TODO(titzer): test various indexing modes.
}

TEST(RunUnalignedLoadImmIndex) {
  RunLoadImmIndex<int16_t>(MachineType::Int16(), TestAlignment::kUnaligned);
  RunLoadImmIndex<uint16_t>(MachineType::Uint16(), TestAlignment::kUnaligned);
  RunLoadImmIndex<int32_t>(MachineType::Int32(), TestAlignment::kUnaligned);
  RunLoadImmIndex<uint32_t>(MachineType::Uint32(), TestAlignment::kUnaligned);
  RunLoadImmIndex<void*>(MachineType::Pointer(), TestAlignment::kUnaligned);
  RunLoadImmIndex<float>(MachineType::Float32(), TestAlignment::kUnaligned);
  RunLoadImmIndex<double>(MachineType::Float64(), TestAlignment::kUnaligned);
#if V8_TARGET_ARCH_64_BIT
  RunLoadImmIndex<int64_t>(MachineType::Int64(), TestAlignment::kUnaligned);
#endif
  // TODO(titzer): test various indexing modes.
}

TEST(RunLoadStore) {
  RunLoadStore<int8_t>(MachineType::Int8(), TestAlignment::kAligned);
  RunLoadStore<uint8_t>(MachineType::Uint8(), TestAlignment::kAligned);
  RunLoadStore<int16_t>(MachineType::Int16(), TestAlignment::kAligned);
  RunLoadStore<uint16_t>(MachineType::Uint16(), TestAlignment::kAligned);
  RunLoadStore<int32_t>(MachineType::Int32(), TestAlignment::kAligned);
  RunLoadStore<uint32_t>(MachineType::Uint32(), TestAlignment::kAligned);
  RunLoadStore<void*>(MachineType::Pointer(), TestAlignment::kAligned);
  RunLoadStore<Tagged<Smi>>(MachineType::TaggedSigned(),
                            TestAlignment::kAligned);
  RunLoadStore<Tagged<HeapObject>>(MachineType::TaggedPointer(),
                                   TestAlignment::kAligned);
  RunLoadStore<Tagged<Object>>(MachineType::AnyTagged(),
                               TestAlignment::kAligned);
  RunLoadStore<float>(MachineType::Float32(), TestAlignment::kAligned);
  RunLoadStore<double>(MachineType::Float64(), TestAlignment::kAligned);
#if V8_TARGET_ARCH_64_BIT
  RunLoadStore<int64_t>(MachineType::Int64(), TestAlignment::kAligned);
#endif
}

TEST(RunUnalignedLoadStore) {
  RunLoadStore<int16_t>(MachineType::Int16(), TestAlignment::kUnaligned);
  RunLoadStore<uint16_t>(MachineType::Uint16(), TestAlignment::kUnaligned);
  RunLoadStore<int32_t>(MachineType::Int32(), TestAlignment::kUnaligned);
  RunLoadStore<uint32_t>(MachineType::Uint32(), TestAlignment::kUnaligned);
  RunLoadStore<void*>(MachineType::Pointer(), TestAlignment::kUnaligned);
  RunLoadStore<float>(MachineType::Float32(), TestAlignment::kUnaligned);
  RunLoadStore<double>(MachineType::Float64(), TestAlignment::kUnaligned);
#if V8_TARGET_ARCH_64_BIT
  RunLoadStore<int64_t>(MachineType::Int64(), TestAlignment::kUnaligned);
#endif
}

TEST(RunUnalignedLoadStoreUnalignedAccess) {
  RunUnalignedLoadStoreUnalignedAccess<int16_t>(MachineType::Int16());
  RunUnalignedLoadStoreUnalignedAccess<uint16_t>(MachineType::Uint16());
  RunUnalignedLoadStoreUnalignedAccess<int32_t>(MachineType::Int32());
  RunUnalignedLoadStoreUnalignedAccess<uint32_t>(MachineType::Uint32());
  RunUnalignedLoadStoreUnalignedAccess<void*>(MachineType::Pointer());
  RunUnalignedLoadStoreUnalignedAccess<float>(MachineType::Float32());
  RunUnalignedLoadStoreUnalignedAccess<double>(MachineType::Float64());
#if V8_TARGET_ARCH_64_BIT
  RunUnalignedLoadStoreUnalignedAccess<int64_t>(MachineType::Int64());
#endif
}

namespace {
void RunLoadStoreSignExtend32(TestAlignment t) {
  int32_t buffer[4];
  RawMachineAssemblerTester<int32_t> m;
  Node* load8 = m.LoadFromPointer(LSB(&buffer[0], 1), MachineType::Int8());
  if (t == TestAlignment::kAligned) {
    Node* load16 = m.LoadFromPointer(LSB(&buffer[0], 2), MachineType::Int16());
    Node* load32 = m.LoadFromPointer(&buffer[0], MachineType::Int32());
    m.StoreToPointer(&buffer[1], MachineRepresentation::kWord32, load8);
    m.StoreToPointer(&buffer[2], MachineRepresentation::kWord32, load16);
    m.StoreToPointer(&buffer[3], MachineRepresentation::kWord32, load32);
  } else if (t == TestAlignment::kUnaligned) {
    Node* load16 =
        m.UnalignedLoadFromPointer(LSB(&buffer[0], 2), MachineType::Int16());
    Node* load32 = m.UnalignedLoadFromPointer(&buffer[0], MachineType::Int32());
    m.StoreToPointer(&buffer[1], MachineRepresentation::kWord32, load8);
    m.UnalignedStoreToPointer(&buffer[2], MachineRepresentation::kWord32,
                              load16);
    m.UnalignedStoreToPointer(&buffer[3], MachineRepresentation::kWord32,
                              load32);
  } else {
    UNREACHABLE();
  }
  m.Return(load8);

  FOR_INT32_INPUTS(i) {
    buffer[0] = i;

    CHECK_EQ(static_cast<int8_t>(i & 0xFF), m.Call());
    CHECK_EQ(static_cast<int8_t>(i & 0xFF), buffer[1]);
    CHECK_EQ(static_cast<int16_t>(i & 0xFFFF), buffer[2]);
    CHECK_EQ(i, buffer[3]);
  }
}

void RunLoadStoreZeroExtend32(TestAlignment t) {
  uint32_t buffer[4];
  RawMachineAssemblerTester<uint32_t> m;
  Node* load8 = m.LoadFromPointer(LSB(&buffer[0], 1), MachineType::Uint8());
  if (t == TestAlignment::kAligned) {
    Node* load16 = m.LoadFromPointer(LSB(&buffer[0], 2), MachineType::Uint16());
    Node* load32 = m.LoadFromPointer(&buffer[0], MachineType::Uint32());
    m.StoreToPointer(&buffer[1], MachineRepresentation::kWord32, load8);
    m.StoreToPointer(&buffer[2], MachineRepresentation::kWord32, load16);
    m.StoreToPointer(&buffer[3], MachineRepresentation::kWord32, load32);
  } else if (t == TestAlignment::kUnaligned) {
    Node* load16 =
        m.UnalignedLoadFromPointer(LSB(&buffer[0], 2), MachineType::Uint16());
    Node* load32 =
        m.UnalignedLoadFromPointer(&buffer[0], MachineType::Uint32());
    m.StoreToPointer(&buffer[1], MachineRepresentation::kWord32, load8);
    m.UnalignedStoreToPointer(&buffer[2], MachineRepresentation::kWord32,
                              load16);
    m.UnalignedStoreToPointer(&buffer[3], MachineRepresentation::kWord32,
                              load32);
  }
  m.Return(load8);

  FOR_UINT32_INPUTS(i) {
    buffer[0] = i;

    CHECK_EQ((i & 0xFF), m.Call());
    CHECK_EQ((i & 0xFF), buffer[1]);
    CHECK_EQ((i & 0xFFFF), buffer[2]);
    CHECK_EQ(i, buffer[3]);
  }
}
}  // namespace

TEST(RunLoadStoreSignExtend32) {
  RunLoadStoreSignExtend32(TestAlignment::kAligned);
}

TEST(RunUnalignedLoadStoreSignExtend32) {
  RunLoadStoreSignExtend32(TestAlignment::kUnaligned);
}

TEST(RunLoadStoreZeroExtend32) {
  RunLoadStoreZeroExtend32(TestAlignment::kAligned);
}

TEST(RunUnalignedLoadStoreZeroExtend32) {
  RunLoadStoreZeroExtend32(TestAlignment::kUnaligned);
}

#if V8_TARGET_ARCH_64_BIT

namespace {
void RunLoadStoreSignExtend64(TestAlignment t) {
  if ((true)) return;  // TODO(titzer): sign extension of loads to 64-bit.
  int64_t buffer[5];
  RawMachineAssemblerTester<int64_t> m;
  Node* load8 = m.LoadFromPointer(LSB(&buffer[0], 1), MachineType::Int8());
  if (t == TestAlignment::kAligned) {
    Node* load16 = m.LoadFromPointer(LSB(&buffer[0], 2), MachineType::Int16());
    Node* load32 = m.LoadFromPointer(LSB(&buffer[0], 4), MachineType::Int32());
    Node* load64 = m.LoadFromPointer(&buffer[0], MachineType::Int64());
    m.StoreToPointer(&buffer[1], MachineRepresentation::kWord64, load8);
    m.StoreToPointer(&buffer[2], MachineRepresentation::kWord64, load16);
    m.StoreToPointer(&buffer[3], MachineRepresentation::kWord64, load32);
    m.StoreToPointer(&buffer[4], MachineRepresentation::kWord64, load64);
  } else if (t == TestAlignment::kUnaligned) {
    Node* load16 =
        m.UnalignedLoadFromPointer(LSB(&buffer[0], 2), MachineType::Int16());
    Node* load32 =
        m.UnalignedLoadFromPointer(LSB(&buffer[0], 4), MachineType::Int32());
    Node* load64 = m.UnalignedLoadFromPointer(&buffer[0], MachineType::Int64());
    m.StoreToPointer(&buffer[1], MachineRepresentation::kWord64, load8);
    m.UnalignedStoreToPointer(&buffer[2], MachineRepresentation::kWord64,
                              load16);
    m.UnalignedStoreToPointer(&buffer[3], MachineRepresentation::kWord64,
                              load32);
    m.UnalignedStoreToPointer(&buffer[4], MachineRepresentation::kWord64,
                              load64);
  } else {
    UNREACHABLE();
  }
  m.Return(load8);

  FOR_INT64_INPUTS(i) {
    buffer[0] = i;

    CHECK_EQ(static_cast<int8_t>(i & 0xFF), m.Call());
    CHECK_EQ(static_cast<int8_t>(i & 0xFF), buffer[1]);
    CHECK_EQ(static_cast<int16_t>(i & 0xFFFF), buffer[2]);
    CHECK_EQ(static_cast<int32_t>(i & 0xFFFFFFFF), buffer[3]);
    CHECK_EQ(i, buffer[4]);
  }
}

void RunLoadStoreZeroExtend64(TestAlignment t) {
  if (kSystemPointerSize < 8) return;
  uint64_t buffer[5];
  RawMachineAssemblerTester<uint64_t> m;
  Node* load8 = m.LoadFromPointer(LSB(&buffer[0], 1), MachineType::Uint8());
  if (t == TestAlignment::kAligned) {
    Node* load16 = m.LoadFromPointer(LSB(&buffer[0], 2), MachineType::Uint16());
    Node* load32 = m.LoadFromPointer(LSB(&buffer[0], 4), MachineType::Uint32());
    Node* load64 = m.LoadFromPointer(&buffer[0], MachineType::Uint64());
    m.StoreToPointer(&buffer[1], MachineRepresentation::kWord64, load8);
    m.StoreToPointer(&buffer[2], MachineRepresentation::kWord64, load16);
    m.StoreToPointer(&buffer[3], MachineRepresentation::kWord64, load32);
    m.StoreToPointer(&buffer[4], MachineRepresentation::kWord64, load64);
  } else if (t == TestAlignment::kUnaligned) {
    Node* load16 =
        m.UnalignedLoadFromPointer(LSB(&buffer[0], 2), MachineType::Uint16());
    Node* load32 =
        m.UnalignedLoadFromPointer(LSB(&buffer[0], 4), MachineType::Uint32());
    Node* load64 =
        m.UnalignedLoadFromPointer(&buffer[0], MachineType::Uint64());
    m.StoreToPointer(&buffer[1], MachineRepresentation::kWord64, load8);
    m.UnalignedStoreToPointer(&buffer[2], MachineRepresentation::kWord64,
                              load16);
    m.UnalignedStoreToPointer(&buffer[3], MachineRepresentation::kWord64,
                              load32);
    m.UnalignedStoreToPointer(&buffer[4], MachineRepresentation::kWord64,
                              load64);
  } else {
    UNREACHABLE();
  }
  m.Return(load8);

  FOR_UINT64_INPUTS(i) {
    buffer[0] = i;

    CHECK_EQ((i & 0xFF), m.Call());
    CHECK_EQ((i & 0xFF), buffer[1]);
    CHECK_EQ((i & 0xFFFF), buffer[2]);
    CHECK_EQ((i & 0xFFFFFFFF), buffer[3]);
    CHECK_EQ(i, buffer[4]);
  }
}

}  // namespace

TEST(RunLoadStoreSignExtend64) {
  RunLoadStoreSignExtend64(TestAlignment::kAligned);
}

TEST(RunUnalignedLoadStoreSignExtend64) {
  RunLoadStoreSignExtend64(TestAlignment::kUnaligned);
}

TEST(RunLoadStoreZeroExtend64) {
  RunLoadStoreZeroExtend64(TestAlignment::kAligned);
}

TEST(RunUnalignedLoadStoreZeroExtend64) {
  RunLoadStoreZeroExtend64(TestAlignment::kUnaligned);
}

#endif

namespace {
template <typename IntType>
void LoadStoreTruncation(MachineType kRepresentation, TestAlignment t) {
  IntType input;

  RawMachineAssemblerTester<int32_t> m;
  Node* ap1;
  if (t == TestAlignment::kAligned) {
    Node* a = m.LoadFromPointer(&input, kRepresentation);
    ap1 = m.Int32Add(a, m.Int32Constant(1));
    m.StoreToPointer(&input, kRepresentation.representation(), ap1);
  } else if (t == TestAlignment::kUnaligned) {
    Node* a = m.UnalignedLoadFromPointer(&input, kRepresentation);
    ap1 = m.Int32Add(a, m.Int32Constant(1));
    m.UnalignedStoreToPointer(&input, kRepresentation.representation(), ap1);
  } else {
    UNREACHABLE();
  }
  m.Return(ap1);

  const IntType max = std::numeric_limits<IntType>::max();
  const IntType min = std::numeric_limits<IntType>::min();

  // Test upper bound.
  input = max;
  CHECK_EQ(max + 1, m.Call());
  CHECK_EQ(min, input);

  // Test lower bound.
  input = min;
  CHECK_EQ(static_cast<IntType>(max + 2), m.Call());
  CHECK_EQ(min + 1, input);

  // Test all one byte values that are not one byte bounds.
  for (int i = -127; i < 127; i++) {
    input = i;
    int expected = i >= 0 ? i + 1 : max + (i - min) + 2;
    CHECK_EQ(static_cast<IntType>(expected), m.Call());
    CHECK_EQ(static_cast<IntType>(i + 1), input);
  }
}
}  // namespace

TEST(RunLoadStoreTruncation) {
  LoadStoreTruncation<int8_t>(MachineType::Int8(), TestAlignment::kAligned);
  LoadStoreTruncation<int16_t>(MachineType::Int16(), TestAlignment::kAligned);
}

TEST(RunUnalignedLoadStoreTruncation) {
  LoadStoreTruncation<int16_t>(MachineType::Int16(), TestAlignment::kUnaligned);
}

#undef LSB
#undef A_BILLION
#undef A_GIG

}  // namespace compiler
}  // namespace internal
}  // namespace v8

"""

```