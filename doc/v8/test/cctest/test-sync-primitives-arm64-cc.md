Response:
Let's break down the thought process for analyzing this C++ V8 test file.

1. **Initial Understanding of the File Path:**  The path `v8/test/cctest/test-sync-primitives-arm64.cc` immediately tells us a few key things:
    * `v8`: This is definitely part of the V8 JavaScript engine's source code.
    * `test`: It's a test file, not core engine code.
    * `cctest`:  This likely refers to "C++ tests," indicating integration or unit tests written in C++.
    * `test-sync-primitives`: The tests are focused on synchronization primitives. This suggests things like mutexes, atomics, or similar mechanisms used for managing concurrent access to shared resources.
    * `arm64`: This specifies the target architecture for these tests. The behavior of synchronization primitives can be architecture-specific.
    * `.cc`:  It's a C++ source file.

2. **Copyright and Licensing:** The initial comment block is standard copyright and licensing information. It's important to note, but doesn't tell us about the *functionality* of the code.

3. **Includes:** The `#include` directives provide clues about what the code uses:
    * `"src/codegen/macro-assembler-inl.h"`:  This strongly suggests the code is dealing with low-level code generation, likely assembly instructions. "MacroAssembler" is a common term for a helper class to generate machine code. The `-inl.h` likely means it's an inline implementation of the macro assembler.
    * `"src/execution/arm64/simulator-arm64.h"`:  This confirms the ARM64 architecture focus and indicates that the tests are likely run *in a simulator* rather than directly on hardware. This is crucial information as the comments later highlight simulator-specific behavior.
    * `"src/objects/objects-inl.h"`: This suggests interaction with V8's object model at a low level. The `-inl.h` again points to inline implementations.
    * `"test/cctest/cctest.h"`:  This is the header for the V8 C++ testing framework.

4. **Namespace:** The code is within `namespace v8 { namespace internal { ... } }`, which is typical for V8's internal implementation details.

5. **Key Comment Block:** The large comment block starting with "These tests rely on the behaviour specific to the simulator..." is extremely important. It tells us:
    * These tests are *specifically* designed to test the *simulator's* behavior of synchronization primitives on ARM64.
    * The simulator is more "conservative" than real hardware regarding exclusive memory accesses (`ldxr`/`stxr`). This explains why certain tests might fail in the simulator but succeed on actual hardware. This is a crucial distinction for understanding the purpose of the tests.

6. **`#if defined(USE_SIMULATOR)`:** This preprocessor directive confirms that the code within this block is only compiled and executed when running in the simulator.

7. **`MemoryAccess` Struct:** This struct defines a way to represent different types of memory access operations (Load, Store, Exclusive Load, Exclusive Store) with details like size (Byte, HalfWord, Word), offset, and value. This is a core building block for the tests.

8. **`TestData` Struct:** This simple struct holds data that will be manipulated by the memory access operations. The union allows accessing the same memory location as different data types (int32_t, int16_t, int8_t).

9. **Helper Functions (`AssembleMemoryAccess`, `AssembleLoadExcl`, `AssembleStoreExcl`):** These functions take `MemoryAccess` structs and generate the corresponding ARM64 assembly instructions using the `MacroAssembler`. This confirms the low-level nature of the tests.

10. **`TestInvalidateExclusiveAccess` Function:** This is a key test function. It sets up a sequence of three memory accesses (load-exclusive, some other access, store-exclusive) and verifies the outcome. The function name strongly suggests it's testing how different memory accesses can invalidate the exclusive access reservation. The `expected_res` and `expected_data` parameters indicate that it's asserting specific outcomes.

11. **`TEST(simulator_invalidate_exclusive_access)` Macro:** This is a CCTEST macro defining a test case. It uses the `TestInvalidateExclusiveAccess` function with various combinations of memory accesses to test different scenarios of exclusive access invalidation.

12. **`ExecuteMemoryAccess` Function:** This function takes a single `MemoryAccess` and executes it using the simulator. It's a simpler version of `TestInvalidateExclusiveAccess` for single operations.

13. **`MemoryAccessThread` Class:** This class creates a separate thread to execute memory access operations concurrently. This indicates the tests are also exploring the behavior of synchronization primitives in a multi-threaded context.

14. **`TEST(simulator_invalidate_exclusive_access_threaded)` Macro:** This test case uses the `MemoryAccessThread` to simulate concurrent memory accesses and test scenarios where exclusive access might be interfered with by another thread.

15. **`#undef __` and `#endif  // USE_SIMULATOR`:**  These are standard cleanup and conditional compilation directives.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This might be about testing JavaScript's `Atomics` API."
* **Correction:** While related, the focus is on the *underlying implementation* of synchronization primitives at the machine code level, as indicated by the `MacroAssembler`. It's testing the simulator's fidelity in representing these low-level operations.
* **Initial thought:** "The `.cc` extension means it's just regular C++ code."
* **Refinement:**  While true, the context within the V8 project and the use of specific V8 headers and testing framework make it more than just generic C++. It's a *V8-specific* C++ test.
* **Noticing the Simulator Emphasis:** The prominent comment block about simulator-specific behavior is crucial. Without it, one might misunderstand why certain tests are structured the way they are. This realization shifts the understanding from "testing real hardware behavior" to "testing the simulator's correctness."

By following this step-by-step analysis of the code's structure, keywords, and comments, we can accurately determine its functionality and purpose within the V8 project. The emphasis on the simulator is the key takeaway.
好的，让我们来分析一下 `v8/test/cctest/test-sync-primitives-arm64.cc` 这个 V8 源代码文件的功能。

**功能概要**

该文件包含了一系列 C++ 单元测试，用于验证 V8 在 ARM64 架构的模拟器环境下，对同步原语（Synchronization Primitives）的实现是否正确。  这些同步原语主要指的是原子操作中的排他性加载（Load-Exclusive，`ldaxr`）和排他性存储（Store-Exclusive，`stlxr`）指令的行为。由于这些测试运行在模拟器上，它们特别关注模拟器对这些指令的保守实现方式。

**详细功能分解**

1. **测试目标：** 主要测试 `ldaxr` 和 `stlxr` 指令的正确性，以及在模拟器环境下，其他内存访问操作如何影响排他性访问的状态。  排他性访问是实现原子操作的关键机制。

2. **模拟器依赖：**  文件中明确指出这些测试依赖于模拟器的特定行为，与真实硬件上的行为可能有所不同。 这是因为模拟器对排他性访问的处理更为保守，例如，即使是对不同地址的普通加载操作，也可能清除排他性状态。

3. **`MemoryAccess` 结构体：** 定义了各种类型的内存访问操作，包括普通加载 (`Load`)、排他性加载 (`LoadExcl`)、普通存储 (`Store`) 和排他性存储 (`StoreExcl`)。  它还包含了访问的大小（字节、半字、字）、偏移量和存储的值。

4. **`TestData` 结构体：**  定义了一个简单的数据结构，用于在内存中进行操作。 使用 `union` 允许以不同的数据类型（`int32_t`、`int16_t`、`int8_t`) 访问相同的内存区域。

5. **辅助函数：**
   - `AssembleMemoryAccess`:  根据 `MemoryAccess` 结构体的描述，生成对应的 ARM64 汇编指令。
   - `AssembleLoadExcl`: 专门用于生成排他性加载指令。
   - `AssembleStoreExcl`: 专门用于生成排他性存储指令。

6. **`TestInvalidateExclusiveAccess` 函数：**  核心的测试函数之一。 它模拟了一系列内存访问操作：
   - 首先执行一个排他性加载 (`ldaxr`)。
   - 然后执行另一个内存访问操作（可以是加载、存储等）。
   - 最后尝试执行一个排他性存储 (`stlxr`)。
   - 该函数验证排他性存储是否成功（返回 0）或失败（返回非 0），并检查内存中的数据是否符合预期。这个测试重点在于验证中间的内存访问是否会使之前的排他性加载失效。

7. **`TEST(simulator_invalidate_exclusive_access)`：**  使用 CCTEST 框架定义的测试用例。它调用 `TestInvalidateExclusiveAccess` 函数，并传入不同的 `MemoryAccess` 组合，以测试各种情况下排他性访问是否会被正确地失效。测试的场景包括：
   - 地址不匹配
   - 大小不匹配
   - 在 `ldaxr` 和 `stlxr` 之间进行普通的加载或存储操作

8. **`ExecuteMemoryAccess` 函数：**  一个简单的函数，用于执行单个内存访问操作。

9. **`MemoryAccessThread` 类：**  创建了一个单独的线程，用于执行内存访问操作。 这用于测试多线程环境下排他性访问的行为，模拟并发场景。

10. **`TEST(simulator_invalidate_exclusive_access_threaded)`：**  使用 CCTEST 框架定义的另一个测试用例，用于测试多线程下的排他性访问。它创建了一个 `MemoryAccessThread`，并在主线程和子线程之间交替执行排他性加载和存储操作，验证在并发情况下排他性访问的正确性。

**它不是 Torque 代码**

由于文件以 `.cc` 结尾，而不是 `.tq`，因此它是一个 C++ 源代码文件，而不是 V8 的 Torque 源代码。

**与 JavaScript 功能的关系**

虽然这个文件本身是用 C++ 编写的，并且直接测试的是底层 ARM64 指令的模拟行为，但它与 JavaScript 的 `Atomics` 对象密切相关。 `Atomics` 对象提供了一组静态方法，用于执行原子操作，这些操作在多线程环境中保证了数据的一致性。

在底层，V8 的 JavaScript 引擎会利用类似 `ldaxr` 和 `stlxr` 这样的硬件指令（或者在模拟器中，模拟这些指令的行为）来实现 `Atomics` API 的功能。  例如，`Atomics.compareExchange()` 操作就需要原子地比较内存中的值并进行交换，这通常会使用到排他性加载和存储指令。

**JavaScript 示例**

```javascript
// 需要在支持 SharedArrayBuffer 的环境中运行

const sab = new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT);
const view = new Int32Array(sab);

// 模拟两个线程同时尝试更新数组中的值

// 线程 1
Atomics.compareExchange(view, 0, 0, 5); // 期望当前值为 0，设置为 5

// 线程 2
Atomics.compareExchange(view, 0, 0, 10); // 期望当前值为 0，设置为 10
```

在这个 JavaScript 例子中，`Atomics.compareExchange()` 尝试原子地将数组中索引为 0 的值从 0 更改为新的值。  在 V8 内部，对于 ARM64 架构，会使用类似 `ldaxr` 读取当前值，然后进行比较，如果匹配则使用 `stlxr` 写入新值。如果 `stlxr` 失败（例如，因为另一个线程已经修改了该值），则操作会失败。 `test-sync-primitives-arm64.cc` 中的测试就是为了验证这种底层的原子操作机制在模拟器中是否工作正常。

**代码逻辑推理和假设输入输出**

让我们以 `TestInvalidateExclusiveAccess` 函数的一个测试用例为例：

```c++
  // Load between ldaxr/stlxr.
  TestInvalidateExclusiveAccess(
      TestData(1), ldaxr_w,
      MemoryAccess(Kind::Load, Size::Word, offsetof(TestData, dummy)), stlxr_w,
      1, TestData(1));
```

**假设输入：**

- `initial_data`: `TestData` 结构体，`w` 字段初始化为 1。
- `access1`: `ldaxr_w`，对 `TestData` 的 `w` 字段进行排他性加载。
- `access2`: `MemoryAccess(Kind::Load, Size::Word, offsetof(TestData, dummy))`，对 `TestData` 的 `dummy` 字段进行普通加载。
- `access3`: `stlxr_w`，尝试将 `TestData` 的 `w` 字段排他性地存储为 7。

**代码逻辑推理：**

1. 首先，执行 `ldaxr_w`，尝试对 `test_data.w` 进行排他性加载。模拟器会标记该内存位置为当前线程独占。
2. 接着，执行 `access2`，对 `test_data.dummy` 进行普通的字加载。根据模拟器的保守行为，即使是对不同地址的普通加载，也可能清除之前在 `test_data.w` 上建立的排他性访问状态。
3. 最后，执行 `stlxr_w`，尝试将值 7 排他性地存储到 `test_data.w`。由于步骤 2 中的普通加载可能已经清除了排他性状态，这次排他性存储很可能会失败。

**预期输出：**

- `expected_res`: `1`，表示排他性存储操作失败（`stlxr` 指令会返回非零值表示失败）。
- `expected_data`: `TestData(1)`，表示 `test_data.w` 的值仍然是初始值 1，因为排他性存储失败了，没有更新成功。

**用户常见的编程错误**

在涉及到同步原语时，用户容易犯以下编程错误：

1. **忘记使用原子操作：**  在多线程环境下修改共享变量时，如果没有使用原子操作或适当的锁机制，可能导致数据竞争和不可预测的结果。

   ```javascript
   let counter = 0;

   // 线程 1
   for (let i = 0; i < 10000; i++) {
     counter++; // 非原子操作
   }

   // 线程 2
   for (let i = 0; i < 10000; i++) {
     counter++; // 非原子操作
   }

   // 最终 counter 的值可能不是 20000
   ```

2. **不正确地使用锁：**
   - **死锁：** 多个线程互相等待对方释放锁，导致程序停滞。
   - **活锁：** 线程不断尝试获取锁，但由于某些条件总是无法满足，导致它们一直重试，但都没有进展。
   - **过度使用锁：**  不必要地使用锁会降低程序的并发性能。

3. **ABA 问题：**  在使用比较并交换 (CAS) 操作时，如果一个值从 A 变为 B，然后再变回 A，另一个线程可能误认为该值没有发生变化，从而导致错误。

   ```javascript
   // 假设有一个内存位置的值为 A
   let value = 'A';

   // 线程 1
   // ... 做一些操作 ...
   value = 'B';
   // ... 做一些操作 ...
   value = 'A';

   // 线程 2 尝试使用 CAS
   if (value === 'A') { // 此时条件成立，但值已经经历了变化
     // ... 执行操作 ...
   }
   ```

4. **对内存模型的理解不足：**  不同的处理器架构有不同的内存模型，定义了不同线程对内存操作的可见性顺序。 开发者需要理解目标平台的内存模型，以避免出现意想不到的并发问题。

`v8/test/cctest/test-sync-primitives-arm64.cc` 这样的测试文件对于确保 V8 引擎在各种架构下正确地实现同步原语至关重要，从而为 JavaScript 开发者提供可靠的并发编程能力。

### 提示词
```
这是目录为v8/test/cctest/test-sync-primitives-arm64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-sync-primitives-arm64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
// Copyright 2017 the V8 project authors. All rights reserved.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright
//       notice, this list of conditions and the following disclaimer.
//     * Redistributions in binary form must reproduce the above
//       copyright notice, this list of conditions and the following
//       disclaimer in the documentation and/or other materials provided
//       with the distribution.
//     * Neither the name of Google Inc. nor the names of its
//       contributors may be used to endorse or promote products derived
//       from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include "src/codegen/macro-assembler-inl.h"
#include "src/execution/arm64/simulator-arm64.h"
#include "src/objects/objects-inl.h"
#include "test/cctest/cctest.h"

namespace v8 {
namespace internal {

// These tests rely on the behaviour specific to the simulator so we cannot
// expect the same results on real hardware. The reason for this is that our
// simulation of synchronisation primitives is more conservative than the
// reality.
// For example:
//   ldxr x1, [x2] ; Load acquire at address x2; x2 is now marked as exclusive.
//   ldr x0, [x4]  ; This is a normal load, and at a different address.
//                 ; However, any memory accesses can potentially clear the
//                 ; exclusivity (See ARM DDI 0487B.a B2.9.5). This is unlikely
//                 ; on real hardware but to be conservative, the simulator
//                 ; always does it.
//   stxr w3, x1, [x2] ; As a result, this will always fail in the simulator but
//                     ; will likely succeed on hardware.
#if defined(USE_SIMULATOR)

#ifndef V8_TARGET_LITTLE_ENDIAN
#error Expected ARM to be little-endian
#endif

#define __ masm.

struct MemoryAccess {
  enum class Kind {
    None,
    Load,
    LoadExcl,
    Store,
    StoreExcl,
  };

  enum class Size {
    Byte,
    HalfWord,
    Word,
  };

  MemoryAccess() : kind(Kind::None) {}
  MemoryAccess(Kind kind, Size size, size_t offset, int value = 0)
      : kind(kind), size(size), offset(offset), value(value) {}

  Kind kind = Kind::None;
  Size size = Size::Byte;
  size_t offset = 0;
  int value = 0;
};

struct TestData {
  explicit TestData(int w) : w(w) {}

  union {
    int32_t w;
    int16_t h;
    int8_t b;
  };
  int dummy;
};

namespace {

void AssembleMemoryAccess(MacroAssembler* assembler, MemoryAccess access,
                          Register dest_reg, Register value_reg,
                          Register addr_reg) {
  MacroAssembler& masm = *assembler;
  __ Add(addr_reg, x0, Operand(access.offset));

  switch (access.kind) {
    case MemoryAccess::Kind::None:
      break;

    case MemoryAccess::Kind::Load:
      switch (access.size) {
        case MemoryAccess::Size::Byte:
          __ ldrb(value_reg, MemOperand(addr_reg));
          break;

        case MemoryAccess::Size::HalfWord:
          __ ldrh(value_reg, MemOperand(addr_reg));
          break;

        case MemoryAccess::Size::Word:
          __ ldr(value_reg, MemOperand(addr_reg));
          break;
      }
      break;

    case MemoryAccess::Kind::LoadExcl:
      switch (access.size) {
        case MemoryAccess::Size::Byte:
          __ ldaxrb(value_reg, addr_reg);
          break;

        case MemoryAccess::Size::HalfWord:
          __ ldaxrh(value_reg, addr_reg);
          break;

        case MemoryAccess::Size::Word:
          __ ldaxr(value_reg, addr_reg);
          break;
      }
      break;

    case MemoryAccess::Kind::Store:
      switch (access.size) {
        case MemoryAccess::Size::Byte:
          __ Mov(value_reg, Operand(access.value));
          __ strb(value_reg, MemOperand(addr_reg));
          break;

        case MemoryAccess::Size::HalfWord:
          __ Mov(value_reg, Operand(access.value));
          __ strh(value_reg, MemOperand(addr_reg));
          break;

        case MemoryAccess::Size::Word:
          __ Mov(value_reg, Operand(access.value));
          __ str(value_reg, MemOperand(addr_reg));
          break;
      }
      break;

    case MemoryAccess::Kind::StoreExcl:
      switch (access.size) {
        case MemoryAccess::Size::Byte:
          __ Mov(value_reg, Operand(access.value));
          __ stlxrb(dest_reg, value_reg, addr_reg);
          break;

        case MemoryAccess::Size::HalfWord:
          __ Mov(value_reg, Operand(access.value));
          __ stlxrh(dest_reg, value_reg, addr_reg);
          break;

        case MemoryAccess::Size::Word:
          __ Mov(value_reg, Operand(access.value));
          __ stlxr(dest_reg, value_reg, addr_reg);
          break;
      }
      break;
  }
}

void AssembleLoadExcl(MacroAssembler* assembler, MemoryAccess access,
                      Register value_reg, Register addr_reg) {
  DCHECK(access.kind == MemoryAccess::Kind::LoadExcl);
  AssembleMemoryAccess(assembler, access, no_reg, value_reg, addr_reg);
}

void AssembleStoreExcl(MacroAssembler* assembler, MemoryAccess access,
                       Register dest_reg, Register value_reg,
                       Register addr_reg) {
  DCHECK(access.kind == MemoryAccess::Kind::StoreExcl);
  AssembleMemoryAccess(assembler, access, dest_reg, value_reg, addr_reg);
}

void TestInvalidateExclusiveAccess(TestData initial_data, MemoryAccess access1,
                                   MemoryAccess access2, MemoryAccess access3,
                                   int expected_res, TestData expected_data) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler masm(isolate, v8::internal::CodeObjectRequired::kYes);

  AssembleLoadExcl(&masm, access1, w1, x1);
  AssembleMemoryAccess(&masm, access2, w3, w2, x1);
  AssembleStoreExcl(&masm, access3, w0, w3, x1);
  __ Ret();

  CodeDesc desc;
  masm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();

  TestData t = initial_data;
  Simulator::current(isolate)->Call<void>(code->instruction_start(), &t);
  int res = Simulator::current(isolate)->wreg(0);

  CHECK_EQ(expected_res, res);
  switch (access3.size) {
    case MemoryAccess::Size::Byte:
      CHECK_EQ(expected_data.b, t.b);
      break;

    case MemoryAccess::Size::HalfWord:
      CHECK_EQ(expected_data.h, t.h);
      break;

    case MemoryAccess::Size::Word:
      CHECK_EQ(expected_data.w, t.w);
      break;
  }
}

}  // namespace

TEST(simulator_invalidate_exclusive_access) {
  using Kind = MemoryAccess::Kind;
  using Size = MemoryAccess::Size;

  MemoryAccess ldaxr_w(Kind::LoadExcl, Size::Word, offsetof(TestData, w));
  MemoryAccess stlxr_w(Kind::StoreExcl, Size::Word, offsetof(TestData, w), 7);

  // Address mismatch.
  TestInvalidateExclusiveAccess(
      TestData(1), ldaxr_w,
      MemoryAccess(Kind::LoadExcl, Size::Word, offsetof(TestData, dummy)),
      stlxr_w, 1, TestData(1));

  // Size mismatch.
  TestInvalidateExclusiveAccess(
      TestData(1), ldaxr_w, MemoryAccess(),
      MemoryAccess(Kind::StoreExcl, Size::HalfWord, offsetof(TestData, w), 7),
      1, TestData(1));

  // Load between ldaxr/stlxr.
  TestInvalidateExclusiveAccess(
      TestData(1), ldaxr_w,
      MemoryAccess(Kind::Load, Size::Word, offsetof(TestData, dummy)), stlxr_w,
      1, TestData(1));

  // Store between ldaxr/stlxr.
  TestInvalidateExclusiveAccess(
      TestData(1), ldaxr_w,
      MemoryAccess(Kind::Store, Size::Word, offsetof(TestData, dummy)), stlxr_w,
      1, TestData(1));

  // Match
  TestInvalidateExclusiveAccess(TestData(1), ldaxr_w, MemoryAccess(), stlxr_w,
                                0, TestData(7));
}

namespace {

int ExecuteMemoryAccess(Isolate* isolate, TestData* test_data,
                        MemoryAccess access) {
  HandleScope scope(isolate);
  MacroAssembler masm(isolate, v8::internal::CodeObjectRequired::kYes);
  AssembleMemoryAccess(&masm, access, w0, w2, x1);
  __ Ret();

  CodeDesc desc;
  masm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  Simulator::current(isolate)->Call<void>(code->instruction_start(), test_data);
  return Simulator::current(isolate)->wreg(0);
}

}  // namespace

class MemoryAccessThread : public v8::base::Thread {
 public:
  MemoryAccessThread()
      : Thread(Options("MemoryAccessThread")),
        test_data_(nullptr),
        is_finished_(false),
        has_request_(false),
        did_request_(false),
        isolate_(nullptr) {}

  virtual void Run() {
    v8::Isolate::CreateParams create_params;
    create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
    isolate_ = v8::Isolate::New(create_params);
    Isolate* i_isolate = reinterpret_cast<Isolate*>(isolate_);
    {
      v8::Isolate::Scope scope(isolate_);
      v8::base::MutexGuard lock_guard(&mutex_);
      while (!is_finished_) {
        while (!(has_request_ || is_finished_)) {
          has_request_cv_.Wait(&mutex_);
        }

        if (is_finished_) {
          break;
        }

        ExecuteMemoryAccess(i_isolate, test_data_, access_);
        has_request_ = false;
        did_request_ = true;
        did_request_cv_.NotifyOne();
      }
    }
    isolate_->Dispose();
  }

  void NextAndWait(TestData* test_data, MemoryAccess access) {
    DCHECK(!has_request_);
    v8::base::MutexGuard lock_guard(&mutex_);
    test_data_ = test_data;
    access_ = access;
    has_request_ = true;
    has_request_cv_.NotifyOne();
    while (!did_request_) {
      did_request_cv_.Wait(&mutex_);
    }
    did_request_ = false;
  }

  void Finish() {
    v8::base::MutexGuard lock_guard(&mutex_);
    is_finished_ = true;
    has_request_cv_.NotifyOne();
  }

 private:
  TestData* test_data_;
  MemoryAccess access_;
  bool is_finished_;
  bool has_request_;
  bool did_request_;
  v8::base::Mutex mutex_;
  v8::base::ConditionVariable has_request_cv_;
  v8::base::ConditionVariable did_request_cv_;
  v8::Isolate* isolate_;
};

TEST(simulator_invalidate_exclusive_access_threaded) {
  using Kind = MemoryAccess::Kind;
  using Size = MemoryAccess::Size;

  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  TestData test_data(1);

  MemoryAccessThread thread;
  CHECK(thread.Start());

  MemoryAccess ldaxr_w(Kind::LoadExcl, Size::Word, offsetof(TestData, w));
  MemoryAccess stlxr_w(Kind::StoreExcl, Size::Word, offsetof(TestData, w), 7);

  // Exclusive store completed by another thread first.
  test_data = TestData(1);
  thread.NextAndWait(&test_data, MemoryAccess(Kind::LoadExcl, Size::Word,
                                              offsetof(TestData, w)));
  ExecuteMemoryAccess(isolate, &test_data, ldaxr_w);
  thread.NextAndWait(&test_data, MemoryAccess(Kind::StoreExcl, Size::Word,
                                              offsetof(TestData, w), 5));
  CHECK_EQ(1, ExecuteMemoryAccess(isolate, &test_data, stlxr_w));
  CHECK_EQ(5, test_data.w);

  // Exclusive store completed by another thread; different address, but masked
  // to same
  test_data = TestData(1);
  ExecuteMemoryAccess(isolate, &test_data, ldaxr_w);
  thread.NextAndWait(&test_data, MemoryAccess(Kind::LoadExcl, Size::Word,
                                              offsetof(TestData, dummy)));
  thread.NextAndWait(&test_data, MemoryAccess(Kind::StoreExcl, Size::Word,
                                              offsetof(TestData, dummy), 5));
  CHECK_EQ(1, ExecuteMemoryAccess(isolate, &test_data, stlxr_w));
  CHECK_EQ(1, test_data.w);

  // Test failure when store between ldaxr/stlxr.
  test_data = TestData(1);
  ExecuteMemoryAccess(isolate, &test_data, ldaxr_w);
  thread.NextAndWait(&test_data, MemoryAccess(Kind::Store, Size::Word,
                                              offsetof(TestData, dummy)));
  CHECK_EQ(1, ExecuteMemoryAccess(isolate, &test_data, stlxr_w));
  CHECK_EQ(1, test_data.w);

  thread.Finish();
  thread.Join();
}

#undef __

#endif  // USE_SIMULATOR

}  // namespace internal
}  // namespace v8
```