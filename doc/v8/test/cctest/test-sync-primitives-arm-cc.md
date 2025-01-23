Response:
Let's break down the thought process for analyzing the provided C++ code.

1. **Understand the Goal:** The request asks for the functionality of the C++ file `v8/test/cctest/test-sync-primitives-arm.cc`. It also asks about Torque relevance, JavaScript connection, logical reasoning, and common errors.

2. **Initial Scan and Keywords:** Quickly read through the code, looking for keywords. "test", "sync", "primitives", "ARM", "simulator", "ldrex", "strex", "mutex", "thread". These words immediately suggest this is a testing file for synchronization primitives on the ARM architecture, specifically within the V8 simulator.

3. **Identify Core Concepts:** The code heavily uses `ldrex` (load exclusive) and `strex` (store exclusive) instructions. These are the key synchronization primitives on ARM. The comments explicitly mention their behavior in the simulator vs. real hardware. The presence of `v8::base::Thread`, `v8::base::Mutex`, and `v8::base::ConditionVariable` further reinforces the focus on synchronization and threading.

4. **Structure Analysis:**  Notice the `#if defined(USE_SIMULATOR)` block. This is crucial. It tells us the tests are *specifically designed* for the simulator's behavior, which might differ from actual hardware. The code is organized into namespaces (`v8::internal` and an anonymous namespace). There are `struct` definitions (`MemoryAccess`, `TestData`) which are data structures used in the tests. Several `TEST()` macros indicate this is using a testing framework (likely Google Test, which V8 uses).

5. **Functionality Breakdown:**

   * **`MemoryAccess` struct:**  Represents a memory access operation (load, store, exclusive load/store) with size and offset. This is a helper to make the test code more readable and configurable.
   * **`TestData` struct:**  A simple union used to hold data of different sizes (byte, half-word, word) for testing.
   * **`AssembleMemoryAccess` function:**  The core function for generating ARM assembly code for different memory access types. It takes a `MemoryAccess` struct and emits the corresponding assembly instructions.
   * **`AssembleLoadExcl` and `AssembleStoreExcl`:** Convenience wrappers for `AssembleMemoryAccess` specifically for exclusive operations.
   * **`TestInvalidateExclusiveAccess`:**  A crucial test function that simulates a sequence of memory accesses (load-exclusive, an intervening access, store-exclusive) and verifies the outcome based on the simulator's behavior regarding invalidating exclusive access.
   * **`ExecuteMemoryAccess`:** A helper to execute a single memory access in a controlled environment.
   * **`MemoryAccessThread`:**  A class that creates a separate thread to perform memory accesses. This is used to test scenarios involving multiple threads competing for access to shared memory.
   * **`simulator_invalidate_exclusive_access` TEST:** Contains various test cases for the single-threaded `TestInvalidateExclusiveAccess` function.
   * **`simulator_invalidate_exclusive_access_threaded` TEST:**  Tests scenarios involving multiple threads using exclusive memory access.

6. **Answering Specific Questions:**

   * **Functionality:** Summarize the purpose of each key component as described above.
   * **Torque:**  The file extension is `.cc`, not `.tq`. Therefore, it's C++, not Torque.
   * **JavaScript Relation:** Explain the connection through the concept of synchronization primitives. JavaScript engines (like V8) need these primitives for implementing higher-level concurrency constructs. Provide a simple JavaScript example demonstrating the need for synchronization (race condition).
   * **Logical Reasoning (Assumptions and I/O):** Focus on the `TestInvalidateExclusiveAccess` function. Provide examples of input `TestData` and `MemoryAccess` combinations, and explain the expected output (return value and modified `TestData`) based on the simulator's rules. Emphasize the "conservative" nature of the simulator.
   * **Common Programming Errors:** Think about the pitfalls of using low-level synchronization primitives: race conditions, deadlocks, not releasing locks, incorrect usage of exclusive access. Provide concrete C++ examples illustrating these issues (even though the code is testing, understanding potential errors is key).

7. **Refinement and Clarity:** Organize the information logically. Use clear and concise language. Explain technical terms like "load exclusive" and "store exclusive."  Emphasize the difference between simulator and real hardware behavior.

8. **Self-Correction/Review:**  Read through the generated response. Does it accurately describe the code's functionality?  Are the JavaScript examples relevant? Are the assumptions and outputs of the logical reasoning clear?  Are the common errors well-explained?  (For instance, initially, I might have forgotten to emphasize the *simulator-specific* nature, but reviewing the code would remind me of the `#if defined(USE_SIMULATOR)` block).

By following this thought process, breaking down the code into smaller, understandable parts, and focusing on the key concepts and questions, one can effectively analyze and explain the functionality of the given C++ source code.
好的，让我们来分析一下 `v8/test/cctest/test-sync-primitives-arm.cc` 这个文件的功能。

**功能概述**

这个 C++ 文件是 V8 JavaScript 引擎的测试代码，专门用于测试 ARM 架构下同步原语（synchronization primitives）的实现。由于文件名中包含了 `-arm`，可以推断出这些测试是针对 ARM 处理器的特定指令和行为。  更具体地说，它重点测试了 `ldrex` (load exclusive) 和 `strex` (store exclusive) 指令，这是 ARM 架构中实现原子操作的关键指令。

**详细功能分解**

1. **测试目标：ARM 架构的同步原语**
   - 文件名明确指出针对 ARM 架构。
   - 代码中大量使用了 `ldrex` 和 `strex` 指令，以及与独占访问相关的概念。

2. **模拟器环境下的测试 (`#if defined(USE_SIMULATOR)`)**
   - 重要的注释说明这些测试依赖于模拟器的特定行为，在真实硬件上可能得到不同的结果。
   - 注释解释了 V8 的模拟器对同步原语的处理比真实硬件更保守，并给出了一个 `ldrex` 和 `strex` 指令交互的例子，说明了模拟器可能产生与硬件不同的行为。

3. **`MemoryAccess` 结构体**
   - 定义了一个 `MemoryAccess` 结构体，用于描述不同类型的内存访问操作，包括：
     - `Kind`: `None`, `Load`, `LoadExcl`, `Store`, `StoreExcl` (无操作，普通加载，独占加载，普通存储，独占存储)
     - `Size`: `Byte`, `HalfWord`, `Word` (字节，半字，字)
     - `offset`: 内存偏移量
     - `value`: 要存储的值
   - 这个结构体是为了方便地描述和组织不同的内存操作序列。

4. **`TestData` 结构体**
   - 定义了一个 `TestData` 结构体，使用 `union` 来允许用不同的类型（`int32_t`, `int16_t`, `int8_t`) 来访问同一块内存，方便测试不同大小的数据操作。

5. **`AssembleMemoryAccess` 函数**
   - 这是一个核心函数，负责根据 `MemoryAccess` 结构体的描述，生成相应的 ARM 汇编代码。
   - 它根据 `access.kind` 和 `access.size` 选择合适的 ARM 指令 (例如 `ldrb`, `ldrh`, `ldr`, `ldrex`, `strb`, `strh`, `str`, `strexb`, `strexh`, `strex`)。

6. **`AssembleLoadExcl` 和 `AssembleStoreExcl` 函数**
   - 这两个是辅助函数，分别用于生成独占加载和独占存储的汇编代码，简化了 `AssembleMemoryAccess` 的调用。

7. **`TestInvalidateExclusiveAccess` 函数**
   - 这个函数用于测试在独占加载 (`ldrex`) 和独占存储 (`strex`) 之间执行其他内存访问操作时，是否会使独占访问失效。
   - 它接收初始数据、三个内存访问描述 (`access1` 通常是 `ldrex`，`access2` 是中间的访问，`access3` 是 `strex`) 以及期望的结果和数据。
   - 它生成一段汇编代码来执行这些内存访问，然后检查 `strex` 的执行结果（成功或失败）以及最终的内存数据。

8. **`simulator_invalidate_exclusive_access` 测试用例**
   - 这个 `TEST` 宏定义了一组测试用例，用于验证 `TestInvalidateExclusiveAccess` 函数的逻辑。
   - 测试了地址不匹配、大小不匹配、在 `ldrex`/`strex` 之间进行普通加载和存储等情况，以验证模拟器是否正确地使独占访问失效。

9. **`ExecuteMemoryAccess` 函数**
   - 一个辅助函数，用于执行单个内存访问操作。

10. **`MemoryAccessThread` 类**
    - 定义了一个多线程类 `MemoryAccessThread`，用于在单独的线程中执行内存访问操作。
    - 使用互斥锁 (`mutex_`) 和条件变量 (`has_request_cv_`, `did_request_cv_`) 来同步主线程和子线程之间的操作。

11. **`simulator_invalidate_exclusive_access_threaded` 测试用例**
    - 这个 `TEST` 宏定义了一组多线程测试用例，用于验证在多线程环境下独占访问的行为。
    - 测试了以下场景：
        - 另一个线程先完成了独占存储。
        - 另一个线程在不同地址但可能被掩码到相同地址的位置进行了独占存储。
        - 在 `ldrex`/`strex` 之间进行普通存储操作。

**关于文件扩展名 `.cc` 和 Torque**

你提到如果文件以 `.tq` 结尾，那就是 Torque 源代码。  `v8/test/cctest/test-sync-primitives-arm.cc` 的确是以 `.cc` 结尾，所以它是 C++ 源代码，而不是 Torque 源代码。 Torque 文件通常用于定义 V8 的内置函数和类型。

**与 JavaScript 的关系**

这个测试文件直接测试了 V8 引擎底层实现的关键部分：同步原语。虽然这段代码本身不是 JavaScript，但它验证了 V8 内部用于支持 JavaScript 并发和原子操作的基础机制。

JavaScript 中并没有直接对应 `ldrex` 和 `strex` 的操作。 然而，JavaScript 提供了一些用于处理并发的 API，例如：

* **`Atomics` 对象**:  `Atomics` 对象提供了一组静态方法来执行原子操作，例如原子加法、原子比较交换等。 V8 引擎内部很可能使用了类似 `ldrex`/`strex` 这样的底层同步原语来实现 `Atomics` 的功能。

**JavaScript 示例**

```javascript
const sab = new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT * 1);
const view = new Int32Array(sab);

// 模拟多个线程（在浏览器或 Node.js 中使用 Worker）并发修改共享内存

// 线程 1:
if (Atomics.compareExchange(view, 0, 0, 10)) {
  console.log("线程 1 成功将值从 0 更新为 10");
} else {
  console.log("线程 1 更新失败");
}

// 线程 2:
if (Atomics.compareExchange(view, 0, 0, 20)) {
  console.log("线程 2 成功将值从 0 更新为 20");
} else {
  console.log("线程 2 更新失败");
}

console.log("最终值:", view[0]);
```

在这个例子中，`Atomics.compareExchange` 方法尝试原子地比较 `view[0]` 的值是否为 0，如果是，则将其更新为新的值。 这背后就需要类似 `ldrex`/`strex` 这样的机制来保证操作的原子性，防止出现竞态条件。  `v8/test/cctest/test-sync-primitives-arm.cc` 就是在测试 V8 引擎中实现这些底层原子操作的正确性。

**代码逻辑推理：假设输入与输出**

以 `TestInvalidateExclusiveAccess` 函数为例，假设我们有以下输入：

* `initial_data`: `TestData` 实例，例如 `{ w: 1 }`
* `access1`:  `MemoryAccess(Kind::LoadExcl, Size::Word, offsetof(TestData, w))`  (独占加载 `TestData.w`)
* `access2`:  `MemoryAccess(Kind::Load, Size::Word, offsetof(TestData, dummy))` (普通加载 `TestData.dummy`)
* `access3`:  `MemoryAccess(Kind::StoreExcl, Size::Word, offsetof(TestData, w), 7)` (尝试独占存储 7 到 `TestData.w`)
* `expected_res`: 期望的 `strex` 指令的返回值（0 表示成功，非 0 表示失败）
* `expected_data`: 期望的最终 `TestData`

**推理:**

1. 执行 `access1` (`ldrex`)：线程尝试独占访问 `TestData.w`。
2. 执行 `access2` (`ldr`)：线程执行一个普通的加载操作，访问 `TestData.dummy`。根据 ARM 的规范和 V8 模拟器的保守实现，即使是对不同地址的普通内存访问，也可能清除之前建立的独占访问权限。
3. 执行 `access3` (`strex`)：由于步骤 2 中执行了普通加载，很可能之前的独占访问权限已经被清除。因此，`strex` 指令会失败。

**假设输入与输出:**

* **假设输入:**
  ```c++
  TestData initial_data(1);
  MemoryAccess ldrex_w(MemoryAccess::Kind::LoadExcl, MemoryAccess::Size::Word, offsetof(TestData, w));
  MemoryAccess load_dummy(MemoryAccess::Kind::Load, MemoryAccess::Size::Word, offsetof(TestData, dummy));
  MemoryAccess strex_w_7(MemoryAccess::Kind::StoreExcl, MemoryAccess::Size::Word, offsetof(TestData, w), 7);
  int expected_res = 1; // 期望 strex 失败
  TestData expected_data(1); // 期望数据不变
  ```
* **预期输出:** `TestInvalidateExclusiveAccess` 函数会调用汇编代码，模拟执行这些操作。由于在 `ldrex` 和 `strex` 之间有对 `dummy` 的普通加载，模拟器会认为独占访问失效。因此，`strex` 指令会返回一个非零值（表示失败），并且 `TestData.w` 的值不会被更新。

**用户常见的编程错误**

涉及到同步原语时，常见的编程错误包括：

1. **忘记检查 `strex` 的返回值:** `strex` 指令会返回一个值来指示存储是否成功（0 表示成功，非 0 表示失败）。如果程序员忘记检查这个返回值，就无法知道独占操作是否真的成功，可能导致数据不一致。

   ```c++
   // 错误示例：没有检查 strex 的返回值
   Assembler assm;
   Register value_reg = r0;
   Register addr_reg = r1;
   Register result_reg = r2;
   int new_value = 10;

   __ mov(value_reg, Operand(new_value));
   __ ldrex(result_reg, addr_reg);
   // ... 可能有其他操作 ...
   __ strex(result_reg, value_reg, addr_reg);
   // 假设这里直接使用了数据，但 strex 可能失败了
   ```

2. **在 `ldrex` 和 `strex` 之间执行不必要的操作:**  如代码所示，即使是不相关的内存访问也可能导致独占访问失效。程序员需要在 `ldrex` 和 `strex` 之间保持操作的原子性，避免插入可能干扰独占访问的操作。

   ```c++
   // 错误示例：在 ldrex 和 strex 之间执行了可能导致独占访问失效的操作
   Assembler assm;
   Register value_reg = r0;
   Register addr_reg = r1;
   Register temp_reg = r2;
   int other_value = 5;
   int new_value = 10;

   __ ldrex(temp_reg, addr_reg);
   __ mov(value_reg, Operand(other_value));
   __ ldr(temp_reg, MemOperand(r3)); // 对另一个地址的加载，可能使独占访问失效
   __ mov(value_reg, Operand(new_value));
   __ strex(temp_reg, value_reg, addr_reg);
   // 如果对 r3 的加载导致独占访问失效，strex 将失败
   ```

3. **死锁和活锁:** 虽然这个测试文件没有直接涉及到锁，但在更复杂的同步场景中，不正确地使用互斥锁、条件变量等同步原语可能导致死锁或活锁。

   ```c++
   // 假设在多线程环境中使用互斥锁
   std::mutex mutex_a;
   std::mutex mutex_b;

   // 线程 1:
   void thread1_func() {
     std::lock_guard<std::mutex> lock_a(mutex_a);
     // ... 执行一些操作 ...
     std::lock_guard<std::mutex> lock_b(mutex_b); // 可能导致死锁
     // ...
   }

   // 线程 2:
   void thread2_func() {
     std::lock_guard<std::mutex> lock_b(mutex_b);
     // ... 执行一些操作 ...
     std::lock_guard<std::mutex> lock_a(mutex_a); // 可能导致死锁
     // ...
   }
   ```

总而言之，`v8/test/cctest/test-sync-primitives-arm.cc` 是 V8 引擎中一个重要的测试文件，它专注于验证 ARM 架构下底层同步原语（特别是 `ldrex` 和 `strex` 指令）在模拟器环境中的正确行为。这对于确保 JavaScript 并发特性的可靠实现至关重要。

### 提示词
```
这是目录为v8/test/cctest/test-sync-primitives-arm.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-sync-primitives-arm.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
// Copyright 2016 the V8 project authors. All rights reserved.
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

#include "src/codegen/assembler-inl.h"
#include "src/codegen/macro-assembler.h"
#include "src/execution/simulator.h"
#include "test/cctest/assembler-helper-arm.h"
#include "test/cctest/cctest.h"

namespace v8 {
namespace internal {

// These tests rely on the behaviour specific to the simulator so we cannot
// expect the same results on real hardware. The reason for this is that our
// simulation of synchronisation primitives is more conservative than the
// reality.
// For example:
//   ldrex r1, [r2] ; Load acquire at address r2; r2 is now marked as exclusive.
//   ldr r0, [r4]   ; This is a normal load, and at a different address.
//                  ; However, any memory accesses can potentially clear the
//                  ; exclusivity (See ARM DDI 0406C.c A3.4.5). This is unlikely
//                  ; on real hardware but to be conservative, the simulator
//                  ; always does it.
//   strex r3, r1, [r2] ; As a result, this will always fail in the simulator
//                      ; but will likely succeed on hardware.
#if defined(USE_SIMULATOR)

#ifndef V8_TARGET_LITTLE_ENDIAN
#error Expected ARM to be little-endian
#endif

#define __ assm.

namespace {

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

void AssembleMemoryAccess(Assembler* assembler, MemoryAccess access,
                          Register dest_reg, Register value_reg,
                          Register addr_reg) {
  Assembler& assm = *assembler;
  __ add(addr_reg, r0, Operand(access.offset));

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
          __ ldrexb(value_reg, addr_reg);
          break;

        case MemoryAccess::Size::HalfWord:
          __ ldrexh(value_reg, addr_reg);
          break;

        case MemoryAccess::Size::Word:
          __ ldrex(value_reg, addr_reg);
          break;
      }
      break;

    case MemoryAccess::Kind::Store:
      switch (access.size) {
        case MemoryAccess::Size::Byte:
          __ mov(value_reg, Operand(access.value));
          __ strb(value_reg, MemOperand(addr_reg));
          break;

        case MemoryAccess::Size::HalfWord:
          __ mov(value_reg, Operand(access.value));
          __ strh(value_reg, MemOperand(addr_reg));
          break;

        case MemoryAccess::Size::Word:
          __ mov(value_reg, Operand(access.value));
          __ str(value_reg, MemOperand(addr_reg));
          break;
      }
      break;

    case MemoryAccess::Kind::StoreExcl:
      switch (access.size) {
        case MemoryAccess::Size::Byte:
          __ mov(value_reg, Operand(access.value));
          __ strexb(dest_reg, value_reg, addr_reg);
          break;

        case MemoryAccess::Size::HalfWord:
          __ mov(value_reg, Operand(access.value));
          __ strexh(dest_reg, value_reg, addr_reg);
          break;

        case MemoryAccess::Size::Word:
          __ mov(value_reg, Operand(access.value));
          __ strex(dest_reg, value_reg, addr_reg);
          break;
      }
      break;
  }
}

void AssembleLoadExcl(Assembler* assembler, MemoryAccess access,
                      Register value_reg, Register addr_reg) {
  DCHECK(access.kind == MemoryAccess::Kind::LoadExcl);
  AssembleMemoryAccess(assembler, access, no_reg, value_reg, addr_reg);
}

void AssembleStoreExcl(Assembler* assembler, MemoryAccess access,
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

  auto f = AssembleCode<int(TestData*, int, int, int)>(
      isolate, [&](Assembler& assm) {
        AssembleLoadExcl(&assm, access1, r1, r1);
        AssembleMemoryAccess(&assm, access2, r3, r2, r1);
        AssembleStoreExcl(&assm, access3, r0, r3, r1);
      });

  TestData t = initial_data;

  int res = f.Call(&t, 0, 0, 0);
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

  MemoryAccess ldrex_w(Kind::LoadExcl, Size::Word, offsetof(TestData, w));
  MemoryAccess strex_w(Kind::StoreExcl, Size::Word, offsetof(TestData, w), 7);

  // Address mismatch.
  TestInvalidateExclusiveAccess(
      TestData(1), ldrex_w,
      MemoryAccess(Kind::LoadExcl, Size::Word, offsetof(TestData, dummy)),
      strex_w, 1, TestData(1));

  // Size mismatch.
  TestInvalidateExclusiveAccess(
      TestData(1), ldrex_w, MemoryAccess(),
      MemoryAccess(Kind::StoreExcl, Size::HalfWord, offsetof(TestData, w), 7),
      1, TestData(1));

  // Load between ldrex/strex.
  TestInvalidateExclusiveAccess(
      TestData(1), ldrex_w,
      MemoryAccess(Kind::Load, Size::Word, offsetof(TestData, dummy)), strex_w,
      1, TestData(1));

  // Store between ldrex/strex.
  TestInvalidateExclusiveAccess(
      TestData(1), ldrex_w,
      MemoryAccess(Kind::Store, Size::Word, offsetof(TestData, dummy)), strex_w,
      1, TestData(1));

  // Match
  TestInvalidateExclusiveAccess(TestData(1), ldrex_w, MemoryAccess(), strex_w,
                                0, TestData(7));
}

namespace {

int ExecuteMemoryAccess(Isolate* isolate, TestData* test_data,
                        MemoryAccess access) {
  HandleScope scope(isolate);
  auto f =
      AssembleCode<int(TestData*, int, int)>(isolate, [&](Assembler& assm) {
        AssembleMemoryAccess(&assm, access, r0, r2, r1);
      });

  return f.Call(test_data, 0, 0);
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

  MemoryAccess ldrex_w(Kind::LoadExcl, Size::Word, offsetof(TestData, w));
  MemoryAccess strex_w(Kind::StoreExcl, Size::Word, offsetof(TestData, w), 7);

  // Exclusive store completed by another thread first.
  test_data = TestData(1);
  thread.NextAndWait(&test_data, MemoryAccess(Kind::LoadExcl, Size::Word,
                                              offsetof(TestData, w)));
  ExecuteMemoryAccess(isolate, &test_data, ldrex_w);
  thread.NextAndWait(&test_data, MemoryAccess(Kind::StoreExcl, Size::Word,
                                              offsetof(TestData, w), 5));
  CHECK_EQ(1, ExecuteMemoryAccess(isolate, &test_data, strex_w));
  CHECK_EQ(5, test_data.w);

  // Exclusive store completed by another thread; different address, but masked
  // to same
  test_data = TestData(1);
  ExecuteMemoryAccess(isolate, &test_data, ldrex_w);
  thread.NextAndWait(&test_data, MemoryAccess(Kind::LoadExcl, Size::Word,
                                              offsetof(TestData, dummy)));
  thread.NextAndWait(&test_data, MemoryAccess(Kind::StoreExcl, Size::Word,
                                              offsetof(TestData, dummy), 5));
  CHECK_EQ(1, ExecuteMemoryAccess(isolate, &test_data, strex_w));
  CHECK_EQ(1, test_data.w);

  // Test failure when store between ldrex/strex.
  test_data = TestData(1);
  ExecuteMemoryAccess(isolate, &test_data, ldrex_w);
  thread.NextAndWait(&test_data, MemoryAccess(Kind::Store, Size::Word,
                                              offsetof(TestData, dummy)));
  CHECK_EQ(1, ExecuteMemoryAccess(isolate, &test_data, strex_w));
  CHECK_EQ(1, test_data.w);

  thread.Finish();
  thread.Join();
}

#undef __

#endif  // defined(USE_SIMULATOR)

}  // namespace internal
}  // namespace v8
```