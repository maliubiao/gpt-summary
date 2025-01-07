Response:
Let's break down the thought process for analyzing the provided C++ code.

1. **Understand the Goal:** The request asks for the functionality of the `jump-table-assembler.cc` file in V8, along with explanations, examples, and potential programming errors.

2. **Initial Skim for High-Level Understanding:**  Read through the code quickly, paying attention to class names (`JumpTableAssembler`), method names (`GenerateLazyCompileTable`, `InitializeJumpsToLazyCompileTable`, `EmitJumpSlot`, etc.), and any obvious data structures or constants (like `kLazyCompileTableSlotSize`, `kJumpTableSlotSize`). This gives a general sense of what the code is about. The names strongly suggest it's involved in creating and managing jump tables, likely for WebAssembly.

3. **Identify Key Classes and Methods:**  The `JumpTableAssembler` class is central. Focus on its public methods, as these define its primary interface and purpose. The static methods also provide important functionality.

4. **Analyze Individual Methods:**  Go through each significant method, understanding its parameters, what it does internally, and its purpose in the larger context.

    * **`GenerateLazyCompileTable`:** This clearly deals with creating a table for "lazy compilation". The parameters (`base`, `num_slots`, `num_imported_functions`, `wasm_compile_lazy_target`) provide clues about the table's structure and purpose. The loop emitting `EmitLazyCompileJumpSlot` is crucial.

    * **`InitializeJumpsToLazyCompileTable`:**  This method sets up the initial jump table entries to point to the lazy compile table. The loop and the call to `EmitJumpSlot` are key. The comment about "near jumps" is important for understanding limitations.

    * **`EmitLazyCompileJumpSlot`:**  This method generates the specific instructions for a single entry in the lazy compile table. The code varies by architecture. The key idea is to push the function index and jump to the lazy compile target.

    * **`EmitJumpSlot`:** This generates a jump instruction to a given target. Again, the implementation varies by architecture. The comment about "updated live" and "atomic" is significant.

    * **`EmitFarJumpSlot`:** Handles jumps that might be outside the range of a near jump. This involves indirect jumps through memory locations.

    * **`PatchFarJumpSlot`:**  Allows updating the target address of a far jump slot. The "atomic" update is again mentioned.

    * **`SkipUntil`:**  A utility for positioning within the jump table. The restriction on some architectures is important.

    * **`emit<T>`:**  Helper functions for writing data to the allocated memory. The `RelaxedStoreTag` and the accompanying comment about atomicity are important details, especially for concurrency.

5. **Determine the Core Functionality:** Based on the method analysis, the core functionality is:
    * Creating and managing jump tables for WebAssembly.
    * Implementing "lazy compilation" by initially jumping to a generic compilation routine.
    * Providing mechanisms for both near and far jumps.
    * Offering a way to patch jump targets dynamically.

6. **Identify Architecture-Specific Code:**  Notice the heavy use of `#if V8_TARGET_ARCH_*`. This indicates the code is highly dependent on the target architecture. Examine the different implementations of `EmitLazyCompileJumpSlot`, `EmitJumpSlot`, and `EmitFarJumpSlot` for each architecture to understand how jumps are implemented on those platforms. While a detailed analysis of each assembly instruction isn't necessary for a high-level understanding, recognizing the different approaches is important.

7. **Connect to JavaScript Functionality:** Consider how this low-level code relates to the execution of JavaScript, specifically WebAssembly. The jump tables are used to dispatch calls to WebAssembly functions. Lazy compilation is a performance optimization where functions are only compiled when they're first called. This leads to the example of a WebAssembly module with an uncalled function.

8. **Infer Code Logic and Provide Examples:** Think about how the methods are used together. `GenerateLazyCompileTable` likely runs once to set up the initial lazy compilation entries. `InitializeJumpsToLazyCompileTable` sets up the primary jump table pointing to the lazy compile entries. When a WebAssembly function is called for the first time, the jump table directs execution to the lazy compilation stub.

9. **Consider Potential Programming Errors:**  Think about how a user interacting with WebAssembly (or the V8 internals) might cause issues related to jump tables. Incorrect function indices, memory corruption (though less likely at the user level), and performance problems due to excessive lazy compilation are possibilities. Focus on errors that are conceptually related to jump tables.

10. **Structure the Answer:** Organize the findings into logical sections: functionality, absence of Torque, relationship to JavaScript, code logic examples, and common programming errors. Use clear and concise language.

11. **Refine and Review:**  Read through the generated answer to ensure accuracy, clarity, and completeness. Check for any inconsistencies or areas that could be explained better. For instance, initially, I might have only mentioned "jump tables," but refining it to explain the *purpose* of these jump tables for WebAssembly dispatch and lazy compilation makes the answer more informative. Also, emphasize the dynamic nature of jump table patching.

By following these steps, combining code analysis with domain knowledge of WebAssembly and V8, one can effectively understand and explain the functionality of the `jump-table-assembler.cc` file.
```cpp
// Copyright 2018 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/wasm/jump-table-assembler.h"

#include "src/base/sanitizer/ubsan.h"
#include "src/codegen/macro-assembler-inl.h"

namespace v8 {
namespace internal {
namespace wasm {

// static
void JumpTableAssembler::GenerateLazyCompileTable(
    Address base, uint32_t num_slots, uint32_t num_imported_functions,
    Address wasm_compile_lazy_target) {
  uint32_t lazy_compile_table_size = num_slots * kLazyCompileTableSlotSize;
  WritableJitAllocation jit_allocation = ThreadIsolation::LookupJitAllocation(
      base, RoundUp<kCodeAlignment>(lazy_compile_table_size),
      ThreadIsolation::JitAllocationType::kWasmLazyCompileTable);
  // Assume enough space, so the Assembler does not try to grow the buffer.
  JumpTableAssembler jtasm(jit_allocation, base);
  for (uint32_t slot_index = 0; slot_index < num_slots; ++slot_index) {
    DCHECK_EQ(slot_index * kLazyCompileTableSlotSize, jtasm.pc_offset());
    jtasm.EmitLazyCompileJumpSlot(slot_index + num_imported_functions,
                                  wasm_compile_lazy_target);
  }
  DCHECK_EQ(lazy_compile_table_size, jtasm.pc_offset());
  FlushInstructionCache(base, lazy_compile_table_size);
}

void JumpTableAssembler::InitializeJumpsToLazyCompileTable(
    Address base, uint32_t num_slots, Address lazy_compile_table_start) {
  uint32_t jump_table_size = SizeForNumberOfSlots(num_slots);
  WritableJitAllocation jit_allocation = ThreadIsolation::LookupJitAllocation(
      base, RoundUp<kCodeAlignment>(jump_table_size),
      ThreadIsolation::JitAllocationType::kWasmJumpTable);
  JumpTableAssembler jtasm(jit_allocation, base);

  for (uint32_t slot_index = 0; slot_index < num_slots; ++slot_index) {
    // Make sure we write at the correct offset.
    int slot_offset =
        static_cast<int>(JumpTableAssembler::JumpSlotIndexToOffset(slot_index));

    jtasm.SkipUntil(slot_offset);

    Address target =
        lazy_compile_table_start +
        JumpTableAssembler::LazyCompileSlotIndexToOffset(slot_index);

#ifdef DEBUG
    int offset_before_emit = jtasm.pc_offset();
#endif
    // This function initializes the first jump table with jumps to the lazy
    // compile table. Both get allocated in the constructor of the
    // {NativeModule}, so they both should end up in the initial code space.
    // Jumps within one code space can always be near jumps, so the following
    // call to {EmitJumpSlot} should always succeed. If the call fails, then
    // either the jump table allocation was changed incorrectly so that the lazy
    // compile table was not within near-jump distance of the jump table
    // anymore (e.g. the initial code space was too small to fit both tables),
    // or the code space was allocated larger than the maximum near-jump
    // distance.
    CHECK(jtasm.EmitJumpSlot(target));

    DCHECK_EQ(kJumpTableSlotSize, jtasm.pc_offset() - offset_before_emit);
  }
  FlushInstructionCache(base, jump_table_size);
}

template <typename T>
void JumpTableAssembler::emit(T value) {
  jit_allocation_.WriteUnalignedValue(pc_, value);
  pc_ += sizeof(T);
}

template <typename T>
void JumpTableAssembler::emit(T value, RelaxedStoreTag) DISABLE_UBSAN {
  // We disable ubsan for these stores since they don't follow the alignment
  // requirements. We instead guarantee in the jump table layout that the writes
  // will still be atomic since they don't cross a qword boundary.
#if V8_TARGET_ARCH_X64
#ifdef DEBUG
  Address write_start = pc_;
  Address write_end = write_start + sizeof(T) - 1;
  // Check that the write doesn't cross a qword boundary.
  DCHECK_EQ(write_start >> kSystemPointerSizeLog2,
            write_end >> kSystemPointerSizeLog2);
#endif
#endif
  jit_allocation_.WriteValue(pc_, value, kRelaxedStore);
  pc_ += sizeof(T);
}

// The implementation is compact enough to implement it inline here. If it gets
// much bigger, we might want to split it in a separate file per architecture.
#if V8_TARGET_ARCH_X64
void JumpTableAssembler::EmitLazyCompileJumpSlot(uint32_t func_index,
                                                 Address lazy_compile_target) {
  // Use a push, because mov to an extended register takes 6 bytes.
  const uint8_t inst[kLazyCompileTableSlotSize] = {
      0x68, 0, 0, 0, 0,  // pushq func_index
      0xe9, 0, 0, 0, 0,  // near_jmp displacement
  };

  intptr_t displacement =
      lazy_compile_target - (pc_ + kLazyCompileTableSlotSize);

  emit<uint8_t>(inst[0]);
  emit<uint32_t>(func_index);
  emit<uint8_t>(inst[5]);
  emit<int32_t>(base::checked_cast<int32_t>(displacement));
}

bool JumpTableAssembler::EmitJumpSlot(Address target) {
#ifdef V8_ENABLE_CET_IBT
  uint32_t endbr_insn = 0xfa1e0ff3;
  uint32_t nop = 0x00401f0f;
  emit<uint32_t>(endbr_insn, kRelaxedStore);
  // Add a nop to ensure that the next block is 8 byte aligned.
  emit<uint32_t>(nop, kRelaxedStore);
#endif

  intptr_t displacement =
      target - (pc_ + MacroAssembler::kIntraSegmentJmpInstrSize);
  if (!is_int32(displacement)) return false;

  uint8_t inst[kJumpTableSlotSize] = {
      0xe9, 0,    0,    0, 0,  // near_jmp displacement
      0xcc, 0xcc, 0xcc,        // int3 * 3
  };
  int32_t displacement32 = base::checked_cast<int32_t>(displacement);
  memcpy(&inst[1], &displacement32, sizeof(int32_t));

  // The jump table is updated live, so the write has to be atomic.
  emit<uint64_t>(*reinterpret_cast<uint64_t*>(inst), kRelaxedStore);

  return true;
}

void JumpTableAssembler::EmitFarJumpSlot(Address target) {
  const uint8_t inst[kFarJumpTableSlotSize] = {
      0xff, 0x25, 0x02, 0, 0, 0,        // jmp [rip+0x2]
      0x66, 0x90,                       // Nop(2)
      0,    0,    0,    0, 0, 0, 0, 0,  // target
  };

  emit<uint64_t>(*reinterpret_cast<const uint64_t*>(inst));
  emit<uint64_t>(target);
}

// static
void JumpTableAssembler::PatchFarJumpSlot(WritableJitAllocation& jit_allocation,
                                          Address slot, Address target) {
  // The slot needs to be pointer-size aligned so we can atomically update it.
  DCHECK(IsAligned(slot, kSystemPointerSize));
  // Offset of the target is at 8 bytes, see {EmitFarJumpSlot}.
  jit_allocation.WriteValue(slot + kSystemPointerSize, target, kRelaxedStore);
  // The update is atomic because the address is properly aligned.
  // Because of cache coherence, the data update will eventually be seen by all
  // cores. It's ok if they temporarily jump to the old target.
}

void JumpTableAssembler::SkipUntil(int offset) {
  DCHECK_GE(offset, pc_offset());
  pc_ += offset - pc_offset();
}

#elif V8_TARGET_ARCH_IA32
void JumpTableAssembler::EmitLazyCompileJumpSlot(uint32_t func_index,
                                                 Address lazy_compile_target) {
  static_assert(kWasmCompileLazyFuncIndexRegister == edi);
  const uint8_t inst[kLazyCompileTableSlotSize] = {
      0xbf, 0, 0, 0, 0,  // mov edi, func_index
      0xe9, 0, 0, 0, 0,  // near_jmp displacement
  };
  intptr_t displacement =
      lazy_compile_target - (pc_ + kLazyCompileTableSlotSize);

  emit<uint8_t>(inst[0]);
  emit<uint32_t>(func_index);
  emit<uint8_t>(inst[5]);
  emit<int32_t>(base::checked_cast<int32_t>(displacement));
}

bool JumpTableAssembler::EmitJumpSlot(Address target) {
  intptr_t displacement = target - (pc_ + kJumpTableSlotSize);

  const uint8_t inst[kJumpTableSlotSize] = {
      0xe9, 0, 0, 0, 0,  // near_jmp displacement
  };

  // The jump table is updated live, so the writes have to be atomic.
  emit<uint8_t>(inst[0], kRelaxedStore);
  emit<int32_t>(base::checked_cast<int32_t>(displacement), kRelaxedStore);

  return true;
}

void JumpTableAssembler::EmitFarJumpSlot(Address target) {
  static_assert(kJumpTableSlotSize == kFarJumpTableSlotSize);
  EmitJumpSlot(target);
}

// static
void JumpTableAssembler::PatchFarJumpSlot(WritableJitAllocation& jit_allocation,
                                          Address slot, Address target) {
  UNREACHABLE();
}

void JumpTableAssembler::SkipUntil(int offset) {
  DCHECK_GE(offset, pc_offset());
  pc_ += offset - pc_offset();
}

// ... (rest of the architecture-specific implementations) ...

}  // namespace wasm
}  // namespace internal
}  // namespace v8
```

### 功能列举

`v8/src/wasm/jump-table-assembler.cc` 的主要功能是：

1. **动态生成和管理 WebAssembly 代码的跳转表 (Jump Table)。** 跳转表是代码中用于间接跳转的一种数据结构，可以根据索引快速跳转到不同的目标地址。

2. **支持懒编译 (Lazy Compilation)。**  它能够生成和初始化用于 WebAssembly 函数懒编译的跳转表。 懒编译是一种优化技术，即在函数第一次被调用时才进行编译，而不是在模块加载时就编译所有函数。

3. **提供近跳转 (Near Jump) 和远跳转 (Far Jump) 的机制。**
   - **近跳转:**  目标地址在当前代码段的相对偏移范围内，可以使用较短的跳转指令。
   - **远跳转:** 目标地址可能在其他代码段，需要使用更通用的跳转方式（例如，通过内存地址加载目标）。

4. **支持在运行时修补 (Patching) 跳转目标。**  允许在程序运行过程中修改跳转表中的目标地址，这对于实现懒编译和动态代码生成非常重要。

5. **针对不同的 CPU 架构提供特定的指令生成逻辑。**  代码中大量使用了 `#if V8_TARGET_ARCH_*` 预处理指令，表明 `JumpTableAssembler` 针对不同的 CPU 架构（如 x64, IA32, ARM, ARM64 等）生成不同的机器码指令来实现跳转功能。

### 是否为 Torque 源代码

`v8/src/wasm/jump-table-assembler.cc` 文件以 `.cc` 结尾，这表示它是一个标准的 C++ 源代码文件。如果它以 `.tq` 结尾，那它才是一个 v8 Torque 源代码文件。因此，**它不是一个 v8 Torque 源代码文件。**

### 与 JavaScript 的功能关系及示例

`v8/src/wasm/jump-table-assembler.cc` 负责 WebAssembly 模块在 V8 引擎中的执行。当 JavaScript 代码调用一个 WebAssembly 模块的函数时，`JumpTableAssembler` 生成的跳转表会被用来定位和执行相应的 WebAssembly 代码。

**懒编译的 JavaScript 示例：**

假设我们有一个包含两个函数的 WebAssembly 模块，但 JavaScript 只调用了其中一个函数。

```javascript
// 假设 'moduleBytes' 是 WebAssembly 模块的字节码
const module = new WebAssembly.Module(moduleBytes);
const instance = new WebAssembly.Instance(module, {});

// 假设模块导出了两个函数：'exportedFunction1' 和 'exportedFunction2'

// 只调用了 exportedFunction1
instance.exports.exportedFunction1();

// 此时，'exportedFunction2' 可能还没有被编译，它的跳转表项会指向懒编译的目标。
```

在这个例子中，当 `exportedFunction1` 第一次被调用时，V8 会使用 `JumpTableAssembler` 生成的跳转表来执行其已编译的代码。对于 `exportedFunction2`，如果它还没有被调用，其在跳转表中的条目可能仍然指向一个“懒编译”的目标地址。当 `exportedFunction2` 第一次被调用时，该跳转表项会被更新为指向其编译后的代码。

### 代码逻辑推理及假设输入输出

**场景：初始化懒编译跳转表**

假设我们正在初始化一个 WebAssembly 模块的懒编译跳转表。

**假设输入：**

- `base`: 懒编译表在内存中的起始地址 (例如: `0x1000`).
- `num_slots`: 需要懒编译的函数数量 (例如: `3`).
- `num_imported_functions`: 导入的函数数量 (例如: `1`).
- `wasm_compile_lazy_target`:  当调用未编译函数时，需要跳转到的懒编译处理函数的地址 (例如: `0x2000`).
- `kLazyCompileTableSlotSize`: 每个懒编译跳转表项的大小 (假设为 `10` 字节).

**代码逻辑：**

`GenerateLazyCompileTable` 函数会循环 `num_slots` 次，为每个需要懒编译的函数生成一个跳转表项。每个条目会调用 `EmitLazyCompileJumpSlot`。

在 x64 架构下，`EmitLazyCompileJumpSlot` 会生成如下指令：

```assembly
pushq func_index     // 将函数索引压入栈
near_jmp displacement // 跳转到 wasm_compile_lazy_target
```

`displacement` 的计算方式是 `lazy_compile_target - (当前指令地址 + kLazyCompileTableSlotSize)`.

**预期输出（x64 架构）：**

在 `base` 地址开始的内存区域，会生成 `num_slots` 个大小为 `kLazyCompileTableSlotSize` 的跳转表项。每个条目包含相应的机器码。

例如，对于第一个槽位 (slot_index = 0)，对应的 `func_index` 是 `0 + 1 = 1` (因为 `num_imported_functions = 1`)。假设当前地址是 `0x1000`，那么生成的机器码可能类似于：

```
68 01 00 00 00  // pushq 0x1 (func_index = 1)
E9 xx xx xx xx  // near_jmp displacement (xx xx xx xx 代表计算出的偏移量)
```

偏移量 `xx xx xx xx` 的值取决于 `wasm_compile_lazy_target` 的地址和当前指令的地址。

### 用户常见的编程错误

虽然用户通常不直接编写或修改 `jump-table-assembler.cc` 这样的 V8 内部代码，但理解其功能可以帮助理解与 WebAssembly 相关的错误。以下是一些可能相关的概念性错误：

1. **调用未导出的 WebAssembly 函数：**  如果 JavaScript 尝试调用一个 WebAssembly 模块中没有导出的函数，V8 可能会抛出一个错误。这与跳转表有关，因为没有导出的函数在跳转表中没有相应的入口。

   ```javascript
   // 假设 instance.exports 没有名为 'nonExistentFunction' 的导出
   // instance.exports.nonExistentFunction(); // 这会导致错误
   ```

2. **WebAssembly 模块实例化失败：** 如果 WebAssembly 模块的字节码无效或存在其他问题导致实例化失败，那么相关的跳转表也无法正确生成。

   ```javascript
   try {
     const module = new WebAssembly.Module(invalidModuleBytes);
     const instance = new WebAssembly.Instance(module, {});
   } catch (e) {
     console.error("WebAssembly module instantiation failed:", e);
   }
   ```

3. **与内存相关的 WebAssembly 错误：** 虽然不是直接与 `JumpTableAssembler` 相关，但如果 WebAssembly 代码尝试访问超出其线性内存范围的地址，可能导致程序崩溃或未定义的行为。跳转表指向的 WebAssembly 代码中的错误也可能导致类似的问题。

理解 `JumpTableAssembler` 的作用有助于深入理解 V8 如何执行 WebAssembly 代码，以及与 WebAssembly 相关的性能优化和潜在错误。

Prompt: 
```
这是目录为v8/src/wasm/jump-table-assembler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/jump-table-assembler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2018 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/wasm/jump-table-assembler.h"

#include "src/base/sanitizer/ubsan.h"
#include "src/codegen/macro-assembler-inl.h"

namespace v8 {
namespace internal {
namespace wasm {

// static
void JumpTableAssembler::GenerateLazyCompileTable(
    Address base, uint32_t num_slots, uint32_t num_imported_functions,
    Address wasm_compile_lazy_target) {
  uint32_t lazy_compile_table_size = num_slots * kLazyCompileTableSlotSize;
  WritableJitAllocation jit_allocation = ThreadIsolation::LookupJitAllocation(
      base, RoundUp<kCodeAlignment>(lazy_compile_table_size),
      ThreadIsolation::JitAllocationType::kWasmLazyCompileTable);
  // Assume enough space, so the Assembler does not try to grow the buffer.
  JumpTableAssembler jtasm(jit_allocation, base);
  for (uint32_t slot_index = 0; slot_index < num_slots; ++slot_index) {
    DCHECK_EQ(slot_index * kLazyCompileTableSlotSize, jtasm.pc_offset());
    jtasm.EmitLazyCompileJumpSlot(slot_index + num_imported_functions,
                                  wasm_compile_lazy_target);
  }
  DCHECK_EQ(lazy_compile_table_size, jtasm.pc_offset());
  FlushInstructionCache(base, lazy_compile_table_size);
}

void JumpTableAssembler::InitializeJumpsToLazyCompileTable(
    Address base, uint32_t num_slots, Address lazy_compile_table_start) {
  uint32_t jump_table_size = SizeForNumberOfSlots(num_slots);
  WritableJitAllocation jit_allocation = ThreadIsolation::LookupJitAllocation(
      base, RoundUp<kCodeAlignment>(jump_table_size),
      ThreadIsolation::JitAllocationType::kWasmJumpTable);
  JumpTableAssembler jtasm(jit_allocation, base);

  for (uint32_t slot_index = 0; slot_index < num_slots; ++slot_index) {
    // Make sure we write at the correct offset.
    int slot_offset =
        static_cast<int>(JumpTableAssembler::JumpSlotIndexToOffset(slot_index));

    jtasm.SkipUntil(slot_offset);

    Address target =
        lazy_compile_table_start +
        JumpTableAssembler::LazyCompileSlotIndexToOffset(slot_index);

#ifdef DEBUG
    int offset_before_emit = jtasm.pc_offset();
#endif
    // This function initializes the first jump table with jumps to the lazy
    // compile table. Both get allocated in the constructor of the
    // {NativeModule}, so they both should end up in the initial code space.
    // Jumps within one code space can always be near jumps, so the following
    // call to {EmitJumpSlot} should always succeed. If the call fails, then
    // either the jump table allocation was changed incorrectly so that the lazy
    // compile table was not within near-jump distance of the jump table
    // anymore (e.g. the initial code space was too small to fit both tables),
    // or the code space was allocated larger than the maximum near-jump
    // distance.
    CHECK(jtasm.EmitJumpSlot(target));

    DCHECK_EQ(kJumpTableSlotSize, jtasm.pc_offset() - offset_before_emit);
  }
  FlushInstructionCache(base, jump_table_size);
}

template <typename T>
void JumpTableAssembler::emit(T value) {
  jit_allocation_.WriteUnalignedValue(pc_, value);
  pc_ += sizeof(T);
}

template <typename T>
void JumpTableAssembler::emit(T value, RelaxedStoreTag) DISABLE_UBSAN {
  // We disable ubsan for these stores since they don't follow the alignment
  // requirements. We instead guarantee in the jump table layout that the writes
  // will still be atomic since they don't cross a qword boundary.
#if V8_TARGET_ARCH_X64
#ifdef DEBUG
  Address write_start = pc_;
  Address write_end = write_start + sizeof(T) - 1;
  // Check that the write doesn't cross a qword boundary.
  DCHECK_EQ(write_start >> kSystemPointerSizeLog2,
            write_end >> kSystemPointerSizeLog2);
#endif
#endif
  jit_allocation_.WriteValue(pc_, value, kRelaxedStore);
  pc_ += sizeof(T);
}

// The implementation is compact enough to implement it inline here. If it gets
// much bigger, we might want to split it in a separate file per architecture.
#if V8_TARGET_ARCH_X64
void JumpTableAssembler::EmitLazyCompileJumpSlot(uint32_t func_index,
                                                 Address lazy_compile_target) {
  // Use a push, because mov to an extended register takes 6 bytes.
  const uint8_t inst[kLazyCompileTableSlotSize] = {
      0x68, 0, 0, 0, 0,  // pushq func_index
      0xe9, 0, 0, 0, 0,  // near_jmp displacement
  };

  intptr_t displacement =
      lazy_compile_target - (pc_ + kLazyCompileTableSlotSize);

  emit<uint8_t>(inst[0]);
  emit<uint32_t>(func_index);
  emit<uint8_t>(inst[5]);
  emit<int32_t>(base::checked_cast<int32_t>(displacement));
}

bool JumpTableAssembler::EmitJumpSlot(Address target) {
#ifdef V8_ENABLE_CET_IBT
  uint32_t endbr_insn = 0xfa1e0ff3;
  uint32_t nop = 0x00401f0f;
  emit<uint32_t>(endbr_insn, kRelaxedStore);
  // Add a nop to ensure that the next block is 8 byte aligned.
  emit<uint32_t>(nop, kRelaxedStore);
#endif

  intptr_t displacement =
      target - (pc_ + MacroAssembler::kIntraSegmentJmpInstrSize);
  if (!is_int32(displacement)) return false;

  uint8_t inst[kJumpTableSlotSize] = {
      0xe9, 0,    0,    0, 0,  // near_jmp displacement
      0xcc, 0xcc, 0xcc,        // int3 * 3
  };
  int32_t displacement32 = base::checked_cast<int32_t>(displacement);
  memcpy(&inst[1], &displacement32, sizeof(int32_t));

  // The jump table is updated live, so the write has to be atomic.
  emit<uint64_t>(*reinterpret_cast<uint64_t*>(inst), kRelaxedStore);

  return true;
}

void JumpTableAssembler::EmitFarJumpSlot(Address target) {
  const uint8_t inst[kFarJumpTableSlotSize] = {
      0xff, 0x25, 0x02, 0, 0, 0,        // jmp [rip+0x2]
      0x66, 0x90,                       // Nop(2)
      0,    0,    0,    0, 0, 0, 0, 0,  // target
  };

  emit<uint64_t>(*reinterpret_cast<const uint64_t*>(inst));
  emit<uint64_t>(target);
}

// static
void JumpTableAssembler::PatchFarJumpSlot(WritableJitAllocation& jit_allocation,
                                          Address slot, Address target) {
  // The slot needs to be pointer-size aligned so we can atomically update it.
  DCHECK(IsAligned(slot, kSystemPointerSize));
  // Offset of the target is at 8 bytes, see {EmitFarJumpSlot}.
  jit_allocation.WriteValue(slot + kSystemPointerSize, target, kRelaxedStore);
  // The update is atomic because the address is properly aligned.
  // Because of cache coherence, the data update will eventually be seen by all
  // cores. It's ok if they temporarily jump to the old target.
}

void JumpTableAssembler::SkipUntil(int offset) {
  DCHECK_GE(offset, pc_offset());
  pc_ += offset - pc_offset();
}

#elif V8_TARGET_ARCH_IA32
void JumpTableAssembler::EmitLazyCompileJumpSlot(uint32_t func_index,
                                                 Address lazy_compile_target) {
  static_assert(kWasmCompileLazyFuncIndexRegister == edi);
  const uint8_t inst[kLazyCompileTableSlotSize] = {
      0xbf, 0, 0, 0, 0,  // mov edi, func_index
      0xe9, 0, 0, 0, 0,  // near_jmp displacement
  };
  intptr_t displacement =
      lazy_compile_target - (pc_ + kLazyCompileTableSlotSize);

  emit<uint8_t>(inst[0]);
  emit<uint32_t>(func_index);
  emit<uint8_t>(inst[5]);
  emit<int32_t>(base::checked_cast<int32_t>(displacement));
}

bool JumpTableAssembler::EmitJumpSlot(Address target) {
  intptr_t displacement = target - (pc_ + kJumpTableSlotSize);

  const uint8_t inst[kJumpTableSlotSize] = {
      0xe9, 0, 0, 0, 0,  // near_jmp displacement
  };

  // The jump table is updated live, so the writes have to be atomic.
  emit<uint8_t>(inst[0], kRelaxedStore);
  emit<int32_t>(base::checked_cast<int32_t>(displacement), kRelaxedStore);

  return true;
}

void JumpTableAssembler::EmitFarJumpSlot(Address target) {
  static_assert(kJumpTableSlotSize == kFarJumpTableSlotSize);
  EmitJumpSlot(target);
}

// static
void JumpTableAssembler::PatchFarJumpSlot(WritableJitAllocation& jit_allocation,
                                          Address slot, Address target) {
  UNREACHABLE();
}

void JumpTableAssembler::SkipUntil(int offset) {
  DCHECK_GE(offset, pc_offset());
  pc_ += offset - pc_offset();
}

#elif V8_TARGET_ARCH_ARM
void JumpTableAssembler::EmitLazyCompileJumpSlot(uint32_t func_index,
                                                 Address lazy_compile_target) {
  static_assert(kWasmCompileLazyFuncIndexRegister == r4);
  // Note that below, [pc] points to the instruction after the next.
  const uint32_t inst[kLazyCompileTableSlotSize / 4] = {
      0xe59f4000,  // ldr r4, [pc]
      0xe59ff000,  // ldr pc, [pc]
      0x00000000,  // func_index
      0x00000000,  // target
  };
  emit<uint32_t>(inst[0]);
  emit<uint32_t>(inst[1]);
  emit<uint32_t>(func_index);
  emit<Address>(lazy_compile_target);
}

bool JumpTableAssembler::EmitJumpSlot(Address target) {
  static_assert(kInstrSize == kInt32Size);
  static_assert(kJumpTableSlotSize == 2 * kInstrSize);

  // Load from [pc + kInstrSize] to pc. Note that {pc} points two instructions
  // after the currently executing one.
  const uint32_t inst[kJumpTableSlotSize / kInstrSize] = {
      0xe51ff004,  // ldr pc, [pc, -4]
      0x00000000,  // target
  };

  // This function is also used for patching existing jump slots and the writes
  // need to be atomic.
  emit<uint32_t>(inst[0], kRelaxedStore);
  emit<uint32_t>(target, kRelaxedStore);
  return true;
}

void JumpTableAssembler::EmitFarJumpSlot(Address target) {
  static_assert(kJumpTableSlotSize == kFarJumpTableSlotSize);
  EmitJumpSlot(target);
}

// static
void JumpTableAssembler::PatchFarJumpSlot(WritableJitAllocation& jit_allocation,
                                          Address slot, Address target) {
  UNREACHABLE();
}

void JumpTableAssembler::SkipUntil(int offset) {
  // On this platform the jump table is not zapped with valid instructions, so
  // skipping over bytes is not allowed.
  DCHECK_EQ(offset, pc_offset());
}

#elif V8_TARGET_ARCH_ARM64
void JumpTableAssembler::EmitLazyCompileJumpSlot(uint32_t func_index,
                                                 Address lazy_compile_target) {
  uint16_t func_index_low = func_index & 0xffff;
  uint16_t func_index_high = func_index >> 16;

  const uint32_t inst[kLazyCompileTableSlotSize / 4] = {
      0x52800008,  // mov  w8, func_index_low
      0x72a00008,  // movk w8, func_index_high, LSL#0x10
      0x14000000,  // b lazy_compile_target
  };
  static_assert(kWasmCompileLazyFuncIndexRegister == x8);

  int64_t target_offset = MacroAssembler::CalculateTargetOffset(
      lazy_compile_target, RelocInfo::NO_INFO,
      reinterpret_cast<uint8_t*>(pc_ + 2 * kInstrSize));
  DCHECK(MacroAssembler::IsNearCallOffset(target_offset));

  emit<uint32_t>(inst[0] | Assembler::ImmMoveWide(func_index_low));
  emit<uint32_t>(inst[1] | Assembler::ImmMoveWide(func_index_high));
  emit<uint32_t>(inst[2] | Assembler::ImmUncondBranch(
                               base::checked_cast<int32_t>(target_offset)));
}

bool JumpTableAssembler::EmitJumpSlot(Address target) {
#ifdef V8_ENABLE_CONTROL_FLOW_INTEGRITY
  static constexpr ptrdiff_t kCodeEntryMarkerSize = kInstrSize;
#else
  static constexpr ptrdiff_t kCodeEntryMarkerSize = 0;
#endif

  int64_t target_offset = MacroAssembler::CalculateTargetOffset(
      target, RelocInfo::NO_INFO,
      reinterpret_cast<uint8_t*>(pc_ + kCodeEntryMarkerSize));
  if (!MacroAssembler::IsNearCallOffset(target_offset)) {
    return false;
  }

#ifdef V8_ENABLE_CONTROL_FLOW_INTEGRITY
  uint32_t bti_inst = 0xd503245f;  // bti c
  emit<uint32_t>(bti_inst, kRelaxedStore);
#endif

  uint32_t branch_inst =
      0x14000000 |
      Assembler::ImmUncondBranch(base::checked_cast<int32_t>(target_offset));
  emit<uint32_t>(branch_inst, kRelaxedStore);

  return true;
}

void JumpTableAssembler::EmitFarJumpSlot(Address target) {
  DCHECK(MacroAssembler::DefaultTmpList().IncludesAliasOf(x16));

  const uint32_t inst[kFarJumpTableSlotSize / 4] = {
      0x58000050,  // ldr x16, #8
      0xd61f0200,  // br x16
      0x00000000,  // target[0]
      0x00000000,  // target[1]
  };
  emit<uint32_t>(inst[0]);
  emit<uint32_t>(inst[1]);
  emit<Address>(target);

  static_assert(2 * kInstrSize == kSystemPointerSize);
}

// static
void JumpTableAssembler::PatchFarJumpSlot(WritableJitAllocation& jit_allocation,
                                          Address slot, Address target) {
  // See {EmitFarJumpSlot} for the offset of the target (16 bytes with
  // CFI enabled, 8 bytes otherwise).
  int kTargetOffset = 2 * kInstrSize;
  // The slot needs to be pointer-size aligned so we can atomically update it.
  DCHECK(IsAligned(slot + kTargetOffset, kSystemPointerSize));
  jit_allocation.WriteValue(slot + kTargetOffset, target, kRelaxedStore);
  // The data update is guaranteed to be atomic since it's a properly aligned
  // and stores a single machine word. This update will eventually be observed
  // by any concurrent [ldr] on the same address because of the data cache
  // coherence. It's ok if other cores temporarily jump to the old target.
}

void JumpTableAssembler::SkipUntil(int offset) {
  // On this platform the jump table is not zapped with valid instructions, so
  // skipping over bytes is not allowed.
  DCHECK_EQ(offset, pc_offset());
}

#elif V8_TARGET_ARCH_S390X
void JumpTableAssembler::EmitLazyCompileJumpSlot(uint32_t func_index,
                                                 Address lazy_compile_target) {
  static_assert(kWasmCompileLazyFuncIndexRegister == r7);
  uint8_t inst[kLazyCompileTableSlotSize] = {
      0xc0, 0x71, 0x00, 0x00, 0x00, 0x00,           // lgfi r7, 0
      0xc0, 0x10, 0x00, 0x00, 0x00, 0x00,           // larl r1, 0
      0xe3, 0x10, 0x10, 0x12, 0x00, 0x04,           // lg r1, 18(r1)
      0x07, 0xf1,                                   // br r1
      0xb9, 0x04, 0x00, 0x00,                       // nop (alignment)
      0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0, 0x0  // lazy_compile_target
  };

#if V8_TARGET_LITTLE_ENDIAN
  // We need to emit the value in big endian format.
  func_index = base::bits::ReverseBytes(func_index);
#endif
  memcpy(&inst[2], &func_index, sizeof(int32_t));
  for (size_t i = 0; i < (kLazyCompileTableSlotSize - sizeof(Address)); i++) {
    emit<uint8_t>(inst[i]);
  }
  emit<Address>(lazy_compile_target);
}

bool JumpTableAssembler::EmitJumpSlot(Address target) {
  intptr_t relative_target = target - pc_;

  if (!is_int32(relative_target / 2)) {
    return false;
  }

  uint8_t inst[kJumpTableSlotSize] = {
      0xc0, 0xf4, 0x00,
      0x00, 0x00, 0x00,  // brcl(al, Operand(relative_target / 2))
      0x18, 0x00         // nop (alignment)
  };

  int32_t relative_target_addr = static_cast<int32_t>(relative_target / 2);
#if V8_TARGET_LITTLE_ENDIAN
  // We need to emit the value in big endian format.
  relative_target_addr = base::bits::ReverseBytes(relative_target_addr);
#endif
  memcpy(&inst[2], &relative_target_addr, sizeof(int32_t));
  // The jump table is updated live, so the write has to be atomic.
  emit<uint64_t>(*reinterpret_cast<uint64_t*>(inst), kRelaxedStore);

  return true;
}

void JumpTableAssembler::EmitFarJumpSlot(Address target) {
  const uint8_t inst[kFarJumpTableSlotSize] = {
      0xc0, 0x10, 0x00, 0x00, 0x00, 0x00,           // larl r1, 0
      0xe3, 0x10, 0x10, 0x10, 0x00, 0x04,           // lg r1, 16(r1)
      0x07, 0xf1,                                   // br r1
      0x18, 0x00,                                   // nop (alignment)
      0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0, 0x0  // target
  };

  for (size_t i = 0; i < (kFarJumpTableSlotSize - sizeof(Address)); i++) {
    emit<uint8_t>(inst[i]);
  }
  emit<Address>(target);
}

// static
void JumpTableAssembler::PatchFarJumpSlot(WritableJitAllocation& jit_allocation,
                                          Address slot, Address target) {
  Address target_addr = slot + 8;
  jit_allocation.WriteValue(target_addr, target, kRelaxedStore);
}

void JumpTableAssembler::SkipUntil(int offset) {
  // On this platform the jump table is not zapped with valid instructions, so
  // skipping over bytes is not allowed.
  DCHECK_EQ(offset, pc_offset());
}

#elif V8_TARGET_ARCH_MIPS64
void JumpTableAssembler::EmitLazyCompileJumpSlot(uint32_t func_index,
                                                 Address lazy_compile_target) {
  uint32_t func_index_low = func_index & 0xffff;
  uint32_t func_index_high = func_index >> 16;

  const uint32_t inst[kLazyCompileTableSlotSize / 4] = {
      0x3c0c0000,  // lui   $t0, func_index_high
      0x358c0000,  // ori   $t0, $t0, func_index_low
      0x03e00825,  // move  $at, $ra
      0x04110001,  // bal   1
      0x00000000,  // nop   (alignment, in delay slot)
      0xdff9000c,  // ld    $t9, 12($ra)  (ra = pc)
      0x03200008,  // jr    $t9
      0x0020f825,  // move  $ra, $at  (in delay slot)
      0x00000000,  // lazy_compile_target[0]
      0x00000000,  // layz_compile_target[1]
  };
  static_assert(kWasmCompileLazyFuncIndexRegister == t0);

  emit<uint32_t>(inst[0] | func_index_high);
  emit<uint32_t>(inst[1] | func_index_low);
  emit<uint32_t>(inst[2]);
  emit<uint32_t>(inst[3]);
  emit<uint32_t>(inst[4]);
  emit<uint32_t>(inst[5]);
  emit<uint32_t>(inst[6]);
  emit<uint32_t>(inst[7]);
  DCHECK(IsAligned(pc_, kSystemPointerSize));
  emit<Address>(lazy_compile_target);
}

bool JumpTableAssembler::EmitJumpSlot(Address target) {
  const uint32_t inst[kJumpTableSlotSize / kInstrSize] = {
      0x03e00825,  // move  $at, $ra
      0x04110001,  // bal   1
      0x00000000,  // nop   (alignment, in delay slot)
      0xdff9000c,  // ld    $t9, 12($ra)  (ra = pc)
      0x03200008,  // jr    $t9
      0x0020f825,  // move  $ra, $at  (in delay slot)
      0x00000000,  // lazy_compile_target[0]
      0x00000000,  // layz_compile_target[1]
  };

  // This function is also used for patching existing jump slots and the writes
  // need to be atomic.
  emit<uint32_t>(inst[0], kRelaxedStore);
  emit<uint32_t>(inst[1], kRelaxedStore);
  emit<uint32_t>(inst[2], kRelaxedStore);
  emit<uint32_t>(inst[3], kRelaxedStore);
  emit<uint32_t>(inst[4], kRelaxedStore);
  emit<uint32_t>(inst[5], kRelaxedStore);
  DCHECK(IsAligned(pc_, kSystemPointerSize));
  emit<Address>(target, kRelaxedStore);
  return true;
}

void JumpTableAssembler::EmitFarJumpSlot(Address target) {
  static_assert(kJumpTableSlotSize == kFarJumpTableSlotSize);
  EmitJumpSlot(target);
}

// static
void JumpTableAssembler::PatchFarJumpSlot(WritableJitAllocation& jit_allocation,
                                          Address slot, Address target) {
  UNREACHABLE();
}

void JumpTableAssembler::SkipUntil(int offset) {
  // On this platform the jump table is not zapped with valid instructions, so
  // skipping over bytes is not allowed.
  DCHECK_EQ(offset, pc_offset());
}

#elif V8_TARGET_ARCH_LOONG64
void JumpTableAssembler::EmitLazyCompileJumpSlot(uint32_t func_index,
                                                 Address lazy_compile_target) {
  uint32_t func_index_low_12 = func_index & 0xfff;
  uint32_t func_index_high_20 = func_index >> 12;

  const uint32_t inst[kLazyCompileTableSlotSize / 4] = {
      0x1400000c,  // lu12i.w  $t0, func_index_high_20
      0x0380018c,  // ori      $t0, $t0, func_index_low_12
      0x50000000,  // b        lazy_compile_target
  };
  static_assert(kWasmCompileLazyFuncIndexRegister == t0);

  int64_t target_offset = MacroAssembler::CalculateTargetOffset(
      lazy_compile_target, RelocInfo::NO_INFO,
      reinterpret_cast<uint8_t*>(pc_ + 2 * kInstrSize));
  DCHECK(MacroAssembler::IsNearCallOffset(target_offset));

  uint32_t target_offset_offs26 = (target_offset & 0xfffffff) >> 2;
  uint32_t target_offset_low_16 = target_offset_offs26 & 0xffff;
  uint32_t target_offset_high_10 = target_offset_offs26 >> 16;

  emit<uint32_t>(inst[0] | func_index_high_20 << kRjShift);
  emit<uint32_t>(inst[1] | func_index_low_12 << kRkShift);
  emit<uint32_t>(inst[2] | target_offset_low_16 << kRkShift |
                 target_offset_high_10);
}

bool JumpTableAssembler::EmitJumpSlot(Address target) {
  int64_t target_offset = MacroAssembler::CalculateTargetOffset(
      target, RelocInfo::NO_INFO, reinterpret_cast<uint8_t*>(pc_));
  if (!MacroAssembler::IsNearCallOffset(target_offset)) {
    return false;
  }

  uint32_t target_offset_offs26 = (target_offset & 0xfffffff) >> 2;
  uint32_t target_offset_low_16 = target_offset_offs26 & 0xffff;
  uint32_t target_offset_high_10 = target_offset_offs26 >> 16;

  uint32_t branch_inst =
      0x50000000 | target_offset_low_16 << kRkShift | target_offset_high_10;
  emit<uint32_t>(branch_inst, kRelaxedStore);

  return true;
}

void JumpTableAssembler::EmitFarJumpSlot(Address target) {
  const uint32_t inst[kFarJumpTableSlotSize / 4] = {
      0x18000093,  // pcaddi $t7, 4
      0x28c00273,  // ld.d   $t7, $t7, 0
      0x4c000260,  // jirl   $zero, $t7, 0
      0x03400000,  // nop (make target pointer-size aligned)
      0x00000000,  // target[0]
      0x00000000,  // target[1]
  };
  emit<uint32_t>(inst[0]);
  emit<uint32_t>(inst[1]);
  emit<uint32_t>(inst[2]);
  emit<uint32_t>(inst[3]);
  DCHECK(IsAligned(pc_, kSystemPointerSize));
  emit<Address>(target);
}

void JumpTableAssembler::PatchFarJumpSlot(WritableJitAllocation& jit_allocation,
                                          Address slot, Address target) {
  // See {EmitFarJumpSlot} for the address of the target.
  Address target_addr = slot + kFarJumpTableSlotSize - kSystemPointerSize;
  // The slot needs to be pointer-size aligned so we can atomically update it.
  DCHECK(IsAligned(target_addr, kSystemPointerSize));
  jit_allocation.WriteValue(target_addr, target, kRelaxedStore);
  // The data update is guaranteed to be atomic since it's a properly aligned
  // and stores a single machine word. This update will eventually be observed
  // by any concurrent [ld.d] on the same address because of the data cache
  // coherence. It's ok if other cores temporarily jump to the old target.
}

void JumpTableAssembler::SkipUntil(int offset) {
  // On this platform the jump table is not zapped with valid instructions, so
  // skipping over bytes is not allowed.
  DCHECK_EQ(offset, pc_offset());
}

#elif V8_TARGET_ARCH_PPC64
void JumpTableAssembler::EmitLazyCompileJumpSlot(uint32_t func_index,
                                                 Address lazy_compile_target) {
  static_assert(kWasmCompileLazyFuncIndexRegister == r15);
  const uint32_t inst[kLazyCompileTableSlotSize / 4] = {
      0x7c0802a6,  // mflr r0
      0x48000005,  // b(4, SetLK)
      0x7d8802a6,  // mflr ip
      0x7c0803a6,  // mtlr r0
      0x81ec0018,  // lwz r15, 24(ip)
      0xe80c0020,  // ld r0, 32(ip)
      0x7c0903a6,  // mtctr r0
      0x4e800420,  // bctr
      0x00000000,  // func_index
      0x60000000,  // nop (alignment)
      0x00000000,  // lazy_compile_target_0
      0x00000000   // lazy_compile_target_1
  };
  emit<uint32_t>(inst[0]);
  emit<uint32_t>(inst[1]);
  emit<uint32_t>(inst[2]);
  emit<uint32_t>(inst[3]);
  emit<uint32_t>(inst[4]);
  emit<uint32_t>(inst[5]);
  emit<uint32_t>(inst[6]);
  emit<uint32_t>(inst[7]);
  emit<uint32_t>(func_index);
  emit<uint32_t>(inst[9]);
  emit<Address>(lazy_compile_target);
}

bool JumpTableAssembler::EmitJumpSlot(Address target) {
  intptr_t relative_target = target - pc_;

  if (!is_int26(relative_target)) {
    return false;
  }

  const uint32_t inst[kJumpTableSlotSize / kInstrSize] = {
      0x48000000  // b(relative_target, LeaveLK)
  };

  CHECK((relative_target & (kAAMask | kLKMask)) == 0);
  // The jump table is updated live, so the write has to be atomic.
  emit<uint32_t>(inst[0] | relative_target, kRelaxedStore);
  return true;
}

void JumpTableAssembler::EmitFarJumpSlot(Address target) {
  const uint32_t inst[kFarJumpTableSlotSize / 4] = {
      0x7c0802a6,  // mflr r0
      0x48000005,  // b(4, SetLK)
      0x7d8802a6,  // mflr ip
      0x7c0803a6,  // mtlr r0
      0xe98c0018,  // ld ip, 24(ip)
      0x7d8903a6,  // mtctr ip
      0x4e800420,  // bctr
      0x60000000,  // nop (alignment)
      0x00000000,  // target_0
      0x00000000,  // target_1
      0x60000000,  // nop
      0x60000000   // nop
  };
  emit<uint32_t>(inst[0]);
  emit<uint32_t>(inst[1]);
  emit<uint32_t>(inst[2]);
  emit<uint32_t>(inst[3]);
  emit<uint32_t>(inst[4]);
  emit<uint32_t>(inst[5]);
  emit<uint32_t>(inst[6]);
  emit<uint32_t>(inst[7]);
  emit<Address>(target);
  emit<uint32_t>(inst[10]);
  emit<uint32_t>(inst[11]);
}

// static
void JumpTableAssembler::PatchFarJumpSlot(WritableJitAllocation& jit_allocation,
                                          Address slot, Address target) {
  Address target_addr = slot + kFarJumpTableSlotSize - 8;
  jit_allocation.WriteValue(target_addr, target, kRelaxedStore);
}

void JumpTableAssembler::SkipUntil(int offset) {
  // On this platform the jump table is not zapped with valid instructions, so
  // skipping over bytes is not allowed.
  DCHECK_EQ(offset, pc_offset());
}

#elif V8_TARGET_ARCH_RISCV64
void JumpTableAssembler::EmitLazyCompileJumpSlot(uint32_t func_index,
                                                 Address lazy_compile_target) {
  static_assert(kLazyCompileTableSlotSize == 3 * kInstrSize);
  int64_t high_20 = (func_index + 0x800) >> 12;
  int64_t low_12 = int64_t(func_index) << 52 >> 52;

  int64_t target_offset = MacroAssembler::CalculateTargetOffset(
      lazy_compile_target, RelocInfo::NO_INFO,
      reinterpret_cast<uint8_t*>(pc_ + 2 * kInstrSize));
  DCHECK(is_int21(target_offset));
  DCHECK_EQ(target_offset & 0x1, 0);

  const uint32_t inst[kLazyCompileTableSlotSize / 4] = {
      (RO_LUI | (kWasmCompileLazyFuncIndexRegister.code() << kRdShift) |
       int32_t(high_20 << kImm20Shift)),  // lui t0, high_20
      (RO_ADDI | (kWasmCompileLazyFuncIndexRegister.code() << kRdShift) |
       (kWasmCompileLazyFuncIndexRegister.code() << kRs1Shift) |
       int32_t(low_12 << kImm12Shift)),  // addi t0, t0, low_12
      (RO_JAL | (zero_reg.code() << kRdShift) |
       uint32_t(target_offset & 0xff000) |           // bits 19-12
       uint32_t((target_offset & 0x800) << 9) |      // bit  11
       uint32_t((target_offset & 0x7fe) << 20) |     // bits 10-1
       uint32_t((target_offset & 0x100000) << 11)),  // bit  20 ),  // jal
  };

  emit<uint32_t>(inst[0]);
  emit<uint32_t>(inst[1]);
  emit<uint32_t>(inst[2]);
}

bool JumpTableAssembler::EmitJumpSlot(Address target) {
  static_assert(kInstrSize == kInt32Size);
  static_assert(kJumpTableSlotSize == 2 * kInstrSize);
  intptr_t relative_target = target - pc_;
  if (!is_int32(relative_target)) {
    return false;
  }

  uint32_t inst[kJumpTableSlotSize / kInstrSize] = {kNopByte, kNopByte};
  if (is_int21(relative_target)) {
    inst[0] =
        (RO_JAL | (zero_reg.code() << kRdShift) |
         uint32_t(relative_target & 0xff000) |           // bits 19-12
         uint32_t((relative_target & 0x800) << 9) |      // bit  11
         uint32_t((relative_target & 0x7fe) << 20) |     // bits 10-1
         uint32_t((relative_target & 0x100000) << 11));  // bit  20 ),  // jal
  } else {
    int64_t high_20 = (relative_target + 0x800) >> 12;
    int64_t low_12 = int64_t(relative_target) << 52 >> 52;
    inst[0] = (RO_AUIPC | (t6.code() << kRdShift) |
               int32_t(high_20 << kImm20Shift));  // auipc t6, high_20
    inst[1] =
        (RO_JALR | (zero_reg.code() << kRdShift) | (t6.code() << kRs1Shift) |
         int32_t(low_12 << kImm12Shift));  // jalr t6, t6, low_12
  }

  // This function is also used for patching existing jump slots and the writes
  // need to be atomic.
  emit<uint64_t>(uint64_t(inst[1]) << 32 | inst[0], kRelaxedStore);
  DCHECK_EQ(relative_target,
            !is_int21(relative_target)
                ? MacroAssembler::BrachlongOffset(
                      Instruction::At((unsigned char*)pc_ - 2 * kInstrSize)
                          ->InstructionBits(),
                      Instruction::At((unsigned char*)pc_ - kInstrSize)
                          ->InstructionBits())
                : Instruction::At((unsigned char*)pc_ - 2 * kInstrSize)
                      ->Imm20JValue());
  return true;
}

void JumpTableAssembler::EmitFarJumpSlot(Address target) {
  uint32_t high_20 = (int64_t(4 * kInstrSize + 0x800) >> 12);
  uint32_t low_12 = (int64_t(4 * kInstrSize) << 52 >> 52);

  const uint32_t inst[kFarJumpTableSlotSize / 4] = {
      (RO_AUIPC | (t6.code() << kRdShift) |
       (high_20 << kImm20Shift)),  // auipc t6, high_20
      (RO_LD | (t6.code() << kRdShift) | (t6.code() << kRs1Shift) |
       (low_12 << kImm12Shift)),  // jalr t6, t6, low_12
      (RO_JALR | (t6.code() << kRs1Shift) | zero_reg.code() << kRdShift),
      (kNopByte),  // nop
      0x0000,      // target[0]
      0x0000,      // target[1]
  };
  emit<uint32_t>(inst[0]);
  emit<uint32_t>(inst[1]);
  emit<uint32_t>(inst[2]);
  emit<uint32_t>(inst[3]);
  emit<Address>(target);
}

// static
void JumpTableAssembler::PatchFarJumpSlot(WritableJitAllocation& jit_allocation,
                                          Address slot, Address target) {
  // See {EmitFarJumpSlot} for the offset of the target (16 bytes with
  // CFI enabled, 8 bytes otherwise).
  int kTargetOffset = kFarJumpTableSlotSize - sizeof(Address);
  jit_allocation.WriteValue(slot + kTargetOffset, target, kRelaxedStore);
  // The data update is guaranteed to be atomic since it's a properly aligned
  // and stores a single machine word. This update will eventually be observed
  // by any concurrent [ldr] on the same address because of the data cache
  // coherence. It's ok if other cores temporarily jump to the old target.
}

void JumpTableAssembler::SkipUntil(int offset) {
  // On this platform the jump table is not zapped with valid instructions, so
  // skipping over bytes is not allowed.
  DCHECK_EQ(offset, pc_offset());
}

#elif V8_TARGET_ARCH_RISCV32
void JumpTableAssembler::EmitLazyCompileJumpSlot(uint32_t func_index,
                                                 Address lazy_compile_target) {
  static_assert(kLazyCompileTableSlotSize == 3 * kInstrSize);
  int64_t high_20 = (func_index + 0x800) >> 12;
  int64_t low_12 = int64_t(func_index) << 52 >> 52;

  int64_t target_offset = MacroAssembler::CalculateTargetOffset(
      lazy_compile_target, RelocInfo::NO_INFO,
      reinterpret_cast<uint8_t*>(pc_ + 2 * kInstrSize));
  DCHECK(is_int21(target_offset));
  DCHECK_EQ(target_offset & 0x1, 0);

  const uint32_t inst[kLazyCompileTableSlotSize / 4] = {
      (RO_LUI | (kWasmCompileLazyFuncIndexRegister.code() << kRdShift) |
       int32_t(high_20 << kImm20Shift)),  // lui t0, high_20
      (RO_ADDI | (kWasmCompileLazyFuncIndexRegister.code() << kRdShift) |
       (kWasmCompileLazyFuncIndexRegister.code() << kRs1Shift) |
       int32_t(low_12 << kImm12Shift)),  // addi t0, t0, low_12
      (RO_JAL | (zero_reg.code() << kRdShift) |
       uint32_t(target_offset & 0xff000) |           // bits 19-12
       uint32_t((target_offset & 0x800) << 9) |      // bit  11
       uint32_t((target_offset & 0x7fe) << 20) |     // bits 10-1
       uint32_t((target_offset & 0x100000) << 11)),  // bit  20 ),  // jal
  };

  emit<uint32_t>(inst[0]);
  emit<uint32_t>(inst[1]);
  emit<uint32_t>(inst[2]);
}
bool JumpTableAssembler::EmitJumpSlot(Address target) {
  uint32_t high_20 = (int64_t(4 * kInstrSize + 0x800) >> 12);
  uint32_t low_12 = (int64_t(4 * kInstrSize) << 52 >> 52);

  const uint32_t inst[kJumpTableSlotSize / 4] = {
      (RO_AUIPC | (t6.code() << kRdShift) |
       (high_20 << kImm20Shift)),  // auipc t6, high_20
      (RO_LW | (t6.code() << kRdShift) | (t6.code() << kRs1Shift) |
       (low_12 << kImm12Shift)),  // jalr t6, t6, low_12
      (RO_JALR | (t6.code() << kRs1Shift) | zero_reg.code() << kRdShift),
      (kNopByte),  // nop
      0x0000,      // target
  };
  emit<uint32_t>(inst[0]);
  emit<uint32_t>(inst[1]);
  emit<uint32_t>(inst[2]);
  emit<uint32_t>(inst[3]);
  emit<uint32_t>(target, kRelaxedStore);
  return true;
}

void JumpTableAssembler::EmitFarJumpSlot(Address target) {
  static_assert(kJumpTableSlotSize == kFarJumpTableSlotSize);
  EmitJumpSlot(target);
}

// static
void JumpTableAssembler::PatchFarJumpSlot(WritableJitAllocation& jit_allocation,
                                          Address slot, Address target) {
  UNREACHABLE();
}

void JumpTableAssembler::SkipUntil(int offset) {
  // On this platform the jump table is not zapped with valid instructions, so
  // skipping over bytes is not allowed.
  DCHECK_EQ(offset, pc_offset());
}

#else
#error Unknown architecture.
#endif

}  // namespace wasm
}  // namespace internal
}  // namespace v8

"""

```