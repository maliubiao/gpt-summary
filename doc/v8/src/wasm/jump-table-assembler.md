Response: Let's break down the thought process for analyzing this C++ code and generating the summary and JavaScript example.

1. **Understand the Goal:** The primary request is to understand the *functionality* of the `JumpTableAssembler` class in the provided C++ code and relate it to JavaScript, providing an example if possible.

2. **Initial Skim and Keywords:** Quickly read through the code, looking for recurring terms and key concepts. Words like "JumpTable," "Assembler," "Wasm," "lazy compile," "slot," "target," "emit," and architecture-specific keywords (like `pushq`, `jmp`, `ldr`, etc.) immediately jump out. This suggests the code is dealing with generating low-level machine code for WebAssembly, specifically related to function calls.

3. **Identify the Core Class:** The `JumpTableAssembler` class is central. Its methods and how they interact will define its functionality.

4. **Analyze Key Methods:**  Focus on the public methods of `JumpTableAssembler` and the static helper functions:
    * `GenerateLazyCompileTable`:  The name suggests creating a table used for initially handling function calls before the function's code is compiled. The arguments `num_slots`, `num_imported_functions`, and `wasm_compile_lazy_target` are clues about its purpose. It initializes slots with jumps to `wasm_compile_lazy_target`.
    * `InitializeJumpsToLazyCompileTable`: This method takes an existing jump table and populates it with jumps to the lazy compile table. This implies there are two tables involved.
    * `EmitLazyCompileJumpSlot`:  This method appears to generate the actual machine code for a single slot in the lazy compile table. The architecture-specific implementations are important here. Notice it often involves setting up a function index and jumping to the `lazy_compile_target`.
    * `EmitJumpSlot`: This generates the machine code for a slot in the main jump table, typically a direct jump to a target address. Again, architecture-specific implementations exist.
    * `EmitFarJumpSlot` and `PatchFarJumpSlot`:  These handle cases where the target address is too far for a direct jump. They use an indirect jump via a memory location.
    * `SkipUntil`: This is a utility for managing the current writing position within the allocated memory.
    * ``emit<T>` methods: These are template methods used for writing raw bytes (machine code instructions or data) into the allocated memory. The `RelaxedStoreTag` version is interesting – it hints at potential atomicity requirements for live updates.

5. **Infer the Purpose of the Tables:** Based on the method names and how they're used, we can infer the roles of the two jump tables:
    * **Initial Jump Table:** This is the first table used when a WebAssembly function is called. Initially, its entries point to the lazy compilation mechanism.
    * **Lazy Compile Table:** This table holds code that, when executed, triggers the actual compilation of a WebAssembly function.

6. **Connect to WebAssembly's Lazy Compilation:** The names and logic strongly suggest this code is implementing lazy compilation for WebAssembly. The initial jump table redirects calls to the lazy compile table, which then handles the compilation and eventually patches the initial jump table to point directly to the compiled code.

7. **Identify Architecture-Specific Code:** The `#if V8_TARGET_ARCH_...` blocks highlight that the exact machine code instructions differ across architectures (x64, IA32, ARM, etc.). The *functionality* remains the same, but the *implementation* varies. This is a standard practice in low-level code generation.

8. **Consider the "Why":** Why have two jump tables and lazy compilation?  The primary reason is to improve startup time. Instead of compiling all WebAssembly functions upfront, only the called functions are compiled when they are first invoked.

9. **Formulate the Summary:** Based on the analysis, construct a concise summary that covers the key aspects:
    * Core functionality: Assembling jump tables for WebAssembly.
    * Purpose of jump tables: Directing function calls.
    * Lazy compilation mechanism: Initial redirection to a lazy compile target.
    * Architecture dependence.
    * Role in V8: Part of the WebAssembly execution engine.

10. **Relate to JavaScript (the Tricky Part):**  Directly mapping this low-level code to a specific JavaScript feature is difficult because it's an *implementation detail* of how WebAssembly works *within* the JavaScript engine. The connection is conceptual.

11. **Develop the JavaScript Example (Conceptual):**  The goal here is to illustrate the *effect* of this C++ code from a JavaScript perspective. Focus on the user-observable behavior:
    * Calling a WebAssembly function for the first time might be slower (due to compilation).
    * Subsequent calls are faster (because the code is now compiled).
    * The example should demonstrate importing and calling a WebAssembly function.

12. **Refine the JavaScript Example:** Make sure the example is clear, uses standard WebAssembly APIs (`fetch`, `compileStreaming`, `instantiateStreaming`), and highlights the performance difference between the first and subsequent calls (even if this is a conceptual demonstration). Use `performance.now()` to measure time, even if the differences might be subtle in a simplified example.

13. **Review and Iterate:** Read through the summary and the JavaScript example to ensure accuracy, clarity, and consistency. Make sure the JavaScript example logically connects to the described C++ functionality (even if it's at a higher level of abstraction). For example, explicitly mention that the C++ code is *behind the scenes* making the initial call slower.

This systematic approach, starting with high-level understanding and gradually diving into specifics, allows for a comprehensive analysis of the C++ code and its relation to JavaScript. The key is to understand the *purpose* and *behavior* of the code, even if the exact implementation details are complex.
这个C++源代码文件 `v8/src/wasm/jump-table-assembler.cc` 的主要功能是 **为 WebAssembly (Wasm) 生成和管理跳转表**。

更具体地说，它提供了 `JumpTableAssembler` 类，用于在内存中动态地构建和修改跳转表，这些跳转表是 Wasm 运行时用来高效地分发函数调用的关键组件。

以下是其主要功能点的归纳：

1. **生成 Lazy Compile 表 (GenerateLazyCompileTable):**
   - 创建一个用于延迟编译的跳转表。
   - 表中的每个 "槽位" (slot) 都包含跳转到 `wasm_compile_lazy_target` 的指令。
   - 当首次调用一个尚未编译的 Wasm 函数时，会跳转到这个 `wasm_compile_lazy_target`，触发该函数的编译。
   - 该方法会预先分配内存，并填充跳转指令。

2. **初始化到 Lazy Compile 表的跳转 (InitializeJumpsToLazyCompileTable):**
   - 初始化主要的 Wasm 函数跳转表。
   - 表中的每个 "槽位" 初始时都包含跳转到 Lazy Compile 表对应槽位的指令。
   - 这样，最初调用任何 Wasm 函数都会先跳转到 Lazy Compile 表。

3. **发射不同类型的跳转槽 (Emit...JumpSlot):**
   - `EmitLazyCompileJumpSlot`: 在 Lazy Compile 表中生成一个跳转槽，包含加载函数索引并跳转到 `lazy_compile_target` 的指令。
   - `EmitJumpSlot`:  在主要的跳转表中生成一个跳转槽，包含直接跳转到目标地址的指令。这个目标地址通常是已编译的 Wasm 函数入口点。
   - `EmitFarJumpSlot`: 生成一个远跳转槽，用于跳转到距离较远的目标地址。
   - `PatchFarJumpSlot`: 用于动态修改远跳转槽的目标地址。

4. **底层操作 (emit):**
   - 提供了 `emit` 模板方法，用于将原始字节数据写入到分配的内存中，这是构建机器码指令的基础。
   - 针对一些可能出现的非对齐写入，提供了带有 `RelaxedStoreTag` 的 `emit` 版本，用于在保证原子性的前提下进行写入。

5. **跨平台支持:**
   - 文件中使用了大量的 `#if V8_TARGET_ARCH_...` 预处理指令，这意味着 `JumpTableAssembler` 的实现会根据不同的处理器架构 (如 x64, IA32, ARM, ARM64 等) 而有所不同。
   - 每种架构都有其特定的指令格式和跳转方式，因此需要针对性地生成机器码。

6. **内存管理:**
   - 使用 `WritableJitAllocation` 来分配和管理用于存储跳转表的内存。
   - `FlushInstructionCache` 用于确保生成的机器码在执行前被刷新到指令缓存。

**与 JavaScript 的关系 (以及 JavaScript 例子):**

`JumpTableAssembler` 的功能是 WebAssembly 在 V8 引擎中执行的关键底层机制，它直接影响了 Wasm 代码的性能和执行流程。虽然 JavaScript 开发者通常不会直接接触到这些底层的实现细节，但了解其背后的原理有助于理解 Wasm 的执行方式。

当你在 JavaScript 中加载和运行 WebAssembly 模块时，V8 引擎会在幕后使用像 `JumpTableAssembler` 这样的组件来管理函数的调用。

**JavaScript 例子：**

假设你有一个简单的 WebAssembly 模块 `my_module.wasm`，其中包含一个名为 `add` 的函数。

```javascript
async function loadAndRunWasm() {
  const response = await fetch('my_module.wasm');
  const buffer = await response.arrayBuffer();
  const module = await WebAssembly.compile(buffer);
  const instance = await WebAssembly.instantiate(module);

  // 第一次调用 'add' 函数
  let result1 = instance.exports.add(5, 3);
  console.log("First call result:", result1);

  // 后续调用 'add' 函数
  let result2 = instance.exports.add(10, 7);
  console.log("Second call result:", result2);
}

loadAndRunWasm();
```

**背后的联系：**

1. **首次调用 (`instance.exports.add(5, 3)`)**:
   - 当首次调用 `add` 函数时，V8 引擎会查找与该函数关联的跳转表条目。
   - 初始时，该条目可能指向 Lazy Compile 表中的一个槽位（由 `InitializeJumpsToLazyCompileTable` 设置）。
   - 跳转到 Lazy Compile 表后，会执行 `EmitLazyCompileJumpSlot` 生成的代码，这会触发 `add` 函数的编译。
   - 编译完成后，`EmitJumpSlot` 或 `PatchFarJumpSlot` 会被用来更新主跳转表中 `add` 函数对应的条目，使其直接指向编译后的机器码。

2. **后续调用 (`instance.exports.add(10, 7)`)**:
   - 再次调用 `add` 函数时，跳转表中的条目现在已经更新，会直接跳转到已编译的 `add` 函数的机器码，从而避免了再次进入 Lazy Compile 流程，提高了执行效率。

**总结来说，`JumpTableAssembler` 就像一个幕后工程师，负责搭建 WebAssembly 函数调用所需的“高速公路”，确保函数能够被快速且正确地调用。Lazy Compile 机制通过初始的“绕行”到编译流程，实现了按需编译，优化了程序的启动时间和执行性能。**

### 提示词
```
这是目录为v8/src/wasm/jump-table-assembler.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
```

### 源代码
```
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
```