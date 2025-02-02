Response:
Let's break down the thought process to analyze the provided C++ code snippet for `v8/src/objects/instruction-stream.cc`.

**1. Initial Scan and Keyword Recognition:**

First, I'd scan the code for keywords and familiar V8 concepts. Things that immediately jump out are:

* `InstructionStream`:  This is the central object we need to understand.
* `Relocate`, `RelocateFromDesc`, `RelocateFromDescWriteBarriers`: These function names strongly suggest the code is dealing with adjusting addresses within the instruction stream, likely during garbage collection or code movement.
* `WritableJitAllocation`, `CodeDesc`: These hint at memory management and code generation.
* `RelocInfo`, `RelocIterator`: These are related to relocation information, crucial for making code position-independent.
* `WriteBarrier`, `WriteBarrierPromise`: These are key concepts in garbage collection, ensuring object references are updated correctly when objects move.
* `Builtins`:  References to built-in functions.
* `Assembler`:  Suggests interaction with the code generation process.
* `FlushInstructionCache`:  A common operation after modifying code in memory.
* `DEBUG`: Conditional compilation, likely for debugging purposes.

**2. Understanding `InstructionStream`:**

Based on the name, `InstructionStream` likely represents a contiguous block of executable code within V8. It's probably the runtime representation of the machine code generated by the JavaScript compiler (Ignition or TurboFan).

**3. Deconstructing the Functions:**

Now, let's analyze each function individually:

* **`Relocate(WritableJitAllocation& jit_allocation, intptr_t delta)`:**
    * Purpose: Adjusts addresses within the `InstructionStream` by a given `delta`. This is called during garbage collection (evacuation) when code objects might be moved in memory.
    * Mechanism: Iterates through relocation entries using `WritableRelocIterator`. For each entry, it applies the `delta` to update the stored address. Finally, it flushes the instruction cache to ensure the CPU sees the updated code.
    * Key Insight:  Handles relocation *after* a move has occurred.

* **`RelocateFromDesc(WritableJitAllocation& jit_allocation, Heap* heap, const CodeDesc& desc, Address constant_pool, const DisallowGarbageCollection& no_gc)`:**
    * Purpose: Performs initial relocation based on a `CodeDesc`, which describes the newly generated code. It updates embedded object pointers, code target pointers, and built-in entry points. Crucially, it *delays* the write barriers.
    * Mechanism: Iterates through relocation entries.
        * **Embedded Objects:** Updates the pointer to the embedded object.
        * **Code Targets:** Updates the pointer to the start of the target `InstructionStream`.
        * **Builtins:** Calculates the PC-relative offset to the built-in entry point.
        * **Wasm Stubs:** Resolves WebAssembly stub calls to their corresponding built-in addresses.
        * **Other Relocations:** Applies a delta based on the difference between the new instruction start and the original buffer.
    * Key Insight:  Handles relocation during the *creation* or movement of a code object, separating the address updates from the write barrier updates for efficiency. The `WriteBarrierPromise` is used to track which addresses need write barriers later.

* **`RelocateFromDescWriteBarriers(Heap* heap, const CodeDesc& desc, Address constant_pool, WriteBarrierPromise& write_barrier_promise, const DisallowGarbageCollection& no_gc)`:**
    * Purpose:  Performs the write barrier updates that were deferred in `RelocateFromDesc`.
    * Mechanism: Iterates through the relocation entries again.
        * **Embedded Objects:** Calls `WriteBarrier::ForRelocInfo` to update the remembered set (or similar GC mechanism) for the embedded object.
        * **Code Targets:** Calls `WriteBarrier::ForRelocInfo` for the target `InstructionStream`.
    * Key Insight:  Completes the relocation process by ensuring garbage collection is aware of the updated pointers. The synchronization with `RelocateFromDesc` is explicitly mentioned in comments.

* **`WriteBarrierPromise` (nested class):**
    * Purpose:  A utility class to manage the delayed write barriers. It tracks addresses that need write barriers and ensures they are eventually resolved.
    * Mechanism: Uses a `std::set` to store addresses. `RegisterAddress` adds an address, `ResolveAddress` removes it, and the destructor asserts that all registered addresses have been resolved.
    * Key Insight:  An optimization to batch write barriers, likely improving performance during relocation.

**4. Connecting to JavaScript and Potential Errors:**

Now, I'd think about how this low-level code relates to JavaScript:

* **Function Calls:** When a JavaScript function is called, the interpreter or JIT compiler needs to jump to the correct machine code. `InstructionStream` holds this code, and relocation ensures these jumps are always valid.
* **Object References:** JavaScript objects can be embedded within compiled code (e.g., constant values). Relocation updates these embedded object pointers.
* **Built-in Functions:**  Calls to built-in functions like `console.log` need to be resolved to their actual machine code addresses.

Potential Programming Errors (from a V8 developer perspective, not a JS user):

* **Incorrect Relocation Logic:**  If the `delta` calculation or the logic within the relocation loops is wrong, the code could jump to incorrect addresses, leading to crashes or undefined behavior.
* **Forgetting Write Barriers:** Failing to call `RelocateFromDescWriteBarriers` after `RelocateFromDesc` would lead to garbage collection not being aware of updated object references, resulting in dangling pointers and crashes.
* **Cache Inconsistency:**  Not calling `FlushInstructionCache` after modifying the instruction stream could lead to the CPU executing stale code.

**5. Torque and File Extension:**

The prompt asks about the `.tq` extension. I know that `.tq` files are for V8's Torque language, which is used for generating built-in functions. The code snippet provided is `.cc`, so it's standard C++. Therefore, it's *not* a Torque file.

**6. Structuring the Answer:**

Finally, I'd organize my findings into a clear and structured answer, addressing each part of the prompt:

* **Functionality Summary:** Provide a high-level overview of the file's purpose.
* **Detailed Function Explanations:**  Describe each function's role, mechanisms, and key insights.
* **JavaScript Relationship (with example):** Illustrate how `InstructionStream` is relevant to JavaScript execution.
* **Code Logic Inference (with example):** Create a simple hypothetical scenario to demonstrate the relocation process.
* **Common Programming Errors:** Highlight potential mistakes from a V8 development perspective.
* **Torque Check:** Address the `.tq` extension question.

This step-by-step process allows for a thorough understanding of the code and a comprehensive answer to the prompt. The key is to start with high-level concepts and gradually dive into the details, connecting the code to the broader context of the V8 JavaScript engine.
```cpp
// Copyright 2023 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/objects/instruction-stream.h"

#include "src/builtins/builtins-inl.h"
#include "src/codegen/assembler-inl.h"
#include "src/codegen/flush-instruction-cache.h"
#include "src/codegen/reloc-info-inl.h"
#include "src/codegen/reloc-info.h"
#include "src/objects/instruction-stream-inl.h"

namespace v8 {
namespace internal {

void InstructionStream::Relocate(WritableJitAllocation& jit_allocation,
                                 intptr_t delta) {
  Tagged<Code> code;
  if (!TryGetCodeUnchecked(&code, kAcquireLoad)) return;
  // This is called during evacuation and code.instruction_stream() will point
  // to the old object. So pass *this directly to the RelocIterator.
  for (WritableRelocIterator it(jit_allocation, *this, constant_pool(),
                                RelocInfo::kApplyMask);
       !it.done(); it.next()) {
    it.rinfo()->apply(delta);
  }
  FlushInstructionCache(instruction_start(), body_size());
}

// This function performs the relocations but doesn't trigger any write barriers
// yet. We skip the write barriers here with UNSAFE_SKIP_WRITE_BARRIER but the
// caller needs to call RelocateFromDescWriteBarriers afterwards.
InstructionStream::WriteBarrierPromise InstructionStream::RelocateFromDesc(
    WritableJitAllocation& jit_allocation, Heap* heap, const CodeDesc& desc,
    Address constant_pool, const DisallowGarbageCollection& no_gc) {
  WriteBarrierPromise write_barrier_promise;
  Assembler* origin = desc.origin;
  const int mode_mask = RelocInfo::PostCodegenRelocationMask();
  for (WritableRelocIterator it(jit_allocation, *this, constant_pool,
                                mode_mask);
       !it.done(); it.next()) {
    // IMPORTANT:
    // this code needs be stay in sync with RelocateFromDescWriteBarriers below.

    RelocInfo::Mode mode = it.rinfo()->rmode();
    if (RelocInfo::IsEmbeddedObjectMode(mode)) {
      DirectHandle<HeapObject> p = it.rinfo()->target_object_handle(origin);
      it.rinfo()->set_target_object(*this, *p, UNSAFE_SKIP_WRITE_BARRIER,
                                    SKIP_ICACHE_FLUSH);
      write_barrier_promise.RegisterAddress(it.rinfo()->pc());
    } else if (RelocInfo::IsCodeTargetMode(mode)) {
      // Rewrite code handles to direct pointers to the first instruction in the
      // code object.
      DirectHandle<HeapObject> p = it.rinfo()->target_object_handle(origin);
      DCHECK(IsCode(*p));
      Tagged<InstructionStream> target_istream =
          Cast<Code>(*p)->instruction_stream();
      it.rinfo()->set_target_address(*this, target_istream->instruction_start(),
                                     UNSAFE_SKIP_WRITE_BARRIER,
                                     SKIP_ICACHE_FLUSH);
      write_barrier_promise.RegisterAddress(it.rinfo()->pc());
    } else if (RelocInfo::IsNearBuiltinEntry(mode)) {
      // Rewrite builtin IDs to PC-relative offset to the builtin entry point.
      Builtin builtin = it.rinfo()->target_builtin_at(origin);
      Address p = Builtins::EntryOf(builtin, heap->isolate());
      // This won't trigger a write barrier, but setting mode to
      // UPDATE_WRITE_BARRIER to make it clear that we didn't forget about it
      // below.
      it.rinfo()->set_target_address(*this, p, UPDATE_WRITE_BARRIER,
                                     SKIP_ICACHE_FLUSH);
      DCHECK_EQ(p, it.rinfo()->target_address());
    } else if (RelocInfo::IsWasmStubCall(mode)) {
#if V8_ENABLE_WEBASSEMBLY
      // Map wasm stub id to builtin.
      uint32_t stub_call_tag = it.rinfo()->wasm_call_tag();
      DCHECK_LT(stub_call_tag,
                static_cast<uint32_t>(Builtin::kFirstBytecodeHandler));
      Builtin builtin = static_cast<Builtin>(stub_call_tag);
      // Store the builtin address in relocation info.
      Address entry = Builtins::EntryOf(builtin, heap->isolate());
      it.rinfo()->set_wasm_stub_call_address(entry);
#else
      UNREACHABLE();
#endif
    } else {
      intptr_t delta =
          instruction_start() - reinterpret_cast<Address>(desc.buffer);
      it.rinfo()->apply(delta);
    }
  }
  return write_barrier_promise;
}

void InstructionStream::RelocateFromDescWriteBarriers(
    Heap* heap, const CodeDesc& desc, Address constant_pool,
    WriteBarrierPromise& write_barrier_promise,
    const DisallowGarbageCollection& no_gc) {
  const int mode_mask = RelocInfo::PostCodegenRelocationMask();
  for (RelocIterator it(code(kAcquireLoad), mode_mask); !it.done(); it.next()) {
    // IMPORTANT:
    // this code needs be stay in sync with RelocateFromDesc above.

    RelocInfo::Mode mode = it.rinfo()->rmode();
    if (RelocInfo::IsEmbeddedObjectMode(mode)) {
      Tagged<HeapObject> p = it.rinfo()->target_object(heap->isolate());
      WriteBarrier::ForRelocInfo(*this, it.rinfo(), p, UPDATE_WRITE_BARRIER);
      write_barrier_promise.ResolveAddress(it.rinfo()->pc());
    } else if (RelocInfo::IsCodeTargetMode(mode)) {
      Tagged<InstructionStream> target_istream =
          InstructionStream::FromTargetAddress(it.rinfo()->target_address());
      WriteBarrier::ForRelocInfo(*this, it.rinfo(), target_istream,
                                 UPDATE_WRITE_BARRIER);
      write_barrier_promise.ResolveAddress(it.rinfo()->pc());
    }
  }
}

#ifdef DEBUG
void InstructionStream::WriteBarrierPromise::RegisterAddress(Address address) {
  DCHECK(delayed_write_barriers_.insert(address).second);
}

void InstructionStream::WriteBarrierPromise::ResolveAddress(Address address) {
  DCHECK_EQ(delayed_write_barriers_.erase(address), 1);
}
InstructionStream::WriteBarrierPromise::~WriteBarrierPromise() {
  DCHECK(delayed_write_barriers_.empty());
}
#endif

}  // namespace internal
}  // namespace v8
```

### 功能列举

`v8/src/objects/instruction-stream.cc` 文件的主要功能是管理和操作 `InstructionStream` 对象。`InstructionStream` 是 V8 中用于存储可执行机器码的核心数据结构。该文件中的代码负责处理在代码移动或加载过程中需要更新的地址引用（重定位）。

具体来说，其功能包括：

1. **代码重定位 (Relocation):**
   - `Relocate`:  在垃圾回收过程中移动代码对象时，更新 `InstructionStream` 中存储的绝对地址引用。这确保了代码中的指针仍然指向正确的内存位置。
   - `RelocateFromDesc`:  在代码生成后，根据 `CodeDesc` 中包含的重定位信息，对 `InstructionStream` 进行初始化重定位。它处理多种类型的重定位，例如嵌入对象、代码目标和内置函数入口点。
   - `RelocateFromDescWriteBarriers`:  与 `RelocateFromDesc` 配合使用，用于处理在重定位过程中涉及的写屏障（Write Barrier）。写屏障是垃圾回收机制的一部分，用于跟踪对象之间的引用关系。

2. **管理重定位信息:**
   - 使用 `RelocIterator` 遍历 `InstructionStream` 中的重定位信息。
   - 根据不同的 `RelocInfo::Mode` (重定位模式) 执行不同的操作，例如更新嵌入对象指针、代码目标地址或计算内置函数的相对偏移。

3. **与垃圾回收集成:**
   - 使用 `WriteBarrierPromise` 延迟执行写屏障操作，以提高性能。
   - 确保在代码移动或更新后，垃圾回收器能够正确地跟踪对象引用。

4. **处理不同类型的代码引用:**
   - **嵌入对象 (Embedded Object):** 更新指向在代码中直接引用的堆对象的指针。
   - **代码目标 (Code Target):** 更新指向其他代码对象的入口点的指针。
   - **内置函数入口点 (Builtin Entry):** 将对内置函数的引用转换为相对于当前代码位置的偏移量，或者直接存储入口地址。
   - **WebAssembly Stub 调用 (Wasm Stub Call):**  将 WebAssembly stub 的 ID 映射到其对应的内置函数入口地址。

5. **刷新指令缓存 (Flush Instruction Cache):**
   - 在代码被修改后，调用 `FlushInstructionCache` 以确保 CPU 缓存与内存中的代码保持一致，避免执行过时的指令。

### 是否为 Torque 源代码

`v8/src/objects/instruction-stream.cc` 以 `.cc` 结尾，这表明它是一个 **C++** 源代码文件，而不是 Torque 源代码文件。 Torque 源代码文件通常以 `.tq` 结尾。

### 与 JavaScript 的关系 (示例)

`InstructionStream` 存储的是 V8 执行 JavaScript 代码时生成的机器码。每当 JavaScript 函数被编译执行时，其对应的机器码就会被存储在 `InstructionStream` 中。

**JavaScript 示例:**

```javascript
function add(a, b) {
  return a + b;
}

let result = add(5, 3);
console.log(result); // 输出 8
```

当 V8 执行 `add(5, 3)` 时，如果 `add` 函数被 JIT (Just-In-Time) 编译，V8 会生成相应的机器码并存储在 `InstructionStream` 对象中。

**`InstructionStream.cc` 中的操作如何影响上述 JavaScript 代码的执行：**

- **`Relocate`:** 如果垃圾回收器移动了包含 `add` 函数机器码的 `Code` 对象，`Relocate` 函数会更新 `InstructionStream` 中可能存在的指向其他对象的指针，例如常量池中的数字 `5` 和 `3`。
- **`RelocateFromDesc`:** 当 `add` 函数首次被编译时，`RelocateFromDesc` 会根据生成的 `CodeDesc` 初始化 `InstructionStream`，设置指向例如加法操作实现的内置函数的引用。
- **内置函数入口点处理:** 在 `RelocateFromDesc` 中，会处理对内置的加法操作的引用，确保机器码能够正确跳转到执行加法运算的代码。

### 代码逻辑推理 (假设输入与输出)

假设我们有一个简单的 JavaScript 函数：

```javascript
function greet(name) {
  return "Hello, " + name;
}
```

当这个函数被编译时，会生成一个 `InstructionStream`。 假设该 `InstructionStream` 中包含一个指令，该指令需要加载字符串字面量 `"Hello, "`。

**假设输入:**

- `InstructionStream` 对象 `istream`，其内部包含一条加载字符串字面量的指令，该指令的重定位信息指向旧的字符串 `"Hello, "` 的内存地址 `0x1000`。
- 垃圾回收器将字符串 `"Hello, "` 移动到新的内存地址 `0x2000`。
- `delta` (内存地址的偏移量) = `0x2000` - `0x1000` = `0x1000`。

**`Relocate` 函数的执行:**

1. `Relocate` 函数遍历 `istream` 的重定位信息。
2. 当遍历到指向字符串字面量的重定位信息时，`it.rinfo()->apply(delta)` 被调用。
3. `apply` 函数会将旧地址 `0x1000` 更新为 `0x1000 + 0x1000 = 0x2000`。

**输出:**

- `istream` 中加载字符串字面量的指令现在指向新的内存地址 `0x2000`，即字符串 `"Hello, "` 的新位置。

**假设输入 (对于 `RelocateFromDesc`):**

- `CodeDesc` 对象 `desc` 描述了 `greet` 函数的机器码，其中包含一个需要重定位的对内置字符串连接函数的调用。
- `desc.origin` 指向生成这段代码的 `Assembler` 对象。
- 重定位信息 `it.rinfo()` 指示需要将一个地址设置为内置字符串连接函数的入口点。
- `Builtins::EntryOf(builtin, heap->isolate())` 返回内置字符串连接函数的入口地址，例如 `0x3000`。

**`RelocateFromDesc` 函数的执行:**

1. `RelocateFromDesc` 遍历 `desc` 中的重定位信息。
2. 当遇到内置函数调用的重定位条目时 (`RelocInfo::IsNearBuiltinEntry(mode)` 为真)。
3. `Builtin builtin = it.rinfo()->target_builtin_at(origin)` 获取内置函数的 ID。
4. `Address p = Builtins::EntryOf(builtin, heap->isolate())` 获取该内置函数的入口地址 `0x3000`。
5. `it.rinfo()->set_target_address(*this, p, UPDATE_WRITE_BARRIER, SKIP_ICACHE_FLUSH)` 将 `InstructionStream` 中对应位置的地址设置为 `0x3000`。

**输出:**

- `InstructionStream` 中，对内置字符串连接函数的调用指令现在包含了正确的入口地址 `0x3000`。

### 涉及用户常见的编程错误 (V8 内部开发角度)

由于 `v8/src/objects/instruction-stream.cc` 是 V8 内部的代码，这里列举的是 V8 开发人员在编写或修改这类代码时可能犯的错误：

1. **错误的重定位计算:** 在 `Relocate` 或 `RelocateFromDesc` 中，如果计算地址偏移量 `delta` 的方式不正确，或者在应用偏移量时出现错误，会导致代码中的指针指向错误的内存位置，引发程序崩溃或未定义的行为。

   **示例 (假设错误地使用了负的 delta):**

   ```c++
   // 错误示例：假设 delta 应该是正的，但错误地使用了负值
   it.rinfo()->apply(-delta);
   ```

2. **忘记刷新指令缓存:** 在修改了 `InstructionStream` 的内容后，如果没有调用 `FlushInstructionCache`，CPU 可能会继续执行旧的指令，导致程序行为异常。

   **示例 (遗漏了刷新指令缓存的步骤):**

   ```c++
   for (WritableRelocIterator it(/* ... */); !it.done(); it.next()) {
     it.rinfo()->apply(delta);
   }
   // 错误：忘记调用 FlushInstructionCache
   ```

3. **写屏障处理不当:** 在涉及对象引用的重定位中，如果 `RelocateFromDescWriteBarriers` 没有正确地执行写屏障操作，垃圾回收器可能无法正确跟踪对象之间的引用，导致悬挂指针和内存泄漏。

   **示例 (在需要写屏障的地方跳过了):**

   ```c++
   if (RelocInfo::IsEmbeddedObjectMode(mode)) {
     DirectHandle<HeapObject> p = it.rinfo()->target_object_handle(origin);
     it.rinfo()->set_target_object(*this, *p, UNSAFE_SKIP_WRITE_BARRIER,
                                   SKIP_ICACHE_FLUSH);
     // 错误：应该在这里或之后调用相应的写屏障处理逻辑
   }
   ```

4. **重定位模式处理不完整或错误:** 如果在 `RelocateFromDesc` 或 `RelocateFromDescWriteBarriers` 中，对不同的 `RelocInfo::Mode` 的处理逻辑有遗漏或者错误，会导致某些类型的引用无法被正确更新。

   **示例 (忘记处理新的重定位模式):**

   ```c++
   if (RelocInfo::IsEmbeddedObjectMode(mode)) {
     // ...
   } else if (RelocInfo::IsCodeTargetMode(mode)) {
     // ...
   }
   // 错误：忘记处理例如 RelocInfo::IsWasmStubCall(mode) 的情况
   ```

理解 `v8/src/objects/instruction-stream.cc` 的功能对于理解 V8 如何管理和执行 JavaScript 代码至关重要。它涉及到代码的生命周期管理，包括代码的生成、移动和垃圾回收过程中的更新。

### 提示词
```
这是目录为v8/src/objects/instruction-stream.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/instruction-stream.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
// Copyright 2023 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/objects/instruction-stream.h"

#include "src/builtins/builtins-inl.h"
#include "src/codegen/assembler-inl.h"
#include "src/codegen/flush-instruction-cache.h"
#include "src/codegen/reloc-info-inl.h"
#include "src/codegen/reloc-info.h"
#include "src/objects/instruction-stream-inl.h"

namespace v8 {
namespace internal {

void InstructionStream::Relocate(WritableJitAllocation& jit_allocation,
                                 intptr_t delta) {
  Tagged<Code> code;
  if (!TryGetCodeUnchecked(&code, kAcquireLoad)) return;
  // This is called during evacuation and code.instruction_stream() will point
  // to the old object. So pass *this directly to the RelocIterator.
  for (WritableRelocIterator it(jit_allocation, *this, constant_pool(),
                                RelocInfo::kApplyMask);
       !it.done(); it.next()) {
    it.rinfo()->apply(delta);
  }
  FlushInstructionCache(instruction_start(), body_size());
}

// This function performs the relocations but doesn't trigger any write barriers
// yet. We skip the write barriers here with UNSAFE_SKIP_WRITE_BARRIER but the
// caller needs to call RelocateFromDescWriteBarriers afterwards.
InstructionStream::WriteBarrierPromise InstructionStream::RelocateFromDesc(
    WritableJitAllocation& jit_allocation, Heap* heap, const CodeDesc& desc,
    Address constant_pool, const DisallowGarbageCollection& no_gc) {
  WriteBarrierPromise write_barrier_promise;
  Assembler* origin = desc.origin;
  const int mode_mask = RelocInfo::PostCodegenRelocationMask();
  for (WritableRelocIterator it(jit_allocation, *this, constant_pool,
                                mode_mask);
       !it.done(); it.next()) {
    // IMPORTANT:
    // this code needs be stay in sync with RelocateFromDescWriteBarriers below.

    RelocInfo::Mode mode = it.rinfo()->rmode();
    if (RelocInfo::IsEmbeddedObjectMode(mode)) {
      DirectHandle<HeapObject> p = it.rinfo()->target_object_handle(origin);
      it.rinfo()->set_target_object(*this, *p, UNSAFE_SKIP_WRITE_BARRIER,
                                    SKIP_ICACHE_FLUSH);
      write_barrier_promise.RegisterAddress(it.rinfo()->pc());
    } else if (RelocInfo::IsCodeTargetMode(mode)) {
      // Rewrite code handles to direct pointers to the first instruction in the
      // code object.
      DirectHandle<HeapObject> p = it.rinfo()->target_object_handle(origin);
      DCHECK(IsCode(*p));
      Tagged<InstructionStream> target_istream =
          Cast<Code>(*p)->instruction_stream();
      it.rinfo()->set_target_address(*this, target_istream->instruction_start(),
                                     UNSAFE_SKIP_WRITE_BARRIER,
                                     SKIP_ICACHE_FLUSH);
      write_barrier_promise.RegisterAddress(it.rinfo()->pc());
    } else if (RelocInfo::IsNearBuiltinEntry(mode)) {
      // Rewrite builtin IDs to PC-relative offset to the builtin entry point.
      Builtin builtin = it.rinfo()->target_builtin_at(origin);
      Address p = Builtins::EntryOf(builtin, heap->isolate());
      // This won't trigger a write barrier, but setting mode to
      // UPDATE_WRITE_BARRIER to make it clear that we didn't forget about it
      // below.
      it.rinfo()->set_target_address(*this, p, UPDATE_WRITE_BARRIER,
                                     SKIP_ICACHE_FLUSH);
      DCHECK_EQ(p, it.rinfo()->target_address());
    } else if (RelocInfo::IsWasmStubCall(mode)) {
#if V8_ENABLE_WEBASSEMBLY
      // Map wasm stub id to builtin.
      uint32_t stub_call_tag = it.rinfo()->wasm_call_tag();
      DCHECK_LT(stub_call_tag,
                static_cast<uint32_t>(Builtin::kFirstBytecodeHandler));
      Builtin builtin = static_cast<Builtin>(stub_call_tag);
      // Store the builtin address in relocation info.
      Address entry = Builtins::EntryOf(builtin, heap->isolate());
      it.rinfo()->set_wasm_stub_call_address(entry);
#else
      UNREACHABLE();
#endif
    } else {
      intptr_t delta =
          instruction_start() - reinterpret_cast<Address>(desc.buffer);
      it.rinfo()->apply(delta);
    }
  }
  return write_barrier_promise;
}

void InstructionStream::RelocateFromDescWriteBarriers(
    Heap* heap, const CodeDesc& desc, Address constant_pool,
    WriteBarrierPromise& write_barrier_promise,
    const DisallowGarbageCollection& no_gc) {
  const int mode_mask = RelocInfo::PostCodegenRelocationMask();
  for (RelocIterator it(code(kAcquireLoad), mode_mask); !it.done(); it.next()) {
    // IMPORTANT:
    // this code needs be stay in sync with RelocateFromDesc above.

    RelocInfo::Mode mode = it.rinfo()->rmode();
    if (RelocInfo::IsEmbeddedObjectMode(mode)) {
      Tagged<HeapObject> p = it.rinfo()->target_object(heap->isolate());
      WriteBarrier::ForRelocInfo(*this, it.rinfo(), p, UPDATE_WRITE_BARRIER);
      write_barrier_promise.ResolveAddress(it.rinfo()->pc());
    } else if (RelocInfo::IsCodeTargetMode(mode)) {
      Tagged<InstructionStream> target_istream =
          InstructionStream::FromTargetAddress(it.rinfo()->target_address());
      WriteBarrier::ForRelocInfo(*this, it.rinfo(), target_istream,
                                 UPDATE_WRITE_BARRIER);
      write_barrier_promise.ResolveAddress(it.rinfo()->pc());
    }
  }
}

#ifdef DEBUG
void InstructionStream::WriteBarrierPromise::RegisterAddress(Address address) {
  DCHECK(delayed_write_barriers_.insert(address).second);
}

void InstructionStream::WriteBarrierPromise::ResolveAddress(Address address) {
  DCHECK_EQ(delayed_write_barriers_.erase(address), 1);
}
InstructionStream::WriteBarrierPromise::~WriteBarrierPromise() {
  DCHECK(delayed_write_barriers_.empty());
}
#endif

}  // namespace internal
}  // namespace v8
```