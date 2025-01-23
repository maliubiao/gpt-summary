Response:
My thinking process to analyze the provided C++ header file and answer the request involved several steps:

1. **Initial Scan for Basic Information:** I first scanned the header file for its name (`liftoff-assembler-mips64-inl.h`), the copyright notice, and the included header files. This gave me a high-level understanding that it's part of the V8 project, specifically related to the WebAssembly baseline compiler ("Liftoff") for the MIPS64 architecture. The `.inl.h` suffix suggests it contains inline function definitions.

2. **Identify Key Data Structures and Concepts:**  I looked for recurring keywords and patterns, like `MemOperand`, `LiftoffAssembler`, `LiftoffRegister`, `ValueKind`, and the frame layout diagram. These hinted at the core functionalities: memory access, register management, data type handling, and stack frame manipulation.

3. **Analyze the Frame Layout:** The diagram was crucial. I carefully read the comments and noted the purpose of each slot in the Liftoff stack frame. This immediately highlighted the file's role in managing function call contexts in WebAssembly.

4. **Categorize Inline Functions:** I then went through each inline function, grouping them by their apparent purpose. Common patterns emerged:
    * **Stack Access:** Functions like `GetStackSlot` and the frame constant definitions.
    * **Memory Operations (Load/Store):**  Functions named `Load` and `Store` for different data types and addressing modes. The distinction between tagged and untagged pointers became apparent.
    * **Endianness Handling:** The `ChangeEndiannessLoad` and `ChangeEndiannessStore` functions stood out, indicating support for different byte orderings.
    * **Stack Manipulation:** The `push` function.
    * **Operand Construction:** `GetMemOp` for creating memory operands.

5. **Look for Control Flow and Optimization Related Functions:** I noticed functions like `PrepareStackFrame`, `CallFrameSetupStub`, `PrepareTailCall`, `PatchPrepareStackFrame`, `CheckTierUp`, and `CheckStackShrink`. These indicated functionalities related to function entry/exit, optimization (tier-up), and stack management.

6. **Analyze Helper Functions:** Functions like `LoadConstant`, `LoadInstanceDataFromFrame`, `LoadTrustedPointer`, `LoadFromInstance`, and `SpillInstanceData` pointed to the file's role in accessing constant values and the WebAssembly instance data.

7. **Identify Atomic Operations:** The presence of `AtomicLoad`, `AtomicStore`, and the `Atomic<Op>` family of functions clearly indicated support for atomic memory operations, crucial for multi-threading and shared memory scenarios.

8. **Connect to WebAssembly Concepts:** Throughout the process, I connected the functions and data structures to my knowledge of WebAssembly. For example, the "instance data" is a fundamental concept in WebAssembly, and the different `ValueKind` enums map to WebAssembly data types.

9. **Address Specific Questions in the Prompt:** After understanding the general functionality, I specifically addressed each point in the request:
    * **Functionality Summary:** Based on the categorization, I summarized the main roles of the header file.
    * **`.tq` Extension:** I knew that `.tq` files in V8 are related to Torque, a TypeScript-like language for generating C++ code. I checked if the filename ended with `.tq`. Since it didn't, it's a regular C++ header.
    * **Relationship to JavaScript:**  I considered how WebAssembly relates to JavaScript. Since WebAssembly code often interoperates with JavaScript, I looked for functions that might bridge this gap (like loading instance data). I then provided a simple JavaScript example demonstrating a WebAssembly module calling back into JavaScript.
    * **Code Logic Inference (with Hypotheses):**  I selected a relatively straightforward function (`GetMemOp`) and provided example inputs and the expected output, explaining the logic of address calculation.
    * **Common Programming Errors:**  I thought about common mistakes when dealing with memory access and data types, such as incorrect offsets or type mismatches. I provided examples related to `Load` and `Store`.
    * **Part 1 Summary:** I reiterated the main functionalities identified in the initial summary.

10. **Refine and Organize:** Finally, I reviewed my analysis, ensuring clarity, accuracy, and proper organization of the information. I used bullet points and clear headings to make the explanation easy to read.

Essentially, my approach was to progressively deepen my understanding of the code, starting with a high-level overview and then drilling down into the details of individual functions and data structures. Connecting the code to the broader context of V8 and WebAssembly was crucial for interpreting its purpose. Answering the specific constraints of the prompt ensured that I addressed all the user's requests.
这是目录为v8/src/wasm/baseline/mips64/liftoff-assembler-mips64-inl.h的V8源代码，它是一个内联头文件，为MIPS64架构上的Liftoff汇编器提供了一些辅助的内联函数。

**功能列举:**

1. **栈帧操作:**
   - 定义了Liftoff在MIPS64上的栈帧布局。
   - 提供了访问栈帧中特定槽位的内联函数，例如 `GetStackSlot` 用于获取指定偏移量的栈槽， `GetInstanceDataOperand` 用于获取 WebAssembly 实例数据的地址。

2. **内存操作:**
   - 提供了通用的内存操作内联函数 `GetMemOp`，用于计算内存地址，可以处理基址寄存器、偏移量寄存器以及立即数偏移量，并支持可选的移位操作。
   - 提供了 `Load` 和 `Store` 内联函数，用于加载和存储不同大小和类型的 WebAssembly 值（如 i32, i64, f32, f64, s128, 引用类型）到/从内存中。

3. **栈操作:**
   - 提供了 `push` 内联函数，用于将不同类型的 WebAssembly 值压入栈中。

4. **大小端处理 (Big Endian)：**
   - 提供了 `ChangeEndiannessLoad` 和 `ChangeEndiannessStore` 内联函数，用于在 MIPS64 大端架构上加载和存储数据时进行字节序转换，以确保 WebAssembly 的正确语义。

5. **代码生成辅助:**
   - 提供了 `PrepareStackFrame` 和 `PatchPrepareStackFrame` 用于处理栈帧的准备和调整，包括处理大栈帧的情况。
   - 提供了 `CallFrameSetupStub` 用于调用运行时辅助函数进行栈帧设置。
   - 提供了 `PrepareTailCall` 用于准备尾调用。

6. **类型和大小相关:**
   - 提供了 `SlotSizeForType` 用于获取特定 ValueKind 的槽位大小。
   - 提供了 `NeedsAlignment` 用于检查特定 ValueKind 是否需要对齐。

7. **优化相关:**
   - 提供了 `CheckTierUp` 用于检查是否需要进行分层编译优化。

8. **常量加载:**
   - 提供了 `LoadConstant` 用于将 WebAssembly 常量加载到寄存器中。

9. **实例数据访问:**
   - 提供了 `LoadInstanceDataFromFrame` 和 `SpillInstanceData` 用于加载和保存 WebAssembly 实例数据。
   - 提供了 `LoadTrustedPointer`, `LoadFromInstance`, `LoadTaggedPointerFromInstance` 用于从实例数据中加载不同类型的指针。

10. **受保护的内存访问:**
    - 提供了 `LoadTaggedPointer` 和 `StoreTaggedPointer` 用于加载和存储标记指针，可能涉及到垃圾回收的屏障操作。
    - 提供了 `LoadProtectedPointer` 和 `LoadFullPointer` 用于加载受保护的和完整的指针。

11. **原子操作:**
    - 提供了 `AtomicLoad` 和 `AtomicStore` 用于执行原子加载和存储操作。
    - 提供了一系列的 `AtomicAdd`, `AtomicSub`, `AtomicAnd`, `AtomicOr`, `AtomicXor` 原子算术和逻辑运算。
    - 提供了 `AtomicExchange` 用于执行原子交换操作。

**关于文件扩展名和 Torque:**

你提供的代码片段是 C++ 头文件 (`.h`)，而不是 Torque 源文件 (`.tq`)。因此，它不是一个 V8 Torque 源代码。

**与 JavaScript 的功能关系:**

此头文件中的代码直接支持 V8 引擎中 WebAssembly 模块的执行。当 JavaScript 代码执行一个 WebAssembly 模块时，V8 会使用 Liftoff 编译器将 WebAssembly 代码编译成本地机器码。这个头文件中的内联函数帮助 Liftoff 汇编器生成高效的 MIPS64 指令，用于执行 WebAssembly 的各种操作，包括内存访问、算术运算、函数调用等。

**JavaScript 示例:**

```javascript
// 创建一个 WebAssembly 实例
const wasmCode = new Uint8Array([
  0, 97, 115, 109, 1, 0, 0, 0, 1, 7, 1, 96, 1, 127, 1, 127, 3, 2, 1, 0, 7, 7, 1,
  3, 97, 100, 100, 0, 0, 10, 12, 1, 10, 0, 32, 0, 16, 0, 16, 0, 106, 11
]);
const wasmModule = new WebAssembly.Module(wasmCode);
const wasmInstance = new WebAssembly.Instance(wasmModule);

// 调用 WebAssembly 导出的函数
const result = wasmInstance.exports.add(5, 3);
console.log(result); // 输出 8
```

在这个例子中，当 `wasmInstance.exports.add(5, 3)` 被调用时，V8 的 Liftoff 编译器（在 MIPS64 架构上）可能会使用 `liftoff-assembler-mips64-inl.h` 中定义的函数来生成将参数加载到寄存器、执行加法运算并将结果存储回内存或寄存器的机器码。例如，`Load` 函数可能用于将参数 5 和 3 从栈或内存加载到寄存器中，而 `Store` 函数可能用于将结果 8 存储回适当的位置。

**代码逻辑推理 (假设输入与输出):**

假设我们调用 `GetMemOp` 函数，目的是计算一个数组元素的地址：

**假设输入:**

- `assm`: 一个指向 `LiftoffAssembler` 实例的指针。
- `addr`: 寄存器 `r10`，其中包含数组的基地址 (例如：0x1000)。
- `offset`: 寄存器 `r11`，其中包含元素的索引 (例如：2)。
- `offset_imm`: 0 (没有额外的立即数偏移)。
- `i64_offset`: `false` (索引不是 64 位)。
- `shift_amount`: 3 (假设数组元素是 8 字节大小，需要左移 3 位，相当于乘以 8)。

**代码逻辑 (相关的 `GetMemOp` 部分):**

```c++
inline MemOperand GetMemOp(LiftoffAssembler* assm, Register addr,
                           Register offset, T offset_imm,
                           bool i64_offset = false, unsigned shift_amount = 0) {
  if (offset != no_reg) {
    if (!i64_offset) {
      assm->Dext(kScratchReg, offset, 0, 32); // 取 offset 的低 32 位
      offset = kScratchReg;
    }
    if (shift_amount != 0) {
      assm->Dlsa(kScratchReg, addr, offset, shift_amount); // kScratchReg = addr + (offset << shift_amount)
    } else {
      assm->daddu(kScratchReg, offset, addr); // kScratchReg = offset + addr
    }
    addr = kScratchReg;
  }
  if (is_int31(offset_imm)) {
    int32_t offset_imm32 = static_cast<int32_t>(offset_imm);
    return MemOperand(addr, offset_imm32);
  } else {
    assm->li(kScratchReg2, Operand(offset_imm));
    assm->daddu(kScratchReg, addr, kScratchReg2);
    return MemOperand(kScratchReg, 0);
  }
}
```

**推理步骤:**

1. `offset` (`r11`) 不是 `no_reg`，进入第一个 `if` 块。
2. `i64_offset` 是 `false`，所以 `Dext` 指令将 `r11` 的低 32 位移动到 `kScratchReg`。假设 `r11` 的值为 2，那么 `kScratchReg` 现在为 2。
3. `shift_amount` 是 3，所以 `Dlsa` 指令执行 `kScratchReg = r10 + (kScratchReg << 3)`。假设 `r10` 的值为 0x1000 (4096)，`kScratchReg` 的值为 2，则 `kScratchReg = 0x1000 + (2 << 3) = 0x1000 + 16 = 0x1010` (4112)。
4. `addr` 现在被更新为 `kScratchReg` 的值，即 0x1010。
5. `offset_imm` 是 0，并且 `is_int31(0)` 为真，进入第二个 `if` 块。
6. 返回 `MemOperand(addr, offset_imm32)`，即 `MemOperand(0x1010, 0)`。

**输出:**

`GetMemOp` 函数将返回一个 `MemOperand` 对象，表示内存地址 `[0x1010 + 0]`，即 `0x1010`。这正是数组中索引为 2 的元素的地址（假设每个元素 8 字节）。

**用户常见的编程错误示例:**

1. **错误的偏移量计算:** 用户可能在调用 `GetMemOp` 或 `Load`/`Store` 时，没有正确计算偏移量，导致访问了错误的内存地址。例如，在访问数组时，忘记乘以元素的大小。

   ```c++
   // 错误示例：假设访问 int32 数组的第 i 个元素，但没有乘以 sizeof(int32)
   MemOperand addr = GetMemOp(assm, array_base_reg, index_reg, 0);
   assm->Lw(dest_reg, addr);
   ```
   应该乘以 `kInt32Size` 或使用带移位的 `GetMemOp`。

2. **类型不匹配的加载/存储:** 用户可能使用错误的 `Load` 或 `Store` 函数来操作内存，导致类型不匹配。

   ```c++
   // 错误示例：将一个 i64 值用 Lw (load word, 32位) 加载到寄存器中
   MemOperand src_addr = ...;
   assm->Lw(dest_reg.gp(), src_addr); // 如果 src_addr 指向一个 i64，这将读取错误的数据
   ```
   应该使用 `Ld` (load doubleword) 来加载 i64 值。

3. **忘记处理大小端问题:** 在大端架构上，如果直接加载或存储多字节数据而没有使用 `ChangeEndiannessLoad` 或 `ChangeEndiannessStore`，可能会导致数据字节序错误。

   ```c++
   // 错误示例（在大端架构上）：直接加载一个 i32
   MemOperand src_addr = ...;
   assm->Lw(dest_reg.gp(), src_addr); // 可能需要 ChangeEndiannessLoad
   ```

**归纳一下它的功能 (第 1 部分):**

`v8/src/wasm/baseline/mips64/liftoff-assembler-mips64-inl.h` 是 V8 引擎中用于 MIPS64 架构的 Liftoff WebAssembly 编译器的关键组成部分。它定义了栈帧结构，并提供了一系列内联函数，用于简化和优化生成 MIPS64 汇编代码的过程。这些函数涵盖了栈操作、内存访问（加载、存储，包括原子操作和大小端处理）、常量加载、实例数据访问以及与编译优化相关的辅助功能。其主要目的是提供高效且类型安全的接口，以便 Liftoff 编译器能够快速生成执行 WebAssembly 代码所需的机器码。

### 提示词
```
这是目录为v8/src/wasm/baseline/mips64/liftoff-assembler-mips64-inl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/baseline/mips64/liftoff-assembler-mips64-inl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共5部分，请归纳一下它的功能
```

### 源代码
```c
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_WASM_BASELINE_MIPS64_LIFTOFF_ASSEMBLER_MIPS64_INL_H_
#define V8_WASM_BASELINE_MIPS64_LIFTOFF_ASSEMBLER_MIPS64_INL_H_

#include "src/codegen/machine-type.h"
#include "src/heap/mutable-page-metadata.h"
#include "src/wasm/baseline/liftoff-assembler.h"
#include "src/wasm/baseline/parallel-move-inl.h"
#include "src/wasm/object-access.h"
#include "src/wasm/wasm-linkage.h"
#include "src/wasm/wasm-objects.h"

namespace v8::internal::wasm {

namespace liftoff {

// Liftoff Frames.
//
//  slot      Frame
//       +--------------------+---------------------------
//  n+4  | optional padding slot to keep the stack 16 byte aligned.
//  n+3  |   parameter n      |
//  ...  |       ...          |
//   4   |   parameter 1      | or parameter 2
//   3   |   parameter 0      | or parameter 1
//   2   |  (result address)  | or parameter 0
//  -----+--------------------+---------------------------
//   1   | return addr (ra)   |
//   0   | previous frame (fp)|
//  -----+--------------------+  <-- frame ptr (fp)
//  -1   | StackFrame::WASM   |
//  -2   |     instance       |
//  -3   |     feedback vector|
//  -----+--------------------+---------------------------
//  -4   |     slot 0         |   ^
//  -5   |     slot 1         |   |
//       |                    | Frame slots
//       |                    |   |
//       |                    |   v
//       | optional padding slot to keep the stack 16 byte aligned.
//  -----+--------------------+  <-- stack ptr (sp)
//

inline MemOperand GetStackSlot(int offset) { return MemOperand(fp, -offset); }

inline MemOperand GetInstanceDataOperand() {
  return GetStackSlot(WasmLiftoffFrameConstants::kInstanceDataOffset);
}

template <typename T>
inline MemOperand GetMemOp(LiftoffAssembler* assm, Register addr,
                           Register offset, T offset_imm,
                           bool i64_offset = false, unsigned shift_amount = 0) {
  if (offset != no_reg) {
    if (!i64_offset) {
      assm->Dext(kScratchReg, offset, 0, 32);
      offset = kScratchReg;
    }
    if (shift_amount != 0) {
      assm->Dlsa(kScratchReg, addr, offset, shift_amount);
    } else {
      assm->daddu(kScratchReg, offset, addr);
    }
    addr = kScratchReg;
  }
  if (is_int31(offset_imm)) {
    int32_t offset_imm32 = static_cast<int32_t>(offset_imm);
    return MemOperand(addr, offset_imm32);
  } else {
    assm->li(kScratchReg2, Operand(offset_imm));
    assm->daddu(kScratchReg, addr, kScratchReg2);
    return MemOperand(kScratchReg, 0);
  }
}

inline void Load(LiftoffAssembler* assm, LiftoffRegister dst, MemOperand src,
                 ValueKind kind) {
  switch (kind) {
    case kI16:
      assm->Lh(dst.gp(), src);
      break;
    case kI32:
      assm->Lw(dst.gp(), src);
      break;
    case kI64:
    case kRef:
    case kRefNull:
    case kRtt:
      assm->Ld(dst.gp(), src);
      break;
    case kF32:
      assm->Lwc1(dst.fp(), src);
      break;
    case kF64:
      assm->Ldc1(dst.fp(), src);
      break;
    case kS128:
      assm->ld_b(dst.fp().toW(), src);
      break;
    default:
      UNREACHABLE();
  }
}

inline void Store(LiftoffAssembler* assm, MemOperand dst, LiftoffRegister src,
                  ValueKind kind) {
  switch (kind) {
    case kI16:
      assm->Ush(src.gp(), dst, t8);
      break;
    case kI32:
      assm->Usw(src.gp(), dst);
      break;
    case kI64:
    case kRefNull:
    case kRef:
    case kRtt:
      assm->Usd(src.gp(), dst);
      break;
    case kF32:
      assm->Uswc1(src.fp(), dst, t8);
      break;
    case kF64:
      assm->Usdc1(src.fp(), dst, t8);
      break;
    case kS128:
      assm->st_b(src.fp().toW(), dst);
      break;
    default:
      UNREACHABLE();
  }
}

inline void Store(LiftoffAssembler* assm, Register base, int32_t offset,
                  LiftoffRegister src, ValueKind kind) {
  MemOperand dst(base, offset);
  Store(assm, dst, src, kind);
}

inline void push(LiftoffAssembler* assm, LiftoffRegister reg, ValueKind kind) {
  switch (kind) {
    case kI32:
      assm->daddiu(sp, sp, -kSystemPointerSize);
      assm->sw(reg.gp(), MemOperand(sp, 0));
      break;
    case kI64:
    case kRefNull:
    case kRef:
    case kRtt:
      assm->push(reg.gp());
      break;
    case kF32:
      assm->daddiu(sp, sp, -kSystemPointerSize);
      assm->swc1(reg.fp(), MemOperand(sp, 0));
      break;
    case kF64:
      assm->daddiu(sp, sp, -kSystemPointerSize);
      assm->Sdc1(reg.fp(), MemOperand(sp, 0));
      break;
    case kS128:
      assm->daddiu(sp, sp, -kSystemPointerSize * 2);
      assm->st_b(reg.fp().toW(), MemOperand(sp, 0));
      break;
    default:
      UNREACHABLE();
  }
}

#if defined(V8_TARGET_BIG_ENDIAN)
inline void ChangeEndiannessLoad(LiftoffAssembler* assm, LiftoffRegister dst,
                                 LoadType type, LiftoffRegList pinned) {
  bool is_float = false;
  LiftoffRegister tmp = dst;
  switch (type.value()) {
    case LoadType::kI64Load8U:
    case LoadType::kI64Load8S:
    case LoadType::kI32Load8U:
    case LoadType::kI32Load8S:
      // No need to change endianness for byte size.
      return;
    case LoadType::kF32Load:
      is_float = true;
      tmp = assm->GetUnusedRegister(kGpReg, pinned);
      assm->emit_type_conversion(kExprI32ReinterpretF32, tmp, dst);
      [[fallthrough]];
    case LoadType::kI64Load32U:
      assm->MacroAssembler::ByteSwapUnsigned(tmp.gp(), tmp.gp(), 4);
      break;
    case LoadType::kI32Load:
    case LoadType::kI64Load32S:
      assm->MacroAssembler::ByteSwapSigned(tmp.gp(), tmp.gp(), 4);
      break;
    case LoadType::kI32Load16S:
    case LoadType::kI64Load16S:
      assm->MacroAssembler::ByteSwapSigned(tmp.gp(), tmp.gp(), 2);
      break;
    case LoadType::kI32Load16U:
    case LoadType::kI64Load16U:
      assm->MacroAssembler::ByteSwapUnsigned(tmp.gp(), tmp.gp(), 2);
      break;
    case LoadType::kF64Load:
      is_float = true;
      tmp = assm->GetUnusedRegister(kGpReg, pinned);
      assm->emit_type_conversion(kExprI64ReinterpretF64, tmp, dst);
      [[fallthrough]];
    case LoadType::kI64Load:
      assm->MacroAssembler::ByteSwapSigned(tmp.gp(), tmp.gp(), 8);
      break;
    default:
      UNREACHABLE();
  }

  if (is_float) {
    switch (type.value()) {
      case LoadType::kF32Load:
        assm->emit_type_conversion(kExprF32ReinterpretI32, dst, tmp);
        break;
      case LoadType::kF64Load:
        assm->emit_type_conversion(kExprF64ReinterpretI64, dst, tmp);
        break;
      default:
        UNREACHABLE();
    }
  }
}

inline void ChangeEndiannessStore(LiftoffAssembler* assm, LiftoffRegister src,
                                  StoreType type, LiftoffRegList pinned) {
  bool is_float = false;
  LiftoffRegister tmp = src;
  switch (type.value()) {
    case StoreType::kI64Store8:
    case StoreType::kI32Store8:
      // No need to change endianness for byte size.
      return;
    case StoreType::kF32Store:
      is_float = true;
      tmp = assm->GetUnusedRegister(kGpReg, pinned);
      assm->emit_type_conversion(kExprI32ReinterpretF32, tmp, src);
      [[fallthrough]];
    case StoreType::kI32Store:
      assm->MacroAssembler::ByteSwapSigned(tmp.gp(), tmp.gp(), 4);
      break;
    case StoreType::kI32Store16:
      assm->MacroAssembler::ByteSwapSigned(tmp.gp(), tmp.gp(), 2);
      break;
    case StoreType::kF64Store:
      is_float = true;
      tmp = assm->GetUnusedRegister(kGpReg, pinned);
      assm->emit_type_conversion(kExprI64ReinterpretF64, tmp, src);
      [[fallthrough]];
    case StoreType::kI64Store:
      assm->MacroAssembler::ByteSwapSigned(tmp.gp(), tmp.gp(), 8);
      break;
    case StoreType::kI64Store32:
      assm->MacroAssembler::ByteSwapSigned(tmp.gp(), tmp.gp(), 4);
      break;
    case StoreType::kI64Store16:
      assm->MacroAssembler::ByteSwapSigned(tmp.gp(), tmp.gp(), 2);
      break;
    default:
      UNREACHABLE();
  }

  if (is_float) {
    switch (type.value()) {
      case StoreType::kF32Store:
        assm->emit_type_conversion(kExprF32ReinterpretI32, src, tmp);
        break;
      case StoreType::kF64Store:
        assm->emit_type_conversion(kExprF64ReinterpretI64, src, tmp);
        break;
      default:
        UNREACHABLE();
    }
  }
}
#endif  // V8_TARGET_BIG_ENDIAN

}  // namespace liftoff

int LiftoffAssembler::PrepareStackFrame() {
  int offset = pc_offset();
  // When the frame size is bigger than 4KB, we need seven instructions for
  // stack checking, so we reserve space for this case.
  daddiu(sp, sp, 0);
  nop();
  nop();
  nop();
  nop();
  nop();
  nop();
  return offset;
}

void LiftoffAssembler::CallFrameSetupStub(int declared_function_index) {
// The standard library used by gcc tryjobs does not consider `std::find` to be
// `constexpr`, so wrap it in a `#ifdef __clang__` block.
#ifdef __clang__
  static_assert(std::find(std::begin(wasm::kGpParamRegisters),
                          std::end(wasm::kGpParamRegisters),
                          kLiftoffFrameSetupFunctionReg) ==
                std::end(wasm::kGpParamRegisters));
#endif

  // On MIPS64, we must push at least {ra} before calling the stub, otherwise
  // it would get clobbered with no possibility to recover it. So just set
  // up the frame here.
  EnterFrame(StackFrame::WASM);
  LoadConstant(LiftoffRegister(kLiftoffFrameSetupFunctionReg),
               WasmValue(declared_function_index));
  CallBuiltin(Builtin::kWasmLiftoffFrameSetup);
}

void LiftoffAssembler::PrepareTailCall(int num_callee_stack_params,
                                       int stack_param_delta) {
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();

  // Push the return address and frame pointer to complete the stack frame.
  Ld(scratch, MemOperand(fp, 8));
  Push(scratch);
  Ld(scratch, MemOperand(fp, 0));
  Push(scratch);

  // Shift the whole frame upwards.
  int slot_count = num_callee_stack_params + 2;
  for (int i = slot_count - 1; i >= 0; --i) {
    Ld(scratch, MemOperand(sp, i * 8));
    Sd(scratch, MemOperand(fp, (i - stack_param_delta) * 8));
  }

  // Set the new stack and frame pointer.
  daddiu(sp, fp, -stack_param_delta * 8);
  Pop(ra, fp);
}

void LiftoffAssembler::AlignFrameSize() {}

void LiftoffAssembler::PatchPrepareStackFrame(
    int offset, SafepointTableBuilder* safepoint_table_builder,
    bool feedback_vector_slot, size_t stack_param_slots) {
  // The frame_size includes the frame marker and the instance slot. Both are
  // pushed as part of frame construction, so we don't need to allocate memory
  // for them anymore.
  int frame_size = GetTotalFrameSize() - 2 * kSystemPointerSize;
  // The frame setup builtin also pushes the feedback vector.
  if (feedback_vector_slot) {
    frame_size -= kSystemPointerSize;
  }

  // We can't run out of space, just pass anything big enough to not cause the
  // assembler to try to grow the buffer.
  constexpr int kAvailableSpace = 256;
  MacroAssembler patching_assembler(
      nullptr, AssemblerOptions{}, CodeObjectRequired::kNo,
      ExternalAssemblerBuffer(buffer_start_ + offset, kAvailableSpace));

  if (V8_LIKELY(frame_size < 4 * KB)) {
    // This is the standard case for small frames: just subtract from SP and be
    // done with it.
    patching_assembler.Daddu(sp, sp, Operand(-frame_size));
    return;
  }

  // The frame size is bigger than 4KB, so we might overflow the available stack
  // space if we first allocate the frame and then do the stack check (we will
  // need some remaining stack space for throwing the exception). That's why we
  // check the available stack space before we allocate the frame. To do this we
  // replace the {__ Daddu(sp, sp, -frame_size)} with a jump to OOL code that
  // does this "extended stack check".
  //
  // The OOL code can simply be generated here with the normal assembler,
  // because all other code generation, including OOL code, has already finished
  // when {PatchPrepareStackFrame} is called. The function prologue then jumps
  // to the current {pc_offset()} to execute the OOL code for allocating the
  // large frame.
  // Emit the unconditional branch in the function prologue (from {offset} to
  // {pc_offset()}).

  int imm32 = pc_offset() - offset - 3 * kInstrSize;
  patching_assembler.BranchLong(imm32);

  // If the frame is bigger than the stack, we throw the stack overflow
  // exception unconditionally. Thereby we can avoid the integer overflow
  // check in the condition code.
  RecordComment("OOL: stack check for large frame");
  Label continuation;
  if (frame_size < v8_flags.stack_size * 1024) {
    Register stack_limit = kScratchReg;
    LoadStackLimit(stack_limit, StackLimitKind::kRealStackLimit);
    Daddu(stack_limit, stack_limit, Operand(frame_size));
    Branch(&continuation, uge, sp, Operand(stack_limit));
  }

  Call(static_cast<Address>(Builtin::kWasmStackOverflow),
       RelocInfo::WASM_STUB_CALL);
  // The call will not return; just define an empty safepoint.
  safepoint_table_builder->DefineSafepoint(this);
  if (v8_flags.debug_code) stop();

  bind(&continuation);

  // Now allocate the stack space. Note that this might do more than just
  // decrementing the SP;
  Daddu(sp, sp, Operand(-frame_size));

  // Jump back to the start of the function, from {pc_offset()} to
  // right after the reserved space for the {__ Daddu(sp, sp, -framesize)}
  // (which is a Branch now).
  int func_start_offset = offset + 7 * kInstrSize;
  imm32 = func_start_offset - pc_offset() - 3 * kInstrSize;
  BranchLong(imm32);
}

void LiftoffAssembler::FinishCode() {}

void LiftoffAssembler::AbortCompilation() {}

// static
constexpr int LiftoffAssembler::StaticStackFrameSize() {
  return WasmLiftoffFrameConstants::kFeedbackVectorOffset;
}

int LiftoffAssembler::SlotSizeForType(ValueKind kind) {
  switch (kind) {
    case kS128:
      return value_kind_size(kind);
    default:
      return kStackSlotSize;
  }
}

bool LiftoffAssembler::NeedsAlignment(ValueKind kind) {
  return kind == kS128 || is_reference(kind);
}

void LiftoffAssembler::CheckTierUp(int declared_func_index, int budget_used,
                                   Label* ool_label,
                                   const FreezeCacheState& frozen) {
  Register budget_array = kScratchReg;

  Register instance_data = cache_state_.cached_instance_data;
  if (instance_data == no_reg) {
    instance_data = budget_array;  // Reuse the scratch register.
    LoadInstanceDataFromFrame(instance_data);
  }

  constexpr int kArrayOffset = wasm::ObjectAccess::ToTagged(
      WasmTrustedInstanceData::kTieringBudgetArrayOffset);
  Ld(budget_array, MemOperand(instance_data, kArrayOffset));

  int budget_arr_offset = kInt32Size * declared_func_index;

  Register budget = kScratchReg2;
  MemOperand budget_addr(budget_array, budget_arr_offset);
  Lw(budget, budget_addr);
  Subu(budget, budget, budget_used);
  Sw(budget, budget_addr);

  Branch(ool_label, less, budget, Operand(zero_reg));
}

Register LiftoffAssembler::LoadOldFramePointer() { return fp; }

void LiftoffAssembler::CheckStackShrink() {
  // TODO(mips64): 42202153
  UNIMPLEMENTED();
}

void LiftoffAssembler::LoadConstant(LiftoffRegister reg, WasmValue value) {
  switch (value.type().kind()) {
    case kI32:
      MacroAssembler::li(reg.gp(), Operand(value.to_i32()));
      break;
    case kI64:
      MacroAssembler::li(reg.gp(), Operand(value.to_i64()));
      break;
    case kF32:
      MacroAssembler::Move(reg.fp(), value.to_f32_boxed().get_bits());
      break;
    case kF64:
      MacroAssembler::Move(reg.fp(), value.to_f64_boxed().get_bits());
      break;
    default:
      UNREACHABLE();
  }
}

void LiftoffAssembler::LoadInstanceDataFromFrame(Register dst) {
  Ld(dst, liftoff::GetInstanceDataOperand());
}

void LiftoffAssembler::LoadTrustedPointer(Register dst, Register src_addr,
                                          int offset, IndirectPointerTag tag) {
  static_assert(!V8_ENABLE_SANDBOX_BOOL);
  static_assert(!COMPRESS_POINTERS_BOOL);
  Ld(dst, MemOperand{src_addr, offset});
}

void LiftoffAssembler::LoadFromInstance(Register dst, Register instance,
                                        int offset, int size) {
  DCHECK_LE(0, offset);
  switch (size) {
    case 1:
      Lb(dst, MemOperand(instance, offset));
      break;
    case 4:
      Lw(dst, MemOperand(instance, offset));
      break;
    case 8:
      Ld(dst, MemOperand(instance, offset));
      break;
    default:
      UNIMPLEMENTED();
  }
}

void LiftoffAssembler::LoadTaggedPointerFromInstance(Register dst,
                                                     Register instance,
                                                     int32_t offset) {
  static_assert(kTaggedSize == kSystemPointerSize);
  Ld(dst, MemOperand(instance, offset));
}

void LiftoffAssembler::SpillInstanceData(Register instance) {
  Sd(instance, liftoff::GetInstanceDataOperand());
}

void LiftoffAssembler::ResetOSRTarget() {}

void LiftoffAssembler::LoadTaggedPointer(Register dst, Register src_addr,
                                         Register offset_reg,
                                         int32_t offset_imm,
                                         uint32_t* protected_load_pc,
                                         bool needs_shift) {
  static_assert(kTaggedSize == kInt64Size);
  unsigned shift_amount = !needs_shift ? 0 : 3;
  MemOperand src_op = liftoff::GetMemOp(this, src_addr, offset_reg, offset_imm,
                                        false, shift_amount);
  Ld(dst, src_op);

  // Since LoadTaggedField might start with an instruction loading an immediate
  // argument to a register, we have to compute the {protected_load_pc} after
  // calling it.
  if (protected_load_pc) {
    *protected_load_pc = pc_offset() - kInstrSize;
  }
}

void LiftoffAssembler::LoadProtectedPointer(Register dst, Register src_addr,
                                            int32_t offset_imm) {
  static_assert(!V8_ENABLE_SANDBOX_BOOL);
  LoadTaggedPointer(dst, src_addr, no_reg, offset_imm);
}

void LiftoffAssembler::LoadFullPointer(Register dst, Register src_addr,
                                       int32_t offset_imm) {
  MemOperand src_op = liftoff::GetMemOp(this, src_addr, no_reg, offset_imm);
  Ld(dst, src_op);
}

void LiftoffAssembler::StoreTaggedPointer(Register dst_addr,
                                          Register offset_reg,
                                          int32_t offset_imm, Register src,
                                          LiftoffRegList pinned,
                                          uint32_t* protected_store_pc,
                                          SkipWriteBarrier skip_write_barrier) {
  static_assert(kTaggedSize == kInt64Size);
  Register scratch = kScratchReg2;
  MemOperand dst_op = liftoff::GetMemOp(this, dst_addr, offset_reg, offset_imm);
  Sd(src, dst_op);

  // Since StoreTaggedField might start with an instruction loading an immediate
  // argument to a register, we have to compute the {protected_load_pc} after
  // calling it.
  if (protected_store_pc) {
    *protected_store_pc = pc_offset() - kInstrSize;
  }

  if (skip_write_barrier || v8_flags.disable_write_barriers) return;

  Label exit;
  CheckPageFlag(dst_addr, scratch,
                MemoryChunk::kPointersFromHereAreInterestingMask, kZero, &exit);
  JumpIfSmi(src, &exit);
  CheckPageFlag(src, scratch, MemoryChunk::kPointersToHereAreInterestingMask,
                eq, &exit);
  Daddu(scratch, dst_op.rm(), dst_op.offset());
  CallRecordWriteStubSaveRegisters(dst_addr, scratch, SaveFPRegsMode::kSave,
                                   StubCallMode::kCallWasmRuntimeStub);
  bind(&exit);
}

void LiftoffAssembler::Load(LiftoffRegister dst, Register src_addr,
                            Register offset_reg, uintptr_t offset_imm,
                            LoadType type, uint32_t* protected_load_pc,
                            bool is_load_mem, bool i64_offset,
                            bool needs_shift) {
  unsigned shift_amount = needs_shift ? type.size_log_2() : 0;
  MemOperand src_op = liftoff::GetMemOp(this, src_addr, offset_reg, offset_imm,
                                        i64_offset, shift_amount);

  switch (type.value()) {
    case LoadType::kI32Load8U:
    case LoadType::kI64Load8U:
      Lbu(dst.gp(), src_op);
      break;
    case LoadType::kI32Load8S:
    case LoadType::kI64Load8S:
      Lb(dst.gp(), src_op);
      break;
    case LoadType::kI32Load16U:
    case LoadType::kI64Load16U:
      MacroAssembler::Ulhu(dst.gp(), src_op);
      break;
    case LoadType::kI32Load16S:
    case LoadType::kI64Load16S:
      MacroAssembler::Ulh(dst.gp(), src_op);
      break;
    case LoadType::kI64Load32U:
      MacroAssembler::Ulwu(dst.gp(), src_op);
      break;
    case LoadType::kI32Load:
    case LoadType::kI64Load32S:
      MacroAssembler::Ulw(dst.gp(), src_op);
      break;
    case LoadType::kI64Load:
      MacroAssembler::Uld(dst.gp(), src_op);
      break;
    case LoadType::kF32Load:
      MacroAssembler::Ulwc1(dst.fp(), src_op, t8);
      break;
    case LoadType::kF32LoadF16:
      UNIMPLEMENTED();
      break;
    case LoadType::kF64Load:
      MacroAssembler::Uldc1(dst.fp(), src_op, t8);
      break;
    case LoadType::kS128Load:
      MacroAssembler::ld_b(dst.fp().toW(), src_op);
      break;
    default:
      UNREACHABLE();
  }

#if defined(V8_TARGET_BIG_ENDIAN)
  if (is_load_mem) {
    pinned.set(src_op.rm());
    liftoff::ChangeEndiannessLoad(this, dst, type, pinned);
  }
#endif
  // Since load macros might start with an instruction loading an immediate
  // argument to a register, we have to compute the {protected_load_pc} after
  // calling them.
  if (protected_load_pc) {
    *protected_load_pc = pc_offset() - kInstrSize;
  }
}

void LiftoffAssembler::Store(Register dst_addr, Register offset_reg,
                             uintptr_t offset_imm, LiftoffRegister src,
                             StoreType type, LiftoffRegList pinned,
                             uint32_t* protected_store_pc, bool is_store_mem,
                             bool i64_offset) {
  MemOperand dst_op =
      liftoff::GetMemOp(this, dst_addr, offset_reg, offset_imm, i64_offset);

#if defined(V8_TARGET_BIG_ENDIAN)
  if (is_store_mem) {
    pinned.set(dst_op.rm());
    LiftoffRegister tmp = kScratchReg2;
    // Save original value.
    Move(tmp, src, type.value_type());

    src = tmp;
    pinned.set(tmp);
    liftoff::ChangeEndiannessStore(this, src, type, pinned);
  }
#endif

  switch (type.value()) {
    case StoreType::kI32Store8:
    case StoreType::kI64Store8:
      Sb(src.gp(), dst_op);
      break;
    case StoreType::kI32Store16:
    case StoreType::kI64Store16:
      MacroAssembler::Ush(src.gp(), dst_op, t8);
      break;
    case StoreType::kI32Store:
    case StoreType::kI64Store32:
      MacroAssembler::Usw(src.gp(), dst_op);
      break;
    case StoreType::kI64Store:
      MacroAssembler::Usd(src.gp(), dst_op);
      break;
    case StoreType::kF32Store:
      MacroAssembler::Uswc1(src.fp(), dst_op, t8);
      break;
    case StoreType::kF32StoreF16:
      UNIMPLEMENTED();
      break;
    case StoreType::kF64Store:
      MacroAssembler::Usdc1(src.fp(), dst_op, t8);
      break;
    case StoreType::kS128Store:
      MacroAssembler::st_b(src.fp().toW(), dst_op);
      break;
    default:
      UNREACHABLE();
  }

  // Since store macros might start with an instruction loading an immediate
  // argument to a register, we have to compute the {protected_store_pc} after
  // calling them.
  if (protected_store_pc) {
    *protected_store_pc = pc_offset() - kInstrSize;
  }
}

void LiftoffAssembler::AtomicLoad(LiftoffRegister dst, Register src_addr,
                                  Register offset_reg, uintptr_t offset_imm,
                                  LoadType type, LiftoffRegList pinned,
                                  bool i64_offset) {
  UseScratchRegisterScope temps(this);
  MemOperand src_op =
      liftoff::GetMemOp(this, src_addr, offset_reg, offset_imm, i64_offset);
  switch (type.value()) {
    case LoadType::kI32Load8U:
    case LoadType::kI64Load8U: {
      Lbu(dst.gp(), src_op);
      sync();
      return;
    }
    case LoadType::kI32Load16U:
    case LoadType::kI64Load16U: {
      Lhu(dst.gp(), src_op);
      sync();
      return;
    }
    case LoadType::kI32Load: {
      Lw(dst.gp(), src_op);
      sync();
      return;
    }
    case LoadType::kI64Load32U: {
      Lwu(dst.gp(), src_op);
      sync();
      return;
    }
    case LoadType::kI64Load: {
      Ld(dst.gp(), src_op);
      sync();
      return;
    }
    default:
      UNREACHABLE();
  }
}

void LiftoffAssembler::AtomicStore(Register dst_addr, Register offset_reg,
                                   uintptr_t offset_imm, LiftoffRegister src,
                                   StoreType type, LiftoffRegList pinned,
                                   bool i64_offset) {
  UseScratchRegisterScope temps(this);
  MemOperand dst_op =
      liftoff::GetMemOp(this, dst_addr, offset_reg, offset_imm, i64_offset);
  switch (type.value()) {
    case StoreType::kI64Store8:
    case StoreType::kI32Store8: {
      sync();
      Sb(src.gp(), dst_op);
      return;
    }
    case StoreType::kI64Store16:
    case StoreType::kI32Store16: {
      sync();
      Sh(src.gp(), dst_op);
      return;
    }
    case StoreType::kI64Store32:
    case StoreType::kI32Store: {
      sync();
      Sw(src.gp(), dst_op);
      return;
    }
    case StoreType::kI64Store: {
      sync();
      Sd(src.gp(), dst_op);
      return;
    }
    default:
      UNREACHABLE();
  }
}

#define ASSEMBLE_ATOMIC_BINOP(load_linked, store_conditional, bin_instr) \
  do {                                                                   \
    Label binop;                                                         \
    sync();                                                              \
    bind(&binop);                                                        \
    load_linked(result.gp(), MemOperand(temp0, 0));                      \
    bin_instr(temp1, result.gp(), Operand(value.gp()));                  \
    store_conditional(temp1, MemOperand(temp0, 0));                      \
    BranchShort(&binop, eq, temp1, Operand(zero_reg));                   \
    sync();                                                              \
  } while (0)

#define ASSEMBLE_ATOMIC_BINOP_EXT(load_linked, store_conditional, size, \
                                  bin_instr, aligned)                   \
  do {                                                                  \
    Label binop;                                                        \
    andi(temp3, temp0, aligned);                                        \
    Dsubu(temp0, temp0, Operand(temp3));                                \
    sll(temp3, temp3, 3);                                               \
    sync();                                                             \
    bind(&binop);                                                       \
    load_linked(temp1, MemOperand(temp0, 0));                           \
    ExtractBits(result.gp(), temp1, temp3, size, false);                \
    bin_instr(temp2, result.gp(), value.gp());                          \
    InsertBits(temp1, temp2, temp3, size);                              \
    store_conditional(temp1, MemOperand(temp0, 0));                     \
    BranchShort(&binop, eq, temp1, Operand(zero_reg));                  \
    sync();                                                             \
  } while (0)

#define ATOMIC_BINOP_CASE(name, inst32, inst64)                                \
  void LiftoffAssembler::Atomic##name(                                         \
      Register dst_addr, Register offset_reg, uintptr_t offset_imm,            \
      LiftoffRegister value, LiftoffRegister result, StoreType type,           \
      bool i64_offset) {                                                       \
    LiftoffRegList pinned{dst_addr, value, result};                            \
    if (offset_reg != no_reg) pinned.set(offset_reg);                          \
    Register temp0 = pinned.set(GetUnusedRegister(kGpReg, pinned)).gp();       \
    Register temp1 = pinned.set(GetUnusedRegister(kGpReg, pinned)).gp();       \
    Register temp2 = pinned.set(GetUnusedRegister(kGpReg, pinned)).gp();       \
    Register temp3 = pinned.set(GetUnusedRegister(kGpReg, pinned)).gp();       \
    MemOperand dst_op =                                                        \
        liftoff::GetMemOp(this, dst_addr, offset_reg, offset_imm, i64_offset); \
    Daddu(temp0, dst_op.rm(), dst_op.offset());                                \
    switch (type.value()) {                                                    \
      case StoreType::kI64Store8:                                              \
        ASSEMBLE_ATOMIC_BINOP_EXT(Lld, Scd, 8, inst64, 7);                     \
        break;                                                                 \
      case StoreType::kI32Store8:                                              \
        ASSEMBLE_ATOMIC_BINOP_EXT(Ll, Sc, 8, inst32, 3);                       \
        break;                                                                 \
      case StoreType::kI64Store16:                                             \
        ASSEMBLE_ATOMIC_BINOP_EXT(Lld, Scd, 16, inst64, 7);                    \
        break;                                                                 \
      case StoreType::kI32Store16:                                             \
        ASSEMBLE_ATOMIC_BINOP_EXT(Ll, Sc, 16, inst32, 3);                      \
        break;                                                                 \
      case StoreType::kI64Store32:                                             \
        ASSEMBLE_ATOMIC_BINOP_EXT(Lld, Scd, 32, inst64, 7);                    \
        break;                                                                 \
      case StoreType::kI32Store:                                               \
        ASSEMBLE_ATOMIC_BINOP(Ll, Sc, inst32);                                 \
        break;                                                                 \
      case StoreType::kI64Store:                                               \
        ASSEMBLE_ATOMIC_BINOP(Lld, Scd, inst64);                               \
        break;                                                                 \
      default:                                                                 \
        UNREACHABLE();                                                         \
    }                                                                          \
  }

ATOMIC_BINOP_CASE(Add, Addu, Daddu)
ATOMIC_BINOP_CASE(Sub, Subu, Dsubu)
ATOMIC_BINOP_CASE(And, And, And)
ATOMIC_BINOP_CASE(Or, Or, Or)
ATOMIC_BINOP_CASE(Xor, Xor, Xor)
#undef ASSEMBLE_ATOMIC_BINOP
#undef ASSEMBLE_ATOMIC_BINOP_EXT
#undef ATOMIC_BINOP_CASE

#define ASSEMBLE_ATOMIC_EXCHANGE_INTEGER(load_linked, store_conditional) \
  do {                                                                   \
    Label exchange;                                                      \
    sync();                                                              \
    bind(&exchange);                                                     \
    load_linked(result.gp(), MemOperand(temp0, 0));                      \
    mov(temp1, value.gp());                                              \
    store_conditional(temp1, MemOperand(temp0, 0));                      \
    BranchShort(&exchange, eq, temp1, Operand(zero_reg));                \
    sync();                                                              \
  } while (0)

#define ASSEMBLE_ATOMIC_EXCHANGE_INTEGER_EXT(load_linked, store_conditional, \
                                             size, aligned)                  \
  do {                                                                       \
    Label exchange;                                                          \
    andi(temp1, temp0, aligned);                                             \
    Dsubu(temp0, temp0, Operand(temp1));                                     \
    sll(temp1, temp1, 3);                                                    \
    sync();                                                                  \
    bind(&exchange);                                                         \
    load_linked(temp2, MemOperand(temp0, 0));                                \
    ExtractBits(result.gp(), temp2, temp1, size, false);
```