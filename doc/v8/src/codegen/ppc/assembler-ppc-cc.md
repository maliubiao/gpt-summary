Response:
The user wants a summary of the provided C++ code snippet. The request includes several specific points to address:

1. **Functionality:** What does the code do?
2. **Torque Source:** Would it be a Torque file if the extension were `.tq`?
3. **JavaScript Relation:** Does it relate to JavaScript, and if so, how? Provide a JavaScript example.
4. **Code Logic Inference:**  If there's code logic, give example input and output.
5. **Common Programming Errors:** Are there related common errors?
6. **Overall Functionality (Part 1):**  A summary of the code's purpose.

Let's break down the code to answer these points:

* **Copyright and License:** Standard licensing information. Ignore for functionality.
* **Includes:**  Including `assembler-ppc.h` and other V8 headers suggests this code is for the PPC architecture within the V8 JavaScript engine.
* **Conditional Includes:**  `__PASE__` likely refers to IBM i (AS/400), indicating platform-specific considerations. `V8_TARGET_ARCH_PPC64` confirms it's for 64-bit PPC.
* **`CpuFeatures` Namespace:** This section deals with detecting and reporting CPU capabilities (like Power 8, 9, 10 support and SIMD). This is crucial for V8 to leverage hardware-specific optimizations.
* **`ToRegister` Function:**  A utility to convert an integer to a `Register` enum, likely for code generation.
* **`RelocInfo` Namespace:** Handles relocation information, which is essential when generating machine code. It deals with patching addresses and references.
* **`Operand` and `MemOperand`:** These classes represent operands for instructions, including immediate values, memory locations, and special embedded objects like HeapNumbers.
* **`Assembler` Class:** This is the core of the code generator. It provides methods to emit PPC instructions, manage labels, handle constant pools, and generate the final code.
* **Instruction Emission Functions:**  Functions like `a_form`, `d_form`, `xo_form`, etc., correspond to different PPC instruction formats and are used to write raw instruction bytes.
* **Branching and Label Management:**  Code for handling labels, linking them, and emitting branch instructions. Includes logic for handling long branches via trampolines.
* **PPC Instruction Implementations:**  A large number of functions like `bclr`, `bcctr`, `bc`, `add`, `sub`, `lwz`, `stw`, etc., which directly correspond to PPC assembly instructions.

Now, let's address the user's specific questions:

1. **Functionality:** The code provides the `Assembler` class, a core component for generating PPC machine code within the V8 JavaScript engine. It handles instruction encoding, relocation, label management, and CPU feature detection.

2. **Torque Source:** The file extension is `.cc`, which is standard for C++ source files. A `.tq` extension indicates a Torque source file in V8. Thus, if the extension were `.tq`, it *would* be a V8 Torque source file.

3. **JavaScript Relation:** This code is directly involved in the process of taking JavaScript code and compiling it into machine code that can run on a PPC processor. For example, when you write `const x = 1 + 2;`, V8 needs to generate PPC instructions to perform the addition and store the result. The `Assembler` class is used to generate these instructions.

4. **Code Logic Inference:**  A good example of code logic is in the label binding and branching mechanisms.

   * **Assumption:** We have a forward jump to a label `L`.
   * **Input:** A call to `b(L)` before `L` is bound.
   * **Process:** The assembler will emit a branch instruction with a placeholder offset and link the current position to the label `L`.
   * **Input:**  Later, `bind(L)` is called at a specific code position.
   * **Process:** The assembler calculates the offset between the branch instruction and the label's bound position and patches the branch instruction with the correct offset. If the offset is too large for a direct branch, it uses a trampoline.

5. **Common Programming Errors:** A common error when working with assemblers is incorrect offset calculations for jumps, especially when dealing with forward references. Forgetting to align code or data correctly can also lead to issues. In this V8 context, developers working on the PPC backend might incorrectly calculate offsets or misinterpret the semantics of PPC instructions.

6. **Overall Functionality (Part 1):** This part of the `assembler-ppc.cc` file focuses on the foundational aspects of assembling PPC machine code within V8. It includes CPU feature detection, the core `Assembler` class with its instruction emission methods, and the logic for handling labels and branches. It sets the stage for more complex code generation tasks.这是v8 JavaScript引擎中用于PowerPC (PPC) 架构的代码生成器的第一部分。它定义了`Assembler`类，该类负责将高级的、与体系结构无关的表示（例如中间代码）转换为实际的PPC机器指令。

以下是其功能的详细列表：

1. **CPU 功能检测 (`CpuFeatures`):**
   - 探测并存储目标PPC处理器的功能，例如是否支持Power 8、Power 9、Power 10 指令集以及 WebAssembly SIMD (Single Instruction, Multiple Data) 扩展。
   - 这允许V8根据运行时的硬件能力生成优化的代码。
   - `ProbeImpl` 函数负责在运行时检测CPU特性。
   - `SupportsWasmSimd128` 检查是否支持Wasm SIMD。
   - `PrintTarget` 和 `PrintFeatures` 用于打印目标架构和支持的特性。

2. **寄存器映射 (`ToRegister`):**
   - 提供一个实用函数，将寄存器编号（整数）转换为 `Register` 枚举类型，方便在代码中使用符号化的寄存器名称。

3. **重定位信息 (`RelocInfo`):**
   - 管理代码中需要稍后修改的地址和引用的信息，例如嵌入的对象指针或函数调用目标。
   - `IsCodedSpecially` 表明PPC上的指针是否经过特殊编码（例如使用 `lis/ori` 指令序列）。
   - `IsInConstantPool` 检查当前位置是否在常量池中。
   - `wasm_call_tag` 用于获取 WebAssembly 调用的标签。

4. **操作数表示 (`Operand`, `MemOperand`):**
   - 定义了 `Operand` 类，用于表示指令的操作数，可以是寄存器、立即数、嵌入的对象句柄或堆数字。
   - `MemOperand` 类用于表示内存操作数，包括基址寄存器和偏移量。
   - `EmbeddedNumber` 静态方法用于创建表示双精度浮点数的 `Operand`，如果可以表示为小的整数，则优先使用Smi。
   - `AllocateAndInstallRequestedHeapNumbers` 函数在代码生成完成后，将请求的堆数字分配到堆上，并将它们的地址写入到代码段中。

5. **汇编器核心 (`Assembler`):**
   - `Assembler` 类是代码生成的核心，它继承自 `AssemblerBase` 并提供了特定于PPC架构的功能。
   - 它管理汇编缓冲区、重定位信息写入器和常量池构建器。
   - `GetCode` 函数用于获取生成的机器代码，并填充 `CodeDesc` 结构，其中包含代码的各种元数据，例如安全点表、处理程序表和常量池的偏移量。
   - `Align` 和 `CodeTargetAlign` 函数用于确保代码在内存中对齐到特定的边界，这对于性能至关重要。
   - `GetCondition` 用于从指令中提取条件码。
   - 提供了一系列用于检查特定PPC指令类型 (`IsLis`, `IsLi`, `IsBranch` 等) 的函数。
   - 提供了用于提取指令中寄存器 (`GetRA`, `GetRB`) 和立即数 (`GetCmpImmediateRawImmediate`) 的函数。

6. **标签管理 (`Label`):**
   - 实现了标签 (`Label`) 的概念，用于在代码中标记位置，以便进行跳转和引用。
   - `target_at` 和 `target_at_put` 用于获取和设置跳转指令的目标地址。
   - `bind_to` 和 `bind` 函数用于将标签绑定到代码中的特定位置。
   - `next` 函数用于遍历已链接的标签。
   - `is_near` 函数用于检查从当前位置到标签的距离是否在短跳转的范围内。

7. **指令发射 (`a_form`, `d_form`, `xo_form` 等):**
   - 提供了一组低级函数，用于将操作码和操作数编码成机器指令的不同格式。

8. **分支指令 (`b`, `bc`, `blr`, `bctr` 等):**
   - 提供了各种分支指令的封装，允许根据条件或无条件地跳转到代码中的其他位置。
   - 实现了对长跳转的处理，如果目标地址超出短跳转的范围，则使用跳转表（trampoline）。

9. **算术和逻辑指令 (`addi`, `subi`, `andi`, `ori`, `xor` 等):**
   - 提供了各种算术和逻辑运算指令的封装，用于执行基本的计算操作。

10. **比较指令 (`cmpi`, `cmpli`, `cmpwi`, `cmplwi`):**
    - 提供了比较立即数和寄存器值的指令，并根据比较结果设置条件码寄存器。

11. **加载和存储指令 (`lbz`, `lwz`, `stb`, `stw` 等):**
    - 提供了从内存加载数据到寄存器以及将寄存器数据存储到内存的指令。

**如果 `v8/src/codegen/ppc/assembler-ppc.cc` 以 `.tq` 结尾：**

如果 `v8/src/codegen/ppc/assembler-ppc.cc` 以 `.tq` 结尾，那么它将是一个 **v8 Torque 源代码**文件。 Torque 是一种 V8 特有的领域特定语言（DSL），用于生成高效的 C++ 代码，通常用于实现内置函数和运行时代码。 Torque 代码会被编译成 C++ 代码，然后与 V8 的其他部分一起编译。

**与 JavaScript 的关系：**

`assembler-ppc.cc` 直接参与 JavaScript 代码的执行过程。当 V8 编译 JavaScript 代码时，它会生成特定于目标架构的机器代码。 `Assembler` 类是生成 PPC 架构机器代码的关键组件。

**JavaScript 示例：**

例如，考虑以下简单的 JavaScript 代码：

```javascript
function add(a, b) {
  return a + b;
}

add(5, 10);
```

当 V8 编译 `add` 函数时，`assembler-ppc.cc` 中的代码将被用来生成执行加法运算的 PPC 指令，例如：

- 将参数 `a` 和 `b` 加载到寄存器中。
- 使用 `add` 指令执行加法操作。
- 将结果存储回寄存器或内存。
- 返回结果。

**代码逻辑推理：**

**假设输入：**

- 调用 `Assembler::b(&myLabel)`，其中 `myLabel` 是一个尚未绑定的标签。
- 随后调用 `Assembler::bind(&myLabel)`，当前程序计数器 (PC) 的偏移量为 `0x1000`。
- 在调用 `b(&myLabel)` 时的 PC 偏移量是 `0x0FF0`。

**输出：**

1. 当调用 `b(&myLabel)` 时，由于 `myLabel` 未绑定，汇编器会生成一个跳转指令，其目标地址暂时设置为一个占位符，并将 `myLabel` 链接到当前指令的位置 (`0x0FF0`)。
2. 当调用 `bind(&myLabel)` 时，汇编器会计算从跳转指令位置 (`0x0FF0`) 到标签绑定位置 (`0x1000`) 的偏移量，即 `0x1000 - 0x0FF0 = 0x10`。
3. 汇编器会回过头来修改地址 `0x0FF0` 处的跳转指令，将占位符替换为计算出的偏移量 `0x10`，生成一个指向地址 `0x1000` 的相对跳转指令。

**用户常见的编程错误：**

在使用汇编器进行底层编程时，用户可能会犯以下常见错误：

1. **寄存器分配错误：** 错误地使用或覆盖了保存重要值的寄存器，导致程序逻辑错误。例如，错误地将返回值覆盖掉。
   ```cpp
   // 假设 r3 需要保存返回值
   asm_.Add(r3, r4, r5); // 正确计算结果
   asm_.Mov(r6, r3);     // 错误地将结果移动到另一个寄存器，可能会被后续操作覆盖
   // ... 其他操作，可能会修改 r3 的值
   asm_.Mr(r3, r6);     // 尝试恢复返回值，但 r3 的值可能已改变
   ```

2. **偏移量计算错误：** 在访问内存时，错误地计算偏移量，导致访问到错误的内存地址，可能导致崩溃或数据损坏。
   ```cpp
   // 假设需要访问数组的第二个元素（大小为 4 字节）
   asm_.Lwz(r3, MemOperand(r4, 4)); // 正确的偏移量
   asm_.Lwz(r3, MemOperand(r4, 8)); // 错误的偏移量，访问了第三个元素
   ```

3. **条件码使用错误：** 在使用条件分支时，没有正确理解或检查条件码的状态，导致程序执行路径错误。
   ```cpp
   asm_.Cmpw(r3, Operand(0));
   asm_.Beq(&label_true); // 假设 r3 == 0 时跳转
   // ... r3 的值可能在比较后被修改
   asm_.Bne(&label_false); // 错误地假设如果之前没有跳转，则 r3 != 0
   ```

4. **指令语义误解：** 没有完全理解 PPC 指令的含义和副作用，导致使用了错误的指令或以错误的方式使用指令。例如，混淆了带符号和无符号的比较指令。

5. **内存对齐问题：**  某些 PPC 指令要求数据在内存中对齐到特定的边界。如果尝试访问未对齐的数据，可能会导致错误或性能下降。例如，尝试使用 `lwz` 加载一个地址不是 4 字节对齐的数据。

**归纳一下它的功能 (第 1 部分)：**

`v8/src/codegen/ppc/assembler-ppc.cc` 的第一部分主要负责搭建 PPC 架构代码生成的基础框架。它提供了以下核心功能：

- **CPU 功能的检测和管理**，以便根据目标硬件生成优化的代码。
- **寄存器的抽象表示**，方便在代码中使用符号化的寄存器名称。
- **重定位信息的管理**，用于处理需要稍后修改的地址和引用。
- **操作数的表示**，包括寄存器、立即数和内存操作数。
- **核心汇编器类的实现**，提供了发射 PPC 指令、管理标签和生成最终机器代码的基本功能。
- **基本指令的封装**，包括分支、算术、逻辑和比较指令。
- **内存加载和存储指令的封装**。

总而言之，这部分代码是构建 V8 中 PPC 代码生成器的基石，它定义了关键的数据结构和方法，使得可以将高级表示的 JavaScript 代码转换为可以在 PPC 处理器上执行的低级机器指令。

### 提示词
```
这是目录为v8/src/codegen/ppc/assembler-ppc.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/ppc/assembler-ppc.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright (c) 1994-2006 Sun Microsystems Inc.
// All Rights Reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
//
// - Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
//
// - Redistribution in binary form must reproduce the above copyright
// notice, this list of conditions and the following disclaimer in the
// documentation and/or other materials provided with the
// distribution.
//
// - Neither the name of Sun Microsystems or the names of contributors may
// be used to endorse or promote products derived from this software without
// specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
// FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
// COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
// INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
// OF THE POSSIBILITY OF SUCH DAMAGE.

// The original source code covered by the above license above has been
// modified significantly by Google Inc.
// Copyright 2014 the V8 project authors. All rights reserved.

#include "src/codegen/ppc/assembler-ppc.h"

#if defined(__PASE__)
#include <sys/utsname.h>
#endif

#if V8_TARGET_ARCH_PPC64

#include "src/base/bits.h"
#include "src/base/cpu.h"
#include "src/codegen/macro-assembler.h"
#include "src/codegen/ppc/assembler-ppc-inl.h"
#include "src/deoptimizer/deoptimizer.h"

namespace v8 {
namespace internal {

// Get the CPU features enabled by the build.
static unsigned CpuFeaturesImpliedByCompiler() {
  unsigned answer = 0;
  return answer;
}

bool CpuFeatures::SupportsWasmSimd128() {
#if V8_ENABLE_WEBASSEMBLY
  return CpuFeatures::IsSupported(PPC_9_PLUS);
#else
  return false;
#endif  // V8_ENABLE_WEBASSEMBLY
}

void CpuFeatures::ProbeImpl(bool cross_compile) {
  supported_ |= CpuFeaturesImpliedByCompiler();
  icache_line_size_ = 128;

  // Only use statically determined features for cross compile (snapshot).
  if (cross_compile) return;

// Probe for additional features at runtime.
#ifdef USE_SIMULATOR
  // Simulator
  supported_ |= (1u << PPC_10_PLUS);
#else
  base::CPU cpu;
  if (cpu.part() == base::CPU::kPPCPower10) {
#if defined(__PASE__)
    // Some P10 features such as prefixed isns will only be supported in future
    // ibmi versions. We only enable full power 10 features if version>7.4
    struct utsname uts;
    memset(reinterpret_cast<void*>(&uts), 0, sizeof(uts));
    int r = uname(&uts);
    CHECK_GE(r, 0);
    int rel = atoi(uts.release);
    if (rel > 4) {
      supported_ |= (1u << PPC_10_PLUS);
    } else {
      supported_ |= (1u << PPC_9_PLUS);
    }
#else
    supported_ |= (1u << PPC_10_PLUS);
#endif
  } else if (cpu.part() == base::CPU::kPPCPower9) {
    supported_ |= (1u << PPC_9_PLUS);
  } else if (cpu.part() == base::CPU::kPPCPower8) {
    supported_ |= (1u << PPC_8_PLUS);
  }
#if V8_OS_LINUX
  if (cpu.icache_line_size() != base::CPU::kUnknownCacheLineSize) {
    icache_line_size_ = cpu.icache_line_size();
  }
#endif
#endif
  if (supported_ & (1u << PPC_10_PLUS)) supported_ |= (1u << PPC_9_PLUS);
  if (supported_ & (1u << PPC_9_PLUS)) supported_ |= (1u << PPC_8_PLUS);

  // Set a static value on whether Simd is supported.
  // This variable is only used for certain archs to query SupportWasmSimd128()
  // at runtime in builtins using an extern ref. Other callers should use
  // CpuFeatures::SupportWasmSimd128().
  CpuFeatures::supports_wasm_simd_128_ = CpuFeatures::SupportsWasmSimd128();
}

void CpuFeatures::PrintTarget() {
  const char* ppc_arch = nullptr;
  ppc_arch = "ppc64";
  printf("target %s\n", ppc_arch);
}

void CpuFeatures::PrintFeatures() {
  printf("PPC_8_PLUS=%d\n", CpuFeatures::IsSupported(PPC_8_PLUS));
  printf("PPC_9_PLUS=%d\n", CpuFeatures::IsSupported(PPC_9_PLUS));
  printf("PPC_10_PLUS=%d\n", CpuFeatures::IsSupported(PPC_10_PLUS));
}

Register ToRegister(int num) {
  DCHECK(num >= 0 && num < kNumRegisters);
  const Register kRegisters[] = {r0,  sp,  r2,  r3,  r4,  r5,  r6,  r7,
                                 r8,  r9,  r10, r11, ip,  r13, r14, r15,
                                 r16, r17, r18, r19, r20, r21, r22, r23,
                                 r24, r25, r26, r27, r28, r29, r30, fp};
  return kRegisters[num];
}

// -----------------------------------------------------------------------------
// Implementation of RelocInfo

const int RelocInfo::kApplyMask =
    RelocInfo::ModeMask(RelocInfo::INTERNAL_REFERENCE) |
    RelocInfo::ModeMask(RelocInfo::INTERNAL_REFERENCE_ENCODED);

bool RelocInfo::IsCodedSpecially() {
  // The deserializer needs to know whether a pointer is specially
  // coded.  Being specially coded on PPC means that it is a lis/ori
  // instruction sequence or is a constant pool entry, and these are
  // always the case inside code objects.
  return true;
}

bool RelocInfo::IsInConstantPool() {
  if (V8_EMBEDDED_CONSTANT_POOL_BOOL && constant_pool_ != kNullAddress) {
    return Assembler::IsConstantPoolLoadStart(pc_);
  }
  return false;
}

uint32_t RelocInfo::wasm_call_tag() const {
  DCHECK(rmode_ == WASM_CALL || rmode_ == WASM_STUB_CALL);
  return static_cast<uint32_t>(
      Assembler::target_address_at(pc_, constant_pool_));
}

// -----------------------------------------------------------------------------
// Implementation of Operand and MemOperand
// See assembler-ppc-inl.h for inlined constructors

Operand::Operand(Handle<HeapObject> handle) {
  rm_ = no_reg;
  value_.immediate = static_cast<intptr_t>(handle.address());
  rmode_ = RelocInfo::FULL_EMBEDDED_OBJECT;
}

Operand Operand::EmbeddedNumber(double value) {
  int32_t smi;
  if (DoubleToSmiInteger(value, &smi)) return Operand(Smi::FromInt(smi));
  Operand result(0, RelocInfo::FULL_EMBEDDED_OBJECT);
  result.is_heap_number_request_ = true;
  result.value_.heap_number_request = HeapNumberRequest(value);
  return result;
}

MemOperand::MemOperand(Register rn, int64_t offset)
    : ra_(rn), offset_(offset), rb_(no_reg) {}

MemOperand::MemOperand(Register ra, Register rb)
    : ra_(ra), offset_(0), rb_(rb) {}

MemOperand::MemOperand(Register ra, Register rb, int64_t offset)
    : ra_(ra), offset_(offset), rb_(rb) {}

void Assembler::AllocateAndInstallRequestedHeapNumbers(LocalIsolate* isolate) {
  DCHECK_IMPLIES(isolate == nullptr, heap_number_requests_.empty());
  for (auto& request : heap_number_requests_) {
    Handle<HeapObject> object =
        isolate->factory()->NewHeapNumber<AllocationType::kOld>(
            request.heap_number());
    Address pc = reinterpret_cast<Address>(buffer_start_) + request.offset();
    Address constant_pool = kNullAddress;
    set_target_address_at(pc, constant_pool, object.address(), nullptr,
                          SKIP_ICACHE_FLUSH);
  }
}

// -----------------------------------------------------------------------------
// Specific instructions, constants, and masks.

Assembler::Assembler(const AssemblerOptions& options,
                     std::unique_ptr<AssemblerBuffer> buffer)
    : AssemblerBase(options, std::move(buffer)),
      scratch_register_list_({ip}),
      constant_pool_builder_(kLoadPtrMaxReachBits, kLoadDoubleMaxReachBits) {
  reloc_info_writer.Reposition(buffer_start_ + buffer_->size(), pc_);

  no_trampoline_pool_before_ = 0;
  trampoline_pool_blocked_nesting_ = 0;
  constant_pool_entry_sharing_blocked_nesting_ = 0;
  next_trampoline_check_ = kMaxInt;
  internal_trampoline_exception_ = false;
  last_bound_pos_ = 0;
  optimizable_cmpi_pos_ = -1;
  trampoline_emitted_ = v8_flags.force_long_branches;
  tracked_branch_count_ = 0;
  relocations_.reserve(128);
}

void Assembler::GetCode(Isolate* isolate, CodeDesc* desc) {
  GetCode(isolate->main_thread_local_isolate(), desc);
}
void Assembler::GetCode(LocalIsolate* isolate, CodeDesc* desc,
                        SafepointTableBuilderBase* safepoint_table_builder,
                        int handler_table_offset) {
  // As a crutch to avoid having to add manual Align calls wherever we use a
  // raw workflow to create InstructionStream objects (mostly in tests), add
  // another Align call here. It does no harm - the end of the InstructionStream
  // object is aligned to the (larger) kCodeAlignment anyways.
  // TODO(jgruber): Consider moving responsibility for proper alignment to
  // metadata table builders (safepoint, handler, constant pool, code
  // comments).
  DataAlign(InstructionStream::kMetadataAlignment);

  // Emit constant pool if necessary.
  int constant_pool_size = EmitConstantPool();

  EmitRelocations();

  int code_comments_size = WriteCodeComments();

  AllocateAndInstallRequestedHeapNumbers(isolate);

  // Set up code descriptor.
  // TODO(jgruber): Reconsider how these offsets and sizes are maintained up to
  // this point to make CodeDesc initialization less fiddly.

  static constexpr int kBuiltinJumpTableInfoSize = 0;
  const int instruction_size = pc_offset();
  const int builtin_jump_table_info_offset =
      instruction_size - kBuiltinJumpTableInfoSize;
  const int code_comments_offset =
      builtin_jump_table_info_offset - code_comments_size;
  const int constant_pool_offset = code_comments_offset - constant_pool_size;
  const int handler_table_offset2 = (handler_table_offset == kNoHandlerTable)
                                        ? constant_pool_offset
                                        : handler_table_offset;
  const int safepoint_table_offset =
      (safepoint_table_builder == kNoSafepointTable)
          ? handler_table_offset2
          : safepoint_table_builder->safepoint_table_offset();
  const int reloc_info_offset =
      static_cast<int>(reloc_info_writer.pos() - buffer_->start());
  CodeDesc::Initialize(desc, this, safepoint_table_offset,
                       handler_table_offset2, constant_pool_offset,
                       code_comments_offset, builtin_jump_table_info_offset,
                       reloc_info_offset);
}

void Assembler::Align(int m) {
  DCHECK(m >= 4 && base::bits::IsPowerOfTwo(m));
  DCHECK_EQ(pc_offset() & (kInstrSize - 1), 0);
  while ((pc_offset() & (m - 1)) != 0) {
    nop();
  }
}

void Assembler::CodeTargetAlign() { Align(8); }

Condition Assembler::GetCondition(Instr instr) {
  switch (instr & kCondMask) {
    case BT:
      return eq;
    case BF:
      return ne;
    default:
      UNIMPLEMENTED();
  }
}

bool Assembler::IsLis(Instr instr) {
  return ((instr & kOpcodeMask) == ADDIS) && GetRA(instr) == r0;
}

bool Assembler::IsLi(Instr instr) {
  return ((instr & kOpcodeMask) == ADDI) && GetRA(instr) == r0;
}

bool Assembler::IsAddic(Instr instr) { return (instr & kOpcodeMask) == ADDIC; }

bool Assembler::IsOri(Instr instr) { return (instr & kOpcodeMask) == ORI; }

bool Assembler::IsBranch(Instr instr) { return ((instr & kOpcodeMask) == BCX); }

Register Assembler::GetRA(Instr instr) {
  return Register::from_code(Instruction::RAValue(instr));
}

Register Assembler::GetRB(Instr instr) {
  return Register::from_code(Instruction::RBValue(instr));
}

// This code assumes a FIXED_SEQUENCE for 64bit loads (lis/ori)
bool Assembler::Is64BitLoadIntoR12(Instr instr1, Instr instr2, Instr instr3,
                                   Instr instr4, Instr instr5) {
  // Check the instructions are indeed a five part load (into r12)
  // 3d800000       lis     r12, 0
  // 618c0000       ori     r12, r12, 0
  // 798c07c6       rldicr  r12, r12, 32, 31
  // 658c00c3       oris    r12, r12, 195
  // 618ccd40       ori     r12, r12, 52544
  return (((instr1 >> 16) == 0x3D80) && ((instr2 >> 16) == 0x618C) &&
          (instr3 == 0x798C07C6) && ((instr4 >> 16) == 0x658C) &&
          ((instr5 >> 16) == 0x618C));
}

bool Assembler::IsCmpRegister(Instr instr) {
  return (((instr & kOpcodeMask) == EXT2) &&
          ((EXT2 | (instr & kExt2OpcodeMask)) == CMP));
}

bool Assembler::IsRlwinm(Instr instr) {
  return ((instr & kOpcodeMask) == RLWINMX);
}

bool Assembler::IsAndi(Instr instr) { return ((instr & kOpcodeMask) == ANDIx); }

bool Assembler::IsRldicl(Instr instr) {
  return (((instr & kOpcodeMask) == EXT5) &&
          ((EXT5 | (instr & kExt5OpcodeMask)) == RLDICL));
}

bool Assembler::IsCmpImmediate(Instr instr) {
  return ((instr & kOpcodeMask) == CMPI);
}

bool Assembler::IsCrSet(Instr instr) {
  return (((instr & kOpcodeMask) == EXT1) &&
          ((EXT1 | (instr & kExt1OpcodeMask)) == CREQV));
}

Register Assembler::GetCmpImmediateRegister(Instr instr) {
  DCHECK(IsCmpImmediate(instr));
  return GetRA(instr);
}

int Assembler::GetCmpImmediateRawImmediate(Instr instr) {
  DCHECK(IsCmpImmediate(instr));
  return instr & kOff16Mask;
}

// Labels refer to positions in the (to be) generated code.
// There are bound, linked, and unused labels.
//
// Bound labels refer to known positions in the already
// generated code. pos() is the position the label refers to.
//
// Linked labels refer to unknown positions in the code
// to be generated; pos() is the position of the last
// instruction using the label.

// The link chain is terminated by a negative code position (must be aligned)
const int kEndOfChain = -4;

// Dummy opcodes for unbound label mov instructions or jump table entries.
enum {
  kUnboundMovLabelOffsetOpcode = 0 << 26,
  kUnboundAddLabelOffsetOpcode = 1 << 26,
  kUnboundAddLabelLongOffsetOpcode = 2 << 26,
  kUnboundMovLabelAddrOpcode = 3 << 26,
  kUnboundJumpTableEntryOpcode = 4 << 26
};

int Assembler::target_at(int pos) {
  Instr instr = instr_at(pos);
  // check which type of branch this is 16 or 26 bit offset
  uint32_t opcode = instr & kOpcodeMask;
  int link;
  switch (opcode) {
    case BX:
      link = SIGN_EXT_IMM26(instr & kImm26Mask);
      link &= ~(kAAMask | kLKMask);  // discard AA|LK bits if present
      break;
    case BCX:
      link = SIGN_EXT_IMM16((instr & kImm16Mask));
      link &= ~(kAAMask | kLKMask);  // discard AA|LK bits if present
      break;
    case kUnboundMovLabelOffsetOpcode:
    case kUnboundAddLabelOffsetOpcode:
    case kUnboundAddLabelLongOffsetOpcode:
    case kUnboundMovLabelAddrOpcode:
    case kUnboundJumpTableEntryOpcode:
      link = SIGN_EXT_IMM26(instr & kImm26Mask);
      link <<= 2;
      break;
    default:
      DCHECK(false);
      return -1;
  }

  if (link == 0) return kEndOfChain;
  return pos + link;
}

void Assembler::target_at_put(int pos, int target_pos, bool* is_branch) {
  Instr instr = instr_at(pos);
  uint32_t opcode = instr & kOpcodeMask;

  if (is_branch != nullptr) {
    *is_branch = (opcode == BX || opcode == BCX);
  }

  switch (opcode) {
    case BX: {
      int imm26 = target_pos - pos;
      CHECK(is_int26(imm26) && (imm26 & (kAAMask | kLKMask)) == 0);
      if (imm26 == kInstrSize && !(instr & kLKMask)) {
        // Branch to next instr without link.
        instr = ORI;  // nop: ori, 0,0,0
      } else {
        instr &= ((~kImm26Mask) | kAAMask | kLKMask);
        instr |= (imm26 & kImm26Mask);
      }
      instr_at_put(pos, instr);
      break;
    }
    case BCX: {
      int imm16 = target_pos - pos;
      CHECK(is_int16(imm16) && (imm16 & (kAAMask | kLKMask)) == 0);
      if (imm16 == kInstrSize && !(instr & kLKMask)) {
        // Branch to next instr without link.
        instr = ORI;  // nop: ori, 0,0,0
      } else {
        instr &= ((~kImm16Mask) | kAAMask | kLKMask);
        instr |= (imm16 & kImm16Mask);
      }
      instr_at_put(pos, instr);
      break;
    }
    case kUnboundMovLabelOffsetOpcode: {
      // Load the position of the label relative to the generated code object
      // pointer in a register.
      Register dst = Register::from_code(instr_at(pos + kInstrSize));
      int32_t offset =
          target_pos + (InstructionStream::kHeaderSize - kHeapObjectTag);
      PatchingAssembler patcher(
          options(), reinterpret_cast<uint8_t*>(buffer_start_ + pos), 2);
      patcher.bitwise_mov32(dst, offset);
      break;
    }
    case kUnboundAddLabelLongOffsetOpcode:
    case kUnboundAddLabelOffsetOpcode: {
      // dst = base + position + immediate
      Instr operands = instr_at(pos + kInstrSize);
      Register dst = Register::from_code((operands >> 27) & 0x1F);
      Register base = Register::from_code((operands >> 22) & 0x1F);
      int32_t delta = (opcode == kUnboundAddLabelLongOffsetOpcode)
                          ? static_cast<int32_t>(instr_at(pos + 2 * kInstrSize))
                          : (SIGN_EXT_IMM22(operands & kImm22Mask));
      int32_t offset = target_pos + delta;
      PatchingAssembler patcher(
          options(), reinterpret_cast<uint8_t*>(buffer_start_ + pos),
          2 + static_cast<int32_t>(opcode == kUnboundAddLabelLongOffsetOpcode));
      patcher.bitwise_add32(dst, base, offset);
      if (opcode == kUnboundAddLabelLongOffsetOpcode) patcher.nop();
      break;
    }
    case kUnboundMovLabelAddrOpcode: {
      // Load the address of the label in a register.
      Register dst = Register::from_code(instr_at(pos + kInstrSize));
      PatchingAssembler patcher(options(),
                                reinterpret_cast<uint8_t*>(buffer_start_ + pos),
                                kMovInstructionsNoConstantPool);
      // Keep internal references relative until EmitRelocations.
      patcher.bitwise_mov(dst, target_pos);
      break;
    }
    case kUnboundJumpTableEntryOpcode: {
      PatchingAssembler patcher(options(),
                                reinterpret_cast<uint8_t*>(buffer_start_ + pos),
                                kSystemPointerSize / kInstrSize);
      // Keep internal references relative until EmitRelocations.
      patcher.dp(target_pos);
      break;
    }
    default:
      DCHECK(false);
      break;
  }
}

int Assembler::max_reach_from(int pos) {
  Instr instr = instr_at(pos);
  uint32_t opcode = instr & kOpcodeMask;

  // check which type of branch this is 16 or 26 bit offset
  switch (opcode) {
    case BX:
      return 26;
    case BCX:
      return 16;
    case kUnboundMovLabelOffsetOpcode:
    case kUnboundAddLabelOffsetOpcode:
    case kUnboundMovLabelAddrOpcode:
    case kUnboundJumpTableEntryOpcode:
      return 0;  // no limit on reach
  }

  DCHECK(false);
  return 0;
}

void Assembler::bind_to(Label* L, int pos) {
  DCHECK(0 <= pos && pos <= pc_offset());  // must have a valid binding position
  int32_t trampoline_pos = kInvalidSlotPos;
  bool is_branch = false;
  while (L->is_linked()) {
    int fixup_pos = L->pos();
    int32_t offset = pos - fixup_pos;
    int maxReach = max_reach_from(fixup_pos);
    next(L);  // call next before overwriting link with target at fixup_pos
    if (maxReach && is_intn(offset, maxReach) == false) {
      if (trampoline_pos == kInvalidSlotPos) {
        trampoline_pos = get_trampoline_entry();
        CHECK_NE(trampoline_pos, kInvalidSlotPos);
        target_at_put(trampoline_pos, pos);
      }
      target_at_put(fixup_pos, trampoline_pos);
    } else {
      target_at_put(fixup_pos, pos, &is_branch);
    }
  }
  L->bind_to(pos);

  if (!trampoline_emitted_ && is_branch) {
    UntrackBranch();
  }

  // Keep track of the last bound label so we don't eliminate any instructions
  // before a bound label.
  if (pos > last_bound_pos_) last_bound_pos_ = pos;
}

void Assembler::bind(Label* L) {
  DCHECK(!L->is_bound());  // label can only be bound once
  bind_to(L, pc_offset());
}

void Assembler::next(Label* L) {
  DCHECK(L->is_linked());
  int link = target_at(L->pos());
  if (link == kEndOfChain) {
    L->Unuse();
  } else {
    DCHECK_GE(link, 0);
    L->link_to(link);
  }
}

bool Assembler::is_near(Label* L, Condition cond) {
  DCHECK(L->is_bound());
  if (L->is_bound() == false) return false;

  int maxReach = ((cond == al) ? 26 : 16);
  int offset = L->pos() - pc_offset();

  return is_intn(offset, maxReach);
}

void Assembler::a_form(Instr instr, DoubleRegister frt, DoubleRegister fra,
                       DoubleRegister frb, RCBit r) {
  emit(instr | frt.code() * B21 | fra.code() * B16 | frb.code() * B11 | r);
}

void Assembler::d_form(Instr instr, Register rt, Register ra,
                       const intptr_t val, bool signed_disp) {
  if (signed_disp) {
    if (!is_int16(val)) {
      PrintF("val = %" V8PRIdPTR ", 0x%" V8PRIxPTR "\n", val, val);
    }
    CHECK(is_int16(val));
  } else {
    if (!is_uint16(val)) {
      PrintF("val = %" V8PRIdPTR ", 0x%" V8PRIxPTR
             ", is_unsigned_imm16(val)=%d, kImm16Mask=0x%x\n",
             val, val, is_uint16(val), kImm16Mask);
    }
    CHECK(is_uint16(val));
  }
  emit(instr | rt.code() * B21 | ra.code() * B16 | (kImm16Mask & val));
}

void Assembler::xo_form(Instr instr, Register rt, Register ra, Register rb,
                        OEBit o, RCBit r) {
  emit(instr | rt.code() * B21 | ra.code() * B16 | rb.code() * B11 | o | r);
}

void Assembler::md_form(Instr instr, Register ra, Register rs, int shift,
                        int maskbit, RCBit r) {
  int sh0_4 = shift & 0x1F;
  int sh5 = (shift >> 5) & 0x1;
  int m0_4 = maskbit & 0x1F;
  int m5 = (maskbit >> 5) & 0x1;

  emit(instr | rs.code() * B21 | ra.code() * B16 | sh0_4 * B11 | m0_4 * B6 |
       m5 * B5 | sh5 * B1 | r);
}

void Assembler::mds_form(Instr instr, Register ra, Register rs, Register rb,
                         int maskbit, RCBit r) {
  int m0_4 = maskbit & 0x1F;
  int m5 = (maskbit >> 5) & 0x1;

  emit(instr | rs.code() * B21 | ra.code() * B16 | rb.code() * B11 | m0_4 * B6 |
       m5 * B5 | r);
}

// Returns the next free trampoline entry.
int32_t Assembler::get_trampoline_entry() {
  int32_t trampoline_entry = kInvalidSlotPos;

  if (!internal_trampoline_exception_) {
    trampoline_entry = trampoline_.take_slot();

    if (kInvalidSlotPos == trampoline_entry) {
      internal_trampoline_exception_ = true;
    }
  }
  return trampoline_entry;
}

int Assembler::link(Label* L) {
  int position;
  if (L->is_bound()) {
    position = L->pos();
  } else {
    if (L->is_linked()) {
      position = L->pos();  // L's link
    } else {
      // was: target_pos = kEndOfChain;
      // However, using self to mark the first reference
      // should avoid most instances of branch offset overflow.  See
      // target_at() for where this is converted back to kEndOfChain.
      position = pc_offset();
    }
    L->link_to(pc_offset());
  }

  return position;
}

// Branch instructions.

void Assembler::bclr(BOfield bo, int condition_bit, LKBit lk) {
  emit(EXT1 | static_cast<uint32_t>(bo) | condition_bit * B16 | BCLRX | lk);
}

void Assembler::bcctr(BOfield bo, int condition_bit, LKBit lk) {
  emit(EXT1 | static_cast<uint32_t>(bo) | condition_bit * B16 | BCCTRX | lk);
}

// Pseudo op - branch to link register
void Assembler::blr() { bclr(BA, 0, LeaveLK); }

// Pseudo op - branch to count register -- used for "jump"
void Assembler::bctr() { bcctr(BA, 0, LeaveLK); }

void Assembler::bctrl() { bcctr(BA, 0, SetLK); }

void Assembler::bc(int branch_offset, BOfield bo, int condition_bit, LKBit lk) {
  int imm16 = branch_offset;
  CHECK(is_int16(imm16) && (imm16 & (kAAMask | kLKMask)) == 0);
  emit(BCX | static_cast<uint32_t>(bo) | condition_bit * B16 |
       (imm16 & kImm16Mask) | lk);
}

void Assembler::b(int branch_offset, LKBit lk) {
  int imm26 = branch_offset;
  CHECK(is_int26(imm26) && (imm26 & (kAAMask | kLKMask)) == 0);
  emit(BX | (imm26 & kImm26Mask) | lk);
}

void Assembler::xori(Register dst, Register src, const Operand& imm) {
  d_form(XORI, src, dst, imm.immediate(), false);
}

void Assembler::xoris(Register ra, Register rs, const Operand& imm) {
  d_form(XORIS, rs, ra, imm.immediate(), false);
}

void Assembler::rlwinm(Register ra, Register rs, int sh, int mb, int me,
                       RCBit rc) {
  sh &= 0x1F;
  mb &= 0x1F;
  me &= 0x1F;
  emit(RLWINMX | rs.code() * B21 | ra.code() * B16 | sh * B11 | mb * B6 |
       me << 1 | rc);
}

void Assembler::rlwnm(Register ra, Register rs, Register rb, int mb, int me,
                      RCBit rc) {
  mb &= 0x1F;
  me &= 0x1F;
  emit(RLWNMX | rs.code() * B21 | ra.code() * B16 | rb.code() * B11 | mb * B6 |
       me << 1 | rc);
}

void Assembler::rlwimi(Register ra, Register rs, int sh, int mb, int me,
                       RCBit rc) {
  sh &= 0x1F;
  mb &= 0x1F;
  me &= 0x1F;
  emit(RLWIMIX | rs.code() * B21 | ra.code() * B16 | sh * B11 | mb * B6 |
       me << 1 | rc);
}

void Assembler::slwi(Register dst, Register src, const Operand& val, RCBit rc) {
  DCHECK((32 > val.immediate()) && (val.immediate() >= 0));
  rlwinm(dst, src, val.immediate(), 0, 31 - val.immediate(), rc);
}

void Assembler::srwi(Register dst, Register src, const Operand& val, RCBit rc) {
  DCHECK((32 > val.immediate()) && (val.immediate() >= 0));
  rlwinm(dst, src, 32 - val.immediate(), val.immediate(), 31, rc);
}

void Assembler::clrrwi(Register dst, Register src, const Operand& val,
                       RCBit rc) {
  DCHECK((32 > val.immediate()) && (val.immediate() >= 0));
  rlwinm(dst, src, 0, 0, 31 - val.immediate(), rc);
}

void Assembler::clrlwi(Register dst, Register src, const Operand& val,
                       RCBit rc) {
  DCHECK((32 > val.immediate()) && (val.immediate() >= 0));
  rlwinm(dst, src, 0, val.immediate(), 31, rc);
}

void Assembler::rotlw(Register ra, Register rs, Register rb, RCBit r) {
  rlwnm(ra, rs, rb, 0, 31, r);
}

void Assembler::rotlwi(Register ra, Register rs, int sh, RCBit r) {
  rlwinm(ra, rs, sh, 0, 31, r);
}

void Assembler::rotrwi(Register ra, Register rs, int sh, RCBit r) {
  rlwinm(ra, rs, 32 - sh, 0, 31, r);
}

void Assembler::subi(Register dst, Register src, const Operand& imm) {
  addi(dst, src, Operand(-(imm.immediate())));
}

void Assembler::addc(Register dst, Register src1, Register src2, OEBit o,
                     RCBit r) {
  xo_form(EXT2 | ADDCX, dst, src1, src2, o, r);
}

void Assembler::adde(Register dst, Register src1, Register src2, OEBit o,
                     RCBit r) {
  xo_form(EXT2 | ADDEX, dst, src1, src2, o, r);
}

void Assembler::addze(Register dst, Register src1, OEBit o, RCBit r) {
  // a special xo_form
  emit(EXT2 | ADDZEX | dst.code() * B21 | src1.code() * B16 | o | r);
}

void Assembler::sub(Register dst, Register src1, Register src2, OEBit o,
                    RCBit r) {
  xo_form(EXT2 | SUBFX, dst, src2, src1, o, r);
}

void Assembler::subc(Register dst, Register src1, Register src2, OEBit o,
                     RCBit r) {
  xo_form(EXT2 | SUBFCX, dst, src2, src1, o, r);
}

void Assembler::sube(Register dst, Register src1, Register src2, OEBit o,
                     RCBit r) {
  xo_form(EXT2 | SUBFEX, dst, src2, src1, o, r);
}

void Assembler::subfic(Register dst, Register src, const Operand& imm) {
  d_form(SUBFIC, dst, src, imm.immediate(), true);
}

void Assembler::add(Register dst, Register src1, Register src2, OEBit o,
                    RCBit r) {
  xo_form(EXT2 | ADDX, dst, src1, src2, o, r);
}

// Multiply low word
void Assembler::mullw(Register dst, Register src1, Register src2, OEBit o,
                      RCBit r) {
  xo_form(EXT2 | MULLW, dst, src1, src2, o, r);
}

void Assembler::mulli(Register dst, Register src, const Operand& imm) {
  d_form(MULLI, dst, src, imm.immediate(), true);
}

// Multiply hi doubleword
void Assembler::mulhd(Register dst, Register src1, Register src2, RCBit r) {
  xo_form(EXT2 | MULHD, dst, src1, src2, LeaveOE, r);
}

// Multiply hi doubleword unsigned
void Assembler::mulhdu(Register dst, Register src1, Register src2, RCBit r) {
  xo_form(EXT2 | MULHDU, dst, src1, src2, LeaveOE, r);
}

// Multiply hi word
void Assembler::mulhw(Register dst, Register src1, Register src2, RCBit r) {
  xo_form(EXT2 | MULHWX, dst, src1, src2, LeaveOE, r);
}

// Multiply hi word unsigned
void Assembler::mulhwu(Register dst, Register src1, Register src2, RCBit r) {
  xo_form(EXT2 | MULHWUX, dst, src1, src2, LeaveOE, r);
}

// Divide word
void Assembler::divw(Register dst, Register src1, Register src2, OEBit o,
                     RCBit r) {
  xo_form(EXT2 | DIVW, dst, src1, src2, o, r);
}

// Divide word unsigned
void Assembler::divwu(Register dst, Register src1, Register src2, OEBit o,
                      RCBit r) {
  xo_form(EXT2 | DIVWU, dst, src1, src2, o, r);
}

void Assembler::addi(Register dst, Register src, const Operand& imm) {
  DCHECK(src != r0);  // use li instead to show intent
  d_form(ADDI, dst, src, imm.immediate(), true);
}

void Assembler::addis(Register dst, Register src, const Operand& imm) {
  DCHECK(src != r0);  // use lis instead to show intent
  d_form(ADDIS, dst, src, imm.immediate(), true);
}

void Assembler::addic(Register dst, Register src, const Operand& imm) {
  d_form(ADDIC, dst, src, imm.immediate(), true);
}

void Assembler::andi(Register ra, Register rs, const Operand& imm) {
  d_form(ANDIx, rs, ra, imm.immediate(), false);
}

void Assembler::andis(Register ra, Register rs, const Operand& imm) {
  d_form(ANDISx, rs, ra, imm.immediate(), false);
}

void Assembler::ori(Register ra, Register rs, const Operand& imm) {
  d_form(ORI, rs, ra, imm.immediate(), false);
}

void Assembler::oris(Register dst, Register src, const Operand& imm) {
  d_form(ORIS, src, dst, imm.immediate(), false);
}

void Assembler::cmpi(Register src1, const Operand& src2, CRegister cr) {
  intptr_t imm16 = src2.immediate();
  int L = 1;
  DCHECK(is_int16(imm16));
  DCHECK(cr.code() >= 0 && cr.code() <= 7);
  imm16 &= kImm16Mask;
  emit(CMPI | cr.code() * B23 | L * B21 | src1.code() * B16 | imm16);
}

void Assembler::cmpli(Register src1, const Operand& src2, CRegister cr) {
  uintptr_t uimm16 = src2.immediate();
  int L = 1;
  DCHECK(is_uint16(uimm16));
  DCHECK(cr.code() >= 0 && cr.code() <= 7);
  uimm16 &= kImm16Mask;
  emit(CMPLI | cr.code() * B23 | L * B21 | src1.code() * B16 | uimm16);
}

void Assembler::cmpwi(Register src1, const Operand& src2, CRegister cr) {
  intptr_t imm16 = src2.immediate();
  int L = 0;
  int pos = pc_offset();
  DCHECK(is_int16(imm16));
  DCHECK(cr.code() >= 0 && cr.code() <= 7);
  imm16 &= kImm16Mask;

  // For cmpwi against 0, save postition and cr for later examination
  // of potential optimization.
  if (imm16 == 0 && pos > 0 && last_bound_pos_ != pos) {
    optimizable_cmpi_pos_ = pos;
    cmpi_cr_ = cr;
  }
  emit(CMPI | cr.code() * B23 | L * B21 | src1.code() * B16 | imm16);
}

void Assembler::cmplwi(Register src1, const Operand& src2, CRegister cr) {
  uintptr_t uimm16 = src2.immediate();
  int L = 0;
  DCHECK(is_uint16(uimm16));
  DCHECK(cr.code() >= 0 && cr.code() <= 7);
  uimm16 &= kImm16Mask;
  emit(CMPLI | cr.code() * B23 | L * B21 | src1.code() * B16 | uimm16);
}

void Assembler::isel(Register rt, Register ra, Register rb, int cb) {
  emit(EXT2 | ISEL | rt.code() * B21 | ra.code() * B16 | rb.code() * B11 |
       cb * B6);
}

// Pseudo op - load immediate
void Assembler::li(Register dst, const Operand& imm) {
  d_form(ADDI, dst, r0, imm.immediate(), true);
}

void Assembler::lis(Register dst, const Operand& imm) {
  d_form(ADDIS, dst, r0, imm.immediate(), true);
}

// Pseudo op - move register
void Assembler::mr(Register dst, Register src) {
  // actually or(dst, src, src)
  orx(dst, src, src);
}

void Assembler::lbz(Register dst, const MemOperand& src) {
  DCHECK(src.ra_ != r0);
  d_form(LBZ, dst, src.ra(), src.offset(), true);
}

void Assembler::lhz(Register dst, const MemOperand& src) {
  DCHECK(src.ra_ != r0);
  d_form(LHZ, dst, src.ra(), src.offset(), true);
}

void Assembler::lwz(Register dst, const MemOperand& src) {
  DCHECK(src.ra_ != r0);
  d_form(LWZ, dst, src.ra(), src.offset(), true);
}

void Assembler::lwzu(Register dst, const MemOperand& src) {
  DCHECK(src.ra_ != r0);
  d_form(LWZU, dst, src.ra(), src.offset(), true);
}

void Assembler::lha(Register dst, const MemOperand& src) {
  DCHECK(src.ra_ != r0);
  d_form(LHA, dst, src.ra(), src.offset(), true);
}

void Assembler::lwa(Register dst, const MemOperand& src) {
  int offset = src.offset();
  DCHECK(src.ra_ != r0);
  CHECK(!(offset & 3) && is_int16(offset));
  offset = kImm16Mask & offset;
  emit(LD | dst.code() * B21 | src.ra().code() * B16 | offset | 2);
}

void Assembler::stb(Register dst, const MemOperand& src) {
  DCHECK(src.ra_ != r0);
  d_form(STB, dst, src.ra(), src.offset(), true);
}

void Assembler::sth(Regist
```