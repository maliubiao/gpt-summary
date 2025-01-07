Response:
Let's break down the thought process for analyzing this code snippet and generating the desired output.

**1. Understanding the Request:**

The core request is to analyze a C++ header file (`liftoff-assembler-x64-inl.h`) from the V8 JavaScript engine. The prompt asks for:

* **Functionality listing:** What does the code do?
* **Torque check:** Is it a Torque file?
* **JavaScript relevance:** How does it relate to JavaScript, and provide examples if it does.
* **Code logic inference:**  Present example inputs and outputs for specific code sections.
* **Common programming errors:** Highlight potential pitfalls for users.
* **Summary of functionality:** A concise overview of the code's purpose.
* **Context:** Acknowledge this is part 2 of a 6-part analysis.

**2. Initial Code Scan and Keyword Recognition:**

The first step is to quickly scan the code for recognizable patterns and keywords. Key observations include:

* **`LiftoffAssembler` class:**  This is the central entity.
* **`Atomic*` functions:** Indicate atomic operations.
* **`Load*`, `Store*` functions:**  Deal with memory access.
* **`Move*` functions:**  Data movement between registers and memory.
* **`Spill`, `Fill`:**  Relate to saving and restoring register values to the stack (important for register allocation).
* **`emit_*` functions:**  These seem to generate specific x64 assembly instructions (like `movq`, `addl`, `imull`, `vaddss`, etc.).
* **Register names:** `rax`, `rbp`, `rsp`, `rcx`, `rdi`, etc., confirm this is x64 assembly-related code.
* **`ValueKind` enum:**  Suggests the code handles different data types (integers, floats).
* **`Operand` class:** Likely represents memory addresses.
* **`lock()`, `mfence()`:** Indicate memory synchronization primitives.
* **Conditional jumps (`j(zero, ...)`):**  Part of control flow within the assembly code generation.
* **CPU feature checks (`CpuFeatures::IsSupported`)**: Indicate conditional code generation based on processor capabilities.

**3. Grouping Functionality:**

Based on the keyword analysis, it's natural to group the functions by their apparent purpose:

* **Memory Operations:** `AtomicExchange`, `AtomicCompareExchange`, `LoadCallerFrameSlot`, `StoreCallerFrameSlot`, `LoadReturnStackSlot`, `MoveStackValue`.
* **Data Movement:** `Move`, `Spill`, `Fill`.
* **Stack Management:** `FillStackSlotsWithZero`, `LoadSpillAddress`.
* **Tracing:** `emit_trace_instruction`.
* **Arithmetic and Logical Operations (Integer):** `emit_i32_*`, `emit_i64_*`. Notice the distinct `i32` and `i64` operations.
* **Floating-Point Operations:** `emit_f32_*`, `emit_f64_*`.
* **Utility/Helpers:** `IncrementSmi`, `emit_u32_to_uintptr`, `clear_i32_upper_half`.

**4. Answering Specific Questions:**

* **Torque:** The prompt explicitly states to check for `.tq`. Since the filename ends in `.h`, it's not a Torque file.
* **JavaScript Relevance:** The code generates assembly instructions. This is the *final step* in compiling JavaScript code in V8. The Liftoff compiler is a baseline compiler, meaning it's relatively fast but might not produce the most optimized code. JavaScript examples should demonstrate operations that would eventually be translated into these assembly instructions (arithmetic, memory access, function calls, etc.).
* **Code Logic Inference:** Choose a few representative functions, like `AtomicExchange` or `emit_i32_add`. For `AtomicExchange`, trace the flow with specific register values and memory addresses to show the before and after state. For `emit_i32_add`, show how the `lea` or `addl` instruction is chosen based on whether the destination is the same as the left operand.
* **Common Programming Errors:** Think about the *user-level* perspective. They don't directly write this assembly code. However, errors in their JavaScript *can* lead to unexpected behavior that might be rooted in how this low-level code works. Examples include integer overflow, division by zero, and NaN issues in floating-point calculations.

**5. Structuring the Output:**

Organize the findings logically:

* Start with the basic information (not a Torque file).
* Explain the core functionality (assembly code generation for the Liftoff compiler).
* Provide JavaScript examples to connect the C++ code to the user-facing language.
* Illustrate code logic with concrete examples.
* Highlight common JavaScript errors that relate to the underlying assembly operations.
* Summarize the functionality concisely.
* Remember to note the "part 2 of 6" context.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe focus on every single function. **Correction:** That would be too verbose. Focus on representative examples of each category of functionality.
* **Initial thought:** Just list the assembly instructions. **Correction:** Explain *why* those instructions are being generated and what they achieve in the context of Wasm execution.
* **Initial thought:** Assume the user understands assembly. **Correction:** Explain concepts like registers, stack, and memory operations at a high level, assuming a developer audience but not necessarily assembly experts.
* **Double-check:** Ensure the JavaScript examples are clear and directly relate to the C++ code being analyzed. Make sure the input/output examples for code logic are easy to follow.

By following these steps of understanding the request, scanning the code, grouping functionality, addressing specific questions, and structuring the output, along with some self-correction,  we can arrive at a comprehensive and informative analysis of the provided C++ header file.
好的，让我们来分析一下 `v8/src/wasm/baseline/x64/liftoff-assembler-x64-inl.h` 代码片段的功能。

**功能归纳**

这段代码定义了 `LiftoffAssembler` 类的一些内联成员函数，这些函数是用于在 x64 架构上为 WebAssembly 的 Liftoff 编译器生成汇编代码的。 这些函数实现了 WebAssembly 规范中定义的各种原子操作、内存访问、数据移动和算术运算。

**详细功能列表**

1. **原子操作:**
   - `AtomicExchange`: 原子地交换内存中的值与寄存器中的值。支持不同大小的数据类型（8位、16位、32位、64位）。
   - `AtomicCompareExchange`: 原子地比较内存中的值与预期值，如果相等则将内存中的值替换为新值。返回旧值。同样支持不同大小的数据类型。
   - `AtomicFence`:  插入内存屏障指令 (`mfence`)，确保所有之前的内存访问都已完成，并且所有后续的内存访问都将在其之后开始。

2. **栈帧操作:**
   - `LoadCallerFrameSlot`: 从调用者的栈帧中加载数据到寄存器。
   - `StoreCallerFrameSlot`: 将寄存器中的数据存储到调用者的栈帧中。
   - `LoadReturnStackSlot`: 从返回栈槽中加载数据到寄存器。

3. **数据移动:**
   - `MoveStackValue`: 在栈上的不同位置之间移动数据。
   - `Move`: 在寄存器之间移动数据 (整数或指针)。
   - `Move`: 在浮点寄存器之间移动数据 (单精度、双精度、128位向量)。
   - `Spill`: 将寄存器中的值保存到栈上。可以保存通用寄存器或浮点寄存器。也支持保存立即数到栈上。
   - `Fill`: 将栈上的值加载到寄存器中。
   - `FillI64Half`:  此函数目前未实现 (`UNREACHABLE()`)，可能与64位值的部分加载有关。
   - `FillStackSlotsWithZero`: 用零填充栈上的指定范围。
   - `LoadSpillAddress`:  加载栈上指定偏移地址到寄存器中。

4. **指令跟踪:**
   - `emit_trace_instruction`: 发射一个跟踪指令，用于调试和性能分析。

5. **整数运算 (32位):**
   - `emit_i32_add`, `emit_i32_addi`: 加法运算。
   - `emit_i32_sub`, `emit_i32_subi`: 减法运算。
   - `emit_i32_mul`: 乘法运算。
   - `emit_i32_divs`, `emit_i32_divu`: 有符号和无符号除法运算，包含除零陷阱的实现。
   - `emit_i32_rems`, `emit_i32_remu`: 有符号和无符号取余运算，包含除零陷阱的实现。
   - `emit_i32_and`, `emit_i32_andi`: 按位与运算。
   - `emit_i32_or`, `emit_i32_ori`: 按位或运算。
   - `emit_i32_xor`, `emit_i32_xori`: 按位异或运算。
   - `emit_i32_shl`, `emit_i32_shli`: 左移运算。
   - `emit_i32_sar`, `emit_i32_sari`: 算术右移运算。
   - `emit_i32_shr`, `emit_i32_shri`: 逻辑右移运算。
   - `emit_i32_clz`: 计算前导零的个数。
   - `emit_i32_ctz`: 计算尾部零的个数。
   - `emit_i32_popcnt`: 计算设置的位的个数 (需要 CPU 支持 `POPCNT` 指令)。

6. **整数运算 (64位):**
   - `emit_i64_add`, `emit_i64_addi`: 加法运算。
   - `emit_i64_sub`: 减法运算。
   - `emit_i64_mul`, `emit_i64_muli`: 乘法运算。
   - `emit_i64_divs`, `emit_i64_divu`: 有符号和无符号除法运算，包含除零和溢出陷阱。
   - `emit_i64_rems`, `emit_i64_remu`: 有符号和无符号取余运算，包含除零陷阱。
   - `emit_i64_and`, `emit_i64_andi`: 按位与运算。
   - `emit_i64_or`, `emit_i64_ori`: 按位或运算。
   - `emit_i64_xor`, `emit_i64_xori`: 按位异或运算。
   - `emit_i64_shl`: 左移运算。
   - `emit_i64_shli`: 带立即数的左移运算。
   - `emit_i64_sar`: 算术右移运算。
   - `emit_i64_sari`: 带立即数的算术右移运算。
   - `emit_i64_shr`: 逻辑右移运算。
   - `emit_i64_shri`: 带立即数的逻辑右移运算。
   - `emit_i64_clz`: 计算前导零的个数。
   - `emit_i64_ctz`: 计算尾部零的个数。
   - `emit_i64_popcnt`: 计算设置的位的个数 (需要 CPU 支持 `POPCNT` 指令)。

7. **其他整数操作:**
   - `IncrementSmi`: 递增一个 Smi (V8 中用于表示小整数的特殊类型)。
   - `emit_u32_to_uintptr`: 将 32 位无符号整数转换为 uintptr_t。
   - `clear_i32_upper_half`: 清除 32 位寄存器的高 32 位。

8. **浮点运算 (单精度):**
   - `emit_f32_add`: 加法运算。
   - `emit_f32_sub`: 减法运算。
   - `emit_f32_mul`: 乘法运算。
   - `emit_f32_div`: 除法运算。
   - `emit_f32_min`: 取最小值。
   - `emit_f32_max`: 取最大值。
   - `emit_f32_copysign`: 复制符号位。
   - `emit_f32_abs`: 计算绝对值。
   - `emit_f32_neg`: 取反。
   - `emit_f32_ceil`: 向上取整。
   - `emit_f32_floor`: 向下取整。
   - `emit_f32_trunc`: 截断取整。
   - `emit_f32_nearest_int`: 四舍五入到最接近的整数。
   - `emit_f32_sqrt`: 计算平方根。

9. **浮点运算 (双精度):**
   - `emit_f64_add`: 加法运算。
   - `emit_f64_sub`: 减法运算。
   - `emit_f64_mul`: 乘法运算。
   - `emit_f64_div`: 除法运算。
   - ... (代码片段在双精度浮点运算部分被截断)

**关于文件类型和 JavaScript 关系**

* **文件类型:**  `v8/src/wasm/baseline/x64/liftoff-assembler-x64-inl.h` 以 `.h` 结尾，因此它是 **C++ 头文件**，而不是以 `.tq` 结尾的 Torque 文件。

* **JavaScript 关系:** 这个文件与 JavaScript 的功能有密切关系。WebAssembly 是一种可以在现代 Web 浏览器中运行的二进制指令格式。V8 引擎负责执行 JavaScript 代码和 WebAssembly 代码。Liftoff 编译器是 V8 中用于快速编译 WebAssembly 代码的基线编译器。

   当 V8 遇到需要执行的 WebAssembly 代码时，Liftoff 编译器会将其翻译成目标架构（这里是 x64）的机器码。`LiftoffAssembler` 类及其内联函数就是用来生成这些 x64 汇编指令的。

**JavaScript 示例**

虽然用户不会直接操作这些汇编指令，但可以通过 JavaScript 使用 WebAssembly 来间接触发这些代码的执行。例如，以下 JavaScript 代码使用 WebAssembly 实现了整数加法：

```javascript
const wasmCode = new Uint8Array([
  0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // WASM magic number and version
  0x01, 0x07, 0x01, 0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7f, // Function signature: (i32, i32) -> i32
  0x03, 0x02, 0x01, 0x00, // Import section (empty)
  0x07, 0x07, 0x01, 0x03, 0x61, 0x64, 0x64, 0x00, 0x00, // Export section: export "add" function
  0x0a, 0x09, 0x01, 0x07, 0x00, 0x20, 0x00, 0x20, 0x01, 0x6a, 0x0b // Code section: local.get 0; local.get 1; i32.add; end
]);

WebAssembly.instantiate(wasmCode).then(wasmModule => {
  const add = wasmModule.instance.exports.add;
  const result = add(5, 10); // 调用 WebAssembly 的 add 函数
  console.log(result); // 输出 15
});
```

在这个例子中，当 `add(5, 10)` 被调用时，如果是由 Liftoff 编译器编译的，那么 `emit_i32_add` 函数（或者类似的函数）会被调用来生成实际执行加法运算的 x64 汇编指令。

**代码逻辑推理示例**

以 `AtomicExchange` 函数为例，假设我们有以下输入：

* `dst_addr`: 寄存器 `r8`，其值指向内存地址 `0x1000`
* `value`: `LiftoffRegister`，代表寄存器 `rax`，其值为 `0xABCD1234`
* `result`: `LiftoffRegister`，代表寄存器 `rcx`
* `type`: `StoreType::kI32Store`

**假设输入:**

* `r8` 指向内存地址 `0x1000`，该地址当前存储的值为 `0x00005678`。
* `rax` 的值为 `0xABCD1234`。

**代码逻辑:**

1. `movq(result.gp(), value.gp());`  将 `value` 寄存器 (`rax`) 的值复制到 `result` 寄存器 (`rcx`)。所以 `rcx` 现在是 `0xABCD1234`。
2. `Operand dst_op = liftoff::GetMemOp(this, dst_addr, offset_reg, offset_imm);`  创建一个操作数，表示内存地址 `[r8 + 0]`，即 `0x1000`。
3. `switch (type.value()) { ... case StoreType::kI32Store: ... }` 进入 `kI32Store` 分支。
4. `xchgl(value.gp(), dst_op);`  原子地交换 `value` 寄存器 (`rax`) 的低 32 位与内存地址 `0x1000` 的值。
5. `if (value != result) { movq(result.gp(), value.gp()); }` 由于 `rax` 和 `rcx` 是不同的寄存器，所以将 `rax` 的值（现在是内存地址 `0x1000` 原来的值，即 `0x00005678`，因为发生了交换）复制回 `rcx`。

**假设输出:**

* 内存地址 `0x1000` 的值变为 `0xABCD1234`。
* 寄存器 `rcx` 的值变为 `0x00005678`。

**用户常见的编程错误**

虽然用户不直接编写汇编代码，但在使用 WebAssembly 或编写需要 V8 优化的 JavaScript 代码时，可能会遇到一些与这些底层操作相关的错误：

1. **整数溢出:**  JavaScript 中的 Number 类型可以安全地表示大整数，但在 WebAssembly 中，整数类型有固定的大小。进行超出范围的整数运算可能导致截断或意外的结果。例如，在 WebAssembly 中进行 `i32.add` 运算，如果结果超出 32 位有符号整数的范围，就会发生溢出。

   ```javascript
   // JavaScript (可能不会立即报错，但结果可能不符合预期)
   const largeNumber = 2147483647 + 1; // 溢出，结果是 -2147483648

   // WebAssembly (使用 i32)
   // ... (wasm 代码执行 i32.add 2147483647 和 1)
   // 结果将是 -2147483648
   ```

2. **除零错误:**  在整数除法中，除数为零会导致错误。这段代码中可以看到有针对除零情况的处理 (`trap_div_by_zero`)。

   ```javascript
   // JavaScript (会抛出异常)
   // console.log(5 / 0); // 输出 Infinity

   // WebAssembly (会触发陷阱，导致程序终止或执行预定义的错误处理)
   // ... (wasm 代码执行 i32.divs 或 i32.divu，除数为 0)
   ```

3. **浮点数精度问题:** 浮点数运算可能存在精度损失。例如，比较两个浮点数是否相等时，由于精度问题，直接使用 `==` 可能不可靠。

   ```javascript
   // JavaScript
   console.log(0.1 + 0.2 === 0.3); // 输出 false (因为浮点数表示的精度问题)

   // WebAssembly (浮点运算同样存在精度问题)
   // ... (wasm 代码执行 f32 或 f64 加法，结果与预期略有偏差)
   ```

**总结**

这段 `liftoff-assembler-x64-inl.h` 代码片段是 V8 引擎中 Liftoff 编译器在 x64 架构上生成汇编指令的关键部分，它实现了 WebAssembly 规范中定义的各种基本操作，包括原子操作、内存访问、数据移动以及整数和浮点数运算。理解这些底层操作有助于理解 WebAssembly 的执行方式以及可能出现的编程错误。

Prompt: 
```
这是目录为v8/src/wasm/baseline/x64/liftoff-assembler-x64-inl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/baseline/x64/liftoff-assembler-x64-inl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共6部分，请归纳一下它的功能

"""
sult} register in the code below.
    movq(result.gp(), value.gp());
    value = result;
  }
  Operand dst_op = liftoff::GetMemOp(this, dst_addr, offset_reg, offset_imm);
  switch (type.value()) {
    case StoreType::kI32Store8:
    case StoreType::kI64Store8:
      xchgb(value.gp(), dst_op);
      movzxbq(result.gp(), value.gp());
      break;
    case StoreType::kI32Store16:
    case StoreType::kI64Store16:
      xchgw(value.gp(), dst_op);
      movzxwq(result.gp(), value.gp());
      break;
    case StoreType::kI32Store:
    case StoreType::kI64Store32:
      xchgl(value.gp(), dst_op);
      if (value != result) {
        movq(result.gp(), value.gp());
      }
      break;
    case StoreType::kI64Store:
      xchgq(value.gp(), dst_op);
      if (value != result) {
        movq(result.gp(), value.gp());
      }
      break;
    default:
      UNREACHABLE();
  }
}

void LiftoffAssembler::AtomicCompareExchange(
    Register dst_addr, Register offset_reg, uintptr_t offset_imm,
    LiftoffRegister expected, LiftoffRegister new_value, LiftoffRegister result,
    StoreType type, bool i64_offset) {
  if (offset_reg != no_reg && !i64_offset) AssertZeroExtended(offset_reg);
  Register value_reg = new_value.gp();
  // The cmpxchg instruction uses rax to store the old value of the
  // compare-exchange primitive. Therefore we have to spill the register and
  // move any use to another register.
  LiftoffRegList pinned = LiftoffRegList{dst_addr, expected, value_reg};
  if (offset_reg != no_reg) pinned.set(offset_reg);
  ClearRegister(rax, {&dst_addr, &offset_reg, &value_reg}, pinned);
  if (expected.gp() != rax) {
    movq(rax, expected.gp());
  }

  Operand dst_op = liftoff::GetMemOp(this, dst_addr, offset_reg, offset_imm);

  lock();
  switch (type.value()) {
    case StoreType::kI32Store8:
    case StoreType::kI64Store8: {
      cmpxchgb(dst_op, value_reg);
      movzxbq(result.gp(), rax);
      break;
    }
    case StoreType::kI32Store16:
    case StoreType::kI64Store16: {
      cmpxchgw(dst_op, value_reg);
      movzxwq(result.gp(), rax);
      break;
    }
    case StoreType::kI32Store: {
      cmpxchgl(dst_op, value_reg);
      if (result.gp() != rax) {
        movl(result.gp(), rax);
      }
      break;
    }
    case StoreType::kI64Store32: {
      cmpxchgl(dst_op, value_reg);
      // Zero extension.
      movl(result.gp(), rax);
      break;
    }
    case StoreType::kI64Store: {
      cmpxchgq(dst_op, value_reg);
      if (result.gp() != rax) {
        movq(result.gp(), rax);
      }
      break;
    }
    default:
      UNREACHABLE();
  }
}

void LiftoffAssembler::AtomicFence() { mfence(); }

void LiftoffAssembler::LoadCallerFrameSlot(LiftoffRegister dst,
                                           uint32_t caller_slot_idx,
                                           ValueKind kind) {
  Operand src(rbp, kSystemPointerSize * (caller_slot_idx + 1));
  liftoff::LoadFromStack(this, dst, src, kind);
}

void LiftoffAssembler::StoreCallerFrameSlot(LiftoffRegister src,
                                            uint32_t caller_slot_idx,
                                            ValueKind kind,
                                            Register frame_pointer) {
  Operand dst(frame_pointer, kSystemPointerSize * (caller_slot_idx + 1));
  liftoff::StoreToMemory(this, dst, src, kind);
}

void LiftoffAssembler::LoadReturnStackSlot(LiftoffRegister reg, int offset,
                                           ValueKind kind) {
  Operand src(rsp, offset);
  liftoff::LoadFromStack(this, reg, src, kind);
}

void LiftoffAssembler::MoveStackValue(uint32_t dst_offset, uint32_t src_offset,
                                      ValueKind kind) {
  DCHECK_NE(dst_offset, src_offset);
  Operand dst = liftoff::GetStackSlot(dst_offset);
  Operand src = liftoff::GetStackSlot(src_offset);
  switch (SlotSizeForType(kind)) {
    case 4:
      movl(kScratchRegister, src);
      movl(dst, kScratchRegister);
      break;
    case 8:
      movq(kScratchRegister, src);
      movq(dst, kScratchRegister);
      break;
    case 16:
      Movdqu(kScratchDoubleReg, src);
      Movdqu(dst, kScratchDoubleReg);
      break;
    default:
      UNREACHABLE();
  }
}

void LiftoffAssembler::Move(Register dst, Register src, ValueKind kind) {
  DCHECK_NE(dst, src);
  if (kind == kI32) {
    movl(dst, src);
  } else {
    DCHECK(kI64 == kind || is_reference(kind));
    movq(dst, src);
  }
}

void LiftoffAssembler::Move(DoubleRegister dst, DoubleRegister src,
                            ValueKind kind) {
  DCHECK_NE(dst, src);
  if (kind == kF32) {
    Movss(dst, src);
  } else if (kind == kF64) {
    Movsd(dst, src);
  } else {
    DCHECK_EQ(kS128, kind);
    Movapd(dst, src);
  }
}

void LiftoffAssembler::Spill(int offset, LiftoffRegister reg, ValueKind kind) {
  RecordUsedSpillOffset(offset);
  Operand dst = liftoff::GetStackSlot(offset);
  switch (kind) {
    case kI32:
      movl(dst, reg.gp());
      break;
    case kI64:
    case kRefNull:
    case kRef:
    case kRtt:
      movq(dst, reg.gp());
      break;
    case kF32:
      Movss(dst, reg.fp());
      break;
    case kF64:
      Movsd(dst, reg.fp());
      break;
    case kS128:
      Movdqu(dst, reg.fp());
      break;
    default:
      UNREACHABLE();
  }
}

void LiftoffAssembler::Spill(int offset, WasmValue value) {
  RecordUsedSpillOffset(offset);
  Operand dst = liftoff::GetStackSlot(offset);
  switch (value.type().kind()) {
    case kI32:
      movl(dst, Immediate(value.to_i32()));
      break;
    case kI64: {
      if (is_int32(value.to_i64())) {
        // Sign extend low word.
        movq(dst, Immediate(static_cast<int32_t>(value.to_i64())));
      } else if (is_uint32(value.to_i64())) {
        // Zero extend low word.
        movl(kScratchRegister, Immediate(static_cast<int32_t>(value.to_i64())));
        movq(dst, kScratchRegister);
      } else {
        movq(kScratchRegister, value.to_i64());
        movq(dst, kScratchRegister);
      }
      break;
    }
    default:
      // We do not track f32 and f64 constants, hence they are unreachable.
      UNREACHABLE();
  }
}

void LiftoffAssembler::Fill(LiftoffRegister reg, int offset, ValueKind kind) {
  liftoff::LoadFromStack(this, reg, liftoff::GetStackSlot(offset), kind);
}

void LiftoffAssembler::FillI64Half(Register, int offset, RegPairHalf) {
  UNREACHABLE();
}

void LiftoffAssembler::FillStackSlotsWithZero(int start, int size) {
  DCHECK_LT(0, size);
  RecordUsedSpillOffset(start + size);

  if (size <= 3 * kStackSlotSize) {
    // Special straight-line code for up to three slots
    // (7-10 bytes per slot: REX C7 <1-4 bytes op> <4 bytes imm>),
    // And a movd (6-9 byte) when size % 8 != 0;
    uint32_t remainder = size;
    for (; remainder >= kStackSlotSize; remainder -= kStackSlotSize) {
      movq(liftoff::GetStackSlot(start + remainder), Immediate(0));
    }
    DCHECK(remainder == 4 || remainder == 0);
    if (remainder) {
      movl(liftoff::GetStackSlot(start + remainder), Immediate(0));
    }
  } else {
    // General case for bigger counts.
    // This sequence takes 19-22 bytes (3 for pushes, 4-7 for lea, 2 for xor, 5
    // for mov, 2 for repstosl, 3 for pops).
    pushq(rax);
    pushq(rcx);
    pushq(rdi);
    leaq(rdi, liftoff::GetStackSlot(start + size));
    xorl(rax, rax);
    // Convert size (bytes) to doublewords (4-bytes).
    movl(rcx, Immediate(size / 4));
    repstosl();
    popq(rdi);
    popq(rcx);
    popq(rax);
  }
}

void LiftoffAssembler::LoadSpillAddress(Register dst, int offset,
                                        ValueKind /* kind */) {
  leaq(dst, liftoff::GetStackSlot(offset));
}

void LiftoffAssembler::emit_trace_instruction(uint32_t markid) {
  Assembler::emit_trace_instruction(Immediate(markid));
}

void LiftoffAssembler::emit_i32_add(Register dst, Register lhs, Register rhs) {
  if (lhs != dst) {
    leal(dst, Operand(lhs, rhs, times_1, 0));
  } else {
    addl(dst, rhs);
  }
}

void LiftoffAssembler::emit_i32_addi(Register dst, Register lhs, int32_t imm) {
  if (lhs != dst) {
    leal(dst, Operand(lhs, imm));
  } else {
    addl(dst, Immediate(imm));
  }
}

void LiftoffAssembler::emit_i32_sub(Register dst, Register lhs, Register rhs) {
  if (dst != rhs) {
    // Default path.
    if (dst != lhs) movl(dst, lhs);
    subl(dst, rhs);
  } else if (lhs == rhs) {
    // Degenerate case.
    xorl(dst, dst);
  } else {
    // Emit {dst = lhs + -rhs} if dst == rhs.
    negl(dst);
    addl(dst, lhs);
  }
}

void LiftoffAssembler::emit_i32_subi(Register dst, Register lhs, int32_t imm) {
  if (dst != lhs) {
    // We'll have to implement an UB-safe version if we need this corner case.
    DCHECK_NE(imm, kMinInt);
    leal(dst, Operand(lhs, -imm));
  } else {
    subl(dst, Immediate(imm));
  }
}

namespace liftoff {
template <void (Assembler::*op)(Register, Register),
          void (Assembler::*mov)(Register, Register)>
void EmitCommutativeBinOp(LiftoffAssembler* assm, Register dst, Register lhs,
                          Register rhs) {
  if (dst == rhs) {
    (assm->*op)(dst, lhs);
  } else {
    if (dst != lhs) (assm->*mov)(dst, lhs);
    (assm->*op)(dst, rhs);
  }
}

template <void (Assembler::*op)(Register, Immediate),
          void (Assembler::*mov)(Register, Register)>
void EmitCommutativeBinOpImm(LiftoffAssembler* assm, Register dst, Register lhs,
                             int32_t imm) {
  if (dst != lhs) (assm->*mov)(dst, lhs);
  (assm->*op)(dst, Immediate(imm));
}

}  // namespace liftoff

void LiftoffAssembler::emit_i32_mul(Register dst, Register lhs, Register rhs) {
  liftoff::EmitCommutativeBinOp<&Assembler::imull, &Assembler::movl>(this, dst,
                                                                     lhs, rhs);
}

namespace liftoff {
enum class DivOrRem : uint8_t { kDiv, kRem };
template <typename type, DivOrRem div_or_rem>
void EmitIntDivOrRem(LiftoffAssembler* assm, Register dst, Register lhs,
                     Register rhs, Label* trap_div_by_zero,
                     Label* trap_div_unrepresentable) {
  constexpr bool needs_unrepresentable_check =
      std::is_signed<type>::value && div_or_rem == DivOrRem::kDiv;
  constexpr bool special_case_minus_1 =
      std::is_signed<type>::value && div_or_rem == DivOrRem::kRem;
  DCHECK_EQ(needs_unrepresentable_check, trap_div_unrepresentable != nullptr);

#define iop(name, ...)            \
  do {                            \
    if (sizeof(type) == 4) {      \
      assm->name##l(__VA_ARGS__); \
    } else {                      \
      assm->name##q(__VA_ARGS__); \
    }                             \
  } while (false)

  // For division, the lhs is always taken from {edx:eax}. Thus, make sure that
  // these registers are unused. If {rhs} is stored in one of them, move it to
  // another temporary register.
  // Do all this before any branch, such that the code is executed
  // unconditionally, as the cache state will also be modified unconditionally.
  assm->SpillRegisters(rdx, rax);
  if (rhs == rax || rhs == rdx) {
    iop(mov, kScratchRegister, rhs);
    rhs = kScratchRegister;
  }

  // Check for division by zero.
  iop(test, rhs, rhs);
  assm->j(zero, trap_div_by_zero);

  Label done;
  if (needs_unrepresentable_check) {
    // Check for {kMinInt / -1}. This is unrepresentable.
    Label do_div;
    iop(cmp, rhs, Immediate(-1));
    assm->j(not_equal, &do_div);
    // {lhs} is min int if {lhs - 1} overflows.
    iop(cmp, lhs, Immediate(1));
    assm->j(overflow, trap_div_unrepresentable);
    assm->bind(&do_div);
  } else if (special_case_minus_1) {
    // {lhs % -1} is always 0 (needs to be special cased because {kMinInt / -1}
    // cannot be computed).
    Label do_rem;
    iop(cmp, rhs, Immediate(-1));
    assm->j(not_equal, &do_rem);
    // clang-format off
    // (conflicts with presubmit checks because it is confused about "xor")
    iop(xor, dst, dst);
    // clang-format on
    assm->jmp(&done);
    assm->bind(&do_rem);
  }

  // Now move {lhs} into {eax}, then zero-extend or sign-extend into {edx}, then
  // do the division.
  if (lhs != rax) iop(mov, rax, lhs);
  if (std::is_same<int32_t, type>::value) {  // i32
    assm->cdq();
    assm->idivl(rhs);
  } else if (std::is_same<uint32_t, type>::value) {  // u32
    assm->xorl(rdx, rdx);
    assm->divl(rhs);
  } else if (std::is_same<int64_t, type>::value) {  // i64
    assm->cqo();
    assm->idivq(rhs);
  } else {  // u64
    assm->xorq(rdx, rdx);
    assm->divq(rhs);
  }

  // Move back the result (in {eax} or {edx}) into the {dst} register.
  constexpr Register kResultReg = div_or_rem == DivOrRem::kDiv ? rax : rdx;
  if (dst != kResultReg) {
    iop(mov, dst, kResultReg);
  }
  if (special_case_minus_1) assm->bind(&done);
}
}  // namespace liftoff

void LiftoffAssembler::emit_i32_divs(Register dst, Register lhs, Register rhs,
                                     Label* trap_div_by_zero,
                                     Label* trap_div_unrepresentable) {
  liftoff::EmitIntDivOrRem<int32_t, liftoff::DivOrRem::kDiv>(
      this, dst, lhs, rhs, trap_div_by_zero, trap_div_unrepresentable);
}

void LiftoffAssembler::emit_i32_divu(Register dst, Register lhs, Register rhs,
                                     Label* trap_div_by_zero) {
  liftoff::EmitIntDivOrRem<uint32_t, liftoff::DivOrRem::kDiv>(
      this, dst, lhs, rhs, trap_div_by_zero, nullptr);
}

void LiftoffAssembler::emit_i32_rems(Register dst, Register lhs, Register rhs,
                                     Label* trap_div_by_zero) {
  liftoff::EmitIntDivOrRem<int32_t, liftoff::DivOrRem::kRem>(
      this, dst, lhs, rhs, trap_div_by_zero, nullptr);
}

void LiftoffAssembler::emit_i32_remu(Register dst, Register lhs, Register rhs,
                                     Label* trap_div_by_zero) {
  liftoff::EmitIntDivOrRem<uint32_t, liftoff::DivOrRem::kRem>(
      this, dst, lhs, rhs, trap_div_by_zero, nullptr);
}

void LiftoffAssembler::emit_i32_and(Register dst, Register lhs, Register rhs) {
  liftoff::EmitCommutativeBinOp<&Assembler::andl, &Assembler::movl>(this, dst,
                                                                    lhs, rhs);
}

void LiftoffAssembler::emit_i32_andi(Register dst, Register lhs, int32_t imm) {
  liftoff::EmitCommutativeBinOpImm<&Assembler::andl, &Assembler::movl>(
      this, dst, lhs, imm);
}

void LiftoffAssembler::emit_i32_or(Register dst, Register lhs, Register rhs) {
  liftoff::EmitCommutativeBinOp<&Assembler::orl, &Assembler::movl>(this, dst,
                                                                   lhs, rhs);
}

void LiftoffAssembler::emit_i32_ori(Register dst, Register lhs, int32_t imm) {
  liftoff::EmitCommutativeBinOpImm<&Assembler::orl, &Assembler::movl>(this, dst,
                                                                      lhs, imm);
}

void LiftoffAssembler::emit_i32_xor(Register dst, Register lhs, Register rhs) {
  liftoff::EmitCommutativeBinOp<&Assembler::xorl, &Assembler::movl>(this, dst,
                                                                    lhs, rhs);
}

void LiftoffAssembler::emit_i32_xori(Register dst, Register lhs, int32_t imm) {
  liftoff::EmitCommutativeBinOpImm<&Assembler::xorl, &Assembler::movl>(
      this, dst, lhs, imm);
}

namespace liftoff {
template <ValueKind kind>
inline void EmitShiftOperation(LiftoffAssembler* assm, Register dst,
                               Register src, Register amount,
                               void (Assembler::*emit_shift)(Register)) {
  // If dst is rcx, compute into the scratch register first, then move to rcx.
  if (dst == rcx) {
    assm->Move(kScratchRegister, src, kind);
    if (amount != rcx) assm->Move(rcx, amount, kind);
    (assm->*emit_shift)(kScratchRegister);
    assm->Move(rcx, kScratchRegister, kind);
    return;
  }

  // Move amount into rcx. If rcx is in use, move its content into the scratch
  // register. If src is rcx, src is now the scratch register.
  bool use_scratch = false;
  if (amount != rcx) {
    use_scratch =
        src == rcx || assm->cache_state()->is_used(LiftoffRegister(rcx));
    if (use_scratch) assm->movq(kScratchRegister, rcx);
    if (src == rcx) src = kScratchRegister;
    assm->Move(rcx, amount, kind);
  }

  // Do the actual shift.
  if (dst != src) assm->Move(dst, src, kind);
  (assm->*emit_shift)(dst);

  // Restore rcx if needed.
  if (use_scratch) assm->movq(rcx, kScratchRegister);
}
}  // namespace liftoff

void LiftoffAssembler::emit_i32_shl(Register dst, Register src,
                                    Register amount) {
  liftoff::EmitShiftOperation<kI32>(this, dst, src, amount,
                                    &Assembler::shll_cl);
}

void LiftoffAssembler::emit_i32_shli(Register dst, Register src,
                                     int32_t amount) {
  if (dst != src) movl(dst, src);
  shll(dst, Immediate(amount & 31));
}

void LiftoffAssembler::emit_i32_sar(Register dst, Register src,
                                    Register amount) {
  liftoff::EmitShiftOperation<kI32>(this, dst, src, amount,
                                    &Assembler::sarl_cl);
}

void LiftoffAssembler::emit_i32_sari(Register dst, Register src,
                                     int32_t amount) {
  if (dst != src) movl(dst, src);
  sarl(dst, Immediate(amount & 31));
}

void LiftoffAssembler::emit_i32_shr(Register dst, Register src,
                                    Register amount) {
  liftoff::EmitShiftOperation<kI32>(this, dst, src, amount,
                                    &Assembler::shrl_cl);
}

void LiftoffAssembler::emit_i32_shri(Register dst, Register src,
                                     int32_t amount) {
  if (dst != src) movl(dst, src);
  shrl(dst, Immediate(amount & 31));
}

void LiftoffAssembler::emit_i32_clz(Register dst, Register src) {
  Lzcntl(dst, src);
}

void LiftoffAssembler::emit_i32_ctz(Register dst, Register src) {
  Tzcntl(dst, src);
}

bool LiftoffAssembler::emit_i32_popcnt(Register dst, Register src) {
  if (!CpuFeatures::IsSupported(POPCNT)) return false;
  CpuFeatureScope scope(this, POPCNT);
  popcntl(dst, src);
  return true;
}

void LiftoffAssembler::emit_i64_add(LiftoffRegister dst, LiftoffRegister lhs,
                                    LiftoffRegister rhs) {
  if (lhs.gp() != dst.gp()) {
    leaq(dst.gp(), Operand(lhs.gp(), rhs.gp(), times_1, 0));
  } else {
    addq(dst.gp(), rhs.gp());
  }
}

void LiftoffAssembler::emit_i64_addi(LiftoffRegister dst, LiftoffRegister lhs,
                                     int64_t imm) {
  if (!is_int32(imm)) {
    MacroAssembler::Move(kScratchRegister, imm);
    if (lhs.gp() == dst.gp()) {
      addq(dst.gp(), kScratchRegister);
    } else {
      leaq(dst.gp(), Operand(lhs.gp(), kScratchRegister, times_1, 0));
    }
  } else if (lhs.gp() == dst.gp()) {
    addq(dst.gp(), Immediate(static_cast<int32_t>(imm)));
  } else {
    leaq(dst.gp(), Operand(lhs.gp(), static_cast<int32_t>(imm)));
  }
}

void LiftoffAssembler::emit_i64_sub(LiftoffRegister dst, LiftoffRegister lhs,
                                    LiftoffRegister rhs) {
  if (lhs.gp() == rhs.gp()) {
    xorq(dst.gp(), dst.gp());
  } else if (dst.gp() == rhs.gp()) {
    negq(dst.gp());
    addq(dst.gp(), lhs.gp());
  } else {
    if (dst.gp() != lhs.gp()) movq(dst.gp(), lhs.gp());
    subq(dst.gp(), rhs.gp());
  }
}

void LiftoffAssembler::emit_i64_mul(LiftoffRegister dst, LiftoffRegister lhs,
                                    LiftoffRegister rhs) {
  liftoff::EmitCommutativeBinOp<&Assembler::imulq, &Assembler::movq>(
      this, dst.gp(), lhs.gp(), rhs.gp());
}

void LiftoffAssembler::emit_i64_muli(LiftoffRegister dst, LiftoffRegister lhs,
                                     int32_t imm) {
  if (base::bits::IsPowerOfTwo(imm)) {
    emit_i64_shli(dst, lhs, base::bits::WhichPowerOfTwo(imm));
  } else {
    imulq(dst.gp(), lhs.gp(), Immediate{imm});
  }
}

bool LiftoffAssembler::emit_i64_divs(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs,
                                     Label* trap_div_by_zero,
                                     Label* trap_div_unrepresentable) {
  liftoff::EmitIntDivOrRem<int64_t, liftoff::DivOrRem::kDiv>(
      this, dst.gp(), lhs.gp(), rhs.gp(), trap_div_by_zero,
      trap_div_unrepresentable);
  return true;
}

bool LiftoffAssembler::emit_i64_divu(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs,
                                     Label* trap_div_by_zero) {
  liftoff::EmitIntDivOrRem<uint64_t, liftoff::DivOrRem::kDiv>(
      this, dst.gp(), lhs.gp(), rhs.gp(), trap_div_by_zero, nullptr);
  return true;
}

bool LiftoffAssembler::emit_i64_rems(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs,
                                     Label* trap_div_by_zero) {
  liftoff::EmitIntDivOrRem<int64_t, liftoff::DivOrRem::kRem>(
      this, dst.gp(), lhs.gp(), rhs.gp(), trap_div_by_zero, nullptr);
  return true;
}

bool LiftoffAssembler::emit_i64_remu(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs,
                                     Label* trap_div_by_zero) {
  liftoff::EmitIntDivOrRem<uint64_t, liftoff::DivOrRem::kRem>(
      this, dst.gp(), lhs.gp(), rhs.gp(), trap_div_by_zero, nullptr);
  return true;
}

void LiftoffAssembler::emit_i64_and(LiftoffRegister dst, LiftoffRegister lhs,
                                    LiftoffRegister rhs) {
  liftoff::EmitCommutativeBinOp<&Assembler::andq, &Assembler::movq>(
      this, dst.gp(), lhs.gp(), rhs.gp());
}

void LiftoffAssembler::emit_i64_andi(LiftoffRegister dst, LiftoffRegister lhs,
                                     int32_t imm) {
  liftoff::EmitCommutativeBinOpImm<&Assembler::andq, &Assembler::movq>(
      this, dst.gp(), lhs.gp(), imm);
}

void LiftoffAssembler::emit_i64_or(LiftoffRegister dst, LiftoffRegister lhs,
                                   LiftoffRegister rhs) {
  liftoff::EmitCommutativeBinOp<&Assembler::orq, &Assembler::movq>(
      this, dst.gp(), lhs.gp(), rhs.gp());
}

void LiftoffAssembler::emit_i64_ori(LiftoffRegister dst, LiftoffRegister lhs,
                                    int32_t imm) {
  liftoff::EmitCommutativeBinOpImm<&Assembler::orq, &Assembler::movq>(
      this, dst.gp(), lhs.gp(), imm);
}

void LiftoffAssembler::emit_i64_xor(LiftoffRegister dst, LiftoffRegister lhs,
                                    LiftoffRegister rhs) {
  liftoff::EmitCommutativeBinOp<&Assembler::xorq, &Assembler::movq>(
      this, dst.gp(), lhs.gp(), rhs.gp());
}

void LiftoffAssembler::emit_i64_xori(LiftoffRegister dst, LiftoffRegister lhs,
                                     int32_t imm) {
  liftoff::EmitCommutativeBinOpImm<&Assembler::xorq, &Assembler::movq>(
      this, dst.gp(), lhs.gp(), imm);
}

void LiftoffAssembler::emit_i64_shl(LiftoffRegister dst, LiftoffRegister src,
                                    Register amount) {
  liftoff::EmitShiftOperation<kI64>(this, dst.gp(), src.gp(), amount,
                                    &Assembler::shlq_cl);
}

void LiftoffAssembler::emit_i64_shli(LiftoffRegister dst, LiftoffRegister src,
                                     int32_t amount) {
  if (dst.gp() != src.gp()) movq(dst.gp(), src.gp());
  shlq(dst.gp(), Immediate(amount & 63));
}

void LiftoffAssembler::emit_i64_sar(LiftoffRegister dst, LiftoffRegister src,
                                    Register amount) {
  liftoff::EmitShiftOperation<kI64>(this, dst.gp(), src.gp(), amount,
                                    &Assembler::sarq_cl);
}

void LiftoffAssembler::emit_i64_sari(LiftoffRegister dst, LiftoffRegister src,
                                     int32_t amount) {
  if (dst.gp() != src.gp()) movq(dst.gp(), src.gp());
  sarq(dst.gp(), Immediate(amount & 63));
}

void LiftoffAssembler::emit_i64_shr(LiftoffRegister dst, LiftoffRegister src,
                                    Register amount) {
  liftoff::EmitShiftOperation<kI64>(this, dst.gp(), src.gp(), amount,
                                    &Assembler::shrq_cl);
}

void LiftoffAssembler::emit_i64_shri(LiftoffRegister dst, LiftoffRegister src,
                                     int32_t amount) {
  if (dst != src) movq(dst.gp(), src.gp());
  shrq(dst.gp(), Immediate(amount & 63));
}

void LiftoffAssembler::emit_i64_clz(LiftoffRegister dst, LiftoffRegister src) {
  Lzcntq(dst.gp(), src.gp());
}

void LiftoffAssembler::emit_i64_ctz(LiftoffRegister dst, LiftoffRegister src) {
  Tzcntq(dst.gp(), src.gp());
}

bool LiftoffAssembler::emit_i64_popcnt(LiftoffRegister dst,
                                       LiftoffRegister src) {
  if (!CpuFeatures::IsSupported(POPCNT)) return false;
  CpuFeatureScope scope(this, POPCNT);
  popcntq(dst.gp(), src.gp());
  return true;
}

void LiftoffAssembler::IncrementSmi(LiftoffRegister dst, int offset) {
  SmiAddConstant(Operand(dst.gp(), offset), Smi::FromInt(1));
}

void LiftoffAssembler::emit_u32_to_uintptr(Register dst, Register src) {
  AssertZeroExtended(src);
  if (dst != src) movl(dst, src);
}

void LiftoffAssembler::clear_i32_upper_half(Register dst) { movl(dst, dst); }

void LiftoffAssembler::emit_f32_add(DoubleRegister dst, DoubleRegister lhs,
                                    DoubleRegister rhs) {
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope scope(this, AVX);
    vaddss(dst, lhs, rhs);
  } else if (dst == rhs) {
    addss(dst, lhs);
  } else {
    if (dst != lhs) movss(dst, lhs);
    addss(dst, rhs);
  }
}

void LiftoffAssembler::emit_f32_sub(DoubleRegister dst, DoubleRegister lhs,
                                    DoubleRegister rhs) {
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope scope(this, AVX);
    vsubss(dst, lhs, rhs);
  } else if (dst == rhs) {
    movss(kScratchDoubleReg, rhs);
    movss(dst, lhs);
    subss(dst, kScratchDoubleReg);
  } else {
    if (dst != lhs) movss(dst, lhs);
    subss(dst, rhs);
  }
}

void LiftoffAssembler::emit_f32_mul(DoubleRegister dst, DoubleRegister lhs,
                                    DoubleRegister rhs) {
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope scope(this, AVX);
    vmulss(dst, lhs, rhs);
  } else if (dst == rhs) {
    mulss(dst, lhs);
  } else {
    if (dst != lhs) movss(dst, lhs);
    mulss(dst, rhs);
  }
}

void LiftoffAssembler::emit_f32_div(DoubleRegister dst, DoubleRegister lhs,
                                    DoubleRegister rhs) {
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope scope(this, AVX);
    vdivss(dst, lhs, rhs);
  } else if (dst == rhs) {
    movss(kScratchDoubleReg, rhs);
    movss(dst, lhs);
    divss(dst, kScratchDoubleReg);
  } else {
    if (dst != lhs) movss(dst, lhs);
    divss(dst, rhs);
  }
}

namespace liftoff {
enum class MinOrMax : uint8_t { kMin, kMax };
template <typename type>
inline void EmitFloatMinOrMax(LiftoffAssembler* assm, DoubleRegister dst,
                              DoubleRegister lhs, DoubleRegister rhs,
                              MinOrMax min_or_max) {
  Label is_nan;
  Label lhs_below_rhs;
  Label lhs_above_rhs;
  Label done;

#define dop(name, ...)            \
  do {                            \
    if (sizeof(type) == 4) {      \
      assm->name##s(__VA_ARGS__); \
    } else {                      \
      assm->name##d(__VA_ARGS__); \
    }                             \
  } while (false)

  // Check the easy cases first: nan (e.g. unordered), smaller and greater.
  // NaN has to be checked first, because PF=1 implies CF=1.
  dop(Ucomis, lhs, rhs);
  assm->j(parity_even, &is_nan, Label::kNear);   // PF=1
  assm->j(below, &lhs_below_rhs, Label::kNear);  // CF=1
  assm->j(above, &lhs_above_rhs, Label::kNear);  // CF=0 && ZF=0

  // If we get here, then either
  // a) {lhs == rhs},
  // b) {lhs == -0.0} and {rhs == 0.0}, or
  // c) {lhs == 0.0} and {rhs == -0.0}.
  // For a), it does not matter whether we return {lhs} or {rhs}. Check the sign
  // bit of {rhs} to differentiate b) and c).
  dop(Movmskp, kScratchRegister, rhs);
  assm->testl(kScratchRegister, Immediate(1));
  assm->j(zero, &lhs_below_rhs, Label::kNear);
  assm->jmp(&lhs_above_rhs, Label::kNear);

  assm->bind(&is_nan);
  // Create a NaN output.
  dop(Xorp, dst, dst);
  dop(Divs, dst, dst);
  assm->jmp(&done, Label::kNear);

  assm->bind(&lhs_below_rhs);
  DoubleRegister lhs_below_rhs_src = min_or_max == MinOrMax::kMin ? lhs : rhs;
  if (dst != lhs_below_rhs_src) dop(Movs, dst, lhs_below_rhs_src);
  assm->jmp(&done, Label::kNear);

  assm->bind(&lhs_above_rhs);
  DoubleRegister lhs_above_rhs_src = min_or_max == MinOrMax::kMin ? rhs : lhs;
  if (dst != lhs_above_rhs_src) dop(Movs, dst, lhs_above_rhs_src);

  assm->bind(&done);
}
}  // namespace liftoff

void LiftoffAssembler::emit_f32_min(DoubleRegister dst, DoubleRegister lhs,
                                    DoubleRegister rhs) {
  liftoff::EmitFloatMinOrMax<float>(this, dst, lhs, rhs,
                                    liftoff::MinOrMax::kMin);
}

void LiftoffAssembler::emit_f32_max(DoubleRegister dst, DoubleRegister lhs,
                                    DoubleRegister rhs) {
  liftoff::EmitFloatMinOrMax<float>(this, dst, lhs, rhs,
                                    liftoff::MinOrMax::kMax);
}

void LiftoffAssembler::emit_f32_copysign(DoubleRegister dst, DoubleRegister lhs,
                                         DoubleRegister rhs) {
  static constexpr int kF32SignBit = 1 << 31;
  Movd(kScratchRegister, lhs);
  andl(kScratchRegister, Immediate(~kF32SignBit));
  Movd(liftoff::kScratchRegister2, rhs);
  andl(liftoff::kScratchRegister2, Immediate(kF32SignBit));
  orl(kScratchRegister, liftoff::kScratchRegister2);
  Movd(dst, kScratchRegister);
}

void LiftoffAssembler::emit_f32_abs(DoubleRegister dst, DoubleRegister src) {
  static constexpr uint32_t kSignBit = uint32_t{1} << 31;
  if (dst == src) {
    MacroAssembler::Move(kScratchDoubleReg, kSignBit - 1);
    Andps(dst, kScratchDoubleReg);
  } else {
    MacroAssembler::Move(dst, kSignBit - 1);
    Andps(dst, src);
  }
}

void LiftoffAssembler::emit_f32_neg(DoubleRegister dst, DoubleRegister src) {
  static constexpr uint32_t kSignBit = uint32_t{1} << 31;
  if (dst == src) {
    MacroAssembler::Move(kScratchDoubleReg, kSignBit);
    Xorps(dst, kScratchDoubleReg);
  } else {
    MacroAssembler::Move(dst, kSignBit);
    Xorps(dst, src);
  }
}

bool LiftoffAssembler::emit_f32_ceil(DoubleRegister dst, DoubleRegister src) {
  RETURN_FALSE_IF_MISSING_CPU_FEATURE(SSE4_1);
  Roundss(dst, src, kRoundUp);
  return true;
}

bool LiftoffAssembler::emit_f32_floor(DoubleRegister dst, DoubleRegister src) {
  RETURN_FALSE_IF_MISSING_CPU_FEATURE(SSE4_1);
  Roundss(dst, src, kRoundDown);
  return true;
}

bool LiftoffAssembler::emit_f32_trunc(DoubleRegister dst, DoubleRegister src) {
  RETURN_FALSE_IF_MISSING_CPU_FEATURE(SSE4_1);
  Roundss(dst, src, kRoundToZero);
  return true;
}

bool LiftoffAssembler::emit_f32_nearest_int(DoubleRegister dst,
                                            DoubleRegister src) {
  RETURN_FALSE_IF_MISSING_CPU_FEATURE(SSE4_1);
  Roundss(dst, src, kRoundToNearest);
  return true;
}

void LiftoffAssembler::emit_f32_sqrt(DoubleRegister dst, DoubleRegister src) {
  Sqrtss(dst, src);
}

void LiftoffAssembler::emit_f64_add(DoubleRegister dst, DoubleRegister lhs,
                                    DoubleRegister rhs) {
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope scope(this, AVX);
    vaddsd(dst, lhs, rhs);
  } else if (dst == rhs) {
    addsd(dst, lhs);
  } else {
    if (dst != lhs) movsd(dst, lhs);
    addsd(dst, rhs);
  }
}

void LiftoffAssembler::emit_f64_sub(DoubleRegister dst, DoubleRegister lhs,
                                    DoubleRegister rhs) {
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope scope(this, AVX);
    vsubsd(dst, lhs, rhs);
  } else if (dst == rhs) {
    movsd(kScratchDoubleReg, rhs);
    movsd(dst, lhs);
    subsd(dst, kScratchDoubleReg);
  } else {
    if (dst != lhs) movsd(dst, lhs);
    subsd(dst, rhs);
  }
}

void LiftoffAssembler::emit_f64_mul(DoubleRegister dst, DoubleRegister lhs,
                                    DoubleRegister rhs) {
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope scope(this, AVX);
    vmulsd(dst, lhs, rhs);
  } else if (dst == rhs) {
    mulsd(dst, lhs);
  } else {
    if (dst != lhs) movsd(dst, lhs);
    mulsd(dst, rhs);
  }
}

void LiftoffAssembler::emit_f64_div(DoubleRegister dst, DoubleRegister lhs,
                                    DoubleRegister rhs) {
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope scope(this, AVX);
    vdivsd(dst, lhs, rhs);
  } else if (dst == rhs) {
    movsd(kScratchDoubleReg, rhs);
    movsd(dst, lhs);
    divsd(dst, kScratchDoubleReg);
  } else {
    if (
"""


```