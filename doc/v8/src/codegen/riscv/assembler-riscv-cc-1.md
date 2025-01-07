Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/codegen/riscv/assembler-riscv.cc`.

Here's a breakdown of the code's responsibilities:

1. **Label Management (`label_at_put`):**  Handles the placement and linking of labels within the generated code. This is crucial for control flow, allowing jumps and branches to specific points in the code.

2. **Instruction Emission:** Provides methods to emit RISC-V instructions, including handling compressed instructions and pseudo-instructions (like `nop`).

3. **Immediate Value Loading (`RV_li`, `GeneralLi`, `li_ptr`, `li_constant`, `li_constant32`):**  Offers various strategies for loading immediate values (constants) into registers. This is architecture-dependent and involves potentially multiple instructions to construct larger immediate values. It needs to consider the availability of temporary registers for efficiency.

4. **Breakpoints and Stops (`break_`, `stop`):**  Implements mechanisms for inserting breakpoints or stop instructions in the generated code, often used for debugging.

5. **Memory Access (`NeedAdjustBaseAndOffset`, `AdjustBaseAndOffset`):** Deals with loading and storing data from memory. It handles cases where the memory offset is too large to fit in the immediate field of a single instruction, adjusting the base register and offset accordingly.

6. **Relocation (`RelocateInternalReference`, `RelocateRelativeReference`):**  Manages the process of updating addresses in the generated code when the code is moved in memory. This is essential for dynamic code generation.

7. **Buffer Management (`GrowBuffer`):**  Dynamically increases the size of the code buffer when needed.

8. **Data Emission (`db`, `dd`, `dq`, `dd(Label*)`):**  Provides functions to directly insert raw byte, word, or quad-word data into the code stream. It also handles emitting the address of a label.

9. **Relocation Information Recording (`RecordRelocInfo`):**  Stores information about where relocatable values are located in the code, needed for the relocation process.

10. **Trampoline Pool Management (`BlockTrampolinePoolFor`, `CheckTrampolinePool`):** Implements a trampoline pool mechanism. Trampolines are small code snippets used to jump to locations that are too far for a direct branch instruction. This involves managing when to insert these trampolines and ensuring they don't disrupt other code sequences.

11. **Target Address Manipulation (`set_target_address_at`, `target_address_at`, `set_target_value_at`):**  Provides functions to read and modify target addresses embedded within instructions. This is often used for patching code or updating function pointers.

12. **Constant Pool Handling (`IsConstantPoolAt`, `ConstantPoolSizeAt`, `RecordConstPool`, `EmitPoolGuard`):** Deals with constant pools, which are regions of memory holding constant values used by the generated code.

13. **Low-level Emission (`EmitHelper`, `emit`):**  Provides the fundamental mechanism for writing instruction bytes to the buffer.

Regarding the user's specific questions:

* **`.tq` extension:** The code is C++, not Torque.
* **JavaScript relation:** The assembler generates machine code that executes JavaScript. Loading immediate values is a common operation needed when executing JavaScript.
* **Code logic reasoning:** The `label_at_put` function demonstrates logic for handling bound and unbound labels, and the `GeneralLi` function shows different strategies for loading immediate values.
* **Common programming errors:**  Incorrectly calculating or handling memory offsets can lead to crashes.

这是 `v8/src/codegen/riscv/assembler-riscv.cc` 源代码的第二部分，它主要负责以下功能：

1. **标签处理的收尾工作:**  `::label_at_put` 函数处理标签的最终放置和链接。如果标签已经绑定，则直接写入目标地址。如果标签未绑定，则根据是否已经链接过采取不同的策略，例如创建跳转链或者预留跳转槽。

2. **指令定义:**  定义了一些基本的 RISC-V 指令，例如 `NOP` 和 `EBREAK`，并考虑了是否存在压缩指令扩展 (`v8_flags.riscv_c_extension`)。

3. **伪指令实现:**  实现了 `nop` 伪指令。

4. **立即数加载的多种策略 (RV64 和 RV32 分别实现):**
   - 提供了 `RV_li` 函数，用于将立即数加载到寄存器中。它会根据立即数的大小和是否需要临时寄存器，选择不同的加载方式 (`GeneralLi` 或 `RecursiveLi`，尽管 `RecursiveLi` 的代码未在此段提供)。
   - `GeneralLi` 函数针对 64 位立即数提供了更细致的处理，包括使用临时寄存器优化加载过程，以及处理高低 32 位的情况。
   - `li_ptr` 函数用于加载指针地址，针对 RISC-V 的 SV39 和非 SV39 内存模型有不同的实现。
   - `li_constant` 和 `li_constant32` 函数提供了加载常数的特定方式。

5. **断点和停止指令:**  提供了 `break_` 和 `stop` 函数，用于在生成的代码中插入断点或停止指令，通常用于调试目的。`break_` 函数使用 `lui` 指令的立即数字段来编码额外的代码信息。

6. **内存操作的辅助函数:**
   - `NeedAdjustBaseAndOffset` 函数判断内存操作数是否需要调整基址寄存器和偏移量，以适应 12 位立即数偏移的限制。
   - `AdjustBaseAndOffset` 函数实际执行基址寄存器和偏移量的调整，将偏移量加载到临时寄存器中，并更新内存操作数。

7. **重定位处理:**
   - `RelocateInternalReference` 函数用于重定位内部引用，即代码块内部的跳转目标。
   - `RelocateRelativeReference` 函数用于重定位相对引用，例如跳转到附近的内置函数。

8. **缓冲区增长:** `GrowBuffer` 函数负责在代码缓冲区空间不足时动态增长缓冲区的大小，并更新相关的指针和重定位信息。

9. **数据直接写入:** 提供了 `db`，`dd`，`dq` 等函数，用于将字节、双字、四字等数据直接写入到代码缓冲区中。`dd(Label*)` 用于写入标签的地址。

10. **重定位信息记录:** `RecordRelocInfo` 函数用于记录需要进行重定位的信息，例如内部引用、常量池等。

11. **Trampoline 池的管理:**
    - `BlockTrampolinePoolFor` 函数用于临时阻止 Trampoline 池的插入。
    - `CheckTrampolinePool` 函数检查是否需要插入 Trampoline 池来处理超出直接跳转范围的跳转目标。如果需要，它会生成一个跳转到 Trampoline 池的指令，并在池中生成实际的长跳转指令。

12. **目标地址的设置和获取:**
    - `set_target_address_at` 函数用于设置指定地址的指令序列的目标地址，会根据指令类型选择合适的修改方式，并刷新指令缓存。
    - `target_address_at` 函数用于获取指定地址的指令序列的目标地址。

13. **常量池处理:**
    - `IsConstantPoolAt` 函数判断指定地址是否是常量池标记。
    - `ConstantPoolSizeAt` 函数获取常量池的大小。
    - `RecordConstPool` 函数记录常量池信息。
    - `EmitPoolGuard` 函数用于发射常量池的保护指令。

14. **底层发射辅助函数:** `EmitHelper` 函数是用于将特定类型的数据写入代码缓冲区的底层辅助函数。

**用 JavaScript 举例说明与立即数加载的关系 (假设，简化概念):**

```javascript
function add(a, b) {
  return a + b;
}
```

当 V8 编译 `add` 函数时，它可能需要将常数加载到寄存器中，例如，在某些内部操作中，或者如果 `a` 或 `b` 是立即数。 `Assembler::RV_li` 等函数就负责生成将这些常数加载到 RISC-V 寄存器的机器码指令。

**代码逻辑推理示例 (`label_at_put`):**

**假设输入:**
- `L`: 一个未绑定且未链接的标签对象。
- `at_offset`: 当前需要放置标签的位置偏移量，比如 `100`。

**输出:**
- 在偏移量 `100` 的位置写入一个表示跳转链末尾的值 (`kEndOfJumpChain`)。
- 标签对象 `L` 被标记为已链接到偏移量 `100`。
- `unbound_labels_count_` 增加。
- `next_buffer_check_` 减小 `kTrampolineSlotsSize`。

**用户常见的编程错误 (与内存操作相关):**

一个常见的错误是在使用 `MemOperand` 时，计算偏移量时出现错误，导致访问了错误的内存地址。例如：

```c++
// 错误示例
void foo(Assembler& assm, Register base, int* array) {
  // 假设想访问数组的第三个元素（索引为 2）
  // 错误的偏移量计算，假设 int 大小为 4 字节
  MemOperand operand(base, 2); // 错误：这里直接使用了索引值，而不是字节偏移量
  assm.lw(t0, operand); // 加载的将是相对于 base 地址偏移 2 字节的内容，而不是第三个 int 元素
}

// 正确示例
void bar(Assembler& assm, Register base, int* array) {
  MemOperand operand(base, 2 * sizeof(int)); // 正确：使用字节偏移量
  assm.lw(t0, operand);
}
```

在这个错误的例子中，程序员直接使用了数组索引作为偏移量，而没有乘以元素的大小，导致访问了错误的内存位置，可能导致程序崩溃或产生未定义的行为。

**归纳一下它的功能 (第 2 部分):**

`v8/src/codegen/riscv/assembler-riscv.cc` 的第二部分主要负责 **代码生成的具体实现细节**，包括：

- **更精细的指令生成和优化:**  例如，针对不同大小的立即数选择最优的加载方式。
- **复杂的控制流管理:**  通过 Trampoline 池机制处理远距离跳转。
- **内存访问的细节处理:**  确保内存操作的正确性和效率。
- **代码缓冲区的管理和维护:**  保证代码生成过程中的空间需求。
- **为代码重定位和调试提供必要的支持。**

这部分代码是连接高级代码生成逻辑和底层机器码指令的关键桥梁。

Prompt: 
```
这是目录为v8/src/codegen/riscv/assembler-riscv.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/riscv/assembler-riscv.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能

"""
::label_at_put(Label* L, int at_offset) {
  int target_pos;
  DEBUG_PRINTF("\tlabel_at_put: %p @ %p (%d)\n", L,
               reinterpret_cast<Instr*>(buffer_start_ + at_offset), at_offset);
  if (L->is_bound()) {
    target_pos = L->pos();
    instr_at_put(at_offset, target_pos + (InstructionStream::kHeaderSize -
                                          kHeapObjectTag));
  } else {
    if (L->is_linked()) {
      target_pos = L->pos();  // L's link.
      int32_t imm18 = target_pos - at_offset;
      DCHECK_EQ(imm18 & 3, 0);
      int32_t imm16 = imm18 >> 2;
      DCHECK(is_int16(imm16));
      instr_at_put(at_offset, (int32_t)(imm16 & kImm16Mask));
    } else {
      target_pos = kEndOfJumpChain;
      instr_at_put(at_offset, target_pos);
      if (!trampoline_emitted_) {
        unbound_labels_count_++;
        next_buffer_check_ -= kTrampolineSlotsSize;
      }
    }
    L->link_to(at_offset);
  }
}

//===----------------------------------------------------------------------===//
// Instructions
//===----------------------------------------------------------------------===//

// Definitions for using compressed vs non compressed

void Assembler::NOP() {
  if (v8_flags.riscv_c_extension)
    c_nop();
  else
    nop();
}

void Assembler::EBREAK() {
  if (v8_flags.riscv_c_extension)
    c_ebreak();
  else
    ebreak();
}

// Assembler Pseudo Instructions (Tables 25.2 and 25.3, RISC-V Unprivileged ISA)

void Assembler::nop() { addi(ToRegister(0), ToRegister(0), 0); }

inline int64_t signExtend(uint64_t V, int N) {
  return int64_t(V << (64 - N)) >> (64 - N);
}

#if V8_TARGET_ARCH_RISCV64
void Assembler::RV_li(Register rd, int64_t imm) {
  UseScratchRegisterScope temps(this);
  if (RecursiveLiCount(imm) > GeneralLiCount(imm, temps.CanAcquire())) {
    GeneralLi(rd, imm);
  } else {
    RecursiveLi(rd, imm);
  }
}

int Assembler::RV_li_count(int64_t imm, bool is_get_temp_reg) {
  if (RecursiveLiCount(imm) > GeneralLiCount(imm, is_get_temp_reg)) {
    return GeneralLiCount(imm, is_get_temp_reg);
  } else {
    return RecursiveLiCount(imm);
  }
}

void Assembler::GeneralLi(Register rd, int64_t imm) {
  // 64-bit imm is put in the register rd.
  // In most cases the imm is 32 bit and 2 instructions are generated. If a
  // temporary register is available, in the worst case, 6 instructions are
  // generated for a full 64-bit immediate. If temporay register is not
  // available the maximum will be 8 instructions. If imm is more than 32 bits
  // and a temp register is available, imm is divided into two 32-bit parts,
  // low_32 and up_32. Each part is built in a separate register. low_32 is
  // built before up_32. If low_32 is negative (upper 32 bits are 1), 0xffffffff
  // is subtracted from up_32 before up_32 is built. This compensates for 32
  // bits of 1's in the lower when the two registers are added. If no temp is
  // available, the upper 32 bit is built in rd, and the lower 32 bits are
  // devided to 3 parts (11, 11, and 10 bits). The parts are shifted and added
  // to the upper part built in rd.
  if (is_int32(imm + 0x800)) {
    // 32-bit case. Maximum of 2 instructions generated
    int64_t high_20 = ((imm + 0x800) >> 12);
    int64_t low_12 = imm << 52 >> 52;
    if (high_20) {
      lui(rd, (int32_t)high_20);
      if (low_12) {
        addi(rd, rd, low_12);
      }
    } else {
      addi(rd, zero_reg, low_12);
    }
    return;
  } else {
    UseScratchRegisterScope temps(this);
    // 64-bit case: divide imm into two 32-bit parts, upper and lower
    int64_t up_32 = imm >> 32;
    int64_t low_32 = imm & 0xffffffffull;
    Register temp_reg = rd;
    // Check if a temporary register is available
    if (up_32 == 0 || low_32 == 0) {
      // No temp register is needed
    } else {
      BlockTrampolinePoolScope block_trampoline_pool(this);
      temp_reg = temps.CanAcquire() ? temps.Acquire() : no_reg;
    }
    if (temp_reg != no_reg) {
      // keep track of hardware behavior for lower part in sim_low
      int64_t sim_low = 0;
      // Build lower part
      if (low_32 != 0) {
        int64_t high_20 = ((low_32 + 0x800) >> 12);
        int64_t low_12 = low_32 & 0xfff;
        if (high_20) {
          // Adjust to 20 bits for the case of overflow
          high_20 &= 0xfffff;
          sim_low = ((high_20 << 12) << 32) >> 32;
          lui(rd, (int32_t)high_20);
          if (low_12) {
            sim_low += (low_12 << 52 >> 52) | low_12;
            addi(rd, rd, low_12);
          }
        } else {
          sim_low = low_12;
          ori(rd, zero_reg, low_12);
        }
      }
      if (sim_low & 0x100000000) {
        // Bit 31 is 1. Either an overflow or a negative 64 bit
        if (up_32 == 0) {
          // Positive number, but overflow because of the add 0x800
          slli(rd, rd, 32);
          srli(rd, rd, 32);
          return;
        }
        // low_32 is a negative 64 bit after the build
        up_32 = (up_32 - 0xffffffff) & 0xffffffff;
      }
      if (up_32 == 0) {
        return;
      }
      // Build upper part in a temporary register
      if (low_32 == 0) {
        // Build upper part in rd
        temp_reg = rd;
      }
      int64_t high_20 = (up_32 + 0x800) >> 12;
      int64_t low_12 = up_32 & 0xfff;
      if (high_20) {
        // Adjust to 20 bits for the case of overflow
        high_20 &= 0xfffff;
        lui(temp_reg, (int32_t)high_20);
        if (low_12) {
          addi(temp_reg, temp_reg, low_12);
        }
      } else {
        ori(temp_reg, zero_reg, low_12);
      }
      // Put it at the bgining of register
      slli(temp_reg, temp_reg, 32);
      if (low_32 != 0) {
        add(rd, rd, temp_reg);
      }
      return;
    }
    // No temp register. Build imm in rd.
    // Build upper 32 bits first in rd. Divide lower 32 bits parts and add
    // parts to the upper part by doing shift and add.
    // First build upper part in rd.
    int64_t high_20 = (up_32 + 0x800) >> 12;
    int64_t low_12 = up_32 & 0xfff;
    if (high_20) {
      // Adjust to 20 bits for the case of overflow
      high_20 &= 0xfffff;
      lui(rd, (int32_t)high_20);
      if (low_12) {
        addi(rd, rd, low_12);
      }
    } else {
      ori(rd, zero_reg, low_12);
    }
    // upper part already in rd. Each part to be added to rd, has maximum of 11
    // bits, and always starts with a 1. rd is shifted by the size of the part
    // plus the number of zeros between the parts. Each part is added after the
    // left shift.
    uint32_t mask = 0x80000000;
    int32_t shift_val = 0;
    int32_t i;
    for (i = 0; i < 32; i++) {
      if ((low_32 & mask) == 0) {
        mask >>= 1;
        shift_val++;
        if (i == 31) {
          // rest is zero
          slli(rd, rd, shift_val);
        }
        continue;
      }
      // The first 1 seen
      int32_t part;
      if ((i + 11) < 32) {
        // Pick 11 bits
        part = ((uint32_t)(low_32 << i) >> i) >> (32 - (i + 11));
        slli(rd, rd, shift_val + 11);
        ori(rd, rd, part);
        i += 10;
        mask >>= 11;
      } else {
        part = (uint32_t)(low_32 << i) >> i;
        slli(rd, rd, shift_val + (32 - i));
        ori(rd, rd, part);
        break;
      }
      shift_val = 0;
    }
  }
}

void Assembler::li_ptr(Register rd, int64_t imm) {
#ifdef RISCV_USE_SV39
  // Initialize rd with an address
  // Pointers are 39 bits
  // 4 fixed instructions are generated
  DCHECK_EQ((imm & 0xffffff8000000000ll), 0);
  int64_t a8 = imm & 0xff;                      // bits 0:7. 8 bits
  int64_t high_31 = (imm >> 8) & 0x7fffffff;    // 31 bits
  int64_t high_20 = ((high_31 + 0x800) >> 12);  // 19 bits
  int64_t low_12 = high_31 & 0xfff;             // 12 bits
  lui(rd, (int32_t)high_20);
  addi(rd, rd, low_12);  // 31 bits in rd.
  slli(rd, rd, 8);       // Space for next 8 bis
  ori(rd, rd, a8);       // 8 bits are put in.
#else
  // Initialize rd with an address
  // Pointers are 48 bits
  // 6 fixed instructions are generated
  DCHECK_EQ((imm & 0xfff0000000000000ll), 0);
  int64_t a6 = imm & 0x3f;                      // bits 0:5. 6 bits
  int64_t b11 = (imm >> 6) & 0x7ff;             // bits 6:11. 11 bits
  int64_t high_31 = (imm >> 17) & 0x7fffffff;   // 31 bits
  int64_t high_20 = ((high_31 + 0x800) >> 12);  // 19 bits
  int64_t low_12 = high_31 & 0xfff;             // 12 bits
  lui(rd, (int32_t)high_20);
  addi(rd, rd, low_12);  // 31 bits in rd.
  slli(rd, rd, 11);      // Space for next 11 bis
  ori(rd, rd, b11);      // 11 bits are put in. 42 bit in rd
  slli(rd, rd, 6);       // Space for next 6 bits
  ori(rd, rd, a6);       // 6 bits are put in. 48 bis in rd
#endif
}

void Assembler::li_constant(Register rd, int64_t imm) {
  DEBUG_PRINTF("\tli_constant(%d, %" PRIx64 " <%" PRId64 ">)\n", ToNumber(rd),
               imm, imm);
  lui(rd, (imm + (1LL << 47) + (1LL << 35) + (1LL << 23) + (1LL << 11)) >>
              48);  // Bits 63:48
  addiw(rd, rd,
        (imm + (1LL << 35) + (1LL << 23) + (1LL << 11)) << 16 >>
            52);  // Bits 47:36
  slli(rd, rd, 12);
  addi(rd, rd, (imm + (1LL << 23) + (1LL << 11)) << 28 >> 52);  // Bits 35:24
  slli(rd, rd, 12);
  addi(rd, rd, (imm + (1LL << 11)) << 40 >> 52);  // Bits 23:12
  slli(rd, rd, 12);
  addi(rd, rd, imm << 52 >> 52);  // Bits 11:0
}

void Assembler::li_constant32(Register rd, int32_t imm) {
  ASM_CODE_COMMENT(this);
  DEBUG_PRINTF("\tli_constant(%d, %x <%d>)\n", ToNumber(rd), imm, imm);
  int32_t high_20 = ((imm + 0x800) >> 12);  // bits31:12
  int32_t low_12 = imm & 0xfff;             // bits11:0
  lui(rd, high_20);
  addi(rd, rd, low_12);
}

#elif V8_TARGET_ARCH_RISCV32
void Assembler::RV_li(Register rd, int32_t imm) {
  int32_t high_20 = ((imm + 0x800) >> 12);
  int32_t low_12 = imm & 0xfff;
  if (high_20) {
    lui(rd, high_20);
    if (low_12) {
      addi(rd, rd, low_12);
    }
  } else {
    addi(rd, zero_reg, low_12);
  }
}

int Assembler::RV_li_count(int32_t imm, bool is_get_temp_reg) {
  int count = 0;
  // imitate Assembler::RV_li
  int32_t high_20 = ((imm + 0x800) >> 12);
  int32_t low_12 = imm & 0xfff;
  if (high_20) {
    count++;
    if (low_12) {
      count++;
    }
  } else {
    // if high_20 is 0, always need one instruction to load the low_12 bit
    count++;
  }

  return count;
}

void Assembler::li_ptr(Register rd, int32_t imm) {
  // Initialize rd with an address
  // Pointers are 32 bits
  // 2 fixed instructions are generated
  int32_t high_20 = ((imm + 0x800) >> 12);  // bits31:12
  int32_t low_12 = imm & 0xfff;             // bits11:0
  lui(rd, high_20);
  addi(rd, rd, low_12);
}

void Assembler::li_constant(Register rd, int32_t imm) {
  ASM_CODE_COMMENT(this);
  DEBUG_PRINTF("\tli_constant(%d, %x <%d>)\n", ToNumber(rd), imm, imm);
  int32_t high_20 = ((imm + 0x800) >> 12);  // bits31:12
  int32_t low_12 = imm & 0xfff;             // bits11:0
  lui(rd, high_20);
  addi(rd, rd, low_12);
}
#endif

// Break / Trap instructions.
void Assembler::break_(uint32_t code, bool break_as_stop) {
  // We need to invalidate breaks that could be stops as well because the
  // simulator expects a char pointer after the stop instruction.
  // See base-constants-riscv.h for explanation.
  DCHECK(
      (break_as_stop && code <= kMaxStopCode && code > kMaxTracepointCode) ||
      (!break_as_stop && (code > kMaxStopCode || code <= kMaxTracepointCode)));

  // since ebreak does not allow additional immediate field, we use the
  // immediate field of lui instruction immediately following the ebreak to
  // encode the "code" info
  ebreak();
  DCHECK(is_uint20(code));
  lui(zero_reg, code);
}

void Assembler::stop(uint32_t code) {
  DCHECK_GT(code, kMaxWatchpointCode);
  DCHECK_LE(code, kMaxStopCode);
#if defined(V8_HOST_ARCH_RISCV64) || defined(V8_HOST_ARCH_RISCV32)
  break_(0x54321);
#else  // V8_HOST_ARCH_RISCV64 || V8_HOST_ARCH_RISCV32
  break_(code, true);
#endif
}

// Original MIPS Instructions

// ------------Memory-instructions-------------

bool Assembler::NeedAdjustBaseAndOffset(const MemOperand& src,
                                        OffsetAccessType access_type,
                                        int second_access_add_to_offset) {
  bool two_accesses = static_cast<bool>(access_type);
  DCHECK_LE(second_access_add_to_offset, 7);  // Must be <= 7.

  // is_int12 must be passed a signed value, hence the static cast below.
  if (is_int12(src.offset()) &&
      (!two_accesses || is_int12(static_cast<int32_t>(
                            src.offset() + second_access_add_to_offset)))) {
    // Nothing to do: 'offset' (and, if needed, 'offset + 4', or other specified
    // value) fits into int12.
    return false;
  }
  return true;
}

void Assembler::AdjustBaseAndOffset(MemOperand* src, Register scratch,
                                    OffsetAccessType access_type,
                                    int second_Access_add_to_offset) {
  // This method is used to adjust the base register and offset pair
  // for a load/store when the offset doesn't fit into int12.

  // Must not overwrite the register 'base' while loading 'offset'.
  constexpr int32_t kMinOffsetForSimpleAdjustment = 0x7F8;
  constexpr int32_t kMaxOffsetForSimpleAdjustment =
      2 * kMinOffsetForSimpleAdjustment;
  if (0 <= src->offset() && src->offset() <= kMaxOffsetForSimpleAdjustment) {
    addi(scratch, src->rm(), kMinOffsetForSimpleAdjustment);
    src->offset_ -= kMinOffsetForSimpleAdjustment;
  } else if (-kMaxOffsetForSimpleAdjustment <= src->offset() &&
             src->offset() < 0) {
    addi(scratch, src->rm(), -kMinOffsetForSimpleAdjustment);
    src->offset_ += kMinOffsetForSimpleAdjustment;
  } else if (access_type == OffsetAccessType::SINGLE_ACCESS) {
    RV_li(scratch, (static_cast<intptr_t>(src->offset()) + 0x800) >> 12 << 12);
    add(scratch, scratch, src->rm());
    src->offset_ = src->offset() << 20 >> 20;
  } else {
    RV_li(scratch, src->offset());
    add(scratch, scratch, src->rm());
    src->offset_ = 0;
  }
  src->rm_ = scratch;
}

int Assembler::RelocateInternalReference(RelocInfo::Mode rmode, Address pc,
                                         intptr_t pc_delta) {
  if (RelocInfo::IsInternalReference(rmode)) {
    intptr_t* p = reinterpret_cast<intptr_t*>(pc);
    if (*p == kEndOfJumpChain) {
      return 0;  // Number of instructions patched.
    }
    *p += pc_delta;
    return 2;  // Number of instructions patched.
  }
  Instr instr = instr_at(pc);
  DCHECK(RelocInfo::IsInternalReferenceEncoded(rmode));
  if (IsLui(instr)) {
    uintptr_t target_address = target_address_at(pc) + pc_delta;
    DEBUG_PRINTF("\ttarget_address 0x%" PRIxPTR "\n", target_address);
    set_target_value_at(pc, target_address);
#if V8_TARGET_ARCH_RISCV64
#ifdef RISCV_USE_SV39
    return 6;  // Number of instructions patched.
#else
    return 8;  // Number of instructions patched.
#endif
#elif V8_TARGET_ARCH_RISCV32
    return 2;  // Number of instructions patched.
#endif
  } else {
    UNIMPLEMENTED();
  }
}

void Assembler::RelocateRelativeReference(RelocInfo::Mode rmode, Address pc,
                                          intptr_t pc_delta) {
  Instr instr = instr_at(pc);
  Instr instr1 = instr_at(pc + 1 * kInstrSize);
  DCHECK(RelocInfo::IsRelativeCodeTarget(rmode) ||
         RelocInfo::IsNearBuiltinEntry(rmode));
  if (IsAuipc(instr) && IsJalr(instr1)) {
    int32_t imm;
    imm = BrachlongOffset(instr, instr1);
    imm -= pc_delta;
    PatchBranchlongOffset(pc, instr, instr1, imm);
    return;
  } else {
    UNREACHABLE();
  }
}

void Assembler::GrowBuffer() {
  DEBUG_PRINTF("GrowBuffer: %p -> ", buffer_start_);
  // Compute new buffer size.
  int old_size = buffer_->size();
  int new_size = std::min(2 * old_size, old_size + 1 * MB);

  // Some internal data structures overflow for very large buffers,
  // they must ensure that kMaximalBufferSize is not too large.
  if (new_size > kMaximalBufferSize) {
    V8::FatalProcessOutOfMemory(nullptr, "Assembler::GrowBuffer");
  }

  // Set up new buffer.
  std::unique_ptr<AssemblerBuffer> new_buffer = buffer_->Grow(new_size);
  DCHECK_EQ(new_size, new_buffer->size());
  uint8_t* new_start = new_buffer->start();

  // Copy the data.
  intptr_t pc_delta = new_start - buffer_start_;
  intptr_t rc_delta = (new_start + new_size) - (buffer_start_ + old_size);
  size_t reloc_size = (buffer_start_ + old_size) - reloc_info_writer.pos();
  MemMove(new_start, buffer_start_, pc_offset());
  MemMove(reloc_info_writer.pos() + rc_delta, reloc_info_writer.pos(),
          reloc_size);

  // Switch buffers.
  buffer_ = std::move(new_buffer);
  buffer_start_ = new_start;
  DEBUG_PRINTF("%p\n", buffer_start_);
  pc_ += pc_delta;
  reloc_info_writer.Reposition(reloc_info_writer.pos() + rc_delta,
                               reloc_info_writer.last_pc() + pc_delta);

  // Relocate runtime entries.
  base::Vector<uint8_t> instructions{buffer_start_,
                                     static_cast<size_t>(pc_offset())};
  base::Vector<const uint8_t> reloc_info{reloc_info_writer.pos(), reloc_size};
  for (RelocIterator it(instructions, reloc_info, 0); !it.done(); it.next()) {
    RelocInfo::Mode rmode = it.rinfo()->rmode();
    if (rmode == RelocInfo::INTERNAL_REFERENCE) {
      RelocateInternalReference(rmode, it.rinfo()->pc(), pc_delta);
    }
  }

  DCHECK(!overflow());
}

void Assembler::db(uint8_t data) {
  if (!is_buffer_growth_blocked()) CheckBuffer();
  DEBUG_PRINTF("%p(%d): constant 0x%x\n", pc_, pc_offset(), data);
  EmitHelper(data);
}

void Assembler::dd(uint32_t data) {
  if (!is_buffer_growth_blocked()) CheckBuffer();
  DEBUG_PRINTF("%p(%d): constant 0x%x\n", pc_, pc_offset(), data);
  EmitHelper(data);
}

void Assembler::dq(uint64_t data) {
  if (!is_buffer_growth_blocked()) CheckBuffer();
  DEBUG_PRINTF("%p(%d): constant 0x%" PRIx64 "\n", pc_, pc_offset(), data);
  EmitHelper(data);
}

void Assembler::dd(Label* label) {
  uintptr_t data;
  if (!is_buffer_growth_blocked()) CheckBuffer();
  if (label->is_bound()) {
    data = reinterpret_cast<uintptr_t>(buffer_start_ + label->pos());
  } else {
    data = jump_address(label);
    internal_reference_positions_.insert(label->pos());
  }
  RecordRelocInfo(RelocInfo::INTERNAL_REFERENCE);
  EmitHelper(data);
}

void Assembler::RecordRelocInfo(RelocInfo::Mode rmode, intptr_t data) {
  if (!ShouldRecordRelocInfo(rmode)) return;
  // We do not try to reuse pool constants.
  RelocInfo rinfo(reinterpret_cast<Address>(pc_), rmode, data);
  DCHECK_GE(buffer_space(), kMaxRelocSize);  // Too late to grow buffer here.
  reloc_info_writer.Write(&rinfo);
}

void Assembler::BlockTrampolinePoolFor(int instructions) {
  DEBUG_PRINTF("\tBlockTrampolinePoolFor %d", instructions);
  CheckTrampolinePoolQuick(instructions);
  DEBUG_PRINTF("\tpc_offset %d,BlockTrampolinePoolBefore %d\n", pc_offset(),
               pc_offset() + instructions * kInstrSize);
  BlockTrampolinePoolBefore(pc_offset() + instructions * kInstrSize);
}

void Assembler::CheckTrampolinePool() {
  // Some small sequences of instructions must not be broken up by the
  // insertion of a trampoline pool; such sequences are protected by setting
  // either trampoline_pool_blocked_nesting_ or no_trampoline_pool_before_,
  // which are both checked here. Also, recursive calls to CheckTrampolinePool
  // are blocked by trampoline_pool_blocked_nesting_.
  DEBUG_PRINTF("\tpc_offset %d no_trampoline_pool_before:%d\n", pc_offset(),
               no_trampoline_pool_before_);
  DEBUG_PRINTF("\ttrampoline_pool_blocked_nesting:%d\n",
               trampoline_pool_blocked_nesting_);
  if ((trampoline_pool_blocked_nesting_ > 0) ||
      (pc_offset() < no_trampoline_pool_before_)) {
    // Emission is currently blocked; make sure we try again as soon as
    // possible.
    if (trampoline_pool_blocked_nesting_ > 0) {
      next_buffer_check_ = pc_offset() + kInstrSize;
    } else {
      next_buffer_check_ = no_trampoline_pool_before_;
    }
    return;
  }

  DCHECK(!trampoline_emitted_);
  DCHECK_GE(unbound_labels_count_, 0);
  if (unbound_labels_count_ > 0) {
    // First we emit jump, then we emit trampoline pool.
    {
      DEBUG_PRINTF("inserting trampoline pool at %p (%d)\n",
                   reinterpret_cast<Instr*>(buffer_start_ + pc_offset()),
                   pc_offset());
      BlockTrampolinePoolScope block_trampoline_pool(this);
      Label after_pool;
      j(&after_pool);

      int pool_start = pc_offset();
      for (int i = 0; i < unbound_labels_count_; i++) {
        int32_t imm;
        imm = branch_long_offset(&after_pool);
        CHECK(is_int32(imm + 0x800));
        int32_t Hi20 = (((int32_t)imm + 0x800) >> 12);
        int32_t Lo12 = (int32_t)imm << 20 >> 20;
        auipc(t6, Hi20);  // Read PC + Hi20 into t6
        jr(t6, Lo12);     // jump PC + Hi20 + Lo12
      }
      // If unbound_labels_count_ is big enough, label after_pool will
      // need a trampoline too, so we must create the trampoline before
      // the bind operation to make sure function 'bind' can get this
      // information.
      trampoline_ = Trampoline(pool_start, unbound_labels_count_);
      bind(&after_pool);

      trampoline_emitted_ = true;
      // As we are only going to emit trampoline once, we need to prevent any
      // further emission.
      next_buffer_check_ = kMaxInt;
    }
  } else {
    // Number of branches to unbound label at this point is zero, so we can
    // move next buffer check to maximum.
    next_buffer_check_ =
        pc_offset() + kMaxBranchOffset - kTrampolineSlotsSize * 16;
  }
  return;
}

void Assembler::set_target_address_at(Address pc, Address constant_pool,
                                      Address target,
                                      WritableJitAllocation* jit_allocation,
                                      ICacheFlushMode icache_flush_mode) {
  Instr* instr = reinterpret_cast<Instr*>(pc);
  if (IsAuipc(*instr)) {
#if V8_TARGET_ARCH_RISCV64
    if (IsLd(*reinterpret_cast<Instr*>(pc + 4))) {
#elif V8_TARGET_ARCH_RISCV32
    if (IsLw(*reinterpret_cast<Instr*>(pc + 4))) {
#endif
      int32_t Hi20 = AuipcOffset(*instr);
      int32_t Lo12 = LoadOffset(*reinterpret_cast<Instr*>(pc + 4));
      jit_allocation->WriteUnalignedValue(
          reinterpret_cast<Address>(pc + Hi20 + Lo12), target);
      if (icache_flush_mode != SKIP_ICACHE_FLUSH) {
        FlushInstructionCache(pc + Hi20 + Lo12, 2 * kInstrSize);
      }
    } else {
      DCHECK(IsJalr(*reinterpret_cast<Instr*>(pc + 4)));
      intptr_t imm = (intptr_t)target - (intptr_t)pc;
      Instr instr = instr_at(pc);
      Instr instr1 = instr_at(pc + 1 * kInstrSize);
      DCHECK(is_int32(imm + 0x800));
      int num = PatchBranchlongOffset(pc, instr, instr1, (int32_t)imm,
                                      jit_allocation);
      if (icache_flush_mode != SKIP_ICACHE_FLUSH) {
        FlushInstructionCache(pc, num * kInstrSize);
      }
    }
  } else {
    set_target_address_at(pc, target, jit_allocation, icache_flush_mode);
  }
}

Address Assembler::target_address_at(Address pc, Address constant_pool) {
  Instr* instr = reinterpret_cast<Instr*>(pc);
  if (IsAuipc(*instr)) {
#if V8_TARGET_ARCH_RISCV64
    if (IsLd(*reinterpret_cast<Instr*>(pc + 4))) {
#elif V8_TARGET_ARCH_RISCV32
    if (IsLw(*reinterpret_cast<Instr*>(pc + 4))) {
#endif
      int32_t Hi20 = AuipcOffset(*instr);
      int32_t Lo12 = LoadOffset(*reinterpret_cast<Instr*>(pc + 4));
      return Memory<Address>(pc + Hi20 + Lo12);
    } else {
      DCHECK(IsJalr(*reinterpret_cast<Instr*>(pc + 4)));
      int32_t Hi20 = AuipcOffset(*instr);
      int32_t Lo12 = JalrOffset(*reinterpret_cast<Instr*>(pc + 4));
      return pc + Hi20 + Lo12;
    }

  } else {
    return target_address_at(pc);
  }
}

#if V8_TARGET_ARCH_RISCV64
Address Assembler::target_address_at(Address pc) {
  DEBUG_PRINTF("target_address_at: pc: %lx\t", pc);
#ifdef RISCV_USE_SV39
  Instruction* instr0 = Instruction::At((unsigned char*)pc);
  Instruction* instr1 = Instruction::At((unsigned char*)(pc + 1 * kInstrSize));
  Instruction* instr2 = Instruction::At((unsigned char*)(pc + 2 * kInstrSize));
  Instruction* instr3 = Instruction::At((unsigned char*)(pc + 3 * kInstrSize));

  // Interpret instructions for address generated by li: See listing in
  // Assembler::set_target_address_at() just below.
  if (IsLui(*reinterpret_cast<Instr*>(instr0)) &&
      IsAddi(*reinterpret_cast<Instr*>(instr1)) &&
      IsSlli(*reinterpret_cast<Instr*>(instr2)) &&
      IsOri(*reinterpret_cast<Instr*>(instr3))) {
    // Assemble the 64 bit value.
    int64_t addr = (int64_t)(instr0->Imm20UValue() << kImm20Shift) +
                   (int64_t)instr1->Imm12Value();
    addr <<= 8;
    addr |= (int64_t)instr3->Imm12Value();
#else
  Instruction* instr0 = Instruction::At((unsigned char*)pc);
  Instruction* instr1 = Instruction::At((unsigned char*)(pc + 1 * kInstrSize));
  Instruction* instr2 = Instruction::At((unsigned char*)(pc + 2 * kInstrSize));
  Instruction* instr3 = Instruction::At((unsigned char*)(pc + 3 * kInstrSize));
  Instruction* instr4 = Instruction::At((unsigned char*)(pc + 4 * kInstrSize));
  Instruction* instr5 = Instruction::At((unsigned char*)(pc + 5 * kInstrSize));

  // Interpret instructions for address generated by li: See listing in
  // Assembler::set_target_address_at() just below.
  if (IsLui(*reinterpret_cast<Instr*>(instr0)) &&
      IsAddi(*reinterpret_cast<Instr*>(instr1)) &&
      IsSlli(*reinterpret_cast<Instr*>(instr2)) &&
      IsOri(*reinterpret_cast<Instr*>(instr3)) &&
      IsSlli(*reinterpret_cast<Instr*>(instr4)) &&
      IsOri(*reinterpret_cast<Instr*>(instr5))) {
    // Assemble the 64 bit value.
    int64_t addr = (int64_t)(instr0->Imm20UValue() << kImm20Shift) +
                   (int64_t)instr1->Imm12Value();
    addr <<= 11;
    addr |= (int64_t)instr3->Imm12Value();
    addr <<= 6;
    addr |= (int64_t)instr5->Imm12Value();
#endif
    DEBUG_PRINTF("addr: %" PRIx64 "\n", addr);
    return static_cast<Address>(addr);
  }
  // We should never get here, force a bad address if we do.
  UNREACHABLE();
}
// On RISC-V, a 48-bit target address is stored in an 6-instruction sequence:
//  lui(reg, (int32_t)high_20); // 19 high bits
//  addi(reg, reg, low_12); // 12 following bits. total is 31 high bits in reg.
//  slli(reg, reg, 11); // Space for next 11 bits
//  ori(reg, reg, b11); // 11 bits are put in. 42 bit in reg
//  slli(reg, reg, 6); // Space for next 6 bits
//  ori(reg, reg, a6); // 6 bits are put in. all 48 bis in reg
//
// If define RISCV_USE_SV39, a 39-bit target address is stored in an
// 4-instruction sequence:
//  lui(reg, (int32_t)high_20); // 20 high bits
//  addi(reg, reg, low_12); // 12 following bits. total is 32 high bits in reg.
//  slli(reg, reg, 7); // Space for next 7 bits
//  ori(reg, reg, a7); // 7 bits are put in.
//
// Patching the address must replace all instructions, and flush the i-cache.
// Note that this assumes the use of SV48, the 48-bit virtual memory system.
void Assembler::set_target_value_at(Address pc, uint64_t target,
                                    WritableJitAllocation* jit_allocation,
                                    ICacheFlushMode icache_flush_mode) {
  DEBUG_PRINTF("set_target_value_at: pc: %" PRIxPTR "\ttarget: %" PRIx64 "\n",
               pc, target);
  uint32_t* p = reinterpret_cast<uint32_t*>(pc);
#ifdef RISCV_USE_SV39
  DCHECK_EQ((target & 0xffffff8000000000ll), 0);
#ifdef DEBUG
  // Check we have the result from a li macro-instruction.
  Instruction* instr0 = Instruction::At((unsigned char*)pc);
  Instruction* instr1 = Instruction::At((unsigned char*)(pc + 1 * kInstrSize));
  Instruction* instr3 = Instruction::At((unsigned char*)(pc + 3 * kInstrSize));
  DCHECK(IsLui(*reinterpret_cast<Instr*>(instr0)) &&
         IsAddi(*reinterpret_cast<Instr*>(instr1)) &&
         IsOri(*reinterpret_cast<Instr*>(instr3)));
#endif
  int64_t a8 = target & 0xff;                    // bits 0:7. 8 bits
  int64_t high_31 = (target >> 8) & 0x7fffffff;  // 31 bits
  int64_t high_20 = ((high_31 + 0x800) >> 12);   // 19 bits
  int64_t low_12 = high_31 & 0xfff;              // 12 bits
  *p = *p & 0xfff;
  *p = *p | ((int32_t)high_20 << 12);
  *(p + 1) = *(p + 1) & 0xfffff;
  *(p + 1) = *(p + 1) | ((int32_t)low_12 << 20);
  *(p + 2) = *(p + 2) & 0xfffff;
  *(p + 2) = *(p + 2) | (8 << 20);
  *(p + 3) = *(p + 3) & 0xfffff;
  *(p + 3) = *(p + 3) | ((int32_t)a8 << 20);
  if (icache_flush_mode != SKIP_ICACHE_FLUSH) {
    FlushInstructionCache(pc, 6 * kInstrSize);
  }
#else
  DCHECK_EQ((target & 0xffff000000000000ll), 0);
#ifdef DEBUG
  // Check we have the result from a li macro-instruction.
  Instruction* instr0 = Instruction::At((unsigned char*)pc);
  Instruction* instr1 = Instruction::At((unsigned char*)(pc + 1 * kInstrSize));
  Instruction* instr3 = Instruction::At((unsigned char*)(pc + 3 * kInstrSize));
  Instruction* instr5 = Instruction::At((unsigned char*)(pc + 5 * kInstrSize));
  DCHECK(IsLui(*reinterpret_cast<Instr*>(instr0)) &&
         IsAddi(*reinterpret_cast<Instr*>(instr1)) &&
         IsOri(*reinterpret_cast<Instr*>(instr3)) &&
         IsOri(*reinterpret_cast<Instr*>(instr5)));
#endif
  int64_t a6 = target & 0x3f;                     // bits 0:6. 6 bits
  int64_t b11 = (target >> 6) & 0x7ff;            // bits 6:11. 11 bits
  int64_t high_31 = (target >> 17) & 0x7fffffff;  // 31 bits
  int64_t high_20 = ((high_31 + 0x800) >> 12);    // 19 bits
  int64_t low_12 = high_31 & 0xfff;               // 12 bits
  *p = *p & 0xfff;
  *p = *p | ((int32_t)high_20 << 12);
  *(p + 1) = *(p + 1) & 0xfffff;
  *(p + 1) = *(p + 1) | ((int32_t)low_12 << 20);
  *(p + 2) = *(p + 2) & 0xfffff;
  *(p + 2) = *(p + 2) | (11 << 20);
  *(p + 3) = *(p + 3) & 0xfffff;
  *(p + 3) = *(p + 3) | ((int32_t)b11 << 20);
  *(p + 4) = *(p + 4) & 0xfffff;
  *(p + 4) = *(p + 4) | (6 << 20);
  *(p + 5) = *(p + 5) & 0xfffff;
  *(p + 5) = *(p + 5) | ((int32_t)a6 << 20);
  if (icache_flush_mode != SKIP_ICACHE_FLUSH) {
    FlushInstructionCache(pc, 8 * kInstrSize);
  }
#endif
  DCHECK_EQ(target_address_at(pc), target);
}

#elif V8_TARGET_ARCH_RISCV32
Address Assembler::target_address_at(Address pc) {
  DEBUG_PRINTF("target_address_at: pc: %x\t", pc);
  int32_t addr = target_constant32_at(pc);
  DEBUG_PRINTF("addr: %x\n", addr);
  return static_cast<Address>(addr);
}
// On RISC-V, a 32-bit target address is stored in an 2-instruction sequence:
//  lui(reg, high_20); // 20 high bits
//  addi(reg, reg, low_12); // 12 following bits. total is 31 high bits in reg.
//
// Patching the address must replace all instructions, and flush the i-cache.
void Assembler::set_target_value_at(Address pc, uint32_t target,
                                    WritableJitAllocation* jit_allocation,
                                    ICacheFlushMode icache_flush_mode) {
  DEBUG_PRINTF("set_target_value_at: pc: %x\ttarget: %x\n", pc, target);
  set_target_constant32_at(pc, target, jit_allocation, icache_flush_mode);
}
#endif

bool Assembler::IsConstantPoolAt(Instruction* instr) {
  // The constant pool marker is made of two instructions. These instructions
  // will never be emitted by the JIT, so checking for the first one is enough:
  // 0: ld x0, x0, #offset
  Instr instr_value = *reinterpret_cast<Instr*>(instr);
#if V8_TARGET_ARCH_RISCV64
  bool result = IsLd(instr_value) && (instr->Rs1Value() == kRegCode_zero_reg) &&
                (instr->RdValue() == kRegCode_zero_reg);
#elif V8_TARGET_ARCH_RISCV32
  bool result = IsLw(instr_value) && (instr->Rs1Value() == kRegCode_zero_reg) &&
                (instr->RdValue() == kRegCode_zero_reg);
#endif
#ifdef DEBUG
  // It is still worth asserting the marker is complete.
  // 1: j 0x0
  Instruction* instr_following = instr + kInstrSize;
  DCHECK(!result || (IsJal(*reinterpret_cast<Instr*>(instr_following)) &&
                     instr_following->Imm20JValue() == 0 &&
                     instr_following->RdValue() == kRegCode_zero_reg));
#endif
  return result;
}

int Assembler::ConstantPoolSizeAt(Instruction* instr) {
  if (IsConstantPoolAt(instr)) {
    return instr->Imm12Value();
  } else {
    return -1;
  }
}

void Assembler::RecordConstPool(int size) {
  // We only need this for debugger support, to correctly compute offsets in the
  // code.
  Assembler::BlockPoolsScope block_pools(this);
  RecordRelocInfo(RelocInfo::CONST_POOL, static_cast<intptr_t>(size));
}

void Assembler::EmitPoolGuard() {
  // We must generate only one instruction as this is used in scopes that
  // control the size of the code generated.
  j(0);
}

// -----------------------------------------------------------------------------
// Assembler.
template <typename T>
void Assembler::EmitHelper(T x) {
  *reinterpret_cast<T*>(pc_) = x;
  pc_ += sizeof(x);
}

void Assembler::emit(Instr x
"""


```