Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/src/execution/ppc/simulator-ppc.cc`. I need to analyze the code, identify its purpose, and then address the specific constraints and questions:

1. **List the functionality:** I'll go through the `switch` statement and describe what each `case` does. These cases correspond to different PowerPC instructions.

2. **Check for `.tq` extension:**  The filename ends in `.cc`, not `.tq`, so it's not a Torque source file.

3. **Relate to JavaScript:** Since this code emulates PowerPC instructions, I need to think about how these instructions might be used when V8 executes JavaScript. This likely involves low-level operations like memory access, floating-point arithmetic, and bit manipulation. I'll try to come up with a simple JavaScript example that could potentially trigger some of these instructions.

4. **Provide logic inference (input/output):** For a few representative instructions, I'll create hypothetical register values as input and then show the resulting output after the instruction is simulated. Focusing on instructions with clear logic will be best.

5. **Illustrate common programming errors:**  I'll think about typical mistakes programmers might make that could lead to issues when executing these instructions (or the underlying assembly they represent). This might include things like incorrect memory access or overflow.

6. **Summarize the functionality:**  Finally, I'll provide a concise summary of the code's overall role.

**Mental Sandbox:**

* **Instruction Mapping:**  I need to understand that each `case` in the `switch` statement corresponds to a specific PowerPC instruction mnemonic (e.g., `ClearFPSCR`, `MTFSB0`, `FABS`).
* **Register Access:** The code uses functions like `get_register`, `set_register`, `get_double_from_d_register`, and `set_d_register_from_double`. These are essential for simulating the processor's register state.
* **Memory Access:**  Instructions like `LD`, `STD`, `LVX`, and `STVX` involve reading and writing to memory using `ReadDW`, `WriteDW`, `ReadW`, `WriteQW`, etc.
* **SIMD Instructions:** The presence of instructions like `LVX`, `STVX`, `VADDDP`, etc., indicates support for Single Instruction, Multiple Data operations, which are crucial for performance.
* **Bit Manipulation:** Instructions like `RLDICL`, `RLDICR`, and the various bitwise logical and shift operations are for manipulating data at the bit level.
* **Floating-Point:** Instructions like `FABS`, `XSADDDP`, `XSSUBDP`, `XSMULDP`, and `XSDIVDP` handle floating-point arithmetic.
* **Conditional Flags:** Instructions like `MTCRF` modify the condition register.
* **Error Handling:** The `UNIMPLEMENTED()` macro suggests that not all PowerPC instructions are implemented in this simulator.

**Example Selection for Logic Inference:**

* **`FABS`:**  A good choice as it's a simple mathematical operation.
* **`RLDICL`:** Demonstrates bitwise rotation and masking.
* **`LD`:** Shows basic memory loading.
* **`XSADDDP`:**  Simple floating-point addition.

**Common Programming Error Examples:**

* **Memory Alignment:**  Instructions like `LD` and `STD` might require memory to be aligned. Accessing unaligned memory can lead to errors.
* **Register Misuse:**  Using the wrong register as a source or destination.
* **Immediate Value Errors:**  Incorrectly specifying immediate values or offsets.
* **SIMD Lane Access:**  Trying to access a SIMD lane out of bounds.

Okay, the planning is complete. I will now generate the response based on these steps.
这是目录为`v8/src/execution/ppc/simulator-ppc.cc` 的一个V8源代码片段，它是一个PowerPC架构的模拟器实现的一部分。这个文件包含了模拟器在执行PowerPC指令时的具体行为。

**功能列举:**

这个代码片段的主要功能是模拟一组特定的PowerPC指令的执行。具体来说，它涵盖了以下类型的操作：

1. **浮点状态寄存器操作:**
   - `ClearFPSCR(VXSOFT)`, `ClearFPSCR(VXSQRT)`, `ClearFPSCR(VXCVI)`: 清除浮点状态寄存器（FPSCR）中的特定位，这些位通常与软件异常、平方根异常和转换到整数异常有关。
   - `ClearFPSCR(bt)`: 清除FPSCR中由 `bt` 指定的位。
   - `SetFPSCR(bt)`: 设置FPSCR中由 `bt` 指定的位。

2. **浮点绝对值:**
   - `FABS`: 计算浮点寄存器 `frb` 中值的绝对值，并将结果存储到浮点寄存器 `frt` 中。

3. **旋转和屏蔽操作:**
   - `RLDICL` (Rotate Left Doubleword Immediate then Clear Left): 将寄存器 `rs` 的值左旋 `sh` 位，然后清除左边 `mb` 位，结果存储到寄存器 `ra`。
   - `RLDICR` (Rotate Left Doubleword Immediate then Clear Right): 将寄存器 `rs` 的值左旋 `sh` 位，然后清除右边 `63 - me` 位，结果存储到寄存器 `ra`。
   - `RLDIC` (Rotate Left Doubleword Immediate then Clear): 将寄存器 `rs` 的值左旋 `sh` 位，然后清除左边 `mb` 位和右边 `sh` 位，结果存储到寄存器 `ra`。
   - `RLDIMI` (Rotate Left Doubleword Immediate then Mask Insert): 将寄存器 `rs` 的值左旋 `sh` 位，然后将结果与寄存器 `ra` 的一部分进行按位或运算，结果存储回寄存器 `ra`。
   - `RLDCL` (Rotate Left Doubleword then Clear Left): 将寄存器 `rs` 的值左旋由寄存器 `rb` 低 6 位指定的位数，然后清除左边 `mb` 位，结果存储到寄存器 `ra`。

4. **加载操作:**
   - `LD` (Load Doubleword): 从内存地址 `ra_val + offset` 加载一个双字（64位）值到寄存器 `rt`。
   - `LDU` (Load Doubleword and Update): 从内存地址 `ra_val + offset` 加载一个双字值到寄存器 `rt`，并将 `ra_val + offset` 更新到寄存器 `ra`。
   - `LWA` (Load Word Algebraic): 从内存地址 `ra_val + offset` 加载一个字（32位）值并进行符号扩展后存储到寄存器 `rt`。

5. **存储操作:**
   - `STD` (Store Doubleword): 将寄存器 `rs` 的值存储到内存地址 `ra_val + offset`。
   - `STDU` (Store Doubleword and Update): 将寄存器 `rs` 的值存储到内存地址 `ra_val + offset`，并将 `ra_val + offset` 更新到寄存器 `ra`。

6. **浮点算术运算 (双精度):**
   - `XSADDDP` (Extended Single Add Double-Precision): 将浮点寄存器 `fra` 和 `frb` 的值相加，结果存储到 `frt`。
   - `XSSUBDP` (Extended Single Subtract Double-Precision): 将浮点寄存器 `fra` 和 `frb` 的值相减，结果存储到 `frt`。
   - `XSMULDP` (Extended Single Multiply Double-Precision): 将浮点寄存器 `fra` 和 `frb` 的值相乘，结果存储到 `frt`。
   - `XSDIVDP` (Extended Single Divide Double-Precision): 将浮点寄存器 `fra` 的值除以 `frb` 的值，结果存储到 `frt`。

7. **条件寄存器操作:**
   - `MTCRF` (Move to Condition Register Field): 将通用寄存器 `rs` 的内容或条件寄存器 `condition_reg_` 的部分内容移动到条件寄存器 `condition_reg_` 的指定字段。

8. **向量（SIMD）指令:** 这部分代码处理各种向量指令，包括加载、存储、算术、逻辑、比较、转换和重排操作。这些指令通常以 `LVX`, `STVX`, `VADDDP` 等开头。

**关于文件类型:**

根据您的描述，如果 `v8/src/execution/ppc/simulator-ppc.cc` 以 `.tq` 结尾，那么它将是一个 V8 Torque 源代码文件。但是，由于它以 `.cc` 结尾，它是一个标准的 C++ 源代码文件。

**与 JavaScript 的关系:**

这个 C++ 代码是 V8 JavaScript 引擎的一部分，负责在 PowerPC 架构上模拟执行 JavaScript 代码。当 V8 需要执行一段 JavaScript 代码时，它会将 JavaScript 代码编译成可以在目标架构上执行的机器码。在某些情况下，或者在某些平台上，V8 可能会使用解释器或模拟器来执行这些代码。

例如，考虑以下 JavaScript 代码：

```javascript
let a = 1.5;
let b = 2.5;
let c = a + b;
```

当 V8 在 PowerPC 架构上执行这段代码时，它可能会使用模拟器来执行底层的加法操作。`XSADDDP` 指令模拟了双精度浮点数的加法，这与 JavaScript 中的浮点数加法操作直接相关。

**代码逻辑推理:**

假设输入以下状态：

* 寄存器 `r5` 的值为 `0xABCDEF0123456789`
* 寄存器 `r6` 的值为 `0x000000000000000F`
* 指令为 `RLDICL r7, r5, 4, 16` (将 `r5` 左旋 4 位，清除左边 16 位，结果存入 `r7`)

执行 `RLDICL` 指令后：

1. `rs_val` (寄存器 `r5` 的值) 为 `0xABCDEF0123456789`。
2. `sh` (旋转位数) 为 4。
3. `mb` (清除左边位数) 为 16。
4. 左旋 4 位后的结果为 `0xBCDEF0123456789A`。
5. 清除左边 16 位，相当于与 `0xFFFFFFFFFFFFFFFF >> 16` (即 `0x0000FFFFFFFFFFFF`) 进行按位与。
6. 最终结果为 `0x0000EF0123456789A`。
7. 寄存器 `r7` 的值将被设置为 `0x0000EF0123456789A`。

**用户常见的编程错误:**

在使用涉及到这些底层操作的编程中（通常不会直接编写这样的代码，而是编译器或虚拟机生成），常见的错误包括：

1. **内存地址未对齐:**  `LD` 和 `STD` 等指令通常要求内存地址按照特定的大小对齐（例如，加载双字需要 8 字节对齐）。如果地址未对齐，会导致错误。

   ```c++
   // 假设 ptr 没有 8 字节对齐
   intptr_t ptr = ...;
   set_register(5, ptr);
   // ... 执行 LD 指令，可能会出错
   // LD rt, offset(ra)  其中 ra 指向 ptr
   ```

2. **错误的位掩码或偏移量:** 在位操作指令中，使用错误的掩码或偏移量会导致意想不到的结果。

   ```c++
   // 错误地清除或保留了某些位
   uintptr_t val = 0xFFFFFFFF;
   // 假设想要清除低 8 位，但 mb 设置错误
   // RLDICL r7, r5, 0, some_wrong_mb
   ```

3. **浮点数精度问题:**  在浮点运算中，由于浮点数的表示方式，可能会出现精度损失或舍入误差。

   ```javascript
   let a = 0.1;
   let b = 0.2;
   let c = a + b; // c 的值可能不是精确的 0.3
   ```

4. **SIMD 指令使用不当:**  SIMD 指令操作向量数据，需要正确理解数据在向量寄存器中的布局和操作的含义。例如，访问错误的 lane 或者对不同类型的数据进行操作。

   ```c++
   // 假设一个向量寄存器存储了 4 个 32 位整数
   // 尝试使用操作双精度浮点数的指令可能会出错
   // XVADDDP vt, va, vb  但 va 和 vb 实际上存储的是整数
   ```

**功能归纳 (第 5 部分，共 6 部分):**

这部分代码专注于模拟 PowerPC 架构中**浮点数操作、位操作、基本的数据加载和存储，以及一部分向量（SIMD）指令**的执行。它为 V8 引擎在 PowerPC 平台上运行 JavaScript 代码提供了底层的指令级模拟能力。通过解释这些指令的行为，模拟器能够准确地反映在真实的 PowerPC 硬件上执行代码的效果。这部分代码是整个模拟器实现中的一个关键组成部分，负责处理多种核心的 CPU 指令。

Prompt: 
```
这是目录为v8/src/execution/ppc/simulator-ppc.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/execution/ppc/simulator-ppc.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共6部分，请归纳一下它的功能

"""
     switch (bfa) {
        case 5:
          ClearFPSCR(VXSOFT);
          ClearFPSCR(VXSQRT);
          ClearFPSCR(VXCVI);
          break;
        default:
          UNIMPLEMENTED();
      }
      return;
    }
    case MTFSB0: {
      int bt = instr->Bits(25, 21);
      ClearFPSCR(bt);
      if (instr->Bit(0)) {  // RC bit set
        UNIMPLEMENTED();
      }
      return;
    }
    case MTFSB1: {
      int bt = instr->Bits(25, 21);
      SetFPSCR(bt);
      if (instr->Bit(0)) {  // RC bit set
        UNIMPLEMENTED();
      }
      return;
    }
    case FABS: {
      int frt = instr->RTValue();
      int frb = instr->RBValue();
      double frb_val = get_double_from_d_register(frb);
      double frt_val = std::fabs(frb_val);
      set_d_register_from_double(frt, frt_val);
      return;
    }
    case RLDICL: {
      int ra = instr->RAValue();
      int rs = instr->RSValue();
      uintptr_t rs_val = get_register(rs);
      int sh = (instr->Bits(15, 11) | (instr->Bit(1) << 5));
      int mb = (instr->Bits(10, 6) | (instr->Bit(5) << 5));
      DCHECK(sh >= 0 && sh <= 63);
      DCHECK(mb >= 0 && mb <= 63);
      uintptr_t result = base::bits::RotateLeft64(rs_val, sh);
      uintptr_t mask = 0xFFFFFFFFFFFFFFFF >> mb;
      result &= mask;
      set_register(ra, result);
      if (instr->Bit(0)) {  // RC bit set
        SetCR0(result);
      }
      return;
    }
    case RLDICR: {
      int ra = instr->RAValue();
      int rs = instr->RSValue();
      uintptr_t rs_val = get_register(rs);
      int sh = (instr->Bits(15, 11) | (instr->Bit(1) << 5));
      int me = (instr->Bits(10, 6) | (instr->Bit(5) << 5));
      DCHECK(sh >= 0 && sh <= 63);
      DCHECK(me >= 0 && me <= 63);
      uintptr_t result = base::bits::RotateLeft64(rs_val, sh);
      uintptr_t mask = 0xFFFFFFFFFFFFFFFF << (63 - me);
      result &= mask;
      set_register(ra, result);
      if (instr->Bit(0)) {  // RC bit set
        SetCR0(result);
      }
      return;
    }
    case RLDIC: {
      int ra = instr->RAValue();
      int rs = instr->RSValue();
      uintptr_t rs_val = get_register(rs);
      int sh = (instr->Bits(15, 11) | (instr->Bit(1) << 5));
      int mb = (instr->Bits(10, 6) | (instr->Bit(5) << 5));
      DCHECK(sh >= 0 && sh <= 63);
      DCHECK(mb >= 0 && mb <= 63);
      uintptr_t result = base::bits::RotateLeft64(rs_val, sh);
      uintptr_t mask = (0xFFFFFFFFFFFFFFFF >> mb) & (0xFFFFFFFFFFFFFFFF << sh);
      result &= mask;
      set_register(ra, result);
      if (instr->Bit(0)) {  // RC bit set
        SetCR0(result);
      }
      return;
    }
    case RLDIMI: {
      int ra = instr->RAValue();
      int rs = instr->RSValue();
      uintptr_t rs_val = get_register(rs);
      intptr_t ra_val = get_register(ra);
      int sh = (instr->Bits(15, 11) | (instr->Bit(1) << 5));
      int mb = (instr->Bits(10, 6) | (instr->Bit(5) << 5));
      int me = 63 - sh;
      uintptr_t result = base::bits::RotateLeft64(rs_val, sh);
      uintptr_t mask = 0;
      if (mb < me + 1) {
        uintptr_t bit = 0x8000000000000000 >> mb;
        for (; mb <= me; mb++) {
          mask |= bit;
          bit >>= 1;
        }
      } else if (mb == me + 1) {
        mask = 0xFFFFFFFFFFFFFFFF;
      } else {                                           // mb > me+1
        uintptr_t bit = 0x8000000000000000 >> (me + 1);  // needs to be tested
        mask = 0xFFFFFFFFFFFFFFFF;
        for (; me < mb; me++) {
          mask ^= bit;
          bit >>= 1;
        }
      }
      result &= mask;
      ra_val &= ~mask;
      result |= ra_val;
      set_register(ra, result);
      if (instr->Bit(0)) {  // RC bit set
        SetCR0(result);
      }
      return;
    }
    case RLDCL: {
      int ra = instr->RAValue();
      int rs = instr->RSValue();
      int rb = instr->RBValue();
      uintptr_t rs_val = get_register(rs);
      uintptr_t rb_val = get_register(rb);
      int sh = (rb_val & 0x3F);
      int mb = (instr->Bits(10, 6) | (instr->Bit(5) << 5));
      DCHECK(sh >= 0 && sh <= 63);
      DCHECK(mb >= 0 && mb <= 63);
      uintptr_t result = base::bits::RotateLeft64(rs_val, sh);
      uintptr_t mask = 0xFFFFFFFFFFFFFFFF >> mb;
      result &= mask;
      set_register(ra, result);
      if (instr->Bit(0)) {  // RC bit set
        SetCR0(result);
      }
      return;
    }

    case LD:
    case LDU:
    case LWA: {
      int ra = instr->RAValue();
      int rt = instr->RTValue();
      int64_t ra_val = ra == 0 ? 0 : get_register(ra);
      int offset = SIGN_EXT_IMM16(instr->Bits(15, 0) & ~3);
      switch (instr->Bits(1, 0)) {
        case 0: {  // ld
          intptr_t result = ReadDW(ra_val + offset);
          set_register(rt, result);
          break;
        }
        case 1: {  // ldu
          intptr_t result = ReadDW(ra_val + offset);
          set_register(rt, result);
          DCHECK_NE(ra, 0);
          set_register(ra, ra_val + offset);
          break;
        }
        case 2: {  // lwa
          intptr_t result = ReadW(ra_val + offset);
          set_register(rt, result);
          break;
        }
      }
      break;
    }

    case STD:
    case STDU: {
      int ra = instr->RAValue();
      int rs = instr->RSValue();
      int64_t ra_val = ra == 0 ? 0 : get_register(ra);
      int64_t rs_val = get_register(rs);
      int offset = SIGN_EXT_IMM16(instr->Bits(15, 0) & ~3);
      WriteDW(ra_val + offset, rs_val);
      if (opcode == STDU) {
        DCHECK_NE(ra, 0);
        set_register(ra, ra_val + offset);
      }
      break;
    }
    case XSADDDP: {
      int frt = instr->RTValue();
      int fra = instr->RAValue();
      int frb = instr->RBValue();
      double fra_val = get_double_from_d_register(fra);
      double frb_val = get_double_from_d_register(frb);
      double frt_val = fra_val + frb_val;
      set_d_register_from_double(frt, frt_val);
      return;
    }
    case XSSUBDP: {
      int frt = instr->RTValue();
      int fra = instr->RAValue();
      int frb = instr->RBValue();
      double fra_val = get_double_from_d_register(fra);
      double frb_val = get_double_from_d_register(frb);
      double frt_val = fra_val - frb_val;
      set_d_register_from_double(frt, frt_val);
      return;
    }
    case XSMULDP: {
      int frt = instr->RTValue();
      int fra = instr->RAValue();
      int frb = instr->RBValue();
      double fra_val = get_double_from_d_register(fra);
      double frb_val = get_double_from_d_register(frb);
      double frt_val = fra_val * frb_val;
      set_d_register_from_double(frt, frt_val);
      return;
    }
    case XSDIVDP: {
      int frt = instr->RTValue();
      int fra = instr->RAValue();
      int frb = instr->RBValue();
      double fra_val = get_double_from_d_register(fra);
      double frb_val = get_double_from_d_register(frb);
      double frt_val = fra_val / frb_val;
      set_d_register_from_double(frt, frt_val);
      return;
    }
    case MTCRF: {
      int rs = instr->RSValue();
      uint32_t rs_val = static_cast<int32_t>(get_register(rs));
      uint8_t fxm = instr->Bits(19, 12);
      uint8_t bit_mask = 0x80;
      const int field_bit_count = 4;
      const int max_field_index = 7;
      uint32_t result = 0;
      for (int i = 0; i <= max_field_index; i++) {
        result <<= field_bit_count;
        uint32_t source = condition_reg_;
        if ((bit_mask & fxm) != 0) {
          // take it from rs.
          source = rs_val;
        }
        result |= ((source << i * field_bit_count) >> i * field_bit_count) >>
                  (max_field_index - i) * field_bit_count;
        bit_mask >>= 1;
      }
      condition_reg_ = result;
      break;
    }
    // Vector instructions.
    case LVX: {
      DECODE_VX_INSTRUCTION(vrt, ra, rb, T)
      GET_ADDRESS(ra, rb, ra_val, rb_val)
      intptr_t addr = (ra_val + rb_val) & 0xFFFFFFFFFFFFFFF0;
      simdr_t* ptr = reinterpret_cast<simdr_t*>(addr);
      set_simd_register(vrt, *ptr);
      break;
    }
    case STVX: {
      DECODE_VX_INSTRUCTION(vrs, ra, rb, S)
      GET_ADDRESS(ra, rb, ra_val, rb_val)
      __int128 vrs_val = base::bit_cast<__int128>(get_simd_register(vrs).int8);
      WriteQW((ra_val + rb_val) & 0xFFFFFFFFFFFFFFF0, vrs_val);
      break;
    }
    case LXVD: {
      DECODE_VX_INSTRUCTION(xt, ra, rb, T)
      GET_ADDRESS(ra, rb, ra_val, rb_val)
      set_simd_register_by_lane<int64_t>(xt, 0, ReadDW(ra_val + rb_val));
      set_simd_register_by_lane<int64_t>(
          xt, 1, ReadDW(ra_val + rb_val + kSystemPointerSize));
      break;
    }
    case LXVX: {
      DECODE_VX_INSTRUCTION(vrt, ra, rb, T)
      GET_ADDRESS(ra, rb, ra_val, rb_val)
      intptr_t addr = ra_val + rb_val;
      simdr_t* ptr = reinterpret_cast<simdr_t*>(addr);
      set_simd_register(vrt, *ptr);
      break;
    }
    case STXVD: {
      DECODE_VX_INSTRUCTION(xs, ra, rb, S)
      GET_ADDRESS(ra, rb, ra_val, rb_val)
      WriteDW(ra_val + rb_val, get_simd_register_by_lane<int64_t>(xs, 0));
      WriteDW(ra_val + rb_val + kSystemPointerSize,
              get_simd_register_by_lane<int64_t>(xs, 1));
      break;
    }
    case STXVX: {
      DECODE_VX_INSTRUCTION(vrs, ra, rb, S)
      GET_ADDRESS(ra, rb, ra_val, rb_val)
      intptr_t addr = ra_val + rb_val;
      __int128 vrs_val = base::bit_cast<__int128>(get_simd_register(vrs).int8);
      WriteQW(addr, vrs_val);
      break;
    }
    case LXSIBZX: {
      DECODE_VX_INSTRUCTION(xt, ra, rb, T)
      GET_ADDRESS(ra, rb, ra_val, rb_val)
      set_simd_register_by_lane<uint64_t>(xt, 0, ReadBU(ra_val + rb_val));
      break;
    }
    case LXSIHZX: {
      DECODE_VX_INSTRUCTION(xt, ra, rb, T)
      GET_ADDRESS(ra, rb, ra_val, rb_val)
      set_simd_register_by_lane<uint64_t>(xt, 0, ReadHU(ra_val + rb_val));
      break;
    }
    case LXSIWZX: {
      DECODE_VX_INSTRUCTION(xt, ra, rb, T)
      GET_ADDRESS(ra, rb, ra_val, rb_val)
      set_simd_register_by_lane<uint64_t>(xt, 0, ReadWU(ra_val + rb_val));
      break;
    }
    case LXSDX: {
      DECODE_VX_INSTRUCTION(xt, ra, rb, T)
      GET_ADDRESS(ra, rb, ra_val, rb_val)
      set_simd_register_by_lane<int64_t>(xt, 0, ReadDW(ra_val + rb_val));
      break;
    }
    case STXSIBX: {
      DECODE_VX_INSTRUCTION(xs, ra, rb, S)
      GET_ADDRESS(ra, rb, ra_val, rb_val)
      WriteB(ra_val + rb_val, get_simd_register_by_lane<int8_t>(xs, 7));
      break;
    }
    case STXSIHX: {
      DECODE_VX_INSTRUCTION(xs, ra, rb, S)
      GET_ADDRESS(ra, rb, ra_val, rb_val)
      WriteH(ra_val + rb_val, get_simd_register_by_lane<int16_t>(xs, 3));
      break;
    }
    case STXSIWX: {
      DECODE_VX_INSTRUCTION(xs, ra, rb, S)
      GET_ADDRESS(ra, rb, ra_val, rb_val)
      WriteW(ra_val + rb_val, get_simd_register_by_lane<int32_t>(xs, 1));
      break;
    }
    case STXSDX: {
      DECODE_VX_INSTRUCTION(xs, ra, rb, S)
      GET_ADDRESS(ra, rb, ra_val, rb_val)
      WriteDW(ra_val + rb_val, get_simd_register_by_lane<int64_t>(xs, 0));
      break;
    }
    case XXBRQ: {
      int t = instr->RTValue();
      int b = instr->RBValue();
      __int128 xb_val = base::bit_cast<__int128>(get_simd_register(b).int8);
      __int128 xb_val_reversed = __builtin_bswap128(xb_val);
      simdr_t simdr_xb = base::bit_cast<simdr_t>(xb_val_reversed);
      set_simd_register(t, simdr_xb);
      break;
    }
#define VSPLT(type)                                       \
  uint8_t uim = instr->Bits(19, 16);                      \
  int vrt = instr->RTValue();                             \
  int vrb = instr->RBValue();                             \
  type value = get_simd_register_by_lane<type>(vrb, uim); \
  FOR_EACH_LANE(i, type) { set_simd_register_by_lane<type>(vrt, i, value); }
    case VSPLTW: {
      VSPLT(int32_t)
      break;
    }
    case VSPLTH: {
      VSPLT(int16_t)
      break;
    }
    case VSPLTB: {
      VSPLT(int8_t)
      break;
    }
    case XXSPLTIB: {
      int8_t imm8 = instr->Bits(18, 11);
      int t = instr->RTValue();
      FOR_EACH_LANE(i, int8_t) {
        set_simd_register_by_lane<int8_t>(t, i, imm8);
      }
      break;
    }
#undef VSPLT
#define VSPLTI(type)                                                \
  type sim = static_cast<type>(SIGN_EXT_IMM5(instr->Bits(20, 16))); \
  int vrt = instr->RTValue();                                       \
  FOR_EACH_LANE(i, type) { set_simd_register_by_lane<type>(vrt, i, sim); }
    case VSPLTISW: {
      VSPLTI(int32_t)
      break;
    }
    case VSPLTISH: {
      VSPLTI(int16_t)
      break;
    }
    case VSPLTISB: {
      VSPLTI(int8_t)
      break;
    }
#undef VSPLTI
#define VINSERT(type, element)       \
  uint8_t uim = instr->Bits(19, 16); \
  int vrt = instr->RTValue();        \
  int vrb = instr->RBValue();        \
  set_simd_register_bytes<type>(     \
      vrt, uim, get_simd_register_by_lane<type>(vrb, element));
    case VINSERTD: {
      VINSERT(int64_t, 0)
      break;
    }
    case VINSERTW: {
      VINSERT(int32_t, 1)
      break;
    }
    case VINSERTH: {
      VINSERT(int16_t, 3)
      break;
    }
    case VINSERTB: {
      VINSERT(int8_t, 7)
      break;
    }
#undef VINSERT
#define VINSERT_IMMEDIATE(type)                   \
  uint8_t uim = instr->Bits(19, 16);              \
  int vrt = instr->RTValue();                     \
  int rb = instr->RBValue();                      \
  type src = static_cast<type>(get_register(rb)); \
  set_simd_register_bytes<type>(vrt, uim, src);
    case VINSD: {
      VINSERT_IMMEDIATE(int64_t)
      break;
    }
    case VINSW: {
      VINSERT_IMMEDIATE(int32_t)
      break;
    }
#undef VINSERT_IMMEDIATE
#define VEXTRACT(type, element)                       \
  uint8_t uim = instr->Bits(19, 16);                  \
  int vrt = instr->RTValue();                         \
  int vrb = instr->RBValue();                         \
  type val = get_simd_register_bytes<type>(vrb, uim); \
  set_simd_register_by_lane<uint64_t>(vrt, 0, 0);     \
  set_simd_register_by_lane<uint64_t>(vrt, 1, 0);     \
  set_simd_register_by_lane<type>(vrt, element, val);
    case VEXTRACTD: {
      VEXTRACT(uint64_t, 0)
      break;
    }
    case VEXTRACTUW: {
      VEXTRACT(uint32_t, 1)
      break;
    }
    case VEXTRACTUH: {
      VEXTRACT(uint16_t, 3)
      break;
    }
    case VEXTRACTUB: {
      VEXTRACT(uint8_t, 7)
      break;
    }
#undef VEXTRACT
#define VECTOR_LOGICAL_OP(expr)                               \
  DECODE_VX_INSTRUCTION(t, a, b, T)                           \
  FOR_EACH_LANE(i, int64_t) {                                 \
    int64_t a_val = get_simd_register_by_lane<int64_t>(a, i); \
    int64_t b_val = get_simd_register_by_lane<int64_t>(b, i); \
    set_simd_register_by_lane<int64_t>(t, i, expr);           \
  }
    case VAND: {
      VECTOR_LOGICAL_OP(a_val & b_val)
      break;
    }
    case VANDC: {
      VECTOR_LOGICAL_OP(a_val & (~b_val))
      break;
    }
    case VOR: {
      VECTOR_LOGICAL_OP(a_val | b_val)
      break;
    }
    case VNOR: {
      VECTOR_LOGICAL_OP(~(a_val | b_val))
      break;
    }
    case VXOR: {
      VECTOR_LOGICAL_OP(a_val ^ b_val)
      break;
    }
#undef VECTOR_LOGICAL_OP
#define VECTOR_ARITHMETIC_OP(type, op)                 \
  DECODE_VX_INSTRUCTION(t, a, b, T)                    \
  FOR_EACH_LANE(i, type) {                             \
    set_simd_register_by_lane<type>(                   \
        t, i,                                          \
        get_simd_register_by_lane<type>(a, i)          \
            op get_simd_register_by_lane<type>(b, i)); \
  }
    case XVADDDP: {
      VECTOR_ARITHMETIC_OP(double, +)
      break;
    }
    case XVSUBDP: {
      VECTOR_ARITHMETIC_OP(double, -)
      break;
    }
    case XVMULDP: {
      VECTOR_ARITHMETIC_OP(double, *)
      break;
    }
    case XVDIVDP: {
      VECTOR_ARITHMETIC_OP(double, /)
      break;
    }
    case VADDFP: {
      VECTOR_ARITHMETIC_OP(float, +)
      break;
    }
    case VSUBFP: {
      VECTOR_ARITHMETIC_OP(float, -)
      break;
    }
    case XVMULSP: {
      VECTOR_ARITHMETIC_OP(float, *)
      break;
    }
    case XVDIVSP: {
      VECTOR_ARITHMETIC_OP(float, /)
      break;
    }
    case VADDUDM: {
      VECTOR_ARITHMETIC_OP(int64_t, +)
      break;
    }
    case VSUBUDM: {
      VECTOR_ARITHMETIC_OP(int64_t, -)
      break;
    }
    case VMULLD: {
      VECTOR_ARITHMETIC_OP(int64_t, *)
      break;
    }
    case VADDUWM: {
      VECTOR_ARITHMETIC_OP(int32_t, +)
      break;
    }
    case VSUBUWM: {
      VECTOR_ARITHMETIC_OP(int32_t, -)
      break;
    }
    case VMULUWM: {
      VECTOR_ARITHMETIC_OP(int32_t, *)
      break;
    }
    case VADDUHM: {
      VECTOR_ARITHMETIC_OP(int16_t, +)
      break;
    }
    case VSUBUHM: {
      VECTOR_ARITHMETIC_OP(int16_t, -)
      break;
    }
    case VADDUBM: {
      VECTOR_ARITHMETIC_OP(int8_t, +)
      break;
    }
    case VSUBUBM: {
      VECTOR_ARITHMETIC_OP(int8_t, -)
      break;
    }
#define VECTOR_MULTIPLY_EVEN_ODD(input_type, result_type, is_odd)              \
  DECODE_VX_INSTRUCTION(t, a, b, T)                                            \
  size_t i = 0, j = 0, k = 0;                                                  \
  size_t lane_size = sizeof(input_type);                                       \
  if (is_odd) {                                                                \
    i = 1;                                                                     \
    j = lane_size;                                                             \
  }                                                                            \
  for (; j < kSimd128Size; i += 2, j += lane_size * 2, k++) {                  \
    result_type src0 =                                                         \
        static_cast<result_type>(get_simd_register_by_lane<input_type>(a, i)); \
    result_type src1 =                                                         \
        static_cast<result_type>(get_simd_register_by_lane<input_type>(b, i)); \
    set_simd_register_by_lane<result_type>(t, k, src0 * src1);                 \
  }
    case VMULEUB: {
      VECTOR_MULTIPLY_EVEN_ODD(uint8_t, uint16_t, false)
      break;
    }
    case VMULESB: {
      VECTOR_MULTIPLY_EVEN_ODD(int8_t, int16_t, false)
      break;
    }
    case VMULOUB: {
      VECTOR_MULTIPLY_EVEN_ODD(uint8_t, uint16_t, true)
      break;
    }
    case VMULOSB: {
      VECTOR_MULTIPLY_EVEN_ODD(int8_t, int16_t, true)
      break;
    }
    case VMULEUH: {
      VECTOR_MULTIPLY_EVEN_ODD(uint16_t, uint32_t, false)
      break;
    }
    case VMULESH: {
      VECTOR_MULTIPLY_EVEN_ODD(int16_t, int32_t, false)
      break;
    }
    case VMULOUH: {
      VECTOR_MULTIPLY_EVEN_ODD(uint16_t, uint32_t, true)
      break;
    }
    case VMULOSH: {
      VECTOR_MULTIPLY_EVEN_ODD(int16_t, int32_t, true)
      break;
    }
    case VMULEUW: {
      VECTOR_MULTIPLY_EVEN_ODD(uint32_t, uint64_t, false)
      break;
    }
    case VMULESW: {
      VECTOR_MULTIPLY_EVEN_ODD(int32_t, int64_t, false)
      break;
    }
    case VMULOUW: {
      VECTOR_MULTIPLY_EVEN_ODD(uint32_t, uint64_t, true)
      break;
    }
    case VMULOSW: {
      VECTOR_MULTIPLY_EVEN_ODD(int32_t, int64_t, true)
      break;
    }
#undef VECTOR_MULTIPLY_EVEN_ODD
#define VECTOR_MERGE(type, is_low_side)                                    \
  DECODE_VX_INSTRUCTION(t, a, b, T)                                        \
  constexpr size_t index_limit = (kSimd128Size / sizeof(type)) / 2;        \
  for (size_t i = 0, source_index = is_low_side ? i + index_limit : i;     \
       i < index_limit; i++, source_index++) {                             \
    set_simd_register_by_lane<type>(                                       \
        t, 2 * i, get_simd_register_by_lane<type>(a, source_index));       \
    set_simd_register_by_lane<type>(                                       \
        t, (2 * i) + 1, get_simd_register_by_lane<type>(b, source_index)); \
  }
    case VMRGLW: {
      VECTOR_MERGE(int32_t, true)
      break;
    }
    case VMRGHW: {
      VECTOR_MERGE(int32_t, false)
      break;
    }
    case VMRGLH: {
      VECTOR_MERGE(int16_t, true)
      break;
    }
    case VMRGHH: {
      VECTOR_MERGE(int16_t, false)
      break;
    }
#undef VECTOR_MERGE
#undef VECTOR_ARITHMETIC_OP
#define VECTOR_MIN_MAX_OP(type, op)                                        \
  DECODE_VX_INSTRUCTION(t, a, b, T)                                        \
  FOR_EACH_LANE(i, type) {                                                 \
    type a_val = get_simd_register_by_lane<type>(a, i);                    \
    type b_val = get_simd_register_by_lane<type>(b, i);                    \
    set_simd_register_by_lane<type>(t, i, a_val op b_val ? a_val : b_val); \
  }
    case XSMINDP: {
      DECODE_VX_INSTRUCTION(t, a, b, T)
      double a_val = get_double_from_d_register(a);
      double b_val = get_double_from_d_register(b);
      set_d_register_from_double(t, VSXFPMin<double>(a_val, b_val));
      break;
    }
    case XSMAXDP: {
      DECODE_VX_INSTRUCTION(t, a, b, T)
      double a_val = get_double_from_d_register(a);
      double b_val = get_double_from_d_register(b);
      set_d_register_from_double(t, VSXFPMax<double>(a_val, b_val));
      break;
    }
    case XVMINDP: {
      DECODE_VX_INSTRUCTION(t, a, b, T)
      FOR_EACH_LANE(i, double) {
        double a_val = get_simd_register_by_lane<double>(a, i);
        double b_val = get_simd_register_by_lane<double>(b, i);
        set_simd_register_by_lane<double>(t, i, VSXFPMin<double>(a_val, b_val));
      }
      break;
    }
    case XVMAXDP: {
      DECODE_VX_INSTRUCTION(t, a, b, T)
      FOR_EACH_LANE(i, double) {
        double a_val = get_simd_register_by_lane<double>(a, i);
        double b_val = get_simd_register_by_lane<double>(b, i);
        set_simd_register_by_lane<double>(t, i, VSXFPMax<double>(a_val, b_val));
      }
      break;
    }
    case VMINFP: {
      DECODE_VX_INSTRUCTION(t, a, b, T)
      FOR_EACH_LANE(i, float) {
        float a_val = get_simd_register_by_lane<float>(a, i);
        float b_val = get_simd_register_by_lane<float>(b, i);
        set_simd_register_by_lane<float>(t, i, VMXFPMin(a_val, b_val));
      }
      break;
    }
    case VMAXFP: {
      DECODE_VX_INSTRUCTION(t, a, b, T)
      FOR_EACH_LANE(i, float) {
        float a_val = get_simd_register_by_lane<float>(a, i);
        float b_val = get_simd_register_by_lane<float>(b, i);
        set_simd_register_by_lane<float>(t, i, VMXFPMax(a_val, b_val));
      }
      break;
    }
    case VMINSD: {
      VECTOR_MIN_MAX_OP(int64_t, <)
      break;
    }
    case VMINUD: {
      VECTOR_MIN_MAX_OP(uint64_t, <)
      break;
    }
    case VMINSW: {
      VECTOR_MIN_MAX_OP(int32_t, <)
      break;
    }
    case VMINUW: {
      VECTOR_MIN_MAX_OP(uint32_t, <)
      break;
    }
    case VMINSH: {
      VECTOR_MIN_MAX_OP(int16_t, <)
      break;
    }
    case VMINUH: {
      VECTOR_MIN_MAX_OP(uint16_t, <)
      break;
    }
    case VMINSB: {
      VECTOR_MIN_MAX_OP(int8_t, <)
      break;
    }
    case VMINUB: {
      VECTOR_MIN_MAX_OP(uint8_t, <)
      break;
    }
    case VMAXSD: {
      VECTOR_MIN_MAX_OP(int64_t, >)
      break;
    }
    case VMAXUD: {
      VECTOR_MIN_MAX_OP(uint64_t, >)
      break;
    }
    case VMAXSW: {
      VECTOR_MIN_MAX_OP(int32_t, >)
      break;
    }
    case VMAXUW: {
      VECTOR_MIN_MAX_OP(uint32_t, >)
      break;
    }
    case VMAXSH: {
      VECTOR_MIN_MAX_OP(int16_t, >)
      break;
    }
    case VMAXUH: {
      VECTOR_MIN_MAX_OP(uint16_t, >)
      break;
    }
    case VMAXSB: {
      VECTOR_MIN_MAX_OP(int8_t, >)
      break;
    }
    case VMAXUB: {
      VECTOR_MIN_MAX_OP(uint8_t, >)
      break;
    }
#undef VECTOR_MIN_MAX_OP
#define VECTOR_SHIFT_OP(type, op, mask)                        \
  DECODE_VX_INSTRUCTION(t, a, b, T)                            \
  FOR_EACH_LANE(i, type) {                                     \
    set_simd_register_by_lane<type>(                           \
        t, i,                                                  \
        get_simd_register_by_lane<type>(a, i)                  \
            op(get_simd_register_by_lane<type>(b, i) & mask)); \
  }
    case VSLD: {
      VECTOR_SHIFT_OP(int64_t, <<, 0x3f)
      break;
    }
    case VSRAD: {
      VECTOR_SHIFT_OP(int64_t, >>, 0x3f)
      break;
    }
    case VSRD: {
      VECTOR_SHIFT_OP(uint64_t, >>, 0x3f)
      break;
    }
    case VSLW: {
      VECTOR_SHIFT_OP(int32_t, <<, 0x1f)
      break;
    }
    case VSRAW: {
      VECTOR_SHIFT_OP(int32_t, >>, 0x1f)
      break;
    }
    case VSRW: {
      VECTOR_SHIFT_OP(uint32_t, >>, 0x1f)
      break;
    }
    case VSLH: {
      VECTOR_SHIFT_OP(int16_t, <<, 0xf)
      break;
    }
    case VSRAH: {
      VECTOR_SHIFT_OP(int16_t, >>, 0xf)
      break;
    }
    case VSRH: {
      VECTOR_SHIFT_OP(uint16_t, >>, 0xf)
      break;
    }
    case VSLB: {
      VECTOR_SHIFT_OP(int8_t, <<, 0x7)
      break;
    }
    case VSRAB: {
      VECTOR_SHIFT_OP(int8_t, >>, 0x7)
      break;
    }
    case VSRB: {
      VECTOR_SHIFT_OP(uint8_t, >>, 0x7)
      break;
    }
#undef VECTOR_SHIFT_OP
#define VECTOR_COMPARE_OP(type_in, type_out, is_fp, op) \
  VectorCompareOp<type_in, type_out>(                   \
      this, instr, is_fp, [](type_in a, type_in b) { return a op b; });
    case XVCMPEQDP: {
      VECTOR_COMPARE_OP(double, int64_t, true, ==)
      break;
    }
    case XVCMPGEDP: {
      VECTOR_COMPARE_OP(double, int64_t, true, >=)
      break;
    }
    case XVCMPGTDP: {
      VECTOR_COMPARE_OP(double, int64_t, true, >)
      break;
    }
    case XVCMPEQSP: {
      VECTOR_COMPARE_OP(float, int32_t, true, ==)
      break;
    }
    case XVCMPGESP: {
      VECTOR_COMPARE_OP(float, int32_t, true, >=)
      break;
    }
    case XVCMPGTSP: {
      VECTOR_COMPARE_OP(float, int32_t, true, >)
      break;
    }
    case VCMPEQUD: {
      VECTOR_COMPARE_OP(uint64_t, int64_t, false, ==)
      break;
    }
    case VCMPGTSD: {
      VECTOR_COMPARE_OP(int64_t, int64_t, false, >)
      break;
    }
    case VCMPGTUD: {
      VECTOR_COMPARE_OP(uint64_t, int64_t, false, >)
      break;
    }
    case VCMPEQUW: {
      VECTOR_COMPARE_OP(uint32_t, int32_t, false, ==)
      break;
    }
    case VCMPGTSW: {
      VECTOR_COMPARE_OP(int32_t, int32_t, false, >)
      break;
    }
    case VCMPGTUW: {
      VECTOR_COMPARE_OP(uint32_t, int32_t, false, >)
      break;
    }
    case VCMPEQUH: {
      VECTOR_COMPARE_OP(uint16_t, int16_t, false, ==)
      break;
    }
    case VCMPGTSH: {
      VECTOR_COMPARE_OP(int16_t, int16_t, false, >)
      break;
    }
    case VCMPGTUH: {
      VECTOR_COMPARE_OP(uint16_t, int16_t, false, >)
      break;
    }
    case VCMPEQUB: {
      VECTOR_COMPARE_OP(uint8_t, int8_t, false, ==)
      break;
    }
    case VCMPGTSB: {
      VECTOR_COMPARE_OP(int8_t, int8_t, false, >)
      break;
    }
    case VCMPGTUB: {
      VECTOR_COMPARE_OP(uint8_t, int8_t, false, >)
      break;
    }
#undef VECTOR_COMPARE_OP
    case XVCVSPSXWS: {
      VectorConverFromFPSaturate<float, int32_t>(this, instr, kMinInt, kMaxInt);
      break;
    }
    case XVCVSPUXWS: {
      VectorConverFromFPSaturate<float, uint32_t>(this, instr, 0, kMaxUInt32);
      break;
    }
    case XVCVDPSXWS: {
      VectorConverFromFPSaturate<double, int32_t>(this, instr, kMinInt, kMaxInt,
                                                  true);
      break;
    }
    case XVCVDPUXWS: {
      VectorConverFromFPSaturate<double, uint32_t>(this, instr, 0, kMaxUInt32,
                                                   true);
      break;
    }
    case XVCVSXWSP: {
      int t = instr->RTValue();
      int b = instr->RBValue();
      FOR_EACH_LANE(i, int32_t) {
        int32_t b_val = get_simd_register_by_lane<int32_t>(b, i);
        set_simd_register_by_lane<float>(t, i, static_cast<float>(b_val));
      }
      break;
    }
    case XVCVUXWSP: {
      int t = instr->RTValue();
      int b = instr->RBValue();
      FOR_EACH_LANE(i, uint32_t) {
        uint32_t b_val = get_simd_register_by_lane<uint32_t>(b, i);
        set_simd_register_by_lane<float>(t, i, static_cast<float>(b_val));
      }
      break;
    }
    case XVCVSXDDP: {
      int t = instr->RTValue();
      int b = instr->RBValue();
      FOR_EACH_LANE(i, int64_t) {
        int64_t b_val = get_simd_register_by_lane<int64_t>(b, i);
        set_simd_register_by_lane<double>(t, i, static_cast<double>(b_val));
      }
      break;
    }
    case XVCVUXDDP: {
      int t = instr->RTValue();
      int b = instr->RBValue();
      FOR_EACH_LANE(i, uint64_t) {
        uint64_t b_val = get_simd_register_by_lane<uint64_t>(b, i);
        set_simd_register_by_lane<double>(t, i, static_cast<double>(b_val));
      }
      break;
    }
    case XVCVSPDP: {
      int t = instr->RTValue();
      int b = instr->RBValue();
      FOR_EACH_LANE(i, double) {
        float b_val = get_simd_register_by_lane<float>(b, 2 * i);
        set_simd_register_by_lane<double>(t, i, static_cast<double>(b_val));
      }
      break;
    }
    case XVCVDPSP: {
      int t = instr->RTValue();
      int b = instr->RBValue();
      FOR_EACH_LANE(i, double) {
        double b_val = get_simd_register_by_lane<double>(b, i);
        set_simd_register_by_lane<float>(t, 2 * i, static_cast<float>(b_val));
      }
      break;
    }
    case XSCVSPDPN: {
      int t = instr->RTValue();
      int b = instr->RBValue();
      uint64_t double_bits = get_d_register(b);
      // Value is at the high 32 bits of the register.
      float f = base::bit_cast<float, uint32_t>(
          static_cast<uint32_t>(double_bits >> 32));
      double_bits = base::bit_cast<uint64_t, double>(static_cast<double>(f));
      // Preserve snan.
      if (is_snan(f)) {
        double_bits &= 0xFFF7FFFFFFFFFFFFU;  // Clear bit 51.
      }
      set_d_register(t, double_bits);
      break;
    }
    case XSCVDPSPN: {
      int t = instr->RTValue();
      int b = instr->RBValue();
      double b_val = get_double_from_d_register(b);
      uint64_t float_bits = static_cast<uint64_t>(
          base::bit_cast<uint32_t, float>(static_cast<float>(b_val)));
      // Preserve snan.
      if (is_snan(b_val)) {
        float_bits &= 0xFFBFFFFFU;  // Clear bit 22.
      }
      // fp result is placed in both 32bit halfs of the dst.
      float_bits = (float_bits << 32) | float_bits;
      set_d_register(t, float_bits);
      break;
    }
#define VECTOR_UNPACK(S, D, if_high_side)                           \
  int t = instr->RTValue();                                         \
  int b = instr->RBValue();                                         \
  constexpr size_t kItemCount = kSimd128Size / sizeof(D);           \
  D temps[kItemCount] = {0};                                        \
  /* Avoid overwriting src if src and dst are the same register. */ \
  FOR_EACH_LANE(i, D) {                                             \
    temps[i] = get_simd_register_by_lane<S>(b, i, if_high_side);    \
  }                                                                 \
  FOR_EACH_LANE(i, D) {                                             \
    set_simd_register_by_lane<D>(t, i, temps[i], if_high_side);     \
  }
    case VUPKHSB: {
      VECTOR_UNPACK(int8_t, int16_t, true)
      break;
    }
    case VUPKHSH: {
      VECTOR_UNPACK(int16_t, int32_t, true)
      break;
    }
    case VUPKHSW: {
      VECTOR_UNPACK(int32_t, int64_t, true)
      break;
    }
    case VUPKLSB: {
      VECTOR_UNPACK(int8_t, int16_t, false)
      break;
    }
    case VUPKLSH: {
      VECTOR_UNPACK(int16_t, int32_t, false)
      break;
    }
    case VUPKLSW: {
      VECTOR_UNPACK(int32_t, int64_t, false)
      break;
    }
#undef VECTOR_UNPACK
    case VPKSWSS: {
      VectorPackSaturate<int32_t, int16_t>(this, instr, kMinInt16, kMaxInt16);
      break;
    }
    case VPKSWUS: {
      VectorPackSaturate<int32_t, uint16_t>(this, instr, 0, kMaxUInt16);
      break;
    }
    case VPKSHSS: {
      VectorPackSaturate<int16_t, int8_t>(this, instr, kMinInt8, kMaxInt8);
      break;
    }
    case VPKSHUS: {
      VectorPackSaturate<int16_t, uint8_t>(this, instr, 0, kMaxUInt8);
      break;
    }
#define VECTOR_ADD_SUB_SATURATE(intermediate_type, result_type, op, min_val, \
                                max_val)                                     \
  DECODE_VX_INSTRUCTION(t, a, b, T)                                          \
  FOR_EACH_LANE(i, result_type) {                                            \
    intermediate_type a_val = static_cast<intermediate_type>(                \
        get_simd_register_by_lane<result_type>(a, i));                       \
    intermediate_type b_val = static_cast<intermediate_type>(                \
        get_simd_register_by_lane<result_type>(b, i));                       \
    intermediate
"""


```