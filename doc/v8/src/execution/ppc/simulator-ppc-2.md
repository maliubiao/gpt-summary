Response: The user wants a summary of the functionality of the provided C++ code. This is the third part of the file `v8/src/execution/ppc/simulator-ppc.cc`. The previous parts have already covered instruction decoding and basic execution. This part seems to focus on the implementation of individual PowerPC instructions within the simulator.

**Plan:**

1. **Identify the core function:** The central part of this code block is the large `switch` statement within the `ExecuteGeneric` function. Each `case` corresponds to a specific PowerPC instruction.
2. **Summarize instruction categories:** Group the instructions by their function (e.g., floating-point operations, integer arithmetic, memory access, vector operations).
3. **Explain the simulation logic:** Describe how the simulator fetches operands, performs the operation, and updates the simulator state (registers, memory).
4. **Highlight JavaScript relevance:** Focus on how these simulated instructions enable the execution of JavaScript code within the V8 engine. Look for examples that illustrate how high-level JavaScript operations translate to these low-level instructions.
5. **Address the "part 3" aspect:**  Acknowledge that this is the final part and likely builds upon the functionality described in the previous parts.
这是 `v8/src/execution/ppc/simulator-ppc.cc` 文件的第三部分，主要负责 **实现 PowerPC 架构指令的模拟执行**。

具体来说，这部分代码包含 `Simulator::ExecuteGeneric(Instruction* instr)` 函数中的一个巨大的 `switch` 语句，该语句根据指令的操作码 (`opcode`) 分发到不同的代码块，每个代码块负责模拟执行一个特定的 PowerPC 指令。

**主要功能可以归纳为：**

1. **指令实现**:  为各种 PowerPC 指令提供具体的模拟执行逻辑，包括：
    * **浮点运算指令 (Floating-point Instructions)**: `FABS`, `XSADDDP`, `XSSUBDP`, `XSMULDP`, `XSDIVDP`, `XVADDDP`, `XVSUBDP`, `XVMULDP`, `XVDIVDP`, `XSMINDP`, `XSMAXDP`, `XVMINDP`, `XVMAXDP`, `XVABSDP`, `XVNEGDP`, `XVSQRTDP`, `XSCVSPDPN`, `XSCVDPSPN`, `XVMADDMDP`, `XVNMSUBMDP` 等，涵盖了加减乘除、绝对值、取反、平方根、类型转换、融合乘加等操作。
    * **整数运算和逻辑指令 (Integer Arithmetic and Logical Instructions)**: `RLDICL`, `RLDICR`, `RLDIC`, `RLDIMI`, `RLDCL`, `VAND`, `VANDC`, `VOR`, `VNOR`, `VXOR`, `VADDUDM`, `VSUBUDM`, `VMULLD`, `VADDUWM`, `VSUBUWM`, `VMULUWM`, `VADDUHM`, `VSUBUHM`, `VADDUBM`, `VSUBUBM` 等，包括了位操作、加减乘等。
    * **内存访问指令 (Memory Access Instructions)**: `LD`, `LDU`, `LWA`, `STD`, `STDU`, `LVX`, `STVX`, `LXVX`, `STXVX`, `LXVD`, `STXVD`, `LXSIBZX`, `LXSIHZX`, `LXSIWZX`, `LXSDX`, `STXSIBX`, `STXSIHX`, `STXSIWX`, `STXSDX` 等，用于模拟数据的加载和存储。
    * **条件寄存器操作指令 (Condition Register Instructions)**: `MTCRF`, `MTFSB0`, `MTFSB1` 等，用于操作条件寄存器的位。
    * **向量 (SIMD) 指令 (Vector/SIMD Instructions)**:  大量的 `V` 开头的指令，例如 `VSPLTW`, `VSPLTH`, `VSPLTB`, `VINSERTD`, `VINSERTW`, `VINSD`, `VINSW`, `VEXTRACTD`, `VEXTRACTUW`, `VMRGLW`, `VMRGHW`, `VMINSD`, `VMAXSD`, `VSLD`, `VSRAD`, `XVCMPEQDP`, `XVCVSPSXWS`, `VUPKHSB`, `VPKSWSS`, `VADDSHS`, `VSEL`, `VPERM`, `VBPERMQ`, `VMHRADDSHS`, `VMSUMMBM`, `VMLADDUHM`, `VAVGUH`, `VPOPCNTB` 等，模拟 SIMD 向量操作，例如元素级的算术运算、逻辑运算、比较、类型转换、重排、饱和运算等。
2. **寄存器和内存状态更新**:  每个指令的模拟执行代码块都会更新模拟器的寄存器状态 (通用寄存器、浮点寄存器、SIMD 寄存器、条件寄存器等) 和内存状态，以反映指令执行后的结果。
3. **标志位操作**:  一些指令会影响处理器的标志位 (例如条件寄存器)，模拟器也会相应地更新这些标志位。
4. **未实现指令处理**:  对于尚未实现的指令，通常会调用 `UNIMPLEMENTED()` 宏，表明该指令在模拟器中还未被支持。
5. **辅助函数**:  代码中也包含一些辅助函数，例如 `get_register`, `set_register`, `get_double_from_d_register`, `set_d_register_from_double`,  `ReadW`, `WriteDW` 等，用于访问和修改模拟器的寄存器和内存。

**与 JavaScript 的关系 (通过举例说明):**

V8 引擎使用这个模拟器来在不支持原生 PowerPC 指令的平台上执行 JavaScript 代码。JavaScript 代码会被编译成 PowerPC 机器码，然后模拟器逐条执行这些机器码。

例如，考虑以下简单的 JavaScript 代码：

```javascript
function add(a, b) {
  return a + b;
}

let result = add(5, 10);
```

当 V8 编译 `add` 函数时，它可能会生成一些 PowerPC 加法指令。在模拟器中执行时，可能涉及到类似以下 `ExecuteGeneric` 函数中的 `case`：

```c++
case XSADDDP: { // 假设是浮点数加法
  int frt = instr->RTValue();
  int fra = instr->RAValue();
  int frb = instr->RBValue();
  double fra_val = get_double_from_d_register(fra); // 获取操作数
  double frb_val = get_double_from_d_register(frb);
  double frt_val = fra_val + frb_val;              // 执行加法
  set_d_register_from_double(frt, frt_val);        // 更新寄存器
  return;
}
```

或者，如果涉及整数加法，可能会执行类似以下指令（尽管例子中的 JavaScript 是数字，V8 内部可能用浮点表示）：

```c++
// ... 在之前的部分可能存在整数加法指令的模拟 ...
```

再比如，JavaScript 中的数组操作可能涉及到内存访问指令的模拟，例如：

```javascript
let arr = [1, 2, 3];
let first = arr[0];
```

在模拟器中，读取 `arr[0]` 可能会对应于 `ExecuteGeneric` 函数中的 `LD` 或类似的内存加载指令的模拟。

SIMD 向量指令的模拟则与 JavaScript 中一些高性能操作 (例如，WebAssembly 的 SIMD 指令，或者未来 JavaScript 引擎可能使用的 SIMD 优化) 相关。 例如，两个数组的元素级加法，如果 V8 进行了 SIMD 优化，就可能对应到 `XVADDDP` 或 `VADDUDM` 等向量加法指令的模拟执行。

**作为第三部分:**

这部分代码是整个 `simulator-ppc.cc` 文件的核心执行部分，建立在第一部分 (可能包含模拟器的初始化、寄存器和内存管理) 和第二部分 (可能包含指令解码和基本的执行框架) 的基础上。它负责将解码后的 PowerPC 指令翻译成模拟器内部的操作，使得 V8 能够在非 PowerPC 平台上运行编译后的 JavaScript 代码。

总而言之，`v8/src/execution/ppc/simulator-ppc.cc` 文件的第三部分实现了 PowerPC 指令集的模拟器，这是 V8 引擎在非 PowerPC 架构上执行 JavaScript 代码的关键组成部分。它通过模拟 PowerPC 指令的行为，使得 JavaScript 代码得以运行。

### 提示词
```
这是目录为v8/src/execution/ppc/simulator-ppc.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第3部分，共3部分，请归纳一下它的功能
```

### 源代码
```
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
    intermediate_type t_val = a_val op b_val;                                \
    if (t_val > max_val)                                                     \
      t_val = max_val;                                                       \
    else if (t_val < min_val)                                                \
      t_val = min_val;                                                       \
    set_simd_register_by_lane<result_type>(t, i,                             \
                                           static_cast<result_type>(t_val)); \
  }
    case VADDSHS: {
      VECTOR_ADD_SUB_SATURATE(int32_t, int16_t, +, kMinInt16, kMaxInt16)
      break;
    }
    case VSUBSHS: {
      VECTOR_ADD_SUB_SATURATE(int32_t, int16_t, -, kMinInt16, kMaxInt16)
      break;
    }
    case VADDUHS: {
      VECTOR_ADD_SUB_SATURATE(int32_t, uint16_t, +, 0, kMaxUInt16)
      break;
    }
    case VSUBUHS: {
      VECTOR_ADD_SUB_SATURATE(int32_t, uint16_t, -, 0, kMaxUInt16)
      break;
    }
    case VADDSBS: {
      VECTOR_ADD_SUB_SATURATE(int16_t, int8_t, +, kMinInt8, kMaxInt8)
      break;
    }
    case VSUBSBS: {
      VECTOR_ADD_SUB_SATURATE(int16_t, int8_t, -, kMinInt8, kMaxInt8)
      break;
    }
    case VADDUBS: {
      VECTOR_ADD_SUB_SATURATE(int16_t, uint8_t, +, 0, kMaxUInt8)
      break;
    }
    case VSUBUBS: {
      VECTOR_ADD_SUB_SATURATE(int16_t, uint8_t, -, 0, kMaxUInt8)
      break;
    }
#undef VECTOR_ADD_SUB_SATURATE
#define VECTOR_FP_ROUNDING(type, op)                       \
  int t = instr->RTValue();                                \
  int b = instr->RBValue();                                \
  FOR_EACH_LANE(i, type) {                                 \
    type b_val = get_simd_register_by_lane<type>(b, i);    \
    set_simd_register_by_lane<type>(t, i, std::op(b_val)); \
  }
    case XVRDPIP: {
      VECTOR_FP_ROUNDING(double, ceil)
      break;
    }
    case XVRDPIM: {
      VECTOR_FP_ROUNDING(double, floor)
      break;
    }
    case XVRDPIZ: {
      VECTOR_FP_ROUNDING(double, trunc)
      break;
    }
    case XVRDPI: {
      VECTOR_FP_ROUNDING(double, nearbyint)
      break;
    }
    case XVRSPIP: {
      VECTOR_FP_ROUNDING(float, ceilf)
      break;
    }
    case XVRSPIM: {
      VECTOR_FP_ROUNDING(float, floorf)
      break;
    }
    case XVRSPIZ: {
      VECTOR_FP_ROUNDING(float, truncf)
      break;
    }
    case XVRSPI: {
      VECTOR_FP_ROUNDING(float, nearbyintf)
      break;
    }
#undef VECTOR_FP_ROUNDING
    case VSEL: {
      int vrt = instr->RTValue();
      int vra = instr->RAValue();
      int vrb = instr->RBValue();
      int vrc = instr->RCValue();
      unsigned __int128 src_1 =
          base::bit_cast<__int128>(get_simd_register(vra).int8);
      unsigned __int128 src_2 =
          base::bit_cast<__int128>(get_simd_register(vrb).int8);
      unsigned __int128 src_3 =
          base::bit_cast<__int128>(get_simd_register(vrc).int8);
      unsigned __int128 tmp = (src_1 & ~src_3) | (src_2 & src_3);
      simdr_t* result = reinterpret_cast<simdr_t*>(&tmp);
      set_simd_register(vrt, *result);
      break;
    }
    case VPERM: {
      int vrt = instr->RTValue();
      int vra = instr->RAValue();
      int vrb = instr->RBValue();
      int vrc = instr->RCValue();
      int8_t temp[kSimd128Size] = {0};
      FOR_EACH_LANE(i, int8_t) {
        int8_t lane_num = get_simd_register_by_lane<int8_t>(vrc, i);
        // Get the five least significant bits.
        lane_num = (lane_num << 3) >> 3;
        int reg = vra;
        if (lane_num >= kSimd128Size) {
          lane_num = lane_num - kSimd128Size;
          reg = vrb;
        }
        temp[i] = get_simd_register_by_lane<int8_t>(reg, lane_num);
      }
      FOR_EACH_LANE(i, int8_t) {
        set_simd_register_by_lane<int8_t>(vrt, i, temp[i]);
      }
      break;
    }
    case VBPERMQ: {
      DECODE_VX_INSTRUCTION(t, a, b, T)
      uint16_t result_bits = 0;
      unsigned __int128 src_bits =
          base::bit_cast<__int128>(get_simd_register(a).int8);
      for (int i = 0; i < kSimd128Size; i++) {
        result_bits <<= 1;
        uint8_t selected_bit_index = get_simd_register_by_lane<uint8_t>(b, i);
        if (selected_bit_index < (kSimd128Size * kBitsPerByte)) {
          unsigned __int128 bit_value = (src_bits << selected_bit_index) >>
                                        (kSimd128Size * kBitsPerByte - 1);
          result_bits |= bit_value;
        }
      }
      set_simd_register_by_lane<uint64_t>(t, 0, 0);
      set_simd_register_by_lane<uint64_t>(t, 1, 0);
      set_simd_register_by_lane<uint16_t>(t, 3, result_bits);
      break;
    }
#define VECTOR_FP_QF(type, sign, function)                       \
  DECODE_VX_INSTRUCTION(t, a, b, T)                              \
  FOR_EACH_LANE(i, type) {                                       \
    type a_val = get_simd_register_by_lane<type>(a, i);          \
    type b_val = get_simd_register_by_lane<type>(b, i);          \
    type t_val = get_simd_register_by_lane<type>(t, i);          \
    type reuslt = sign * function(a_val, t_val, (sign * b_val)); \
    if (isinf(a_val)) reuslt = a_val;                            \
    if (isinf(b_val)) reuslt = b_val;                            \
    if (isinf(t_val)) reuslt = t_val;                            \
    set_simd_register_by_lane<type>(t, i, reuslt);               \
  }
    case XVMADDMDP: {
      VECTOR_FP_QF(double, +1, fma)
      break;
    }
    case XVNMSUBMDP: {
      VECTOR_FP_QF(double, -1, fma)
      break;
    }
    case XVMADDMSP: {
      VECTOR_FP_QF(float, +1, fmaf)
      break;
    }
    case XVNMSUBMSP: {
      VECTOR_FP_QF(float, -1, fmaf)
      break;
    }
#undef VECTOR_FP_QF
    case VMHRADDSHS: {
      int vrt = instr->RTValue();
      int vra = instr->RAValue();
      int vrb = instr->RBValue();
      int vrc = instr->RCValue();
      FOR_EACH_LANE(i, int16_t) {
        int16_t vra_val = get_simd_register_by_lane<int16_t>(vra, i);
        int16_t vrb_val = get_simd_register_by_lane<int16_t>(vrb, i);
        int16_t vrc_val = get_simd_register_by_lane<int16_t>(vrc, i);
        int32_t temp = vra_val * vrb_val;
        temp = (temp + 0x00004000) >> 15;
        temp += vrc_val;
        if (temp > kMaxInt16)
          temp = kMaxInt16;
        else if (temp < kMinInt16)
          temp = kMinInt16;
        set_simd_register_by_lane<int16_t>(vrt, i, static_cast<int16_t>(temp));
      }
      break;
    }
    case VMSUMMBM: {
      int vrt = instr->RTValue();
      int vra = instr->RAValue();
      int vrb = instr->RBValue();
      int vrc = instr->RCValue();
      FOR_EACH_LANE(i, int32_t) {
        int8_t vra_1_val = get_simd_register_by_lane<int8_t>(vra, 4 * i),
               vra_2_val = get_simd_register_by_lane<int8_t>(vra, (4 * i) + 1),
               vra_3_val = get_simd_register_by_lane<int8_t>(vra, (4 * i) + 2),
               vra_4_val = get_simd_register_by_lane<int8_t>(vra, (4 * i) + 3);
        uint8_t vrb_1_val = get_simd_register_by_lane<uint8_t>(vrb, 4 * i),
                vrb_2_val =
                    get_simd_register_by_lane<uint8_t>(vrb, (4 * i) + 1),
                vrb_3_val =
                    get_simd_register_by_lane<uint8_t>(vrb, (4 * i) + 2),
                vrb_4_val =
                    get_simd_register_by_lane<uint8_t>(vrb, (4 * i) + 3);
        int32_t vrc_val = get_simd_register_by_lane<int32_t>(vrc, i);
        int32_t temp1 = vra_1_val * vrb_1_val, temp2 = vra_2_val * vrb_2_val,
                temp3 = vra_3_val * vrb_3_val, temp4 = vra_4_val * vrb_4_val;
        temp1 = temp1 + temp2 + temp3 + temp4 + vrc_val;
        set_simd_register_by_lane<int32_t>(vrt, i, temp1);
      }
      break;
    }
    case VMSUMSHM: {
      int vrt = instr->RTValue();
      int vra = instr->RAValue();
      int vrb = instr->RBValue();
      int vrc = instr->RCValue();
      FOR_EACH_LANE(i, int32_t) {
        int16_t vra_1_val = get_simd_register_by_lane<int16_t>(vra, 2 * i);
        int16_t vra_2_val =
            get_simd_register_by_lane<int16_t>(vra, (2 * i) + 1);
        int16_t vrb_1_val = get_simd_register_by_lane<int16_t>(vrb, 2 * i);
        int16_t vrb_2_val =
            get_simd_register_by_lane<int16_t>(vrb, (2 * i) + 1);
        int32_t vrc_val = get_simd_register_by_lane<int32_t>(vrc, i);
        int32_t temp1 = vra_1_val * vrb_1_val, temp2 = vra_2_val * vrb_2_val;
        temp1 = temp1 + temp2 + vrc_val;
        set_simd_register_by_lane<int32_t>(vrt, i, temp1);
      }
      break;
    }
    case VMLADDUHM: {
      int vrt = instr->RTValue();
      int vra = instr->RAValue();
      int vrb = instr->RBValue();
      int vrc = instr->RCValue();
      FOR_EACH_LANE(i, uint16_t) {
        uint16_t vra_val = get_simd_register_by_lane<uint16_t>(vra, i);
        uint16_t vrb_val = get_simd_register_by_lane<uint16_t>(vrb, i);
        uint16_t vrc_val = get_simd_register_by_lane<uint16_t>(vrc, i);
        set_simd_register_by_lane<uint16_t>(vrt, i,
                                            (vra_val * vrb_val) + vrc_val);
      }
      break;
    }
#define VECTOR_UNARY_OP(type, op)                         \
  int t = instr->RTValue();                               \
  int b = instr->RBValue();                               \
  FOR_EACH_LANE(i, type) {                                \
    set_simd_register_by_lane<type>(                      \
        t, i, op(get_simd_register_by_lane<type>(b, i))); \
  }
    case XVABSDP: {
      VECTOR_UNARY_OP(double, std::abs)
      break;
    }
    case XVNEGDP: {
      VECTOR_UNARY_OP(double, -)
      break;
    }
    case XVSQRTDP: {
      VECTOR_UNARY_OP(double, std::sqrt)
      break;
    }
    case XVABSSP: {
      VECTOR_UNARY_OP(float, std::abs)
      break;
    }
    case XVNEGSP: {
      VECTOR_UNARY_OP(float, -)
      break;
    }
    case XVSQRTSP: {
      VECTOR_UNARY_OP(float, std::sqrt)
      break;
    }
    case XVRESP: {
      VECTOR_UNARY_OP(float, base::Recip)
      break;
    }
    case XVRSQRTESP: {
      VECTOR_UNARY_OP(float, base::RecipSqrt)
      break;
    }
    case VNEGW: {
      VECTOR_UNARY_OP(int32_t, -)
      break;
    }
    case VNEGD: {
      VECTOR_UNARY_OP(int64_t, -)
      break;
    }
#undef VECTOR_UNARY_OP
#define VECTOR_ROUNDING_AVERAGE(intermediate_type, result_type)              \
  DECODE_VX_INSTRUCTION(t, a, b, T)                                          \
  FOR_EACH_LANE(i, result_type) {                                            \
    intermediate_type a_val = static_cast<intermediate_type>(                \
        get_simd_register_by_lane<result_type>(a, i));                       \
    intermediate_type b_val = static_cast<intermediate_type>(                \
        get_simd_register_by_lane<result_type>(b, i));                       \
    intermediate_type t_val = ((a_val + b_val) + 1) >> 1;                    \
    set_simd_register_by_lane<result_type>(t, i,                             \
                                           static_cast<result_type>(t_val)); \
  }
    case VAVGUH: {
      VECTOR_ROUNDING_AVERAGE(uint32_t, uint16_t)
      break;
    }
    case VAVGUB: {
      VECTOR_ROUNDING_AVERAGE(uint16_t, uint8_t)
      break;
    }
#undef VECTOR_ROUNDING_AVERAGE
    case VPOPCNTB: {
      int t = instr->RTValue();
      int b = instr->RBValue();
      FOR_EACH_LANE(i, uint8_t) {
        set_simd_register_by_lane<uint8_t>(
            t, i,
            base::bits::CountPopulation(
                get_simd_register_by_lane<uint8_t>(b, i)));
      }
      break;
    }
#define EXTRACT_MASK(type)                                           \
  int rt = instr->RTValue();                                         \
  int vrb = instr->RBValue();                                        \
  uint64_t result = 0;                                               \
  FOR_EACH_LANE(i, type) {                                           \
    if (i > 0) result <<= 1;                                         \
    result |= std::signbit(get_simd_register_by_lane<type>(vrb, i)); \
  }                                                                  \
  set_register(rt, result);
    case VEXTRACTDM: {
      EXTRACT_MASK(int64_t)
      break;
    }
    case VEXTRACTWM: {
      EXTRACT_MASK(int32_t)
      break;
    }
    case VEXTRACTHM: {
      EXTRACT_MASK(int16_t)
      break;
    }
    case VEXTRACTBM: {
      EXTRACT_MASK(int8_t)
      break;
    }
#undef EXTRACT_MASK
#undef FOR_EACH_LANE
#undef DECODE_VX_INSTRUCTION
#undef GET_ADDRESS
    default: {
      UNIMPLEMENTED();
    }
  }
}

void Simulator::Trace(Instruction* instr) {
  disasm::NameConverter converter;
  disasm::Disassembler dasm(converter);
  // use a reasonably large buffer
  v8::base::EmbeddedVector<char, 256> buffer;
  dasm.InstructionDecode(buffer, reinterpret_cast<uint8_t*>(instr));
  PrintF("%05d  %08" V8PRIxPTR "  %s\n", icount_,
         reinterpret_cast<intptr_t>(instr), buffer.begin());
}

// Executes the current instruction.
void Simulator::ExecuteInstruction(Instruction* instr) {
  if (v8_flags.check_icache) {
    CheckICache(i_cache(), instr);
  }
  pc_modified_ = false;
  if (v8_flags.trace_sim) {
    Trace(instr);
  }
  uint32_t opcode = instr->OpcodeField();
  if (opcode == TWI) {
    SoftwareInterrupt(instr);
  } else {
    ExecuteGeneric(instr);
  }
  if (!pc_modified_) {
    set_pc(reinterpret_cast<intptr_t>(instr) + kInstrSize);
  }
}

void Simulator::Execute() {
  // Get the PC to simulate. Cannot use the accessor here as we need the
  // raw PC value and not the one used as input to arithmetic instructions.
  intptr_t program_counter = get_pc();

  if (v8_flags.stop_sim_at == 0) {
    // Fast version of the dispatch loop without checking whether the simulator
    // should be stopping at a particular executed instruction.
    while (program_counter != end_sim_pc) {
      Instruction* instr = reinterpret_cast<Instruction*>(program_counter);
      icount_++;
      ExecuteInstruction(instr);
      program_counter = get_pc();
    }
  } else {
    // v8_flags.stop_sim_at is at the non-default value. Stop in the debugger
    // when we reach the particular instruction count.
    while (program_counter != end_sim_pc) {
      Instruction* instr = reinterpret_cast<Instruction*>(program_counter);
      icount_++;
      if (icount_ == v8_flags.stop_sim_at) {
        PPCDebugger dbg(this);
        dbg.Debug();
      } else {
        ExecuteInstruction(instr);
      }
      program_counter = get_pc();
    }
  }
}

void Simulator::CallInternal(Address entry) {
  // Adjust JS-based stack limit to C-based stack limit.
  isolate_->stack_guard()->AdjustStackLimitForSimulator();

  // Prepare to execute the code at entry
  if (ABI_USES_FUNCTION_DESCRIPTORS) {
    // entry is the function descriptor
    set_pc(*(reinterpret_cast<intptr_t*>(entry)));
  } else {
    // entry is the instruction address
    set_pc(static_cast<intptr_t>(entry));
  }

  if (ABI_CALL_VIA_IP) {
    // Put target address in ip (for JS prologue).
    set_register(r12, get_pc());
  }

  // Put down marker for end of simulation. The simulator will stop simulation
  // when the PC reaches this value. By saving the "end simulation" value into
  // the LR the simulation stops when returning to this call point.
  special_reg_lr_ = end_sim_pc;

  // Remember the values of non-volatile registers.
  intptr_t r2_val = get_register(r2);
  intptr_t r13_val = get_register(r13);
  intptr_t r14_val = get_register(r14);
  intptr_t r15_val = get_register(r15);
  intptr_t r16_val = get_register(r16);
  intptr_t r17_val = get_register(r17);
  intptr_t r18_val = get_register(r18);
  intptr_t r19_val = get_register(r19);
  intptr_t r20_val = get_register(r20);
  intptr_t r21_val = get_register(r21);
  intptr_t r22_val = get_register(r22);
  intptr_t r23_val = get_register(r23);
  intptr_t r24_val = get_register(r24);
  intptr_t r25_val = get_register(r25);
  intptr_t r26_val = get_register(r26);
  intptr_t r27_val = get_register(r27);
  intptr_t r28_val = get_register(r28);
  intptr_t r29_val = get_register(r29);
  intptr_t r30_val = get_register(r30);
  intptr_t r31_val = get_register(fp);

  // Set up the non-volatile registers with a known value. To be able to check
  // that they are preserved properly across JS execution.
  intptr_t callee_saved_value = icount_;
  set_register(r2, callee_saved_value);
  set_register(r13, callee_saved_value);
  set_register(r14, callee_saved_value);
  set_register(r15, callee_saved_value);
  set_register(r16, callee_saved_value);
  set_register(r17, callee_saved_value);
  set_register(r18, callee_saved_value);
  set_register(r19, callee_saved_value);
  set_register(r20, callee_saved_value);
  set_register(r21, callee_saved_value);
  set_register(r22, callee_saved_value);
  set_register(r23, callee_saved_value);
  set_register(r24, callee_saved_value);
  set_register(r25, callee_saved_value);
  set_register(r26, callee_saved_value);
  set_register(r27, callee_saved_value);
  set_register(r28, callee_saved_value);
  set_register(r29, callee_saved_value);
  set_register(r30, callee_saved_value);
  set_register(fp, callee_saved_value);

  // Start the simulation
  Execute();

  // Check that the non-volatile registers have been preserved.
  if (ABI_TOC_REGISTER != 2) {
    CHECK_EQ(callee_saved_value, get_register(r2));
  }
  if (ABI_TOC_REGISTER != 13) {
    CHECK_EQ(callee_saved_value, get_register(r13));
  }
  CHECK_EQ(callee_saved_value, get_register(r14));
  CHECK_EQ(callee_saved_value, get_register(r15));
  CHECK_EQ(callee_saved_value, get_register(r16));
  CHECK_EQ(callee_saved_value, get_register(r17));
  CHECK_EQ(callee_saved_value, get_register(r18));
  CHECK_EQ(callee_saved_value, get_register(r19));
  CHECK_EQ(callee_saved_value, get_register(r20));
  CHECK_EQ(callee_saved_value, get_register(r21));
  CHECK_EQ(callee_saved_value, get_register(r22));
  CHECK_EQ(callee_saved_value, get_register(r23));
  CHECK_EQ(callee_saved_value, get_register(r24));
  CHECK_EQ(callee_saved_value, get_register(r25));
  CHECK_EQ(callee_saved_value, get_register(r26));
  CHECK_EQ(callee_saved_value, get_register(r27));
  CHECK_EQ(callee_saved_value, get_register(r28));
  CHECK_EQ(callee_saved_value, get_register(r29));
  CHECK_EQ(callee_saved_value, get_register(r30));
  CHECK_EQ(callee_saved_value, get_register(fp));

  // Restore non-volatile registers with the original value.
  set_register(r2, r2_val);
  set_register(r13, r13_val);
  set_register(r14, r14_val);
  set_register(r15, r15_val);
  set_register(r16, r16_val);
  set_register(r17, r17_val);
  set_register(r18, r18_val);
  set_register(r19, r19_val);
  set_register(r20, r20_val);
  set_register(r21, r21_val);
  set_register(r22, r22_val);
  set_register(r23, r23_val);
  set_register(r24, r24_val);
  set_register(r25, r25_val);
  set_register(r26, r26_val);
  set_register(r27, r27_val);
  set_register(r28, r28_val);
  set_register(r29, r29_val);
  set_register(r30, r30_val);
  set_register(fp, r31_val);
}

intptr_t Simulator::CallImpl(Address entry, int argument_count,
                             const intptr_t* arguments) {
  // Set up arguments

  // First eight arguments passed in registers r3-r10.
  int reg_arg_count = std::min(8, argument_count);
  int stack_arg_count = argument_count - reg_arg_count;
  for (int i = 0; i < reg_arg_count; i++) {
    set_register(i + 3, arguments[i]);
  }

  // Remaining arguments passed on stack.
  intptr_t original_stack = get_register(sp);
  // Compute position of stack on entry to generated code.
  intptr_t entry_stack =
      (original_stack -
       (kNumRequiredStackFrameSlots + stack_arg_count) * sizeof(intptr_t));
  if (base::OS::ActivationFrameAlignment() != 0) {
    entry_stack &= -base::OS::ActivationFrameAlignment();
  }
  // Store remaining arguments on stack, from low to high memory.
  // +2 is a hack for the LR slot + old SP on PPC
  intptr_t* stack_argument =
      reinterpret_cast<intptr_t*>(entry_stack) + kStackFrameExtraParamSlot;
  memcpy(stack_argument, arguments + reg_arg_count,
         stack_arg_count * sizeof(*arguments));
  set_register(sp, entry_stack);

  CallInternal(entry);

  // Pop stack passed arguments.
  CHECK_EQ(entry_stack, get_register(sp));
  set_register(sp, original_stack);

  return get_register(r3);
}

void Simulator::CallFP(Address entry, double d0, double d1) {
  set_d_register_from_double(1, d0);
  set_d_register_from_double(2, d1);
  CallInternal(entry);
}

int32_t Simulator::CallFPReturnsInt(Address entry, double d0, double d1) {
  CallFP(entry, d0, d1);
  int32_t result = get_register(r3);
  return result;
}

double Simulator::CallFPReturnsDouble(Address entry, double d0, double d1) {
  CallFP(entry, d0, d1);
  return get_double_from_d_register(1);
}

uintptr_t Simulator::PushAddress(uintptr_t address) {
  uintptr_t new_sp = get_register(sp) - sizeof(uintptr_t);
  uintptr_t* stack_slot = reinterpret_cast<uintptr_t*>(new_sp);
  *stack_slot = address;
  set_register(sp, new_sp);
  return new_sp;
}

uintptr_t Simulator::PopAddress() {
  uintptr_t current_sp = get_register(sp);
  uintptr_t* stack_slot = reinterpret_cast<uintptr_t*>(current_sp);
  uintptr_t address = *stack_slot;
  set_register(sp, current_sp + sizeof(uintptr_t));
  return address;
}

void Simulator::GlobalMonitor::Clear() {
  access_state_ = MonitorAccess::Open;
  tagged_addr_ = 0;
  size_ = TransactionSize::None;
  thread_id_ = ThreadId::Invalid();
}

void Simulator::GlobalMonitor::NotifyLoadExcl(uintptr_t addr,
                                              TransactionSize size,
                                              ThreadId thread_id) {
  // TODO(s390): By using Global Monitors, we are effectively limiting one
  // active reservation across all processors. This would potentially serialize
  // parallel threads executing load&reserve + store conditional on unrelated
  // memory. Technically, this implementation would still make the simulator
  // adhere to the spec, but seems overly heavy-handed.
  access_state_ = MonitorAccess::Exclusive;
  tagged_addr_ = addr;
  size_ = size;
  thread_id_ = thread_id;
}

void Simulator::GlobalMonitor::NotifyStore(uintptr_t addr, TransactionSize size,
                                           ThreadId thread_id) {
  if (access_state_ == MonitorAccess::Exclusive) {
    // Calculate if the transaction has been overlapped
    uintptr_t transaction_start = addr;
    uintptr_t transaction_end = addr + static_cast<uintptr_t>(size);
    uintptr_t exclusive_transaction_start = tagged_addr_;
    uintptr_t exclusive_transaction_end =
        tagged_addr_ + static_cast<uintptr_t>(size_);
    bool is_not_overlapped = transaction_end < exclusive_transaction_start ||
                             exclusive_transaction_end < transaction_start;
    if (!is_not_overlapped && thread_id_ != thread_id) {
      Clear();
    }
  }
}

bool Simulator::GlobalMonitor::NotifyStoreExcl(uintptr_t addr,
                                               TransactionSize size,
                                               ThreadId thread_id) {
  bool permission = access_state_ == MonitorAccess::Exclusive &&
                    addr == tagged_addr_ && size_ == size &&
                    thread_id_ == thread_id;
  // The reservation is cleared if the processor holding the reservation
  // executes a store conditional instruction to any address.
  Clear();
  return permission;
}

}  // namespace internal
}  // namespace v8

#undef SScanF
#endif  // USE_SIMULATOR
```