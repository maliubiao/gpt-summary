Response: The user wants a summary of the functionality of the provided C++ code snippet, which is part of a larger file simulating ARM architecture within the V8 JavaScript engine. I need to focus on the operations performed in this specific segment.

The code mainly deals with:
1. **SIMD (NEON) instructions**: It handles left and right shifts, including shift and insert operations, on different data sizes (8, 16, 32, 64 bits) for both 128-bit and 64-bit SIMD registers.
2. **Memory hints and barriers**: It seems to ignore `pld`, `dsb`, `dmb`, and `isb` instructions for now, indicating potential areas for future implementation.
3. **Advanced SIMD Load/Store**: It includes logic for loading and storing multiple or single structures to or from all/one lane of SIMD registers.
4. **Floating-point data processing**: It handles instructions like rounding (`vrinta`, `vrintn`, `vrintp`, `vrintm`), minimum/maximum number selection (ignoring NaNs - `vminnm`, `vmaxnm`), and conditional selection (`VSELEQ`, `VSELVS`, `VSELGE`, `VSELGT`).

If there is a connection to JavaScript, I need to illustrate it with an example. Since this code simulates low-level ARM instructions, its direct impact on JavaScript is in how JavaScript code is executed on ARM architectures. The SIMD and floating-point operations are particularly relevant for performance-critical JavaScript tasks.
这是v8 JavaScript引擎中ARM架构模拟器的源代码文件（第4部分）。该部分代码主要负责**解码和执行ARM架构中的高级SIMD（NEON）指令、内存提示和屏障指令，以及浮点数据处理指令**。它模拟了这些指令在ARM处理器上的行为。

**功能归纳:**

1. **高级SIMD (NEON) 指令模拟:**
   - 实现了向量数据的位移操作，包括左移 (`vsli`, `shl`) 和右移 (`vsri`, `ushr`)，并支持插入操作 (`ShiftLeftAndInsert`, `ShiftRightAndInsert`)。
   - 支持不同的数据类型和大小，例如 `uint8_t`, `uint16_t`, `uint32_t`, `uint64_t`，以及 64 位 (Double) 和 128 位 (Quad) 的向量寄存器。
   - 这些操作模拟了NEON指令集在处理并行数据时的行为。

2. **内存提示和屏障指令模拟:**
   -  目前的代码对于内存预取 (`pld`) 指令选择忽略。
   -  对于数据同步屏障 (`dsb`)、数据内存屏障 (`dmb`) 和指令同步屏障 (`isb`) 指令，代码中标记为“暂时忽略”，并指出未来需要实现。

3. **高级SIMD加载/存储指令模拟:**
   -  实现了加载和存储多个结构体的指令 (`vld1`, `vst1`)。
   -  实现了将单个结构体加载到所有向量通道的指令 (`vld1`，将单个元素复制到整个向量寄存器)。
   -  实现了加载和存储单个结构体到一个向量通道的指令 (`vld1`, `vst1s`)。

4. **浮点数据处理指令模拟:**
   -  实现了浮点数的舍入操作 (`vrinta`, `vrintn`, `vrintp`, `vrintm`)，支持四种不同的舍入模式（向远离零舍入、向偶数舍入、向上取整、向下取整）。
   -  实现了浮点数的最小值和最大值选择操作 (`vminnm`, `vmaxnm`)，这些操作会考虑 `NaN` 值，并确保正负零的符号正确。
   -  实现了浮点数的条件选择操作 (`VSELEQ`, `VSELVS`, `VSELGE`, `VSELGT`)，根据条件标志位选择源操作数。

**与JavaScript的关系 (使用JavaScript举例说明):**

虽然这个C++代码是模拟器的一部分，直接操作的是底层的指令执行，但它直接影响了JavaScript代码在ARM架构上的执行效率，尤其是在处理需要大量并行计算或浮点运算的场景下。

例如，JavaScript中的 `SIMD` API 允许开发者利用底层的SIMD指令来加速计算密集型任务。当V8引擎在ARM架构上运行时，这个模拟器会负责模拟 `SIMD` API 背后对应的NEON指令。

```javascript
// JavaScript SIMD 代码示例 (假设支持 SIMD)
const a = SIMD.float32x4(1.0, 2.0, 3.0, 4.0);
const b = SIMD.float32x4(5.0, 6.0, 7.0, 8.0);
const sum = SIMD.float32x4.add(a, b); // 向量加法
// sum 的值将是 float32x4(6.0, 8.0, 10.0, 12.0)
```

在这个 JavaScript 示例中，`SIMD.float32x4.add(a, b)` 操作会被 V8 引擎编译成底层的 ARM NEON 指令 (例如 `fadd`). `simulator-arm.cc` 中的代码 (比如 `ShiftLeft`, `ShiftRightAndInsert`, 或者浮点数加法相关的模拟代码) 就负责模拟这些底层 NEON 指令的行为。当 JavaScript 代码在模拟器环境下执行时，这个 C++ 文件中的代码会被调用，模拟实际硬件执行这些向量加法的过程。

同样，JavaScript 中使用 `Math.round`, `Math.ceil`, `Math.floor`, `Math.min`, `Math.max` 等函数进行数值计算时，如果涉及到浮点数，并且代码运行在 ARM 架构上，那么 `simulator-arm.cc` 中 `DecodeFloatingPointDataProcessing` 函数里模拟浮点数舍入和比较的代码就会被执行。

**总结:**

这个代码片段是V8引擎在非ARM硬件上模拟ARM架构执行JavaScript代码的关键组成部分。它精确地模拟了ARM处理器的指令行为，使得开发者可以在非ARM平台上测试和调试针对ARM架构优化的JavaScript代码。特别地，对于利用了 SIMD API 或大量浮点运算的 JavaScript 代码，这个模拟器提供的功能至关重要。

### 提示词
```
这是目录为v8/src/execution/arm/simulator-arm.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第4部分，共4部分，请归纳一下它的功能
```

### 源代码
```
{
          case Neon8:
            ShiftLeft<uint8_t, kSimd128Size>(this, Vd, Vm, shift);
            break;
          case Neon16:
            ShiftLeft<uint16_t, kSimd128Size>(this, Vd, Vm, shift);
            break;
          case Neon32:
            ShiftLeft<uint32_t, kSimd128Size>(this, Vd, Vm, shift);
            break;
          case Neon64:
            ShiftLeft<uint64_t, kSimd128Size>(this, Vd, Vm, shift);
            break;
        }
      } else if (u && imm3H_L != 0 && opc == 0b0100) {
        // vsri.<size> Dd, Dm, shift
        int shift = 2 * size - imm7;
        int Vd = instr->VFPDRegValue(kDoublePrecision);
        int Vm = instr->VFPMRegValue(kDoublePrecision);
        switch (size) {
          case 8:
            ShiftRightAndInsert<uint8_t, kDoubleSize>(this, Vd, Vm, shift);
            break;
          case 16:
            ShiftRightAndInsert<uint16_t, kDoubleSize>(this, Vd, Vm, shift);
            break;
          case 32:
            ShiftRightAndInsert<uint32_t, kDoubleSize>(this, Vd, Vm, shift);
            break;
          case 64:
            ShiftRightAndInsert<uint64_t, kDoubleSize>(this, Vd, Vm, shift);
            break;
          default:
            UNREACHABLE();
        }
      } else if (u && imm3H_L != 0 && opc == 0b0101) {
        // vsli.<size> Dd, Dm, shift
        int shift = imm7 - size;
        int Vd = instr->VFPDRegValue(kDoublePrecision);
        int Vm = instr->VFPMRegValue(kDoublePrecision);
        switch (size) {
          case 8:
            ShiftLeftAndInsert<uint8_t, kDoubleSize>(this, Vd, Vm, shift);
            break;
          case 16:
            ShiftLeftAndInsert<uint16_t, kDoubleSize>(this, Vd, Vm, shift);
            break;
          case 32:
            ShiftLeftAndInsert<uint32_t, kDoubleSize>(this, Vd, Vm, shift);
            break;
          case 64:
            ShiftLeftAndInsert<uint64_t, kDoubleSize>(this, Vd, Vm, shift);
            break;
          default:
            UNREACHABLE();
        }
      }
    }
    return;
  }
}

void Simulator::DecodeMemoryHintsAndBarriers(Instruction* instr) {
  switch (instr->SpecialValue()) {
    case 0xA:
    case 0xB:
      if ((instr->Bits(22, 20) == 5) && (instr->Bits(15, 12) == 0xF)) {
        // pld: ignore instruction.
      } else if (instr->SpecialValue() == 0xA && instr->Bits(22, 20) == 7) {
        // dsb, dmb, isb: ignore instruction for now.
        // TODO(binji): implement
        // Also refer to the ARMv6 CP15 equivalents in DecodeTypeCP15.
      } else {
        UNIMPLEMENTED();
      }
      break;
    default:
      UNIMPLEMENTED();
  }
}

void Simulator::DecodeAdvancedSIMDElementOrStructureLoadStore(
    Instruction* instr) {
  int op0 = instr->Bit(23);
  int op1 = instr->Bits(11, 10);

  if (!op0) {
    DecodeAdvancedSIMDLoadStoreMultipleStructures(instr);
  } else if (op1 == 0b11) {
    DecodeAdvancedSIMDLoadSingleStructureToAllLanes(instr);
  } else {
    DecodeAdvancedSIMDLoadStoreSingleStructureToOneLane(instr);
  }
}

void Simulator::DecodeAdvancedSIMDLoadStoreMultipleStructures(
    Instruction* instr) {
  int Vd = instr->VFPDRegValue(kDoublePrecision);
  int Rn = instr->VnValue();
  int Rm = instr->VmValue();
  int type = instr->Bits(11, 8);
  int32_t address = get_register(Rn);
  int regs = 0;
  switch (type) {
    case nlt_1:
      regs = 1;
      break;
    case nlt_2:
      regs = 2;
      break;
    case nlt_3:
      regs = 3;
      break;
    case nlt_4:
      regs = 4;
      break;
    default:
      UNIMPLEMENTED();
  }
  if (instr->Bit(21)) {
    // vld1
    int r = 0;
    while (r < regs) {
      uint32_t data[2];
      data[0] = ReadW(address);
      data[1] = ReadW(address + 4);
      set_d_register(Vd + r, data);
      address += 8;
      r++;
    }
  } else {
    // vst1
    int r = 0;
    while (r < regs) {
      uint32_t data[2];
      get_d_register(Vd + r, data);
      WriteW(address, data[0]);
      WriteW(address + 4, data[1]);
      address += 8;
      r++;
    }
  }
  AdvancedSIMDElementOrStructureLoadStoreWriteback(Rn, Rm, 8 * regs);
}

void Simulator::DecodeAdvancedSIMDLoadSingleStructureToAllLanes(
    Instruction* instr) {
  DCHECK_NE(0, instr->Bit(21));
  int N = instr->Bits(9, 8);

  int Vd = instr->VFPDRegValue(kDoublePrecision);
  int Rn = instr->VnValue();
  int Rm = instr->VmValue();
  int32_t address = get_register(Rn);

  if (!N) {
    // vld1 (single element to all lanes).
    int regs = instr->Bit(5) + 1;
    int size = instr->Bits(7, 6);
    uint32_t q_data[2];
    switch (size) {
      case Neon8: {
        uint8_t data = ReadBU(address);
        uint8_t* dst = reinterpret_cast<uint8_t*>(q_data);
        for (int i = 0; i < 8; i++) {
          dst[i] = data;
        }
        break;
      }
      case Neon16: {
        uint16_t data = ReadHU(address);
        uint16_t* dst = reinterpret_cast<uint16_t*>(q_data);
        for (int i = 0; i < 4; i++) {
          dst[i] = data;
        }
        break;
      }
      case Neon32: {
        uint32_t data = ReadW(address);
        for (int i = 0; i < 2; i++) {
          q_data[i] = data;
        }
        break;
      }
    }
    for (int r = 0; r < regs; r++) {
      set_neon_register<uint32_t, kDoubleSize>(Vd + r, q_data);
    }
    AdvancedSIMDElementOrStructureLoadStoreWriteback(Rn, Rm, 1 << size);
  } else {
    UNIMPLEMENTED();
  }
}

void Simulator::DecodeAdvancedSIMDLoadStoreSingleStructureToOneLane(
    Instruction* instr) {
  int L = instr->Bit(21);
  int size = instr->Bits(11, 10);
  int N = instr->Bits(9, 8);
  int Vd = instr->VFPDRegValue(kDoublePrecision);
  int Rn = instr->VnValue();
  int Rm = instr->VmValue();
  int32_t address = get_register(Rn);

  if (L && N == 0) {
    // vld1 (single element to one lane)
    DCHECK_NE(3, size);
    uint64_t dreg;
    get_d_register(Vd, &dreg);
    switch (size) {
      case Neon8: {
        uint64_t data = ReadBU(address);
        DCHECK_EQ(0, instr->Bit(4));
        int i = instr->Bits(7, 5) * 8;
        dreg = (dreg & ~(uint64_t{0xff} << i)) | (data << i);
        break;
      }
      case Neon16: {
        DCHECK_EQ(0, instr->Bits(5, 4));  // Alignment not supported.
        uint64_t data = ReadHU(address);
        int i = instr->Bits(7, 6) * 16;
        dreg = (dreg & ~(uint64_t{0xffff} << i)) | (data << i);
        break;
      }
      case Neon32: {
        DCHECK_EQ(0, instr->Bits(6, 4));  // Alignment not supported.
        uint64_t data = static_cast<unsigned>(ReadW(address));
        int i = instr->Bit(7) * 32;
        dreg = (dreg & ~(uint64_t{0xffffffff} << i)) | (data << i);
        break;
      }
      case Neon64: {
        // Should have been handled by vld1 (single element to all lanes).
        UNREACHABLE();
      }
    }
    set_d_register(Vd, &dreg);
    AdvancedSIMDElementOrStructureLoadStoreWriteback(Rn, Rm, 1 << size);
  } else if (!L && N == 0) {
    // vst1s (single element from one lane).
    DCHECK_NE(3, size);
    uint64_t dreg;
    get_d_register(Vd, &dreg);
    switch (size) {
      case Neon8: {
        DCHECK_EQ(0, instr->Bit(4));
        int i = instr->Bits(7, 5) * 8;
        dreg = (dreg >> i) & 0xff;
        WriteB(address, static_cast<uint8_t>(dreg));
        break;
      }
      case Neon16: {
        DCHECK_EQ(0, instr->Bits(5, 4));  // Alignment not supported.
        int i = instr->Bits(7, 6) * 16;
        dreg = (dreg >> i) & 0xffff;
        WriteH(address, static_cast<uint16_t>(dreg));
        break;
      }
      case Neon32: {
        DCHECK_EQ(0, instr->Bits(6, 4));  // Alignment not supported.
        int i = instr->Bit(7) * 32;
        dreg = (dreg >> i) & 0xffffffff;
        WriteW(address, base::bit_cast<int>(static_cast<uint32_t>(dreg)));
        break;
      }
      case Neon64: {
        // Should have been handled by vst1 (single element to all lanes).
        UNREACHABLE();
      }
    }
    AdvancedSIMDElementOrStructureLoadStoreWriteback(Rn, Rm, 1 << size);
  } else {
    UNIMPLEMENTED();
  }
}

void Simulator::DecodeFloatingPointDataProcessing(Instruction* instr) {
  switch (instr->SpecialValue()) {
    case 0x1D:
      if (instr->Opc1Value() == 0x7 && instr->Opc3Value() == 0x1 &&
          instr->Bits(11, 9) == 0x5 && instr->Bits(19, 18) == 0x2) {
        if (instr->SzValue() == 0x1) {
          int vm = instr->VFPMRegValue(kDoublePrecision);
          int vd = instr->VFPDRegValue(kDoublePrecision);
          double dm_value = get_double_from_d_register(vm).get_scalar();
          double dd_value = 0.0;
          int rounding_mode = instr->Bits(17, 16);
          switch (rounding_mode) {
            case 0x0:  // vrinta - round with ties to away from zero
              dd_value = round(dm_value);
              break;
            case 0x1: {  // vrintn - round with ties to even
              dd_value = nearbyint(dm_value);
              break;
            }
            case 0x2:  // vrintp - ceil
              dd_value = ceil(dm_value);
              break;
            case 0x3:  // vrintm - floor
              dd_value = floor(dm_value);
              break;
            default:
              UNREACHABLE();  // Case analysis is exhaustive.
          }
          dd_value = canonicalizeNaN(dd_value);
          set_d_register_from_double(vd, dd_value);
        } else {
          int m = instr->VFPMRegValue(kSinglePrecision);
          int d = instr->VFPDRegValue(kSinglePrecision);
          float sm_value = get_float_from_s_register(m).get_scalar();
          float sd_value = 0.0;
          int rounding_mode = instr->Bits(17, 16);
          switch (rounding_mode) {
            case 0x0:  // vrinta - round with ties to away from zero
              sd_value = roundf(sm_value);
              break;
            case 0x1: {  // vrintn - round with ties to even
              sd_value = nearbyintf(sm_value);
              break;
            }
            case 0x2:  // vrintp - ceil
              sd_value = ceilf(sm_value);
              break;
            case 0x3:  // vrintm - floor
              sd_value = floorf(sm_value);
              break;
            default:
              UNREACHABLE();  // Case analysis is exhaustive.
          }
          sd_value = canonicalizeNaN(sd_value);
          set_s_register_from_float(d, sd_value);
        }
      } else if ((instr->Opc1Value() == 0x4) && (instr->Bits(11, 9) == 0x5) &&
                 (instr->Bit(4) == 0x0)) {
        if (instr->SzValue() == 0x1) {
          int m = instr->VFPMRegValue(kDoublePrecision);
          int n = instr->VFPNRegValue(kDoublePrecision);
          int d = instr->VFPDRegValue(kDoublePrecision);
          double dn_value = get_double_from_d_register(n).get_scalar();
          double dm_value = get_double_from_d_register(m).get_scalar();
          double dd_value;
          if (instr->Bit(6) == 0x1) {  // vminnm
            if ((dn_value < dm_value) || std::isnan(dm_value)) {
              dd_value = dn_value;
            } else if ((dm_value < dn_value) || std::isnan(dn_value)) {
              dd_value = dm_value;
            } else {
              DCHECK_EQ(dn_value, dm_value);
              // Make sure that we pick the most negative sign for +/-0.
              dd_value = std::signbit(dn_value) ? dn_value : dm_value;
            }
          } else {  // vmaxnm
            if ((dn_value > dm_value) || std::isnan(dm_value)) {
              dd_value = dn_value;
            } else if ((dm_value > dn_value) || std::isnan(dn_value)) {
              dd_value = dm_value;
            } else {
              DCHECK_EQ(dn_value, dm_value);
              // Make sure that we pick the most positive sign for +/-0.
              dd_value = std::signbit(dn_value) ? dm_value : dn_value;
            }
          }
          dd_value = canonicalizeNaN(dd_value);
          set_d_register_from_double(d, dd_value);
        } else {
          int m = instr->VFPMRegValue(kSinglePrecision);
          int n = instr->VFPNRegValue(kSinglePrecision);
          int d = instr->VFPDRegValue(kSinglePrecision);
          float sn_value = get_float_from_s_register(n).get_scalar();
          float sm_value = get_float_from_s_register(m).get_scalar();
          float sd_value;
          if (instr->Bit(6) == 0x1) {  // vminnm
            if ((sn_value < sm_value) || std::isnan(sm_value)) {
              sd_value = sn_value;
            } else if ((sm_value < sn_value) || std::isnan(sn_value)) {
              sd_value = sm_value;
            } else {
              DCHECK_EQ(sn_value, sm_value);
              // Make sure that we pick the most negative sign for +/-0.
              sd_value = std::signbit(sn_value) ? sn_value : sm_value;
            }
          } else {  // vmaxnm
            if ((sn_value > sm_value) || std::isnan(sm_value)) {
              sd_value = sn_value;
            } else if ((sm_value > sn_value) || std::isnan(sn_value)) {
              sd_value = sm_value;
            } else {
              DCHECK_EQ(sn_value, sm_value);
              // Make sure that we pick the most positive sign for +/-0.
              sd_value = std::signbit(sn_value) ? sm_value : sn_value;
            }
          }
          sd_value = canonicalizeNaN(sd_value);
          set_s_register_from_float(d, sd_value);
        }
      } else {
        UNIMPLEMENTED();
      }
      break;
    case 0x1C:
      if ((instr->Bits(11, 9) == 0x5) && (instr->Bit(6) == 0) &&
          (instr->Bit(4) == 0)) {
        // VSEL* (floating-point)
        bool condition_holds;
        switch (instr->Bits(21, 20)) {
          case 0x0:  // VSELEQ
            condition_holds = (z_flag_ == 1);
            break;
          case 0x1:  // VSELVS
            condition_holds = (v_flag_ == 1);
            break;
          case 0x2:  // VSELGE
            condition_holds = (n_flag_ == v_flag_);
            break;
          case 0x3:  // VSELGT
            condition_holds = ((z_flag_ == 0) && (n_flag_ == v_flag_));
            break;
          default:
            UNREACHABLE();  // Case analysis is exhaustive.
        }
        if (instr->SzValue() == 0x1) {
          int n = instr->VFPNRegValue(kDoublePrecision);
          int m = instr->VFPMRegValue(kDoublePrecision);
          int d = instr->VFPDRegValue(kDoublePrecision);
          Float64 result = get_double_from_d_register(condition_holds ? n : m);
          set_d_register_from_double(d, result);
        } else {
          int n = instr->VFPNRegValue(kSinglePrecision);
          int m = instr->VFPMRegValue(kSinglePrecision);
          int d = instr->VFPDRegValue(kSinglePrecision);
          Float32 result = get_float_from_s_register(condition_holds ? n : m);
          set_s_register_from_float(d, result);
        }
      } else {
        UNIMPLEMENTED();
      }
      break;
    default:
      UNIMPLEMENTED();
  }
}

void Simulator::DecodeSpecialCondition(Instruction* instr) {
  int op0 = instr->Bits(25, 24);
  int op1 = instr->Bits(11, 9);
  int op2 = instr->Bit(4);

  if (instr->Bit(27) == 0) {
    DecodeUnconditional(instr);
  } else if ((instr->Bits(27, 26) == 0b11) && (op0 == 0b10) &&
             ((op1 >> 1) == 0b10) && !op2) {
    DecodeFloatingPointDataProcessing(instr);
  } else {
    UNIMPLEMENTED();
  }
}

// Executes the current instruction.
void Simulator::InstructionDecode(Instruction* instr) {
  if (v8_flags.check_icache) {
    CheckICache(i_cache(), instr);
  }
  pc_modified_ = false;
  if (InstructionTracingEnabled()) {
    disasm::NameConverter converter;
    disasm::Disassembler dasm(converter);
    // use a reasonably large buffer
    v8::base::EmbeddedVector<char, 256> buffer;
    dasm.InstructionDecode(buffer, reinterpret_cast<uint8_t*>(instr));
    PrintF("  0x%08" V8PRIxPTR "  %s\n", reinterpret_cast<intptr_t>(instr),
           buffer.begin());
  }
  if (instr->ConditionField() == kSpecialCondition) {
    DecodeSpecialCondition(instr);
  } else if (ConditionallyExecute(instr)) {
    switch (instr->TypeValue()) {
      case 0:
      case 1: {
        DecodeType01(instr);
        break;
      }
      case 2: {
        DecodeType2(instr);
        break;
      }
      case 3: {
        DecodeType3(instr);
        break;
      }
      case 4: {
        DecodeType4(instr);
        break;
      }
      case 5: {
        DecodeType5(instr);
        break;
      }
      case 6: {
        DecodeType6(instr);
        break;
      }
      case 7: {
        DecodeType7(instr);
        break;
      }
      default: {
        UNIMPLEMENTED();
      }
    }
  }
  if (!pc_modified_) {
    set_register(pc, reinterpret_cast<int32_t>(instr) + kInstrSize);
  }
}

void Simulator::Execute() {
  // Get the PC to simulate. Cannot use the accessor here as we need the
  // raw PC value and not the one used as input to arithmetic instructions.
  int program_counter = get_pc();

  if (v8_flags.stop_sim_at == 0) {
    // Fast version of the dispatch loop without checking whether the simulator
    // should be stopping at a particular executed instruction.
    while (program_counter != end_sim_pc) {
      Instruction* instr = reinterpret_cast<Instruction*>(program_counter);
      icount_ = base::AddWithWraparound(icount_, 1);
      InstructionDecode(instr);
      program_counter = get_pc();
    }
  } else {
    // v8_flags.stop_sim_at is at the non-default value. Stop in the debugger
    // when we reach the particular instruction count.
    while (program_counter != end_sim_pc) {
      Instruction* instr = reinterpret_cast<Instruction*>(program_counter);
      icount_ = base::AddWithWraparound(icount_, 1);
      if (icount_ == v8_flags.stop_sim_at) {
        ArmDebugger dbg(this);
        dbg.Debug();
      } else {
        InstructionDecode(instr);
      }
      program_counter = get_pc();
    }
  }
}

void Simulator::CallInternal(Address entry) {
  // Adjust JS-based stack limit to C-based stack limit.
  isolate_->stack_guard()->AdjustStackLimitForSimulator();

  // Prepare to execute the code at entry
  set_register(pc, static_cast<int32_t>(entry));
  // Put down marker for end of simulation. The simulator will stop simulation
  // when the PC reaches this value. By saving the "end simulation" value into
  // the LR the simulation stops when returning to this call point.
  set_register(lr, end_sim_pc);

  // Remember the values of callee-saved registers.
  // The code below assumes that r9 is not used as sb (static base) in
  // simulator code and therefore is regarded as a callee-saved register.
  int32_t r4_val = get_register(r4);
  int32_t r5_val = get_register(r5);
  int32_t r6_val = get_register(r6);
  int32_t r7_val = get_register(r7);
  int32_t r8_val = get_register(r8);
  int32_t r9_val = get_register(r9);
  int32_t r10_val = get_register(r10);
  int32_t r11_val = get_register(r11);

  // Set up the callee-saved registers with a known value. To be able to check
  // that they are preserved properly across JS execution.
  int32_t callee_saved_value = icount_;
  set_register(r4, callee_saved_value);
  set_register(r5, callee_saved_value);
  set_register(r6, callee_saved_value);
  set_register(r7, callee_saved_value);
  set_register(r8, callee_saved_value);
  set_register(r9, callee_saved_value);
  set_register(r10, callee_saved_value);
  set_register(r11, callee_saved_value);

  // Start the simulation
  Execute();

  // Check that the callee-saved registers have been preserved.
  CHECK_EQ(callee_saved_value, get_register(r4));
  CHECK_EQ(callee_saved_value, get_register(r5));
  CHECK_EQ(callee_saved_value, get_register(r6));
  CHECK_EQ(callee_saved_value, get_register(r7));
  CHECK_EQ(callee_saved_value, get_register(r8));
  CHECK_EQ(callee_saved_value, get_register(r9));
  CHECK_EQ(callee_saved_value, get_register(r10));
  CHECK_EQ(callee_saved_value, get_register(r11));

  // Restore callee-saved registers with the original value.
  set_register(r4, r4_val);
  set_register(r5, r5_val);
  set_register(r6, r6_val);
  set_register(r7, r7_val);
  set_register(r8, r8_val);
  set_register(r9, r9_val);
  set_register(r10, r10_val);
  set_register(r11, r11_val);
}

intptr_t Simulator::CallImpl(Address entry, int argument_count,
                             const intptr_t* arguments) {
  // Set up arguments

  // First four arguments passed in registers.
  int reg_arg_count = std::min(4, argument_count);
  if (reg_arg_count > 0) set_register(r0, arguments[0]);
  if (reg_arg_count > 1) set_register(r1, arguments[1]);
  if (reg_arg_count > 2) set_register(r2, arguments[2]);
  if (reg_arg_count > 3) set_register(r3, arguments[3]);

  // Remaining arguments passed on stack.
  int original_stack = get_register(sp);
  // Compute position of stack on entry to generated code.
  int entry_stack = (original_stack - (argument_count - 4) * sizeof(int32_t));
  if (base::OS::ActivationFrameAlignment() != 0) {
    entry_stack &= -base::OS::ActivationFrameAlignment();
  }
  // Store remaining arguments on stack, from low to high memory.
  memcpy(reinterpret_cast<intptr_t*>(entry_stack), arguments + reg_arg_count,
         (argument_count - reg_arg_count) * sizeof(*arguments));
  set_register(sp, entry_stack);

  CallInternal(entry);

  // Pop stack passed arguments.
  CHECK_EQ(entry_stack, get_register(sp));
  set_register(sp, original_stack);

  return get_register(r0);
}

intptr_t Simulator::CallFPImpl(Address entry, double d0, double d1) {
  if (use_eabi_hardfloat()) {
    set_d_register_from_double(0, d0);
    set_d_register_from_double(1, d1);
  } else {
    set_register_pair_from_double(0, &d0);
    set_register_pair_from_double(2, &d1);
  }
  CallInternal(entry);
  return get_register(r0);
}

uintptr_t Simulator::PushAddress(uintptr_t address) {
  int new_sp = get_register(sp) - sizeof(uintptr_t);
  uintptr_t* stack_slot = reinterpret_cast<uintptr_t*>(new_sp);
  *stack_slot = address;
  set_register(sp, new_sp);
  return new_sp;
}

uintptr_t Simulator::PopAddress() {
  int current_sp = get_register(sp);
  uintptr_t* stack_slot = reinterpret_cast<uintptr_t*>(current_sp);
  uintptr_t address = *stack_slot;
  set_register(sp, current_sp + sizeof(uintptr_t));
  return address;
}

Simulator::LocalMonitor::LocalMonitor()
    : access_state_(MonitorAccess::Open),
      tagged_addr_(0),
      size_(TransactionSize::None) {}

void Simulator::LocalMonitor::Clear() {
  access_state_ = MonitorAccess::Open;
  tagged_addr_ = 0;
  size_ = TransactionSize::None;
}

void Simulator::LocalMonitor::NotifyLoad(int32_t addr) {
  if (access_state_ == MonitorAccess::Exclusive) {
    // A load could cause a cache eviction which will affect the monitor. As a
    // result, it's most strict to unconditionally clear the local monitor on
    // load.
    Clear();
  }
}

void Simulator::LocalMonitor::NotifyLoadExcl(int32_t addr,
                                             TransactionSize size) {
  access_state_ = MonitorAccess::Exclusive;
  tagged_addr_ = addr;
  size_ = size;
}

void Simulator::LocalMonitor::NotifyStore(int32_t addr) {
  if (access_state_ == MonitorAccess::Exclusive) {
    // It is implementation-defined whether a non-exclusive store to an address
    // covered by the local monitor during exclusive access transitions to open
    // or exclusive access. See ARM DDI 0406C.b, A3.4.1.
    //
    // However, a store could cause a cache eviction which will affect the
    // monitor. As a result, it's most strict to unconditionally clear the
    // local monitor on store.
    Clear();
  }
}

bool Simulator::LocalMonitor::NotifyStoreExcl(int32_t addr,
                                              TransactionSize size) {
  if (access_state_ == MonitorAccess::Exclusive) {
    // It is allowed for a processor to require that the address matches
    // exactly (A3.4.5), so this comparison does not mask addr.
    if (addr == tagged_addr_ && size_ == size) {
      Clear();
      return true;
    } else {
      // It is implementation-defined whether an exclusive store to a
      // non-tagged address will update memory. Behavior is unpredictable if
      // the transaction size of the exclusive store differs from that of the
      // exclusive load. See ARM DDI 0406C.b, A3.4.5.
      Clear();
      return false;
    }
  } else {
    DCHECK(access_state_ == MonitorAccess::Open);
    return false;
  }
}

Simulator::GlobalMonitor::Processor::Processor()
    : access_state_(MonitorAccess::Open),
      tagged_addr_(0),
      next_(nullptr),
      prev_(nullptr),
      failure_counter_(0) {}

void Simulator::GlobalMonitor::Processor::Clear_Locked() {
  access_state_ = MonitorAccess::Open;
  tagged_addr_ = 0;
}

void Simulator::GlobalMonitor::Processor::NotifyLoadExcl_Locked(int32_t addr) {
  access_state_ = MonitorAccess::Exclusive;
  tagged_addr_ = addr;
}

void Simulator::GlobalMonitor::Processor::NotifyStore_Locked(
    int32_t addr, bool is_requesting_processor) {
  if (access_state_ == MonitorAccess::Exclusive) {
    // It is implementation-defined whether a non-exclusive store by the
    // requesting processor to an address covered by the global monitor
    // during exclusive access transitions to open or exclusive access.
    //
    // For any other processor, the access state always transitions to open
    // access.
    //
    // See ARM DDI 0406C.b, A3.4.2.
    //
    // However, similar to the local monitor, it is possible that a store
    // caused a cache eviction, which can affect the montior, so
    // conservatively, we always clear the monitor.
    Clear_Locked();
  }
}

bool Simulator::GlobalMonitor::Processor::NotifyStoreExcl_Locked(
    int32_t addr, bool is_requesting_processor) {
  if (access_state_ == MonitorAccess::Exclusive) {
    if (is_requesting_processor) {
      // It is allowed for a processor to require that the address matches
      // exactly (A3.4.5), so this comparison does not mask addr.
      if (addr == tagged_addr_) {
        // The access state for the requesting processor after a successful
        // exclusive store is implementation-defined, but according to the ARM
        // DDI, this has no effect on the subsequent operation of the global
        // monitor.
        Clear_Locked();
        // Introduce occasional strex failures. This is to simulate the
        // behavior of hardware, which can randomly fail due to background
        // cache evictions.
        if (failure_counter_++ >= kMaxFailureCounter) {
          failure_counter_ = 0;
          return false;
        } else {
          return true;
        }
      }
    } else if ((addr & kExclusiveTaggedAddrMask) ==
               (tagged_addr_ & kExclusiveTaggedAddrMask)) {
      // Check the masked addresses when responding to a successful lock by
      // another processor so the implementation is more conservative (i.e. the
      // granularity of locking is as large as possible.)
      Clear_Locked();
      return false;
    }
  }
  return false;
}

void Simulator::GlobalMonitor::NotifyLoadExcl_Locked(int32_t addr,
                                                     Processor* processor) {
  processor->NotifyLoadExcl_Locked(addr);
  PrependProcessor_Locked(processor);
}

void Simulator::GlobalMonitor::NotifyStore_Locked(int32_t addr,
                                                  Processor* processor) {
  // Notify each processor of the store operation.
  for (Processor* iter = head_; iter; iter = iter->next_) {
    bool is_requesting_processor = iter == processor;
    iter->NotifyStore_Locked(addr, is_requesting_processor);
  }
}

bool Simulator::GlobalMonitor::NotifyStoreExcl_Locked(int32_t addr,
                                                      Processor* processor) {
  DCHECK(IsProcessorInLinkedList_Locked(processor));
  if (processor->NotifyStoreExcl_Locked(addr, true)) {
    // Notify the other processors that this StoreExcl succeeded.
    for (Processor* iter = head_; iter; iter = iter->next_) {
      if (iter != processor) {
        iter->NotifyStoreExcl_Locked(addr, false);
      }
    }
    return true;
  } else {
    return false;
  }
}

bool Simulator::GlobalMonitor::IsProcessorInLinkedList_Locked(
    Processor* processor) const {
  return head_ == processor || processor->next_ || processor->prev_;
}

void Simulator::GlobalMonitor::PrependProcessor_Locked(Processor* processor) {
  if (IsProcessorInLinkedList_Locked(processor)) {
    return;
  }

  if (head_) {
    head_->prev_ = processor;
  }
  processor->prev_ = nullptr;
  processor->next_ = head_;
  head_ = processor;
}

void Simulator::GlobalMonitor::RemoveProcessor(Processor* processor) {
  base::MutexGuard lock_guard(&mutex);
  if (!IsProcessorInLinkedList_Locked(processor)) {
    return;
  }

  if (processor->prev_) {
    processor->prev_->next_ = processor->next_;
  } else {
    head_ = processor->next_;
  }
  if (processor->next_) {
    processor->next_->prev_ = processor->prev_;
  }
  processor->prev_ = nullptr;
  processor->next_ = nullptr;
}

#undef SScanF

}  // namespace internal
}  // namespace v8

//
// The following functions are used by our gdb macros.
//
V8_DONT_STRIP_SYMBOL
V8_EXPORT_PRIVATE extern bool _v8_internal_Simulator_ExecDebugCommand(
    const char* command) {
  i::Isolate* isolate = i::Isolate::Current();
  if (!isolate) {
    fprintf(stderr, "No V8 Isolate found\n");
    return false;
  }
  i::Simulator* simulator = i::Simulator::current(isolate);
  if (!simulator) {
    fprintf(stderr, "No Arm simulator found\n");
    return false;
  }
  // Copy the command so that the simulator can take ownership of it.
  size_t len = strlen(command);
  i::ArrayUniquePtr<char> command_copy(i::NewArray<char>(len + 1));
  i::MemCopy(command_copy.get(), command, len + 1);
  return i::ArmDebugger(simulator).ExecDebugCommand(std::move(command_copy));
}

#endif  // USE_SIMULATOR
```