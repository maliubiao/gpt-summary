Response: The user wants a summary of the provided C++ code. This is the second part of a three-part file. The code seems to define an assembler for the MIPS64 architecture.

Here's a breakdown of the code's functionality:

1. **Shift and Rotate Instructions:** Defines functions for various shift and rotate operations (logical left/right, arithmetic right, rotate left/right) on registers, with immediate values or other registers as operands. Includes double-word versions of these instructions.
2. **Memory Access Instructions:** Provides functions for loading and storing bytes, half-words, words, and double-words from memory. Includes instructions for aligned and unaligned access, as well as load-linked and store-conditional instructions for atomic operations.
3. **Immediate Instructions:** Defines functions for instructions that operate with immediate values, such as `lui` (load upper immediate), `aui` (add upper immediate), `daddiu` (add immediate unsigned), etc.
4. **PC-Relative Instructions:** Introduces instructions that calculate addresses relative to the program counter. This is common for accessing data or code near the current instruction.
5. **Miscellaneous Instructions:** Covers a range of other operations like breakpoints (`break_`, `stop`), traps (`tge`, `tlt`, `teq`, `tne`), synchronization (`sync`), moving data between HI/LO registers (`mfhi`, `mflo`), set-on-less-than instructions (`slt`, `sltu`, `slti`, `sltiu`), conditional moves (`movz`, `movn`, `movt`, `movf`).
6. **Floating-Point Instructions (Part 1):** Implements instructions for comparing floating-point numbers (`min_s`, `min_d`, `max_s`, `max_d`, `mina_s`, `mina_d`, `maxa_s`, `maxa_d`).
7. **Conditional Selection (Part 1):**  Includes instructions for selecting values based on a condition (`seleqz`, `selnez`).
8. **Bit Manipulation Instructions:** Defines functions for counting leading zeros (`clz`, `dclz`), and inserting/extracting bit fields (`ins_`, `dins_`, `dinsm_`, `dinsu_`, `ext_`, `dext_`, `dextm_`, `dextu_`).
9. **More Bit Manipulation:** Includes instructions for bit swapping (`bitswap`, `dbitswap`), cache hints (`pref`), and byte/half-word alignment and swapping (`align`, `dalign`, `wsbh`, `dsbh`, `dshd`, `seh`, `seb`).

Regarding the connection to JavaScript, these instructions are the building blocks of the JavaScript virtual machine (V8) when running on a MIPS64 architecture. V8 compiles JavaScript code into machine code, and this file provides the means to generate that machine code.

**Example in JavaScript (Conceptual):**

Let's say you have the following JavaScript code:

```javascript
function add(a, b) {
  return a + b;
}
```

When V8 compiles this function for MIPS64, it might generate assembly code that uses some of the instructions defined in this file. For instance:

* **`ld` (load doubleword):** To load the values of `a` and `b` from memory into registers.
* **`daddu` (doubleword add unsigned):** To perform the addition of the two loaded values in registers.
* **`sd` (store doubleword):** To store the result back into memory or a register used for the return value.
* **Shift/Rotate Instructions:**  If the JavaScript code involves bitwise operations, instructions like `dsll` (doubleword shift left logical) or `dsrl` (doubleword shift right logical) would be used.
* **Floating-Point Instructions:** If the JavaScript code uses floating-point numbers, instructions like `add_d` (add double-precision float) or `mul_s` (multiply single-precision float) would be employed.

The `Assembler` class defined in this file provides the interface to generate these low-level MIPS64 instructions, enabling V8 to execute JavaScript code efficiently on this architecture.
This C++ code snippet is part of the `Assembler` class for the MIPS64 architecture within the V8 JavaScript engine. It defines a collection of functions that correspond directly to MIPS64 assembly instructions.

Here's a breakdown of the functionality provided in this section:

**1. Shift and Rotate Instructions:**

* It provides functions to generate instructions for various shift and rotate operations on registers:
    * **Logical Shifts:** `sll`, `sllv`, `srl`, `srlv` (left and right logical shifts, immediate and register variants).
    * **Arithmetic Shifts:** `sra`, `srav` (right arithmetic shifts, immediate and register variants).
    * **Rotates:** `rotr`, `rotrv` (right rotates, immediate and register variants), with checks for MIPS64r2/r6 architecture.
    * **Doubleword Shifts and Rotates:** `dsll`, `dsllv`, `dsrl`, `dsrlv`, `drotr`, `drotr32`, `drotrv`, `dsra`, `dsrav`, `dsll32`, `dsrl32`, `dsra32` (similar operations but on 64-bit values).
    * **Logical Shift Add:** `lsa`, `dlsa` (MIPS64r6 specific).

**2. Memory Access Instructions:**

* It defines functions for generating instructions to load and store data from memory:
    * **Byte Access:** `lb` (load byte), `lbu` (load byte unsigned), `sb` (store byte).
    * **Half-word Access:** `lh` (load half-word), `lhu` (load half-word unsigned), `sh` (store half-word).
    * **Word Access:** `lw` (load word), `lwu` (load word unsigned), `sw` (store word).
    * **Partial Word Access (MIPS64r2):** `lwl` (load word left), `lwr` (load word right), `swl` (store word left), `swr` (store word right).
    * **Load-Linked and Store-Conditional (Atomic Operations):** `ll` (load-linked word), `lld` (load-linked doubleword), `sc` (store-conditional word), `scd` (store-conditional doubleword).
    * **Doubleword Access:** `ldl` (load doubleword left), `ldr` (load doubleword right), `sdl` (store doubleword left), `sdr` (store doubleword right), `ld` (load doubleword), `sd` (store doubleword).
* It includes a helper function `AdjustBaseAndOffset` to handle memory operands where the offset doesn't fit into a 16-bit immediate. This involves potentially loading parts of the offset into a temporary register and adjusting the base register.

**3. Immediate Instructions:**

* It provides functions for instructions that use immediate (constant) values:
    * **Load Upper Immediate:** `lui` (loads a 16-bit immediate into the upper half of a register).
    * **Add Upper Immediate:** `aui` (adds a 16-bit immediate to the upper half of a register).
    * **Double Add Upper Immediate:** `daui` (adds a 16-bit immediate to the upper half of a 64-bit register).
    * **Double Add High Immediate:** `dahi` (adds a shifted 16-bit immediate to a register).
    * **Double Add Top Immediate:** `dati` (adds a shifted 16-bit immediate to a register).

**4. PC-Relative Instructions (MIPS64r6):**

* It defines functions for instructions that calculate memory addresses relative to the Program Counter (PC):
    * `addiupc` (add immediate unsigned to PC), `lwpc` (load word from PC-relative address), `lwupc`, `ldpc`, `auipc` (add upper immediate to PC), `aluipc`.

**5. Miscellaneous Instructions:**

* **Breakpoints and Traps:** `break_`, `stop` (for debugging and halting execution), `tge`, `tgeu`, `tlt`, `tltu`, `teq`, `tne` (trap if conditions are met).
* **Synchronization:** `sync` (ensures memory operations are completed in order).
* **Move from HI/LO Registers:** `mfhi`, `mflo` (moves the contents of special registers HI and LO to a general-purpose register).
* **Set on Less Than:** `slt`, `sltu`, `slti`, `sltiu` (sets a register to 1 if a comparison is true, 0 otherwise).
* **Conditional Move:** `movz`, `movn`, `movt`, `movf` (moves data based on whether a register is zero/non-zero or a floating-point condition is true/false).

**6. Floating-Point Instructions (Initial Set):**

* It starts defining functions for basic floating-point operations:
    * **Min/Max:** `min_s`, `min_d`, `max_s`, `max_d`, `mina_s`, `mina_d`, `maxa_s`, `maxa_d` (minimum and maximum of single and double-precision floats, including absolute versions).

**7. Conditional Selection (Initial Set):**

* `seleqz`, `selnez` (selects one of two registers based on whether a third register is zero or not).

**8. Bit Twiddling Instructions:**

* `clz`, `dclz` (count leading zeros in a word or doubleword).
* `ins_`, `dins_`, `dinsm_`, `dinsu_` (insert bit fields into a register).
* `ext_`, `dext_`, `dextm_`, `dextu_` (extract bit fields from a register).

**9. More Bit Manipulation:**

* `bitswap`, `dbitswap` (swaps the byte order of a word or doubleword).
* `pref` (prefetch data into the cache).
* `align`, `dalign` (aligns data within a register).
* `wsbh`, `dsbh`, `dshd`, `seh`, `seb` (byte and half-word swap and sign extension).

**Relationship to JavaScript:**

This code is crucial for the V8 JavaScript engine. When V8 compiles JavaScript code, it translates it into native machine code for the target architecture. This `assembler-mips64.cc` file provides the interface to generate the actual MIPS64 instructions that will be executed by the processor.

**JavaScript Examples (Conceptual):**

* **Shift Operators (>>, <<, >>>):** JavaScript's bitwise shift operators would translate into MIPS64 shift instructions like `dsll`, `dsrl`, `dsra`.
  ```javascript
  let x = 10 << 2; // Left shift
  let y = 20 >> 1; // Right shift
  ```
* **Bitwise Operators (&, |, ^, ~):** While not directly present in this snippet, other parts of the assembler would handle these, potentially using the `andi`, `ori`, `xori`, `nori` instructions (defined later in the file).
* **Memory Access (e.g., Array access):** When accessing elements in JavaScript arrays, V8 would use load and store instructions like `ld` and `sd` to read and write data from memory.
  ```javascript
  let arr = [1, 2, 3];
  let first = arr[0]; // Load operation
  arr[1] = 5;         // Store operation
  ```
* **Arithmetic Operations (+, -, * , /):**  Simple addition would use `daddu`, subtraction `dsubu`, multiplication `dmul`, and division would involve floating-point instructions if necessary.
  ```javascript
  let sum = a + b;
  let difference = c - d;
  ```
* **Floating-point operations (Math.sin, Math.cos, etc.):** JavaScript's `Math` object functions that operate on floating-point numbers would directly correspond to the floating-point instructions defined in this and subsequent parts of the file.

In essence, this file is a fundamental part of V8's code generation pipeline for MIPS64. It provides the low-level building blocks that allow the engine to execute JavaScript code efficiently on that architecture. The functions in this file act as a high-level interface to the raw MIPS64 assembly instructions.

### 提示词
```
这是目录为v8/src/codegen/mips64/assembler-mips64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```
ister(SPECIAL, zero_reg, rt, rd, sa & 0x1F, SRA);
}

void Assembler::srav(Register rd, Register rt, Register rs) {
  GenInstrRegister(SPECIAL, rs, rt, rd, 0, SRAV);
}

void Assembler::rotr(Register rd, Register rt, uint16_t sa) {
  // Should be called via MacroAssembler::Ror.
  DCHECK(rd.is_valid() && rt.is_valid() && is_uint5(sa));
  DCHECK(kArchVariant == kMips64r2 || kArchVariant == kMips64r6);
  Instr instr = SPECIAL | (1 << kRsShift) | (rt.code() << kRtShift) |
                (rd.code() << kRdShift) | (sa << kSaShift) | SRL;
  emit(instr);
}

void Assembler::rotrv(Register rd, Register rt, Register rs) {
  // Should be called via MacroAssembler::Ror.
  DCHECK(rd.is_valid() && rt.is_valid() && rs.is_valid());
  DCHECK(kArchVariant == kMips64r2 || kArchVariant == kMips64r6);
  Instr instr = SPECIAL | (rs.code() << kRsShift) | (rt.code() << kRtShift) |
                (rd.code() << kRdShift) | (1 << kSaShift) | SRLV;
  emit(instr);
}

void Assembler::dsll(Register rd, Register rt, uint16_t sa) {
  GenInstrRegister(SPECIAL, zero_reg, rt, rd, sa & 0x1F, DSLL);
}

void Assembler::dsllv(Register rd, Register rt, Register rs) {
  GenInstrRegister(SPECIAL, rs, rt, rd, 0, DSLLV);
}

void Assembler::dsrl(Register rd, Register rt, uint16_t sa) {
  GenInstrRegister(SPECIAL, zero_reg, rt, rd, sa & 0x1F, DSRL);
}

void Assembler::dsrlv(Register rd, Register rt, Register rs) {
  GenInstrRegister(SPECIAL, rs, rt, rd, 0, DSRLV);
}

void Assembler::drotr(Register rd, Register rt, uint16_t sa) {
  DCHECK(rd.is_valid() && rt.is_valid() && is_uint5(sa));
  Instr instr = SPECIAL | (1 << kRsShift) | (rt.code() << kRtShift) |
                (rd.code() << kRdShift) | (sa << kSaShift) | DSRL;
  emit(instr);
}

void Assembler::drotr32(Register rd, Register rt, uint16_t sa) {
  DCHECK(rd.is_valid() && rt.is_valid() && is_uint5(sa));
  Instr instr = SPECIAL | (1 << kRsShift) | (rt.code() << kRtShift) |
                (rd.code() << kRdShift) | (sa << kSaShift) | DSRL32;
  emit(instr);
}

void Assembler::drotrv(Register rd, Register rt, Register rs) {
  DCHECK(rd.is_valid() && rt.is_valid() && rs.is_valid());
  Instr instr = SPECIAL | (rs.code() << kRsShift) | (rt.code() << kRtShift) |
                (rd.code() << kRdShift) | (1 << kSaShift) | DSRLV;
  emit(instr);
}

void Assembler::dsra(Register rd, Register rt, uint16_t sa) {
  GenInstrRegister(SPECIAL, zero_reg, rt, rd, sa & 0x1F, DSRA);
}

void Assembler::dsrav(Register rd, Register rt, Register rs) {
  GenInstrRegister(SPECIAL, rs, rt, rd, 0, DSRAV);
}

void Assembler::dsll32(Register rd, Register rt, uint16_t sa) {
  GenInstrRegister(SPECIAL, zero_reg, rt, rd, sa & 0x1F, DSLL32);
}

void Assembler::dsrl32(Register rd, Register rt, uint16_t sa) {
  GenInstrRegister(SPECIAL, zero_reg, rt, rd, sa & 0x1F, DSRL32);
}

void Assembler::dsra32(Register rd, Register rt, uint16_t sa) {
  GenInstrRegister(SPECIAL, zero_reg, rt, rd, sa & 0x1F, DSRA32);
}

void Assembler::lsa(Register rd, Register rt, Register rs, uint8_t sa) {
  DCHECK(rd.is_valid() && rt.is_valid() && rs.is_valid());
  DCHECK_LE(sa, 3);
  DCHECK_EQ(kArchVariant, kMips64r6);
  Instr instr = SPECIAL | rs.code() << kRsShift | rt.code() << kRtShift |
                rd.code() << kRdShift | sa << kSaShift | LSA;
  emit(instr);
}

void Assembler::dlsa(Register rd, Register rt, Register rs, uint8_t sa) {
  DCHECK(rd.is_valid() && rt.is_valid() && rs.is_valid());
  DCHECK_LE(sa, 3);
  DCHECK_EQ(kArchVariant, kMips64r6);
  Instr instr = SPECIAL | rs.code() << kRsShift | rt.code() << kRtShift |
                rd.code() << kRdShift | sa << kSaShift | DLSA;
  emit(instr);
}

// ------------Memory-instructions-------------

void Assembler::AdjustBaseAndOffset(MemOperand* src,
                                    OffsetAccessType access_type,
                                    int second_access_add_to_offset) {
  // This method is used to adjust the base register and offset pair
  // for a load/store when the offset doesn't fit into int16_t.
  // It is assumed that 'base + offset' is sufficiently aligned for memory
  // operands that are machine word in size or smaller. For doubleword-sized
  // operands it's assumed that 'base' is a multiple of 8, while 'offset'
  // may be a multiple of 4 (e.g. 4-byte-aligned long and double arguments
  // and spilled variables on the stack accessed relative to the stack
  // pointer register).
  // We preserve the "alignment" of 'offset' by adjusting it by a multiple of 8.

  bool doubleword_aligned = (src->offset() & (kDoubleSize - 1)) == 0;
  bool two_accesses = static_cast<bool>(access_type) || !doubleword_aligned;
  DCHECK_LE(second_access_add_to_offset, 7);  // Must be <= 7.

  // is_int16 must be passed a signed value, hence the static cast below.
  if (is_int16(src->offset()) &&
      (!two_accesses || is_int16(static_cast<int32_t>(
                            src->offset() + second_access_add_to_offset)))) {
    // Nothing to do: 'offset' (and, if needed, 'offset + 4', or other specified
    // value) fits into int16_t.
    return;
  }

  DCHECK(src->rm() !=
         at);  // Must not overwrite the register 'base' while loading 'offset'.

#ifdef DEBUG
  // Remember the "(mis)alignment" of 'offset', it will be checked at the end.
  uint32_t misalignment = src->offset() & (kDoubleSize - 1);
#endif

  // Do not load the whole 32-bit 'offset' if it can be represented as
  // a sum of two 16-bit signed offsets. This can save an instruction or two.
  // To simplify matters, only do this for a symmetric range of offsets from
  // about -64KB to about +64KB, allowing further addition of 4 when accessing
  // 64-bit variables with two 32-bit accesses.
  constexpr int32_t kMinOffsetForSimpleAdjustment =
      0x7FF8;  // Max int16_t that's a multiple of 8.
  constexpr int32_t kMaxOffsetForSimpleAdjustment =
      2 * kMinOffsetForSimpleAdjustment;

  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  if (0 <= src->offset() && src->offset() <= kMaxOffsetForSimpleAdjustment) {
    daddiu(scratch, src->rm(), kMinOffsetForSimpleAdjustment);
    src->offset_ -= kMinOffsetForSimpleAdjustment;
  } else if (-kMaxOffsetForSimpleAdjustment <= src->offset() &&
             src->offset() < 0) {
    daddiu(scratch, src->rm(), -kMinOffsetForSimpleAdjustment);
    src->offset_ += kMinOffsetForSimpleAdjustment;
  } else if (kArchVariant == kMips64r6) {
    // On r6 take advantage of the daui instruction, e.g.:
    //    daui   at, base, offset_high
    //   [dahi   at, 1]                       // When `offset` is close to +2GB.
    //    lw     reg_lo, offset_low(at)
    //   [lw     reg_hi, (offset_low+4)(at)]  // If misaligned 64-bit load.
    // or when offset_low+4 overflows int16_t:
    //    daui   at, base, offset_high
    //    daddiu at, at, 8
    //    lw     reg_lo, (offset_low-8)(at)
    //    lw     reg_hi, (offset_low-4)(at)
    int16_t offset_low = static_cast<uint16_t>(src->offset());
    int32_t offset_low32 = offset_low;
    int16_t offset_high = static_cast<uint16_t>(src->offset() >> 16);
    bool increment_hi16 = offset_low < 0;
    bool overflow_hi16 = false;

    if (increment_hi16) {
      offset_high++;
      overflow_hi16 = (offset_high == -32768);
    }
    daui(scratch, src->rm(), static_cast<uint16_t>(offset_high));

    if (overflow_hi16) {
      dahi(scratch, 1);
    }

    if (two_accesses && !is_int16(static_cast<int32_t>(
                            offset_low32 + second_access_add_to_offset))) {
      // Avoid overflow in the 16-bit offset of the load/store instruction when
      // adding 4.
      daddiu(scratch, scratch, kDoubleSize);
      offset_low32 -= kDoubleSize;
    }

    src->offset_ = offset_low32;
  } else {
    // Do not load the whole 32-bit 'offset' if it can be represented as
    // a sum of three 16-bit signed offsets. This can save an instruction.
    // To simplify matters, only do this for a symmetric range of offsets from
    // about -96KB to about +96KB, allowing further addition of 4 when accessing
    // 64-bit variables with two 32-bit accesses.
    constexpr int32_t kMinOffsetForMediumAdjustment =
        2 * kMinOffsetForSimpleAdjustment;
    constexpr int32_t kMaxOffsetForMediumAdjustment =
        3 * kMinOffsetForSimpleAdjustment;
    if (0 <= src->offset() && src->offset() <= kMaxOffsetForMediumAdjustment) {
      daddiu(scratch, src->rm(), kMinOffsetForMediumAdjustment / 2);
      daddiu(scratch, scratch, kMinOffsetForMediumAdjustment / 2);
      src->offset_ -= kMinOffsetForMediumAdjustment;
    } else if (-kMaxOffsetForMediumAdjustment <= src->offset() &&
               src->offset() < 0) {
      daddiu(scratch, src->rm(), -kMinOffsetForMediumAdjustment / 2);
      daddiu(scratch, scratch, -kMinOffsetForMediumAdjustment / 2);
      src->offset_ += kMinOffsetForMediumAdjustment;
    } else {
      // Now that all shorter options have been exhausted, load the full 32-bit
      // offset.
      int32_t loaded_offset = RoundDown(src->offset(), kDoubleSize);
      lui(scratch, (loaded_offset >> kLuiShift) & kImm16Mask);
      ori(scratch, scratch, loaded_offset & kImm16Mask);  // Load 32-bit offset.
      daddu(scratch, scratch, src->rm());
      src->offset_ -= loaded_offset;
    }
  }
  src->rm_ = scratch;

  DCHECK(is_int16(src->offset()));
  if (two_accesses) {
    DCHECK(is_int16(
        static_cast<int32_t>(src->offset() + second_access_add_to_offset)));
  }
  DCHECK(misalignment == (src->offset() & (kDoubleSize - 1)));
}

void Assembler::lb(Register rd, const MemOperand& rs) {
  GenInstrImmediate(LB, rs.rm(), rd, rs.offset_);
}

void Assembler::lbu(Register rd, const MemOperand& rs) {
  GenInstrImmediate(LBU, rs.rm(), rd, rs.offset_);
}

void Assembler::lh(Register rd, const MemOperand& rs) {
  GenInstrImmediate(LH, rs.rm(), rd, rs.offset_);
}

void Assembler::lhu(Register rd, const MemOperand& rs) {
  GenInstrImmediate(LHU, rs.rm(), rd, rs.offset_);
}

void Assembler::lw(Register rd, const MemOperand& rs) {
  GenInstrImmediate(LW, rs.rm(), rd, rs.offset_);
}

void Assembler::lwu(Register rd, const MemOperand& rs) {
  GenInstrImmediate(LWU, rs.rm(), rd, rs.offset_);
}

void Assembler::lwl(Register rd, const MemOperand& rs) {
  DCHECK(is_int16(rs.offset_));
  DCHECK_EQ(kArchVariant, kMips64r2);
  GenInstrImmediate(LWL, rs.rm(), rd, rs.offset_);
}

void Assembler::lwr(Register rd, const MemOperand& rs) {
  DCHECK(is_int16(rs.offset_));
  DCHECK_EQ(kArchVariant, kMips64r2);
  GenInstrImmediate(LWR, rs.rm(), rd, rs.offset_);
}

void Assembler::sb(Register rd, const MemOperand& rs) {
  GenInstrImmediate(SB, rs.rm(), rd, rs.offset_);
}

void Assembler::sh(Register rd, const MemOperand& rs) {
  GenInstrImmediate(SH, rs.rm(), rd, rs.offset_);
}

void Assembler::sw(Register rd, const MemOperand& rs) {
  GenInstrImmediate(SW, rs.rm(), rd, rs.offset_);
}

void Assembler::swl(Register rd, const MemOperand& rs) {
  DCHECK(is_int16(rs.offset_));
  DCHECK_EQ(kArchVariant, kMips64r2);
  GenInstrImmediate(SWL, rs.rm(), rd, rs.offset_);
}

void Assembler::swr(Register rd, const MemOperand& rs) {
  DCHECK(is_int16(rs.offset_));
  DCHECK_EQ(kArchVariant, kMips64r2);
  GenInstrImmediate(SWR, rs.rm(), rd, rs.offset_);
}

void Assembler::ll(Register rd, const MemOperand& rs) {
  if (kArchVariant == kMips64r6) {
    DCHECK(is_int9(rs.offset_));
    GenInstrImmediate(SPECIAL3, rs.rm(), rd, rs.offset_, 0, LL_R6);
  } else {
    DCHECK_EQ(kArchVariant, kMips64r2);
    DCHECK(is_int16(rs.offset_));
    GenInstrImmediate(LL, rs.rm(), rd, rs.offset_);
  }
}

void Assembler::lld(Register rd, const MemOperand& rs) {
  if (kArchVariant == kMips64r6) {
    DCHECK(is_int9(rs.offset_));
    GenInstrImmediate(SPECIAL3, rs.rm(), rd, rs.offset_, 0, LLD_R6);
  } else {
    DCHECK_EQ(kArchVariant, kMips64r2);
    DCHECK(is_int16(rs.offset_));
    GenInstrImmediate(LLD, rs.rm(), rd, rs.offset_);
  }
}

void Assembler::sc(Register rd, const MemOperand& rs) {
  if (kArchVariant == kMips64r6) {
    DCHECK(is_int9(rs.offset_));
    GenInstrImmediate(SPECIAL3, rs.rm(), rd, rs.offset_, 0, SC_R6);
  } else {
    DCHECK_EQ(kArchVariant, kMips64r2);
    GenInstrImmediate(SC, rs.rm(), rd, rs.offset_);
  }
}

void Assembler::scd(Register rd, const MemOperand& rs) {
  if (kArchVariant == kMips64r6) {
    DCHECK(is_int9(rs.offset_));
    GenInstrImmediate(SPECIAL3, rs.rm(), rd, rs.offset_, 0, SCD_R6);
  } else {
    DCHECK_EQ(kArchVariant, kMips64r2);
    GenInstrImmediate(SCD, rs.rm(), rd, rs.offset_);
  }
}

void Assembler::lui(Register rd, int32_t j) {
  DCHECK(is_uint16(j) || is_int16(j));
  GenInstrImmediate(LUI, zero_reg, rd, j);
}

void Assembler::aui(Register rt, Register rs, int32_t j) {
  // This instruction uses same opcode as 'lui'. The difference in encoding is
  // 'lui' has zero reg. for rs field.
  DCHECK(is_uint16(j));
  GenInstrImmediate(LUI, rs, rt, j);
}

void Assembler::daui(Register rt, Register rs, int32_t j) {
  DCHECK(is_uint16(j));
  DCHECK(rs != zero_reg);
  GenInstrImmediate(DAUI, rs, rt, j);
}

void Assembler::dahi(Register rs, int32_t j) {
  DCHECK(is_uint16(j));
  GenInstrImmediate(REGIMM, rs, DAHI, j);
}

void Assembler::dati(Register rs, int32_t j) {
  DCHECK(is_uint16(j));
  GenInstrImmediate(REGIMM, rs, DATI, j);
}

void Assembler::ldl(Register rd, const MemOperand& rs) {
  DCHECK(is_int16(rs.offset_));
  DCHECK_EQ(kArchVariant, kMips64r2);
  GenInstrImmediate(LDL, rs.rm(), rd, rs.offset_);
}

void Assembler::ldr(Register rd, const MemOperand& rs) {
  DCHECK(is_int16(rs.offset_));
  DCHECK_EQ(kArchVariant, kMips64r2);
  GenInstrImmediate(LDR, rs.rm(), rd, rs.offset_);
}

void Assembler::sdl(Register rd, const MemOperand& rs) {
  DCHECK(is_int16(rs.offset_));
  DCHECK_EQ(kArchVariant, kMips64r2);
  GenInstrImmediate(SDL, rs.rm(), rd, rs.offset_);
}

void Assembler::sdr(Register rd, const MemOperand& rs) {
  DCHECK(is_int16(rs.offset_));
  DCHECK_EQ(kArchVariant, kMips64r2);
  GenInstrImmediate(SDR, rs.rm(), rd, rs.offset_);
}

void Assembler::ld(Register rd, const MemOperand& rs) {
  GenInstrImmediate(LD, rs.rm(), rd, rs.offset_);
}

void Assembler::sd(Register rd, const MemOperand& rs) {
  GenInstrImmediate(SD, rs.rm(), rd, rs.offset_);
}

// ---------PC-Relative instructions-----------

void Assembler::addiupc(Register rs, int32_t imm19) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  DCHECK(rs.is_valid() && is_int19(imm19));
  uint32_t imm21 = ADDIUPC << kImm19Bits | (imm19 & kImm19Mask);
  GenInstrImmediate(PCREL, rs, imm21);
}

void Assembler::lwpc(Register rs, int32_t offset19) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  DCHECK(rs.is_valid() && is_int19(offset19));
  uint32_t imm21 = LWPC << kImm19Bits | (offset19 & kImm19Mask);
  GenInstrImmediate(PCREL, rs, imm21);
}

void Assembler::lwupc(Register rs, int32_t offset19) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  DCHECK(rs.is_valid() && is_int19(offset19));
  uint32_t imm21 = LWUPC << kImm19Bits | (offset19 & kImm19Mask);
  GenInstrImmediate(PCREL, rs, imm21);
}

void Assembler::ldpc(Register rs, int32_t offset18) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  DCHECK(rs.is_valid() && is_int18(offset18));
  uint32_t imm21 = LDPC << kImm18Bits | (offset18 & kImm18Mask);
  GenInstrImmediate(PCREL, rs, imm21);
}

void Assembler::auipc(Register rs, int16_t imm16) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  DCHECK(rs.is_valid());
  uint32_t imm21 = AUIPC << kImm16Bits | (imm16 & kImm16Mask);
  GenInstrImmediate(PCREL, rs, imm21);
}

void Assembler::aluipc(Register rs, int16_t imm16) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  DCHECK(rs.is_valid());
  uint32_t imm21 = ALUIPC << kImm16Bits | (imm16 & kImm16Mask);
  GenInstrImmediate(PCREL, rs, imm21);
}

// -------------Misc-instructions--------------

// Break / Trap instructions.
void Assembler::break_(uint32_t code, bool break_as_stop) {
  DCHECK_EQ(code & ~0xFFFFF, 0);
  // We need to invalidate breaks that could be stops as well because the
  // simulator expects a char pointer after the stop instruction.
  // See constants-mips.h for explanation.
  DCHECK(
      (break_as_stop && code <= kMaxStopCode && code > kMaxWatchpointCode) ||
      (!break_as_stop && (code > kMaxStopCode || code <= kMaxWatchpointCode)));
  Instr break_instr = SPECIAL | BREAK | (code << 6);
  emit(break_instr);
}

void Assembler::stop(uint32_t code) {
  DCHECK_GT(code, kMaxWatchpointCode);
  DCHECK_LE(code, kMaxStopCode);
#if defined(V8_HOST_ARCH_MIPS) || defined(V8_HOST_ARCH_MIPS64)
  break_(0x54321);
#else  // V8_HOST_ARCH_MIPS
  break_(code, true);
#endif
}

void Assembler::tge(Register rs, Register rt, uint16_t code) {
  DCHECK(is_uint10(code));
  Instr instr =
      SPECIAL | TGE | rs.code() << kRsShift | rt.code() << kRtShift | code << 6;
  emit(instr);
}

void Assembler::tgeu(Register rs, Register rt, uint16_t code) {
  DCHECK(is_uint10(code));
  Instr instr = SPECIAL | TGEU | rs.code() << kRsShift | rt.code() << kRtShift |
                code << 6;
  emit(instr);
}

void Assembler::tlt(Register rs, Register rt, uint16_t code) {
  DCHECK(is_uint10(code));
  Instr instr =
      SPECIAL | TLT | rs.code() << kRsShift | rt.code() << kRtShift | code << 6;
  emit(instr);
}

void Assembler::tltu(Register rs, Register rt, uint16_t code) {
  DCHECK(is_uint10(code));
  Instr instr = SPECIAL | TLTU | rs.code() << kRsShift | rt.code() << kRtShift |
                code << 6;
  emit(instr);
}

void Assembler::teq(Register rs, Register rt, uint16_t code) {
  DCHECK(is_uint10(code));
  Instr instr =
      SPECIAL | TEQ | rs.code() << kRsShift | rt.code() << kRtShift | code << 6;
  emit(instr);
}

void Assembler::tne(Register rs, Register rt, uint16_t code) {
  DCHECK(is_uint10(code));
  Instr instr =
      SPECIAL | TNE | rs.code() << kRsShift | rt.code() << kRtShift | code << 6;
  emit(instr);
}

void Assembler::sync() {
  Instr sync_instr = SPECIAL | SYNC;
  emit(sync_instr);
}

// Move from HI/LO register.

void Assembler::mfhi(Register rd) {
  GenInstrRegister(SPECIAL, zero_reg, zero_reg, rd, 0, MFHI);
}

void Assembler::mflo(Register rd) {
  GenInstrRegister(SPECIAL, zero_reg, zero_reg, rd, 0, MFLO);
}

// Set on less than instructions.
void Assembler::slt(Register rd, Register rs, Register rt) {
  GenInstrRegister(SPECIAL, rs, rt, rd, 0, SLT);
}

void Assembler::sltu(Register rd, Register rs, Register rt) {
  GenInstrRegister(SPECIAL, rs, rt, rd, 0, SLTU);
}

void Assembler::slti(Register rt, Register rs, int32_t j) {
  GenInstrImmediate(SLTI, rs, rt, j);
}

void Assembler::sltiu(Register rt, Register rs, int32_t j) {
  GenInstrImmediate(SLTIU, rs, rt, j);
}

// Conditional move.
void Assembler::movz(Register rd, Register rs, Register rt) {
  GenInstrRegister(SPECIAL, rs, rt, rd, 0, MOVZ);
}

void Assembler::movn(Register rd, Register rs, Register rt) {
  GenInstrRegister(SPECIAL, rs, rt, rd, 0, MOVN);
}

void Assembler::movt(Register rd, Register rs, uint16_t cc) {
  Register rt = Register::from_code((cc & 0x0007) << 2 | 1);
  GenInstrRegister(SPECIAL, rs, rt, rd, 0, MOVCI);
}

void Assembler::movf(Register rd, Register rs, uint16_t cc) {
  Register rt = Register::from_code((cc & 0x0007) << 2 | 0);
  GenInstrRegister(SPECIAL, rs, rt, rd, 0, MOVCI);
}

void Assembler::min_s(FPURegister fd, FPURegister fs, FPURegister ft) {
  min(S, fd, fs, ft);
}

void Assembler::min_d(FPURegister fd, FPURegister fs, FPURegister ft) {
  min(D, fd, fs, ft);
}

void Assembler::max_s(FPURegister fd, FPURegister fs, FPURegister ft) {
  max(S, fd, fs, ft);
}

void Assembler::max_d(FPURegister fd, FPURegister fs, FPURegister ft) {
  max(D, fd, fs, ft);
}

void Assembler::mina_s(FPURegister fd, FPURegister fs, FPURegister ft) {
  mina(S, fd, fs, ft);
}

void Assembler::mina_d(FPURegister fd, FPURegister fs, FPURegister ft) {
  mina(D, fd, fs, ft);
}

void Assembler::maxa_s(FPURegister fd, FPURegister fs, FPURegister ft) {
  maxa(S, fd, fs, ft);
}

void Assembler::maxa_d(FPURegister fd, FPURegister fs, FPURegister ft) {
  maxa(D, fd, fs, ft);
}

void Assembler::max(SecondaryField fmt, FPURegister fd, FPURegister fs,
                    FPURegister ft) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  DCHECK((fmt == D) || (fmt == S));
  GenInstrRegister(COP1, fmt, ft, fs, fd, MAX);
}

void Assembler::min(SecondaryField fmt, FPURegister fd, FPURegister fs,
                    FPURegister ft) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  DCHECK((fmt == D) || (fmt == S));
  GenInstrRegister(COP1, fmt, ft, fs, fd, MIN);
}

// GPR.
void Assembler::seleqz(Register rd, Register rs, Register rt) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  GenInstrRegister(SPECIAL, rs, rt, rd, 0, SELEQZ_S);
}

// GPR.
void Assembler::selnez(Register rd, Register rs, Register rt) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  GenInstrRegister(SPECIAL, rs, rt, rd, 0, SELNEZ_S);
}

// Bit twiddling.
void Assembler::clz(Register rd, Register rs) {
  if (kArchVariant != kMips64r6) {
    // clz instr requires same GPR number in 'rd' and 'rt' fields.
    GenInstrRegister(SPECIAL2, rs, rd, rd, 0, CLZ);
  } else {
    GenInstrRegister(SPECIAL, rs, zero_reg, rd, 1, CLZ_R6);
  }
}

void Assembler::dclz(Register rd, Register rs) {
  if (kArchVariant != kMips64r6) {
    // dclz instr requires same GPR number in 'rd' and 'rt' fields.
    GenInstrRegister(SPECIAL2, rs, rd, rd, 0, DCLZ);
  } else {
    GenInstrRegister(SPECIAL, rs, zero_reg, rd, 1, DCLZ_R6);
  }
}

void Assembler::ins_(Register rt, Register rs, uint16_t pos, uint16_t size) {
  // Should be called via MacroAssembler::Ins.
  // ins instr has 'rt' field as dest, and two uint5: msb, lsb.
  DCHECK((kArchVariant == kMips64r2) || (kArchVariant == kMips64r6));
  GenInstrRegister(SPECIAL3, rs, rt, pos + size - 1, pos, INS);
}

void Assembler::dins_(Register rt, Register rs, uint16_t pos, uint16_t size) {
  // Should be called via MacroAssembler::Dins.
  // dins instr has 'rt' field as dest, and two uint5: msb, lsb.
  DCHECK(kArchVariant == kMips64r2 || kArchVariant == kMips64r6);
  GenInstrRegister(SPECIAL3, rs, rt, pos + size - 1, pos, DINS);
}

void Assembler::dinsm_(Register rt, Register rs, uint16_t pos, uint16_t size) {
  // Should be called via MacroAssembler::Dins.
  // dinsm instr has 'rt' field as dest, and two uint5: msbminus32, lsb.
  DCHECK(kArchVariant == kMips64r2 || kArchVariant == kMips64r6);
  GenInstrRegister(SPECIAL3, rs, rt, pos + size - 1 - 32, pos, DINSM);
}

void Assembler::dinsu_(Register rt, Register rs, uint16_t pos, uint16_t size) {
  // Should be called via MacroAssembler::Dins.
  // dinsu instr has 'rt' field as dest, and two uint5: msbminus32, lsbminus32.
  DCHECK(kArchVariant == kMips64r2 || kArchVariant == kMips64r6);
  GenInstrRegister(SPECIAL3, rs, rt, pos + size - 1 - 32, pos - 32, DINSU);
}

void Assembler::ext_(Register rt, Register rs, uint16_t pos, uint16_t size) {
  // Should be called via MacroAssembler::Ext.
  // ext instr has 'rt' field as dest, and two uint5: msbd, lsb.
  DCHECK(kArchVariant == kMips64r2 || kArchVariant == kMips64r6);
  GenInstrRegister(SPECIAL3, rs, rt, size - 1, pos, EXT);
}

void Assembler::dext_(Register rt, Register rs, uint16_t pos, uint16_t size) {
  // Should be called via MacroAssembler::Dext.
  // dext instr has 'rt' field as dest, and two uint5: msbd, lsb.
  DCHECK(kArchVariant == kMips64r2 || kArchVariant == kMips64r6);
  GenInstrRegister(SPECIAL3, rs, rt, size - 1, pos, DEXT);
}

void Assembler::dextm_(Register rt, Register rs, uint16_t pos, uint16_t size) {
  // Should be called via MacroAssembler::Dextm.
  // dextm instr has 'rt' field as dest, and two uint5: msbdminus32, lsb.
  DCHECK(kArchVariant == kMips64r2 || kArchVariant == kMips64r6);
  GenInstrRegister(SPECIAL3, rs, rt, size - 1 - 32, pos, DEXTM);
}

void Assembler::dextu_(Register rt, Register rs, uint16_t pos, uint16_t size) {
  // Should be called via MacroAssembler::Dextu.
  // dextu instr has 'rt' field as dest, and two uint5: msbd, lsbminus32.
  DCHECK(kArchVariant == kMips64r2 || kArchVariant == kMips64r6);
  GenInstrRegister(SPECIAL3, rs, rt, size - 1, pos - 32, DEXTU);
}

void Assembler::bitswap(Register rd, Register rt) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  GenInstrRegister(SPECIAL3, zero_reg, rt, rd, 0, BSHFL);
}

void Assembler::dbitswap(Register rd, Register rt) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  GenInstrRegister(SPECIAL3, zero_reg, rt, rd, 0, DBSHFL);
}

void Assembler::pref(int32_t hint, const MemOperand& rs) {
  DCHECK(is_uint5(hint) && is_uint16(rs.offset_));
  Instr instr =
      PREF | (rs.rm().code() << kRsShift) | (hint << kRtShift) | (rs.offset_);
  emit(instr);
}

void Assembler::align(Register rd, Register rs, Register rt, uint8_t bp) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  DCHECK(is_uint3(bp));
  uint16_t sa = (ALIGN << kBp2Bits) | bp;
  GenInstrRegister(SPECIAL3, rs, rt, rd, sa, BSHFL);
}

void Assembler::dalign(Register rd, Register rs, Register rt, uint8_t bp) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  DCHECK(is_uint3(bp));
  uint16_t sa = (DALIGN << kBp3Bits) | bp;
  GenInstrRegister(SPECIAL3, rs, rt, rd, sa, DBSHFL);
}

void Assembler::wsbh(Register rd, Register rt) {
  DCHECK(kArchVariant == kMips64r2 || kArchVariant == kMips64r6);
  GenInstrRegister(SPECIAL3, zero_reg, rt, rd, WSBH, BSHFL);
}

void Assembler::dsbh(Register rd, Register rt) {
  DCHECK(kArchVariant == kMips64r2 || kArchVariant == kMips64r6);
  GenInstrRegister(SPECIAL3, zero_reg, rt, rd, DSBH, DBSHFL);
}

void Assembler::dshd(Register rd, Register rt) {
  DCHECK(kArchVariant == kMips64r2 || kArchVariant == kMips64r6);
  GenInstrRegister(SPECIAL3, zero_reg, rt, rd, DSHD, DBSHFL);
}

void Assembler::seh(Register rd, Register rt) {
  DCHECK(kArchVariant == kMips64r2 || kArchVariant == kMips64r6);
  GenInstrRegister(SPECIAL3, zero_reg, rt, rd, SEH, BSHFL);
}

void Assembler::seb(Register rd, Register rt) {
  DCHECK(kArchVariant == kMips64r2 || kArchVariant == kMips64r6);
  GenInstrRegister(SPECIAL3, zero_reg, rt, rd, SEB, BSHFL);
}

// --------Coprocessor-instructions----------------

// Load, store, move.
void Assembler::lwc1(FPURegister fd, const MemOperand& src) {
  GenInstrImmediate(LWC1, src.rm(), fd, src.offset_);
}

void Assembler::ldc1(FPURegister fd, const MemOperand& src) {
  GenInstrImmediate(LDC1, src.rm(), fd, src.offset_);
}

void Assembler::swc1(FPURegister fs, const MemOperand& src) {
  GenInstrImmediate(SWC1, src.rm(), fs, src.offset_);
}

void Assembler::sdc1(FPURegister fs, const MemOperand& src) {
  GenInstrImmediate(SDC1, src.rm(), fs, src.offset_);
}

void Assembler::mtc1(Register rt, FPURegister fs) {
  GenInstrRegister(COP1, MTC1, rt, fs, f0);
}

void Assembler::mthc1(Register rt, FPURegister fs) {
  GenInstrRegister(COP1, MTHC1, rt, fs, f0);
}

void Assembler::dmtc1(Register rt, FPURegister fs) {
  GenInstrRegister(COP1, DMTC1, rt, fs, f0);
}

void Assembler::mfc1(Register rt, FPURegister fs) {
  GenInstrRegister(COP1, MFC1, rt, fs, f0);
}

void Assembler::mfhc1(Register rt, FPURegister fs) {
  GenInstrRegister(COP1, MFHC1, rt, fs, f0);
}

void Assembler::dmfc1(Register rt, FPURegister fs) {
  GenInstrRegister(COP1, DMFC1, rt, fs, f0);
}

void Assembler::ctc1(Register rt, FPUControlRegister fs) {
  GenInstrRegister(COP1, CTC1, rt, fs);
}

void Assembler::cfc1(Register rt, FPUControlRegister fs) {
  GenInstrRegister(COP1, CFC1, rt, fs);
}

void Assembler::sel(SecondaryField fmt, FPURegister fd, FPURegister fs,
                    FPURegister ft) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  DCHECK((fmt == D) || (fmt == S));

  GenInstrRegister(COP1, fmt, ft, fs, fd, SEL);
}

void Assembler::sel_s(FPURegister fd, FPURegister fs, FPURegister ft) {
  sel(S, fd, fs, ft);
}

void Assembler::sel_d(FPURegister fd, FPURegister fs, FPURegister ft) {
  sel(D, fd, fs, ft);
}

// FPR.
void Assembler::seleqz(SecondaryField fmt, FPURegister fd, FPURegister fs,
                       FPURegister ft) {
  DCHECK((fmt == D) || (fmt == S));
  GenInstrRegister(COP1, fmt, ft, fs, fd, SELEQZ_C);
}

void Assembler::seleqz_d(FPURegister fd, FPURegister fs, FPURegister ft) {
  seleqz(D, fd, fs, ft);
}

void Assembler::seleqz_s(FPURegister fd, FPURegister fs, FPURegister ft) {
  seleqz(S, fd, fs, ft);
}

void Assembler::selnez_d(FPURegister fd, FPURegister fs, FPURegister ft) {
  selnez(D, fd, fs, ft);
}

void Assembler::selnez_s(FPURegister fd, FPURegister fs, FPURegister ft) {
  selnez(S, fd, fs, ft);
}

void Assembler::movz_s(FPURegister fd, FPURegister fs, Register rt) {
  DCHECK_EQ(kArchVariant, kMips64r2);
  GenInstrRegister(COP1, S, rt, fs, fd, MOVZ_C);
}

void Assembler::movz_d(FPURegister fd, FPURegister fs, Register rt) {
  DCHECK_EQ(kArchVariant, kMips64r2);
  GenInstrRegister(COP1, D, rt, fs, fd, MOVZ_C);
}

void Assembler::movt_s(FPURegister fd, FPURegister fs, uint16_t cc) {
  DCHECK_EQ(kArchVariant, kMips64r2);
  FPURegister ft = FPURegister::from_code((cc & 0x0007) << 2 | 1);
  GenInstrRegister(COP1, S, ft, fs, fd, MOVF);
}

void Assembler::movt_d(FPURegister fd, FPURegister fs, uint16_t cc) {
  DCHECK_EQ(kArchVariant, kMips64r2);
  FPURegister ft = FPURegister::from_code((cc & 0x0007) << 2 | 1);
  GenInstrRegister(COP1, D, ft, fs, fd, MOVF);
}

void Assembler::movf_s(FPURegister fd, FPURegister fs, uint16_t cc) {
  DCHECK_EQ(kArchVariant, kMips64r2);
  FPURegister ft = FPURegister::from_code((cc & 0x0007) << 2 | 0);
  GenInstrRegister(COP1, S, ft, fs, fd, MOVF);
}

void Assembler::movf_d(FPURegister fd, FPURegister fs, uint16_t cc) {
  DCHECK_EQ(kArchVariant, kMips64r2);
  FPURegister ft = FPURegister::from_code((cc & 0x0007) << 2 | 0);
  GenInstrRegister(COP1, D, ft, fs, fd, MOVF);
}

void Assembler::movn_s(FPURegister fd, FPURegister fs, Register rt) {
  DCHECK_EQ(kArchVariant, kMips64r2);
  GenInstrRegister(COP1, S, rt, fs, fd, MOVN_C);
}

void Assembler::movn_d(FPURegister fd, FPURegister fs, Register rt) {
  DCHECK_EQ(kArchVariant, kMips64r2);
  GenInstrRegister(COP1, D, rt, fs, fd, MOVN_C);
}

// FPR.
void Assembler::selnez(SecondaryField fmt, FPURegister fd, FPURegister fs,
                       FPURegister ft) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  DCHECK((fmt == D) || (fmt == S));
  GenInstrRegister(COP1, fmt, ft, fs, fd, SELNEZ_C);
}

// Arithmetic.

void Assembler::add_s(FPURegister fd, FPURegister fs, FPURegister ft) {
  GenInstrRegister(COP1, S, ft, fs, fd, ADD_D);
}

void Assembler::add_d(FPURegister fd, FPURegister fs, FPURegister ft) {
  GenInstrRegister(COP1, D, ft, fs, fd, ADD_D);
}

void Assembler::sub_s(FPURegister fd, FPURegister fs, FPURegister ft) {
  GenInstrRegister(COP1, S, ft, fs, fd, SUB_D);
}

void Assembler::sub_d(FPURegister fd, FPURegister fs, FPURegister ft) {
  GenInstrRegister(COP1, D, ft, fs, fd, SUB_D);
}

void Assembler::mul_s(FPURegister fd, FPURegister fs, FPURegister ft) {
  GenInstrRegister(COP1, S, ft, fs, fd, MUL_D);
}

void Assembler::mul_d(FPURegister fd, FPURegister fs, FPURegister ft) {
  GenInstrRegister(COP1, D, ft, fs, fd, MUL_D);
}

void Assembler::madd_s(FPURegister fd, FPURegister fr, FPURegister fs,
                       FPURegister ft) {
  // On Loongson 3A (MIPS64R2), MADD.S instruction is actually fused MADD.S and
  // this causes failure in some of the tests. Since this optimization is rarely
  // used, and not used at all on MIPS64R6, this isntruction is removed.
  UNREACHABLE();
}

void Assembler::madd_d(FPURegister fd, FPURegister fr, FPURegister fs,
                       FPURegister ft) {
  // On Loongson 3A (MIPS64R2), MADD.D instruction is actually fused MADD.D and
  // this causes failure in some of the tests. Since this optimization is rarely
  // used, and not used at all on MIPS64R6, this isntruction is removed.
  UNREACHABLE();
}

void Assembler::msub_s(FPURegister fd, FPURegister fr, FPURegister fs,
                       FPURegister ft) {
  // See explanation for instruction madd_s.
  UNREACHABLE();
}

void Assembler::msub_d(FPURegister fd, FPURegister fr, FPURegister fs,
                       FPURegister ft) {
  // See explanation for instruction madd_d.
  UNREACHABLE();
}

void Assembler::maddf_s(FPURegister fd, FPURegister fs, FPURegister ft) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  GenInstrRegister(COP1, S, ft, fs, fd, MADDF_S);
}

void Assembler::maddf_d(FPURegister fd, FPURegister fs, FPURegister ft) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  GenInstrRegister(COP1, D, ft, fs, fd, MADDF_D);
}

void Assembler::msubf_s(FPURegister fd, FPURegister fs, FPURegister ft) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  GenInstrRegister(COP1, S, ft, fs, fd, MSUBF_S);
}

void Assembler::msubf_d(FPURegister fd, FPURegister fs, FPURegister ft) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  GenInstrRegister(COP1, D, ft, fs, fd, MSUBF_D);
}

void Assembler::div_s(FPURegister fd, FPURegister fs, FPURegister ft) {
  GenInstrRegister(COP1, S, ft, fs, fd, DIV_D);
}

void Assembler::div_d(FPURegister fd, FPURegister fs, FPURegister ft) {
  GenInstrRegister(COP1, D, ft, fs, fd, DIV_D);
}

void Assembler::abs_s(FPURegister fd, FPURegister fs) {
  GenInstrRegister(COP1, S, f0, fs, fd, ABS_D);
}

void Assembler::abs_d(FPURegister fd, FPURegister fs) {
  GenInstrRegister(COP1, D, f0, fs, fd, ABS_D);
}

void Assembler::mov_d(FPURegister fd, FPURegister fs) {
  GenInstrRegister(COP1, D, f0, fs, fd, MOV_D);
}

void Assembler::mov_s(FPURegister fd, FPURegister fs) {
  GenInstrRegister(COP1, S, f0, fs, fd, MOV_S);
}

void Assembler::neg_s(FPURegister fd, FPURegister fs) {
  GenInstrRegister(COP1, S, f0, fs, fd, NEG_D);
}

void Assembler::neg_d(FPURegister fd, FPURegister fs) {
  GenInstrRegister(COP1, D, f0, fs, fd, NEG_D);
}

void Assembler::sqrt_s(FPURegister fd, FPURegister fs) {
  GenInstrRegister(COP1, S, f0, fs, fd, SQRT_D);
}

void Assembler::sqrt_d(FPURegister fd, FPURegister fs) {
  GenInstrRegister(COP1, D, f0, fs, fd, SQRT_D);
}

void Assembler::rsqrt_s(FPURegister fd, FPURegister fs) {
  GenInstrRegister(COP1, S, f0, fs, fd, RSQRT_S);
}

void Assembler::rsqrt_d(FPURegister fd, FPURegister fs) {
  GenInstrRegister(COP1, D, f0, fs, fd, RSQRT_D);
}

void Assembler::recip_d(FPURegister fd, FPURegister fs) {
  GenInstrRegister(COP1, D, f0, fs, fd, RECIP_D);
}

void Assembler::recip_s(FPURegister fd, FPURegister fs) {
  GenInstrRegister(COP1, S, f0, fs, fd, RECIP_S);
}

// Conversions.
void Assembler::cvt_w_s(FPURegister fd, FPURegister fs) {
  GenInstrRegister(COP1, S, f0, fs, fd, CVT_W_S);
}

void Assembler::cvt_w_d(FPURegister fd, FPURegister fs) {
  GenInstrRegister(COP1, D, f0, fs, fd, CVT_W_D);
}

void Assembler::trunc_w_s(FPURegister fd, FPURegister fs) {
  GenInstrRegister(COP1, S, f0, fs, fd, TRUNC_W_S);
}

void Assembler::trunc_w_d(FPURegister fd, FPURegister fs) {
  GenInstrRegister(COP1, D, f0, fs, fd, TRUNC_W_D);
}

void Assembler::round_w_s(FPURegister fd, FPURegister fs) {
  GenInstrRegister(COP1, S, f0, fs, fd, ROUND_W_S);
}

void Assembler::round_w_d(FPURegister fd, FPURegister fs) {
  GenInstrRegister(COP1, D, f0, fs, fd, ROUND_W_D);
}

void Assembler::floor_w_s(FPURegister fd, FPURegister fs) {
  GenInstrRegister(COP1, S, f0, fs, fd, FLOOR_W_S);
}

void Assembler::floor_w_d(FPURegister fd, FPURegister fs) {
  GenInstrRegister(COP1, D, f0, fs, fd, FLOOR_W_D);
}

void Assembler::ceil_w_s(FPURegister fd, FPURegister fs) {
  GenInstrRegister(COP1, S, f0, fs, fd, CEIL_W_S);
}

void Assembler::ceil_w_d(FPURegister fd, FPURegister fs) {
  GenInstrRegister(COP1, D, f0, fs, fd, CEIL_W_D);
}

void Assembler::rint_s(FPURegister fd, FPURegister fs) { rint(S, fd, fs); }

void Assembler::rint_d(FPURegister fd, FPURegister fs) { rint(D, fd, fs); }

void Assembler::rint(SecondaryField fmt, FPURegister fd, FPURegister fs) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  GenInstrRegister(COP1, fmt, f0, fs, fd, RINT);
}

void Assembler::cvt_l_s(FPURegister fd, FPURegister fs) {
  DCHECK(kArchVariant == kMips64r2 || kArchVariant == kMips64r6);
  GenInstrRegister(COP1, S, f0, fs, fd, CVT_L_S);
}

void Assembler::cvt_l_d(FPURegister fd, FPURegister fs) {
  DCHECK(kArchVariant == kMips64r2 || kArchVariant == kMips64r6);
  GenInstrRegister(COP1, D, f0, fs, fd, CVT_L_D);
}

void Assembler::trunc_l_s(FPURegister fd, FPURegister fs) {
  DCHECK(kArchVariant == kMips64r2 || kArchVariant == kMips64r6);
  GenInstrRegister(COP1, S, f0, fs, fd, TRUNC_L_S);
}

void Assembler::trunc_l_d(FPURegister fd, FPURegister fs) {
  DCHECK(kArchVariant == kMips64r2 || kArchVariant == kMips64r6);
  GenInstrRegister(COP1, D, f0, fs, fd, TRUNC_L_D);
}

void Assembler::round_l_s(FPURegister fd, FPURegister fs) {
  GenInstrRegister(COP1, S, f0, fs, fd, ROUND_L_S);
}

void Assembler::round_l_d(FPURegister fd, FPURegister fs) {
  GenInstrRegister(COP1, D, f0, fs, fd, ROUND_L_D);
}

void Assembler::floor_l_s(FPURegister fd, FPURegister fs) {
  GenInstrRegister(COP1, S, f0, fs, fd, FLOOR_L_S);
}

void Assembler::floor_l_d(FPURegister fd, FPURegister fs) {
  GenInstrRegister(COP1, D, f0, fs, fd, FLOOR_L_D);
}

void Assembler::ceil_l_s(FPURegister fd, FPURegister fs) {
  GenInstrRegister(COP1, S, f0, fs, fd, CEIL_L_S);
}

void Assembler::ceil_l_d(FPURegister fd, FPURegister fs) {
  GenInstrRegister(COP1, D, f0, fs, fd, CEIL_L_D);
}

void Assembler::class_s(FPURegister fd, FPURegister fs) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  GenInstrRegister(COP1, S, f0, fs, fd, CLASS_S);
}

void Assembler::class_d(FPURegister fd, FPURegister fs) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  GenInstrRegister(COP1, D, f0, fs, fd, CLASS_D);
}

void Assembler::mina(SecondaryField fmt, FPURegister fd, FPURegister fs,
                     FPURegister ft) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  DCHECK((fmt == D) || (fmt == S));
  GenInstrRegister(COP1, fmt, ft, fs, fd, MINA);
}

void Assembler::maxa(SecondaryField fmt, FPURegister fd, FPURegister fs,
                     FPURegister ft) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  DCHECK((fmt == D) || (fmt == S));
  GenInstrRegister(COP1, fmt, ft, fs, fd, MAXA);
}

void Assembler::cvt_s_w(FPURegister fd, FPURegister fs) {
  GenInstrRegister(COP1, W, f0, fs, fd, CVT_S_W);
}

void Assembler::cvt_s_l(FPURegister fd, FPURegister fs) {
  DCHECK(kArchVariant == kMips64r2 || kArchVariant == kMips64r6);
  GenInstrRegister(COP1, L, f0, fs, fd, CVT_S_L);
}

void Assembler::cvt_s_d(FPURegister fd, FPURegister fs) {
  GenInstrRegister(COP1, D, f0, fs, fd, CVT_S_D);
}

void Assembler::cvt_d_w(FPURegister fd, FPURegister fs) {
  GenInstrRegister(COP1, W, f0, fs, fd, CVT_D_W);
}

void Assembler::cvt_d_l(FPURegister fd, FPURegister fs) {
  DCHECK(kArchVariant == kMips64r2 || kArchVariant == kMips64r6);
  GenInstrRegister(COP1, L, f0, fs, fd, CVT_D_L);
}

void Assembler::cvt_d_s(FPURegister fd, FPURegister fs) {
  GenInstrRegister(COP1, S, f0, fs, fd, CVT_D_S);
}

// Conditions for >= MIPSr6.
void Assembler::cmp(FPUCondition cond, SecondaryField fmt, FPURegister fd,
                    FPURegister fs, FPURegister ft) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  DCHECK_EQ(fmt & ~(31 << kRsShift), 0);
  Instr instr = COP1 | fmt | ft.code() << kFtShift | fs.code() << kFsShift |
                fd.code() << kFdShift | (0 << 5) | cond;
  emit(instr);
}

void Assembler::cmp_s(FPUCondition cond, FPURegister fd, FPURegister fs,
                      FPURegister ft) {
  cmp(cond, W, fd, fs, ft);
}

void Assembler::cmp_d(FPUCondition cond, FPURegister fd, FPURegister fs,
                      FPURegister ft) {
  cmp(cond, L, fd, fs, ft);
}

void Assembler::bc1eqz(int16_t offset, FPURegister ft) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  BlockTrampolinePoolScope block_trampoline_pool(this);
  Instr instr = COP1 | BC1EQZ | ft.code() << kFtShift | (offset & kImm16Mask);
  emit(instr);
  BlockTrampolinePoolFor(1);  // For associated delay slot.
}

void Assembler::bc1nez(int16_t offset, FPURegister ft) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  BlockTrampolinePoolScope block_trampoline_pool(this);
  Instr instr = COP1 | BC1NEZ | ft.code() << kFtShift | (offset & kImm16Mask);
  emit(instr);
  BlockTrampolinePoolFor(1);  // For associated delay slot.
}

// Conditions for < MIPSr6.
void Assembler::c(FPUCondition cond, SecondaryField fmt, FPURegister fs,
                  FPURegister ft, uint16_t cc) {
  DCHECK_NE(kArchVariant, kMips64r6);
  DCHECK(is_uint3(cc));
  DCHECK(fmt == S || fmt == D);
  DCHECK_EQ(fmt & ~(31 << kRsShift), 0);
  Instr instr = COP1 | fmt | ft.code() << kFtShift | fs.code() << kFsShift |
                cc << 8 | 3 << 4 | cond;
  emit(instr);
}

void Assembler::c_s(FPUCondition cond, FPURegister fs, FPURegister ft,
                    uint16_t cc) {
  c(cond, S, fs, ft, cc);
}

void Assembler::c_d(FPUCondition cond, FPURegister fs, FPURegister ft,
                    uint16_t cc) {
  c(cond, D, fs, ft, cc);
}

void Assembler::fcmp(FPURegister src1, const double src2, FPUCondition cond) {
  DCHECK_EQ(src2, 0.0);
  mtc1(zero_reg, f14);
  cvt_d_w(f14, f14);
  c(cond, D, src1, f14, 0);
}

void Assembler::bc1f(int16_t offset, uint16_t cc) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  DCHECK(is_uint3(cc));
  Instr instr = COP1 | BC1 | cc << 18 | 0 << 16 | (offset & kImm16Mask);
  emit(instr);
  BlockTrampolinePoolFor(1);  // For associated delay slot.
}

void Assembler::bc1t(int16_t offset, uint16_t cc) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  DCHECK(is_uint3(cc));
  Instr instr = COP1 | BC1 | cc << 18 | 1 << 16 | (offset & kImm16Mask);
  emit(instr);
  BlockTrampolinePoolFor(1);  // For associated delay slot.
}

// ---------- MSA instructions ------------
#define MSA_BRANCH_LIST(V) \
  V(bz_v, BZ_V)            \
  V(bz_b, BZ_B)            \
  V(bz_h, BZ_H)            \
  V(bz_w, BZ_W)            \
  V(bz_d, BZ_D)            \
  V(bnz_v, BNZ_V)          \
  V(bnz_b, BNZ_B)          \
  V(bnz_h, BNZ_H)          \
  V(bnz_w, BNZ_W)          \
  V(bnz_d, BNZ_D)

#define MSA_BRANCH(name, opcode)                         \
  void Assembler::name(MSARegister wt, int16_t offset) { \
    GenInstrMsaBranch(opcode, wt, offset);               \
  }

MSA_BRANCH_LIST(MSA_BRANCH)
#undef MSA_BRANCH
#undef MSA_BRANCH_LIST

#define MSA_LD_ST_LIST(V) \
  V(ld_b, LD_B, 1)        \
  V(ld_h, LD_H, 2)        \
  V(ld_w, LD_W, 4)        \
  V(ld_d, LD_D, 8)        \
  V(st_b, ST_B, 1)        \
  V(st_h, ST_H, 2)        \
  V(st_w, ST_W, 4)        \
  V(st_d, ST_D, 8)

#define MSA_LD_ST(name, opcode, b)                                   \
  void Assembler::name(MSARegister wd, const MemOperand& rs) {       \
    MemOperand source = rs;                                          \
    AdjustBaseAndOffset(&source);                                    \
    if (is_int10(source.offset())) {                                 \
      DCHECK_EQ(source.offset() % b, 0);                             \
      GenInstrMsaMI10(opcode, source.offset() / b, source.rm(), wd); \
    } else {                                                         \
      UseScratchRegisterScope temps(this);                           \
      Register scratch = temps.Acquire();                            \
      DCHECK_NE(rs.rm(), scratch);                                   \
      daddiu(scratch, source.rm(), source.offset());                 \
      GenInstrMsaMI10(opcode, 0, scratch, wd);                       \
    }                                                                \
  }

MSA_LD_ST_LIST(MSA_LD_ST)
#undef MSA_LD_ST
#undef MSA_LD_ST_LIST

#define MSA_I10_LIST(V) \
  V(ldi_b, I5_DF_b)     \
  V(ldi_h, I5_DF_h)     \
  V(ldi_w, I5_DF_w)     \
  V(ldi_d, I5_DF_d)

#define MSA_I10(name, format)                           \
  void Assembler::name(MSARegister wd, int32_t imm10) { \
    GenInstrMsaI10(LDI, format, imm10, wd);             \
  }
MSA_I10_LIST(MSA_I10)
#undef MSA_I10
#undef MSA_I10_LIST

#define MSA_I5_LIST(V) \
  V(addvi, ADDVI)      \
  V(subvi, SUBVI)      \
  V(maxi_s, MAXI_S)    \
  V(maxi_u, MAXI_U)    \
  V(mini_s, MINI_S)    \
  V(mini_u, MINI_U)    \
  V(ceqi, CEQI)        \
  V(clti_s, CLTI_S)    \
  V(clti_u, CLTI_U)    \
  V(clei_s, CLEI_S)    \
  V(clei_u, CLEI_U)

#define MSA_I5_FORMAT(name, opcode, format)                       \
  void Assembler::name##_##format(MSARegister wd, MSARegister ws, \
                                  uint32_t imm5) {                \
    GenInstrMsaI5(opcode, I5_DF_##format, imm5, ws, wd);          \
  }

#define MSA_I5(name, opcode)     \
  MSA_I5_FORMAT(name, opcode, b) \
  MSA_I5_FORMAT(name, opcode, h) \
  MSA_I5_FORMAT(name, opcode, w) \
  MSA_I5_FORMAT(name, opcode, d)

MSA_I5_LIST(MSA_I5)
#undef MSA_I5
#undef MSA_I5_FORMAT
#undef MSA_I5_LIST

#define MSA_I8_LIST(V) \
  V(andi_b, ANDI_B)    \
  V(ori_b, ORI_B)      \
  V(nori_b, NORI_B)    \
  V(xori_b, XORI_B)    \
  V(bmnzi_b, BMNZI_B)  \
  V(bmzi_b, BMZI_B)    \
  V(bseli_b, BSELI_B)  \
  V(shf_b, SHF_B)      \
  V(shf_h, SHF_H)      \
  V(shf_w, SHF_W)

#define MSA_I8(name, opcode)                                            \
  void Assembler::name(MSARegister wd, MSARegister ws, uint32_t imm8) { \
    GenInstrMsaI8(opcode, imm8, ws, wd);                                \
  }

MSA_I8_LIST(MSA_I8)
#undef MSA_I8
#undef MSA_I8_LIST

#define MSA_VEC_LIST(V) \
  V(and_v, AND_V)       \
  V(or_v, OR_V)         \
  V(nor_v, NOR_V)       \
  V(xor_v, XOR_V)       \
  V(bmnz_v, BMNZ_V)     \
  V(bmz_v, BMZ_V)       \
  V(bsel_v, BSEL_V)

#define MSA_VEC(name, opcode)                                            \
  void Assembler::name(MSARegister wd, MSARegister ws, MSARegister wt) { \
    GenInstrMsaVec(opcode, wt, ws, wd);                                  \
  }

MSA_VEC_LIST(MSA_VEC)
#undef MSA_VEC
#undef MSA_VEC_LIST

#define MSA_2R_LIST(V) \
  V(pcnt, PCNT)        \
  V(nloc, NLOC)        \
  V(nlzc, NLZC)

#define MSA_2R_FORMAT(name, opcode, format)                         \
  void Assembler::name##_##format(MSARegister wd, MSARegister ws) { \
    GenInstrMsa2R(opcode, MSA_2R_DF_##format, ws, wd);              \
  }

#define MSA_2R(name, opcode)     \
  MSA_2R_FORMAT(name, opcode, b) \
  MSA_2R_FORMAT(name, opcode, h) \
  MSA_2R_FORMAT(name, opcode, w) \
  MSA_2R_FORMAT(name, opcode, d)

MSA_2R_LIST(MSA_2R)
#undef MSA_2R
#undef MSA_2R_FORMAT
#undef MSA_2R_LIST

#define MSA_FILL(format)                                              \
  void Assembler::fill_##format(MSARegister wd, Register rs) {        \
    DCHECK(IsEnabled(MIPS_SIMD));                                     \
    DCHECK(rs.is_valid() && wd.is_valid());                           \
    Instr instr = MSA | MSA_2R_FORMAT | FILL | MSA_2R_DF_##format |   \
                  (rs.code() << kWsShift) | (wd.code() << kWdShift) | \
                  MSA_VEC_2R_2RF_MINOR;                               \
    emit(instr);                                                      \
  }

MSA_FILL(b)
MSA_FILL(h)
MSA_FILL(w)
MSA_FILL(d)
#undef MSA_FILL

#define MSA_2RF_LIST(V) \
  V(fclass, FCLASS)     \
  V(ftrunc_s, FTRUNC_S) \
  V(ftrunc_u, FTRUNC_U) \
  V(fsqrt, FSQRT)       \
  V(frsqrt, FRSQRT)     \
  V(frcp, FRCP)         \
  V(frint, FRINT)       \
  V(flog2, FLOG2)       \
  V(fexupl, FEXUPL)     \
  V(fexupr, FEXUPR)     \
  V(ffql, FFQL)         \
  V(ffqr, FFQR)         \
  V(ftint_s, FTINT_S)   \
  V(ftint_u, FTINT_U)   \
  V(ffint_s, FFINT_S)   \
  V(ffint_u, FFINT_U)

#define MSA_2RF_FORMAT(name, opcode, format)                        \
  void Assembler::name##_##format(MSARegister wd, MSARegister ws) { \
    GenInstrMsa2RF(opcode, MSA_2RF_DF_##format, ws, wd);            \
  }

#define MSA_2RF(name, opcode)     \
  MSA_2RF_FORMAT(name, opcode, w) \
  MSA_2RF_FORMAT(name, opcode, d)

MSA_2RF_LIST(MSA_2RF)
#undef MSA_2RF
#undef MSA_2RF_FORMAT
#undef MSA_2RF_LIST

#define MSA_3R_LIST(V)  \
  V(sll, SLL_MSA)       \
  V(sra, SRA_MSA)       \
  V(srl, SRL_MSA)       \
  V(bclr, BCLR)         \
  V(bset, BSET)         \
  V(bneg, BNEG)         \
  V(binsl, BINSL)       \
  V(binsr, BINSR)       \
  V(addv, ADDV)         \
  V(subv, SUBV)         \
  V(max_s, MAX_S)       \
  V(max_u, MAX_U)       \
  V(min_s, MIN_S)       \
  V(min_u, MIN_U)       \
  V(max_a, MAX_A)       \
  V(min_a, MIN_A)       \
  V(ceq, CEQ)           \
  V(clt_s, CLT_S)       \
  V(clt_u, CLT_U)       \
  V(cle_s, CLE_S)       \
  V(cle_u, CLE_U)       \
  V(add_a, ADD_A)       \
  V(adds_a, ADDS_A)     \
  V(adds_s, ADDS_S)     \
  V(adds_u, ADDS_U)     \
  V(ave_s, AVE_S)       \
  V(ave_u, AVE_U)       \
  V(aver_s, AVER_S)     \
  V(aver_u, AVER_U)     \
  V(subs_s, SUBS_S)     \
  V(subs_u, SUBS_U)     \
  V(subsus_u, SUBSUS_U) \
  V(subsuu_s, SUBSUU_S) \
  V(asub_s, ASUB_S)     \
  V(asub_u, ASUB_U)     \
  V(mulv, MULV)         \
  V(maddv, MADDV)       \
  V(msubv, MSUBV)       \
  V(div_s, DIV_S_MSA)   \
  V(div_u, DIV_U)       \
  V(mod_s, MOD_S)       \
  V(mod_u, MOD_U)       \
  V(dotp_s, DOTP_S)     \
  V(dotp_u, DOTP_U)     \
  V(dpadd_s, DPADD_S)   \
  V(dpadd_u, DPADD_U)   \
  V(dpsub_s, DPSUB_S)   \
  V(dpsub_u, DPSUB_U)   \
  V(pckev, PCKEV)       \
  V(pckod, PCKOD)       \
  V(ilvl, ILVL)         \
  V(ilvr, ILVR)         \
  V(ilvev, ILVEV)       \
  V(ilvod, ILVOD)       \
  V(vshf, VSHF)         \
  V(srar, SRAR)         \
  V(srlr, SRLR)         \
  V(hadd_s, HADD_S)     \
  V(hadd_u, HADD_U)     \
  V(hsub_s, HSUB_S)     \
  V(hsub_u, HSUB_U)

#define MSA_3R_FORMAT(name, opcode, format)                             \
  void Assembler::name##_##format(MSARegister wd, MSARegister ws,       \
                                  MSARegister wt) {                     \
    GenInstrMsa3R<MSARegister>(opcode, MSA_3R_DF_##format, wt, ws, wd); \
  }

#define MSA_3R_FORMAT_SLD_SPLAT(name, opcode, format)                \
  void Assembler::name##_##format(MSARegister wd, MSARegister ws,    \
                                  Register rt) {                     \
    GenInstrMsa3R<Register>(opcode, MSA_3R_DF_##format, rt, ws, wd); \
  }

#define MSA_3R(name, opcode)     \
  MSA_3R_FORMAT(name, opcode, b) \
  MSA_3R_FORMAT(name, opcode, h) \
  MSA_3R_FORMAT(name, opcode, w) \
  MSA_3R_FORMAT(name, opcode, d)

#define MSA_3R_SLD_SPLAT(name, opcode)     \
  MSA_3R_FORMAT_SLD_SPLAT(name, opcode, b) \
  MSA_3R_FORMAT_SLD_SPLAT(name, opcode, h) \
  MSA_3R_FORMAT_SLD_SPLAT(name, opcode, w) \
  MSA_3R_FORMAT_SLD_SPLAT(name, opcode, d)

MSA_3R_LIST(MSA_3R)
MSA_3R_SLD_SPLAT(sld, SLD)
MSA_3R_SLD_SPLAT(splat, SPLAT)

#undef MSA_3R
#undef MSA_3R_FORMAT
#undef MSA_3R_FORMAT_SLD_SPLAT
#undef MSA_3R_SLD_SPLAT
#undef MSA_3R_LIST

#define MSA_3RF_LIST1(V) \
  V(fcaf, FCAF)          \
  V(fcun, FCUN)          \
  V(fceq, FCEQ)          \
  V(fcueq, FCUEQ)        \
  V(fclt, FCLT)          \
  V(fcult, FCULT)        \
  V(fcle, FCLE)          \
  V(fcule, FCULE)        \
  V(fsaf, FSAF)          \
  V(fsun, FSUN)          \
  V(fseq, FSEQ)          \
  V(fsueq, FSUEQ)        \
  V(fslt, FSLT)          \
  V(fsult, FSULT)        \
  V(fsle, FSLE)          \
  V(fsule, FSULE)        \
  V(fadd, FADD)          \
  V(fsub, FSUB)          \
  V(fmul, FMUL)          \
  V(fdiv, FDIV)          \
  V(fmadd, FMADD)        \
  V(fmsub, FMSUB)        \
  V(fexp2, FEXP2)        \
  V(fmin, FMIN)          \
  V(fmin_a, FMIN_A)      \
  V(fmax, FMAX)          \
  V(fmax_a, FMAX_A)      \
  V(fcor, FCOR)          \
  V(fcune, FCUNE)        \
  V(fcne, FCNE)          \
  V(fsor, FSOR)          \
  V(fsune, FSUNE)        \
  V(fsne, FSNE)

#define MSA_3RF_LIST2(V) \
  V(fexdo, FEXDO)        \
  V(ftq, FTQ)            \
  V(mul_q, MUL_Q)        \
  V(madd_q, MADD_Q)      \
  V(msub_q, MSUB_Q)      \
  V(mulr_q, MULR_Q)      \
  V(maddr_q, MADDR_Q)    \
  V(msubr_q, MSUBR_Q)

#define MSA_3RF_FORMAT(name, opcode, df, df_c)                \
  void Assembler::name##_##df(MSARegister wd, MSARegister ws, \
                              MSARegister wt) {               \
    GenInstrMsa3RF(opcode, df_c, wt, ws, wd);                 \
  }

#define MSA_3RF_1(name, opcode)      \
  MSA_3RF_FORMAT(name, opcode, w, 0) \
  MSA_3RF_FORMAT(name, opcode, d, 1)

#define MSA_3RF_2(name, opcode)      \
  MSA_3RF_FORMAT(name, opcode, h, 0) \
  MSA_3RF_FORMAT(name, opcode, w, 1)

MSA_3RF_LIST1(MSA_3RF_1)
MSA_3RF_LIST2(MSA_3RF_2)
#undef MSA_3RF_1
#undef MSA_3RF_2
#undef MSA_3RF_FORMAT
#undef MSA_3RF_LIST1
#undef MSA_3RF_LIST2

void Assembler::sldi_b(MSARegister wd, MSARegister ws, uint32_t n) {
  GenInstrMsaElm<MSARegister, MSARegister>(SLDI, ELM_DF_B, n, ws, wd);
}

void Assembler::sldi_h(MSARegister wd, MSARegister ws, uint32_t n) {
  GenInstrMsaElm<MSARegister, MSARegister>(SLDI, ELM_DF_H, n, ws, wd);
}

void Assembler::sldi_w(MSARegister wd, MSARegister ws, uint32_t n) {
  GenInstrMsaElm<MSARegister, MSARegister>(SLDI, ELM_DF_W, n, ws, wd);
}

void Assembler::sldi_d(MSARegister wd, MSARegister ws, uint32_t n) {
  GenInstrMsaElm<MSARegister, MSARegister>(SLDI, ELM_DF_D, n, ws, wd);
}

void Assembler::splati_b(MSARegister wd, MSARegister ws, uint32_t n) {
  GenInstrMsaElm<MSARegister, MSARegister>(SPLATI, ELM_DF_B, n, ws, wd);
}

void Assembler::splati_h(MSARegister wd, MSARegister ws, uint32_t n) {
  GenInstrMsaElm<MSARegister, MSARegister>(SPLATI, ELM_DF_H, n, ws, wd);
}

void Assembler::splati_w(MSARegister wd, MSARegister ws, uint32_t n) {
  GenInstrMsaElm<MSARegister, MSARegister>(SPLATI, ELM_DF_W, n, ws, wd);
}

void Assembler::splati_d(MSARegister wd, MSARegister ws, uint32_t n) {
  GenInstrMsaElm<MSARegister, MSARegister>(SPLATI, ELM_DF_D, n, ws, wd);
}

void Assembler::copy_s_b(Register rd, MSARegister ws, uint32_t n) {
  GenInstrMsaElm<Register, MSARegister>(COPY_S, ELM_DF_B, n, ws, rd);
}

void Assembler::copy_s_h(Register rd, MSARegister ws, uint32_t n) {
  GenInstrMsaElm<Register, MSARegister>(COPY_S, ELM_DF_H, n, ws, rd);
}

void Assembler::copy_s_w(Register rd, MSARegister ws, uint32_t n) {
  GenInstrMsaElm<Register, MSARegister>(COPY_S, ELM_DF_W, n, ws, rd);
}

void Assembler::copy_s_d(Register rd, MSARegister ws, uint32_t n) {
  GenInstrMsaElm<Register, MSARegister>(COPY_S, ELM_DF_D, n, ws, rd);
}

void Assembler::copy_u_b(Register rd, MSARegister ws, uint32_t n) {
  GenInstrMsaElm<Register, MSARegister>(COPY_U, ELM_DF_B, n, ws, rd);
}

void Assembler::copy_u_h(Register rd, MSARegister ws, uint32_t n) {
  GenInstrMsaElm<Register, MSARegister>(COPY_U, ELM_DF_H, n, ws, rd);
}

void Assembler::copy_u_w(Register rd, MSARegister ws, uint32_t n) {
  GenInstrMsaElm<Register, MSARegister>(COPY_U, ELM_DF_W, n, ws, rd);
}

void Assembler::insert_b(MSARegister wd, uint32_t n, Register rs) {
  GenInstrMsaElm<MSARegister, Register>(INSERT, ELM_DF_B, n, rs, wd);
}

void Assembler::insert_h(MSARegister wd, uint32_t n, Register rs) {
  GenInstrMsaElm<MSARegister, Register>(INSERT, ELM_DF_H, n, rs, wd);
}

void Assembler::insert_w(MSARegister wd, uint32_t n, Register rs) {
  GenInstrMsaElm<MSARegister, Register>(INSERT, ELM_DF_W, n, rs, wd);
}

void Assembler::insert_d(MSARegister wd, uint32_t n, Register rs) {
  GenInstrMsaElm<MSARegister, Register>(INSERT, ELM_DF_D, n, rs, wd);
}

void Assembler::insve_b(MSARegister wd, uint32_t n, MSARegister ws) {
  GenInstrMsaElm<MSARegister, MSARegister>(INSVE, ELM_DF_B, n, ws, wd);
}

void Assembler::insve_h(MSARegister wd, uint32_t n, MSARegister ws) {
  GenInstrMsaElm<MSARegister, MSARegister>(INSVE, ELM_DF_H, n, ws, wd);
}

void Assembler::insve_w(MSARegister wd, uint32_t n, MSARegister ws) {
  GenInstrMsaElm<MSARegister, MSARegister>(INSVE, ELM_DF_W, n, ws, wd);
}

void Assembler::insve_d(MSARegister wd, uint32_t n, MSARegister ws) {
  GenInstrMsaElm<MSARegister, MSARegister>(INSVE, ELM_DF_D, n, ws, wd);
}

void Assembler::move_v(MSARegister wd, MSARegister ws) {
  DCHECK(IsEnabled(MIPS_SIMD));
  DCHECK(ws.is_valid() && wd.is_valid());
  Instr instr = MSA | MOVE_V | (ws.code() << kWsShift) |
                (wd.code() << kWdShift) | MSA_ELM_MINOR;
  emit(instr);
}

void Assembler::ctcmsa(MSAControlRegister cd, Register rs) {
  DCHECK(IsEnabled(MIPS_SIMD));
  DCHECK(cd.is_valid() && rs.is_valid());
  Instr instr = MSA | CTCMSA | (rs.code() << kWsShift) |
                (cd.code() << kWdShift) | MSA_ELM_MINOR;
  emit(instr);
}

void Assembler::cfcmsa(Register rd, MSAControlRegister cs) {
  DCHECK(IsEnabled(MIPS_SIMD));
  DCHECK(rd.is_valid() && cs.is_valid());
  Instr instr = MSA | CFCMSA | (cs.code() << kWsShift) |
                (rd.code() << kWdShift) | MSA_ELM_MINOR;
  emit(instr);
}

#define MSA_BIT_LIST(V) \
  V(slli, SLLI)         \
  V(srai, SRAI)         \
  V(srli, SRLI)         \
  V(bclri, BCLRI)       \
  V(bseti, BSETI)       \
  V(bnegi, BNEGI)       \
  V(binsli, BINSLI)     \
  V(binsri, BINSRI)     \
  V(sat_s, SAT_S)       \
  V(sat_u, SAT_U)       \
  V(srari, SRARI)       \
  V(srlri, SRLRI)

#define MSA_BIT_FORMAT(name, opcode, format)                      \
  void Assembler::name##_##format(MSARegister wd, MSARegister ws, \
                                  uint32_t m) {                   \
    GenInstrMsaBit(opcode, BIT_DF_##format, m, ws, wd);           \
  }

#define MSA_BIT(name, opcode)     \
  MSA_BIT_FORMAT(name, opcode, b) \
  MSA_BIT_FORMAT(name, opcode, h) \
  MSA_BIT_FORMAT(name, opcode, w) \
  MSA_BIT_FORMAT(name, opcode, d)

MSA_BIT_LIST(MSA_BIT)
#undef MSA_BIT
#undef MSA_BIT_FORMAT
#undef MSA_BIT_LIST

int Assembler::RelocateInternalReference(
    RelocInfo::Mode rmode, Address pc, intptr_t pc_delta,
    WritableJitAllocation* jit_allocation) {
  if (RelocInfo::IsInternalReference(rmode)) {
    intptr_t internal_ref = ReadUnalignedValue<intptr_t>(pc);
    if (internal_ref == kEndOfJumpChain) {
      return 0;  // Number of instructions patched.
    }
    internal_ref += pc_delta;  // Relocate entry.
    if (jit_allocation) {
      jit_allocation->WriteUnalignedValue<intptr_t>(pc, internal_ref);
    } else {
      WriteUnalignedValue<intptr_t>(pc, internal_ref);
    }
    return 2;  // Number of instructions patched.
  }
  Instr instr = instr_at(pc);
  DCHECK(RelocInfo::IsInternalReferenceEncoded(rmode));
  if (IsLui(instr)) {
    Instr instr_lui = instr_at(pc + 0 * kInstrSize);
    Instr instr_ori = instr_at(pc + 1 * kInstrSize);
    Instr instr_ori2 = instr_at(pc + 3 * kInstrSize);
    DCHECK(IsOri(instr_ori));
    DCHECK(IsOri(instr_ori2));
    // TODO(plind): symbolic names for the shifts.
    int64_t imm = (instr_lui & static_cast<int64_t>(kImm16Mask)) << 48;
    imm |= (instr_ori & static_cast<int64_t>(kImm16Mask)) << 32;
    imm |= (instr_ori2 & static_cast<int64_t>(kImm16Mask)) << 16;
    // Sign extend address.
    imm >>= 16;

    if (imm == kEndOfJumpChain) {
      return 0;  // Number of instructions patched.
    }
    imm += pc_delta;
    DCHECK_EQ(imm & 3, 0);

    instr_lui &= ~kImm16Mask;
    instr_ori &= ~kImm16Mask;
    instr_ori2 &= ~kImm16Mask;

    instr_at_put(pc + 0 * kInstrSize, instr_lui | ((imm >> 32) & kImm16Mask),
                 jit_allocation);
    instr_at_put(pc + 1 * kInstrSize, instr_ori | (imm >> 16 & kImm16Mask),
                 jit_allocation);
    instr_at_put(pc + 3 * kInstrSize, instr_ori2 | (imm & kImm16Mask),
                 jit_allocation);
    return 4;  // Number of instructions patched.
  } else if (IsJ(instr) || IsJal(instr)) {
    // Regular j/jal relocation.
    uint32_t imm28 = (instr & static_cast<int32_t>(kImm26Mask)) << 2;
    imm28 += pc_delta;
    imm28 &= kImm28Mask;
    instr &= ~kImm26Mask;
    DCHECK_EQ(imm28 & 3, 0);
    uint32_t imm26 = static_cast<uint32_t>(imm28 >> 2);
    instr_at_put(pc, instr | (imm26 & kImm26Mask), jit_allocation);
    return 1;  // Number of instructions patched.
  } else {
    DCHECK(((instr & kJumpRawMask) == kJRawMark) ||
           ((instr & kJumpRawMask) == kJalRawMark));
    // Unbox raw offset and emit j/jal.
    int32_t imm28 = (instr & static_cast<int32_t>(kImm26Mask)) << 2;
    // Sign extend 28-bit offset to 32-bit.
    imm28 = (imm28 << 4) >> 4;
    uint64_t target =
        static_cast<int64_t>(imm28) + reinterpret_cast<uint64_t>(pc);
    target &= kImm28Mask;
    DCHECK_EQ(imm28 & 3, 0);
    uint32_t imm26 = static_cast<uint32_t>(target >> 2);
    // Check markings whether to emit j or jal.
    uint32_t unbox = (instr & kJRawMark) ? J : JAL;
    instr_at_put(pc, unbox | (imm26 & kImm26Mask), jit_allocation);
    return 1;  // Number of instructions patched.
  }
}

void Assembler::GrowBuffer() {
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
  pc_ += pc_delta;
  pc_for_safepoint_ += pc_delta;
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
  CheckForEmitInForbiddenSlot();
  *reinterpret_cast<uint8_t*>(pc_) = data;
  pc_ += sizeof(uint8_t);
}

void Assembler::dd(uint32_t data) {
  CheckForEmitInForbiddenSlot();
  *reinterpret_cast<uint32_t*>(pc_) = data;
  pc_ += sizeof(uint32_t);
}

void Assembler::dq(uint64_t data) {
  CheckForEmitInForbiddenSlot();
  *reinterpret_cast<uint64_t*>(pc_) = data;
  pc_ += sizeof(uint64_t);
}

void Assembler::dd(Label* label) {
  uint64_t data;
  CheckForEmitInForbiddenSlot();
  if (label->is_bound()) {
    data = reinterpret_cast<uint64_t>(buffer_start_ + label->pos());
  } else {
    data = jump_address(label);
    unbound_labels_count_++;
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
  CheckTrampolinePoolQuick(instructions);
  BlockTrampolinePoolBefore(pc_offset() + instructions * kInstrSize);
}

void Assembler::CheckTrampolinePool() {
  // Some small sequences of instructions must not be broken up by the
  // insertion of a trampoline pool; such sequences are protected by setting
  // either trampoline_pool_blocked_nesting_ or no_trampoline_pool_before_,
  // which are both checked here. Also, recursive calls to CheckTrampolinePool
  // are blocked by trampoline_pool_blocked_nesting_.
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
    // First we emit jump (2 instructions), then we emit trampoline pool.
    {
      BlockTrampolinePoolScope block_trampoline_pool(this);
      Label after_pool;
      if (kArchVariant == kMips64r6) {
        bc(&after_pool);
      } else {
        b(&after_pool);
      }
      nop();

      int pool_start = pc_offset();
      for (int i = 0; i < unbound_labels_count_; i++) {
        {
          if (kArchVariant == kMips64r6) {
            bc(&after_pool);
            nop();
          } else {
            or_(t8, ra, zero_reg);
            nal();       // Read PC into ra register.
            lui(t9, 0);  // Branch delay slot.
            ori(t9, t9, 0);
            daddu(t9, ra, t9);
            or_(ra, t8, zero_reg);
            // Instruction jr will take or_ from the next trampoline.
            // in its branch delay slot. This is the expected behavior
            // in order to decrease size of trampoline pool.
            jr(t9);
          }
        }
      }
      nop();
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
    // Number of branches t
```