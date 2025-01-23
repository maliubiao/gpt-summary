Response:

### 提示词
```
这是目录为v8/src/execution/arm64/simulator-arm64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/execution/arm64/simulator-arm64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共7部分，请归纳一下它的功能
```

### 源代码
```cpp
", 0x%016" PRIx64 ", 0x%016" PRIx64 ", 0x%016" PRIx64,
          arg0, arg1, arg2, arg3);
      double result = target(arg0, arg1, arg2, arg3);
      TraceSim("Returned: %f\n", result);
#ifdef DEBUG
      CorruptAllCallerSavedCPURegisters();
#endif
      set_dreg(0, result);
      break;
    }

    case ExternalReference::DIRECT_API_CALL: {
      // void f(v8::FunctionCallbackInfo&)
      TraceSim("Type: DIRECT_API_CALL\n");
      TraceSim("Arguments: 0x%016" PRIx64 "\n", arg0);
      SimulatorRuntimeDirectApiCall target =
          reinterpret_cast<SimulatorRuntimeDirectApiCall>(external);
      target(arg0);
      TraceSim("No return value.");
#ifdef DEBUG
      CorruptAllCallerSavedCPURegisters();
#endif
      break;
    }

    case ExternalReference::DIRECT_GETTER_CALL: {
      // void f(v8::Local<String> property, v8::PropertyCallbackInfo& info)
      TraceSim("Type: DIRECT_GETTER_CALL\n");
      TraceSim("Arguments: 0x%016" PRIx64 ", 0x%016" PRIx64 "\n", arg0, arg1);
      SimulatorRuntimeDirectGetterCall target =
          reinterpret_cast<SimulatorRuntimeDirectGetterCall>(external);
      target(arg0, arg1);
      TraceSim("No return value.");
#ifdef DEBUG
      CorruptAllCallerSavedCPURegisters();
#endif
      break;
    }
  }

  set_lr(return_address);
  set_pc(return_address);
}

const char* Simulator::xreg_names[] = {
    "x0",  "x1",  "x2",  "x3",  "x4",  "x5",  "x6",  "x7",  "x8",  "x9",  "x10",
    "x11", "x12", "x13", "x14", "x15", "ip0", "ip1", "x18", "x19", "x20", "x21",
    "x22", "x23", "x24", "x25", "x26", "cp",  "x28", "fp",  "lr",  "xzr", "sp"};

const char* Simulator::wreg_names[] = {
    "w0",  "w1",  "w2",  "w3",  "w4",  "w5",  "w6",  "w7",  "w8",
    "w9",  "w10", "w11", "w12", "w13", "w14", "w15", "w16", "w17",
    "w18", "w19", "w20", "w21", "w22", "w23", "w24", "w25", "w26",
    "wcp", "w28", "wfp", "wlr", "wzr", "wsp"};

const char* Simulator::sreg_names[] = {
    "s0",  "s1",  "s2",  "s3",  "s4",  "s5",  "s6",  "s7",  "s8",  "s9",  "s10",
    "s11", "s12", "s13", "s14", "s15", "s16", "s17", "s18", "s19", "s20", "s21",
    "s22", "s23", "s24", "s25", "s26", "s27", "s28", "s29", "s30", "s31"};

const char* Simulator::dreg_names[] = {
    "d0",  "d1",  "d2",  "d3",  "d4",  "d5",  "d6",  "d7",  "d8",  "d9",  "d10",
    "d11", "d12", "d13", "d14", "d15", "d16", "d17", "d18", "d19", "d20", "d21",
    "d22", "d23", "d24", "d25", "d26", "d27", "d28", "d29", "d30", "d31"};

const char* Simulator::vreg_names[] = {
    "v0",  "v1",  "v2",  "v3",  "v4",  "v5",  "v6",  "v7",  "v8",  "v9",  "v10",
    "v11", "v12", "v13", "v14", "v15", "v16", "v17", "v18", "v19", "v20", "v21",
    "v22", "v23", "v24", "v25", "v26", "v27", "v28", "v29", "v30", "v31"};

const char* Simulator::WRegNameForCode(unsigned code, Reg31Mode mode) {
  static_assert(arraysize(Simulator::wreg_names) == (kNumberOfRegisters + 1),
                "Array must be large enough to hold all register names.");
  DCHECK_LT(code, static_cast<unsigned>(kNumberOfRegisters));
  // The modulo operator has no effect here, but it silences a broken GCC
  // warning about out-of-bounds array accesses.
  code %= kNumberOfRegisters;

  // If the code represents the stack pointer, index the name after zr.
  if ((code == kZeroRegCode) && (mode == Reg31IsStackPointer)) {
    code = kZeroRegCode + 1;
  }
  return wreg_names[code];
}

const char* Simulator::XRegNameForCode(unsigned code, Reg31Mode mode) {
  static_assert(arraysize(Simulator::xreg_names) == (kNumberOfRegisters + 1),
                "Array must be large enough to hold all register names.");
  DCHECK_LT(code, static_cast<unsigned>(kNumberOfRegisters));
  code %= kNumberOfRegisters;

  // If the code represents the stack pointer, index the name after zr.
  if ((code == kZeroRegCode) && (mode == Reg31IsStackPointer)) {
    code = kZeroRegCode + 1;
  }
  return xreg_names[code];
}

const char* Simulator::SRegNameForCode(unsigned code) {
  static_assert(arraysize(Simulator::sreg_names) == kNumberOfVRegisters,
                "Array must be large enough to hold all register names.");
  DCHECK_LT(code, static_cast<unsigned>(kNumberOfVRegisters));
  return sreg_names[code % kNumberOfVRegisters];
}

const char* Simulator::DRegNameForCode(unsigned code) {
  static_assert(arraysize(Simulator::dreg_names) == kNumberOfVRegisters,
                "Array must be large enough to hold all register names.");
  DCHECK_LT(code, static_cast<unsigned>(kNumberOfVRegisters));
  return dreg_names[code % kNumberOfVRegisters];
}

const char* Simulator::VRegNameForCode(unsigned code) {
  static_assert(arraysize(Simulator::vreg_names) == kNumberOfVRegisters,
                "Array must be large enough to hold all register names.");
  DCHECK_LT(code, static_cast<unsigned>(kNumberOfVRegisters));
  return vreg_names[code % kNumberOfVRegisters];
}

void LogicVRegister::ReadUintFromMem(VectorFormat vform, int index,
                                     uint64_t addr) const {
  switch (LaneSizeInBitsFromFormat(vform)) {
    case 8:
      register_.Insert(index, SimMemory::Read<uint8_t>(addr));
      break;
    case 16:
      register_.Insert(index, SimMemory::Read<uint16_t>(addr));
      break;
    case 32:
      register_.Insert(index, SimMemory::Read<uint32_t>(addr));
      break;
    case 64:
      register_.Insert(index, SimMemory::Read<uint64_t>(addr));
      break;
    default:
      UNREACHABLE();
  }
}

void LogicVRegister::WriteUintToMem(VectorFormat vform, int index,
                                    uint64_t addr) const {
  switch (LaneSizeInBitsFromFormat(vform)) {
    case 8:
      SimMemory::Write<uint8_t>(addr, static_cast<uint8_t>(Uint(vform, index)));
      break;
    case 16:
      SimMemory::Write<uint16_t>(addr,
                                 static_cast<uint16_t>(Uint(vform, index)));
      break;
    case 32:
      SimMemory::Write<uint32_t>(addr,
                                 static_cast<uint32_t>(Uint(vform, index)));
      break;
    case 64:
      SimMemory::Write<uint64_t>(addr, Uint(vform, index));
      break;
    default:
      UNREACHABLE();
  }
}

int Simulator::CodeFromName(const char* name) {
  for (unsigned i = 0; i < kNumberOfRegisters; i++) {
    if ((strcmp(xreg_names[i], name) == 0) ||
        (strcmp(wreg_names[i], name) == 0)) {
      return i;
    }
  }
  for (unsigned i = 0; i < kNumberOfVRegisters; i++) {
    if ((strcmp(vreg_names[i], name) == 0) ||
        (strcmp(dreg_names[i], name) == 0) ||
        (strcmp(sreg_names[i], name) == 0)) {
      return i;
    }
  }
  if ((strcmp("sp", name) == 0) || (strcmp("wsp", name) == 0)) {
    return kSPRegInternalCode;
  }
  if (strcmp("x16", name) == 0) return CodeFromName("ip0");
  if (strcmp("x17", name) == 0) return CodeFromName("ip1");
  if (strcmp("x29", name) == 0) return CodeFromName("fp");
  if (strcmp("x30", name) == 0) return CodeFromName("lr");
  return -1;
}

// Helpers ---------------------------------------------------------------------
template <typename T>
T Simulator::AddWithCarry(bool set_flags, T left, T right, int carry_in) {
  // Use unsigned types to avoid implementation-defined overflow behaviour.
  static_assert(std::is_unsigned<T>::value, "operands must be unsigned");
  static_assert((sizeof(T) == kWRegSize) || (sizeof(T) == kXRegSize),
                "Only W- or X-sized operands are tested");

  DCHECK((carry_in == 0) || (carry_in == 1));
  T result = left + right + carry_in;

  if (set_flags) {
    nzcv().SetN(CalcNFlag(result));
    nzcv().SetZ(CalcZFlag(result));

    // Compute the C flag by comparing the result to the max unsigned integer.
    T max_uint_2op = std::numeric_limits<T>::max() - carry_in;
    nzcv().SetC((left > max_uint_2op) || ((max_uint_2op - left) < right));

    // Overflow iff the sign bit is the same for the two inputs and different
    // for the result.
    T sign_mask = T(1) << (sizeof(T) * 8 - 1);
    T left_sign = left & sign_mask;
    T right_sign = right & sign_mask;
    T result_sign = result & sign_mask;
    nzcv().SetV((left_sign == right_sign) && (left_sign != result_sign));

    LogSystemRegister(NZCV);
  }
  return result;
}

template <typename T>
void Simulator::AddSubWithCarry(Instruction* instr) {
  // Use unsigned types to avoid implementation-defined overflow behaviour.
  static_assert(std::is_unsigned<T>::value, "operands must be unsigned");

  T op2 = reg<T>(instr->Rm());
  T new_val;

  if ((instr->Mask(AddSubOpMask) == SUB) || instr->Mask(AddSubOpMask) == SUBS) {
    op2 = ~op2;
  }

  new_val = AddWithCarry<T>(instr->FlagsUpdate(), reg<T>(instr->Rn()), op2,
                            nzcv().C());

  set_reg<T>(instr->Rd(), new_val);
}

sim_uint128_t Simulator::PolynomialMult128(uint64_t op1, uint64_t op2,
                                           int lane_size_in_bits) const {
  DCHECK_LE(static_cast<unsigned>(lane_size_in_bits), kDRegSizeInBits);
  sim_uint128_t result = std::make_pair(0, 0);
  sim_uint128_t op2q = std::make_pair(0, op2);
  for (int i = 0; i < lane_size_in_bits; i++) {
    if ((op1 >> i) & 1) {
      result = Eor128(result, Lsl128(op2q, i));
    }
  }
  return result;
}

sim_uint128_t Simulator::Lsl128(sim_uint128_t x, unsigned shift) const {
  DCHECK_LE(shift, 64);
  if (shift == 0) return x;
  if (shift == 64) return std::make_pair(x.second, 0);
  uint64_t lo = x.second << shift;
  uint64_t hi = (x.first << shift) | (x.second >> (64 - shift));
  return std::make_pair(hi, lo);
}

sim_uint128_t Simulator::Eor128(sim_uint128_t x, sim_uint128_t y) const {
  return std::make_pair(x.first ^ y.first, x.second ^ y.second);
}

template <typename T>
T Simulator::ShiftOperand(T value, Shift shift_type, unsigned amount) {
  using unsignedT = typename std::make_unsigned<T>::type;

  if (amount == 0) {
    return value;
  }
  // Larger shift {amount}s would be undefined behavior in C++.
  DCHECK(amount < sizeof(value) * kBitsPerByte);

  switch (shift_type) {
    case LSL:
      return static_cast<unsignedT>(value) << amount;
    case LSR:
      return static_cast<unsignedT>(value) >> amount;
    case ASR:
      return value >> amount;
    case ROR: {
      unsignedT mask = (static_cast<unsignedT>(1) << amount) - 1;
      return (static_cast<unsignedT>(value) >> amount) |
             ((value & mask) << (sizeof(mask) * 8 - amount));
    }
    default:
      UNIMPLEMENTED();
      return 0;
  }
}

template <typename T>
T Simulator::ExtendValue(T value, Extend extend_type, unsigned left_shift) {
  const unsigned kSignExtendBShift = (sizeof(T) - 1) * 8;
  const unsigned kSignExtendHShift = (sizeof(T) - 2) * 8;
  const unsigned kSignExtendWShift = (sizeof(T) - 4) * 8;
  using unsignedT = typename std::make_unsigned<T>::type;

  switch (extend_type) {
    case UXTB:
      value &= kByteMask;
      break;
    case UXTH:
      value &= kHalfWordMask;
      break;
    case UXTW:
      value &= kWordMask;
      break;
    case SXTB:
      value =
          static_cast<T>(static_cast<unsignedT>(value) << kSignExtendBShift) >>
          kSignExtendBShift;
      break;
    case SXTH:
      value =
          static_cast<T>(static_cast<unsignedT>(value) << kSignExtendHShift) >>
          kSignExtendHShift;
      break;
    case SXTW:
      value =
          static_cast<T>(static_cast<unsignedT>(value) << kSignExtendWShift) >>
          kSignExtendWShift;
      break;
    case UXTX:
    case SXTX:
      break;
    default:
      UNREACHABLE();
  }
  return static_cast<T>(static_cast<unsignedT>(value) << left_shift);
}

template <typename T>
void Simulator::Extract(Instruction* instr) {
  unsigned lsb = instr->ImmS();
  T op2 = reg<T>(instr->Rm());
  T result = op2;

  if (lsb) {
    T op1 = reg<T>(instr->Rn());
    result = op2 >> lsb | (op1 << ((sizeof(T) * 8) - lsb));
  }
  set_reg<T>(instr->Rd(), result);
}

void Simulator::FPCompare(double val0, double val1) {
  AssertSupportedFPCR();

  // TODO(jbramley): This assumes that the C++ implementation handles
  // comparisons in the way that we expect (as per AssertSupportedFPCR()).
  if ((std::isnan(val0) != 0) || (std::isnan(val1) != 0)) {
    nzcv().SetRawValue(FPUnorderedFlag);
  } else if (val0 < val1) {
    nzcv().SetRawValue(FPLessThanFlag);
  } else if (val0 > val1) {
    nzcv().SetRawValue(FPGreaterThanFlag);
  } else if (val0 == val1) {
    nzcv().SetRawValue(FPEqualFlag);
  } else {
    UNREACHABLE();
  }
  LogSystemRegister(NZCV);
}

Simulator::PrintRegisterFormat Simulator::GetPrintRegisterFormatForSize(
    size_t reg_size, size_t lane_size) {
  DCHECK_GE(reg_size, lane_size);

  uint32_t format = 0;
  if (reg_size != lane_size) {
    switch (reg_size) {
      default:
        UNREACHABLE();
      case kQRegSize:
        format = kPrintRegAsQVector;
        break;
      case kDRegSize:
        format = kPrintRegAsDVector;
        break;
    }
  }

  switch (lane_size) {
    default:
      UNREACHABLE();
    case kQRegSize:
      format |= kPrintReg1Q;
      break;
    case kDRegSize:
      format |= kPrintReg1D;
      break;
    case kSRegSize:
      format |= kPrintReg1S;
      break;
    case kHRegSize:
      format |= kPrintReg1H;
      break;
    case kBRegSize:
      format |= kPrintReg1B;
      break;
  }

  // These sizes would be duplicate case labels.
  static_assert(kXRegSize == kDRegSize, "X and D registers must be same size.");
  static_assert(kWRegSize == kSRegSize, "W and S registers must be same size.");
  static_assert(kPrintXReg == kPrintReg1D,
                "X and D register printing code is shared.");
  static_assert(kPrintWReg == kPrintReg1S,
                "W and S register printing code is shared.");

  return static_cast<PrintRegisterFormat>(format);
}

Simulator::PrintRegisterFormat Simulator::GetPrintRegisterFormat(
    VectorFormat vform) {
  switch (vform) {
    default:
      UNREACHABLE();
    case kFormat16B:
      return kPrintReg16B;
    case kFormat8B:
      return kPrintReg8B;
    case kFormat8H:
      return kPrintReg8H;
    case kFormat4H:
      return kPrintReg4H;
    case kFormat4S:
      return kPrintReg4S;
    case kFormat2S:
      return kPrintReg2S;
    case kFormat2D:
      return kPrintReg2D;
    case kFormat1D:
      return kPrintReg1D;

    case kFormatB:
      return kPrintReg1B;
    case kFormatH:
      return kPrintReg1H;
    case kFormatS:
      return kPrintReg1S;
    case kFormatD:
      return kPrintReg1D;
  }
}

Simulator::PrintRegisterFormat Simulator::GetPrintRegisterFormatFP(
    VectorFormat vform) {
  switch (vform) {
    default:
      UNREACHABLE();
    case kFormat4S:
      return kPrintReg4SFP;
    case kFormat2S:
      return kPrintReg2SFP;
    case kFormat2D:
      return kPrintReg2DFP;
    case kFormat1D:
      return kPrintReg1DFP;

    case kFormatS:
      return kPrintReg1SFP;
    case kFormatD:
      return kPrintReg1DFP;
  }
}

void Simulator::SetBreakpoint(Instruction* location) {
  for (unsigned i = 0; i < breakpoints_.size(); i++) {
    if (breakpoints_.at(i).location == location) {
      PrintF(stream_, "Existing breakpoint at %p was %s\n",
             reinterpret_cast<void*>(location),
             breakpoints_.at(i).enabled ? "disabled" : "enabled");
      breakpoints_.at(i).enabled = !breakpoints_.at(i).enabled;
      return;
    }
  }
  Breakpoint new_breakpoint = {location, true};
  breakpoints_.push_back(new_breakpoint);
  PrintF(stream_, "Set a breakpoint at %p\n",
         reinterpret_cast<void*>(location));
}

void Simulator::ListBreakpoints() {
  PrintF(stream_, "Breakpoints:\n");
  for (unsigned i = 0; i < breakpoints_.size(); i++) {
    PrintF(stream_, "%p  : %s\n",
           reinterpret_cast<void*>(breakpoints_.at(i).location),
           breakpoints_.at(i).enabled ? "enabled" : "disabled");
  }
}

void Simulator::CheckBreakpoints() {
  bool hit_a_breakpoint = false;
  for (unsigned i = 0; i < breakpoints_.size(); i++) {
    if ((breakpoints_.at(i).location == pc_) && breakpoints_.at(i).enabled) {
      hit_a_breakpoint = true;
      // Disable this breakpoint.
      breakpoints_.at(i).enabled = false;
    }
  }
  if (hit_a_breakpoint) {
    PrintF(stream_, "Hit and disabled a breakpoint at %p.\n",
           reinterpret_cast<void*>(pc_));
    Debug();
  }
}

void Simulator::CheckBreakNext() {
  // If the current instruction is a BL, insert a breakpoint just after it.
  if (break_on_next_ && pc_->IsBranchAndLinkToRegister()) {
    SetBreakpoint(pc_->following());
    break_on_next_ = false;
  }
}

void Simulator::PrintInstructionsAt(Instruction* start, uint64_t count) {
  Instruction* end = start->InstructionAtOffset(count * kInstrSize);
  for (Instruction* pc = start; pc < end; pc = pc->following()) {
    disassembler_decoder_->Decode(pc);
  }
}

void Simulator::PrintWrittenRegisters() {
  for (unsigned i = 0; i < kNumberOfRegisters; i++) {
    if (registers_[i].WrittenSinceLastLog()) PrintRegister(i);
  }
}

void Simulator::PrintWrittenVRegisters() {
  for (unsigned i = 0; i < kNumberOfVRegisters; i++) {
    // At this point there is no type information, so print as a raw 1Q.
    if (vregisters_[i].WrittenSinceLastLog()) PrintVRegister(i, kPrintReg1Q);
  }
}

void Simulator::PrintSystemRegisters() {
  PrintSystemRegister(NZCV);
  PrintSystemRegister(FPCR);
}

void Simulator::PrintRegisters() {
  for (unsigned i = 0; i < kNumberOfRegisters; i++) {
    PrintRegister(i);
  }
}

void Simulator::PrintVRegisters() {
  for (unsigned i = 0; i < kNumberOfVRegisters; i++) {
    // At this point there is no type information, so print as a raw 1Q.
    PrintVRegister(i, kPrintReg1Q);
  }
}

void Simulator::PrintRegister(unsigned code, Reg31Mode r31mode) {
  registers_[code].NotifyRegisterLogged();

  // Don't print writes into xzr.
  if ((code == kZeroRegCode) && (r31mode == Reg31IsZeroRegister)) {
    return;
  }

  // The template for all x and w registers:
  //   "# x{code}: 0x{value}"
  //   "# w{code}: 0x{value}"

  PrintRegisterRawHelper(code, r31mode);
  fprintf(stream_, "\n");
}

// Print a register's name and raw value.
//
// The `bytes` and `lsb` arguments can be used to limit the bytes that are
// printed. These arguments are intended for use in cases where register hasn't
// actually been updated (such as in PrintVWrite).
//
// No newline is printed. This allows the caller to print more details (such as
// a floating-point interpretation or a memory access annotation).
void Simulator::PrintVRegisterRawHelper(unsigned code, int bytes, int lsb) {
  // The template for vector types:
  //   "# v{code}: 0xFFEEDDCCBBAA99887766554433221100".
  // An example with bytes=4 and lsb=8:
  //   "# v{code}:         0xBBAA9988                ".
  fprintf(stream_, "# %s%5s: %s", clr_vreg_name, VRegNameForCode(code),
          clr_vreg_value);

  int msb = lsb + bytes - 1;
  int byte = kQRegSize - 1;

  // Print leading padding spaces. (Two spaces per byte.)
  while (byte > msb) {
    fprintf(stream_, "  ");
    byte--;
  }

  // Print the specified part of the value, byte by byte.
  qreg_t rawbits = qreg(code);
  fprintf(stream_, "0x");
  while (byte >= lsb) {
    fprintf(stream_, "%02x", rawbits.val[byte]);
    byte--;
  }

  // Print trailing padding spaces.
  while (byte >= 0) {
    fprintf(stream_, "  ");
    byte--;
  }
  fprintf(stream_, "%s", clr_normal);
}

// Print each of the specified lanes of a register as a float or double value.
//
// The `lane_count` and `lslane` arguments can be used to limit the lanes that
// are printed. These arguments are intended for use in cases where register
// hasn't actually been updated (such as in PrintVWrite).
//
// No newline is printed. This allows the caller to print more details (such as
// a memory access annotation).
void Simulator::PrintVRegisterFPHelper(unsigned code,
                                       unsigned lane_size_in_bytes,
                                       int lane_count, int rightmost_lane) {
  DCHECK((lane_size_in_bytes == kSRegSize) ||
         (lane_size_in_bytes == kDRegSize));

  unsigned msb = (lane_count + rightmost_lane) * lane_size_in_bytes;
  DCHECK_LE(msb, static_cast<unsigned>(kQRegSize));

  // For scalar types ((lane_count == 1) && (rightmost_lane == 0)), a register
  // name is used:
  //   " (s{code}: {value})"
  //   " (d{code}: {value})"
  // For vector types, "..." is used to represent one or more omitted lanes.
  //   " (..., {value}, {value}, ...)"
  if ((lane_count == 1) && (rightmost_lane == 0)) {
    const char* name = (lane_size_in_bytes == kSRegSize)
                           ? SRegNameForCode(code)
                           : DRegNameForCode(code);
    fprintf(stream_, " (%s%s: ", clr_vreg_name, name);
  } else {
    if (msb < (kQRegSize - 1)) {
      fprintf(stream_, " (..., ");
    } else {
      fprintf(stream_, " (");
    }
  }

  // Print the list of values.
  const char* separator = "";
  int leftmost_lane = rightmost_lane + lane_count - 1;
  for (int lane = leftmost_lane; lane >= rightmost_lane; lane--) {
    double value = (lane_size_in_bytes == kSRegSize)
                       ? vreg(code).Get<float>(lane)
                       : vreg(code).Get<double>(lane);
    fprintf(stream_, "%s%s%#g%s", separator, clr_vreg_value, value, clr_normal);
    separator = ", ";
  }

  if (rightmost_lane > 0) {
    fprintf(stream_, ", ...");
  }
  fprintf(stream_, ")");
}

// Print a register's name and raw value.
//
// Only the least-significant `size_in_bytes` bytes of the register are printed,
// but the value is aligned as if the whole register had been printed.
//
// For typical register updates, size_in_bytes should be set to kXRegSize
// -- the default -- so that the whole register is printed. Other values of
// size_in_bytes are intended for use when the register hasn't actually been
// updated (such as in PrintWrite).
//
// No newline is printed. This allows the caller to print more details (such as
// a memory access annotation).
void Simulator::PrintRegisterRawHelper(unsigned code, Reg31Mode r31mode,
                                       int size_in_bytes) {
  // The template for all supported sizes.
  //   "# x{code}: 0xFFEEDDCCBBAA9988"
  //   "# w{code}:         0xBBAA9988"
  //   "# w{code}<15:0>:       0x9988"
  //   "# w{code}<7:0>:          0x88"
  unsigned padding_chars = (kXRegSize - size_in_bytes) * 2;

  const char* name = "";
  const char* suffix = "";
  switch (size_in_bytes) {
    case kXRegSize:
      name = XRegNameForCode(code, r31mode);
      break;
    case kWRegSize:
      name = WRegNameForCode(code, r31mode);
      break;
    case 2:
      name = WRegNameForCode(code, r31mode);
      suffix = "<15:0>";
      padding_chars -= strlen(suffix);
      break;
    case 1:
      name = WRegNameForCode(code, r31mode);
      suffix = "<7:0>";
      padding_chars -= strlen(suffix);
      break;
    default:
      UNREACHABLE();
  }
  fprintf(stream_, "# %s%5s%s: ", clr_reg_name, name, suffix);

  // Print leading padding spaces.
  DCHECK_LT(padding_chars, kXRegSize * 2U);
  for (unsigned i = 0; i < padding_chars; i++) {
    putc(' ', stream_);
  }

  // Print the specified bits in hexadecimal format.
  uint64_t bits = reg<uint64_t>(code, r31mode);
  bits &= kXRegMask >> ((kXRegSize - size_in_bytes) * 8);
  static_assert(sizeof(bits) == kXRegSize,
                "X registers and uint64_t must be the same size.");

  int chars = size_in_bytes * 2;
  fprintf(stream_, "%s0x%0*" PRIx64 "%s", clr_reg_value, chars, bits,
          clr_normal);
}

void Simulator::PrintVRegister(unsigned code, PrintRegisterFormat format) {
  vregisters_[code].NotifyRegisterLogged();

  int lane_size_log2 = format & kPrintRegLaneSizeMask;

  int reg_size_log2;
  if (format & kPrintRegAsQVector) {
    reg_size_log2 = kQRegSizeLog2;
  } else if (format & kPrintRegAsDVector) {
    reg_size_log2 = kDRegSizeLog2;
  } else {
    // Scalar types.
    reg_size_log2 = lane_size_log2;
  }

  int lane_count = 1 << (reg_size_log2 - lane_size_log2);
  int lane_size = 1 << lane_size_log2;

  // The template for vector types:
  //   "# v{code}: 0x{rawbits} (..., {value}, ...)".
  // The template for scalar types:
  //   "# v{code}: 0x{rawbits} ({reg}:{value})".
  // The values in parentheses after the bit representations are floating-point
  // interpretations. They are displayed only if the kPrintVRegAsFP bit is set.

  PrintVRegisterRawHelper(code);
  if (format & kPrintRegAsFP) {
    PrintVRegisterFPHelper(code, lane_size, lane_count);
  }

  fprintf(stream_, "\n");
}

void Simulator::PrintSystemRegister(SystemRegister id) {
  switch (id) {
    case NZCV:
      fprintf(stream_, "# %sNZCV: %sN:%d Z:%d C:%d V:%d%s\n", clr_flag_name,
              clr_flag_value, nzcv().N(), nzcv().Z(), nzcv().C(), nzcv().V(),
              clr_normal);
      break;
    case FPCR: {
      static const char* rmode[] = {
          "0b00 (Round to Nearest)", "0b01 (Round towards Plus Infinity)",
          "0b10 (Round towards Minus Infinity)", "0b11 (Round towards Zero)"};
      DCHECK(fpcr().RMode() < arraysize(rmode));
      fprintf(stream_, "# %sFPCR: %sAHP:%d DN:%d FZ:%d RMode:%s%s\n",
              clr_flag_name, clr_flag_value, fpcr().AHP(), fpcr().DN(),
              fpcr().FZ(), rmode[fpcr().RMode()], clr_normal);
      break;
    }
    default:
      UNREACHABLE();
  }
}

void Simulator::PrintRead(uintptr_t address, unsigned reg_code,
                          PrintRegisterFormat format) {
  registers_[reg_code].NotifyRegisterLogged();

  USE(format);

  // The template is "# {reg}: 0x{value} <- {address}".
  PrintRegisterRawHelper(reg_code, Reg31IsZeroRegister);
  fprintf(stream_, " <- %s0x%016" PRIxPTR "%s\n", clr_memory_address, address,
          clr_normal);
}

void Simulator::PrintVRead(uintptr_t address, unsigned reg_code,
                           PrintRegisterFormat format, unsigned lane) {
  vregisters_[reg_code].NotifyRegisterLogged();

  // The template is "# v{code}: 0x{rawbits} <- address".
  PrintVRegisterRawHelper(reg_code);
  if (format & kPrintRegAsFP) {
    PrintVRegisterFPHelper(reg_code, GetPrintRegLaneSizeInBytes(format),
                           GetPrintRegLaneCount(format), lane);
  }
  fprintf(stream_, " <- %s0x%016" PRIxPTR "%s\n", clr_memory_address, address,
          clr_normal);
}

void Simulator::PrintWrite(uintptr_t address, unsigned reg_code,
                           PrintRegisterFormat format) {
  DCHECK_EQ(GetPrintRegLaneCount(format), 1U);

  // The template is "# v{code}: 0x{value} -> {address}". To keep the trace tidy
  // and readable, the value is aligned with the values in the register trace.
  PrintRegisterRawHelper(reg_code, Reg31IsZeroRegister,
                         GetPrintRegSizeInBytes(format));
  fprintf(stream_, " -> %s0x%016" PRIxPTR "%s\n", clr_memory_address, address,
          clr_normal);
}

void Simulator::PrintVWrite(uintptr_t address, unsigned reg_code,
                            PrintRegisterFormat format, unsigned lane) {
  // The templates:
  //   "# v{code}: 0x{rawbits} -> {address}"
  //   "# v{code}: 0x{rawbits} (..., {value}, ...) -> {address}".
  //   "# v{code}: 0x{rawbits} ({reg}:{value}) -> {address}"
  // Because this trace doesn't represent a change to the source register's
  // value, only the relevant part of the value is printed. To keep the trace
  // tidy and readable, the raw value is aligned with the other values in the
  // register trace.
  int lane_count = GetPrintRegLaneCount(format);
  int lane_size = GetPrintRegLaneSizeInBytes(format);
  int reg_size = GetPrintRegSizeInBytes(format);
  PrintVRegisterRawHelper(reg_code, reg_size, lane_size * lane);
  if (format & kPrintRegAsFP) {
    PrintVRegisterFPHelper(reg_code, lane_size, lane_count, lane);
  }
  fprintf(stream_, " -> %s0x%016" PRIxPTR "%s\n", clr_memory_address, address,
          clr_normal);
}

// Visitors---------------------------------------------------------------------

void Simulator::VisitUnimplemented(Instruction* instr) {
  fprintf(stream_, "Unimplemented instruction at %p: 0x%08" PRIx32 "\n",
          reinterpret_cast<void*>(instr), instr->InstructionBits());
  UNIMPLEMENTED();
}

void Simulator::VisitUnallocated(Instruction* instr) {
  fprintf(stream_, "Unallocated instruction at %p: 0x%08" PRIx32 "\n",
          reinterpret_cast<void*>(instr), instr->InstructionBits());
  UNIMPLEMENTED();
}

void Simulator::VisitPCRelAddressing(Instruction* instr) {
  switch (instr->Mask(PCRelAddressingMask)) {
    case ADR:
      set_reg(instr->Rd(), instr->ImmPCOffsetTarget());
      break;
    case ADRP:  // Not implemented in the assembler.
      UNIMPLEMENTED();
    default:
      UNREACHABLE();
  }
}

void Simulator::VisitUnconditionalBranch(Instruction* instr) {
  switch (instr->Mask(UnconditionalBranchMask)) {
    case BL:
      set_lr(instr->following());
      [[fallthrough]];
    case B:
      set_pc(instr->ImmPCOffsetTarget());
      break;
    default:
      UNREACHABLE();
  }
}

void Simulator::VisitConditionalBranch(Instruction* instr) {
  DCHECK(instr->Mask(ConditionalBranchMask) == B_cond);
  if (ConditionPassed(static_cast<Condition>(instr->ConditionBranch()))) {
    set_pc(instr->ImmPCOffsetTarget());
  }
}

Simulator::BType Simulator::GetBTypeFromInstruction(
    const Instruction* instr) const {
  switch (instr->Mask(UnconditionalBranchToRegisterMask)) {
    case BLR:
      return BranchAndLink;
    case BR:
      if (!PcIsInGuardedPage() || (instr->Rn() == 16) || (instr->Rn() == 17)) {
        return BranchFromUnguardedOrToIP;
      }
      return BranchFromGuardedNotToIP;
  }
  return DefaultBType;
}

void Simulator::VisitUnconditionalBranchToRegister(Instruction* instr) {
  Instruction* target = reg<Instruction*>(instr->Rn());
  switch (instr->Mask(UnconditionalBranchToRegisterMask)) {
    case BLR: {
      set_lr(instr->following());
      if (instr->Rn() == 31) {
        // BLR XZR is used as a guard for the constant pool. We should never hit
        // this, but if we do trap to allow debugging.
        Debug();
      }
      [[fallthrough]];
    }
    case BR:
    case RET:
      set_pc(target);
      break;
    default:
      UNIMPLEMENTED();
  }
  set_btype(GetBTypeFromInstruction(instr));
}

void Simulator::VisitTestBranch(Instruction* instr) {
  unsigned bit_pos =
      (instr->ImmTestBranchBit5() << 5) | instr->ImmTestBranchBit40();
  bool take_branch = ((xreg(instr->Rt()) & (1ULL << bit_pos)) == 0);
  switch (instr->Mask(TestBranchMask)) {
    case TBZ:
      break;
    case TBNZ:
      take_branch = !take_branch;
      break;
    default:
      UNIMPLEMENTED();
  }
  if (take_branch) {
    set_pc(instr->ImmPCOffsetTarget());
  }
}

void Simulator::VisitCompareBranch(Instruction* instr) {
  unsigned rt = instr->Rt();
  bool take_branch = false;
  switch (instr->Mask(CompareBranchMask)) {
    case CBZ_w:
      take_branch = (wreg(rt) == 0);
      break;
    case CBZ_x:
      take_branch = (xreg(rt) == 0);
      break;
    case CBNZ_w:
      take_branch = (wreg(rt) != 0);
      break;
    case CBNZ_x:
      take_branch = (xreg(rt) != 0);
      break;
    default:
      UNIMPLEMENTED();
  }
  if (take_branch) {
    set_pc(instr->ImmPCOffsetTarget());
  }
}

template <typename T>
void Simulator::AddSubHelper(Instruction* instr, T op2) {
  // Use unsigned types to avoid implementation-defined overflow behaviour.
  static_assert(std::is_unsigned<T>::value, "operands must be unsigned");

  bool set_flags = instr->FlagsUpdate();
  T new_val = 0;
  Instr operation = instr->Mask(AddSubOpMask);

  switch (operation) {
    case ADD:
    case ADDS: {
      new_val =
          AddWithCarry<T>(set_flags, reg<T>(instr->Rn(), instr->RnMode()), op2);
      break;
    }
    case SUB:
    case SUBS: {
      new_val = AddWithCarry<T>(set_flags, reg<T>(instr->Rn(), instr->RnMode()),
                                ~op2, 1);
      break;
    }
    default:
      UNREACHABLE();
  }

  set_reg<T>(instr->Rd(), new_val, instr->RdMode());
}

void Simulator::VisitAddSubShifted(Instruction* instr) {
  Shift shift_type = static_cast<Shift>(instr->ShiftDP());
  unsigned shift_amount = instr->ImmDPShift();

  if (instr->SixtyFourBits()) {
    uint64_t op2 = ShiftOperand(xreg(instr->Rm()), shift_type, shift_amount);
    AddSubHelper(instr, op2);
  } else {
    uint32_t op2 = ShiftOperand(wreg(instr->Rm()), shift_type, shift_amount);
    AddSubHelper(instr, op2);
  }
}

void Simulator::VisitAddSubImmediate(Instruction* instr) {
  int64_t op2 = instr->ImmAddSub() << ((instr->ShiftAddSub() == 1) ? 12 : 0);
  if (instr->SixtyFourBits()) {
    AddSubHelper(instr, static_cast<uint64_t>(op2));
  } else {
    AddSubHelper(instr, static_cast<uint32_t>(op2));
  }
}

void Simulator::VisitAddSubExtended(Instruction* instr) {
  Extend ext = static_cast<Extend>(instr->ExtendMode());
  unsigned left_shift = instr->ImmExtendShift();
  if (instr->Six
```