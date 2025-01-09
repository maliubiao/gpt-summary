Response:
The user wants a summary of the functionality of the provided C++ header file, which is part of the V8 JavaScript engine.

Here's a plan to address the request:

1. **Identify the main purpose:**  The file is named `maglev-assembler-riscv-inl.h`, suggesting it provides inline helper functions for generating RISC-V assembly code within the Maglev compiler of V8.

2. **Analyze key functionalities:** Scan the code for recurring patterns and common operations. Look for functions related to:
    - Memory access (loads, stores)
    - Comparisons (integer, float, tagged values, object types)
    - Control flow (jumps, branches)
    - Deoptimization
    - Function calls
    - Type checking (Smi, object types, callables)
    - Assertions

3. **Determine if it's a Torque file:** Check if the filename ends in `.tq`. In this case, it doesn't.

4. **Check for Javascript relevance and provide examples:** Many of the functions directly correspond to low-level operations needed to execute Javascript. Illustrate with simple Javascript code snippets.

5. **Identify code logic and provide examples:**  Pick a few representative functions and demonstrate their behavior with hypothetical inputs and outputs.

6. **Point out common programming errors:**  Think about how a developer using these low-level building blocks might make mistakes.

7. **Summarize the overall functionality:** Condense the findings into a concise description of the file's role.
```cpp
(scratch, zero_reg, Operand(0x406FE));
  Sll64(scratch, scratch, Operand(44));
  fmv_d_x(ftmp1, scratch);
  MacroAssembler::CompareF64(scratch, GE, value, ftmp1);
  MacroAssembler::Branch(max,  // value >= 255.0
                         not_equal, scratch, Operand(zero_reg));

  // value in (0.0, 255.0)
  fmv_x_d(result, value);
  // check if fractional part in result is absent
  Label has_fraction;
  Mv(scratch, result);
  SllWord(scratch, scratch, Operand(64 - kFloat64MantissaBits));
  MacroAssembler::Branch(&has_fraction, not_equal, scratch, Operand(zero_reg));
  // no fractional part, compute exponent part taking bias into account.
  SrlWord(result, result, Operand(kFloat64MantissaBits));
  SubWord(result, result, kFloat64ExponentBias);
  MacroAssembler::Branch(done);

  bind(&has_fraction);
  // Actual rounding is here. Notice that ToUint8Clamp does “round half to even”
  // tie-breaking and that differs from Math.round which does “round half up”
  // tie-breaking.
  fcvt_l_d(scratch, value, RNE);
  fcvt_d_l(ftmp1, scratch, RNE);
  // A special handling is needed if the result is a very small positive number
  // that rounds to zero. JS semantics requires that the rounded result retains
  // the sign of the input, so a very small positive floating-point number
  // should be rounded to positive 0.
  fsgnj_d(ftmp1, ftmp1, value);
  fmv_x_d(result, ftmp1);
  MacroAssembler::Branch(done);
}

template <typename NodeT>
inline void MaglevAssembler::DeoptIfBufferDetached(Register array,
                                                   Register scratch,
                                                   NodeT* node) {
  // A detached buffer leads to megamorphic feedback, so we won't have a deopt
  // loop if we deopt here.
  LoadTaggedField(scratch,
                  FieldMemOperand(array, JSArrayBufferView::kBufferOffset));
  LoadTaggedField(scratch,
                  FieldMemOperand(scratch, JSArrayBuffer::kBitFieldOffset));
  ZeroExtendWord(scratch, scratch);
  And(scratch, scratch, Operand(JSArrayBuffer::WasDetachedBit::kMask));
  Label* deopt_label =
      GetDeoptLabel(node, DeoptimizeReason::kArrayBufferWasDetached);
  RecordComment("-- Jump to eager deopt");
  MacroAssembler::Branch(deopt_label, not_equal, scratch, Operand(zero_reg));
}

inline void MaglevAssembler::LoadByte(Register dst, MemOperand src) {
  Lbu(dst, src);
}

inline Condition MaglevAssembler::IsCallableAndNotUndetectable(
    Register map, Register scratch) {
  Load32U(scratch, FieldMemOperand(map, Map::kBitFieldOffset));
  And(scratch, scratch,
      Operand(Map::Bits1::IsUndetectableBit::kMask |
              Map::Bits1::IsCallableBit::kMask));
  // NB: TestTypeOf=>Branch=>JumpIf expects the result of a comparison
  // in dedicated "flag" register
  constexpr Register bit_set_flag = MaglevAssembler::GetFlagsRegister();
  Sub32(bit_set_flag, scratch, Operand(Map::Bits1::IsCallableBit::kMask));
  return kEqual;
}

inline Condition MaglevAssembler::IsNotCallableNorUndetactable(
    Register map, Register scratch) {
  Load32U(scratch, FieldMemOperand(map, Map::kBitFieldOffset));

  // NB: TestTypeOf=>Branch=>JumpIf expects the result of a comparison
  // in dedicated "flag" register
  constexpr Register bits_unset_flag = MaglevAssembler::GetFlagsRegister();
  And(bits_unset_flag, scratch,
      Operand(Map::Bits1::IsUndetectableBit::kMask |
              Map::Bits1::IsCallableBit::kMask));
  return kEqual;
}

inline void MaglevAssembler::LoadInstanceType(Register instance_type,
                                              Register heap_object) {
  LoadMap(instance_type, heap_object);
  Lhu(instance_type, FieldMemOperand(instance_type, Map::kInstanceTypeOffset));
}

inline void MaglevAssembler::CompareInstanceTypeAndJumpIf(
    Register map, InstanceType type, Condition cond, Label* target,
    Label::Distance distance) {
  MaglevAssembler::TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  Lhu(scratch, FieldMemOperand(map, Map::kInstanceTypeOffset));
  // we could be out of scratch registers by this moment already, and Branch
  // with Immediate operand require one so use Sub and compare against x0 later,
  // saves a register. can be done only for signed comparisons
  bool can_sub = false;
  switch (cond) {
    case Condition::kEqual:
    case Condition::kNotEqual:
    case Condition::kLessThan:
    case Condition::kLessThanEqual:
    case Condition::kGreaterThan:
    case Condition::kGreaterThanEqual:
      can_sub = true;
      break;
    default:
      break;
  }
  if (can_sub) {
    SubWord(scratch, scratch, Operand(type));
    type = static_cast<InstanceType>(0);
  }
  MacroAssembler::Branch(target, cond, scratch, Operand(type), distance);
}

inline Condition MaglevAssembler::CompareInstanceTypeRange(
    Register map, Register instance_type_out, InstanceType lower_limit,
    InstanceType higher_limit) {
  DCHECK_LT(lower_limit, higher_limit);
  Lhu(instance_type_out, FieldMemOperand(map, Map::kInstanceTypeOffset));
  Sub32(instance_type_out, instance_type_out, Operand(lower_limit));
  Register aflag = MaglevAssembler::GetFlagsRegister();
  // NB: JumpIf expects the result in dedicated "flag" register
  Sleu(aflag, instance_type_out, Operand(higher_limit - lower_limit));
  return kNotZero;
}

inline void MaglevAssembler::JumpIfNotObjectType(Register heap_object,
                                                 InstanceType type,
                                                 Label* target,
                                                 Label::Distance distance) {
  constexpr Register flag = MaglevAssembler::GetFlagsRegister();
  IsObjectType(heap_object, flag, flag, type);
  // NB: JumpIf expects the result in dedicated "flag" register
  JumpIf(kNotEqual, target, distance);
}

inline void MaglevAssembler::AssertObjectType(Register heap_object,
                                              InstanceType type,
                                              AbortReason reason) {
  AssertNotSmi(heap_object);
  constexpr Register flag = MaglevAssembler::GetFlagsRegister();
  IsObjectType(heap_object, flag, flag, type);
  // NB: Assert expects the result in dedicated "flag" register
  Assert(Condition::kEqual, reason);
}

inline void MaglevAssembler::BranchOnObjectType(
    Register heap_object, InstanceType type, Label* if_true,
    Label::Distance true_distance, bool fallthrough_when_true, Label* if_false,
    Label::Distance false_distance, bool fallthrough_when_false) {
  MaglevAssembler::TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  IsObjectType(heap_object, scratch, scratch, type);
  Branch(kEqual, if_true, true_distance, fallthrough_when_true, if_false,
         false_distance, fallthrough_when_false);
}

inline void MaglevAssembler::JumpIfObjectTypeInRange(Register heap_object,
                                                     InstanceType lower_limit,
                                                     InstanceType higher_limit,
                                                     Label* target,
                                                     Label::Distance distance) {
  TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  LoadMap(scratch, heap_object);
  Lhu(scratch, FieldMemOperand(scratch, Map::kInstanceTypeOffset));
  Sub32(scratch, scratch, Operand(lower_limit));
  MacroAssembler::Branch(target, kUnsignedLessThanEqual, scratch,
                         Operand(higher_limit - lower_limit));
}

inline void MaglevAssembler::JumpIfObjectTypeNotInRange(
    Register heap_object, InstanceType lower_limit, InstanceType higher_limit,
    Label* target, Label::Distance distance) {
  TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  LoadMap(scratch, heap_object);
  Lhu(scratch, FieldMemOperand(scratch, Map::kInstanceTypeOffset));
  Sub32(scratch, scratch, Operand(lower_limit));
  MacroAssembler::Branch(target, kUnsignedGreaterThan, scratch,
                         Operand(higher_limit - lower_limit));
}

inline void MaglevAssembler::AssertObjectTypeInRange(Register heap_object,
                                                     InstanceType lower_limit,
                                                     InstanceType higher_limit,
                                                     AbortReason reason) {
  AssertNotSmi(heap_object);
  TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  LoadMap(scratch, heap_object);
  Lhu(scratch, FieldMemOperand(scratch, Map::kInstanceTypeOffset));
  Sub32(scratch, scratch, Operand(lower_limit));
  MacroAssembler::Assert(kUnsignedLessThanEqual, reason, scratch,
                         Operand(higher_limit - lower_limit));
}

inline void MaglevAssembler::BranchOnObjectTypeInRange(
    Register heap_object, InstanceType lower_limit, InstanceType higher_limit,
    Label* if_true, Label::Distance true_distance, bool fallthrough_when_true,
    Label* if_false, Label::Distance false_distance,
    bool fallthrough_when_false) {
  TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  LoadMap(scratch, heap_object);
  Lhu(scratch, FieldMemOperand(scratch, Map::kInstanceTypeOffset));
  Sub32(scratch, scratch, Operand(lower_limit));
  constexpr Register flags_reg = MaglevAssembler::GetFlagsRegister();
  // if scratch <= (higher_limit - lower_limit) then flags_reg = 0 else
  // flags_reg = 1
  CompareI(flags_reg, scratch, Operand(higher_limit - lower_limit),
           Condition::kUnsignedGreaterThan);
  // now compare against 0 witj kEqual
  Branch(Condition::kEqual, if_true, true_distance, fallthrough_when_true,
         if_false, false_distance, fallthrough_when_false);
}

#if V8_STATIC_ROOTS_BOOL
// FIXME: not tested
inline void MaglevAssembler::JumpIfObjectInRange(Register heap_object,
                                                 Tagged_t lower_limit,
                                                 Tagged_t higher_limit,
                                                 Label* target,
                                                 Label::Distance distance) {
  // Only allowed for comparisons against RORoots.
  DCHECK_LE(lower_limit, StaticReadOnlyRoot::kLastAllocatedRoot);
  DCHECK_LE(higher_limit, StaticReadOnlyRoot::kLastAllocatedRoot);
  TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  AssertNotSmi(heap_object);
  CompareRange(heap_object, scratch, lower_limit, higher_limit);
  JumpIf(kUnsignedLessThanEqual, target, distance);
}

inline void MaglevAssembler::JumpIfObjectNotInRange(Register heap_object,
                                                    Tagged_t lower_limit,
                                                    Tagged_t higher_limit,
                                                    Label* target,
                                                    Label::Distance distance) {
  // Only allowed for comparisons against RORoots.
  DCHECK_LE(lower_limit, StaticReadOnlyRoot::kLastAllocatedRoot);
  DCHECK_LE(higher_limit, StaticReadOnlyRoot::kLastAllocatedRoot);
  TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  AssertNotSmi(heap_object);
  CompareRange(heap_object, scratch, lower_limit, higher_limit);
  JumpIf(kUnsignedGreaterThan, target, distance);
}

inline void MaglevAssembler::AssertObjectInRange(Register heap_object,
                                                 Tagged_t lower_limit,
                                                 Tagged_t higher_limit,
                                                 AbortReason reason) {
  // Only allowed for comparisons against RORoots.
  DCHECK_LE(lower_limit, StaticReadOnlyRoot::kLastAllocatedRoot);
  DCHECK_LE(higher_limit, StaticReadOnlyRoot::kLastAllocatedRoot);
  TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  AssertNotSmi(heap_object);
  CompareRange(heap_object, scratch, lower_limit, higher_limit);
  Assert(kUnsignedLessThanEqual, reason);
}
#endif

inline void MaglevAssembler::JumpIfJSAnyIsNotPrimitive(
    Register heap_object, Label* target, Label::Distance distance) {
  TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  MacroAssembler::JumpIfJSAnyIsNotPrimitive(heap_object, scratch, target,
                                            distance);
}

template <typename NodeT>
inline void MaglevAssembler::CompareRootAndEmitEagerDeoptIf(
    Register reg, RootIndex index, Condition cond, DeoptimizeReason reason,
    NodeT* node) {
  Label Deopt, Done;

  CompareRootAndBranch(reg, index, cond, &Deopt);
  Jump(&Done, Label::kNear);
  bind(&Deopt);
  EmitEagerDeopt(node, reason);
  bind(&Done);
}

template <typename NodeT>
inline void MaglevAssembler::CompareMapWithRootAndEmitEagerDeoptIf(
    Register reg, RootIndex index, Register scratch, Condition cond,
    DeoptimizeReason reason, NodeT* node) {
  CompareMapWithRoot(reg, index, scratch);
  DCHECK_EQ(cond, kNotEqual);  // so far we only support kNotEqual, flag reg is
                               // 0 for equal, 1 for not equal
  EmitEagerDeoptIf(cond, reason,
                   node);  // Jump to deopt only if flag reg is not equal 0
}

template <typename NodeT>
inline void MaglevAssembler::CompareTaggedRootAndEmitEagerDeoptIf(
    Register reg, RootIndex index, Condition cond, DeoptimizeReason reason,
    NodeT* node) {
  DCHECK_EQ(cond, kNotEqual);
  MaglevAssembler::TemporaryRegisterScope temps(this);
  Register cmp_result = temps.AcquireScratch();
  MacroAssembler::CompareTaggedRoot(reg, index, cmp_result);
  Label* deopt_label = GetDeoptLabel(node, reason);
  RecordComment("-- Jump to eager deopt");
  MacroAssembler::Branch(deopt_label, cond, cmp_result, Operand(zero_reg));
}

template <typename NodeT>
inline void MaglevAssembler::CompareUInt32AndEmitEagerDeoptIf(
    Register reg, int imm, Condition cond, DeoptimizeReason reason,
    NodeT* node) {
  Label Deopt, Done;

  MacroAssembler::Branch(&Deopt, cond, reg, Operand(imm), Label::kNear);
  Jump(&Done, Label::kNear);
  bind(&Deopt);
  EmitEagerDeopt(node, reason);
  bind(&Done);
}

inline void MaglevAssembler::CompareMapWithRoot(Register object,
                                                RootIndex index,
                                                Register scratch) {
  constexpr Register Jump_flag = MaglevAssembler::GetFlagsRegister();

  if (V8_STATIC_ROOTS_BOOL && RootsTable::IsReadOnly(index)) {
    LoadCompressedMap(scratch, object);
    MaglevAssembler::TemporaryRegisterScope temps(this);
    Register index_reg = temps.AcquireScratch();
    Li(index_reg, ReadOnlyRootPtr(index));
    MacroAssembler::CmpTagged(Jump_flag, scratch, index_reg);
    return;
  }
  LoadMap(scratch, object);
  MacroAssembler::CompareRoot(scratch, index,
                              Jump_flag);  // so 0 if equal, 1 if not
}

template <typename NodeT>
inline void MaglevAssembler::CompareInstanceTypeRangeAndEagerDeoptIf(
    Register map, Register instance_type_out, InstanceType lower_limit,
    InstanceType higher_limit, Condition cond, DeoptimizeReason reason,
    NodeT* node) {
  DCHECK_LT(lower_limit, higher_limit);
  Lhu(instance_type_out, FieldMemOperand(map, Map::kInstanceTypeOffset));
  Sub32(instance_type_out, instance_type_out, Operand(lower_limit));
  DCHECK_EQ(cond, kUnsignedGreaterThan);
  Label* deopt_label = GetDeoptLabel(node, reason);
  RecordComment("-- Jump to eager deopt");
  MacroAssembler::Branch(deopt_label, Ugreater, instance_type_out,
                         Operand(higher_limit - lower_limit));
}

inline void MaglevAssembler::CompareFloat64AndJumpIf(
    DoubleRegister src1, DoubleRegister src2, Condition cond, Label* target,
    Label* nan_failed, Label::Distance distance) {
  MaglevAssembler::TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  Register scratch2 = temps.AcquireScratch();
  Register cmp = temps.AcquireScratch();
  // FIXME: check, which condition can be on input
  // If cond - condition for overflow, skip check for NaN,
  // such check implemented below, using fclass results
  if (cond != kOverflow && cond != kNoOverflow) {
    feq_d(scratch, src1, src1);
    feq_d(scratch2, src2, src2);
    And(scratch2, scratch, scratch2);
    MacroAssembler::Branch(nan_failed, equal, scratch2, Operand(zero_reg));
    // actual comparison
    FPUCondition fcond = ConditionToConditionCmpFPU(cond);
    MacroAssembler::CompareF64(cmp, fcond, src1, src2);
    MacroAssembler::Branch(target, not_equal, cmp, Operand(zero_reg), distance);
  } else {
    // Case for conditions connected with overflow should be checked,
    // and, maybe, removed in future (FPUCondition does not implement oveflow
    // cases)
    fclass_d(scratch, src1);
    fclass_d(scratch2, src2);
    Or(scratch2, scratch, scratch2);
    And(cmp, scratch2, FClassFlag::kQuietNaN | FClassFlag::kSignalingNaN);
    MacroAssembler::Branch(nan_failed, not_equal, cmp, Operand(zero_reg));
    And(cmp, scratch2,
        FClassFlag::kNegativeInfinity | FClassFlag::kPositiveInfinity);
    MacroAssembler::Branch(target, not_equal, cmp, Operand(zero_reg), distance);
  }
}

inline void MaglevAssembler::CompareFloat64AndBranch(
    DoubleRegister src1, DoubleRegister src2, Condition cond,
    BasicBlock* if_true, BasicBlock* if_false, BasicBlock* next_block,
    BasicBlock* nan_failed) {
  MaglevAssembler::TemporaryRegisterScope temps(this);
  Register scratch1 = temps.AcquireScratch();
  Register scratch2 = temps.AcquireScratch();
  // emit check for NaN
  feq_d(scratch1, src1, src1);
  feq_d(scratch2, src2, src2);
  Register any_nan = scratch2;
  And(any_nan, scratch1, scratch2);
  MacroAssembler::Branch(nan_failed->label(), equal, any_nan,
                         Operand(zero_reg));
  // actual comparison
  Register cmp = temps.AcquireScratch();
  bool fallthrough_when_true = (if_true == next_block);
  bool fallthrough_when_false = (if_false == next_block);
  Label* if_true_label = if_true->label();
  Label* if_false_label = if_false->label();
  if (fallthrough_when_false) {
    if (fallthrough_when_true) {
      // If both paths are a fallthrough, do nothing.
      DCHECK_EQ(if_true_label, if_false_label);
      return;
    }
    FPUCondition fcond = ConditionToConditionCmpFPU(cond);
    MacroAssembler::CompareF64(cmp, fcond, src1, src2);
    // Jump over the false block if true, otherwise fall through into it.
    MacroAssembler::Branch(if_true_label, ne, cmp, Operand(zero_reg),
                           Label::kFar);
  } else {
    FPUCondition neg_fcond = ConditionToConditionCmpFPU(NegateCondition(cond));
    MacroAssembler::CompareF64(cmp, neg_fcond, src1, src2);
    // Jump to the false block if true.
    MacroAssembler::Branch(if_false_label, ne, cmp, Operand(zero_reg),
                           Label::kFar);
    // Jump to the true block if it's not the next block.
    if (!fallthrough_when_true) {
      MacroAssembler::Branch(if_true_label, Label::kFar);
    }
  }
}

inline void MaglevAssembler::PrepareCallCFunction(int num_reg_arguments,
                                                  int num_double_registers) {
  MaglevAssembler::TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  MacroAssembler::PrepareCallCFunction(num_reg_arguments, num_double_registers,
                                       scratch);
}

inline void MaglevAssembler::CallSelf() {
  DCHECK(allow_call());
  DCHECK(code_gen_state()->entry_label()->is_bound());
  MacroAssembler::Branch(code_gen_state()->entry_label());
}

inline void MaglevAssembler::Jump(Label* target, Label::Distance distance) {
  DCHECK(!IsDeoptLabel(target));
  MacroAssembler::Branch(target, distance);
}

inline void MaglevAssembler::JumpToDeopt(Label* target) {
  DCHECK(IsDeoptLabel(target));
  MacroAssembler::Branch(target);
}

inline void MaglevAssembler::EmitEagerDeoptStress(Label* target) {
  // TODO(olivf): On arm `--deopt-every-n-times` is currently not supported.
  // Supporting it would require to implement this method, additionally handle
  // deopt branches in Cbz, and handle all cases where we fall through to the
  // deopt branch (like Int32Divide).
}

inline void MaglevAssembler::JumpIf(Condition cond, Label* target,
                                    Label::Distance distance) {
  // NOTE: for now keep in mind that we always put the result of a comparison
  // into dedicated register ("set flag"), and then compare it with x0.
  constexpr Register aflag = MaglevAssembler::GetFlagsRegister();
  MacroAssembler::Branch(target, cond, aflag, Operand(zero_reg), distance);
}

inline void MaglevAssembler::JumpIfRoot(Register with, RootIndex index,
                                        Label* if_equal,
                                        Label::Distance distance) {
  MacroAssembler::JumpIfRoot(with, index, if_equal, distance);
}

inline void MaglevAssembler::JumpIfNotRoot(Register with, RootIndex index,
                                           Label* if_not_equal,
                                           Label::Distance distance) {
  MacroAssembler::JumpIfNotRoot(with, index, if_not_equal, distance);
}

inline void MaglevAssembler::JumpIfSmi(Register src, Label* on_smi,
                                       Label::Distance distance) {
  MacroAssembler::JumpIfSmi(src, on_smi, distance);
}

inline void MaglevAssembler::JumpIfNotSmi(Register src, Label* on_smi,
                                          Label::Distance distance) {
  MacroAssembler::JumpIfNotSmi(src, on_smi, distance);
}

void MaglevAssembler::JumpIfByte(Condition cc, Register value, int32_t byte,
                                 Label* target, Label::Distance distance) {
  MacroAssembler::Branch(target, cc, value, Operand(byte), distance);
}

void MaglevAssembler::JumpIfHoleNan(DoubleRegister value, Register scratch,
                                    Label* target, Label::Distance distance) {
  // TODO(leszeks): Right now this only accepts Zone-allocated target labels.
  // This works because all callsites are jumping to either a deopt, deferred
  // code, or a basic block. If we ever need to jump to an on-stack label, we
  // have to add support for it here change the caller to pass a ZoneLabelRef.
  DCHECK(compilation_info()->zone()->Contains(target));
  ZoneLabelRef is_hole = ZoneLabelRef::UnsafeFromLabelPointer(target);
  ZoneLabelRef is_not_hole(this);
  MaglevAssembler::TemporaryRegisterScope temps(this);
  Register scratch2 = temps.AcquireScratch();

  feq_d(scratch2, value, value);  // 0 if value is NaN
  Label* deferred_code = MakeDeferredCode(
      [](MaglevAssembler* masm, DoubleRegister value, Register scratch,
         ZoneLabelRef is_hole, ZoneLabelRef is_not_hole) {
        masm->ExtractHighWordFromF64(scratch, value);
        masm->CompareInt32AndJumpIf(scratch, kHoleNanUpper32, kEqual, *is_hole);
        masm->MacroAssembler::Branch(*is_not_hole);
      },
      value, scratch, is_hole, is_not_hole);
  MacroAssembler::Branch(deferred_code, equal, scratch2, Operand(zero_reg));
  bind(*is_not_hole);
}

void MaglevAssembler::JumpIfNotHoleNan(DoubleRegister value, Register scratch,
                                       Label* target,
                                       Label::Distance distance) {
  JumpIfNotNan(value, target, distance);
  ExtractHighWordFromF64(scratch, value);
  CompareInt32AndJumpIf(scratch, kHoleNanUpper32, kNotEqual, target, distance);
}

void MaglevAssembler::JumpIfNotHoleNan(MemOperand operand, Label* target,
                                       Label::Distance distance) {
  MaglevAssembler::TemporaryRegisterScope temps(this);
  Register upper_bits = temps.AcquireScratch();
  Load32U(upper_bits,
          MemOperand(operand.rm(), operand.offset() + (kDoubleSize / 2)));
  CompareInt32AndJumpIf(upper_bits, kHoleNanUpper32, kNotEqual, target,
                        distance);
}

void MaglevAssembler::JumpIfNan(DoubleRegister value, Label* target,
                                Label::Distance distance) {
  MaglevAssembler::TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  feq_d(scratch, value, value);  // 0 if value is NaN
  MacroAssembler::Branch(target, equal, scratch, Operand(zero_reg), distance);
}

void MaglevAssembler::JumpIfNotNan(DoubleRegister value, Label* target,
                                   Label::Distance distance) {
  MaglevAssembler::TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  feq_d(scratch, value, value);  // 1 if value is not NaN
  MacroAssembler::Branch(target, not_equal, scratch, Operand(zero_reg),
                         distance);
}

inline void MaglevAssembler::CompareInt32AndJumpIf(Register r1, Register r2,
                                                   Condition cond,
                                                   Label* target,
                                                   Label::Distance distance) {
  MaglevAssembler::TemporaryRegisterScope temps(this);
  Register r1w = temps.AcquireScratch();
  Register r2w = temps.AcquireScratch();
  // TODO(Yuri Gaevsky): is zero/sign extension really needed here?
  switch (cond) {
    case ult:
    case uge:
    case ule:
    case ugt:
      ZeroExtendWord(r1w, r1);
      ZeroExtendWord(r2w, r2);
      break;
    default:
      SignExtend32To64Bits(r1w, r1);
      SignExtend32To64Bits(r2w, r2);
  }
  MacroAssembler::Branch(target, cond, r1w, Operand(r2w), distance);
}

void MaglevAssembler::CompareIntPtrAndJumpIf(Register r1, Register r2,
                                             Condition cond, Label* target,
                                             Label::Distance distance) {
  MacroAssembler::Branch(target, cond, r1, Operand(r2), distance);
}

inline void MaglevAssembler::CompareInt32AndJumpIf(Register r1, int32_t value,
                                                   Condition cond,
                                                   Label* target,
                                                   Label::Distance distance) {
  MaglevAssembler::TemporaryRegisterScope temps(this);
  Register r1w = temps.AcquireScratch();
  // TODO(Yuri Gaevsky): is zero/sign extension really needed here?
  switch (cond) {
    case ult:
    case uge:
    case ule:
    case ugt:
      ZeroExtendWord(r1w, r1);
      break;
    default:
      SignExtend32To64Bits(r1w, r1);
  }
  MacroAssembler::Branch(target, cond, r1w, Operand(value), distance);
}

inline void MaglevAssembler::CompareInt32AndAssert(Register r1, Register r2,
                                                   Condition cond,
                                                   AbortReason reason) {
  MaglevAssembler::TemporaryRegisterScope temps(this);
  Register r1w = temps.AcquireScratch();
  Register r2w = temps.AcquireScratch();
  // TODO(Yuri Gaevsky): is zero/sign extension really needed here?
  switch (cond) {
    case ult:
    case uge:
    case ule:
    case ugt:
      ZeroExtendWord(r1w, r1);
      ZeroExtendWord(r2w, r2);
      break;
    default:
      SignExtend32To64Bits(r1w, r1);
      SignExtend32To64Bits(r2w, r2);
  }
  MacroAssembler::Assert(cond, reason, r1w, Operand(r2w));
}

inline void MaglevAssembler::CompareInt32AndAssert(Register r1, int32_t value,
                                                   Condition cond,
                                                   AbortReason reason) {
  MaglevAssembler::TemporaryRegisterScope temps(this);
  Register r1w = temps.AcquireScratch();
  // TODO(Yuri Gaevsky): is zero/sign extension really needed here?
  switch (cond) {
    case ult:
    case uge:
    case ule:
    case ugt:
      ZeroExtendWord(r1w, r1);
      break;
    default:
      SignExtend32To64Bits(r1w, r1);
  }
  MacroAssembler::Assert(cond, reason, r1w, Operand(value));
}

inline void MaglevAssembler::CompareInt32AndBranch(
    Register r1, int32_t value, Condition cond, Label* if_true,
    Label::Distance true_distance, bool fallthrough_when_true, Label* if_false,
    Label::Distance false_distance, bool fallthrough_when_false) {
  // expect only specific conditions
  switch (cond) {
    case eq:
    case ne:
    case greater:
    case greater_equal:
    case less:
    case less_equal:
    case Ugreater:
    case Ugreater_equal:
    case Uless:
    case Uless_equal:
      break;  // expected
    case cc_always:
    default:
      UNREACHABLE
Prompt: 
```
这是目录为v8/src/maglev/riscv/maglev-assembler-riscv-inl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/maglev/riscv/maglev-assembler-riscv-inl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能

"""
(scratch, zero_reg, Operand(0x406FE));
  Sll64(scratch, scratch, Operand(44));
  fmv_d_x(ftmp1, scratch);
  MacroAssembler::CompareF64(scratch, GE, value, ftmp1);
  MacroAssembler::Branch(max,  // value >= 255.0
                         not_equal, scratch, Operand(zero_reg));

  // value in (0.0, 255.0)
  fmv_x_d(result, value);
  // check if fractional part in result is absent
  Label has_fraction;
  Mv(scratch, result);
  SllWord(scratch, scratch, Operand(64 - kFloat64MantissaBits));
  MacroAssembler::Branch(&has_fraction, not_equal, scratch, Operand(zero_reg));
  // no fractional part, compute exponent part taking bias into account.
  SrlWord(result, result, Operand(kFloat64MantissaBits));
  SubWord(result, result, kFloat64ExponentBias);
  MacroAssembler::Branch(done);

  bind(&has_fraction);
  // Actual rounding is here. Notice that ToUint8Clamp does “round half to even”
  // tie-breaking and that differs from Math.round which does “round half up”
  // tie-breaking.
  fcvt_l_d(scratch, value, RNE);
  fcvt_d_l(ftmp1, scratch, RNE);
  // A special handling is needed if the result is a very small positive number
  // that rounds to zero. JS semantics requires that the rounded result retains
  // the sign of the input, so a very small positive floating-point number
  // should be rounded to positive 0.
  fsgnj_d(ftmp1, ftmp1, value);
  fmv_x_d(result, ftmp1);
  MacroAssembler::Branch(done);
}

template <typename NodeT>
inline void MaglevAssembler::DeoptIfBufferDetached(Register array,
                                                   Register scratch,
                                                   NodeT* node) {
  // A detached buffer leads to megamorphic feedback, so we won't have a deopt
  // loop if we deopt here.
  LoadTaggedField(scratch,
                  FieldMemOperand(array, JSArrayBufferView::kBufferOffset));
  LoadTaggedField(scratch,
                  FieldMemOperand(scratch, JSArrayBuffer::kBitFieldOffset));
  ZeroExtendWord(scratch, scratch);
  And(scratch, scratch, Operand(JSArrayBuffer::WasDetachedBit::kMask));
  Label* deopt_label =
      GetDeoptLabel(node, DeoptimizeReason::kArrayBufferWasDetached);
  RecordComment("-- Jump to eager deopt");
  MacroAssembler::Branch(deopt_label, not_equal, scratch, Operand(zero_reg));
}

inline void MaglevAssembler::LoadByte(Register dst, MemOperand src) {
  Lbu(dst, src);
}

inline Condition MaglevAssembler::IsCallableAndNotUndetectable(
    Register map, Register scratch) {
  Load32U(scratch, FieldMemOperand(map, Map::kBitFieldOffset));
  And(scratch, scratch,
      Operand(Map::Bits1::IsUndetectableBit::kMask |
              Map::Bits1::IsCallableBit::kMask));
  // NB: TestTypeOf=>Branch=>JumpIf expects the result of a comparison
  // in dedicated "flag" register
  constexpr Register bit_set_flag = MaglevAssembler::GetFlagsRegister();
  Sub32(bit_set_flag, scratch, Operand(Map::Bits1::IsCallableBit::kMask));
  return kEqual;
}

inline Condition MaglevAssembler::IsNotCallableNorUndetactable(
    Register map, Register scratch) {
  Load32U(scratch, FieldMemOperand(map, Map::kBitFieldOffset));

  // NB: TestTypeOf=>Branch=>JumpIf expects the result of a comparison
  // in dedicated "flag" register
  constexpr Register bits_unset_flag = MaglevAssembler::GetFlagsRegister();
  And(bits_unset_flag, scratch,
      Operand(Map::Bits1::IsUndetectableBit::kMask |
              Map::Bits1::IsCallableBit::kMask));
  return kEqual;
}

inline void MaglevAssembler::LoadInstanceType(Register instance_type,
                                              Register heap_object) {
  LoadMap(instance_type, heap_object);
  Lhu(instance_type, FieldMemOperand(instance_type, Map::kInstanceTypeOffset));
}

inline void MaglevAssembler::CompareInstanceTypeAndJumpIf(
    Register map, InstanceType type, Condition cond, Label* target,
    Label::Distance distance) {
  MaglevAssembler::TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  Lhu(scratch, FieldMemOperand(map, Map::kInstanceTypeOffset));
  // we could be out of scratch registers by this moment already, and Branch
  // with Immediate operand require one so use Sub and compare against x0 later,
  // saves a register. can be done only for signed comparisons
  bool can_sub = false;
  switch (cond) {
    case Condition::kEqual:
    case Condition::kNotEqual:
    case Condition::kLessThan:
    case Condition::kLessThanEqual:
    case Condition::kGreaterThan:
    case Condition::kGreaterThanEqual:
      can_sub = true;
      break;
    default:
      break;
  }
  if (can_sub) {
    SubWord(scratch, scratch, Operand(type));
    type = static_cast<InstanceType>(0);
  }
  MacroAssembler::Branch(target, cond, scratch, Operand(type), distance);
}

inline Condition MaglevAssembler::CompareInstanceTypeRange(
    Register map, Register instance_type_out, InstanceType lower_limit,
    InstanceType higher_limit) {
  DCHECK_LT(lower_limit, higher_limit);
  Lhu(instance_type_out, FieldMemOperand(map, Map::kInstanceTypeOffset));
  Sub32(instance_type_out, instance_type_out, Operand(lower_limit));
  Register aflag = MaglevAssembler::GetFlagsRegister();
  // NB: JumpIf expects the result in dedicated "flag" register
  Sleu(aflag, instance_type_out, Operand(higher_limit - lower_limit));
  return kNotZero;
}

inline void MaglevAssembler::JumpIfNotObjectType(Register heap_object,
                                                 InstanceType type,
                                                 Label* target,
                                                 Label::Distance distance) {
  constexpr Register flag = MaglevAssembler::GetFlagsRegister();
  IsObjectType(heap_object, flag, flag, type);
  // NB: JumpIf expects the result in dedicated "flag" register
  JumpIf(kNotEqual, target, distance);
}

inline void MaglevAssembler::AssertObjectType(Register heap_object,
                                              InstanceType type,
                                              AbortReason reason) {
  AssertNotSmi(heap_object);
  constexpr Register flag = MaglevAssembler::GetFlagsRegister();
  IsObjectType(heap_object, flag, flag, type);
  // NB: Assert expects the result in dedicated "flag" register
  Assert(Condition::kEqual, reason);
}

inline void MaglevAssembler::BranchOnObjectType(
    Register heap_object, InstanceType type, Label* if_true,
    Label::Distance true_distance, bool fallthrough_when_true, Label* if_false,
    Label::Distance false_distance, bool fallthrough_when_false) {
  MaglevAssembler::TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  IsObjectType(heap_object, scratch, scratch, type);
  Branch(kEqual, if_true, true_distance, fallthrough_when_true, if_false,
         false_distance, fallthrough_when_false);
}

inline void MaglevAssembler::JumpIfObjectTypeInRange(Register heap_object,
                                                     InstanceType lower_limit,
                                                     InstanceType higher_limit,
                                                     Label* target,
                                                     Label::Distance distance) {
  TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  LoadMap(scratch, heap_object);
  Lhu(scratch, FieldMemOperand(scratch, Map::kInstanceTypeOffset));
  Sub32(scratch, scratch, Operand(lower_limit));
  MacroAssembler::Branch(target, kUnsignedLessThanEqual, scratch,
                         Operand(higher_limit - lower_limit));
}

inline void MaglevAssembler::JumpIfObjectTypeNotInRange(
    Register heap_object, InstanceType lower_limit, InstanceType higher_limit,
    Label* target, Label::Distance distance) {
  TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  LoadMap(scratch, heap_object);
  Lhu(scratch, FieldMemOperand(scratch, Map::kInstanceTypeOffset));
  Sub32(scratch, scratch, Operand(lower_limit));
  MacroAssembler::Branch(target, kUnsignedGreaterThan, scratch,
                         Operand(higher_limit - lower_limit));
}

inline void MaglevAssembler::AssertObjectTypeInRange(Register heap_object,
                                                     InstanceType lower_limit,
                                                     InstanceType higher_limit,
                                                     AbortReason reason) {
  AssertNotSmi(heap_object);
  TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  LoadMap(scratch, heap_object);
  Lhu(scratch, FieldMemOperand(scratch, Map::kInstanceTypeOffset));
  Sub32(scratch, scratch, Operand(lower_limit));
  MacroAssembler::Assert(kUnsignedLessThanEqual, reason, scratch,
                         Operand(higher_limit - lower_limit));
}

inline void MaglevAssembler::BranchOnObjectTypeInRange(
    Register heap_object, InstanceType lower_limit, InstanceType higher_limit,
    Label* if_true, Label::Distance true_distance, bool fallthrough_when_true,
    Label* if_false, Label::Distance false_distance,
    bool fallthrough_when_false) {
  TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  LoadMap(scratch, heap_object);
  Lhu(scratch, FieldMemOperand(scratch, Map::kInstanceTypeOffset));
  Sub32(scratch, scratch, Operand(lower_limit));
  constexpr Register flags_reg = MaglevAssembler::GetFlagsRegister();
  // if scratch <= (higher_limit - lower_limit) then flags_reg = 0 else
  // flags_reg = 1
  CompareI(flags_reg, scratch, Operand(higher_limit - lower_limit),
           Condition::kUnsignedGreaterThan);
  // now compare against 0 witj kEqual
  Branch(Condition::kEqual, if_true, true_distance, fallthrough_when_true,
         if_false, false_distance, fallthrough_when_false);
}

#if V8_STATIC_ROOTS_BOOL
// FIXME: not tested
inline void MaglevAssembler::JumpIfObjectInRange(Register heap_object,
                                                 Tagged_t lower_limit,
                                                 Tagged_t higher_limit,
                                                 Label* target,
                                                 Label::Distance distance) {
  // Only allowed for comparisons against RORoots.
  DCHECK_LE(lower_limit, StaticReadOnlyRoot::kLastAllocatedRoot);
  DCHECK_LE(higher_limit, StaticReadOnlyRoot::kLastAllocatedRoot);
  TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  AssertNotSmi(heap_object);
  CompareRange(heap_object, scratch, lower_limit, higher_limit);
  JumpIf(kUnsignedLessThanEqual, target, distance);
}

inline void MaglevAssembler::JumpIfObjectNotInRange(Register heap_object,
                                                    Tagged_t lower_limit,
                                                    Tagged_t higher_limit,
                                                    Label* target,
                                                    Label::Distance distance) {
  // Only allowed for comparisons against RORoots.
  DCHECK_LE(lower_limit, StaticReadOnlyRoot::kLastAllocatedRoot);
  DCHECK_LE(higher_limit, StaticReadOnlyRoot::kLastAllocatedRoot);
  TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  AssertNotSmi(heap_object);
  CompareRange(heap_object, scratch, lower_limit, higher_limit);
  JumpIf(kUnsignedGreaterThan, target, distance);
}

inline void MaglevAssembler::AssertObjectInRange(Register heap_object,
                                                 Tagged_t lower_limit,
                                                 Tagged_t higher_limit,
                                                 AbortReason reason) {
  // Only allowed for comparisons against RORoots.
  DCHECK_LE(lower_limit, StaticReadOnlyRoot::kLastAllocatedRoot);
  DCHECK_LE(higher_limit, StaticReadOnlyRoot::kLastAllocatedRoot);
  TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  AssertNotSmi(heap_object);
  CompareRange(heap_object, scratch, lower_limit, higher_limit);
  Assert(kUnsignedLessThanEqual, reason);
}
#endif

inline void MaglevAssembler::JumpIfJSAnyIsNotPrimitive(
    Register heap_object, Label* target, Label::Distance distance) {
  TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  MacroAssembler::JumpIfJSAnyIsNotPrimitive(heap_object, scratch, target,
                                            distance);
}

template <typename NodeT>
inline void MaglevAssembler::CompareRootAndEmitEagerDeoptIf(
    Register reg, RootIndex index, Condition cond, DeoptimizeReason reason,
    NodeT* node) {
  Label Deopt, Done;

  CompareRootAndBranch(reg, index, cond, &Deopt);
  Jump(&Done, Label::kNear);
  bind(&Deopt);
  EmitEagerDeopt(node, reason);
  bind(&Done);
}

template <typename NodeT>
inline void MaglevAssembler::CompareMapWithRootAndEmitEagerDeoptIf(
    Register reg, RootIndex index, Register scratch, Condition cond,
    DeoptimizeReason reason, NodeT* node) {
  CompareMapWithRoot(reg, index, scratch);
  DCHECK_EQ(cond, kNotEqual);  // so far we only support kNotEqual, flag reg is
                               // 0 for equal, 1 for not equal
  EmitEagerDeoptIf(cond, reason,
                   node);  // Jump to deopt only if flag reg is not equal 0
}

template <typename NodeT>
inline void MaglevAssembler::CompareTaggedRootAndEmitEagerDeoptIf(
    Register reg, RootIndex index, Condition cond, DeoptimizeReason reason,
    NodeT* node) {
  DCHECK_EQ(cond, kNotEqual);
  MaglevAssembler::TemporaryRegisterScope temps(this);
  Register cmp_result = temps.AcquireScratch();
  MacroAssembler::CompareTaggedRoot(reg, index, cmp_result);
  Label* deopt_label = GetDeoptLabel(node, reason);
  RecordComment("-- Jump to eager deopt");
  MacroAssembler::Branch(deopt_label, cond, cmp_result, Operand(zero_reg));
}

template <typename NodeT>
inline void MaglevAssembler::CompareUInt32AndEmitEagerDeoptIf(
    Register reg, int imm, Condition cond, DeoptimizeReason reason,
    NodeT* node) {
  Label Deopt, Done;

  MacroAssembler::Branch(&Deopt, cond, reg, Operand(imm), Label::kNear);
  Jump(&Done, Label::kNear);
  bind(&Deopt);
  EmitEagerDeopt(node, reason);
  bind(&Done);
}

inline void MaglevAssembler::CompareMapWithRoot(Register object,
                                                RootIndex index,
                                                Register scratch) {
  constexpr Register Jump_flag = MaglevAssembler::GetFlagsRegister();

  if (V8_STATIC_ROOTS_BOOL && RootsTable::IsReadOnly(index)) {
    LoadCompressedMap(scratch, object);
    MaglevAssembler::TemporaryRegisterScope temps(this);
    Register index_reg = temps.AcquireScratch();
    Li(index_reg, ReadOnlyRootPtr(index));
    MacroAssembler::CmpTagged(Jump_flag, scratch, index_reg);
    return;
  }
  LoadMap(scratch, object);
  MacroAssembler::CompareRoot(scratch, index,
                              Jump_flag);  // so 0 if equal, 1 if not
}

template <typename NodeT>
inline void MaglevAssembler::CompareInstanceTypeRangeAndEagerDeoptIf(
    Register map, Register instance_type_out, InstanceType lower_limit,
    InstanceType higher_limit, Condition cond, DeoptimizeReason reason,
    NodeT* node) {
  DCHECK_LT(lower_limit, higher_limit);
  Lhu(instance_type_out, FieldMemOperand(map, Map::kInstanceTypeOffset));
  Sub32(instance_type_out, instance_type_out, Operand(lower_limit));
  DCHECK_EQ(cond, kUnsignedGreaterThan);
  Label* deopt_label = GetDeoptLabel(node, reason);
  RecordComment("-- Jump to eager deopt");
  MacroAssembler::Branch(deopt_label, Ugreater, instance_type_out,
                         Operand(higher_limit - lower_limit));
}

inline void MaglevAssembler::CompareFloat64AndJumpIf(
    DoubleRegister src1, DoubleRegister src2, Condition cond, Label* target,
    Label* nan_failed, Label::Distance distance) {
  MaglevAssembler::TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  Register scratch2 = temps.AcquireScratch();
  Register cmp = temps.AcquireScratch();
  // FIXME: check, which condition can be on input
  // If cond - condition for overflow, skip check for NaN,
  // such check implemented below, using fclass results
  if (cond != kOverflow && cond != kNoOverflow) {
    feq_d(scratch, src1, src1);
    feq_d(scratch2, src2, src2);
    And(scratch2, scratch, scratch2);
    MacroAssembler::Branch(nan_failed, equal, scratch2, Operand(zero_reg));
    // actual comparison
    FPUCondition fcond = ConditionToConditionCmpFPU(cond);
    MacroAssembler::CompareF64(cmp, fcond, src1, src2);
    MacroAssembler::Branch(target, not_equal, cmp, Operand(zero_reg), distance);
  } else {
    // Case for conditions connected with overflow should be checked,
    // and, maybe, removed in future (FPUCondition does not implement oveflow
    // cases)
    fclass_d(scratch, src1);
    fclass_d(scratch2, src2);
    Or(scratch2, scratch, scratch2);
    And(cmp, scratch2, FClassFlag::kQuietNaN | FClassFlag::kSignalingNaN);
    MacroAssembler::Branch(nan_failed, not_equal, cmp, Operand(zero_reg));
    And(cmp, scratch2,
        FClassFlag::kNegativeInfinity | FClassFlag::kPositiveInfinity);
    MacroAssembler::Branch(target, not_equal, cmp, Operand(zero_reg), distance);
  }
}

inline void MaglevAssembler::CompareFloat64AndBranch(
    DoubleRegister src1, DoubleRegister src2, Condition cond,
    BasicBlock* if_true, BasicBlock* if_false, BasicBlock* next_block,
    BasicBlock* nan_failed) {
  MaglevAssembler::TemporaryRegisterScope temps(this);
  Register scratch1 = temps.AcquireScratch();
  Register scratch2 = temps.AcquireScratch();
  // emit check for NaN
  feq_d(scratch1, src1, src1);
  feq_d(scratch2, src2, src2);
  Register any_nan = scratch2;
  And(any_nan, scratch1, scratch2);
  MacroAssembler::Branch(nan_failed->label(), equal, any_nan,
                         Operand(zero_reg));
  // actual comparison
  Register cmp = temps.AcquireScratch();
  bool fallthrough_when_true = (if_true == next_block);
  bool fallthrough_when_false = (if_false == next_block);
  Label* if_true_label = if_true->label();
  Label* if_false_label = if_false->label();
  if (fallthrough_when_false) {
    if (fallthrough_when_true) {
      // If both paths are a fallthrough, do nothing.
      DCHECK_EQ(if_true_label, if_false_label);
      return;
    }
    FPUCondition fcond = ConditionToConditionCmpFPU(cond);
    MacroAssembler::CompareF64(cmp, fcond, src1, src2);
    // Jump over the false block if true, otherwise fall through into it.
    MacroAssembler::Branch(if_true_label, ne, cmp, Operand(zero_reg),
                           Label::kFar);
  } else {
    FPUCondition neg_fcond = ConditionToConditionCmpFPU(NegateCondition(cond));
    MacroAssembler::CompareF64(cmp, neg_fcond, src1, src2);
    // Jump to the false block if true.
    MacroAssembler::Branch(if_false_label, ne, cmp, Operand(zero_reg),
                           Label::kFar);
    // Jump to the true block if it's not the next block.
    if (!fallthrough_when_true) {
      MacroAssembler::Branch(if_true_label, Label::kFar);
    }
  }
}

inline void MaglevAssembler::PrepareCallCFunction(int num_reg_arguments,
                                                  int num_double_registers) {
  MaglevAssembler::TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  MacroAssembler::PrepareCallCFunction(num_reg_arguments, num_double_registers,
                                       scratch);
}

inline void MaglevAssembler::CallSelf() {
  DCHECK(allow_call());
  DCHECK(code_gen_state()->entry_label()->is_bound());
  MacroAssembler::Branch(code_gen_state()->entry_label());
}

inline void MaglevAssembler::Jump(Label* target, Label::Distance distance) {
  DCHECK(!IsDeoptLabel(target));
  MacroAssembler::Branch(target, distance);
}

inline void MaglevAssembler::JumpToDeopt(Label* target) {
  DCHECK(IsDeoptLabel(target));
  MacroAssembler::Branch(target);
}

inline void MaglevAssembler::EmitEagerDeoptStress(Label* target) {
  // TODO(olivf): On arm `--deopt-every-n-times` is currently not supported.
  // Supporting it would require to implement this method, additionally handle
  // deopt branches in Cbz, and handle all cases where we fall through to the
  // deopt branch (like Int32Divide).
}

inline void MaglevAssembler::JumpIf(Condition cond, Label* target,
                                    Label::Distance distance) {
  // NOTE: for now keep in mind that we always put the result of a comparison
  // into dedicated register ("set flag"), and then compare it with x0.
  constexpr Register aflag = MaglevAssembler::GetFlagsRegister();
  MacroAssembler::Branch(target, cond, aflag, Operand(zero_reg), distance);
}

inline void MaglevAssembler::JumpIfRoot(Register with, RootIndex index,
                                        Label* if_equal,
                                        Label::Distance distance) {
  MacroAssembler::JumpIfRoot(with, index, if_equal, distance);
}

inline void MaglevAssembler::JumpIfNotRoot(Register with, RootIndex index,
                                           Label* if_not_equal,
                                           Label::Distance distance) {
  MacroAssembler::JumpIfNotRoot(with, index, if_not_equal, distance);
}

inline void MaglevAssembler::JumpIfSmi(Register src, Label* on_smi,
                                       Label::Distance distance) {
  MacroAssembler::JumpIfSmi(src, on_smi, distance);
}

inline void MaglevAssembler::JumpIfNotSmi(Register src, Label* on_smi,
                                          Label::Distance distance) {
  MacroAssembler::JumpIfNotSmi(src, on_smi, distance);
}

void MaglevAssembler::JumpIfByte(Condition cc, Register value, int32_t byte,
                                 Label* target, Label::Distance distance) {
  MacroAssembler::Branch(target, cc, value, Operand(byte), distance);
}

void MaglevAssembler::JumpIfHoleNan(DoubleRegister value, Register scratch,
                                    Label* target, Label::Distance distance) {
  // TODO(leszeks): Right now this only accepts Zone-allocated target labels.
  // This works because all callsites are jumping to either a deopt, deferred
  // code, or a basic block. If we ever need to jump to an on-stack label, we
  // have to add support for it here change the caller to pass a ZoneLabelRef.
  DCHECK(compilation_info()->zone()->Contains(target));
  ZoneLabelRef is_hole = ZoneLabelRef::UnsafeFromLabelPointer(target);
  ZoneLabelRef is_not_hole(this);
  MaglevAssembler::TemporaryRegisterScope temps(this);
  Register scratch2 = temps.AcquireScratch();

  feq_d(scratch2, value, value);  // 0 if value is NaN
  Label* deferred_code = MakeDeferredCode(
      [](MaglevAssembler* masm, DoubleRegister value, Register scratch,
         ZoneLabelRef is_hole, ZoneLabelRef is_not_hole) {
        masm->ExtractHighWordFromF64(scratch, value);
        masm->CompareInt32AndJumpIf(scratch, kHoleNanUpper32, kEqual, *is_hole);
        masm->MacroAssembler::Branch(*is_not_hole);
      },
      value, scratch, is_hole, is_not_hole);
  MacroAssembler::Branch(deferred_code, equal, scratch2, Operand(zero_reg));
  bind(*is_not_hole);
}

void MaglevAssembler::JumpIfNotHoleNan(DoubleRegister value, Register scratch,
                                       Label* target,
                                       Label::Distance distance) {
  JumpIfNotNan(value, target, distance);
  ExtractHighWordFromF64(scratch, value);
  CompareInt32AndJumpIf(scratch, kHoleNanUpper32, kNotEqual, target, distance);
}

void MaglevAssembler::JumpIfNotHoleNan(MemOperand operand, Label* target,
                                       Label::Distance distance) {
  MaglevAssembler::TemporaryRegisterScope temps(this);
  Register upper_bits = temps.AcquireScratch();
  Load32U(upper_bits,
          MemOperand(operand.rm(), operand.offset() + (kDoubleSize / 2)));
  CompareInt32AndJumpIf(upper_bits, kHoleNanUpper32, kNotEqual, target,
                        distance);
}

void MaglevAssembler::JumpIfNan(DoubleRegister value, Label* target,
                                Label::Distance distance) {
  MaglevAssembler::TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  feq_d(scratch, value, value);  // 0 if value is NaN
  MacroAssembler::Branch(target, equal, scratch, Operand(zero_reg), distance);
}

void MaglevAssembler::JumpIfNotNan(DoubleRegister value, Label* target,
                                   Label::Distance distance) {
  MaglevAssembler::TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  feq_d(scratch, value, value);  // 1 if value is not NaN
  MacroAssembler::Branch(target, not_equal, scratch, Operand(zero_reg),
                         distance);
}

inline void MaglevAssembler::CompareInt32AndJumpIf(Register r1, Register r2,
                                                   Condition cond,
                                                   Label* target,
                                                   Label::Distance distance) {
  MaglevAssembler::TemporaryRegisterScope temps(this);
  Register r1w = temps.AcquireScratch();
  Register r2w = temps.AcquireScratch();
  // TODO(Yuri Gaevsky): is zero/sign extension really needed here?
  switch (cond) {
    case ult:
    case uge:
    case ule:
    case ugt:
      ZeroExtendWord(r1w, r1);
      ZeroExtendWord(r2w, r2);
      break;
    default:
      SignExtend32To64Bits(r1w, r1);
      SignExtend32To64Bits(r2w, r2);
  }
  MacroAssembler::Branch(target, cond, r1w, Operand(r2w), distance);
}

void MaglevAssembler::CompareIntPtrAndJumpIf(Register r1, Register r2,
                                             Condition cond, Label* target,
                                             Label::Distance distance) {
  MacroAssembler::Branch(target, cond, r1, Operand(r2), distance);
}

inline void MaglevAssembler::CompareInt32AndJumpIf(Register r1, int32_t value,
                                                   Condition cond,
                                                   Label* target,
                                                   Label::Distance distance) {
  MaglevAssembler::TemporaryRegisterScope temps(this);
  Register r1w = temps.AcquireScratch();
  // TODO(Yuri Gaevsky): is zero/sign extension really needed here?
  switch (cond) {
    case ult:
    case uge:
    case ule:
    case ugt:
      ZeroExtendWord(r1w, r1);
      break;
    default:
      SignExtend32To64Bits(r1w, r1);
  }
  MacroAssembler::Branch(target, cond, r1w, Operand(value), distance);
}

inline void MaglevAssembler::CompareInt32AndAssert(Register r1, Register r2,
                                                   Condition cond,
                                                   AbortReason reason) {
  MaglevAssembler::TemporaryRegisterScope temps(this);
  Register r1w = temps.AcquireScratch();
  Register r2w = temps.AcquireScratch();
  // TODO(Yuri Gaevsky): is zero/sign extension really needed here?
  switch (cond) {
    case ult:
    case uge:
    case ule:
    case ugt:
      ZeroExtendWord(r1w, r1);
      ZeroExtendWord(r2w, r2);
      break;
    default:
      SignExtend32To64Bits(r1w, r1);
      SignExtend32To64Bits(r2w, r2);
  }
  MacroAssembler::Assert(cond, reason, r1w, Operand(r2w));
}

inline void MaglevAssembler::CompareInt32AndAssert(Register r1, int32_t value,
                                                   Condition cond,
                                                   AbortReason reason) {
  MaglevAssembler::TemporaryRegisterScope temps(this);
  Register r1w = temps.AcquireScratch();
  // TODO(Yuri Gaevsky): is zero/sign extension really needed here?
  switch (cond) {
    case ult:
    case uge:
    case ule:
    case ugt:
      ZeroExtendWord(r1w, r1);
      break;
    default:
      SignExtend32To64Bits(r1w, r1);
  }
  MacroAssembler::Assert(cond, reason, r1w, Operand(value));
}

inline void MaglevAssembler::CompareInt32AndBranch(
    Register r1, int32_t value, Condition cond, Label* if_true,
    Label::Distance true_distance, bool fallthrough_when_true, Label* if_false,
    Label::Distance false_distance, bool fallthrough_when_false) {
  // expect only specific conditions
  switch (cond) {
    case eq:
    case ne:
    case greater:
    case greater_equal:
    case less:
    case less_equal:
    case Ugreater:
    case Ugreater_equal:
    case Uless:
    case Uless_equal:
      break;  // expected
    case cc_always:
    default:
      UNREACHABLE();  // not expected
  }

  MaglevAssembler::TemporaryRegisterScope temps(this);
  Register lhs = temps.AcquireScratch();
  if (fallthrough_when_false) {
    if (fallthrough_when_true) {
      // If both paths are a fallthrough, do nothing.
      DCHECK_EQ(if_true, if_false);
      return;
    }
    // TODO(Yuri Gaevsky): is zero/sign extension really needed here?
    switch (cond) {
      case ult:
      case uge:
      case ule:
      case ugt:
        ZeroExtendWord(lhs, r1);
        break;
      default:
        SignExtend32To64Bits(lhs, r1);
    }
    // Jump over the false block if true, otherwise fall through into it.
    MacroAssembler::Branch(if_true, cond, lhs, Operand(value), true_distance);
  } else {
    // TODO(Yuri Gaevsky): is zero/sign extension really needed here?
    switch (cond) {
      case ult:
      case uge:
      case ule:
      case ugt:
        ZeroExtendWord(lhs, r1);
        break;
      default:
        SignExtend32To64Bits(lhs, r1);
    }
    // Jump to the false block if true.
    MacroAssembler::Branch(if_false, NegateCondition(cond), lhs, Operand(value),
                           false_distance);
    // Jump to the true block if it's not the next block.
    if (!fallthrough_when_true) {
      MacroAssembler::Branch(if_true, true_distance);
    }
  }
}

inline void MaglevAssembler::CompareInt32AndBranch(
    Register r1, Register value, Condition cond, Label* if_true,
    Label::Distance true_distance, bool fallthrough_when_true, Label* if_false,
    Label::Distance false_distance, bool fallthrough_when_false) {
  // expect only specific conditions
  switch (cond) {
    case eq:
    case ne:
    case greater:
    case greater_equal:
    case less:
    case less_equal:
    case Ugreater:
    case Ugreater_equal:
    case Uless:
    case Uless_equal:
      break;  // expected
    case cc_always:
    default:
      UNREACHABLE();  // not expected
  }

  MaglevAssembler::TemporaryRegisterScope temps(this);
  Register lhs = temps.AcquireScratch();
  Register rhs = temps.AcquireScratch();
  if (fallthrough_when_false) {
    if (fallthrough_when_true) {
      // If both paths are a fallthrough, do nothing.
      DCHECK_EQ(if_true, if_false);
      return;
    }
    // TODO(Yuri Gaevsky): is zero/sign extension really needed here?
    switch (cond) {
      case ult:
      case uge:
      case ule:
      case ugt:
        ZeroExtendWord(lhs, r1);
        ZeroExtendWord(rhs, value);
        break;
      default:
        SignExtend32To64Bits(lhs, r1);
        SignExtend32To64Bits(rhs, value);
    }
    // Jump over the false block if true, otherwise fall through into it.
    MacroAssembler::Branch(if_true, cond, lhs, Operand(rhs), true_distance);
  } else {
    switch (cond) {
      // TODO(Yuri Gaevsky): is zero/sign extension really needed here?
      case ult:
      case uge:
      case ule:
      case ugt:
        ZeroExtendWord(lhs, r1);
        ZeroExtendWord(rhs, value);
        break;
      default:
        SignExtend32To64Bits(lhs, r1);
        SignExtend32To64Bits(rhs, value);
    }
    // Jump to the false block if true.
    MacroAssembler::Branch(if_false, NegateCondition(cond), lhs, Operand(rhs),
                           false_distance);
    // Jump to the true block if it's not the next block.
    if (!fallthrough_when_true) {
      MacroAssembler::Branch(if_true, true_distance);
    }
  }
}

inline void MaglevAssembler::CompareSmiAndJumpIf(Register r1, Tagged<Smi> value,
                                                 Condition cond, Label* target,
                                                 Label::Distance distance) {
  AssertSmi(r1);
  CompareTaggedAndBranch(target, cond, r1, Operand(value), distance);
}

inline void MaglevAssembler::CompareByteAndJumpIf(MemOperand left, int8_t right,
                                                  Condition cond,
                                                  Register scratch,
                                                  Label* target,
                                                  Label::Distance distance) {
  LoadByte(scratch, left);
  MacroAssembler::Branch(target, cond, scratch, Operand(right), distance);
}

inline void MaglevAssembler::CompareTaggedAndJumpIf(Register r1,
                                                    Tagged<Smi
"""


```