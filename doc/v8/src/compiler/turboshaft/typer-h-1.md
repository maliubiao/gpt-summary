Response:
The user wants to understand the functionality of a C++ header file related to type analysis in the V8 JavaScript engine's Turboshaft compiler.

Here's a plan to address the request:

1. **Identify the core purpose:** The code defines classes and methods for inferring and manipulating types of values during compilation.
2. **Break down the functionality:** Analyze the different classes (`FloatOperationTyper`, `WordOperationTyper`, `Typer`) and their methods.
3. **Illustrate with JavaScript:** If a functionality relates to JavaScript behavior, provide a simple JavaScript example.
4. **Demonstrate logical inference:** For code performing logical deductions about types, give an example with input and output types.
5. **Point out potential errors:** Identify scenarios where incorrect type assumptions could lead to issues.
6. **Summarize the overall function:** Provide a concise summary of the header file's role.```cpp
an = l.has_nan() || r.has_nan();

    // In order to ensure monotonicity of the computation below, we additionally
    // pretend +0 is present (for simplicity on both sides).
    bool maybe_minuszero = false;
    if (l.has_minus_zero() && !(r.min() > 0.0)) {
      maybe_minuszero = true;
      l = type_t::LeastUpperBound(l, type_t::Constant(0), zone);
    }
    if (r.has_minus_zero() && !(l.min() > 0.0)) {
      maybe_minuszero = true;
      r = type_t::LeastUpperBound(r, type_t::Constant(0), zone);
    }

    uint32_t special_values = (maybe_nan ? type_t::kNaN : 0) |
                              (maybe_minuszero ? type_t::kMinusZero : 0);
    // If both sides are decently small sets, we produce the product set.
    auto combine = [](float_t a, float_t b) { return std::max(a, b); };
    if (l.is_set() && r.is_set()) {
      // TODO(nicohartmann@): There is a faster way to compute this set.
      auto result = ProductSet(l, r, special_values, zone, combine);
      if (!result.IsInvalid()) return result;
    }

    // Otherwise just construct a range.
    auto [l_min, l_max] = l.minmax();
    auto [r_min, r_max] = r.minmax();

    auto min = std::max(l_min, r_min);
    auto max = std::max(l_max, r_max);
    return Range(min, max, special_values, zone);
  }

  static Type Power(const type_t& l, const type_t& r, Zone* zone) {
    // x ** NaN => Nan.
    if (r.is_only_nan()) return type_t::NaN();
    // x ** +-0 => 1.
    if (r.is_constant(0) || r.is_only_minus_zero()) return type_t::Constant(1);
    if (l.is_only_nan()) {
      // NaN ** 0 => 1.
      if (r.Contains(0) || r.has_minus_zero()) {
        return type_t::Set({1}, type_t::kNaN, zone);
      }
      // NaN ** x => NaN (x != +-0).
      return type_t::NaN();
    }
    bool maybe_nan = l.has_nan() || r.has_nan();
    // +-1 ** +-Infinity => NaN.
    if (r.Contains(-inf) || r.Contains(inf)) {
      if (l.Contains(1) || l.Contains(-1)) maybe_nan = true;
    }

    // a ** b produces NaN if a < 0 && b is fraction.
    if (l.min() < 0.0 && !IsIntegerSet(r)) maybe_nan = true;

    // Precise checks for when the result can be -0 is difficult, because of
    // large (negative) exponents. To be safe we add -0 whenever the left hand
    // side can be negative. We might refine this when necessary.
    bool maybe_minus_zero = l.min() < 0.0 || l.has_minus_zero();
    uint32_t special_values = (maybe_nan ? type_t::kNaN : 0) |
                              (maybe_minus_zero ? type_t::kMinusZero : 0) |
                              l.special_values();

    // If both sides are decently small sets, we produce the product set.
    auto combine = [](float_t a, float_t b) { return std::pow(a, b); };
    if (l.is_set() && r.is_set()) {
      auto result = ProductSet(l, r, special_values, zone, combine);
      if (!result.IsInvalid()) return result;
    }

    // TODO(nicohartmann@): Maybe we can produce a more precise range here.
    return type_t::Any(special_values);
  }

  static Type Atan2(const type_t& l, const type_t& r, Zone* zone) {
    // TODO(nicohartmann@): Maybe we can produce a more precise range here.
    return type_t::Any();
  }

  static Type LessThan(const type_t& lhs, const type_t& rhs, Zone* zone) {
    bool can_be_true = false;
    bool can_be_false = false;
    if (lhs.is_only_special_values()) {
      if (lhs.has_minus_zero()) {
        can_be_true = !rhs.is_only_special_values() && rhs.max() > 0.0;
        can_be_false = rhs.min() <= 0.0;
      } else {
        DCHECK(lhs.is_only_nan());
      }
    } else if (rhs.is_only_special_values()) {
      if (rhs.has_minus_zero()) {
        can_be_true = lhs.min() < 0.0;
        can_be_false = lhs.max() >= 0.0;
      } else {
        DCHECK(rhs.is_only_nan());
      }
    } else {
      // Both sides have at least one non-special value. We don't have to treat
      // special values here, because nan has been taken care of already and
      // -0.0 is included in min/max.
      can_be_true = lhs.min() < rhs.max();
      can_be_false = lhs.max() >= rhs.min();
    }

    // Consider NaN.
    can_be_false = can_be_false || lhs.has_nan() || rhs.has_nan();

    if (!can_be_true) return Word32Type::Constant(0);
    if (!can_be_false) return Word32Type::Constant(1);
    return Word32Type::Set({0, 1}, zone);
  }

  static Type LessThanOrEqual(const type_t& lhs, const type_t& rhs,
                              Zone* zone) {
    bool can_be_true = false;
    bool can_be_false = false;
    if (lhs.is_only_special_values()) {
      if (lhs.has_minus_zero()) {
        can_be_true = (!rhs.is_only_special_values() && rhs.max() >= 0.0) ||
                      rhs.has_minus_zero();
        can_be_false = rhs.min() < 0.0;
      } else {
        DCHECK(lhs.is_only_nan());
      }
    } else if (rhs.is_only_special_values()) {
      if (rhs.has_minus_zero()) {
        can_be_true = (!lhs.is_only_special_values() && lhs.min() <= 0.0) ||
                      lhs.has_minus_zero();
        can_be_false = lhs.max() > 0.0;
      } else {
        DCHECK(rhs.is_only_nan());
      }
    } else {
      // Both sides have at least one non-special value. We don't have to treat
      // special values here, because nan has been taken care of already and
      // -0.0 is included in min/max.
      can_be_true = can_be_true || lhs.min() <= rhs.max();
      can_be_false = can_be_false || lhs.max() > rhs.min();
    }

    // Consider NaN.
    can_be_false = can_be_false || lhs.has_nan() || rhs.has_nan();

    if (!can_be_true) return Word32Type::Constant(0);
    if (!can_be_false) return Word32Type::Constant(1);
    return Word32Type::Set({0, 1}, zone);
  }

  static Word32Type UnsignedLessThanOrEqual(const type_t& lhs,
                                            const type_t& rhs, Zone* zone) {
    bool can_be_true = lhs.unsigned_min() <= rhs.unsigned_max();
    bool can_be_false = lhs.unsigned_max() > rhs.unsigned_min();

    if (!can_be_true) return Word32Type::Constant(0);
    if (!can_be_false) return Word32Type::Constant(1);
    return Word32Type::Set({0, 1}, zone);
  }

  // Computes the ranges to which the sides of the comparison (lhs < rhs) can be
  // restricted when the comparison is true. When the comparison is true, we
  // learn: lhs cannot be >= rhs.max and rhs cannot be <= lhs.min and neither
  // can be NaN.
  static std::pair<Type, Type> RestrictionForLessThan_True(const type_t& lhs,
                                                           const type_t& rhs,
                                                           Zone* zone) {
    // If either side is only NaN, this comparison can never be true.
    if (lhs.is_only_nan() || rhs.is_only_nan()) {
      return {Type::None(), Type::None()};
    }

    Type restrict_lhs;
    if (rhs.max() == -inf) {
      // There is no value for lhs that could make (lhs < -inf) true.
      restrict_lhs = Type::None();
    } else {
      const auto max = next_smaller(rhs.max());
      uint32_t sv = max >= 0 ? type_t::kMinusZero : type_t::kNoSpecialValues;
      restrict_lhs = type_t::Range(-inf, max, sv, zone);
    }

    Type restrict_rhs;
    if (lhs.min() == inf) {
      // There is no value for rhs that could make (inf < rhs) true.
      restrict_rhs = Type::None();
    } else {
      const auto min = next_larger(lhs.min());
      uint32_t sv = min <= 0 ? type_t::kMinusZero : type_t::kNoSpecialValues;
      restrict_rhs = type_t::Range(min, inf, sv, zone);
    }

    return {restrict_lhs, restrict_rhs};
  }

  // Computes the ranges to which the sides of the comparison (lhs < rhs) can be
  // restricted when the comparison is false. When the comparison is false, we
  // learn: lhs cannot be < rhs.min and rhs cannot be > lhs.max.
  static std::pair<Type, Type> RestrictionForLessThan_False(const type_t& lhs,
                                                            const type_t& rhs,
                                                            Zone* zone) {
    Type restrict_lhs;
    if (rhs.has_nan()) {
      restrict_lhs = type_t::Any();
    } else {
      uint32_t lhs_sv =
          type_t::kNaN |
          (rhs.min() <= 0 ? type_t::kMinusZero : type_t::kNoSpecialValues);
      restrict_lhs = type_t::Range(rhs.min(), inf, lhs_sv, zone);
    }

    Type restrict_rhs;
    if (lhs.has_nan()) {
      restrict_rhs = type_t::Any();
    } else {
      uint32_t rhs_sv =
          type_t::kNaN |
          (lhs.max() >= 0 ? type_t::kMinusZero : type_t::kNoSpecialValues);
      restrict_rhs = type_t::Range(-inf, lhs.max(), rhs_sv, zone);
    }

    return {restrict_lhs, restrict_rhs};
  }

  // Computes the ranges to which the sides of the comparison (lhs <= rhs) can
  // be restricted when the comparison is true. When the comparison is true, we
  // learn: lhs cannot be > rhs.max and rhs cannot be < lhs.min and neither can
  // be NaN.
  static std::pair<Type, Type> RestrictionForLessThanOrEqual_True(
      const type_t& lhs, const type_t& rhs, Zone* zone) {
    // If either side is only NaN, this comparison can never be true.
    if (lhs.is_only_nan() || rhs.is_only_nan()) {
      return {Type::None(), Type::None()};
    }

    uint32_t lhs_sv =
        rhs.max() >= 0 ? type_t::kMinusZero : type_t::kNoSpecialValues;
    uint32_t rhs_sv =
        lhs.min() <= 0 ? type_t::kMinusZero : type_t::kNoSpecialValues;
    return {type_t::Range(-inf, rhs.max(), lhs_sv, zone),
            type_t::Range(lhs.min(), inf, rhs_sv, zone)};
  }

  // Computes the ranges to which the sides of the comparison (lhs <= rhs) can
  // be restricted when the comparison is false. When the comparison is false,
  // we learn: lhs cannot be <= rhs.min and rhs cannot be >= lhs.max.
  static std::pair<Type, Type> RestrictionForLessThanOrEqual_False(
      const type_t& lhs, const type_t& rhs, Zone* zone) {
    Type restrict_lhs;
    if (rhs.has_nan()) {
      restrict_lhs = type_t::Any();
    } else if (rhs.min() == inf) {
      // The only value for lhs that could make (lhs <= inf) false is NaN.
      restrict_lhs = type_t::NaN();
    } else {
      const auto min = next_larger(rhs.min());
      uint32_t sv = type_t::kNaN |
                    (min <= 0 ? type_t::kMinusZero : type_t::kNoSpecialValues);
      restrict_lhs = type_t::Range(min, inf, sv, zone);
    }

    Type restrict_rhs;
    if (lhs.has_nan()) {
      restrict_rhs = type_t::Any();
    } else if (lhs.max() == -inf) {
      // The only value for rhs that could make (-inf <= rhs) false is NaN.
      restrict_rhs = type_t::NaN();
    } else {
      const auto max = next_smaller(lhs.max());
      uint32_t sv = type_t::kNaN |
                    (max >= 0 ? type_t::kMinusZero : type_t::kNoSpecialValues);
      restrict_rhs = type_t::Range(-inf, max, sv, zone);
    }

    return {restrict_lhs, restrict_rhs};
  }
};

class Typer {
 public:
  static Type TypeForRepresentation(RegisterRepresentation rep) {
    switch (rep.value()) {
      case RegisterRepresentation::Word32():
        return Word32Type::Any();
      case RegisterRepresentation::Word64():
        return Word64Type::Any();
      case RegisterRepresentation::Float32():
        return Float32Type::Any();
      case RegisterRepresentation::Float64():
        return Float64Type::Any();

      case RegisterRepresentation::Tagged():
      case RegisterRepresentation::Compressed():
      case RegisterRepresentation::Simd128():
      case RegisterRepresentation::Simd256():
        // TODO(nicohartmann@): Support these representations.
        return Type::Any();
    }
  }

  static Type TypeForRepresentation(
      base::Vector<const RegisterRepresentation> reps, Zone* zone) {
    DCHECK_LT(0, reps.size());
    if (reps.size() == 1) return TypeForRepresentation(reps[0]);
    base::SmallVector<Type, 4> tuple_types;
    for (auto rep : reps) tuple_types.push_back(TypeForRepresentation(rep));
    return TupleType::Tuple(base::VectorOf(tuple_types), zone);
  }

  static Type TypeConstant(ConstantOp::Kind kind, ConstantOp::Storage value) {
    switch (kind) {
      case ConstantOp::Kind::kFloat32:
        if (value.float32.is_nan()) return Float32Type::NaN();
        if (IsMinusZero(value.float32.get_scalar()))
          return Float32Type::MinusZero();
        return Float32Type::Constant(value.float32.get_scalar());
      case ConstantOp::Kind::kFloat64:
        if (value.float64.is_nan()) return Float64Type::NaN();
        if (IsMinusZero(value.float64.get_scalar()))
          return Float64Type::MinusZero();
        return Float64Type::Constant(value.float64.get_scalar());
      case ConstantOp::Kind::kWord32:
        return Word32Type::Constant(static_cast<uint32_t>(value.integral));
      case ConstantOp::Kind::kWord64:
        return Word64Type::Constant(static_cast<uint64_t>(value.integral));
      default:
        // TODO(nicohartmann@): Support remaining {kind}s.
        return Type::Any();
    }
  }

  static Type TypeProjection(const Type& input, uint16_t idx) {
    if (input.IsNone()) return Type::None();
    if (!input.IsTuple()) return Type::Any();
    const TupleType& tuple = input.AsTuple();
    DCHECK_LT(idx, tuple.size());
    return tuple.element(idx);
  }

  static Type TypeWordBinop(Type left_type, Type right_type,
                            WordBinopOp::Kind kind, WordRepresentation rep,
                            Zone* zone) {
    DCHECK(!left_type.IsInvalid());
    DCHECK(!right_type.IsInvalid());

    if (rep == WordRepresentation::Word32()) {
      switch (kind) {
        case WordBinopOp::Kind::kAdd:
          return TypeWord32Add(left_type, right_type, zone);
        case WordBinopOp::Kind::kSub:
          return TypeWord32Sub(left_type, right_type, zone);
        default:
          // TODO(nicohartmann@): Support remaining {kind}s.
          return Word32Type::Any();
      }
    } else {
      DCHECK_EQ(rep, WordRepresentation::Word64());
      switch (kind) {
        case WordBinopOp::Kind::kAdd:
          return TypeWord64Add(left_type, right_type, zone);
        case WordBinopOp::Kind::kSub:
          return TypeWord64Sub(left_type, right_type, zone);
        default:
          // TODO(nicohartmann@): Support remaining {kind}s.
          return Word64Type::Any();
      }
    }
  }

  static Type TypeWord32Add(const Type& lhs, const Type& rhs, Zone* zone) {
    if (lhs.IsNone() || rhs.IsNone()) return Type::None();
    auto l = TruncateWord32Input(lhs, true, zone);
    auto r = TruncateWord32Input(rhs, true, zone);
    return WordOperationTyper<32>::Add(l, r, zone);
  }

  static Type TypeWord32Sub(const Type& lhs, const Type& rhs, Zone* zone) {
    if (lhs.IsNone() || rhs.IsNone()) return Type::None();
    auto l = TruncateWord32Input(lhs, true, zone);
    auto r = TruncateWord32Input(rhs, true, zone);
    return WordOperationTyper<32>::Subtract(l, r, zone);
  }

  static Type TypeWord64Add(const Type& lhs, const Type& rhs, Zone* zone) {
    if (lhs.IsNone() || rhs.IsNone()) return Type::None();
    if (!InputIs(lhs, Type::Kind::kWord64) ||
        !InputIs(rhs, Type::Kind::kWord64)) {
      return Word64Type::Any();
    }
    const auto& l = lhs.AsWord64();
    const auto& r = rhs.AsWord64();

    return WordOperationTyper<64>::Add(l, r, zone);
  }

  static Type TypeWord64Sub(const Type& lhs, const Type& rhs, Zone* zone) {
    if (lhs.IsNone() || rhs.IsNone()) return Type::None();
    if (!InputIs(lhs, Type::Kind::kWord64) ||
        !InputIs(rhs, Type::Kind::kWord64)) {
      return Word64Type::Any();
    }

    const auto& l = lhs.AsWord64();
    const auto& r = rhs.AsWord64();

    return WordOperationTyper<64>::Subtract(l, r, zone);
  }

  static Type TypeFloatBinop(Type left_type, Type right_type,
                             FloatBinopOp::Kind kind, FloatRepresentation rep,
                             Zone* zone) {
    DCHECK(!left_type.IsInvalid());
    DCHECK(!right_type.IsInvalid());

#define FLOAT_BINOP(op, bits)     \
  case FloatBinopOp::Kind::k##op: \
    return TypeFloat##bits##op(left_type, right_type, zone);

    if (rep == FloatRepresentation::Float32()) {
      switch (kind) {
        FLOAT_BINOP(Add, 32)
        FLOAT_BINOP(Sub, 32)
        FLOAT_BINOP(Mul, 32)
        FLOAT_BINOP(Div, 32)
        FLOAT_BINOP(Mod, 32)
        FLOAT_BINOP(Min, 32)
        FLOAT_BINOP(Max, 32)
        FLOAT_BINOP(Power, 32)
        FLOAT_BINOP(Atan2, 32)
      }
    } else {
      DCHECK_EQ(rep, FloatRepresentation::Float64());
      switch (kind) {
        FLOAT_BINOP(Add, 64)
        FLOAT_BINOP(Sub, 64)
        FLOAT_BINOP(Mul, 64)
        FLOAT_BINOP(Div, 64)
        FLOAT_BINOP(Mod, 64)
        FLOAT_BINOP(Min, 64)
        FLOAT_BINOP(Max, 64)
        FLOAT_BINOP(Power, 64)
        FLOAT_BINOP(Atan2, 64)
      }
    }

#undef FLOAT_BINOP
  }

#define FLOAT_BINOP(op, bits, float_typer_handler)                     \
  static Type TypeFloat##bits##op(const Type& lhs, const Type& rhs,    \
                                  Zone* zone) {                        \
    if (lhs.IsNone() || rhs.IsNone()) return Type::None();             \
    if (!InputIs(lhs, Type::Kind::kFloat##bits) ||                     \
        !InputIs(rhs, Type::Kind::kFloat##bits)) {                     \
      return Float##bits##Type::Any();                                 \
    }                                                                  \
    const auto& l = lhs.AsFloat##bits();                               \
    const auto& r = rhs.AsFloat##bits();                               \
    return FloatOperationTyper<bits>::float_typer_handler(l, r, zone); \
  }

  // Float32 operations
  FLOAT_BINOP(Add, 32, Add)
  FLOAT_BINOP(Sub, 32, Subtract)
  FLOAT_BINOP(Mul, 32, Multiply)
  FLOAT_BINOP(Div, 32, Divide)
  FLOAT_BINOP(Mod, 32, Modulus)
  FLOAT_BINOP(Min, 32, Min)
  FLOAT_BINOP(Max, 32, Max)
  FLOAT_BINOP(Power, 32, Power)
  FLOAT_BINOP(Atan2, 32, Atan2)
  // Float64 operations
  FLOAT_BINOP(Add, 64, Add)
  FLOAT_BINOP(Sub, 64, Subtract)
  FLOAT_BINOP(Mul, 64, Multiply)
  FLOAT_BINOP(Div, 64, Divide)
  FLOAT_BINOP(Mod, 64, Modulus)
  FLOAT_BINOP(Min, 64, Min)
  FLOAT_BINOP(Max, 64, Max)
  FLOAT_BINOP(Power, 64, Power)
  FLOAT_BINOP(Atan2, 64, Atan2)
#undef FLOAT_BINOP

  static Type TypeOverflowCheckedBinop(const Type& left_type,
                                       const Type& right_type,
                                       OverflowCheckedBinopOp::Kind kind,
                                       WordRepresentation rep, Zone* zone) {
    DCHECK(!left_type.IsInvalid());
    DCHECK(!right_type.IsInvalid());

    if (rep == WordRepresentation::Word32()) {
      switch (kind) {
        case OverflowCheckedBinopOp::Kind::kSignedAdd:
          return TypeWord32OverflowCheckedAdd(left_type, right_type, zone);
        case OverflowCheckedBinopOp::Kind::kSignedSub:
        case OverflowCheckedBinopOp::Kind::kSignedMul:
          // TODO(nicohartmann@): Support these.
          return TupleType::Tuple(Word32Type::Any(),
                                  Word32Type::Set({0, 1}, zone), zone);
      }
    } else {
      DCHECK_EQ(rep, WordRepresentation::Word64());
      switch (kind) {
        case OverflowCheckedBinopOp::Kind::kSignedAdd:
        case OverflowCheckedBinopOp::Kind::kSignedSub:
        case OverflowCheckedBinopOp::Kind::kSignedMul:
          // TODO(nicohartmann@): Support these.
          return TupleType::Tuple(Word64Type::Any(),
                                  Word32Type::Set({0, 1}, zone), zone);
      }
    }
  }

  static Type TypeWord32OverflowCheckedAdd(const Type& lhs, const Type& rhs,
                                           Zone* zone) {
    if (lhs.IsNone() || rhs.IsNone()) return Type::None();
    auto l = TruncateWord32Input(lhs, true, zone);
    auto r = TruncateWord32Input(rhs, true, zone);

    auto value = WordOperationTyper<32>::Add(l, r, zone);
    // We check for signed overflow and if the topmost bits of both opperands
    // are 0, we know that the result cannot overflow.
    if ((0xC0000000 & l.unsigned_max()) == 0 &&
        (0xC0000000 & r.unsigned_max()) == 0) {
      // Cannot overflow.
      return TupleType::Tuple(value, Word32Type::Constant(0), zone);
    }
    // Special case for two constant inputs to figure out the overflow.
    if (l.is_constant() && r.is_constant()) {
      constexpr uint32_t msb_mask = 0x80000000;
      DCHECK(value.is_constant());
      uint32_t l_msb = (*l.try_get_constant()) & msb_mask;
      uint32_t r_msb = (*r.try_get_constant()) & msb_mask;
      if (l_msb != r_msb) {
        // Different sign bits can never lead to an overflow.
        return TupleType::Tuple(value, Word32Type::Constant(0), zone);
      }
      uint32_t value_msb = (*value.try_get_constant()) & msb_mask;
      const uint32_t overflow = value_msb == l_msb ? 0 : 1;
      return TupleType::Tuple(value, Word32Type::Constant(overflow), zone);
    }
    // Otherwise we accept some imprecision.
    return TupleType::Tuple(value, Word32Type::Set({0, 1}, zone), zone);
  }

  static Type TypeComparison(const Type& lhs, const Type& rhs,
                             RegisterRepresentation rep,
                             ComparisonOp::Kind kind, Zone* zone) {
    switch (rep.value()) {
      case RegisterRepresentation::Word32():
        return TypeWord32Comparison(lhs, rhs, kind, zone);
      case RegisterRepresentation::Word64():
        return TypeWord64Comparison(lhs, rhs, kind, zone);
      case RegisterRepresentation::Float32():
        return TypeFloat32Comparison(lhs, rhs, kind, zone);
      case RegisterRepresentation::Float64():
        return TypeFloat64Comparison(lhs, rhs, kind, zone);
      case RegisterRepresentation::Tagged():
      case RegisterRepresentation::Compressed():
      case RegisterRepresentation::Simd128():
      case RegisterRepresentation::Simd256():
        if (lhs.IsNone() || rhs.IsNone()) return Type::None();
        // TODO(nicohartmann@): Support those cases.
        return Word32Type::Set({0, 1}, zone);
    }
  }

  static Type TypeWord32Comparison(const Type& lhs, const Type& rhs,
                                   ComparisonOp::Kind kind, Zone* zone) {
    if (lhs.IsNone() || rhs.IsNone()) return Type::None();
    auto l = TruncateWord32Input(lhs, true, zone);
    auto r = TruncateWord32Input(rhs, true, zone);
    switch (kind) {
      case ComparisonOp::Kind::kEqual:
      case ComparisonOp::Kind::kSignedLessThan:
      case ComparisonOp::Kind::kSignedLessThanOrEqual:
        // TODO(nicohartmann@): Support this.
        return Word32Type::Set({0, 1}, zone);
      case ComparisonOp::Kind::kUnsignedLessThan:
        return WordOperationTyper<32>::UnsignedLessThan(l, r, zone);
      case ComparisonOp::Kind::kUnsignedLessThanOrEqual:
        return WordOperationTyper<32>::UnsignedLessThanOrEqual(l, r, zone);
    }
    UNREACHABLE();
  }

  static Type TypeWord64Comparison(const Type& lhs, const Type& rhs,
                                   ComparisonOp::Kind kind, Zone* zone) {
    if (lhs.IsNone() || rhs.IsNone()) return Type::None();
    switch (kind) {
      case ComparisonOp::Kind::kEqual:
      case ComparisonOp::Kind::kSignedLessThan:
      case ComparisonOp::Kind::kSignedLessThanOrEqual:
        // TODO(nicohartmann@): Support this.
        return Word32Type::Set({0, 1}, zone);
      case ComparisonOp::Kind::kUnsignedLessThan:
        return WordOperationTyper<64>::UnsignedLessThan(lhs.AsWord64(),
                                                        rhs.AsWord64(), zone);
      case ComparisonOp::Kind::kUnsignedLessThanOrEqual:
        return WordOperationTyper<64>::UnsignedLessThanOrEqual(
            lhs.AsWord64(), rhs.AsWord64(), zone);
    }
    UNREACHABLE();
  }

  static Type TypeFloat32Comparison(const Type& lhs, const Type& rhs,
                                    ComparisonOp::Kind kind, Zone* zone) {
    if (lhs.IsNone() || rhs.IsNone()) return Type::None();
    switch (kind) {
      case ComparisonOp::Kind::kEqual:
        // TODO(nicohartmann@): Support this.
        return Word32Type::Set({0, 1}, zone);
      case ComparisonOp::Kind::kSignedLessThan:
        return FloatOperationTyper<32>::LessThan(lhs.AsFloat32(),
                                                 rhs.AsFloat32(), zone);
      case ComparisonOp::Kind::kSignedLessThanOrEqual:
        return FloatOperationTyper<32>::LessThanOrEqual(lhs.AsFloat32(),
                                                        rhs.AsFloat32(), zone);
      case ComparisonOp::Kind::kUnsignedLessThan:
      case ComparisonOp::Kind::kUnsignedLessThanOrEqual:
        UNREACHABLE();
    }
  }

  static Type TypeFloat64Comparison(const Type& lhs, const Type& rhs,
                                    ComparisonOp::Kind kind, Zone* zone) {
    if (lhs.IsNone() || rhs.IsNone()) return Type::None();
    switch (kind) {
      case ComparisonOp::Kind::kEqual:
        // TODO(nicohartmann@): Support this.
        return Word32Type::Set({0, 1}, zone);
      case ComparisonOp::Kind::kSignedLessThan:
        return FloatOperationTyper<64>::LessThan(lhs.AsFloat64(),
                                                 rhs.AsFloat64(), zone);
      case ComparisonOp::Kind::kSignedLessThanOrEqual:
        
### 提示词
```
这是目录为v8/src/compiler/turboshaft/typer.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/turboshaft/typer.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```c
an = l.has_nan() || r.has_nan();

    // In order to ensure monotonicity of the computation below, we additionally
    // pretend +0 is present (for simplicity on both sides).
    bool maybe_minuszero = false;
    if (l.has_minus_zero() && !(r.min() > 0.0)) {
      maybe_minuszero = true;
      l = type_t::LeastUpperBound(l, type_t::Constant(0), zone);
    }
    if (r.has_minus_zero() && !(l.min() > 0.0)) {
      maybe_minuszero = true;
      r = type_t::LeastUpperBound(r, type_t::Constant(0), zone);
    }

    uint32_t special_values = (maybe_nan ? type_t::kNaN : 0) |
                              (maybe_minuszero ? type_t::kMinusZero : 0);
    // If both sides are decently small sets, we produce the product set.
    auto combine = [](float_t a, float_t b) { return std::max(a, b); };
    if (l.is_set() && r.is_set()) {
      // TODO(nicohartmann@): There is a faster way to compute this set.
      auto result = ProductSet(l, r, special_values, zone, combine);
      if (!result.IsInvalid()) return result;
    }

    // Otherwise just construct a range.
    auto [l_min, l_max] = l.minmax();
    auto [r_min, r_max] = r.minmax();

    auto min = std::max(l_min, r_min);
    auto max = std::max(l_max, r_max);
    return Range(min, max, special_values, zone);
  }

  static Type Power(const type_t& l, const type_t& r, Zone* zone) {
    // x ** NaN => Nan.
    if (r.is_only_nan()) return type_t::NaN();
    // x ** +-0 => 1.
    if (r.is_constant(0) || r.is_only_minus_zero()) return type_t::Constant(1);
    if (l.is_only_nan()) {
      // NaN ** 0 => 1.
      if (r.Contains(0) || r.has_minus_zero()) {
        return type_t::Set({1}, type_t::kNaN, zone);
      }
      // NaN ** x => NaN (x != +-0).
      return type_t::NaN();
    }
    bool maybe_nan = l.has_nan() || r.has_nan();
    // +-1 ** +-Infinity => NaN.
    if (r.Contains(-inf) || r.Contains(inf)) {
      if (l.Contains(1) || l.Contains(-1)) maybe_nan = true;
    }

    // a ** b produces NaN if a < 0 && b is fraction.
    if (l.min() < 0.0 && !IsIntegerSet(r)) maybe_nan = true;

    // Precise checks for when the result can be -0 is difficult, because of
    // large (negative) exponents. To be safe we add -0 whenever the left hand
    // side can be negative. We might refine this when necessary.
    bool maybe_minus_zero = l.min() < 0.0 || l.has_minus_zero();
    uint32_t special_values = (maybe_nan ? type_t::kNaN : 0) |
                              (maybe_minus_zero ? type_t::kMinusZero : 0) |
                              l.special_values();

    // If both sides are decently small sets, we produce the product set.
    auto combine = [](float_t a, float_t b) { return std::pow(a, b); };
    if (l.is_set() && r.is_set()) {
      auto result = ProductSet(l, r, special_values, zone, combine);
      if (!result.IsInvalid()) return result;
    }

    // TODO(nicohartmann@): Maybe we can produce a more precise range here.
    return type_t::Any(special_values);
  }

  static Type Atan2(const type_t& l, const type_t& r, Zone* zone) {
    // TODO(nicohartmann@): Maybe we can produce a more precise range here.
    return type_t::Any();
  }

  static Type LessThan(const type_t& lhs, const type_t& rhs, Zone* zone) {
    bool can_be_true = false;
    bool can_be_false = false;
    if (lhs.is_only_special_values()) {
      if (lhs.has_minus_zero()) {
        can_be_true = !rhs.is_only_special_values() && rhs.max() > 0.0;
        can_be_false = rhs.min() <= 0.0;
      } else {
        DCHECK(lhs.is_only_nan());
      }
    } else if (rhs.is_only_special_values()) {
      if (rhs.has_minus_zero()) {
        can_be_true = lhs.min() < 0.0;
        can_be_false = lhs.max() >= 0.0;
      } else {
        DCHECK(rhs.is_only_nan());
      }
    } else {
      // Both sides have at least one non-special value. We don't have to treat
      // special values here, because nan has been taken care of already and
      // -0.0 is included in min/max.
      can_be_true = lhs.min() < rhs.max();
      can_be_false = lhs.max() >= rhs.min();
    }

    // Consider NaN.
    can_be_false = can_be_false || lhs.has_nan() || rhs.has_nan();

    if (!can_be_true) return Word32Type::Constant(0);
    if (!can_be_false) return Word32Type::Constant(1);
    return Word32Type::Set({0, 1}, zone);
  }

  static Type LessThanOrEqual(const type_t& lhs, const type_t& rhs,
                              Zone* zone) {
    bool can_be_true = false;
    bool can_be_false = false;
    if (lhs.is_only_special_values()) {
      if (lhs.has_minus_zero()) {
        can_be_true = (!rhs.is_only_special_values() && rhs.max() >= 0.0) ||
                      rhs.has_minus_zero();
        can_be_false = rhs.min() < 0.0;
      } else {
        DCHECK(lhs.is_only_nan());
      }
    } else if (rhs.is_only_special_values()) {
      if (rhs.has_minus_zero()) {
        can_be_true = (!lhs.is_only_special_values() && lhs.min() <= 0.0) ||
                      lhs.has_minus_zero();
        can_be_false = lhs.max() > 0.0;
      } else {
        DCHECK(rhs.is_only_nan());
      }
    } else {
      // Both sides have at least one non-special value. We don't have to treat
      // special values here, because nan has been taken care of already and
      // -0.0 is included in min/max.
      can_be_true = can_be_true || lhs.min() <= rhs.max();
      can_be_false = can_be_false || lhs.max() > rhs.min();
    }

    // Consider NaN.
    can_be_false = can_be_false || lhs.has_nan() || rhs.has_nan();

    if (!can_be_true) return Word32Type::Constant(0);
    if (!can_be_false) return Word32Type::Constant(1);
    return Word32Type::Set({0, 1}, zone);
  }

  static Word32Type UnsignedLessThanOrEqual(const type_t& lhs,
                                            const type_t& rhs, Zone* zone) {
    bool can_be_true = lhs.unsigned_min() <= rhs.unsigned_max();
    bool can_be_false = lhs.unsigned_max() > rhs.unsigned_min();

    if (!can_be_true) return Word32Type::Constant(0);
    if (!can_be_false) return Word32Type::Constant(1);
    return Word32Type::Set({0, 1}, zone);
  }

  // Computes the ranges to which the sides of the comparison (lhs < rhs) can be
  // restricted when the comparison is true. When the comparison is true, we
  // learn: lhs cannot be >= rhs.max and rhs cannot be <= lhs.min and neither
  // can be NaN.
  static std::pair<Type, Type> RestrictionForLessThan_True(const type_t& lhs,
                                                           const type_t& rhs,
                                                           Zone* zone) {
    // If either side is only NaN, this comparison can never be true.
    if (lhs.is_only_nan() || rhs.is_only_nan()) {
      return {Type::None(), Type::None()};
    }

    Type restrict_lhs;
    if (rhs.max() == -inf) {
      // There is no value for lhs that could make (lhs < -inf) true.
      restrict_lhs = Type::None();
    } else {
      const auto max = next_smaller(rhs.max());
      uint32_t sv = max >= 0 ? type_t::kMinusZero : type_t::kNoSpecialValues;
      restrict_lhs = type_t::Range(-inf, max, sv, zone);
    }

    Type restrict_rhs;
    if (lhs.min() == inf) {
      // There is no value for rhs that could make (inf < rhs) true.
      restrict_rhs = Type::None();
    } else {
      const auto min = next_larger(lhs.min());
      uint32_t sv = min <= 0 ? type_t::kMinusZero : type_t::kNoSpecialValues;
      restrict_rhs = type_t::Range(min, inf, sv, zone);
    }

    return {restrict_lhs, restrict_rhs};
  }

  // Computes the ranges to which the sides of the comparison (lhs < rhs) can be
  // restricted when the comparison is false. When the comparison is false, we
  // learn: lhs cannot be < rhs.min and rhs cannot be > lhs.max.
  static std::pair<Type, Type> RestrictionForLessThan_False(const type_t& lhs,
                                                            const type_t& rhs,
                                                            Zone* zone) {
    Type restrict_lhs;
    if (rhs.has_nan()) {
      restrict_lhs = type_t::Any();
    } else {
      uint32_t lhs_sv =
          type_t::kNaN |
          (rhs.min() <= 0 ? type_t::kMinusZero : type_t::kNoSpecialValues);
      restrict_lhs = type_t::Range(rhs.min(), inf, lhs_sv, zone);
    }

    Type restrict_rhs;
    if (lhs.has_nan()) {
      restrict_rhs = type_t::Any();
    } else {
      uint32_t rhs_sv =
          type_t::kNaN |
          (lhs.max() >= 0 ? type_t::kMinusZero : type_t::kNoSpecialValues);
      restrict_rhs = type_t::Range(-inf, lhs.max(), rhs_sv, zone);
    }

    return {restrict_lhs, restrict_rhs};
  }

  // Computes the ranges to which the sides of the comparison (lhs <= rhs) can
  // be restricted when the comparison is true. When the comparison is true, we
  // learn: lhs cannot be > rhs.max and rhs cannot be < lhs.min and neither can
  // be NaN.
  static std::pair<Type, Type> RestrictionForLessThanOrEqual_True(
      const type_t& lhs, const type_t& rhs, Zone* zone) {
    // If either side is only NaN, this comparison can never be true.
    if (lhs.is_only_nan() || rhs.is_only_nan()) {
      return {Type::None(), Type::None()};
    }

    uint32_t lhs_sv =
        rhs.max() >= 0 ? type_t::kMinusZero : type_t::kNoSpecialValues;
    uint32_t rhs_sv =
        lhs.min() <= 0 ? type_t::kMinusZero : type_t::kNoSpecialValues;
    return {type_t::Range(-inf, rhs.max(), lhs_sv, zone),
            type_t::Range(lhs.min(), inf, rhs_sv, zone)};
  }

  // Computes the ranges to which the sides of the comparison (lhs <= rhs) can
  // be restricted when the comparison is false. When the comparison is false,
  // we learn: lhs cannot be <= rhs.min and rhs cannot be >= lhs.max.
  static std::pair<Type, Type> RestrictionForLessThanOrEqual_False(
      const type_t& lhs, const type_t& rhs, Zone* zone) {
    Type restrict_lhs;
    if (rhs.has_nan()) {
      restrict_lhs = type_t::Any();
    } else if (rhs.min() == inf) {
      // The only value for lhs that could make (lhs <= inf) false is NaN.
      restrict_lhs = type_t::NaN();
    } else {
      const auto min = next_larger(rhs.min());
      uint32_t sv = type_t::kNaN |
                    (min <= 0 ? type_t::kMinusZero : type_t::kNoSpecialValues);
      restrict_lhs = type_t::Range(min, inf, sv, zone);
    }

    Type restrict_rhs;
    if (lhs.has_nan()) {
      restrict_rhs = type_t::Any();
    } else if (lhs.max() == -inf) {
      // The only value for rhs that could make (-inf <= rhs) false is NaN.
      restrict_rhs = type_t::NaN();
    } else {
      const auto max = next_smaller(lhs.max());
      uint32_t sv = type_t::kNaN |
                    (max >= 0 ? type_t::kMinusZero : type_t::kNoSpecialValues);
      restrict_rhs = type_t::Range(-inf, max, sv, zone);
    }

    return {restrict_lhs, restrict_rhs};
  }
};

class Typer {
 public:
  static Type TypeForRepresentation(RegisterRepresentation rep) {
    switch (rep.value()) {
      case RegisterRepresentation::Word32():
        return Word32Type::Any();
      case RegisterRepresentation::Word64():
        return Word64Type::Any();
      case RegisterRepresentation::Float32():
        return Float32Type::Any();
      case RegisterRepresentation::Float64():
        return Float64Type::Any();

      case RegisterRepresentation::Tagged():
      case RegisterRepresentation::Compressed():
      case RegisterRepresentation::Simd128():
      case RegisterRepresentation::Simd256():
        // TODO(nicohartmann@): Support these representations.
        return Type::Any();
    }
  }

  static Type TypeForRepresentation(
      base::Vector<const RegisterRepresentation> reps, Zone* zone) {
    DCHECK_LT(0, reps.size());
    if (reps.size() == 1) return TypeForRepresentation(reps[0]);
    base::SmallVector<Type, 4> tuple_types;
    for (auto rep : reps) tuple_types.push_back(TypeForRepresentation(rep));
    return TupleType::Tuple(base::VectorOf(tuple_types), zone);
  }

  static Type TypeConstant(ConstantOp::Kind kind, ConstantOp::Storage value) {
    switch (kind) {
      case ConstantOp::Kind::kFloat32:
        if (value.float32.is_nan()) return Float32Type::NaN();
        if (IsMinusZero(value.float32.get_scalar()))
          return Float32Type::MinusZero();
        return Float32Type::Constant(value.float32.get_scalar());
      case ConstantOp::Kind::kFloat64:
        if (value.float64.is_nan()) return Float64Type::NaN();
        if (IsMinusZero(value.float64.get_scalar()))
          return Float64Type::MinusZero();
        return Float64Type::Constant(value.float64.get_scalar());
      case ConstantOp::Kind::kWord32:
        return Word32Type::Constant(static_cast<uint32_t>(value.integral));
      case ConstantOp::Kind::kWord64:
        return Word64Type::Constant(static_cast<uint64_t>(value.integral));
      default:
        // TODO(nicohartmann@): Support remaining {kind}s.
        return Type::Any();
    }
  }

  static Type TypeProjection(const Type& input, uint16_t idx) {
    if (input.IsNone()) return Type::None();
    if (!input.IsTuple()) return Type::Any();
    const TupleType& tuple = input.AsTuple();
    DCHECK_LT(idx, tuple.size());
    return tuple.element(idx);
  }

  static Type TypeWordBinop(Type left_type, Type right_type,
                            WordBinopOp::Kind kind, WordRepresentation rep,
                            Zone* zone) {
    DCHECK(!left_type.IsInvalid());
    DCHECK(!right_type.IsInvalid());

    if (rep == WordRepresentation::Word32()) {
      switch (kind) {
        case WordBinopOp::Kind::kAdd:
          return TypeWord32Add(left_type, right_type, zone);
        case WordBinopOp::Kind::kSub:
          return TypeWord32Sub(left_type, right_type, zone);
        default:
          // TODO(nicohartmann@): Support remaining {kind}s.
          return Word32Type::Any();
      }
    } else {
      DCHECK_EQ(rep, WordRepresentation::Word64());
      switch (kind) {
        case WordBinopOp::Kind::kAdd:
          return TypeWord64Add(left_type, right_type, zone);
        case WordBinopOp::Kind::kSub:
          return TypeWord64Sub(left_type, right_type, zone);
        default:
          // TODO(nicohartmann@): Support remaining {kind}s.
          return Word64Type::Any();
      }
    }
  }

  static Type TypeWord32Add(const Type& lhs, const Type& rhs, Zone* zone) {
    if (lhs.IsNone() || rhs.IsNone()) return Type::None();
    auto l = TruncateWord32Input(lhs, true, zone);
    auto r = TruncateWord32Input(rhs, true, zone);
    return WordOperationTyper<32>::Add(l, r, zone);
  }

  static Type TypeWord32Sub(const Type& lhs, const Type& rhs, Zone* zone) {
    if (lhs.IsNone() || rhs.IsNone()) return Type::None();
    auto l = TruncateWord32Input(lhs, true, zone);
    auto r = TruncateWord32Input(rhs, true, zone);
    return WordOperationTyper<32>::Subtract(l, r, zone);
  }

  static Type TypeWord64Add(const Type& lhs, const Type& rhs, Zone* zone) {
    if (lhs.IsNone() || rhs.IsNone()) return Type::None();
    if (!InputIs(lhs, Type::Kind::kWord64) ||
        !InputIs(rhs, Type::Kind::kWord64)) {
      return Word64Type::Any();
    }
    const auto& l = lhs.AsWord64();
    const auto& r = rhs.AsWord64();

    return WordOperationTyper<64>::Add(l, r, zone);
  }

  static Type TypeWord64Sub(const Type& lhs, const Type& rhs, Zone* zone) {
    if (lhs.IsNone() || rhs.IsNone()) return Type::None();
    if (!InputIs(lhs, Type::Kind::kWord64) ||
        !InputIs(rhs, Type::Kind::kWord64)) {
      return Word64Type::Any();
    }

    const auto& l = lhs.AsWord64();
    const auto& r = rhs.AsWord64();

    return WordOperationTyper<64>::Subtract(l, r, zone);
  }

  static Type TypeFloatBinop(Type left_type, Type right_type,
                             FloatBinopOp::Kind kind, FloatRepresentation rep,
                             Zone* zone) {
    DCHECK(!left_type.IsInvalid());
    DCHECK(!right_type.IsInvalid());

#define FLOAT_BINOP(op, bits)     \
  case FloatBinopOp::Kind::k##op: \
    return TypeFloat##bits##op(left_type, right_type, zone);

    if (rep == FloatRepresentation::Float32()) {
      switch (kind) {
        FLOAT_BINOP(Add, 32)
        FLOAT_BINOP(Sub, 32)
        FLOAT_BINOP(Mul, 32)
        FLOAT_BINOP(Div, 32)
        FLOAT_BINOP(Mod, 32)
        FLOAT_BINOP(Min, 32)
        FLOAT_BINOP(Max, 32)
        FLOAT_BINOP(Power, 32)
        FLOAT_BINOP(Atan2, 32)
      }
    } else {
      DCHECK_EQ(rep, FloatRepresentation::Float64());
      switch (kind) {
        FLOAT_BINOP(Add, 64)
        FLOAT_BINOP(Sub, 64)
        FLOAT_BINOP(Mul, 64)
        FLOAT_BINOP(Div, 64)
        FLOAT_BINOP(Mod, 64)
        FLOAT_BINOP(Min, 64)
        FLOAT_BINOP(Max, 64)
        FLOAT_BINOP(Power, 64)
        FLOAT_BINOP(Atan2, 64)
      }
    }

#undef FLOAT_BINOP
  }

#define FLOAT_BINOP(op, bits, float_typer_handler)                     \
  static Type TypeFloat##bits##op(const Type& lhs, const Type& rhs,    \
                                  Zone* zone) {                        \
    if (lhs.IsNone() || rhs.IsNone()) return Type::None();             \
    if (!InputIs(lhs, Type::Kind::kFloat##bits) ||                     \
        !InputIs(rhs, Type::Kind::kFloat##bits)) {                     \
      return Float##bits##Type::Any();                                 \
    }                                                                  \
    const auto& l = lhs.AsFloat##bits();                               \
    const auto& r = rhs.AsFloat##bits();                               \
    return FloatOperationTyper<bits>::float_typer_handler(l, r, zone); \
  }

  // Float32 operations
  FLOAT_BINOP(Add, 32, Add)
  FLOAT_BINOP(Sub, 32, Subtract)
  FLOAT_BINOP(Mul, 32, Multiply)
  FLOAT_BINOP(Div, 32, Divide)
  FLOAT_BINOP(Mod, 32, Modulus)
  FLOAT_BINOP(Min, 32, Min)
  FLOAT_BINOP(Max, 32, Max)
  FLOAT_BINOP(Power, 32, Power)
  FLOAT_BINOP(Atan2, 32, Atan2)
  // Float64 operations
  FLOAT_BINOP(Add, 64, Add)
  FLOAT_BINOP(Sub, 64, Subtract)
  FLOAT_BINOP(Mul, 64, Multiply)
  FLOAT_BINOP(Div, 64, Divide)
  FLOAT_BINOP(Mod, 64, Modulus)
  FLOAT_BINOP(Min, 64, Min)
  FLOAT_BINOP(Max, 64, Max)
  FLOAT_BINOP(Power, 64, Power)
  FLOAT_BINOP(Atan2, 64, Atan2)
#undef FLOAT_BINOP

  static Type TypeOverflowCheckedBinop(const Type& left_type,
                                       const Type& right_type,
                                       OverflowCheckedBinopOp::Kind kind,
                                       WordRepresentation rep, Zone* zone) {
    DCHECK(!left_type.IsInvalid());
    DCHECK(!right_type.IsInvalid());

    if (rep == WordRepresentation::Word32()) {
      switch (kind) {
        case OverflowCheckedBinopOp::Kind::kSignedAdd:
          return TypeWord32OverflowCheckedAdd(left_type, right_type, zone);
        case OverflowCheckedBinopOp::Kind::kSignedSub:
        case OverflowCheckedBinopOp::Kind::kSignedMul:
          // TODO(nicohartmann@): Support these.
          return TupleType::Tuple(Word32Type::Any(),
                                  Word32Type::Set({0, 1}, zone), zone);
      }
    } else {
      DCHECK_EQ(rep, WordRepresentation::Word64());
      switch (kind) {
        case OverflowCheckedBinopOp::Kind::kSignedAdd:
        case OverflowCheckedBinopOp::Kind::kSignedSub:
        case OverflowCheckedBinopOp::Kind::kSignedMul:
          // TODO(nicohartmann@): Support these.
          return TupleType::Tuple(Word64Type::Any(),
                                  Word32Type::Set({0, 1}, zone), zone);
      }
    }
  }

  static Type TypeWord32OverflowCheckedAdd(const Type& lhs, const Type& rhs,
                                           Zone* zone) {
    if (lhs.IsNone() || rhs.IsNone()) return Type::None();
    auto l = TruncateWord32Input(lhs, true, zone);
    auto r = TruncateWord32Input(rhs, true, zone);

    auto value = WordOperationTyper<32>::Add(l, r, zone);
    // We check for signed overflow and if the topmost bits of both opperands
    // are 0, we know that the result cannot overflow.
    if ((0xC0000000 & l.unsigned_max()) == 0 &&
        (0xC0000000 & r.unsigned_max()) == 0) {
      // Cannot overflow.
      return TupleType::Tuple(value, Word32Type::Constant(0), zone);
    }
    // Special case for two constant inputs to figure out the overflow.
    if (l.is_constant() && r.is_constant()) {
      constexpr uint32_t msb_mask = 0x80000000;
      DCHECK(value.is_constant());
      uint32_t l_msb = (*l.try_get_constant()) & msb_mask;
      uint32_t r_msb = (*r.try_get_constant()) & msb_mask;
      if (l_msb != r_msb) {
        // Different sign bits can never lead to an overflow.
        return TupleType::Tuple(value, Word32Type::Constant(0), zone);
      }
      uint32_t value_msb = (*value.try_get_constant()) & msb_mask;
      const uint32_t overflow = value_msb == l_msb ? 0 : 1;
      return TupleType::Tuple(value, Word32Type::Constant(overflow), zone);
    }
    // Otherwise we accept some imprecision.
    return TupleType::Tuple(value, Word32Type::Set({0, 1}, zone), zone);
  }

  static Type TypeComparison(const Type& lhs, const Type& rhs,
                             RegisterRepresentation rep,
                             ComparisonOp::Kind kind, Zone* zone) {
    switch (rep.value()) {
      case RegisterRepresentation::Word32():
        return TypeWord32Comparison(lhs, rhs, kind, zone);
      case RegisterRepresentation::Word64():
        return TypeWord64Comparison(lhs, rhs, kind, zone);
      case RegisterRepresentation::Float32():
        return TypeFloat32Comparison(lhs, rhs, kind, zone);
      case RegisterRepresentation::Float64():
        return TypeFloat64Comparison(lhs, rhs, kind, zone);
      case RegisterRepresentation::Tagged():
      case RegisterRepresentation::Compressed():
      case RegisterRepresentation::Simd128():
      case RegisterRepresentation::Simd256():
        if (lhs.IsNone() || rhs.IsNone()) return Type::None();
        // TODO(nicohartmann@): Support those cases.
        return Word32Type::Set({0, 1}, zone);
    }
  }

  static Type TypeWord32Comparison(const Type& lhs, const Type& rhs,
                                   ComparisonOp::Kind kind, Zone* zone) {
    if (lhs.IsNone() || rhs.IsNone()) return Type::None();
    auto l = TruncateWord32Input(lhs, true, zone);
    auto r = TruncateWord32Input(rhs, true, zone);
    switch (kind) {
      case ComparisonOp::Kind::kEqual:
      case ComparisonOp::Kind::kSignedLessThan:
      case ComparisonOp::Kind::kSignedLessThanOrEqual:
        // TODO(nicohartmann@): Support this.
        return Word32Type::Set({0, 1}, zone);
      case ComparisonOp::Kind::kUnsignedLessThan:
        return WordOperationTyper<32>::UnsignedLessThan(l, r, zone);
      case ComparisonOp::Kind::kUnsignedLessThanOrEqual:
        return WordOperationTyper<32>::UnsignedLessThanOrEqual(l, r, zone);
    }
    UNREACHABLE();
  }

  static Type TypeWord64Comparison(const Type& lhs, const Type& rhs,
                                   ComparisonOp::Kind kind, Zone* zone) {
    if (lhs.IsNone() || rhs.IsNone()) return Type::None();
    switch (kind) {
      case ComparisonOp::Kind::kEqual:
      case ComparisonOp::Kind::kSignedLessThan:
      case ComparisonOp::Kind::kSignedLessThanOrEqual:
        // TODO(nicohartmann@): Support this.
        return Word32Type::Set({0, 1}, zone);
      case ComparisonOp::Kind::kUnsignedLessThan:
        return WordOperationTyper<64>::UnsignedLessThan(lhs.AsWord64(),
                                                        rhs.AsWord64(), zone);
      case ComparisonOp::Kind::kUnsignedLessThanOrEqual:
        return WordOperationTyper<64>::UnsignedLessThanOrEqual(
            lhs.AsWord64(), rhs.AsWord64(), zone);
    }
    UNREACHABLE();
  }

  static Type TypeFloat32Comparison(const Type& lhs, const Type& rhs,
                                    ComparisonOp::Kind kind, Zone* zone) {
    if (lhs.IsNone() || rhs.IsNone()) return Type::None();
    switch (kind) {
      case ComparisonOp::Kind::kEqual:
        // TODO(nicohartmann@): Support this.
        return Word32Type::Set({0, 1}, zone);
      case ComparisonOp::Kind::kSignedLessThan:
        return FloatOperationTyper<32>::LessThan(lhs.AsFloat32(),
                                                 rhs.AsFloat32(), zone);
      case ComparisonOp::Kind::kSignedLessThanOrEqual:
        return FloatOperationTyper<32>::LessThanOrEqual(lhs.AsFloat32(),
                                                        rhs.AsFloat32(), zone);
      case ComparisonOp::Kind::kUnsignedLessThan:
      case ComparisonOp::Kind::kUnsignedLessThanOrEqual:
        UNREACHABLE();
    }
  }

  static Type TypeFloat64Comparison(const Type& lhs, const Type& rhs,
                                    ComparisonOp::Kind kind, Zone* zone) {
    if (lhs.IsNone() || rhs.IsNone()) return Type::None();
    switch (kind) {
      case ComparisonOp::Kind::kEqual:
        // TODO(nicohartmann@): Support this.
        return Word32Type::Set({0, 1}, zone);
      case ComparisonOp::Kind::kSignedLessThan:
        return FloatOperationTyper<64>::LessThan(lhs.AsFloat64(),
                                                 rhs.AsFloat64(), zone);
      case ComparisonOp::Kind::kSignedLessThanOrEqual:
        return FloatOperationTyper<64>::LessThanOrEqual(lhs.AsFloat64(),
                                                        rhs.AsFloat64(), zone);
      case ComparisonOp::Kind::kUnsignedLessThan:
      case ComparisonOp::Kind::kUnsignedLessThanOrEqual:
        UNREACHABLE();
    }
  }

  static Word64Type ExtendWord32ToWord64(const Word32Type& t, Zone* zone) {
    // We cannot infer much, but the lower bound of the word32 is also the lower
    // bound of the word64 type.
    if (t.is_wrapping()) return Word64Type::Any();
    return Word64Type::Range(static_cast<uint64_t>(t.unsigned_min()),
                             std::numeric_limits<uint64_t>::max(), zone);
  }

  static Word32Type TruncateWord32Input(const Type& input,
                                        bool implicit_word64_narrowing,
                                        Zone* zone) {
    DCHECK(!input.IsInvalid());
    DCHECK(!input.IsNone());

    if (input.IsAny()) {
      if (allow_invalid_inputs()) return Word32Type::Any();
    } else if (input.IsWord32()) {
      return input.AsWord32();
    } else if (input.IsWord64() && implicit_word64_narrowing) {
      // The input is implicitly converted to word32.
      const auto& w64 = input.AsWord64();
      if (w64.is_set()) {
        WordOperationTyper<32>::ElementsVector elements;
        for (uint64_t e : w64.set_elements()) {
          elements.push_back(static_cast<uint32_t>(e));
        }
        return WordOperationTyper<32>::FromElements(std::move(elements), zone);
      }

      if (w64.is_any() || w64.is_wrapping()) return Word32Type::Any();

      if (w64.range_to() <= std::numeric_limits<uint32_t>::max()) {
        DCHECK_LE(w64.range_from(), std::numeric_limits<uint32_t>::max());
        return Word32Type::Range(static_cast<uint32_t>(w64.range_from()),
                                 static_cast<uint32_t>(w64.range_to()), zone);
      }

      // TODO(nicohartmann@): Might compute a more precise range here.
      return Word32Type::Any();
    }

    FATAL("Missing proper type for TruncateWord32Input. Type is: %s",
          input.ToString().c_str());
  }

  class BranchRefinements {
   public:
    // type_getter_t has to provide the type for a given input index.
    using type_getter_t = std::function<Type(OpIndex)>;
    // type_refiner_t is called with those arguments:
    //  - OpIndex: index of the operation whose type is refined by the branch.
    //  - Type: the refined type of the operation (after refinement, guaranteed
    //  to be a subtype of the original type).
    using type_refiner_t = std::function<void(OpIndex, const Type&)>;

    BranchRefinements(type_getter_t type_getter, type_refiner_t type_refiner)
        : type_getter_(type_getter), type_refiner_(type_refiner) {
      DCHECK(type_getter_);
      DCHECK(type_refiner_);
    }

    void RefineTypes(const Operation& condition, bool then_branch, Zone* zone);

   private:
    template <bool allow_implicit_word64_truncation>
    Type RefineWord32Type(const Type& type, const Type& refinement,
                          Zone* zone) {
      // If refinement is Type::None(), the operation/branch is unreachable.
      if (refinement.IsNone()) return Type::None();
      DCHECK(refinement.IsWord32());
      if constexpr (allow_implicit_word64_truncation) {
        // Turboshaft allows implicit trunction of Word64 values to Word32. When
        // an operation on Word32 representation computes a refinement type,
        // this is going to be a Type::Word32() even if the actual {type} was
        // Word64 before truncation. To correctly refine this type, we need to
        // extend the {refinement} to Word64 such that it reflects the
        // corresponding values in the original type (before truncation) before
        // we intersect.
        if (type.IsWord64()) {
          return Word64Type::Intersect(
              type.AsWord64(),
              Typer::ExtendWord32ToWord64(refinement.AsWord32(), zone),
              Type::ResolutionMode::kOverApproximate, zone);
        }
      }
      // We limit the values of {type} to those in {refinement}.
      return Word32Type::Intersect(type.AsWord32(), refinement.AsWord32(),
                                   Type::ResolutionMode::kOverApproximate,
                                   zone);
    }

    type_getter_t type_getter_;
    type_refiner_t type_refiner_;
  };

  static bool InputIs(const Type& input, Type::Kind expected) {
    if (input.IsInvalid()) {
      if (allow_invalid_inputs()) return false;
    } else if (input.kind() == expected) {
      return true;
    } else if (input.IsAny()) {
      if (allow_invalid_inputs()) return false;
    }

    std::stringstream s;
    s << expected;
    FATAL("Missing proper type (%s). Type is: %s", s.str().c_str(),
          input.ToString().c_str());
  }

  // For now we allow invalid inputs (which will then just lead to very generic
  // typing). Once all operations are implemented, we are going to disable this.
  static bool allow_invalid_inputs() { return true; }
};

}  // namespace v8::internal::compiler::turboshaft

#endif  // V8_COMPILER_TURBOSHAFT_TYPER_H_
```