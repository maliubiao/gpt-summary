Response: The user wants a summary of the functionality of the provided C++ code snippet, which is part of a larger file responsible for instruction selection in the V8 JavaScript engine for the x64 architecture. The request also asks to illustrate the connection to JavaScript using an example if one exists. This is the fourth part of a five-part series, so the summary should focus on the functionality present in *this* specific snippet.

The code snippet primarily handles the translation of intermediate representation (IR) operations into x64 machine code instructions. It focuses on several categories of operations:

1. **Comparison and Conditional Branching:**  It deals with comparing values (integer, floating-point) and setting flags, as well as generating conditional branches based on those flags.
2. **Switch Statements:** It implements different strategies for compiling switch statements, including jump tables and binary search trees.
3. **Arithmetic Operations with Overflow:** It handles integer addition, subtraction, and multiplication, specifically addressing cases where overflow needs to be detected.
4. **Floating-point Comparisons:** It covers various floating-point comparisons (equality, less than, less than or equal to) and includes optimizations for specific patterns.
5. **Bitwise Operations on Floating-point Numbers:** It provides support for inserting and extracting parts of floating-point numbers at the bit level.
6. **Memory Barriers:** It handles memory barrier instructions for controlling memory ordering in multi-threaded scenarios.
7. **Atomic Operations:** It includes support for atomic loads, stores, exchanges, and compare-and-exchange operations on both 32-bit and 64-bit values.
8. **SIMD (Single Instruction, Multiple Data) Operations:** A significant portion of the code is dedicated to handling SIMD instructions, covering a wide range of operations on 128-bit and 256-bit vectors of different data types (integer and floating-point). This includes splatting, extracting lanes, replacing lanes, arithmetic operations, comparisons, shifts, and bitwise operations.

Considering this is part 4 of 5, it likely builds upon the foundational logic established in previous parts and focuses on more complex and specific instruction selection scenarios.

To provide a JavaScript example, focusing on the SIMD functionality would be the most relevant, as it's a relatively direct mapping of low-level operations exposed to JavaScript.
这是 `v8/src/compiler/backend/x64/instruction-selector-x64.cc` 文件的一部分，主要负责将**中间代码 (Intermediate Representation - IR)** 中的特定操作（特别是与比较、分支、原子操作和 SIMD 相关的操作）转换为 **x64 汇编指令**。

这是第 4 部分，因此它可能专注于处理一些更复杂的或特定的 IR 节点类型。从代码片段来看，其功能可以归纳为：

1. **处理比较和分支相关的 IR 节点：**
    *   针对不同的比较操作（例如 `kInt32Sub`、`kWord32And`、`kStackPointerGreaterThan`）生成相应的 x64 比较指令（例如 `kX64Cmp32`、`kX64Test32`）。
    *   处理无法与比较操作合并的分支情况，会生成与 0 比较的指令。
    *   优化了某些带溢出检查的算术运算，可以将溢出条件直接用于后续的分支判断。

2. **处理 `switch` 语句：**
    *   根据 `switch` 语句的 case 数量和值的范围，选择使用**跳转表 (`ArchTableSwitch`)** 或 **二分查找 (`ArchBinarySearchSwitch`)** 的方式来实现。
    *   如果满足特定条件（例如 case 数量较多、值范围较小），会优先考虑使用跳转表以提高效率。

3. **处理相等性比较 (`kWord32Equal`, `kWord64Equal`)：**
    *   针对与 0 的比较进行了优化，可以直接利用比较指令的结果。
    *   尝试将相等性检查与之前的比较操作（例如 `kInt64Sub`、`kWord64And`）合并，避免重复计算。

4. **处理带溢出的算术运算 (`kInt32AddWithOverflow`, `kInt32SubWithOverflow`)：**
    *   可以针对溢出标志生成相应的条件设置指令，以便后续使用。

5. **处理大小比较 (`kInt32LessThan`, `kInt32LessThanOrEqual` 等)：**
    *   针对有符号和无符号的整数以及 64 位整数生成相应的比较指令。

6. **处理浮点数比较 (`kFloat32Equal`, `kFloat32LessThan` 等)：**
    *   针对单精度和双精度浮点数生成相应的比较指令，并设置相应的条件标志（例如 `kUnorderedEqual`）。
    *   针对特定的浮点数比较模式（例如 `Float64LessThan(0.0, Float64Abs(x))`）进行了优化。

7. **处理浮点数的位操作 (`kFloat64InsertLowWord32`, `kFloat64InsertHighWord32`)：**
    *   用于将 32 位整数插入到 64 位浮点数的低位或高位。

8. **处理 `kFloat64SilenceNaN`：**
    *   生成指令来将 NaN 值转换为其静默形式。

9. **处理内存屏障 (`kMemoryBarrier`)：**
    *   根据内存顺序的要求，生成相应的内存屏障指令（例如 `kX64MFence`）。

10. **处理原子操作 (`kWord32AtomicLoad`, `kWord64AtomicStore` 等)：**
    *   为原子加载、存储、交换和比较交换操作生成相应的 x64 原子指令。这些操作涵盖了不同大小的数据类型（8位、16位、32位、64位）。
    *   对于原子二元操作（例如 `AtomicAdd`、`AtomicSub`），会根据操作数类型选择合适的原子指令。

11. **处理 SIMD (Single Instruction, Multiple Data) 操作：**
    *   包含了大量的代码来处理各种 SIMD 指令，这些指令可以同时操作多个数据。
    *   涵盖了 SIMD 常量加载 (`kS128Const`)、零值加载 (`kS128Zero`)、通道提取 (`VisitF64x2ExtractLane`)、通道替换 (`VisitF64x2ReplaceLane`)、向量 Splat (`VisitI64x2Splat`) 以及各种 SIMD 算术、逻辑和比较操作。
    *   根据 SIMD 操作的数据类型（例如 `I64x2`、`F32x4`）、向量长度 (128位或 256位) 和通道大小来选择不同的 x64 SIMD 指令。
    *   针对不同的 SIMD 指令，可能会有 AVX 和 SSE 的版本选择。

**与 JavaScript 的关系和示例：**

这段代码是 V8 引擎编译 JavaScript 代码的关键部分。JavaScript 本身并没有直接的指令来操作底层的 x64 汇编指令。但是，V8 引擎会将 JavaScript 代码编译成 IR，然后 `instruction-selector-x64.cc` 的功能就是将这些 IR 操作转换为高效的机器码。

**例如，对于 SIMD 操作，JavaScript 中可以通过 `SIMD` API 来使用：**

```javascript
// JavaScript SIMD 代码
const a = SIMD.float32x4(1.0, 2.0, 3.0, 4.0);
const b = SIMD.float32x4(5.0, 6.0, 7.0, 8.0);
const sum = SIMD.float32x4.add(a, b); // 执行向量加法

console.log(sum); // 输出: Float32x4 [ 6, 8, 10, 12 ]
```

当 V8 编译这段 JavaScript 代码时，`SIMD.float32x4.add(a, b)` 这个操作可能会被转换成一个表示 SIMD 加法的 IR 节点。而 `instruction-selector-x64.cc` 中的 `VisitF32x4Add` 函数（如代码片段所示）就会负责将这个 IR 节点转换为相应的 x64 SIMD 加法指令（例如 `kX64FAdd | LaneSizeField::encode(kL32) | VectorLengthField::encode(kV128)`）。

**再比如，对于原子操作，JavaScript 中可以通过 `SharedArrayBuffer` 和 `Atomics` API 来使用：**

```javascript
// JavaScript 原子操作代码
const sab = new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT * 1);
const view = new Int32Array(sab);

Atomics.add(view, 0, 5); // 原子地将 view[0] 的值加上 5

console.log(Atomics.load(view, 0)); // 原子地读取 view[0] 的值
```

当编译 `Atomics.add` 时，对应的 IR 节点会被 `instruction-selector-x64.cc` 中的 `VisitWord32AtomicAdd` 函数处理，并生成相应的 x64 原子加法指令 (例如 `kAtomicAddWord32`)。

总而言之，`instruction-selector-x64.cc` 是 V8 引擎将高级 JavaScript 代码转换为底层机器码的关键桥梁，它负责针对 x64 架构选择最佳的指令序列来实现 JavaScript 的各种功能，包括数值计算、控制流、并发和 SIMD 操作等。

Prompt: 
```
这是目录为v8/src/compiler/backend/x64/instruction-selector-x64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第4部分，共5部分，请归纳一下它的功能

"""
              case IrOpcode::kInt32MulWithOverflow:
                cont->OverwriteAndNegateIfEqual(kOverflow);
                return VisitBinop(this, node, kX64Imul32, cont);
              case IrOpcode::kInt64AddWithOverflow:
                cont->OverwriteAndNegateIfEqual(kOverflow);
                return VisitBinop(this, node, kX64Add, cont);
              case IrOpcode::kInt64SubWithOverflow:
                cont->OverwriteAndNegateIfEqual(kOverflow);
                return VisitBinop(this, node, kX64Sub, cont);
              case IrOpcode::kInt64MulWithOverflow:
                cont->OverwriteAndNegateIfEqual(kOverflow);
                return VisitBinop(this, node, kX64Imul, cont);
              default:
                break;
            }
          }
        }
        break;
      case IrOpcode::kInt32Sub:
        return VisitWordCompare(this, value, kX64Cmp32, cont);
      case IrOpcode::kWord32And:
        return VisitWordCompare(this, value, kX64Test32, cont);
      case IrOpcode::kStackPointerGreaterThan:
        cont->OverwriteAndNegateIfEqual(kStackPointerGreaterThanCondition);
        return VisitStackPointerGreaterThan(value, cont);
      default:
        break;
    }
  }

  // Branch could not be combined with a compare, emit compare against 0.
  VisitCompareZero(this, user, value, kX64Cmp32, cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitSwitch(node_t node,
                                                const SwitchInfo& sw) {
  X64OperandGeneratorT<Adapter> g(this);
  DCHECK_EQ(this->value_input_count(node), 1);
  InstructionOperand value_operand = g.UseRegister(this->input_at(node, 0));

  // Emit either ArchTableSwitch or ArchBinarySearchSwitch.
  if (enable_switch_jump_table_ ==
      InstructionSelector::kEnableSwitchJumpTable) {
    static const size_t kMaxTableSwitchValueRange = 2 << 16;
    size_t table_space_cost = 4 + sw.value_range();
    size_t table_time_cost = 3;
    size_t lookup_space_cost = 3 + 2 * sw.case_count();
    size_t lookup_time_cost = sw.case_count();
    if (sw.case_count() > 4 &&
        table_space_cost + 3 * table_time_cost <=
            lookup_space_cost + 3 * lookup_time_cost &&
        sw.min_value() > std::numeric_limits<int32_t>::min() &&
        sw.value_range() <= kMaxTableSwitchValueRange) {
      InstructionOperand index_operand = g.TempRegister();
      if (sw.min_value()) {
        // The leal automatically zero extends, so result is a valid 64-bit
        // index.
        Emit(kX64Lea32 | AddressingModeField::encode(kMode_MRI), index_operand,
             value_operand, g.TempImmediate(-sw.min_value()));
      } else {
        // Zero extend, because we use it as 64-bit index into the jump table.
        if (ZeroExtendsWord32ToWord64(this->input_at(node, 0))) {
          // Input value has already been zero-extended.
          index_operand = value_operand;
        } else {
          Emit(kX64Movl, index_operand, value_operand);
        }
      }
      // Generate a table lookup.
      return EmitTableSwitch(sw, index_operand);
    }
  }

  // Generate a tree of conditional jumps.
  return EmitBinarySearchSwitch(sw, value_operand);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitWord32Equal(node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  FlagsContinuation cont = FlagsContinuation::ForSet(kEqual, node);
  const ComparisonOp& equal = this->Get(node).Cast<ComparisonOp>();
  DCHECK_EQ(equal.kind, ComparisonOp::Kind::kEqual);
  DCHECK(equal.rep == RegisterRepresentation::Word32() ||
         equal.rep == RegisterRepresentation::Tagged());
  if (MatchIntegralZero(equal.right())) {
    return VisitWordCompareZero(node, equal.left(), &cont);
  }
  VisitWord32EqualImpl(this, node, &cont);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitWord32Equal(node_t node) {
  FlagsContinuation cont = FlagsContinuation::ForSet(kEqual, node);
  Int32BinopMatcher m(node);
  if (m.right().Is(0)) {
    return VisitWordCompareZero(m.node(), m.left().node(), &cont);
  }
  VisitWord32EqualImpl(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32LessThan(node_t node) {
  FlagsContinuation cont = FlagsContinuation::ForSet(kSignedLessThan, node);
  VisitWordCompare(this, node, kX64Cmp32, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32LessThanOrEqual(node_t node) {
  FlagsContinuation cont =
      FlagsContinuation::ForSet(kSignedLessThanOrEqual, node);
  VisitWordCompare(this, node, kX64Cmp32, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUint32LessThan(node_t node) {
  FlagsContinuation cont = FlagsContinuation::ForSet(kUnsignedLessThan, node);
  VisitWordCompare(this, node, kX64Cmp32, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUint32LessThanOrEqual(node_t node) {
  FlagsContinuation cont =
      FlagsContinuation::ForSet(kUnsignedLessThanOrEqual, node);
  VisitWordCompare(this, node, kX64Cmp32, &cont);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitWord64Equal(node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  FlagsContinuation cont = FlagsContinuation::ForSet(kEqual, node);
  const ComparisonOp& equal = this->Get(node).Cast<ComparisonOp>();
  DCHECK_EQ(equal.kind, ComparisonOp::Kind::kEqual);
  DCHECK(equal.rep == RegisterRepresentation::Word64() ||
         equal.rep == RegisterRepresentation::Tagged());
  if (MatchIntegralZero(equal.right())) {
    if (CanCover(node, equal.left())) {
      const Operation& left_op = this->Get(equal.left());
      if (left_op.Is<Opmask::kWord64Sub>()) {
        return VisitWordCompare(this, equal.left(), kX64Cmp, &cont);
      } else if (left_op.Is<Opmask::kWord64BitwiseAnd>()) {
        return VisitWordCompare(this, equal.left(), kX64Test, &cont);
      }
    }
  }
  VisitWord64EqualImpl(this, node, &cont);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitWord64Equal(node_t node) {
  FlagsContinuation cont = FlagsContinuation::ForSet(kEqual, node);
  Int64BinopMatcher m(node);
  if (m.right().Is(0)) {
    // Try to combine the equality check with a comparison.
    Node* const user = m.node();
    Node* const value = m.left().node();
    if (CanCover(user, value)) {
      switch (value->opcode()) {
        case IrOpcode::kInt64Sub:
          return VisitWordCompare(this, value, kX64Cmp, &cont);
        case IrOpcode::kWord64And:
          return VisitWordCompare(this, value, kX64Test, &cont);
        default:
          break;
      }
    }
  }
  VisitWord64EqualImpl(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32AddWithOverflow(node_t node) {
  node_t ovf = FindProjection(node, 1);
  if (Adapter::valid(ovf)) {
    FlagsContinuation cont = FlagsContinuation::ForSet(kOverflow, ovf);
    return VisitBinop(this, node, kX64Add32, &cont);
  }
  FlagsContinuation cont;
  VisitBinop(this, node, kX64Add32, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32SubWithOverflow(node_t node) {
  node_t ovf = FindProjection(node, 1);
  if (Adapter::valid(ovf)) {
    FlagsContinuation cont = FlagsContinuation::ForSet(kOverflow, ovf);
    return VisitBinop(this, node, kX64Sub32, &cont);
  }
  FlagsContinuation cont;
  VisitBinop(this, node, kX64Sub32, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt64LessThan(node_t node) {
  FlagsContinuation cont = FlagsContinuation::ForSet(kSignedLessThan, node);
  VisitWordCompare(this, node, kX64Cmp, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt64LessThanOrEqual(node_t node) {
  FlagsContinuation cont =
      FlagsContinuation::ForSet(kSignedLessThanOrEqual, node);
  VisitWordCompare(this, node, kX64Cmp, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUint64LessThan(node_t node) {
  FlagsContinuation cont = FlagsContinuation::ForSet(kUnsignedLessThan, node);
  VisitWordCompare(this, node, kX64Cmp, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUint64LessThanOrEqual(node_t node) {
  FlagsContinuation cont =
      FlagsContinuation::ForSet(kUnsignedLessThanOrEqual, node);
  VisitWordCompare(this, node, kX64Cmp, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32Equal(node_t node) {
  FlagsContinuation cont = FlagsContinuation::ForSet(kUnorderedEqual, node);
  VisitFloat32Compare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32LessThan(node_t node) {
  FlagsContinuation cont =
      FlagsContinuation::ForSet(kUnsignedGreaterThan, node);
  VisitFloat32Compare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32LessThanOrEqual(node_t node) {
  FlagsContinuation cont =
      FlagsContinuation::ForSet(kUnsignedGreaterThanOrEqual, node);
  VisitFloat32Compare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Equal(node_t node) {
  bool is_self_compare = this->input_at(node, 0) == this->input_at(node, 1);
  FlagsContinuation cont = FlagsContinuation::ForSet(
      is_self_compare ? kIsNotNaN : kUnorderedEqual, node);
  VisitFloat64Compare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64LessThan(node_t node) {
  // Check for the pattern
  //
  //   Float64LessThan(#0.0, Float64Abs(x))
  //
  // which TurboFan generates for NumberToBoolean in the general case,
  // and which evaluates to false if x is 0, -0 or NaN. We can compile
  // this to a simple (v)ucomisd using not_equal flags condition, which
  // avoids the costly Float64Abs.
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const ComparisonOp& cmp = this->Get(node).template Cast<ComparisonOp>();
    DCHECK_EQ(cmp.rep, RegisterRepresentation::Float64());
    DCHECK_EQ(cmp.kind, ComparisonOp::Kind::kSignedLessThan);
    if (this->MatchZero(cmp.left())) {
      if (const FloatUnaryOp* right_op =
              this->Get(cmp.right()).template TryCast<Opmask::kFloat64Abs>()) {
        FlagsContinuation cont = FlagsContinuation::ForSet(kNotEqual, node);
        InstructionCode const opcode =
            IsSupported(AVX) ? kAVXFloat64Cmp : kSSEFloat64Cmp;
        return VisitCompare(this, opcode, cmp.left(), right_op->input(), &cont,
                            false);
      }
    }
  } else {
    Float64BinopMatcher m(node);
    if (m.left().Is(0.0) && m.right().IsFloat64Abs()) {
      FlagsContinuation cont = FlagsContinuation::ForSet(kNotEqual, node);
      InstructionCode const opcode =
          IsSupported(AVX) ? kAVXFloat64Cmp : kSSEFloat64Cmp;
      return VisitCompare(this, opcode, m.left().node(), m.right().InputAt(0),
                          &cont, false);
    }
  }
  FlagsContinuation cont =
      FlagsContinuation::ForSet(kUnsignedGreaterThan, node);
  VisitFloat64Compare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64LessThanOrEqual(node_t node) {
  FlagsContinuation cont =
      FlagsContinuation::ForSet(kUnsignedGreaterThanOrEqual, node);
  VisitFloat64Compare(this, node, &cont);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitBitcastWord32PairToFloat64(
    node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  X64OperandGeneratorT<TurboshaftAdapter> g(this);
  const auto& bitcast =
      this->Cast<turboshaft::BitcastWord32PairToFloat64Op>(node);
  node_t hi = bitcast.high_word32();
  node_t lo = bitcast.low_word32();

  // TODO(nicohartmann@): We could try to emit a better sequence here.
  InstructionOperand zero = sequence()->AddImmediate(Constant(0.0));
  InstructionOperand temp = g.TempDoubleRegister();
  Emit(kSSEFloat64InsertHighWord32, temp, zero, g.Use(hi));
  Emit(kSSEFloat64InsertLowWord32, g.DefineSameAsFirst(node), temp, g.Use(lo));
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitFloat64InsertLowWord32(
    node_t node) {
  X64OperandGeneratorT<TurbofanAdapter> g(this);
  DCHECK_EQ(this->value_input_count(node), 2);
  node_t left = this->input_at(node, 0);
  node_t right = this->input_at(node, 1);
  Float64Matcher mleft(left);
  if (mleft.HasResolvedValue() &&
      (base::bit_cast<uint64_t>(mleft.ResolvedValue()) >> 32) == 0u) {
    Emit(kSSEFloat64LoadLowWord32, g.DefineAsRegister(node), g.Use(right));
    return;
  }
  Emit(kSSEFloat64InsertLowWord32, g.DefineSameAsFirst(node),
       g.UseRegister(left), g.Use(right));
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitFloat64InsertHighWord32(
    node_t node) {
  X64OperandGeneratorT<TurbofanAdapter> g(this);
  DCHECK_EQ(this->value_input_count(node), 2);
  node_t left = this->input_at(node, 0);
  node_t right = this->input_at(node, 1);
  Emit(kSSEFloat64InsertHighWord32, g.DefineSameAsFirst(node),
       g.UseRegister(left), g.Use(right));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64SilenceNaN(node_t node) {
  X64OperandGeneratorT<Adapter> g(this);
  DCHECK_EQ(this->value_input_count(node), 1);
  Emit(kSSEFloat64SilenceNaN, g.DefineSameAsFirst(node),
       g.UseRegister(this->input_at(node, 0)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitMemoryBarrier(node_t node) {
  AtomicMemoryOrder order;
  if constexpr (Adapter::IsTurboshaft) {
    order = this->Get(node)
                .template Cast<turboshaft::MemoryBarrierOp>()
                .memory_order;
  } else {
    order = OpParameter<AtomicMemoryOrder>(node->op());
  }
  // x64 is no weaker than release-acquire and only needs to emit an
  // instruction for SeqCst memory barriers.
  if (order == AtomicMemoryOrder::kSeqCst) {
    X64OperandGeneratorT<Adapter> g(this);
    Emit(kX64MFence, g.NoOutput());
    return;
  }
  DCHECK_EQ(AtomicMemoryOrder::kAcqRel, order);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicLoad(node_t node) {
  LoadRepresentation load_rep = this->load_view(node).loaded_rep();
  DCHECK(IsIntegral(load_rep.representation()) ||
         IsAnyTagged(load_rep.representation()) ||
         (COMPRESS_POINTERS_BOOL &&
          CanBeCompressedPointer(load_rep.representation())));
  DCHECK_NE(load_rep.representation(), MachineRepresentation::kWord64);
  DCHECK(!load_rep.IsMapWord());
  // The memory order is ignored as both acquire and sequentially consistent
  // loads can emit MOV.
  // https://www.cl.cam.ac.uk/~pes20/cpp/cpp0xmappings.html
  VisitLoad(node, node, GetLoadOpcode(load_rep));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64AtomicLoad(node_t node) {
  LoadRepresentation load_rep = this->load_view(node).loaded_rep();
  DCHECK(!load_rep.IsMapWord());
  // The memory order is ignored as both acquire and sequentially consistent
  // loads can emit MOV.
  // https://www.cl.cam.ac.uk/~pes20/cpp/cpp0xmappings.html
  VisitLoad(node, node, GetLoadOpcode(load_rep));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicStore(node_t node) {
  auto store = this->store_view(node);
  DCHECK_NE(store.stored_rep().representation(),
            MachineRepresentation::kWord64);
  DCHECK_IMPLIES(
      CanBeTaggedOrCompressedPointer(store.stored_rep().representation()),
      kTaggedSize == 4);
  VisitStoreCommon(this, store);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64AtomicStore(node_t node) {
  auto store = this->store_view(node);
  DCHECK_IMPLIES(
      CanBeTaggedOrCompressedPointer(store.stored_rep().representation()),
      kTaggedSize == 8);
  VisitStoreCommon(this, store);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitWord32AtomicExchange(
    Node* node) {
  AtomicOpParameters params = AtomicOpParametersOf(node->op());
  ArchOpcode opcode;
  if (params.type() == MachineType::Int8()) {
    opcode = kAtomicExchangeInt8;
  } else if (params.type() == MachineType::Uint8()) {
    opcode = kAtomicExchangeUint8;
  } else if (params.type() == MachineType::Int16()) {
    opcode = kAtomicExchangeInt16;
  } else if (params.type() == MachineType::Uint16()) {
    opcode = kAtomicExchangeUint16;
  } else if (params.type() == MachineType::Int32()
    || params.type() == MachineType::Uint32()) {
    opcode = kAtomicExchangeWord32;
  } else {
    UNREACHABLE();
  }
  VisitAtomicExchange(this, node, opcode, AtomicWidth::kWord32, params.kind());
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitWord32AtomicExchange(
    node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  const AtomicRMWOp& atomic_op = this->Get(node).template Cast<AtomicRMWOp>();
  ArchOpcode opcode;
  if (atomic_op.memory_rep == MemoryRepresentation::Int8()) {
    opcode = kAtomicExchangeInt8;
  } else if (atomic_op.memory_rep == MemoryRepresentation::Uint8()) {
    opcode = kAtomicExchangeUint8;
  } else if (atomic_op.memory_rep == MemoryRepresentation::Int16()) {
    opcode = kAtomicExchangeInt16;
  } else if (atomic_op.memory_rep == MemoryRepresentation::Uint16()) {
    opcode = kAtomicExchangeUint16;
  } else if (atomic_op.memory_rep == MemoryRepresentation::Int32() ||
             atomic_op.memory_rep == MemoryRepresentation::Uint32()) {
    opcode = kAtomicExchangeWord32;
  } else {
    UNREACHABLE();
  }
  VisitAtomicExchange(this, node, opcode, AtomicWidth::kWord32,
                      atomic_op.memory_access_kind);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitWord64AtomicExchange(
    Node* node) {
  AtomicOpParameters params = AtomicOpParametersOf(node->op());
  ArchOpcode opcode;
  if (params.type() == MachineType::Uint8()) {
    opcode = kAtomicExchangeUint8;
  } else if (params.type() == MachineType::Uint16()) {
    opcode = kAtomicExchangeUint16;
  } else if (params.type() == MachineType::Uint32()) {
    opcode = kAtomicExchangeWord32;
  } else if (params.type() == MachineType::Uint64()) {
    opcode = kX64Word64AtomicExchangeUint64;
  } else {
    UNREACHABLE();
  }
  VisitAtomicExchange(this, node, opcode, AtomicWidth::kWord64, params.kind());
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitWord64AtomicExchange(
    node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  const AtomicRMWOp& atomic_op = this->Get(node).template Cast<AtomicRMWOp>();
  ArchOpcode opcode;
  if (atomic_op.memory_rep == MemoryRepresentation::Uint8()) {
    opcode = kAtomicExchangeUint8;
  } else if (atomic_op.memory_rep == MemoryRepresentation::Uint16()) {
    opcode = kAtomicExchangeUint16;
  } else if (atomic_op.memory_rep == MemoryRepresentation::Uint32()) {
    opcode = kAtomicExchangeWord32;
  } else if (atomic_op.memory_rep == MemoryRepresentation::Uint64()) {
    opcode = kX64Word64AtomicExchangeUint64;
  } else {
    UNREACHABLE();
  }
  VisitAtomicExchange(this, node, opcode, AtomicWidth::kWord64,
                      atomic_op.memory_access_kind);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitWord32AtomicCompareExchange(
    Node* node) {
  AtomicOpParameters params = AtomicOpParametersOf(node->op());
  ArchOpcode opcode;
  if (params.type() == MachineType::Int8()) {
    opcode = kAtomicCompareExchangeInt8;
  } else if (params.type() == MachineType::Uint8()) {
    opcode = kAtomicCompareExchangeUint8;
  } else if (params.type() == MachineType::Int16()) {
    opcode = kAtomicCompareExchangeInt16;
  } else if (params.type() == MachineType::Uint16()) {
    opcode = kAtomicCompareExchangeUint16;
  } else if (params.type() == MachineType::Int32()
    || params.type() == MachineType::Uint32()) {
    opcode = kAtomicCompareExchangeWord32;
  } else {
    UNREACHABLE();
  }
  VisitAtomicCompareExchange(this, node, opcode, AtomicWidth::kWord32,
                             params.kind());
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitWord32AtomicCompareExchange(
    node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  const AtomicRMWOp& atomic_op = this->Get(node).template Cast<AtomicRMWOp>();
  ArchOpcode opcode;
  if (atomic_op.memory_rep == MemoryRepresentation::Int8()) {
    opcode = kAtomicCompareExchangeInt8;
  } else if (atomic_op.memory_rep == MemoryRepresentation::Uint8()) {
    opcode = kAtomicCompareExchangeUint8;
  } else if (atomic_op.memory_rep == MemoryRepresentation::Int16()) {
    opcode = kAtomicCompareExchangeInt16;
  } else if (atomic_op.memory_rep == MemoryRepresentation::Uint16()) {
    opcode = kAtomicCompareExchangeUint16;
  } else if (atomic_op.memory_rep == MemoryRepresentation::Int32() ||
             atomic_op.memory_rep == MemoryRepresentation::Uint32()) {
    opcode = kAtomicCompareExchangeWord32;
  } else {
    UNREACHABLE();
  }
  VisitAtomicCompareExchange(this, node, opcode, AtomicWidth::kWord32,
                             atomic_op.memory_access_kind);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitWord64AtomicCompareExchange(
    Node* node) {
  AtomicOpParameters params = AtomicOpParametersOf(node->op());
  ArchOpcode opcode;
  if (params.type() == MachineType::Uint8()) {
    opcode = kAtomicCompareExchangeUint8;
  } else if (params.type() == MachineType::Uint16()) {
    opcode = kAtomicCompareExchangeUint16;
  } else if (params.type() == MachineType::Uint32()) {
    opcode = kAtomicCompareExchangeWord32;
  } else if (params.type() == MachineType::Uint64()) {
    opcode = kX64Word64AtomicCompareExchangeUint64;
  } else {
    UNREACHABLE();
  }
  VisitAtomicCompareExchange(this, node, opcode, AtomicWidth::kWord64,
                             params.kind());
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitWord64AtomicCompareExchange(
    node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  const AtomicRMWOp& atomic_op = this->Get(node).template Cast<AtomicRMWOp>();
  ArchOpcode opcode;
  if (atomic_op.memory_rep == MemoryRepresentation::Uint8()) {
    opcode = kAtomicCompareExchangeUint8;
  } else if (atomic_op.memory_rep == MemoryRepresentation::Uint16()) {
    opcode = kAtomicCompareExchangeUint16;
  } else if (atomic_op.memory_rep == MemoryRepresentation::Uint32()) {
    opcode = kAtomicCompareExchangeWord32;
  } else if (atomic_op.memory_rep == MemoryRepresentation::Uint64()) {
    opcode = kX64Word64AtomicCompareExchangeUint64;
  } else {
    UNREACHABLE();
  }
  VisitAtomicCompareExchange(this, node, opcode, AtomicWidth::kWord64,
                             atomic_op.memory_access_kind);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitWord32AtomicBinaryOperation(
    turboshaft::OpIndex node, ArchOpcode int8_op, ArchOpcode uint8_op,
    ArchOpcode int16_op, ArchOpcode uint16_op, ArchOpcode word32_op) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  const AtomicRMWOp& atomic_op = this->Get(node).template Cast<AtomicRMWOp>();
  ArchOpcode opcode;
  if (atomic_op.memory_rep == MemoryRepresentation::Int8()) {
    opcode = int8_op;
  } else if (atomic_op.memory_rep == MemoryRepresentation::Uint8()) {
    opcode = uint8_op;
  } else if (atomic_op.memory_rep == MemoryRepresentation::Int16()) {
    opcode = int16_op;
  } else if (atomic_op.memory_rep == MemoryRepresentation::Uint16()) {
    opcode = uint16_op;
  } else if (atomic_op.memory_rep == MemoryRepresentation::Int32() ||
             atomic_op.memory_rep == MemoryRepresentation::Uint32()) {
    opcode = word32_op;
  } else {
    UNREACHABLE();
  }
  VisitAtomicBinop(this, node, opcode, AtomicWidth::kWord32,
                   atomic_op.memory_access_kind);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitWord32AtomicBinaryOperation(
    Node* node, ArchOpcode int8_op, ArchOpcode uint8_op, ArchOpcode int16_op,
    ArchOpcode uint16_op, ArchOpcode word32_op) {
  AtomicOpParameters params = AtomicOpParametersOf(node->op());
  ArchOpcode opcode;
  if (params.type() == MachineType::Int8()) {
    opcode = int8_op;
  } else if (params.type() == MachineType::Uint8()) {
    opcode = uint8_op;
  } else if (params.type() == MachineType::Int16()) {
    opcode = int16_op;
  } else if (params.type() == MachineType::Uint16()) {
    opcode = uint16_op;
  } else if (params.type() == MachineType::Int32()
    || params.type() == MachineType::Uint32()) {
    opcode = word32_op;
  } else {
    UNREACHABLE();
  }
  VisitAtomicBinop(this, node, opcode, AtomicWidth::kWord32, params.kind());
}

#define VISIT_ATOMIC_BINOP(op)                                             \
  template <typename Adapter>                                              \
  void InstructionSelectorT<Adapter>::VisitWord32Atomic##op(node_t node) { \
    VisitWord32AtomicBinaryOperation(                                      \
        node, kAtomic##op##Int8, kAtomic##op##Uint8, kAtomic##op##Int16,   \
        kAtomic##op##Uint16, kAtomic##op##Word32);                         \
  }
VISIT_ATOMIC_BINOP(Add)
VISIT_ATOMIC_BINOP(Sub)
VISIT_ATOMIC_BINOP(And)
VISIT_ATOMIC_BINOP(Or)
VISIT_ATOMIC_BINOP(Xor)
#undef VISIT_ATOMIC_BINOP

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitWord64AtomicBinaryOperation(
    node_t node, ArchOpcode uint8_op, ArchOpcode uint16_op,
    ArchOpcode uint32_op, ArchOpcode word64_op) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  const AtomicRMWOp& atomic_op = this->Get(node).template Cast<AtomicRMWOp>();
  ArchOpcode opcode;
  if (atomic_op.memory_rep == MemoryRepresentation::Uint8()) {
    opcode = uint8_op;
  } else if (atomic_op.memory_rep == MemoryRepresentation::Uint16()) {
    opcode = uint16_op;
  } else if (atomic_op.memory_rep == MemoryRepresentation::Uint32()) {
    opcode = uint32_op;
  } else if (atomic_op.memory_rep == MemoryRepresentation::Uint64()) {
    opcode = word64_op;
  } else {
    UNREACHABLE();
  }
  VisitAtomicBinop(this, node, opcode, AtomicWidth::kWord64,
                   atomic_op.memory_access_kind);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitWord64AtomicBinaryOperation(
    Node* node, ArchOpcode uint8_op, ArchOpcode uint16_op, ArchOpcode uint32_op,
    ArchOpcode word64_op) {
  AtomicOpParameters params = AtomicOpParametersOf(node->op());
  ArchOpcode opcode;
  if (params.type() == MachineType::Uint8()) {
    opcode = uint8_op;
  } else if (params.type() == MachineType::Uint16()) {
    opcode = uint16_op;
  } else if (params.type() == MachineType::Uint32()) {
    opcode = uint32_op;
  } else if (params.type() == MachineType::Uint64()) {
    opcode = word64_op;
  } else {
    UNREACHABLE();
  }
  VisitAtomicBinop(this, node, opcode, AtomicWidth::kWord64, params.kind());
}

#define VISIT_ATOMIC_BINOP(op)                                                 \
  template <typename Adapter>                                                  \
  void InstructionSelectorT<Adapter>::VisitWord64Atomic##op(node_t node) {     \
    VisitWord64AtomicBinaryOperation(node, kAtomic##op##Uint8,                 \
                                     kAtomic##op##Uint16, kAtomic##op##Word32, \
                                     kX64Word64Atomic##op##Uint64);            \
  }
VISIT_ATOMIC_BINOP(Add)
VISIT_ATOMIC_BINOP(Sub)
VISIT_ATOMIC_BINOP(And)
VISIT_ATOMIC_BINOP(Or)
VISIT_ATOMIC_BINOP(Xor)
#undef VISIT_ATOMIC_BINOP

#ifdef V8_ENABLE_WEBASSEMBLY
#define SIMD_BINOP_SSE_AVX_LIST(V) \
  V(I64x2ExtMulLowI32x4S)          \
  V(I64x2ExtMulHighI32x4S)         \
  V(I64x2ExtMulLowI32x4U)          \
  V(I64x2ExtMulHighI32x4U)         \
  V(I32x4DotI16x8S)                \
  V(I32x8DotI16x16S)               \
  V(I32x4ExtMulLowI16x8S)          \
  V(I32x4ExtMulHighI16x8S)         \
  V(I32x4ExtMulLowI16x8U)          \
  V(I32x4ExtMulHighI16x8U)         \
  V(I16x8SConvertI32x4)            \
  V(I16x8UConvertI32x4)            \
  V(I16x8ExtMulLowI8x16S)          \
  V(I16x8ExtMulHighI8x16S)         \
  V(I16x8ExtMulLowI8x16U)          \
  V(I16x8ExtMulHighI8x16U)         \
  V(I16x8Q15MulRSatS)              \
  V(I16x8RelaxedQ15MulRS)          \
  V(I8x16SConvertI16x8)            \
  V(I8x16UConvertI16x8)            \
  V(I16x16SConvertI32x8)           \
  V(I16x16UConvertI32x8)           \
  V(I8x32SConvertI16x16)           \
  V(I8x32UConvertI16x16)           \
  V(I64x4ExtMulI32x4S)             \
  V(I64x4ExtMulI32x4U)             \
  V(I32x8ExtMulI16x8S)             \
  V(I32x8ExtMulI16x8U)             \
  V(I16x16ExtMulI8x16S)            \
  V(I16x16ExtMulI8x16U)

#define SIMD_BINOP_SSE_AVX_LANE_SIZE_VECTOR_LENGTH_LIST(V)  \
  V(F64x2Add, FAdd, kL64, kV128)                            \
  V(F64x4Add, FAdd, kL64, kV256)                            \
  V(F32x4Add, FAdd, kL32, kV128)                            \
  V(F32x8Add, FAdd, kL32, kV256)                            \
  V(I64x2Add, IAdd, kL64, kV128)                            \
  V(I64x4Add, IAdd, kL64, kV256)                            \
  V(I32x8Add, IAdd, kL32, kV256)                            \
  V(I16x16Add, IAdd, kL16, kV256)                           \
  V(I8x32Add, IAdd, kL8, kV256)                             \
  V(I32x4Add, IAdd, kL32, kV128)                            \
  V(I16x8Add, IAdd, kL16, kV128)                            \
  V(I8x16Add, IAdd, kL8, kV128)                             \
  V(F64x4Sub, FSub, kL64, kV256)                            \
  V(F64x2Sub, FSub, kL64, kV128)                            \
  V(F32x4Sub, FSub, kL32, kV128)                            \
  V(F32x8Sub, FSub, kL32, kV256)                            \
  V(I64x2Sub, ISub, kL64, kV128)                            \
  V(I64x4Sub, ISub, kL64, kV256)                            \
  V(I32x8Sub, ISub, kL32, kV256)                            \
  V(I16x16Sub, ISub, kL16, kV256)                           \
  V(I8x32Sub, ISub, kL8, kV256)                             \
  V(I32x4Sub, ISub, kL32, kV128)                            \
  V(I16x8Sub, ISub, kL16, kV128)                            \
  V(I8x16Sub, ISub, kL8, kV128)                             \
  V(F64x2Mul, FMul, kL64, kV128)                            \
  V(F32x4Mul, FMul, kL32, kV128)                            \
  V(F64x4Mul, FMul, kL64, kV256)                            \
  V(F32x8Mul, FMul, kL32, kV256)                            \
  V(I32x8Mul, IMul, kL32, kV256)                            \
  V(I16x16Mul, IMul, kL16, kV256)                           \
  V(I32x4Mul, IMul, kL32, kV128)                            \
  V(I16x8Mul, IMul, kL16, kV128)                            \
  V(F64x2Div, FDiv, kL64, kV128)                            \
  V(F32x4Div, FDiv, kL32, kV128)                            \
  V(F64x4Div, FDiv, kL64, kV256)                            \
  V(F32x8Div, FDiv, kL32, kV256)                            \
  V(I16x8AddSatS, IAddSatS, kL16, kV128)                    \
  V(I16x16AddSatS, IAddSatS, kL16, kV256)                   \
  V(I8x16AddSatS, IAddSatS, kL8, kV128)                     \
  V(I8x32AddSatS, IAddSatS, kL8, kV256)                     \
  V(I16x8SubSatS, ISubSatS, kL16, kV128)                    \
  V(I16x16SubSatS, ISubSatS, kL16, kV256)                   \
  V(I8x16SubSatS, ISubSatS, kL8, kV128)                     \
  V(I8x32SubSatS, ISubSatS, kL8, kV256)                     \
  V(I16x8AddSatU, IAddSatU, kL16, kV128)                    \
  V(I16x16AddSatU, IAddSatU, kL16, kV256)                   \
  V(I8x16AddSatU, IAddSatU, kL8, kV128)                     \
  V(I8x32AddSatU, IAddSatU, kL8, kV256)                     \
  V(I16x8SubSatU, ISubSatU, kL16, kV128)                    \
  V(I16x16SubSatU, ISubSatU, kL16, kV256)                   \
  V(I8x16SubSatU, ISubSatU, kL8, kV128)                     \
  V(I8x32SubSatU, ISubSatU, kL8, kV256)                     \
  V(F64x2Eq, FEq, kL64, kV128)                              \
  V(F32x4Eq, FEq, kL32, kV128)                              \
  V(F32x8Eq, FEq, kL32, kV256)                              \
  V(F64x4Eq, FEq, kL64, kV256)                              \
  V(I8x32Eq, IEq, kL8, kV256)                               \
  V(I16x16Eq, IEq, kL16, kV256)                             \
  V(I32x8Eq, IEq, kL32, kV256)                              \
  V(I64x4Eq, IEq, kL64, kV256)                              \
  V(I64x2Eq, IEq, kL64, kV128)                              \
  V(I32x4Eq, IEq, kL32, kV128)                              \
  V(I16x8Eq, IEq, kL16, kV128)                              \
  V(I8x16Eq, IEq, kL8, kV128)                               \
  V(F64x2Ne, FNe, kL64, kV128)                              \
  V(F32x4Ne, FNe, kL32, kV128)                              \
  V(F32x8Ne, FNe, kL32, kV256)                              \
  V(F64x4Ne, FNe, kL64, kV256)                              \
  V(I32x4GtS, IGtS, kL32, kV128)                            \
  V(I16x8GtS, IGtS, kL16, kV128)                            \
  V(I8x16GtS, IGtS, kL8, kV128)                             \
  V(I8x32GtS, IGtS, kL8, kV256)                             \
  V(I16x16GtS, IGtS, kL16, kV256)                           \
  V(I32x8GtS, IGtS, kL32, kV256)                            \
  V(I64x4GtS, IGtS, kL64, kV256)                            \
  V(F64x2Lt, FLt, kL64, kV128)                              \
  V(F32x4Lt, FLt, kL32, kV128)                              \
  V(F64x4Lt, FLt, kL64, kV256)                              \
  V(F32x8Lt, FLt, kL32, kV256)                              \
  V(F64x2Le, FLe, kL64, kV128)                              \
  V(F32x4Le, FLe, kL32, kV128)                              \
  V(F64x4Le, FLe, kL64, kV256)                              \
  V(F32x8Le, FLe, kL32, kV256)                              \
  V(I32x4MinS, IMinS, kL32, kV128)                          \
  V(I16x8MinS, IMinS, kL16, kV128)                          \
  V(I8x16MinS, IMinS, kL8, kV128)                           \
  V(I32x4MinU, IMinU, kL32, kV128)                          \
  V(I16x8MinU, IMinU, kL16, kV128)                          \
  V(I8x16MinU, IMinU, kL8, kV128)                           \
  V(I32x4MaxS, IMaxS, kL32, kV128)                          \
  V(I16x8MaxS, IMaxS, kL16, kV128)                          \
  V(I8x16MaxS, IMaxS, kL8, kV128)                           \
  V(I32x4MaxU, IMaxU, kL32, kV128)                          \
  V(I16x8MaxU, IMaxU, kL16, kV128)                          \
  V(I8x16MaxU, IMaxU, kL8, kV128)                           \
  V(I32x8MinS, IMinS, kL32, kV256)                          \
  V(I16x16MinS, IMinS, kL16, kV256)                         \
  V(I8x32MinS, IMinS, kL8, kV256)                           \
  V(I32x8MinU, IMinU, kL32, kV256)                          \
  V(I16x16MinU, IMinU, kL16, kV256)                         \
  V(I8x32MinU, IMinU, kL8, kV256)                           \
  V(I32x8MaxS, IMaxS, kL32, kV256)                          \
  V(I16x16MaxS, IMaxS, kL16, kV256)                         \
  V(I8x32MaxS, IMaxS, kL8, kV256)                           \
  V(I32x8MaxU, IMaxU, kL32, kV256)                          \
  V(I16x16MaxU, IMaxU, kL16, kV256)                         \
  V(I8x32MaxU, IMaxU, kL8, kV256)                           \
  V(I16x8RoundingAverageU, IRoundingAverageU, kL16, kV128)  \
  V(I16x16RoundingAverageU, IRoundingAverageU, kL16, kV256) \
  V(I8x16RoundingAverageU, IRoundingAverageU, kL8, kV128)   \
  V(I8x32RoundingAverageU, IRoundingAverageU, kL8, kV256)   \
  V(S128And, SAnd, kL8, kV128)                              \
  V(S256And, SAnd, kL8, kV256)                              \
  V(S128Or, SOr, kL8, kV128)                                \
  V(S256Or, SOr, kL8, kV256)                                \
  V(S128Xor, SXor, kL8, kV128)                              \
  V(S256Xor, SXor, kL8, kV256)

#define SIMD_F16x8_BINOP_LIST(V) \
  V(F16x8Add, FAdd)              \
  V(F16x8Sub, FSub)              \
  V(F16x8Mul, FMul)              \
  V(F16x8Div, FDiv)              \
  V(F16x8Min, FMin)              \
  V(F16x8Max, FMax)              \
  V(F16x8Eq, FEq)                \
  V(F16x8Ne, FNe)                \
  V(F16x8Lt, FLt)                \
  V(F16x8Le, FLe)

#define SIMD_BINOP_LANE_SIZE_VECTOR_LENGTH_LIST(V) \
  V(F64x2Min, FMin, kL64, kV128)                   \
  V(F32x4Min, FMin, kL32, kV128)                   \
  V(F64x4Min, FMin, kL64, kV256)                   \
  V(F32x8Min, FMin, kL32, kV256)                   \
  V(F64x2Max, FMax, kL64, kV128)                   \
  V(F32x4Max, FMax, kL32, kV128)                   \
  V(F64x4Max, FMax, kL64, kV256)                   \
  V(F32x8Max, FMax, kL32, kV256)                   \
  V(I64x2Ne, INe, kL64, kV128)                     \
  V(I32x4Ne, INe, kL32, kV128)                     \
  V(I16x8Ne, INe, kL16, kV128)                     \
  V(I8x16Ne, INe, kL8, kV128)                      \
  V(I64x4Ne, INe, kL64, kV256)                     \
  V(I32x8Ne, INe, kL32, kV256)                     \
  V(I16x16Ne, INe, kL16, kV256)                    \
  V(I8x32Ne, INe, kL8, kV256)                      \
  V(I32x4GtU, IGtU, kL32, kV128)                   \
  V(I16x8GtU, IGtU, kL16, kV128)                   \
  V(I8x16GtU, IGtU, kL8, kV128)                    \
  V(I32x8GtU, IGtU, kL32, kV256)                   \
  V(I16x16GtU, IGtU, kL16, kV256)                  \
  V(I8x32GtU, IGtU, kL8, kV256)                    \
  V(I32x4GeS, IGeS, kL32, kV128)                   \
  V(I16x8GeS, IGeS, kL16, kV128)                   \
  V(I8x16GeS, IGeS, kL8, kV128)                    \
  V(I32x8GeS, IGeS, kL32, kV256)                   \
  V(I16x16GeS, IGeS, kL16, kV256)                  \
  V(I8x32GeS, IGeS, kL8, kV256)                    \
  V(I32x4GeU, IGeU, kL32, kV128)                   \
  V(I16x8GeU, IGeU, kL16, kV128)                   \
  V(I8x16GeU, IGeU, kL8, kV128)                    \
  V(I32x8GeU, IGeU, kL32, kV256)                   \
  V(I16x16GeU, IGeU, kL16, kV256)                  \
  V(I8x32GeU, IGeU, kL8, kV256)

#define SIMD_UNOP_LIST(V)   \
  V(F64x2ConvertLowI32x4S)  \
  V(F64x4ConvertI32x4S)     \
  V(F32x4SConvertI32x4)     \
  V(F32x8SConvertI32x8)     \
  V(F32x4DemoteF64x2Zero)   \
  V(F32x4DemoteF64x4)       \
  V(I16x8SConvertF16x8)     \
  V(I16x8UConvertF16x8)     \
  V(F16x8SConvertI16x8)     \
  V(F16x8UConvertI16x8)     \
  V(F16x8DemoteF32x4Zero)   \
  V(F32x4PromoteLowF16x8)   \
  V(I64x2SConvertI32x4Low)  \
  V(I64x2SConvertI32x4High) \
  V(I64x4SConvertI32x4)     \
  V(I64x2UConvertI32x4Low)  \
  V(I64x2UConvertI32x4High) \
  V(I64x4UConvertI32x4)     \
  V(I32x4SConvertI16x8Low)  \
  V(I32x4SConvertI16x8High) \
  V(I32x8SConvertI16x8)     \
  V(I32x4UConvertI16x8Low)  \
  V(I32x4UConvertI16x8High) \
  V(I32x8UConvertI16x8)     \
  V(I16x8SConvertI8x16Low)  \
  V(I16x8SConvertI8x16High) \
  V(I16x16SConvertI8x16)    \
  V(I16x8UConvertI8x16Low)  \
  V(I16x8UConvertI8x16High) \
  V(I16x16UConvertI8x16)

#define SIMD_UNOP_LANE_SIZE_VECTOR_LENGTH_LIST(V) \
  V(F32x4Abs, FAbs, kL32, kV128)                  \
  V(I32x4Abs, IAbs, kL32, kV128)                  \
  V(F16x8Abs, FAbs, kL16, kV128)                  \
  V(I16x8Abs, IAbs, kL16, kV128)                  \
  V(I8x16Abs, IAbs, kL8, kV128)                   \
  V(F32x4Neg, FNeg, kL32, kV128)                  \
  V(I32x4Neg, INeg, kL32, kV128)                  \
  V(F16x8Neg, FNeg, kL16, kV128)                  \
  V(I16x8Neg, INeg, kL16, kV128)                  \
  V(I8x16Neg, INeg, kL8, kV128)                   \
  V(F64x2Sqrt, FSqrt, kL64, kV128)                \
  V(F32x4Sqrt, FSqrt, kL32, kV128)                \
  V(F16x8Sqrt, FSqrt, kL16, kV128)                \
  V(I64x2BitMask, IBitMask, kL64, kV128)          \
  V(I32x4BitMask, IBitMask, kL32, kV128)          \
  V(I16x8BitMask, IBitMask, kL16, kV128)          \
  V(I8x16BitMask, IBitMask, kL8, kV128)           \
  V(I64x2AllTrue, IAllTrue, kL64, kV128)          \
  V(I32x4AllTrue, IAllTrue, kL32, kV128)          \
  V(I16x8AllTrue, IAllTrue, kL16, kV128)          \
  V(I8x16AllTrue, IAllTrue, kL8, kV128)           \
  V(S128Not, SNot, kL8, kV128)                    \
  V(F64x4Abs, FAbs, kL64, kV256)                  \
  V(F32x8Abs, FAbs, kL32, kV256)                  \
  V(I32x8Abs, IAbs, kL32, kV256)                  \
  V(I16x16Abs, IAbs, kL16, kV256)                 \
  V(I8x32Abs, IAbs, kL8, kV256)                   \
  V(F64x4Neg, FNeg, kL64, kV256)                  \
  V(F32x8Neg, FNeg, kL32, kV256)                  \
  V(I32x8Neg, INeg, kL32, kV256)                  \
  V(I16x16Neg, INeg, kL16, kV256)                 \
  V(I8x32Neg, INeg, kL8, kV256)                   \
  V(F64x4Sqrt, FSqrt, kL64, kV256)                \
  V(F32x8Sqrt, FSqrt, kL32, kV256)                \
  V(S256Not, SNot, kL8, kV256)

#define SIMD_SHIFT_LANE_SIZE_VECTOR_LENGTH_OPCODES(V) \
  V(I64x2Shl, IShl, kL64, kV128)                      \
  V(I32x4Shl, IShl, kL32, kV128)                      \
  V(I16x8Shl, IShl, kL16, kV128)                      \
  V(I32x4ShrS, IShrS, kL32, kV128)                    \
  V(I16x8ShrS, IShrS, kL16, kV128)                    \
  V(I64x2ShrU, IShrU, kL64, kV128)                    \
  V(I32x4ShrU, IShrU, kL32, kV128)                    \
  V(I16x8ShrU, IShrU, kL16, kV128)                    \
  V(I64x4Shl, IShl, kL64, kV256)                      \
  V(I32x8Shl, IShl, kL32, kV256)                      \
  V(I16x16Shl, IShl, kL16, kV256)                     \
  V(I32x8ShrS, IShrS, kL32, kV256)                    \
  V(I16x16ShrS, IShrS, kL16, kV256)                   \
  V(I64x4ShrU, IShrU, kL64, kV256)                    \
  V(I32x8ShrU, IShrU, kL32, kV256)                    \
  V(I16x16ShrU, IShrU, kL16, kV256)

#define SIMD_NARROW_SHIFT_LANE_SIZE_VECTOR_LENGTH_OPCODES(V) \
  V(I8x16Shl, IShl, kL8, kV128)                              \
  V(I8x16ShrS, IShrS, kL8, kV128)                            \
  V(I8x16ShrU, IShrU, kL8, kV128)

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitS128Const(node_t node) {
  X64OperandGeneratorT<Adapter> g(this);
  static const int kUint32Immediates = kSimd128Size / sizeof(uint32_t);
  uint32_t val[kUint32Immediates];
  if constexpr (Adapter::IsTurboshaft) {
    const turboshaft::Simd128ConstantOp& constant =
        this->Get(node).template Cast<turboshaft::Simd128ConstantOp>();
    memcpy(val, constant.value, kSimd128Size);
  } else {
    memcpy(val, S128ImmediateParameterOf(node->op()).data(), kSimd128Size);
  }
  // If all bytes are zeros or ones, avoid emitting code for generic constants
  bool all_zeros = !(val[0] || val[1] || val[2] || val[3]);
  bool all_ones = val[0] == UINT32_MAX && val[1] == UINT32_MAX &&
                  val[2] == UINT32_MAX && val[3] == UINT32_MAX;
  InstructionOperand dst = g.DefineAsRegister(node);
  if (all_zeros) {
    Emit(kX64SZero | VectorLengthField::encode(kV128), dst);
  } else if (all_ones) {
    Emit(kX64SAllOnes | VectorLengthField::encode(kV128), dst);
  } else {
    Emit(kX64S128Const, dst, g.UseImmediate(val[0]), g.UseImmediate(val[1]),
         g.UseImmediate(val[2]), g.UseImmediate(val[3]));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitS128Zero(node_t node) {
  X64OperandGeneratorT<Adapter> g(this);
  Emit(kX64SZero | VectorLengthField::encode(kV128), g.DefineAsRegister(node));
}
// Name, LaneSize, VectorLength
#define SIMD_INT_TYPES_FOR_SPLAT(V) \
  V(I64x2, kL64, kV128)             \
  V(I32x4, kL32, kV128)             \
  V(I16x8, kL16, kV128)             \
  V(I8x16, kL8, kV128)              \
  V(I64x4, kL64, kV256)             \
  V(I32x8, kL32, kV256)             \
  V(I16x16, kL16, kV256)            \
  V(I8x32, kL8, kV256)

// Splat with an optimization for const 0.
#define VISIT_INT_SIMD_SPLAT(Type, LaneSize, VectorLength)                   \
  template <typename Adapter>                                                \
  void InstructionSelectorT<Adapter>::Visit##Type##Splat(node_t node) {      \
    X64OperandGeneratorT<Adapter> g(this);                                   \
    DCHECK_EQ(this->value_input_count(node), 1);                             \
    node_t input = this->input_at(node, 0);                                  \
    if (g.CanBeImmediate(input) && g.GetImmediateIntegerValue(input) == 0) { \
      Emit(kX64SZero | VectorLengthField::encode(VectorLength),              \
           g.DefineAsRegister(node));                                        \
    } else {                                                                 \
      Emit(kX64ISplat | LaneSizeField::encode(LaneSize) |                    \
               VectorLengthField::encode(VectorLength),                      \
           g.DefineAsRegister(node), g.Use(input));                          \
    }                                                                        \
  }
SIMD_INT_TYPES_FOR_SPLAT(VISIT_INT_SIMD_SPLAT)
#undef VISIT_INT_SIMD_SPLAT
#undef SIMD_INT_TYPES_FOR_SPLAT

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF64x2Splat(node_t node) {
  X64OperandGeneratorT<Adapter> g(this);
  DCHECK_EQ(this->value_input_count(node), 1);
  Emit(kX64FSplat | LaneSizeField::encode(kL64) |
           VectorLengthField::encode(kV128),
       g.DefineAsRegister(node), g.Use(this->input_at(node, 0)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF32x4Splat(node_t node) {
  X64OperandGeneratorT<Adapter> g(this);
  DCHECK_EQ(this->value_input_count(node), 1);
  Emit(kX64FSplat | LaneSizeField::encode(kL32) |
           VectorLengthField::encode(kV128),
       g.DefineAsRegister(node), g.UseRegister(this->input_at(node, 0)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF16x8Splat(node_t node) {
  X64OperandGeneratorT<Adapter> g(this);
  DCHECK_EQ(this->value_input_count(node), 1);
  Emit(kX64FSplat | LaneSizeField::encode(kL16) |
           VectorLengthField::encode(kV128),
       g.DefineAsRegister(node), g.UseRegister(this->input_at(node, 0)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF64x4Splat(node_t node) {
  X64OperandGeneratorT<Adapter> g(this);
  DCHECK_EQ(this->value_input_count(node), 1);
  Emit(kX64FSplat | LaneSizeField::encode(kL64) |
           VectorLengthField::encode(kV256),
       g.DefineAsRegister(node), g.UseRegister(this->input_at(node, 0)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF32x8Splat(node_t node) {
  X64OperandGeneratorT<Adapter> g(this);
  DCHECK_EQ(this->value_input_count(node), 1);
  Emit(kX64FSplat | LaneSizeField::encode(kL32) |
           VectorLengthField::encode(kV256),
       g.DefineAsRegister(node), g.UseRegister(this->input_at(node, 0)));
}

#define SIMD_VISIT_EXTRACT_LANE(IF, Type, Sign, LaneSize, VectorLength)        \
  template <>                                                                  \
  void InstructionSelectorT<TurbofanAdapter>::Visit##Type##ExtractLane##Sign(  \
      node_t node) {                                                           \
    X64OperandGeneratorT<TurbofanAdapter> g(this);                             \
    int32_t lane = OpParameter<int32_t>(node->op());                           \
    Emit(kX64##IF##ExtractLane##Sign | LaneSizeField::encode(LaneSize) |       \
             VectorLengthField::encode(VectorLength),                          \
         g.DefineAsRegister(node), g.UseRegister(node->InputAt(0)),            \
         g.UseImmediate(lane));                                                \
  }                                                                            \
  template <>                                                                  \
  void                                                                         \
      InstructionSelectorT<TurboshaftAdapter>::Visit##Type##ExtractLane##Sign( \
          node_t node) {                                                       \
    X64OperandGeneratorT<TurboshaftAdapter> g(this);                           \
    const turboshaft::Simd128ExtractLaneOp& op =                               \
        this->Get(node).template Cast<turboshaft::Simd128ExtractLaneOp>();     \
    int32_t lane = op.lane;                                                    \
    Emit(kX64##IF##ExtractLane##Sign | LaneSizeField::encode(LaneSize) |       \
             VectorLengthField::encode(VectorLength),                          \
         g.DefineAsRegister(node), g.UseRegister(op.input()),                  \
         g.UseImmediate(lane));                                                \
  }

SIMD_VISIT_EXTRACT_LANE(F, F64x2, , kL64, kV128)
SIMD_VISIT_EXTRACT_LANE(F, F32x4, , kL32, kV128)
SIMD_VISIT_EXTRACT_LANE(F, F16x8, , kL16, kV128)
SIMD_VISIT_EXTRACT_LANE(I, I64x2, , kL64, kV128)
SIMD_VISIT_EXTRACT_LANE(I, I32x4, , kL32, kV128)
SIMD_VISIT_EXTRACT_LANE(I, I16x8, S, kL16, kV128)
SIMD_VISIT_EXTRACT_LANE(I, I8x16, S, kL8, kV128)
#undef SIMD_VISIT_EXTRACT_LANE

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI16x8ExtractLaneU(node_t node) {
  X64OperandGeneratorT<Adapter> g(this);
  if constexpr (Adapter::IsTurboshaft) {
    const turboshaft::Simd128ExtractLaneOp& op =
        this->Get(node).template Cast<turboshaft::Simd128ExtractLaneOp>();
    Emit(kX64Pextrw, g.DefineAsRegister(node), g.UseRegister(op.input()),
         g.UseImmediate(static_cast<int32_t>(op.lane)));

  } else {
    int32_t lane = OpParameter<int32_t>(node->op());
    Emit(kX64Pextrw, g.DefineAsRegister(node), g.UseRegister(node->InputAt(0)),
         g.UseImmediate(lane));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI8x16ExtractLaneU(node_t node) {
  X64OperandGeneratorT<Adapter> g(this);
  if constexpr (Adapter::IsTurboshaft) {
    const turboshaft::Simd128ExtractLaneOp& op =
        this->Get(node).template Cast<turboshaft::Simd128ExtractLaneOp>();
    Emit(kX64Pextrb, g.DefineAsRegister(node), g.UseRegister(op.input()),
         g.UseImmediate(op.lane));

  } else {
    int32_t lane = OpParameter<int32_t>(node->op());
    Emit(kX64Pextrb, g.DefineAsRegister(node), g.UseRegister(node->InputAt(0)),
         g.UseImmediate(lane));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF16x8ReplaceLane(node_t node) {
  X64OperandGeneratorT<Adapter> g(this);
  if constexpr (Adapter::IsTurboshaft) {
    auto& op =
        this->Get(node).template Cast<turboshaft::Simd128ReplaceLaneOp>();
    Emit(kX64FReplaceLane | LaneSizeField::encode(kL16) |
             VectorLengthField::encode(kV128),
         g.DefineSameAsFirst(node), g.UseRegister(op.into()),
         g.UseImmediate(op.lane), g.Use(op.new_lane()));

  } else {
    int32_t lane = OpParameter<int32_t>(node->op());
    Emit(kX64FReplaceLane | LaneSizeField::encode(kL16) |
             VectorLengthField::encode(kV128),
         g.DefineSameAsFirst(node), g.UseRegister(node->InputAt(0)),
         g.UseImmediate(lane), g.Use(node->InputAt(1)));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF32x4ReplaceLane(node_t node) {
  X64OperandGeneratorT<Adapter> g(this);
  if constexpr (Adapter::IsTurboshaft) {
    const turboshaft::Simd128ReplaceLaneOp& op =
        this->Get(node).template Cast<turboshaft::Simd128ReplaceLaneOp>();
    Emit(kX64FReplaceLane | LaneSizeField::encode(kL32) |
             VectorLengthField::encode(kV128),
         g.DefineSameAsFirst(node), g.UseRegister(op.into()),
         g.UseImmediate(op.lane), g.Use(op.new_lane()));

  } else {
    int32_t lane = OpParameter<int32_t>(node->op());
    Emit(kX64FReplaceLane | LaneSizeField::encode(kL32) |
             VectorLengthField::encode(kV128),
         g.DefineSameAsFirst(node), g.UseRegister(node->InputAt(0)),
         g.UseImmediate(lane), g.Use(node->InputAt(1)));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF64x2ReplaceLane(node_t node) {
  X64OperandGeneratorT<Adapter> g(this);
  // When no-AVX, define dst == src to save a move.
  InstructionOperand dst =
      IsSupported(AVX) ? g.DefineAsRegister(node) : g.DefineSameAsFirst(node);
  if constexpr (Adapter::IsTurboshaft) {
    const turboshaft::Simd128ReplaceLaneOp& op =
        this->Get(node).template Cast<turboshaft::Simd128ReplaceLaneOp>();
    Emit(kX64FReplaceLane | LaneSizeField::encode(kL64) |
             VectorLengthField::encode(kV128),
         dst, g.UseRegister(op.into()), g.UseImmediate(op.lane),
         g.UseRegister(op.new_lane()));

  } else {
    int32_t lane = OpParameter<int32_t>(node->op());
    Emit(kX64FReplaceLane | LaneSizeField::encode(kL64) |
             VectorLengthField::encode(kV128),
         dst, g.UseRegister(node->InputAt(0)), g.UseImmediate(lane),
         g.UseRegister(node->InputAt(1)));
  }
}

#define VISIT_SIMD_REPLACE_LANE(TYPE, OPCODE)                                 \
  template <typename Adapter>                                                 \
  void InstructionSelectorT<Adapter>::Visit##TYPE##ReplaceLane(node_t node) { \
    X64OperandGeneratorT<Adapter> g(this);                                    \
    if constexpr (Adapter::IsTurboshaft) {                                    \
      const turboshaft::Simd128ReplaceLaneOp& op =                            \
          this->Get(node).template Cast<turboshaft::Simd128ReplaceLaneOp>();  \
      Emit(OPCODE, g.DefineAsRegister(node), g.UseRegister(op.into()),        \
           g.UseImmediate(op.lane), g.Use(op.new_lane()));                    \
    } else {                                                                  \
      int32_t lane = OpParameter<int32_t>(node->op());                        \
      Emit(OPCODE, g.DefineAsRegister(node), g.UseRegister(node->InputAt(0)), \
           g.UseImmediate(lane), g.Use(node->InputAt(1)));                    \
    }                                                                         \
  }

#define SIMD_TYPES_FOR_REPLACE_LANE(V) \
  V(I64x2, kX64Pinsrq)                 \
  V(I32x4, kX64Pinsrd)                 \
  V(I16x8, kX64Pinsrw)                 \
  V(I8x16, kX64Pinsrb)

SIMD_TYPES_FOR_REPLACE_LANE(VISIT_SIMD_REPLACE_LANE)
#undef SIMD_TYPES_FOR_REPLACE_LANE
#undef VISIT_SIMD_REPLACE_LANE

#define VISIT_SIMD_SHIFT_LANE_SIZE_VECTOR_LENGTH_OPCODES(                  \
    Name, Opcode, LaneSize, VectorLength)                                  \
  template <typename Adapter>                                              \
  void InstructionSelectorT<Adapter>::Visit##Name(node_t node) {           \
    X64OperandGeneratorT<Adapter> g(this);                                 \
    DCHECK_EQ(this->value_input_count(node), 2);                           \
    InstructionOperand dst = IsSupported(AVX) ? g.DefineAsRegister(node)   \
                                              : g.DefineSameAsFirst(node); \
    if (g.CanBeImmediate(this->input_at(node, 1))) {                       \
      Emit(kX64##Opcode | LaneSizeField::encode(LaneSize) |                \
               VectorLengthField::encode(VectorLength),                    \
           dst, g.UseRegister(this->input_at(node, 0)),                    \
           g.UseImmediate(this->input_at(node, 1)));                       \
    } else {                                                               \
      Emit(kX64##Opcode | LaneSizeField::encode(LaneSize) |                \
               VectorLengthField::encode(VectorLength),                    \
           dst, g.UseRegister(this->input_at(node, 0)),                    \
           g.UseRegister(this->input_at(node, 1)));                        \
    }                                                                      \
  }
SIMD_SHIFT_LANE_SIZE_VECTOR_LENGTH_OPCODES(
    VISIT_SIMD_SHIFT_LANE_SIZE_VECTOR_LENGTH_OPCODES)

#undef VISIT_SIMD_SHIFT_LANE_SIZE_VECTOR_LENGTH_OPCODES
#undef SIMD_SHIFT_LANE_SIZE_VECTOR_LENGTH_OPCODES

#define VISIT_SIMD_NARROW_SHIFT_LANE_SIZE_VECTOR_LENGTH_OPCODES(            \
    Name, Opcode, LaneSize, VectorLength)                                   \
  template <typename Adapter>                                               \
  void InstructionSelectorT<Adapter>::Visit##Name(node_t node) {            \
    X64OperandGeneratorT<Adapter> g(this);                                  \
    DCHECK_EQ(this->value_input_count(node), 2);                            \
    InstructionOperand output =                                             \
        IsSupported(AVX) ? g.UseRegister(node) : g.DefineSameAsFirst(node); \
    if (g.CanBeImmediate(this->input_at(node, 1))) {                        \
      Emit(kX64##Opcode | LaneSizeField::encode(LaneSize) |                 \
               VectorLengthField::encode(VectorLength),                     \
           output, g.UseRegister(this->input_at(node, 0)),                  \
           g.UseImmediate(this->input_at(node, 1)));                        \
    } else {                                                                \
      InstructionOperand temps[] = {g.TempSimd128Register()};               \
      Emit(kX64##Opcode | LaneSizeField::encode(LaneSize) |                 \
               VectorLengthField::encode(VectorLength),                     \
           output, g.UseUniqueRegister(this->input_at(node, 0)),            \
           g.UseUniqueRegister(this->input_at(node, 1)), arraysize(temps),  \
           temps);                                                          \
    }                                                                       \
  }
SIMD_NARROW_SHIFT_LANE_SIZE_VECTOR_LENGTH_OPCODES(
    VISIT_SIMD_NARROW_SHIFT_LANE_SIZE_VECTOR_LENGTH_OPCODES)
#undef VISIT_SIMD_NARROW_SHIFT_LANE_SIZE_VECTOR_LENGTH_OPCODES
#undef SIMD_NARROW_SHIFT_LANE_SIZE_VECTOR_LENGTH_OPCODES

#define VISIT_SIMD_UNOP(Opcode)                                    \
  template <typename Adapter>                                      \
  void InstructionSelectorT<Adapter>::Visit##Opcode(node_t node) { \
    X64OperandGeneratorT<Adapter> g(this);                         \
    DCHECK_EQ(this->value_input_count(node), 1);                   \
    Emit(kX64##Opcode, g.DefineAsRegister(node),                   \
         g.UseRegister(this->input_at(node, 0)));                  \
  }
SIMD_UNOP_LIST(VISIT_SIMD_UNOP)
#undef VISIT_SIMD_UNOP
#undef SIMD_UNOP_LIST

#define VISIT_SIMD_UNOP_LANE_SIZE_VECTOR_LENGTH(Name, Opcode, LaneSize,     \
                                                VectorLength)               \
  template <typename Adapter>                                               \
  void InstructionSelectorT<Adapter>::Visit##Name(node_t node) {            \
    X64OperandGeneratorT<Adapter> g(this);                                  \
    DCHECK_EQ(this->value_input_count(node), 1);                            \
    Emit(kX64##Opcode | LaneSizeField::encode(LaneSize) |                   \
             VectorLengthField::encode(VectorLength),                       \
         g.DefineAsRegister(node), g.UseRegister(this->input_at(node, 0))); \
  }

SIMD_UNOP_LANE_SIZE_VECTOR_LENGTH_LIST(VISIT_SIMD_UNOP_LANE_SIZE_VECTOR_LENGTH)

#undef VISIT_SIMD_UNOP_LANE_SIZE_VECTOR_LENGTH
#undef SIMD_UNOP_LANE_SIZE_VECTOR_LENGTH_LIST

#define VISIT_SIMD_BINOP_LANE_SIZE_VECTOR_LENGTH(Name, Opcode, LaneSize,    \
                                                 VectorLength)              \
  template <typename Adapter>                                               \
  void InstructionSelectorT<Adapter>::Visit##Name(node_t node) {            \
    X64OperandGeneratorT<Adapter> g(this);                                  \
    DCHECK_EQ(this->value_input_count(node), 2);                            \
    Emit(kX64##Opcode | LaneSizeField::encode(LaneSize) |                   \
             VectorLengthField::encode(VectorLength),                       \
         g.DefineSameAsFirst(node), g.UseRegister(this->input_at(node, 0)), \
         g.UseRegister(this->input_at(node, 1)));                           \
  }

SIMD_BINOP_LANE_SIZE_VECTOR_LENGTH_LIST(
    VISIT_SIMD_BINOP_LANE_SIZE_VECTOR_LENGTH)

#undef VISIT_SIMD_BINOP_LANE_SIZE_VECTOR_LENGTH
#undef SIMD_BINOP_LANE_SIZE_VECTOR_LENGTH_LIST

#define VISIT_SIMD_BINOP(Opcode)                                   \
  template <typename Adapter>                                      \
  void InstructionSelectorT<Adapter>::Visit##Opcode(node_t node) { \
    X64OperandGeneratorT<Adapter> g(this);                         \
    DCHECK_EQ(this->value_input_count(node), 2);                   \
    if (IsSupported(AVX)) {                                        \
      Emit(kX64##Opcode, g.DefineAsRegister(node),                 \
           g.UseRegister(this->input_at(node, 0)),                 \
           g.UseRegister(this->input_at(node, 1)));                \
    } else {                                                       \
      Emit(kX64##Opcode, g.DefineSameAsFirst(node),                \
           g.UseRegister(this->input_at(node, 0)),                 \
           g.UseRegister(this->input_at(node, 1)));                \
    }                                                              \
  }

SIMD_BINOP_SSE_AVX_LIST(VISIT_SIMD_BINOP)
#undef VISIT_SIMD_BINOP
#undef SIMD_BINOP_SSE_AVX_LIST

#define VISIT_SIMD_BINOP_LANE_SIZE_VECTOR_LENGTH(Name, Opcode, LaneSize,      \
                                                 VectorLength)                \
  template <typename Adapter>                                                 \
  void InstructionSelectorT<Adapter>::Visit##Name(node_t node) {              \
    X64OperandGeneratorT<Adapter> g(this);                                    \
    DCHECK_EQ(this->value_input_count(node), 2);                              \
    if (IsSupported(AVX)) {                                                   \
      Emit(kX64##Opcode | LaneSizeField::encode(LaneSize) |                   \
               VectorLengthField::encode(VectorLength),                       \
           g.DefineAsRegister(node), g.UseRegister(this->input_at(node, 0)),  \
           g.UseRegister(this->input_at(node, 1)));                           \
    } else {                                                                  \
      Emit(kX64##Opcode | LaneSizeField::encode(LaneSize) |                   \
               VectorLengthField::encode(VectorLength),                       \
           g.DefineSameAsFirst(node), g.UseRegister(this->input_at(node, 0)), \
           g.UseRegister(this->input_at(node, 1)));                           \
    }                                                                         \
  }

SIMD_BINOP_SSE_AVX_LANE_SIZE_VECTOR_LENGTH_LIST(
    VISIT_SIMD_BINOP_LANE_SIZE_VECTOR_LENGTH)
#undef VISIT_SIMD_BINOP_LANE_SIZE_VECTOR_LENGTH
#undef SIMD_BINOP_SSE_AVX_LANE_SIZE_VECTOR_LENGTH_LIST

#define VISIT_SIMD_F16x8_BINOP(Name, Opcode)                               \
  template <typename Adapter>                                              \
  void InstructionSelectorT<Adapter>::Visit##Name(node_t node) {           \
    X64OperandGeneratorT<Adapter> g(this);                                 \
    DCHECK_EQ(this->value_input_count(node), 2);                           \
    InstructionOperand temps[] = {g.TempSimd256Register(),                 \
                                  g.TempSimd256Register()};                \
    size_t temp_count = arraysize(temps);                                  \
    Emit(kX64##Opcode | LaneSizeField::encode(kL16) |                      \
             VectorLengthField::encode(kV128),                             \
         g.DefineAsRegister(node),                                         \
         g.UseUniqueRegister(this->input_at(node, 0)),                     \
         g.UseUniqueRegister(this->input_at(node, 1)), temp_count, temps); \
  }

SIMD_F16x8_BINOP_LIST(VISIT_SIMD_F16x8_BINOP)
#undef VISIT_SIMD_F16x8_BINOP
#undef SIMD_F16x8_BINOP_LIST

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitV128AnyTrue(node_t node) {
  X64OperandGeneratorT<Adapter> g(this);
  DCHECK_EQ(this->value_input_count(node), 1);
  Emit(kX64V128AnyTrue, g.DefineAsRegister(node),
       g.UseUniqueRegister(this->input_at(node, 0)));
}

namespace {

static bool IsV128ZeroConst(InstructionSelectorT<TurbofanAdapter>* selector,
                            Node* node) {
  if (node->opcode() == IrOpcode::kS128Zero) {
    return true;
  }
  // If the node is a V128 const, check all the elements
  auto m = V128ConstMatcher(node);
  if (m.HasResolvedValue()) {
    auto imms = m.ResolvedValue().immediate();
    return std::all_of(imms.begin(), imms.end(), [](auto i) { return i == 0; });
  }
  return false;
}

static bool IsV128ZeroConst(InstructionSelectorT<TurboshaftAdapter>* selector,
                            turboshaft::OpIndex node) {
  const turboshaft::Operation& op = selector->Get(node);
  if (auto constant = op.TryCast<turboshaft::Simd128ConstantOp>()) {
    return constant->IsZero();
  }
  return false;
}

static bool MatchSimd128Constant(
    InstructionSelectorT<TurbofanAdapter>* selector, Node* node,
    std::array<uint8_t, kSimd128Size>* constant) {
  DCHECK_NOT_NULL(constant);
  auto m = V128ConstMatcher(node);
  if (m.HasResolvedValue()) {
    // If the indices vector is a const, check if they are in range, or if the
    // top bit is set, then we can avoid th
"""


```