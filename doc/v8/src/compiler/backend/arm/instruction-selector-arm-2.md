Response: The user wants a summary of the C++ code provided. This is the third part of a four-part code snippet. The file is part of the V8 JavaScript engine and deals with instruction selection for the ARM architecture.

Therefore, the functionality likely revolves around selecting appropriate ARM instructions for higher-level operations represented in V8's intermediate representation.

Based on the code, this part seems to focus on:

1. **Control flow:** Handling `Switch` statements.
2. **Comparisons:** Generating instructions for equality and less-than comparisons for both signed and unsigned integers and floats.
3. **Arithmetic with overflow:**  Dealing with addition, subtraction, and multiplication where overflow needs to be detected.
4. **Floating-point operations:**  Inserting words into double-precision floats and bitcasting.
5. **Memory Barriers:** Implementing memory barriers for atomic operations.
6. **Atomic Operations:**  Handling various atomic load, store, exchange, compare-exchange, and binary operations on 32-bit words. It also covers pair-wise atomic operations.
7. **SIMD (Single Instruction, Multiple Data) operations:**  Implementing a wide range of SIMD instructions, particularly for WebAssembly. This includes unary operations, shifts, binary operations, splatting, lane extraction and replacement, shuffling, and other more specialized SIMD instructions.
8. **Stack pointer manipulation:**  Setting the stack pointer.
9. **Sign extension:**  Extending the sign of 8-bit and 16-bit words to 32 bits.
10. **Bitmask operations:** Creating bitmasks from SIMD vectors.
11. **Packed min/max operations:** Finding the minimum or maximum elements in SIMD vectors.
12. **Extended multiplication and addition:** Performing extended multiplication and pairwise addition on SIMD vectors.
13. **Type conversions:** Converting between different SIMD vector types and scalar types.
14. **Floating-point truncation:** Truncating floats to integers with different overflow handling strategies.

Considering this is part 3, it builds upon the foundational instruction selection logic likely present in the previous parts and delves into more complex and specialized operations.
这个C++源代码文件（`instruction-selector-arm.cc` 的第三部分）的主要功能是**为V8 JavaScript引擎在ARM架构上进行代码生成过程中的指令选择**。

具体来说，这部分代码负责将V8的中间表示（IR，Intermediate Representation）节点转换为相应的ARM机器指令。它涵盖了多种操作，包括：

1. **控制流语句的指令选择：**  如 `Switch` 语句，它会根据情况选择生成查找表跳转或者二分查找的条件跳转树。
2. **比较操作的指令选择：**  包括整数（有符号和无符号）和浮点数的相等、小于、小于等于等比较操作，并设置相应的标志位。
3. **带溢出检测的算术运算指令选择：**  如带溢出的加法、减法和乘法，能够检测并处理溢出情况。
4. **浮点数操作的指令选择：**  如向双精度浮点数中插入低位和高位字，以及浮点数的比较操作。
5. **位操作指令选择：**  例如将32位整数对转换为64位浮点数的位操作。
6. **内存屏障指令选择：**  用于确保内存操作的顺序性。
7. **原子操作指令选择：**  包括原子加载、原子存储、原子交换、原子比较并交换以及原子二进制运算（加、减、与、或、异或）。还包括原子对操作（加载、存储、加、减、与、或、异或、交换、比较并交换）。
8. **SIMD（单指令多数据流）指令选择：**  为WebAssembly的SIMD操作选择合适的ARM NEON指令，包括各种向量的绝对值、取反、平方根、类型转换、加法、减法、乘法、除法、最小值、最大值、比较、移位、逻辑运算、车道操作（提取和替换）、混洗（shuffle）等。
9. **设置栈指针的指令选择。**
10. **符号扩展指令选择：**  将8位和16位的有符号数扩展为32位。
11. **位掩码操作指令选择：**  用于生成SIMD向量的位掩码。
12. **浮点数的近似和精确的最小值和最大值指令选择。**
13. **扩展乘法指令选择。**
14. **成对加法指令选择。**
15. **浮点数截断为整数的指令选择：**  处理将浮点数截断为有符号和无符号32位整数的情况，并考虑溢出处理。

**与JavaScript功能的关系：**

这段代码是V8引擎的核心组成部分，直接影响JavaScript代码的执行效率。JavaScript中的各种操作，例如算术运算、比较、逻辑运算，特别是涉及到大量数据处理的场景（例如WebAssembly中的SIMD操作），都会最终由这里的指令选择逻辑转化为底层的ARM机器指令来执行。

**JavaScript示例：**

1. **比较操作：**

```javascript
let a = 10;
let b = 20;
if (a < b) { // 对应 VisitInt32LessThan
  console.log("a is less than b");
}
```

2. **带溢出检测的算术运算 (通常 JavaScript 不直接暴露溢出，但在 V8 内部需要处理):**

```javascript
// 虽然 JavaScript 的 Number 类型可以表示很大的整数，
// 但在某些内部操作或者优化的场景下，V8 可能会使用 32 位整数运算。
// 这部分代码处理了这些底层运算的溢出情况。
```

3. **SIMD 操作 (WebAssembly):**

```javascript
// WebAssembly 中使用 SIMD
const a = i32x4(1, 2, 3, 4);
const b = i32x4(5, 6, 7, 8);
const sum = a.add(b); // 对应各种 VisitI32x4Add 等 SIMD 指令选择
console.log(sum); // 输出 i32x4(6, 8, 10, 12)
```

4. **原子操作 (SharedArrayBuffer 和 Atomics):**

```javascript
const sab = new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT * 1);
const view = new Int32Array(sab);
Atomics.add(view, 0, 5); // 对应 VisitWord32AtomicAdd
console.log(view[0]); // 输出 5
```

**总结：**

这部分 `instruction-selector-arm.cc` 代码是V8引擎将JavaScript（特别是涉及到性能密集型操作和底层特性的WebAssembly）代码高效地转化为ARM机器码的关键环节。它根据不同的操作类型选择最优的ARM指令，从而保证JavaScript代码在ARM架构上的执行效率。

Prompt: 
```
这是目录为v8/src/compiler/backend/arm/instruction-selector-arm.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第3部分，共4部分，请归纳一下它的功能

"""
perand = g.UseRegister(value);
  EmitWithContinuation(opcode, value_operand, value_operand, cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitSwitch(node_t node,
                                                const SwitchInfo& sw) {
  ArmOperandGeneratorT<Adapter> g(this);
  InstructionOperand value_operand = g.UseRegister(this->input_at(node, 0));

  // Emit either ArchTableSwitch or ArchBinarySearchSwitch.
  if (enable_switch_jump_table_ ==
      InstructionSelector::kEnableSwitchJumpTable) {
    static const size_t kMaxTableSwitchValueRange = 2 << 16;
    size_t table_space_cost = 4 + sw.value_range();
    size_t table_time_cost = 3;
    size_t lookup_space_cost = 3 + 2 * sw.case_count();
    size_t lookup_time_cost = sw.case_count();
    if (sw.case_count() > 0 &&
        table_space_cost + 3 * table_time_cost <=
            lookup_space_cost + 3 * lookup_time_cost &&
        sw.min_value() > std::numeric_limits<int32_t>::min() &&
        sw.value_range() <= kMaxTableSwitchValueRange) {
      InstructionOperand index_operand = value_operand;
      if (sw.min_value()) {
        index_operand = g.TempRegister();
        Emit(kArmSub | AddressingModeField::encode(kMode_Operand2_I),
             index_operand, value_operand, g.TempImmediate(sw.min_value()));
      }
      // Generate a table lookup.
      return EmitTableSwitch(sw, index_operand);
    }
  }

  // Generate a tree of conditional jumps.
  return EmitBinarySearchSwitch(sw, value_operand);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Equal(node_t node) {
  FlagsContinuation cont = FlagsContinuation::ForSet(kEqual, node);
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const ComparisonOp& equal = this->Get(node).template Cast<ComparisonOp>();
    if (this->MatchIntegralZero(equal.right())) {
      return VisitWordCompareZero(node, equal.left(), &cont);
    }
  } else {
    Int32BinopMatcher m(node);
    if (m.right().Is(0)) {
      return VisitWordCompareZero(m.node(), m.left().node(), &cont);
    }
  }
  VisitWordCompare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32LessThan(node_t node) {
  FlagsContinuation cont = FlagsContinuation::ForSet(kSignedLessThan, node);
  VisitWordCompare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32LessThanOrEqual(node_t node) {
  FlagsContinuation cont =
      FlagsContinuation::ForSet(kSignedLessThanOrEqual, node);
  VisitWordCompare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUint32LessThan(node_t node) {
  FlagsContinuation cont = FlagsContinuation::ForSet(kUnsignedLessThan, node);
  VisitWordCompare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUint32LessThanOrEqual(node_t node) {
  FlagsContinuation cont =
      FlagsContinuation::ForSet(kUnsignedLessThanOrEqual, node);
  VisitWordCompare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32AddWithOverflow(node_t node) {
  node_t ovf = FindProjection(node, 1);
  if (this->valid(ovf)) {
    FlagsContinuation cont = FlagsContinuation::ForSet(kOverflow, ovf);
    return VisitBinop(this, node, kArmAdd, kArmAdd, &cont);
  }
  FlagsContinuation cont;
  VisitBinop(this, node, kArmAdd, kArmAdd, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32SubWithOverflow(node_t node) {
  node_t ovf = FindProjection(node, 1);
  if (this->valid(ovf)) {
    FlagsContinuation cont = FlagsContinuation::ForSet(kOverflow, ovf);
    return VisitBinop(this, node, kArmSub, kArmRsb, &cont);
  }
  FlagsContinuation cont;
  VisitBinop(this, node, kArmSub, kArmRsb, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32MulWithOverflow(node_t node) {
  node_t ovf = FindProjection(node, 1);
  if (this->valid(ovf)) {
    // ARM doesn't set the overflow flag for multiplication, so we need to
    // test on kNotEqual. Here is the code sequence used:
    //   smull resultlow, resulthigh, left, right
    //   cmp resulthigh, Operand(resultlow, ASR, 31)
    FlagsContinuation cont = FlagsContinuation::ForSet(kNotEqual, ovf);
    return EmitInt32MulWithOverflow(this, node, &cont);
  }
  FlagsContinuation cont;
  EmitInt32MulWithOverflow(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32Equal(node_t node) {
  FlagsContinuation cont = FlagsContinuation::ForSet(kEqual, node);
  VisitFloat32Compare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32LessThan(node_t node) {
  FlagsContinuation cont = FlagsContinuation::ForSet(kFloatLessThan, node);
  VisitFloat32Compare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32LessThanOrEqual(node_t node) {
  FlagsContinuation cont =
      FlagsContinuation::ForSet(kFloatLessThanOrEqual, node);
  VisitFloat32Compare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Equal(node_t node) {
  FlagsContinuation cont = FlagsContinuation::ForSet(kEqual, node);
  VisitFloat64Compare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64LessThan(node_t node) {
  FlagsContinuation cont = FlagsContinuation::ForSet(kFloatLessThan, node);
  VisitFloat64Compare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64LessThanOrEqual(node_t node) {
  FlagsContinuation cont =
      FlagsContinuation::ForSet(kFloatLessThanOrEqual, node);
  VisitFloat64Compare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64InsertLowWord32(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    UNIMPLEMENTED();
  } else {
    ArmOperandGeneratorT<Adapter> g(this);
    Node* left = node->InputAt(0);
    Node* right = node->InputAt(1);
    if (left->opcode() == IrOpcode::kFloat64InsertHighWord32 &&
        CanCover(node, left)) {
      left = left->InputAt(1);
      Emit(kArmVmovF64U32U32, g.DefineAsRegister(node), g.UseRegister(right),
           g.UseRegister(left));
      return;
    }
    Emit(kArmVmovLowF64U32, g.DefineSameAsFirst(node), g.UseRegister(left),
         g.UseRegister(right));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64InsertHighWord32(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    UNIMPLEMENTED();
  } else {
    ArmOperandGeneratorT<Adapter> g(this);
    Node* left = node->InputAt(0);
    Node* right = node->InputAt(1);
    if (left->opcode() == IrOpcode::kFloat64InsertLowWord32 &&
        CanCover(node, left)) {
      left = left->InputAt(1);
      Emit(kArmVmovF64U32U32, g.DefineAsRegister(node), g.UseRegister(left),
           g.UseRegister(right));
      return;
    }
    Emit(kArmVmovHighF64U32, g.DefineSameAsFirst(node), g.UseRegister(left),
         g.UseRegister(right));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitBitcastWord32PairToFloat64(
    node_t node) {
  if constexpr (Adapter::IsTurbofan) {
    // The Turbofan implementation is split across VisitFloat64InsertLowWord32
    // and VisitFloat64InsertHighWord32.
    UNREACHABLE();
  } else {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    ArmOperandGeneratorT<TurboshaftAdapter> g(this);
    const BitcastWord32PairToFloat64Op& cast_op =
        this->Get(node).template Cast<BitcastWord32PairToFloat64Op>();
    Emit(kArmVmovF64U32U32, g.DefineAsRegister(node),
         g.UseRegister(cast_op.low_word32()),
         g.UseRegister(cast_op.high_word32()));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitMemoryBarrier(node_t node) {
  // Use DMB ISH for both acquire-release and sequentially consistent barriers.
  ArmOperandGeneratorT<Adapter> g(this);
  Emit(kArmDmbIsh, g.NoOutput());
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicLoad(node_t node) {
  // The memory order is ignored as both acquire and sequentially consistent
  // loads can emit LDR; DMB ISH.
  // https://www.cl.cam.ac.uk/~pes20/cpp/cpp0xmappings.html
  ArmOperandGeneratorT<Adapter> g(this);
  auto load = this->load_view(node);
  node_t base = load.base();
  node_t index = load.index();
  ArchOpcode opcode;
  LoadRepresentation load_rep = load.loaded_rep();
  switch (load_rep.representation()) {
    case MachineRepresentation::kWord8:
      opcode = load_rep.IsSigned() ? kAtomicLoadInt8 : kAtomicLoadUint8;
      break;
    case MachineRepresentation::kWord16:
      opcode = load_rep.IsSigned() ? kAtomicLoadInt16 : kAtomicLoadUint16;
      break;
    case MachineRepresentation::kTaggedSigned:   // Fall through.
    case MachineRepresentation::kTaggedPointer:  // Fall through.
    case MachineRepresentation::kTagged:         // Fall through.
    case MachineRepresentation::kWord32:
      opcode = kAtomicLoadWord32;
      break;
    default:
      UNREACHABLE();
  }
  Emit(opcode | AddressingModeField::encode(kMode_Offset_RR),
       g.DefineAsRegister(node), g.UseRegister(base), g.UseRegister(index));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicStore(node_t node) {
  auto store = this->store_view(node);
  AtomicStoreParameters store_params(store.stored_rep().representation(),
                                     store.stored_rep().write_barrier_kind(),
                                     store.memory_order().value(),
                                     store.access_kind());
  VisitStoreCommon(this, node, store_params.store_representation(),
                   store_params.order());
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicExchange(node_t node) {
  ArmOperandGeneratorT<Adapter> g(this);
  auto atomic_op = this->atomic_rmw_view(node);
  ArchOpcode opcode;
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const AtomicRMWOp& atomic_op = this->Get(node).template Cast<AtomicRMWOp>();
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
  } else {
    MachineType type = AtomicOpType(node->op());
    if (type == MachineType::Int8()) {
      opcode = kAtomicExchangeInt8;
    } else if (type == MachineType::Uint8()) {
      opcode = kAtomicExchangeUint8;
    } else if (type == MachineType::Int16()) {
      opcode = kAtomicExchangeInt16;
    } else if (type == MachineType::Uint16()) {
      opcode = kAtomicExchangeUint16;
    } else if (type == MachineType::Int32() || type == MachineType::Uint32()) {
      opcode = kAtomicExchangeWord32;
    } else {
      UNREACHABLE();
    }
  }

  AddressingMode addressing_mode = kMode_Offset_RR;
  InstructionOperand inputs[3];
  size_t input_count = 0;
  inputs[input_count++] = g.UseRegister(atomic_op.base());
  inputs[input_count++] = g.UseRegister(atomic_op.index());
  inputs[input_count++] = g.UseUniqueRegister(atomic_op.value());
  InstructionOperand outputs[1];
  outputs[0] = g.DefineAsRegister(node);
  InstructionOperand temps[] = {g.TempRegister(), g.TempRegister()};
  InstructionCode code = opcode | AddressingModeField::encode(addressing_mode);
  Emit(code, 1, outputs, input_count, inputs, arraysize(temps), temps);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicCompareExchange(
    node_t node) {
  ArmOperandGeneratorT<Adapter> g(this);
  auto atomic_op = this->atomic_rmw_view(node);
  node_t base = atomic_op.base();
  node_t index = atomic_op.index();
  node_t old_value = atomic_op.expected();
  node_t new_value = atomic_op.value();
  ArchOpcode opcode;
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const AtomicRMWOp& atomic_op = this->Get(node).template Cast<AtomicRMWOp>();
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
  } else {
    MachineType type = AtomicOpType(node->op());
    if (type == MachineType::Int8()) {
      opcode = kAtomicCompareExchangeInt8;
    } else if (type == MachineType::Uint8()) {
      opcode = kAtomicCompareExchangeUint8;
    } else if (type == MachineType::Int16()) {
      opcode = kAtomicCompareExchangeInt16;
    } else if (type == MachineType::Uint16()) {
      opcode = kAtomicCompareExchangeUint16;
    } else if (type == MachineType::Int32() || type == MachineType::Uint32()) {
      opcode = kAtomicCompareExchangeWord32;
    } else {
      UNREACHABLE();
    }
  }

  AddressingMode addressing_mode = kMode_Offset_RR;
  InstructionOperand inputs[4];
  size_t input_count = 0;
  inputs[input_count++] = g.UseRegister(base);
  inputs[input_count++] = g.UseRegister(index);
  inputs[input_count++] = g.UseUniqueRegister(old_value);
  inputs[input_count++] = g.UseUniqueRegister(new_value);
  InstructionOperand outputs[1];
  outputs[0] = g.DefineAsRegister(node);
  InstructionOperand temps[] = {g.TempRegister(), g.TempRegister(),
                                g.TempRegister()};
  InstructionCode code = opcode | AddressingModeField::encode(addressing_mode);
  Emit(code, 1, outputs, input_count, inputs, arraysize(temps), temps);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicBinaryOperation(
    node_t node, ArchOpcode int8_op, ArchOpcode uint8_op, ArchOpcode int16_op,
    ArchOpcode uint16_op, ArchOpcode word32_op) {
  ArmOperandGeneratorT<Adapter> g(this);
  auto atomic_op = this->atomic_rmw_view(node);
  ArchOpcode opcode;
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const AtomicRMWOp& atomic_op = this->Get(node).template Cast<AtomicRMWOp>();
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
  } else {
    MachineType type = AtomicOpType(node->op());
    if (type == MachineType::Int8()) {
      opcode = int8_op;
    } else if (type == MachineType::Uint8()) {
      opcode = uint8_op;
    } else if (type == MachineType::Int16()) {
      opcode = int16_op;
    } else if (type == MachineType::Uint16()) {
      opcode = uint16_op;
    } else if (type == MachineType::Int32() || type == MachineType::Uint32()) {
      opcode = word32_op;
    } else {
      UNREACHABLE();
    }
  }

  AddressingMode addressing_mode = kMode_Offset_RR;
  InstructionOperand inputs[3];
  size_t input_count = 0;
  inputs[input_count++] = g.UseRegister(atomic_op.base());
  inputs[input_count++] = g.UseRegister(atomic_op.index());
  inputs[input_count++] = g.UseUniqueRegister(atomic_op.value());
  InstructionOperand outputs[1];
  outputs[0] = g.DefineAsRegister(node);
  InstructionOperand temps[] = {g.TempRegister(), g.TempRegister(),
                                g.TempRegister()};
  InstructionCode code = opcode | AddressingModeField::encode(addressing_mode);
  Emit(code, 1, outputs, input_count, inputs, arraysize(temps), temps);
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

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicPairLoad(node_t node) {
  ArmOperandGeneratorT<Adapter> g(this);
  node_t base = this->input_at(node, 0);
  node_t index = this->input_at(node, 1);
  InstructionOperand inputs[3];
  size_t input_count = 0;
  inputs[input_count++] = g.UseUniqueRegister(base);
  inputs[input_count++] = g.UseUniqueRegister(index);
  InstructionOperand temps[1];
  size_t temp_count = 0;
  InstructionOperand outputs[2];
  size_t output_count = 0;

  node_t projection0 = FindProjection(node, 0);
  node_t projection1 = FindProjection(node, 1);
  if (this->valid(projection0) && this->valid(projection1)) {
    outputs[output_count++] = g.DefineAsFixed(projection0, r0);
    outputs[output_count++] = g.DefineAsFixed(projection1, r1);
    temps[temp_count++] = g.TempRegister();
  } else if (this->valid(projection0)) {
    inputs[input_count++] = g.UseImmediate(0);
    outputs[output_count++] = g.DefineAsRegister(projection0);
  } else if (this->valid(projection1)) {
    inputs[input_count++] = g.UseImmediate(4);
    temps[temp_count++] = g.TempRegister();
    outputs[output_count++] = g.DefineAsRegister(projection1);
  } else {
    // There is no use of the loaded value, we don't need to generate code.
    return;
  }
  Emit(kArmWord32AtomicPairLoad, output_count, outputs, input_count, inputs,
       temp_count, temps);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicPairStore(node_t node) {
  ArmOperandGeneratorT<Adapter> g(this);
  auto store = this->word32_atomic_pair_store_view(node);
  AddressingMode addressing_mode = kMode_Offset_RR;
  InstructionOperand inputs[] = {
      g.UseUniqueRegister(store.base()), g.UseUniqueRegister(store.index()),
      g.UseFixed(store.value_low(), r2), g.UseFixed(store.value_high(), r3)};
  InstructionOperand temps[] = {g.TempRegister(), g.TempRegister(r0),
                                g.TempRegister(r1)};
  InstructionCode code =
      kArmWord32AtomicPairStore | AddressingModeField::encode(addressing_mode);
  Emit(code, 0, nullptr, arraysize(inputs), inputs, arraysize(temps), temps);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicPairAdd(node_t node) {
  VisitPairAtomicBinOp(this, node, kArmWord32AtomicPairAdd);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicPairSub(node_t node) {
  VisitPairAtomicBinOp(this, node, kArmWord32AtomicPairSub);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicPairAnd(node_t node) {
  VisitPairAtomicBinOp(this, node, kArmWord32AtomicPairAnd);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicPairOr(node_t node) {
  VisitPairAtomicBinOp(this, node, kArmWord32AtomicPairOr);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicPairXor(node_t node) {
  VisitPairAtomicBinOp(this, node, kArmWord32AtomicPairXor);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicPairExchange(node_t node) {
  ArmOperandGeneratorT<Adapter> g(this);
  node_t base = this->input_at(node, 0);
  node_t index = this->input_at(node, 1);
  node_t value = this->input_at(node, 2);
  node_t value_high = this->input_at(node, 3);
  AddressingMode addressing_mode = kMode_Offset_RR;
  InstructionOperand inputs[] = {
      g.UseFixed(value, r0), g.UseFixed(value_high, r1),
      g.UseUniqueRegister(base), g.UseUniqueRegister(index)};
  InstructionCode code = kArmWord32AtomicPairExchange |
                         AddressingModeField::encode(addressing_mode);
  node_t projection0 = FindProjection(node, 0);
  node_t projection1 = FindProjection(node, 1);
  InstructionOperand outputs[2];
  size_t output_count = 0;
  InstructionOperand temps[4];
  size_t temp_count = 0;
  temps[temp_count++] = g.TempRegister();
  temps[temp_count++] = g.TempRegister();
  if (this->valid(projection0)) {
    outputs[output_count++] = g.DefineAsFixed(projection0, r6);
  } else {
    temps[temp_count++] = g.TempRegister(r6);
  }
  if (this->valid(projection1)) {
    outputs[output_count++] = g.DefineAsFixed(projection1, r7);
  } else {
    temps[temp_count++] = g.TempRegister(r7);
  }
  Emit(code, output_count, outputs, arraysize(inputs), inputs, temp_count,
       temps);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicPairCompareExchange(
    node_t node) {
  ArmOperandGeneratorT<Adapter> g(this);
  AddressingMode addressing_mode = kMode_Offset_RR;

  // In the Turbofan and the Turboshaft graph the order of expected and value is
  // swapped.
  const size_t expected_offset = Adapter::IsTurboshaft ? 4 : 2;
  const size_t value_offset = Adapter::IsTurboshaft ? 2 : 4;
  InstructionOperand inputs[] = {
      g.UseFixed(this->input_at(node, expected_offset), r4),
      g.UseFixed(this->input_at(node, expected_offset + 1), r5),
      g.UseFixed(this->input_at(node, value_offset), r8),
      g.UseFixed(this->input_at(node, value_offset + 1), r9),
      g.UseUniqueRegister(this->input_at(node, 0)),
      g.UseUniqueRegister(this->input_at(node, 1))};
  InstructionCode code = kArmWord32AtomicPairCompareExchange |
                         AddressingModeField::encode(addressing_mode);
  node_t projection0 = FindProjection(node, 0);
  node_t projection1 = FindProjection(node, 1);
  InstructionOperand outputs[2];
  size_t output_count = 0;
  InstructionOperand temps[4];
  size_t temp_count = 0;
  temps[temp_count++] = g.TempRegister();
  temps[temp_count++] = g.TempRegister();
  if (this->valid(projection0)) {
    outputs[output_count++] = g.DefineAsFixed(projection0, r2);
  } else {
    temps[temp_count++] = g.TempRegister(r2);
  }
  if (this->valid(projection1)) {
    outputs[output_count++] = g.DefineAsFixed(projection1, r3);
  } else {
    temps[temp_count++] = g.TempRegister(r3);
  }
  Emit(code, output_count, outputs, arraysize(inputs), inputs, temp_count,
       temps);
}

#define SIMD_UNOP_LIST(V)                               \
  V(F64x2Abs, kArmF64x2Abs)                             \
  V(F64x2Neg, kArmF64x2Neg)                             \
  V(F64x2Sqrt, kArmF64x2Sqrt)                           \
  V(F32x4SConvertI32x4, kArmF32x4SConvertI32x4)         \
  V(F32x4UConvertI32x4, kArmF32x4UConvertI32x4)         \
  V(F32x4Abs, kArmF32x4Abs)                             \
  V(F32x4Neg, kArmF32x4Neg)                             \
  V(I64x2Abs, kArmI64x2Abs)                             \
  V(I64x2SConvertI32x4Low, kArmI64x2SConvertI32x4Low)   \
  V(I64x2SConvertI32x4High, kArmI64x2SConvertI32x4High) \
  V(I64x2UConvertI32x4Low, kArmI64x2UConvertI32x4Low)   \
  V(I64x2UConvertI32x4High, kArmI64x2UConvertI32x4High) \
  V(I32x4SConvertF32x4, kArmI32x4SConvertF32x4)         \
  V(I32x4RelaxedTruncF32x4S, kArmI32x4SConvertF32x4)    \
  V(I32x4SConvertI16x8Low, kArmI32x4SConvertI16x8Low)   \
  V(I32x4SConvertI16x8High, kArmI32x4SConvertI16x8High) \
  V(I32x4Neg, kArmI32x4Neg)                             \
  V(I32x4UConvertF32x4, kArmI32x4UConvertF32x4)         \
  V(I32x4RelaxedTruncF32x4U, kArmI32x4UConvertF32x4)    \
  V(I32x4UConvertI16x8Low, kArmI32x4UConvertI16x8Low)   \
  V(I32x4UConvertI16x8High, kArmI32x4UConvertI16x8High) \
  V(I32x4Abs, kArmI32x4Abs)                             \
  V(I16x8SConvertI8x16Low, kArmI16x8SConvertI8x16Low)   \
  V(I16x8SConvertI8x16High, kArmI16x8SConvertI8x16High) \
  V(I16x8Neg, kArmI16x8Neg)                             \
  V(I16x8UConvertI8x16Low, kArmI16x8UConvertI8x16Low)   \
  V(I16x8UConvertI8x16High, kArmI16x8UConvertI8x16High) \
  V(I16x8Abs, kArmI16x8Abs)                             \
  V(I8x16Neg, kArmI8x16Neg)                             \
  V(I8x16Abs, kArmI8x16Abs)                             \
  V(I8x16Popcnt, kArmVcnt)                              \
  V(S128Not, kArmS128Not)                               \
  V(I64x2AllTrue, kArmI64x2AllTrue)                     \
  V(I32x4AllTrue, kArmI32x4AllTrue)                     \
  V(I16x8AllTrue, kArmI16x8AllTrue)                     \
  V(V128AnyTrue, kArmV128AnyTrue)                       \
  V(I8x16AllTrue, kArmI8x16AllTrue)

#define SIMD_SHIFT_OP_LIST(V) \
  V(I64x2Shl, 64)             \
  V(I64x2ShrS, 64)            \
  V(I64x2ShrU, 64)            \
  V(I32x4Shl, 32)             \
  V(I32x4ShrS, 32)            \
  V(I32x4ShrU, 32)            \
  V(I16x8Shl, 16)             \
  V(I16x8ShrS, 16)            \
  V(I16x8ShrU, 16)            \
  V(I8x16Shl, 8)              \
  V(I8x16ShrS, 8)             \
  V(I8x16ShrU, 8)

#define SIMD_BINOP_LIST(V)                            \
  V(F64x2Add, kArmF64x2Add)                           \
  V(F64x2Sub, kArmF64x2Sub)                           \
  V(F64x2Mul, kArmF64x2Mul)                           \
  V(F64x2Div, kArmF64x2Div)                           \
  V(F64x2Min, kArmF64x2Min)                           \
  V(F64x2Max, kArmF64x2Max)                           \
  V(F64x2Eq, kArmF64x2Eq)                             \
  V(F64x2Ne, kArmF64x2Ne)                             \
  V(F64x2Lt, kArmF64x2Lt)                             \
  V(F64x2Le, kArmF64x2Le)                             \
  V(F32x4Add, kArmF32x4Add)                           \
  V(F32x4Sub, kArmF32x4Sub)                           \
  V(F32x4Mul, kArmF32x4Mul)                           \
  V(F32x4Min, kArmF32x4Min)                           \
  V(F32x4RelaxedMin, kArmF32x4Min)                    \
  V(F32x4Max, kArmF32x4Max)                           \
  V(F32x4RelaxedMax, kArmF32x4Max)                    \
  V(F32x4Eq, kArmF32x4Eq)                             \
  V(F32x4Ne, kArmF32x4Ne)                             \
  V(F32x4Lt, kArmF32x4Lt)                             \
  V(F32x4Le, kArmF32x4Le)                             \
  V(I64x2Add, kArmI64x2Add)                           \
  V(I64x2Sub, kArmI64x2Sub)                           \
  V(I32x4Sub, kArmI32x4Sub)                           \
  V(I32x4Mul, kArmI32x4Mul)                           \
  V(I32x4MinS, kArmI32x4MinS)                         \
  V(I32x4MaxS, kArmI32x4MaxS)                         \
  V(I32x4Eq, kArmI32x4Eq)                             \
  V(I64x2Eq, kArmI64x2Eq)                             \
  V(I64x2Ne, kArmI64x2Ne)                             \
  V(I64x2GtS, kArmI64x2GtS)                           \
  V(I64x2GeS, kArmI64x2GeS)                           \
  V(I32x4Ne, kArmI32x4Ne)                             \
  V(I32x4GtS, kArmI32x4GtS)                           \
  V(I32x4GeS, kArmI32x4GeS)                           \
  V(I32x4MinU, kArmI32x4MinU)                         \
  V(I32x4MaxU, kArmI32x4MaxU)                         \
  V(I32x4GtU, kArmI32x4GtU)                           \
  V(I32x4GeU, kArmI32x4GeU)                           \
  V(I16x8SConvertI32x4, kArmI16x8SConvertI32x4)       \
  V(I16x8AddSatS, kArmI16x8AddSatS)                   \
  V(I16x8Sub, kArmI16x8Sub)                           \
  V(I16x8SubSatS, kArmI16x8SubSatS)                   \
  V(I16x8Mul, kArmI16x8Mul)                           \
  V(I16x8MinS, kArmI16x8MinS)                         \
  V(I16x8MaxS, kArmI16x8MaxS)                         \
  V(I16x8Eq, kArmI16x8Eq)                             \
  V(I16x8Ne, kArmI16x8Ne)                             \
  V(I16x8GtS, kArmI16x8GtS)                           \
  V(I16x8GeS, kArmI16x8GeS)                           \
  V(I16x8UConvertI32x4, kArmI16x8UConvertI32x4)       \
  V(I16x8AddSatU, kArmI16x8AddSatU)                   \
  V(I16x8SubSatU, kArmI16x8SubSatU)                   \
  V(I16x8MinU, kArmI16x8MinU)                         \
  V(I16x8MaxU, kArmI16x8MaxU)                         \
  V(I16x8GtU, kArmI16x8GtU)                           \
  V(I16x8GeU, kArmI16x8GeU)                           \
  V(I16x8RoundingAverageU, kArmI16x8RoundingAverageU) \
  V(I16x8Q15MulRSatS, kArmI16x8Q15MulRSatS)           \
  V(I16x8RelaxedQ15MulRS, kArmI16x8Q15MulRSatS)       \
  V(I8x16SConvertI16x8, kArmI8x16SConvertI16x8)       \
  V(I8x16Add, kArmI8x16Add)                           \
  V(I8x16AddSatS, kArmI8x16AddSatS)                   \
  V(I8x16Sub, kArmI8x16Sub)                           \
  V(I8x16SubSatS, kArmI8x16SubSatS)                   \
  V(I8x16MinS, kArmI8x16MinS)                         \
  V(I8x16MaxS, kArmI8x16MaxS)                         \
  V(I8x16Eq, kArmI8x16Eq)                             \
  V(I8x16Ne, kArmI8x16Ne)                             \
  V(I8x16GtS, kArmI8x16GtS)                           \
  V(I8x16GeS, kArmI8x16GeS)                           \
  V(I8x16UConvertI16x8, kArmI8x16UConvertI16x8)       \
  V(I8x16AddSatU, kArmI8x16AddSatU)                   \
  V(I8x16SubSatU, kArmI8x16SubSatU)                   \
  V(I8x16MinU, kArmI8x16MinU)                         \
  V(I8x16MaxU, kArmI8x16MaxU)                         \
  V(I8x16GtU, kArmI8x16GtU)                           \
  V(I8x16GeU, kArmI8x16GeU)                           \
  V(I8x16RoundingAverageU, kArmI8x16RoundingAverageU) \
  V(S128And, kArmS128And)                             \
  V(S128Or, kArmS128Or)                               \
  V(S128Xor, kArmS128Xor)                             \
  V(S128AndNot, kArmS128AndNot)

#if V8_ENABLE_WEBASSEMBLY
template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI32x4DotI16x8S(node_t node) {
  ArmOperandGeneratorT<Adapter> g(this);
  Emit(kArmI32x4DotI16x8S, g.DefineAsRegister(node),
       g.UseUniqueRegister(this->input_at(node, 0)),
       g.UseUniqueRegister(this->input_at(node, 1)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI16x8DotI8x16I7x16S(node_t node) {
  ArmOperandGeneratorT<Adapter> g(this);
  Emit(kArmI16x8DotI8x16S, g.DefineAsRegister(node),
       g.UseUniqueRegister(this->input_at(node, 0)),
       g.UseUniqueRegister(this->input_at(node, 1)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI32x4DotI8x16I7x16AddS(node_t node) {
  ArmOperandGeneratorT<Adapter> g(this);
  InstructionOperand temps[] = {g.TempSimd128Register()};
  Emit(kArmI32x4DotI8x16AddS, g.DefineSameAsInput(node, 2),
       g.UseUniqueRegister(this->input_at(node, 0)),
       g.UseUniqueRegister(this->input_at(node, 1)),
       g.UseUniqueRegister(this->input_at(node, 2)), arraysize(temps), temps);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitS128Const(node_t node) {
  ArmOperandGeneratorT<Adapter> g(this);
  uint32_t val[kSimd128Size / sizeof(uint32_t)];
  if constexpr (Adapter::IsTurboshaft) {
    const turboshaft::Simd128ConstantOp& constant =
        this->Get(node).template Cast<turboshaft::Simd128ConstantOp>();
    memcpy(val, constant.value, kSimd128Size);
  } else {
    memcpy(val, S128ImmediateParameterOf(node->op()).data(), kSimd128Size);
  }
  // If all bytes are zeros, avoid emitting code for generic constants.
  bool all_zeros = !(val[0] || val[1] || val[2] || val[3]);
  bool all_ones = val[0] == UINT32_MAX && val[1] == UINT32_MAX &&
                  val[2] == UINT32_MAX && val[3] == UINT32_MAX;
  InstructionOperand dst = g.DefineAsRegister(node);
  if (all_zeros) {
    Emit(kArmS128Zero, dst);
  } else if (all_ones) {
    Emit(kArmS128AllOnes, dst);
  } else {
    Emit(kArmS128Const, dst, g.UseImmediate(val[0]), g.UseImmediate(val[1]),
         g.UseImmediate(val[2]), g.UseImmediate(val[3]));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitS128Zero(node_t node) {
  ArmOperandGeneratorT<Adapter> g(this);
  Emit(kArmS128Zero, g.DefineAsRegister(node));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF64x2Splat(node_t node) {
  VisitRR(this, kArmF64x2Splat, node);
}
template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF32x4Splat(node_t node) {
  VisitRR(this, kArmF32x4Splat, node);
}
template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF16x8Splat(node_t node) {
  UNIMPLEMENTED();
}
template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI32x4Splat(node_t node) {
  VisitRR(this, kArmI32x4Splat, node);
}
template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI16x8Splat(node_t node) {
  VisitRR(this, kArmI16x8Splat, node);
}
#endif  // V8_ENABLE_WEBASSEMBLY

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI8x16Splat(node_t node) {
  VisitRR(this, kArmI8x16Splat, node);
}

#if V8_ENABLE_WEBASSEMBLY
#define SIMD_VISIT_EXTRACT_LANE(Type, Sign)                           \
  template <typename Adapter>                                         \
  void InstructionSelectorT<Adapter>::Visit##Type##ExtractLane##Sign( \
      node_t node) {                                                  \
    VisitRRI(this, kArm##Type##ExtractLane##Sign, node);              \
  }
SIMD_VISIT_EXTRACT_LANE(F64x2, )
SIMD_VISIT_EXTRACT_LANE(F32x4, )
SIMD_VISIT_EXTRACT_LANE(I32x4, )
SIMD_VISIT_EXTRACT_LANE(I16x8, U)
SIMD_VISIT_EXTRACT_LANE(I16x8, S)
SIMD_VISIT_EXTRACT_LANE(I8x16, U)
SIMD_VISIT_EXTRACT_LANE(I8x16, S)
#undef SIMD_VISIT_EXTRACT_LANE

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF16x8ExtractLane(node_t node) {
  UNIMPLEMENTED();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF64x2ReplaceLane(node_t node) {
  VisitRRIR(this, kArmF64x2ReplaceLane, node);
}
template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF32x4ReplaceLane(node_t node) {
  VisitRRIR(this, kArmF32x4ReplaceLane, node);
}
template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF16x8ReplaceLane(node_t node) {
  UNIMPLEMENTED();
}
template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI32x4ReplaceLane(node_t node) {
  VisitRRIR(this, kArmI32x4ReplaceLane, node);
}
template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI16x8ReplaceLane(node_t node) {
  VisitRRIR(this, kArmI16x8ReplaceLane, node);
}
template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI8x16ReplaceLane(node_t node) {
  VisitRRIR(this, kArmI8x16ReplaceLane, node);
}

#define SIMD_VISIT_UNOP(Name, instruction)                       \
  template <typename Adapter>                                    \
  void InstructionSelectorT<Adapter>::Visit##Name(node_t node) { \
    VisitRR(this, instruction, node);                            \
  }
SIMD_UNOP_LIST(SIMD_VISIT_UNOP)
#undef SIMD_VISIT_UNOP
#undef SIMD_UNOP_LIST

#define UNIMPLEMENTED_SIMD_UNOP_LIST(V) \
  V(F16x8Abs)                           \
  V(F16x8Neg)                           \
  V(F16x8Sqrt)                          \
  V(F16x8Floor)                         \
  V(F16x8Ceil)                          \
  V(F16x8Trunc)                         \
  V(F16x8NearestInt)

#define SIMD_VISIT_UNIMPL_UNOP(Name)                             \
  template <typename Adapter>                                    \
  void InstructionSelectorT<Adapter>::Visit##Name(node_t node) { \
    UNIMPLEMENTED();                                             \
  }

UNIMPLEMENTED_SIMD_UNOP_LIST(SIMD_VISIT_UNIMPL_UNOP)
#undef SIMD_VISIT_UNIMPL_UNOP
#undef UNIMPLEMENTED_SIMD_UNOP_LIST

#define UNIMPLEMENTED_SIMD_CVTOP_LIST(V) \
  V(F16x8SConvertI16x8)                  \
  V(F16x8UConvertI16x8)                  \
  V(I16x8SConvertF16x8)                  \
  V(I16x8UConvertF16x8)                  \
  V(F32x4PromoteLowF16x8)                \
  V(F16x8DemoteF32x4Zero)                \
  V(F16x8DemoteF64x2Zero)

#define SIMD_VISIT_UNIMPL_CVTOP(Name)                            \
  template <typename Adapter>                                    \
  void InstructionSelectorT<Adapter>::Visit##Name(node_t node) { \
    UNIMPLEMENTED();                                             \
  }

UNIMPLEMENTED_SIMD_CVTOP_LIST(SIMD_VISIT_UNIMPL_CVTOP)
#undef SIMD_VISIT_UNIMPL_CVTOP
#undef UNIMPLEMENTED_SIMD_CVTOP_LIST

#define SIMD_VISIT_SHIFT_OP(Name, width)                         \
  template <typename Adapter>                                    \
  void InstructionSelectorT<Adapter>::Visit##Name(node_t node) { \
    VisitSimdShiftRRR(this, kArm##Name, node, width);            \
  }
SIMD_SHIFT_OP_LIST(SIMD_VISIT_SHIFT_OP)
#undef SIMD_VISIT_SHIFT_OP
#undef SIMD_SHIFT_OP_LIST

#define SIMD_VISIT_BINOP(Name, instruction)                      \
  template <typename Adapter>                                    \
  void InstructionSelectorT<Adapter>::Visit##Name(node_t node) { \
    VisitRRR(this, instruction, node);                           \
  }
SIMD_BINOP_LIST(SIMD_VISIT_BINOP)
#undef SIMD_VISIT_BINOP
#undef SIMD_BINOP_LIST

#define UNIMPLEMENTED_SIMD_BINOP_LIST(V) \
  V(F16x8Add)                            \
  V(F16x8Sub)                            \
  V(F16x8Mul)                            \
  V(F16x8Div)                            \
  V(F16x8Min)                            \
  V(F16x8Max)                            \
  V(F16x8Pmin)                           \
  V(F16x8Pmax)                           \
  V(F16x8Eq)                             \
  V(F16x8Ne)                             \
  V(F16x8Lt)                             \
  V(F16x8Le)

#define SIMD_VISIT_UNIMPL_BINOP(Name)                            \
  template <typename Adapter>                                    \
  void InstructionSelectorT<Adapter>::Visit##Name(node_t node) { \
    UNIMPLEMENTED();                                             \
  }

UNIMPLEMENTED_SIMD_BINOP_LIST(SIMD_VISIT_UNIMPL_BINOP)
#undef SIMD_VISIT_UNIMPL_BINOP
#undef UNIMPLEMENTED_SIMD_BINOP_LIST

// TODO(mliedtke): This macro has only two uses. Maybe this could be refactored
// into some helpers instead of the huge macro.
#define VISIT_SIMD_ADD(Type, PairwiseType, NeonWidth)                          \
  template <>                                                                  \
  void InstructionSelectorT<TurboshaftAdapter>::Visit##Type##Add(              \
      node_t node) {                                                           \
    using namespace turboshaft; /*NOLINT(build/namespaces)*/                   \
    ArmOperandGeneratorT<TurboshaftAdapter> g(this);                           \
    const Simd128BinopOp& add_op = Get(node).Cast<Simd128BinopOp>();           \
    const Operation& left = Get(add_op.left());                                \
    const Operation& right = Get(add_op.right());                              \
    if (left.Is<Opmask::kSimd128##Type##ExtAddPairwise##PairwiseType##S>() &&  \
        CanCover(node, add_op.left())) {                                       \
      Emit(kArmVpadal | MiscField::encode(NeonS##NeonWidth),                   \
           g.DefineSameAsFirst(node), g.UseRegister(add_op.right()),           \
           g.UseRegister(left.input(0)));                                      \
      return;                                                                  \
    }                                                                          \
    if (left.Is<Opmask::kSimd128##Type##ExtAddPairwise##PairwiseType##U>() &&  \
        CanCover(node, add_op.left())) {                                       \
      Emit(kArmVpadal | MiscField::encode(NeonU##NeonWidth),                   \
           g.DefineSameAsFirst(node), g.UseRegister(add_op.right()),           \
           g.UseRegister(left.input(0)));                                      \
      return;                                                                  \
    }                                                                          \
    if (right.Is<Opmask::kSimd128##Type##ExtAddPairwise##PairwiseType##S>() && \
        CanCover(node, add_op.right())) {                                      \
      Emit(kArmVpadal | MiscField::encode(NeonS##NeonWidth),                   \
           g.DefineSameAsFirst(node), g.UseRegister(add_op.left()),            \
           g.UseRegister(right.input(0)));                                     \
      return;                                                                  \
    }                                                                          \
    if (right.Is<Opmask::kSimd128##Type##ExtAddPairwise##PairwiseType##U>() && \
        CanCover(node, add_op.right())) {                                      \
      Emit(kArmVpadal | MiscField::encode(NeonU##NeonWidth),                   \
           g.DefineSameAsFirst(node), g.UseRegister(add_op.left()),            \
           g.UseRegister(right.input(0)));                                     \
      return;                                                                  \
    }                                                                          \
    VisitRRR(this, kArm##Type##Add, node);                                     \
  }                                                                            \
  template <>                                                                  \
  void InstructionSelectorT<TurbofanAdapter>::Visit##Type##Add(Node* node) {   \
    ArmOperandGeneratorT<TurbofanAdapter> g(this);                             \
    Node* left = node->InputAt(0);                                             \
    Node* right = node->InputAt(1);                                            \
    if (left->opcode() ==                                                      \
            IrOpcode::k##Type##ExtAddPairwise##PairwiseType##S &&              \
        CanCover(node, left)) {                                                \
      Emit(kArmVpadal | MiscField::encode(NeonS##NeonWidth),                   \
           g.DefineSameAsFirst(node), g.UseRegister(right),                    \
           g.UseRegister(left->InputAt(0)));                                   \
      return;                                                                  \
    }                                                                          \
    if (left->opcode() ==                                                      \
            IrOpcode::k##Type##ExtAddPairwise##PairwiseType##U &&              \
        CanCover(node, left)) {                                                \
      Emit(kArmVpadal | MiscField::encode(NeonU##NeonWidth),                   \
           g.DefineSameAsFirst(node), g.UseRegister(right),                    \
           g.UseRegister(left->InputAt(0)));                                   \
      return;                                                                  \
    }                                                                          \
    if (right->opcode() ==                                                     \
            IrOpcode::k##Type##ExtAddPairwise##PairwiseType##S &&              \
        CanCover(node, right)) {                                               \
      Emit(kArmVpadal | MiscField::encode(NeonS##NeonWidth),                   \
           g.DefineSameAsFirst(node), g.UseRegister(left),                     \
           g.UseRegister(right->InputAt(0)));                                  \
      return;                                                                  \
    }                                                                          \
    if (right->opcode() ==                                                     \
            IrOpcode::k##Type##ExtAddPairwise##PairwiseType##U &&              \
        CanCover(node, right)) {                                               \
      Emit(kArmVpadal | MiscField::encode(NeonU##NeonWidth),                   \
           g.DefineSameAsFirst(node), g.UseRegister(left),                     \
           g.UseRegister(right->InputAt(0)));                                  \
      return;                                                                  \
    }                                                                          \
    VisitRRR(this, kArm##Type##Add, node);                                     \
  }

VISIT_SIMD_ADD(I16x8, I8x16, 8)
VISIT_SIMD_ADD(I32x4, I16x8, 16)
#undef VISIT_SIMD_ADD

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI64x2SplatI32Pair(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    // In turboshaft it gets lowered to an I32x4Splat.
    UNREACHABLE();
  } else {
    ArmOperandGeneratorT<Adapter> g(this);
    InstructionOperand operand0 = g.UseRegister(node->InputAt(0));
    InstructionOperand operand1 = g.UseRegister(node->InputAt(1));
    Emit(kArmI64x2SplatI32Pair, g.DefineAsRegister(node), operand0, operand1);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI64x2ReplaceLaneI32Pair(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    // In turboshaft it gets lowered to an I32x4ReplaceLane.
    UNREACHABLE();
  } else {
    ArmOperandGeneratorT<Adapter> g(this);
    InstructionOperand operand = g.UseRegister(node->InputAt(0));
    InstructionOperand lane = g.UseImmediate(OpParameter<int32_t>(node->op()));
    InstructionOperand low = g.UseRegister(node->InputAt(1));
    InstructionOperand high = g.UseRegister(node->InputAt(2));
    Emit(kArmI64x2ReplaceLaneI32Pair, g.DefineSameAsFirst(node), operand, lane,
         low, high);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI64x2Neg(node_t node) {
    ArmOperandGeneratorT<Adapter> g(this);
    Emit(kArmI64x2Neg, g.DefineAsRegister(node),
         g.UseUniqueRegister(this->input_at(node, 0)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI64x2Mul(node_t node) {
    ArmOperandGeneratorT<Adapter> g(this);
    InstructionOperand temps[] = {g.TempSimd128Register()};
    Emit(kArmI64x2Mul, g.DefineAsRegister(node),
         g.UseUniqueRegister(this->input_at(node, 0)),
         g.UseUniqueRegister(this->input_at(node, 1)), arraysize(temps), temps);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF32x4Sqrt(node_t node) {
  ArmOperandGeneratorT<Adapter> g(this);
  // Use fixed registers in the lower 8 Q-registers so we can directly access
  // mapped registers S0-S31.
  Emit(kArmF32x4Sqrt, g.DefineAsFixed(node, q0),
       g.UseFixed(this->input_at(node, 0), q0));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF32x4Div(node_t node) {
  ArmOperandGeneratorT<Adapter> g(this);
  // Use fixed registers in the lower 8 Q-registers so we can directly access
  // mapped registers S0-S31.
  Emit(kArmF32x4Div, g.DefineAsFixed(node, q0),
       g.UseFixed(this->input_at(node, 0), q0),
       g.UseFixed(this->input_at(node, 1), q1));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitS128Select(node_t node) {
  ArmOperandGeneratorT<Adapter> g(this);
  Emit(kArmS128Select, g.DefineSameAsFirst(node),
       g.UseRegister(this->input_at(node, 0)),
       g.UseRegister(this->input_at(node, 1)),
       g.UseRegister(this->input_at(node, 2)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI8x16RelaxedLaneSelect(node_t node) {
  VisitS128Select(node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI16x8RelaxedLaneSelect(node_t node) {
  VisitS128Select(node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI32x4RelaxedLaneSelect(node_t node) {
  VisitS128Select(node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI64x2RelaxedLaneSelect(node_t node) {
  VisitS128Select(node);
}

#define VISIT_SIMD_QFMOP(op)                                   \
  template <typename Adapter>                                  \
  void InstructionSelectorT<Adapter>::Visit##op(node_t node) { \
    ArmOperandGeneratorT<Adapter> g(this);                     \
    Emit(kArm##op, g.DefineAsRegister(node),                   \
         g.UseUniqueRegister(this->input_at(node, 0)),         \
         g.UseUniqueRegister(this->input_at(node, 1)),         \
         g.UseUniqueRegister(this->input_at(node, 2)));        \
  }
VISIT_SIMD_QFMOP(F64x2Qfma)
VISIT_SIMD_QFMOP(F64x2Qfms)
VISIT_SIMD_QFMOP(F32x4Qfma)
VISIT_SIMD_QFMOP(F32x4Qfms)
#undef VISIT_SIMD_QFMOP

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF16x8Qfma(node_t node) {
  UNIMPLEMENTED();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF16x8Qfms(node_t node) {
  UNIMPLEMENTED();
}
namespace {

struct ShuffleEntry {
  uint8_t shuffle[kSimd128Size];
  ArchOpcode opcode;
};

static const ShuffleEntry arch_shuffles[] = {
    {{0, 1, 2, 3, 16, 17, 18, 19, 4, 5, 6, 7, 20, 21, 22, 23},
     kArmS32x4ZipLeft},
    {{8, 9, 10, 11, 24, 25, 26, 27, 12, 13, 14, 15, 28, 29, 30, 31},
     kArmS32x4ZipRight},
    {{0, 1, 2, 3, 8, 9, 10, 11, 16, 17, 18, 19, 24, 25, 26, 27},
     kArmS32x4UnzipLeft},
    {{4, 5, 6, 7, 12, 13, 14, 15, 20, 21, 22, 23, 28, 29, 30, 31},
     kArmS32x4UnzipRight},
    {{0, 1, 2, 3, 16, 17, 18, 19, 8, 9, 10, 11, 24, 25, 26, 27},
     kArmS32x4TransposeLeft},
    {{4, 5, 6, 7, 20, 21, 22, 23, 12, 13, 14, 15, 28, 29, 30, 31},
     kArmS32x4TransposeRight},
    {{4, 5, 6, 7, 0, 1, 2, 3, 12, 13, 14, 15, 8, 9, 10, 11}, kArmS32x2Reverse},

    {{0, 1, 16, 17, 2, 3, 18, 19, 4, 5, 20, 21, 6, 7, 22, 23},
     kArmS16x8ZipLeft},
    {{8, 9, 24, 25, 10, 11, 26, 27, 12, 13, 28, 29, 14, 15, 30, 31},
     kArmS16x8ZipRight},
    {{0, 1, 4, 5, 8, 9, 12, 13, 16, 17, 20, 21, 24, 25, 28, 29},
     kArmS16x8UnzipLeft},
    {{2, 3, 6, 7, 10, 11, 14, 15, 18, 19, 22, 23, 26, 27, 30, 31},
     kArmS16x8UnzipRight},
    {{0, 1, 16, 17, 4, 5, 20, 21, 8, 9, 24, 25, 12, 13, 28, 29},
     kArmS16x8TransposeLeft},
    {{2, 3, 18, 19, 6, 7, 22, 23, 10, 11, 26, 27, 14, 15, 30, 31},
     kArmS16x8TransposeRight},
    {{6, 7, 4, 5, 2, 3, 0, 1, 14, 15, 12, 13, 10, 11, 8, 9}, kArmS16x4Reverse},
    {{2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13}, kArmS16x2Reverse},

    {{0, 16, 1, 17, 2, 18, 3, 19, 4, 20, 5, 21, 6, 22, 7, 23},
     kArmS8x16ZipLeft},
    {{8, 24, 9, 25, 10, 26, 11, 27, 12, 28, 13, 29, 14, 30, 15, 31},
     kArmS8x16ZipRight},
    {{0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30},
     kArmS8x16UnzipLeft},
    {{1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23, 25, 27, 29, 31},
     kArmS8x16UnzipRight},
    {{0, 16, 2, 18, 4, 20, 6, 22, 8, 24, 10, 26, 12, 28, 14, 30},
     kArmS8x16TransposeLeft},
    {{1, 17, 3, 19, 5, 21, 7, 23, 9, 25, 11, 27, 13, 29, 15, 31},
     kArmS8x16TransposeRight},
    {{7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8}, kArmS8x8Reverse},
    {{3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12}, kArmS8x4Reverse},
    {{1, 0, 3, 2, 5, 4, 7, 6, 9, 8, 11, 10, 13, 12, 15, 14}, kArmS8x2Reverse}};

bool TryMatchArchShuffle(const uint8_t* shuffle, const ShuffleEntry* table,
                         size_t num_entries, bool is_swizzle,
                         ArchOpcode* opcode) {
  uint8_t mask = is_swizzle ? kSimd128Size - 1 : 2 * kSimd128Size - 1;
  for (size_t i = 0; i < num_entries; ++i) {
    const ShuffleEntry& entry = table[i];
    int j = 0;
    for (; j < kSimd128Size; ++j) {
      if ((entry.shuffle[j] & mask) != (shuffle[j] & mask)) {
        break;
      }
    }
    if (j == kSimd128Size) {
      *opcode = entry.opcode;
      return true;
    }
  }
  return false;
}

template <typename Adapter>
void ArrangeShuffleTable(ArmOperandGeneratorT<Adapter>* g,
                         typename Adapter::node_t input0,
                         typename Adapter::node_t input1,
                         InstructionOperand* src0, InstructionOperand* src1) {
  if (input0 == input1) {
    // Unary, any q-register can be the table.
    *src0 = *src1 = g->UseRegister(input0);
  } else {
    // Binary, table registers must be consecutive.
    *src0 = g->UseFixed(input0, q0);
    *src1 = g->UseFixed(input1, q1);
  }
}

}  // namespace

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI8x16Shuffle(node_t node) {
  uint8_t shuffle[kSimd128Size];
  bool is_swizzle;
  // TODO(nicohartmann@): Properly use view here once Turboshaft support is
  // implemented.
  auto view = this->simd_shuffle_view(node);
  CanonicalizeShuffle(view, shuffle, &is_swizzle);
  node_t input0 = view.input(0);
  node_t input1 = view.input(1);
  uint8_t shuffle32x4[4];
  ArmOperandGeneratorT<Adapter> g(this);
  int index = 0;
  if (wasm::SimdShuffle::TryMatch32x4Shuffle(shuffle, shuffle32x4)) {
    if (wasm::SimdShuffle::TryMatchSplat<4>(shuffle, &index)) {
      DCHECK_GT(4, index);
      Emit(kArmS128Dup, g.DefineAsRegister(node), g.UseRegister(input0),
           g.UseImmediate(Neon32), g.UseImmediate(index % 4));
    } else if (wasm::SimdShuffle::TryMatchIdentity(shuffle)) {
      // Bypass normal shuffle code generation in this case.
      // EmitIdentity
      MarkAsUsed(input0);
      MarkAsDefined(node);
      SetRename(node, input0);
    } else {
      // 32x4 shuffles are implemented as s-register moves. To simplify these,
      // make sure the destination is distinct from both sources.
      InstructionOperand src0 = g.UseUniqueRegister(input0);
      InstructionOperand src1 = is_swizzle ? src0 : g.UseUniqueRegister(input1);
      Emit(kArmS32x4Shuffle, g.DefineAsRegister(node), src0, src1,
           g.UseImmediate(wasm::SimdShuffle::Pack4Lanes(shuffle32x4)));
    }
    return;
  }
  if (wasm::SimdShuffle::TryMatchSplat<8>(shuffle, &index)) {
    DCHECK_GT(8, index);
    Emit(kArmS128Dup, g.DefineAsRegister(node), g.UseRegister(input0),
         g.UseImmediate(Neon16), g.UseImmediate(index % 8));
    return;
  }
  if (wasm::SimdShuffle::TryMatchSplat<16>(shuffle, &index)) {
    DCHECK_GT(16, index);
    Emit(kArmS128Dup, g.DefineAsRegister(node), g.UseRegister(input0),
         g.UseImmediate(Neon8), g.UseImmediate(index % 16));
    return;
  }
  ArchOpcode opcode;
  if (TryMatchArchShuffle(shuffle, arch_shuffles, arraysize(arch_shuffles),
                          is_swizzle, &opcode)) {
    VisitRRRShuffle(this, opcode, node, input0, input1);
    return;
  }
  uint8_t offset;
  if (wasm::SimdShuffle::TryMatchConcat(shuffle, &offset)) {
    Emit(kArmS8x16Concat, g.DefineAsRegister(node), g.UseRegister(input0),
         g.UseRegister(input1), g.UseImmediate(offset));
    return;
  }
  // Code generator uses vtbl, arrange sources to form a valid lookup table.
  InstructionOperand src0, src1;
  ArrangeShuffleTable(&g, input0, input1, &src0, &src1);
  Emit(kArmI8x16Shuffle, g.DefineAsRegister(node), src0, src1,
       g.UseImmediate(wasm::SimdShuffle::Pack4Lanes(shuffle)),
       g.UseImmediate(wasm::SimdShuffle::Pack4Lanes(shuffle + 4)),
       g.UseImmediate(wasm::SimdShuffle::Pack4Lanes(shuffle + 8)),
       g.UseImmediate(wasm::SimdShuffle::Pack4Lanes(shuffle + 12)));
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitSetStackPointer(Node* node) {
  OperandGenerator g(this);
  auto input = g.UseRegister(node->InputAt(0));
  Emit(kArchSetStackPointer, 0, nullptr, 1, &input);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitSetStackPointer(
    node_t node) {
  OperandGenerator g(this);
  auto input = g.UseRegister(this->input_at(node, 0));
  Emit(kArchSetStackPointer, 0, nullptr, 1, &input);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI8x16Swizzle(node_t node) {
    ArmOperandGeneratorT<Adapter> g(this);
    // We don't want input 0 (the table) to be the same as output, since we will
    // modify output twice (low and high), and need to keep the table the same.
    Emit(kArmI8x16Swizzle, g.DefineAsRegister(node),
         g.UseUniqueRegister(this->input_at(node, 0)),
         g.UseRegister(this->input_at(node, 1)));
}

#endif  // V8_ENABLE_WEBASSEMBLY

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitSignExtendWord8ToInt32(node_t node) {
  ArmOperandGeneratorT<Adapter> g(this);
  Emit(kArmSxtb, g.DefineAsRegister(node),
       g.UseRegister(this->input_at(node, 0)), g.TempImmediate(0));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitSignExtendWord16ToInt32(node_t node) {
  ArmOperandGeneratorT<Adapter> g(this);
  Emit(kArmSxth, g.DefineAsRegister(node),
       g.UseRegister(this->input_at(node, 0)), g.TempImmediate(0));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32AbsWithOverflow(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt64AbsWithOverflow(node_t node) {
  UNREACHABLE();
}

namespace {
template <typename Adapter, ArchOpcode opcode>
void VisitBitMask(InstructionSelectorT<Adapter>* selector,
                  typename Adapter::node_t node) {
    ArmOperandGeneratorT<Adapter> g(selector);
    InstructionOperand temps[] = {g.TempSimd128Register()};
    selector->Emit(opcode, g.DefineAsRegister(node),
                   g.UseRegister(selector->input_at(node, 0)), arraysize(temps),
                   temps);
}
}  // namespace

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI8x16BitMask(node_t node) {
  VisitBitMask<Adapter, kArmI8x16BitMask>(this, node);
}

#if V8_ENABLE_WEBASSEMBLY
template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI16x8BitMask(node_t node) {
  VisitBitMask<Adapter, kArmI16x8BitMask>(this, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI32x4BitMask(node_t node) {
  VisitBitMask<Adapter, kArmI32x4BitMask>(this, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI64x2BitMask(node_t node) {
  VisitBitMask<Adapter, kArmI64x2BitMask>(this, node);
}

namespace {
template <typename Adapter>
void VisitF32x4PminOrPmax(InstructionSelectorT<Adapter>* selector,
                          ArchOpcode opcode, typename Adapter::node_t node) {
    ArmOperandGeneratorT<Adapter> g(selector);
    // Need all unique registers because we first compare the two inputs, then
    // we need the inputs to remain unchanged for the bitselect later.
    selector->Emit(opcode, g.DefineAsRegister(node),
                   g.UseUniqueRegister(selector->input_at(node, 0)),
                   g.UseUniqueRegister(selector->input_at(node, 1)));
}

template <typename Adapter>
void VisitF64x2PminOrPMax(InstructionSelectorT<Adapter>* selector,
                          ArchOpcode opcode, typename Adapter::node_t node) {
    ArmOperandGeneratorT<Adapter> g(selector);
    selector->Emit(opcode, g.DefineSameAsFirst(node),
                   g.UseRegister(selector->input_at(node, 0)),
                   g.UseRegister(selector->input_at(node, 1)));
}
}  // namespace

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF32x4Pmin(node_t node) {
  VisitF32x4PminOrPmax(this, kArmF32x4Pmin, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF32x4Pmax(node_t node) {
  VisitF32x4PminOrPmax(this, kArmF32x4Pmax, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF64x2Pmin(node_t node) {
  VisitF64x2PminOrPMax(this, kArmF64x2Pmin, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF64x2Pmax(node_t node) {
  VisitF64x2PminOrPMax(this, kArmF64x2Pmax, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF64x2RelaxedMin(node_t node) {
  VisitF64x2Pmin(node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF64x2RelaxedMax(node_t node) {
  VisitF64x2Pmax(node);
}

#define EXT_MUL_LIST(V)                            \
  V(I16x8ExtMulLowI8x16S, kArmVmullLow, NeonS8)    \
  V(I16x8ExtMulHighI8x16S, kArmVmullHigh, NeonS8)  \
  V(I16x8ExtMulLowI8x16U, kArmVmullLow, NeonU8)    \
  V(I16x8ExtMulHighI8x16U, kArmVmullHigh, NeonU8)  \
  V(I32x4ExtMulLowI16x8S, kArmVmullLow, NeonS16)   \
  V(I32x4ExtMulHighI16x8S, kArmVmullHigh, NeonS16) \
  V(I32x4ExtMulLowI16x8U, kArmVmullLow, NeonU16)   \
  V(I32x4ExtMulHighI16x8U, kArmVmullHigh, NeonU16) \
  V(I64x2ExtMulLowI32x4S, kArmVmullLow, NeonS32)   \
  V(I64x2ExtMulHighI32x4S, kArmVmullHigh, NeonS32) \
  V(I64x2ExtMulLowI32x4U, kArmVmullLow, NeonU32)   \
  V(I64x2ExtMulHighI32x4U, kArmVmullHigh, NeonU32)

#define VISIT_EXT_MUL(OPCODE, VMULL, NEONSIZE)                     \
  template <typename Adapter>                                      \
  void InstructionSelectorT<Adapter>::Visit##OPCODE(node_t node) { \
    VisitRRR(this, VMULL | MiscField::encode(NEONSIZE), node);     \
  }

EXT_MUL_LIST(VISIT_EXT_MUL)

#undef VISIT_EXT_MUL
#undef EXT_MUL_LIST

#define VISIT_EXTADD_PAIRWISE(OPCODE, NEONSIZE)                    \
  template <typename Adapter>                                      \
  void InstructionSelectorT<Adapter>::Visit##OPCODE(node_t node) { \
    VisitRR(this, kArmVpaddl | MiscField::encode(NEONSIZE), node); \
  }
VISIT_EXTADD_PAIRWISE(I16x8ExtAddPairwiseI8x16S, NeonS8)
VISIT_EXTADD_PAIRWISE(I16x8ExtAddPairwiseI8x16U, NeonU8)
VISIT_EXTADD_PAIRWISE(I32x4ExtAddPairwiseI16x8S, NeonS16)
VISIT_EXTADD_PAIRWISE(I32x4ExtAddPairwiseI16x8U, NeonU16)
#undef VISIT_EXTADD_PAIRWISE

// TODO(v8:9780)
// These double precision conversion instructions need a low Q register (q0-q7)
// because the codegen accesses the S registers they overlap with.
template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF64x2ConvertLowI32x4S(node_t node) {
    ArmOperandGeneratorT<Adapter> g(this);
    Emit(kArmF64x2ConvertLowI32x4S, g.DefineAsRegister(node),
         g.UseFixed(this->input_at(node, 0), q0));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF64x2ConvertLowI32x4U(node_t node) {
    ArmOperandGeneratorT<Adapter> g(this);
    Emit(kArmF64x2ConvertLowI32x4U, g.DefineAsRegister(node),
         g.UseFixed(this->input_at(node, 0), q0));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI32x4TruncSatF64x2SZero(node_t node) {
    ArmOperandGeneratorT<Adapter> g(this);
    Emit(kArmI32x4TruncSatF64x2SZero, g.DefineAsFixed(node, q0),
         g.UseUniqueRegister(this->input_at(node, 0)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI32x4TruncSatF64x2UZero(node_t node) {
  ArmOperandGeneratorT<Adapter> g(this);
  Emit(kArmI32x4TruncSatF64x2UZero, g.DefineAsFixed(node, q0),
       g.UseUniqueRegister(this->input_at(node, 0)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF32x4DemoteF64x2Zero(node_t node) {
    ArmOperandGeneratorT<Adapter> g(this);
    Emit(kArmF32x4DemoteF64x2Zero, g.DefineAsFixed(node, q0),
         g.UseUniqueRegister(this->input_at(node, 0)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF64x2PromoteLowF32x4(node_t node) {
    ArmOperandGeneratorT<Adapter> g(this);
    Emit(kArmF64x2PromoteLowF32x4, g.DefineAsRegister(node),
         g.UseFixed(this->input_at(node, 0), q0));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI32x4RelaxedTruncF64x2SZero(
    node_t node) {
  VisitI32x4TruncSatF64x2SZero(node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI32x4RelaxedTruncF64x2UZero(
    node_t node) {
  VisitI32x4TruncSatF64x2UZero(node);
}
#endif  // V8_ENABLE_WEBASSEMBLY

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTruncateFloat32ToInt32(node_t node) {
  ArmOperandGeneratorT<Adapter> g(this);
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const Operation& op = this->Get(node);
    InstructionCode opcode = kArmVcvtS32F32;
    if (op.Is<Opmask::kTruncateFloat32ToInt32OverflowToMin>()) {
      opcode |= MiscField::encode(true);
    }
    Emit(opcode, g.DefineAsRegister(node),
         g.UseRegister(this->input_at(node, 0)));
  } else {
    InstructionCode opcode = kArmVcvtS32F32;
    TruncateKind kind = OpParameter<TruncateKind>(node->op());
    if (kind == TruncateKind::kSetOverflowToMin) {
      opcode |= MiscField::encode(true);
    }

    Emit(opcode, g.DefineAsRegister(node), g.UseRegister(node->InputAt(0)));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTruncateFloat32ToUint32(node_t node) {
  ArmOperandGeneratorT<Adapter> g(this);
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const Operation& op =
"""


```