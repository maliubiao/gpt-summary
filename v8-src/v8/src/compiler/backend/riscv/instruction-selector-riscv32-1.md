Response: The user has provided the second part of a C++ source code file for the RISC-V 32-bit architecture within the V8 JavaScript engine. They want a summary of the file's functionality, specifically focusing on its relationship to JavaScript. Since this is part 2, I should consider that it likely continues the work of part 1.

**High-Level Plan:**

1. **Analyze the code snippets:** Look for patterns in the function names and the operations they perform. Pay attention to keywords like "Atomic," "Pair," "Shift," and SIMD-related instructions.
2. **Identify the core functionalities:** Based on the analysis, group related functions and determine the overall purposes of these code blocks.
3. **Connect to JavaScript:** Consider how these low-level operations might be used in the implementation of JavaScript features. Focus on areas like concurrency (atomics), efficient handling of larger integers (pairs), and potential optimizations for SIMD operations.
4. **Provide a JavaScript example:**  Choose a relevant JavaScript feature that demonstrates the underlying functionality. Atomic operations and SIMD are good candidates.
5. **Structure the summary:** Organize the findings into clear points, explaining the purpose and relevance of the code.

**Detailed Analysis of Code Snippets:**

* **Atomic Operations (Single Word):** The `VisitWord32AtomicBinaryOperation` function and the `VISIT_ATOMIC_BINOP` macro indicate the handling of atomic arithmetic and logical operations on 32-bit integers. This is directly related to JavaScript's `Atomics` object.
* **Pair Operations (64-bit using 32-bit):** Functions like `VisitInt32PairAdd`, `VisitInt32PairSub`, `VisitWord32PairShl`, etc., suggest operations on 64-bit values by treating them as pairs of 32-bit words. This is often needed for architectures without native 64-bit support and can be relevant to how JavaScript numbers (which can represent larger integers) are handled.
* **Atomic Pair Operations:**  Functions like `VisitWord32AtomicPairLoad`, `VisitWord32AtomicPairStore`, and the various `VisitWord32AtomicPair...` functions point to atomic operations on these 64-bit "pair" values. This is an extension of the single-word atomics, crucial for concurrent programming with larger data.
* **SIMD Operations (F64x2Min/Max):** The `VisitF64x2Min` and `VisitF64x2Max` functions clearly deal with SIMD (Single Instruction, Multiple Data) operations on pairs of 64-bit floating-point numbers. This relates to JavaScript's SIMD API (`Float64x2`).
* **Instruction Selection:** The code heavily uses `InstructionSelectorT`, suggesting this file is part of the instruction selection phase of the compiler, where high-level operations are translated into low-level machine instructions.

**Connecting to JavaScript:**

* **Atomics:** The atomic operations directly correspond to the `Atomics` object in JavaScript, allowing for safe concurrent operations on shared memory.
* **Large Integers:** While JavaScript's `Number` type can represent integers up to a certain limit, internal representations and certain operations might involve handling them as pairs of 32-bit values, especially when dealing with bitwise operations or when targeting 32-bit architectures.
* **SIMD:** The `F64x2Min` and `F64x2Max` operations directly relate to the `Float64x2` data type in JavaScript's SIMD API, offering performance benefits for parallel computations on numerical data.

**JavaScript Example (Atomics):**

```javascript
const sab = new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT * 2);
const view = new Int32Array(sab);

// In one thread:
Atomics.add(view, 0, 5);

// In another thread (potentially running concurrently):
Atomics.sub(view, 0, 2);

console.log(Atomics.load(view, 0)); // The final value will be 3
```

**Summary Structure:**

I'll structure the summary by grouping the identified functionalities and then providing the JavaScript example. I also need to acknowledge that this is the *second part* and likely builds upon the first.
好的，这是v8/src/compiler/backend/riscv/instruction-selector-riscv32.cc文件的第二部分，延续了第一部分的功能，主要负责为RISC-V 32位架构选择合适的机器指令，以实现高级的中间表示（IR）节点所代表的操作。

结合这部分的代码，我们可以归纳出以下功能：

1. **原子操作支持 (Atomic Operations):**
   - 实现了针对单字（32位）的原子加、减、与、或、异或操作。这些操作保证了在多线程环境下的数据一致性。
   - `VisitWord32AtomicBinaryOperation` 函数根据操作类型和内存表示选择合适的原子操作指令。
   - `VISIT_ATOMIC_BINOP` 宏简化了定义不同原子二元操作访问函数的流程。

2. **不支持溢出检测的绝对值操作:**
   - `VisitInt32AbsWithOverflow` 和 `VisitInt64AbsWithOverflow` 函数被标记为 `UNREACHABLE()`，表明该架构上可能不直接支持带溢出检测的绝对值操作，或者在指令选择阶段不处理这种情况。

3. **双字操作支持 (Pair Operations):**
   - 实现了针对由两个32位字组成的64位整数的算术运算，如加法、减法和乘法。
   - `VisitInt32PairBinop` 是一个模板函数，用于处理这类双字二元操作，它可以根据是否需要结果的高位来选择发射双字指令或单字指令。
   - 实现了将两个32位整数拼接成一个64位整数的操作 (`VisitI64x2SplatI32Pair`)，以及替换64位整数中特定32位字的操作 (`VisitI64x2ReplaceLaneI32Pair`)。

4. **双字移位操作支持 (Pair Shift Operations):**
   - 实现了针对双字（64位）的左移、逻辑右移和算术右移操作。
   - `VisitWord32PairShift` 是一个模板函数，用于处理这些移位操作，它会处理移位量是立即数还是寄存器的情况。

5. **原子双字操作支持 (Atomic Pair Operations):**
   - 实现了针对由两个32位字组成的64位数据的原子加载和存储操作 (`VisitWord32AtomicPairLoad`, `VisitWord32AtomicPairStore`).
   - 实现了针对双字的原子加、减、与、或、异或和交换操作 (`VisitPairAtomicBinop` 模板和相应的访问函数)。
   - 实现了原子双字比较并交换操作 (`VisitWord32AtomicPairCompareExchange`)，这是一个更复杂的原子操作，用于实现无锁数据结构。

6. **SIMD 浮点操作支持 (SIMD Floating-Point Operations):**
   - 实现了针对两个64位浮点数的 SIMD 最小 (`VisitF64x2Min`) 和最大值 (`VisitF64x2Max`) 操作。这些操作利用了 RISC-V 的向量扩展指令。

7. **支持的机器操作标志:**
   - `SupportedMachineOperatorFlags` 函数返回了该指令选择器支持的特定机器操作标志，例如计算尾部零个数 (`kWord32Ctz`)、人口计数 (`kWord32Popcnt`)、安全的整数除法 (`kInt32DivIsSafe`, `kUint32DivIsSafe`) 以及浮点数的舍入模式。

**与 JavaScript 的关系及示例:**

这些底层的指令选择直接影响了 V8 引擎执行 JavaScript 代码的效率和功能。

* **原子操作 (Atomics):** JavaScript 的 `Atomics` 对象允许在共享内存上执行原子操作，这部分代码就是为 RISC-V 32 位架构实现了这些原子操作的基础。

   ```javascript
   const sab = new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT);
   const view = new Int32Array(sab);

   // 在一个线程中
   Atomics.add(view, 0, 5);

   // 在另一个线程中
   Atomics.sub(view, 0, 2);

   console.log(Atomics.load(view, 0)); // 输出可能是 3
   ```

* **大整数操作 (BigInt):** 虽然这段代码主要处理 32 位和模拟的 64 位整数，但其处理双字运算的思想与 JavaScript 中 `BigInt` 类型的某些底层实现可能有关，尤其是在 32 位架构上高效处理大整数时。

* **SIMD (SIMD):** JavaScript 的 SIMD API (`Float64x2`) 允许进行并行计算。 `VisitF64x2Min` 和 `VisitF64x2Max` 这样的函数就是为 RISC-V 架构上的 `Float64x2` 类型的 `min` 和 `max` 操作选择了合适的向量指令。

   ```javascript
   const a = Float64x2(1.0, 3.0);
   const b = Float64x2(2.0, 1.0);
   const min = Math.f64x2.min(a, b);
   console.log(min.x, min.y); // 输出 1, 1
   ```

总而言之，这个代码文件的第二部分继续为 RISC-V 32 位架构的 V8 引擎提供了关键的指令选择功能，涵盖了原子操作、双字整数运算和 SIMD 浮点运算，这些都直接支持了 JavaScript 的相关语言特性和性能优化。它将高级的抽象操作转化为具体的 RISC-V 汇编指令，使得 JavaScript 代码可以在 RISC-V 架构上高效运行。

Prompt: 
```
这是目录为v8/src/compiler/backend/riscv/instruction-selector-riscv32.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""
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

    VisitAtomicBinop(this, node, opcode);
}

#define VISIT_ATOMIC_BINOP(op)                                             \
  template <typename Adapter>                                              \
  void InstructionSelectorT<Adapter>::VisitWord32Atomic##op(node_t node) {  \
      VisitWord32AtomicBinaryOperation(                                    \
          node, kAtomic##op##Int8, kAtomic##op##Uint8, kAtomic##op##Int16, \
          kAtomic##op##Uint16, kAtomic##op##Word32);                       \
  }
VISIT_ATOMIC_BINOP(Add)
VISIT_ATOMIC_BINOP(Sub)
VISIT_ATOMIC_BINOP(And)
VISIT_ATOMIC_BINOP(Or)
VISIT_ATOMIC_BINOP(Xor)
#undef VISIT_ATOMIC_BINOP

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32AbsWithOverflow(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt64AbsWithOverflow(node_t node) {
  UNREACHABLE();
}

template <unsigned N, typename Adapter>
static void VisitInt32PairBinop(InstructionSelectorT<Adapter>* selector,
                                InstructionCode pair_opcode,
                                InstructionCode single_opcode,
                                typename Adapter::node_t node) {
  static_assert(N == 3 || N == 4,
                "Pair operations can only have 3 or 4 inputs");

  RiscvOperandGeneratorT<Adapter> g(selector);
  using node_t = typename Adapter::node_t;
  node_t projection1 = selector->FindProjection(node, 1);

  if (selector->valid(projection1)) {
    InstructionOperand outputs[] = {
        g.DefineAsRegister(node),
        g.DefineAsRegister(selector->FindProjection(node, 1))};

    if constexpr (N == 3) {
      // We use UseUniqueRegister here to avoid register sharing with the output
      // register.
      InstructionOperand inputs[] = {
          g.UseUniqueRegister(selector->input_at(node, 0)),
          g.UseUniqueRegister(selector->input_at(node, 1)),
          g.UseUniqueRegister(selector->input_at(node, 2))};

      selector->Emit(pair_opcode, 2, outputs, N, inputs);

    } else if constexpr (N == 4) {
      // We use UseUniqueRegister here to avoid register sharing with the output
      // register.
      InstructionOperand inputs[] = {
          g.UseUniqueRegister(selector->input_at(node, 0)),
          g.UseUniqueRegister(selector->input_at(node, 1)),
          g.UseUniqueRegister(selector->input_at(node, 2)),
          g.UseUniqueRegister(selector->input_at(node, 3))};

      selector->Emit(pair_opcode, 2, outputs, N, inputs);
    }

  } else {
    // The high word of the result is not used, so we emit the standard 32 bit
    // instruction.
    selector->Emit(single_opcode, g.DefineSameAsFirst(node),
                   g.UseRegister(selector->input_at(node, 0)),
                   g.UseRegister(selector->input_at(node, 2)));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32PairAdd(node_t node) {
    VisitInt32PairBinop<4>(this, kRiscvAddPair, kRiscvAdd32, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32PairSub(node_t node) {
    VisitInt32PairBinop<4>(this, kRiscvSubPair, kRiscvSub32, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32PairMul(node_t node) {
    VisitInt32PairBinop<4>(this, kRiscvMulPair, kRiscvMul32, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI64x2SplatI32Pair(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    UNIMPLEMENTED();
  } else {
    RiscvOperandGeneratorT<Adapter> g(this);
    InstructionOperand low = g.UseRegister(node->InputAt(0));
    InstructionOperand high = g.UseRegister(node->InputAt(1));
    Emit(kRiscvI64x2SplatI32Pair, g.DefineAsRegister(node), low, high);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI64x2ReplaceLaneI32Pair(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    UNIMPLEMENTED();
  } else {
    RiscvOperandGeneratorT<Adapter> g(this);
    InstructionOperand operand = g.UseRegister(node->InputAt(0));
    InstructionOperand lane = g.UseImmediate(OpParameter<int32_t>(node->op()));
    InstructionOperand low = g.UseRegister(node->InputAt(1));
    InstructionOperand high = g.UseRegister(node->InputAt(2));
    Emit(kRiscvI64x2ReplaceLaneI32Pair, g.DefineSameAsFirst(node), operand,
         lane, low, high);
  }
}

// Shared routine for multiple shift operations.
template <typename Adapter>
static void VisitWord32PairShift(InstructionSelectorT<Adapter>* selector,
                                 InstructionCode opcode,
                                 typename Adapter::node_t node) {
  RiscvOperandGeneratorT<Adapter> g(selector);
  InstructionOperand shift_operand;
  typename Adapter::node_t shift_by = selector->input_at(node, 2);
  if (selector->is_integer_constant(shift_by)) {
    shift_operand = g.UseImmediate(shift_by);
  } else {
    shift_operand = g.UseUniqueRegister(shift_by);
  }

  // We use UseUniqueRegister here to avoid register sharing with the output
  // register.
  InstructionOperand inputs[] = {
      g.UseUniqueRegister(selector->input_at(node, 0)),
      g.UseUniqueRegister(selector->input_at(node, 1)), shift_operand};

  typename Adapter::node_t projection1 = selector->FindProjection(node, 1);

  InstructionOperand outputs[2];
  InstructionOperand temps[1];
  int32_t output_count = 0;
  int32_t temp_count = 0;

  outputs[output_count++] = g.DefineAsRegister(node);
  if (selector->valid(projection1)) {
    outputs[output_count++] = g.DefineAsRegister(projection1);
  } else {
    temps[temp_count++] = g.TempRegister();
  }

  selector->Emit(opcode, output_count, outputs, 3, inputs, temp_count, temps);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32PairShl(node_t node) {
    VisitWord32PairShift(this, kRiscvShlPair, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32PairShr(node_t node) {
    VisitWord32PairShift(this, kRiscvShrPair, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32PairSar(node_t node) {
    VisitWord32PairShift(this, kRiscvSarPair, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicPairLoad(node_t node) {
  RiscvOperandGeneratorT<Adapter> g(this);
  node_t base = this->input_at(node, 0);
  node_t index = this->input_at(node, 1);

  ArchOpcode opcode = kRiscvWord32AtomicPairLoad;
  AddressingMode addressing_mode = kMode_MRI;
  InstructionCode code = opcode | AddressingModeField::encode(addressing_mode);
  InstructionOperand inputs[] = {g.UseRegister(base), g.UseRegister(index)};
  InstructionOperand temps[3];
  size_t temp_count = 0;
  temps[temp_count++] = g.TempRegister(t0);
  InstructionOperand outputs[2];
  size_t output_count = 0;

  node_t projection0 = this->FindProjection(node, 0);
  node_t projection1 = this->FindProjection(node, 1);
  if (this->valid(projection0)) {
    outputs[output_count++] = g.DefineAsFixed(projection0, a0);
  } else {
    temps[temp_count++] = g.TempRegister(a0);
  }
  if (this->valid(projection1)) {
    outputs[output_count++] = g.DefineAsFixed(projection1, a1);
  } else {
    temps[temp_count++] = g.TempRegister(a1);
  }
  Emit(code, output_count, outputs, arraysize(inputs), inputs, temp_count,
       temps);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicPairStore(node_t node) {
  RiscvOperandGeneratorT<Adapter> g(this);
  auto store = this->word32_atomic_pair_store_view(node);

  node_t base = store.base();
  node_t index = store.index();
  node_t value_low = store.value_low();
  node_t value_high = store.value_high();

  InstructionOperand inputs[] = {g.UseRegister(base), g.UseRegister(index),
                                 g.UseFixed(value_low, a1),
                                 g.UseFixed(value_high, a2)};
  InstructionOperand temps[] = {g.TempRegister(a0), g.TempRegister(),
                                g.TempRegister()};
  Emit(kRiscvWord32AtomicPairStore | AddressingModeField::encode(kMode_MRI), 0,
       nullptr, arraysize(inputs), inputs, arraysize(temps), temps);
}

template <typename Adapter>
void VisitPairAtomicBinop(InstructionSelectorT<Adapter>* selector,
                          typename Adapter::node_t node, ArchOpcode opcode) {
  using node_t = typename Adapter::node_t;
  RiscvOperandGeneratorT<Adapter> g(selector);
  node_t base = selector->input_at(node, 0);
  node_t index = selector->input_at(node, 1);
  node_t value = selector->input_at(node, 2);
  node_t value_high = selector->input_at(node, 3);

  AddressingMode addressing_mode = kMode_None;
  InstructionCode code = opcode | AddressingModeField::encode(addressing_mode);
  InstructionOperand inputs[] = {g.UseRegister(base), g.UseRegister(index),
                                 g.UseFixed(value, a1),
                                 g.UseFixed(value_high, a2)};
  InstructionOperand outputs[2];
  size_t output_count = 0;
  InstructionOperand temps[3];
  size_t temp_count = 0;
  temps[temp_count++] = g.TempRegister(t0);

  node_t projection0 = selector->FindProjection(node, 0);
  node_t projection1 = selector->FindProjection(node, 1);
  if (selector->valid(projection0)) {
    outputs[output_count++] = g.DefineAsFixed(projection0, a0);
  } else {
    temps[temp_count++] = g.TempRegister(a0);
  }
  if (selector->valid(projection1)) {
    outputs[output_count++] = g.DefineAsFixed(projection1, a1);
  } else {
    temps[temp_count++] = g.TempRegister(a1);
  }
  selector->Emit(code, output_count, outputs, arraysize(inputs), inputs,
                 temp_count, temps);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicPairAdd(node_t node) {
  VisitPairAtomicBinop(this, node, kRiscvWord32AtomicPairAdd);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicPairSub(node_t node) {
  VisitPairAtomicBinop(this, node, kRiscvWord32AtomicPairSub);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicPairAnd(node_t node) {
  VisitPairAtomicBinop(this, node, kRiscvWord32AtomicPairAnd);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicPairOr(node_t node) {
  VisitPairAtomicBinop(this, node, kRiscvWord32AtomicPairOr);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicPairXor(node_t node) {
  VisitPairAtomicBinop(this, node, kRiscvWord32AtomicPairXor);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicPairExchange(node_t node) {
  VisitPairAtomicBinop(this, node, kRiscvWord32AtomicPairExchange);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicPairCompareExchange(
    typename Adapter::node_t node) {
  using node_t = typename Adapter::node_t;
  RiscvOperandGeneratorT<Adapter> g(this);
  // In the Turbofan and the Turboshaft graph the order of expected and value is
  // swapped.
  const size_t expected_offset = Adapter::IsTurboshaft ? 4 : 2;
  const size_t value_offset = Adapter::IsTurboshaft ? 2 : 4;
  InstructionOperand inputs[] = {
      g.UseRegister(this->input_at(node, 0)),
      g.UseRegister(this->input_at(node, 1)),
      g.UseFixed(this->input_at(node, expected_offset), a1),
      g.UseFixed(this->input_at(node, expected_offset + 1), a2),
      g.UseFixed(this->input_at(node, value_offset), a3),
      g.UseFixed(this->input_at(node, value_offset + 1), a4)};

  InstructionCode code = kRiscvWord32AtomicPairCompareExchange |
                         AddressingModeField::encode(kMode_MRI);
  node_t projection0 = this->FindProjection(node, 0);
  node_t projection1 = this->FindProjection(node, 1);
  InstructionOperand outputs[2];
  size_t output_count = 0;
  InstructionOperand temps[3];
  size_t temp_count = 0;
  temps[temp_count++] = g.TempRegister(t0);
  if (this->valid(projection0)) {
    outputs[output_count++] = g.DefineAsFixed(projection0, a0);
  } else {
    temps[temp_count++] = g.TempRegister(a0);
  }
  if (this->valid(projection1)) {
    outputs[output_count++] = g.DefineAsFixed(projection1, a1);
  } else {
    temps[temp_count++] = g.TempRegister(a1);
  }
  Emit(code, output_count, outputs, arraysize(inputs), inputs, temp_count,
       temps);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF64x2Min(node_t node) {
    RiscvOperandGeneratorT<Adapter> g(this);
    InstructionOperand temp1 = g.TempFpRegister(v0);
    InstructionOperand mask_reg = g.TempFpRegister(v0);
    InstructionOperand temp2 = g.TempFpRegister(kSimd128ScratchReg);
    const int32_t kNaN = 0x7ff80000L, kNaNShift = 32;
    this->Emit(kRiscvVmfeqVv, temp1, g.UseRegister(this->input_at(node, 0)),
               g.UseRegister(this->input_at(node, 0)), g.UseImmediate(E64),
               g.UseImmediate(m1));
    this->Emit(kRiscvVmfeqVv, temp2, g.UseRegister(this->input_at(node, 1)),
               g.UseRegister(this->input_at(node, 1)), g.UseImmediate(E64),
               g.UseImmediate(m1));
    this->Emit(kRiscvVandVv, mask_reg, temp2, temp1, g.UseImmediate(E64),
               g.UseImmediate(m1));

    InstructionOperand temp3 = g.TempFpRegister(kSimd128ScratchReg);
    InstructionOperand temp4 = g.TempFpRegister(kSimd128ScratchReg);
    InstructionOperand temp5 = g.TempFpRegister(kSimd128ScratchReg);
    this->Emit(kRiscvVmv, temp3, g.UseImmediate(kNaN), g.UseImmediate(E64),
               g.UseImmediate(m1));
    this->Emit(kRiscvVsll, temp4, temp3, g.UseImmediate(kNaNShift),
               g.UseImmediate(E64), g.UseImmediate(m1));
    this->Emit(kRiscvVfminVv, temp5, g.UseRegister(this->input_at(node, 1)),
               g.UseRegister(this->input_at(node, 0)), g.UseImmediate(E64),
               g.UseImmediate(m1), g.UseImmediate(Mask));
    this->Emit(kRiscvVmv, g.DefineAsRegister(node), temp5, g.UseImmediate(E64),
               g.UseImmediate(m1));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF64x2Max(node_t node) {
    RiscvOperandGeneratorT<Adapter> g(this);
    InstructionOperand temp1 = g.TempFpRegister(v0);
    InstructionOperand mask_reg = g.TempFpRegister(v0);
    InstructionOperand temp2 = g.TempFpRegister(kSimd128ScratchReg);
    const int32_t kNaN = 0x7ff80000L, kNaNShift = 32;
    this->Emit(kRiscvVmfeqVv, temp1, g.UseRegister(this->input_at(node, 0)),
               g.UseRegister(this->input_at(node, 0)), g.UseImmediate(E64),
               g.UseImmediate(m1));
    this->Emit(kRiscvVmfeqVv, temp2, g.UseRegister(this->input_at(node, 1)),
               g.UseRegister(this->input_at(node, 1)), g.UseImmediate(E64),
               g.UseImmediate(m1));
    this->Emit(kRiscvVandVv, mask_reg, temp2, temp1, g.UseImmediate(E64),
               g.UseImmediate(m1));

    InstructionOperand temp3 = g.TempFpRegister(kSimd128ScratchReg);
    InstructionOperand temp4 = g.TempFpRegister(kSimd128ScratchReg);
    InstructionOperand temp5 = g.TempFpRegister(kSimd128ScratchReg);
    this->Emit(kRiscvVmv, temp3, g.UseImmediate(kNaN), g.UseImmediate(E64),
               g.UseImmediate(m1));
    this->Emit(kRiscvVsll, temp4, temp3, g.UseImmediate(kNaNShift),
               g.UseImmediate(E64), g.UseImmediate(m1));
    this->Emit(kRiscvVfmaxVv, temp5, g.UseRegister(this->input_at(node, 1)),
               g.UseRegister(this->input_at(node, 0)), g.UseImmediate(E64),
               g.UseImmediate(m1), g.UseImmediate(Mask));
    this->Emit(kRiscvVmv, g.DefineAsRegister(node), temp5, g.UseImmediate(E64),
               g.UseImmediate(m1));
}
// static
MachineOperatorBuilder::Flags
InstructionSelector::SupportedMachineOperatorFlags() {
  MachineOperatorBuilder::Flags flags = MachineOperatorBuilder::kNoFlags;
  return flags | MachineOperatorBuilder::kWord32Ctz |
         MachineOperatorBuilder::kWord32Ctz |
         MachineOperatorBuilder::kWord32Popcnt |
         MachineOperatorBuilder::kInt32DivIsSafe |
         MachineOperatorBuilder::kUint32DivIsSafe |
         MachineOperatorBuilder::kFloat32RoundDown |
         MachineOperatorBuilder::kFloat32RoundUp |
         MachineOperatorBuilder::kFloat32RoundTruncate |
         MachineOperatorBuilder::kFloat32RoundTiesEven;
}

#undef TRACE

template class EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE)
    InstructionSelectorT<TurbofanAdapter>;
template class EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE)
    InstructionSelectorT<TurboshaftAdapter>;
}  // namespace compiler
}  // namespace internal
}  // namespace v8

"""


```