Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of the V8 JavaScript engine. The code is located in `v8/src/compiler/backend/riscv/instruction-selector-riscv32.cc`.

Here's a breakdown of the thinking process:

1. **Identify the Core Purpose:** The filename `instruction-selector-riscv32.cc` and the content strongly suggest that this code is responsible for selecting specific RISC-V 32-bit instructions to implement higher-level operations. This is a crucial part of the compiler's backend.

2. **Analyze the Structure:** The code is organized into template functions parameterized by an `Adapter` type. This suggests the code is designed to be used with different compiler phases or intermediate representations (like Turbofan and Turboshaft, as seen at the end).

3. **Examine Key Function Prefixes:**  Notice the repeated prefixes like `VisitWord32Atomic`, `VisitInt32Pair`, and `VisitF64x2`. These prefixes, combined with the operation names (e.g., `Add`, `Sub`, `Shl`, `Min`, `Max`), clearly indicate the types of operations being handled:
    * `Word32Atomic`: Atomic operations on 32-bit words.
    * `Int32Pair`: Operations on pairs of 32-bit integers, often representing 64-bit values.
    * `F64x2`: Operations on pairs of 64-bit floating-point numbers (SIMD).

4. **Understand the `Visit` Pattern:** The `Visit...` functions are a common pattern in compiler design for traversing an intermediate representation of the code. Each `Visit` function corresponds to a specific node or operation in that representation.

5. **Focus on the Operations:** Go through the different `Visit` functions and categorize the operations being implemented:
    * **Atomic Operations:**  `VisitWord32AtomicAdd`, `VisitWord32AtomicSub`, etc., handle atomic read-modify-write operations. The code checks the `MemoryRepresentation` to determine the correct instruction size.
    * **Pairwise Integer Operations:** `VisitInt32PairAdd`, `VisitInt32PairSub`, `VisitInt32PairMul` perform arithmetic operations on pairs of 32-bit integers. The code handles cases where only the low 32 bits of the result are needed.
    * **Pairwise Shift Operations:** `VisitWord32PairShl`, `VisitWord32PairShr`, `VisitWord32PairSar` perform shift operations on pairs of 32-bit integers.
    * **Atomic Pair Operations:** `VisitWord32AtomicPairLoad`, `VisitWord32AtomicPairStore`, `VisitWord32AtomicPairAdd`, etc., handle atomic operations on pairs of 32-bit integers.
    * **SIMD Floating-Point Operations:** `VisitF64x2Min`, `VisitF64x2Max` implement minimum and maximum operations on pairs of 64-bit floating-point numbers using RISC-V vector instructions.
    * **Other Operations:** `VisitInt32AbsWithOverflow` and `VisitInt64AbsWithOverflow` are present but marked as `UNREACHABLE()`, suggesting they might not be implemented or used on this architecture.

6. **Identify Key Concepts:** The code utilizes concepts like:
    * **Instruction Selection:** Choosing the right machine instruction.
    * **Addressing Modes:** Different ways to access memory.
    * **Registers:**  Using registers for operands and results.
    * **Temporary Registers:**  Allocating temporary registers when needed.
    * **SIMD (Single Instruction, Multiple Data):**  Performing the same operation on multiple data elements simultaneously (evident in the `F64x2` operations).
    * **Atomic Operations:**  Ensuring thread safety when accessing shared memory.

7. **Consider the File Extension:** The prompt mentions checking for a `.tq` extension. Since it's `.cc`, it's C++ code, not Torque. Torque is a domain-specific language used in V8 for generating compiler code.

8. **Think about JavaScript Relevance:**  Since this code is part of V8, it directly relates to how JavaScript code is executed. The operations implemented here correspond to JavaScript language features like arithmetic operators, bitwise operators, and potentially Typed Arrays and SharedArrayBuffers (for atomic operations).

9. **Develop Examples (if requested):**  Think of simple JavaScript code snippets that would trigger the kind of operations handled in the C++ code.

10. **Address Potential Errors:** Consider common programming errors that might relate to the operations, such as incorrect assumptions about atomicity or issues with integer overflow.

11. **Synthesize the Summary:** Combine the observations into a concise summary, focusing on the main functions and their purposes.

12. **Review and Refine:**  Read through the generated summary to ensure accuracy and clarity. Make sure to address all the specific points raised in the user's prompt. For example, explicitly state that the file is C++ and not Torque.

By following these steps, we can arrive at a comprehensive and accurate description of the code's functionality. The process involves understanding the context, analyzing the structure and content, and making connections to the broader goals of the V8 JavaScript engine.
好的，这是对提供的 V8 源代码片段（第 3 部分）的功能归纳：

**功能归纳:**

这段 C++ 代码是 V8 JavaScript 引擎中 RISC-V 32 位架构的指令选择器的一部分 (`instruction-selector-riscv32.cc`)。它的主要功能是将高级的、与平台无关的中间代码（可能是来自 Turbofan 或 Turboshaft 编译器）转换为特定的 RISC-V 32 位机器指令。

具体来说，这段代码负责处理以下类型的操作：

* **原子操作 (Atomic Operations):**
    * 对 32 位整数执行原子加、减、与、或、异或操作。它根据操作数的类型（有符号或无符号，8位、16位或32位）选择相应的 RISC-V 指令。
    * 对 32 位整数对（可以看作是 64 位值）执行原子加载和存储操作。
    * 对 32 位整数对执行原子加、减、与、或、异或和交换操作。
    * 对 32 位整数对执行原子比较并交换操作。

* **成对整数操作 (Pairwise Integer Operations):**
    * 对 32 位整数对执行加法、减法和乘法操作。代码会检查结果的高 32 位是否被使用，如果未使用，则可能只发射标准的 32 位指令。
    * 将两个 32 位整数合并成一个 64 位值。
    * 将一个 64 位值中的一个 32 位通道替换为新的 32 位值。
    * 对 32 位整数对执行左移、右移（逻辑和算术）操作。

* **SIMD 浮点操作 (SIMD Floating-Point Operations):**
    * 对两个 64 位浮点数组成的向量执行最小值和最大值操作。这里使用了 RISC-V 的向量指令。

**与 JavaScript 功能的关系:**

这段代码直接关系到 JavaScript 中需要进行原子操作、处理 64 位整数或使用 SIMD 指令的场景。例如：

* **原子操作:**  JavaScript 的 `Atomics` API 允许在共享内存上执行原子操作。这段代码中的 `VisitWord32Atomic...` 和 `VisitWord32AtomicPair...` 函数就负责将 `Atomics` API 对应的操作转换为 RISC-V 指令。

```javascript
// JavaScript 示例：使用 Atomics 进行原子加法
const sab = new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT);
const view = new Int32Array(sab);
Atomics.add(view, 0, 5);
console.log(view[0]); // 输出：5
```

* **64 位整数模拟:**  虽然 JavaScript 的 `Number` 类型是双精度浮点数，但在某些情况下，V8 需要处理 64 位整数（例如，在内部表示或处理某些特定的 API 时）。这段代码中的 `VisitInt32Pair...` 函数处理了将两个 32 位整数作为一个 64 位值进行操作的情况。

```javascript
// JavaScript 示例：虽然 JavaScript 没有直接的 64 位整数类型，
// 但在某些底层操作中，V8 可能会将两个 32 位整数组合起来处理。
// 例如，BigInt 的底层实现可能会用到类似的机制。
const a = 0xFFFFFFFF;
const b = 0x00000001;
// 在 V8 内部，可能需要将 a 和 b 组合成一个 64 位值进行处理。
```

* **SIMD 操作:** JavaScript 的 `SIMD` API 允许进行单指令多数据操作。`VisitF64x2Min` 和 `VisitF64x2Max` 函数对应于 `SIMD.float64x2.min` 和 `SIMD.float64x2.max` 操作。

```javascript
// JavaScript 示例：使用 SIMD 进行浮点数比较
const a = SIMD.float64x2(1.0, 2.0);
const b = SIMD.float64x2(3.0, 1.5);
const min = SIMD.float64x2.min(a, b);
console.log(SIMD.extractLane(min, 0)); // 输出：1
console.log(SIMD.extractLane(min, 1)); // 输出：1.5
```

**代码逻辑推理 (假设输入与输出):**

假设有一个 `VisitWord32AtomicAdd` 函数的调用，其对应的中间代码节点表示一个对内存地址 `ptr` 的原子加 5 操作，且 `ptr` 中存储的是一个无符号 32 位整数。

* **假设输入:**
    * `node`: 代表原子加操作的中间代码节点。
    * `atomic_op.memory_rep`:  `MemoryRepresentation::Uint32()` (表示内存中的数据是无符号 32 位整数)。
    * `node->op()`:  代表原子加法操作。

* **代码逻辑推理:**
    1. 代码会进入 `if (atomic_op.memory_rep == MemoryRepresentation::Uint32())` 分支。
    2. `opcode` 会被设置为 `kAtomicAddWord32`。
    3. `VisitAtomicBinop` 函数会被调用，并根据 `kAtomicAddWord32` 生成相应的 RISC-V 原子加法指令（例如，`amoadd.w`）。

* **预期输出:**  生成的 RISC-V 指令会对 `ptr` 指向的内存地址执行原子加 5 的操作。

**用户常见的编程错误:**

与这段代码相关的用户常见编程错误可能包括：

* **不正确的原子操作使用:**  在多线程环境下，如果没有正确使用原子操作，可能会导致数据竞争和不一致性。

```javascript
// 错误示例：没有使用 Atomics 进行同步，可能导致数据竞争
let counter = 0;
function increment() {
  counter++; // 非原子操作
}

// 多个线程同时调用 increment 可能导致 counter 的值不正确
```

* **对齐问题:** 原子操作通常对内存地址的对齐有要求。如果传递给原子操作的地址未对齐，可能会导致程序崩溃或未定义的行为。虽然 V8 内部会处理这些问题，但理解对齐的概念对于理解底层原理很重要。

* **误解 SIMD 操作的特性:** 用户可能不理解 SIMD 操作是并行处理多个数据，如果数据量不适合或操作不当，可能无法充分利用 SIMD 的性能优势，甚至引入额外的复杂性。

**总结:**

这段代码是 V8 编译器后端的重要组成部分，它专注于将高级语言的原子操作、成对整数运算和 SIMD 浮点运算转换为高效的 RISC-V 32 位机器指令。这使得 V8 能够在 RISC-V 32 位架构上高效地执行需要这些特性的 JavaScript 代码。它处理了从基本原子操作到更复杂的成对运算和 SIMD 指令的选择和生成。

### 提示词
```
这是目录为v8/src/compiler/backend/riscv/instruction-selector-riscv32.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/riscv/instruction-selector-riscv32.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
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
```