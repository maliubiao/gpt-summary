Response:
Let's break down the thought process for analyzing the provided C++ code snippet.

1. **Identify the Core Purpose:** The file name `instruction-selector-riscv64.cc` and the namespace `v8::internal::compiler` immediately suggest this code is responsible for selecting RISC-V 64-bit instructions during the compilation process within the V8 JavaScript engine. The presence of templates with `TurbofanAdapter` and `TurboshaftAdapter` further hints at its integration with different compilation pipelines within V8.

2. **Examine the Structure:** The code is organized into template specializations of `InstructionSelectorT`. This tells us that the core logic is likely shared, but there are specific implementations depending on the `Adapter` type (Turbofan or Turboshaft). The functions are named `Visit...`, indicating they handle specific intermediate representation (IR) nodes in the compiler.

3. **Focus on Key Functionalities (and their patterns):**

    * **Atomic Operations:** A significant portion of the code deals with atomic operations (`VisitWord32AtomicExchange`, `VisitWord32AtomicCompareExchange`, `VisitWord32AtomicAdd`, etc.). Notice the consistent pattern:
        * Determine the data type (Int8, Uint8, Int16, Uint16, Int32, Uint32, Uint64).
        * Select the appropriate RISC-V opcode based on the data type (e.g., `kAtomicExchangeInt8`, `kRiscvWord64AtomicExchangeUint64`).
        * Call a generic `VisitAtomic...` function, passing the opcode and other parameters.
        * The `TurboshaftAdapter` and `TurbofanAdapter` have slight differences in how they access the data type information (through `AtomicRMWOp` and `AtomicOpParametersOf`, respectively).

    * **Sign Extension:**  Functions like `VisitSignExtendWord8ToInt64`, `VisitSignExtendWord16ToInt64`, and `VisitSignExtendWord32ToInt64` are clearly responsible for generating sign-extension instructions. The RISC-V specific opcodes (`kRiscvSignExtendByte`, `kRiscvSignExtendShort`) are used.

    * **Floating-Point SIMD (F64x2):** The `VisitF64x2Min` and `VisitF64x2Max` functions show how the instruction selector handles SIMD min/max operations for double-precision floating-point numbers. This involves generating sequences of RISC-V vector instructions (`kRiscvVmfeqVv`, `kRiscvVandVv`, `kRiscvVfminVv`, `kRiscvVfmaxVv`).

    * **Unsupported Operations:**  `VisitInt32AbsWithOverflow` and `VisitInt64AbsWithOverflow` have `UNREACHABLE()`, indicating that these specific operations might not be directly supported on the RISC-V architecture or are handled differently.

4. **Infer Relationships to JavaScript:**  Atomic operations, sign extension, and floating-point operations are all fundamental to how JavaScript works. JavaScript uses atomic operations for shared memory concurrency. Sign extension is necessary for handling different integer sizes. Floating-point numbers are a core data type. Therefore, this code directly contributes to the correct execution of JavaScript code on RISC-V.

5. **Consider the `.tq` Extension:**  The prompt specifically mentions `.tq`. While the provided snippet is `.cc`, it's important to acknowledge that `.tq` files in V8 are Torque files, used for generating C++ code. This is a potential point of confusion in the prompt itself, as the given code is definitely C++.

6. **Formulate Examples:** Based on the identified functionalities, construct concrete JavaScript examples that would trigger the code within this file. For instance, using `Atomics` in JavaScript would lead to the execution of the atomic operation handling code.

7. **Address Potential Errors:** Think about common programming mistakes that could relate to the functionalities. For atomic operations, race conditions are the most obvious example. For integer operations, overflow can be a concern (though the code explicitly marks some overflow operations as unsupported).

8. **Synthesize the Summary:**  Combine the individual observations into a concise summary of the file's purpose and key functionalities. Emphasize its role in the V8 compilation pipeline for the RISC-V architecture.

9. **Review and Refine:**  Read through the generated analysis to ensure clarity, accuracy, and completeness. Check if all parts of the prompt have been addressed. For instance, the prompt asks about code logic推理 (reasoning). This is present in how the code selects different opcodes based on the data type. The "假设输入与输出" (assuming input and output) aspect is addressed implicitly by describing the function of the `Visit...` methods – they take an IR node as input and produce RISC-V instructions as output.

This systematic approach, starting with identifying the high-level purpose and then drilling down into specific functionalities and their connections to JavaScript, allows for a comprehensive understanding of the given code snippet.
好的，我们来分析一下 `v8/src/compiler/backend/riscv/instruction-selector-riscv64.cc` 这个文件的功能。

**文件功能概览**

`v8/src/compiler/backend/riscv/instruction-selector-riscv64.cc` 是 V8 JavaScript 引擎中，针对 RISC-V 64 位架构的**指令选择器 (Instruction Selector)** 的源代码。

**核心功能：**

1. **将中间表示 (IR) 转换为 RISC-V 64 位机器指令:**  这是指令选择器的主要职责。它接收 V8 编译器生成的与平台无关的中间表示 (例如，来自 Turbofan 或 Turboshaft 的节点)，并将其转换为可以在 RISC-V 64 位处理器上执行的具体机器指令序列。

2. **处理特定的 IR 节点:** 文件中定义了多个 `Visit...` 函数（例如 `VisitWord32AtomicExchange`、`VisitF64x2Min` 等），每个函数负责处理一种或多种特定类型的 IR 节点。这些节点代表了各种操作，例如原子操作、算术运算、逻辑运算、内存访问、SIMD 操作等。

3. **针对 RISC-V 64 位架构进行优化:**  指令选择器会考虑 RISC-V 64 位架构的特性和指令集，选择最合适的指令来实现 IR 节点所表示的操作，以提高代码的执行效率。

4. **支持不同的编译器后端 (Turbofan 和 Turboshaft):** 从代码中可以看出，使用了模板 `InstructionSelectorT<Adapter>`，并针对 `TurbofanAdapter` 和 `TurboshaftAdapter` 进行了特化。这表明该指令选择器可以与 V8 的两个不同的编译器后端集成。

5. **处理原子操作:** 代码中包含了大量处理原子操作的函数，例如 `VisitWord32AtomicExchange`、`VisitWord32AtomicCompareExchange`、`VisitWord32AtomicAdd` 等。这些函数确保在多线程环境下对共享内存的访问是安全的。

6. **处理 SIMD 指令:**  代码中包含了处理 SIMD (Single Instruction, Multiple Data) 指令的函数，例如 `VisitF64x2Min` 和 `VisitF64x2Max`，用于处理 128 位（两个 64 位浮点数）的向量运算。

7. **处理符号扩展:**  代码中包含了处理符号扩展的函数，例如 `VisitSignExtendWord8ToInt64`，用于将较小的数据类型扩展到更大的数据类型，并保持其符号。

**关于 `.tq` 扩展名:**

如果 `v8/src/compiler/backend/riscv/instruction-selector-riscv64.cc` 以 `.tq` 结尾，那么它就是一个 **V8 Torque 源代码**。 Torque 是 V8 用于生成高效 C++ 代码的领域特定语言。  当前的 `.cc` 结尾表明它是直接编写的 C++ 代码。

**与 JavaScript 的功能关系 (并用 JavaScript 举例说明):**

该文件直接关系到 JavaScript 代码在 RISC-V 64 位架构上的执行效率和正确性。当 V8 编译 JavaScript 代码时，指令选择器会将高级的 JavaScript 操作转换为底层的机器指令。

**JavaScript 示例:**

```javascript
// 原子操作示例
const sab = new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT * 2);
const ia = new Int32Array(sab);

Atomics.add(ia, 0, 5); // 对索引 0 的元素原子地加 5

// SIMD 操作示例 (需要启用实验性特性)
// const a = Float64x2(1.0, 2.0);
// const b = Float64x2(3.0, 4.0);
// const min = Math.fround(Math.min(a.x, b.x)), Math.fround(Math.min(a.y, b.y)));

// 类型转换和符号扩展的隐式使用
let smallInt = 10; // 内部表示可能是一个较小的整数类型
let bigInt = smallInt; // JavaScript 会自动进行类型转换，可能涉及符号扩展
```

* 当 JavaScript 代码中使用 `Atomics` 对象进行原子操作时，`VisitWord32Atomic...` 系列的函数会被调用，生成相应的 RISC-V 原子指令。
* 当 JavaScript 代码执行涉及到 SIMD 操作（如果底层硬件和 V8 支持）时，`VisitF64x2Min` 和 `VisitF64x2Max` 等函数会被调用，生成 RISC-V 的 SIMD 指令。
* 当 JavaScript 中的数值类型在内部表示中需要进行转换（例如，从小整数转换为大整数）时，`VisitSignExtend...` 系列的函数会被调用，确保符号的正确性。

**代码逻辑推理 (假设输入与输出):**

**假设输入:** 一个表示原子加法操作的 IR 节点，操作数为两个寄存器，目标内存地址在一个寄存器中，数据类型为 `MachineType::Int32()`。

**预期输出:**  一段 RISC-V 汇编指令，执行以下操作：

1. 从目标内存地址加载一个 32 位整数值到寄存器。
2. 将另一个寄存器中的值加到加载的值上。
3. 将结果原子地写回目标内存地址。

具体生成的指令可能会是类似以下形式（简化表示）：

```assembly
amoadd.w.aq rl, rs2, (rs1)  // 原子加法指令
```

其中 `rs1` 包含目标内存地址，`rs2` 包含要加的值，`rl` 包含加载和存储的寄存器。

**涉及用户常见的编程错误:**

1. **在多线程环境中使用共享内存但没有进行适当的同步:** 这会导致数据竞争和未定义的行为。`v8/src/compiler/backend/riscv/instruction-selector-riscv64.cc` 中处理原子操作的代码，配合 JavaScript 的 `Atomics` API，可以帮助开发者避免这类错误。

   ```javascript
   // 错误示例：多线程环境下的数据竞争
   let counter = 0;

   // 线程 1
   for (let i = 0; i < 10000; i++) {
     counter++;
   }

   // 线程 2
   for (let i = 0; i < 10000; i++) {
     counter++;
   }

   // 最终 counter 的值可能不是 20000

   // 正确示例：使用原子操作
   const sab = new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT);
   const ia = new Int32Array(sab);

   // 线程 1
   for (let i = 0; i < 10000; i++) {
     Atomics.add(ia, 0, 1);
   }

   // 线程 2
   for (let i = 0; i < 10000; i++) {
     Atomics.add(ia, 0, 1);
   }

   // 最终 ia[0] 的值一定是 20000
   ```

2. **对不同大小的整数进行操作时，没有考虑到符号扩展:** 这可能导致意外的结果，尤其是在进行位运算或比较操作时。虽然 JavaScript 引擎会尽力处理类型转换，但理解底层的符号扩展机制有助于避免潜在的错误。

   ```javascript
   let signedByte = -10; // 8 位有符号整数，二进制表示可能是 11110110
   let integer = signedByte; // 隐式转换为 32 位整数

   console.log(integer); // 输出 -10，因为进行了符号扩展，高位用 1 填充

   let unsignedByte = 246; // 8 位无符号整数，二进制表示 11110110
   integer = unsignedByte;

   console.log(integer); // 输出 246，高位用 0 填充
   ```

**归纳一下它的功能 (第 5 部分，共 5 部分):**

作为系列的一部分，`v8/src/compiler/backend/riscv/instruction-selector-riscv64.cc` 的主要功能是 **V8 编译器后端针对 RISC-V 64 位架构进行指令选择的关键组件**。它负责将中间表示的抽象操作转换为具体的、高效的 RISC-V 机器指令。这包括处理各种类型的操作，例如原子操作、SIMD 运算、符号扩展等，并确保生成的代码能够在 RISC-V 64 位处理器上正确、高效地执行 JavaScript 代码。该文件是 V8 引擎支持 RISC-V 64 位架构的重要组成部分。

Prompt: 
```
这是目录为v8/src/compiler/backend/riscv/instruction-selector-riscv64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/riscv/instruction-selector-riscv64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共5部分，请归纳一下它的功能

"""
int8;
  } else if (params.type() == MachineType::Uint16()) {
    opcode = kAtomicExchangeUint16;
  } else if (params.type() == MachineType::Uint32()) {
    opcode = kAtomicExchangeWord32;
  } else if (params.type() == MachineType::Uint64()) {
    opcode = kRiscvWord64AtomicExchangeUint64;
  } else {
    UNREACHABLE();
  }
  VisitAtomicExchange(this, node, opcode, AtomicWidth::kWord64, params.kind());
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
void InstructionSelectorT<TurbofanAdapter>::VisitWord32AtomicCompareExchange(
    Node* node) {
  ArchOpcode opcode;
  AtomicOpParameters params = AtomicOpParametersOf(node->op());
  if (params.type() == MachineType::Int8()) {
    opcode = kAtomicCompareExchangeInt8;
  } else if (params.type() == MachineType::Uint8()) {
    opcode = kAtomicCompareExchangeUint8;
  } else if (params.type() == MachineType::Int16()) {
    opcode = kAtomicCompareExchangeInt16;
  } else if (params.type() == MachineType::Uint16()) {
    opcode = kAtomicCompareExchangeUint16;
  } else if (params.type() == MachineType::Int32() ||
             params.type() == MachineType::Uint32()) {
    opcode = kAtomicCompareExchangeWord32;
  } else {
    UNREACHABLE();
  }

  VisitAtomicCompareExchange(this, node, opcode, AtomicWidth::kWord32,
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
    opcode = kRiscvWord64AtomicCompareExchangeUint64;
  } else {
    UNREACHABLE();
  }
  VisitAtomicCompareExchange(this, node, opcode, AtomicWidth::kWord64,
                             atomic_op.memory_access_kind);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitWord64AtomicCompareExchange(
    Node* node) {
  ArchOpcode opcode;
  AtomicOpParameters params = AtomicOpParametersOf(node->op());
  if (params.type() == MachineType::Uint8()) {
    opcode = kAtomicCompareExchangeUint8;
  } else if (params.type() == MachineType::Uint16()) {
    opcode = kAtomicCompareExchangeUint16;
  } else if (params.type() == MachineType::Uint32()) {
    opcode = kAtomicCompareExchangeWord32;
  } else if (params.type() == MachineType::Uint64()) {
    opcode = kRiscvWord64AtomicCompareExchangeUint64;
  } else {
    UNREACHABLE();
  }
  VisitAtomicCompareExchange(this, node, opcode, AtomicWidth::kWord64,
                             params.kind());
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicBinaryOperation(
    node_t node, ArchOpcode int8_op, ArchOpcode uint8_op, ArchOpcode int16_op,
    ArchOpcode uint16_op, ArchOpcode word32_op) {
  if constexpr (Adapter::IsTurboshaft) {
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
  } else {
    ArchOpcode opcode;
    AtomicOpParameters params = AtomicOpParametersOf(node->op());
    if (params.type() == MachineType::Int8()) {
      opcode = int8_op;
    } else if (params.type() == MachineType::Uint8()) {
      opcode = uint8_op;
    } else if (params.type() == MachineType::Int16()) {
      opcode = int16_op;
    } else if (params.type() == MachineType::Uint16()) {
      opcode = uint16_op;
    } else if (params.type() == MachineType::Int32() ||
               params.type() == MachineType::Uint32()) {
      opcode = word32_op;
    } else {
      UNREACHABLE();
    }

    VisitAtomicBinop(this, node, opcode, AtomicWidth::kWord32, params.kind());
  }
}

#define VISIT_ATOMIC_BINOP(op)                                             \
  template <typename Adapter>                                              \
  void InstructionSelectorT<Adapter>::VisitWord32Atomic##op(node_t node) { \
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
void InstructionSelectorT<Adapter>::VisitWord64AtomicBinaryOperation(
    node_t node, ArchOpcode uint8_op, ArchOpcode uint16_op,
    ArchOpcode uint32_op, ArchOpcode uint64_op) {
  if constexpr (Adapter::IsTurboshaft) {
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
      opcode = uint64_op;
    } else {
      UNREACHABLE();
    }
    VisitAtomicBinop(this, node, opcode, AtomicWidth::kWord64,
                     atomic_op.memory_access_kind);
  } else {
    ArchOpcode opcode;
    AtomicOpParameters params = AtomicOpParametersOf(node->op());
    if (params.type() == MachineType::Uint8()) {
      opcode = uint8_op;
    } else if (params.type() == MachineType::Uint16()) {
      opcode = uint16_op;
    } else if (params.type() == MachineType::Uint32()) {
      opcode = uint32_op;
    } else if (params.type() == MachineType::Uint64()) {
      opcode = uint64_op;
    } else {
      UNREACHABLE();
    }
    VisitAtomicBinop(this, node, opcode, AtomicWidth::kWord64, params.kind());
  }
}

#define VISIT_ATOMIC_BINOP(op)                                                \
  template <typename Adapter>                                                 \
  void InstructionSelectorT<Adapter>::VisitWord64Atomic##op(node_t node) {    \
      VisitWord64AtomicBinaryOperation(                                       \
          node, kAtomic##op##Uint8, kAtomic##op##Uint16, kAtomic##op##Word32, \
          kRiscvWord64Atomic##op##Uint64);                                    \
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

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitSignExtendWord8ToInt64(node_t node) {
    RiscvOperandGeneratorT<Adapter> g(this);
    Emit(kRiscvSignExtendByte, g.DefineAsRegister(node),
         g.UseRegister(this->input_at(node, 0)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitSignExtendWord16ToInt64(node_t node) {
    RiscvOperandGeneratorT<Adapter> g(this);
    Emit(kRiscvSignExtendShort, g.DefineAsRegister(node),
         g.UseRegister(this->input_at(node, 0)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitSignExtendWord32ToInt64(node_t node) {
    EmitSignExtendWord(this, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF64x2Min(node_t node) {
    RiscvOperandGeneratorT<Adapter> g(this);
    InstructionOperand temp1 = g.TempFpRegister(v0);
    InstructionOperand temp2 = g.TempFpRegister(kSimd128ScratchReg);
    InstructionOperand mask_reg = g.TempFpRegister(v0);
    this->Emit(kRiscvVmfeqVv, temp1, g.UseRegister(this->input_at(node, 0)),
               g.UseRegister(this->input_at(node, 0)), g.UseImmediate(E64),
               g.UseImmediate(m1));
    this->Emit(kRiscvVmfeqVv, temp2, g.UseRegister(this->input_at(node, 1)),
               g.UseRegister(this->input_at(node, 1)), g.UseImmediate(E64),
               g.UseImmediate(m1));
    this->Emit(kRiscvVandVv, mask_reg, temp2, temp1, g.UseImmediate(E64),
               g.UseImmediate(m1));

    InstructionOperand NaN = g.TempFpRegister(kSimd128ScratchReg);
    InstructionOperand result = g.TempFpRegister(kSimd128ScratchReg);
    this->Emit(kRiscvVmv, NaN, g.UseImmediate64(0x7ff8000000000000L),
               g.UseImmediate(E64), g.UseImmediate(m1));
    this->Emit(kRiscvVfminVv, result, g.UseRegister(this->input_at(node, 1)),
               g.UseRegister(this->input_at(node, 0)), g.UseImmediate(E64),
               g.UseImmediate(m1), g.UseImmediate(MaskType::Mask));
    this->Emit(kRiscvVmv, g.DefineAsRegister(node), result, g.UseImmediate(E64),
               g.UseImmediate(m1));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF64x2Max(node_t node) {
    RiscvOperandGeneratorT<Adapter> g(this);
    InstructionOperand temp1 = g.TempFpRegister(v0);
    InstructionOperand temp2 = g.TempFpRegister(kSimd128ScratchReg);
    InstructionOperand mask_reg = g.TempFpRegister(v0);
    this->Emit(kRiscvVmfeqVv, temp1, g.UseRegister(this->input_at(node, 0)),
               g.UseRegister(this->input_at(node, 0)), g.UseImmediate(E64),
               g.UseImmediate(m1));
    this->Emit(kRiscvVmfeqVv, temp2, g.UseRegister(this->input_at(node, 1)),
               g.UseRegister(this->input_at(node, 1)), g.UseImmediate(E64),
               g.UseImmediate(m1));
    this->Emit(kRiscvVandVv, mask_reg, temp2, temp1, g.UseImmediate(E64),
               g.UseImmediate(m1));

    InstructionOperand NaN = g.TempFpRegister(kSimd128ScratchReg);
    InstructionOperand result = g.TempFpRegister(kSimd128ScratchReg);
    this->Emit(kRiscvVmv, NaN, g.UseImmediate64(0x7ff8000000000000L),
               g.UseImmediate(E64), g.UseImmediate(m1));
    this->Emit(kRiscvVfmaxVv, result, g.UseRegister(this->input_at(node, 1)),
               g.UseRegister(this->input_at(node, 0)), g.UseImmediate(E64),
               g.UseImmediate(m1), g.UseImmediate(MaskType::Mask));
    this->Emit(kRiscvVmv, g.DefineAsRegister(node), result, g.UseImmediate(E64),
               g.UseImmediate(m1));
}

// template <typename Adapter>
// void InstructionSelectorT<Adapter>::Comment(const std::string msg){
//     RiscvOperandGeneratorT<Adapter> g(this);
//     if (!v8_flags.code_comments) return;
//     int64_t length = msg.length() + 1;
//     char* zone_buffer =
//     reinterpret_cast<char*>(this->isolate()->array_buffer_allocator()->Allocate(length));
//     memset(zone_buffer, '\0', length);
//     MemCopy(zone_buffer, msg.c_str(), length);
//     using ptrsize_int_t =
//         std::conditional<kSystemPointerSize == 8, int64_t, int32_t>::type;
//     InstructionOperand operand = this->sequence()->AddImmediate(
//         Constant{reinterpret_cast<ptrsize_int_t>(zone_buffer)});
//     InstructionOperand inputs[2];
//     inputs[0] = operand;
//     inputs[1] = g.UseImmediate64(length);
//     this->Emit(kArchComment, 0, nullptr, 1, inputs);
// }

// static
MachineOperatorBuilder::Flags
InstructionSelector::SupportedMachineOperatorFlags() {
  MachineOperatorBuilder::Flags flags = MachineOperatorBuilder::kNoFlags;
  return flags | MachineOperatorBuilder::kWord32Ctz |
         MachineOperatorBuilder::kWord64Ctz |
         MachineOperatorBuilder::kWord32Popcnt |
         MachineOperatorBuilder::kWord64Popcnt |
         MachineOperatorBuilder::kWord32ShiftIsSafe |
         MachineOperatorBuilder::kInt32DivIsSafe |
         MachineOperatorBuilder::kUint32DivIsSafe |
         MachineOperatorBuilder::kFloat64RoundDown |
         MachineOperatorBuilder::kFloat32RoundDown |
         MachineOperatorBuilder::kFloat64RoundUp |
         MachineOperatorBuilder::kFloat32RoundUp |
         MachineOperatorBuilder::kFloat64RoundTruncate |
         MachineOperatorBuilder::kFloat32RoundTruncate |
         MachineOperatorBuilder::kFloat64RoundTiesEven |
         MachineOperatorBuilder::kFloat32RoundTiesEven;
}

template class EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE)
    InstructionSelectorT<TurbofanAdapter>;
template class EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE)
    InstructionSelectorT<TurboshaftAdapter>;
}  // namespace compiler
}  // namespace internal
}  // namespace v8

"""


```