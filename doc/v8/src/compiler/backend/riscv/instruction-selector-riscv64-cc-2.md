Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/compiler/backend/riscv/instruction-selector-riscv64.cc`.

Here's a breakdown of the thought process to generate the response:

1. **Identify the core purpose:** The filename and the content immediately suggest this code is responsible for *instruction selection* for the RISC-V 64-bit architecture within the V8 compiler. Instruction selection is the process of mapping high-level intermediate representation (IR) operations to specific machine instructions.

2. **Analyze the code structure:** The code consists mainly of template functions within a class named `InstructionSelectorT`. The template parameter `Adapter` suggests different strategies or contexts for instruction selection (e.g., for the Turbofan or Turboshaft pipelines). There are numerous `Visit...` methods, each handling a specific IR operation (like `kLoad`, `kChangeUint32ToUint64`, `kTruncateInt64ToInt32`, etc.). This indicates a pattern of handling various IR node types.

3. **Group functionalities by type of operation:**  Observing the `Visit...` methods reveals categories of operations:
    * **Loads:** Handling different load sizes (8-bit, 16-bit, 32-bit, 64-bit), signed/unsigned variations, and tagged values. The presence of `VisitUnalignedLoad` and `VisitAtomicLoad` highlights special cases.
    * **Stores:** Although not explicitly in this snippet, the code mentions `EmitStoreToStackSlot`, and the context strongly implies the full file handles stores similarly to loads. The `VisitUnalignedStore` and `VisitAtomicStore` reinforce this.
    * **Type Conversions:** Functions like `VisitChangeUint32ToUint64`, `VisitTruncateInt64ToInt32`, and `VisitBitcast...` demonstrate handling of conversions between different data types (integers, floats).
    * **Floating-point Operations:** The `VisitRound...`, `VisitFloat...Binop`, and `VisitFloat...Unop` methods clearly deal with floating-point arithmetic and conversions.
    * **Function Calls:** The `EmitPrepareArguments` function shows how function call setup is handled on RISC-V.
    * **Comparisons:** The `VisitWord32Compare` and `VisitWord64Compare` functions demonstrate how comparisons are translated to RISC-V instructions, paying attention to signedness.
    * **Atomic Operations:** The presence of `VisitAtomicLoad` and `VisitAtomicStore` indicates support for atomic memory operations.

4. **Address specific questions from the prompt:**
    * **File extension:** The code is C++, not Torque, so it won't have a `.tq` extension.
    * **Relationship to JavaScript:**  While this C++ code isn't *directly* JavaScript, it's a crucial part of the V8 JavaScript engine. It's responsible for taking the optimized representation of JavaScript code and generating the actual machine code that runs it. Examples can be drawn by showing JavaScript code and then explaining what kind of operations in the IR might be generated from it.
    * **Code Logic Reasoning:** The comparison section offers an example of conditional logic based on signedness. We can create a hypothetical input and expected output based on this.
    * **Common Programming Errors:** Type mismatches are a common source of errors that this code addresses. Showing a JavaScript example where an implicit conversion occurs can illustrate this.

5. **Synthesize a summary:** Combine the identified functionalities into a concise summary, addressing the user's request for a high-level overview.

6. **Review and refine:** Ensure the explanation is clear, accurate, and addresses all parts of the user's prompt. For instance, initially, I focused too much on individual functions. Refining the summary to focus on the broader *categories* of operations makes it more understandable. Also, explicitly stating that it's part of the V8 compiler and not directly JavaScript code is important.
`v8/src/compiler/backend/riscv/instruction-selector-riscv64.cc` 的代码片段主要负责 **为 RISC-V 64位架构选择合适的机器指令**，这是 V8 编译器的后端代码生成阶段的关键部分。  它将中间表示 (IR) 的操作转换为 RISC-V 汇编指令。

**功能归纳：**

这个代码片段主要涉及以下几个方面的功能：

1. **加载指令选择 (Load Instruction Selection):**
   - 根据要加载的数据类型 (`MachineRepresentation`)，选择合适的 RISC-V 加载指令，例如 `lb` (load byte), `lbu` (load byte unsigned), `lh` (load half-word), `lhu` (load half-word unsigned), `lw` (load word), `ld` (load double-word)。
   - 针对不同的数据类型（如 8位、16位、32位、64位整数，以及 `Tagged` 指针类型），选择不同的加载指令。
   - 特别处理了 `kWord32` 和 `kWord64`，指出在 RV64 架构下，`lw` 指令会加载 32 位并进行符号扩展到 64 位。
   - 调用 `EmitLoad` 函数来实际生成加载指令。

2. **零扩展判断 (Zero Extension Check):**
   - `ZeroExtendsWord32ToWord64NoPhis` 函数用于判断一个 32 位的值是否需要零扩展到 64 位，而不需要额外的 `Phi` 节点。
   - 主要检查 `Load` 和 `LoadImmutable` 操作，并且加载的是无符号的 8 位或 16 位数据。
   - 这在优化场景中很有用，可以避免不必要的零扩展操作。

3. **类型转换指令选择 (Type Conversion Instruction Selection):**
   - `VisitChangeUint32ToUint64`: 将 32 位无符号整数转换为 64 位无符号整数。如果输入已经是零扩展的，则生成 `nop` 指令；否则，生成 `kRiscvZeroExtendWord` 指令。
   - `VisitTruncateInt64ToInt32`: 将 64 位整数截断为 32 位整数。
     - 尝试覆盖某些特定的操作序列，如右移操作 (`kWord64Sar`)，并尝试生成更优化的加载指令 (`TryEmitExtendingLoad`)。
     - 对于一般的截断操作，生成 `kRiscvSignExtendWord` 指令，尽管注释提到 RISC-V 的 `ext` 指令是零扩展，但此处为了语义明确进行了符号扩展。
   - `VisitRoundInt64ToFloat32`, `VisitRoundInt64ToFloat64`, `VisitRoundUint64ToFloat32`, `VisitRoundUint64ToFloat64`:  选择将整数转换为浮点数的指令。
   - `VisitBitcastFloat32ToInt32`, `VisitBitcastFloat64ToInt64`, `VisitBitcastInt32ToFloat32`, `VisitBitcastInt64ToFloat64`: 选择用于位转换的指令，不改变数据的二进制表示。

4. **浮点运算指令选择 (Floating-Point Operation Instruction Selection):**
   - `VisitFloat...Round...`: 选择不同的浮点数舍入指令。
   - `VisitFloat...Neg`: 选择浮点数取反指令。
   - `VisitFloat64Ieee754Binop`, `VisitFloat64Ieee754Unop`: 处理 IEEE 754 标准的浮点二元和一元操作，通常会标记为函数调用 (`MarkAsCall`)。

5. **函数调用参数准备 (Function Call Argument Preparation):**
   - `EmitPrepareArguments`:  为 C 函数调用或 JavaScript 函数调用准备参数。
   - 对于 C 函数调用，会计算通用寄存器和浮点寄存器参数的数量，并可能将参数推入栈中。
   - 对于 JavaScript 函数调用，会在栈上分配空间来存储参数。

6. **非对齐内存访问指令选择 (Unaligned Memory Access Instruction Selection):**
   - `VisitUnalignedLoad`: 处理非对齐内存加载，选择 `kRiscvULoadFloat`, `kRiscvULoadDouble`, `kRiscvLbu`, `kRiscvUlhu`, `kRiscvUlw`, `kRiscvUld` 等指令。
   - `VisitUnalignedStore`: 处理非对齐内存存储，选择 `kRiscvUStoreFloat`, `kRiscvUStoreDouble`, `kRiscvSb`, `kRiscvUsh`, `kRiscvUsw`, `kRiscvUsd` 等指令。
   - 根据索引是否能作为立即数，选择不同的寻址模式。

7. **原子操作指令选择 (Atomic Operation Instruction Selection):**
   - `VisitAtomicLoad`: 选择原子加载指令，例如 `kAtomicLoadInt8`, `kAtomicLoadUint8`, `kAtomicLoadInt16`, `kAtomicLoadUint16`, `kAtomicLoadWord32`, `kRiscvWord64AtomicLoadUint64` 等。
   - `VisitAtomicStore`: 选择原子存储指令，例如 `kAtomicStoreWord8`, `kAtomicStoreWord16`, `kAtomicStoreWord32`, `kRiscvWord64AtomicStoreWord64`，以及带有写屏障的 `kArchAtomicStoreWithWriteBarrier`。

8. **比较指令选择 (Comparison Instruction Selection):**
   - `VisitWord32Compare`: 处理 32 位整数的比较。由于 RISC-V 没有直接的 32 位比较指令，通常会使用 64 位比较。代码中包含了一些针对有符号和无符号数比较的特殊处理，以保证语义正确。
   - `VisitWord64Compare`: 处理 64 位整数的比较，选择 `kRiscvCmp` 指令。

**关于文件扩展名和 Torque：**

代码片段显示的是 C++ 代码，因此 `v8/src/compiler/backend/riscv/instruction-selector-riscv64.cc` 不会以 `.tq` 结尾。 `.tq` 结尾的文件是 V8 的 Torque 语言源代码，用于定义内置函数和类型系统。

**与 JavaScript 功能的关系及示例：**

`v8/src/compiler/backend/riscv/instruction-selector-riscv64.cc` 的功能是直接服务于 JavaScript 代码的执行。当 V8 执行 JavaScript 代码时，它会先将 JavaScript 代码编译成中间表示 (IR)。然后，指令选择器会将这些 IR 操作转换成目标架构（这里是 RISC-V 64位）的机器指令。

**示例：**

```javascript
// JavaScript 代码
let a = 10;
let b = 20;
let c = a + b;
console.log(c);

let unsignedInt = 4294967290; // 一个大的无符号 32 位整数
let longUnsignedInt = unsignedInt; // 隐式转换为 64 位

let floatValue = 3.14;
let intValue = Math.round(floatValue);
```

**对应的指令选择 (简化说明)：**

* **`let a = 10;`**:  可能会生成将立即数 10 加载到寄存器的指令。
* **`let c = a + b;`**: 可能会生成加载 `a` 和 `b` 的值到寄存器，然后执行加法操作的 RISC-V 指令。
* **`let longUnsignedInt = unsignedInt;`**:  `VisitChangeUint32ToUint64` 函数会被调用，生成将 32 位无符号整数零扩展到 64 位的 RISC-V 指令 (`kRiscvZeroExtendWord`)。
* **`let intValue = Math.round(floatValue);`**:  可能会调用浮点数舍入函数，`VisitFloat64RoundTiesEven` (或其他舍入模式) 可能会被调用，生成相应的 RISC-V 浮点舍入指令。
* **内存加载 (`console.log(c)`)**: 当需要访问变量 `c` 的值时，如果 `c` 存储在内存中，则会调用类似于 `EmitLoad` 的函数来生成加载指令。

**代码逻辑推理及假设输入输出：**

**假设输入:** 一个 IR 节点，表示要加载一个 16 位无符号整数。
```c++
// 假设的 IR 节点结构
struct IRNode {
  IrOpcode opcode; // IrOpcode::kLoad
  MachineRepresentation representation; // MachineRepresentation::kWord16
  bool isUnsigned; // true
  // ... 其他信息
};

IRNode loadNode;
loadNode.opcode = IrOpcode::kLoad;
loadNode.representation = MachineRepresentation::kWord16;
loadNode.isUnsigned = true;
```

**代码逻辑 (从片段中推断):**

```c++
// ... 在 VisitLoad 函数中 ...
case MachineRepresentation::kWord16:
  opcode = load_rep.IsUnsigned() ? kRiscvLhu : kRiscvLh;
  break;
```

**假设输出:**  `opcode` 变量将被赋值为 `kRiscvLhu` (load half-word unsigned)。

**用户常见的编程错误及示例：**

1. **类型不匹配导致的截断或扩展问题：**

   ```javascript
   let bigNumber = 9007199254740991; // 大于 32 位有符号整数的最大值
   let smallInt = bigNumber; // 可能被隐式截断为 32 位整数

   let smallNumber = -10;
   let unsignedSmall = smallNumber >>> 0; // 将有符号数转换为无符号数
   ```

   在编译这些代码时，指令选择器需要处理不同大小和符号的整数之间的转换。例如，将 `bigNumber` 赋值给 `smallInt` 可能涉及到 `VisitTruncateInt64ToInt32`，而将 `smallNumber` 转换为无符号数可能涉及到零扩展操作。如果程序员不注意类型溢出或符号问题，可能会导致意想不到的结果。

2. **非对齐内存访问：**

   虽然现代处理器通常可以处理非对齐访问，但可能会有性能损失或在某些架构上导致错误。程序员可能会无意中创建非对齐的内存访问模式，例如通过不正确的类型转换或指针操作。`VisitUnalignedLoad` 和 `VisitUnalignedStore` 的存在表明 V8 需要处理这种情况。

**总结 `v8/src/compiler/backend/riscv/instruction-selector-riscv64.cc` 的功能 (第3部分):**

这部分代码主要负责 **将 IR 图中的加载、类型转换、浮点运算、函数调用参数准备、非对齐内存访问以及原子操作节点转换为 RISC-V 64位架构的机器指令**。它根据操作的类型和涉及的数据类型选择最合适的 RISC-V 指令，并处理一些特殊的优化场景，例如零扩展。 这段代码是 V8 编译器后端代码生成阶段的核心组成部分，直接影响 JavaScript 代码在 RISC-V 架构上的执行效率和正确性。

Prompt: 
```
这是目录为v8/src/compiler/backend/riscv/instruction-selector-riscv64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/riscv/instruction-selector-riscv64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共5部分，请归纳一下它的功能

"""
chineRepresentation::kWord8:
          opcode = load_rep.IsUnsigned() ? kRiscvLbu : kRiscvLb;
          break;
        case MachineRepresentation::kWord16:
          opcode = load_rep.IsUnsigned() ? kRiscvLhu : kRiscvLh;
          break;
        case MachineRepresentation::kWord32:
        case MachineRepresentation::kWord64:
          // Since BitcastElider may remove nodes of
          // IrOpcode::kTruncateInt64ToInt32 and directly use the inputs, values
          // with kWord64 can also reach this line.
          // For RV64, the lw loads a 32 bit value from memory and sign-extend
          // it to 64 bits before storing it in rd register
        case MachineRepresentation::kTaggedSigned:
        case MachineRepresentation::kTagged:
          opcode = kRiscvLw;
          break;
        default:
          UNREACHABLE();
      }
      EmitLoad(this, value, opcode, node);
    } else {
      EmitSignExtendWord(this, node);
      return;
    }
  }
}

template <typename Adapter>
bool InstructionSelectorT<Adapter>::ZeroExtendsWord32ToWord64NoPhis(
    node_t node) {
    DCHECK_NE(node->opcode(), IrOpcode::kPhi);
    if (node->opcode() == IrOpcode::kLoad ||
        node->opcode() == IrOpcode::kLoadImmutable) {
      LoadRepresentation load_rep = LoadRepresentationOf(node->op());
      if (load_rep.IsUnsigned()) {
        switch (load_rep.representation()) {
          case MachineRepresentation::kWord8:
          case MachineRepresentation::kWord16:
            return true;
          default:
            return false;
        }
      }
    }

    // All other 32-bit operations sign-extend to the upper 32 bits
    return false;
}

template <>
bool InstructionSelectorT<TurboshaftAdapter>::ZeroExtendsWord32ToWord64NoPhis(
    node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  DCHECK(!this->Get(node).Is<PhiOp>());
  const Operation& op = this->Get(node);
  if (op.opcode == Opcode::kLoad) {
    auto load = this->load_view(node);
    LoadRepresentation load_rep = load.loaded_rep();
    if (load_rep.IsUnsigned()) {
      switch (load_rep.representation()) {
        case MachineRepresentation::kWord8:
        case MachineRepresentation::kWord16:
          return true;
        default:
          return false;
      }
    }
  }
  // All other 32-bit operations sign-extend to the upper 32 bits
  return false;
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitChangeUint32ToUint64(node_t node) {
    RiscvOperandGeneratorT<Adapter> g(this);
    node_t value = this->input_at(node, 0);
    if (ZeroExtendsWord32ToWord64(value)) {
      Emit(kArchNop, g.DefineSameAsFirst(node), g.Use(value));
      return;
    }
    Emit(kRiscvZeroExtendWord, g.DefineAsRegister(node), g.UseRegister(value));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTruncateInt64ToInt32(node_t node) {
    RiscvOperandGeneratorT<Adapter> g(this);
    Node* value = this->input_at(node, 0);
    if (CanCover(node, value)) {
      switch (value->opcode()) {
        case IrOpcode::kWord64Sar: {
          if (CanCover(value, value->InputAt(0)) &&
              TryEmitExtendingLoad(this, value, node)) {
            return;
          } else {
            Int64BinopMatcher m(value);
            if (m.right().IsInRange(32, 63)) {
              // After smi untagging no need for truncate. Combine sequence.
              Emit(kRiscvSar64, g.DefineSameAsFirst(node),
                   g.UseRegister(m.left().node()),
                   g.UseImmediate(m.right().node()));
              return;
            }
          }
          break;
        }
        default:
          break;
      }
    }
    // Semantics of this machine IR is not clear. For example, x86 zero-extend
    // the truncated value; arm treats it as nop thus the upper 32-bit as
    // undefined; Riscv emits ext instruction which zero-extend the 32-bit
    // value; for riscv, we do sign-extension of the truncated value
    Emit(kRiscvSignExtendWord, g.DefineAsRegister(node),
         g.UseRegister(this->input_at(node, 0)), g.TempImmediate(0));
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitTruncateInt64ToInt32(
    node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  RiscvOperandGeneratorT<TurboshaftAdapter> g(this);
  auto value = input_at(node, 0);
  if (CanCover(node, value)) {
    if (Get(value).Is<Opmask::kWord64ShiftRightArithmetic>()) {
      auto shift_value = input_at(value, 1);
      if (CanCover(value, input_at(value, 0)) &&
          TryEmitExtendingLoad(this, value, node)) {
        return;
      } else if (g.IsIntegerConstant(shift_value)) {
        auto constant = constant_view(shift_value);
        if (constant.is_int64()) {
          if (constant.int64_value() <= 63 && constant.int64_value() >= 32) {
            // After smi untagging no need for truncate. Combine sequence.
            Emit(kRiscvSar64, g.DefineSameAsFirst(node),
                 g.UseRegister(input_at(value, 0)), g.UseImmediate(constant));
            return;
          }
        }
      }
    }
  }
  // Semantics of this machine IR is not clear. For example, x86 zero-extend
  // the truncated value; arm treats it as nop thus the upper 32-bit as
  // undefined; Riscv emits ext instruction which zero-extend the 32-bit
  // value; for riscv, we do sign-extension of the truncated value
  Emit(kRiscvSignExtendWord, g.DefineAsRegister(node), g.UseRegister(value),
       g.TempImmediate(0));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitRoundInt64ToFloat32(node_t node) {
    VisitRR(this, kRiscvCvtSL, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitRoundInt64ToFloat64(node_t node) {
    VisitRR(this, kRiscvCvtDL, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitRoundUint64ToFloat32(node_t node) {
    VisitRR(this, kRiscvCvtSUl, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitRoundUint64ToFloat64(node_t node) {
    VisitRR(this, kRiscvCvtDUl, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitBitcastFloat32ToInt32(node_t node) {
    VisitRR(this, kRiscvBitcastFloat32ToInt32, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitBitcastFloat64ToInt64(node_t node) {
    VisitRR(this, kRiscvBitcastDL, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitBitcastInt32ToFloat32(node_t node) {
    VisitRR(this, kRiscvBitcastInt32ToFloat32, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitBitcastInt64ToFloat64(node_t node) {
    VisitRR(this, kRiscvBitcastLD, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64RoundDown(node_t node) {
  VisitRR(this, kRiscvFloat64RoundDown, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32RoundUp(node_t node) {
  VisitRR(this, kRiscvFloat32RoundUp, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64RoundUp(node_t node) {
    VisitRR(this, kRiscvFloat64RoundUp, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32RoundTruncate(node_t node) {
  VisitRR(this, kRiscvFloat32RoundTruncate, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64RoundTruncate(node_t node) {
  VisitRR(this, kRiscvFloat64RoundTruncate, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64RoundTiesAway(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32RoundTiesEven(node_t node) {
  VisitRR(this, kRiscvFloat32RoundTiesEven, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64RoundTiesEven(node_t node) {
  VisitRR(this, kRiscvFloat64RoundTiesEven, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32Neg(node_t node) {
  VisitRR(this, kRiscvNegS, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Neg(node_t node) {
  VisitRR(this, kRiscvNegD, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Ieee754Binop(
    node_t node, InstructionCode opcode) {
    RiscvOperandGeneratorT<Adapter> g(this);
    Emit(opcode, g.DefineAsFixed(node, fa0),
         g.UseFixed(this->input_at(node, 0), fa0),
         g.UseFixed(this->input_at(node, 1), fa1))
        ->MarkAsCall();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Ieee754Unop(
    node_t node, InstructionCode opcode) {
  RiscvOperandGeneratorT<Adapter> g(this);
  Emit(opcode, g.DefineAsFixed(node, fa0),
       g.UseFixed(this->input_at(node, 0), fa1))
      ->MarkAsCall();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::EmitPrepareArguments(
    ZoneVector<PushParameter>* arguments, const CallDescriptor* call_descriptor,
    node_t node) {
    RiscvOperandGeneratorT<Adapter> g(this);

    // Prepare for C function call.
    if (call_descriptor->IsCFunctionCall()) {
      int gp_param_count =
          static_cast<int>(call_descriptor->GPParameterCount());
      int fp_param_count =
          static_cast<int>(call_descriptor->FPParameterCount());
      Emit(kArchPrepareCallCFunction | ParamField::encode(gp_param_count) |
               FPParamField::encode(fp_param_count),
           0, nullptr, 0, nullptr);

      // Poke any stack arguments.
      int slot = kCArgSlotCount;
      for (PushParameter input : (*arguments)) {
        Emit(kRiscvStoreToStackSlot, g.NoOutput(), g.UseRegister(input.node),
             g.TempImmediate(slot << kSystemPointerSizeLog2));
        ++slot;
      }
    } else {
      int push_count = static_cast<int>(call_descriptor->ParameterSlotCount());
      if (push_count > 0) {
        // Calculate needed space
        int stack_size = 0;
        for (PushParameter input : (*arguments)) {
          if (this->valid(input.node)) {
            stack_size += input.location.GetSizeInPointers();
          }
        }
        Emit(kRiscvStackClaim, g.NoOutput(),
             g.TempImmediate(stack_size << kSystemPointerSizeLog2));
      }
      for (size_t n = 0; n < arguments->size(); ++n) {
        PushParameter input = (*arguments)[n];
        if (this->valid(input.node)) {
          Emit(kRiscvStoreToStackSlot, g.NoOutput(), g.UseRegister(input.node),
               g.TempImmediate(static_cast<int>(n << kSystemPointerSizeLog2)));
        }
      }
    }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUnalignedLoad(node_t node) {
    auto load = this->load_view(node);
    LoadRepresentation load_rep = load.loaded_rep();
    RiscvOperandGeneratorT<Adapter> g(this);
    node_t base = this->input_at(node, 0);
    node_t index = this->input_at(node, 1);

    InstructionCode opcode = kArchNop;
    switch (load_rep.representation()) {
      case MachineRepresentation::kFloat32:
        opcode = kRiscvULoadFloat;
        break;
      case MachineRepresentation::kFloat64:
        opcode = kRiscvULoadDouble;
        break;
      case MachineRepresentation::kWord8:
        opcode = load_rep.IsUnsigned() ? kRiscvLbu : kRiscvLb;
        break;
      case MachineRepresentation::kWord16:
        opcode = load_rep.IsUnsigned() ? kRiscvUlhu : kRiscvUlh;
        break;
      case MachineRepresentation::kWord32:
        opcode = kRiscvUlw;
        break;
      case MachineRepresentation::kTaggedSigned:   // Fall through.
      case MachineRepresentation::kTaggedPointer:  // Fall through.
      case MachineRepresentation::kTagged:         // Fall through.
      case MachineRepresentation::kWord64:
        opcode = kRiscvUld;
        break;
      case MachineRepresentation::kSimd128:
        opcode = kRiscvRvvLd;
        break;
      case MachineRepresentation::kSimd256:            // Fall through.
      case MachineRepresentation::kBit:                // Fall through.
      case MachineRepresentation::kCompressedPointer:  // Fall through.
      case MachineRepresentation::kCompressed:         // Fall through.
      case MachineRepresentation::kSandboxedPointer:   // Fall through.
      case MachineRepresentation::kMapWord:            // Fall through.
      case MachineRepresentation::kIndirectPointer:    // Fall through.
      case MachineRepresentation::kProtectedPointer:   // Fall through.
      case MachineRepresentation::kFloat16:            // Fall through.
      case MachineRepresentation::kNone:
        UNREACHABLE();
    }
    bool traps_on_null;
    if (load.is_protected(&traps_on_null)) {
      if (traps_on_null) {
        opcode |=
            AccessModeField::encode(kMemoryAccessProtectedNullDereference);
      } else {
        opcode |= AccessModeField::encode(kMemoryAccessProtectedMemOutOfBounds);
      }
    }
    if (g.CanBeImmediate(index, opcode)) {
      Emit(opcode | AddressingModeField::encode(kMode_MRI),
           g.DefineAsRegister(node), g.UseRegister(base),
           g.UseImmediate(index));
    } else {
      InstructionOperand addr_reg = g.TempRegister();
      Emit(kRiscvAdd64 | AddressingModeField::encode(kMode_None), addr_reg,
           g.UseRegister(index), g.UseRegister(base));
      // Emit desired load opcode, using temp addr_reg.
      Emit(opcode | AddressingModeField::encode(kMode_MRI),
           g.DefineAsRegister(node), addr_reg, g.TempImmediate(0));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUnalignedStore(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    UNIMPLEMENTED();
  } else {
    RiscvOperandGeneratorT<Adapter> g(this);
    Node* base = this->input_at(node, 0);
    Node* index = this->input_at(node, 1);
    Node* value = node->InputAt(2);

    UnalignedStoreRepresentation rep =
        UnalignedStoreRepresentationOf(node->op());
    ArchOpcode opcode;
    switch (rep) {
      case MachineRepresentation::kFloat32:
        opcode = kRiscvUStoreFloat;
        break;
      case MachineRepresentation::kFloat64:
        opcode = kRiscvUStoreDouble;
        break;
      case MachineRepresentation::kWord8:
        opcode = kRiscvSb;
        break;
      case MachineRepresentation::kWord16:
        opcode = kRiscvUsh;
        break;
      case MachineRepresentation::kWord32:
        opcode = kRiscvUsw;
        break;
      case MachineRepresentation::kTaggedSigned:   // Fall through.
      case MachineRepresentation::kTaggedPointer:  // Fall through.
      case MachineRepresentation::kTagged:         // Fall through.
      case MachineRepresentation::kWord64:
        opcode = kRiscvUsd;
        break;
      case MachineRepresentation::kSimd128:
        opcode = kRiscvRvvSt;
        break;
      case MachineRepresentation::kSimd256:            // Fall through.
      case MachineRepresentation::kBit:                // Fall through.
      case MachineRepresentation::kCompressedPointer:  // Fall through.
      case MachineRepresentation::kCompressed:         // Fall through.
      case MachineRepresentation::kSandboxedPointer:   // Fall through.
      case MachineRepresentation::kMapWord:            // Fall through.
      case MachineRepresentation::kIndirectPointer:    // Fall through.
      case MachineRepresentation::kProtectedPointer:   // Fall through.
      case MachineRepresentation::kFloat16:
      case MachineRepresentation::kNone:
        UNREACHABLE();
    }

    if (g.CanBeImmediate(index, opcode)) {
      Emit(opcode | AddressingModeField::encode(kMode_MRI), g.NoOutput(),
           g.UseRegister(base), g.UseImmediate(index),
           g.UseRegisterOrImmediateZero(value));
    } else {
      InstructionOperand addr_reg = g.TempRegister();
      Emit(kRiscvAdd64 | AddressingModeField::encode(kMode_None), addr_reg,
           g.UseRegister(index), g.UseRegister(base));
      // Emit desired store opcode, using temp addr_reg.
      Emit(opcode | AddressingModeField::encode(kMode_MRI), g.NoOutput(),
           addr_reg, g.TempImmediate(0), g.UseRegisterOrImmediateZero(value));
    }
  }
}

namespace {

bool IsNodeUnsigned(typename TurbofanAdapter::node_t n) {
  NodeMatcher m(n);
  if (m.IsLoad() || m.IsUnalignedLoad() || m.IsProtectedLoad()) {
    LoadRepresentation load_rep = LoadRepresentationOf(n->op());
    return load_rep.IsUnsigned();
  } else if (m.IsWord32AtomicLoad() || m.IsWord64AtomicLoad()) {
    AtomicLoadParameters atomic_load_params = AtomicLoadParametersOf(n->op());
    LoadRepresentation load_rep = atomic_load_params.representation();
    return load_rep.IsUnsigned();
  } else {
    return m.IsUint32Div() || m.IsUint32LessThan() ||
           m.IsUint32LessThanOrEqual() || m.IsUint32Mod() ||
           m.IsUint32MulHigh() || m.IsChangeFloat64ToUint32() ||
           m.IsTruncateFloat64ToUint32() || m.IsTruncateFloat32ToUint32();
  }
}

bool IsNodeUnsigned(InstructionSelectorT<TurboshaftAdapter>* selector,
                    typename TurboshaftAdapter::node_t n) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  const Operation& op = selector->Get(n);
  if (op.Is<LoadOp>()) {
    const LoadOp& load = op.Cast<LoadOp>();
    return load.machine_type().IsUnsigned() ||
           load.machine_type().IsCompressed();
  } else if (op.Is<WordBinopOp>()) {
    const WordBinopOp& binop = op.Cast<WordBinopOp>();
    switch (binop.kind) {
      case WordBinopOp::Kind::kUnsignedDiv:
      case WordBinopOp::Kind::kUnsignedMod:
      case WordBinopOp::Kind::kUnsignedMulOverflownBits:
        return true;
      default:
        return false;
    }
  } else if (op.Is<ChangeOrDeoptOp>()) {
    const ChangeOrDeoptOp& change = op.Cast<ChangeOrDeoptOp>();
    return change.kind == ChangeOrDeoptOp::Kind::kFloat64ToUint32;
  } else if (op.Is<ConvertJSPrimitiveToUntaggedOp>()) {
    const ConvertJSPrimitiveToUntaggedOp& convert =
        op.Cast<ConvertJSPrimitiveToUntaggedOp>();
    return convert.kind ==
           ConvertJSPrimitiveToUntaggedOp::UntaggedKind::kUint32;
  } else if (op.Is<ConstantOp>()) {
    const ConstantOp& constant = op.Cast<ConstantOp>();
    return constant.kind == ConstantOp::Kind::kCompressedHeapObject;
  } else {
    return false;
  }
}

bool CanUseOptimizedWord32Compare(
    InstructionSelectorT<TurboshaftAdapter>* selector,
    typename TurboshaftAdapter::node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  if (COMPRESS_POINTERS_BOOL) {
    return false;
  }
  if (IsNodeUnsigned(selector, selector->input_at(node, 0)) ==
      IsNodeUnsigned(selector, selector->input_at(node, 1))) {
    return true;
  }
  return false;
}

// Shared routine for multiple word compare operations.
template <typename Adapter>
void VisitFullWord32Compare(InstructionSelectorT<Adapter>* selector,
                            typename Adapter::node_t node,
                            InstructionCode opcode,
                            FlagsContinuationT<Adapter>* cont) {
  RiscvOperandGeneratorT<Adapter> g(selector);
  InstructionOperand leftOp = g.TempRegister();
  InstructionOperand rightOp = g.TempRegister();

  selector->Emit(kRiscvShl64, leftOp,
                 g.UseRegister(selector->input_at(node, 0)),
                 g.TempImmediate(32));
  selector->Emit(kRiscvShl64, rightOp,
                 g.UseRegister(selector->input_at(node, 1)),
                 g.TempImmediate(32));

  Instruction* instr = VisitCompare(selector, opcode, leftOp, rightOp, cont);
  if constexpr (Adapter::IsTurboshaft) {
    selector->UpdateSourcePosition(instr, node);
  }
}

template <typename Adapter>
void VisitOptimizedWord32Compare(InstructionSelectorT<Adapter>* selector,
                                 typename Adapter::node_t node,
                                 InstructionCode opcode,
                                 FlagsContinuationT<Adapter>* cont) {
  if (v8_flags.debug_code) {
    RiscvOperandGeneratorT<Adapter> g(selector);
    InstructionOperand leftOp = g.TempRegister();
    InstructionOperand rightOp = g.TempRegister();
    InstructionOperand optimizedResult = g.TempRegister();
    InstructionOperand fullResult = g.TempRegister();
    FlagsCondition condition = cont->condition();
    InstructionCode testOpcode = opcode |
                                 FlagsConditionField::encode(condition) |
                                 FlagsModeField::encode(kFlags_set);

    selector->Emit(testOpcode, optimizedResult,
                   g.UseRegister(selector->input_at(node, 0)),
                   g.UseRegister(selector->input_at(node, 1)));
    selector->Emit(kRiscvShl64, leftOp,
                   g.UseRegister(selector->input_at(node, 0)),
                   g.TempImmediate(32));
    selector->Emit(kRiscvShl64, rightOp,
                   g.UseRegister(selector->input_at(node, 1)),
                   g.TempImmediate(32));
    selector->Emit(testOpcode, fullResult, leftOp, rightOp);

    selector->Emit(kRiscvAssertEqual, g.NoOutput(), optimizedResult, fullResult,
                   g.TempImmediate(static_cast<int>(
                       AbortReason::kUnsupportedNonPrimitiveCompare)));
  }

  Instruction* instr = VisitWordCompare(selector, node, opcode, cont, false);
  if constexpr (Adapter::IsTurboshaft) {
    selector->UpdateSourcePosition(instr, node);
  }
}

template <typename Adapter>
void VisitWord32Compare(InstructionSelectorT<Adapter>* selector,
                        typename Adapter::node_t node,
                        FlagsContinuationT<Adapter>* cont) {
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
#ifdef USE_SIMULATOR
    const Operation& lhs = selector->Get(selector->input_at(node, 0));
    const Operation& rhs = selector->Get(selector->input_at(node, 1));
    if (lhs.Is<DidntThrowOp>() || rhs.Is<DidntThrowOp>()) {
      VisitFullWord32Compare(selector, node, kRiscvCmp, cont);
    } else
#endif
        if (!CanUseOptimizedWord32Compare(selector, node)) {
      VisitFullWord32Compare(selector, node, kRiscvCmp, cont);
    } else {
      VisitOptimizedWord32Compare(selector, node, kRiscvCmp, cont);
    }
  } else {
    // RISC-V doesn't support Word32 compare instructions. Instead it relies
    // that the values in registers are correctly sign-extended and uses
    // Word64 comparison instead. This behavior is correct in most cases,
    // but doesn't work when comparing signed with unsigned operands.
    // We could simulate full Word32 compare in all cases but this would
    // create an unnecessary overhead since unsigned integers are rarely
    // used in JavaScript.
    // The solution proposed here tries to match a comparison of signed
    // with unsigned operand, and perform full Word32Compare only
    // in those cases. Unfortunately, the solution is not complete because
    // it might skip cases where Word32 full compare is needed, so
    // basically it is a hack.
    // When calling a host function in the simulator, if the function returns an
    // int32 value, the simulator does not sign-extend it to int64 because in
    // the simulator we do not know whether the function returns an int32 or
    // an int64. So we need to do a full word32 compare in this case.
    if (!COMPRESS_POINTERS_BOOL) {
#ifndef USE_SIMULATOR
      if (IsNodeUnsigned(selector->input_at(node, 0)) !=
          IsNodeUnsigned(node->InputAt(1))) {
#else
      if (IsNodeUnsigned(selector->input_at(node, 0)) !=
              IsNodeUnsigned(node->InputAt(1)) ||
          node->InputAt(0)->opcode() == IrOpcode::kCall ||
          node->InputAt(1)->opcode() == IrOpcode::kCall) {
#endif
        VisitFullWord32Compare(selector, node, kRiscvCmp, cont);
      } else {
        VisitOptimizedWord32Compare(selector, node, kRiscvCmp, cont);
      }
    } else {
      VisitFullWord32Compare(selector, node, kRiscvCmp, cont);
    }
  }
}

template <typename Adapter>
void VisitWord64Compare(InstructionSelectorT<Adapter>* selector,
                        typename Adapter::node_t node,
                        FlagsContinuationT<Adapter>* cont) {
  VisitWordCompare(selector, node, kRiscvCmp, cont, false);
}

template <typename Adapter>
void VisitAtomicLoad(InstructionSelectorT<Adapter>* selector,
                     typename Adapter::node_t node, AtomicWidth width) {
  using node_t = typename Adapter::node_t;
  RiscvOperandGeneratorT<Adapter> g(selector);
  auto load = selector->load_view(node);
  node_t base = load.base();
  node_t index = load.index();

  // The memory order is ignored as both acquire and sequentially consistent
  // loads can emit LDAR.
  // https://www.cl.cam.ac.uk/~pes20/cpp/cpp0xmappings.html
  LoadRepresentation load_rep = load.loaded_rep();
  InstructionCode code;
  switch (load_rep.representation()) {
    case MachineRepresentation::kWord8:
      DCHECK_IMPLIES(load_rep.IsSigned(), width == AtomicWidth::kWord32);
      code = load_rep.IsSigned() ? kAtomicLoadInt8 : kAtomicLoadUint8;
      break;
    case MachineRepresentation::kWord16:
      DCHECK_IMPLIES(load_rep.IsSigned(), width == AtomicWidth::kWord32);
      code = load_rep.IsSigned() ? kAtomicLoadInt16 : kAtomicLoadUint16;
      break;
    case MachineRepresentation::kWord32:
      code = kAtomicLoadWord32;
      break;
    case MachineRepresentation::kWord64:
      code = kRiscvWord64AtomicLoadUint64;
      break;
#ifdef V8_COMPRESS_POINTERS
    case MachineRepresentation::kTaggedSigned:
      code = kRiscvAtomicLoadDecompressTaggedSigned;
      break;
    case MachineRepresentation::kTaggedPointer:
    case MachineRepresentation::kTagged:
      code = kRiscvAtomicLoadDecompressTagged;
      break;
#else
    case MachineRepresentation::kTaggedSigned:   // Fall through.
    case MachineRepresentation::kTaggedPointer:  // Fall through.
    case MachineRepresentation::kTagged:
      if (kTaggedSize == 8) {
        code = kRiscvWord64AtomicLoadUint64;
      } else {
        code = kAtomicLoadWord32;
      }
      break;
#endif
    case MachineRepresentation::kCompressedPointer:  // Fall through.
    case MachineRepresentation::kCompressed:
      DCHECK(COMPRESS_POINTERS_BOOL);
      code = kAtomicLoadWord32;
      break;
    default:
      UNREACHABLE();
  }

  bool traps_on_null;
  if (load.is_protected(&traps_on_null)) {
    // Atomic loads and null dereference are mutually exclusive. This might
    // change with multi-threaded wasm-gc in which case the access mode should
    // probably be kMemoryAccessProtectedNullDereference.
    DCHECK(!traps_on_null);
    code |= AccessModeField::encode(kMemoryAccessProtectedMemOutOfBounds);
  }

  if (g.CanBeImmediate(index, code)) {
    selector->Emit(code | AddressingModeField::encode(kMode_MRI) |
                       AtomicWidthField::encode(width),
                   g.DefineAsRegister(node), g.UseRegister(base),
                   g.UseImmediate(index));
  } else {
    InstructionOperand addr_reg = g.TempRegister();
    selector->Emit(kRiscvAdd64 | AddressingModeField::encode(kMode_None),
                   addr_reg, g.UseRegister(base), g.UseRegister(index));
    // Emit desired load opcode, using temp addr_reg.
    selector->Emit(code | AddressingModeField::encode(kMode_MRI) |
                       AtomicWidthField::encode(width),
                   g.DefineAsRegister(node), addr_reg, g.TempImmediate(0));
  }
}

void VisitAtomicLoad(InstructionSelectorT<TurbofanAdapter>* selector,
                     Node* node, AtomicWidth width) {
  RiscvOperandGeneratorT<TurbofanAdapter> g(selector);
  Node* base = selector->input_at(node, 0);
  Node* index = selector->input_at(node, 1);

  // The memory order is ignored.
  AtomicLoadParameters atomic_load_params = AtomicLoadParametersOf(node->op());
  LoadRepresentation load_rep = atomic_load_params.representation();
  InstructionCode code;
  switch (load_rep.representation()) {
    case MachineRepresentation::kWord8:
      DCHECK_IMPLIES(load_rep.IsSigned(), width == AtomicWidth::kWord32);
      code = load_rep.IsSigned() ? kAtomicLoadInt8 : kAtomicLoadUint8;
      break;
    case MachineRepresentation::kWord16:
      DCHECK_IMPLIES(load_rep.IsSigned(), width == AtomicWidth::kWord32);
      code = load_rep.IsSigned() ? kAtomicLoadInt16 : kAtomicLoadUint16;
      break;
    case MachineRepresentation::kWord32:
      code = kAtomicLoadWord32;
      break;
    case MachineRepresentation::kWord64:
      code = kRiscvWord64AtomicLoadUint64;
      break;
#ifdef V8_COMPRESS_POINTERS
    case MachineRepresentation::kTaggedSigned:
      code = kRiscvAtomicLoadDecompressTaggedSigned;
      break;
    case MachineRepresentation::kTaggedPointer:
    case MachineRepresentation::kTagged:
      code = kRiscvAtomicLoadDecompressTagged;
      break;
#else
    case MachineRepresentation::kTaggedSigned:   // Fall through.
    case MachineRepresentation::kTaggedPointer:  // Fall through.
    case MachineRepresentation::kTagged:
      DCHECK_EQ(kTaggedSize, 8);
      code = kRiscvWord64AtomicLoadUint64;
      break;
#endif
    default:
      UNREACHABLE();
  }

  if (atomic_load_params.kind() == MemoryAccessKind::kProtectedByTrapHandler) {
    code |= AccessModeField::encode(kMemoryAccessProtectedMemOutOfBounds);
  }

  if (g.CanBeImmediate(index, code)) {
    selector->Emit(code | AddressingModeField::encode(kMode_MRI) |
                       AtomicWidthField::encode(width),
                   g.DefineAsRegister(node), g.UseRegister(base),
                   g.UseImmediate(index));
  } else {
    InstructionOperand addr_reg = g.TempRegister();
    selector->Emit(kRiscvAdd64 | AddressingModeField::encode(kMode_None),
                   addr_reg, g.UseRegister(index), g.UseRegister(base));
    // Emit desired load opcode, using temp addr_reg.
    selector->Emit(code | AddressingModeField::encode(kMode_MRI) |
                       AtomicWidthField::encode(width),
                   g.DefineAsRegister(node), addr_reg, g.TempImmediate(0));
  }
}

template <typename Adapter>
AtomicStoreParameters AtomicStoreParametersOf(
    InstructionSelectorT<Adapter>* selector, typename Adapter::node_t node) {
  auto store = selector->store_view(node);
  return AtomicStoreParameters(store.stored_rep().representation(),
                               store.stored_rep().write_barrier_kind(),
                               store.memory_order().value(),
                               store.access_kind());
}

template <typename Adapter>
void VisitAtomicStore(InstructionSelectorT<Adapter>* selector,
                      typename Adapter::node_t node, AtomicWidth width) {
  using node_t = typename Adapter::node_t;
  RiscvOperandGeneratorT<Adapter> g(selector);
  auto store = selector->store_view(node);
  node_t base = store.base();
  node_t index = selector->value(store.index());
  node_t value = store.value();
  DCHECK_EQ(store.displacement(), 0);

  // The memory order is ignored.
  AtomicStoreParameters store_params = AtomicStoreParametersOf(selector, node);
  WriteBarrierKind write_barrier_kind = store_params.write_barrier_kind();
  MachineRepresentation rep = store_params.representation();

  if (v8_flags.enable_unconditional_write_barriers &&
      CanBeTaggedOrCompressedPointer(rep)) {
    write_barrier_kind = kFullWriteBarrier;
  }

  InstructionCode code;

  if (write_barrier_kind != kNoWriteBarrier &&
      !v8_flags.disable_write_barriers) {
    DCHECK(CanBeTaggedPointer(rep));
    DCHECK_EQ(AtomicWidthSize(width), kTaggedSize);

    InstructionOperand inputs[3];
    size_t input_count = 0;
    inputs[input_count++] = g.UseUniqueRegister(base);
    inputs[input_count++] = g.UseUniqueRegister(index);
    inputs[input_count++] = g.UseUniqueRegister(value);
    RecordWriteMode record_write_mode =
        WriteBarrierKindToRecordWriteMode(write_barrier_kind);
    InstructionOperand temps[] = {g.TempRegister(), g.TempRegister()};
    size_t const temp_count = arraysize(temps);
    code = kArchAtomicStoreWithWriteBarrier;
    code |= RecordWriteModeField::encode(record_write_mode);
    selector->Emit(code, 0, nullptr, input_count, inputs, temp_count, temps);
  } else {
    switch (rep) {
      case MachineRepresentation::kWord8:
        code = kAtomicStoreWord8;
        break;
      case MachineRepresentation::kWord16:
        code = kAtomicStoreWord16;
        break;
      case MachineRepresentation::kWord32:
        code = kAtomicStoreWord32;
        break;
      case MachineRepresentation::kWord64:
        DCHECK_EQ(width, AtomicWidth::kWord64);
        code = kRiscvWord64AtomicStoreWord64;
        break;
      case MachineRepresentation::kTaggedSigned:   // Fall through.
      case MachineRepresentation::kTaggedPointer:  // Fall through.
      case MachineRepresentation::kTagged:
        DCHECK_EQ(AtomicWidthSize(width), kTaggedSi
"""


```