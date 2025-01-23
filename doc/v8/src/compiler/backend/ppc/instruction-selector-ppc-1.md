Response: The user wants me to summarize the functionality of the C++ code provided. This code seems to be part of the V8 JavaScript engine, specifically the instruction selector for the PowerPC (PPC) architecture.

Here's a breakdown of how to approach this:

1. **Identify the core purpose:** The file name `instruction-selector-ppc.cc` and the context within the V8 codebase suggest this code is responsible for translating high-level, architecture-independent operations into low-level PPC instructions.

2. **Analyze the code structure:** The code is organized around the `InstructionSelectorT` template class, which implements the visitor pattern to handle different types of operations (nodes in the intermediate representation).

3. **Examine individual visitor methods:** Each `Visit...` method corresponds to a specific operation. By looking at the PPC instructions emitted within these methods, we can understand how each operation is translated. Key instruction prefixes like `kPPC_` help identify PPC-specific instructions.

4. **Look for patterns and common themes:** Notice how many methods deal with arithmetic operations (`Add`, `Sub`, `Mul`, `Div`), bitwise operations (`ReverseBytes`), comparisons, type conversions, and memory access (`Load`, `Store`, atomic operations). This suggests the code covers a broad range of fundamental operations.

5. **Consider the "Adapter" template parameter:** The presence of the `Adapter` template parameter (and the `IsTurboshaft` check) indicates that this code might be used by both the older "Crankshaft" and the newer "Turboshaft" compilers within V8. The logic often branches based on the adapter type.

6. **Relate to JavaScript functionality (if applicable):**  Since this is part of a JavaScript engine, many of these operations have direct counterparts in JavaScript. For example, integer addition in JavaScript corresponds to the `VisitInt32Add` and `VisitInt64Add` methods.

7. **Formulate a concise summary:** Based on the above analysis, create a summary that captures the main purpose and key functionalities of the code.

8. **Provide JavaScript examples (if applicable):** Illustrate the connection to JavaScript by giving simple JavaScript code snippets that would trigger some of the translated operations.

**Self-Correction/Refinement during the thought process:**

* **Initial thought:**  This file just selects instructions.
* **Refinement:** It selects *and emits* instructions. The `Emit()` calls are crucial.
* **Initial thought:** The adapter is just an internal detail.
* **Refinement:** The adapter signifies the support for different compiler pipelines, which is a significant aspect of the code's context. Mentioning Turboshaft specifically is important.
* **Initial thought:** Focus on every single `Visit...` method.
* **Refinement:**  Group related methods (e.g., all the arithmetic operations) in the summary to avoid unnecessary detail. Emphasize the *types* of operations handled.

By following these steps, I can arrive at the desired summary and JavaScript examples.
这是 `v8/src/compiler/backend/ppc/instruction-selector-ppc.cc` 文件的第二部分代码。延续第一部分的功能，这部分代码主要负责 **将 V8 的中间表示 (IR) 节点转换成针对 PowerPC (PPC) 架构的机器指令**。

具体来说，这部分代码继续实现了 `InstructionSelectorT` 模板类的各种 `Visit` 方法，每个方法对应一种特定的 IR 节点类型，例如：

* **位操作:**  `VisitWord64ReverseBytes`, `VisitWord32ReverseBytes`, `VisitSimd128ReverseBytes`，用于处理字节序反转。
* **算术运算:** `VisitInt32Add`, `VisitInt64Add`, `VisitInt32Sub`, `VisitInt64Sub`, `VisitInt32Mul`, `VisitInt64Mul`, `VisitInt32Div`, `VisitInt64Div`, `VisitUint32Div`, `VisitUint64Div`, `VisitInt32Mod`, `VisitInt64Mod`, `VisitUint32Mod`, `VisitUint64Mod`，处理加减乘除和取模运算。
* **浮点数转换:** `VisitChangeFloat32ToFloat64`, `VisitRoundInt32ToFloat32`, `VisitChangeInt32ToFloat64`, `VisitChangeFloat64ToInt32`, `VisitTruncateFloat64ToUint32` 等，处理各种浮点数和整数之间的类型转换。
* **符号扩展:** `VisitSignExtendWord8ToInt32`, `VisitSignExtendWord16ToInt32`, `VisitSignExtendWord8ToInt64` 等，处理将较小的数据类型扩展到更大的数据类型并保留符号。
* **截断:** `VisitTruncateFloat64ToInt64`, `VisitTruncateFloat32ToInt32`, `VisitTruncateInt64ToInt32` 等，处理将较大的数据类型截断为较小的数据类型。
* **位操作（续）:** `VisitBitcastWord32ToWord64`, `VisitBitcastFloat32ToInt32`, `VisitBitcastInt32ToFloat32` 等，处理不同数据类型之间的位级转换。
* **浮点数运算:** `VisitFloat32Add`, `VisitFloat64Add`, `VisitFloat32Sub`, `VisitFloat64Sub`, `VisitFloat32Mul`, `VisitFloat64Mul`, `VisitFloat32Div`, `VisitFloat64Div`, `VisitFloat64Mod`, `VisitFloat32Max`, `VisitFloat64Max`, `VisitFloat32Min`, `VisitFloat64Min`, `VisitFloat32Abs`, `VisitFloat64Abs`, `VisitFloat32Sqrt`, `VisitFloat64Sqrt`，处理各种浮点数运算。
* **舍入:** `VisitFloat32RoundDown`, `VisitFloat64RoundDown`, `VisitFloat32RoundUp`, `VisitFloat64RoundUp`, `VisitFloat32RoundTruncate`, `VisitFloat64RoundTruncate`, `VisitFloat64RoundTiesAway`，处理不同的浮点数舍入模式。
* **溢出检查的运算:** `VisitInt32AddWithOverflow`, `VisitInt32SubWithOverflow`, `VisitInt64AddWithOverflow`, `VisitInt64SubWithOverflow`, `VisitInt64MulWithOverflow`，处理可能导致溢出的算术运算。
* **比较运算:**  包含了辅助函数 `VisitCompare`, `VisitWordCompare`, `VisitWord32Compare`, `VisitWord64Compare`, `VisitFloat32Compare`, `VisitFloat64Compare` 以及 `VisitWordCompareZero`，用于处理各种类型的比较操作。
* **Switch 语句:** `VisitSwitch`，处理 switch 语句的指令选择。
* **条件比较:** `VisitWord32Equal`, `VisitInt32LessThan`, `VisitInt32LessThanOrEqual`, `VisitUint32LessThan`, `VisitUint32LessThanOrEqual`, `VisitWord64Equal`, `VisitInt64LessThan`, `VisitInt64LessThanOrEqual`, `VisitUint64LessThan`, `VisitUint64LessThanOrEqual`, `VisitInt32MulWithOverflow`, `VisitFloat32Equal`, `VisitFloat32LessThan`, `VisitFloat32LessThanOrEqual`, `VisitFloat64Equal`, `VisitFloat64LessThan`, `VisitFloat64LessThanOrEqual`，用于处理各种条件比较操作。
* **函数调用参数准备:** `EmitPrepareArguments`，用于准备函数调用的参数。
* **浮点数寄存器操作:** `VisitFloat64ExtractLowWord32`, `VisitFloat64ExtractHighWord32`, `VisitBitcastWord32PairToFloat64`, `VisitFloat64InsertLowWord32`, `VisitFloat64InsertHighWord32`，处理浮点数和整数之间的位级操作。
* **内存屏障:** `VisitMemoryBarrier`，确保内存操作的顺序性。
* **原子操作:** `VisitWord32AtomicLoad`, `VisitWord64AtomicLoad`, `VisitWord32AtomicStore`, `VisitWord64AtomicStore`, `VisitWord32AtomicExchange`, `VisitWord64AtomicExchange`, `VisitWord32AtomicCompareExchange`, `VisitWord64AtomicCompareExchange`，处理原子级别的内存操作。

**与 JavaScript 的关系:**

这些代码是 JavaScript 引擎执行过程中的关键部分。当 JavaScript 代码执行时，V8 会将其编译成机器码。`instruction-selector-ppc.cc` 的作用就是将 JavaScript 中的各种操作，例如算术运算、类型转换、比较等，转换为底层的 PPC 机器指令。

**JavaScript 示例:**

以下是一些 JavaScript 示例，以及它们可能触发的代码片段中对应的 `Visit` 方法：

1. **整数加法:**

   ```javascript
   let a = 10;
   let b = 20;
   let sum = a + b;
   ```

   这会触发 `VisitInt32Add` 或 `VisitInt64Add`，具体取决于变量 `a` 和 `b` 的大小。

2. **浮点数乘法:**

   ```javascript
   let x = 3.14;
   let y = 2.0;
   let product = x * y;
   ```

   这会触发 `VisitFloat64Mul`。

3. **类型转换:**

   ```javascript
   let num = 10;
   let str = String(num);
   ```

   内部可能会涉及将整数转换为字符串的操作，但更直接相关的可能是数值类型之间的转换，例如：

   ```javascript
   let floatNum = 10.5;
   let intNum = Math.floor(floatNum);
   ```

   这可能会触发 `VisitTruncateFloat64ToInt32`。

4. **比较操作:**

   ```javascript
   let p = 5;
   let q = 10;
   if (p < q) {
       console.log("p is less than q");
   }
   ```

   这会触发 `VisitInt32LessThan`。

5. **位操作:**

   ```javascript
   let val = 0xFF;
   let reversed = val << 8;
   ```

   虽然这个例子是位移，但类似的反转字节序操作可能会触发 `VisitWord32ReverseBytes` 或 `VisitWord64ReverseBytes`，尽管 JavaScript 中直接操作字节序的场景较少，更多可能出现在 TypedArray 或 Buffer 的操作中。

6. **原子操作 (需要使用 SharedArrayBuffer 和 Atomics API):**

   ```javascript
   const sab = new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT * 2);
   const view = new Int32Array(sab);
   Atomics.add(view, 0, 5);
   ```

   这会触发 `VisitWord32AtomicAdd` (虽然这段代码中没有直接展示 `VisitWord32AtomicAdd`，但原子操作的原理类似)。

总而言之，这部分代码是 V8 引擎将 JavaScript 代码转换为可在 PPC 架构上执行的机器码的关键组成部分，涵盖了各种基本的和高级的计算和数据处理操作。理解这部分代码有助于深入了解 JavaScript 引擎的内部工作原理。

### 提示词
```
这是目录为v8/src/compiler/backend/ppc/instruction-selector-ppc.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```
atomic = load.is_atomic();
        Emit(kPPC_LoadByteRev64 | AddressingModeField::encode(kMode_MRR),
             g.DefineAsRegister(node), g.UseRegister(base),
             g.UseRegister(offset), g.UseImmediate(is_atomic));
        return;
      }
    }
    Emit(kPPC_ByteRev64, g.DefineAsRegister(node),
         g.UseUniqueRegister(this->input_at(node, 0)), 1, temp);
  } else {
    PPCOperandGeneratorT<Adapter> g(this);
    InstructionOperand temp[] = {g.TempRegister()};
    NodeMatcher input(node->InputAt(0));
    if (CanCover(node, input.node()) && input.IsLoad()) {
      LoadRepresentation load_rep = LoadRepresentationOf(input.node()->op());
      if (load_rep.representation() == MachineRepresentation::kWord64) {
        Node* load_op = input.node();
        Node* base = load_op->InputAt(0);
        Node* offset = load_op->InputAt(1);
        bool is_atomic = (load_op->opcode() == IrOpcode::kWord32AtomicLoad ||
                          load_op->opcode() == IrOpcode::kWord64AtomicLoad);
        Emit(kPPC_LoadByteRev64 | AddressingModeField::encode(kMode_MRR),
             g.DefineAsRegister(node), g.UseRegister(base),
             g.UseRegister(offset), g.UseImmediate(is_atomic));
        return;
      }
    }
    Emit(kPPC_ByteRev64, g.DefineAsRegister(node),
         g.UseUniqueRegister(node->InputAt(0)), 1, temp);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32ReverseBytes(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    PPCOperandGeneratorT<Adapter> g(this);
    node_t input = this->Get(node).input(0);
    const Operation& input_op = this->Get(input);
    if (CanCover(node, input) && input_op.Is<LoadOp>()) {
      auto load = this->load_view(input);
      LoadRepresentation load_rep = load.loaded_rep();
      if (load_rep.representation() == MachineRepresentation::kWord32) {
        node_t base = load.base();
        node_t offset = load.index();
        bool is_atomic = load.is_atomic();
        Emit(kPPC_LoadByteRev32 | AddressingModeField::encode(kMode_MRR),
             g.DefineAsRegister(node), g.UseRegister(base),
             g.UseRegister(offset), g.UseImmediate(is_atomic));
        return;
      }
    }
    Emit(kPPC_ByteRev32, g.DefineAsRegister(node),
         g.UseUniqueRegister(this->input_at(node, 0)));
  } else {
    PPCOperandGeneratorT<Adapter> g(this);
    NodeMatcher input(node->InputAt(0));
    if (CanCover(node, input.node()) && input.IsLoad()) {
      LoadRepresentation load_rep = LoadRepresentationOf(input.node()->op());
      if (load_rep.representation() == MachineRepresentation::kWord32) {
        Node* load_op = input.node();
        Node* base = load_op->InputAt(0);
        Node* offset = load_op->InputAt(1);
        bool is_atomic = (load_op->opcode() == IrOpcode::kWord32AtomicLoad ||
                          load_op->opcode() == IrOpcode::kWord64AtomicLoad);
        Emit(kPPC_LoadByteRev32 | AddressingModeField::encode(kMode_MRR),
             g.DefineAsRegister(node), g.UseRegister(base),
             g.UseRegister(offset), g.UseImmediate(is_atomic));
        return;
      }
    }
    Emit(kPPC_ByteRev32, g.DefineAsRegister(node),
         g.UseRegister(node->InputAt(0)));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitSimd128ReverseBytes(node_t node) {
  PPCOperandGeneratorT<Adapter> g(this);
  Emit(kPPC_LoadReverseSimd128RR, g.DefineAsRegister(node),
       g.UseRegister(this->input_at(node, 0)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32Add(node_t node) {
  VisitBinop<Adapter>(this, node, kPPC_Add32, kInt16Imm);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt64Add(node_t node) {
  VisitBinop<Adapter>(this, node, kPPC_Add64, kInt16Imm);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32Sub(node_t node) {
    PPCOperandGeneratorT<Adapter> g(this);
    if constexpr (Adapter::IsTurboshaft) {
      using namespace turboshaft;  // NOLINT(build/namespaces)
      const WordBinopOp& sub = this->Get(node).template Cast<WordBinopOp>();
      if (this->MatchIntegralZero(sub.left())) {
        Emit(kPPC_Neg, g.DefineAsRegister(node), g.UseRegister(sub.right()));
      } else {
        VisitBinop<Adapter>(this, node, kPPC_Sub, kInt16Imm_Negate);
      }
    } else {
      Int32BinopMatcher m(node);
      if (m.left().Is(0)) {
        Emit(kPPC_Neg, g.DefineAsRegister(node),
             g.UseRegister(m.right().node()));
      } else {
        VisitBinop<Adapter>(this, node, kPPC_Sub, kInt16Imm_Negate);
      }
    }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt64Sub(node_t node) {
  PPCOperandGeneratorT<Adapter> g(this);
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const WordBinopOp& sub = this->Get(node).template Cast<WordBinopOp>();
    if (this->MatchIntegralZero(sub.left())) {
      Emit(kPPC_Neg, g.DefineAsRegister(node), g.UseRegister(sub.right()));
    } else {
      VisitBinop<Adapter>(this, node, kPPC_Sub, kInt16Imm_Negate);
    }
  } else {
    PPCOperandGeneratorT<Adapter> g(this);
    Int64BinopMatcher m(node);
    if (m.left().Is(0)) {
      Emit(kPPC_Neg, g.DefineAsRegister(node), g.UseRegister(m.right().node()));
    } else {
      VisitBinop<Adapter>(this, node, kPPC_Sub, kInt16Imm_Negate);
    }
  }
}

namespace {

template <typename Adapter>
void VisitCompare(InstructionSelectorT<Adapter>* selector,
                  InstructionCode opcode, InstructionOperand left,
                  InstructionOperand right, FlagsContinuationT<Adapter>* cont);
template <typename Adapter>
void EmitInt32MulWithOverflow(InstructionSelectorT<Adapter>* selector,
                              typename Adapter::node_t node,
                              FlagsContinuationT<Adapter>* cont) {
  PPCOperandGeneratorT<Adapter> g(selector);
  typename Adapter::node_t lhs = selector->input_at(node, 0);
  typename Adapter::node_t rhs = selector->input_at(node, 1);
  InstructionOperand result_operand = g.DefineAsRegister(node);
  InstructionOperand high32_operand = g.TempRegister();
  InstructionOperand temp_operand = g.TempRegister();
  {
    InstructionOperand outputs[] = {result_operand, high32_operand};
    InstructionOperand inputs[] = {g.UseRegister(lhs), g.UseRegister(rhs)};
    selector->Emit(kPPC_Mul32WithHigh32, 2, outputs, 2, inputs);
  }
  {
    InstructionOperand shift_31 = g.UseImmediate(31);
    InstructionOperand outputs[] = {temp_operand};
    InstructionOperand inputs[] = {result_operand, shift_31};
    selector->Emit(kPPC_ShiftRightAlg32, 1, outputs, 2, inputs);
  }

  VisitCompare(selector, kPPC_Cmp32, high32_operand, temp_operand, cont);
}

template <typename Adapter>
void EmitInt64MulWithOverflow(InstructionSelectorT<Adapter>* selector,
                              typename Adapter::node_t node,
                              FlagsContinuationT<Adapter>* cont) {
  PPCOperandGeneratorT<Adapter> g(selector);
  typename Adapter::node_t lhs = selector->input_at(node, 0);
  typename Adapter::node_t rhs = selector->input_at(node, 1);
  InstructionOperand result = g.DefineAsRegister(node);
  InstructionOperand left = g.UseRegister(lhs);
  InstructionOperand high = g.TempRegister();
  InstructionOperand result_sign = g.TempRegister();
  InstructionOperand right = g.UseRegister(rhs);
  selector->Emit(kPPC_Mul64, result, left, right);
  selector->Emit(kPPC_MulHighS64, high, left, right);
  selector->Emit(kPPC_ShiftRightAlg64, result_sign, result,
                 g.TempImmediate(63));
  // Test whether {high} is a sign-extension of {result}.
  selector->EmitWithContinuation(kPPC_Cmp64, high, result_sign, cont);
}

}  // namespace

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32Mul(node_t node) {
    VisitRRR(this, kPPC_Mul32, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt64Mul(node_t node) {
    VisitRRR(this, kPPC_Mul64, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32MulHigh(node_t node) {
    PPCOperandGeneratorT<Adapter> g(this);
    Emit(kPPC_MulHigh32, g.DefineAsRegister(node),
         g.UseRegister(this->input_at(node, 0)),
         g.UseRegister(this->input_at(node, 1)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUint32MulHigh(node_t node) {
    PPCOperandGeneratorT<Adapter> g(this);
    Emit(kPPC_MulHighU32, g.DefineAsRegister(node),
         g.UseRegister(this->input_at(node, 0)),
         g.UseRegister(this->input_at(node, 1)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt64MulHigh(node_t node) {
    PPCOperandGeneratorT<Adapter> g(this);
    Emit(kPPC_MulHighS64, g.DefineAsRegister(node),
         g.UseRegister(this->input_at(node, 0)),
         g.UseRegister(this->input_at(node, 1)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUint64MulHigh(node_t node) {
    PPCOperandGeneratorT<Adapter> g(this);
    Emit(kPPC_MulHighU64, g.DefineAsRegister(node),
         g.UseRegister(this->input_at(node, 0)),
         g.UseRegister(this->input_at(node, 1)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32Div(node_t node) {
    VisitRRR(this, kPPC_Div32, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt64Div(node_t node) {
    VisitRRR(this, kPPC_Div64, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUint32Div(node_t node) {
    VisitRRR(this, kPPC_DivU32, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUint64Div(node_t node) {
    VisitRRR(this, kPPC_DivU64, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32Mod(node_t node) {
    VisitRRR(this, kPPC_Mod32, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt64Mod(node_t node) {
    VisitRRR(this, kPPC_Mod64, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUint32Mod(node_t node) {
    VisitRRR(this, kPPC_ModU32, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUint64Mod(node_t node) {
    VisitRRR(this, kPPC_ModU64, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitChangeFloat32ToFloat64(node_t node) {
    VisitRR(this, kPPC_Float32ToDouble, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitRoundInt32ToFloat32(node_t node) {
    VisitRR(this, kPPC_Int32ToFloat32, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitRoundUint32ToFloat32(node_t node) {
    VisitRR(this, kPPC_Uint32ToFloat32, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitChangeInt32ToFloat64(node_t node) {
    VisitRR(this, kPPC_Int32ToDouble, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitChangeUint32ToFloat64(node_t node) {
    VisitRR(this, kPPC_Uint32ToDouble, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitChangeFloat64ToInt32(node_t node) {
    VisitRR(this, kPPC_DoubleToInt32, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitChangeFloat64ToUint32(node_t node) {
    VisitRR(this, kPPC_DoubleToUint32, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTruncateFloat64ToUint32(node_t node) {
    VisitRR(this, kPPC_DoubleToUint32, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitSignExtendWord8ToInt32(node_t node) {
    // TODO(mbrandy): inspect input to see if nop is appropriate.
    VisitRR(this, kPPC_ExtendSignWord8, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitSignExtendWord16ToInt32(node_t node) {
    // TODO(mbrandy): inspect input to see if nop is appropriate.
    VisitRR(this, kPPC_ExtendSignWord16, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTryTruncateFloat32ToInt64(
    node_t node) {
    VisitTryTruncateDouble(this, kPPC_DoubleToInt64, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTryTruncateFloat64ToInt64(
    node_t node) {
    VisitTryTruncateDouble(this, kPPC_DoubleToInt64, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTruncateFloat64ToInt64(node_t node) {
    VisitRR(this, kPPC_DoubleToInt64, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTryTruncateFloat32ToUint64(
    node_t node) {
    VisitTryTruncateDouble(this, kPPC_DoubleToUint64, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTryTruncateFloat64ToUint64(
    node_t node) {
    VisitTryTruncateDouble(this, kPPC_DoubleToUint64, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTryTruncateFloat64ToInt32(
    node_t node) {
    VisitTryTruncateDouble(this, kPPC_DoubleToInt32, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTryTruncateFloat64ToUint32(
    node_t node) {
    VisitTryTruncateDouble(this, kPPC_DoubleToUint32, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitBitcastWord32ToWord64(node_t node) {
    DCHECK(SmiValuesAre31Bits());
    DCHECK(COMPRESS_POINTERS_BOOL);
    EmitIdentity(node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitChangeInt32ToInt64(node_t node) {
    // TODO(mbrandy): inspect input to see if nop is appropriate.
    VisitRR(this, kPPC_ExtendSignWord32, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitSignExtendWord8ToInt64(node_t node) {
    // TODO(mbrandy): inspect input to see if nop is appropriate.
    VisitRR(this, kPPC_ExtendSignWord8, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitSignExtendWord16ToInt64(node_t node) {
    // TODO(mbrandy): inspect input to see if nop is appropriate.
    VisitRR(this, kPPC_ExtendSignWord16, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitSignExtendWord32ToInt64(node_t node) {
    // TODO(mbrandy): inspect input to see if nop is appropriate.
    VisitRR(this, kPPC_ExtendSignWord32, node);
}

template <typename Adapter>
bool InstructionSelectorT<Adapter>::ZeroExtendsWord32ToWord64NoPhis(
    node_t node) {
  UNIMPLEMENTED();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitChangeUint32ToUint64(node_t node) {
    // TODO(mbrandy): inspect input to see if nop is appropriate.
    VisitRR(this, kPPC_Uint32ToUint64, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTruncateFloat64ToFloat16RawBits(
    node_t node) {
  UNIMPLEMENTED();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitChangeFloat64ToUint64(node_t node) {
    VisitRR(this, kPPC_DoubleToUint64, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitChangeFloat64ToInt64(node_t node) {
    VisitRR(this, kPPC_DoubleToInt64, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTruncateFloat64ToFloat32(node_t node) {
    VisitRR(this, kPPC_DoubleToFloat32, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTruncateFloat64ToWord32(node_t node) {
  VisitRR(this, kArchTruncateDoubleToI, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitRoundFloat64ToInt32(node_t node) {
    VisitRR(this, kPPC_DoubleToInt32, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTruncateFloat32ToInt32(node_t node) {
  PPCOperandGeneratorT<Adapter> g(this);
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const Operation& op = this->Get(node);
    InstructionCode opcode = kPPC_Float32ToInt32;
    if (op.Is<Opmask::kTruncateFloat32ToInt32OverflowToMin>()) {
      opcode |= MiscField::encode(true);
    }
    Emit(opcode, g.DefineAsRegister(node),
         g.UseRegister(this->input_at(node, 0)));
  } else {
    InstructionCode opcode = kPPC_Float32ToInt32;
    TruncateKind kind = OpParameter<TruncateKind>(node->op());
    if (kind == TruncateKind::kSetOverflowToMin) {
      opcode |= MiscField::encode(true);
    }

    Emit(opcode, g.DefineAsRegister(node), g.UseRegister(node->InputAt(0)));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTruncateFloat32ToUint32(node_t node) {
  PPCOperandGeneratorT<Adapter> g(this);
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const Operation& op = this->Get(node);
    InstructionCode opcode = kPPC_Float32ToUint32;
    if (op.Is<Opmask::kTruncateFloat32ToUint32OverflowToMin>()) {
      opcode |= MiscField::encode(true);
    }

    Emit(opcode, g.DefineAsRegister(node),
         g.UseRegister(this->input_at(node, 0)));
  } else {
    InstructionCode opcode = kPPC_Float32ToUint32;
    TruncateKind kind = OpParameter<TruncateKind>(node->op());
    if (kind == TruncateKind::kSetOverflowToMin) {
      opcode |= MiscField::encode(true);
    }

    Emit(opcode, g.DefineAsRegister(node), g.UseRegister(node->InputAt(0)));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTruncateInt64ToInt32(node_t node) {
    // TODO(mbrandy): inspect input to see if nop is appropriate.
    VisitRR(this, kPPC_Int64ToInt32, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitRoundInt64ToFloat32(node_t node) {
    VisitRR(this, kPPC_Int64ToFloat32, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitRoundInt64ToFloat64(node_t node) {
    VisitRR(this, kPPC_Int64ToDouble, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitChangeInt64ToFloat64(node_t node) {
    VisitRR(this, kPPC_Int64ToDouble, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitRoundUint64ToFloat32(node_t node) {
    VisitRR(this, kPPC_Uint64ToFloat32, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitRoundUint64ToFloat64(node_t node) {
    VisitRR(this, kPPC_Uint64ToDouble, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitBitcastFloat32ToInt32(node_t node) {
  VisitRR(this, kPPC_BitcastFloat32ToInt32, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitBitcastFloat64ToInt64(node_t node) {
  VisitRR(this, kPPC_BitcastDoubleToInt64, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitBitcastInt32ToFloat32(node_t node) {
    VisitRR(this, kPPC_BitcastInt32ToFloat32, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitBitcastInt64ToFloat64(node_t node) {
    VisitRR(this, kPPC_BitcastInt64ToDouble, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32Add(node_t node) {
    VisitRRR(this, kPPC_AddDouble | MiscField::encode(1), node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Add(node_t node) {
    // TODO(mbrandy): detect multiply-add
    VisitRRR(this, kPPC_AddDouble, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32Sub(node_t node) {
    VisitRRR(this, kPPC_SubDouble | MiscField::encode(1), node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Sub(node_t node) {
    // TODO(mbrandy): detect multiply-subtract
    VisitRRR(this, kPPC_SubDouble, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32Mul(node_t node) {
    VisitRRR(this, kPPC_MulDouble | MiscField::encode(1), node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Mul(node_t node) {
    // TODO(mbrandy): detect negate
    VisitRRR(this, kPPC_MulDouble, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32Div(node_t node) {
    VisitRRR(this, kPPC_DivDouble | MiscField::encode(1), node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Div(node_t node) {
    VisitRRR(this, kPPC_DivDouble, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Mod(node_t node) {
    PPCOperandGeneratorT<Adapter> g(this);
    Emit(kPPC_ModDouble, g.DefineAsFixed(node, d1),
         g.UseFixed(this->input_at(node, 0), d1),
         g.UseFixed(this->input_at(node, 1), d2))
        ->MarkAsCall();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32Max(node_t node) {
    VisitRRR(this, kPPC_MaxDouble | MiscField::encode(1), node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Max(node_t node) {
    VisitRRR(this, kPPC_MaxDouble, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64SilenceNaN(node_t node) {
    VisitRR(this, kPPC_Float64SilenceNaN, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32Min(node_t node) {
    VisitRRR(this, kPPC_MinDouble | MiscField::encode(1), node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Min(node_t node) {
    VisitRRR(this, kPPC_MinDouble, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32Abs(node_t node) {
    VisitRR(this, kPPC_AbsDouble | MiscField::encode(1), node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Abs(node_t node) {
    VisitRR(this, kPPC_AbsDouble, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32Sqrt(node_t node) {
    VisitRR(this, kPPC_SqrtDouble | MiscField::encode(1), node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Ieee754Unop(
    node_t node, InstructionCode opcode) {
  PPCOperandGeneratorT<Adapter> g(this);
  Emit(opcode, g.DefineAsFixed(node, d1),
       g.UseFixed(this->input_at(node, 0), d1))
      ->MarkAsCall();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Ieee754Binop(
    node_t node, InstructionCode opcode) {
    PPCOperandGeneratorT<Adapter> g(this);
    Emit(opcode, g.DefineAsFixed(node, d1),
         g.UseFixed(this->input_at(node, 0), d1),
         g.UseFixed(this->input_at(node, 1), d2))
        ->MarkAsCall();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Sqrt(node_t node) {
    VisitRR(this, kPPC_SqrtDouble, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32RoundDown(node_t node) {
    VisitRR(this, kPPC_FloorDouble | MiscField::encode(1), node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64RoundDown(node_t node) {
    VisitRR(this, kPPC_FloorDouble, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32RoundUp(node_t node) {
    VisitRR(this, kPPC_CeilDouble | MiscField::encode(1), node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64RoundUp(node_t node) {
    VisitRR(this, kPPC_CeilDouble, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32RoundTruncate(node_t node) {
    VisitRR(this, kPPC_TruncateDouble | MiscField::encode(1), node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64RoundTruncate(node_t node) {
    VisitRR(this, kPPC_TruncateDouble, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64RoundTiesAway(node_t node) {
    VisitRR(this, kPPC_RoundDouble, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32Neg(node_t node) {
    VisitRR(this, kPPC_NegDouble, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Neg(node_t node) {
    VisitRR(this, kPPC_NegDouble, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32AddWithOverflow(node_t node) {
  node_t ovf = FindProjection(node, 1);
  if (this->valid(ovf)) {
    FlagsContinuation cont = FlagsContinuation::ForSet(kOverflow, ovf);
    return VisitBinop<Adapter>(this, node, kPPC_AddWithOverflow32, kInt16Imm,
                               &cont);
  }
    FlagsContinuation cont;
    VisitBinop<Adapter>(this, node, kPPC_AddWithOverflow32, kInt16Imm, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32SubWithOverflow(node_t node) {
  node_t ovf = FindProjection(node, 1);
  if (this->valid(ovf)) {
    FlagsContinuation cont = FlagsContinuation::ForSet(kOverflow, ovf);
    return VisitBinop<Adapter>(this, node, kPPC_SubWithOverflow32,
                               kInt16Imm_Negate, &cont);
  }
    FlagsContinuation cont;
    VisitBinop<Adapter>(this, node, kPPC_SubWithOverflow32, kInt16Imm_Negate,
                        &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt64AddWithOverflow(node_t node) {
  node_t ovf = FindProjection(node, 1);
  if (this->valid(ovf)) {
    FlagsContinuation cont = FlagsContinuation::ForSet(kOverflow, ovf);
    return VisitBinop<Adapter>(this, node, kPPC_Add64, kInt16Imm, &cont);
  }
    FlagsContinuation cont;
    VisitBinop<Adapter>(this, node, kPPC_Add64, kInt16Imm, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt64SubWithOverflow(node_t node) {
  node_t ovf = FindProjection(node, 1);
  if (this->valid(ovf)) {
    FlagsContinuation cont = FlagsContinuation::ForSet(kOverflow, ovf);
    return VisitBinop<Adapter>(this, node, kPPC_Sub, kInt16Imm_Negate, &cont);
  }
    FlagsContinuation cont;
    VisitBinop<Adapter>(this, node, kPPC_Sub, kInt16Imm_Negate, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt64MulWithOverflow(node_t node) {
  node_t ovf = FindProjection(node, 1);
  if (this->valid(ovf)) {
    FlagsContinuation cont = FlagsContinuation::ForSet(kNotEqual, ovf);
    return EmitInt64MulWithOverflow(this, node, &cont);
  }
    FlagsContinuation cont;
    EmitInt64MulWithOverflow(this, node, &cont);
}

template <typename Adapter>
static bool CompareLogical(FlagsContinuationT<Adapter>* cont) {
    switch (cont->condition()) {
      case kUnsignedLessThan:
      case kUnsignedGreaterThanOrEqual:
      case kUnsignedLessThanOrEqual:
      case kUnsignedGreaterThan:
        return true;
      default:
        return false;
    }
    UNREACHABLE();
}

namespace {

// Shared routine for multiple compare operations.
template <typename Adapter>
void VisitCompare(InstructionSelectorT<Adapter>* selector,
                  InstructionCode opcode, InstructionOperand left,
                  InstructionOperand right, FlagsContinuationT<Adapter>* cont) {
  selector->EmitWithContinuation(opcode, left, right, cont);
}

// Shared routine for multiple word compare operations.
template <typename Adapter>
void VisitWordCompare(InstructionSelectorT<Adapter>* selector,
                      typename Adapter::node_t node, InstructionCode opcode,
                      FlagsContinuationT<Adapter>* cont, bool commutative,
                      ImmediateMode immediate_mode) {
    PPCOperandGeneratorT<Adapter> g(selector);
    typename Adapter::node_t lhs = selector->input_at(node, 0);
    typename Adapter::node_t rhs = selector->input_at(node, 1);

    // Match immediates on left or right side of comparison.
    if (g.CanBeImmediate(rhs, immediate_mode)) {
      VisitCompare(selector, opcode, g.UseRegister(lhs), g.UseImmediate(rhs),
                   cont);
    } else if (g.CanBeImmediate(lhs, immediate_mode)) {
      if (!commutative) cont->Commute();
      VisitCompare(selector, opcode, g.UseRegister(rhs), g.UseImmediate(lhs),
                   cont);
    } else {
      VisitCompare(selector, opcode, g.UseRegister(lhs), g.UseRegister(rhs),
                   cont);
    }
}

template <typename Adapter>
void VisitWord32Compare(InstructionSelectorT<Adapter>* selector,
                        typename Adapter::node_t node,
                        FlagsContinuationT<Adapter>* cont) {
    ImmediateMode mode =
        (CompareLogical(cont) ? kInt16Imm_Unsigned : kInt16Imm);
    VisitWordCompare(selector, node, kPPC_Cmp32, cont, false, mode);
}

template <typename Adapter>
void VisitWord64Compare(InstructionSelectorT<Adapter>* selector,
                        typename Adapter::node_t node,
                        FlagsContinuationT<Adapter>* cont) {
  ImmediateMode mode = (CompareLogical(cont) ? kInt16Imm_Unsigned : kInt16Imm);
  VisitWordCompare(selector, node, kPPC_Cmp64, cont, false, mode);
}

// Shared routine for multiple float32 compare operations.
template <typename Adapter>
void VisitFloat32Compare(InstructionSelectorT<Adapter>* selector,
                         typename Adapter::node_t node,
                         FlagsContinuationT<Adapter>* cont) {
    PPCOperandGeneratorT<Adapter> g(selector);
    typename Adapter::node_t lhs = selector->input_at(node, 0);
    typename Adapter::node_t rhs = selector->input_at(node, 1);
    VisitCompare(selector, kPPC_CmpDouble, g.UseRegister(lhs),
                 g.UseRegister(rhs), cont);
}

// Shared routine for multiple float64 compare operations.
template <typename Adapter>
void VisitFloat64Compare(InstructionSelectorT<Adapter>* selector,
                         typename Adapter::node_t node,
                         FlagsContinuationT<Adapter>* cont) {
    PPCOperandGeneratorT<Adapter> g(selector);
    typename Adapter::node_t lhs = selector->input_at(node, 0);
    typename Adapter::node_t rhs = selector->input_at(node, 1);
    VisitCompare(selector, kPPC_CmpDouble, g.UseRegister(lhs),
                 g.UseRegister(rhs), cont);
}

}  // namespace

// Shared routine for word comparisons against zero.
template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWordCompareZero(
    node_t user, node_t value, FlagsContinuation* cont) {
    // Try to combine with comparisons against 0 by simply inverting the branch.
    while (value->opcode() == IrOpcode::kWord32Equal && CanCover(user, value)) {
      Int32BinopMatcher m(value);
      if (!m.right().Is(0)) break;

      user = value;
      value = m.left().node();
      cont->Negate();
    }

    if (CanCover(user, value)) {
      switch (value->opcode()) {
        case IrOpcode::kWord32Equal:
          cont->OverwriteAndNegateIfEqual(kEqual);
          return VisitWord32Compare(this, value, cont);
        case IrOpcode::kInt32LessThan:
          cont->OverwriteAndNegateIfEqual(kSignedLessThan);
          return VisitWord32Compare(this, value, cont);
        case IrOpcode::kInt32LessThanOrEqual:
          cont->OverwriteAndNegateIfEqual(kSignedLessThanOrEqual);
          return VisitWord32Compare(this, value, cont);
        case IrOpcode::kUint32LessThan:
          cont->OverwriteAndNegateIfEqual(kUnsignedLessThan);
          return VisitWord32Compare(this, value, cont);
        case IrOpcode::kUint32LessThanOrEqual:
          cont->OverwriteAndNegateIfEqual(kUnsignedLessThanOrEqual);
          return VisitWord32Compare(this, value, cont);
      case IrOpcode::kWord64Equal:
        cont->OverwriteAndNegateIfEqual(kEqual);
        return VisitWord64Compare(this, value, cont);
      case IrOpcode::kInt64LessThan:
        cont->OverwriteAndNegateIfEqual(kSignedLessThan);
        return VisitWord64Compare(this, value, cont);
      case IrOpcode::kInt64LessThanOrEqual:
        cont->OverwriteAndNegateIfEqual(kSignedLessThanOrEqual);
        return VisitWord64Compare(this, value, cont);
      case IrOpcode::kUint64LessThan:
        cont->OverwriteAndNegateIfEqual(kUnsignedLessThan);
        return VisitWord64Compare(this, value, cont);
      case IrOpcode::kUint64LessThanOrEqual:
        cont->OverwriteAndNegateIfEqual(kUnsignedLessThanOrEqual);
        return VisitWord64Compare(this, value, cont);
      case IrOpcode::kFloat32Equal:
        cont->OverwriteAndNegateIfEqual(kEqual);
        return VisitFloat32Compare(this, value, cont);
      case IrOpcode::kFloat32LessThan:
        cont->OverwriteAndNegateIfEqual(kUnsignedLessThan);
        return VisitFloat32Compare(this, value, cont);
      case IrOpcode::kFloat32LessThanOrEqual:
        cont->OverwriteAndNegateIfEqual(kUnsignedLessThanOrEqual);
        return VisitFloat32Compare(this, value, cont);
      case IrOpcode::kFloat64Equal:
        cont->OverwriteAndNegateIfEqual(kEqual);
        return VisitFloat64Compare(this, value, cont);
      case IrOpcode::kFloat64LessThan:
        cont->OverwriteAndNegateIfEqual(kUnsignedLessThan);
        return VisitFloat64Compare(this, value, cont);
      case IrOpcode::kFloat64LessThanOrEqual:
        cont->OverwriteAndNegateIfEqual(kUnsignedLessThanOrEqual);
        return VisitFloat64Compare(this, value, cont);
      case IrOpcode::kProjection:
        // Check if this is the overflow output projection of an
        // <Operation>WithOverflow node.
        if (ProjectionIndexOf(value->op()) == 1u) {
          // We cannot combine the <Operation>WithOverflow with this branch
          // unless the 0th projection (the use of the actual value of the
          // <Operation> is either nullptr, which means there's no use of the
          // actual value, or was already defined, which means it is scheduled
          // *AFTER* this branch).
          Node* const node = value->InputAt(0);
          Node* const result = NodeProperties::FindProjection(node, 0);
          if (result == nullptr || IsDefined(result)) {
            switch (node->opcode()) {
              case IrOpcode::kInt32AddWithOverflow:
                cont->OverwriteAndNegateIfEqual(kOverflow);
                return VisitBinop<Adapter>(this, node, kPPC_AddWithOverflow32,
                                           kInt16Imm, cont);
              case IrOpcode::kInt32SubWithOverflow:
                cont->OverwriteAndNegateIfEqual(kOverflow);
                return VisitBinop<Adapter>(this, node, kPPC_SubWithOverflow32,
                                           kInt16Imm_Negate, cont);
              case IrOpcode::kInt32MulWithOverflow:
                cont->OverwriteAndNegateIfEqual(kNotEqual);
                return EmitInt32MulWithOverflow(this, node, cont);
              case IrOpcode::kInt64AddWithOverflow:
                cont->OverwriteAndNegateIfEqual(kOverflow);
                return VisitBinop<Adapter>(this, node, kPPC_Add64, kInt16Imm,
                                           cont);
              case IrOpcode::kInt64SubWithOverflow:
                cont->OverwriteAndNegateIfEqual(kOverflow);
                return VisitBinop<Adapter>(this, node, kPPC_Sub,
                                           kInt16Imm_Negate, cont);
              case IrOpcode::kInt64MulWithOverflow:
                cont->OverwriteAndNegateIfEqual(kNotEqual);
                return EmitInt64MulWithOverflow(this, node, cont);
              default:
                break;
            }
          }
        }
        break;
      case IrOpcode::kInt32Sub:
        return VisitWord32Compare(this, value, cont);
      case IrOpcode::kWord32And:
        // TODO(mbandy): opportunity for rlwinm?
        return VisitWordCompare(this, value, kPPC_Tst32, cont, true,
                                kInt16Imm_Unsigned);
// TODO(mbrandy): Handle?
// case IrOpcode::kInt32Add:
// case IrOpcode::kWord32Or:
// case IrOpcode::kWord32Xor:
// case IrOpcode::kWord32Sar:
// case IrOpcode::kWord32Shl:
// case IrOpcode::kWord32Shr:
// case IrOpcode::kWord32Ror:
      case IrOpcode::kInt64Sub:
        return VisitWord64Compare(this, value, cont);
      case IrOpcode::kWord64And:
        // TODO(mbandy): opportunity for rldic?
        return VisitWordCompare(this, value, kPPC_Tst64, cont, true,
                                kInt16Imm_Unsigned);
// TODO(mbrandy): Handle?
// case IrOpcode::kInt64Add:
// case IrOpcode::kWord64Or:
// case IrOpcode::kWord64Xor:
// case IrOpcode::kWord64Sar:
// case IrOpcode::kWord64Shl:
// case IrOpcode::kWord64Shr:
// case IrOpcode::kWord64Ror:
      case IrOpcode::kStackPointerGreaterThan:
        cont->OverwriteAndNegateIfEqual(kStackPointerGreaterThanCondition);
        return VisitStackPointerGreaterThan(value, cont);
      default:
        break;
      }
    }

  // Branch could not be combined with a compare, emit compare against 0.
  PPCOperandGeneratorT<Adapter> g(this);
  VisitCompare(this, kPPC_Cmp32, g.UseRegister(value), g.TempImmediate(0),
               cont);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitWordCompareZero(
    node_t user, node_t value, FlagsContinuation* cont) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  // Try to combine with comparisons against 0 by simply inverting the branch.
  ConsumeEqualZero(&user, &value, cont);

  if (CanCover(user, value)) {
    const Operation& value_op = Get(value);
    if (const ComparisonOp* comparison = value_op.TryCast<ComparisonOp>()) {
      switch (comparison->rep.MapTaggedToWord().value()) {
        case RegisterRepresentation::Word32():
          cont->OverwriteAndNegateIfEqual(
              GetComparisonFlagCondition(*comparison));
          return VisitWord32Compare(this, value, cont);
        case RegisterRepresentation::Word64():
          cont->OverwriteAndNegateIfEqual(
              GetComparisonFlagCondition(*comparison));
          return VisitWord64Compare(this, value, cont);
        case RegisterRepresentation::Float32():
          switch (comparison->kind) {
            case ComparisonOp::Kind::kEqual:
              cont->OverwriteAndNegateIfEqual(kEqual);
              return VisitFloat32Compare(this, value, cont);
            case ComparisonOp::Kind::kSignedLessThan:
              cont->OverwriteAndNegateIfEqual(kUnsignedLessThan);
              return VisitFloat32Compare(this, value, cont);
            case ComparisonOp::Kind::kSignedLessThanOrEqual:
              cont->OverwriteAndNegateIfEqual(kUnsignedLessThanOrEqual);
              return VisitFloat32Compare(this, value, cont);
            default:
              UNREACHABLE();
          }
        case RegisterRepresentation::Float64():
          switch (comparison->kind) {
            case ComparisonOp::Kind::kEqual:
              cont->OverwriteAndNegateIfEqual(kEqual);
              return VisitFloat64Compare(this, value, cont);
            case ComparisonOp::Kind::kSignedLessThan:
              cont->OverwriteAndNegateIfEqual(kUnsignedLessThan);
              return VisitFloat64Compare(this, value, cont);
            case ComparisonOp::Kind::kSignedLessThanOrEqual:
              cont->OverwriteAndNegateIfEqual(kUnsignedLessThanOrEqual);
              return VisitFloat64Compare(this, value, cont);
            default:
              UNREACHABLE();
          }
        default:
          break;
      }
    } else if (const ProjectionOp* projection =
                   value_op.TryCast<ProjectionOp>()) {
      // Check if this is the overflow output projection of an
      // <Operation>WithOverflow node.
      if (projection->index == 1u) {
        // We cannot combine the <Operation>WithOverflow with this branch
        // unless the 0th projection (the use of the actual value of the
        // <Operation> is either nullptr, which means there's no use of the
        // actual value, or was already defined, which means it is scheduled
        // *AFTER* this branch).
        OpIndex node = projection->input();
        OpIndex result = FindProjection(node, 0);
        if (!result.valid() || IsDefined(result)) {
          if (const OverflowCheckedBinopOp* binop =
                  TryCast<OverflowCheckedBinopOp>(node)) {
            const bool is64 = binop->rep == WordRepresentation::Word64();
            switch (binop->kind) {
              case OverflowCheckedBinopOp::Kind::kSignedAdd:
                cont->OverwriteAndNegateIfEqual(kOverflow);
                return VisitBinop(this, node,
                                  is64 ? kPPC_Add64 : kPPC_AddWithOverflow32,
                                  kInt16Imm, cont);
              case OverflowCheckedBinopOp::Kind::kSignedSub:
                cont->OverwriteAndNegateIfEqual(kOverflow);
                return VisitBinop(this, node,
                                  is64 ? kPPC_Sub : kPPC_SubWithOverflow32,
                                  kInt16Imm_Negate, cont);
              case OverflowCheckedBinopOp::Kind::kSignedMul:
                if (is64) {
                  cont->OverwriteAndNegateIfEqual(kNotEqual);
                  return EmitInt64MulWithOverflow(this, node, cont);
                } else {
                  cont->OverwriteAndNegateIfEqual(kNotEqual);
                  return EmitInt32MulWithOverflow(this, node, cont);
                }
            }
          }
        }
      }
    } else if (value_op.Is<Opmask::kWord32Sub>()) {
      return VisitWord32Compare(this, value, cont);
    } else if (value_op.Is<Opmask::kWord32BitwiseAnd>()) {
      return VisitWordCompare(this, value, kPPC_Tst32, cont, true,
                              kInt16Imm_Unsigned);
    } else if (value_op.Is<Opmask::kWord64Sub>()) {
      return VisitWord64Compare(this, value, cont);
    } else if (value_op.Is<Opmask::kWord64BitwiseAnd>()) {
      return VisitWordCompare(this, value, kPPC_Tst64, cont, true,
                              kInt16Imm_Unsigned);
    } else if (value_op.Is<StackPointerGreaterThanOp>()) {
      cont->OverwriteAndNegateIfEqual(kStackPointerGreaterThanCondition);
      return VisitStackPointerGreaterThan(value, cont);
    }
  }

  // Branch could not be combined with a compare, emit compare against 0.
  PPCOperandGeneratorT<TurboshaftAdapter> g(this);
  VisitCompare(this, kPPC_Cmp32, g.UseRegister(value), g.TempImmediate(0),
               cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitSwitch(node_t node,
                                                const SwitchInfo& sw) {
  PPCOperandGeneratorT<Adapter> g(this);
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
      Emit(kPPC_Sub, index_operand, value_operand,
           g.TempImmediate(sw.min_value()));
      }
      // Zero extend, because we use it as 64-bit index into the jump table.
      InstructionOperand index_operand_zero_ext = g.TempRegister();
      Emit(kPPC_Uint32ToUint64, index_operand_zero_ext, index_operand);
      index_operand = index_operand_zero_ext;
      // Generate a table lookup.
      return EmitTableSwitch(sw, index_operand);
  }
  }

  // Generate a tree of conditional jumps.
  return EmitBinarySearchSwitch(sw, value_operand);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitWord32Equal(
    node_t const node) {
  FlagsContinuation cont = FlagsContinuation::ForSet(kEqual, node);
  if (isolate() && (V8_STATIC_ROOTS_BOOL ||
                    (COMPRESS_POINTERS_BOOL && !isolate()->bootstrapper()))) {
    PPCOperandGeneratorT<TurbofanAdapter> g(this);
    const RootsTable& roots_table = isolate()->roots_table();
    RootIndex root_index;
    Node* left = nullptr;
    Handle<HeapObject> right;
    // HeapConstants and CompressedHeapConstants can be treated the same when
    // using them as an input to a 32-bit comparison. Check whether either is
    // present.
    {
      CompressedHeapObjectBinopMatcher m(node);
      if (m.right().HasResolvedValue()) {
      left = m.left().node();
      right = m.right().ResolvedValue();
      } else {
      HeapObjectBinopMatcher m2(node);
      if (m2.right().HasResolvedValue()) {
          left = m2.left().node();
          right = m2.right().ResolvedValue();
      }
      }
    }
  if (!right.is_null() && roots_table.IsRootHandle(right, &root_index)) {
      DCHECK_NE(left, nullptr);
      if (RootsTable::IsReadOnly(root_index)) {
      Tagged_t ptr = MacroAssemblerBase::ReadOnlyRootPtr(root_index, isolate());
      if (g.CanBeImmediate(ptr, kInt16Imm)) {
          return VisitCompare(this, kPPC_Cmp32, g.UseRegister(left),
                              g.TempImmediate(ptr), &cont);
      }
      }
  }
  }
  VisitWord32Compare(this, node, &cont);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitWord32Equal(
    node_t const node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  const Operation& equal = Get(node);
  DCHECK(equal.Is<ComparisonOp>());
  OpIndex left = equal.input(0);
  FlagsContinuation cont = FlagsContinuation::ForSet(kEqual, node);
  if (isolate() && (V8_STATIC_ROOTS_BOOL ||
                    (COMPRESS_POINTERS_BOOL && !isolate()->bootstrapper()))) {
    PPCOperandGeneratorT<TurboshaftAdapter> g(this);
    const RootsTable& roots_table = isolate()->roots_table();
    RootIndex root_index;
    Handle<HeapObject> right;
    // HeapConstants and CompressedHeapConstants can be treated the same when
    // using them as an input to a 32-bit comparison. Check whether either is
    // present.
    if (MatchHeapConstant(node, &right) && !right.is_null() &&
        roots_table.IsRootHandle(right, &root_index)) {
      if (RootsTable::IsReadOnly(root_index)) {
        Tagged_t ptr =
            MacroAssemblerBase::ReadOnlyRootPtr(root_index, isolate());
        if (g.CanBeImmediate(ptr, kInt16Imm)) {
          return VisitCompare(this, kPPC_Cmp32, g.UseRegister(left),
                              g.TempImmediate(ptr), &cont);
        }
      }
    }
  }
  VisitWord32Compare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32LessThan(node_t node) {
  FlagsContinuation cont = FlagsContinuation::ForSet(kSignedLessThan, node);
  VisitWord32Compare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32LessThanOrEqual(node_t node) {
  FlagsContinuation cont =
      FlagsContinuation::ForSet(kSignedLessThanOrEqual, node);
  VisitWord32Compare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUint32LessThan(node_t node) {
  FlagsContinuation cont = FlagsContinuation::ForSet(kUnsignedLessThan, node);
  VisitWord32Compare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUint32LessThanOrEqual(node_t node) {
  FlagsContinuation cont =
      FlagsContinuation::ForSet(kUnsignedLessThanOrEqual, node);
  VisitWord32Compare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64Equal(node_t const node) {
  FlagsContinuation cont = FlagsContinuation::ForSet(kEqual, node);
  VisitWord64Compare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt64LessThan(node_t node) {
  FlagsContinuation cont = FlagsContinuation::ForSet(kSignedLessThan, node);
  VisitWord64Compare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt64LessThanOrEqual(node_t node) {
  FlagsContinuation cont =
      FlagsContinuation::ForSet(kSignedLessThanOrEqual, node);
  VisitWord64Compare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUint64LessThan(node_t node) {
  FlagsContinuation cont = FlagsContinuation::ForSet(kUnsignedLessThan, node);
  VisitWord64Compare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUint64LessThanOrEqual(node_t node) {
  FlagsContinuation cont =
      FlagsContinuation::ForSet(kUnsignedLessThanOrEqual, node);
  VisitWord64Compare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32MulWithOverflow(node_t node) {
  node_t ovf = FindProjection(node, 1);
  if (this->valid(ovf)) {
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
  FlagsContinuation cont = FlagsContinuation::ForSet(kUnsignedLessThan, node);
  VisitFloat32Compare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32LessThanOrEqual(node_t node) {
  FlagsContinuation cont =
      FlagsContinuation::ForSet(kUnsignedLessThanOrEqual, node);
  VisitFloat32Compare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Equal(node_t node) {
  FlagsContinuation cont = FlagsContinuation::ForSet(kEqual, node);
  VisitFloat64Compare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64LessThan(node_t node) {
  FlagsContinuation cont = FlagsContinuation::ForSet(kUnsignedLessThan, node);
  VisitFloat64Compare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64LessThanOrEqual(node_t node) {
  FlagsContinuation cont =
      FlagsContinuation::ForSet(kUnsignedLessThanOrEqual, node);
  VisitFloat64Compare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::EmitMoveParamToFPR(node_t node, int index) {
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::EmitMoveFPRToParam(
    InstructionOperand* op, LinkageLocation location) {}

template <typename Adapter>
void InstructionSelectorT<Adapter>::EmitPrepareArguments(
    ZoneVector<PushParameter>* arguments, const CallDescriptor* call_descriptor,
    node_t node) {
  PPCOperandGeneratorT<Adapter> g(this);

  // Prepare for C function call.
  if (call_descriptor->IsCFunctionCall()) {
    Emit(kArchPrepareCallCFunction | MiscField::encode(static_cast<int>(
                                         call_descriptor->ParameterCount())),
         0, nullptr, 0, nullptr);

    // Poke any stack arguments.
    int slot = kStackFrameExtraParamSlot;
    for (PushParameter input : (*arguments)) {
      if (!this->valid(input.node)) continue;
      Emit(kPPC_StoreToStackSlot, g.NoOutput(), g.UseRegister(input.node),
           g.TempImmediate(slot));
      ++slot;
    }
  } else {
    // Push any stack arguments.
    int stack_decrement = 0;
    for (PushParameter input : base::Reversed(*arguments)) {
      stack_decrement += kSystemPointerSize;
      // Skip any alignment holes in pushed nodes.
      if (!this->valid(input.node)) continue;
      InstructionOperand decrement = g.UseImmediate(stack_decrement);
      stack_decrement = 0;
      Emit(kPPC_Push, g.NoOutput(), decrement, g.UseRegister(input.node));
    }
  }
}

template <typename Adapter>
bool InstructionSelectorT<Adapter>::IsTailCallAddressImmediate() {
  return false;
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64ExtractLowWord32(node_t node) {
  PPCOperandGeneratorT<Adapter> g(this);
  Emit(kPPC_DoubleExtractLowWord32, g.DefineAsRegister(node),
       g.UseRegister(this->input_at(node, 0)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64ExtractHighWord32(node_t node) {
  PPCOperandGeneratorT<Adapter> g(this);
  Emit(kPPC_DoubleExtractHighWord32, g.DefineAsRegister(node),
       g.UseRegister(this->input_at(node, 0)));
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitBitcastWord32PairToFloat64(
    node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  PPCOperandGeneratorT<TurboshaftAdapter> g(this);
  const auto& bitcast = this->Cast<BitcastWord32PairToFloat64Op>(node);
  node_t hi = bitcast.high_word32();
  node_t lo = bitcast.low_word32();

  InstructionOperand temps[] = {g.TempRegister()};
  Emit(kPPC_DoubleFromWord32Pair, g.DefineAsRegister(node), g.UseRegister(hi),
       g.UseRegister(lo), arraysize(temps), temps);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64InsertLowWord32(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
  UNIMPLEMENTED();
  } else {
  PPCOperandGeneratorT<Adapter> g(this);
  Node* left = node->InputAt(0);
  Node* right = node->InputAt(1);
  if (left->opcode() == IrOpcode::kFloat64InsertHighWord32 &&
      CanCover(node, left)) {
    left = left->InputAt(1);
    Emit(kPPC_DoubleConstruct, g.DefineAsRegister(node), g.UseRegister(left),
         g.UseRegister(right));
    return;
  }
  Emit(kPPC_DoubleInsertLowWord32, g.DefineSameAsFirst(node),
       g.UseRegister(left), g.UseRegister(right));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64InsertHighWord32(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
  UNIMPLEMENTED();
  } else {
  PPCOperandGeneratorT<Adapter> g(this);
  Node* left = node->InputAt(0);
  Node* right = node->InputAt(1);
  if (left->opcode() == IrOpcode::kFloat64InsertLowWord32 &&
      CanCover(node, left)) {
    left = left->InputAt(1);
    Emit(kPPC_DoubleConstruct, g.DefineAsRegister(node), g.UseRegister(right),
         g.UseRegister(left));
    return;
  }
  Emit(kPPC_DoubleInsertHighWord32, g.DefineSameAsFirst(node),
       g.UseRegister(left), g.UseRegister(right));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitMemoryBarrier(node_t node) {
  PPCOperandGeneratorT<Adapter> g(this);
  Emit(kPPC_Sync, g.NoOutput());
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicLoad(node_t node) {
  auto load_view = this->load_view(node);
  ImmediateMode mode;
  InstructionCode opcode = SelectLoadOpcode(load_view.loaded_rep(), &mode);
  VisitLoadCommon(this, node, mode, opcode);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64AtomicLoad(node_t node) {
  auto load_view = this->load_view(node);
  ImmediateMode mode;
  InstructionCode opcode = SelectLoadOpcode(load_view.loaded_rep(), &mode);
  VisitLoadCommon(this, node, mode, opcode);
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
void InstructionSelectorT<Adapter>::VisitWord64AtomicStore(node_t node) {
  auto store = this->store_view(node);
  AtomicStoreParameters store_params(store.stored_rep().representation(),
                                     store.stored_rep().write_barrier_kind(),
                                     store.memory_order().value(),
                                     store.access_kind());
  VisitStoreCommon(this, node, store_params.store_representation(),
                   store_params.order());
}

template <typename Adapter>
void VisitAtomicExchange(InstructionSelectorT<Adapter>* selector,
                         typename Adapter::node_t node, ArchOpcode opcode) {
  using node_t = typename Adapter::node_t;
  PPCOperandGeneratorT<Adapter> g(selector);
  auto atomic_op = selector->atomic_rmw_view(node);
  node_t base = atomic_op.base();
  node_t index = atomic_op.index();
  node_t value = atomic_op.value();

  AddressingMode addressing_mode = kMode_MRR;
  InstructionOperand inputs[3];
  size_t input_count = 0;
  inputs[input_count++] = g.UseUniqueRegister(base);
  inputs[input_count++] = g.UseUniqueRegister(index);
  inputs[input_count++] = g.UseUniqueRegister(value);
  InstructionOperand outputs[1];
  outputs[0] = g.UseUniqueRegister(node);
  InstructionCode code = opcode | AddressingModeField::encode(addressing_mode);
  selector->Emit(code, 1, outputs, input_count, inputs);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicExchange(node_t node) {
  ArchOpcode opcode;
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const AtomicRMWOp& atomic_op = this->Get(node).template Cast<AtomicRMWOp>();
    if (atomic_op.memory_rep == MemoryRepresentation::Int8()) {
      opcode = kAtomicExchangeInt8;
    } else if (atomic_op.memory_rep == MemoryRepresentation::Uint8()) {
      opcode = kPPC_AtomicExchangeUint8;
    } else if (atomic_op.memory_rep == MemoryRepresentation::Int16()) {
      opcode = kAtomicExchangeInt16;
    } else if (atomic_op.memory_rep == MemoryRepresentation::Uint16()) {
      opcode = kPPC_AtomicExchangeUint16;
    } else if (atomic_op.memory_rep == MemoryRepresentation::Int32() ||
               atomic_op.memory_rep == MemoryRepresentation::Uint32()) {
      opcode = kPPC_AtomicExchangeWord32;
    } else {
      UNREACHABLE();
    }
  } else {
    MachineType type = AtomicOpType(node->op());
    if (type == MachineType::Int8()) {
      opcode = kAtomicExchangeInt8;
    } else if (type == MachineType::Uint8()) {
      opcode = kPPC_AtomicExchangeUint8;
    } else if (type == MachineType::Int16()) {
      opcode = kAtomicExchangeInt16;
    } else if (type == MachineType::Uint16()) {
      opcode = kPPC_AtomicExchangeUint16;
    } else if (type == MachineType::Int32() || type == MachineType::Uint32()) {
      opcode = kPPC_AtomicExchangeWord32;
    } else {
      UNREACHABLE();
    }
  }
  VisitAtomicExchange(this, node, opcode);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64AtomicExchange(node_t node) {
  ArchOpcode opcode;
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const AtomicRMWOp& atomic_op = this->Get(node).template Cast<AtomicRMWOp>();
    if (atomic_op.memory_rep == MemoryRepresentation::Uint8()) {
      opcode = kPPC_AtomicExchangeUint8;
    } else if (atomic_op.memory_rep == MemoryRepresentation::Uint16()) {
      opcode = kPPC_AtomicExchangeUint16;
    } else if (atomic_op.memory_rep == MemoryRepresentation::Uint32()) {
      opcode = kPPC_AtomicExchangeWord32;
    } else if (atomic_op.memory_rep == MemoryRepresentation::Uint64()) {
      opcode = kPPC_AtomicExchangeWord64;
    } else {
      UNREACHABLE();
    }
  } else {
    MachineType type = AtomicOpType(node->op());
    if (type == MachineType::Uint8()) {
      opcode = kPPC_AtomicExchangeUint8;
    } else if (type == MachineType::Uint16()) {
      opcode = kPPC_AtomicExchangeUint16;
    } else if (type == MachineType::Uint32()) {
      opcode = kPPC_AtomicExchangeWord32;
    } else if (type == MachineType::Uint64()) {
      opcode = kPPC_AtomicExchangeWord64;
    } else {
      UNREACHABLE();
    }
  }
  VisitAtomicExchange(this, node, opcode);
}

template <typename Adapter>
void VisitAtomicCompareExchange(InstructionSelectorT<Adapter>* selector,
                                typename Adapter::node_t node,
                                ArchOpcode opcode) {
  using node_t = typename Adapter::node_t;
  PPCOperandGeneratorT<Adapter> g(selector);
  auto atomic_op = selector->atomic_rmw_view(node);
  node_t base = atomic_op.base();
  node_t index = atomic_op.index();
  node_t old_value = atomic_op.expected();
  node_t new_value = atomic_op.value();

  AddressingMode addressing_mode = kMode_MRR;
  InstructionCode code = opcode | AddressingModeField::encode(addressing_mode);

  InstructionOperand inputs[4];
  size_t input_count = 0;
  inputs[input_count++] = g.UseUniqueRegister(base);
  inputs[input_count++] = g.UseUniqueRegister(index);
  inputs[input_count++] = g.UseUniqueRegister(old_value);
  inputs[input_count++] = g.UseUniqueRegister(new_value);

  InstructionOperand outputs[1];
  size_t output_count = 0;
  outputs[output_count++] = g.DefineAsRegister(node);

  selector->Emit(code, output_count, outputs, input_count, inputs);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicCompareExchange(
    node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  ArchOpcode opcode;
  if constexpr (Adapter::IsTurboshaft) {
    const AtomicRMWOp& atomic_op = this->Get(node).template Cast<AtomicRMWOp>();
    if (atomic_op.memory_rep == MemoryRepresentation::Int8()) {
      opcode = kAtomicCompareExchangeInt8;
    } else if (atomic_op.memory_rep == MemoryRepresentation::Uint8()) {
      opcode = kPPC_AtomicCompareExchangeUint8;
    } else if (atomic_op.memory_rep == MemoryRepresentation::Int16()) {
      opcode = kAtomicCompareExchangeInt16;
    } else if (atomic_op.memory_rep == MemoryRepresentation::Uint16()) {
      opcode = kPPC_AtomicCompareExchangeUint16;
    } else if (atomic_op.memory_rep == MemoryRepresentation::Int32() ||
               atomic_op.memory_rep == MemoryRepresentation::Uint32()) {
      opcode = kPPC_AtomicCompareExchangeWord32;
    } else {
      UNREACHABLE();
    }
  } else {
    MachineType type = AtomicOpType(node->op());
    if (type == MachineType::Int8()) {
      opcode = kAtomicCompareExchangeInt8;
    } else if (type == MachineType::Uint8()) {
      opcode = kPPC_AtomicCompareExchangeUint8;
    } else if (type == MachineType::Int16()) {
      opcode = kAtomicCompareExchangeInt16;
    } else if (type == MachineType::Uint16()) {
      opcode = kPPC_AtomicCompareExchangeUint16;
    } else if (type == MachineType::Int32() || type == MachineType::Uint32()) {
      opcode = kPPC_AtomicCompareExchangeWord32;
    } else {
      UNREACHABLE();
    }
  }
  VisitAtomicCompareExchange(this, node, opcode);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64AtomicCompareExchange(
    node_t node) {
  ArchOpcode opcode;
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const AtomicRMWOp& atomic_op = this->Get(node).template Cast<AtomicRMWOp>();
    if (atomic_op.memory_rep == MemoryRepresentation::Uint8()) {
      opcode = kPPC_AtomicCompareExchangeUint8;
    } else if (atomic_op.memory_rep == MemoryRepresentation::Uint16()) {
      opcode = kPPC_AtomicCompareExchangeUint16;
    } else if (atomic_op.memory_rep == MemoryRepresentation::Uint32()) {
      opcode = kPPC_AtomicCompareExchangeWord32;
    } else if (atomic_op.memory_rep == MemoryRepresentation::Uint64()) {
      opcode = kPPC_AtomicCompareExchangeWord64;
    } else {
      UNREACHABLE();
    }
  } else {
    MachineType type = AtomicOpType(node->op());
    if (type == MachineType::Uint8()) {
      opcode = kPPC_AtomicCompareExchangeUint8;
    } else if (type == MachineType::Uint16()) {
      opcode = kPPC_AtomicCompareExchangeUint16;
    } else if (type == MachineType::Uint32()) {
      opcode = kPPC_AtomicCompareExchangeWord32;
    } else if (type == MachineType::Uint64()) {
      opcode = kPPC_AtomicCompareExchangeWord64;
    } else {
      UNREACHABLE();
    }
  }
  VisitAtomicCompareExchange(this, node, opcode);
}

template <typename Adapter>
void VisitAtomicBinaryOperation(InstructionSelectorT<Adapter>* selector,
                                typename Adapter::node_t node,
                                ArchOpcode int8_op, ArchOpcode uint8_op,
                                ArchOpcode int16_op, ArchOpcode uint16_op,
                                ArchOpcode int32_op, ArchOpcode uint32_op,
                                ArchOpcode int64_op, ArchOpcode uint64_op) {
  using node_t = typename Adapter::node_t;
  PPCOperandGeneratorT<Adapter> g(selector);
  auto atomic_op = selector->atomic_rmw_view(node);
  node_t base = atomic_op.base();
  node_t index = atomic_op.index();
  node_t value = atomic_op.value();

  ArchOpcode opcode;
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const AtomicRMWOp& atomic_op =
        selector->Get(node).template Cast<AtomicRMWOp>();
    if (atomic_op.memory_rep == MemoryRepresentation::Int8()) {
      opcode = int8_op;
    } else if (atomic_op.memory_rep == MemoryRepresentation::Uint8()) {
      opcode = uint8_op;
    } else if (atomic_op.memory_rep == MemoryRepresentation::Int16()) {
      opcode = int16_op;
    } else if (atomic_op.memory_rep == MemoryRepresentation::Uint16()) {
      opcode = uint16_op;
    } else if (atomic_op.memory_rep == MemoryRepresentation::Int32()) {
      opcode = int32_op;
    } else if (atomic_op.memory_rep == MemoryRepresentation::Uint32()) {
      opcode = uint32_op;
    } else if (atomic_op.memory_rep == MemoryRepresentation::Int64()) {
      opcode = int64_op;
    } else if (atomic_op.memory_rep == Memor
```