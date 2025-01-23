Response:
The user wants a summary of the functionalities present in the provided C++ header file for the RISC-V architecture within the V8 JavaScript engine.

Here's a breakdown of the thought process to arrive at the summary:

1. **Identify the Core Purpose:** The file name `instruction-selector-riscv.h` strongly suggests its primary role is selecting and emitting RISC-V instructions based on higher-level operations. This is the central function.

2. **Look for Key Classes and Templates:** The code heavily uses templates like `InstructionSelectorT<Adapter>`, `RiscvOperandGeneratorT<Adapter>`, and `FlagsContinuationT<Adapter>`. These indicate a generic design allowing adaptation for different stages or needs within the compilation pipeline (represented by `Adapter`).

3. **Analyze Function Names and Groupings:**  The functions often follow a pattern like `Visit[Operation]` (e.g., `VisitFloat32Add`, `VisitWord32Shl`). This pattern clearly links the code to specific operations or nodes in an intermediate representation (likely the Turbofan or Turboshaft graph). Grouping these functions by data type (float32, float64, int32, SIMD) reveals distinct sets of supported operations.

4. **Examine Emitted Instructions:** Calls to `selector->Emit...` or `Emit(...)` followed by constants like `kRiscvCmpZero`, `kRiscvAddS`, `kRiscvVaddVv` are the core instruction emission logic. Recognizing these as RISC-V mnemonics confirms the instruction selection aspect.

5. **Focus on Specific Operation Categories:**
    * **Comparisons:** Functions like `EmitWordCompareZero`, `VisitFloat32Equal`, `VisitFloat64LessThan` deal with generating compare instructions and managing flags.
    * **Floating-Point Operations:**  A wide range of functions for arithmetic (`Add`, `Sub`, `Mul`, `Div`), comparisons, conversions (`TruncateFloat64ToWord32`, `TruncateFloat64ToFloat32`), and special operations (`Abs`, `Sqrt`, `SilenceNaN`).
    * **Integer Operations:**  Basic arithmetic and bitwise operations (`Shl`, `Shr`, `Sar`).
    * **SIMD Operations:**  A substantial portion is dedicated to SIMD instructions, including arithmetic, logical, comparison, lane manipulation, and conversions for various data types (I8x16, I16x8, I32x4, I64x2, F32x4, F64x2). The presence of RVV-specific instructions (those with `V` in the mnemonic) indicates vector processing support.
    * **Memory Barriers:**  The `VisitMemoryBarrier` function and `kRiscvSync` instruction indicate handling memory synchronization.
    * **Call Handling:**  `EmitPrepareResults` suggests preparing data for function calls.
    * **Conversions:**  Functions like `VisitBitcastWord32PairToFloat64` handle type reinterpretations.

6. **Consider the Role of `RiscvOperandGeneratorT`:** This class is used to create operands for instructions, handling registers, immediates, and potentially memory locations.

7. **Infer Adapter's Purpose:** The use of templates with `Adapter` suggests a way to customize the instruction selection process for different compilation phases or optimizers (like Turbofan and Turboshaft).

8. **Address Specific Questions from the Prompt:**
    * **`.tq` extension:**  The code confirms that the file is a `.h` header file, not a Torque file.
    * **JavaScript Relevance:** The file is crucial for compiling JavaScript to RISC-V machine code. The floating-point and integer operations directly correspond to JavaScript number and bitwise operations. The SIMD instructions are related to WebAssembly SIMD and potentially JavaScript typed arrays.
    * **Code Logic Inference:** The comparison functions combined with `FlagsContinuation` demonstrate a pattern for setting processor flags based on comparison results.
    * **Common Programming Errors:** The file itself doesn't directly *cause* common JavaScript errors, but incorrect instruction selection *could* lead to incorrect behavior mirroring such errors (e.g., incorrect floating-point results).

9. **Structure the Summary:** Organize the findings into logical categories to make the information clear and digestible. Start with the main purpose and then elaborate on specific functionalities.

10. **Refine and Elaborate:** Review the initial summary for clarity, completeness, and accuracy. Add details like the role of operands and the significance of the `Adapter` template. Ensure the language is precise and avoids jargon where possible.
这是一个V8源代码文件，位于`v8/src/compiler/backend/riscv/`目录下，名为`instruction-selector-riscv.h`。根据您的描述，这是一个C++头文件（因为没有以`.tq`结尾）。

**这个文件的主要功能是为RISC-V架构的V8后端实现指令选择。**

更具体地说，它定义了 `InstructionSelectorT` 模板类及其相关的辅助函数和结构，用于将高级的、平台无关的中间表示（例如，来自Turbofan或Turboshaft编译器）的节点转换为特定的RISC-V汇编指令。

**以下是根据您提供的代码片段归纳出的功能点：**

1. **比较操作 (Comparison Operations):**
   - 提供了比较寄存器或立即数与零的函数 (`EmitWordCompareZero`, `EmitWord32CompareZero`)，并允许指定比较结果的后续处理 (`FlagsContinuationT`).
   - 针对 `float32` 和 `float64` 类型的相等、小于、小于等于比较 (`VisitFloat32Equal`, `VisitFloat32LessThan`, 等等)。这些函数会设置相应的条件标志。

2. **浮点数操作 (Floating-Point Operations):**
   - 提供了提取 `float64` 类型的高低 32 位字的指令 (`VisitFloat64ExtractLowWord32`, `VisitFloat64ExtractHighWord32`).
   - 提供了静默 NaN 的指令 (`VisitFloat64SilenceNaN`).
   - 提供了将 32 位整数对转换为 `float64` 的指令 (`VisitBitcastWord32PairToFloat64`).
   - 提供了插入 `float64` 类型的高低 32 位字的指令 (`VisitFloat64InsertLowWord32`, `VisitFloat64InsertHighWord32`).
   - 提供了浮点数的绝对值、平方根、向下取整等操作 (`VisitFloat32Abs`, `VisitFloat64Abs`, `VisitFloat32Sqrt`, `VisitFloat64Sqrt`, `VisitFloat32RoundDown`).
   - 提供了浮点数的加、减、乘、除、取模操作 (`VisitFloat32Add`, `VisitFloat64Add`, `VisitFloat32Sub`, `VisitFloat64Sub`, `VisitFloat32Mul`, `VisitFloat64Mul`, `VisitFloat32Div`, `VisitFloat64Div`, `VisitFloat64Mod`).
   - 提供了浮点数的最大值和最小值操作 (`VisitFloat32Max`, `VisitFloat64Max`, `VisitFloat32Min`, `VisitFloat64Min`).
   - 提供了将 `float64` 转换为 `word32` 和 `float32` 的操作 (`VisitTruncateFloat64ToWord32`, `VisitRoundFloat64ToInt32`, `VisitTruncateFloat64ToFloat32`).

3. **整数操作 (Integer Operations):**
   - 提供了 32 位整数的左移、右移、算术右移操作 (`VisitWord32Shl`, `VisitWord32Shr`, `VisitWord32Sar`). 其中 `VisitWord32Sar` 针对 TurbofanAdapter 进行了特定的优化，可以识别 `Word32Sar(Word32Shl(x, imm), imm)` 模式并生成更高效的符号扩展指令。

4. **内存屏障 (Memory Barrier):**
   - 提供了内存屏障指令 (`VisitMemoryBarrier`)，用于保证内存操作的顺序性。

5. **函数调用准备 (Call Preparation):**
   - 提供了 `EmitPrepareResults` 函数，用于在函数调用前准备返回值，特别是处理返回值位于调用者帧槽的情况。

6. **浮点寄存器参数传递 (Floating-Point Register Parameter Passing):**
   - 提供了将参数移动到浮点寄存器 (`EmitMoveParamToFPR`) 和从浮点寄存器移动参数 (`EmitMoveFPRToParam`) 的函数，尽管在提供的代码片段中，`EmitMoveParamToFPR` 是空的。

7. **SIMD 操作 (SIMD Operations - 向量处理):**
   - 提供了大量的 SIMD 指令支持，涵盖了各种数据类型 (I8x16, I16x8, I32x4, I64x2, F32x4, F64x2) 的操作，包括：
     - 成对加法扩展 (`VisitI32x4ExtAddPairwiseI16x8S`, `VisitI32x4ExtAddPairwiseI16x8U`, `VisitI16x8ExtAddPairwiseI8x16S`, `VisitI16x8ExtAddPairwiseI8x16U`).
     - 各种一元操作，如取负、绝对值、Splat (创建所有元素相同值的向量) (`SIMD_UNOP_LIST2`, `SIMD_UNOP_LIST`).
     - 移位操作 (`SIMD_SHIFT_OP_LIST`).
     - 各种二元操作，如加、减、乘、比较、逻辑运算 (`SIMD_BINOP_LIST`).
     - `S128AndNot` (向量按位与非)。
     - `S128Const` (加载向量常量)。
     - `S128Zero` (创建零向量)。
     - 提取和替换向量通道 (`SIMD_VISIT_EXTRACT_LANE`, `SIMD_VISIT_REPLACE_LANE`).
     - 选择操作 (`VisitS128Select`, `SIMD_VISIT_SELECT_LANE`).
     - 融合乘法加/减 (`VISIT_SIMD_QFMOP`).
     - 最小值操作 (`VisitF32x4Min`).
   - 针对未实现的 FP16 SIMD 操作，提供了空的 Visit 函数 (`UNIMPLEMENTED_SIMD_FP16_OP_LIST`).

**关于与 JavaScript 功能的关系：**

这个文件中的代码直接参与了将 JavaScript 代码编译成 RISC-V 机器码的过程。例如：

```javascript
// JavaScript 示例

let a = 1.5;
let b = 2.5;
let sum = a + b;

let arr = new Float32Array([1.0, 2.0, 3.0, 4.0]);
let neg_arr = arr.map(x => -x);
```

- **`let sum = a + b;`**:  JavaScript 的加法操作会被编译成对 `VisitFloat64Add` (如果 `a` 和 `b` 是双精度浮点数) 或 `VisitFloat32Add` (如果它们是单精度浮点数) 等函数的调用，最终生成 RISC-V 的浮点加法指令 (`kRiscvAddD` 或 `kRiscvAddS`)。
- **`let arr = new Float32Array(...)` 和 `arr.map(x => -x)`**:  涉及到 `Float32Array` 的操作可能会使用 SIMD 指令进行优化。 `arr.map(x => -x)` 中的取负操作可能对应于 `VisitF32x4Neg` 并生成 RISC-V 的向量取反指令 (`kRiscvVfnegVv`)。

**代码逻辑推理示例：**

**假设输入：** 一个表示 `a < b` 的中间表示节点，其中 `a` 和 `b` 是 `float32` 类型的变量。

**输出：**  会调用 `InstructionSelectorT<Adapter>::VisitFloat32LessThan(node)`，该函数会创建一个 `FlagsContinuationT` 对象用于处理比较结果，并调用 `VisitFloat32Compare` 函数。`VisitFloat32Compare` 最终会 `Emit` 一个 RISC-V 的浮点比较指令，并根据比较结果设置相应的条件标志。后续的代码可能会根据这些标志进行条件跳转。

**用户常见的编程错误示例：**

这个文件本身是编译器的一部分，它的错误可能导致生成的机器码不正确，从而导致各种运行时错误。但它不直接对应于用户编写 JavaScript 代码时常见的语法错误。

然而，理解这个文件的工作原理有助于理解 V8 如何优化某些 JavaScript 代码模式。例如，了解 SIMD 指令的支持可以鼓励开发者在性能关键的代码中使用类型化数组和 SIMD 操作，从而利用硬件加速。如果 V8 的指令选择器中存在错误，可能会导致某些看似正确的 JavaScript 代码产生意想不到的结果。

**总结 (第2部分功能归纳):**

此代码片段主要关注 RISC-V 架构的指令选择，涵盖了：

- **基本的比较操作和条件标志设置。**
- **全面的浮点数算术、转换和特殊操作的指令选择。**
- **基本的整数位运算的指令选择。**
- **内存屏障指令的选择。**
- **初步的函数调用结果准备逻辑。**
- **对大量 SIMD (向量) 操作的指令选择，支持多种数据类型和操作类型，包括算术、逻辑、比较、通道操作等。**

总而言之，这个文件是 V8 编译器后端中至关重要的一部分，它负责将高级的程序表示转换为可以在 RISC-V 处理器上执行的低级机器指令。

### 提示词
```
这是目录为v8/src/compiler/backend/riscv/instruction-selector-riscv.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/riscv/instruction-selector-riscv.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```c
FlagsContinuationT<Adapter>* cont) {
  RiscvOperandGeneratorT<Adapter> g(selector);
  selector->EmitWithContinuation(kRiscvCmpZero,
                                 g.UseRegisterOrImmediateZero(value), cont);
}

#ifdef V8_TARGET_ARCH_RISCV64
template <typename Adapter>
void EmitWord32CompareZero(InstructionSelectorT<Adapter>* selector,
                         typename Adapter::node_t value,
                         FlagsContinuationT<Adapter>* cont) {
  RiscvOperandGeneratorT<Adapter> g(selector);
  InstructionOperand inputs[] = {g.UseRegisterOrImmediateZero(value)};
  InstructionOperand temps[] = {g.TempRegister()};
  selector->EmitWithContinuation(kRiscvCmpZero32, 0, nullptr, arraysize(inputs),
                                 inputs, arraysize(temps), temps, cont);
}
#endif


template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32Equal(node_t node) {
  FlagsContinuationT<Adapter> cont = FlagsContinuation::ForSet(kEqual, node);
  VisitFloat32Compare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32LessThan(node_t node) {
  FlagsContinuationT<Adapter> cont =
      FlagsContinuation::ForSet(kUnsignedLessThan, node);
  VisitFloat32Compare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32LessThanOrEqual(node_t node) {
  FlagsContinuationT<Adapter> cont =
      FlagsContinuation::ForSet(kUnsignedLessThanOrEqual, node);
  VisitFloat32Compare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Equal(node_t node) {
  FlagsContinuationT<Adapter> cont = FlagsContinuation::ForSet(kEqual, node);
  VisitFloat64Compare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64LessThan(node_t node) {
  FlagsContinuationT<Adapter> cont =
      FlagsContinuation::ForSet(kUnsignedLessThan, node);
  VisitFloat64Compare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64LessThanOrEqual(node_t node) {
  FlagsContinuationT<Adapter> cont =
      FlagsContinuation::ForSet(kUnsignedLessThanOrEqual, node);
  VisitFloat64Compare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64ExtractLowWord32(node_t node) {
    VisitRR(this, kRiscvFloat64ExtractLowWord32, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64ExtractHighWord32(node_t node) {
    VisitRR(this, kRiscvFloat64ExtractHighWord32, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64SilenceNaN(node_t node) {
    VisitRR(this, kRiscvFloat64SilenceNaN, node);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitBitcastWord32PairToFloat64(
    node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  RiscvOperandGeneratorT<TurboshaftAdapter> g(this);
  const auto& bitcast =
      this->Cast<turboshaft::BitcastWord32PairToFloat64Op>(node);
  node_t hi = bitcast.high_word32();
  node_t lo = bitcast.low_word32();
  // TODO(nicohartmann@): We could try to emit a better sequence here.
  InstructionOperand zero = sequence()->AddImmediate(Constant(0.0));
  InstructionOperand temp = g.TempDoubleRegister();
  Emit(kRiscvFloat64InsertHighWord32, temp, zero, g.Use(hi));
  Emit(kRiscvFloat64InsertLowWord32, g.DefineSameAsFirst(node), temp,
       g.Use(lo));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64InsertLowWord32(node_t node) {
    RiscvOperandGeneratorT<Adapter> g(this);
    node_t left = this->input_at(node, 0);
    node_t right = this->input_at(node, 1);
    Emit(kRiscvFloat64InsertLowWord32, g.DefineSameAsFirst(node),
         g.UseRegister(left), g.UseRegister(right));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64InsertHighWord32(node_t node) {
    RiscvOperandGeneratorT<Adapter> g(this);
    node_t left = this->input_at(node, 0);
    node_t right = this->input_at(node, 1);
    Emit(kRiscvFloat64InsertHighWord32, g.DefineSameAsFirst(node),
         g.UseRegister(left), g.UseRegister(right));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitMemoryBarrier(node_t node) {
    RiscvOperandGeneratorT<Adapter> g(this);
    Emit(kRiscvSync, g.NoOutput());
}

template <typename Adapter>
bool InstructionSelectorT<Adapter>::IsTailCallAddressImmediate() {
  return false;
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::EmitPrepareResults(
    ZoneVector<PushParameter>* results, const CallDescriptor* call_descriptor,
    node_t node) {
  RiscvOperandGeneratorT<Adapter> g(this);

  for (PushParameter output : *results) {
    if (!output.location.IsCallerFrameSlot()) continue;
    // Skip any alignment holes in nodes.
    if (this->valid(output.node)) {
      DCHECK(!call_descriptor->IsCFunctionCall());
      if (output.location.GetType() == MachineType::Float32()) {
        MarkAsFloat32(output.node);
      } else if (output.location.GetType() == MachineType::Float64()) {
        MarkAsFloat64(output.node);
      } else if (output.location.GetType() == MachineType::Simd128()) {
        MarkAsSimd128(output.node);
      }
      int offset = call_descriptor->GetOffsetToReturns();
      int reverse_slot = -output.location.GetLocation() - offset;
      Emit(kRiscvPeek, g.DefineAsRegister(output.node),
           g.UseImmediate(reverse_slot));
    }
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::EmitMoveParamToFPR(node_t node, int index) {
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::EmitMoveFPRToParam(
    InstructionOperand* op, LinkageLocation location) {}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32Abs(node_t node) {
    VisitRR(this, kRiscvAbsS, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Abs(node_t node) {
    VisitRR(this, kRiscvAbsD, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32Sqrt(node_t node) {
  VisitRR(this, kRiscvSqrtS, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Sqrt(node_t node) {
  VisitRR(this, kRiscvSqrtD, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32RoundDown(node_t node) {
  VisitRR(this, kRiscvFloat32RoundDown, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32Add(node_t node) {
    VisitRRR(this, kRiscvAddS, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Add(node_t node) {
    VisitRRR(this, kRiscvAddD, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32Sub(node_t node) {
    VisitRRR(this, kRiscvSubS, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Sub(node_t node) {
  VisitRRR(this, kRiscvSubD, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32Mul(node_t node) {
    VisitRRR(this, kRiscvMulS, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Mul(node_t node) {
    VisitRRR(this, kRiscvMulD, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32Div(node_t node) {
    VisitRRR(this, kRiscvDivS, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Div(node_t node) {
  VisitRRR(this, kRiscvDivD, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Mod(node_t node) {
    RiscvOperandGeneratorT<Adapter> g(this);
    Emit(kRiscvModD, g.DefineAsFixed(node, fa0),
         g.UseFixed(this->input_at(node, 0), fa0),
         g.UseFixed(this->input_at(node, 1), fa1))
        ->MarkAsCall();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32Max(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    VisitRRR(this, kRiscvFloat32Max, node);
  } else {
    RiscvOperandGeneratorT<Adapter> g(this);
    Emit(kRiscvFloat32Max, g.DefineAsRegister(node),
         g.UseRegister(this->input_at(node, 0)),
         g.UseRegister(this->input_at(node, 1)));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Max(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    VisitRRR(this, kRiscvFloat64Max, node);
  } else {
    RiscvOperandGeneratorT<Adapter> g(this);
    Emit(kRiscvFloat64Max, g.DefineAsRegister(node),
         g.UseRegister(this->input_at(node, 0)),
         g.UseRegister(this->input_at(node, 1)));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32Min(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    VisitRRR(this, kRiscvFloat32Min, node);
  } else {
    RiscvOperandGeneratorT<Adapter> g(this);
    Emit(kRiscvFloat32Min, g.DefineAsRegister(node),
         g.UseRegister(this->input_at(node, 0)),
         g.UseRegister(this->input_at(node, 1)));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Min(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    VisitRRR(this, kRiscvFloat64Min, node);
  } else {
    RiscvOperandGeneratorT<Adapter> g(this);
    Emit(kRiscvFloat64Min, g.DefineAsRegister(node),
         g.UseRegister(this->input_at(node, 0)),
         g.UseRegister(this->input_at(node, 1)));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTruncateFloat64ToWord32(node_t node) {
  VisitRR(this, kArchTruncateDoubleToI, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitRoundFloat64ToInt32(node_t node) {
  VisitRR(this, kRiscvTruncWD, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTruncateFloat64ToFloat32(node_t node) {
    RiscvOperandGeneratorT<Adapter> g(this);
    node_t value = this->input_at(node, 0);
    // Match TruncateFloat64ToFloat32(ChangeInt32ToFloat64) to corresponding
    // instruction.
    if constexpr (Adapter::IsTurboshaft) {
      using Rep = turboshaft::RegisterRepresentation;
      if (CanCover(node, value)) {
        const turboshaft::Operation& op = this->Get(value);
        if (op.Is<turboshaft::ChangeOp>()) {
          const turboshaft::ChangeOp& change = op.Cast<turboshaft::ChangeOp>();
          if (change.kind == turboshaft::ChangeOp::Kind::kSignedToFloat) {
            if (change.from == Rep::Word32() && change.to == Rep::Float64()) {
              Emit(kRiscvCvtSW, g.DefineAsRegister(node),
                   g.UseRegister(this->input_at(value, 0)));
              return;
            }
          }
        }
      }
    } else {
      if (CanCover(node, value) &&
          this->opcode(value) == IrOpcode::kChangeInt32ToFloat64) {
        Emit(kRiscvCvtSW, g.DefineAsRegister(node),
             g.UseRegister(this->input_at(value, 0)));
        return;
      }
    }
    VisitRR(this, kRiscvCvtSD, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Shl(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    // todo(RISCV): Optimize it
    VisitRRO(this, kRiscvShl32, node);
  } else {
    Int32BinopMatcher m(node);
    if (m.left().IsWord32And() && CanCover(node, m.left().node()) &&
        m.right().IsInRange(1, 31)) {
      RiscvOperandGeneratorT<Adapter> g(this);
      Int32BinopMatcher mleft(m.left().node());
      // Match Word32Shl(Word32And(x, mask), imm) to Shl where the mask is
      // contiguous, and the shift immediate non-zero.
      if (mleft.right().HasResolvedValue()) {
        uint32_t mask = mleft.right().ResolvedValue();
        uint32_t mask_width = base::bits::CountPopulation(mask);
        uint32_t mask_msb = base::bits::CountLeadingZeros32(mask);
        if ((mask_width != 0) && (mask_msb + mask_width == 32)) {
          uint32_t shift = m.right().ResolvedValue();
          DCHECK_EQ(0u, base::bits::CountTrailingZeros32(mask));
          DCHECK_NE(0u, shift);
          if ((shift + mask_width) >= 32) {
            // If the mask is contiguous and reaches or extends beyond the top
            // bit, only the shift is needed.
            Emit(kRiscvShl32, g.DefineAsRegister(node),
                 g.UseRegister(mleft.left().node()),
                 g.UseImmediate(m.right().node()));
            return;
          }
        }
      }
    }
    VisitRRO(this, kRiscvShl32, node);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Shr(node_t node) {
  VisitRRO(this, kRiscvShr32, node);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitWord32Sar(
    turboshaft::OpIndex node) {
  // todo(RISCV): Optimize it
  VisitRRO(this, kRiscvSar32, node);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitWord32Sar(Node* node) {
  Int32BinopMatcher m(node);
  if (CanCover(node, m.left().node())) {
    RiscvOperandGeneratorT<TurbofanAdapter> g(this);
    if (m.left().IsWord32Shl()) {
      Int32BinopMatcher mleft(m.left().node());
      if (m.right().HasResolvedValue() && mleft.right().HasResolvedValue()) {
        uint32_t sar = m.right().ResolvedValue();
        uint32_t shl = mleft.right().ResolvedValue();
        if ((sar == shl) && (sar == 16)) {
          Emit(kRiscvSignExtendShort, g.DefineAsRegister(node),
               g.UseRegister(mleft.left().node()));
          return;
        } else if ((sar == shl) && (sar == 24)) {
          Emit(kRiscvSignExtendByte, g.DefineAsRegister(node),
               g.UseRegister(mleft.left().node()));
          return;
        } else if ((sar == shl) && (sar == 32)) {
          Emit(kRiscvShl32, g.DefineAsRegister(node),
               g.UseRegister(mleft.left().node()), g.TempImmediate(0));
          return;
        }
      }
    }
  }
  VisitRRO(this, kRiscvSar32, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI32x4ExtAddPairwiseI16x8S(
    node_t node) {
    RiscvOperandGeneratorT<Adapter> g(this);
    InstructionOperand src1 = g.TempSimd128Register();
    InstructionOperand src2 = g.TempSimd128Register();
    InstructionOperand src = g.UseUniqueRegister(this->input_at(node, 0));
    Emit(kRiscvVrgather, src1, src, g.UseImmediate64(0x0006000400020000),
         g.UseImmediate(int8_t(E16)), g.UseImmediate(int8_t(m1)));
    Emit(kRiscvVrgather, src2, src, g.UseImmediate64(0x0007000500030001),
         g.UseImmediate(int8_t(E16)), g.UseImmediate(int8_t(m1)));
    Emit(kRiscvVwaddVv, g.DefineAsRegister(node), src1, src2,
         g.UseImmediate(int8_t(E16)), g.UseImmediate(int8_t(mf2)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI32x4ExtAddPairwiseI16x8U(
    node_t node) {
    RiscvOperandGeneratorT<Adapter> g(this);
    InstructionOperand src1 = g.TempSimd128Register();
    InstructionOperand src2 = g.TempSimd128Register();
    InstructionOperand src = g.UseUniqueRegister(this->input_at(node, 0));
    Emit(kRiscvVrgather, src1, src, g.UseImmediate64(0x0006000400020000),
         g.UseImmediate(int8_t(E16)), g.UseImmediate(int8_t(m1)));
    Emit(kRiscvVrgather, src2, src, g.UseImmediate64(0x0007000500030001),
         g.UseImmediate(int8_t(E16)), g.UseImmediate(int8_t(m1)));
    Emit(kRiscvVwadduVv, g.DefineAsRegister(node), src1, src2,
         g.UseImmediate(int8_t(E16)), g.UseImmediate(int8_t(mf2)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI16x8ExtAddPairwiseI8x16S(
    node_t node) {
    RiscvOperandGeneratorT<Adapter> g(this);
    InstructionOperand src1 = g.TempSimd128Register();
    InstructionOperand src2 = g.TempSimd128Register();
    InstructionOperand src = g.UseUniqueRegister(this->input_at(node, 0));
    Emit(kRiscvVrgather, src1, src, g.UseImmediate64(0x0E0C0A0806040200),
         g.UseImmediate(int8_t(E8)), g.UseImmediate(int8_t(m1)));
    Emit(kRiscvVrgather, src2, src, g.UseImmediate64(0x0F0D0B0907050301),
         g.UseImmediate(int8_t(E8)), g.UseImmediate(int8_t(m1)));
    Emit(kRiscvVwaddVv, g.DefineAsRegister(node), src1, src2,
         g.UseImmediate(int8_t(E8)), g.UseImmediate(int8_t(mf2)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI16x8ExtAddPairwiseI8x16U(
    node_t node) {
    RiscvOperandGeneratorT<Adapter> g(this);
    InstructionOperand src1 = g.TempSimd128Register();
    InstructionOperand src2 = g.TempSimd128Register();
    InstructionOperand src = g.UseUniqueRegister(this->input_at(node, 0));
    Emit(kRiscvVrgather, src1, src, g.UseImmediate64(0x0E0C0A0806040200),
         g.UseImmediate(int8_t(E8)), g.UseImmediate(int8_t(m1)));
    Emit(kRiscvVrgather, src2, src, g.UseImmediate64(0x0F0D0B0907050301),
         g.UseImmediate(int8_t(E8)), g.UseImmediate(int8_t(m1)));
    Emit(kRiscvVwadduVv, g.DefineAsRegister(node), src1, src2,
         g.UseImmediate(int8_t(E8)), g.UseImmediate(int8_t(mf2)));
}

#define SIMD_INT_TYPE_LIST(V) \
  V(I64x2, E64, m1)           \
  V(I32x4, E32, m1)           \
  V(I16x8, E16, m1)           \
  V(I8x16, E8, m1)

#define SIMD_TYPE_LIST(V) \
  V(F32x4)                \
  V(I64x2)                \
  V(I32x4)                \
  V(I16x8)                \
  V(I8x16)

#define SIMD_UNOP_LIST2(V)                 \
  V(F32x4Splat, kRiscvVfmvVf, E32, m1)     \
  V(I8x16Neg, kRiscvVnegVv, E8, m1)        \
  V(I16x8Neg, kRiscvVnegVv, E16, m1)       \
  V(I32x4Neg, kRiscvVnegVv, E32, m1)       \
  V(I64x2Neg, kRiscvVnegVv, E64, m1)       \
  V(I8x16Splat, kRiscvVmv, E8, m1)         \
  V(I16x8Splat, kRiscvVmv, E16, m1)        \
  V(I32x4Splat, kRiscvVmv, E32, m1)        \
  V(I64x2Splat, kRiscvVmv, E64, m1)        \
  V(F32x4Neg, kRiscvVfnegVv, E32, m1)      \
  V(F64x2Neg, kRiscvVfnegVv, E64, m1)      \
  V(F64x2Splat, kRiscvVfmvVf, E64, m1)     \
  V(I32x4AllTrue, kRiscvVAllTrue, E32, m1) \
  V(I16x8AllTrue, kRiscvVAllTrue, E16, m1) \
  V(I8x16AllTrue, kRiscvVAllTrue, E8, m1)  \
  V(I64x2AllTrue, kRiscvVAllTrue, E64, m1) \
  V(I64x2Abs, kRiscvVAbs, E64, m1)         \
  V(I32x4Abs, kRiscvVAbs, E32, m1)         \
  V(I16x8Abs, kRiscvVAbs, E16, m1)         \
  V(I8x16Abs, kRiscvVAbs, E8, m1)

#define SIMD_UNOP_LIST(V)                                       \
  V(F64x2Abs, kRiscvF64x2Abs)                                   \
  V(F64x2Sqrt, kRiscvF64x2Sqrt)                                 \
  V(F64x2ConvertLowI32x4S, kRiscvF64x2ConvertLowI32x4S)         \
  V(F64x2ConvertLowI32x4U, kRiscvF64x2ConvertLowI32x4U)         \
  V(F64x2PromoteLowF32x4, kRiscvF64x2PromoteLowF32x4)           \
  V(F64x2Ceil, kRiscvF64x2Ceil)                                 \
  V(F64x2Floor, kRiscvF64x2Floor)                               \
  V(F64x2Trunc, kRiscvF64x2Trunc)                               \
  V(F64x2NearestInt, kRiscvF64x2NearestInt)                     \
  V(F32x4SConvertI32x4, kRiscvF32x4SConvertI32x4)               \
  V(F32x4UConvertI32x4, kRiscvF32x4UConvertI32x4)               \
  V(F32x4Abs, kRiscvF32x4Abs)                                   \
  V(F32x4Sqrt, kRiscvF32x4Sqrt)                                 \
  V(F32x4DemoteF64x2Zero, kRiscvF32x4DemoteF64x2Zero)           \
  V(F32x4Ceil, kRiscvF32x4Ceil)                                 \
  V(F32x4Floor, kRiscvF32x4Floor)                               \
  V(F32x4Trunc, kRiscvF32x4Trunc)                               \
  V(F32x4NearestInt, kRiscvF32x4NearestInt)                     \
  V(I32x4RelaxedTruncF32x4S, kRiscvI32x4SConvertF32x4)          \
  V(I32x4RelaxedTruncF32x4U, kRiscvI32x4UConvertF32x4)          \
  V(I32x4RelaxedTruncF64x2SZero, kRiscvI32x4TruncSatF64x2SZero) \
  V(I32x4RelaxedTruncF64x2UZero, kRiscvI32x4TruncSatF64x2UZero) \
  V(I64x2SConvertI32x4Low, kRiscvI64x2SConvertI32x4Low)         \
  V(I64x2SConvertI32x4High, kRiscvI64x2SConvertI32x4High)       \
  V(I64x2UConvertI32x4Low, kRiscvI64x2UConvertI32x4Low)         \
  V(I64x2UConvertI32x4High, kRiscvI64x2UConvertI32x4High)       \
  V(I32x4SConvertF32x4, kRiscvI32x4SConvertF32x4)               \
  V(I32x4UConvertF32x4, kRiscvI32x4UConvertF32x4)               \
  V(I32x4TruncSatF64x2SZero, kRiscvI32x4TruncSatF64x2SZero)     \
  V(I32x4TruncSatF64x2UZero, kRiscvI32x4TruncSatF64x2UZero)     \
  V(I8x16Popcnt, kRiscvI8x16Popcnt)                             \
  V(S128Not, kRiscvVnot)                                        \
  V(V128AnyTrue, kRiscvV128AnyTrue)

#define SIMD_SHIFT_OP_LIST(V) \
  V(I64x2Shl)                 \
  V(I64x2ShrS)                \
  V(I64x2ShrU)                \
  V(I32x4Shl)                 \
  V(I32x4ShrS)                \
  V(I32x4ShrU)                \
  V(I16x8Shl)                 \
  V(I16x8ShrS)                \
  V(I16x8ShrU)                \
  V(I8x16Shl)                 \
  V(I8x16ShrS)                \
  V(I8x16ShrU)

#define SIMD_BINOP_LIST(V)                    \
  V(I64x2Add, kRiscvVaddVv, E64, m1)          \
  V(I32x4Add, kRiscvVaddVv, E32, m1)          \
  V(I16x8Add, kRiscvVaddVv, E16, m1)          \
  V(I8x16Add, kRiscvVaddVv, E8, m1)           \
  V(I64x2Sub, kRiscvVsubVv, E64, m1)          \
  V(I32x4Sub, kRiscvVsubVv, E32, m1)          \
  V(I16x8Sub, kRiscvVsubVv, E16, m1)          \
  V(I8x16Sub, kRiscvVsubVv, E8, m1)           \
  V(I32x4MaxU, kRiscvVmaxuVv, E32, m1)        \
  V(I16x8MaxU, kRiscvVmaxuVv, E16, m1)        \
  V(I8x16MaxU, kRiscvVmaxuVv, E8, m1)         \
  V(I32x4MaxS, kRiscvVmax, E32, m1)           \
  V(I16x8MaxS, kRiscvVmax, E16, m1)           \
  V(I8x16MaxS, kRiscvVmax, E8, m1)            \
  V(I32x4MinS, kRiscvVminsVv, E32, m1)        \
  V(I16x8MinS, kRiscvVminsVv, E16, m1)        \
  V(I8x16MinS, kRiscvVminsVv, E8, m1)         \
  V(I32x4MinU, kRiscvVminuVv, E32, m1)        \
  V(I16x8MinU, kRiscvVminuVv, E16, m1)        \
  V(I8x16MinU, kRiscvVminuVv, E8, m1)         \
  V(I64x2Mul, kRiscvVmulVv, E64, m1)          \
  V(I32x4Mul, kRiscvVmulVv, E32, m1)          \
  V(I16x8Mul, kRiscvVmulVv, E16, m1)          \
  V(I64x2GtS, kRiscvVgtsVv, E64, m1)          \
  V(I32x4GtS, kRiscvVgtsVv, E32, m1)          \
  V(I16x8GtS, kRiscvVgtsVv, E16, m1)          \
  V(I8x16GtS, kRiscvVgtsVv, E8, m1)           \
  V(I64x2GeS, kRiscvVgesVv, E64, m1)          \
  V(I32x4GeS, kRiscvVgesVv, E32, m1)          \
  V(I16x8GeS, kRiscvVgesVv, E16, m1)          \
  V(I8x16GeS, kRiscvVgesVv, E8, m1)           \
  V(I32x4GeU, kRiscvVgeuVv, E32, m1)          \
  V(I16x8GeU, kRiscvVgeuVv, E16, m1)          \
  V(I8x16GeU, kRiscvVgeuVv, E8, m1)           \
  V(I32x4GtU, kRiscvVgtuVv, E32, m1)          \
  V(I16x8GtU, kRiscvVgtuVv, E16, m1)          \
  V(I8x16GtU, kRiscvVgtuVv, E8, m1)           \
  V(I64x2Eq, kRiscvVeqVv, E64, m1)            \
  V(I32x4Eq, kRiscvVeqVv, E32, m1)            \
  V(I16x8Eq, kRiscvVeqVv, E16, m1)            \
  V(I8x16Eq, kRiscvVeqVv, E8, m1)             \
  V(I64x2Ne, kRiscvVneVv, E64, m1)            \
  V(I32x4Ne, kRiscvVneVv, E32, m1)            \
  V(I16x8Ne, kRiscvVneVv, E16, m1)            \
  V(I8x16Ne, kRiscvVneVv, E8, m1)             \
  V(I16x8AddSatS, kRiscvVaddSatSVv, E16, m1)  \
  V(I8x16AddSatS, kRiscvVaddSatSVv, E8, m1)   \
  V(I16x8AddSatU, kRiscvVaddSatUVv, E16, m1)  \
  V(I8x16AddSatU, kRiscvVaddSatUVv, E8, m1)   \
  V(I16x8SubSatS, kRiscvVsubSatSVv, E16, m1)  \
  V(I8x16SubSatS, kRiscvVsubSatSVv, E8, m1)   \
  V(I16x8SubSatU, kRiscvVsubSatUVv, E16, m1)  \
  V(I8x16SubSatU, kRiscvVsubSatUVv, E8, m1)   \
  V(F64x2Add, kRiscvVfaddVv, E64, m1)         \
  V(F32x4Add, kRiscvVfaddVv, E32, m1)         \
  V(F64x2Sub, kRiscvVfsubVv, E64, m1)         \
  V(F32x4Sub, kRiscvVfsubVv, E32, m1)         \
  V(F64x2Mul, kRiscvVfmulVv, E64, m1)         \
  V(F32x4Mul, kRiscvVfmulVv, E32, m1)         \
  V(F64x2Div, kRiscvVfdivVv, E64, m1)         \
  V(F32x4Div, kRiscvVfdivVv, E32, m1)         \
  V(S128And, kRiscvVandVv, E8, m1)            \
  V(S128Or, kRiscvVorVv, E8, m1)              \
  V(S128Xor, kRiscvVxorVv, E8, m1)            \
  V(I16x8Q15MulRSatS, kRiscvVsmulVv, E16, m1) \
  V(I16x8RelaxedQ15MulRS, kRiscvVsmulVv, E16, m1)

#define UNIMPLEMENTED_SIMD_FP16_OP_LIST(V) \
  V(F16x8Splat)                            \
  V(F16x8ExtractLane)                      \
  V(F16x8ReplaceLane)                      \
  V(F16x8Abs)                              \
  V(F16x8Neg)                              \
  V(F16x8Sqrt)                             \
  V(F16x8Floor)                            \
  V(F16x8Ceil)                             \
  V(F16x8Trunc)                            \
  V(F16x8NearestInt)                       \
  V(F16x8Add)                              \
  V(F16x8Sub)                              \
  V(F16x8Mul)                              \
  V(F16x8Div)                              \
  V(F16x8Min)                              \
  V(F16x8Max)                              \
  V(F16x8Pmin)                             \
  V(F16x8Pmax)                             \
  V(F16x8Eq)                               \
  V(F16x8Ne)                               \
  V(F16x8Lt)                               \
  V(F16x8Le)                               \
  V(F16x8SConvertI16x8)                    \
  V(F16x8UConvertI16x8)                    \
  V(I16x8SConvertF16x8)                    \
  V(I16x8UConvertF16x8)                    \
  V(F16x8DemoteF32x4Zero)                  \
  V(F16x8DemoteF64x2Zero)                  \
  V(F32x4PromoteLowF16x8)                  \
  V(F16x8Qfma)                             \
  V(F16x8Qfms)

#define SIMD_VISIT_UNIMPL_FP16_OP(Name)                          \
  template <typename Adapter>                                    \
  void InstructionSelectorT<Adapter>::Visit##Name(node_t node) { \
    UNIMPLEMENTED();                                             \
  }
UNIMPLEMENTED_SIMD_FP16_OP_LIST(SIMD_VISIT_UNIMPL_FP16_OP)
#undef SIMD_VISIT_UNIMPL_FP16_OP
#undef UNIMPLEMENTED_SIMD_FP16_OP_LIST

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitS128AndNot(node_t node) {
    RiscvOperandGeneratorT<Adapter> g(this);
    InstructionOperand temp1 = g.TempFpRegister(v0);
    this->Emit(kRiscvVnotVv, temp1, g.UseRegister(this->input_at(node, 1)),
               g.UseImmediate(E8), g.UseImmediate(m1));
    this->Emit(kRiscvVandVv, g.DefineAsRegister(node),
               g.UseRegister(this->input_at(node, 0)), temp1,
               g.UseImmediate(E8), g.UseImmediate(m1));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitS128Const(node_t node) {
    RiscvOperandGeneratorT<Adapter> g(this);
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
      Emit(kRiscvS128Zero, dst);
    } else if (all_ones) {
      Emit(kRiscvS128AllOnes, dst);
    } else {
      Emit(kRiscvS128Const, dst, g.UseImmediate(val[0]), g.UseImmediate(val[1]),
           g.UseImmediate(val[2]), g.UseImmediate(val[3]));
    }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitS128Zero(node_t node) {
    RiscvOperandGeneratorT<Adapter> g(this);
    Emit(kRiscvS128Zero, g.DefineAsRegister(node));
}

#define SIMD_VISIT_EXTRACT_LANE(Type, Sign)                           \
  template <typename Adapter>                                         \
  void InstructionSelectorT<Adapter>::Visit##Type##ExtractLane##Sign( \
      node_t node) {                                                  \
      VisitRRI(this, kRiscv##Type##ExtractLane##Sign, node);          \
  }
SIMD_VISIT_EXTRACT_LANE(F64x2, )
SIMD_VISIT_EXTRACT_LANE(F32x4, )
SIMD_VISIT_EXTRACT_LANE(I32x4, )
SIMD_VISIT_EXTRACT_LANE(I64x2, )
SIMD_VISIT_EXTRACT_LANE(I16x8, U)
SIMD_VISIT_EXTRACT_LANE(I16x8, S)
SIMD_VISIT_EXTRACT_LANE(I8x16, U)
SIMD_VISIT_EXTRACT_LANE(I8x16, S)
#undef SIMD_VISIT_EXTRACT_LANE

#define SIMD_VISIT_REPLACE_LANE(Type)                                         \
  template <typename Adapter>                                                 \
  void InstructionSelectorT<Adapter>::Visit##Type##ReplaceLane(node_t node) { \
      VisitRRIR(this, kRiscv##Type##ReplaceLane, node);                       \
  }
SIMD_TYPE_LIST(SIMD_VISIT_REPLACE_LANE)
SIMD_VISIT_REPLACE_LANE(F64x2)
#undef SIMD_VISIT_REPLACE_LANE

#define SIMD_VISIT_UNOP(Name, instruction)                       \
  template <typename Adapter>                                    \
  void InstructionSelectorT<Adapter>::Visit##Name(node_t node) { \
      VisitRR(this, instruction, node);                          \
  }
SIMD_UNOP_LIST(SIMD_VISIT_UNOP)
#undef SIMD_VISIT_UNOP

#define SIMD_VISIT_SHIFT_OP(Name)                                \
  template <typename Adapter>                                    \
  void InstructionSelectorT<Adapter>::Visit##Name(node_t node) { \
      VisitSimdShift(this, kRiscv##Name, node);                  \
  }
SIMD_SHIFT_OP_LIST(SIMD_VISIT_SHIFT_OP)
#undef SIMD_VISIT_SHIFT_OP

#define SIMD_VISIT_BINOP_RVV(Name, instruction, VSEW, LMUL)                    \
  template <typename Adapter>                                                  \
  void InstructionSelectorT<Adapter>::Visit##Name(node_t node) {               \
      RiscvOperandGeneratorT<Adapter> g(this);                                 \
      this->Emit(instruction, g.DefineAsRegister(node),                        \
                 g.UseRegister(this->input_at(node, 0)),                       \
                 g.UseRegister(this->input_at(node, 1)), g.UseImmediate(VSEW), \
                 g.UseImmediate(LMUL));                                        \
  }
SIMD_BINOP_LIST(SIMD_VISIT_BINOP_RVV)
#undef SIMD_VISIT_BINOP_RVV

#define SIMD_VISIT_UNOP2(Name, instruction, VSEW, LMUL)                        \
  template <typename Adapter>                                                  \
  void InstructionSelectorT<Adapter>::Visit##Name(node_t node) {               \
      RiscvOperandGeneratorT<Adapter> g(this);                                 \
      this->Emit(instruction, g.DefineAsRegister(node),                        \
                 g.UseRegister(this->input_at(node, 0)), g.UseImmediate(VSEW), \
                 g.UseImmediate(LMUL));                                        \
  }
SIMD_UNOP_LIST2(SIMD_VISIT_UNOP2)
#undef SIMD_VISIT_UNOP2

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitS128Select(node_t node) {
    VisitRRRR(this, kRiscvS128Select, node);
}

#define SIMD_VISIT_SELECT_LANE(Name)                             \
  template <typename Adapter>                                    \
  void InstructionSelectorT<Adapter>::Visit##Name(node_t node) { \
      VisitRRRR(this, kRiscvS128Select, node);                   \
  }
SIMD_VISIT_SELECT_LANE(I8x16RelaxedLaneSelect)
SIMD_VISIT_SELECT_LANE(I16x8RelaxedLaneSelect)
SIMD_VISIT_SELECT_LANE(I32x4RelaxedLaneSelect)
SIMD_VISIT_SELECT_LANE(I64x2RelaxedLaneSelect)
#undef SIMD_VISIT_SELECT_LANE

#define VISIT_SIMD_QFMOP(Name, instruction)                      \
  template <typename Adapter>                                    \
  void InstructionSelectorT<Adapter>::Visit##Name(node_t node) { \
      VisitRRRR(this, instruction, node);                        \
  }
VISIT_SIMD_QFMOP(F64x2Qfma, kRiscvF64x2Qfma)
VISIT_SIMD_QFMOP(F64x2Qfms, kRiscvF64x2Qfms)
VISIT_SIMD_QFMOP(F32x4Qfma, kRiscvF32x4Qfma)
VISIT_SIMD_QFMOP(F32x4Qfms, kRiscvF32x4Qfms)
#undef VISIT_SIMD_QFMOP

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF32x4Min(node_t node) {
    RiscvOperandGeneratorT<Adapter> g(this);
    InstructionOperand temp1 = g.TempFpRegister(v0);
    InstructionOperand mask_reg = g.TempFpRegister(v0);
    InstructionOperand temp2 = g.TempFpRegister(kSimd128ScratchReg);

    this->Emit(kRiscvVmfeqVv, temp1, g.UseRegister(this->input_at(node, 0)),
               g.UseRegister(this->input_at(node, 0)), g.UseImmediate(E32),
               g.UseImmediate(m1));
    this->Emit(kRiscvVmfeqVv, temp2, g.UseRegister(this->input_at(node, 1)),
               g.UseRegister(this->input_at(node, 1)), g.UseImmediate(E32),
               g.UseImmediate(m1));
    this->Emit(kRiscvVandVv, mask_reg, temp2, temp1, g.UseImmediate(E32),
               g.UseImmediate(m1));

    InstructionOperand NaN = g.TempFpRegister(kSimd128ScratchReg);
    InstructionOperand result = g.TempFpRegister(kSimd128S
```