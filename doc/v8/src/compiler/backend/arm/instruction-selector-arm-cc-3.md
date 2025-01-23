Response:
The user wants a summary of the functionality of the provided C++ code snippet. I need to identify the core purpose of this code within the V8 JavaScript engine.

The code deals with instruction selection for the ARM architecture in the V8 compiler backend. It appears to be responsible for translating high-level intermediate representation (IR) operations into specific ARM assembly instructions.

Here's a breakdown of the observed functionality:

1. **Instruction Selection:**  The code defines functions like `VisitFloat32Add`, `VisitFloat64Sub`, `VisitWordCompare`, etc. These functions seem to correspond to different IR operations (addition, subtraction, comparison, etc.) and are responsible for selecting the appropriate ARM instructions to implement them.

2. **ARM-Specific Instructions:** The code uses constants like `kArmVmlaF32`, `kArmVaddF64`, `kArmCmp`, `kArmTst`, etc., which are mnemonics for ARM assembly instructions. This confirms the code's role in generating ARM-specific code.

3. **Operand Handling:**  The `ArmOperandGeneratorT` class is used to manage operands for the instructions. It helps in defining where the inputs and outputs of instructions reside (registers, immediate values, memory locations).

4. **Code Optimization:**  The code includes logic to recognize certain patterns in the IR and emit more efficient ARM instructions. For example, it checks for multiplication followed by addition/subtraction and uses the `VMLA`/`VMLS` instructions, which perform fused multiply-accumulate operations.

5. **Flags and Condition Codes:** The code manipulates flags and condition codes (e.g., `FlagsContinuationT`, `kEqual`, `kSignedLessThan`). This is crucial for implementing conditional branches and comparisons.

6. **Turboshaft Support:** The `if constexpr (Adapter::IsTurboshaft)` blocks suggest that this code supports both the old Crankshaft/Lithium pipeline and the newer Turboshaft pipeline in V8.

7. **C Function Calls:** There's code to handle calls to C functions (`EmitPrepareArguments`).

8. **No `.tq` extension:** The code is clearly C++ (`.cc`) and not Torque (`.tq`).

9. **Relationship to JavaScript:** This code is a core part of how V8 executes JavaScript code on ARM processors. When JavaScript code is compiled, this instruction selector plays a vital role in generating the low-level machine code that the CPU understands.

10. **Code Logic and Assumptions:**  The code makes assumptions about the input IR structure. For example, the `Float32BinopMatcher` and `Float64BinopMatcher` classes are used to extract operands from specific types of IR nodes.

11. **Potential for Errors:**  While the provided code doesn't directly show user programming errors, incorrect logic in this instruction selector could lead to incorrect or inefficient code execution, which would manifest as bugs in JavaScript programs.

Now I can formulate the summary.
这是 V8 JavaScript 引擎中针对 ARM 架构的指令选择器代码的一部分。它的主要功能是将高级的、平台无关的中间表示 (IR) 操作转换为特定的 ARM 汇编指令。

以下是代码的功能归纳：

1. **指令选择 (Instruction Selection):**  该代码的核心任务是为各种算术和逻辑运算选择合适的 ARM 指令。例如，`VisitFloat32Add` 函数负责将浮点数加法操作转换为对应的 ARM 浮点加法指令 (`kArmVaddF32` 或 `kArmVmlaF32` 用于融合乘法累加)。

2. **ARM 特定的优化:** 代码中包含针对 ARM 架构的优化，例如识别乘法后紧跟加法或减法的模式，并使用融合乘法累加指令 (`kArmVmlaF32`, `kArmVmlaF64`, `kArmVmlsF32`, `kArmVmlsF64`) 来提高效率。

3. **操作数生成 (Operand Generation):**  `ArmOperandGeneratorT` 类用于生成指令所需的操作数，包括寄存器、立即数等。

4. **浮点运算支持:** 代码专门处理单精度 (`VisitFloat32Add`, `VisitFloat32Sub`) 和双精度 (`VisitFloat64Add`, `VisitFloat64Sub`, `VisitFloat64Mod`, `VisitFloat64Ieee754Binop`, `VisitFloat64Ieee754Unop`) 浮点数运算。

5. **函数调用支持:** `EmitPrepareArguments` 和 `EmitPrepareResults` 函数用于处理函数调用，包括参数的传递和返回值的接收。它区分了 C 函数调用和 JavaScript 函数调用，并采取不同的参数准备策略（例如，C 函数调用可能需要调整堆栈）。

6. **比较操作支持:** `VisitCompare`, `VisitFloat32Compare`, `VisitFloat64Compare`, `VisitWordCompare`, `VisitWordCompareZero` 等函数处理各种比较操作，并与 `FlagsContinuationT` 结合使用来管理条件码和分支。

7. **条件码优化:** 代码尝试将比较操作与之前的算术或逻辑运算结合起来，以减少指令数量。例如，它会检查是否可以将 `((a <op> b) cmp 0)` 优化为直接使用 `a <ops> b` 的结果标志。

8. **Turboshaft 支持:**  代码中使用了 `if constexpr (Adapter::IsTurboshaft)`，表明该代码支持 V8 的新一代编译器 Turboshaft。它针对 Turboshaft 的 IR 结构使用了不同的类型和方法 (`turboshaft::FloatBinopOp`, `turboshaft::Operation`, `turboshaft::ComparisonOp` 等)。

9. **没有 Torque 代码:**  代码以 `.cc` 结尾，是标准的 C++ 代码，而不是以 `.tq` 结尾的 V8 Torque 代码。

**与 JavaScript 的关系 (使用 JavaScript 举例):**

这段 C++ 代码的功能直接支持 JavaScript 中各种运算的执行。例如，当你执行以下 JavaScript 代码时：

```javascript
let a = 1.5;
let b = 2.0;
let c = a + b * 3.0; // 乘法后加法
```

V8 引擎会将这段代码编译成机器码。`v8/src/compiler/backend/arm/instruction-selector-arm.cc` 中的代码（特别是 `VisitFloat64Add` 和 `VisitFloat64Mul`）会参与将 `b * 3.0` 和 `a + ...` 这两个操作转换为相应的 ARM 浮点乘法和加法指令。由于代码中存在对乘法后加法的优化，V8 可能会生成 `kArmVmlaF64` 指令来提高效率。

**代码逻辑推理 (假设输入与输出):**

假设有以下 IR 节点表示浮点数加法：

* **Node:**  `add_node` (表示加法操作)
* **Inputs:**
    * `mul_node` (表示乘法操作，`add_node` 的左操作数)
        * **Inputs:** `operand1_node`, `operand2_node`
    * `operand3_node` (`add_node` 的右操作数)

当 `InstructionSelectorT::VisitFloat64Add` 处理 `add_node` 时，并且检测到左操作数是一个乘法操作 (`lhs.Is<Opmask::kFloat64Mul>()` 或 `m.left().IsFloat64Mul()`)，它会尝试生成 `kArmVmlaF64` 指令。

**假设输入:** IR 结构如上所述，其中 `mul_node` 可以被 `add_node` 覆盖 (`CanCover(node, add.left())` 或 `CanCover(node, m.left().node())`)。

**输出:** 生成的 ARM 指令可能是：

```assembly
VMLA.F64 Dreg_result, Dreg_operand3, Dreg_operand1, Dreg_operand2
```

其中 `Dreg_result` 是 `add_node` 的结果寄存器，`Dreg_operand3` 是 `operand3_node` 的寄存器，`Dreg_operand1` 和 `Dreg_operand2` 是 `operand1_node` 和 `operand2_node` 的寄存器。

**用户常见的编程错误 (举例说明):**

这段代码本身是编译器内部的代码，开发者通常不会直接与之交互。但是，编译器中的错误可能会导致生成的机器码不正确，从而导致 JavaScript 代码出现意想不到的行为。

例如，如果指令选择器在处理浮点数运算时出现逻辑错误，可能会导致：

1. **精度丢失:**  生成的指令可能无法正确地执行浮点数运算，导致精度丢失。
2. **计算错误:**  生成的指令可能执行了错误的运算，导致计算结果错误。
3. **性能下降:**  如果优化逻辑存在缺陷，可能无法生成最优的 ARM 指令，导致 JavaScript 代码执行效率降低。

虽然用户不会直接编写导致此代码出错的 "编程错误"，但用户的 JavaScript 代码的复杂性和特定模式可能会暴露编译器中的 bug。

**第4部分功能归纳:**

这部分代码主要关注 **浮点数加法和减法运算的指令选择和优化**，特别是针对 ARM 架构的融合乘法累加/减法指令的使用。它还初步涉及了函数调用的参数准备以及比较操作的框架。 此外，它开始展现对 V8 新编译器 **Turboshaft** 的支持。

### 提示词
```
这是目录为v8/src/compiler/backend/arm/instruction-selector-arm.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/arm/instruction-selector-arm.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共7部分，请归纳一下它的功能
```

### 源代码
```cpp
Mul>() && CanCover(node, add.right())) {
      const FloatBinopOp& mul = rhs.Cast<FloatBinopOp>();
      Emit(kArmVmlaF32, g.DefineSameAsFirst(node), g.UseRegister(add.left()),
           g.UseRegister(mul.left()), g.UseRegister(mul.right()));
      return;
    }
    VisitRRR(this, kArmVaddF32, node);
  } else {
    Float32BinopMatcher m(node);
    if (m.left().IsFloat32Mul() && CanCover(node, m.left().node())) {
      Float32BinopMatcher mleft(m.left().node());
      Emit(kArmVmlaF32, g.DefineSameAsFirst(node),
           g.UseRegister(m.right().node()), g.UseRegister(mleft.left().node()),
           g.UseRegister(mleft.right().node()));
      return;
    }
    if (m.right().IsFloat32Mul() && CanCover(node, m.right().node())) {
      Float32BinopMatcher mright(m.right().node());
      Emit(kArmVmlaF32, g.DefineSameAsFirst(node),
           g.UseRegister(m.left().node()), g.UseRegister(mright.left().node()),
           g.UseRegister(mright.right().node()));
      return;
    }
    VisitRRR(this, kArmVaddF32, node);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Add(node_t node) {
  ArmOperandGeneratorT<Adapter> g(this);
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const FloatBinopOp& add = this->Get(node).template Cast<FloatBinopOp>();
    const Operation& lhs = this->Get(add.left());
    if (lhs.Is<Opmask::kFloat64Mul>() && CanCover(node, add.left())) {
      const FloatBinopOp& mul = lhs.Cast<FloatBinopOp>();
      Emit(kArmVmlaF64, g.DefineSameAsFirst(node), g.UseRegister(add.right()),
           g.UseRegister(mul.left()), g.UseRegister(mul.right()));
      return;
    }
    const Operation& rhs = this->Get(add.right());
    if (rhs.Is<Opmask::kFloat64Mul>() && CanCover(node, add.right())) {
      const FloatBinopOp& mul = rhs.Cast<FloatBinopOp>();
      Emit(kArmVmlaF64, g.DefineSameAsFirst(node), g.UseRegister(add.left()),
           g.UseRegister(mul.left()), g.UseRegister(mul.right()));
      return;
    }
    VisitRRR(this, kArmVaddF64, node);
  } else {
    Float64BinopMatcher m(node);
    if (m.left().IsFloat64Mul() && CanCover(node, m.left().node())) {
      Float64BinopMatcher mleft(m.left().node());
      Emit(kArmVmlaF64, g.DefineSameAsFirst(node),
           g.UseRegister(m.right().node()), g.UseRegister(mleft.left().node()),
           g.UseRegister(mleft.right().node()));
      return;
    }
    if (m.right().IsFloat64Mul() && CanCover(node, m.right().node())) {
      Float64BinopMatcher mright(m.right().node());
      Emit(kArmVmlaF64, g.DefineSameAsFirst(node),
           g.UseRegister(m.left().node()), g.UseRegister(mright.left().node()),
           g.UseRegister(mright.right().node()));
      return;
    }
    VisitRRR(this, kArmVaddF64, node);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32Sub(node_t node) {
  ArmOperandGeneratorT<Adapter> g(this);
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const FloatBinopOp& sub = this->Get(node).template Cast<FloatBinopOp>();
    const Operation& rhs = this->Get(sub.right());
    if (rhs.Is<Opmask::kFloat32Mul>() && CanCover(node, sub.right())) {
      const FloatBinopOp& mul = rhs.Cast<FloatBinopOp>();
      Emit(kArmVmlsF32, g.DefineSameAsFirst(node), g.UseRegister(sub.left()),
           g.UseRegister(mul.left()), g.UseRegister(mul.right()));
      return;
    }
    VisitRRR(this, kArmVsubF32, node);
  } else {
    Float32BinopMatcher m(node);
    if (m.right().IsFloat32Mul() && CanCover(node, m.right().node())) {
      Float32BinopMatcher mright(m.right().node());
      Emit(kArmVmlsF32, g.DefineSameAsFirst(node),
           g.UseRegister(m.left().node()), g.UseRegister(mright.left().node()),
           g.UseRegister(mright.right().node()));
      return;
    }
    VisitRRR(this, kArmVsubF32, node);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Sub(node_t node) {
  ArmOperandGeneratorT<Adapter> g(this);
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const FloatBinopOp& sub = this->Get(node).template Cast<FloatBinopOp>();
    const Operation& rhs = this->Get(sub.right());
    if (rhs.Is<Opmask::kFloat64Mul>() && CanCover(node, sub.right())) {
      const FloatBinopOp& mul = rhs.Cast<FloatBinopOp>();
      Emit(kArmVmlsF64, g.DefineSameAsFirst(node), g.UseRegister(sub.left()),
           g.UseRegister(mul.left()), g.UseRegister(mul.right()));
      return;
    }
    VisitRRR(this, kArmVsubF64, node);
  } else {
    Float64BinopMatcher m(node);
    if (m.right().IsFloat64Mul() && CanCover(node, m.right().node())) {
      Float64BinopMatcher mright(m.right().node());
      Emit(kArmVmlsF64, g.DefineSameAsFirst(node),
           g.UseRegister(m.left().node()), g.UseRegister(mright.left().node()),
           g.UseRegister(mright.right().node()));
      return;
    }
    VisitRRR(this, kArmVsubF64, node);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Mod(node_t node) {
  ArmOperandGeneratorT<Adapter> g(this);
  Emit(kArmVmodF64, g.DefineAsFixed(node, d0),
       g.UseFixed(this->input_at(node, 0), d0),
       g.UseFixed(this->input_at(node, 1), d1))
      ->MarkAsCall();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Ieee754Binop(
    node_t node, InstructionCode opcode) {
  ArmOperandGeneratorT<Adapter> g(this);
  Emit(opcode, g.DefineAsFixed(node, d0),
       g.UseFixed(this->input_at(node, 0), d0),
       g.UseFixed(this->input_at(node, 1), d1))
      ->MarkAsCall();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Ieee754Unop(
    node_t node, InstructionCode opcode) {
  ArmOperandGeneratorT<Adapter> g(this);
  Emit(opcode, g.DefineAsFixed(node, d0),
       g.UseFixed(this->input_at(node, 0), d0))
      ->MarkAsCall();
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
    ArmOperandGeneratorT<Adapter> g(this);

    // Prepare for C function call.
    if (call_descriptor->IsCFunctionCall()) {
      Emit(kArchPrepareCallCFunction | MiscField::encode(static_cast<int>(
                                           call_descriptor->ParameterCount())),
           0, nullptr, 0, nullptr);

      // Poke any stack arguments.
      for (size_t n = 0; n < arguments->size(); ++n) {
        PushParameter input = (*arguments)[n];
        if (this->valid(input.node)) {
          int slot = static_cast<int>(n);
          Emit(kArmPoke | MiscField::encode(slot), g.NoOutput(),
               g.UseRegister(input.node));
        }
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
        Emit(kArmPush, g.NoOutput(), decrement, g.UseRegister(input.node));
      }
    }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::EmitPrepareResults(
    ZoneVector<PushParameter>* results, const CallDescriptor* call_descriptor,
    node_t node) {
    ArmOperandGeneratorT<Adapter> g(this);

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
        Emit(kArmPeek, g.DefineAsRegister(output.node),
             g.UseImmediate(reverse_slot));
      }
    }
}

template <typename Adapter>
bool InstructionSelectorT<Adapter>::IsTailCallAddressImmediate() {
  return false;
}

namespace {

// Shared routine for multiple compare operations.
template <typename Adapter>
void VisitCompare(InstructionSelectorT<Adapter>* selector,
                  InstructionCode opcode, InstructionOperand left,
                  InstructionOperand right, FlagsContinuationT<Adapter>* cont) {
  selector->EmitWithContinuation(opcode, left, right, cont);
}

// Shared routine for multiple float32 compare operations.
template <typename Adapter>
void VisitFloat32Compare(InstructionSelectorT<Adapter>* selector,
                         typename Adapter::node_t node,
                         FlagsContinuationT<Adapter>* cont) {
  ArmOperandGeneratorT<Adapter> g(selector);
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const ComparisonOp& cmp = selector->Get(node).template Cast<ComparisonOp>();
    if (selector->MatchZero(cmp.right())) {
      VisitCompare(selector, kArmVcmpF32, g.UseRegister(cmp.left()),
                   g.UseImmediate(cmp.right()), cont);
    } else if (selector->MatchZero(cmp.left())) {
      cont->Commute();
      VisitCompare(selector, kArmVcmpF32, g.UseRegister(cmp.right()),
                   g.UseImmediate(cmp.left()), cont);
    } else {
      VisitCompare(selector, kArmVcmpF32, g.UseRegister(cmp.left()),
                   g.UseRegister(cmp.right()), cont);
    }
  } else {
    Float32BinopMatcher m(node);
    if (m.right().Is(0.0f)) {
      VisitCompare(selector, kArmVcmpF32, g.UseRegister(m.left().node()),
                   g.UseImmediate(m.right().node()), cont);
    } else if (m.left().Is(0.0f)) {
      cont->Commute();
      VisitCompare(selector, kArmVcmpF32, g.UseRegister(m.right().node()),
                   g.UseImmediate(m.left().node()), cont);
    } else {
      VisitCompare(selector, kArmVcmpF32, g.UseRegister(m.left().node()),
                   g.UseRegister(m.right().node()), cont);
    }
  }
}

// Shared routine for multiple float64 compare operations.
template <typename Adapter>
void VisitFloat64Compare(InstructionSelectorT<Adapter>* selector,
                         typename Adapter::node_t node,
                         FlagsContinuationT<Adapter>* cont) {
  ArmOperandGeneratorT<Adapter> g(selector);
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const ComparisonOp& op = selector->Get(node).template Cast<ComparisonOp>();
    if (selector->MatchZero(op.right())) {
      VisitCompare(selector, kArmVcmpF64, g.UseRegister(op.left()),
                   g.UseImmediate(op.right()), cont);
    } else if (selector->MatchZero(op.left())) {
      cont->Commute();
      VisitCompare(selector, kArmVcmpF64, g.UseRegister(op.right()),
                   g.UseImmediate(op.left()), cont);
    } else {
      VisitCompare(selector, kArmVcmpF64, g.UseRegister(op.left()),
                   g.UseRegister(op.right()), cont);
    }
  } else {
    Float64BinopMatcher m(node);
    if (m.right().Is(0.0)) {
      VisitCompare(selector, kArmVcmpF64, g.UseRegister(m.left().node()),
                   g.UseImmediate(m.right().node()), cont);
    } else if (m.left().Is(0.0)) {
      cont->Commute();
      VisitCompare(selector, kArmVcmpF64, g.UseRegister(m.right().node()),
                   g.UseImmediate(m.left().node()), cont);
    } else {
      VisitCompare(selector, kArmVcmpF64, g.UseRegister(m.left().node()),
                   g.UseRegister(m.right().node()), cont);
    }
  }
}

// Check whether we can convert:
// ((a <op> b) cmp 0), b.<cond>
// to:
// (a <ops> b), b.<cond'>
// where <ops> is the flag setting version of <op>.
// We only generate conditions <cond'> that are a combination of the N
// and Z flags. This avoids the need to make this function dependent on
// the flag-setting operation.
bool CanUseFlagSettingBinop(FlagsCondition cond) {
  switch (cond) {
    case kEqual:
    case kNotEqual:
    case kSignedLessThan:
    case kSignedGreaterThanOrEqual:
    case kUnsignedLessThanOrEqual:  // x <= 0 -> x == 0
    case kUnsignedGreaterThan:      // x > 0 -> x != 0
      return true;
    default:
      return false;
  }
}

// Map <cond> to <cond'> so that the following transformation is possible:
// ((a <op> b) cmp 0), b.<cond>
// to:
// (a <ops> b), b.<cond'>
// where <ops> is the flag setting version of <op>.
FlagsCondition MapForFlagSettingBinop(FlagsCondition cond) {
  DCHECK(CanUseFlagSettingBinop(cond));
  switch (cond) {
    case kEqual:
    case kNotEqual:
      return cond;
    case kSignedLessThan:
      return kNegative;
    case kSignedGreaterThanOrEqual:
      return kPositiveOrZero;
    case kUnsignedLessThanOrEqual:  // x <= 0 -> x == 0
      return kEqual;
    case kUnsignedGreaterThan:  // x > 0 -> x != 0
      return kNotEqual;
    default:
      UNREACHABLE();
  }
}

// Check if we can perform the transformation:
// ((a <op> b) cmp 0), b.<cond>
// to:
// (a <ops> b), b.<cond'>
// where <ops> is the flag setting version of <op>, and if so,
// updates {node}, {opcode} and {cont} accordingly.
template <typename Adapter>
void MaybeReplaceCmpZeroWithFlagSettingBinop(
    InstructionSelectorT<Adapter>* selector, typename Adapter::node_t* node,
    typename Adapter::node_t binop, InstructionCode* opcode,
    FlagsCondition cond, FlagsContinuationT<Adapter>* cont) {
  InstructionCode binop_opcode;
  InstructionCode no_output_opcode;
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const Operation& op = selector->Get(binop);
    if (op.Is<Opmask::kWord32Add>()) {
      binop_opcode = kArmAdd;
      no_output_opcode = kArmCmn;
    } else if (op.Is<Opmask::kWord32BitwiseAnd>()) {
      binop_opcode = kArmAnd;
      no_output_opcode = kArmTst;
    } else if (op.Is<Opmask::kWord32BitwiseOr>()) {
      binop_opcode = kArmOrr;
      no_output_opcode = kArmOrr;
    } else if (op.Is<Opmask::kWord32BitwiseXor>()) {
      binop_opcode = kArmEor;
      no_output_opcode = kArmTeq;
    }
  } else {
    switch (binop->opcode()) {
      case IrOpcode::kInt32Add:
        binop_opcode = kArmAdd;
        no_output_opcode = kArmCmn;
        break;
      case IrOpcode::kWord32And:
        binop_opcode = kArmAnd;
        no_output_opcode = kArmTst;
        break;
      case IrOpcode::kWord32Or:
        binop_opcode = kArmOrr;
        no_output_opcode = kArmOrr;
        break;
      case IrOpcode::kWord32Xor:
        binop_opcode = kArmEor;
        no_output_opcode = kArmTeq;
        break;
      default:
        UNREACHABLE();
    }
  }

  if (selector->CanCover(*node, binop)) {
    // The comparison is the only user of {node}.
    cont->Overwrite(MapForFlagSettingBinop(cond));
    *opcode = no_output_opcode;
    *node = binop;
  } else if (selector->IsOnlyUserOfNodeInSameBlock(*node, binop)) {
    // We can also handle the case where the {node} and the comparison are in
    // the same basic block, and the comparison is the only user of {node} in
    // this basic block ({node} has users in other basic blocks).
    cont->Overwrite(MapForFlagSettingBinop(cond));
    *opcode = binop_opcode;
    *node = binop;
  }
}

// Shared routine for multiple word compare operations.
template <typename Adapter>
void VisitWordCompare(InstructionSelectorT<Adapter>* selector,
                      typename Adapter::node_t node, InstructionCode opcode,
                      FlagsContinuationT<Adapter>* cont) {
    ArmOperandGeneratorT<Adapter> g(selector);
    typename Adapter::node_t lhs = selector->input_at(node, 0);
    typename Adapter::node_t rhs = selector->input_at(node, 1);
    InstructionOperand inputs[3];
    size_t input_count = 0;
    InstructionOperand outputs[2];
    size_t output_count = 0;
    bool has_result = (opcode != kArmCmp) && (opcode != kArmCmn) &&
                      (opcode != kArmTst) && (opcode != kArmTeq);

    if (TryMatchImmediateOrShift(selector, &opcode, rhs, &input_count,
                                 &inputs[1])) {
      inputs[0] = g.UseRegister(lhs);
      input_count++;
    } else if (TryMatchImmediateOrShift(selector, &opcode, lhs, &input_count,
                                        &inputs[1])) {
      if constexpr (Adapter::IsTurboshaft) {
        using namespace turboshaft;  // NOLINT(build/namespaces)
        const Operation& op = selector->Get(node);
        if (const ComparisonOp* cmp = op.TryCast<ComparisonOp>()) {
          if (!ComparisonOp::IsCommutative(cmp->kind)) cont->Commute();
        } else if (const WordBinopOp* binop = op.TryCast<WordBinopOp>()) {
          if (!WordBinopOp::IsCommutative(binop->kind)) cont->Commute();
        } else {
          UNREACHABLE();
        }
      } else {
        if (!node->op()->HasProperty(Operator::kCommutative)) cont->Commute();
      }
      inputs[0] = g.UseRegister(rhs);
      input_count++;
    } else {
      opcode |= AddressingModeField::encode(kMode_Operand2_R);
      inputs[input_count++] = g.UseRegister(lhs);
      inputs[input_count++] = g.UseRegister(rhs);
    }

    if (has_result) {
      if (cont->IsDeoptimize()) {
        // If we can deoptimize as a result of the binop, we need to make sure
        // that the deopt inputs are not overwritten by the binop result. One
        // way to achieve that is to declare the output register as
        // same-as-first.
        outputs[output_count++] = g.DefineSameAsFirst(node);
      } else {
        outputs[output_count++] = g.DefineAsRegister(node);
      }
    }

    DCHECK_NE(0u, input_count);
    DCHECK_GE(arraysize(inputs), input_count);
    DCHECK_GE(arraysize(outputs), output_count);

    selector->EmitWithContinuation(opcode, output_count, outputs, input_count,
                                   inputs, cont);
}

template <typename Adapter>
void VisitWordCompare(InstructionSelectorT<Adapter>* selector,
                      typename Adapter::node_t node,
                      FlagsContinuationT<Adapter>* cont) {
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    InstructionCode opcode = kArmCmp;
    const ComparisonOp& comparison =
        selector->Get(node).template Cast<ComparisonOp>();
    const Operation& lhs = selector->Get(comparison.left());
    const Operation& rhs = selector->Get(comparison.right());

    FlagsCondition cond = cont->condition();
    if (selector->MatchIntegralZero(comparison.right()) &&
        (lhs.Is<Opmask::kWord32Add>() || lhs.Is<Opmask::kWord32BitwiseOr>() ||
         lhs.Is<Opmask::kWord32BitwiseAnd>() ||
         lhs.Is<Opmask::kWord32BitwiseXor>())) {
      // Emit flag setting instructions for comparisons against zero.
      if (CanUseFlagSettingBinop(cond)) {
        MaybeReplaceCmpZeroWithFlagSettingBinop(
            selector, &node, comparison.left(), &opcode, cond, cont);
      }
    } else if (selector->MatchIntegralZero(comparison.left()) &&
               (rhs.Is<Opmask::kWord32Add>() ||
                rhs.Is<Opmask::kWord32BitwiseOr>() ||
                rhs.Is<Opmask::kWord32BitwiseAnd>() ||
                rhs.Is<Opmask::kWord32BitwiseXor>())) {
      // Same as above, but we need to commute the condition before we
      // continue with the rest of the checks.
      cond = CommuteFlagsCondition(cond);
      if (CanUseFlagSettingBinop(cond)) {
        MaybeReplaceCmpZeroWithFlagSettingBinop(
            selector, &node, comparison.right(), &opcode, cond, cont);
      }
    }

    VisitWordCompare(selector, node, opcode, cont);
  } else {
    InstructionCode opcode = kArmCmp;
    Int32BinopMatcher m(node);

    FlagsCondition cond = cont->condition();
    if (m.right().Is(0) && (m.left().IsInt32Add() || m.left().IsWord32Or() ||
                            m.left().IsWord32And() || m.left().IsWord32Xor())) {
      // Emit flag setting instructions for comparisons against zero.
      if (CanUseFlagSettingBinop(cond)) {
        Node* binop = m.left().node();
        MaybeReplaceCmpZeroWithFlagSettingBinop(selector, &node, binop, &opcode,
                                                cond, cont);
      }
    } else if (m.left().Is(0) &&
               (m.right().IsInt32Add() || m.right().IsWord32Or() ||
                m.right().IsWord32And() || m.right().IsWord32Xor())) {
      // Same as above, but we need to commute the condition before we
      // continue with the rest of the checks.
      cond = CommuteFlagsCondition(cond);
      if (CanUseFlagSettingBinop(cond)) {
        Node* binop = m.right().node();
        MaybeReplaceCmpZeroWithFlagSettingBinop(selector, &node, binop, &opcode,
                                                cond, cont);
      }
    }

    VisitWordCompare(selector, node, opcode, cont);
  }
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
          return VisitWordCompare(this, value, cont);
        case IrOpcode::kInt32LessThan:
          cont->OverwriteAndNegateIfEqual(kSignedLessThan);
          return VisitWordCompare(this, value, cont);
        case IrOpcode::kInt32LessThanOrEqual:
          cont->OverwriteAndNegateIfEqual(kSignedLessThanOrEqual);
          return VisitWordCompare(this, value, cont);
        case IrOpcode::kUint32LessThan:
          cont->OverwriteAndNegateIfEqual(kUnsignedLessThan);
          return VisitWordCompare(this, value, cont);
        case IrOpcode::kUint32LessThanOrEqual:
          cont->OverwriteAndNegateIfEqual(kUnsignedLessThanOrEqual);
          return VisitWordCompare(this, value, cont);
        case IrOpcode::kFloat32Equal:
          cont->OverwriteAndNegateIfEqual(kEqual);
          return VisitFloat32Compare(this, value, cont);
        case IrOpcode::kFloat32LessThan:
          cont->OverwriteAndNegateIfEqual(kFloatLessThan);
          return VisitFloat32Compare(this, value, cont);
        case IrOpcode::kFloat32LessThanOrEqual:
          cont->OverwriteAndNegateIfEqual(kFloatLessThanOrEqual);
          return VisitFloat32Compare(this, value, cont);
        case IrOpcode::kFloat64Equal:
          cont->OverwriteAndNegateIfEqual(kEqual);
          return VisitFloat64Compare(this, value, cont);
        case IrOpcode::kFloat64LessThan:
          cont->OverwriteAndNegateIfEqual(kFloatLessThan);
          return VisitFloat64Compare(this, value, cont);
        case IrOpcode::kFloat64LessThanOrEqual:
          cont->OverwriteAndNegateIfEqual(kFloatLessThanOrEqual);
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
            if (!result || IsDefined(result)) {
              switch (node->opcode()) {
                case IrOpcode::kInt32AddWithOverflow:
                  cont->OverwriteAndNegateIfEqual(kOverflow);
                  return VisitBinop(this, node, kArmAdd, kArmAdd, cont);
                case IrOpcode::kInt32SubWithOverflow:
                  cont->OverwriteAndNegateIfEqual(kOverflow);
                  return VisitBinop(this, node, kArmSub, kArmRsb, cont);
                case IrOpcode::kInt32MulWithOverflow:
                  // ARM doesn't set the overflow flag for multiplication, so we
                  // need to test on kNotEqual. Here is the code sequence used:
                  //   smull resultlow, resulthigh, left, right
                  //   cmp resulthigh, Operand(resultlow, ASR, 31)
                  cont->OverwriteAndNegateIfEqual(kNotEqual);
                  return EmitInt32MulWithOverflow(this, node, cont);
                default:
                  break;
              }
            }
          }
          break;
        case IrOpcode::kInt32Add:
          return VisitWordCompare(this, value, kArmCmn, cont);
        case IrOpcode::kInt32Sub:
          return VisitWordCompare(this, value, kArmCmp, cont);
        case IrOpcode::kWord32And:
          return VisitWordCompare(this, value, kArmTst, cont);
        case IrOpcode::kWord32Or:
          return VisitBinop(this, value, kArmOrr, kArmOrr, cont);
        case IrOpcode::kWord32Xor:
          return VisitWordCompare(this, value, kArmTeq, cont);
        case IrOpcode::kWord32Sar:
          return VisitShift(this, value, TryMatchASR<Adapter>, cont);
        case IrOpcode::kWord32Shl:
          return VisitShift(this, value, TryMatchLSL<Adapter>, cont);
        case IrOpcode::kWord32Shr:
          return VisitShift(this, value, TryMatchLSR<Adapter>, cont);
        case IrOpcode::kWord32Ror:
          return VisitShift(this, value, TryMatchROR<Adapter>, cont);
        case IrOpcode::kStackPointerGreaterThan:
          cont->OverwriteAndNegateIfEqual(kStackPointerGreaterThanCondition);
          return VisitStackPointerGreaterThan(value, cont);
        default:
          break;
      }
    }

    if (user->opcode() == IrOpcode::kWord32Equal) {
      return VisitWordCompare(this, user, cont);
    }

    // Continuation could not be combined with a compare, emit compare against
    // 0.
    ArmOperandGeneratorT<Adapter> g(this);
    InstructionCode const opcode =
        kArmTst | AddressingModeField::encode(kMode_Operand2_R);
    InstructionOperand const value_operand = g.UseRegister(value);
    EmitWithContinuation(opcode, value_operand, value_operand, cont);
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
          return VisitWordCompare(this, value, cont);
        case RegisterRepresentation::Float32():
          switch (comparison->kind) {
            case ComparisonOp::Kind::kEqual:
              cont->OverwriteAndNegateIfEqual(kEqual);
              return VisitFloat32Compare(this, value, cont);
            case ComparisonOp::Kind::kSignedLessThan:
              cont->OverwriteAndNegateIfEqual(kFloatLessThan);
              return VisitFloat32Compare(this, value, cont);
            case ComparisonOp::Kind::kSignedLessThanOrEqual:
              cont->OverwriteAndNegateIfEqual(kFloatLessThanOrEqual);
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
              cont->OverwriteAndNegateIfEqual(kFloatLessThan);
              return VisitFloat64Compare(this, value, cont);
            case ComparisonOp::Kind::kSignedLessThanOrEqual:
              cont->OverwriteAndNegateIfEqual(kFloatLessThanOrEqual);
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
            DCHECK_EQ(binop->rep, WordRepresentation::Word32());
            switch (binop->kind) {
              case OverflowCheckedBinopOp::Kind::kSignedAdd:
                cont->OverwriteAndNegateIfEqual(kOverflow);
                return VisitBinop(this, node, kArmAdd, kArmAdd, cont);
              case OverflowCheckedBinopOp::Kind::kSignedSub:
                cont->OverwriteAndNegateIfEqual(kOverflow);
                return VisitBinop(this, node, kArmSub, kArmRsb, cont);
              case OverflowCheckedBinopOp::Kind::kSignedMul:
                // ARM doesn't set the overflow flag for multiplication, so we
                // need to test on kNotEqual. Here is the code sequence used:
                //   smull resultlow, resulthigh, left, right
                //   cmp resulthigh, Operand(resultlow, ASR, 31)
                cont->OverwriteAndNegateIfEqual(kNotEqual);
                return EmitInt32MulWithOverflow(this, node, cont);
            }
          }
        }
      }
    } else if (value_op.Is<Opmask::kWord32Add>()) {
      return VisitWordCompare(this, value, kArmCmn, cont);
    } else if (value_op.Is<Opmask::kWord32Sub>()) {
      return VisitWordCompare(this, value, kArmCmp, cont);
    } else if (value_op.Is<Opmask::kWord32BitwiseAnd>()) {
      return VisitWordCompare(this, value, kArmTst, cont);
    } else if (value_op.Is<Opmask::kWord32BitwiseOr>()) {
      return VisitBinop(this, value, kArmOrr, kArmOrr, cont);
    } else if (value_op.Is<Opmask::kWord32BitwiseXor>()) {
      return VisitWordCompare(this, value, kArmTeq, cont);
    } else if (value_op.Is<Opmask::kWord32ShiftRightArithmetic>()) {
      return VisitShift(this, value, TryMatchASR<TurboshaftAdapter>, cont);
    } else if (value_op.Is<Opmask::kWord32ShiftLeft>()) {
      return VisitShift(this, value, TryMatchLSL<TurboshaftAdapter>, cont);
    } else if (value_op.Is<Opmask::kWord32ShiftRightLogical>()) {
      return VisitShift(this, value, TryMatchLSR<TurboshaftAdapter>, cont);
    } else if (value_op.Is<Opmask::kWord32RotateRight>()) {
      return VisitShift(this, value, TryMatchROR<TurboshaftAdapter>, cont);
    } else if (value_op.Is<StackPointerGreaterThanOp>()) {
      cont->OverwriteAndNegateIfEqual(kStackPointerGreaterThanCondition);
      return VisitStackPointerGreaterThan(value, cont);
    }
  }

  if (Get(user).Is<Opmask::kWord32Equal>()) {
    return VisitWordCompare(this, user, cont);
  }

  // Continuation could not be combined with a compare, emit compare against
  // 0.
  ArmOperandGeneratorT<TurboshaftAdapter> g(this);
  InstructionCode const opcode =
      kArmTst | AddressingModeField::encode(kMode_Operand2_R);
  InstructionOperand const value_o
```