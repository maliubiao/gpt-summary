Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/compiler/backend/riscv/instruction-selector-riscv64.cc`. The summary should include:

1. **Overall purpose:** What does this code do?
2. **`.tq` check:** Is it a Torque file?
3. **JavaScript relation:** Does it relate to JavaScript functionality? If so, provide a JavaScript example.
4. **Code logic example:** Provide a hypothetical input and output for a specific function.
5. **Common programming errors:** Are there common errors this code helps avoid or could be related to?
6. **Summarize the functionality:** A concise overview.

Let's break down the code:

*   It's C++ code, not Torque.
*   It's part of the V8 compiler's backend for the RISC-V 64-bit architecture.
*   The name `instruction-selector` suggests it's involved in selecting specific RISC-V instructions to implement higher-level operations.
*   It handles various operations like loads, stores (including atomic), comparisons, arithmetic (with overflow checks), and stack checks.
*   It seems to have different implementations based on whether Turbofan or Turboshaft is used as the optimizing compiler.
*   There are specific functions for handling atomic operations, which are crucial for concurrent programming.
*   The code interacts with the `InstructionSelector` class and uses `OperandGenerator` to manage operands.
*   It uses `FlagsContinuation` to handle conditional branching based on the results of operations.
*   There's logic for optimizing comparisons against zero by inverting branches.
*   It handles comparisons with immediate values, including read-only root handles.

Based on this analysis, I can now formulate the answers.
```
/**
 * @file src/compiler/backend/riscv/instruction-selector-riscv64.cc
 * @brief Instruction selector for the riscv64 architecture.
 */
```

这是 V8 引擎中 RISC-V 64 位架构的指令选择器（Instruction Selector）的 C++ 源代码。它的主要功能是将 V8 编译器生成的中间表示（IR - Intermediate Representation）转换为目标 RISC-V 64 位架构的机器指令。

**功能列表:**

1. **内存访问指令选择:**  选择合适的 RISC-V 指令来执行内存的加载 (Load) 和存储 (Store) 操作，包括常规的加载/存储以及原子操作（如 `VisitAtomicLoad`, `VisitAtomicStore`, `VisitAtomicExchange`, `VisitAtomicCompareExchange`）。
2. **算术运算指令选择:**  选择 RISC-V 指令来实现各种算术运算，例如加法、减法、乘法等，并处理溢出情况 (`VisitInt32AddWithOverflow`, `VisitInt32SubWithOverflow`, 等)。
3. **比较指令选择:**  选择 RISC-V 指令来执行比较操作 (`VisitWord32Equal`, `VisitInt32LessThan`, 等)，并根据比较结果设置标志位，供后续条件跳转使用。
4. **栈操作指令选择:**  处理与栈相关的操作，例如检查栈指针是否超出限制 (`VisitStackPointerGreaterThan`)。
5. **条件分支指令优化:**  优化条件分支指令的选择，例如将与零比较的操作与后续的条件跳转指令合并，以提高效率 (`VisitWordCompareZero`)。
6. **常量加载优化:**  针对某些常量（例如只读根对象），尝试使用立即数寻址模式，以减少指令数量。
7. **原子操作处理:**  针对原子加载、存储、交换和比较交换等操作，生成相应的原子指令序列，保证并发安全性。
8. **支持 Turbofan 和 Turboshaft 编译器:**  代码中可以看到针对不同编译器的适配 (`template <typename Adapter>`)，这表明该文件被 Turbofan 和 Turboshaft 两个 V8 的优化编译器后端所使用。

**关于源代码类型:**

`v8/src/compiler/backend/riscv/instruction-selector-riscv64.cc`  以 `.cc` 结尾，这是一个标准的 C++ 源代码文件。如果以 `.tq` 结尾，那它才是一个 V8 Torque 源代码。

**与 JavaScript 功能的关系和示例:**

指令选择器的主要任务是将高级的 JavaScript 操作转换为底层的机器指令。以下是一些 JavaScript 代码示例以及 `instruction-selector-riscv64.cc` 中可能处理的相关功能：

**示例 1: 内存访问**

```javascript
let a = [1, 2, 3];
let b = a[1]; // 加载操作
a[0] = 4;     // 存储操作
```

在 `instruction-selector-riscv64.cc` 中，`VisitLoadField`, `VisitStoreField`, `VisitLoadElement`, `VisitStoreElement` 等函数会负责将这些 JavaScript 的数组元素访问转换为 RISC-V 的加载和存储指令。例如，访问 `a[1]` 可能会生成类似于 `ld x10, offset(x11)` 的指令，其中 `x11` 是存储数组 `a` 基地址的寄存器，`offset` 是偏移量。

**示例 2: 算术运算**

```javascript
let x = 5;
let y = 10;
let sum = x + y;
```

`VisitInt32Add` (或 `VisitInt64Add`) 等函数会将 JavaScript 的加法操作转换为 RISC-V 的加法指令，如 `addw x12, x10, x11` (32位加法) 或 `add x12, x10, x11` (64位加法)。

**示例 3: 比较操作**

```javascript
let p = 5;
let q = 10;
if (p < q) {
  console.log("p is less than q");
}
```

`VisitInt32LessThan` 会将 `<` 比较操作转换为 RISC-V 的比较指令，例如 `slt x10, x11, x12` (set less than)。后续的条件分支语句会使用比较结果设置的标志位。

**示例 4: 原子操作 (适用于多线程/共享内存)**

```javascript
// 使用 SharedArrayBuffer 和 Atomics API
const sab = new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT * 1);
const view = new Int32Array(sab);
Atomics.add(view, 0, 5);
```

`VisitWord32AtomicAdd` 等函数会负责将 `Atomics.add` 这样的原子操作转换为 RISC-V 的原子指令，例如 `amoadd.w.aqrl x10, x11, (x12)`，确保在多线程环境下的数据一致性。

**代码逻辑推理的假设输入与输出:**

假设有一个简单的加法操作的 IR 节点需要被处理：

**假设输入 (IR 节点):**

*   **操作类型:**  `Int32Add`
*   **输入 1:**  一个表示数值 `5` 的寄存器 (假设是 `v1`)
*   **输入 2:**  一个表示数值 `10` 的寄存器 (假设是 `v2`)
*   **输出:**  一个新的寄存器 (假设是 `v3`)

**可能输出 (RISC-V 指令):**

```assembly
addw v3, v1, v2  // 将 v1 和 v2 的值相加，结果存储到 v3
```

在这个例子中，`VisitInt32Add` 函数会接收这个 IR 节点的信息，并生成相应的 `addw` 指令。

**涉及用户常见的编程错误:**

虽然指令选择器本身不直接处理用户的编程错误，但它生成的代码与某些常见的错误密切相关：

1. **整数溢出:**  代码中的 `VisitInt32AddWithOverflow` 等函数会处理可能导致溢出的算术运算。如果 JavaScript 代码中没有进行溢出检查，并且结果超出了整数类型的范围，可能会导致不可预测的行为。指令选择器会生成带有溢出检测的指令，并在溢出时触发相应的处理（例如抛出异常）。

    ```javascript
    let maxInt = 2147483647;
    let result = maxInt + 1; // 可能会溢出
    ```

2. **并发问题 (数据竞争):**  在多线程环境下，对共享变量的并发访问如果没有适当的同步机制，可能导致数据竞争。`VisitAtomicLoad`, `VisitAtomicStore` 等函数生成的原子指令可以帮助避免这类问题。用户如果直接使用底层的非原子操作来修改共享数据，就会出现问题。

    ```javascript
    // 错误示例 (没有使用 Atomics)
    let sharedValue = 0;
    // 线程 1: sharedValue++;
    // 线程 2: sharedValue++; // 可能导致数据丢失
    ```

3. **内存访问错误:**  访问未分配或越界的内存可能导致程序崩溃。指令选择器在生成内存访问指令时，会基于编译器的类型信息和边界检查来生成相应的代码。如果 JavaScript 代码中存在数组越界访问等错误，最终生成的机器码可能会触发硬件异常。

    ```javascript
    let arr = [1, 2];
    let value = arr[2]; // 越界访问
    ```

**归纳功能:**

`v8/src/compiler/backend/riscv/instruction-selector-riscv64.cc` 负责将 V8 编译器生成的平台无关的中间表示（IR）转换为特定于 RISC-V 64 位架构的高效机器指令。它针对各种操作（内存访问、算术运算、比较、原子操作等）选择合适的 RISC-V 指令，并进行一些优化，以确保生成的代码能够正确、高效地执行 JavaScript 代码。它是 V8 编译器后端的重要组成部分，连接了高级的语言特性和底层的硬件指令。

Prompt: 
```
这是目录为v8/src/compiler/backend/riscv/instruction-selector-riscv64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/riscv/instruction-selector-riscv64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共5部分，请归纳一下它的功能

"""
ze);
        code = kRiscvStoreCompressTagged;
        break;
      default:
        UNREACHABLE();
    }
    code |= AtomicWidthField::encode(width);

    if (store_params.kind() == MemoryAccessKind::kProtectedByTrapHandler) {
      code |= AccessModeField::encode(kMemoryAccessProtectedMemOutOfBounds);
    }
    if (g.CanBeImmediate(index, code)) {
      selector->Emit(code | AddressingModeField::encode(kMode_MRI) |
                         AtomicWidthField::encode(width),
                     g.NoOutput(), g.UseRegisterOrImmediateZero(value),
                     g.UseRegister(base), g.UseImmediate(index));
    } else {
      InstructionOperand addr_reg = g.TempRegister();
      selector->Emit(kRiscvAdd64 | AddressingModeField::encode(kMode_None),
                     addr_reg, g.UseRegister(index), g.UseRegister(base));
      // Emit desired store opcode, using temp addr_reg.
      selector->Emit(code | AddressingModeField::encode(kMode_MRI) |
                         AtomicWidthField::encode(width),
                     g.NoOutput(), g.UseRegisterOrImmediateZero(value),
                     addr_reg, g.TempImmediate(0));
    }
  }
}

template <typename Adapter>
void VisitAtomicBinop(InstructionSelectorT<Adapter>* selector,
                      typename Adapter::node_t node, ArchOpcode opcode,
                      AtomicWidth width, MemoryAccessKind access_kind) {
  using node_t = typename Adapter::node_t;
  RiscvOperandGeneratorT<Adapter> g(selector);
  auto atomic_op = selector->atomic_rmw_view(node);
  node_t base = atomic_op.base();
  node_t index = atomic_op.index();
  node_t value = atomic_op.value();

  AddressingMode addressing_mode = kMode_MRI;
  InstructionOperand inputs[3];
  size_t input_count = 0;
  inputs[input_count++] = g.UseUniqueRegister(base);
  inputs[input_count++] = g.UseUniqueRegister(index);
  inputs[input_count++] = g.UseUniqueRegister(value);
  InstructionOperand outputs[1];
  outputs[0] = g.UseUniqueRegister(node);
  InstructionOperand temps[4];
  temps[0] = g.TempRegister();
  temps[1] = g.TempRegister();
  temps[2] = g.TempRegister();
  temps[3] = g.TempRegister();
  InstructionCode code = opcode | AddressingModeField::encode(addressing_mode) |
                         AtomicWidthField::encode(width);
  if (access_kind == MemoryAccessKind::kProtectedByTrapHandler) {
    code |= AccessModeField::encode(kMemoryAccessProtectedMemOutOfBounds);
  }
  selector->Emit(code, 1, outputs, input_count, inputs, 4, temps);
}

}  // namespace

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitStackPointerGreaterThan(
    node_t node, FlagsContinuationT<Adapter>* cont) {
  StackCheckKind kind;
  node_t value;
  if constexpr (Adapter::IsTurboshaft) {
    const auto& op =
        this->turboshaft_graph()
            ->Get(node)
            .template Cast<turboshaft::StackPointerGreaterThanOp>();
    kind = op.kind;
    value = op.stack_limit();
  } else {
    kind = StackCheckKindOf(node->op());
    value = this->input_at(node, 0);
  }
  InstructionCode opcode =
      kArchStackPointerGreaterThan | MiscField::encode(static_cast<int>(kind));

  RiscvOperandGeneratorT<Adapter> g(this);

  // No outputs.
  InstructionOperand* const outputs = nullptr;
  const int output_count = 0;

  // Applying an offset to this stack check requires a temp register. Offsets
  // are only applied to the first stack check. If applying an offset, we must
  // ensure the input and temp registers do not alias, thus kUniqueRegister.
  InstructionOperand temps[] = {g.TempRegister()};
  const int temp_count = (kind == StackCheckKind::kJSFunctionEntry ? 1 : 0);
  const auto register_mode = (kind == StackCheckKind::kJSFunctionEntry)
                                 ? OperandGenerator::kUniqueRegister
                                 : OperandGenerator::kRegister;

  InstructionOperand inputs[] = {g.UseRegisterWithMode(value, register_mode)};
  static constexpr int input_count = arraysize(inputs);

  EmitWithContinuation(opcode, output_count, outputs, input_count, inputs,
                       temp_count, temps, cont);
}

bool CanCoverTrap(Node* user, Node* value) {
  if (user->opcode() != IrOpcode::kTrapUnless &&
      user->opcode() != IrOpcode::kTrapIf)
    return true;
  if (value->opcode() == IrOpcode::kWord32Equal ||
      value->opcode() == IrOpcode::kInt32LessThan ||
      value->opcode() == IrOpcode::kInt32LessThanOrEqual ||
      value->opcode() == IrOpcode::kUint32LessThan ||
      value->opcode() == IrOpcode::kUint32LessThanOrEqual)
    return false;
  return true;
}
// Shared routine for word comparisons against zero.
template <>
void InstructionSelectorT<TurbofanAdapter>::VisitWordCompareZero(
    node_t user, node_t value, FlagsContinuation* cont) {
  // Try to combine with comparisons against 0 by simply inverting the branch.
  while (CanCover(user, value)) {
    if (value->opcode() == IrOpcode::kWord32Equal) {
      Int32BinopMatcher m(value);
      if (!m.right().Is(0)) break;
      user = value;
      value = m.left().node();
    } else if (value->opcode() == IrOpcode::kWord64Equal) {
      Int64BinopMatcher m(value);
      if (!m.right().Is(0)) break;
      user = value;
      value = m.left().node();
    } else {
      break;
    }
    cont->Negate();
  }

  if (CanCoverTrap(user, value) && CanCover(user, value)) {
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
                return VisitBinop<TurbofanAdapter, Int32BinopMatcher>(
                    this, node, kRiscvAdd64, cont);
              case IrOpcode::kInt32SubWithOverflow:
                cont->OverwriteAndNegateIfEqual(kOverflow);
                return VisitBinop<TurbofanAdapter, Int32BinopMatcher>(
                    this, node, kRiscvSub64, cont);
              case IrOpcode::kInt32MulWithOverflow:
                cont->OverwriteAndNegateIfEqual(kOverflow);
                return VisitBinop<TurbofanAdapter, Int32BinopMatcher>(
                    this, node, kRiscvMulOvf32, cont);
              case IrOpcode::kInt64AddWithOverflow:
                cont->OverwriteAndNegateIfEqual(kOverflow);
                return VisitBinop<TurbofanAdapter, Int32BinopMatcher>(
                    this, node, kRiscvAddOvf64, cont);
              case IrOpcode::kInt64SubWithOverflow:
                cont->OverwriteAndNegateIfEqual(kOverflow);
                return VisitBinop<TurbofanAdapter, Int32BinopMatcher>(
                    this, node, kRiscvSubOvf64, cont);
              default:
                break;
            }
          }
        }
        break;
      case IrOpcode::kWord32And:
#if V8_COMPRESS_POINTERS
        VisitWordCompare(this, value, kRiscvTst32, cont, true);
        return;
#endif
        case IrOpcode::kWord64And:
          VisitWordCompare(this, value, kRiscvTst64, cont, true);
          return;
        case IrOpcode::kStackPointerGreaterThan:
          cont->OverwriteAndNegateIfEqual(kStackPointerGreaterThanCondition);
          return VisitStackPointerGreaterThan(value, cont);
        default:
          break;
      }
    }

    // Continuation could not be combined with a compare, emit compare against
    // 0.
#ifdef V8_COMPRESS_POINTERS
    switch (user->opcode()) {
      case IrOpcode::kWord64Equal:
      case IrOpcode::kInt64LessThan:
      case IrOpcode::kInt64LessThanOrEqual:
      case IrOpcode::kUint64LessThan:
      case IrOpcode::kUint64LessThanOrEqual:
        return EmitWordCompareZero(this, value, cont);
      default:
        return EmitWord32CompareZero(this, value, cont);
    }
#else
    switch (user->opcode()) {
      case IrOpcode::kWord32Equal:
      case IrOpcode::kInt32LessThan:
      case IrOpcode::kInt32LessThanOrEqual:
      case IrOpcode::kUint32LessThan:
      case IrOpcode::kUint32LessThanOrEqual:
        return EmitWord32CompareZero(this, value, cont);
      default:
        return EmitWordCompareZero(this, value, cont);
    }
#endif
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitWordCompareZero(
    node_t user, node_t value, FlagsContinuation* cont) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  // Try to combine with comparisons against 0 by simply inverting the branch.
  while (const ComparisonOp* equal =
             this->TryCast<Opmask::kWord32Equal>(value)) {
    if (!CanCover(user, value)) break;
    if (!MatchIntegralZero(equal->right())) break;

    user = value;
    value = equal->left();
    cont->Negate();
  }

  const Operation& value_op = Get(value);
  if (CanCover(user, value)) {
    if (const ComparisonOp* comparison = value_op.TryCast<ComparisonOp>()) {
      switch (comparison->rep.value()) {
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
            const bool is64 = binop->rep == WordRepresentation::Word64();
            switch (binop->kind) {
              case OverflowCheckedBinopOp::Kind::kSignedAdd:
                cont->OverwriteAndNegateIfEqual(kOverflow);
                return VisitBinop<TurboshaftAdapter, Int32BinopMatcher>(
                    this, node, is64 ? kRiscvAddOvf64 : kRiscvAdd64, cont);
              case OverflowCheckedBinopOp::Kind::kSignedSub:
                cont->OverwriteAndNegateIfEqual(kOverflow);
                return VisitBinop<TurboshaftAdapter, Int32BinopMatcher>(
                    this, node, is64 ? kRiscvSubOvf64 : kRiscvSub64, cont);
              case OverflowCheckedBinopOp::Kind::kSignedMul:
                cont->OverwriteAndNegateIfEqual(kOverflow);
                return VisitBinop<TurboshaftAdapter, Int32BinopMatcher>(
                    this, node, is64 ? kRiscvMulOvf64 : kRiscvMulOvf32, cont);
            }
          }
        }
      }
    }
  }

  // Continuation could not be combined with a compare, emit compare against
  // 0.
  const ComparisonOp* comparison = this->Get(user).TryCast<ComparisonOp>();
#ifdef V8_COMPRESS_POINTERS
  if (comparison &&
      comparison->rep.value() == RegisterRepresentation::Word64()) {
    return EmitWordCompareZero(this, value, cont);
  } else {
    return EmitWord32CompareZero(this, value, cont);
  }
#else
  if (comparison &&
      comparison->rep.value() == RegisterRepresentation::Word32()) {
    return EmitWord32CompareZero(this, value, cont);
  } else {
    return EmitWordCompareZero(this, value, cont);
  }
#endif
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Equal(node_t node) {
    Node* const user = node;
    FlagsContinuation cont = FlagsContinuation::ForSet(kEqual, node);
    Int32BinopMatcher m(user);
    if (m.right().Is(0)) {
      return VisitWordCompareZero(m.node(), m.left().node(), &cont);
    }
    if (isolate() && (V8_STATIC_ROOTS_BOOL ||
                      (COMPRESS_POINTERS_BOOL && !isolate()->bootstrapper()))) {
      RiscvOperandGeneratorT<Adapter> g(this);
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
          Tagged_t ptr =
              MacroAssemblerBase::ReadOnlyRootPtr(root_index, isolate());
          if (g.CanBeImmediate(ptr, kRiscvCmp32)) {
            VisitCompare(this, kRiscvCmp32, g.UseRegister(left),
                         g.TempImmediate(int32_t(ptr)), &cont);
            return;
          }
        }
      }
    }
    VisitWord32Compare(this, node, &cont);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitWord32Equal(node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  const Operation& equal = Get(node);
  DCHECK(equal.Is<ComparisonOp>());
  OpIndex left = equal.input(0);
  OpIndex right = equal.input(1);
  OpIndex user = node;
  FlagsContinuation cont = FlagsContinuation::ForSet(kEqual, node);

  if (MatchZero(right)) {
    return VisitWordCompareZero(user, left, &cont);
  }

  if (isolate() && (V8_STATIC_ROOTS_BOOL ||
                    (COMPRESS_POINTERS_BOOL && !isolate()->bootstrapper()))) {
    RiscvOperandGeneratorT<TurboshaftAdapter> g(this);
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
        if (g.CanBeImmediate(ptr, kRiscvCmp32)) {
          VisitCompare(this, kRiscvCmp32, g.UseRegister(left),
                       g.TempImmediate(int32_t(ptr)), &cont);
          return;
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
void InstructionSelectorT<Adapter>::VisitInt32AddWithOverflow(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    OpIndex ovf = FindProjection(node, 1);
    if (ovf.valid() && IsUsed(ovf)) {
      FlagsContinuation cont = FlagsContinuation::ForSet(kOverflow, ovf);
      return VisitBinop<Adapter, Int32BinopMatcher>(this, node, kRiscvAdd64,
                                                    &cont);
    }
    FlagsContinuation cont;
    VisitBinop<Adapter, Int32BinopMatcher>(this, node, kRiscvAdd64, &cont);
  } else {
    if (Node* ovf = NodeProperties::FindProjection(node, 1)) {
      FlagsContinuation cont = FlagsContinuation::ForSet(kOverflow, ovf);
      return VisitBinop<Adapter, Int32BinopMatcher>(this, node, kRiscvAdd64,
                                                    &cont);
    }
    FlagsContinuation cont;
    VisitBinop<Adapter, Int32BinopMatcher>(this, node, kRiscvAdd64, &cont);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32SubWithOverflow(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    OpIndex ovf = FindProjection(node, 1);
    if (ovf.valid()) {
      FlagsContinuation cont = FlagsContinuation::ForSet(kOverflow, ovf);
      return VisitBinop<Adapter, Int32BinopMatcher>(this, node, kRiscvSub64,
                                                    &cont);
    }
    FlagsContinuation cont;
    VisitBinop<Adapter, Int32BinopMatcher>(this, node, kRiscvSub64, &cont);
  } else {
    if (Node* ovf = NodeProperties::FindProjection(node, 1)) {
      FlagsContinuation cont = FlagsContinuation::ForSet(kOverflow, ovf);
      return VisitBinop<Adapter, Int32BinopMatcher>(this, node, kRiscvSub64,
                                                    &cont);
    }
    FlagsContinuation cont;
    VisitBinop<Adapter, Int32BinopMatcher>(this, node, kRiscvSub64, &cont);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32MulWithOverflow(node_t node) {
  node_t ovf = FindProjection(node, 1);
  if (this->valid(ovf)) {
    FlagsContinuation cont = FlagsContinuation::ForSet(kOverflow, ovf);
    return VisitBinop<Adapter, Int32BinopMatcher>(this, node, kRiscvMulOvf32,
                                                  &cont);
  }
  FlagsContinuation cont;
  VisitBinop<Adapter, Int32BinopMatcher>(this, node, kRiscvMulOvf32, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt64AddWithOverflow(node_t node) {
  node_t ovf = FindProjection(node, 1);
  if (this->valid(ovf)) {
    FlagsContinuation cont = FlagsContinuation::ForSet(kOverflow, ovf);
    return VisitBinop<Adapter, Int64BinopMatcher>(this, node, kRiscvAddOvf64,
                                                  &cont);
  }
  FlagsContinuation cont;
  VisitBinop<Adapter, Int64BinopMatcher>(this, node, kRiscvAddOvf64, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt64SubWithOverflow(node_t node) {
  node_t ovf = FindProjection(node, 1);
  if (this->valid(ovf)) {
    FlagsContinuation cont = FlagsContinuation::ForSet(kOverflow, ovf);
    return VisitBinop<Adapter, Int64BinopMatcher>(this, node, kRiscvSubOvf64,
                                                  &cont);
  }
    FlagsContinuation cont;
    VisitBinop<Adapter, Int64BinopMatcher>(this, node, kRiscvSubOvf64, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt64MulWithOverflow(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    OpIndex ovf = FindProjection(node, 1);
    if (ovf.valid()) {
      FlagsContinuation cont = FlagsContinuation::ForSet(kOverflow, ovf);
      return VisitBinop<Adapter, Int64BinopMatcher>(this, node, kRiscvMulOvf64,
                                                    &cont);
    }
  } else {
    if (Node* ovf = NodeProperties::FindProjection(node, 1)) {
      FlagsContinuation cont = FlagsContinuation::ForSet(kNotEqual, ovf);
      return VisitBinop<Adapter, Int64BinopMatcher>(this, node, kRiscvMulOvf64,
                                                    &cont);
    }
  }
    FlagsContinuation cont;
    VisitBinop<Adapter, Int64BinopMatcher>(this, node, kRiscvMulOvf64, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64Equal(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    FlagsContinuation cont = FlagsContinuation::ForSet(kEqual, node);
    const ComparisonOp& equal = this->Get(node).template Cast<ComparisonOp>();
    DCHECK_EQ(equal.kind, ComparisonOp::Kind::kEqual);
    if (this->MatchIntegralZero(equal.right())) {
      return VisitWordCompareZero(node, equal.left(), &cont);
    }
    VisitWord64Compare(this, node, &cont);
  } else {
    FlagsContinuation cont = FlagsContinuation::ForSet(kEqual, node);
    Int64BinopMatcher m(node);
    if (m.right().Is(0)) {
      return VisitWordCompareZero(m.node(), m.left().node(), &cont);
    }

    VisitWord64Compare(this, node, &cont);
  }
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
void InstructionSelectorT<Adapter>::VisitWord32AtomicLoad(node_t node) {
    VisitAtomicLoad(this, node, AtomicWidth::kWord32);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicStore(node_t node) {
    VisitAtomicStore(this, node, AtomicWidth::kWord32);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64AtomicLoad(node_t node) {
    VisitAtomicLoad(this, node, AtomicWidth::kWord64);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64AtomicStore(node_t node) {
    VisitAtomicStore(this, node, AtomicWidth::kWord64);
}

template <typename Adapter>
void VisitAtomicExchange(InstructionSelectorT<Adapter>* selector,
                         typename Adapter::node_t node, ArchOpcode opcode,
                         AtomicWidth width, MemoryAccessKind access_kind) {
  using node_t = typename Adapter::node_t;
  auto atomic_op = selector->atomic_rmw_view(node);
  RiscvOperandGeneratorT<Adapter> g(selector);
  node_t base = atomic_op.base();
  node_t index = atomic_op.index();
  node_t value = atomic_op.value();

  InstructionOperand inputs[3];
  size_t input_count = 0;
  inputs[input_count++] = g.UseUniqueRegister(base);
  inputs[input_count++] = g.UseUniqueRegister(index);
  inputs[input_count++] = g.UseUniqueRegister(value);
  InstructionOperand outputs[1];
  outputs[0] = g.UseUniqueRegister(node);
  InstructionOperand temp[3];
  temp[0] = g.TempRegister();
  temp[1] = g.TempRegister();
  temp[2] = g.TempRegister();

  InstructionCode code = opcode | AddressingModeField::encode(kMode_MRI) |
                         AtomicWidthField::encode(width);
  if (access_kind == MemoryAccessKind::kProtectedByTrapHandler) {
    code |= AccessModeField::encode(kMemoryAccessProtectedMemOutOfBounds);
  }
  selector->Emit(code, 1, outputs, input_count, inputs, 3, temp);
}

template <typename Adapter>
void VisitAtomicCompareExchange(InstructionSelectorT<Adapter>* selector,
                                typename Adapter::node_t node,
                                ArchOpcode opcode, AtomicWidth width,
                                MemoryAccessKind access_kind) {
  RiscvOperandGeneratorT<Adapter> g(selector);
  using node_t = typename Adapter::node_t;
  auto atomic_op = selector->atomic_rmw_view(node);
  node_t base = atomic_op.base();
  node_t index = atomic_op.index();
  node_t old_value = atomic_op.expected();
  node_t new_value = atomic_op.value();

  AddressingMode addressing_mode = kMode_MRI;
  InstructionOperand inputs[4];
  size_t input_count = 0;
  inputs[input_count++] = g.UseUniqueRegister(base);
  inputs[input_count++] = g.UseUniqueRegister(index);
  inputs[input_count++] = g.UseUniqueRegister(old_value);
  inputs[input_count++] = g.UseUniqueRegister(new_value);
  InstructionOperand outputs[1];
  outputs[0] = g.UseUniqueRegister(node);
  InstructionOperand temp[3];
  temp[0] = g.TempRegister();
  temp[1] = g.TempRegister();
  temp[2] = g.TempRegister();
  InstructionCode code = opcode | AddressingModeField::encode(addressing_mode) |
                         AtomicWidthField::encode(width);
  if (access_kind == MemoryAccessKind::kProtectedByTrapHandler) {
    code |= AccessModeField::encode(kMemoryAccessProtectedMemOutOfBounds);
  }
  selector->Emit(code, 1, outputs, input_count, inputs, 3, temp);
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
void InstructionSelectorT<TurbofanAdapter>::VisitWord32AtomicExchange(
    Node* node) {
  ArchOpcode opcode;
  AtomicOpParameters params = AtomicOpParametersOf(node->op());
  if (params.type() == MachineType::Int8()) {
    opcode = kAtomicExchangeInt8;
  } else if (params.type() == MachineType::Uint8()) {
    opcode = kAtomicExchangeUint8;
  } else if (params.type() == MachineType::Int16()) {
    opcode = kAtomicExchangeInt16;
  } else if (params.type() == MachineType::Uint16()) {
    opcode = kAtomicExchangeUint16;
  } else if (params.type() == MachineType::Int32() ||
             params.type() == MachineType::Uint32()) {
    opcode = kAtomicExchangeWord32;
  } else {
    UNREACHABLE();
  }

  VisitAtomicExchange(this, node, opcode, AtomicWidth::kWord32, params.kind());
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
    opcode = kRiscvWord64AtomicExchangeUint64;
  } else {
    UNREACHABLE();
  }
  VisitAtomicExchange(this, node, opcode, AtomicWidth::kWord64,
                      atomic_op.memory_access_kind);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitWord64AtomicExchange(
    Node* node) {
  ArchOpcode opcode;
  AtomicOpParameters params = AtomicOpParametersOf(node->op());
  if (params.type() == MachineType::Uint8()) {
    opcode = kAtomicExchangeU
"""


```