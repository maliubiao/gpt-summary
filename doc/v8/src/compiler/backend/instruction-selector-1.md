Response: The user wants a summary of the C++ code file `v8/src/compiler/backend/instruction-selector.cc`. This is the second part of a four-part file. The request also asks to illustrate the functionality with JavaScript if applicable.

**Plan:**

1. **Identify Key Components:** Scan the code for major classes, functions, and data structures.
2. **Infer Functionality:** Based on the names and operations within these components, deduce the purpose of the code.
3. **Focus on Part 2:** Ensure the summary specifically covers the functionality present in the provided snippet.
4. **Connect to JavaScript (if possible):**  If the code relates to how JavaScript code is translated or optimized, provide a JavaScript example to illustrate the concept.

**Observations from the Code Snippet:**

* **Templates:** The code heavily uses C++ templates (`template <typename Adapter>`). This suggests it's designed to be adaptable to different architectures or intermediate representations.
* **`InstructionSelectorT` class:** This seems to be the central class for selecting instructions.
* **`Visit...` methods:**  A large number of methods starting with `Visit` suggests a visitor pattern for traversing an intermediate representation of code (likely an Abstract Syntax Tree or a similar graph-based structure).
* **`Emit` method:** This likely generates machine instructions or adds them to a list.
* **`FlagsContinuation`:**  This seems related to handling conditional branching and flags in machine code.
* **WebAssembly Specific Code:** The presence of `#if V8_ENABLE_WEBASSEMBLY` blocks indicates some logic is specific to WebAssembly compilation.
* **Turbofan and Turboshaft:** The code branches based on `Adapter::IsTurboshaft`, suggesting support for two different V8 compiler pipelines (Turbofan and the newer Turboshaft).
* **Source Position Handling:**  Functions like `UpdateSourcePosition` and `IsSourcePositionUsed` indicate a mechanism for tracking the original source code location of generated instructions.
* **Effect Levels:** The code tracks an "effect level," likely related to the order of operations and side effects.
* **Call Handling:**  Functions related to `VisitCall` and `VisitTailCall` deal with generating code for function calls.
* **Switch Statement Handling:** `VisitSwitch`, `EmitTableSwitch`, and `EmitBinarySearchSwitch` handle different ways of implementing switch statements in machine code.
* **Atomic Operations:**  Code dealing with `Word32Atomic...` and `Word64Atomic...` indicates support for atomic operations.
* **Deoptimization:** `VisitDeoptimizeIf` and `VisitDeoptimizeUnless` are about generating code for deoptimizing the compiled code.
* **Constants and Parameters:** Methods for handling constants and function parameters.
* **Phi Functions:** `VisitPhi` handles Phi functions, which are used in Static Single Assignment (SSA) form.

**High-Level Functionality Deduction:**

This part of the `InstructionSelector` is responsible for iterating through a block of code in an intermediate representation (either Turbofan's or Turboshaft's) and generating low-level machine instructions. It handles various language constructs, including arithmetic operations, memory access, control flow (branches, calls, returns, switches), and special V8 features like deoptimization and WebAssembly support. The template design allows the same instruction selection logic to be used with different underlying representations and target architectures.
这是 `v8/src/compiler/backend/instruction-selector.cc` 源代码文件的第二部分，主要负责以下功能：

**1. 指令选择的核心循环和块处理:**

* **`VisitBlock(block_t block)`:**  这是处理代码块的核心函数。它负责：
    * 初始化当前处理的代码块。
    * 计算块内指令的副作用级别 (`effect_level`)，用于保证指令执行顺序的正确性。
    * 遍历块内的节点，按照逆序执行 `VisitNode` 为每个节点生成相应的机器指令。
    * 调用 `VisitControl` 处理块的控制流指令（例如跳转、返回、分支等）。
    * 将生成的指令添加到当前代码块的指令序列中。
    * 处理空块，插入 `kArchNop` 指令。
    * 设置代码块的起始和结束指令索引。

**2. 源位置信息处理:**

* **`UpdateSourcePosition(Instruction* instruction, node_t node)`:**  为生成的机器指令设置对应的源代码位置信息，这对于调试和错误报告非常重要。这个函数在 Turboshaft 编译管道中被使用。
* **`IsSourcePositionUsed(node_t node)`:**  判断某个节点是否需要记录源代码位置信息。这通常用于可能触发异常或需要精细调试的指令，例如函数调用、内存访问、原子操作等。

**3. 控制流指令处理:**

* **`VisitGoto(block_t target)`:** 生成无条件跳转指令。
* **`VisitBranch(node_t branch_node, block_t tbranch, block_t fbranch)`:** 生成条件分支指令，根据条件跳转到不同的目标块。
* **`VisitReturn(node_t node)`:** 生成函数返回指令。
* **`VisitTailCall(node_t node)`:** 生成尾调用指令，这是一种优化技术，可以避免不必要的栈帧开销。
* **`VisitSwitch(node_t node, const SwitchInfo& sw)`:** 处理 `switch` 语句，根据不同的 `case` 值生成跳转指令。它提供了两种实现方式：`EmitTableSwitch` (适用于 `case` 值连续的情况) 和 `EmitBinarySearchSwitch` (适用于 `case` 值不连续的情况)。

**4. 函数调用处理:**

* **`VisitCall(node_t node, block_t handler)`:** 生成函数调用指令。它会处理调用约定、参数传递、异常处理等。
* **`VisitIfException(node_t node)`:**  处理异常处理逻辑，在调用可能抛出异常的函数后执行。

**5. Deoptimization 处理:**

* **`VisitDeoptimizeIf(node_t node)` 和 `VisitDeoptimizeUnless(node_t node)`:** 生成条件反优化指令。当某些假设不成立时，会触发反优化，回到解释器执行。
* **`VisitDeoptimize(DeoptimizeReason reason, id_t node_id, FeedbackSource const& feedback, node_t frame_state)`:** 生成无条件反优化指令。

**6. 常量和参数处理:**

* **`VisitConstant(node_t node)`:**  处理常量值。
* **`VisitParameter(node_t node)`:** 处理函数参数。
* **`VisitOsrValue(node_t node)`:** 处理 On-Stack Replacement (OSR) 的值。

**7. 其他节点处理:**

* **`VisitPhi(node_t node)`:** 处理 Phi 节点，用于合并来自不同控制流路径的值。
* **`VisitProjection(node_t node)`:** 处理 Projection 节点，用于提取多返回值操作的单个返回值。
* **`VisitBitcastTaggedToWord(node_t node)` 和 `VisitBitcastWordToTagged(node_t node)`:** 处理类型转换操作。
* **`VisitStackPointerGreaterThan(node_t node)`:** 比较栈指针。
* **`VisitLoadStackCheckOffset(node_t node)`、`VisitLoadFramePointer(node_t node)`、`VisitLoadParentFramePointer(node_t node)`:** 加载与栈帧相关的指针。
* **`VisitComment(node_t node)`:**  插入注释指令，用于调试和代码理解。
* **`VisitRetain(node_t node)`:**  用于控制垃圾回收。
* 还有一系列 `VisitFloat64...` 的方法，用于处理 `float64` 类型的数学运算。

**与 JavaScript 的关系及示例:**

此部分代码是 V8 引擎在将 JavaScript 代码编译成机器码过程中的一个关键步骤。它接收由前端（Parser 和 Compiler）生成的中间表示，并将其转换为特定架构的机器指令。

**JavaScript 示例（与 `VisitCall` 相关）:**

```javascript
function add(a, b) {
  return a + b;
}

function main() {
  let result = add(5, 10);
  console.log(result);
}

main();
```

当 V8 编译 `main` 函数时，遇到 `add(5, 10)` 这个函数调用时，`InstructionSelector` 的 `VisitCall` 方法就会被调用。它会：

1. **识别被调用函数:**  识别出 `add` 函数。
2. **准备参数:** 将参数 `5` 和 `10` 准备好，并根据调用约定放到寄存器或栈上。
3. **生成调用指令:** 生成一条机器指令来跳转到 `add` 函数的入口地址。 这条指令会涉及到目标地址的计算（可能是直接地址或间接地址）。
4. **处理返回值:**  在 `add` 函数返回后，生成指令来获取返回值并将其存储到变量 `result` 中。

**JavaScript 示例（与 `VisitBranch` 相关）:**

```javascript
function isPositive(num) {
  if (num > 0) {
    console.log("Positive");
  } else {
    console.log("Not positive");
  }
}

isPositive(-5);
```

当编译 `isPositive` 函数时，`if (num > 0)` 这个条件判断会触发 `InstructionSelector` 的 `VisitBranch` 方法。它会：

1. **生成比较指令:** 生成一条机器指令来比较 `num` 和 `0`。
2. **生成条件跳转指令:** 根据比较的结果（大于 0），生成一条条件跳转指令。如果条件成立，就跳转到打印 "Positive" 的代码块；否则，跳转到打印 "Not positive" 的代码块。

**总结:**

这部分 `InstructionSelector` 的代码是 V8 代码生成器的核心，负责将高级的中间表示转换为底层的机器指令，从而实现 JavaScript 代码的执行。它处理了各种不同的 JavaScript 语法结构和运行时特性，是连接 JavaScript 语义和机器码执行的关键桥梁。 它通过模板化的设计支持不同的编译器管道和目标架构。

### 提示词
```
这是目录为v8/src/compiler/backend/instruction-selector.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共4部分，请归纳一下它的功能
```

### 源代码
```
ion::ForSavedCallerReturnAddress();
    InstructionOperand return_address =
        g.UsePointerLocation(LinkageLocation::ConvertToTailCallerLocation(
                                 saved_return_location, stack_param_delta),
                             saved_return_location);
    buffer->instruction_args.push_back(return_address);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::UpdateSourcePosition(
    Instruction* instruction, node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    sequence()->SetSourcePosition(instruction, (*source_positions_)[node]);
  } else {
    UNREACHABLE();
  }
}

template <typename Adapter>
bool InstructionSelectorT<Adapter>::IsSourcePositionUsed(node_t node) {
  if (source_position_mode_ == InstructionSelector::kAllSourcePositions) {
    return true;
  }
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const Operation& operation = this->Get(node);
    // DidntThrow is where the actual call is generated.
    if (operation.Is<DidntThrowOp>()) return true;
    if (const LoadOp* load = operation.TryCast<LoadOp>()) {
      return load->kind.with_trap_handler;
    }
    if (const StoreOp* store = operation.TryCast<StoreOp>()) {
      return store->kind.with_trap_handler;
    }
#if V8_ENABLE_WEBASSEMBLY
    if (operation.Is<TrapIfOp>()) return true;
    if (const AtomicRMWOp* rmw = operation.TryCast<AtomicRMWOp>()) {
      return rmw->memory_access_kind ==
             MemoryAccessKind::kProtectedByTrapHandler;
    }
    if (const Simd128LoadTransformOp* lt =
            operation.TryCast<Simd128LoadTransformOp>()) {
      return lt->load_kind.with_trap_handler;
    }
#if V8_ENABLE_WASM_SIMD256_REVEC
    if (const Simd256LoadTransformOp* lt =
            operation.TryCast<Simd256LoadTransformOp>()) {
      return lt->load_kind.with_trap_handler;
    }
#endif  // V8_ENABLE_WASM_SIMD256_REVEC
    if (const Simd128LaneMemoryOp* lm =
            operation.TryCast<Simd128LaneMemoryOp>()) {
      return lm->kind.with_trap_handler;
    }
#endif
    if (additional_protected_instructions_->Contains(this->id(node))) {
      return true;
    }
    return false;
  } else {
    switch (node->opcode()) {
      case IrOpcode::kCall:
      case IrOpcode::kTrapIf:
      case IrOpcode::kTrapUnless:
      case IrOpcode::kProtectedLoad:
      case IrOpcode::kProtectedStore:
      case IrOpcode::kLoadTrapOnNull:
      case IrOpcode::kStoreTrapOnNull:
#if V8_ENABLE_WEBASSEMBLY
      case IrOpcode::kLoadTransform:
      case IrOpcode::kLoadLane:
      case IrOpcode::kStoreLane:
#endif  // V8_ENABLE_WEBASSEMBLY
      case IrOpcode::kLoad:
      case IrOpcode::kStore:
      case IrOpcode::kWord32AtomicLoad:
      case IrOpcode::kWord32AtomicStore:
      case IrOpcode::kWord32AtomicAdd:
      case IrOpcode::kWord32AtomicSub:
      case IrOpcode::kWord32AtomicAnd:
      case IrOpcode::kWord32AtomicOr:
      case IrOpcode::kWord32AtomicXor:
      case IrOpcode::kWord32AtomicExchange:
      case IrOpcode::kWord32AtomicCompareExchange:
      case IrOpcode::kWord64AtomicLoad:
      case IrOpcode::kWord64AtomicStore:
      case IrOpcode::kWord64AtomicAdd:
      case IrOpcode::kWord64AtomicSub:
      case IrOpcode::kWord64AtomicAnd:
      case IrOpcode::kWord64AtomicOr:
      case IrOpcode::kWord64AtomicXor:
      case IrOpcode::kWord64AtomicExchange:
      case IrOpcode::kWord64AtomicCompareExchange:
      case IrOpcode::kUnalignedLoad:
      case IrOpcode::kUnalignedStore:
        return true;
      default:
        return false;
    }
  }
}

namespace {
bool increment_effect_level_for_node(TurbofanAdapter* adapter, Node* node) {
  const IrOpcode::Value opcode = node->opcode();
  return opcode == IrOpcode::kStore || opcode == IrOpcode::kUnalignedStore ||
         opcode == IrOpcode::kCall || opcode == IrOpcode::kProtectedStore ||
         opcode == IrOpcode::kStoreTrapOnNull ||
#if V8_ENABLE_WEBASSEMBLY
         opcode == IrOpcode::kStoreLane ||
#endif
         opcode == IrOpcode::kStorePair ||
         opcode == IrOpcode::kStoreIndirectPointer ||
#define ADD_EFFECT_FOR_ATOMIC_OP(Opcode) opcode == IrOpcode::k##Opcode ||
         MACHINE_ATOMIC_OP_LIST(ADD_EFFECT_FOR_ATOMIC_OP)
#undef ADD_EFFECT_FOR_ATOMIC_OP
                 opcode == IrOpcode::kMemoryBarrier;
}

bool increment_effect_level_for_node(TurboshaftAdapter* adapter,
                                     turboshaft::OpIndex node) {
  // We need to increment the effect level if the operation consumes any of the
  // dimensions of the {kTurboshaftEffectLevelMask}.
  const turboshaft::Operation& op = adapter->Get(node);
  if (op.Is<turboshaft::RetainOp>()) {
    // Retain has CanWrite effect so that it's not reordered before the last
    // read it protects, but it shouldn't increment the effect level, since
    // doing a Load(x) after a Retain(x) is safe as long as there is not call
    // (or something that can trigger GC) in between Retain(x) and Load(x), and
    // if there were, then this call would increment the effect level, which
    // would prevent covering in the ISEL.
    return false;
  }
  return (op.Effects().consumes.bits() & kTurboshaftEffectLevelMask.bits()) !=
         0;
}
}  // namespace

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitBlock(block_t block) {
  DCHECK(!current_block_);
  current_block_ = block;
  auto current_num_instructions = [&] {
    DCHECK_GE(kMaxInt, instructions_.size());
    return static_cast<int>(instructions_.size());
  };
  int current_block_end = current_num_instructions();

  int effect_level = 0;
  for (node_t node : this->nodes(block)) {
    SetEffectLevel(node, effect_level);
    if (increment_effect_level_for_node(this, node)) {
      ++effect_level;
    }
  }

  // We visit the control first, then the nodes in the block, so the block's
  // control input should be on the same effect level as the last node.
  if (node_t terminator = this->block_terminator(block);
      this->valid(terminator)) {
    SetEffectLevel(terminator, effect_level);
    current_effect_level_ = effect_level;
  }

  auto FinishEmittedInstructions = [&](node_t node, int instruction_start) {
    if (instruction_selection_failed()) return false;
    if (current_num_instructions() == instruction_start) return true;
    std::reverse(instructions_.begin() + instruction_start,
                 instructions_.end());
    if (!this->valid(node)) return true;
    if (!source_positions_) return true;

    SourcePosition source_position;
    if constexpr (Adapter::IsTurboshaft) {
#if V8_ENABLE_WEBASSEMBLY && V8_TARGET_ARCH_X64
      if (V8_UNLIKELY(
              this->Get(node)
                  .template Is<
                      turboshaft::Opmask::kSimd128F64x2PromoteLowF32x4>())) {
        // On x64 there exists an optimization that folds
        // `kF64x2PromoteLowF32x4` and `kS128Load64Zero` together into a single
        // instruction. If the instruction causes an out-of-bounds memory
        // access exception, then the stack trace has to show the source
        // position of the `kS128Load64Zero` and not of the
        // `kF64x2PromoteLowF32x4`.
        if (this->CanOptimizeF64x2PromoteLowF32x4(node)) {
          node = this->input_at(node, 0);
        }
      }
#endif  // V8_ENABLE_WEBASSEMBLY && V8_TARGET_ARCH_X64
      source_position = (*source_positions_)[node];
    } else {
#if V8_ENABLE_WEBASSEMBLY && V8_TARGET_ARCH_X64
      if (V8_UNLIKELY(node->opcode() == IrOpcode::kF64x2PromoteLowF32x4)) {
        // On x64 there exists an optimization that folds
        // `kF64x2PromoteLowF32x4` and `kS128Load64Zero` together into a single
        // instruction. If the instruction causes an out-of-bounds memory
        // access exception, then the stack trace has to show the source
        // position of the `kS128Load64Zero` and not of the
        // `kF64x2PromoteLowF32x4`.
        node_t input = node->InputAt(0);
        LoadTransformMatcher m(input);

        if (m.Is(LoadTransformation::kS128Load64Zero) &&
            CanCover(node, input)) {
          node = input;
        }
      }
#endif  // V8_ENABLE_WEBASSEMBLY && V8_TARGET_ARCH_X64
      source_position = source_positions_->GetSourcePosition(node);
    }
    if (source_position.IsKnown() && IsSourcePositionUsed(node)) {
      sequence()->SetSourcePosition(instructions_.back(), source_position);
    }
    return true;
  };

  // Generate code for the block control "top down", but schedule the code
  // "bottom up".
  VisitControl(block);
  if (!FinishEmittedInstructions(this->block_terminator(block),
                                 current_block_end)) {
    return;
  }

  // Visit code in reverse control flow order, because architecture-specific
  // matching may cover more than one node at a time.
  for (node_t node : base::Reversed(this->nodes(block))) {
    int current_node_end = current_num_instructions();

    if constexpr (Adapter::IsTurboshaft) {
      if (protected_loads_to_remove_->Contains(this->id(node)) &&
          !IsReallyUsed(node)) {
        MarkAsDefined(node);
      }
    }

    if (!IsUsed(node)) {
      // Skip nodes that are unused, while marking them as Defined so that it's
      // clear that these unused nodes have been visited and will not be Defined
      // later.
      MarkAsDefined(node);
    } else if (!IsDefined(node)) {
      // Generate code for this node "top down", but schedule the code "bottom
      // up".
      current_effect_level_ = GetEffectLevel(node);
      VisitNode(node);
      if (!FinishEmittedInstructions(node, current_node_end)) return;
    }
    if (trace_turbo_ == InstructionSelector::kEnableTraceTurboJson) {
      instr_origins_[this->id(node)] = {current_num_instructions(),
                                        current_node_end};
    }
  }

  // We're done with the block.
  InstructionBlock* instruction_block =
      sequence()->InstructionBlockAt(this->rpo_number(block));
  if (current_num_instructions() == current_block_end) {
    // Avoid empty block: insert a {kArchNop} instruction.
    Emit(Instruction::New(sequence()->zone(), kArchNop));
  }
  instruction_block->set_code_start(current_num_instructions());
  instruction_block->set_code_end(current_block_end);
  current_block_ = nullptr;
}

template <typename Adapter>
FlagsCondition InstructionSelectorT<Adapter>::GetComparisonFlagCondition(
    const turboshaft::ComparisonOp& op) const {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  switch (op.kind) {
    case ComparisonOp::Kind::kEqual:
      return kEqual;
    case ComparisonOp::Kind::kSignedLessThan:
      return kSignedLessThan;
    case ComparisonOp::Kind::kSignedLessThanOrEqual:
      return kSignedLessThanOrEqual;
    case ComparisonOp::Kind::kUnsignedLessThan:
      return kUnsignedLessThan;
    case ComparisonOp::Kind::kUnsignedLessThanOrEqual:
      return kUnsignedLessThanOrEqual;
  }
}

template <>
FlagsCondition
InstructionSelectorT<TurbofanAdapter>::GetComparisonFlagCondition(
    const turboshaft::ComparisonOp& op) const {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::MarkPairProjectionsAsWord32(node_t node) {
  node_t projection0 = FindProjection(node, 0);
  if (Adapter::valid(projection0)) {
    MarkAsWord32(projection0);
  }
  node_t projection1 = FindProjection(node, 1);
  if (Adapter::valid(projection1)) {
    MarkAsWord32(projection1);
  }
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::ConsumeEqualZero(
    turboshaft::OpIndex* user, turboshaft::OpIndex* value,
    FlagsContinuation* cont) {
  // Try to combine with comparisons against 0 by simply inverting the branch.
  using namespace turboshaft;  // NOLINT(build/namespaces)
  while (const ComparisonOp* equal =
             TryCast<Opmask::kComparisonEqual>(*value)) {
    if (equal->rep == RegisterRepresentation::Word32()) {
      if (!MatchIntegralZero(equal->right())) return;
#ifdef V8_COMPRESS_POINTERS
    } else if (equal->rep == RegisterRepresentation::Tagged()) {
      static_assert(RegisterRepresentation::Tagged().MapTaggedToWord() ==
                    RegisterRepresentation::Word32());
      if (!MatchSmiZero(equal->right())) return;
#endif  // V8_COMPRESS_POINTERS
    } else {
      return;
    }
    if (!CanCover(*user, *value)) return;

    *user = *value;
    *value = equal->left();
    cont->Negate();
  }
}

#if V8_ENABLE_WEBASSEMBLY
template <>
void InstructionSelectorT<TurbofanAdapter>::VisitI8x16RelaxedSwizzle(
    node_t node) {
  UNREACHABLE();
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitI8x16RelaxedSwizzle(
    node_t node) {
  return VisitI8x16Swizzle(node);
}
#endif  // V8_ENABLE_WEBASSEMBLY

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitStackPointerGreaterThan(node_t node) {
  FlagsContinuation cont =
      FlagsContinuation::ForSet(kStackPointerGreaterThanCondition, node);
  VisitStackPointerGreaterThan(node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitLoadStackCheckOffset(node_t node) {
  OperandGenerator g(this);
  Emit(kArchStackCheckOffset, g.DefineAsRegister(node));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitLoadFramePointer(node_t node) {
  OperandGenerator g(this);
  Emit(kArchFramePointer, g.DefineAsRegister(node));
}

#if V8_ENABLE_WEBASSEMBLY
template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitLoadStackPointer(node_t node) {
  OperandGenerator g(this);
  Emit(kArchStackPointer, g.DefineAsRegister(node));
}
#endif  // V8_ENABLE_WEBASSEMBLY

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitLoadParentFramePointer(node_t node) {
  OperandGenerator g(this);
  Emit(kArchParentFramePointer, g.DefineAsRegister(node));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitLoadRootRegister(node_t node) {
  // Do nothing. Following loads/stores from this operator will use kMode_Root
  // to load/store from an offset of the root register.
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Acos(node_t node) {
  VisitFloat64Ieee754Unop(node, kIeee754Float64Acos);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Acosh(node_t node) {
  VisitFloat64Ieee754Unop(node, kIeee754Float64Acosh);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Asin(node_t node) {
  VisitFloat64Ieee754Unop(node, kIeee754Float64Asin);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Asinh(node_t node) {
  VisitFloat64Ieee754Unop(node, kIeee754Float64Asinh);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Atan(node_t node) {
  VisitFloat64Ieee754Unop(node, kIeee754Float64Atan);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Atanh(node_t node) {
  VisitFloat64Ieee754Unop(node, kIeee754Float64Atanh);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Atan2(node_t node) {
  VisitFloat64Ieee754Binop(node, kIeee754Float64Atan2);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Cbrt(node_t node) {
  VisitFloat64Ieee754Unop(node, kIeee754Float64Cbrt);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Cos(node_t node) {
  VisitFloat64Ieee754Unop(node, kIeee754Float64Cos);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Cosh(node_t node) {
  VisitFloat64Ieee754Unop(node, kIeee754Float64Cosh);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Exp(node_t node) {
  VisitFloat64Ieee754Unop(node, kIeee754Float64Exp);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Expm1(node_t node) {
  VisitFloat64Ieee754Unop(node, kIeee754Float64Expm1);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Log(node_t node) {
  VisitFloat64Ieee754Unop(node, kIeee754Float64Log);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Log1p(node_t node) {
  VisitFloat64Ieee754Unop(node, kIeee754Float64Log1p);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Log2(node_t node) {
  VisitFloat64Ieee754Unop(node, kIeee754Float64Log2);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Log10(node_t node) {
  VisitFloat64Ieee754Unop(node, kIeee754Float64Log10);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Pow(node_t node) {
  VisitFloat64Ieee754Binop(node, kIeee754Float64Pow);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Sin(node_t node) {
  VisitFloat64Ieee754Unop(node, kIeee754Float64Sin);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Sinh(node_t node) {
  VisitFloat64Ieee754Unop(node, kIeee754Float64Sinh);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Tan(node_t node) {
  VisitFloat64Ieee754Unop(node, kIeee754Float64Tan);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Tanh(node_t node) {
  VisitFloat64Ieee754Unop(node, kIeee754Float64Tanh);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::EmitTableSwitch(
    const SwitchInfo& sw, InstructionOperand const& index_operand) {
  OperandGenerator g(this);
  size_t input_count = 2 + sw.value_range();
  DCHECK_LE(sw.value_range(), std::numeric_limits<size_t>::max() - 2);
  auto* inputs =
      zone()->template AllocateArray<InstructionOperand>(input_count);
  inputs[0] = index_operand;
  InstructionOperand default_operand = g.Label(sw.default_branch());
  std::fill(&inputs[1], &inputs[input_count], default_operand);
  for (const CaseInfo& c : sw.CasesUnsorted()) {
    size_t value = c.value - sw.min_value();
    DCHECK_LE(0u, value);
    DCHECK_LT(value + 2, input_count);
    inputs[value + 2] = g.Label(c.branch);
  }
  Emit(kArchTableSwitch, 0, nullptr, input_count, inputs, 0, nullptr);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::EmitBinarySearchSwitch(
    const SwitchInfo& sw, InstructionOperand const& value_operand) {
  OperandGenerator g(this);
  size_t input_count = 2 + sw.case_count() * 2;
  DCHECK_LE(sw.case_count(), (std::numeric_limits<size_t>::max() - 2) / 2);
  auto* inputs =
      zone()->template AllocateArray<InstructionOperand>(input_count);
  inputs[0] = value_operand;
  inputs[1] = g.Label(sw.default_branch());
  std::vector<CaseInfo> cases = sw.CasesSortedByValue();
  for (size_t index = 0; index < cases.size(); ++index) {
    const CaseInfo& c = cases[index];
    inputs[index * 2 + 2 + 0] = g.TempImmediate(c.value);
    inputs[index * 2 + 2 + 1] = g.Label(c.branch);
  }
  Emit(kArchBinarySearchSwitch, 0, nullptr, input_count, inputs, 0, nullptr);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitBitcastTaggedToWord(node_t node) {
  EmitIdentity(node);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitBitcastWordToTagged(
    node_t node) {
  OperandGenerator g(this);
  Emit(kArchNop, g.DefineSameAsFirst(node), g.Use(node->InputAt(0)));
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitBitcastWordToTagged(
    node_t node) {
  OperandGenerator g(this);
  Emit(kArchNop, g.DefineSameAsFirst(node),
       g.Use(this->Get(node).Cast<turboshaft::TaggedBitcastOp>().input()));
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitBitcastSmiToWord(
    node_t node) {
  // TODO(dmercadier): using EmitIdentity here is not ideal, because users of
  // {node} will then use its input, which may not have the Word32
  // representation. This might in turn lead to the register allocator wrongly
  // tracking Tagged values that are in fact just Smis. However, using
  // Emit(kArchNop) hurts performance because it inserts a gap move which cannot
  // always be eliminated because the operands may have different sizes (and the
  // move is then truncating or extending). As a temporary work-around until the
  // register allocator is fixed, we use Emit(kArchNop) in DEBUG mode to silence
  // the register allocator verifier.
#ifdef DEBUG
  OperandGenerator g(this);
  Emit(kArchNop, g.DefineSameAsFirst(node),
       g.Use(this->Get(node).Cast<turboshaft::TaggedBitcastOp>().input()));
#else
  EmitIdentity(node);
#endif
}

// 32 bit targets do not implement the following instructions.
#if V8_TARGET_ARCH_32_BIT

VISIT_UNSUPPORTED_OP(Word64And)
VISIT_UNSUPPORTED_OP(Word64Or)
VISIT_UNSUPPORTED_OP(Word64Xor)
VISIT_UNSUPPORTED_OP(Word64Shl)
VISIT_UNSUPPORTED_OP(Word64Shr)
VISIT_UNSUPPORTED_OP(Word64Sar)
VISIT_UNSUPPORTED_OP(Word64Rol)
VISIT_UNSUPPORTED_OP(Word64Ror)
VISIT_UNSUPPORTED_OP(Word64Clz)
VISIT_UNSUPPORTED_OP(Word64Ctz)
VISIT_UNSUPPORTED_OP(Word64ReverseBits)
VISIT_UNSUPPORTED_OP(Word64Popcnt)
VISIT_UNSUPPORTED_OP(Word64Equal)
VISIT_UNSUPPORTED_OP(Int64Add)
VISIT_UNSUPPORTED_OP(Int64Sub)
VISIT_UNSUPPORTED_OP(Int64Mul)
VISIT_UNSUPPORTED_OP(Int64MulHigh)
VISIT_UNSUPPORTED_OP(Uint64MulHigh)
VISIT_UNSUPPORTED_OP(Int64Div)
VISIT_UNSUPPORTED_OP(Int64Mod)
VISIT_UNSUPPORTED_OP(Uint64Div)
VISIT_UNSUPPORTED_OP(Uint64Mod)
VISIT_UNSUPPORTED_OP(Int64AddWithOverflow)
VISIT_UNSUPPORTED_OP(Int64MulWithOverflow)
VISIT_UNSUPPORTED_OP(Int64SubWithOverflow)
VISIT_UNSUPPORTED_OP(Int64LessThan)
VISIT_UNSUPPORTED_OP(Int64LessThanOrEqual)
VISIT_UNSUPPORTED_OP(Uint64LessThan)
VISIT_UNSUPPORTED_OP(Uint64LessThanOrEqual)
VISIT_UNSUPPORTED_OP(BitcastWord32ToWord64)
VISIT_UNSUPPORTED_OP(ChangeInt32ToInt64)
VISIT_UNSUPPORTED_OP(ChangeInt64ToFloat64)
VISIT_UNSUPPORTED_OP(ChangeUint32ToUint64)
VISIT_UNSUPPORTED_OP(ChangeFloat64ToInt64)
VISIT_UNSUPPORTED_OP(ChangeFloat64ToUint64)
VISIT_UNSUPPORTED_OP(TruncateFloat64ToInt64)
VISIT_UNSUPPORTED_OP(TruncateInt64ToInt32)
VISIT_UNSUPPORTED_OP(TryTruncateFloat32ToInt64)
VISIT_UNSUPPORTED_OP(TryTruncateFloat64ToInt64)
VISIT_UNSUPPORTED_OP(TryTruncateFloat32ToUint64)
VISIT_UNSUPPORTED_OP(TryTruncateFloat64ToUint64)
VISIT_UNSUPPORTED_OP(TryTruncateFloat64ToInt32)
VISIT_UNSUPPORTED_OP(TryTruncateFloat64ToUint32)
VISIT_UNSUPPORTED_OP(RoundInt64ToFloat32)
VISIT_UNSUPPORTED_OP(RoundInt64ToFloat64)
VISIT_UNSUPPORTED_OP(RoundUint64ToFloat32)
VISIT_UNSUPPORTED_OP(RoundUint64ToFloat64)
VISIT_UNSUPPORTED_OP(BitcastFloat64ToInt64)
VISIT_UNSUPPORTED_OP(BitcastInt64ToFloat64)
VISIT_UNSUPPORTED_OP(SignExtendWord8ToInt64)
VISIT_UNSUPPORTED_OP(SignExtendWord16ToInt64)
VISIT_UNSUPPORTED_OP(SignExtendWord32ToInt64)
#endif  // V8_TARGET_ARCH_32_BIT

// 64 bit targets do not implement the following instructions.
#if V8_TARGET_ARCH_64_BIT
VISIT_UNSUPPORTED_OP(Int32PairAdd)
VISIT_UNSUPPORTED_OP(Int32PairSub)
VISIT_UNSUPPORTED_OP(Int32PairMul)
VISIT_UNSUPPORTED_OP(Word32PairShl)
VISIT_UNSUPPORTED_OP(Word32PairShr)
VISIT_UNSUPPORTED_OP(Word32PairSar)
#endif  // V8_TARGET_ARCH_64_BIT

#if !V8_TARGET_ARCH_IA32 && !V8_TARGET_ARCH_ARM && !V8_TARGET_ARCH_RISCV32
template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicPairLoad(node_t node) {
  UNIMPLEMENTED();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicPairStore(node_t node) {
  UNIMPLEMENTED();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicPairAdd(node_t node) {
  UNIMPLEMENTED();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicPairSub(node_t node) {
  UNIMPLEMENTED();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicPairAnd(node_t node) {
  UNIMPLEMENTED();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicPairOr(node_t node) {
  UNIMPLEMENTED();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicPairXor(node_t node) {
  UNIMPLEMENTED();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicPairExchange(node_t node) {
  UNIMPLEMENTED();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicPairCompareExchange(
    node_t node) {
  UNIMPLEMENTED();
}
#endif  // !V8_TARGET_ARCH_IA32 && !V8_TARGET_ARCH_ARM
        // && !V8_TARGET_ARCH_RISCV32

#if !V8_TARGET_ARCH_X64 && !V8_TARGET_ARCH_ARM64 && !V8_TARGET_ARCH_MIPS64 && \
    !V8_TARGET_ARCH_S390X && !V8_TARGET_ARCH_PPC64 &&                         \
    !V8_TARGET_ARCH_RISCV64 && !V8_TARGET_ARCH_LOONG64

VISIT_UNSUPPORTED_OP(Word64AtomicLoad)
VISIT_UNSUPPORTED_OP(Word64AtomicStore)
VISIT_UNSUPPORTED_OP(Word64AtomicAdd)
VISIT_UNSUPPORTED_OP(Word64AtomicSub)
VISIT_UNSUPPORTED_OP(Word64AtomicAnd)
VISIT_UNSUPPORTED_OP(Word64AtomicOr)
VISIT_UNSUPPORTED_OP(Word64AtomicXor)
VISIT_UNSUPPORTED_OP(Word64AtomicExchange)
VISIT_UNSUPPORTED_OP(Word64AtomicCompareExchange)

#endif  // !V8_TARGET_ARCH_X64 && !V8_TARGET_ARCH_ARM64 && !V8_TARGET_ARCH_PPC64
        // !V8_TARGET_ARCH_MIPS64 && !V8_TARGET_ARCH_S390X &&
        // !V8_TARGET_ARCH_RISCV64 && !V8_TARGET_ARCH_LOONG64

#if !V8_TARGET_ARCH_IA32 && !V8_TARGET_ARCH_ARM && !V8_TARGET_ARCH_RISCV32
// This is only needed on 32-bit to split the 64-bit value into two operands.
IF_WASM(VISIT_UNSUPPORTED_OP, I64x2SplatI32Pair)
IF_WASM(VISIT_UNSUPPORTED_OP, I64x2ReplaceLaneI32Pair)
#endif  // !V8_TARGET_ARCH_IA32 && !V8_TARGET_ARCH_ARM &&
        // !V8_TARGET_ARCH_RISCV32

#if !V8_TARGET_ARCH_X64 && !V8_TARGET_ARCH_S390X && !V8_TARGET_ARCH_PPC64
#if !V8_TARGET_ARCH_ARM64
#if !V8_TARGET_ARCH_MIPS64 && !V8_TARGET_ARCH_LOONG64 && \
    !V8_TARGET_ARCH_RISCV32 && !V8_TARGET_ARCH_RISCV64

IF_WASM(VISIT_UNSUPPORTED_OP, I64x2Splat)
IF_WASM(VISIT_UNSUPPORTED_OP, I64x2ExtractLane)
IF_WASM(VISIT_UNSUPPORTED_OP, I64x2ReplaceLane)

#endif  // !V8_TARGET_ARCH_MIPS64 && !V8_TARGET_ARCH_LOONG64 &&
        // !V8_TARGET_ARCH_RISCV64 && !V8_TARGET_ARCH_RISCV32
#endif  // !V8_TARGET_ARCH_ARM64
#endif  // !V8_TARGET_ARCH_X64 && !V8_TARGET_ARCH_S390X && !V8_TARGET_ARCH_PPC64

#if !V8_TARGET_ARCH_ARM64

IF_WASM(VISIT_UNSUPPORTED_OP, I8x16AddReduce)
IF_WASM(VISIT_UNSUPPORTED_OP, I16x8AddReduce)
IF_WASM(VISIT_UNSUPPORTED_OP, I32x4AddReduce)
IF_WASM(VISIT_UNSUPPORTED_OP, I64x2AddReduce)
IF_WASM(VISIT_UNSUPPORTED_OP, F32x4AddReduce)
IF_WASM(VISIT_UNSUPPORTED_OP, F64x2AddReduce)

#endif  // !V8_TARGET_ARCH_ARM64

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitFinishRegion(Node* node) {
  EmitIdentity(node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitParameter(node_t node) {
  OperandGenerator g(this);
  int index = this->parameter_index_of(node);

  if (linkage()->GetParameterLocation(index).IsNullRegister()) {
    EmitMoveParamToFPR(node, index);
  } else {
    InstructionOperand op =
        linkage()->ParameterHasSecondaryLocation(index)
            ? g.DefineAsDualLocation(
                  node, linkage()->GetParameterLocation(index),
                  linkage()->GetParameterSecondaryLocation(index))
            : g.DefineAsLocation(node, linkage()->GetParameterLocation(index));
    Emit(kArchNop, op);
  }
}

namespace {

LinkageLocation ExceptionLocation() {
  return LinkageLocation::ForRegister(kReturnRegister0.code(),
                                      MachineType::TaggedPointer());
}

constexpr InstructionCode EncodeCallDescriptorFlags(
    InstructionCode opcode, CallDescriptor::Flags flags) {
  // Note: Not all bits of `flags` are preserved.
  static_assert(CallDescriptor::kFlagsBitsEncodedInInstructionCode ==
                MiscField::kSize);
  DCHECK(Instruction::IsCallWithDescriptorFlags(opcode));
  return opcode | MiscField::encode(flags & MiscField::kMax);
}

}  // namespace

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitIfException(node_t node) {
  OperandGenerator g(this);
  if constexpr (Adapter::IsTurbofan) {
    DCHECK_EQ(IrOpcode::kCall, node->InputAt(1)->opcode());
  }
  Emit(kArchNop, g.DefineAsLocation(node, ExceptionLocation()));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitOsrValue(node_t node) {
  OperandGenerator g(this);
  int index = this->osr_value_index_of(node);
  Emit(kArchNop,
       g.DefineAsLocation(node, linkage()->GetOsrValueLocation(index)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitPhi(node_t node) {
  const int input_count = this->value_input_count(node);
  DCHECK_EQ(input_count, this->PredecessorCount(current_block_));
  PhiInstruction* phi = instruction_zone()->template New<PhiInstruction>(
      instruction_zone(), GetVirtualRegister(node),
      static_cast<size_t>(input_count));
  sequence()->InstructionBlockAt(this->rpo_number(current_block_))->AddPhi(phi);
  for (int i = 0; i < input_count; ++i) {
    node_t input = this->input_at(node, i);
    MarkAsUsed(input);
    phi->SetInput(static_cast<size_t>(i), GetVirtualRegister(input));
  }
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitProjection(
    turboshaft::OpIndex node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  const ProjectionOp& projection = this->Get(node).Cast<ProjectionOp>();
  const Operation& value_op = this->Get(projection.input());
  if (value_op.Is<OverflowCheckedBinopOp>() ||
      value_op.Is<OverflowCheckedUnaryOp>() || value_op.Is<TryChangeOp>() ||
      value_op.Is<Word32PairBinopOp>()) {
    if (projection.index == 0u) {
      EmitIdentity(node);
    } else {
      DCHECK_EQ(1u, projection.index);
      MarkAsUsed(projection.input());
    }
  } else if (value_op.Is<DidntThrowOp>()) {
    // Nothing to do here?
  } else if (value_op.Is<CallOp>()) {
    // Call projections need to be behind the call's DidntThrow.
    UNREACHABLE();
  } else if (value_op.Is<AtomicWord32PairOp>()) {
    // Nothing to do here.
  } else {
    UNIMPLEMENTED();
  }
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitProjection(Node* node) {
  OperandGenerator g(this);
  Node* value = node->InputAt(0);
  switch (value->opcode()) {
    case IrOpcode::kInt32AddWithOverflow:
    case IrOpcode::kInt32SubWithOverflow:
    case IrOpcode::kInt32MulWithOverflow:
    case IrOpcode::kInt64AddWithOverflow:
    case IrOpcode::kInt64SubWithOverflow:
    case IrOpcode::kInt64MulWithOverflow:
    case IrOpcode::kTryTruncateFloat32ToInt64:
    case IrOpcode::kTryTruncateFloat64ToInt64:
    case IrOpcode::kTryTruncateFloat32ToUint64:
    case IrOpcode::kTryTruncateFloat64ToUint64:
    case IrOpcode::kTryTruncateFloat64ToInt32:
    case IrOpcode::kTryTruncateFloat64ToUint32:
    case IrOpcode::kInt32PairAdd:
    case IrOpcode::kInt32PairSub:
    case IrOpcode::kInt32PairMul:
    case IrOpcode::kWord32PairShl:
    case IrOpcode::kWord32PairShr:
    case IrOpcode::kWord32PairSar:
    case IrOpcode::kInt32AbsWithOverflow:
    case IrOpcode::kInt64AbsWithOverflow:
      if (ProjectionIndexOf(node->op()) == 0u) {
        EmitIdentity(node);
      } else {
        DCHECK_EQ(1u, ProjectionIndexOf(node->op()));
        MarkAsUsed(value);
      }
      break;
    case IrOpcode::kCall:
    case IrOpcode::kWord32AtomicPairLoad:
    case IrOpcode::kWord32AtomicPairExchange:
    case IrOpcode::kWord32AtomicPairCompareExchange:
    case IrOpcode::kWord32AtomicPairAdd:
    case IrOpcode::kWord32AtomicPairSub:
    case IrOpcode::kWord32AtomicPairAnd:
    case IrOpcode::kWord32AtomicPairOr:
    case IrOpcode::kWord32AtomicPairXor:
      // Nothing to do for these opcodes.
      break;
    default:
      UNREACHABLE();
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitConstant(node_t node) {
  // We must emit a NOP here because every live range needs a defining
  // instruction in the register allocator.
  OperandGenerator g(this);
  Emit(kArchNop, g.DefineAsConstant(node));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::UpdateMaxPushedArgumentCount(size_t count) {
  *max_pushed_argument_count_ = std::max(count, *max_pushed_argument_count_);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitCall(node_t node, block_t handler) {
  OperandGenerator g(this);
  auto call = this->call_view(node);
  const CallDescriptor* call_descriptor = call.call_descriptor();
  SaveFPRegsMode mode = call_descriptor->NeedsCallerSavedFPRegisters()
                            ? SaveFPRegsMode::kSave
                            : SaveFPRegsMode::kIgnore;

  if (call_descriptor->NeedsCallerSavedRegisters()) {
    Emit(kArchSaveCallerRegisters | MiscField::encode(static_cast<int>(mode)),
         g.NoOutput());
  }

  FrameStateDescriptor* frame_state_descriptor = nullptr;
  bool needs_frame_state = false;
  if (call_descriptor->NeedsFrameState()) {
    needs_frame_state = true;
    frame_state_descriptor = GetFrameStateDescriptor(call.frame_state());
  }

  CallBuffer buffer(zone(), call_descriptor, frame_state_descriptor);
  CallDescriptor::Flags flags = call_descriptor->flags();

  // Compute InstructionOperands for inputs and outputs.
  // TODO(turbofan): on some architectures it's probably better to use
  // the code object in a register if there are multiple uses of it.
  // Improve constant pool and the heuristics in the register allocator
  // for where to emit constants.
  CallBufferFlags call_buffer_flags(kCallCodeImmediate | kCallAddressImmediate);
  if (flags & CallDescriptor::kFixedTargetRegister) {
    call_buffer_flags |= kCallFixedTargetRegister;
  }
  InitializeCallBuffer(node, &buffer, call_buffer_flags);

  EmitPrepareArguments(&buffer.pushed_nodes, call_descriptor, node);
  UpdateMaxPushedArgumentCount(buffer.pushed_nodes.size());

  if (call_descriptor->RequiresEntrypointTagForCall()) {
    DCHECK(!call_descriptor->IsJSFunctionCall());
    buffer.instruction_args.push_back(
        g.TempImmediate(call_descriptor->shifted_tag()));
  } else if (call_descriptor->IsJSFunctionCall()) {
    // For JSFunctions we need to know the number of pushed parameters during
    // code generation.
    uint32_t parameter_count =
        static_cast<uint32_t>(buffer.pushed_nodes.size());
    buffer.instruction_args.push_back(g.TempImmediate(parameter_count));
  }

  // Pass label of exception handler block.
  if (handler) {
    if constexpr (Adapter::IsTurbofan) {
      DCHECK_EQ(IrOpcode::kIfException, handler->front()->opcode());
    }
    flags |= CallDescriptor::kHasExceptionHandler;
    buffer.instruction_args.push_back(g.Label(handler));
  } else {
    if constexpr (Adapter::IsTurboshaft) {
      if (call.ts_call_descriptor()->lazy_deopt_on_throw ==
          LazyDeoptOnThrow::kYes) {
        flags |= CallDescriptor::kHasExceptionHandler;
        buffer.instruction_args.push_back(
            g.UseImmediate(kLazyDeoptOnThrowSentinel));
      }
    }
  }

  // Select the appropriate opcode based on the call type.
  InstructionCode opcode;
  switch (call_descriptor->kind()) {
    case CallDescriptor::kCallAddress: {
      int gp_param_count =
          static_cast<int>(call_descriptor->GPParameterCount());
      int fp_param_count =
          static_cast<int>(call_descriptor->FPParameterCount());
#if ABI_USES_FUNCTION_DESCRIPTORS
      // Highest fp_param_count bit is used on AIX to indicate if a CFunction
      // call has function descriptor or not.
      static_assert(FPParamField::kSize == kHasFunctionDescriptorBitShift + 1);
      if (!call_descriptor->NoFunctionDescriptor()) {
        fp_param_count |= 1 << kHasFunctionDescriptorBitShift;
      }
#endif
      opcode = needs_frame_state ? kArchCallCFunctionWithFrameState
                                 : kArchCallCFunction;
      opcode |= ParamField::encode(gp_param_count) |
                FPParamField::encode(fp_param_count);
      break;
    }
    case CallDescriptor::kCallCodeObject:
      opcode = EncodeCallDescriptorFlags(kArchCallCodeObject, flags);
      break;
    case CallDescriptor::kCallJSFunction:
      opcode = EncodeCallDescriptorFlags(kArchCallJSFunction, flags);
      break;
#if V8_ENABLE_WEBASSEMBLY
    case CallDescriptor::kCallWasmCapiFunction:
    case CallDescriptor::kCallWasmFunction:
    case CallDescriptor::kCallWasmImportWrapper:
      opcode = EncodeCallDescriptorFlags(kArchCallWasmFunction, flags);
      break;
#endif  // V8_ENABLE_WEBASSEMBLY
    case CallDescriptor::kCallBuiltinPointer:
      opcode = EncodeCallDescriptorFlags(kArchCallBuiltinPointer, flags);
      break;
  }

  // Emit the call instruction.
  size_t const output_count = buffer.outputs.size();
  auto* outputs = output_count ? &buffer.outputs.front() : nullptr;
  Instruction* call_instr =
      Emit(opcode, output_count, outputs, buffer.instruction_args.size(),
           &buffer.instruction_args.front());
  if (instruction_selection_failed()) return;
  call_instr->MarkAsCall();

  EmitPrepareResults(&(buffer.output_nodes), call_descriptor, node);

  if (call_descriptor->NeedsCallerSavedRegisters()) {
    Emit(
        kArchRestoreCallerRegisters | MiscField::encode(static_cast<int>(mode)),
        g.NoOutput());
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTailCall(node_t node) {
  OperandGenerator g(this);

  auto call = this->call_view(node);
  auto caller = linkage()->GetIncomingDescriptor();
  auto callee = call.call_descriptor();
  DCHECK(caller->CanTailCall(callee));
  const int stack_param_delta = callee->GetStackParameterDelta(caller);
  CallBuffer buffer(zone(), callee, nullptr);

  // Compute InstructionOperands for inputs and outputs.
  CallBufferFlags flags(kCallCodeImmediate | kCallTail);
  if (IsTailCallAddressImmediate()) {
    flags |= kCallAddressImmediate;
  }
  if (callee->flags() & CallDescriptor::kFixedTargetRegister) {
    flags |= kCallFixedTargetRegister;
  }
  InitializeCallBuffer(node, &buffer, flags, stack_param_delta);
  UpdateMaxPushedArgumentCount(stack_param_delta);

  // Select the appropriate opcode based on the call type.
  InstructionCode opcode;
  InstructionOperandVector temps(zone());
  switch (callee->kind()) {
    case CallDescriptor::kCallCodeObject:
      opcode = kArchTailCallCodeObject;
      break;
    case CallDescriptor::kCallAddress:
      DCHECK(!caller->IsJSFunctionCall());
      opcode = kArchTailCallAddress;
      break;
#if V8_ENABLE_WEBASSEMBLY
    case CallDescriptor::kCallWasmFunction:
      DCHECK(!caller->IsJSFunctionCall());
      opcode = kArchTailCallWasm;
      break;
#endif  // V8_ENABLE_WEBASSEMBLY
    default:
      UNREACHABLE();
  }
  opcode = EncodeCallDescriptorFlags(opcode, callee->flags());

  Emit(kArchPrepareTailCall, g.NoOutput());

  if (callee->RequiresEntrypointTagForCall()) {
    buffer.instruction_args.push_back(g.TempImmediate(callee->shifted_tag()));
  }

  // Add an immediate operand that represents the offset to the first slot
  // that is unused with respect to the stack pointer that has been updated
  // for the tail call instruction. Backends that pad arguments can write the
  // padding value at this offset from the stack.
  const int optional_padding_offset =
      callee->GetOffsetToFirstUnusedStackSlot() - 1;
  buffer.instruction_args.push_back(g.TempImmediate(optional_padding_offset));

  const int first_unused_slot_offset =
      kReturnAddressStackSlotCount + stack_param_delta;
  buffer.instruction_args.push_back(g.TempImmediate(first_unused_slot_offset));

  // Emit the tailcall instruction.
  Emit(opcode, 0, nullptr, buffer.instruction_args.size(),
       &buffer.instruction_args.front(), temps.size(),
       temps.empty() ? nullptr : &temps.front());
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitGoto(block_t target) {
  // jump to the next block.
  OperandGenerator g(this);
  Emit(kArchJmp, g.NoOutput(), g.Label(target));
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitReturn(node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  const ReturnOp& ret = schedule()->Get(node).Cast<ReturnOp>();

  OperandGenerator g(this);
  const int input_count =
      linkage()->GetIncomingDescriptor()->ReturnCount() == 0
          ? 1
          : (1 + static_cast<int>(ret.return_values().size()));
  DCHECK_GE(input_count, 1);

  auto value_locations =
      zone()->template AllocateArray<InstructionOperand>(input_count);
  const Operation& pop_count = schedule()->Get(ret.pop_count());
  if (pop_count.Is<Opmask::kWord32Constant>() ||
      pop_count.Is<Opmask::kWord64Constant>()) {
    value_locations[0] = g.UseImmediate(ret.pop_count());
  } else {
    value_locations[0] = g.UseRegister(ret.pop_count());
  }
  for (int i = 0, return_value_idx = 0; i < input_count - 1; ++i) {
    LinkageLocation loc = linkage()->GetReturnLocation(i);
    // Return values passed via frame slots have already been stored
    // on the stack by the GrowableStacksReducer.
    if (loc.IsCallerFrameSlot() && ret.spill_caller_frame_slots) {
      continue;
    }
    value_locations[return_value_idx + 1] =
        g.UseLocation(ret.return_values()[return_value_idx], loc);
    return_value_idx++;
  }
  Emit(kArchRet, 0, nullptr, input_count, value_locations);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitReturn(node_t ret) {
  OperandGenerator g(this);
  const int input_count = linkage()->GetIncomingDescriptor()->ReturnCount() == 0
                              ? 1
                              : ret->op()->ValueInputCount();
  DCHECK_GE(input_count, 1);
  auto value_locations =
      zone()->template AllocateArray<InstructionOperand>(input_count);
  Node* pop_count = ret->InputAt(0);
  value_locations[0] = (pop_count->opcode() == IrOpcode::kInt32Constant ||
                        pop_count->opcode() == IrOpcode::kInt64Constant)
                           ? g.UseImmediate(pop_count)
                           : g.UseRegister(pop_count);
  for (int i = 1; i < input_count; ++i) {
    value_locations[i] =
        g.UseLocation(ret->InputAt(i), linkage()->GetReturnLocation(i - 1));
  }
  Emit(kArchRet, 0, nullptr, input_count, value_locations);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitBranch(node_t branch_node,
                                                block_t tbranch,
                                                block_t fbranch) {
  auto branch = this->branch_view(branch_node);
  TryPrepareScheduleFirstProjection(branch.condition());

  FlagsContinuation cont =
      FlagsContinuation::ForBranch(kNotEqual, tbranch, fbranch);
  VisitWordCompareZero(branch, branch.condition(), &cont);
}

// When a DeoptimizeIf/DeoptimizeUnless/Branch depends on a BinopOverflow, the
// InstructionSelector can sometimes generate a fuse instruction covering both
// the BinopOverflow and the DeoptIf/Branch, and the final emitted code will
// look like:
//
//     r = BinopOverflow
//     jo branch_target/deopt_target
//
// When this fusing fails, the final code looks like:
//
//     r = BinopOverflow
//     o = sete  // sets overflow bit
//     cmp o, 0
//     jnz branch_target/deopt_target
//
// To be able to fuse tue BinopOverflow and the DeoptIf/Branch, the 1st
// projection (Projection[0], which contains the actual result) must already be
// scheduled (and a few other conditions must be satisfied, see
// InstructionSelectorXXX::VisitWordCompareZero).
// TryPrepareScheduleFirstProjection is thus called from
// VisitDeoptimizeIf/VisitDeoptimizeUnless/VisitBranch and detects if the 1st
// projection could be scheduled now, and, if so, defines it.
template <typename Adapter>
void InstructionSelectorT<Adapter>::TryPrepareScheduleFirstProjection(
    node_t maybe_projection) {
  // The DeoptimizeIf/DeoptimizeUnless/Branch condition is not a projection.
  if (!this->is_projection(maybe_projection)) return;

  if (this->projection_index_of(maybe_projection) != 1u) {
    // The DeoptimizeIf/DeoptimizeUnless/Branch isn't on the Projection[1]
    // (ie, not on the overflow bit of a BinopOverflow).
    return;
  }

  DCHECK_EQ(this->value_input_count(maybe_projection), 1);
  node_t node = this->input_at(maybe_projection, 0);
  if (this->block(schedule_, node) != current_block_) {
    // The projection input is not in the current block, so it shouldn't be
    // emitted now, so we don't need to eagerly schedule its Projection[0].
    return;
  }

  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    auto* binop = this->Get(node).template TryCast<OverflowCheckedBinopOp>();
    auto* unop = this->Get(node).template TryCast<OverflowCheckedUnaryOp>();
    if (binop == nullptr && unop == nullptr) return;
    if (binop) {
      DCHECK(binop->kind == OverflowCheckedBinopOp::Kind::kSignedAdd ||
             binop->kind == OverflowCheckedBinopOp::Kind::kSignedSub ||
             binop->kind == OverflowCheckedBinopOp::Kind::kSignedMul);
    } else {
      DCHECK_EQ(unop->kind, OverflowCheckedUnaryOp::Kind::kAbs);
    }
  } else {
    switch (node->opcode()) {
      case IrOpcode::kInt32AddWithOverflow:
      case IrOpcode::kInt32SubWithOverflow:
      case IrOpcode::kInt32MulWithOverflow:
      case IrOpcode::kInt64AddWithOverflow:
      case IrOpcode::kInt64SubWithOverflow:
      case IrOpcode::kInt64MulWithOverflow:
        break;
      default:
        return;
    }
  }

  node_t result = FindProjection(node, 0);
  if (!Adapter::valid(result) || IsDefined(result)) {
    // No Projection(0), or it's already defined.
    return;
  }

  if (this->block(schedule_, result) != current_block_) {
    // {result} wasn't planned to be scheduled in {current_block_}. To
    // avoid adding checks to see if it can still be scheduled now, we
    // just bail out.
    return;
  }

  // Checking if all uses of {result} that are in the current block have
  // already been Defined.
  // We also ignore Phi uses: if {result} is used in a Phi in the block in
  // which it is defined, this means that this block is a loop header, and
  // {result} back into it through the back edge. In this case, it's
  // normal to schedule {result} before the Phi that uses it.
  if constexpr (Adapter::IsTurboshaft) {
    for (turboshaft::OpIndex use : turboshaft_uses(result)) {
      // We ignore TupleOp uses, since TupleOp don't lead to emitted machine
      // instructions and are just Turboshaft "meta operations".
      if (!this->Get(use).template Is<turboshaft::TupleOp>() &&
          !IsDefined(use) && this->block(schedule_, use) == current_block_ &&
          !this->Get(use).template Is<turboshaft::PhiOp>()) {
        return;
      }
    }
  } else {
    for (Node* use : result->uses()) {
      if (!IsDefined(use) && this->block(schedule_, use) == current_block_ &&
          use->opcode() != IrOpcode::kPhi) {
        // {use} is in the current block but is not defined yet. It's
        // possible that it's not actually used, but the IsUsed(x) predicate
        // is not valid until we have visited `x`, so we overaproximate and
        // assume that {use} is itself used.
        return;
      }
    }
  }

  // Visiting the projection now. Note that this relies on the fact that
  // VisitProjection doesn't Emit something: if it did, then we could be
  // Emitting something after a Branch, which is invalid (Branch can only
  // be at the end of a block, and the end of a block must always be a
  // block terminator). (remember that we emit operation in reverse order,
  // so because we are doing TryPrepareScheduleFirstProjection before
  // actually emitting the Branch, it would be after in the final
  // instruction sequence, not before)
  VisitProjection(result);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitDeoptimizeIf(node_t node) {
  auto deopt = this->deoptimize_view(node);
  DCHECK(deopt.is_deoptimize_if());

  TryPrepareScheduleFirstProjection(deopt.condition());

  FlagsContinuation cont = FlagsContinuation::ForDeoptimize(
      kNotEqual, deopt.reason(), this->id(node), deopt.feedback(),
      deopt.frame_state());
  VisitWordCompareZero(node, deopt.condition(), &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitDeoptimizeUnless(node_t node) {
  auto deopt = this->deoptimize_view(node);
  DCHECK(deopt.is_deoptimize_unless());
  TryPrepareScheduleFirstProjection(deopt.condition());

  FlagsContinuation cont =
      FlagsContinuation::ForDeoptimize(kEqual, deopt.reason(), this->id(node),
                                       deopt.feedback(), deopt.frame_state());
  VisitWordCompareZero(node, deopt.condition(), &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitSelect(node_t node) {
  DCHECK_EQ(this->value_input_count(node), 3);
  FlagsContinuation cont = FlagsContinuation::ForSelect(
      kNotEqual, node, this->input_at(node, 1), this->input_at(node, 2));
  VisitWordCompareZero(node, this->input_at(node, 0), &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTrapIf(node_t node, TrapId trap_id) {
  // FrameStates are only used for wasm traps inlined in JS. In that case the
  // trap node will be lowered (replaced) before instruction selection.
  // Therefore any TrapIf node has only one input.
  DCHECK_EQ(this->value_input_count(node), 1);
  FlagsContinuation cont = FlagsContinuation::ForTrap(kNotEqual, trap_id);
  VisitWordCompareZero(node, this->input_at(node, 0), &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTrapUnless(node_t node,
                                                    TrapId trap_id) {
  // FrameStates are only used for wasm traps inlined in JS. In that case the
  // trap node will be lowered (replaced) before instruction selection.
  // Therefore any TrapUnless node has only one input.
  DCHECK_EQ(this->value_input_count(node), 1);
  FlagsContinuation cont = FlagsContinuation::ForTrap(kEqual, trap_id);
  VisitWordCompareZero(node, this->input_at(node, 0), &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::EmitIdentity(node_t node) {
  MarkAsUsed(this->input_at(node, 0));
  MarkAsDefined(node);
  SetRename(node, this->input_at(node, 0));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitDeoptimize(
    DeoptimizeReason reason, id_t node_id, FeedbackSource const& feedback,
    node_t frame_state) {
  InstructionOperandVector args(instruction_zone());
  AppendDeoptimizeArguments(&args, reason, node_id, feedback, frame_state);
  Emit(kArchDeoptimize, 0, nullptr, args.size(), &args.front(), 0, nullptr);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitThrow(Node* node) {
  OperandGenerator g(this);
  Emit(kArchThrowTerminator, g.NoOutput());
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitDebugBreak(node_t node) {
  OperandGenerator g(this);
  Emit(kArchDebugBreak, g.NoOutput());
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUnreachable(node_t node) {
  OperandGenerator g(this);
  Emit(kArchDebugBreak, g.NoOutput());
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitStaticAssert(node_t node) {
  DCHECK_EQ(this->value_input_count(node), 1);
  node_t asserted = this->input_at(node, 0);
  UnparkedScopeIfNeeded scope(broker_);
  AllowHandleDereference allow_handle_dereference;
  if constexpr (Adapter::IsTurboshaft) {
    StdoutStream os;
    os << this->Get(asserted);
    FATAL(
        "Expected Turbofan static assert to hold, but got non-true input:\n  "
        "%s",
        this->Get(node).template Cast<turboshaft::StaticAssertOp>().source);
  } else {
    asserted->Print(4);
    FATAL(
        "Expected Turbofan static assert to hold, but got non-true input:\n  "
        "%s",
        StaticAssertSourceOf(node->op()));
  }
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitDeadValue(Node* node) {
  OperandGenerator g(this);
  MarkAsRepresentation(DeadValueRepresentationOf(node->op()), node);
  Emit(kArchDebugBreak, g.DefineAsConstant(node));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitComment(node_t node) {
  OperandGenerator g(this);
  if constexpr (Adapter::IsTurboshaft) {
    const turboshaft::CommentOp& comment =
        this->turboshaft_graph()
            ->Get(node)
            .template Cast<turboshaft::CommentOp>();
    using ptrsize_int_t =
        std::conditional<kSystemPointerSize == 8, int64_t, int32_t>::type;
    InstructionOperand operand = sequence()->AddImmediate(
        Constant{reinterpret_cast<ptrsize_int_t>(comment.message)});
    Emit(kArchComment, 0, nullptr, 1, &operand);
  } else {
    InstructionOperand operand(g.UseImmediate(node));
    Emit(kArchComment, 0, nullptr, 1, &operand);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitRetain(node_t node) {
  OperandGenerator g(this);
  DCHECK_EQ(this->value_input_count(node), 1);
  Emit(kArchNop, g.NoOutput(), g.UseAny(this->input_at(node, 0)));
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitControl(block_t block) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
#ifdef DEBUG
  // SSA deconstruction requires targets of branches not to have phis.
  // Edge split form guarantees this property, but is more strict.
  if (auto successors =
          SuccessorBlocks(block->LastOperation(*turboshaft_graph()));
      successors.size() > 1) {
    for (Block* successor : successors) {
      if (successor->HasPhis(*turboshaft_graph())) {
        std::ostringstream str;
        str << "You might have specified merged variables for a label with "
            << "only one predecessor." << std::endl
            << "# Current Block: " << successor->index() << std::endl;
        FATAL("%s", str.str().c_str());
      }
    }
  }
#endif  // DEBUG
  const Operation& op = block->LastOperation(*schedule());
  OpIndex node = schedule()->Index(op);
  int instruction_end = static_cast<int>(instructions_.size());
  switch (op.opcode) {
    case Opcode::kGoto:
      VisitGoto(op.Cast<GotoOp>().destination);
      break;
    case Opcode::kReturn:
      VisitReturn(node);
      break;
    case Opcode::kTailCall:
      VisitTailCall(node);
      break;
    case Opcode::kDeoptimize: {
      const DeoptimizeOp& deoptimize = op.Cast<DeoptimizeOp>();
      VisitDeoptimize(deoptimize.parameters->reason(), node.id(),
                      deoptimize.parameters->feedback(),
                      deoptimize.frame_state());
      break;
    }
    case Opcode::kBranch: {
      const BranchOp& branch = op.Cast<BranchOp>();
      block_t tbranch = branch.if_true;
      block_t fbranch = branch.if_false;
      if (tbranch == fbranch) {
        VisitGoto(tbranch);
      } else {
        VisitBranch(node, tbranch, fbranch);
      }
      break;
    }
    case Opcode::kSwitch: {
      const SwitchOp& swtch = op.Cast<SwitchOp>();
      int32_t min_value = std::numeric_limits<int32_t>::max();
      int32_t max_value = std::numeric_limits<int32_t>::min();

      ZoneVector<CaseInfo> cases(swtch.cases.size(), zone());
      for (size_t i = 0; i < swtch.cases.size(); ++i) {
        const SwitchOp::Case& c = swtch.cases[i];
        cases[i] = CaseInfo{c.value, 0, c.destination};
        if (min_value > c.value) min_value = c.value;
        if (max_value < c.value) max_value = c.value;
      }
      SwitchInfo sw(std::move(cases), min_value, max_value, swtch.default_case);
      return VisitSwitch(node, sw);
    }
    case Opcode::kCheckException: {
      const CheckExceptionOp& check = op.Cast<CheckExceptionOp>();
      VisitCall(check.throwing_operation(), check.catch_block);
      VisitGoto(check.didnt_throw_block);
      return;
    }
    case Opcode::kUnreachable:
      return VisitUnreachable(node);
    case Opcode::kStaticAssert:
      return VisitStaticAssert(node);
    default: {
      const std::string op_string = op.ToString();
      PrintF("\033[31mNo ISEL support for: %s\033[m\n", op_string.c_str());
      FATAL("Unexpected operation #%d:%s", node.id(), op_string.c_str());
    }
  }

  if (trace_turbo_ == InstructionSelector::kEnableTraceTurboJson) {
    DCHECK(node.valid());
    int instruction_start = static_cast<int>(instructions_.size());
    instr_origins_[this->id(node)] = {instruction_start, instruction_end};
  }
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitControl(BasicBlock* block) {
#ifdef DEBUG
  // SSA deconstruction requires targets of branches not to have phis.
  // Edge split form guarantees this property, but is more strict.
  if (block->SuccessorCount() > 1) {
    for (BasicBlock* const successor : block->successors()) {
      for (Node* const node : *successor) {
        if (IrOpcode::IsPhiOpcode(node->opcode())) {
          std::ostringstream str;
          str << "You might have specified merged variables for a label with "
              << "only one predecessor." << std::endl
              << "# Current Block: " << *successor << std::endl
              << "#          Node: " << *node;
          FATAL("%s", str.str().c_str());
        }
      }
    }
  }
#endif

  Node* input = block->control_input();
  int instruction_end = static_cast<int>(instructions_.size());
  switch (block->control()) {
    case BasicBlock::kGoto:
      VisitGoto(block->SuccessorAt(0));
      break;
    case BasicBlock::kCall: {
      DCHECK_EQ(IrOpcode::kCall, input->opcode());
      BasicBlock* success = block->SuccessorAt(0);
      BasicBlock* exception = block->SuccessorAt(1);
      VisitCall(input, exception);
      VisitGoto(success);
      break;
    }
    case BasicBlock::kTailCall: {
      DCHECK_EQ(IrOpcode::kTailCall, input->opcode());
      VisitTailCall(input);
      break;
    }
    case BasicBlock::kBranch: {
      DCHECK_EQ(IrOpcode::kBranch, input->opcode());
      // TODO(nicohartmann@): Once all branches have explicitly specified
      // semantics, we should allow only BranchSemantics::kMachine here.
      DCHECK_NE(BranchSemantics::kJS,
                BranchParametersOf(input->op()).semantics());
      BasicBlock* tbranch = block->SuccessorAt(0);
      BasicBlock* fbranch = block->SuccessorAt(1);
      if (tbranch == fbranch) {
        VisitGoto(tbranch);
      } else {
        VisitBranch(input, tbranch, fbranch);
      }
      break;
    }
    case BasicBlock::kSwitch: {
      DCHECK_EQ(IrOpcode::kSwitch, input->opcode());
      // Last successor must be {IfDefault}.
      BasicBlock* default_branch = block->successors().back();
      DCHECK_EQ(IrOpcode::kIfDefault, default_branch->front()->opcode());
      // All other successors must be {IfValue}s.
      int32_t min_value = std::numeric_limits<int32_t>::max();
      int32_t max_value = std::numeric_limits<int32_t>::min();
      size_t case_count = block->SuccessorCount() - 1;
      ZoneVector<CaseInfo> cases(case_count, zone());
      for (size_t i = 0; i < case_count; ++i) {
        BasicBlock* branch = block->SuccessorAt(i);
        const IfValueParameters& p = IfValueParametersOf(branch->front()->op());
        cases[i] = CaseInfo{p.value(), p.comparison_order(), branch};
        if (min_value > p.value()) min_value = p.value();
        if (max_value < p.value()) max_value = p.value();
      }
      SwitchInfo sw(cases, min_value, max_value, default_branch);
      VisitSwitch(input, sw);
      break;
    }
    case BasicBlock::kReturn: {
      DCHECK_EQ(IrOpcode::kReturn, input->opcode());
      VisitReturn(input);
      break;
    }
    case BasicBlock::kDeoptimize: {
      DeoptimizeParameters p = DeoptimizeParametersOf(input->op());
      FrameState value{input->InputAt(0)};
      VisitDeoptimize(p.reason(), input->id(), p.feedback(), value);
      break;
    }
    case BasicBlock::kThrow:
      DCHECK_EQ(IrOpcode::kThrow, input->opcode());
      VisitThrow(input);
      break;
    case BasicBlock::kNone: {
      // Exit block doesn't have control.
      DCHECK_NULL(input);
      break;
    }
    default:
      UNREACHABLE();
  }
  if (trace_turbo_ == InstructionSelector::kEnableTraceTurboJson && input) {
    int instruction_start = static_cast<int>(instructions_.size());
    instr_origins_[input->id()] = {instruction_start, instruction_end};
  }
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitNode(Node* node) {
  tick_counter_->TickAndMaybeEnterSafepoint();
  DCHECK_NOT_NULL(
      this->block(schedule(), node));  // should only use scheduled nodes.
  switch (node->opcode()) {
    case IrOpcode::kTraceInstruction:
#if V8_TARGET_ARCH_X64
      return VisitTraceInstruction(node);
#else
      return;
#endif
    case IrOpcode::kStart:
    case IrOpcode::kLoop:
    case IrOpcode::kEnd:
    case IrOpcode::kBranch:
    case IrOpcode::kIfTrue:
    case IrOpcode::kIfFalse:
    case IrOpcode::kIfSuccess:
    case IrOpcode::kSwitch:
    case IrOpcode::kIfValue:
    case IrOpcode::kIfDefault:
    case IrOpcode::kEffectPhi:
    case IrOpcode::kMerge:
    case IrOpcode::kTerminate:
    case IrOpcode::kBeginRegion:
      // No code needed for these graph artifacts.
      return;
    case IrOpcode::kIfException:
      return MarkAsTagged(node), VisitIfException(node);
    case IrOpcode::kFinishRegion:
      return MarkAsTagged(node), VisitFinishRegion(node);
    case IrOpcode::kParameter: {
      // Parameters should always be scheduled to the first block.
      DCHECK_EQ(this->rpo_number(this->block(schedule(), node)).ToInt(), 0);
      MachineType type =
          linkage()->GetParameterType(ParameterIndexOf(node->op()));
      MarkAsRepresentation(type.representation(), node);
      return VisitParameter(node);
    }
    case IrOpcode::kOsrValue:
      return MarkAsTagged(node), VisitOsrValue(node);
    case IrOpcode::kPhi: {
      MachineRepresentation rep = PhiRepresentationOf(node->op());
      if (rep == MachineRepresentation::kNone) return;
      MarkAsRepresentation(rep, node);
      return VisitPhi(node);
    }
    case IrOpcode::kProjection:
      return VisitProjection(node);
    case IrOpcode::kInt32Constant:
    case IrOpcode::kInt64Constant:
    case IrOpcode::kTaggedIndexConstant:
    case IrOpcode::kExternalConstant:
    case IrOpcode::kRelocatableInt64Constant:
      return VisitConstant(node);
    case IrOpcode::kRelocatableInt32Constant:
      return MarkAsWord32(node), VisitConstant(node);
    case IrOpcode::kFloat32Constant:
      return MarkAsFloat32(node), VisitConstant(node);
    case IrOpcode::kFloat64Constant:
      return MarkAsFloat64(node), VisitConstant(node);
    case IrOpcode::kHeapConstant:
      return MarkAsTagged(node), VisitConstant(node);
    case IrOpcode::kCompressedHeapConstant:
      return MarkAsCompressed(node), VisitConstant(node);
    case IrOpcode::kTrustedHeapConstant:
      return MarkAsTagged(node), VisitConstant(node);
    case IrOpcode::kNumberConstant: {
      double value = OpParameter<double>(node->op());
      if (!IsSmiDouble(value)) MarkAsTagged(node);
      return VisitConstant(node);
    }
    case IrOpcode::kCall:
      return VisitCall(node);
    case IrOpcode::kDeoptimizeIf:
      return VisitDeoptimizeIf(node);
    case IrOpcode::kDeoptimizeUnless:
      return VisitDeoptimizeUnless(node);
#if V8_ENABLE_WEBASSEMBLY
    case IrOpcode::kTrapIf:
      return VisitTrapIf(node, TrapIdOf(node->op()));
    case IrOpcode::kTrapUnless:
      return VisitTrapUnless(node, TrapIdOf(node->op()));
#endif  // V8_ENABLE_WEBASSEMBLY
    case IrOpcode::kFrameState:
    case IrOpcode::kStateValues:
    case IrOpcode::kObjectState:
      return;
    case IrOpcode::kAbortCSADcheck:
      VisitAbortCSADcheck(node);
      return;
    case IrOpcode::kDebugBreak:
      VisitDebugBreak(node);
      return;
    case IrOpcode::kUnreachable:
      VisitUnreachable(node);
      return;
    case IrOpcode::kStaticAssert:
      VisitStaticAssert(node);
      return;
    case IrOpcode::kDeadValue:
      VisitDeadValue(node);
      return;
    case IrOpcode::kComment:
      VisitComment(node);
      return;
    case IrOpcode::kRetain:
      VisitRetain(node);
      return;
    case IrOpcode::kLoad:
    case IrOpcode::kLoadImmutable: {
      LoadRepresentation type = LoadRepresentationOf(node->op());
      MarkAsRepresentation(type.representation(), node);
      return VisitLoad(node);
    }
#if V8_ENABLE_WEBASSEMBLY
    case IrOpcode::kLoadTransform: {
      LoadTransformParameters params = LoadTransformParametersOf(node->op());
      if (params.transformation >= LoadTransformation::kFirst256Transform) {
        MarkAsRepresentation(MachineRepresentation::kSimd256, node);
      } else {
        MarkAsRepresentation(MachineRepresentation::kSimd128, node);
      }
      return VisitLoadTransform(node);
    }
    case IrOpcode::kLoadLane: {
      MarkAsRepresentation(MachineRepresentation::kSimd128, node);
      return VisitLoadLane(node);
    }
    case IrOpcode::kStoreLane: {
      MarkAsRepresentation(MachineRepresentation::kSimd128, node);
      return VisitStoreLane(node);
    }
#endif  // V8_ENABLE_WEBASSEMBLY
    case IrOpcode::kStore:
    case IrOpcode::kStoreIndirectPointer:
      return VisitStore(node);
    case IrOpcode::kStorePair:
      return VisitStorePair(node);
    case IrOpcode::kProtectedStore:
    case IrOpcode::kStoreTrapOnNull:
      return VisitProtectedStore(node);
    case IrOpcode::kWord32And:
      return MarkAsWord32(node), VisitWord32And(node);
    case IrOpcode::kWord32Or:
      return MarkAsWord32(node), VisitWord32Or(node);
    case IrOpcode::kWord32Xor:
      return MarkAsWord32(node), VisitWord32Xor(node);
    case IrOpcode::kWord32Shl:
      return MarkAsWord32(node), VisitWord32Shl(node);
    case IrOpcode::kWord32Shr:
      re
```