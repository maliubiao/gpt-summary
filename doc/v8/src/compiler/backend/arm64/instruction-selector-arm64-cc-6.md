Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/compiler/backend/arm64/instruction-selector-arm64.cc`.

Here's a breakdown of how to arrive at the answer:

1. **Identify the File's Purpose:** The filename `instruction-selector-arm64.cc` strongly suggests that this code is responsible for selecting appropriate ARM64 instructions based on the intermediate representation (IR) of the JavaScript code being compiled by V8. This is a key part of the compilation pipeline.

2. **Analyze Key Functions:**  The code is organized around `Visit...` functions. Each `Visit...` function seems to handle a specific type of operation or node in the IR. For example, `VisitWord32Compare`, `VisitFloat64Compare`, `VisitAtomicExchange`, etc. This suggests the code iterates through the IR and translates each node into ARM64 instructions.

3. **Focus on Data Types and Operations:**  Notice the prevalence of data types like `Word32`, `Word64`, `Float32`, `Float64`, and operations like `Compare`, `Test`, `Add`, `Sub`, `And`, `AtomicExchange`, `AtomicLoad`, `AtomicStore`. This confirms the instruction selector deals with different data types and their corresponding operations.

4. **Look for Specific ARM64 Instructions:**  The code uses constants like `kArm64Cmp32`, `kArm64Tst`, `kArm64Add`, `kArm64Ldar`, `kArm64Stlr`. These are mnemonics for specific ARM64 instructions. This reinforces the idea that the code is mapping IR operations to concrete machine instructions.

5. **Observe Conditional Logic:** The code uses `if` and `else if` statements extensively to handle different scenarios and optimize instruction selection. For instance, it checks for comparisons with zero to use more efficient instructions like `cbz` or `tbz`. It also handles cases where operands are constants or when operations can be combined or simplified.

6. **Consider the `FlagsContinuation`:** The presence of `FlagsContinuationT` indicates the code is also managing CPU flags and conditional branching. It manipulates the continuation to invert conditions and optimize branch instructions.

7. **Identify Atomic Operations:** The `VisitAtomic...` functions and terms like `AtomicExchange`, `AtomicLoad`, and `AtomicStore` point to support for atomic operations, crucial for multi-threaded JavaScript environments.

8. **Look for Adapter Patterns:** The `<typename Adapter>` template suggests the code might be using an adapter pattern to handle different compilation pipelines or IR representations (e.g., Turbofan vs. Turboshaft).

9. **Check for Torque Mentions:** The initial instruction mentions ".tq" and Torque. While this specific snippet doesn't seem to be Torque code, it's important to note the context for other parts of the file.

10. **Relate to JavaScript:** Think about how these operations map to JavaScript. Comparisons (`==`, `<`, `>`), arithmetic operations (`+`, `-`, `&`), and atomic operations (using `SharedArrayBuffer` and `Atomics`) are all directly related to JavaScript functionality.

11. **Infer Code Logic:**  Consider simple scenarios. If the code encounters an addition of two 32-bit integers, it will select an `ADD` instruction. If it encounters a comparison with zero, it might use a `CMP` followed by a conditional branch or a more specialized `CBZ` instruction.

12. **Identify Potential Errors:** Think about common programming errors related to these operations, like integer overflow or incorrect use of atomic operations leading to race conditions.

13. **Synthesize the Information:** Combine the observations into a concise summary of the code's purpose and functionality.

By following these steps, we can arrive at the detailed explanation provided in the initial good answer, covering the core functionalities of instruction selection, handling different data types and operations, optimization strategies, and support for atomic operations.
让我来归纳一下 `v8/src/compiler/backend/arm64/instruction-selector-arm64.cc` 代码片段（第 7 部分）的功能。

**功能归纳：**

这段代码是 V8 编译器中针对 ARM64 架构的指令选择器的一部分，其核心功能是将高级中间表示 (IR) 的操作转换为具体的 ARM64 汇编指令。  第 7 部分主要关注 **比较 (Compare) 和测试 (Test) 操作** 的指令选择，并包含对 **原子操作 (Atomic Operations)** 的处理。

**更详细的功能点：**

1. **比较指令选择 (VisitCompare, VisitWord32Compare, VisitFloat32Compare, VisitFloat64Compare):**
   - 针对不同数据类型（32 位整数、64 位整数、单精度浮点数、双精度浮点数）的比较操作，选择合适的 ARM64 `CMP` 或 `CMN` 指令。
   - 优化了与零比较的情况，尝试使用更高效的 `CBZ` (Compare and Branch if Zero) 或 `TBZ` (Test bit and Branch if Zero) 指令。
   - 对于特定模式（例如，与零比较的加法或按位与操作），可能会使用能同时设置标志位的算术或逻辑指令来替代显式的比较指令。
   - 针对 `kEqual` 和 `kNotEqual` 的比较，当右操作数是零减去一个值时，会选择 `CMN` (Compare Negative) 指令。

2. **测试指令选择 (VisitWordTest, VisitWord32Test, VisitWord64Test):**
   - 将位测试操作转换为 ARM64 的 `TST` (Test bits) 指令。

3. **测试并分支优化 (TestAndBranchMatcher, TestAndBranchMatcherTurboshaft):**
   - 识别形如 `(x & mask) == 0` 或 `(x & mask) != 0` 的模式，其中 `mask` 是 2 的幂。
   - 将这种模式优化为使用 `TBZ` (Test bit and Branch if Zero) 或 `TBNZ` (Test bit and Branch if Non-Zero) 指令，这比先进行按位与再比较更高效。

4. **原子操作指令选择 (VisitAtomicExchange, VisitAtomicCompareExchange, VisitAtomicLoad, VisitAtomicStore, VisitAtomicBinop):**
   - 处理各种原子操作，例如原子交换、原子比较并交换、原子加载和原子存储。
   - 针对不同的数据宽度（字节、半字、字、双字）选择合适的原子指令，例如 `LDAR` (Load-Acquire Register)、`STLR` (Store-Release Register)、`SWP` (Swap word or doubleword in memory)。
   - 考虑了内存访问顺序和是否需要写屏障 (Write Barrier)。
   - 针对支持 LSE (Large System Extensions) 的 CPU 特性，可能会使用更高效的原子指令。
   - 考虑了受陷阱处理程序保护的内存访问 (`MemoryAccessKind::kProtectedByTrapHandler`)，并设置相应的访问模式。

5. **Turboshaft 特殊处理:**
   - 代码中存在针对 `TurboshaftAdapter` 的特殊处理，这表明 V8 中存在不同的编译器管道（Turbofan 和 Turboshaft）。

**与 JavaScript 的关系：**

这些指令选择最终是为了执行 JavaScript 代码。例如：

```javascript
let a = 10;
let b = 5;

if (a > b) { // 这会触发比较指令的选择
  console.log("a is greater than b");
}

let mask = 0b0001;
if (a & mask) { // 这会触发测试或测试并分支指令的选择
  console.log("least significant bit of a is set");
}

const sab = new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT);
const view = new Int32Array(sab);
Atomics.add(view, 0, 1); // 这会触发原子操作指令的选择
```

**代码逻辑推理（假设输入与输出）：**

**假设输入：** 一个 IR 节点，表示对两个 32 位整数进行小于比较 (`Int32LessThan`)，并有一个跳转到某个标签的 `FlagsContinuation`。

**输出：**  选择 `kArm64Cmp32` 指令来比较这两个整数，并将比较结果传递给 `FlagsContinuation` 以生成相应的条件分支指令。

**用户常见的编程错误：**

1. **整数溢出：**  例如，在进行加法或乘法运算时，结果超出了 32 位或 64 位整数的范围。V8 的指令选择器会尝试处理带有溢出检查的操作 (`kInt32AddWithOverflow` 等)，并生成相应的代码来检测和处理溢出。

   ```javascript
   let maxInt = 2147483647;
   let result = maxInt + 1; // 整数溢出
   ```

2. **未正确使用原子操作：** 在多线程环境下，如果没有正确使用原子操作来保护共享数据，可能会导致数据竞争和不可预测的结果。

   ```javascript
   const sab = new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT);
   const view = new Int32Array(sab);

   // 线程 1
   view[0]++; // 非原子操作，可能导致数据竞争

   // 线程 2
   view[0]++; // 非原子操作，可能导致数据竞争
   ```
   应该使用 `Atomics.add(view, 0, 1)` 来确保操作的原子性。

**总结第 7 部分的功能：**

第 7 部分的 `instruction-selector-arm64.cc` 代码专注于将 IR 中的比较、测试以及原子操作转换为高效的 ARM64 汇编指令。它包含了针对不同数据类型、优化场景以及多线程环境的特殊处理逻辑，旨在提升 JavaScript 代码在 ARM64 架构上的执行效率。

### 提示词
```
这是目录为v8/src/compiler/backend/arm64/instruction-selector-arm64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/arm64/instruction-selector-arm64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第7部分，共11部分，请归纳一下它的功能
```

### 源代码
```cpp
node, cont->condition(), cont)) {
        return;
      }
    }
  }

  VisitCompare(selector, opcode, g.UseRegister(left),
               g.UseOperand(right, immediate_mode), cont);
}

template <typename Adapter>
void VisitWord32Compare(InstructionSelectorT<Adapter>* selector,
                        typename Adapter::node_t node,
                        FlagsContinuationT<Adapter>* cont) {
  {
    Int32BinopMatcher m(node);
    FlagsCondition cond = cont->condition();
    if (m.right().HasResolvedValue()) {
      if (TryEmitCbzOrTbz<Adapter, 32>(selector, m.left().node(),
                                       m.right().ResolvedValue(), node, cond,
                                       cont)) {
        return;
      }
    } else if (m.left().HasResolvedValue()) {
      FlagsCondition commuted_cond = CommuteFlagsCondition(cond);
      if (TryEmitCbzOrTbz<Adapter, 32>(selector, m.right().node(),
                                       m.left().ResolvedValue(), node,
                                       commuted_cond, cont)) {
        return;
      }
    }
    ArchOpcode opcode = kArm64Cmp32;
    ImmediateMode immediate_mode = kArithmeticImm;
    if (m.right().Is(0) && (m.left().IsInt32Add() || m.left().IsWord32And())) {
      // Emit flag setting add/and instructions for comparisons against zero.
      if (CanUseFlagSettingBinop(cond)) {
        Node* binop = m.left().node();
        MaybeReplaceCmpZeroWithFlagSettingBinop(selector, &node, binop, &opcode,
                                                cond, cont, &immediate_mode);
      }
    } else if (m.left().Is(0) &&
               (m.right().IsInt32Add() || m.right().IsWord32And())) {
      // Same as above, but we need to commute the condition before we
      // continue with the rest of the checks.
      FlagsCondition commuted_cond = CommuteFlagsCondition(cond);
      if (CanUseFlagSettingBinop(commuted_cond)) {
        Node* binop = m.right().node();
        MaybeReplaceCmpZeroWithFlagSettingBinop(selector, &node, binop, &opcode,
                                                commuted_cond, cont,
                                                &immediate_mode);
      }
    } else if (m.right().IsInt32Sub() &&
               (cond == kEqual || cond == kNotEqual)) {
      // Select negated compare for comparisons with negated right input.
      // Only do this for kEqual and kNotEqual, which do not depend on the
      // C and V flags, as those flags will be different with CMN when the
      // right-hand side of the original subtraction is INT_MIN.
      Node* sub = m.right().node();
      Int32BinopMatcher msub(sub);
      if (msub.left().Is(0)) {
        bool can_cover = selector->CanCover(node, sub);
        node->ReplaceInput(1, msub.right().node());
        // Even if the comparison node covers the subtraction, after the input
        // replacement above, the node still won't cover the input to the
        // subtraction; the subtraction still uses it.
        // In order to get shifted operations to work, we must remove the rhs
        // input to the subtraction, as TryMatchAnyShift requires this node to
        // cover the input shift. We do this by setting it to the lhs input,
        // as we know it's zero, and the result of the subtraction isn't used by
        // any other node.
        if (can_cover) sub->ReplaceInput(1, msub.left().node());
        opcode = kArm64Cmn32;
      }
    }
    VisitBinop<Adapter, Int32BinopMatcher>(selector, node, opcode,
                                           immediate_mode, cont);
  }
}

template <>
void VisitWord32Compare(InstructionSelectorT<TurboshaftAdapter>* selector,
                        typename TurboshaftAdapter::node_t node,
                        FlagsContinuationT<TurboshaftAdapter>* cont) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  const Operation& compare = selector->Get(node);
  DCHECK_GE(compare.input_count, 2);
  OpIndex lhs = compare.input(0);
  OpIndex rhs = compare.input(1);
  FlagsCondition cond = cont->condition();

  if (selector->is_integer_constant(rhs) &&
      TryEmitCbzOrTbz<TurboshaftAdapter, 32>(
          selector, lhs, static_cast<uint32_t>(selector->integer_constant(rhs)),
          node, cond, cont)) {
    return;
  }
  if (selector->is_integer_constant(lhs) &&
      TryEmitCbzOrTbz<TurboshaftAdapter, 32>(
          selector, rhs, static_cast<uint32_t>(selector->integer_constant(lhs)),
          node, CommuteFlagsCondition(cond), cont)) {
    return;
  }

  const Operation& left = selector->Get(lhs);
  const Operation& right = selector->Get(rhs);
  ArchOpcode opcode = kArm64Cmp32;
  ImmediateMode immediate_mode = kArithmeticImm;

  if (selector->MatchIntegralZero(rhs) &&
      (left.Is<Opmask::kWord32Add>() || left.Is<Opmask::kWord32BitwiseAnd>())) {
    // Emit flag setting add/and instructions for comparisons against zero.
    if (CanUseFlagSettingBinop(cond)) {
      MaybeReplaceCmpZeroWithFlagSettingBinop(selector, &node, lhs, &opcode,
                                              cond, cont, &immediate_mode);
    }
  } else if (selector->MatchIntegralZero(lhs) &&
             (right.Is<Opmask::kWord32Add>() ||
              right.Is<Opmask::kWord32BitwiseAnd>())) {
    // Same as above, but we need to commute the condition before we
    // continue with the rest of the checks.
    FlagsCondition commuted_cond = CommuteFlagsCondition(cond);
    if (CanUseFlagSettingBinop(commuted_cond)) {
      MaybeReplaceCmpZeroWithFlagSettingBinop(
          selector, &node, rhs, &opcode, commuted_cond, cont, &immediate_mode);
    }
  } else if (right.Is<Opmask::kWord32Sub>() &&
             (cond == kEqual || cond == kNotEqual)) {
    const WordBinopOp& sub = right.Cast<WordBinopOp>();
    if (selector->MatchIntegralZero(sub.left())) {
      // For a given compare(x, 0 - y) where compare is kEqual or kNotEqual,
      // it can be expressed as cmn(x, y).
      opcode = kArm64Cmn32;
      VisitBinopImpl(selector, node, lhs, sub.right(),
                     RegisterRepresentation::Word32(), opcode, immediate_mode,
                     cont);
      return;
    }
  }
  VisitBinop(selector, node, RegisterRepresentation::Word32(), opcode,
             immediate_mode, cont);
}

template <typename Adapter>
void VisitWordTest(InstructionSelectorT<Adapter>* selector,
                   typename Adapter::node_t node, InstructionCode opcode,
                   FlagsContinuationT<Adapter>* cont) {
  Arm64OperandGeneratorT<Adapter> g(selector);
  VisitCompare(selector, opcode, g.UseRegister(node), g.UseRegister(node),
               cont);
}

template <typename Adapter>
void VisitWord32Test(InstructionSelectorT<Adapter>* selector,
                     typename Adapter::node_t node,
                     FlagsContinuationT<Adapter>* cont) {
  VisitWordTest(selector, node, kArm64Tst32, cont);
}

template <typename Adapter>
void VisitWord64Test(InstructionSelectorT<Adapter>* selector,
                     typename Adapter::node_t node,
                     FlagsContinuationT<Adapter>* cont) {
  VisitWordTest(selector, node, kArm64Tst, cont);
}

template <typename Adapter, typename Matcher>
struct TestAndBranchMatcher {
  TestAndBranchMatcher(Node* node, FlagsContinuationT<Adapter>* cont)
      : matches_(false), cont_(cont), matcher_(node) {
    Initialize();
  }
  bool Matches() const { return matches_; }

  unsigned bit() const {
    DCHECK(Matches());
    return base::bits::CountTrailingZeros(matcher_.right().ResolvedValue());
  }

  Node* input() const {
    DCHECK(Matches());
    return matcher_.left().node();
  }

 private:
  bool matches_;
  FlagsContinuationT<Adapter>* cont_;
  Matcher matcher_;

  void Initialize() {
    if (cont_->IsBranch() && matcher_.right().HasResolvedValue() &&
        base::bits::IsPowerOfTwo(matcher_.right().ResolvedValue())) {
      // If the mask has only one bit set, we can use tbz/tbnz.
      DCHECK((cont_->condition() == kEqual) ||
             (cont_->condition() == kNotEqual));
      matches_ = true;
    } else {
      matches_ = false;
    }
  }
};

struct TestAndBranchMatcherTurboshaft {
  TestAndBranchMatcherTurboshaft(
      InstructionSelectorT<TurboshaftAdapter>* selector,
      const turboshaft::WordBinopOp& binop)
      : selector_(selector), binop_(binop) {
    Initialize();
  }

  bool Matches() const { return matches_; }

  unsigned bit() const {
    DCHECK(Matches());
    return bit_;
  }

 private:
  void Initialize() {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    if (binop_.kind != WordBinopOp::Kind::kBitwiseAnd) return;
    uint64_t value{0};
    if (!selector_->MatchUnsignedIntegralConstant(binop_.right(), &value) ||
        !base::bits::IsPowerOfTwo(value)) {
      return;
    }
    // All preconditions for TBZ/TBNZ matched.
    matches_ = true;
    bit_ = base::bits::CountTrailingZeros(value);
  }

  InstructionSelectorT<TurboshaftAdapter>* selector_;
  const turboshaft::WordBinopOp& binop_;
  bool matches_ = false;
  unsigned bit_ = 0;
};

// Shared routine for multiple float32 compare operations.
template <typename Adapter>
void VisitFloat32Compare(InstructionSelectorT<Adapter>* selector,
                         typename Adapter::node_t node,
                         FlagsContinuationT<Adapter>* cont) {
  Arm64OperandGeneratorT<Adapter> g(selector);
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const ComparisonOp& op = selector->Get(node).template Cast<ComparisonOp>();
    OpIndex left = op.left();
    OpIndex right = op.right();
    if (selector->MatchZero(right)) {
      VisitCompare(selector, kArm64Float32Cmp, g.UseRegister(left),
                   g.UseImmediate(right), cont);
    } else if (selector->MatchZero(left)) {
      cont->Commute();
      VisitCompare(selector, kArm64Float32Cmp, g.UseRegister(right),
                   g.UseImmediate(left), cont);
    } else {
      VisitCompare(selector, kArm64Float32Cmp, g.UseRegister(left),
                   g.UseRegister(right), cont);
    }
  } else {
    Float32BinopMatcher m(node);
    if (m.right().Is(0.0f)) {
      VisitCompare(selector, kArm64Float32Cmp, g.UseRegister(m.left().node()),
                   g.UseImmediate(m.right().node()), cont);
    } else if (m.left().Is(0.0f)) {
      cont->Commute();
      VisitCompare(selector, kArm64Float32Cmp, g.UseRegister(m.right().node()),
                   g.UseImmediate(m.left().node()), cont);
    } else {
      VisitCompare(selector, kArm64Float32Cmp, g.UseRegister(m.left().node()),
                   g.UseRegister(m.right().node()), cont);
    }
  }
}

// Shared routine for multiple float64 compare operations.
template <typename Adapter>
void VisitFloat64Compare(InstructionSelectorT<Adapter>* selector,
                         typename Adapter::node_t node,
                         FlagsContinuationT<Adapter>* cont) {
  if constexpr (Adapter::IsTurboshaft) {
    Arm64OperandGeneratorT<Adapter> g(selector);
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const Operation& compare = selector->Get(node);
    DCHECK(compare.Is<ComparisonOp>());
    OpIndex lhs = compare.input(0);
    OpIndex rhs = compare.input(1);
    if (selector->MatchZero(rhs)) {
      VisitCompare(selector, kArm64Float64Cmp, g.UseRegister(lhs),
                   g.UseImmediate(rhs), cont);
    } else if (selector->MatchZero(lhs)) {
      cont->Commute();
      VisitCompare(selector, kArm64Float64Cmp, g.UseRegister(rhs),
                   g.UseImmediate(lhs), cont);
    } else {
      VisitCompare(selector, kArm64Float64Cmp, g.UseRegister(lhs),
                   g.UseRegister(rhs), cont);
    }
  } else {
    Arm64OperandGeneratorT<Adapter> g(selector);
    Float64BinopMatcher m(node);
    if (m.right().Is(0.0)) {
      VisitCompare(selector, kArm64Float64Cmp, g.UseRegister(m.left().node()),
                   g.UseImmediate(m.right().node()), cont);
    } else if (m.left().Is(0.0)) {
      cont->Commute();
      VisitCompare(selector, kArm64Float64Cmp, g.UseRegister(m.right().node()),
                   g.UseImmediate(m.left().node()), cont);
    } else {
      VisitCompare(selector, kArm64Float64Cmp, g.UseRegister(m.left().node()),
                   g.UseRegister(m.right().node()), cont);
    }
  }
}

template <typename Adapter>
void VisitAtomicExchange(InstructionSelectorT<Adapter>* selector,
                         typename Adapter::node_t node, ArchOpcode opcode,
                         AtomicWidth width, MemoryAccessKind access_kind) {
  using node_t = typename Adapter::node_t;
  auto atomic_op = selector->atomic_rmw_view(node);
  Arm64OperandGeneratorT<Adapter> g(selector);
  node_t base = atomic_op.base();
  node_t index = atomic_op.index();
  node_t value = atomic_op.value();
  InstructionOperand inputs[] = {g.UseRegister(base), g.UseRegister(index),
                                 g.UseUniqueRegister(value)};
  InstructionOperand outputs[] = {g.DefineAsRegister(node)};
  InstructionCode code = opcode | AddressingModeField::encode(kMode_MRR) |
                         AtomicWidthField::encode(width);
  if (access_kind == MemoryAccessKind::kProtectedByTrapHandler) {
    code |= AccessModeField::encode(kMemoryAccessProtectedMemOutOfBounds);
  }
  if (CpuFeatures::IsSupported(LSE)) {
    InstructionOperand temps[] = {g.TempRegister()};
    selector->Emit(code, arraysize(outputs), outputs, arraysize(inputs), inputs,
                   arraysize(temps), temps);
  } else {
    InstructionOperand temps[] = {g.TempRegister(), g.TempRegister()};
    selector->Emit(code, arraysize(outputs), outputs, arraysize(inputs), inputs,
                   arraysize(temps), temps);
  }
}

template <typename Adapter>
void VisitAtomicCompareExchange(InstructionSelectorT<Adapter>* selector,
                                typename Adapter::node_t node,
                                ArchOpcode opcode, AtomicWidth width,
                                MemoryAccessKind access_kind) {
  using node_t = typename Adapter::node_t;
  Arm64OperandGeneratorT<Adapter> g(selector);
  auto atomic_op = selector->atomic_rmw_view(node);
  node_t base = atomic_op.base();
  node_t index = atomic_op.index();
  node_t old_value = atomic_op.expected();
  node_t new_value = atomic_op.value();
  InstructionOperand inputs[] = {g.UseRegister(base), g.UseRegister(index),
                                 g.UseUniqueRegister(old_value),
                                 g.UseUniqueRegister(new_value)};
  InstructionOperand outputs[1];
  InstructionCode code = opcode | AddressingModeField::encode(kMode_MRR) |
                         AtomicWidthField::encode(width);
  if (access_kind == MemoryAccessKind::kProtectedByTrapHandler) {
    code |= AccessModeField::encode(kMemoryAccessProtectedMemOutOfBounds);
  }
  if (CpuFeatures::IsSupported(LSE)) {
    InstructionOperand temps[] = {g.TempRegister()};
    outputs[0] = g.DefineSameAsInput(node, 2);
    selector->Emit(code, arraysize(outputs), outputs, arraysize(inputs), inputs,
                   arraysize(temps), temps);
  } else {
    InstructionOperand temps[] = {g.TempRegister(), g.TempRegister()};
    outputs[0] = g.DefineAsRegister(node);
    selector->Emit(code, arraysize(outputs), outputs, arraysize(inputs), inputs,
                   arraysize(temps), temps);
  }
}

template <typename Adapter>
void VisitAtomicLoad(InstructionSelectorT<Adapter>* selector,
                     typename Adapter::node_t node, AtomicWidth width) {
  using node_t = typename Adapter::node_t;
  Arm64OperandGeneratorT<Adapter> g(selector);
  auto load = selector->load_view(node);
  node_t base = load.base();
  node_t index = load.index();
  InstructionOperand inputs[] = {g.UseRegister(base), g.UseRegister(index)};
  InstructionOperand outputs[] = {g.DefineAsRegister(node)};
  InstructionOperand temps[] = {g.TempRegister()};

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
      code = kArm64Word64AtomicLoadUint64;
      break;
#ifdef V8_COMPRESS_POINTERS
    case MachineRepresentation::kTaggedSigned:
      code = kArm64LdarDecompressTaggedSigned;
      break;
    case MachineRepresentation::kTaggedPointer:
      code = kArm64LdarDecompressTagged;
      break;
    case MachineRepresentation::kTagged:
      code = kArm64LdarDecompressTagged;
      break;
#else
    case MachineRepresentation::kTaggedSigned:   // Fall through.
    case MachineRepresentation::kTaggedPointer:  // Fall through.
    case MachineRepresentation::kTagged:
      if (kTaggedSize == 8) {
        code = kArm64Word64AtomicLoadUint64;
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

  code |=
      AddressingModeField::encode(kMode_MRR) | AtomicWidthField::encode(width);
  selector->Emit(code, arraysize(outputs), outputs, arraysize(inputs), inputs,
                 arraysize(temps), temps);
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
  Arm64OperandGeneratorT<Adapter> g(selector);
  auto store = selector->store_view(node);
  node_t base = store.base();
  node_t index = selector->value(store.index());
  node_t value = store.value();
  DCHECK_EQ(store.displacement(), 0);

  // The memory order is ignored as both release and sequentially consistent
  // stores can emit STLR.
  // https://www.cl.cam.ac.uk/~pes20/cpp/cpp0xmappings.html
  AtomicStoreParameters store_params = AtomicStoreParametersOf(selector, node);
  WriteBarrierKind write_barrier_kind = store_params.write_barrier_kind();
  MachineRepresentation rep = store_params.representation();

  if (v8_flags.enable_unconditional_write_barriers &&
      CanBeTaggedOrCompressedPointer(rep)) {
    write_barrier_kind = kFullWriteBarrier;
  }

  InstructionOperand inputs[] = {g.UseRegister(base), g.UseRegister(index),
                                 g.UseUniqueRegister(value)};
  InstructionOperand temps[] = {g.TempRegister()};
  InstructionCode code;

  if (write_barrier_kind != kNoWriteBarrier &&
      !v8_flags.disable_write_barriers) {
    DCHECK(CanBeTaggedOrCompressedPointer(rep));
    DCHECK_EQ(AtomicWidthSize(width), kTaggedSize);

    RecordWriteMode record_write_mode =
        WriteBarrierKindToRecordWriteMode(write_barrier_kind);
    code = kArchAtomicStoreWithWriteBarrier;
    code |= RecordWriteModeField::encode(record_write_mode);
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
        code = kArm64Word64AtomicStoreWord64;
        break;
      case MachineRepresentation::kTaggedSigned:   // Fall through.
      case MachineRepresentation::kTaggedPointer:  // Fall through.
      case MachineRepresentation::kTagged:
        DCHECK_EQ(AtomicWidthSize(width), kTaggedSize);
        code = kArm64StlrCompressTagged;
        break;
      case MachineRepresentation::kCompressedPointer:  // Fall through.
      case MachineRepresentation::kCompressed:
        CHECK(COMPRESS_POINTERS_BOOL);
        DCHECK_EQ(width, AtomicWidth::kWord32);
        code = kArm64StlrCompressTagged;
        break;
      default:
        UNREACHABLE();
    }
    code |= AtomicWidthField::encode(width);
  }

  if (store_params.kind() == MemoryAccessKind::kProtectedByTrapHandler) {
    code |= AccessModeField::encode(kMemoryAccessProtectedMemOutOfBounds);
  }

  code |= AddressingModeField::encode(kMode_MRR);
  selector->Emit(code, 0, nullptr, arraysize(inputs), inputs, arraysize(temps),
                 temps);
}

template <typename Adapter>
void VisitAtomicBinop(InstructionSelectorT<Adapter>* selector,
                      typename Adapter::node_t node, ArchOpcode opcode,
                      AtomicWidth width, MemoryAccessKind access_kind) {
  using node_t = typename Adapter::node_t;
  Arm64OperandGeneratorT<Adapter> g(selector);
  auto atomic_op = selector->atomic_rmw_view(node);
  node_t base = atomic_op.base();
  node_t index = atomic_op.index();
  node_t value = atomic_op.value();
  AddressingMode addressing_mode = kMode_MRR;
  InstructionOperand inputs[] = {g.UseRegister(base), g.UseRegister(index),
                                 g.UseUniqueRegister(value)};
  InstructionOperand outputs[] = {g.DefineAsRegister(node)};
  InstructionCode code = opcode | AddressingModeField::encode(addressing_mode) |
                         AtomicWidthField::encode(width);
  if (access_kind == MemoryAccessKind::kProtectedByTrapHandler) {
    code |= AccessModeField::encode(kMemoryAccessProtectedMemOutOfBounds);
  }

  if (CpuFeatures::IsSupported(LSE)) {
    InstructionOperand temps[] = {g.TempRegister()};
    selector->Emit(code, arraysize(outputs), outputs, arraysize(inputs), inputs,
                   arraysize(temps), temps);
  } else {
    InstructionOperand temps[] = {g.TempRegister(), g.TempRegister(),
                                  g.TempRegister()};
    selector->Emit(code, arraysize(outputs), outputs, arraysize(inputs), inputs,
                   arraysize(temps), temps);
  }
}

}  // namespace

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitWordCompareZero(
    node_t user, node_t value, FlagsContinuation* cont) {
  {
    Arm64OperandGeneratorT<TurbofanAdapter> g(this);
    // Try to combine with comparisons against 0 by simply inverting the branch.
    while (value->opcode() == IrOpcode::kWord32Equal && CanCover(user, value)) {
      Int32BinopMatcher m(value);
      if (!m.right().Is(0)) break;

      user = value;
      value = m.left().node();
      cont->Negate();
    }

    // Try to match bit checks to create TBZ/TBNZ instructions.
    // Unlike the switch below, CanCover check is not needed here.
    // If there are several uses of the given operation, we will generate a TBZ
    // instruction for each. This is useful even if there are other uses of the
    // arithmetic result, because it moves dependencies further back.
    switch (value->opcode()) {
      case IrOpcode::kWord64Equal: {
        Int64BinopMatcher m(value);
        if (m.right().Is(0)) {
          Node* const left = m.left().node();
          if (left->opcode() == IrOpcode::kWord64And) {
            // Attempt to merge the Word64Equal(Word64And(x, y), 0) comparison
            // into a tbz/tbnz instruction.
            TestAndBranchMatcher<TurbofanAdapter, Uint64BinopMatcher> tbm(left,
                                                                          cont);
            if (tbm.Matches()) {
              Arm64OperandGeneratorT<TurbofanAdapter> gen(this);
              cont->OverwriteAndNegateIfEqual(kEqual);
              this->EmitWithContinuation(kArm64TestAndBranch,
                                         gen.UseRegister(tbm.input()),
                                         gen.TempImmediate(tbm.bit()), cont);
              return;
            }
          }
        }
        break;
      }
      case IrOpcode::kWord32And: {
        TestAndBranchMatcher<TurbofanAdapter, Uint32BinopMatcher> tbm(value,
                                                                      cont);
        if (tbm.Matches()) {
          Arm64OperandGeneratorT<TurbofanAdapter> gen(this);
          this->EmitWithContinuation(kArm64TestAndBranch32,
                                     gen.UseRegister(tbm.input()),
                                     gen.TempImmediate(tbm.bit()), cont);
          return;
        }
        break;
      }
      case IrOpcode::kWord64And: {
        TestAndBranchMatcher<TurbofanAdapter, Uint64BinopMatcher> tbm(value,
                                                                      cont);
        if (tbm.Matches()) {
          Arm64OperandGeneratorT<TurbofanAdapter> gen(this);
          this->EmitWithContinuation(kArm64TestAndBranch,
                                     gen.UseRegister(tbm.input()),
                                     gen.TempImmediate(tbm.bit()), cont);
          return;
        }
        break;
      }
      default:
        break;
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
        case IrOpcode::kWord64Equal: {
          cont->OverwriteAndNegateIfEqual(kEqual);
          Int64BinopMatcher m(value);
          if (m.right().Is(0)) {
            Node* const left = m.left().node();
            if (CanCover(value, left) &&
                left->opcode() == IrOpcode::kWord64And) {
              return VisitWordCompare(this, left, kArm64Tst, cont,
                                      kLogical64Imm);
            }
          }
          return VisitWordCompare(this, value, kArm64Cmp, cont, kArithmeticImm);
        }
        case IrOpcode::kInt64LessThan:
          cont->OverwriteAndNegateIfEqual(kSignedLessThan);
          return VisitWordCompare(this, value, kArm64Cmp, cont, kArithmeticImm);
        case IrOpcode::kInt64LessThanOrEqual:
          cont->OverwriteAndNegateIfEqual(kSignedLessThanOrEqual);
          return VisitWordCompare(this, value, kArm64Cmp, cont, kArithmeticImm);
        case IrOpcode::kUint64LessThan:
          cont->OverwriteAndNegateIfEqual(kUnsignedLessThan);
          return VisitWordCompare(this, value, kArm64Cmp, cont, kArithmeticImm);
        case IrOpcode::kUint64LessThanOrEqual:
          cont->OverwriteAndNegateIfEqual(kUnsignedLessThanOrEqual);
          return VisitWordCompare(this, value, kArm64Cmp, cont, kArithmeticImm);
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
            if (result == nullptr || IsDefined(result)) {
              switch (node->opcode()) {
                case IrOpcode::kInt32AddWithOverflow:
                  cont->OverwriteAndNegateIfEqual(kOverflow);
                  return VisitBinop<TurbofanAdapter, Int32BinopMatcher>(
                      this, node, kArm64Add32, kArithmeticImm, cont);
                case IrOpcode::kInt32SubWithOverflow:
                  cont->OverwriteAndNegateIfEqual(kOverflow);
                  return VisitBinop<TurbofanAdapter, Int32BinopMatcher>(
                      this, node, kArm64Sub32, kArithmeticImm, cont);
                case IrOpcode::kInt32MulWithOverflow:
                  // ARM64 doesn't set the overflow flag for multiplication, so
                  // we need to test on kNotEqual. Here is the code sequence
                  // used:
                  //   smull result, left, right
                  //   cmp result.X(), Operand(result, SXTW)
                  cont->OverwriteAndNegateIfEqual(kNotEqual);
                  return EmitInt32MulWithOverflow(this, node, cont);
                case IrOpcode::kInt64AddWithOverflow:
                  cont->OverwriteAndNegateIfEqual(kOverflow);
                  return VisitBinop<TurbofanAdapter, Int64BinopMatcher>(
                      this, node, kArm64Add, kArithmeticImm, cont);
                case IrOpcode::kInt64SubWithOverflow:
                  cont->OverwriteAndNegateIfEqual(kOverflow);
                  return VisitBinop<TurbofanAdapter, Int64BinopMatcher>(
                      this, node, kArm64Sub, kArithmeticImm, cont);
                case IrOpcode::kInt64MulWithOverflow:
                  // ARM64 doesn't set the overflow flag for multiplication, so
                  // we need to test on kNotEqual. Here is the code sequence
                  // used:
                  //   mul result, left, right
                  //   smulh high, left, right
                  //   cmp high, result, asr 63
                  cont->OverwriteAndNegateIfEqual(kNotEqual);
                  return EmitInt64MulWithOverflow(this, node, cont);
                default:
                  break;
              }
            }
          }
          break;
        case IrOpcode::kInt32Add:
          return VisitWordCompare(this, value, kArm64Cmn32, cont,
                                  kArithmeticImm);
        case IrOpcode::kInt32Sub:
          return VisitWord32Compare(this, value, cont);
        case IrOpcode::kWord32And:
          return VisitWordCompare(this, value, kArm64Tst32, cont,
                                  kLogical32Imm);
        case IrOpcode::kWord64And:
          return VisitWordCompare(this, value, kArm64Tst, cont, kLogical64Imm);
        case IrOpcode::kStackPointerGreaterThan:
```