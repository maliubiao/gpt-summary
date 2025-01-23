Response: The user is asking for a summary of the functionality of the provided C++ code snippet. This is the fourth part of a six-part file. The code seems to be responsible for selecting ARM64 instructions based on the high-level operations represented by the input `node`. It deals with various arithmetic, comparison, and bitwise operations on different data types (integers and floats). It also handles atomic operations.

Here's a breakdown of the thinking process to arrive at the summary:

1. **Identify the Core Task:** The file name `instruction-selector-arm64.cc` immediately suggests that this code selects ARM64 instructions. The function signatures like `VisitWordCompare`, `VisitFloat32Compare`, and `VisitAtomicExchange` reinforce this.

2. **Recognize the Context:** The code uses templates with `Adapter` suggesting it's part of a larger system where different adapters might be used (likely for different compilation phases or intermediate representations). The presence of both `TurbofanAdapter` and `TurboshaftAdapter` confirms this.

3. **Analyze the Function Names:** The names of the `Visit...` functions are highly descriptive. They indicate the kind of operation being handled (e.g., `WordCompare`, `Float32Compare`, `AtomicExchange`). This provides a high-level overview of the file's responsibilities.

4. **Examine the Logic Within Functions:**  Looking at the `VisitCompare` family of functions reveals that they take a `FlagsContinuation` argument. This suggests these functions are involved in setting processor flags and handling conditional branching. The code tries to optimize comparisons, for example, by using `cbz`/`tbz` instructions for comparisons against zero or bit tests.

5. **Identify Data Types:** The function names and the use of `Int32BinopMatcher`, `Float64BinopMatcher` etc., indicate that the code handles different data types: 32-bit and 64-bit integers, and single and double-precision floating-point numbers.

6. **Note Specific Optimizations:** The code includes checks for specific patterns, like comparisons against zero after an addition or AND operation, or comparisons with a negated right operand. This suggests performance optimization is a goal.

7. **Recognize Atomic Operations:** The `VisitAtomic...` functions deal with atomic memory operations like exchange, compare-and-exchange, load, and store. This indicates support for multi-threading and concurrency.

8. **Pay Attention to Template Specializations:** The specializations for `TurbofanAdapter` and `TurboshaftAdapter` within `VisitWordCompareZero` and `VisitWord32Equal` highlight differences in how these two adapters handle instruction selection for the same high-level operations. This likely reflects different internal representations and optimization strategies in the two systems.

9. **Look for Connections to JavaScript:** The presence of "Tagged" representations in the atomic load/store functions (e.g., `kArm64LdarDecompressTagged`) hints at a connection to JavaScript's tagged pointers. This is a key area where the compiler interacts with JavaScript's runtime representation.

10. **Formulate the Summary:** Based on the above observations, construct a summary that covers the main functionalities: instruction selection for ARM64, handling various arithmetic, comparison, and bitwise operations, supporting different data types, implementing optimizations, dealing with atomic operations, and having specific logic for Turbofan and Turboshaft.

11. **Construct the JavaScript Example:**  To illustrate the connection to JavaScript, choose a simple JavaScript comparison and show how it might be translated to a specific ARM64 comparison instruction. The `if (a == 0)` example is straightforward and demonstrates the use of a comparison instruction.

12. **Address the "Part 4 of 6" Aspect:** Acknowledge that this is part of a larger file and that other parts likely handle different aspects of instruction selection.
这个C++代码文件是V8 JavaScript引擎中用于将高级中间表示（IR）转换为ARM64架构机器指令的**指令选择器**的一部分。具体来说，这部分代码主要负责处理**比较操作**和**原子操作**的指令选择。

**功能归纳:**

1. **处理比较操作 (Comparison Operations):**
   - 针对不同的数据类型（32位和64位整数、单精度和双精度浮点数）生成相应的比较指令 (`CMP`, `TST`, `FCMP`)。
   - 能够识别并优化特定的比较模式，例如：
     - 与零的比较 (`VisitWordCompareZero`)，并尝试将其与前面的操作合并或优化为 `CBZ`/`TBNZ` 指令 (条件分支，如果为零/非零则分支)。
     - 比较结果的设置 (`VisitWord32Equal`, `VisitInt32LessThan` 等)。
     - 能够识别带有溢出检查的运算，并根据溢出结果设置标志 (`VisitInt32AddWithOverflow` 等)。
   - 支持基于位掩码的测试 (`VisitWordTest`, `VisitWord32Test`, `VisitWord64Test`)。
   - 处理浮点数的比较 (`VisitFloat32Compare`, `VisitFloat64Compare`)。
   - 支持 `switch` 语句的指令选择 (`VisitSwitch`)，可以选择生成跳转表或二分查找的实现。

2. **处理原子操作 (Atomic Operations):**
   - 提供了处理各种原子操作的函数，例如：
     - 原子交换 (`VisitAtomicExchange`)
     - 原子比较并交换 (`VisitAtomicCompareExchange`)
     - 原子加载 (`VisitAtomicLoad`)
     - 原子存储 (`VisitAtomicStore`)
     - 原子二元运算（例如，原子加法、原子与运算等，`VisitAtomicBinop`）
   - 这些原子操作支持不同的数据宽度 (`AtomicWidth`) 和内存访问模式 (`MemoryAccessKind`)。
   - 考虑了内存顺序和写屏障 (`WriteBarrierKind`)，以确保多线程环境下的正确性。
   - 针对Tagged Pointer等V8特定的数据类型进行了优化。

**与 JavaScript 的关系 (Relationship with JavaScript):**

这段代码是 JavaScript 代码执行的关键组成部分。当 JavaScript 代码中的比较操作或需要原子操作时，V8的编译器（Turbofan 或 Turboshaft）会将这些操作转换为中间表示，然后指令选择器会将这些中间表示转换为具体的ARM64指令。

**JavaScript 例子:**

```javascript
function compareNumbers(a) {
  if (a == 0) { // JavaScript 的相等比较
    console.log("a is zero");
  } else if (a < 10) { // JavaScript 的小于比较
    console.log("a is less than 10");
  }
}

let counter = 0;
function incrementCounter() {
  // 模拟原子操作 (JavaScript 本身不直接提供原子操作的语法，
  // 但可以使用 SharedArrayBuffer 和 Atomics 对象实现)
  // 这里只是一个概念性的例子
  counter++;
}
```

**对应的 ARM64 指令选择 (概念性):**

1. **`if (a == 0)`:**  `VisitWordCompareZero` 函数会被调用，最终可能生成类似以下的 ARM64 指令：
   ```assembly
   // 假设 'a' 的值在寄存器 Xn 中
   CMP Xn, #0   // 比较寄存器 Xn 的值与 0
   BEQ label_zero // 如果相等 (Zero Flag 设置)，则跳转到 label_zero
   ```

2. **`else if (a < 10)`:** `VisitInt32LessThan` 函数会被调用，最终可能生成类似以下的 ARM64 指令：
   ```assembly
   // 假设 'a' 的值在寄存器 Xn 中
   CMP Xn, #10  // 比较寄存器 Xn 的值与 10
   BLT label_less_than_ten // 如果小于 (LessThan Flag 设置)，则跳转到 label_less_than_ten
   ```

3. **`counter++;` (概念性的原子操作):** 如果 `counter` 存储在共享内存中，并且使用了 `Atomics` 对象，则 `VisitAtomicBinop` (或类似的原子操作处理函数) 会被调用，可能生成类似以下的 ARM64 指令（以原子加法为例）：
   ```assembly
   // 假设 counter 的内存地址在寄存器 Xm 中，增量为 1
   LDADD Wzr, Wt, [Xm] // 原子地将寄存器 Wt 的值加到内存地址 Xm 的值上
                        // Wzr 通常用于丢弃旧值，Wt 存储增量值 (这里是 1)
   ```

**总结:**

这部分 `instruction-selector-arm64.cc` 代码的核心功能是根据 JavaScript 代码生成的中间表示，为 ARM64 架构选择合适的机器指令，特别是针对比较操作和原子操作，确保 JavaScript 代码能够在 ARM64 平台上高效且正确地执行。它是 V8 编译器将高级语言转换为底层机器码的关键环节。

作为第 4 部分，它很可能依赖于之前的部分（例如，处理算术运算、加载存储等），并为后续部分（例如，生成最终的代码、处理调用等）提供基础。

### 提示词
```
这是目录为v8/src/compiler/backend/arm64/instruction-selector-arm64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第4部分，共6部分，请归纳一下它的功能
```

### 源代码
```
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
          cont->OverwriteAndNegateIfEqual(kStackPointerGreaterThanCondition);
          return VisitStackPointerGreaterThan(value, cont);
        default:
          break;
      }
    }

    // Branch could not be combined with a compare, compare against 0 and
    // branch.
    if (cont->IsBranch()) {
      Emit(cont->Encode(kArm64CompareAndBranch32), g.NoOutput(),
           g.UseRegister(value), g.Label(cont->true_block()),
           g.Label(cont->false_block()));
    } else {
      VisitCompare(this, cont->Encode(kArm64Tst32), g.UseRegister(value),
                   g.UseRegister(value), cont);
    }
  }
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitWordCompareZero(
    node_t user, node_t value, FlagsContinuation* cont) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  Arm64OperandGeneratorT<TurboshaftAdapter> g(this);
  // Try to combine with comparisons against 0 by simply inverting the branch.
  ConsumeEqualZero(&user, &value, cont);

  // Remove Word64->Word32 truncation.
  if (this->is_truncate_word64_to_word32(value) && CanCover(user, value)) {
    user = value;
    value = this->remove_truncate_word64_to_word32(value);
  }

  // Try to match bit checks to create TBZ/TBNZ instructions.
  // Unlike the switch below, CanCover check is not needed here.
  // If there are several uses of the given operation, we will generate a TBZ
  // instruction for each. This is useful even if there are other uses of the
  // arithmetic result, because it moves dependencies further back.
  const Operation& value_op = Get(value);

  if (cont->IsBranch()) {
    if (value_op.Is<Opmask::kWord64Equal>()) {
      const ComparisonOp& equal = value_op.Cast<ComparisonOp>();
      if (MatchIntegralZero(equal.right())) {
        const WordBinopOp* left_binop =
            Get(equal.left()).TryCast<WordBinopOp>();
        if (left_binop) {
          TestAndBranchMatcherTurboshaft matcher(this, *left_binop);
          if (matcher.Matches()) {
            // If the mask has only one bit set, we can use tbz/tbnz.
            DCHECK((cont->condition() == kEqual) ||
                   (cont->condition() == kNotEqual));
            Arm64OperandGeneratorT<TurboshaftAdapter> gen(this);
            cont->OverwriteAndNegateIfEqual(kEqual);
            EmitWithContinuation(kArm64TestAndBranch,
                                 gen.UseRegister(left_binop->left()),
                                 gen.TempImmediate(matcher.bit()), cont);
            return;
          }
        }
      }
    }

    if (const WordBinopOp* value_binop = value_op.TryCast<WordBinopOp>()) {
      TestAndBranchMatcherTurboshaft matcher(this, *value_binop);
      if (matcher.Matches()) {
        // If the mask has only one bit set, we can use tbz/tbnz.
        DCHECK((cont->condition() == kEqual) ||
               (cont->condition() == kNotEqual));
        InstructionCode opcode = value_binop->rep.MapTaggedToWord() ==
                                         RegisterRepresentation::Word32()
                                     ? kArm64TestAndBranch32
                                     : kArm64TestAndBranch;
        Arm64OperandGeneratorT<TurboshaftAdapter> gen(this);
        EmitWithContinuation(opcode, gen.UseRegister(value_binop->left()),
                             gen.TempImmediate(matcher.bit()), cont);
        return;
      }
    }
  }

  if (CanCover(user, value)) {
    if (const ComparisonOp* comparison = value_op.TryCast<ComparisonOp>()) {
      switch (comparison->rep.MapTaggedToWord().value()) {
        case RegisterRepresentation::Word32():
          cont->OverwriteAndNegateIfEqual(
              GetComparisonFlagCondition(*comparison));
          return VisitWord32Compare(this, value, cont);

        case RegisterRepresentation::Word64():
          cont->OverwriteAndNegateIfEqual(
              GetComparisonFlagCondition(*comparison));

          if (comparison->kind == ComparisonOp::Kind::kEqual) {
            const Operation& left_op = Get(comparison->left());
            if (MatchIntegralZero(comparison->right()) &&
                left_op.Is<Opmask::kWord64BitwiseAnd>() &&
                CanCover(value, comparison->left())) {
              return VisitWordCompare(this, comparison->left(), kArm64Tst, cont,
                                      kLogical64Imm);
            }
          }
          return VisitWordCompare(this, value, kArm64Cmp, cont, kArithmeticImm);

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
                return VisitBinop(this, node, binop->rep,
                                  is64 ? kArm64Add : kArm64Add32,
                                  kArithmeticImm, cont);
              case OverflowCheckedBinopOp::Kind::kSignedSub:
                cont->OverwriteAndNegateIfEqual(kOverflow);
                return VisitBinop(this, node, binop->rep,
                                  is64 ? kArm64Sub : kArm64Sub32,
                                  kArithmeticImm, cont);
              case OverflowCheckedBinopOp::Kind::kSignedMul:
                if (is64) {
                  // ARM64 doesn't set the overflow flag for multiplication, so
                  // we need to test on kNotEqual. Here is the code sequence
                  // used:
                  //   mul result, left, right
                  //   smulh high, left, right
                  //   cmp high, result, asr 63
                  cont->OverwriteAndNegateIfEqual(kNotEqual);
                  return EmitInt64MulWithOverflow(this, node, cont);
                } else {
                  // ARM64 doesn't set the overflow flag for multiplication, so
                  // we need to test on kNotEqual. Here is the code sequence
                  // used:
                  //   smull result, left, right
                  //   cmp result.X(), Operand(result, SXTW)
                  cont->OverwriteAndNegateIfEqual(kNotEqual);
                  return EmitInt32MulWithOverflow(this, node, cont);
                }
            }
          }
        }
      }
    } else if (value_op.Is<Opmask::kWord32Add>()) {
      return VisitWordCompare(this, value, kArm64Cmn32, cont, kArithmeticImm);
    } else if (value_op.Is<Opmask::kWord32Sub>()) {
      return VisitWord32Compare(this, value, cont);
    } else if (value_op.Is<Opmask::kWord32BitwiseAnd>()) {
      if (TryMatchConditionalCompareChainBranch(this, zone(), value, cont)) {
        return;
      }
      return VisitWordCompare(this, value, kArm64Tst32, cont, kLogical32Imm);
    } else if (value_op.Is<Opmask::kWord64BitwiseAnd>()) {
      return VisitWordCompare(this, value, kArm64Tst, cont, kLogical64Imm);
    } else if (value_op.Is<Opmask::kWord32BitwiseOr>()) {
      if (TryMatchConditionalCompareChainBranch(this, zone(), value, cont)) {
        return;
      }
    } else if (value_op.Is<StackPointerGreaterThanOp>()) {
      cont->OverwriteAndNegateIfEqual(kStackPointerGreaterThanCondition);
      return VisitStackPointerGreaterThan(value, cont);
    }
  }

  // Branch could not be combined with a compare, compare against 0 and
  // branch.
  if (cont->IsBranch()) {
    Emit(cont->Encode(kArm64CompareAndBranch32), g.NoOutput(),
         g.UseRegister(value), g.Label(cont->true_block()),
         g.Label(cont->false_block()));
  } else {
    VisitCompare(this, cont->Encode(kArm64Tst32), g.UseRegister(value),
                 g.UseRegister(value), cont);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitSwitch(node_t node,
                                                const SwitchInfo& sw) {
  Arm64OperandGeneratorT<Adapter> g(this);
  InstructionOperand value_operand = g.UseRegister(this->input_at(node, 0));

  // Emit either ArchTableSwitch or ArchBinarySearchSwitch.
  if (enable_switch_jump_table_ ==
      InstructionSelector::kEnableSwitchJumpTable) {
    static const size_t kMaxTableSwitchValueRange = 2 << 16;
    size_t table_space_cost = 4 + sw.value_range();
    size_t table_time_cost = 3;
    size_t lookup_space_cost = 3 + 2 * sw.case_count();
    size_t lookup_time_cost = sw.case_count();
    if (sw.case_count() > 4 &&
        table_space_cost + 3 * table_time_cost <=
            lookup_space_cost + 3 * lookup_time_cost &&
        sw.min_value() > std::numeric_limits<int32_t>::min() &&
        sw.value_range() <= kMaxTableSwitchValueRange) {
      InstructionOperand index_operand = value_operand;
      if (sw.min_value()) {
        index_operand = g.TempRegister();
        Emit(kArm64Sub32, index_operand, value_operand,
             g.TempImmediate(sw.min_value()));
      } else {
        // Smis top bits are undefined, so zero-extend if not already done so.
        if (!ZeroExtendsWord32ToWord64(this->input_at(node, 0))) {
          index_operand = g.TempRegister();
          Emit(kArm64Mov32, index_operand, value_operand);
        }
      }
      // Generate a table lookup.
      return EmitTableSwitch(sw, index_operand);
    }
  }

  // Generate a tree of conditional jumps.
  return EmitBinarySearchSwitch(sw, value_operand);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitWord32Equal(node_t node) {
  {
    Node* const user = node;
    FlagsContinuation cont = FlagsContinuation::ForSet(kEqual, node);
    Int32BinopMatcher m(user);
    if (m.right().Is(0)) {
      Node* const value = m.left().node();
      if (CanCover(user, value)) {
        switch (value->opcode()) {
          case IrOpcode::kInt32Add:
          case IrOpcode::kWord32And:
            return VisitWord32Compare(this, node, &cont);
          case IrOpcode::kInt32Sub:
            return VisitWordCompare(this, value, kArm64Cmp32, &cont,
                                    kArithmeticImm);
          case IrOpcode::kWord32Equal: {
            // Word32Equal(Word32Equal(x, y), 0) => Word32Compare(x, y, ne).
            Int32BinopMatcher mequal(value);
            node->ReplaceInput(0, mequal.left().node());
            node->ReplaceInput(1, mequal.right().node());
            cont.Negate();
            // {node} still does not cover its new operands, because {mequal} is
            // still using them.
            // Since we won't generate any more code for {mequal}, set its
            // operands to zero to make sure {node} can cover them.
            // This improves pattern matching in VisitWord32Compare.
            mequal.node()->ReplaceInput(0, m.right().node());
            mequal.node()->ReplaceInput(1, m.right().node());
            return VisitWord32Compare(this, node, &cont);
          }
          default:
            break;
        }
        return VisitWord32Test(this, value, &cont);
      }
    }

    if (isolate() && (V8_STATIC_ROOTS_BOOL ||
                      (COMPRESS_POINTERS_BOOL && !isolate()->bootstrapper()))) {
      Arm64OperandGeneratorT<TurbofanAdapter> g(this);
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
          if (g.CanBeImmediate(ptr, ImmediateMode::kArithmeticImm)) {
            return VisitCompare(this, kArm64Cmp32, g.UseRegister(left),
                                g.TempImmediate(ptr), &cont);
          }
        }
      }
    }

    VisitWord32Compare(this, node, &cont);
  }
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
    OpIndex value = left;
    if (CanCover(user, value)) {
      const Operation& value_op = Get(value);
      if (value_op.Is<Opmask::kWord32Add>() ||
          value_op.Is<Opmask::kWord32BitwiseAnd>()) {
        return VisitWord32Compare(this, node, &cont);
      }
      if (value_op.Is<Opmask::kWord32Sub>()) {
        return VisitWordCompare(this, value, kArm64Cmp32, &cont,
                                kArithmeticImm);
      }
      if (value_op.Is<Opmask::kWord32Equal>()) {
        // Word32Equal(Word32Equal(x, y), 0) => Word32Compare(x, y, ne).
        // A new FlagsContinuation is needed as instead of generating the result
        // for {node}, it is generated for {value}.
        FlagsContinuation cont = FlagsContinuation::ForSet(kEqual, value);
        cont.Negate();
        VisitWord32Compare(this, value, &cont);
        EmitIdentity(node);
        return;
      }
      return VisitWord32Test(this, value, &cont);
    }
  }

  if (isolate() && (V8_STATIC_ROOTS_BOOL ||
                    (COMPRESS_POINTERS_BOOL && !isolate()->bootstrapper()))) {
    Arm64OperandGeneratorT<TurboshaftAdapter> g(this);
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
        if (g.CanBeImmediate(ptr, ImmediateMode::kArithmeticImm)) {
          return VisitCompare(this, kArm64Cmp32, g.UseRegister(left),
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
void InstructionSelectorT<Adapter>::VisitWord64Equal(node_t node) {
  FlagsContinuation cont = FlagsContinuation::ForSet(kEqual, node);
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const ComparisonOp& equal = this->Get(node).template Cast<ComparisonOp>();
    DCHECK_EQ(equal.kind, ComparisonOp::Kind::kEqual);
    if (this->MatchIntegralZero(equal.right()) &&
        CanCover(node, equal.left())) {
      if (this->Get(equal.left()).template Is<Opmask::kWord64BitwiseAnd>()) {
        return VisitWordCompare(this, equal.left(), kArm64Tst, &cont,
                                kLogical64Imm);
      }
      return VisitWord64Test(this, equal.left(), &cont);
    }
    VisitWordCompare(this, node, kArm64Cmp, &cont, kArithmeticImm);
  } else {
    Node* const user = node;
    Int64BinopMatcher m(user);
    if (m.right().Is(0)) {
      Node* const value = m.left().node();
      if (CanCover(user, value)) {
        switch (value->opcode()) {
          case IrOpcode::kWord64And:
            return VisitWordCompare(this, value, kArm64Tst, &cont,
                                    kLogical64Imm);
          default:
            break;
        }
        return VisitWord64Test(this, value, &cont);
      }
    }
    VisitWordCompare(this, node, kArm64Cmp, &cont, kArithmeticImm);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32AddWithOverflow(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    OpIndex ovf = FindProjection(node, 1);
    if (ovf.valid() && IsUsed(ovf)) {
      FlagsContinuation cont = FlagsContinuation::ForSet(kOverflow, ovf);
      return VisitBinop(this, node, RegisterRepresentation::Word32(),
                        kArm64Add32, kArithmeticImm, &cont);
    }
    FlagsContinuation cont;
    VisitBinop(this, node, RegisterRepresentation::Word32(), kArm64Add32,
               kArithmeticImm, &cont);
  } else {
    if (Node* ovf = NodeProperties::FindProjection(node, 1)) {
      FlagsContinuation cont = FlagsContinuation::ForSet(kOverflow, ovf);
      return VisitBinop<Adapter, Int32BinopMatcher>(this, node, kArm64Add32,
                                                    kArithmeticImm, &cont);
    }
    FlagsContinuation cont;
    VisitBinop<Adapter, Int32BinopMatcher>(this, node, kArm64Add32,
                                           kArithmeticImm, &cont);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32SubWithOverflow(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    OpIndex ovf = FindProjection(node, 1);
    if (ovf.valid()) {
      FlagsContinuation cont = FlagsContinuation::ForSet(kOverflow, ovf);
      return VisitBinop(this, node, RegisterRepresentation::Word32(),
                        kArm64Sub32, kArithmeticImm, &cont);
    }
    FlagsContinuation cont;
    VisitBinop(this, node, RegisterRepresentation::Word32(), kArm64Sub32,
               kArithmeticImm, &cont);
  } else {
    if (Node* ovf = NodeProperties::FindProjection(node, 1)) {
      FlagsContinuation cont = FlagsContinuation::ForSet(kOverflow, ovf);
      return VisitBinop<Adapter, Int32BinopMatcher>(this, node, kArm64Sub32,
                                                    kArithmeticImm, &cont);
    }
    FlagsContinuation cont;
    VisitBinop<Adapter, Int32BinopMatcher>(this, node, kArm64Sub32,
                                           kArithmeticImm, &cont);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32MulWithOverflow(node_t node) {
  node_t ovf = FindProjection(node, 1);
  if (this->valid(ovf)) {
    // ARM64 doesn't set the overflow flag for multiplication, so we need to
    // test on kNotEqual. Here is the code sequence used:
    //   smull result, left, right
    //   cmp result.X(), Operand(result, SXTW)
    FlagsContinuation cont = FlagsContinuation::ForSet(kNotEqual, ovf);
    return EmitInt32MulWithOverflow(this, node, &cont);
  }
  FlagsContinuation cont;
  EmitInt32MulWithOverflow(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt64AddWithOverflow(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    OpIndex ovf = FindProjection(node, 1);
    if (ovf.valid()) {
      FlagsContinuation cont = FlagsContinuation::ForSet(kOverflow, ovf);
      return VisitBinop(this, node, RegisterRepresentation::Word64(), kArm64Add,
                        kArithmeticImm, &cont);
    }
    FlagsContinuation cont;
    VisitBinop(this, node, RegisterRepresentation::Word64(), kArm64Add,
               kArithmeticImm, &cont);
  } else {
    if (Node* ovf = NodeProperties::FindProjection(node, 1)) {
      FlagsContinuation cont = FlagsContinuation::ForSet(kOverflow, ovf);
      return VisitBinop<Adapter, Int64BinopMatcher>(this, node, kArm64Add,
                                                    kArithmeticImm, &cont);
    }
    FlagsContinuation cont;
    VisitBinop<Adapter, Int64BinopMatcher>(this, node, kArm64Add,
                                           kArithmeticImm, &cont);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt64SubWithOverflow(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    OpIndex ovf = FindProjection(node, 1);
    if (ovf.valid()) {
      FlagsContinuation cont = FlagsContinuation::ForSet(kOverflow, ovf);
      return VisitBinop(this, node, RegisterRepresentation::Word64(), kArm64Sub,
                        kArithmeticImm, &cont);
    }
    FlagsContinuation cont;
    VisitBinop(this, node, RegisterRepresentation::Word64(), kArm64Sub,
               kArithmeticImm, &cont);
  } else {
    if (Node* ovf = NodeProperties::FindProjection(node, 1)) {
      FlagsContinuation cont = FlagsContinuation::ForSet(kOverflow, ovf);
      return VisitBinop<Adapter, Int64BinopMatcher>(this, node, kArm64Sub,
                                                    kArithmeticImm, &cont);
    }
    FlagsContinuation cont;
    VisitBinop<Adapter, Int64BinopMatcher>(this, node, kArm64Sub,
                                           kArithmeticImm, &cont);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt64MulWithOverflow(node_t node) {
  node_t ovf = FindProjection(node, 1);
  if (this->valid(ovf)) {
    // ARM64 doesn't set the overflow flag for multiplication, so we need to
    // test on kNotEqual. Here is the code sequence used:
    //   mul result, left, right
    //   smulh high, left, right
    //   cmp high, result, asr 63
    FlagsContinuation cont = FlagsContinuation::ForSet(kNotEqual, ovf);
    return EmitInt64MulWithOverflow(this, node, &cont);
  }
  FlagsContinuation cont;
  EmitInt64MulWithOverflow(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt64LessThan(node_t node) {
  FlagsContinuation cont = FlagsContinuation::ForSet(kSignedLessThan, node);
  VisitWordCompare(this, node, kArm64Cmp, &cont, kArithmeticImm);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt64LessThanOrEqual(node_t node) {
  FlagsContinuation cont =
      FlagsContinuation::ForSet(kSignedLessThanOrEqual, node);
  VisitWordCompare(this, node, kArm64Cmp, &cont, kArithmeticImm);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUint64LessThan(node_t node) {
  FlagsContinuation cont = FlagsContinuation::ForSet(kUnsignedLessThan, node);
  VisitWordCompare(this, node, kArm64Cmp, &cont, kArithmeticImm);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUint64LessThanOrEqual(node_t node) {
  FlagsContinuation cont =
      FlagsContinuation::ForSet(kUnsignedLessThanOrEqual, node);
  VisitWordCompare(this, node, kArm64Cmp, &cont, kArithmeticImm);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32Neg(node_t node) {
  Arm64OperandGeneratorT<Adapter> g(this);
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    OpIndex input = this->Get(node).input(0);
    const Operation& input_op = this->Get(input);
    if (input_op.Is<Opmask::kFloat32Mul>() && CanCover(node, input)) {
      const FloatBinopOp& mul = input_op.Cast<FloatBinopOp>();
      Emit(kArm64Float32Fnmul, g.DefineAsRegister(node),
           g.UseRegister(mul.left()), g.UseRegister(mul.right()));
      return;
    }
    VisitRR(this, kArm64Float32Neg, node);

  } else {
    Node* in = node->InputAt(0);
    if (in->opcode() == IrOpcode::kFloat32Mul && CanCover(node, in)) {
      Float32BinopMatcher m(in);
      Emit(kArm64Float32Fnmul, g.DefineAsRegister(node),
           g.UseRegister(m.left().node()), g.UseRegister(m.right().node()));
      return;
    }
    VisitRR(this, kArm64Float32Neg, node);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32Mul(node_t node) {
  Arm64OperandGeneratorT<Adapter> g(this);
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const FloatBinopOp& mul = this->Get(node).template Cast<FloatBinopOp>();
    const Operation& lhs = this->Get(mul.left());

    if (lhs.Is<Opmask::kFloat32Negate>() && CanCover(node, mul.left())) {
      Emit(kArm64Float32Fnmul, g.DefineAsRegister(node),
           g.UseRegister(lhs.input(0)), g.UseRegister(mul.right()));
      return;
    }

    const Operation& rhs = this->Get(mul.right());
    if (rhs.Is<Opmask::kFloat32Negate>() && CanCover(node, mul.right())) {
      Emit(kArm64Float32Fnmul, g.DefineAsRegister(node),
           g.UseRegister(rhs.input(0)), g.UseRegister(mul.left()));
      return;
    }
    return VisitRRR(this, kArm64Float32Mul, node);

  } else {
    Arm64OperandGeneratorT<Adapter> g(this);
    Float32BinopMatcher m(node);

    if (m.left().IsFloat32Neg() && CanCover(node, m.left().node())) {
      Emit(kArm64Float32Fnmul, g.DefineAsRegister(node),
           g.UseRegister(m.left().node()->InputAt(0)),
           g.UseRegister(m.right().node()));
      return;
    }

    if (m.right().IsFloat32Neg() && CanCover(node, m.right().node())) {
      Emit(kArm64Float32Fnmul, g.DefineAsRegister(node),
           g.UseRegister(m.right().node()->InputAt(0)),
           g.UseRegister(m.left().node()));
      return;
    }
    return VisitRRR(this, kArm64Float32Mul, node);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32Abs(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    Arm64OperandGeneratorT<Adapter> g(this);
    using namespace turboshaft;  // NOLINT(build/namespaces)
    OpIndex in = this->input_at(node, 0);
    const Operation& input_op = this->Get(in);
    if (input_op.Is<Opmask::kFloat32Sub>() && CanCover(node, in)) {
      const FloatBinopOp& sub = input_op.Cast<FloatBinopOp>();
      Emit(kArm64Float32Abd, g.DefineAsRegister(node),
           g.UseRegister(sub.left()), g.UseRegister(sub.right()));
      return;
    }

    return VisitRR(this, kArm64Float32Abs, node);
  } else {
    Arm64OperandGeneratorT<Adapter> g(this);
    Node* in = node->InputAt(0);
    if (in->opcode() == IrOpcode::kFloat32Sub && CanCover(node, in)) {
      Emit(kArm64Float32Abd, g.DefineAsRegister(node),
           g.UseRegister(in->InputAt(0)), g.UseRegister(in->InputAt(1)));
      return;
    }

    return VisitRR(this, kArm64Float32Abs, node);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Abs(node_t node) {
  Arm64OperandGeneratorT<Adapter> g(this);
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    OpIndex in = this->input_at(node, 0);
    const Operation& input_op = this->Get(in);
    if (input_op.Is<Opmask::kFloat64Sub>() && CanCover(node, in)) {
      const FloatBinopOp& sub = input_op.Cast<FloatBinopOp>();
      Emit(kArm64Float64Abd, g.DefineAsRegister(node),
           g.UseRegister(sub.left()), g.UseRegister(sub.right()));
      return;
    }

    return VisitRR(this, kArm64Float64Abs, node);
  } else {
    Node* in = node->InputAt(0);
    if (in->opcode() == IrOpcode::kFloat64Sub && CanCover(node, in)) {
      Emit(kArm64Float64Abd, g.DefineAsRegister(node),
           g.UseRegister(in->InputAt(0)), g.UseRegister(in->InputAt(1)));
      return;
    }

    return VisitRR(this, kArm64Float64Abs, node);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32Equal(node_t node) {
  FlagsContinuation cont = FlagsContinuation::ForSet(kEqual, node);
  VisitFloat32Compare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32LessThan(node_t node) {
  FlagsContinuation cont = FlagsContinuation::ForSet(kFloatLessThan, node);
  VisitFloat32Compare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32LessThanOrEqual(node_t node) {
  FlagsContinuation cont =
      FlagsContinuation::ForSet(kFloatLessThanOrEqual, node);
  VisitFloat32Compare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Equal(node_t node) {
  FlagsContinuation cont = FlagsContinuation::ForSet(kEqual, node);
  VisitFloat64Compare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64LessThan(node_t node) {
  FlagsContinuation cont = FlagsContinuation::ForSet(kFloatLessThan, node);
  VisitFloat64Compare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64LessThanOrEqual(node_t node) {
  FlagsContinuation cont =
      FlagsContinuation::ForSet(kFloatLessThanOrEqual, node);
  VisitFloat64Compare(this, node, &cont);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitBitcastWord32PairToFloat64(
    node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  Arm64OperandGeneratorT<TurboshaftAdapter> g(this);
  const auto& bitcast = this->Cast<BitcastWord32PairToFloat64Op>(node);
  node_t hi = bitcast.high_word32();
  node_t lo = bitcast.low_word32();

  int vreg = g.AllocateVirtualRegister();
  Emit(kArm64Bfi, g.DefineSameAsFirstForVreg(vreg), g.UseRegister(lo),
       g.UseRegister(hi), g.TempImmediate(32), g.TempImmediate(32));
  Emit(kArm64Float64MoveU64, g.DefineAsRegister(node),
       g.UseRegisterForVreg(vreg));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64InsertLowWord32(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    UNIMPLEMENTED();
  } else {
    Arm64OperandGeneratorT<Adapter> g(this);
    Node* left = node->InputAt(0);
    Node* right = node->InputAt(1);
    if (left->opcode() == IrOpcode::kFloat64InsertHighWord32 &&
        CanCover(node, left)) {
```