Response:
The user wants to understand the functionality of the `instruction-selector-mips64.cc` file in the V8 project. This is part 5 of a 6-part explanation.

Here's a plan to address the request:

1. **General Functionality:** Describe the role of an instruction selector in a compiler. Mention that this specific file is for the MIPS64 architecture.
2. **Torque Check:** Examine the file extension and confirm it's not a Torque file.
3. **JavaScript Relationship:**  Explain how the instruction selector connects high-level JavaScript code to low-level machine instructions. Provide a simple JavaScript example and how it might be translated.
4. **Code Logic Reasoning:** Select a simple function (like `VisitWord32Equal`) and illustrate its input and output based on the provided code.
5. **Common Programming Errors:** Discuss how the instruction selector helps in handling potential errors, for example, overflow conditions.
6. **Part 5 Summary:**  Focus on the types of operations handled in this specific snippet of the code, which includes comparisons, arithmetic operations (with overflow checks), and SIMD instructions. Emphasize that this is *part* of the instruction selection process.
这是 `v8/src/compiler/backend/mips64/instruction-selector-mips64.cc` 源代码的第五部分。根据你提供的代码片段，我们可以归纳一下它的功能：

**核心功能:**

这个代码片段主要负责 **为 MIPS64 架构选择合适的机器指令**，这是编译器后端的一个关键步骤。具体来说，它遍历中间代码表示（通常是抽象语法树或更底层的图结构），并针对每个操作（例如加法、比较、内存访问等）选择一条或多条对应的 MIPS64 汇编指令。

**具体功能点 (基于提供的代码片段):**

* **处理比较操作:**
    * 针对不同的比较类型 (等于、小于、大于等) 和数据类型 (32位整数、64位整数、浮点数)，选择合适的比较指令。
    * 能够将比较操作与后续的控制流操作 (例如条件跳转) 结合起来，通过 `FlagsContinuation` 实现。
    * 特别处理与零的比较，可以选择更优化的指令。
* **处理 `switch` 语句:**
    * 根据 `switch` 语句的特性 (case 数量、值范围)，决定使用跳转表 (`ArchTableSwitch`) 还是二分查找 (`ArchBinarySearchSwitch`) 来实现。
    * 涉及到一个权衡：跳转表在值范围较小且密集时效率更高，而二分查找在 case 数量较少或值范围较大时更合适。
* **处理带溢出检查的算术运算:**
    * 针对加法、减法、乘法等运算，存在带溢出检查的版本 (`VisitInt32AddWithOverflow`, `VisitInt64MulWithOverflow` 等)。
    * 这些函数会检查操作是否会发生溢出，并根据结果设置相应的标志位。
* **处理原子操作:**
    * 提供了对原子加载 (`VisitWord32AtomicLoad`, `VisitWord64AtomicLoad`) 和原子存储 (`VisitWord32AtomicStore`, `VisitWord64AtomicStore`) 的支持。
    * 实现了原子交换 (`VisitWord32AtomicExchange`, `VisitWord64AtomicExchange`) 和原子比较并交换 (`VisitWord32AtomicCompareExchange`, `VisitWord64AtomicCompareExchange`) 等更复杂的原子操作。
    * 针对不同大小的数据类型 (8位、16位、32位、64位) 选择不同的原子指令。
    * 提供了原子二元运算（加、减、与、或、异或）。
* **处理浮点数操作:**
    * 包括浮点数的比较 (`VisitFloat32Equal`, `VisitFloat64LessThan`)。
    * 以及一些特定的浮点数操作，如提取高低位 (`VisitFloat64ExtractLowWord32`, `VisitFloat64ExtractHighWord32`)，以及插入高低位 (`VisitFloat64InsertLowWord32`, `VisitFloat64InsertHighWord32`)。
* **处理 SIMD 指令:**
    * 代码中定义了大量的宏 (`SIMD_TYPE_LIST`, `SIMD_UNOP_LIST`, `SIMD_BINOP_LIST`)，用于处理 SIMD (Single Instruction, Multiple Data) 类型的操作。
    * 这些宏列出了各种 SIMD 操作及其对应的 MIPS64 指令，例如向量加法、减法、绝对值、比较等。

**关于你的问题:**

* **`.tq` 结尾:**  从提供的代码来看，`v8/src/compiler/backend/mips64/instruction-selector-mips64.cc` **不是**以 `.tq` 结尾。因此，它不是一个 V8 Torque 源代码，而是一个标准的 C++ 源代码文件。

* **与 JavaScript 的关系:**  `instruction-selector-mips64.cc` 的功能是将 V8 编译后的 JavaScript 代码 (中间表示) 转换为可以在 MIPS64 架构上执行的机器指令。例如，考虑以下 JavaScript 代码：

   ```javascript
   function compare(a, b) {
     return a > b;
   }
   ```

   当 V8 编译这个函数时，`instruction-selector-mips64.cc` 中的 `VisitInt32LessThan` (如果 `a` 和 `b` 是 32 位整数) 或类似的函数会被调用，以选择合适的 MIPS64 比较指令 (例如 `slt` 或 `sltu`)，并配合条件跳转指令来实现 `>` 的逻辑。

* **代码逻辑推理:**

   **假设输入:** 一个表示 `a == 0` 的中间代码节点，其中 `a` 是一个 32 位整数。
   **`VisitWord32Equal` 函数的行为:**
   1. `FlagsContinuation cont = FlagsContinuation::ForSet(kEqual, node);`：创建一个 `FlagsContinuation` 对象，表示比较结果将用于设置等于标志位。
   2. `Int32BinopMatcher m(node);`：尝试将节点匹配为一个二元操作，这里 `m.left()` 代表 `a`，`m.right()` 代表 `0`。
   3. `if (m.right().Is(0)) { ... }`：条件成立，因为比较的是 `0`。
   4. `return VisitWordCompareZero(m.node(), m.left().node(), &cont);`：调用 `VisitWordCompareZero` 函数，专门处理与零的比较。
   **`VisitWordCompareZero` 函数的行为:**
   5. `Mips64OperandGeneratorT<Adapter> g(this);`：创建一个操作数生成器。
   6. `InstructionOperand value_operand = g.UseRegister(value);`：将 `a` 的值加载到寄存器中。
   7. `Emit(kMips64Teqz, cont, value_operand);`：生成 MIPS64 指令 `teqz value_operand` (Test Equal Zero)，这条指令会比较 `value_operand` 是否为零，并根据结果设置标志位。

   **输出:**  生成一条 MIPS64 的 `teqz` 指令，它会检查 `a` 的值是否为零。

* **用户常见的编程错误:**

   * **整数溢出:**  用户在进行算术运算时，可能会导致结果超出数据类型的表示范围。例如：
     ```javascript
     let maxInt = 2147483647;
     let result = maxInt + 1; // 预期发生溢出
     ```
     `instruction-selector-mips64.cc` 中的 `VisitInt32AddWithOverflow` 函数会选择带有溢出检测的指令。如果检测到溢出，V8 运行时可以抛出错误或采取其他适当的措施，防止程序出现未定义的行为。

* **第 5 部分功能归纳:**

   这个代码片段（第五部分）主要集中在 **比较操作、`switch` 语句的实现、带溢出检查的整数运算、原子操作以及 SIMD 向量运算的指令选择**。它是 `instruction-selector-mips64.cc` 文件的一部分，负责将高级的程序逻辑转换为底层的 MIPS64 机器指令，确保代码能够在 MIPS64 架构上正确且高效地执行。这部分展示了指令选择器处理多种不同类型操作的能力，以及针对特定架构优化的考量 (例如针对与零比较的优化)。

### 提示词
```
这是目录为v8/src/compiler/backend/mips64/instruction-selector-mips64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/mips64/instruction-selector-mips64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
}
        }
      } else if (value_op.Is<Opmask::kWord32BitwiseAnd>() ||
                 value_op.Is<Opmask::kWord64BitwiseAnd>()) {
        VisitWordCompare(this, value, kMips64Tst, cont, true);
        return;
      } else if (value_op.Is<StackPointerGreaterThanOp>()) {
        cont->OverwriteAndNegateIfEqual(kStackPointerGreaterThanCondition);
        return VisitStackPointerGreaterThan(value, cont);
      }
    }
    // Continuation could not be combined with a compare, emit compare against
    // 0.
    EmitWordCompareZero(this, value, cont);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitSwitch(node_t node,
                                                const SwitchInfo& sw) {
  Mips64OperandGeneratorT<Adapter> g(this);
  InstructionOperand value_operand = g.UseRegister(this->input_at(node, 0));

  // Emit either ArchTableSwitch or ArchBinarySearchSwitch.
  if (enable_switch_jump_table_ ==
      InstructionSelector::kEnableSwitchJumpTable) {
    static const size_t kMaxTableSwitchValueRange = 2 << 16;
    size_t table_space_cost = 10 + 2 * sw.value_range();
    size_t table_time_cost = 3;
    size_t lookup_space_cost = 2 + 2 * sw.case_count();
    size_t lookup_time_cost = sw.case_count();
    if (sw.case_count() > 0 &&
        table_space_cost + 3 * table_time_cost <=
            lookup_space_cost + 3 * lookup_time_cost &&
        sw.min_value() > std::numeric_limits<int32_t>::min() &&
        sw.value_range() <= kMaxTableSwitchValueRange) {
      InstructionOperand index_operand = value_operand;
      if (sw.min_value()) {
        index_operand = g.TempRegister();
        Emit(kMips64Sub, index_operand, value_operand,
             g.TempImmediate(sw.min_value()));
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
  FlagsContinuation cont = FlagsContinuation::ForSet(kEqual, node);

  Int32BinopMatcher m(node);
  if (m.right().Is(0)) {
    return VisitWordCompareZero(m.node(), m.left().node(), &cont);
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
      return VisitBinop(this, node, kMips64Dadd, &cont);
    }
  } else {
    if (Node* ovf = NodeProperties::FindProjection(node, 1)) {
      FlagsContinuation cont = FlagsContinuation::ForSet(kOverflow, ovf);
      return VisitBinop(this, node, kMips64Dadd, &cont);
    }
  }

  FlagsContinuation cont;
  VisitBinop(this, node, kMips64Dadd, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32SubWithOverflow(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    OpIndex ovf = FindProjection(node, 1);
    if (ovf.valid()) {
      FlagsContinuation cont = FlagsContinuation::ForSet(kOverflow, ovf);
      return VisitBinop(this, node, kMips64Dsub, &cont);
    }
  } else {
    if (Node* ovf = NodeProperties::FindProjection(node, 1)) {
      FlagsContinuation cont = FlagsContinuation::ForSet(kOverflow, ovf);
      return VisitBinop(this, node, kMips64Dsub, &cont);
    }
  }

  FlagsContinuation cont;
  VisitBinop(this, node, kMips64Dsub, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32MulWithOverflow(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    OpIndex ovf = FindProjection(node, 1);
    if (ovf.valid()) {
      FlagsContinuation cont = FlagsContinuation::ForSet(kOverflow, ovf);
      return VisitBinop(this, node, kMips64MulOvf, &cont);
    }
  } else {
    if (Node* ovf = NodeProperties::FindProjection(node, 1)) {
      FlagsContinuation cont = FlagsContinuation::ForSet(kOverflow, ovf);
      return VisitBinop(this, node, kMips64MulOvf, &cont);
    }
  }

  FlagsContinuation cont;
  VisitBinop(this, node, kMips64MulOvf, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt64MulWithOverflow(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    OpIndex ovf = FindProjection(node, 1);
    if (ovf.valid()) {
      FlagsContinuation cont = FlagsContinuation::ForSet(kOverflow, ovf);
      return VisitBinop(this, node, kMips64DMulOvf, &cont);
    }
  } else {
    if (Node* ovf = NodeProperties::FindProjection(node, 1)) {
      FlagsContinuation cont = FlagsContinuation::ForSet(kOverflow, ovf);
      return VisitBinop(this, node, kMips64DMulOvf, &cont);
    }
  }

  FlagsContinuation cont;
  VisitBinop(this, node, kMips64DMulOvf, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt64AddWithOverflow(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    OpIndex ovf = FindProjection(node, 1);
    if (ovf.valid()) {
      FlagsContinuation cont = FlagsContinuation::ForSet(kOverflow, ovf);
      return VisitBinop(this, node, kMips64DaddOvf, &cont);
    }
  } else {
    if (Node* ovf = NodeProperties::FindProjection(node, 1)) {
      FlagsContinuation cont = FlagsContinuation::ForSet(kOverflow, ovf);
      return VisitBinop(this, node, kMips64DaddOvf, &cont);
    }
  }

  FlagsContinuation cont;
  VisitBinop(this, node, kMips64DaddOvf, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt64SubWithOverflow(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    OpIndex ovf = FindProjection(node, 1);
    if (ovf.valid()) {
      FlagsContinuation cont = FlagsContinuation::ForSet(kOverflow, ovf);
      return VisitBinop(this, node, kMips64DsubOvf, &cont);
    }
  } else {
    if (Node* ovf = NodeProperties::FindProjection(node, 1)) {
      FlagsContinuation cont = FlagsContinuation::ForSet(kOverflow, ovf);
      return VisitBinop(this, node, kMips64DsubOvf, &cont);
    }
  }

  FlagsContinuation cont;
  VisitBinop(this, node, kMips64DsubOvf, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64Equal(node_t node) {
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
void InstructionSelectorT<Adapter>::VisitFloat64ExtractLowWord32(node_t node) {
  VisitRR(this, kMips64Float64ExtractLowWord32, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64ExtractHighWord32(node_t node) {
  VisitRR(this, kMips64Float64ExtractHighWord32, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64SilenceNaN(node_t node) {
  VisitRR(this, kMips64Float64SilenceNaN, node);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitBitcastWord32PairToFloat64(
    node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  Mips64OperandGeneratorT<TurboshaftAdapter> g(this);
  const auto& bitcast = this->Cast<BitcastWord32PairToFloat64Op>(node);
  node_t hi = bitcast.high_word32();
  node_t lo = bitcast.low_word32();

  InstructionOperand temps[] = {g.TempRegister()};
  Emit(kMips64Float64FromWord32Pair, g.DefineAsRegister(node), g.Use(hi),
       g.Use(lo), arraysize(temps), temps);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64InsertLowWord32(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    UNIMPLEMENTED();
  } else {
    Mips64OperandGeneratorT<Adapter> g(this);
    Node* left = node->InputAt(0);
    Node* right = node->InputAt(1);
    Emit(kMips64Float64InsertLowWord32, g.DefineSameAsFirst(node),
         g.UseRegister(left), g.UseRegister(right));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64InsertHighWord32(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    UNIMPLEMENTED();
  } else {
    Mips64OperandGeneratorT<Adapter> g(this);
    Node* left = node->InputAt(0);
    Node* right = node->InputAt(1);
    Emit(kMips64Float64InsertHighWord32, g.DefineSameAsFirst(node),
         g.UseRegister(left), g.UseRegister(right));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitMemoryBarrier(node_t node) {
  Mips64OperandGeneratorT<Adapter> g(this);
  Emit(kMips64Sync, g.NoOutput());
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
  VisitAtomicExchange(this, node, opcode, AtomicWidth::kWord32);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitWord32AtomicExchange(
    Node* node) {
  ArchOpcode opcode;
  MachineType type = AtomicOpType(node->op());
  if (type == MachineType::Int8()) {
    opcode = kAtomicExchangeInt8;
  } else if (type == MachineType::Uint8()) {
    opcode = kAtomicExchangeUint8;
  } else if (type == MachineType::Int16()) {
    opcode = kAtomicExchangeInt16;
  } else if (type == MachineType::Uint16()) {
    opcode = kAtomicExchangeUint16;
  } else if (type == MachineType::Int32() || type == MachineType::Uint32()) {
    opcode = kAtomicExchangeWord32;
  } else {
    UNREACHABLE();
  }

  VisitAtomicExchange(this, node, opcode, AtomicWidth::kWord32);
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
    opcode = kMips64Word64AtomicExchangeUint64;
  } else {
    UNREACHABLE();
  }
  VisitAtomicExchange(this, node, opcode, AtomicWidth::kWord64);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitWord64AtomicExchange(
    Node* node) {
  ArchOpcode opcode;
  MachineType type = AtomicOpType(node->op());
  if (type == MachineType::Uint8()) {
    opcode = kAtomicExchangeUint8;
  } else if (type == MachineType::Uint16()) {
    opcode = kAtomicExchangeUint16;
  } else if (type == MachineType::Uint32()) {
    opcode = kAtomicExchangeWord32;
  } else if (type == MachineType::Uint64()) {
    opcode = kMips64Word64AtomicExchangeUint64;
  } else {
    UNREACHABLE();
  }
  VisitAtomicExchange(this, node, opcode, AtomicWidth::kWord64);
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
  VisitAtomicCompareExchange(this, node, opcode, AtomicWidth::kWord32);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitWord32AtomicCompareExchange(
    Node* node) {
  ArchOpcode opcode;
  MachineType type = AtomicOpType(node->op());
  if (type == MachineType::Int8()) {
    opcode = kAtomicCompareExchangeInt8;
  } else if (type == MachineType::Uint8()) {
    opcode = kAtomicCompareExchangeUint8;
  } else if (type == MachineType::Int16()) {
    opcode = kAtomicCompareExchangeInt16;
  } else if (type == MachineType::Uint16()) {
    opcode = kAtomicCompareExchangeUint16;
  } else if (type == MachineType::Int32() || type == MachineType::Uint32()) {
    opcode = kAtomicCompareExchangeWord32;
  } else {
    UNREACHABLE();
  }
  VisitAtomicCompareExchange(this, node, opcode, AtomicWidth::kWord32);
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
    opcode = kMips64Word64AtomicCompareExchangeUint64;
  } else {
    UNREACHABLE();
  }
  VisitAtomicCompareExchange(this, node, opcode, AtomicWidth::kWord64);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitWord64AtomicCompareExchange(
    Node* node) {
  ArchOpcode opcode;
  MachineType type = AtomicOpType(node->op());
  if (type == MachineType::Uint8()) {
    opcode = kAtomicCompareExchangeUint8;
  } else if (type == MachineType::Uint16()) {
    opcode = kAtomicCompareExchangeUint16;
  } else if (type == MachineType::Uint32()) {
    opcode = kAtomicCompareExchangeWord32;
  } else if (type == MachineType::Uint64()) {
    opcode = kMips64Word64AtomicCompareExchangeUint64;
  } else {
    UNREACHABLE();
  }
  VisitAtomicCompareExchange(this, node, opcode, AtomicWidth::kWord64);
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
    VisitAtomicBinop(this, node, opcode, AtomicWidth::kWord32);
  } else {
    ArchOpcode opcode;
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

    VisitAtomicBinop(this, node, opcode, AtomicWidth::kWord32);
  }
}

#define VISIT_ATOMIC_BINOP(op)                                             \
  template <typename Adapter>                                              \
  void InstructionSelectorT<Adapter>::VisitWord32Atomic##op(node_t node) { \
    VisitWord32AtomicBinaryOperation(                                      \
        node, kAtomic##op##Int8, kAtomic##op##Uint8, kAtomic##op##Int16,   \
        kAtomic##op##Uint16, kAtomic##op##Word32);                         \
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
    VisitAtomicBinop(this, node, opcode, AtomicWidth::kWord64);
  } else {
    ArchOpcode opcode;
    MachineType type = AtomicOpType(node->op());
    if (type == MachineType::Uint8()) {
      opcode = uint8_op;
    } else if (type == MachineType::Uint16()) {
      opcode = uint16_op;
    } else if (type == MachineType::Uint32()) {
      opcode = uint32_op;
    } else if (type == MachineType::Uint64()) {
      opcode = uint64_op;
    } else {
      UNREACHABLE();
    }
    VisitAtomicBinop(this, node, opcode, AtomicWidth::kWord64);
  }
}

#define VISIT_ATOMIC_BINOP(op)                                                 \
  template <typename Adapter>                                                  \
  void InstructionSelectorT<Adapter>::VisitWord64Atomic##op(node_t node) {     \
    VisitWord64AtomicBinaryOperation(node, kAtomic##op##Uint8,                 \
                                     kAtomic##op##Uint16, kAtomic##op##Word32, \
                                     kMips64Word64Atomic##op##Uint64);         \
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

#define SIMD_TYPE_LIST(V) \
  V(F64x2)                \
  V(F32x4)                \
  V(I64x2)                \
  V(I32x4)                \
  V(I16x8)                \
  V(I8x16)

#define SIMD_UNOP_LIST(V)                                    \
  V(F64x2Abs, kMips64F64x2Abs)                               \
  V(F64x2Neg, kMips64F64x2Neg)                               \
  V(F64x2Sqrt, kMips64F64x2Sqrt)                             \
  V(F64x2Ceil, kMips64F64x2Ceil)                             \
  V(F64x2Floor, kMips64F64x2Floor)                           \
  V(F64x2Trunc, kMips64F64x2Trunc)                           \
  V(F64x2NearestInt, kMips64F64x2NearestInt)                 \
  V(I64x2Neg, kMips64I64x2Neg)                               \
  V(I64x2BitMask, kMips64I64x2BitMask)                       \
  V(F64x2ConvertLowI32x4S, kMips64F64x2ConvertLowI32x4S)     \
  V(F64x2ConvertLowI32x4U, kMips64F64x2ConvertLowI32x4U)     \
  V(F64x2PromoteLowF32x4, kMips64F64x2PromoteLowF32x4)       \
  V(F32x4SConvertI32x4, kMips64F32x4SConvertI32x4)           \
  V(F32x4UConvertI32x4, kMips64F32x4UConvertI32x4)           \
  V(F32x4Abs, kMips64F32x4Abs)                               \
  V(F32x4Neg, kMips64F32x4Neg)                               \
  V(F32x4Sqrt, kMips64F32x4Sqrt)                             \
  V(F32x4Ceil, kMips64F32x4Ceil)                             \
  V(F32x4Floor, kMips64F32x4Floor)                           \
  V(F32x4Trunc, kMips64F32x4Trunc)                           \
  V(F32x4NearestInt, kMips64F32x4NearestInt)                 \
  V(F32x4DemoteF64x2Zero, kMips64F32x4DemoteF64x2Zero)       \
  V(I64x2Abs, kMips64I64x2Abs)                               \
  V(I64x2SConvertI32x4Low, kMips64I64x2SConvertI32x4Low)     \
  V(I64x2SConvertI32x4High, kMips64I64x2SConvertI32x4High)   \
  V(I64x2UConvertI32x4Low, kMips64I64x2UConvertI32x4Low)     \
  V(I64x2UConvertI32x4High, kMips64I64x2UConvertI32x4High)   \
  V(I32x4SConvertF32x4, kMips64I32x4SConvertF32x4)           \
  V(I32x4UConvertF32x4, kMips64I32x4UConvertF32x4)           \
  V(I32x4Neg, kMips64I32x4Neg)                               \
  V(I32x4SConvertI16x8Low, kMips64I32x4SConvertI16x8Low)     \
  V(I32x4SConvertI16x8High, kMips64I32x4SConvertI16x8High)   \
  V(I32x4UConvertI16x8Low, kMips64I32x4UConvertI16x8Low)     \
  V(I32x4UConvertI16x8High, kMips64I32x4UConvertI16x8High)   \
  V(I32x4Abs, kMips64I32x4Abs)                               \
  V(I32x4BitMask, kMips64I32x4BitMask)                       \
  V(I32x4TruncSatF64x2SZero, kMips64I32x4TruncSatF64x2SZero) \
  V(I32x4TruncSatF64x2UZero, kMips64I32x4TruncSatF64x2UZero) \
  V(I16x8Neg, kMips64I16x8Neg)                               \
  V(I16x8SConvertI8x16Low, kMips64I16x8SConvertI8x16Low)     \
  V(I16x8SConvertI8x16High, kMips64I16x8SConvertI8x16High)   \
  V(I16x8UConvertI8x16Low, kMips64I16x8UConvertI8x16Low)     \
  V(I16x8UConvertI8x16High, kMips64I16x8UConvertI8x16High)   \
  V(I16x8Abs, kMips64I16x8Abs)                               \
  V(I16x8BitMask, kMips64I16x8BitMask)                       \
  V(I8x16Neg, kMips64I8x16Neg)                               \
  V(I8x16Abs, kMips64I8x16Abs)                               \
  V(I8x16Popcnt, kMips64I8x16Popcnt)                         \
  V(I8x16BitMask, kMips64I8x16BitMask)                       \
  V(S128Not, kMips64S128Not)                                 \
  V(I64x2AllTrue, kMips64I64x2AllTrue)                       \
  V(I32x4AllTrue, kMips64I32x4AllTrue)                       \
  V(I16x8AllTrue, kMips64I16x8AllTrue)                       \
  V(I8x16AllTrue, kMips64I8x16AllTrue)                       \
  V(V128AnyTrue, kMips64V128AnyTrue)

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

#define SIMD_BINOP_LIST(V)                               \
  V(F64x2Add, kMips64F64x2Add)                           \
  V(F64x2Sub, kMips64F64x2Sub)                           \
  V(F64x2Mul, kMips64F64x2Mul)                           \
  V(F64x2Div, kMips64F64x2Div)                           \
  V(F64x2Min, kMips64F64x2Min)                           \
  V(F64x2Max, kMips64F64x2Max)                           \
  V(F64x2Eq, kMips64F64x2Eq)                             \
  V(F64x2Ne, kMips64F64x2Ne)                             \
  V(F64x2Lt, kMips64F64x2Lt)                             \
  V(F64x2Le, kMips64F64x2Le)                             \
  V(I64x2Eq, kMips64I64x2Eq)                             \
  V(I64x2Ne, kMips64I64x2Ne)                             \
  V(I64x2Add, kMips64I64x2Add)                           \
  V(I64x2Sub, kMips64I64x2Sub)                           \
  V(I64x2Mul, kMips64I64x2Mul)                           \
  V(I64x2GtS, kMips64I64x2GtS)                           \
  V(I64x2GeS, kMips64I64x2GeS)                           \
  V(F32x4Add, kMips64F32x4Add)                           \
  V(F32x4Sub, kMips64F32x4Sub)                           \
  V(F32x4Mul, kMips64F32x4Mul)                           \
  V(F32x4Div, kMips64F32x4Div)                           \
  V(F32x4Max, kMips64F32x4Max)                           \
  V(F32x4Min, kMips64F32x4Min)                           \
  V(F32x4Eq, kMips64F32x4Eq)                             \
  V(F32x4Ne, kMips64F32x4Ne)                             \
  V(F32x4Lt, kMips64F32x4Lt)                             \
  V(F32x4Le, kMips64F32x4Le)                             \
  V(I32x4Add, kMips64I32x4Add)                           \
  V(I32x4Sub, kMips64I32x4Sub)                           \
  V(I32x4Mul, kMips64I32x4Mul)                           \
  V(I32x4MaxS, kMips64I32x4MaxS)                         \
  V(I32x4MinS, kMips64I32x4MinS)                         \
  V(I32x4MaxU, kMips64I32x4MaxU)                         \
  V(I32x4MinU, kMips64I32x4MinU)                         \
  V(I32x4Eq, kMips64I32x4Eq)                             \
  V(I32x4Ne, kMips64I32x4Ne)                             \
  V(I32x4GtS, kMips64I32x4GtS)                           \
  V(I32x4GeS, kMips64I32x4GeS)                           \
  V(I32x4GtU, kMips64I32x4GtU)                           \
  V(I32x4GeU, kMips64I32x4GeU)                           \
  V(I32x4DotI16x8S, kMips64I32x4DotI16x8S)               \
  V(I16x8Add, kMips64I16x8Add)                           \
  V(I16x8AddSatS, kMips64I16x8AddSatS)                   \
  V(I16x8AddSatU, kMips64I16x8AddSatU)                   \
  V(I16x8Sub, kMips64I16x8Sub)                           \
  V(I16x8SubSatS, kMips64I16x8SubSatS)                   \
  V(I16x8SubSatU, kMips64I16x8SubSatU)                   \
  V(I16x8Mul, kMips64I16x8Mul)                           \
  V(I16x8MaxS, kMips64I16x8MaxS)                         \
  V(I16x8MinS, kMips64I16x8MinS)                         \
  V(I16x8MaxU, kMips64I16x8MaxU)                         \
  V(I16x8MinU, kMips64I16x8MinU)                         \
  V(I16x8Eq, kMips64I16x8Eq)                             \
  V(I16x8Ne, kMips64I16x8Ne)                             \
  V(I16x8GtS, kMips64I16x8GtS)                           \
  V(I16x8GeS, kMips64I16x8GeS)                           \
  V(I16x8GtU, kMips64I16x8GtU)                           \
  V(I16x8GeU, kMips64I16x8GeU)                           \
  V(I16x8RoundingAverageU, kMips64I16x8RoundingAverageU) \
  V(I16x8SConvertI32x4, kMips64I16x8SConvertI32x4)       \
  V(I16x8UConvertI32x4, kMips64I16x8UConvertI32x4)       \
  V(I16x8Q15MulRSatS, kMips64I16x8Q15MulRSatS)           \
  V(I8x16Add, kMips64I8x16Add)                           \
  V(I8x16AddSatS, kMips64I8x16AddSatS)                   \
  V(I8x16AddSatU, kMips64I8x16AddSatU)                   \
  V(I8x16Sub, kMips64I8x16Sub)                           \
  V(I8x16SubSatS, kMips64I8x16SubSatS)                   \
  V(I8x16SubSatU, kMips64I8x16SubSatU)                   \
  V(I8x16MaxS, kMips64I8x16MaxS)                         \
  V(I8x16MinS, kMips64I8x16MinS)                         \
  V(I8x16MaxU, kMips64I8x16MaxU)                         \
  V(I8x16MinU, kMips64I8x16MinU)                         \
  V(I8x16Eq, kMips64I8x16Eq)                             \
  V(I8x16Ne, kMips64I8x16Ne)                             \
  V(I8x16GtS, kMips64I8x16GtS)                           \
  V(I8x16GeS, kMips64I8x16GeS)                           \
  V(I8x16GtU, kMips64I8x16GtU)                           \
  V(I8x16GeU, kMips64I8x16GeU)                           \
  V(I8x16RoundingAverageU, kMips64I8x16RoundingAverageU) \
  V(
```