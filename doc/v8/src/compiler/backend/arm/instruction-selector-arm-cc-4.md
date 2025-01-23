Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/compiler/backend/arm/instruction-selector-arm.cc`.

Here's a plan to address the request:

1. **Identify the core purpose of the code:** This file seems to be responsible for selecting ARM instructions based on higher-level operations.
2. **Analyze the functions present:** Each `Visit...` function likely corresponds to a specific intermediate representation (IR) node or operation.
3. **Categorize the functionalities:** Group the `Visit...` functions by the type of operation they handle (e.g., arithmetic, comparisons, memory access, SIMD).
4. **Check for Torque usage:** The prompt explicitly asks about `.tq` files. This file is `.cc`, so it's not Torque.
5. **JavaScript relevance:** Determine if the operations have direct equivalents in JavaScript. Provide examples where applicable.
6. **Logic and assumptions:**  Look for code that makes decisions based on input values or conditions. Formulate input/output scenarios for these cases.
7. **Common programming errors:** Identify potential errors related to the handled operations.
8. **Synthesize a concise summary:** Combine the identified functionalities into a clear description.
这是 V8 编译器后端针对 ARM 架构的指令选择器的一部分代码。指令选择器的主要功能是将 V8 的中间表示（IR）转换为目标架构（这里是 ARM）的机器指令。

以下是代码片段中展示的功能归纳：

**1. 控制流相关的指令选择:**

* **`VisitSwitch(node_t node, const SwitchInfo& sw)`:**  处理 `switch` 语句。它会根据 `switch` 语句的 case 数量和值的范围，决定使用跳转表 (`ArchTableSwitch`) 还是二分查找 (`ArchBinarySearchSwitch`) 来实现。
    * **代码逻辑推理:**
        * **假设输入:** 一个 `switch` 语句，有 100 个 case，值的范围是 1 到 100。`enable_switch_jump_table_` 设置为启用跳转表。
        * **输出:** 代码会计算使用跳转表的开销 (`table_space_cost`, `table_time_cost`) 和使用二分查找的开销 (`lookup_space_cost`, `lookup_time_cost`)。如果跳转表的开销更低，则会调用 `EmitTableSwitch`，否则调用 `EmitBinarySearchSwitch`。
* **`EmitWithContinuation(opcode, value_operand, value_operand, cont)`:**  可能是一个辅助函数，用于在生成指令后处理后续操作或条件。

**2. 比较相关的指令选择:**

* **`VisitWord32Equal(node_t node)`:** 处理 32 位整数相等比较 (`==`)。它会检查是否与 0 比较，如果是，则调用 `VisitWordCompareZero` 进行优化。否则，调用通用的 `VisitWordCompare`。
* **`VisitInt32LessThan(node_t node)`:** 处理 32 位有符号整数小于比较 (`<`)。
* **`VisitInt32LessThanOrEqual(node_t node)`:** 处理 32 位有符号整数小于等于比较 (`<=`)。
* **`VisitUint32LessThan(node_t node)`:** 处理 32 位无符号整数小于比较 (`<`)。
* **`VisitUint32LessThanOrEqual(node_t node)`:** 处理 32 位无符号整数小于等于比较 (`<=`)。
* **`VisitFloat32Equal(node_t node)`:** 处理 32 位浮点数相等比较 (`==`)。
* **`VisitFloat32LessThan(node_t node)`:** 处理 32 位浮点数小于比较 (`<`)。
* **`VisitFloat32LessThanOrEqual(node_t node)`:** 处理 32 位浮点数小于等于比较 (`<=`)。
* **`VisitFloat64Equal(node_t node)`:** 处理 64 位浮点数相等比较 (`==`)。
* **`VisitFloat64LessThan(node_t node)`:** 处理 64 位浮点数小于比较 (`<`)。
* **`VisitFloat64LessThanOrEqual(node_t node)`:** 处理 64 位浮点数小于等于比较 (`<=`)。

**3. 算术运算相关的指令选择:**

* **`VisitInt32AddWithOverflow(node_t node)`:** 处理可能溢出的 32 位整数加法 (`+`)。如果需要检查溢出，会设置 `FlagsContinuation`。
* **`VisitInt32SubWithOverflow(node_t node)`:** 处理可能溢出的 32 位整数减法 (`-`)。
* **`VisitInt32MulWithOverflow(node_t node)`:** 处理可能溢出的 32 位整数乘法 (`*`)。由于 ARM 乘法指令不直接设置溢出标志，需要额外的指令序列来检测溢出。

**4. 位运算相关的指令选择:**

* **没有直接的位运算 `Visit...` 函数在这个片段中，但可以推断其他部分的代码会处理位运算。**

**5. 类型转换和数据操作相关的指令选择:**

* **`VisitFloat64InsertLowWord32(node_t node)`:** 将一个 32 位整数插入到 64 位浮点数的低 32 位。
* **`VisitFloat64InsertHighWord32(node_t node)`:** 将一个 32 位整数插入到 64 位浮点数的高 32 位。这两个函数可能会被优化成一个 `kArmVmovF64U32U32` 指令。
    * **代码逻辑推理:**
        * **假设输入:** 一个 `Float64InsertLowWord32` 节点，其输入是一个 `Float64InsertHighWord32` 节点。
        * **输出:** 代码会检测到这种模式，并生成 `kArmVmovF64U32U32` 指令，直接将两个 32 位输入组合成一个 64 位浮点数。
* **`VisitBitcastWord32PairToFloat64(node_t node)`:** 将一对 32 位整数按位转换为 64 位浮点数。

**6. 原子操作相关的指令选择:**

* **`VisitMemoryBarrier(node_t node)`:** 处理内存屏障，确保内存操作的顺序性。
* **`VisitWord32AtomicLoad(node_t node)`:** 处理 32 位原子加载操作。
* **`VisitWord32AtomicStore(node_t node)`:** 处理 32 位原子存储操作。
* **`VisitWord32AtomicExchange(node_t node)`:** 处理 32 位原子交换操作。
* **`VisitWord32AtomicCompareExchange(node_t node)`:** 处理 32 位原子比较并交换操作。
* **`VisitWord32AtomicBinaryOperation(...)` 和 `VISIT_ATOMIC_BINOP(...)` 宏:** 处理各种 32 位原子二元运算，如加法、减法、与、或、异或等。
* **`VisitWord32AtomicPairLoad(node_t node)`:** 处理 64 位原子加载操作（由两个 32 位字组成）。
* **`VisitWord32AtomicPairStore(node_t node)`:** 处理 64 位原子存储操作。
* **`VisitWord32AtomicPairAdd(...)` 等:** 处理 64 位原子二元运算。
* **`VisitWord32AtomicPairExchange(node_t node)`:** 处理 64 位原子交换操作。
* **`VisitWord32AtomicPairCompareExchange(node_t node)`:** 处理 64 位原子比较并交换操作。

**7. SIMD (Single Instruction, Multiple Data) 相关的指令选择:**

* 包含大量的 `Visit...` 函数，对应于各种 SIMD 操作，例如：
    * **`F64x2...`:** 处理 2 个 64 位浮点数的 SIMD 操作。
    * **`F32x4...`:** 处理 4 个 32 位浮点数的 SIMD 操作。
    * **`I64x2...`:** 处理 2 个 64 位整数的 SIMD 操作。
    * **`I32x4...`:** 处理 4 个 32 位整数的 SIMD 操作。
    * **`I16x8...`:** 处理 8 个 16 位整数的 SIMD 操作。
    * **`I8x16...`:** 处理 16 个 8 位整数的 SIMD 操作。
    * **`S128...`:** 处理 128 位 SIMD 向量的通用操作。
* 这些函数会根据具体的 SIMD 操作类型，选择相应的 ARM SIMD 指令 (例如，`kArmF64x2Add`, `kArmI32x4Mul` 等)。
* **`VisitS128Const(node_t node)`:**  处理 128 位 SIMD 常量。对于全零或全一的常量会进行优化。

**关于 .tq 结尾的文件:**

代码片段显示文件名为 `instruction-selector-arm.cc`，因此它不是 Torque 源代码。如果文件以 `.tq` 结尾，那么它将是使用 V8 的 Torque 语言编写的，这是一种用于生成编译器代码的领域特定语言。

**与 JavaScript 的关系和示例:**

这些指令选择器处理的操作很多都与 JavaScript 的功能直接相关：

* **算术运算:**  JavaScript 中的 `+`, `-`, `*` 等运算符。
    ```javascript
    let a = 10;
    let b = 5;
    let sum = a + b; // VisitInt32AddWithOverflow (如果编译器认为可能溢出) 或其他加法指令
    ```
* **比较运算:** JavaScript 中的 `==`, `!=`, `<`, `>`, `<=`, `>=` 等运算符。
    ```javascript
    let x = 5;
    let y = 10;
    if (x < y) { // VisitInt32LessThan
      console.log("x is less than y");
    }
    ```
* **类型转换:** JavaScript 中发生的隐式或显式类型转换。
    ```javascript
    let num = 1.5;
    let intNum = num | 0; // 某些位运算可能涉及类型转换
    ```
* **`switch` 语句:**  JavaScript 的 `switch` 语句。
    ```javascript
    let fruit = "apple";
    switch (fruit) { // VisitSwitch
      case "banana":
        console.log("It's a banana");
        break;
      case "apple":
        console.log("It's an apple");
        break;
      default:
        console.log("Unknown fruit");
    }
    ```
* **原子操作:**  `Atomics` 对象提供的原子操作。
    ```javascript
    const sab = new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT);
    const view = new Int32Array(sab);
    Atomics.add(view, 0, 5); // VisitWord32AtomicAdd
    ```
* **SIMD 操作:**  WebAssembly 的 SIMD 指令可以通过 JavaScript 调用（需要 WebAssembly 支持）。
    ```javascript
    // WebAssembly 代码示例 (概念性)
    // i32x4.add ... // 对应于 VisitI32x4Add
    ```

**常见的编程错误:**

* **整数溢出:**  在 JavaScript 中，整数运算通常不会抛出溢出错误，而是会得到不期望的结果。`VisitInt32AddWithOverflow` 等函数在 V8 内部处理溢出检查，但开发者可能没有意识到 JavaScript 的数字表示方式可能导致溢出。
    ```javascript
    let maxInt = 2147483647;
    let result = maxInt + 1; // JavaScript 中不会报错，但结果可能不是期望的
    ```
* **浮点数比较:**  直接比较浮点数是否相等可能由于精度问题而导致错误。应该使用一个小的误差范围进行比较。
    ```javascript
    let a = 0.1 + 0.2;
    let b = 0.3;
    if (a === b) { // 可能会失败，因为浮点数精度问题
      console.log("Equal");
    }
    ```
* **未正确使用原子操作:** 在多线程环境下，不正确地使用原子操作可能导致数据竞争和不一致性。

**总结一下它的功能 (第 5 部分):**

这部分代码主要负责将 V8 编译器生成的中间表示转换为 ARM 架构的机器指令，涵盖了：

* **控制流语句:**  特别是 `switch` 语句的指令选择策略。
* **各种类型的比较操作:** 针对整数和浮点数的比较操作。
* **带有溢出检查的算术运算:**  加法、减法和乘法。
* **浮点数和整数之间的位级转换操作。**
* **原子操作:**  包括加载、存储、交换和比较交换等，以及原子二元运算。
* **SIMD 指令的选择:**  支持各种 SIMD 数据类型的运算，涵盖浮点数和整数。

总体而言，这部分代码是 V8 编译器后端指令生成的核心组成部分，它确保了 JavaScript 代码能够在 ARM 架构上高效地执行。

### 提示词
```
这是目录为v8/src/compiler/backend/arm/instruction-selector-arm.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/arm/instruction-selector-arm.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共7部分，请归纳一下它的功能
```

### 源代码
```cpp
perand = g.UseRegister(value);
  EmitWithContinuation(opcode, value_operand, value_operand, cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitSwitch(node_t node,
                                                const SwitchInfo& sw) {
  ArmOperandGeneratorT<Adapter> g(this);
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
        Emit(kArmSub | AddressingModeField::encode(kMode_Operand2_I),
             index_operand, value_operand, g.TempImmediate(sw.min_value()));
      }
      // Generate a table lookup.
      return EmitTableSwitch(sw, index_operand);
    }
  }

  // Generate a tree of conditional jumps.
  return EmitBinarySearchSwitch(sw, value_operand);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Equal(node_t node) {
  FlagsContinuation cont = FlagsContinuation::ForSet(kEqual, node);
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const ComparisonOp& equal = this->Get(node).template Cast<ComparisonOp>();
    if (this->MatchIntegralZero(equal.right())) {
      return VisitWordCompareZero(node, equal.left(), &cont);
    }
  } else {
    Int32BinopMatcher m(node);
    if (m.right().Is(0)) {
      return VisitWordCompareZero(m.node(), m.left().node(), &cont);
    }
  }
  VisitWordCompare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32LessThan(node_t node) {
  FlagsContinuation cont = FlagsContinuation::ForSet(kSignedLessThan, node);
  VisitWordCompare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32LessThanOrEqual(node_t node) {
  FlagsContinuation cont =
      FlagsContinuation::ForSet(kSignedLessThanOrEqual, node);
  VisitWordCompare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUint32LessThan(node_t node) {
  FlagsContinuation cont = FlagsContinuation::ForSet(kUnsignedLessThan, node);
  VisitWordCompare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUint32LessThanOrEqual(node_t node) {
  FlagsContinuation cont =
      FlagsContinuation::ForSet(kUnsignedLessThanOrEqual, node);
  VisitWordCompare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32AddWithOverflow(node_t node) {
  node_t ovf = FindProjection(node, 1);
  if (this->valid(ovf)) {
    FlagsContinuation cont = FlagsContinuation::ForSet(kOverflow, ovf);
    return VisitBinop(this, node, kArmAdd, kArmAdd, &cont);
  }
  FlagsContinuation cont;
  VisitBinop(this, node, kArmAdd, kArmAdd, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32SubWithOverflow(node_t node) {
  node_t ovf = FindProjection(node, 1);
  if (this->valid(ovf)) {
    FlagsContinuation cont = FlagsContinuation::ForSet(kOverflow, ovf);
    return VisitBinop(this, node, kArmSub, kArmRsb, &cont);
  }
  FlagsContinuation cont;
  VisitBinop(this, node, kArmSub, kArmRsb, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32MulWithOverflow(node_t node) {
  node_t ovf = FindProjection(node, 1);
  if (this->valid(ovf)) {
    // ARM doesn't set the overflow flag for multiplication, so we need to
    // test on kNotEqual. Here is the code sequence used:
    //   smull resultlow, resulthigh, left, right
    //   cmp resulthigh, Operand(resultlow, ASR, 31)
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

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64InsertLowWord32(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    UNIMPLEMENTED();
  } else {
    ArmOperandGeneratorT<Adapter> g(this);
    Node* left = node->InputAt(0);
    Node* right = node->InputAt(1);
    if (left->opcode() == IrOpcode::kFloat64InsertHighWord32 &&
        CanCover(node, left)) {
      left = left->InputAt(1);
      Emit(kArmVmovF64U32U32, g.DefineAsRegister(node), g.UseRegister(right),
           g.UseRegister(left));
      return;
    }
    Emit(kArmVmovLowF64U32, g.DefineSameAsFirst(node), g.UseRegister(left),
         g.UseRegister(right));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64InsertHighWord32(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    UNIMPLEMENTED();
  } else {
    ArmOperandGeneratorT<Adapter> g(this);
    Node* left = node->InputAt(0);
    Node* right = node->InputAt(1);
    if (left->opcode() == IrOpcode::kFloat64InsertLowWord32 &&
        CanCover(node, left)) {
      left = left->InputAt(1);
      Emit(kArmVmovF64U32U32, g.DefineAsRegister(node), g.UseRegister(left),
           g.UseRegister(right));
      return;
    }
    Emit(kArmVmovHighF64U32, g.DefineSameAsFirst(node), g.UseRegister(left),
         g.UseRegister(right));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitBitcastWord32PairToFloat64(
    node_t node) {
  if constexpr (Adapter::IsTurbofan) {
    // The Turbofan implementation is split across VisitFloat64InsertLowWord32
    // and VisitFloat64InsertHighWord32.
    UNREACHABLE();
  } else {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    ArmOperandGeneratorT<TurboshaftAdapter> g(this);
    const BitcastWord32PairToFloat64Op& cast_op =
        this->Get(node).template Cast<BitcastWord32PairToFloat64Op>();
    Emit(kArmVmovF64U32U32, g.DefineAsRegister(node),
         g.UseRegister(cast_op.low_word32()),
         g.UseRegister(cast_op.high_word32()));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitMemoryBarrier(node_t node) {
  // Use DMB ISH for both acquire-release and sequentially consistent barriers.
  ArmOperandGeneratorT<Adapter> g(this);
  Emit(kArmDmbIsh, g.NoOutput());
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicLoad(node_t node) {
  // The memory order is ignored as both acquire and sequentially consistent
  // loads can emit LDR; DMB ISH.
  // https://www.cl.cam.ac.uk/~pes20/cpp/cpp0xmappings.html
  ArmOperandGeneratorT<Adapter> g(this);
  auto load = this->load_view(node);
  node_t base = load.base();
  node_t index = load.index();
  ArchOpcode opcode;
  LoadRepresentation load_rep = load.loaded_rep();
  switch (load_rep.representation()) {
    case MachineRepresentation::kWord8:
      opcode = load_rep.IsSigned() ? kAtomicLoadInt8 : kAtomicLoadUint8;
      break;
    case MachineRepresentation::kWord16:
      opcode = load_rep.IsSigned() ? kAtomicLoadInt16 : kAtomicLoadUint16;
      break;
    case MachineRepresentation::kTaggedSigned:   // Fall through.
    case MachineRepresentation::kTaggedPointer:  // Fall through.
    case MachineRepresentation::kTagged:         // Fall through.
    case MachineRepresentation::kWord32:
      opcode = kAtomicLoadWord32;
      break;
    default:
      UNREACHABLE();
  }
  Emit(opcode | AddressingModeField::encode(kMode_Offset_RR),
       g.DefineAsRegister(node), g.UseRegister(base), g.UseRegister(index));
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
void InstructionSelectorT<Adapter>::VisitWord32AtomicExchange(node_t node) {
  ArmOperandGeneratorT<Adapter> g(this);
  auto atomic_op = this->atomic_rmw_view(node);
  ArchOpcode opcode;
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const AtomicRMWOp& atomic_op = this->Get(node).template Cast<AtomicRMWOp>();
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
  } else {
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
  }

  AddressingMode addressing_mode = kMode_Offset_RR;
  InstructionOperand inputs[3];
  size_t input_count = 0;
  inputs[input_count++] = g.UseRegister(atomic_op.base());
  inputs[input_count++] = g.UseRegister(atomic_op.index());
  inputs[input_count++] = g.UseUniqueRegister(atomic_op.value());
  InstructionOperand outputs[1];
  outputs[0] = g.DefineAsRegister(node);
  InstructionOperand temps[] = {g.TempRegister(), g.TempRegister()};
  InstructionCode code = opcode | AddressingModeField::encode(addressing_mode);
  Emit(code, 1, outputs, input_count, inputs, arraysize(temps), temps);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicCompareExchange(
    node_t node) {
  ArmOperandGeneratorT<Adapter> g(this);
  auto atomic_op = this->atomic_rmw_view(node);
  node_t base = atomic_op.base();
  node_t index = atomic_op.index();
  node_t old_value = atomic_op.expected();
  node_t new_value = atomic_op.value();
  ArchOpcode opcode;
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const AtomicRMWOp& atomic_op = this->Get(node).template Cast<AtomicRMWOp>();
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
  } else {
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
  }

  AddressingMode addressing_mode = kMode_Offset_RR;
  InstructionOperand inputs[4];
  size_t input_count = 0;
  inputs[input_count++] = g.UseRegister(base);
  inputs[input_count++] = g.UseRegister(index);
  inputs[input_count++] = g.UseUniqueRegister(old_value);
  inputs[input_count++] = g.UseUniqueRegister(new_value);
  InstructionOperand outputs[1];
  outputs[0] = g.DefineAsRegister(node);
  InstructionOperand temps[] = {g.TempRegister(), g.TempRegister(),
                                g.TempRegister()};
  InstructionCode code = opcode | AddressingModeField::encode(addressing_mode);
  Emit(code, 1, outputs, input_count, inputs, arraysize(temps), temps);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicBinaryOperation(
    node_t node, ArchOpcode int8_op, ArchOpcode uint8_op, ArchOpcode int16_op,
    ArchOpcode uint16_op, ArchOpcode word32_op) {
  ArmOperandGeneratorT<Adapter> g(this);
  auto atomic_op = this->atomic_rmw_view(node);
  ArchOpcode opcode;
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const AtomicRMWOp& atomic_op = this->Get(node).template Cast<AtomicRMWOp>();
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
  } else {
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
  }

  AddressingMode addressing_mode = kMode_Offset_RR;
  InstructionOperand inputs[3];
  size_t input_count = 0;
  inputs[input_count++] = g.UseRegister(atomic_op.base());
  inputs[input_count++] = g.UseRegister(atomic_op.index());
  inputs[input_count++] = g.UseUniqueRegister(atomic_op.value());
  InstructionOperand outputs[1];
  outputs[0] = g.DefineAsRegister(node);
  InstructionOperand temps[] = {g.TempRegister(), g.TempRegister(),
                                g.TempRegister()};
  InstructionCode code = opcode | AddressingModeField::encode(addressing_mode);
  Emit(code, 1, outputs, input_count, inputs, arraysize(temps), temps);
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
void InstructionSelectorT<Adapter>::VisitWord32AtomicPairLoad(node_t node) {
  ArmOperandGeneratorT<Adapter> g(this);
  node_t base = this->input_at(node, 0);
  node_t index = this->input_at(node, 1);
  InstructionOperand inputs[3];
  size_t input_count = 0;
  inputs[input_count++] = g.UseUniqueRegister(base);
  inputs[input_count++] = g.UseUniqueRegister(index);
  InstructionOperand temps[1];
  size_t temp_count = 0;
  InstructionOperand outputs[2];
  size_t output_count = 0;

  node_t projection0 = FindProjection(node, 0);
  node_t projection1 = FindProjection(node, 1);
  if (this->valid(projection0) && this->valid(projection1)) {
    outputs[output_count++] = g.DefineAsFixed(projection0, r0);
    outputs[output_count++] = g.DefineAsFixed(projection1, r1);
    temps[temp_count++] = g.TempRegister();
  } else if (this->valid(projection0)) {
    inputs[input_count++] = g.UseImmediate(0);
    outputs[output_count++] = g.DefineAsRegister(projection0);
  } else if (this->valid(projection1)) {
    inputs[input_count++] = g.UseImmediate(4);
    temps[temp_count++] = g.TempRegister();
    outputs[output_count++] = g.DefineAsRegister(projection1);
  } else {
    // There is no use of the loaded value, we don't need to generate code.
    return;
  }
  Emit(kArmWord32AtomicPairLoad, output_count, outputs, input_count, inputs,
       temp_count, temps);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicPairStore(node_t node) {
  ArmOperandGeneratorT<Adapter> g(this);
  auto store = this->word32_atomic_pair_store_view(node);
  AddressingMode addressing_mode = kMode_Offset_RR;
  InstructionOperand inputs[] = {
      g.UseUniqueRegister(store.base()), g.UseUniqueRegister(store.index()),
      g.UseFixed(store.value_low(), r2), g.UseFixed(store.value_high(), r3)};
  InstructionOperand temps[] = {g.TempRegister(), g.TempRegister(r0),
                                g.TempRegister(r1)};
  InstructionCode code =
      kArmWord32AtomicPairStore | AddressingModeField::encode(addressing_mode);
  Emit(code, 0, nullptr, arraysize(inputs), inputs, arraysize(temps), temps);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicPairAdd(node_t node) {
  VisitPairAtomicBinOp(this, node, kArmWord32AtomicPairAdd);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicPairSub(node_t node) {
  VisitPairAtomicBinOp(this, node, kArmWord32AtomicPairSub);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicPairAnd(node_t node) {
  VisitPairAtomicBinOp(this, node, kArmWord32AtomicPairAnd);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicPairOr(node_t node) {
  VisitPairAtomicBinOp(this, node, kArmWord32AtomicPairOr);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicPairXor(node_t node) {
  VisitPairAtomicBinOp(this, node, kArmWord32AtomicPairXor);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicPairExchange(node_t node) {
  ArmOperandGeneratorT<Adapter> g(this);
  node_t base = this->input_at(node, 0);
  node_t index = this->input_at(node, 1);
  node_t value = this->input_at(node, 2);
  node_t value_high = this->input_at(node, 3);
  AddressingMode addressing_mode = kMode_Offset_RR;
  InstructionOperand inputs[] = {
      g.UseFixed(value, r0), g.UseFixed(value_high, r1),
      g.UseUniqueRegister(base), g.UseUniqueRegister(index)};
  InstructionCode code = kArmWord32AtomicPairExchange |
                         AddressingModeField::encode(addressing_mode);
  node_t projection0 = FindProjection(node, 0);
  node_t projection1 = FindProjection(node, 1);
  InstructionOperand outputs[2];
  size_t output_count = 0;
  InstructionOperand temps[4];
  size_t temp_count = 0;
  temps[temp_count++] = g.TempRegister();
  temps[temp_count++] = g.TempRegister();
  if (this->valid(projection0)) {
    outputs[output_count++] = g.DefineAsFixed(projection0, r6);
  } else {
    temps[temp_count++] = g.TempRegister(r6);
  }
  if (this->valid(projection1)) {
    outputs[output_count++] = g.DefineAsFixed(projection1, r7);
  } else {
    temps[temp_count++] = g.TempRegister(r7);
  }
  Emit(code, output_count, outputs, arraysize(inputs), inputs, temp_count,
       temps);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicPairCompareExchange(
    node_t node) {
  ArmOperandGeneratorT<Adapter> g(this);
  AddressingMode addressing_mode = kMode_Offset_RR;

  // In the Turbofan and the Turboshaft graph the order of expected and value is
  // swapped.
  const size_t expected_offset = Adapter::IsTurboshaft ? 4 : 2;
  const size_t value_offset = Adapter::IsTurboshaft ? 2 : 4;
  InstructionOperand inputs[] = {
      g.UseFixed(this->input_at(node, expected_offset), r4),
      g.UseFixed(this->input_at(node, expected_offset + 1), r5),
      g.UseFixed(this->input_at(node, value_offset), r8),
      g.UseFixed(this->input_at(node, value_offset + 1), r9),
      g.UseUniqueRegister(this->input_at(node, 0)),
      g.UseUniqueRegister(this->input_at(node, 1))};
  InstructionCode code = kArmWord32AtomicPairCompareExchange |
                         AddressingModeField::encode(addressing_mode);
  node_t projection0 = FindProjection(node, 0);
  node_t projection1 = FindProjection(node, 1);
  InstructionOperand outputs[2];
  size_t output_count = 0;
  InstructionOperand temps[4];
  size_t temp_count = 0;
  temps[temp_count++] = g.TempRegister();
  temps[temp_count++] = g.TempRegister();
  if (this->valid(projection0)) {
    outputs[output_count++] = g.DefineAsFixed(projection0, r2);
  } else {
    temps[temp_count++] = g.TempRegister(r2);
  }
  if (this->valid(projection1)) {
    outputs[output_count++] = g.DefineAsFixed(projection1, r3);
  } else {
    temps[temp_count++] = g.TempRegister(r3);
  }
  Emit(code, output_count, outputs, arraysize(inputs), inputs, temp_count,
       temps);
}

#define SIMD_UNOP_LIST(V)                               \
  V(F64x2Abs, kArmF64x2Abs)                             \
  V(F64x2Neg, kArmF64x2Neg)                             \
  V(F64x2Sqrt, kArmF64x2Sqrt)                           \
  V(F32x4SConvertI32x4, kArmF32x4SConvertI32x4)         \
  V(F32x4UConvertI32x4, kArmF32x4UConvertI32x4)         \
  V(F32x4Abs, kArmF32x4Abs)                             \
  V(F32x4Neg, kArmF32x4Neg)                             \
  V(I64x2Abs, kArmI64x2Abs)                             \
  V(I64x2SConvertI32x4Low, kArmI64x2SConvertI32x4Low)   \
  V(I64x2SConvertI32x4High, kArmI64x2SConvertI32x4High) \
  V(I64x2UConvertI32x4Low, kArmI64x2UConvertI32x4Low)   \
  V(I64x2UConvertI32x4High, kArmI64x2UConvertI32x4High) \
  V(I32x4SConvertF32x4, kArmI32x4SConvertF32x4)         \
  V(I32x4RelaxedTruncF32x4S, kArmI32x4SConvertF32x4)    \
  V(I32x4SConvertI16x8Low, kArmI32x4SConvertI16x8Low)   \
  V(I32x4SConvertI16x8High, kArmI32x4SConvertI16x8High) \
  V(I32x4Neg, kArmI32x4Neg)                             \
  V(I32x4UConvertF32x4, kArmI32x4UConvertF32x4)         \
  V(I32x4RelaxedTruncF32x4U, kArmI32x4UConvertF32x4)    \
  V(I32x4UConvertI16x8Low, kArmI32x4UConvertI16x8Low)   \
  V(I32x4UConvertI16x8High, kArmI32x4UConvertI16x8High) \
  V(I32x4Abs, kArmI32x4Abs)                             \
  V(I16x8SConvertI8x16Low, kArmI16x8SConvertI8x16Low)   \
  V(I16x8SConvertI8x16High, kArmI16x8SConvertI8x16High) \
  V(I16x8Neg, kArmI16x8Neg)                             \
  V(I16x8UConvertI8x16Low, kArmI16x8UConvertI8x16Low)   \
  V(I16x8UConvertI8x16High, kArmI16x8UConvertI8x16High) \
  V(I16x8Abs, kArmI16x8Abs)                             \
  V(I8x16Neg, kArmI8x16Neg)                             \
  V(I8x16Abs, kArmI8x16Abs)                             \
  V(I8x16Popcnt, kArmVcnt)                              \
  V(S128Not, kArmS128Not)                               \
  V(I64x2AllTrue, kArmI64x2AllTrue)                     \
  V(I32x4AllTrue, kArmI32x4AllTrue)                     \
  V(I16x8AllTrue, kArmI16x8AllTrue)                     \
  V(V128AnyTrue, kArmV128AnyTrue)                       \
  V(I8x16AllTrue, kArmI8x16AllTrue)

#define SIMD_SHIFT_OP_LIST(V) \
  V(I64x2Shl, 64)             \
  V(I64x2ShrS, 64)            \
  V(I64x2ShrU, 64)            \
  V(I32x4Shl, 32)             \
  V(I32x4ShrS, 32)            \
  V(I32x4ShrU, 32)            \
  V(I16x8Shl, 16)             \
  V(I16x8ShrS, 16)            \
  V(I16x8ShrU, 16)            \
  V(I8x16Shl, 8)              \
  V(I8x16ShrS, 8)             \
  V(I8x16ShrU, 8)

#define SIMD_BINOP_LIST(V)                            \
  V(F64x2Add, kArmF64x2Add)                           \
  V(F64x2Sub, kArmF64x2Sub)                           \
  V(F64x2Mul, kArmF64x2Mul)                           \
  V(F64x2Div, kArmF64x2Div)                           \
  V(F64x2Min, kArmF64x2Min)                           \
  V(F64x2Max, kArmF64x2Max)                           \
  V(F64x2Eq, kArmF64x2Eq)                             \
  V(F64x2Ne, kArmF64x2Ne)                             \
  V(F64x2Lt, kArmF64x2Lt)                             \
  V(F64x2Le, kArmF64x2Le)                             \
  V(F32x4Add, kArmF32x4Add)                           \
  V(F32x4Sub, kArmF32x4Sub)                           \
  V(F32x4Mul, kArmF32x4Mul)                           \
  V(F32x4Min, kArmF32x4Min)                           \
  V(F32x4RelaxedMin, kArmF32x4Min)                    \
  V(F32x4Max, kArmF32x4Max)                           \
  V(F32x4RelaxedMax, kArmF32x4Max)                    \
  V(F32x4Eq, kArmF32x4Eq)                             \
  V(F32x4Ne, kArmF32x4Ne)                             \
  V(F32x4Lt, kArmF32x4Lt)                             \
  V(F32x4Le, kArmF32x4Le)                             \
  V(I64x2Add, kArmI64x2Add)                           \
  V(I64x2Sub, kArmI64x2Sub)                           \
  V(I32x4Sub, kArmI32x4Sub)                           \
  V(I32x4Mul, kArmI32x4Mul)                           \
  V(I32x4MinS, kArmI32x4MinS)                         \
  V(I32x4MaxS, kArmI32x4MaxS)                         \
  V(I32x4Eq, kArmI32x4Eq)                             \
  V(I64x2Eq, kArmI64x2Eq)                             \
  V(I64x2Ne, kArmI64x2Ne)                             \
  V(I64x2GtS, kArmI64x2GtS)                           \
  V(I64x2GeS, kArmI64x2GeS)                           \
  V(I32x4Ne, kArmI32x4Ne)                             \
  V(I32x4GtS, kArmI32x4GtS)                           \
  V(I32x4GeS, kArmI32x4GeS)                           \
  V(I32x4MinU, kArmI32x4MinU)                         \
  V(I32x4MaxU, kArmI32x4MaxU)                         \
  V(I32x4GtU, kArmI32x4GtU)                           \
  V(I32x4GeU, kArmI32x4GeU)                           \
  V(I16x8SConvertI32x4, kArmI16x8SConvertI32x4)       \
  V(I16x8AddSatS, kArmI16x8AddSatS)                   \
  V(I16x8Sub, kArmI16x8Sub)                           \
  V(I16x8SubSatS, kArmI16x8SubSatS)                   \
  V(I16x8Mul, kArmI16x8Mul)                           \
  V(I16x8MinS, kArmI16x8MinS)                         \
  V(I16x8MaxS, kArmI16x8MaxS)                         \
  V(I16x8Eq, kArmI16x8Eq)                             \
  V(I16x8Ne, kArmI16x8Ne)                             \
  V(I16x8GtS, kArmI16x8GtS)                           \
  V(I16x8GeS, kArmI16x8GeS)                           \
  V(I16x8UConvertI32x4, kArmI16x8UConvertI32x4)       \
  V(I16x8AddSatU, kArmI16x8AddSatU)                   \
  V(I16x8SubSatU, kArmI16x8SubSatU)                   \
  V(I16x8MinU, kArmI16x8MinU)                         \
  V(I16x8MaxU, kArmI16x8MaxU)                         \
  V(I16x8GtU, kArmI16x8GtU)                           \
  V(I16x8GeU, kArmI16x8GeU)                           \
  V(I16x8RoundingAverageU, kArmI16x8RoundingAverageU) \
  V(I16x8Q15MulRSatS, kArmI16x8Q15MulRSatS)           \
  V(I16x8RelaxedQ15MulRS, kArmI16x8Q15MulRSatS)       \
  V(I8x16SConvertI16x8, kArmI8x16SConvertI16x8)       \
  V(I8x16Add, kArmI8x16Add)                           \
  V(I8x16AddSatS, kArmI8x16AddSatS)                   \
  V(I8x16Sub, kArmI8x16Sub)                           \
  V(I8x16SubSatS, kArmI8x16SubSatS)                   \
  V(I8x16MinS, kArmI8x16MinS)                         \
  V(I8x16MaxS, kArmI8x16MaxS)                         \
  V(I8x16Eq, kArmI8x16Eq)                             \
  V(I8x16Ne, kArmI8x16Ne)                             \
  V(I8x16GtS, kArmI8x16GtS)                           \
  V(I8x16GeS, kArmI8x16GeS)                           \
  V(I8x16UConvertI16x8, kArmI8x16UConvertI16x8)       \
  V(I8x16AddSatU, kArmI8x16AddSatU)                   \
  V(I8x16SubSatU, kArmI8x16SubSatU)                   \
  V(I8x16MinU, kArmI8x16MinU)                         \
  V(I8x16MaxU, kArmI8x16MaxU)                         \
  V(I8x16GtU, kArmI8x16GtU)                           \
  V(I8x16GeU, kArmI8x16GeU)                           \
  V(I8x16RoundingAverageU, kArmI8x16RoundingAverageU) \
  V(S128And, kArmS128And)                             \
  V(S128Or, kArmS128Or)                               \
  V(S128Xor, kArmS128Xor)                             \
  V(S128AndNot, kArmS128AndNot)

#if V8_ENABLE_WEBASSEMBLY
template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI32x4DotI16x8S(node_t node) {
  ArmOperandGeneratorT<Adapter> g(this);
  Emit(kArmI32x4DotI16x8S, g.DefineAsRegister(node),
       g.UseUniqueRegister(this->input_at(node, 0)),
       g.UseUniqueRegister(this->input_at(node, 1)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI16x8DotI8x16I7x16S(node_t node) {
  ArmOperandGeneratorT<Adapter> g(this);
  Emit(kArmI16x8DotI8x16S, g.DefineAsRegister(node),
       g.UseUniqueRegister(this->input_at(node, 0)),
       g.UseUniqueRegister(this->input_at(node, 1)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI32x4DotI8x16I7x16AddS(node_t node) {
  ArmOperandGeneratorT<Adapter> g(this);
  InstructionOperand temps[] = {g.TempSimd128Register()};
  Emit(kArmI32x4DotI8x16AddS, g.DefineSameAsInput(node, 2),
       g.UseUniqueRegister(this->input_at(node, 0)),
       g.UseUniqueRegister(this->input_at(node, 1)),
       g.UseUniqueRegister(this->input_at(node, 2)), arraysize(temps), temps);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitS128Const(node_t node) {
  ArmOperandGeneratorT<Adapter> g(this);
  uint32_t val[kSimd128Size / sizeof(uint32_t)];
  if constexpr (Adapter::IsTurboshaft) {
    const turboshaft::Simd128ConstantOp& constant =
        this->Get(node).template Cast<turboshaft::Simd128ConstantOp>();
    memcpy(val, constant.value, kSimd128Size);
  } else {
    memcpy(val, S128ImmediateParameterOf(node->op()).data(), kSimd128Size);
  }
  // If all bytes are zeros, avoid emitting code for generic constants.
  bool all_zeros = !(val[0] || val[1] || val[2] || val[3]);
  bool all_ones = val[0] == UINT32_MAX && val[1] == UINT32_MAX &&
                  val[2] == UINT32_MAX && val[3] == UINT32_MAX;
  InstructionOperand dst = g.DefineAsRegister(node);
  if (all_zeros) {
    Emit(kArmS128Zero, dst);
  } else if (all_ones) {
    Emit(kArmS128AllOnes, dst);
  } else {
    Emit(kArmS128Const, dst, g.UseImmediate(val[0])
```