Response: The user wants a summary of the provided C++ code snippet, which is part 3 of 3 of a file named `instruction-selector-s390.cc`. This file is located within the V8 JavaScript engine's compiler for the s390 architecture.

Therefore, the primary goal is to understand the functionalities implemented in this specific portion of the instruction selector. Given the context, it's highly likely that this code deals with selecting and emitting machine instructions for various intermediate representation (IR) operations on the s390 architecture.

The snippet contains a large number of template functions within the `InstructionSelectorT` class. These functions appear to handle specific IR opcodes.

Let's break down the code section by section:

1. **Conditional Branch Handling:** The `VisitConditionalExpression` function seems to optimize conditional branches by potentially combining them with preceding comparison operations. If not combinable, it emits a `LoadAndTest` instruction.

2. **Switch Statement Handling:** The `VisitSwitch` function implements logic for selecting between a table-based switch and a binary search-based switch based on the range of values and the number of cases.

3. **Comparison Operations:**  A series of `VisitWord32Equal`, `VisitInt32LessThan`, etc., functions are present. These seem to handle comparison operations and set the processor flags accordingly. Some of these functions also have specific optimizations for comparisons with zero.

4. **Floating-Point Comparisons:** Similar to integer comparisons, functions like `VisitFloat32Equal`, `VisitFloat32LessThan`, etc., are used for floating-point comparisons.

5. **Bitcast Operation:**  `VisitBitcastWord32PairToFloat64` handles the conversion of a 32-bit integer pair to a 64-bit float.

6. **Parameter Passing:**  `EmitMoveParamToFPR`, `EmitMoveFPRToParam`, and `EmitPrepareArguments` seem to manage the movement of parameters between registers and the stack during function calls, considering both C function calls and regular JavaScript calls.

7. **Memory Barrier:** `VisitMemoryBarrier` likely inserts a memory barrier instruction to ensure memory ordering.

8. **Atomic Operations:** A significant portion of the code deals with atomic operations like `VisitWord32AtomicLoad`, `VisitWord32AtomicStore`, `VisitWord32AtomicExchange`, `VisitWord32AtomicCompareExchange`, and various atomic binary operations (Add, Sub, And, Or, Xor) for both 32-bit and 64-bit values. These functions emit specific atomic instructions for the s390 architecture.

9. **SIMD Operations:**  A large section of the code is dedicated to handling SIMD (Single Instruction, Multiple Data) operations. This includes functions for various SIMD types (F64x2, F32x4, I64x2, etc.) and operations like addition, subtraction, multiplication, comparison, lane extraction, lane replacement, shuffling, swizzling, and more. There's also specific handling for relaxed SIMD operations and potentially for 16-bit floating-point (F16x8) operations.

10. **WebAssembly Integration:**  There are specific code sections and conditional compilation (`#if V8_ENABLE_WEBASSEMBLY`) related to WebAssembly, particularly for SIMD instructions like `I8x16Shuffle` and `I8x16Swizzle`, as well as handling stack pointer manipulation (`VisitSetStackPointer`).

11. **Constant Loading:** `VisitS128Const` handles loading constant SIMD values, optimizing for all-zeros and all-ones cases.

12. **Result Preparation:** `EmitPrepareResults` deals with moving function call results back to the appropriate locations.

13. **Load and Store with Lane:** Functions like `VisitLoadLane` and `VisitStoreLane` handle loading and storing specific lanes of SIMD vectors.

14. **Load Transform:** `VisitLoadTransform` seems to handle loading data into SIMD registers with various transformations (e.g., splatting, extending).

15. **Dot Product:**  `VisitI16x8DotI8x16I7x16S` and `VisitI32x4DotI8x16I7x16AddS` handle dot product operations on SIMD vectors.

16. **Floating-Point Truncation:** `VisitTruncateFloat32ToInt32` and `VisitTruncateFloat32ToUint32` handle the truncation of floating-point numbers to integers, potentially considering overflow behavior.

17. **Helper Functions and Configuration:** There are helper functions and configurations like `SupportedMachineOperatorFlags` and `AlignmentRequirements` that define the capabilities and requirements of the instruction selector.

**Relationship to JavaScript:**

This code is a crucial part of the V8 JavaScript engine's compilation pipeline. When JavaScript code is executed, V8 compiles it into machine code for the target architecture (in this case, s390). The `instruction-selector-s390.cc` file plays a vital role in this process by taking the high-level operations represented in V8's intermediate representation (IR) and translating them into specific machine instructions for the s390 processor.

**JavaScript Examples:**

Let's illustrate with JavaScript examples how some of these functionalities relate:

* **Integer Comparisons:**
   ```javascript
   let a = 10;
   let b = 5;
   if (a > b) { // This would likely trigger a comparison operation handled by VisitInt32LessThan (after negation) or similar.
       console.log("a is greater than b");
   }
   ```

* **Floating-Point Comparisons:**
   ```javascript
   let x = 3.14;
   let y = 2.71;
   if (x < y) { // This would likely trigger a comparison operation handled by VisitFloat64LessThan or similar.
       console.log("x is less than y");
   }
   ```

* **Atomic Operations (SharedArrayBuffer):**
   ```javascript
   const sab = new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT * 1);
   const view = new Int32Array(sab);
   Atomics.add(view, 0, 5); // This will use the atomic operations handled by VisitWord32AtomicAdd.
   ```

* **SIMD Operations:**
   ```javascript
   const a = Float32x4(1, 2, 3, 4);
   const b = Float32x4(5, 6, 7, 8);
   const sum = a.add(b); // This will utilize the SIMD operations handled by VisitF32x4Add.
   console.log(sum); // Output: Float32x4(6, 8, 10, 12)
   ```

* **Switch Statements:**
   ```javascript
   let day = 2;
   switch (day) { // This would trigger the switch statement logic in VisitSwitch.
       case 1:
           console.log("Monday");
           break;
       case 2:
           console.log("Tuesday");
           break;
       default:
           console.log("Other day");
   }
   ```

In summary, this part of the `instruction-selector-s390.cc` file is responsible for a wide range of code generation tasks within the V8 compiler for the s390 architecture, covering conditional branches, switch statements, integer and floating-point comparisons, atomic operations, SIMD instructions, and interactions with WebAssembly. It directly translates JavaScript language features into low-level machine instructions.
这是 `v8/src/compiler/backend/s390/instruction-selector-s390.cc` 文件的第三部分，它主要负责 **将 V8 的中间表示 (IR) 节点转换成 S390 架构的机器指令**。更具体地说，这部分代码实现了 `InstructionSelectorT` 类的成员函数，这些函数对应着特定的 IR 节点类型，并生成相应的 S390 指令序列。

**主要功能归纳如下：**

1. **处理控制流相关的 IR 节点:**
   - `VisitConditionalExpression`:  尝试将条件表达式与之前的比较操作合并，如果不能合并，则生成 `LoadAndTest` 指令。
   - `VisitSwitch`:  实现 `switch` 语句的指令选择，根据 `switch` 语句的范围和 case 数量选择生成跳转表或二分查找的指令序列。

2. **处理比较相关的 IR 节点:**
   - `VisitWord32Equal`, `VisitInt32LessThan`, `VisitInt32LessThanOrEqual`, `VisitUint32LessThan`, `VisitUint32LessThanOrEqual`: 处理 32 位整数的相等、小于、小于等于的比较操作，并设置相应的条件码。
   - `VisitWord64Equal`, `VisitInt64LessThan`, `VisitInt64LessThanOrEqual`, `VisitUint64LessThan`, `VisitUint64LessThanOrEqual`: 处理 64 位整数的比较操作。
   - `VisitFloat32Equal`, `VisitFloat32LessThan`, `VisitFloat32LessThanOrEqual`: 处理 32 位浮点数的比较操作。
   - `VisitFloat64Equal`, `VisitFloat64LessThan`, `VisitFloat64LessThanOrEqual`: 处理 64 位浮点数的比较操作。

3. **处理类型转换相关的 IR 节点:**
   - `VisitTruncateFloat64ToFloat16RawBits`: 将 64 位浮点数截断为 16 位浮点数（未实现）。
   - `VisitBitcastWord32PairToFloat64`: 将两个 32 位整数的组合转换为 64 位浮点数。

4. **处理函数调用相关的 IR 节点:**
   - `EmitMoveParamToFPR`, `EmitMoveFPRToParam`:  移动参数到浮点寄存器或从浮点寄存器移动参数。
   - `EmitPrepareArguments`:  为函数调用准备参数，包括 C 函数调用和 JavaScript 函数调用，涉及参数压栈等操作。
   - `EmitPrepareResults`: 为函数调用准备返回值，将返回值从特定位置移动到寄存器。

5. **处理内存操作相关的 IR 节点:**
   - `VisitMemoryBarrier`: 生成内存屏障指令。
   - `VisitWord32AtomicLoad`, `VisitWord64AtomicLoad`:  生成原子加载指令。
   - `VisitWord32AtomicStore`, `VisitWord64AtomicStore`:  生成原子存储指令。
   - `VisitWord32AtomicExchange`, `VisitWord64AtomicExchange`: 生成原子交换指令。
   - `VisitWord32AtomicCompareExchange`, `VisitWord64AtomicCompareExchange`: 生成原子比较并交换指令。
   - `VisitWord32AtomicAdd`, `VisitWord32AtomicSub`, `VisitWord32AtomicAnd`, `VisitWord32AtomicOr`, `VisitWord32AtomicXor`: 生成 32 位原子算术和逻辑运算指令。
   - `VisitWord64AtomicAdd`, `VisitWord64AtomicSub`, `VisitWord64AtomicAnd`, `VisitWord64AtomicOr`, `VisitWord64AtomicXor`: 生成 64 位原子算术和逻辑运算指令。
   - `VisitLoadLane`, `VisitStoreLane`: 处理 SIMD 向量特定 lane 的加载和存储操作。
   - `VisitLoadTransform`: 处理 SIMD 向量的加载并进行特定转换的操作，例如 splat。

6. **处理 SIMD (Single Instruction, Multiple Data) 相关的 IR 节点:**
   - 提供了大量的 `Visit` 函数来处理各种 SIMD 操作，涵盖了不同数据类型 (F64x2, F32x4, I64x2, I32x4, I16x8, I8x16) 的加减乘除、比较、绝对值、取反、平方根、截断、舍入、转换、位运算、移位、车道操作 (提取、替换、shuffle、swizzle) 等。
   - 包括了对 Relaxed SIMD 操作的支持。
   - 也包含对 WebAssembly SIMD 指令的支持 (`VisitI8x16Shuffle`, `VisitI8x16Swizzle`)。
   - `VisitS128Const`, `VisitS128Zero`, `VisitS128Select`: 处理 SIMD 常量、零向量和选择操作。

7. **处理 WebAssembly 特有的 IR 节点:**
   - `VisitSetStackPointer`:  设置栈指针（仅在 WebAssembly 启用时）。

8. **处理浮点数截断为整数的 IR 节点:**
   - `VisitTruncateFloat32ToInt32`, `VisitTruncateFloat32ToUint32`:  将 32 位浮点数截断为 32 位有符号和无符号整数。

**与 Javascript 的关系:**

这段 C++ 代码是 V8 JavaScript 引擎的核心组成部分，它负责将 JavaScript 代码编译成可以在 S390 架构上执行的机器码。当 JavaScript 代码执行时，V8 会将其解析成抽象语法树 (AST)，然后将 AST 转换为中间表示 (IR)。`instruction-selector-s390.cc` 中的代码就是在这个阶段工作的，它将 IR 节点翻译成底层的机器指令。

**Javascript 举例说明:**

* **整数比较:**
  ```javascript
  let a = 10;
  let b = 5;
  if (a > b) { //  这段代码在编译时，`VisitInt32LessThan` (或者类似的函数) 会被调用来生成 S390 的比较指令。
    console.log("a 大于 b");
  }
  ```

* **浮点数运算:**
  ```javascript
  let x = 3.14;
  let y = 2.0;
  let sum = x + y; //  `VisitFloat64Add` (假设是 64 位浮点数) 会生成 S390 的浮点数加法指令。
  ```

* **原子操作 (使用 SharedArrayBuffer):**
  ```javascript
  const sab = new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT);
  const view = new Int32Array(sab);
  Atomics.add(view, 0, 5); // `VisitWord32AtomicAdd` 会生成相应的原子加法指令，保证线程安全。
  ```

* **SIMD 操作:**
  ```javascript
  const a = Float32x4(1, 2, 3, 4);
  const b = Float32x4(5, 6, 7, 8);
  const sum = a.add(b); // `VisitF32x4Add` 会生成 S390 的 SIMD 加法指令，一次处理多个浮点数。
  ```

* **Switch 语句:**
  ```javascript
  let day = 2;
  switch (day) { // `VisitSwitch` 会根据情况生成跳转表或二分查找的指令序列。
    case 1:
      console.log("星期一");
      break;
    case 2:
      console.log("星期二");
      break;
    default:
      console.log("其他");
  }
  ```

总而言之，`instruction-selector-s390.cc` 的这部分代码是 V8 将 JavaScript 代码高效地编译成 S390 机器码的关键环节，它连接了高级的 JavaScript 语义和底层的硬件指令。

Prompt: 
```
这是目录为v8/src/compiler/backend/s390/instruction-selector-s390.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第3部分，共3部分，请归纳一下它的功能

"""
      return VisitWord64UnaryOp(this, node, kS390_Abs64,
                                          OperandMode::kNone, cont);
              case IrOpcode::kInt64AddWithOverflow:
                cont->OverwriteAndNegateIfEqual(kOverflow);
                return VisitWord64BinOp(this, node, kS390_Add64, AddOperandMode,
                                        cont);
              case IrOpcode::kInt64SubWithOverflow:
                cont->OverwriteAndNegateIfEqual(kOverflow);
                return VisitWord64BinOp(this, node, kS390_Sub64, SubOperandMode,
                                        cont);
              case IrOpcode::kInt64MulWithOverflow:
                cont->OverwriteAndNegateIfEqual(
                    CpuFeatures::IsSupported(MISC_INSTR_EXT2) ? kOverflow
                                                              : kNotEqual);
                return EmitInt64MulWithOverflow(this, node, cont);
              default:
                break;
            }
          }
        }
        break;
      case IrOpcode::kInt32Sub:
        if (fc == kNotEqual || fc == kEqual)
          return VisitWord32Compare(this, value, cont);
        break;
      case IrOpcode::kWord32And:
        return VisitTestUnderMask(this, value, cont);
      case IrOpcode::kLoad:
      case IrOpcode::kLoadImmutable: {
        LoadRepresentation load_rep = LoadRepresentationOf(value->op());
        switch (load_rep.representation()) {
          case MachineRepresentation::kWord32:
            return VisitLoadAndTest(this, kS390_LoadAndTestWord32, user, value,
                                    cont);
          default:
            break;
        }
        break;
      }
      case IrOpcode::kInt32Add:
        // can't handle overflow case.
        break;
      case IrOpcode::kWord32Or:
        if (fc == kNotEqual || fc == kEqual)
          return VisitWord32BinOp(this, value, kS390_Or32, Or32OperandMode,
                                  cont);
        break;
      case IrOpcode::kWord32Xor:
        if (fc == kNotEqual || fc == kEqual)
          return VisitWord32BinOp(this, value, kS390_Xor32, Xor32OperandMode,
                                  cont);
        break;
      case IrOpcode::kWord32Sar:
      case IrOpcode::kWord32Shl:
      case IrOpcode::kWord32Shr:
      case IrOpcode::kWord32Ror:
        // doesn't generate cc, so ignore.
        break;
      case IrOpcode::kInt64Sub:
        if (fc == kNotEqual || fc == kEqual)
          return VisitWord64Compare(this, value, cont);
        break;
      case IrOpcode::kWord64And:
        return VisitTestUnderMask(this, value, cont);
      case IrOpcode::kInt64Add:
        // can't handle overflow case.
        break;
      case IrOpcode::kWord64Or:
        if (fc == kNotEqual || fc == kEqual)
          return VisitWord64BinOp(this, value, kS390_Or64, Or64OperandMode,
                                  cont);
        break;
      case IrOpcode::kWord64Xor:
        if (fc == kNotEqual || fc == kEqual)
          return VisitWord64BinOp(this, value, kS390_Xor64, Xor64OperandMode,
                                  cont);
        break;
      case IrOpcode::kWord64Sar:
      case IrOpcode::kWord64Shl:
      case IrOpcode::kWord64Shr:
      case IrOpcode::kWord64Ror:
        // doesn't generate cc, so ignore
        break;
      case IrOpcode::kStackPointerGreaterThan:
        cont->OverwriteAndNegateIfEqual(kStackPointerGreaterThanCondition);
        return VisitStackPointerGreaterThan(value, cont);
      default:
        break;
      }
    }

  // Branch could not be combined with a compare, emit LoadAndTest
  VisitLoadAndTest(this, kS390_LoadAndTestWord32, user, value, cont, true);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitSwitch(node_t node,
                                                const SwitchInfo& sw) {
  S390OperandGeneratorT<Adapter> g(this);
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
      Emit(kS390_Lay | AddressingModeField::encode(kMode_MRI), index_operand,
           value_operand, g.TempImmediate(-sw.min_value()));
      }
      InstructionOperand index_operand_zero_ext = g.TempRegister();
      Emit(kS390_Uint32ToUint64, index_operand_zero_ext, index_operand);
      index_operand = index_operand_zero_ext;
      // Generate a table lookup.
      return EmitTableSwitch(sw, index_operand);
  }
  }

  // Generate a tree of conditional jumps.
  return EmitBinarySearchSwitch(sw, value_operand);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Equal(node_t const node) {
  FlagsContinuation cont = FlagsContinuation::ForSet(kEqual, node);
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const ComparisonOp& op = this->Get(node).template Cast<ComparisonOp>();
    if (this->MatchIntegralZero(op.right())) {
      return VisitLoadAndTest(this, kS390_LoadAndTestWord32, node, op.left(),
                              &cont, true);
    }

  } else {
    Int32BinopMatcher m(node);
    if (m.right().Is(0)) {
      return VisitLoadAndTest(this, kS390_LoadAndTestWord32, m.node(),
                              m.left().node(), &cont, true);
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
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const ComparisonOp& op = this->Get(node).template Cast<ComparisonOp>();
    if (this->MatchIntegralZero(op.right())) {
      return VisitLoadAndTest(this, kS390_LoadAndTestWord64, node, op.left(),
                              &cont, true);
    }
  } else {
  Int64BinopMatcher m(node);
  if (m.right().Is(0)) {
      return VisitLoadAndTest(this, kS390_LoadAndTestWord64, m.node(),
                              m.left().node(), &cont, true);
  }
  }
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
void InstructionSelectorT<Adapter>::VisitTruncateFloat64ToFloat16RawBits(
    node_t node) {
  UNIMPLEMENTED();
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

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitBitcastWord32PairToFloat64(
    node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  S390OperandGeneratorT<TurboshaftAdapter> g(this);
  const auto& bitcast = this->Cast<BitcastWord32PairToFloat64Op>(node);
  node_t hi = bitcast.high_word32();
  node_t lo = bitcast.low_word32();

  InstructionOperand temps[] = {g.TempRegister()};
  Emit(kS390_DoubleFromWord32Pair, g.DefineAsRegister(node), g.UseRegister(hi),
       g.UseRegister(lo), arraysize(temps), temps);
}

template <typename Adapter>
bool InstructionSelectorT<Adapter>::ZeroExtendsWord32ToWord64NoPhis(
    node_t node) {
  UNIMPLEMENTED();
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
  S390OperandGeneratorT<Adapter> g(this);

  // Prepare for C function call.
  if (call_descriptor->IsCFunctionCall()) {
      Emit(kArchPrepareCallCFunction | MiscField::encode(static_cast<int>(
                                           call_descriptor->ParameterCount())),
           0, nullptr, 0, nullptr);

      // Poke any stack arguments.
      int slot = kStackFrameExtraParamSlot;
      for (PushParameter input : (*arguments)) {
        if (!this->valid(input.node)) continue;
        Emit(kS390_StoreToStackSlot, g.NoOutput(), g.UseRegister(input.node),
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
      Emit(kS390_Push, g.NoOutput(), decrement, g.UseRegister(input.node));
      }
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitMemoryBarrier(node_t node) {
  S390OperandGeneratorT<Adapter> g(this);
  Emit(kArchNop, g.NoOutput());
}

template <typename Adapter>
bool InstructionSelectorT<Adapter>::IsTailCallAddressImmediate() {
  return false;
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicLoad(node_t node) {
  auto load = this->load_view(node);
  LoadRepresentation load_rep = load.loaded_rep();
  VisitLoad(node, node, SelectLoadOpcode(load_rep));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicStore(node_t node) {
  auto store = this->store_view(node);
  AtomicStoreParameters store_params(store.stored_rep().representation(),
                                     store.stored_rep().write_barrier_kind(),
                                     store.memory_order().value(),
                                     store.access_kind());
  VisitGeneralStore(this, node, store_params.representation());
}

template <typename Adapter>
void VisitAtomicExchange(InstructionSelectorT<Adapter>* selector,
                         typename Adapter::node_t node, ArchOpcode opcode,
                         AtomicWidth width) {
  using node_t = typename Adapter::node_t;
  S390OperandGeneratorT<Adapter> g(selector);
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
  outputs[0] = g.DefineAsRegister(node);
  InstructionCode code = opcode | AddressingModeField::encode(addressing_mode) |
                         AtomicWidthField::encode(width);
  selector->Emit(code, 1, outputs, input_count, inputs);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitWord32AtomicExchange(
    node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  ArchOpcode opcode;
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
  VisitAtomicExchange(this, node, opcode, AtomicWidth::kWord32);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitWord32AtomicExchange(
    node_t node) {
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
  ArchOpcode opcode;
  using namespace turboshaft;  // NOLINT(build/namespaces)
  const AtomicRMWOp& atomic_op = this->Get(node).template Cast<AtomicRMWOp>();
  if (atomic_op.memory_rep == MemoryRepresentation::Uint8()) {
    opcode = kAtomicExchangeUint8;
  } else if (atomic_op.memory_rep == MemoryRepresentation::Uint16()) {
    opcode = kAtomicExchangeUint16;
  } else if (atomic_op.memory_rep == MemoryRepresentation::Uint32()) {
    opcode = kAtomicExchangeWord32;
  } else if (atomic_op.memory_rep == MemoryRepresentation::Uint64()) {
    opcode = kS390_Word64AtomicExchangeUint64;
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
    opcode = kS390_Word64AtomicExchangeUint64;
  } else {
    UNREACHABLE();
  }
  VisitAtomicExchange(this, node, opcode, AtomicWidth::kWord64);
}

template <typename Adapter>
void VisitAtomicCompareExchange(InstructionSelectorT<Adapter>* selector,
                                typename Adapter::node_t node,
                                ArchOpcode opcode, AtomicWidth width) {
  using node_t = typename Adapter::node_t;
  S390OperandGeneratorT<Adapter> g(selector);
  auto atomic_op = selector->atomic_rmw_view(node);
  node_t base = atomic_op.base();
  node_t index = atomic_op.index();
  node_t old_value = atomic_op.expected();
  node_t new_value = atomic_op.value();

  InstructionOperand inputs[4];
  size_t input_count = 0;
  inputs[input_count++] = g.UseUniqueRegister(old_value);
  inputs[input_count++] = g.UseUniqueRegister(new_value);
  inputs[input_count++] = g.UseUniqueRegister(base);

  AddressingMode addressing_mode;
  if (g.CanBeImmediate(index, OperandMode::kInt20Imm)) {
    inputs[input_count++] = g.UseImmediate(index);
    addressing_mode = kMode_MRI;
  } else {
    inputs[input_count++] = g.UseUniqueRegister(index);
    addressing_mode = kMode_MRR;
  }

  InstructionOperand outputs[1];
  size_t output_count = 0;
  outputs[output_count++] = g.DefineSameAsFirst(node);

  InstructionCode code = opcode | AddressingModeField::encode(addressing_mode) |
                         AtomicWidthField::encode(width);
  selector->Emit(code, output_count, outputs, input_count, inputs);
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
  MachineType type = AtomicOpType(node->op());
  ArchOpcode opcode;
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
    opcode = kS390_Word64AtomicCompareExchangeUint64;
  } else {
    UNREACHABLE();
  }
  VisitAtomicCompareExchange(this, node, opcode, AtomicWidth::kWord64);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitWord64AtomicCompareExchange(
    Node* node) {
  MachineType type = AtomicOpType(node->op());
  ArchOpcode opcode;
  if (type == MachineType::Uint8()) {
    opcode = kAtomicCompareExchangeUint8;
  } else if (type == MachineType::Uint16()) {
    opcode = kAtomicCompareExchangeUint16;
  } else if (type == MachineType::Uint32()) {
    opcode = kAtomicCompareExchangeWord32;
  } else if (type == MachineType::Uint64()) {
    opcode = kS390_Word64AtomicCompareExchangeUint64;
  } else {
    UNREACHABLE();
  }
  VisitAtomicCompareExchange(this, node, opcode, AtomicWidth::kWord64);
}

template <typename Adapter>
void VisitAtomicBinop(InstructionSelectorT<Adapter>* selector,
                      typename Adapter::node_t node, ArchOpcode opcode,
                      AtomicWidth width) {
  using node_t = typename Adapter::node_t;
  S390OperandGeneratorT<Adapter> g(selector);
  auto atomic_op = selector->atomic_rmw_view(node);
  node_t base = atomic_op.base();
  node_t index = atomic_op.index();
  node_t value = atomic_op.value();

  InstructionOperand inputs[3];
  size_t input_count = 0;
  inputs[input_count++] = g.UseUniqueRegister(base);

  AddressingMode addressing_mode;
  if (g.CanBeImmediate(index, OperandMode::kInt20Imm)) {
    inputs[input_count++] = g.UseImmediate(index);
    addressing_mode = kMode_MRI;
  } else {
    inputs[input_count++] = g.UseUniqueRegister(index);
    addressing_mode = kMode_MRR;
  }

  inputs[input_count++] = g.UseUniqueRegister(value);

  InstructionOperand outputs[1];
  size_t output_count = 0;
  outputs[output_count++] = g.DefineAsRegister(node);

  InstructionOperand temps[1];
  size_t temp_count = 0;
  temps[temp_count++] = g.TempRegister();

  InstructionCode code = opcode | AddressingModeField::encode(addressing_mode) |
                         AtomicWidthField::encode(width);
  selector->Emit(code, output_count, outputs, input_count, inputs, temp_count,
                 temps);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicBinaryOperation(
    node_t node, ArchOpcode int8_op, ArchOpcode uint8_op, ArchOpcode int16_op,
    ArchOpcode uint16_op, ArchOpcode word32_op) {
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
  VisitAtomicBinop(this, node, opcode, AtomicWidth::kWord32);
}

#define VISIT_ATOMIC_BINOP(op)                                             \
  template <typename Adapter>                                              \
  void InstructionSelectorT<Adapter>::VisitWord32Atomic##op(node_t node) { \
      VisitWord32AtomicBinaryOperation(                                    \
          node, kAtomic##op##Int8, kAtomic##op##Uint8, kAtomic##op##Int16, \
          kAtomic##op##Uint16, kAtomic##op##Word32);                       \
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
    ArchOpcode word32_op, ArchOpcode word64_op) {
  ArchOpcode opcode;
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const AtomicRMWOp& atomic_op = this->Get(node).template Cast<AtomicRMWOp>();
    if (atomic_op.memory_rep == MemoryRepresentation::Uint8()) {
      opcode = uint8_op;
    } else if (atomic_op.memory_rep == MemoryRepresentation::Uint16()) {
      opcode = uint16_op;
    } else if (atomic_op.memory_rep == MemoryRepresentation::Uint32()) {
      opcode = word32_op;
    } else if (atomic_op.memory_rep == MemoryRepresentation::Uint64()) {
      opcode = word64_op;
    } else {
      UNREACHABLE();
    }
  } else {
    MachineType type = AtomicOpType(node->op());

    if (type == MachineType::Uint8()) {
      opcode = uint8_op;
    } else if (type == MachineType::Uint16()) {
      opcode = uint16_op;
    } else if (type == MachineType::Uint32()) {
      opcode = word32_op;
    } else if (type == MachineType::Uint64()) {
      opcode = word64_op;
    } else {
      UNREACHABLE();
    }
  }
  VisitAtomicBinop(this, node, opcode, AtomicWidth::kWord64);
}

#define VISIT_ATOMIC64_BINOP(op)                                              \
  template <typename Adapter>                                                 \
  void InstructionSelectorT<Adapter>::VisitWord64Atomic##op(node_t node) {    \
      VisitWord64AtomicBinaryOperation(                                       \
          node, kAtomic##op##Uint8, kAtomic##op##Uint16, kAtomic##op##Word32, \
          kS390_Word64Atomic##op##Uint64);                                    \
  }
VISIT_ATOMIC64_BINOP(Add)
VISIT_ATOMIC64_BINOP(Sub)
VISIT_ATOMIC64_BINOP(And)
VISIT_ATOMIC64_BINOP(Or)
VISIT_ATOMIC64_BINOP(Xor)
#undef VISIT_ATOMIC64_BINOP

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64AtomicLoad(node_t node) {
  auto load = this->load_view(node);
  LoadRepresentation load_rep = load.loaded_rep();
  VisitLoad(node, node, SelectLoadOpcode(load_rep));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64AtomicStore(node_t node) {
  auto store = this->store_view(node);
  AtomicStoreParameters store_params(store.stored_rep().representation(),
                                     store.stored_rep().write_barrier_kind(),
                                     store.memory_order().value(),
                                     store.access_kind());
  VisitGeneralStore(this, node, store_params.representation());
}

#define SIMD_TYPES(V) \
  V(F64x2)            \
  V(F32x4)            \
  V(I64x2)            \
  V(I32x4)            \
  V(I16x8)            \
  V(I8x16)

#define SIMD_BINOP_LIST(V) \
  V(F64x2Add)              \
  V(F64x2Sub)              \
  V(F64x2Mul)              \
  V(F64x2Div)              \
  V(F64x2Eq)               \
  V(F64x2Ne)               \
  V(F64x2Lt)               \
  V(F64x2Le)               \
  V(F64x2Min)              \
  V(F64x2Max)              \
  V(F64x2Pmin)             \
  V(F64x2Pmax)             \
  V(F32x4Add)              \
  V(F32x4Sub)              \
  V(F32x4Mul)              \
  V(F32x4Eq)               \
  V(F32x4Ne)               \
  V(F32x4Lt)               \
  V(F32x4Le)               \
  V(F32x4Div)              \
  V(F32x4Min)              \
  V(F32x4Max)              \
  V(F32x4Pmin)             \
  V(F32x4Pmax)             \
  V(I64x2Add)              \
  V(I64x2Sub)              \
  V(I64x2Mul)              \
  V(I64x2Eq)               \
  V(I64x2ExtMulLowI32x4S)  \
  V(I64x2ExtMulHighI32x4S) \
  V(I64x2ExtMulLowI32x4U)  \
  V(I64x2ExtMulHighI32x4U) \
  V(I64x2Ne)               \
  V(I64x2GtS)              \
  V(I64x2GeS)              \
  V(I64x2Shl)              \
  V(I64x2ShrS)             \
  V(I64x2ShrU)             \
  V(I32x4Add)              \
  V(I32x4Sub)              \
  V(I32x4Mul)              \
  V(I32x4MinS)             \
  V(I32x4MinU)             \
  V(I32x4MaxS)             \
  V(I32x4MaxU)             \
  V(I32x4Eq)               \
  V(I32x4Ne)               \
  V(I32x4GtS)              \
  V(I32x4GeS)              \
  V(I32x4GtU)              \
  V(I32x4GeU)              \
  V(I32x4ExtMulLowI16x8S)  \
  V(I32x4ExtMulHighI16x8S) \
  V(I32x4ExtMulLowI16x8U)  \
  V(I32x4ExtMulHighI16x8U) \
  V(I32x4Shl)              \
  V(I32x4ShrS)             \
  V(I32x4ShrU)             \
  V(I32x4DotI16x8S)        \
  V(I16x8Add)              \
  V(I16x8Sub)              \
  V(I16x8Mul)              \
  V(I16x8MinS)             \
  V(I16x8MinU)             \
  V(I16x8MaxS)             \
  V(I16x8MaxU)             \
  V(I16x8Eq)               \
  V(I16x8Ne)               \
  V(I16x8GtS)              \
  V(I16x8GeS)              \
  V(I16x8GtU)              \
  V(I16x8GeU)              \
  V(I16x8SConvertI32x4)    \
  V(I16x8UConvertI32x4)    \
  V(I16x8RoundingAverageU) \
  V(I16x8ExtMulLowI8x16S)  \
  V(I16x8ExtMulHighI8x16S) \
  V(I16x8ExtMulLowI8x16U)  \
  V(I16x8ExtMulHighI8x16U) \
  V(I16x8Shl)              \
  V(I16x8ShrS)             \
  V(I16x8ShrU)             \
  V(I8x16Add)              \
  V(I8x16Sub)              \
  V(I8x16MinS)             \
  V(I8x16MinU)             \
  V(I8x16MaxS)             \
  V(I8x16MaxU)             \
  V(I8x16Eq)               \
  V(I8x16Ne)               \
  V(I8x16GtS)              \
  V(I8x16GeS)              \
  V(I8x16GtU)              \
  V(I8x16GeU)              \
  V(I8x16SConvertI16x8)    \
  V(I8x16UConvertI16x8)    \
  V(I8x16RoundingAverageU) \
  V(I8x16Shl)              \
  V(I8x16ShrS)             \
  V(I8x16ShrU)             \
  V(S128And)               \
  V(S128Or)                \
  V(S128Xor)               \
  V(S128AndNot)

#define SIMD_BINOP_UNIQUE_REGISTER_LIST(V) \
  V(I16x8AddSatS)                          \
  V(I16x8SubSatS)                          \
  V(I16x8AddSatU)                          \
  V(I16x8SubSatU)                          \
  V(I16x8Q15MulRSatS)                      \
  V(I8x16AddSatS)                          \
  V(I8x16SubSatS)                          \
  V(I8x16AddSatU)                          \
  V(I8x16SubSatU)

#define SIMD_UNOP_LIST(V)    \
  V(F64x2Abs)                \
  V(F64x2Neg)                \
  V(F64x2Sqrt)               \
  V(F64x2Ceil)               \
  V(F64x2Floor)              \
  V(F64x2Trunc)              \
  V(F64x2NearestInt)         \
  V(F64x2ConvertLowI32x4S)   \
  V(F64x2ConvertLowI32x4U)   \
  V(F64x2PromoteLowF32x4)    \
  V(F64x2Splat)              \
  V(F32x4Abs)                \
  V(F32x4Neg)                \
  V(F32x4Sqrt)               \
  V(F32x4Ceil)               \
  V(F32x4Floor)              \
  V(F32x4Trunc)              \
  V(F32x4NearestInt)         \
  V(F32x4DemoteF64x2Zero)    \
  V(F32x4SConvertI32x4)      \
  V(F32x4UConvertI32x4)      \
  V(F32x4Splat)              \
  V(I64x2Neg)                \
  V(I64x2SConvertI32x4Low)   \
  V(I64x2SConvertI32x4High)  \
  V(I64x2UConvertI32x4Low)   \
  V(I64x2UConvertI32x4High)  \
  V(I64x2Abs)                \
  V(I64x2BitMask)            \
  V(I64x2Splat)              \
  V(I64x2AllTrue)            \
  V(I32x4Neg)                \
  V(I32x4Abs)                \
  V(I32x4SConvertF32x4)      \
  V(I32x4UConvertF32x4)      \
  V(I32x4SConvertI16x8Low)   \
  V(I32x4SConvertI16x8High)  \
  V(I32x4UConvertI16x8Low)   \
  V(I32x4UConvertI16x8High)  \
  V(I32x4TruncSatF64x2SZero) \
  V(I32x4TruncSatF64x2UZero) \
  V(I32x4BitMask)            \
  V(I32x4Splat)              \
  V(I32x4AllTrue)            \
  V(I16x8Neg)                \
  V(I16x8Abs)                \
  V(I16x8SConvertI8x16Low)   \
  V(I16x8SConvertI8x16High)  \
  V(I16x8UConvertI8x16Low)   \
  V(I16x8UConvertI8x16High)  \
  V(I16x8BitMask)            \
  V(I16x8Splat)              \
  V(I16x8AllTrue)            \
  V(I8x16Neg)                \
  V(I8x16Abs)                \
  V(I8x16Popcnt)             \
  V(I8x16BitMask)            \
  V(I8x16Splat)              \
  V(I8x16AllTrue)            \
  V(S128Not)                 \
  V(V128AnyTrue)

#define SIMD_UNOP_UNIQUE_REGISTER_LIST(V) \
  V(I32x4ExtAddPairwiseI16x8S)            \
  V(I32x4ExtAddPairwiseI16x8U)            \
  V(I16x8ExtAddPairwiseI8x16S)            \
  V(I16x8ExtAddPairwiseI8x16U)

#define SIMD_VISIT_EXTRACT_LANE(Type, Sign)                             \
  template <typename Adapter>                                           \
  void InstructionSelectorT<Adapter>::Visit##Type##ExtractLane##Sign(   \
      node_t node) {                                                    \
    S390OperandGeneratorT<Adapter> g(this);                             \
    int32_t lane;                                                       \
    if constexpr (Adapter::IsTurboshaft) {                              \
      using namespace turboshaft; /* NOLINT(build/namespaces) */        \
      const Operation& op = this->Get(node);                            \
      lane = op.template Cast<Simd128ExtractLaneOp>().lane;             \
    } else {                                                            \
      lane = OpParameter<int32_t>(node->op());                          \
    }                                                                   \
    Emit(kS390_##Type##ExtractLane##Sign, g.DefineAsRegister(node),     \
         g.UseRegister(this->input_at(node, 0)), g.UseImmediate(lane)); \
  }
SIMD_VISIT_EXTRACT_LANE(F64x2, )
SIMD_VISIT_EXTRACT_LANE(F32x4, )
SIMD_VISIT_EXTRACT_LANE(I64x2, )
SIMD_VISIT_EXTRACT_LANE(I32x4, )
SIMD_VISIT_EXTRACT_LANE(I16x8, U)
SIMD_VISIT_EXTRACT_LANE(I16x8, S)
SIMD_VISIT_EXTRACT_LANE(I8x16, U)
SIMD_VISIT_EXTRACT_LANE(I8x16, S)
#undef SIMD_VISIT_EXTRACT_LANE

#define SIMD_VISIT_REPLACE_LANE(Type)                                         \
  template <typename Adapter>                                                 \
  void InstructionSelectorT<Adapter>::Visit##Type##ReplaceLane(node_t node) { \
    S390OperandGeneratorT<Adapter> g(this);                                   \
    int32_t lane;                                                             \
    if constexpr (Adapter::IsTurboshaft) {                                    \
      using namespace turboshaft; /* NOLINT(build/namespaces) */              \
      const Operation& op = this->Get(node);                                  \
      lane = op.template Cast<Simd128ReplaceLaneOp>().lane;                   \
    } else {                                                                  \
      lane = OpParameter<int32_t>(node->op());                                \
    }                                                                         \
    Emit(kS390_##Type##ReplaceLane, g.DefineAsRegister(node),                 \
         g.UseRegister(this->input_at(node, 0)), g.UseImmediate(lane),        \
         g.UseRegister(this->input_at(node, 1)));                             \
  }
SIMD_TYPES(SIMD_VISIT_REPLACE_LANE)
#undef SIMD_VISIT_REPLACE_LANE

#define SIMD_VISIT_BINOP(Opcode)                                   \
  template <typename Adapter>                                      \
  void InstructionSelectorT<Adapter>::Visit##Opcode(node_t node) { \
    S390OperandGeneratorT<Adapter> g(this);                        \
    Emit(kS390_##Opcode, g.DefineAsRegister(node),                 \
         g.UseRegister(this->input_at(node, 0)),                   \
         g.UseRegister(this->input_at(node, 1)));                  \
  }
SIMD_BINOP_LIST(SIMD_VISIT_BINOP)
#undef SIMD_VISIT_BINOP
#undef SIMD_BINOP_LIST

#define SIMD_VISIT_BINOP_UNIQUE_REGISTER(Opcode)                         \
  template <typename Adapter>                                            \
  void InstructionSelectorT<Adapter>::Visit##Opcode(node_t node) {       \
    S390OperandGeneratorT<Adapter> g(this);                              \
    InstructionOperand temps[] = {g.TempSimd128Register(),               \
                                  g.TempSimd128Register()};              \
    Emit(kS390_##Opcode, g.DefineAsRegister(node),                       \
         g.UseUniqueRegister(this->input_at(node, 0)),                   \
         g.UseUniqueRegister(this->input_at(node, 1)), arraysize(temps), \
         temps);                                                         \
  }
SIMD_BINOP_UNIQUE_REGISTER_LIST(SIMD_VISIT_BINOP_UNIQUE_REGISTER)
#undef SIMD_VISIT_BINOP_UNIQUE_REGISTER
#undef SIMD_BINOP_UNIQUE_REGISTER_LIST

#define SIMD_VISIT_UNOP(Opcode)                                    \
  template <typename Adapter>                                      \
  void InstructionSelectorT<Adapter>::Visit##Opcode(node_t node) { \
    S390OperandGeneratorT<Adapter> g(this);                        \
    Emit(kS390_##Opcode, g.DefineAsRegister(node),                 \
         g.UseRegister(this->input_at(node, 0)));                  \
  }
SIMD_UNOP_LIST(SIMD_VISIT_UNOP)
#undef SIMD_VISIT_UNOP
#undef SIMD_UNOP_LIST

#define SIMD_VISIT_UNOP_UNIQUE_REGISTER(Opcode)                          \
  template <typename Adapter>                                            \
  void InstructionSelectorT<Adapter>::Visit##Opcode(node_t node) {       \
    S390OperandGeneratorT<Adapter> g(this);                              \
    InstructionOperand temps[] = {g.TempSimd128Register()};              \
    Emit(kS390_##Opcode, g.DefineAsRegister(node),                       \
         g.UseUniqueRegister(this->input_at(node, 0)), arraysize(temps), \
         temps);                                                         \
  }
SIMD_UNOP_UNIQUE_REGISTER_LIST(SIMD_VISIT_UNOP_UNIQUE_REGISTER)
#undef SIMD_VISIT_UNOP_UNIQUE_REGISTER
#undef SIMD_UNOP_UNIQUE_REGISTER_LIST

#define SIMD_VISIT_QFMOP(Opcode)                                   \
  template <typename Adapter>                                      \
  void InstructionSelectorT<Adapter>::Visit##Opcode(node_t node) { \
    S390OperandGeneratorT<Adapter> g(this);                        \
    Emit(kS390_##Opcode, g.DefineSameAsFirst(node),                \
         g.UseRegister(this->input_at(node, 0)),                   \
         g.UseRegister(this->input_at(node, 1)),                   \
         g.UseRegister(this->input_at(node, 2)));                  \
  }
SIMD_VISIT_QFMOP(F64x2Qfma)
SIMD_VISIT_QFMOP(F64x2Qfms)
SIMD_VISIT_QFMOP(F32x4Qfma)
SIMD_VISIT_QFMOP(F32x4Qfms)
#undef SIMD_VISIT_QFMOP

#define SIMD_RELAXED_OP_LIST(V)                           \
  V(F64x2RelaxedMin, F64x2Pmin)                           \
  V(F64x2RelaxedMax, F64x2Pmax)                           \
  V(F32x4RelaxedMin, F32x4Pmin)                           \
  V(F32x4RelaxedMax, F32x4Pmax)                           \
  V(I32x4RelaxedTruncF32x4S, I32x4SConvertF32x4)          \
  V(I32x4RelaxedTruncF32x4U, I32x4UConvertF32x4)          \
  V(I32x4RelaxedTruncF64x2SZero, I32x4TruncSatF64x2SZero) \
  V(I32x4RelaxedTruncF64x2UZero, I32x4TruncSatF64x2UZero) \
  V(I16x8RelaxedQ15MulRS, I16x8Q15MulRSatS)               \
  V(I8x16RelaxedLaneSelect, S128Select)                   \
  V(I16x8RelaxedLaneSelect, S128Select)                   \
  V(I32x4RelaxedLaneSelect, S128Select)                   \
  V(I64x2RelaxedLaneSelect, S128Select)

#define SIMD_VISIT_RELAXED_OP(name, op)                          \
  template <typename Adapter>                                    \
  void InstructionSelectorT<Adapter>::Visit##name(node_t node) { \
    Visit##op(node);                                             \
  }
SIMD_RELAXED_OP_LIST(SIMD_VISIT_RELAXED_OP)
#undef SIMD_VISIT_RELAXED_OP
#undef SIMD_RELAXED_OP_LIST

#define F16_OP_LIST(V)    \
  V(F16x8Splat)           \
  V(F16x8ExtractLane)     \
  V(F16x8ReplaceLane)     \
  V(F16x8Abs)             \
  V(F16x8Neg)             \
  V(F16x8Sqrt)            \
  V(F16x8Floor)           \
  V(F16x8Ceil)            \
  V(F16x8Trunc)           \
  V(F16x8NearestInt)      \
  V(F16x8Add)             \
  V(F16x8Sub)             \
  V(F16x8Mul)             \
  V(F16x8Div)             \
  V(F16x8Min)             \
  V(F16x8Max)             \
  V(F16x8Pmin)            \
  V(F16x8Pmax)            \
  V(F16x8Eq)              \
  V(F16x8Ne)              \
  V(F16x8Lt)              \
  V(F16x8Le)              \
  V(F16x8SConvertI16x8)   \
  V(F16x8UConvertI16x8)   \
  V(I16x8SConvertF16x8)   \
  V(I16x8UConvertF16x8)   \
  V(F32x4PromoteLowF16x8) \
  V(F16x8DemoteF32x4Zero) \
  V(F16x8DemoteF64x2Zero) \
  V(F16x8Qfma)            \
  V(F16x8Qfms)

#define VISIT_F16_OP(name)                                       \
  template <typename Adapter>                                    \
  void InstructionSelectorT<Adapter>::Visit##name(node_t node) { \
    UNIMPLEMENTED();                                             \
  }
F16_OP_LIST(VISIT_F16_OP)
#undef VISIT_F16_OP
#undef F16_OP_LIST
#undef SIMD_TYPES

#if V8_ENABLE_WEBASSEMBLY
template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI8x16Shuffle(node_t node) {
    uint8_t shuffle[kSimd128Size];
    bool is_swizzle;
    // TODO(nicohartmann@): Properly use view here once Turboshaft support is
    // implemented.
    auto view = this->simd_shuffle_view(node);
    CanonicalizeShuffle(view, shuffle, &is_swizzle);
    S390OperandGeneratorT<Adapter> g(this);
    node_t input0 = view.input(0);
    node_t input1 = view.input(1);
    // Remap the shuffle indices to match IBM lane numbering.
    int max_index = 15;
    int total_lane_count = 2 * kSimd128Size;
    uint8_t shuffle_remapped[kSimd128Size];
    for (int i = 0; i < kSimd128Size; i++) {
      uint8_t current_index = shuffle[i];
      shuffle_remapped[i] =
          (current_index <= max_index
               ? max_index - current_index
               : total_lane_count - current_index + max_index);
    }
    Emit(kS390_I8x16Shuffle, g.DefineAsRegister(node), g.UseRegister(input0),
         g.UseRegister(input1),
         g.UseImmediate(wasm::SimdShuffle::Pack4Lanes(shuffle_remapped)),
         g.UseImmediate(wasm::SimdShuffle::Pack4Lanes(shuffle_remapped + 4)),
         g.UseImmediate(wasm::SimdShuffle::Pack4Lanes(shuffle_remapped + 8)),
         g.UseImmediate(wasm::SimdShuffle::Pack4Lanes(shuffle_remapped + 12)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI8x16Swizzle(node_t node) {
  S390OperandGeneratorT<Adapter> g(this);
  bool relaxed;
  if constexpr (Adapter::IsTurboshaft) {
    const turboshaft::Simd128BinopOp& binop =
        this->Get(node).template Cast<turboshaft::Simd128BinopOp>();
    DCHECK(binop.kind ==
           turboshaft::any_of(
               turboshaft::Simd128BinopOp::Kind::kI8x16Swizzle,
               turboshaft::Simd128BinopOp::Kind::kI8x16RelaxedSwizzle));
    relaxed =
        binop.kind == turboshaft::Simd128BinopOp::Kind::kI8x16RelaxedSwizzle;
  } else {
    relaxed = OpParameter<bool>(node->op());
  }
    // TODO(miladfarca): Optimize Swizzle if relaxed.
    USE(relaxed);

    Emit(kS390_I8x16Swizzle, g.DefineAsRegister(node),
         g.UseUniqueRegister(this->input_at(node, 0)),
         g.UseUniqueRegister(this->input_at(node, 1)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitSetStackPointer(node_t node) {
  OperandGenerator g(this);
  // TODO(miladfarca): Optimize by using UseAny.
  auto input = g.UseRegister(this->input_at(node, 0));
  Emit(kArchSetStackPointer, 0, nullptr, 1, &input);
}

#else
template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI8x16Shuffle(node_t node) {
  UNREACHABLE();
}
template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI8x16Swizzle(node_t node) {
  UNREACHABLE();
}
#endif  // V8_ENABLE_WEBASSEMBLY

// This is a replica of SimdShuffle::Pack4Lanes. However, above function will
// not be available on builds with webassembly disabled, hence we need to have
// it declared locally as it is used on other visitors such as S128Const.
static int32_t Pack4Lanes(const uint8_t* shuffle) {
  int32_t result = 0;
  for (int i = 3; i >= 0; --i) {
    result <<= 8;
    result |= shuffle[i];
  }
  return result;
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitS128Const(node_t node) {
    S390OperandGeneratorT<Adapter> g(this);
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
      Emit(kS390_S128Zero, dst);
    } else if (all_ones) {
      Emit(kS390_S128AllOnes, dst);
    } else {
      // We have to use Pack4Lanes to reverse the bytes (lanes) on BE,
      // Which in this case is ineffective on LE.
      Emit(
          kS390_S128Const, dst,
          g.UseImmediate(Pack4Lanes(reinterpret_cast<uint8_t*>(&val[0]))),
          g.UseImmediate(Pack4Lanes(reinterpret_cast<uint8_t*>(&val[0]) + 4)),
          g.UseImmediate(Pack4Lanes(reinterpret_cast<uint8_t*>(&val[0]) + 8)),
          g.UseImmediate(Pack4Lanes(reinterpret_cast<uint8_t*>(&val[0]) + 12)));
    }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitS128Zero(node_t node) {
    S390OperandGeneratorT<Adapter> g(this);
    Emit(kS390_S128Zero, g.DefineAsRegister(node));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitS128Select(node_t node) {
    S390OperandGeneratorT<Adapter> g(this);
    Emit(kS390_S128Select, g.DefineAsRegister(node),
         g.UseRegister(this->input_at(node, 0)),
         g.UseRegister(this->input_at(node, 1)),
         g.UseRegister(this->input_at(node, 2)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::EmitPrepareResults(
    ZoneVector<PushParameter>* results, const CallDescriptor* call_descriptor,
    node_t node) {
    S390OperandGeneratorT<Adapter> g(this);

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
        Emit(kS390_Peek, g.DefineAsRegister(output.node),
             g.UseImmediate(reverse_slot));
      }
    }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitLoadLane(node_t node) {
  InstructionCode opcode;
  int32_t lane;
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const Simd128LaneMemoryOp& load =
        this->Get(node).template Cast<Simd128LaneMemoryOp>();
    lane = load.lane;
    switch (load.lane_kind) {
      case Simd128LaneMemoryOp::LaneKind::k8:
        opcode = kS390_S128Load8Lane;
        break;
      case Simd128LaneMemoryOp::LaneKind::k16:
        opcode = kS390_S128Load16Lane;
        break;
      case Simd128LaneMemoryOp::LaneKind::k32:
        opcode = kS390_S128Load32Lane;
        break;
      case Simd128LaneMemoryOp::LaneKind::k64:
        opcode = kS390_S128Load64Lane;
        break;
    }
  } else {
    LoadLaneParameters params = LoadLaneParametersOf(node->op());
    lane = params.laneidx;
    if (params.rep == MachineType::Int8()) {
      opcode = kS390_S128Load8Lane;
    } else if (params.rep == MachineType::Int16()) {
      opcode = kS390_S128Load16Lane;
    } else if (params.rep == MachineType::Int32()) {
      opcode = kS390_S128Load32Lane;
    } else if (params.rep == MachineType::Int64()) {
      opcode = kS390_S128Load64Lane;
    } else {
      UNREACHABLE();
    }
  }
    S390OperandGeneratorT<Adapter> g(this);
    InstructionOperand outputs[] = {g.DefineSameAsFirst(node)};
    InstructionOperand inputs[5];
    size_t input_count = 0;

    inputs[input_count++] = g.UseRegister(this->input_at(node, 2));
    inputs[input_count++] = g.UseImmediate(lane);

    AddressingMode mode =
        g.GetEffectiveAddressMemoryOperand(node, inputs, &input_count);
    opcode |= AddressingModeField::encode(mode);
    Emit(opcode, 1, outputs, input_count, inputs);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitLoadTransform(node_t node) {
  ArchOpcode opcode;
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const Simd128LoadTransformOp& op =
        this->Get(node).template Cast<Simd128LoadTransformOp>();
    switch (op.transform_kind) {
      case Simd128LoadTransformOp::TransformKind::k8Splat:
        opcode = kS390_S128Load8Splat;
        break;
      case Simd128LoadTransformOp::TransformKind::k16Splat:
        opcode = kS390_S128Load16Splat;
        break;
      case Simd128LoadTransformOp::TransformKind::k32Splat:
        opcode = kS390_S128Load32Splat;
        break;
      case Simd128LoadTransformOp::TransformKind::k64Splat:
        opcode = kS390_S128Load64Splat;
        break;
      case Simd128LoadTransformOp::TransformKind::k8x8S:
        opcode = kS390_S128Load8x8S;
        break;
      case Simd128LoadTransformOp::TransformKind::k8x8U:
        opcode = kS390_S128Load8x8U;
        break;
      case Simd128LoadTransformOp::TransformKind::k16x4S:
        opcode = kS390_S128Load16x4S;
        break;
      case Simd128LoadTransformOp::TransformKind::k16x4U:
        opcode = kS390_S128Load16x4U;
        break;
      case Simd128LoadTransformOp::TransformKind::k32x2S:
        opcode = kS390_S128Load32x2S;
        break;
      case Simd128LoadTransformOp::TransformKind::k32x2U:
        opcode = kS390_S128Load32x2U;
        break;
      case Simd128LoadTransformOp::TransformKind::k32Zero:
        opcode = kS390_S128Load32Zero;
        break;
      case Simd128LoadTransformOp::TransformKind::k64Zero:
        opcode = kS390_S128Load64Zero;
        break;
      default:
        UNIMPLEMENTED();
    }
  } else {
    LoadTransformParameters params = LoadTransformParametersOf(node->op());
    switch (params.transformation) {
      case LoadTransformation::kS128Load8Splat:
        opcode = kS390_S128Load8Splat;
        break;
      case LoadTransformation::kS128Load16Splat:
        opcode = kS390_S128Load16Splat;
        break;
      case LoadTransformation::kS128Load32Splat:
        opcode = kS390_S128Load32Splat;
        break;
      case LoadTransformation::kS128Load64Splat:
        opcode = kS390_S128Load64Splat;
        break;
      case LoadTransformation::kS128Load8x8S:
        opcode = kS390_S128Load8x8S;
        break;
      case LoadTransformation::kS128Load8x8U:
        opcode = kS390_S128Load8x8U;
        break;
      case LoadTransformation::kS128Load16x4S:
        opcode = kS390_S128Load16x4S;
        break;
      case LoadTransformation::kS128Load16x4U:
        opcode = kS390_S128Load16x4U;
        break;
      case LoadTransformation::kS128Load32x2S:
        opcode = kS390_S128Load32x2S;
        break;
      case LoadTransformation::kS128Load32x2U:
        opcode = kS390_S128Load32x2U;
        break;
      case LoadTransformation::kS128Load32Zero:
        opcode = kS390_S128Load32Zero;
        break;
      case LoadTransformation::kS128Load64Zero:
        opcode = kS390_S128Load64Zero;
        break;
      default:
        UNREACHABLE();
    }
  }
  VisitLoad(node, node, opcode);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitStoreLane(node_t node) {
  InstructionCode opcode = kArchNop;
  int32_t lane;
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const Simd128LaneMemoryOp& store =
        this->Get(node).template Cast<Simd128LaneMemoryOp>();
    lane = store.lane;
    switch (store.lane_kind) {
      case Simd128LaneMemoryOp::LaneKind::k8:
        opcode = kS390_S128Store8Lane;
        break;
      case Simd128LaneMemoryOp::LaneKind::k16:
        opcode = kS390_S128Store16Lane;
        break;
      case Simd128LaneMemoryOp::LaneKind::k32:
        opcode = kS390_S128Store32Lane;
        break;
      case Simd128LaneMemoryOp::LaneKind::k64:
        opcode = kS390_S128Store64Lane;
        break;
    }
  } else {
    StoreLaneParameters params = StoreLaneParametersOf(node->op());
    lane = params.laneidx;
    if (params.rep == MachineRepresentation::kWord8) {
      opcode = kS390_S128Store8Lane;
    } else if (params.rep == MachineRepresentation::kWord16) {
      opcode = kS390_S128Store16Lane;
    } else if (params.rep == MachineRepresentation::kWord32) {
      opcode = kS390_S128Store32Lane;
    } else if (params.rep == MachineRepresentation::kWord64) {
      opcode = kS390_S128Store64Lane;
    } else {
      UNREACHABLE();
    }
  }
  S390OperandGeneratorT<Adapter> g(this);
  InstructionOperand inputs[5];
  size_t input_count = 0;

  inputs[input_count++] = g.UseRegister(this->input_at(node, 2));
  inputs[input_count++] = g.UseImmediate(lane);

  AddressingMode mode =
      g.GetEffectiveAddressMemoryOperand(node, inputs, &input_count);
  opcode |= AddressingModeField::encode(mode);
  Emit(opcode, 0, nullptr, input_count, inputs);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI16x8DotI8x16I7x16S(node_t node) {
    S390OperandGeneratorT<Adapter> g(this);
    Emit(kS390_I16x8DotI8x16S, g.DefineAsRegister(node),
         g.UseUniqueRegister(this->input_at(node, 0)),
         g.UseUniqueRegister(this->input_at(node, 1)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI32x4DotI8x16I7x16AddS(node_t node) {
    S390OperandGeneratorT<Adapter> g(this);
    InstructionOperand temps[] = {g.TempSimd128Register()};
    Emit(kS390_I32x4DotI8x16AddS, g.DefineAsRegister(node),
         g.UseUniqueRegister(this->input_at(node, 0)),
         g.UseUniqueRegister(this->input_at(node, 1)),
         g.UseUniqueRegister(this->input_at(node, 2)), arraysize(temps), temps);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTruncateFloat32ToInt32(node_t node) {
  S390OperandGeneratorT<Adapter> g(this);
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const Operation& op = this->Get(node);
    InstructionCode opcode = kS390_Float32ToInt32;
    if (op.Is<Opmask::kTruncateFloat32ToInt32OverflowToMin>()) {
      opcode |= MiscField::encode(true);
    }
    Emit(opcode, g.DefineAsRegister(node),
         g.UseRegister(this->input_at(node, 0)));
  } else {
    InstructionCode opcode = kS390_Float32ToInt32;
    TruncateKind kind = OpParameter<TruncateKind>(node->op());
    if (kind == TruncateKind::kSetOverflowToMin) {
      opcode |= MiscField::encode(true);
    }

    Emit(opcode, g.DefineAsRegister(node), g.UseRegister(node->InputAt(0)));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTruncateFloat32ToUint32(node_t node) {
    S390OperandGeneratorT<Adapter> g(this);
    if constexpr (Adapter::IsTurboshaft) {
      using namespace turboshaft;  // NOLINT(build/namespaces)
      const Operation& op = this->Get(node);
      InstructionCode opcode = kS390_Float32ToUint32;
      if (op.Is<Opmask::kTruncateFloat32ToUint32OverflowToMin>()) {
        opcode |= MiscField::encode(true);
      }

      Emit(opcode, g.DefineAsRegister(node),
           g.UseRegister(this->input_at(node, 0)));
    } else {
      InstructionCode opcode = kS390_Float32ToUint32;
      TruncateKind kind = OpParameter<TruncateKind>(node->op());
      if (kind == TruncateKind::kSetOverflowToMin) {
        opcode |= MiscField::encode(true);
      }

      Emit(opcode, g.DefineAsRegister(node), g.UseRegister(node->InputAt(0)));
    }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::AddOutputToSelectContinuation(
    OperandGenerator* g, int first_input_index, node_t node) {
  UNREACHABLE();
}

MachineOperatorBuilder::Flags
InstructionSelector::SupportedMachineOperatorFlags() {
  return MachineOperatorBuilder::kFloat32RoundDown |
         MachineOperatorBuilder::kFloat64RoundDown |
         MachineOperatorBuilder::kFloat32RoundUp |
         MachineOperatorBuilder::kFloat64RoundUp |
         MachineOperatorBuilder::kFloat32RoundTruncate |
         MachineOperatorBuilder::kFloat64RoundTruncate |
         MachineOperatorBuilder::kFloat32RoundTiesEven |
         MachineOperatorBuilder::kFloat64RoundTiesEven |
         MachineOperatorBuilder::kFloat64RoundTiesAway |
         MachineOperatorBuilder::kWord32Popcnt |
         MachineOperatorBuilder::kInt32AbsWithOverflow |
         MachineOperatorBuilder::kInt64AbsWithOverflow |
         MachineOperatorBuilder::kWord64Popcnt;
}

MachineOperatorBuilder::AlignmentRequirements
InstructionSelector::AlignmentRequirements() {
  return MachineOperatorBuilder::AlignmentRequirements::
      FullUnalignedAccessSupport();
}

template class EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE)
    InstructionSelectorT<TurbofanAdapter>;
template class EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE)
    InstructionSelectorT<TurboshaftAdapter>;

}  // namespace compiler
}  // namespace internal
}  // namespace v8

"""


```