Response: The user wants a summary of the C++ source code file `v8/src/compiler/backend/mips64/instruction-selector-mips64.cc`. This is the third part of a three-part file.

The file seems to be responsible for selecting MIPS64 instructions based on a higher-level intermediate representation (IR) of code. It's likely part of the V8 JavaScript engine's compiler.

Here's a breakdown of what the code does in this third part:

1. **Handling Comparisons and Control Flow:** It continues to define how comparison operations (like equality, less than) are translated into MIPS64 instructions, including optimizing for comparisons against zero and handling `switch` statements.
2. **Handling Arithmetic Operations with Overflow:** It details how arithmetic operations like addition, subtraction, and multiplication, specifically those that need to detect overflow, are implemented on MIPS64.
3. **Handling Floating-Point Operations:**  It defines instruction selection for various floating-point operations, including comparisons, extracting parts of doubles, and inserting parts into doubles.
4. **Handling Memory Barriers and Atomic Operations:** It defines how memory barriers and atomic operations (load, store, exchange, compare-and-exchange, and other binary operations) are translated to MIPS64 instructions. This is crucial for multi-threaded JavaScript execution.
5. **Handling SIMD (Single Instruction, Multiple Data) Operations:** A significant portion of this part deals with selecting instructions for SIMD operations on various data types (F64x2, F32x4, I64x2, I32x4, I16x8, I8x16). This includes unary operations, shifts, binary operations, shuffles, lane extraction/replacement, and some relaxed/unimplemented operations. There's a specific section for handling `I8x16Shuffle` which might involve matching patterns for efficient instruction selection.
6. **Handling Stack Pointer Manipulation:** It includes functions for setting the stack pointer.
7. **Handling Sign Extension:** It defines how to generate instructions for sign-extending smaller integer types to larger ones.
8. **Handling Packed Min/Max:** It defines instruction selection for packed minimum and maximum operations.
9. **Handling Extended Multiplication and Addition:** It covers instructions for extended multiplication and pairwise addition operations on SIMD vectors.
10. **Helper Functions and Static Data:**  It includes helper functions and static data structures (like `arch_shuffles`) to assist in instruction selection.
11. **Turbofan and Turboshaft Support:** The code is templated to support two different compilation pipelines within V8: Turbofan and the newer Turboshaft. It handles cases where functionality is implemented differently or not yet implemented in one of them.
12. **WebAssembly Integration:** There's a section specifically for WebAssembly SIMD shuffles, indicating its relevance to running WebAssembly code in V8.
13. **Machine Operator Flags and Alignment Requirements:** It defines what machine operator flags are supported on MIPS64 and the alignment requirements for memory access.

**Relationship to JavaScript:**

This file is a crucial part of how JavaScript code is executed efficiently. When JavaScript code is compiled by V8, it goes through several stages, and this file is involved in the final stage where the optimized intermediate representation is translated into actual machine code (MIPS64 instructions in this case).

**JavaScript Examples:**

* **Comparisons and Control Flow:**

```javascript
let x = 10;
let y = 5;
if (x > y) {
  console.log("x is greater than y");
}

switch (x) {
  case 10:
    console.log("x is 10");
    break;
  default:
    console.log("x is not 10");
}
```
The `if` statement and the `switch` statement would be processed by the functions in this file (like `VisitInt32LessThan`, `VisitSwitch`) to generate the appropriate MIPS64 compare and branch instructions.

* **Arithmetic with Overflow:**

```javascript
let a = 2147483647; // Maximum 32-bit integer
let b = 1;
try {
  Math.imul(a, b); // Safe multiplication, doesn't throw on overflow in standard JS
  // However, internal operations might need to detect overflow
  let c = a + b; // This will wrap around in standard JS, but the compiler might use overflow-detecting instructions internally.
} catch (e) {
  console.error("Overflow detected!");
}
```
The `VisitInt32AddWithOverflow`, `VisitInt32MulWithOverflow` functions would be involved if the compiler needs to generate code that explicitly checks for overflow during these operations.

* **SIMD Operations:**

```javascript
const a = Float64x2(1.0, 2.0);
const b = Float64x2(3.0, 4.0);
const sum = a.add(b); // SIMD addition
console.log(sum.x, sum.y); // Output: 4, 6
```
The `VisitF64x2Add`, `VisitF64x2Splat`, `VisitF64x2ExtractLane` functions would be used to generate MIPS64 SIMD instructions to perform these vector operations efficiently.

* **Atomic Operations:**

```javascript
const sab = new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT * 1);
const atomicArray = new Int32Array(sab);
Atomics.add(atomicArray, 0, 5); // Atomic addition
console.log(atomicArray[0]); // Output: 5
```
The `VisitWord32AtomicAdd`, `VisitWord32AtomicLoad`, `VisitWord32AtomicStore` functions would be responsible for generating the correct MIPS64 atomic instructions to ensure thread-safe updates to shared memory.

In essence, this file bridges the gap between the high-level logic of JavaScript and the low-level instructions that the MIPS64 processor understands, enabling efficient execution of JavaScript code.

这是 `v8/src/compiler/backend/mips64/instruction-selector-mips64.cc` 文件的第三部分，它的主要功能是**将 V8 引擎的中间表示 (IR) 节点转换为具体的 MIPS64 汇编指令**。这是代码生成过程中的关键步骤，它决定了如何将高级的编程概念映射到目标架构的指令上。

作为第三部分，它延续了前两部分的工作，涵盖了更广泛的 IR 节点类型，并定义了它们对应的 MIPS64 指令选择逻辑。

**具体功能归纳如下：**

1. **处理比较操作和控制流:**
   -  定义了如何将比较操作（如相等、小于等）转换为 MIPS64 的比较指令 (`kMips64Tst`, `kMips64Cmp`, `kMips64Cmpg`).
   -  优化了与零的比较操作 (`EmitWordCompareZero`).
   -  处理 `switch` 语句，根据 case 的数量和范围选择使用跳转表 (`EmitTableSwitch`) 或二分查找 (`EmitBinarySearchSwitch`) 来实现。

2. **处理带溢出检查的算术运算:**
   -  为带溢出的加法 (`VisitInt32AddWithOverflow`, `VisitInt64AddWithOverflow`)、减法 (`VisitInt32SubWithOverflow`, `VisitInt64SubWithOverflow`) 和乘法 (`VisitInt32MulWithOverflow`, `VisitInt64MulWithOverflow`) 操作选择相应的 MIPS64 指令（例如 `kMips64DaddOvf`, `kMips64DsubOvf`, `kMips64DMulOvf`）。

3. **处理浮点数运算:**
   -  定义了浮点数比较操作 (`VisitFloat32Equal`, `VisitFloat64LessThan` 等) 到 MIPS64 浮点比较指令的映射。
   -  处理提取双精度浮点数的低 32 位和高 32 位 (`VisitFloat64ExtractLowWord32`, `VisitFloat64ExtractHighWord32`).
   -  处理双精度浮点数的 NaN 静默化 (`VisitFloat64SilenceNaN`).
   -  处理将 32 位整数对转换为双精度浮点数 (`VisitBitcastWord32PairToFloat64`) 以及双精度浮点数插入低/高 32 位 (`VisitFloat64InsertLowWord32`, `VisitFloat64InsertHighWord32`).

4. **处理内存屏障和原子操作:**
   -  将内存屏障操作 (`VisitMemoryBarrier`) 转换为 MIPS64 的同步指令 (`kMips64Sync`).
   -  处理原子加载 (`VisitWord32AtomicLoad`, `VisitWord64AtomicLoad`) 和存储 (`VisitWord32AtomicStore`, `VisitWord64AtomicStore`) 操作。
   -  处理原子交换 (`VisitWord32AtomicExchange`, `VisitWord64AtomicExchange`) 和原子比较并交换 (`VisitWord32AtomicCompareExchange`, `VisitWord64AtomicCompareExchange`) 操作。
   -  处理各种原子二元操作（加、减、与、或、异或），例如 `VisitWord32AtomicAdd`，并根据操作数类型选择相应的 MIPS64 原子指令。

5. **处理 SIMD (单指令多数据) 操作:**
   -  这是该部分的一个重要组成部分，涵盖了各种 SIMD 操作，包括：
     -  **常量加载:** `VisitS128Const`, `VisitS128Zero`.
     -  **Splat (复制标量到向量):** `VisitF64x2Splat`, `VisitI32x4Splat` 等。
     -  **Lane 提取:** `VisitF64x2ExtractLane`, `VisitI8x16ExtractLaneS` 等。
     -  **Lane 替换:** `VisitF64x2ReplaceLane`, `VisitI32x4ReplaceLane` 等。
     -  **一元操作:** `VisitF64x2Abs`, `VisitI32x4Neg` 等。
     -  **移位操作:** `VisitI64x2Shl`, `VisitI16x8ShrS` 等。
     -  **二元操作:** `VisitF64x2Add`, `VisitI32x4Mul` 等。
     -  **Relaxed 操作:**  处理一些宽松的 SIMD 操作，可能用于性能优化。
     -  **Select 操作:** `VisitS128Select`.
     -  **Shuffle 操作:** `VisitI8x16Shuffle`，用于重新排列向量中的元素，其中包含针对特定 shuffle 模式的优化。
     -  **Swizzle 操作:** `VisitI8x16Swizzle`，用于根据索引向量重新排列向量中的字节。
   -  针对不同的 SIMD 数据类型 (F64x2, F32x4, I64x2, I32x4, I16x8, I8x16) 提供了相应的指令选择逻辑。

6. **处理栈指针操作:**
   -  定义了设置栈指针的操作 (`VisitSetStackPointer`).

7. **处理符号扩展操作:**
   -  将有符号的 8 位、16 位和 32 位整数扩展为 32 位或 64 位整数 (`VisitSignExtendWord8ToInt32`, `VisitSignExtendWord16ToInt64`, `VisitSignExtendWord32ToInt64`).

8. **处理 SIMD 的 Packed Min/Max 操作:**
   -  `VisitF32x4Pmin`, `VisitF64x2Pmax` 等，用于在 SIMD 向量中执行按元素的最小值和最大值操作。

9. **处理 SIMD 的扩展乘法操作:**
   -  `VisitI64x2ExtMulLowI32x4S`, `VisitI32x4ExtMulHighI16x8U` 等，用于执行 SIMD 向量的扩展乘法，结果可以是更高精度的向量。

10. **处理 SIMD 的成对加法操作:**
    - `VisitI16x8ExtAddPairwiseI8x16S`, `VisitI32x4ExtAddPairwiseI16x8U` 等，用于对 SIMD 向量中的相邻元素对进行加法运算。

11. **定义支持的机器操作标志和对齐要求:**
    -  `SupportedMachineOperatorFlags()`  定义了 MIPS64 架构支持的特定机器操作标志。
    -  `AlignmentRequirements()` 定义了 MIPS64 架构的内存对齐要求。

**与 JavaScript 的关系:**

该文件是 V8 JavaScript 引擎将 JavaScript 代码编译成机器码的关键部分。当 V8 编译 JavaScript 代码时，它会将代码转换为一种中间表示形式。`instruction-selector-mips64.cc` 的功能就是将这种中间表示形式翻译成可以在 MIPS64 架构上执行的实际机器指令。

**JavaScript 示例:**

以下 JavaScript 代码片段展示了可能触发此文件中某些功能的场景：

```javascript
// 比较操作
let a = 10;
let b = 5;
if (a > b) {
  console.log("a is greater than b");
}

// 带溢出检查的算术运算 (尽管 JavaScript 默认不抛出溢出错误，但 V8 内部可能会使用带溢出检查的指令)
let maxInt = 2147483647;
let result = maxInt + 1; // JavaScript 会发生回绕，但在内部表示中可能会使用带溢出检查的指令

// 浮点数运算
let x = 1.5;
let y = 2.5;
let sum = x + y;

// SIMD 操作 (需要使用 SIMD API)
const arr1 = new Float64Array([1.0, 2.0]);
const arr2 = new Float64Array([3.0, 4.0]);
const vec1 = Float64x2(arr1[0], arr1[1]);
const vec2 = Float64x2(arr2[0], arr2[1]);
const sumVec = vec1.add(vec2);

// 原子操作 (需要使用 SharedArrayBuffer 和 Atomics API)
const sab = new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT);
const view = new Int32Array(sab);
Atomics.add(view, 0, 5);

// 类型转换
let smallInt = 127;
let largerInt = smallInt; // 内部可能涉及符号扩展

```

总而言之，`instruction-selector-mips64.cc` (第三部分) 负责将高级的 JavaScript 概念转化为底层的 MIPS64 机器指令，是 V8 引擎执行 JavaScript 代码的关键组成部分。它针对不同的操作和数据类型提供了指令选择的详细规则，并考虑了性能优化，例如针对 `switch` 语句和 SIMD 操作的特殊处理。

Prompt: 
```
这是目录为v8/src/compiler/backend/mips64/instruction-selector-mips64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第3部分，共3部分，请归纳一下它的功能

"""
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
  V(I8x16SConvertI16x8, kMips64I8x16SConvertI16x8)       \
  V(I8x16UConvertI16x8, kMips64I8x16UConvertI16x8)       \
  V(S128And, kMips64S128And)                             \
  V(S128Or, kMips64S128Or)                               \
  V(S128Xor, kMips64S128Xor)                             \
  V(S128AndNot, kMips64S128AndNot)

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitS128Const(node_t node) {
  UNIMPLEMENTED();
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitS128Const(Node* node) {
  Mips64OperandGeneratorT<TurbofanAdapter> g(this);
  static const int kUint32Immediates = kSimd128Size / sizeof(uint32_t);
  uint32_t val[kUint32Immediates];
  memcpy(val, S128ImmediateParameterOf(node->op()).data(), kSimd128Size);
  // If all bytes are zeros or ones, avoid emitting code for generic constants
  bool all_zeros = !(val[0] || val[1] || val[2] || val[3]);
  bool all_ones = val[0] == UINT32_MAX && val[1] == UINT32_MAX &&
                  val[2] == UINT32_MAX && val[3] == UINT32_MAX;
  InstructionOperand dst = g.DefineAsRegister(node);
  if (all_zeros) {
    Emit(kMips64S128Zero, dst);
  } else if (all_ones) {
    Emit(kMips64S128AllOnes, dst);
  } else {
    Emit(kMips64S128Const, dst, g.UseImmediate(val[0]), g.UseImmediate(val[1]),
         g.UseImmediate(val[2]), g.UseImmediate(val[3]));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitS128Zero(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    UNIMPLEMENTED();
  } else {
    Mips64OperandGeneratorT<Adapter> g(this);
    Emit(kMips64S128Zero, g.DefineAsRegister(node));
  }
}
#define SIMD_VISIT_SPLAT(Type)                                          \
  template <typename Adapter>                                           \
  void InstructionSelectorT<Adapter>::Visit##Type##Splat(node_t node) { \
    VisitRR(this, kMips64##Type##Splat, node);                          \
  }
SIMD_TYPE_LIST(SIMD_VISIT_SPLAT)
#undef SIMD_VISIT_SPLAT

#define SIMD_VISIT_EXTRACT_LANE(Type, Sign)                           \
  template <typename Adapter>                                         \
  void InstructionSelectorT<Adapter>::Visit##Type##ExtractLane##Sign( \
      node_t node) {                                                  \
    VisitRRI(this, kMips64##Type##ExtractLane##Sign, node);           \
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
    VisitRRIR(this, kMips64##Type##ReplaceLane, node);                        \
  }
SIMD_TYPE_LIST(SIMD_VISIT_REPLACE_LANE)
#undef SIMD_VISIT_REPLACE_LANE

#define SIMD_VISIT_UNOP(Name, instruction)                       \
  template <typename Adapter>                                    \
  void InstructionSelectorT<Adapter>::Visit##Name(node_t node) { \
    VisitRR(this, instruction, node);                            \
  }
SIMD_UNOP_LIST(SIMD_VISIT_UNOP)
#undef SIMD_VISIT_UNOP

#define SIMD_VISIT_SHIFT_OP(Name)                                \
  template <typename Adapter>                                    \
  void InstructionSelectorT<Adapter>::Visit##Name(node_t node) { \
    VisitSimdShift(this, kMips64##Name, node);                   \
  }
SIMD_SHIFT_OP_LIST(SIMD_VISIT_SHIFT_OP)
#undef SIMD_VISIT_SHIFT_OP

#define SIMD_VISIT_BINOP(Name, instruction)                      \
  template <typename Adapter>                                    \
  void InstructionSelectorT<Adapter>::Visit##Name(node_t node) { \
    VisitRRR(this, instruction, node);                           \
  }
SIMD_BINOP_LIST(SIMD_VISIT_BINOP)
#undef SIMD_VISIT_BINOP

#define SIMD_RELAXED_OP_LIST(V)  \
  V(F64x2RelaxedMin)             \
  V(F64x2RelaxedMax)             \
  V(F32x4RelaxedMin)             \
  V(F32x4RelaxedMax)             \
  V(I32x4RelaxedTruncF32x4S)     \
  V(I32x4RelaxedTruncF32x4U)     \
  V(I32x4RelaxedTruncF64x2SZero) \
  V(I32x4RelaxedTruncF64x2UZero) \
  V(I16x8RelaxedQ15MulRS)        \
  V(I8x16RelaxedLaneSelect)      \
  V(I16x8RelaxedLaneSelect)      \
  V(I32x4RelaxedLaneSelect)      \
  V(I64x2RelaxedLaneSelect)

#define SIMD_VISIT_RELAXED_OP(Name)                              \
  template <typename Adapter>                                    \
  void InstructionSelectorT<Adapter>::Visit##Name(node_t node) { \
    UNREACHABLE();                                               \
  }
SIMD_RELAXED_OP_LIST(SIMD_VISIT_RELAXED_OP)
#undef SIMD_VISIT_SHIFT_OP

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitS128Select(node_t node) {
  VisitRRRR(this, kMips64S128Select, node);
}

#define SIMD_UNIMP_OP_LIST(V) \
  V(F64x2Qfma)                \
  V(F64x2Qfms)                \
  V(F32x4Qfma)                \
  V(F32x4Qfms)                \
  V(I16x8DotI8x16I7x16S)      \
  V(I32x4DotI8x16I7x16AddS)

#define SIMD_VISIT_UNIMP_OP(Name)                                \
  template <typename Adapter>                                    \
  void InstructionSelectorT<Adapter>::Visit##Name(node_t node) { \
    UNIMPLEMENTED();                                             \
  }
SIMD_UNIMP_OP_LIST(SIMD_VISIT_UNIMP_OP)

#undef SIMD_VISIT_UNIMP_OP
#undef SIMD_UNIMP_OP_LIST

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
  V(F32x4PromoteLowF16x8)                  \
  V(F16x8DemoteF32x4Zero)                  \
  V(F16x8DemoteF64x2Zero)                  \
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

#if V8_ENABLE_WEBASSEMBLY
namespace {

struct ShuffleEntry {
  uint8_t shuffle[kSimd128Size];
  ArchOpcode opcode;
};

static const ShuffleEntry arch_shuffles[] = {
    {{0, 1, 2, 3, 16, 17, 18, 19, 4, 5, 6, 7, 20, 21, 22, 23},
     kMips64S32x4InterleaveRight},
    {{8, 9, 10, 11, 24, 25, 26, 27, 12, 13, 14, 15, 28, 29, 30, 31},
     kMips64S32x4InterleaveLeft},
    {{0, 1, 2, 3, 8, 9, 10, 11, 16, 17, 18, 19, 24, 25, 26, 27},
     kMips64S32x4PackEven},
    {{4, 5, 6, 7, 12, 13, 14, 15, 20, 21, 22, 23, 28, 29, 30, 31},
     kMips64S32x4PackOdd},
    {{0, 1, 2, 3, 16, 17, 18, 19, 8, 9, 10, 11, 24, 25, 26, 27},
     kMips64S32x4InterleaveEven},
    {{4, 5, 6, 7, 20, 21, 22, 23, 12, 13, 14, 15, 28, 29, 30, 31},
     kMips64S32x4InterleaveOdd},

    {{0, 1, 16, 17, 2, 3, 18, 19, 4, 5, 20, 21, 6, 7, 22, 23},
     kMips64S16x8InterleaveRight},
    {{8, 9, 24, 25, 10, 11, 26, 27, 12, 13, 28, 29, 14, 15, 30, 31},
     kMips64S16x8InterleaveLeft},
    {{0, 1, 4, 5, 8, 9, 12, 13, 16, 17, 20, 21, 24, 25, 28, 29},
     kMips64S16x8PackEven},
    {{2, 3, 6, 7, 10, 11, 14, 15, 18, 19, 22, 23, 26, 27, 30, 31},
     kMips64S16x8PackOdd},
    {{0, 1, 16, 17, 4, 5, 20, 21, 8, 9, 24, 25, 12, 13, 28, 29},
     kMips64S16x8InterleaveEven},
    {{2, 3, 18, 19, 6, 7, 22, 23, 10, 11, 26, 27, 14, 15, 30, 31},
     kMips64S16x8InterleaveOdd},
    {{6, 7, 4, 5, 2, 3, 0, 1, 14, 15, 12, 13, 10, 11, 8, 9},
     kMips64S16x4Reverse},
    {{2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13},
     kMips64S16x2Reverse},

    {{0, 16, 1, 17, 2, 18, 3, 19, 4, 20, 5, 21, 6, 22, 7, 23},
     kMips64S8x16InterleaveRight},
    {{8, 24, 9, 25, 10, 26, 11, 27, 12, 28, 13, 29, 14, 30, 15, 31},
     kMips64S8x16InterleaveLeft},
    {{0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30},
     kMips64S8x16PackEven},
    {{1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23, 25, 27, 29, 31},
     kMips64S8x16PackOdd},
    {{0, 16, 2, 18, 4, 20, 6, 22, 8, 24, 10, 26, 12, 28, 14, 30},
     kMips64S8x16InterleaveEven},
    {{1, 17, 3, 19, 5, 21, 7, 23, 9, 25, 11, 27, 13, 29, 15, 31},
     kMips64S8x16InterleaveOdd},
    {{7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8},
     kMips64S8x8Reverse},
    {{3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12},
     kMips64S8x4Reverse},
    {{1, 0, 3, 2, 5, 4, 7, 6, 9, 8, 11, 10, 13, 12, 15, 14},
     kMips64S8x2Reverse}};

bool TryMatchArchShuffle(const uint8_t* shuffle, const ShuffleEntry* table,
                         size_t num_entries, bool is_swizzle,
                         ArchOpcode* opcode) {
  uint8_t mask = is_swizzle ? kSimd128Size - 1 : 2 * kSimd128Size - 1;
  for (size_t i = 0; i < num_entries; ++i) {
    const ShuffleEntry& entry = table[i];
    int j = 0;
    for (; j < kSimd128Size; ++j) {
      if ((entry.shuffle[j] & mask) != (shuffle[j] & mask)) {
        break;
      }
    }
    if (j == kSimd128Size) {
      *opcode = entry.opcode;
      return true;
    }
  }
  return false;
}

}  // namespace

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitI8x16Shuffle(node_t node) {
  UNIMPLEMENTED();
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitI8x16Shuffle(Node* node) {
  uint8_t shuffle[kSimd128Size];
  bool is_swizzle;
  // TODO(MIPS_dev): Properly use view here once Turboshaft support is
  // implemented.
  auto view = this->simd_shuffle_view(node);
  CanonicalizeShuffle(view, shuffle, &is_swizzle);
  uint8_t shuffle32x4[4];
  ArchOpcode opcode;
  if (TryMatchArchShuffle(shuffle, arch_shuffles, arraysize(arch_shuffles),
                          is_swizzle, &opcode)) {
    VisitRRR(this, opcode, node);
    return;
  }
  Node* input0 = node->InputAt(0);
  Node* input1 = node->InputAt(1);
  uint8_t offset;
  Mips64OperandGeneratorT<TurbofanAdapter> g(this);
  if (wasm::SimdShuffle::TryMatchConcat(shuffle, &offset)) {
    Emit(kMips64S8x16Concat, g.DefineSameAsFirst(node), g.UseRegister(input1),
         g.UseRegister(input0), g.UseImmediate(offset));
    return;
  }
  if (wasm::SimdShuffle::TryMatch32x4Shuffle(shuffle, shuffle32x4)) {
    Emit(kMips64S32x4Shuffle, g.DefineAsRegister(node), g.UseRegister(input0),
         g.UseRegister(input1),
         g.UseImmediate(wasm::SimdShuffle::Pack4Lanes(shuffle32x4)));
    return;
  }
  Emit(kMips64I8x16Shuffle, g.DefineAsRegister(node), g.UseRegister(input0),
       g.UseRegister(input1),
       g.UseImmediate(wasm::SimdShuffle::Pack4Lanes(shuffle)),
       g.UseImmediate(wasm::SimdShuffle::Pack4Lanes(shuffle + 4)),
       g.UseImmediate(wasm::SimdShuffle::Pack4Lanes(shuffle + 8)),
       g.UseImmediate(wasm::SimdShuffle::Pack4Lanes(shuffle + 12)));
}
#else
template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI8x16Shuffle(node_t node) {
  UNREACHABLE();
}
#endif  // V8_ENABLE_WEBASSEMBLY

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI8x16Swizzle(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    UNIMPLEMENTED();
  } else {
    Mips64OperandGeneratorT<Adapter> g(this);
    InstructionOperand temps[] = {g.TempSimd128Register()};
    // We don't want input 0 or input 1 to be the same as output, since we will
    // modify output before do the calculation.
    Emit(kMips64I8x16Swizzle, g.DefineAsRegister(node),
         g.UseUniqueRegister(node->InputAt(0)),
         g.UseUniqueRegister(node->InputAt(1)), arraysize(temps), temps);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitSetStackPointer(node_t node) {
  OperandGenerator g(this);
  auto input = g.UseRegister(this->input_at(node, 0));
  Emit(kArchSetStackPointer, 0, nullptr, 1, &input);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitSignExtendWord8ToInt32(node_t node) {
  VisitRR(this, kMips64Seb, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitSignExtendWord16ToInt32(node_t node) {
  VisitRR(this, kMips64Seh, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitSignExtendWord8ToInt64(node_t node) {
  VisitRR(this, kMips64Seb, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitSignExtendWord16ToInt64(node_t node) {
  VisitRR(this, kMips64Seh, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitSignExtendWord32ToInt64(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    UNIMPLEMENTED();
  } else {
    Mips64OperandGeneratorT<Adapter> g(this);
    Emit(kMips64Shl, g.DefineAsRegister(node), g.UseRegister(node->InputAt(0)),
         g.TempImmediate(0));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF32x4Pmin(node_t node) {
  VisitUniqueRRR(this, kMips64F32x4Pmin, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF32x4Pmax(node_t node) {
  VisitUniqueRRR(this, kMips64F32x4Pmax, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF64x2Pmin(node_t node) {
  VisitUniqueRRR(this, kMips64F64x2Pmin, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF64x2Pmax(node_t node) {
  VisitUniqueRRR(this, kMips64F64x2Pmax, node);
}

#define VISIT_EXT_MUL(OPCODE1, OPCODE2, TYPE)                              \
  template <typename Adapter>                                              \
  void InstructionSelectorT<Adapter>::Visit##OPCODE1##ExtMulLow##OPCODE2(  \
      node_t node) {                                                       \
    if constexpr (Adapter::IsTurboshaft) {                                 \
      UNIMPLEMENTED();                                                     \
    } else {                                                               \
      Mips64OperandGeneratorT<Adapter> g(this);                            \
      Emit(kMips64ExtMulLow | MiscField::encode(TYPE),                     \
           g.DefineAsRegister(node), g.UseRegister(node->InputAt(0)),      \
           g.UseRegister(node->InputAt(1)));                               \
    }                                                                      \
  }                                                                        \
  template <typename Adapter>                                              \
  void InstructionSelectorT<Adapter>::Visit##OPCODE1##ExtMulHigh##OPCODE2( \
      node_t node) {                                                       \
    if constexpr (Adapter::IsTurboshaft) {                                 \
      UNIMPLEMENTED();                                                     \
    } else {                                                               \
      Mips64OperandGeneratorT<Adapter> g(this);                            \
      Emit(kMips64ExtMulHigh | MiscField::encode(TYPE),                    \
           g.DefineAsRegister(node), g.UseRegister(node->InputAt(0)),      \
           g.UseRegister(node->InputAt(1)));                               \
    }                                                                      \
  }

VISIT_EXT_MUL(I64x2, I32x4S, MSAS32)
VISIT_EXT_MUL(I64x2, I32x4U, MSAU32)
VISIT_EXT_MUL(I32x4, I16x8S, MSAS16)
VISIT_EXT_MUL(I32x4, I16x8U, MSAU16)
VISIT_EXT_MUL(I16x8, I8x16S, MSAS8)
VISIT_EXT_MUL(I16x8, I8x16U, MSAU8)
#undef VISIT_EXT_MUL

#define VISIT_EXTADD_PAIRWISE(OPCODE, TYPE)                            \
  template <typename Adapter>                                          \
  void InstructionSelectorT<Adapter>::Visit##OPCODE(node_t node) {     \
    if constexpr (Adapter::IsTurboshaft) {                             \
      UNIMPLEMENTED();                                                 \
    } else {                                                           \
      Mips64OperandGeneratorT<Adapter> g(this);                        \
      Emit(kMips64ExtAddPairwise | MiscField::encode(TYPE),            \
           g.DefineAsRegister(node), g.UseRegister(node->InputAt(0))); \
    }                                                                  \
  }
VISIT_EXTADD_PAIRWISE(I16x8ExtAddPairwiseI8x16S, MSAS8)
VISIT_EXTADD_PAIRWISE(I16x8ExtAddPairwiseI8x16U, MSAU8)
VISIT_EXTADD_PAIRWISE(I32x4ExtAddPairwiseI16x8S, MSAS16)
VISIT_EXTADD_PAIRWISE(I32x4ExtAddPairwiseI16x8U, MSAU16)
#undef VISIT_EXTADD_PAIRWISE

template <typename Adapter>
void InstructionSelectorT<Adapter>::AddOutputToSelectContinuation(
    OperandGenerator* g, int first_input_index, node_t node) {
  UNREACHABLE();
}

// static
MachineOperatorBuilder::Flags
InstructionSelector::SupportedMachineOperatorFlags() {
  MachineOperatorBuilder::Flags flags = MachineOperatorBuilder::kNoFlags;
  return flags | MachineOperatorBuilder::kWord32Ctz |
         MachineOperatorBuilder::kWord64Ctz |
         MachineOperatorBuilder::kWord32Popcnt |
         MachineOperatorBuilder::kWord64Popcnt |
         MachineOperatorBuilder::kWord32ShiftIsSafe |
         MachineOperatorBuilder::kInt32DivIsSafe |
         MachineOperatorBuilder::kUint32DivIsSafe |
         MachineOperatorBuilder::kFloat64RoundDown |
         MachineOperatorBuilder::kFloat32RoundDown |
         MachineOperatorBuilder::kFloat64RoundUp |
         MachineOperatorBuilder::kFloat32RoundUp |
         MachineOperatorBuilder::kFloat64RoundTruncate |
         MachineOperatorBuilder::kFloat32RoundTruncate |
         MachineOperatorBuilder::kFloat64RoundTiesEven |
         MachineOperatorBuilder::kFloat32RoundTiesEven;
}

// static
MachineOperatorBuilder::AlignmentRequirements
InstructionSelector::AlignmentRequirements() {
  if (kArchVariant == kMips64r6) {
    return MachineOperatorBuilder::AlignmentRequirements::
        FullUnalignedAccessSupport();
  } else {
    DCHECK_EQ(kMips64r2, kArchVariant);
    return MachineOperatorBuilder::AlignmentRequirements::
        NoUnalignedAccessSupport();
  }
}

template class EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE)
    InstructionSelectorT<TurbofanAdapter>;
template class EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE)
    InstructionSelectorT<TurboshaftAdapter>;

#undef SIMD_BINOP_LIST
#undef SIMD_SHIFT_OP_LIST
#undef SIMD_RELAXED_OP_LIST
#undef SIMD_UNOP_LIST
#undef SIMD_TYPE_LIST
#undef TRACE

}  // namespace compiler
}  // namespace internal
}  // namespace v8

"""


```