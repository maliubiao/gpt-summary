Response: The user is asking for a summary of the functionality of the C++ code provided, specifically the `InstructionSelector::VisitNode` method within the `v8/src/compiler/backend/instruction-selector.cc` file. This is part 3 of 4.

The code snippet is a large switch statement that handles different types of intermediate representation (IR) opcodes. Each case within the switch statement corresponds to a specific operation in the IR.

The main goal of this code is to translate the high-level, platform-independent IR operations into low-level, machine-specific instructions. This process is known as instruction selection.

Here's a breakdown of the observed actions:

1. **Dispatching to Specific Visitors:**  The code dispatches to different `Visit...` methods based on the `IrOpcode` or `Opcode`. Each `Visit...` method is responsible for handling the instruction selection logic for that particular operation.

2. **Marking Node Representations:** Before dispatching to a `Visit...` method, the code often calls `MarkAs...` methods (e.g., `MarkAsWord32`, `MarkAsFloat64`, `MarkAsTagged`, `MarkAsSimd128`). This seems to be about assigning or confirming the data representation type of the IR node being processed. This is crucial for ensuring that the correct machine instructions are selected.

3. **Handling Various Data Types:** The code handles a wide range of data types, including:
    - 32-bit and 64-bit integers (`Word32`, `Word64`, `Int32`, `Int64`, `Uint32`, `Uint64`)
    - Single-precision and double-precision floating-point numbers (`Float32`, `Float64`)
    - SIMD (Single Instruction, Multiple Data) vectors of various sizes and types (`Simd128`, `Simd256`, `F32x4`, `F64x2`, `I32x4`, etc.)
    - Tagged pointers (`Tagged`)

4. **Implementing Operations:** The cases in the switch statement cover a wide range of operations, including:
    - Arithmetic operations (add, subtract, multiply, divide, modulo)
    - Bitwise operations (and, or, xor, shift, rotate, count leading zeros, count trailing zeros, reverse bits/bytes)
    - Comparison operations (equal, less than, less than or equal)
    - Conversions between different data types (integer to float, float to integer, signed to unsigned, widening/narrowing conversions)
    - SIMD operations (splat, extract lane, replace lane, arithmetic, logical, comparison, conversions, shuffles, etc.)
    - Memory operations (unaligned load/store, atomic load/store)
    - Stack operations (stack slot allocation, stack pointer comparisons)
    - Function calls (parameter handling)

5. **WebAssembly Support:** The code includes sections specifically for WebAssembly (`#if V8_ENABLE_WEBASSEMBLY`). This indicates that this part of the instruction selector handles WebAssembly-specific operations.

6. **Turboshaft Integration:** The second part of the provided code snippet seems to be related to a newer compiler pipeline in V8 called Turboshaft. It handles instruction selection for Turboshaft's IR.

**Relationship to JavaScript:**

This code is a crucial part of the V8 JavaScript engine's compilation pipeline. When JavaScript code is executed, V8 compiles it into machine code. The `InstructionSelector` is a key component in this process.

The IR opcodes handled here often directly correspond to JavaScript language features and operations. For example:

- **`IrOpcode::kWord32Add`**:  Corresponds to the `+` operator for 32-bit integers in JavaScript.
- **`IrOpcode::kFloat64Add`**: Corresponds to the `+` operator for floating-point numbers in JavaScript.
- **`IrOpcode::kCall` (not explicitly shown but likely handled in other parts of the file or related files):** Corresponds to calling a function in JavaScript.
- **SIMD opcodes**: Correspond to the JavaScript WebAssembly SIMD API, allowing for high-performance parallel computations.

**JavaScript Examples:**

```javascript
// Example of integer addition
let a = 10;
let b = 20;
let sum = a + b; // This might lead to IrOpcode::kWord32Add

// Example of floating-point multiplication
let x = 3.14;
let y = 2.0;
let product = x * y; // This might lead to IrOpcode::kFloat64Mul

// Example of bitwise AND
let mask = 0xFF;
let value = 0xAB;
let result = mask & value; // This might lead to IrOpcode::kWord32And

// Example of WebAssembly SIMD
// (Assuming you have a WebAssembly module loaded)
const simdArray = new Float32Array([1, 2, 3, 4]);
const f32x4 = wasmModule.instance.exports.f32x4_load(simdArray.buffer);
const doubled = wasmModule.instance.exports.f32x4_mul(f32x4, wasmModule.instance.exports.f32x4_splat(2.0)); // Might involve IrOpcode::kF32x4Mul and kF32x4Splat
```

**Summary of Functionality (Part 3):**

This part of the `InstructionSelector` code in V8 is responsible for selecting machine instructions for a wide range of arithmetic, bitwise, conversion, SIMD, memory, and stack operations represented in the intermediate representation. It takes platform-independent IR nodes and translates them into platform-specific instructions. It plays a crucial role in the efficient execution of JavaScript and WebAssembly code by mapping high-level operations to low-level machine code.

这是 `InstructionSelector.cc` 文件的第三部分，主要负责处理各种算术、位运算、类型转换、SIMD（单指令多数据流）以及一些内存和栈操作的中间表示（IR）节点的指令选择。

**主要功能归纳:**

1. **处理多种数据类型的运算:** 代码涵盖了 32 位和 64 位整数（有符号和无符号）、单精度和双精度浮点数以及 SIMD 向量的各种操作。例如：
    - 整数加减乘除、位运算（与、或、异或、移位、旋转等）
    - 浮点数加减乘除、绝对值、平方根、三角函数等
    - SIMD 向量的各种操作，包括车道访问、算术运算、逻辑运算、比较运算、类型转换、混洗等。

2. **类型转换:**  负责处理不同数据类型之间的转换，包括：
    - 整数和浮点数之间的转换
    - 不同位宽整数之间的转换（例如，int32 到 int64）
    - 浮点数精度转换（例如，float32 到 float64）
    - 位类型转换 (bitcast)

3. **SIMD 指令选择:**  针对 SIMD 操作提供指令选择，这是 V8 引擎支持 WebAssembly 和 JavaScript SIMD API 的关键部分。 代码中包含了大量的 `IrOpcode::kF32x4...`, `IrOpcode::kI32x4...` 等，这些都对应于 SIMD 的各种操作。

4. **内存和栈操作:**  处理与内存和栈相关的操作，例如：
    - 非对齐的加载和存储 (`UnalignedLoad`, `UnalignedStore`)
    - 原子操作 (`Word32AtomicLoad`, `Word32AtomicStore` 等)
    - 栈槽分配 (`StackSlot`)
    - 栈指针比较 (`StackPointerGreaterThan`)
    - 加载帧指针和根寄存器等

5. **标记节点表示:**  在进行指令选择之前，会使用 `MarkAs...` 函数来标记节点的机器表示类型，这有助于后续选择正确的机器指令。

6. **Turboshaft 支持:**  代码片段中也包含了对 Turboshaft 的支持，Turboshaft 是 V8 中一个新的编译管道。针对 Turboshaft 的 IR 节点（`turboshaft::Opcode`），也有相应的指令选择逻辑。

**与 JavaScript 的关系及示例:**

这段代码直接关系到 JavaScript 代码的执行效率。当 V8 引擎编译 JavaScript 代码时，会将 JavaScript 代码转换为中间表示（IR），然后 `InstructionSelector` 会将这些 IR 节点转换为特定架构的机器指令。

例如，在 JavaScript 中进行简单的加法运算：

```javascript
let a = 10;
let b = 20;
let sum = a + b;
```

在 V8 的编译过程中，`a + b` 这个操作可能会被表示为一个 `IrOpcode::kWord32Add` 的 IR 节点（假设 `a` 和 `b` 被推断为 32 位整数）。`InstructionSelector` 的这部分代码就会负责为 `IrOpcode::kWord32Add` 选择合适的机器指令，例如在 x86 架构上可能是 `ADD` 指令。

再例如，使用 JavaScript 的 SIMD API：

```javascript
let a = Float32x4(1, 2, 3, 4);
let b = Float32x4(5, 6, 7, 8);
let c = a.add(b);
```

这里的 `a.add(b)` 操作可能会对应到 `IrOpcode::kF32x4Add` 这个 IR 节点。`InstructionSelector` 就会负责选择对应的 SIMD 加法指令，例如在支持 AVX 的架构上可能是 `vaddps` 指令。

**总结来说，这部分代码是 V8 引擎将平台无关的中间表示转换为特定硬件平台可执行的机器指令的关键组件，它直接影响着 JavaScript 和 WebAssembly 代码的执行性能。** 这段代码处理了大量的基本运算和类型转换，是 V8 编译器后端的核心部分。

### 提示词
```
这是目录为v8/src/compiler/backend/instruction-selector.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第3部分，共4部分，请归纳一下它的功能
```

### 源代码
```
turn MarkAsWord32(node), VisitWord32Shr(node);
    case IrOpcode::kWord32Sar:
      return MarkAsWord32(node), VisitWord32Sar(node);
    case IrOpcode::kWord32Rol:
      return MarkAsWord32(node), VisitWord32Rol(node);
    case IrOpcode::kWord32Ror:
      return MarkAsWord32(node), VisitWord32Ror(node);
    case IrOpcode::kWord32Equal:
      return VisitWord32Equal(node);
    case IrOpcode::kWord32Clz:
      return MarkAsWord32(node), VisitWord32Clz(node);
    case IrOpcode::kWord32Ctz:
      return MarkAsWord32(node), VisitWord32Ctz(node);
    case IrOpcode::kWord32ReverseBits:
      return MarkAsWord32(node), VisitWord32ReverseBits(node);
    case IrOpcode::kWord32ReverseBytes:
      return MarkAsWord32(node), VisitWord32ReverseBytes(node);
    case IrOpcode::kInt32AbsWithOverflow:
      return MarkAsWord32(node), VisitInt32AbsWithOverflow(node);
    case IrOpcode::kWord32Popcnt:
      return MarkAsWord32(node), VisitWord32Popcnt(node);
    case IrOpcode::kWord64Popcnt:
      return MarkAsWord64(node), VisitWord64Popcnt(node);
    case IrOpcode::kWord32Select:
      return MarkAsWord32(node), VisitSelect(node);
    case IrOpcode::kWord64And:
      return MarkAsWord64(node), VisitWord64And(node);
    case IrOpcode::kWord64Or:
      return MarkAsWord64(node), VisitWord64Or(node);
    case IrOpcode::kWord64Xor:
      return MarkAsWord64(node), VisitWord64Xor(node);
    case IrOpcode::kWord64Shl:
      return MarkAsWord64(node), VisitWord64Shl(node);
    case IrOpcode::kWord64Shr:
      return MarkAsWord64(node), VisitWord64Shr(node);
    case IrOpcode::kWord64Sar:
      return MarkAsWord64(node), VisitWord64Sar(node);
    case IrOpcode::kWord64Rol:
      return MarkAsWord64(node), VisitWord64Rol(node);
    case IrOpcode::kWord64Ror:
      return MarkAsWord64(node), VisitWord64Ror(node);
    case IrOpcode::kWord64Clz:
      return MarkAsWord64(node), VisitWord64Clz(node);
    case IrOpcode::kWord64Ctz:
      return MarkAsWord64(node), VisitWord64Ctz(node);
    case IrOpcode::kWord64ReverseBits:
      return MarkAsWord64(node), VisitWord64ReverseBits(node);
    case IrOpcode::kWord64ReverseBytes:
      return MarkAsWord64(node), VisitWord64ReverseBytes(node);
    case IrOpcode::kSimd128ReverseBytes:
      return MarkAsSimd128(node), VisitSimd128ReverseBytes(node);
    case IrOpcode::kInt64AbsWithOverflow:
      return MarkAsWord64(node), VisitInt64AbsWithOverflow(node);
    case IrOpcode::kWord64Equal:
      return VisitWord64Equal(node);
    case IrOpcode::kWord64Select:
      return MarkAsWord64(node), VisitSelect(node);
    case IrOpcode::kInt32Add:
      return MarkAsWord32(node), VisitInt32Add(node);
    case IrOpcode::kInt32AddWithOverflow:
      return MarkAsWord32(node), VisitInt32AddWithOverflow(node);
    case IrOpcode::kInt32Sub:
      return MarkAsWord32(node), VisitInt32Sub(node);
    case IrOpcode::kInt32SubWithOverflow:
      return VisitInt32SubWithOverflow(node);
    case IrOpcode::kInt32Mul:
      return MarkAsWord32(node), VisitInt32Mul(node);
    case IrOpcode::kInt32MulWithOverflow:
      return MarkAsWord32(node), VisitInt32MulWithOverflow(node);
    case IrOpcode::kInt32MulHigh:
      return VisitInt32MulHigh(node);
    case IrOpcode::kInt64MulHigh:
      return VisitInt64MulHigh(node);
    case IrOpcode::kInt32Div:
      return MarkAsWord32(node), VisitInt32Div(node);
    case IrOpcode::kInt32Mod:
      return MarkAsWord32(node), VisitInt32Mod(node);
    case IrOpcode::kInt32LessThan:
      return VisitInt32LessThan(node);
    case IrOpcode::kInt32LessThanOrEqual:
      return VisitInt32LessThanOrEqual(node);
    case IrOpcode::kUint32Div:
      return MarkAsWord32(node), VisitUint32Div(node);
    case IrOpcode::kUint32LessThan:
      return VisitUint32LessThan(node);
    case IrOpcode::kUint32LessThanOrEqual:
      return VisitUint32LessThanOrEqual(node);
    case IrOpcode::kUint32Mod:
      return MarkAsWord32(node), VisitUint32Mod(node);
    case IrOpcode::kUint32MulHigh:
      return VisitUint32MulHigh(node);
    case IrOpcode::kUint64MulHigh:
      return VisitUint64MulHigh(node);
    case IrOpcode::kInt64Add:
      return MarkAsWord64(node), VisitInt64Add(node);
    case IrOpcode::kInt64AddWithOverflow:
      return MarkAsWord64(node), VisitInt64AddWithOverflow(node);
    case IrOpcode::kInt64Sub:
      return MarkAsWord64(node), VisitInt64Sub(node);
    case IrOpcode::kInt64SubWithOverflow:
      return MarkAsWord64(node), VisitInt64SubWithOverflow(node);
    case IrOpcode::kInt64Mul:
      return MarkAsWord64(node), VisitInt64Mul(node);
    case IrOpcode::kInt64MulWithOverflow:
      return MarkAsWord64(node), VisitInt64MulWithOverflow(node);
    case IrOpcode::kInt64Div:
      return MarkAsWord64(node), VisitInt64Div(node);
    case IrOpcode::kInt64Mod:
      return MarkAsWord64(node), VisitInt64Mod(node);
    case IrOpcode::kInt64LessThan:
      return VisitInt64LessThan(node);
    case IrOpcode::kInt64LessThanOrEqual:
      return VisitInt64LessThanOrEqual(node);
    case IrOpcode::kUint64Div:
      return MarkAsWord64(node), VisitUint64Div(node);
    case IrOpcode::kUint64LessThan:
      return VisitUint64LessThan(node);
    case IrOpcode::kUint64LessThanOrEqual:
      return VisitUint64LessThanOrEqual(node);
    case IrOpcode::kUint64Mod:
      return MarkAsWord64(node), VisitUint64Mod(node);
    case IrOpcode::kBitcastTaggedToWord:
    case IrOpcode::kBitcastTaggedToWordForTagAndSmiBits:
      return MarkAsRepresentation(MachineType::PointerRepresentation(), node),
             VisitBitcastTaggedToWord(node);
    case IrOpcode::kBitcastWordToTagged:
      return MarkAsTagged(node), VisitBitcastWordToTagged(node);
    case IrOpcode::kBitcastWordToTaggedSigned:
      return MarkAsRepresentation(MachineRepresentation::kTaggedSigned, node),
             EmitIdentity(node);
    case IrOpcode::kChangeFloat32ToFloat64:
      return MarkAsFloat64(node), VisitChangeFloat32ToFloat64(node);
    case IrOpcode::kChangeInt32ToFloat64:
      return MarkAsFloat64(node), VisitChangeInt32ToFloat64(node);
    case IrOpcode::kChangeInt64ToFloat64:
      return MarkAsFloat64(node), VisitChangeInt64ToFloat64(node);
    case IrOpcode::kChangeUint32ToFloat64:
      return MarkAsFloat64(node), VisitChangeUint32ToFloat64(node);
    case IrOpcode::kChangeFloat64ToInt32:
      return MarkAsWord32(node), VisitChangeFloat64ToInt32(node);
    case IrOpcode::kChangeFloat64ToInt64:
      return MarkAsWord64(node), VisitChangeFloat64ToInt64(node);
    case IrOpcode::kChangeFloat64ToUint32:
      return MarkAsWord32(node), VisitChangeFloat64ToUint32(node);
    case IrOpcode::kChangeFloat64ToUint64:
      return MarkAsWord64(node), VisitChangeFloat64ToUint64(node);
    case IrOpcode::kFloat64SilenceNaN:
      MarkAsFloat64(node);
      if (CanProduceSignalingNaN(node->InputAt(0))) {
        return VisitFloat64SilenceNaN(node);
      } else {
        return EmitIdentity(node);
      }
    case IrOpcode::kTruncateFloat64ToInt64:
      return MarkAsWord64(node), VisitTruncateFloat64ToInt64(node);
    case IrOpcode::kTruncateFloat64ToUint32:
      return MarkAsWord32(node), VisitTruncateFloat64ToUint32(node);
    case IrOpcode::kTruncateFloat32ToInt32:
      return MarkAsWord32(node), VisitTruncateFloat32ToInt32(node);
    case IrOpcode::kTruncateFloat32ToUint32:
      return MarkAsWord32(node), VisitTruncateFloat32ToUint32(node);
    case IrOpcode::kTryTruncateFloat32ToInt64:
      return MarkAsWord64(node), VisitTryTruncateFloat32ToInt64(node);
    case IrOpcode::kTryTruncateFloat64ToInt64:
      return MarkAsWord64(node), VisitTryTruncateFloat64ToInt64(node);
    case IrOpcode::kTryTruncateFloat32ToUint64:
      return MarkAsWord64(node), VisitTryTruncateFloat32ToUint64(node);
    case IrOpcode::kTryTruncateFloat64ToUint64:
      return MarkAsWord64(node), VisitTryTruncateFloat64ToUint64(node);
    case IrOpcode::kTryTruncateFloat64ToInt32:
      return MarkAsWord32(node), VisitTryTruncateFloat64ToInt32(node);
    case IrOpcode::kTryTruncateFloat64ToUint32:
      return MarkAsWord32(node), VisitTryTruncateFloat64ToUint32(node);
    case IrOpcode::kBitcastWord32ToWord64:
      MarkAsWord64(node);
      return VisitBitcastWord32ToWord64(node);
    case IrOpcode::kChangeInt32ToInt64:
      return MarkAsWord64(node), VisitChangeInt32ToInt64(node);
    case IrOpcode::kChangeUint32ToUint64:
      return MarkAsWord64(node), VisitChangeUint32ToUint64(node);
    case IrOpcode::kTruncateFloat64ToFloat32:
      return MarkAsFloat32(node), VisitTruncateFloat64ToFloat32(node);
    case IrOpcode::kTruncateFloat64ToWord32:
      return MarkAsWord32(node), VisitTruncateFloat64ToWord32(node);
    case IrOpcode::kTruncateInt64ToInt32:
      return MarkAsWord32(node), VisitTruncateInt64ToInt32(node);
    case IrOpcode::kRoundFloat64ToInt32:
      return MarkAsWord32(node), VisitRoundFloat64ToInt32(node);
    case IrOpcode::kRoundInt64ToFloat32:
      return MarkAsFloat32(node), VisitRoundInt64ToFloat32(node);
    case IrOpcode::kRoundInt32ToFloat32:
      return MarkAsFloat32(node), VisitRoundInt32ToFloat32(node);
    case IrOpcode::kRoundInt64ToFloat64:
      return MarkAsFloat64(node), VisitRoundInt64ToFloat64(node);
    case IrOpcode::kBitcastFloat32ToInt32:
      return MarkAsWord32(node), VisitBitcastFloat32ToInt32(node);
    case IrOpcode::kRoundUint32ToFloat32:
      return MarkAsFloat32(node), VisitRoundUint32ToFloat32(node);
    case IrOpcode::kRoundUint64ToFloat32:
      return MarkAsFloat32(node), VisitRoundUint64ToFloat32(node);
    case IrOpcode::kRoundUint64ToFloat64:
      return MarkAsFloat64(node), VisitRoundUint64ToFloat64(node);
    case IrOpcode::kBitcastFloat64ToInt64:
      return MarkAsWord64(node), VisitBitcastFloat64ToInt64(node);
    case IrOpcode::kBitcastInt32ToFloat32:
      return MarkAsFloat32(node), VisitBitcastInt32ToFloat32(node);
    case IrOpcode::kBitcastInt64ToFloat64:
      return MarkAsFloat64(node), VisitBitcastInt64ToFloat64(node);
    case IrOpcode::kFloat32Add:
      return MarkAsFloat32(node), VisitFloat32Add(node);
    case IrOpcode::kFloat32Sub:
      return MarkAsFloat32(node), VisitFloat32Sub(node);
    case IrOpcode::kFloat32Neg:
      return MarkAsFloat32(node), VisitFloat32Neg(node);
    case IrOpcode::kFloat32Mul:
      return MarkAsFloat32(node), VisitFloat32Mul(node);
    case IrOpcode::kFloat32Div:
      return MarkAsFloat32(node), VisitFloat32Div(node);
    case IrOpcode::kFloat32Abs:
      return MarkAsFloat32(node), VisitFloat32Abs(node);
    case IrOpcode::kFloat32Sqrt:
      return MarkAsFloat32(node), VisitFloat32Sqrt(node);
    case IrOpcode::kFloat32Equal:
      return VisitFloat32Equal(node);
    case IrOpcode::kFloat32LessThan:
      return VisitFloat32LessThan(node);
    case IrOpcode::kFloat32LessThanOrEqual:
      return VisitFloat32LessThanOrEqual(node);
    case IrOpcode::kFloat32Max:
      return MarkAsFloat32(node), VisitFloat32Max(node);
    case IrOpcode::kFloat32Min:
      return MarkAsFloat32(node), VisitFloat32Min(node);
    case IrOpcode::kFloat32Select:
      return MarkAsFloat32(node), VisitSelect(node);
    case IrOpcode::kFloat64Add:
      return MarkAsFloat64(node), VisitFloat64Add(node);
    case IrOpcode::kFloat64Sub:
      return MarkAsFloat64(node), VisitFloat64Sub(node);
    case IrOpcode::kFloat64Neg:
      return MarkAsFloat64(node), VisitFloat64Neg(node);
    case IrOpcode::kFloat64Mul:
      return MarkAsFloat64(node), VisitFloat64Mul(node);
    case IrOpcode::kFloat64Div:
      return MarkAsFloat64(node), VisitFloat64Div(node);
    case IrOpcode::kFloat64Mod:
      return MarkAsFloat64(node), VisitFloat64Mod(node);
    case IrOpcode::kFloat64Min:
      return MarkAsFloat64(node), VisitFloat64Min(node);
    case IrOpcode::kFloat64Max:
      return MarkAsFloat64(node), VisitFloat64Max(node);
    case IrOpcode::kFloat64Abs:
      return MarkAsFloat64(node), VisitFloat64Abs(node);
    case IrOpcode::kFloat64Acos:
      return MarkAsFloat64(node), VisitFloat64Acos(node);
    case IrOpcode::kFloat64Acosh:
      return MarkAsFloat64(node), VisitFloat64Acosh(node);
    case IrOpcode::kFloat64Asin:
      return MarkAsFloat64(node), VisitFloat64Asin(node);
    case IrOpcode::kFloat64Asinh:
      return MarkAsFloat64(node), VisitFloat64Asinh(node);
    case IrOpcode::kFloat64Atan:
      return MarkAsFloat64(node), VisitFloat64Atan(node);
    case IrOpcode::kFloat64Atanh:
      return MarkAsFloat64(node), VisitFloat64Atanh(node);
    case IrOpcode::kFloat64Atan2:
      return MarkAsFloat64(node), VisitFloat64Atan2(node);
    case IrOpcode::kFloat64Cbrt:
      return MarkAsFloat64(node), VisitFloat64Cbrt(node);
    case IrOpcode::kFloat64Cos:
      return MarkAsFloat64(node), VisitFloat64Cos(node);
    case IrOpcode::kFloat64Cosh:
      return MarkAsFloat64(node), VisitFloat64Cosh(node);
    case IrOpcode::kFloat64Exp:
      return MarkAsFloat64(node), VisitFloat64Exp(node);
    case IrOpcode::kFloat64Expm1:
      return MarkAsFloat64(node), VisitFloat64Expm1(node);
    case IrOpcode::kFloat64Log:
      return MarkAsFloat64(node), VisitFloat64Log(node);
    case IrOpcode::kFloat64Log1p:
      return MarkAsFloat64(node), VisitFloat64Log1p(node);
    case IrOpcode::kFloat64Log10:
      return MarkAsFloat64(node), VisitFloat64Log10(node);
    case IrOpcode::kFloat64Log2:
      return MarkAsFloat64(node), VisitFloat64Log2(node);
    case IrOpcode::kFloat64Pow:
      return MarkAsFloat64(node), VisitFloat64Pow(node);
    case IrOpcode::kFloat64Sin:
      return MarkAsFloat64(node), VisitFloat64Sin(node);
    case IrOpcode::kFloat64Sinh:
      return MarkAsFloat64(node), VisitFloat64Sinh(node);
    case IrOpcode::kFloat64Sqrt:
      return MarkAsFloat64(node), VisitFloat64Sqrt(node);
    case IrOpcode::kFloat64Tan:
      return MarkAsFloat64(node), VisitFloat64Tan(node);
    case IrOpcode::kFloat64Tanh:
      return MarkAsFloat64(node), VisitFloat64Tanh(node);
    case IrOpcode::kFloat64Equal:
      return VisitFloat64Equal(node);
    case IrOpcode::kFloat64LessThan:
      return VisitFloat64LessThan(node);
    case IrOpcode::kFloat64LessThanOrEqual:
      return VisitFloat64LessThanOrEqual(node);
    case IrOpcode::kFloat64Select:
      return MarkAsFloat64(node), VisitSelect(node);
    case IrOpcode::kFloat32RoundDown:
      return MarkAsFloat32(node), VisitFloat32RoundDown(node);
    case IrOpcode::kFloat64RoundDown:
      return MarkAsFloat64(node), VisitFloat64RoundDown(node);
    case IrOpcode::kFloat32RoundUp:
      return MarkAsFloat32(node), VisitFloat32RoundUp(node);
    case IrOpcode::kFloat64RoundUp:
      return MarkAsFloat64(node), VisitFloat64RoundUp(node);
    case IrOpcode::kFloat32RoundTruncate:
      return MarkAsFloat32(node), VisitFloat32RoundTruncate(node);
    case IrOpcode::kFloat64RoundTruncate:
      return MarkAsFloat64(node), VisitFloat64RoundTruncate(node);
    case IrOpcode::kFloat64RoundTiesAway:
      return MarkAsFloat64(node), VisitFloat64RoundTiesAway(node);
    case IrOpcode::kFloat32RoundTiesEven:
      return MarkAsFloat32(node), VisitFloat32RoundTiesEven(node);
    case IrOpcode::kFloat64RoundTiesEven:
      return MarkAsFloat64(node), VisitFloat64RoundTiesEven(node);
    case IrOpcode::kFloat64ExtractLowWord32:
      return MarkAsWord32(node), VisitFloat64ExtractLowWord32(node);
    case IrOpcode::kFloat64ExtractHighWord32:
      return MarkAsWord32(node), VisitFloat64ExtractHighWord32(node);
    case IrOpcode::kFloat64InsertLowWord32:
      return MarkAsFloat64(node), VisitFloat64InsertLowWord32(node);
    case IrOpcode::kFloat64InsertHighWord32:
      return MarkAsFloat64(node), VisitFloat64InsertHighWord32(node);
    case IrOpcode::kStackSlot:
      return VisitStackSlot(node);
    case IrOpcode::kStackPointerGreaterThan:
      return VisitStackPointerGreaterThan(node);
    case IrOpcode::kLoadStackCheckOffset:
      return VisitLoadStackCheckOffset(node);
    case IrOpcode::kLoadFramePointer:
      return VisitLoadFramePointer(node);
#if V8_ENABLE_WEBASSEMBLY
    case IrOpcode::kLoadStackPointer:
      return VisitLoadStackPointer(node);
    case IrOpcode::kSetStackPointer:
      return VisitSetStackPointer(node);
#endif  // V8_ENABLE_WEBASSEMBLY
    case IrOpcode::kLoadParentFramePointer:
      return VisitLoadParentFramePointer(node);
    case IrOpcode::kLoadRootRegister:
      return VisitLoadRootRegister(node);
    case IrOpcode::kUnalignedLoad: {
      LoadRepresentation type = LoadRepresentationOf(node->op());
      MarkAsRepresentation(type.representation(), node);
      return VisitUnalignedLoad(node);
    }
    case IrOpcode::kUnalignedStore:
      return VisitUnalignedStore(node);
    case IrOpcode::kInt32PairAdd:
      MarkAsWord32(node);
      MarkPairProjectionsAsWord32(node);
      return VisitInt32PairAdd(node);
    case IrOpcode::kInt32PairSub:
      MarkAsWord32(node);
      MarkPairProjectionsAsWord32(node);
      return VisitInt32PairSub(node);
    case IrOpcode::kInt32PairMul:
      MarkAsWord32(node);
      MarkPairProjectionsAsWord32(node);
      return VisitInt32PairMul(node);
    case IrOpcode::kWord32PairShl:
      MarkAsWord32(node);
      MarkPairProjectionsAsWord32(node);
      return VisitWord32PairShl(node);
    case IrOpcode::kWord32PairShr:
      MarkAsWord32(node);
      MarkPairProjectionsAsWord32(node);
      return VisitWord32PairShr(node);
    case IrOpcode::kWord32PairSar:
      MarkAsWord32(node);
      MarkPairProjectionsAsWord32(node);
      return VisitWord32PairSar(node);
    case IrOpcode::kMemoryBarrier:
      return VisitMemoryBarrier(node);
    case IrOpcode::kWord32AtomicLoad: {
      AtomicLoadParameters params = AtomicLoadParametersOf(node->op());
      LoadRepresentation type = params.representation();
      MarkAsRepresentation(type.representation(), node);
      return VisitWord32AtomicLoad(node);
    }
    case IrOpcode::kWord64AtomicLoad: {
      AtomicLoadParameters params = AtomicLoadParametersOf(node->op());
      LoadRepresentation type = params.representation();
      MarkAsRepresentation(type.representation(), node);
      return VisitWord64AtomicLoad(node);
    }
    case IrOpcode::kWord32AtomicStore:
      return VisitWord32AtomicStore(node);
    case IrOpcode::kWord64AtomicStore:
      return VisitWord64AtomicStore(node);
    case IrOpcode::kWord32AtomicPairStore:
      return VisitWord32AtomicPairStore(node);
    case IrOpcode::kWord32AtomicPairLoad: {
      MarkAsWord32(node);
      MarkPairProjectionsAsWord32(node);
      return VisitWord32AtomicPairLoad(node);
    }
#define ATOMIC_CASE(name, rep)                         \
  case IrOpcode::k##rep##Atomic##name: {               \
    MachineType type = AtomicOpType(node->op());       \
    MarkAsRepresentation(type.representation(), node); \
    return Visit##rep##Atomic##name(node);             \
  }
      ATOMIC_CASE(Add, Word32)
      ATOMIC_CASE(Add, Word64)
      ATOMIC_CASE(Sub, Word32)
      ATOMIC_CASE(Sub, Word64)
      ATOMIC_CASE(And, Word32)
      ATOMIC_CASE(And, Word64)
      ATOMIC_CASE(Or, Word32)
      ATOMIC_CASE(Or, Word64)
      ATOMIC_CASE(Xor, Word32)
      ATOMIC_CASE(Xor, Word64)
      ATOMIC_CASE(Exchange, Word32)
      ATOMIC_CASE(Exchange, Word64)
      ATOMIC_CASE(CompareExchange, Word32)
      ATOMIC_CASE(CompareExchange, Word64)
#undef ATOMIC_CASE
#define ATOMIC_CASE(name)                     \
  case IrOpcode::kWord32AtomicPair##name: {   \
    MarkAsWord32(node);                       \
    MarkPairProjectionsAsWord32(node);        \
    return VisitWord32AtomicPair##name(node); \
  }
      ATOMIC_CASE(Add)
      ATOMIC_CASE(Sub)
      ATOMIC_CASE(And)
      ATOMIC_CASE(Or)
      ATOMIC_CASE(Xor)
      ATOMIC_CASE(Exchange)
      ATOMIC_CASE(CompareExchange)
#undef ATOMIC_CASE
    case IrOpcode::kProtectedLoad:
    case IrOpcode::kLoadTrapOnNull: {
      LoadRepresentation type = LoadRepresentationOf(node->op());
      MarkAsRepresentation(type.representation(), node);
      return VisitProtectedLoad(node);
    }
    case IrOpcode::kSignExtendWord8ToInt32:
      return MarkAsWord32(node), VisitSignExtendWord8ToInt32(node);
    case IrOpcode::kSignExtendWord16ToInt32:
      return MarkAsWord32(node), VisitSignExtendWord16ToInt32(node);
    case IrOpcode::kSignExtendWord8ToInt64:
      return MarkAsWord64(node), VisitSignExtendWord8ToInt64(node);
    case IrOpcode::kSignExtendWord16ToInt64:
      return MarkAsWord64(node), VisitSignExtendWord16ToInt64(node);
    case IrOpcode::kSignExtendWord32ToInt64:
      return MarkAsWord64(node), VisitSignExtendWord32ToInt64(node);
#if V8_ENABLE_WEBASSEMBLY
    case IrOpcode::kF64x2Splat:
      return MarkAsSimd128(node), VisitF64x2Splat(node);
    case IrOpcode::kF64x2ExtractLane:
      return MarkAsFloat64(node), VisitF64x2ExtractLane(node);
    case IrOpcode::kF64x2ReplaceLane:
      return MarkAsSimd128(node), VisitF64x2ReplaceLane(node);
    case IrOpcode::kF64x2Abs:
      return MarkAsSimd128(node), VisitF64x2Abs(node);
    case IrOpcode::kF64x2Neg:
      return MarkAsSimd128(node), VisitF64x2Neg(node);
    case IrOpcode::kF64x2Sqrt:
      return MarkAsSimd128(node), VisitF64x2Sqrt(node);
    case IrOpcode::kF64x2Add:
      return MarkAsSimd128(node), VisitF64x2Add(node);
    case IrOpcode::kF64x2Sub:
      return MarkAsSimd128(node), VisitF64x2Sub(node);
    case IrOpcode::kF64x2Mul:
      return MarkAsSimd128(node), VisitF64x2Mul(node);
    case IrOpcode::kF64x2Div:
      return MarkAsSimd128(node), VisitF64x2Div(node);
    case IrOpcode::kF64x2Min:
      return MarkAsSimd128(node), VisitF64x2Min(node);
    case IrOpcode::kF64x2Max:
      return MarkAsSimd128(node), VisitF64x2Max(node);
    case IrOpcode::kF64x2Eq:
      return MarkAsSimd128(node), VisitF64x2Eq(node);
    case IrOpcode::kF64x2Ne:
      return MarkAsSimd128(node), VisitF64x2Ne(node);
    case IrOpcode::kF64x2Lt:
      return MarkAsSimd128(node), VisitF64x2Lt(node);
    case IrOpcode::kF64x2Le:
      return MarkAsSimd128(node), VisitF64x2Le(node);
    case IrOpcode::kF64x2Qfma:
      return MarkAsSimd128(node), VisitF64x2Qfma(node);
    case IrOpcode::kF64x2Qfms:
      return MarkAsSimd128(node), VisitF64x2Qfms(node);
    case IrOpcode::kF64x2Pmin:
      return MarkAsSimd128(node), VisitF64x2Pmin(node);
    case IrOpcode::kF64x2Pmax:
      return MarkAsSimd128(node), VisitF64x2Pmax(node);
    case IrOpcode::kF64x2Ceil:
      return MarkAsSimd128(node), VisitF64x2Ceil(node);
    case IrOpcode::kF64x2Floor:
      return MarkAsSimd128(node), VisitF64x2Floor(node);
    case IrOpcode::kF64x2Trunc:
      return MarkAsSimd128(node), VisitF64x2Trunc(node);
    case IrOpcode::kF64x2NearestInt:
      return MarkAsSimd128(node), VisitF64x2NearestInt(node);
    case IrOpcode::kF64x2ConvertLowI32x4S:
      return MarkAsSimd128(node), VisitF64x2ConvertLowI32x4S(node);
    case IrOpcode::kF64x2ConvertLowI32x4U:
      return MarkAsSimd128(node), VisitF64x2ConvertLowI32x4U(node);
    case IrOpcode::kF64x2PromoteLowF32x4:
      return MarkAsSimd128(node), VisitF64x2PromoteLowF32x4(node);
    case IrOpcode::kF32x4Splat:
      return MarkAsSimd128(node), VisitF32x4Splat(node);
    case IrOpcode::kF32x4ExtractLane:
      return MarkAsFloat32(node), VisitF32x4ExtractLane(node);
    case IrOpcode::kF32x4ReplaceLane:
      return MarkAsSimd128(node), VisitF32x4ReplaceLane(node);
    case IrOpcode::kF32x4SConvertI32x4:
      return MarkAsSimd128(node), VisitF32x4SConvertI32x4(node);
    case IrOpcode::kF32x4UConvertI32x4:
      return MarkAsSimd128(node), VisitF32x4UConvertI32x4(node);
    case IrOpcode::kF32x4Abs:
      return MarkAsSimd128(node), VisitF32x4Abs(node);
    case IrOpcode::kF32x4Neg:
      return MarkAsSimd128(node), VisitF32x4Neg(node);
    case IrOpcode::kF32x4Sqrt:
      return MarkAsSimd128(node), VisitF32x4Sqrt(node);
    case IrOpcode::kF32x4Add:
      return MarkAsSimd128(node), VisitF32x4Add(node);
    case IrOpcode::kF32x4Sub:
      return MarkAsSimd128(node), VisitF32x4Sub(node);
    case IrOpcode::kF32x4Mul:
      return MarkAsSimd128(node), VisitF32x4Mul(node);
    case IrOpcode::kF32x4Div:
      return MarkAsSimd128(node), VisitF32x4Div(node);
    case IrOpcode::kF32x4Min:
      return MarkAsSimd128(node), VisitF32x4Min(node);
    case IrOpcode::kF32x4Max:
      return MarkAsSimd128(node), VisitF32x4Max(node);
    case IrOpcode::kF32x4Eq:
      return MarkAsSimd128(node), VisitF32x4Eq(node);
    case IrOpcode::kF32x4Ne:
      return MarkAsSimd128(node), VisitF32x4Ne(node);
    case IrOpcode::kF32x4Lt:
      return MarkAsSimd128(node), VisitF32x4Lt(node);
    case IrOpcode::kF32x4Le:
      return MarkAsSimd128(node), VisitF32x4Le(node);
    case IrOpcode::kF32x4Qfma:
      return MarkAsSimd128(node), VisitF32x4Qfma(node);
    case IrOpcode::kF32x4Qfms:
      return MarkAsSimd128(node), VisitF32x4Qfms(node);
    case IrOpcode::kF32x4Pmin:
      return MarkAsSimd128(node), VisitF32x4Pmin(node);
    case IrOpcode::kF32x4Pmax:
      return MarkAsSimd128(node), VisitF32x4Pmax(node);
    case IrOpcode::kF32x4Ceil:
      return MarkAsSimd128(node), VisitF32x4Ceil(node);
    case IrOpcode::kF32x4Floor:
      return MarkAsSimd128(node), VisitF32x4Floor(node);
    case IrOpcode::kF32x4Trunc:
      return MarkAsSimd128(node), VisitF32x4Trunc(node);
    case IrOpcode::kF32x4NearestInt:
      return MarkAsSimd128(node), VisitF32x4NearestInt(node);
    case IrOpcode::kF32x4DemoteF64x2Zero:
      return MarkAsSimd128(node), VisitF32x4DemoteF64x2Zero(node);
    case IrOpcode::kI64x2Splat:
      return MarkAsSimd128(node), VisitI64x2Splat(node);
    case IrOpcode::kI64x2SplatI32Pair:
      return MarkAsSimd128(node), VisitI64x2SplatI32Pair(node);
    case IrOpcode::kI64x2ExtractLane:
      return MarkAsWord64(node), VisitI64x2ExtractLane(node);
    case IrOpcode::kI64x2ReplaceLane:
      return MarkAsSimd128(node), VisitI64x2ReplaceLane(node);
    case IrOpcode::kI64x2ReplaceLaneI32Pair:
      return MarkAsSimd128(node), VisitI64x2ReplaceLaneI32Pair(node);
    case IrOpcode::kI64x2Abs:
      return MarkAsSimd128(node), VisitI64x2Abs(node);
    case IrOpcode::kI64x2Neg:
      return MarkAsSimd128(node), VisitI64x2Neg(node);
    case IrOpcode::kI64x2SConvertI32x4Low:
      return MarkAsSimd128(node), VisitI64x2SConvertI32x4Low(node);
    case IrOpcode::kI64x2SConvertI32x4High:
      return MarkAsSimd128(node), VisitI64x2SConvertI32x4High(node);
    case IrOpcode::kI64x2UConvertI32x4Low:
      return MarkAsSimd128(node), VisitI64x2UConvertI32x4Low(node);
    case IrOpcode::kI64x2UConvertI32x4High:
      return MarkAsSimd128(node), VisitI64x2UConvertI32x4High(node);
    case IrOpcode::kI64x2BitMask:
      return MarkAsWord32(node), VisitI64x2BitMask(node);
    case IrOpcode::kI64x2Shl:
      return MarkAsSimd128(node), VisitI64x2Shl(node);
    case IrOpcode::kI64x2ShrS:
      return MarkAsSimd128(node), VisitI64x2ShrS(node);
    case IrOpcode::kI64x2Add:
      return MarkAsSimd128(node), VisitI64x2Add(node);
    case IrOpcode::kI64x2Sub:
      return MarkAsSimd128(node), VisitI64x2Sub(node);
    case IrOpcode::kI64x2Mul:
      return MarkAsSimd128(node), VisitI64x2Mul(node);
    case IrOpcode::kI64x2Eq:
      return MarkAsSimd128(node), VisitI64x2Eq(node);
    case IrOpcode::kI64x2Ne:
      return MarkAsSimd128(node), VisitI64x2Ne(node);
    case IrOpcode::kI64x2GtS:
      return MarkAsSimd128(node), VisitI64x2GtS(node);
    case IrOpcode::kI64x2GeS:
      return MarkAsSimd128(node), VisitI64x2GeS(node);
    case IrOpcode::kI64x2ShrU:
      return MarkAsSimd128(node), VisitI64x2ShrU(node);
    case IrOpcode::kI64x2ExtMulLowI32x4S:
      return MarkAsSimd128(node), VisitI64x2ExtMulLowI32x4S(node);
    case IrOpcode::kI64x2ExtMulHighI32x4S:
      return MarkAsSimd128(node), VisitI64x2ExtMulHighI32x4S(node);
    case IrOpcode::kI64x2ExtMulLowI32x4U:
      return MarkAsSimd128(node), VisitI64x2ExtMulLowI32x4U(node);
    case IrOpcode::kI64x2ExtMulHighI32x4U:
      return MarkAsSimd128(node), VisitI64x2ExtMulHighI32x4U(node);
    case IrOpcode::kI32x4Splat:
      return MarkAsSimd128(node), VisitI32x4Splat(node);
    case IrOpcode::kI32x4ExtractLane:
      return MarkAsWord32(node), VisitI32x4ExtractLane(node);
    case IrOpcode::kI32x4ReplaceLane:
      return MarkAsSimd128(node), VisitI32x4ReplaceLane(node);
    case IrOpcode::kI32x4SConvertF32x4:
      return MarkAsSimd128(node), VisitI32x4SConvertF32x4(node);
    case IrOpcode::kI32x4SConvertI16x8Low:
      return MarkAsSimd128(node), VisitI32x4SConvertI16x8Low(node);
    case IrOpcode::kI32x4SConvertI16x8High:
      return MarkAsSimd128(node), VisitI32x4SConvertI16x8High(node);
    case IrOpcode::kI32x4Neg:
      return MarkAsSimd128(node), VisitI32x4Neg(node);
    case IrOpcode::kI32x4Shl:
      return MarkAsSimd128(node), VisitI32x4Shl(node);
    case IrOpcode::kI32x4ShrS:
      return MarkAsSimd128(node), VisitI32x4ShrS(node);
    case IrOpcode::kI32x4Add:
      return MarkAsSimd128(node), VisitI32x4Add(node);
    case IrOpcode::kI32x4Sub:
      return MarkAsSimd128(node), VisitI32x4Sub(node);
    case IrOpcode::kI32x4Mul:
      return MarkAsSimd128(node), VisitI32x4Mul(node);
    case IrOpcode::kI32x4MinS:
      return MarkAsSimd128(node), VisitI32x4MinS(node);
    case IrOpcode::kI32x4MaxS:
      return MarkAsSimd128(node), VisitI32x4MaxS(node);
    case IrOpcode::kI32x4Eq:
      return MarkAsSimd128(node), VisitI32x4Eq(node);
    case IrOpcode::kI32x4Ne:
      return MarkAsSimd128(node), VisitI32x4Ne(node);
    case IrOpcode::kI32x4GtS:
      return MarkAsSimd128(node), VisitI32x4GtS(node);
    case IrOpcode::kI32x4GeS:
      return MarkAsSimd128(node), VisitI32x4GeS(node);
    case IrOpcode::kI32x4UConvertF32x4:
      return MarkAsSimd128(node), VisitI32x4UConvertF32x4(node);
    case IrOpcode::kI32x4UConvertI16x8Low:
      return MarkAsSimd128(node), VisitI32x4UConvertI16x8Low(node);
    case IrOpcode::kI32x4UConvertI16x8High:
      return MarkAsSimd128(node), VisitI32x4UConvertI16x8High(node);
    case IrOpcode::kI32x4ShrU:
      return MarkAsSimd128(node), VisitI32x4ShrU(node);
    case IrOpcode::kI32x4MinU:
      return MarkAsSimd128(node), VisitI32x4MinU(node);
    case IrOpcode::kI32x4MaxU:
      return MarkAsSimd128(node), VisitI32x4MaxU(node);
    case IrOpcode::kI32x4GtU:
      return MarkAsSimd128(node), VisitI32x4GtU(node);
    case IrOpcode::kI32x4GeU:
      return MarkAsSimd128(node), VisitI32x4GeU(node);
    case IrOpcode::kI32x4Abs:
      return MarkAsSimd128(node), VisitI32x4Abs(node);
    case IrOpcode::kI32x4BitMask:
      return MarkAsWord32(node), VisitI32x4BitMask(node);
    case IrOpcode::kI32x4DotI16x8S:
      return MarkAsSimd128(node), VisitI32x4DotI16x8S(node);
    case IrOpcode::kI32x4ExtMulLowI16x8S:
      return MarkAsSimd128(node), VisitI32x4ExtMulLowI16x8S(node);
    case IrOpcode::kI32x4ExtMulHighI16x8S:
      return MarkAsSimd128(node), VisitI32x4ExtMulHighI16x8S(node);
    case IrOpcode::kI32x4ExtMulLowI16x8U:
      return MarkAsSimd128(node), VisitI32x4ExtMulLowI16x8U(node);
    case IrOpcode::kI32x4ExtMulHighI16x8U:
      return MarkAsSimd128(node), VisitI32x4ExtMulHighI16x8U(node);
    case IrOpcode::kI32x4ExtAddPairwiseI16x8S:
      return MarkAsSimd128(node), VisitI32x4ExtAddPairwiseI16x8S(node);
    case IrOpcode::kI32x4ExtAddPairwiseI16x8U:
      return MarkAsSimd128(node), VisitI32x4ExtAddPairwiseI16x8U(node);
    case IrOpcode::kI32x4TruncSatF64x2SZero:
      return MarkAsSimd128(node), VisitI32x4TruncSatF64x2SZero(node);
    case IrOpcode::kI32x4TruncSatF64x2UZero:
      return MarkAsSimd128(node), VisitI32x4TruncSatF64x2UZero(node);
    case IrOpcode::kI16x8Splat:
      return MarkAsSimd128(node), VisitI16x8Splat(node);
    case IrOpcode::kI16x8ExtractLaneU:
      return MarkAsWord32(node), VisitI16x8ExtractLaneU(node);
    case IrOpcode::kI16x8ExtractLaneS:
      return MarkAsWord32(node), VisitI16x8ExtractLaneS(node);
    case IrOpcode::kI16x8ReplaceLane:
      return MarkAsSimd128(node), VisitI16x8ReplaceLane(node);
    case IrOpcode::kI16x8SConvertI8x16Low:
      return MarkAsSimd128(node), VisitI16x8SConvertI8x16Low(node);
    case IrOpcode::kI16x8SConvertI8x16High:
      return MarkAsSimd128(node), VisitI16x8SConvertI8x16High(node);
    case IrOpcode::kI16x8Neg:
      return MarkAsSimd128(node), VisitI16x8Neg(node);
    case IrOpcode::kI16x8Shl:
      return MarkAsSimd128(node), VisitI16x8Shl(node);
    case IrOpcode::kI16x8ShrS:
      return MarkAsSimd128(node), VisitI16x8ShrS(node);
    case IrOpcode::kI16x8SConvertI32x4:
      return MarkAsSimd128(node), VisitI16x8SConvertI32x4(node);
    case IrOpcode::kI16x8Add:
      return MarkAsSimd128(node), VisitI16x8Add(node);
    case IrOpcode::kI16x8AddSatS:
      return MarkAsSimd128(node), VisitI16x8AddSatS(node);
    case IrOpcode::kI16x8Sub:
      return MarkAsSimd128(node), VisitI16x8Sub(node);
    case IrOpcode::kI16x8SubSatS:
      return MarkAsSimd128(node), VisitI16x8SubSatS(node);
    case IrOpcode::kI16x8Mul:
      return MarkAsSimd128(node), VisitI16x8Mul(node);
    case IrOpcode::kI16x8MinS:
      return MarkAsSimd128(node), VisitI16x8MinS(node);
    case IrOpcode::kI16x8MaxS:
      return MarkAsSimd128(node), VisitI16x8MaxS(node);
    case IrOpcode::kI16x8Eq:
      return MarkAsSimd128(node), VisitI16x8Eq(node);
    case IrOpcode::kI16x8Ne:
      return MarkAsSimd128(node), VisitI16x8Ne(node);
    case IrOpcode::kI16x8GtS:
      return MarkAsSimd128(node), VisitI16x8GtS(node);
    case IrOpcode::kI16x8GeS:
      return MarkAsSimd128(node), VisitI16x8GeS(node);
    case IrOpcode::kI16x8UConvertI8x16Low:
      return MarkAsSimd128(node), VisitI16x8UConvertI8x16Low(node);
    case IrOpcode::kI16x8UConvertI8x16High:
      return MarkAsSimd128(node), VisitI16x8UConvertI8x16High(node);
    case IrOpcode::kI16x8ShrU:
      return MarkAsSimd128(node), VisitI16x8ShrU(node);
    case IrOpcode::kI16x8UConvertI32x4:
      return MarkAsSimd128(node), VisitI16x8UConvertI32x4(node);
    case IrOpcode::kI16x8AddSatU:
      return MarkAsSimd128(node), VisitI16x8AddSatU(node);
    case IrOpcode::kI16x8SubSatU:
      return MarkAsSimd128(node), VisitI16x8SubSatU(node);
    case IrOpcode::kI16x8MinU:
      return MarkAsSimd128(node), VisitI16x8MinU(node);
    case IrOpcode::kI16x8MaxU:
      return MarkAsSimd128(node), VisitI16x8MaxU(node);
    case IrOpcode::kI16x8GtU:
      return MarkAsSimd128(node), VisitI16x8GtU(node);
    case IrOpcode::kI16x8GeU:
      return MarkAsSimd128(node), VisitI16x8GeU(node);
    case IrOpcode::kI16x8RoundingAverageU:
      return MarkAsSimd128(node), VisitI16x8RoundingAverageU(node);
    case IrOpcode::kI16x8Q15MulRSatS:
      return MarkAsSimd128(node), VisitI16x8Q15MulRSatS(node);
    case IrOpcode::kI16x8Abs:
      return MarkAsSimd128(node), VisitI16x8Abs(node);
    case IrOpcode::kI16x8BitMask:
      return MarkAsWord32(node), VisitI16x8BitMask(node);
    case IrOpcode::kI16x8ExtMulLowI8x16S:
      return MarkAsSimd128(node), VisitI16x8ExtMulLowI8x16S(node);
    case IrOpcode::kI16x8ExtMulHighI8x16S:
      return MarkAsSimd128(node), VisitI16x8ExtMulHighI8x16S(node);
    case IrOpcode::kI16x8ExtMulLowI8x16U:
      return MarkAsSimd128(node), VisitI16x8ExtMulLowI8x16U(node);
    case IrOpcode::kI16x8ExtMulHighI8x16U:
      return MarkAsSimd128(node), VisitI16x8ExtMulHighI8x16U(node);
    case IrOpcode::kI16x8ExtAddPairwiseI8x16S:
      return MarkAsSimd128(node), VisitI16x8ExtAddPairwiseI8x16S(node);
    case IrOpcode::kI16x8ExtAddPairwiseI8x16U:
      return MarkAsSimd128(node), VisitI16x8ExtAddPairwiseI8x16U(node);
    case IrOpcode::kI8x16Splat:
      return MarkAsSimd128(node), VisitI8x16Splat(node);
    case IrOpcode::kI8x16ExtractLaneU:
      return MarkAsWord32(node), VisitI8x16ExtractLaneU(node);
    case IrOpcode::kI8x16ExtractLaneS:
      return MarkAsWord32(node), VisitI8x16ExtractLaneS(node);
    case IrOpcode::kI8x16ReplaceLane:
      return MarkAsSimd128(node), VisitI8x16ReplaceLane(node);
    case IrOpcode::kI8x16Neg:
      return MarkAsSimd128(node), VisitI8x16Neg(node);
    case IrOpcode::kI8x16Shl:
      return MarkAsSimd128(node), VisitI8x16Shl(node);
    case IrOpcode::kI8x16ShrS:
      return MarkAsSimd128(node), VisitI8x16ShrS(node);
    case IrOpcode::kI8x16SConvertI16x8:
      return MarkAsSimd128(node), VisitI8x16SConvertI16x8(node);
    case IrOpcode::kI8x16Add:
      return MarkAsSimd128(node), VisitI8x16Add(node);
    case IrOpcode::kI8x16AddSatS:
      return MarkAsSimd128(node), VisitI8x16AddSatS(node);
    case IrOpcode::kI8x16Sub:
      return MarkAsSimd128(node), VisitI8x16Sub(node);
    case IrOpcode::kI8x16SubSatS:
      return MarkAsSimd128(node), VisitI8x16SubSatS(node);
    case IrOpcode::kI8x16MinS:
      return MarkAsSimd128(node), VisitI8x16MinS(node);
    case IrOpcode::kI8x16MaxS:
      return MarkAsSimd128(node), VisitI8x16MaxS(node);
    case IrOpcode::kI8x16Eq:
      return MarkAsSimd128(node), VisitI8x16Eq(node);
    case IrOpcode::kI8x16Ne:
      return MarkAsSimd128(node), VisitI8x16Ne(node);
    case IrOpcode::kI8x16GtS:
      return MarkAsSimd128(node), VisitI8x16GtS(node);
    case IrOpcode::kI8x16GeS:
      return MarkAsSimd128(node), VisitI8x16GeS(node);
    case IrOpcode::kI8x16ShrU:
      return MarkAsSimd128(node), VisitI8x16ShrU(node);
    case IrOpcode::kI8x16UConvertI16x8:
      return MarkAsSimd128(node), VisitI8x16UConvertI16x8(node);
    case IrOpcode::kI8x16AddSatU:
      return MarkAsSimd128(node), VisitI8x16AddSatU(node);
    case IrOpcode::kI8x16SubSatU:
      return MarkAsSimd128(node), VisitI8x16SubSatU(node);
    case IrOpcode::kI8x16MinU:
      return MarkAsSimd128(node), VisitI8x16MinU(node);
    case IrOpcode::kI8x16MaxU:
      return MarkAsSimd128(node), VisitI8x16MaxU(node);
    case IrOpcode::kI8x16GtU:
      return MarkAsSimd128(node), VisitI8x16GtU(node);
    case IrOpcode::kI8x16GeU:
      return MarkAsSimd128(node), VisitI8x16GeU(node);
    case IrOpcode::kI8x16RoundingAverageU:
      return MarkAsSimd128(node), VisitI8x16RoundingAverageU(node);
    case IrOpcode::kI8x16Popcnt:
      return MarkAsSimd128(node), VisitI8x16Popcnt(node);
    case IrOpcode::kI8x16Abs:
      return MarkAsSimd128(node), VisitI8x16Abs(node);
    case IrOpcode::kI8x16BitMask:
      return MarkAsWord32(node), VisitI8x16BitMask(node);
    case IrOpcode::kS128Const:
      return MarkAsSimd128(node), VisitS128Const(node);
    case IrOpcode::kS128Zero:
      return MarkAsSimd128(node), VisitS128Zero(node);
    case IrOpcode::kS128And:
      return MarkAsSimd128(node), VisitS128And(node);
    case IrOpcode::kS128Or:
      return MarkAsSimd128(node), VisitS128Or(node);
    case IrOpcode::kS128Xor:
      return MarkAsSimd128(node), VisitS128Xor(node);
    case IrOpcode::kS128Not:
      return MarkAsSimd128(node), VisitS128Not(node);
    case IrOpcode::kS128Select:
      return MarkAsSimd128(node), VisitS128Select(node);
    case IrOpcode::kS128AndNot:
      return MarkAsSimd128(node), VisitS128AndNot(node);
    case IrOpcode::kI8x16Swizzle:
      return MarkAsSimd128(node), VisitI8x16Swizzle(node);
    case IrOpcode::kI8x16Shuffle:
      return MarkAsSimd128(node), VisitI8x16Shuffle(node);
    case IrOpcode::kV128AnyTrue:
      return MarkAsWord32(node), VisitV128AnyTrue(node);
    case IrOpcode::kI64x2AllTrue:
      return MarkAsWord32(node), VisitI64x2AllTrue(node);
    case IrOpcode::kI32x4AllTrue:
      return MarkAsWord32(node), VisitI32x4AllTrue(node);
    case IrOpcode::kI16x8AllTrue:
      return MarkAsWord32(node), VisitI16x8AllTrue(node);
    case IrOpcode::kI8x16AllTrue:
      return MarkAsWord32(node), VisitI8x16AllTrue(node);
    case IrOpcode::kI8x16RelaxedLaneSelect:
      return MarkAsSimd128(node), VisitI8x16RelaxedLaneSelect(node);
    case IrOpcode::kI16x8RelaxedLaneSelect:
      return MarkAsSimd128(node), VisitI16x8RelaxedLaneSelect(node);
    case IrOpcode::kI32x4RelaxedLaneSelect:
      return MarkAsSimd128(node), VisitI32x4RelaxedLaneSelect(node);
    case IrOpcode::kI64x2RelaxedLaneSelect:
      return MarkAsSimd128(node), VisitI64x2RelaxedLaneSelect(node);
    case IrOpcode::kF32x4RelaxedMin:
      return MarkAsSimd128(node), VisitF32x4RelaxedMin(node);
    case IrOpcode::kF32x4RelaxedMax:
      return MarkAsSimd128(node), VisitF32x4RelaxedMax(node);
    case IrOpcode::kF64x2RelaxedMin:
      return MarkAsSimd128(node), VisitF64x2RelaxedMin(node);
    case IrOpcode::kF64x2RelaxedMax:
      return MarkAsSimd128(node), VisitF64x2RelaxedMax(node);
    case IrOpcode::kI32x4RelaxedTruncF64x2SZero:
      return MarkAsSimd128(node), VisitI32x4RelaxedTruncF64x2SZero(node);
    case IrOpcode::kI32x4RelaxedTruncF64x2UZero:
      return MarkAsSimd128(node), VisitI32x4RelaxedTruncF64x2UZero(node);
    case IrOpcode::kI32x4RelaxedTruncF32x4S:
      return MarkAsSimd128(node), VisitI32x4RelaxedTruncF32x4S(node);
    case IrOpcode::kI32x4RelaxedTruncF32x4U:
      return MarkAsSimd128(node), VisitI32x4RelaxedTruncF32x4U(node);
    case IrOpcode::kI16x8RelaxedQ15MulRS:
      return MarkAsSimd128(node), VisitI16x8RelaxedQ15MulRS(node);
    case IrOpcode::kI16x8DotI8x16I7x16S:
      return MarkAsSimd128(node), VisitI16x8DotI8x16I7x16S(node);
    case IrOpcode::kI32x4DotI8x16I7x16AddS:
      return MarkAsSimd128(node), VisitI32x4DotI8x16I7x16AddS(node);
    case IrOpcode::kF16x8Splat:
      return MarkAsSimd128(node), VisitF16x8Splat(node);
    case IrOpcode::kF16x8ExtractLane:
      return MarkAsFloat32(node), VisitF16x8ExtractLane(node);
    case IrOpcode::kF16x8ReplaceLane:
      return MarkAsSimd128(node), VisitF16x8ReplaceLane(node);
    case IrOpcode::kF16x8Abs:
      return MarkAsSimd128(node), VisitF16x8Abs(node);
    case IrOpcode::kF16x8Neg:
      return MarkAsSimd128(node), VisitF16x8Neg(node);
    case IrOpcode::kF16x8Sqrt:
      return MarkAsSimd128(node), VisitF16x8Sqrt(node);
    case IrOpcode::kF16x8Ceil:
      return MarkAsSimd128(node), VisitF16x8Ceil(node);
    case IrOpcode::kF16x8Floor:
      return MarkAsSimd128(node), VisitF16x8Floor(node);
    case IrOpcode::kF16x8Trunc:
      return MarkAsSimd128(node), VisitF16x8Trunc(node);
    case IrOpcode::kF16x8NearestInt:
      return MarkAsSimd128(node), VisitF16x8NearestInt(node);
    case IrOpcode::kF16x8Add:
      return MarkAsSimd128(node), VisitF16x8Add(node);
    case IrOpcode::kF16x8Sub:
      return MarkAsSimd128(node), VisitF16x8Sub(node);
    case IrOpcode::kF16x8Mul:
      return MarkAsSimd128(node), VisitF16x8Mul(node);
    case IrOpcode::kF16x8Div:
      return MarkAsSimd128(node), VisitF16x8Div(node);
    case IrOpcode::kF16x8Min:
      return MarkAsSimd128(node), VisitF16x8Min(node);
    case IrOpcode::kF16x8Max:
      return MarkAsSimd128(node), VisitF16x8Max(node);
    case IrOpcode::kF16x8Pmin:
      return MarkAsSimd128(node), VisitF16x8Pmin(node);
    case IrOpcode::kF16x8Pmax:
      return MarkAsSimd128(node), VisitF16x8Pmax(node);
    case IrOpcode::kF16x8Eq:
      return MarkAsSimd128(node), VisitF16x8Eq(node);
    case IrOpcode::kF16x8Ne:
      return MarkAsSimd128(node), VisitF16x8Ne(node);
    case IrOpcode::kF16x8Lt:
      return MarkAsSimd128(node), VisitF16x8Lt(node);
    case IrOpcode::kF16x8Le:
      return MarkAsSimd128(node), VisitF16x8Le(node);
    case IrOpcode::kF16x8SConvertI16x8:
      return MarkAsSimd128(node), VisitF16x8SConvertI16x8(node);
    case IrOpcode::kF16x8UConvertI16x8:
      return MarkAsSimd128(node), VisitF16x8UConvertI16x8(node);
    case IrOpcode::kI16x8UConvertF16x8:
      return MarkAsSimd128(node), VisitI16x8UConvertF16x8(node);
    case IrOpcode::kI16x8SConvertF16x8:
      return MarkAsSimd128(node), VisitI16x8SConvertF16x8(node);
    case IrOpcode::kF16x8DemoteF32x4Zero:
      return MarkAsSimd128(node), VisitF16x8DemoteF32x4Zero(node);
    case IrOpcode::kF16x8DemoteF64x2Zero:
      return MarkAsSimd128(node), VisitF16x8DemoteF64x2Zero(node);
    case IrOpcode::kF32x4PromoteLowF16x8:
      return MarkAsSimd128(node), VisitF32x4PromoteLowF16x8(node);
    case IrOpcode::kF16x8Qfma:
      return MarkAsSimd128(node), VisitF16x8Qfma(node);
    case IrOpcode::kF16x8Qfms:
      return MarkAsSimd128(node), VisitF16x8Qfms(node);

      // SIMD256
#if defined(V8_TARGET_ARCH_X64) && defined(V8_ENABLE_WASM_SIMD256_REVEC)
    case IrOpcode::kF64x4Min:
      return MarkAsSimd256(node), VisitF64x4Min(node);
    case IrOpcode::kF64x4Max:
      return MarkAsSimd256(node), VisitF64x4Max(node);
    case IrOpcode::kF64x4Add:
      return MarkAsSimd256(node), VisitF64x4Add(node);
    case IrOpcode::kF32x8Add:
      return MarkAsSimd256(node), VisitF32x8Add(node);
    case IrOpcode::kI64x4Add:
      return MarkAsSimd256(node), VisitI64x4Add(node);
    case IrOpcode::kI32x8Add:
      return MarkAsSimd256(node), VisitI32x8Add(node);
    case IrOpcode::kI16x16Add:
      return MarkAsSimd256(node), VisitI16x16Add(node);
    case IrOpcode::kI8x32Add:
      return MarkAsSimd256(node), VisitI8x32Add(node);
    case IrOpcode::kF64x4Sub:
      return MarkAsSimd256(node), VisitF64x4Sub(node);
    case IrOpcode::kF32x8Sub:
      return MarkAsSimd256(node), VisitF32x8Sub(node);
    case IrOpcode::kF32x8Min:
      return MarkAsSimd256(node), VisitF32x8Min(node);
    case IrOpcode::kF32x8Max:
      return MarkAsSimd256(node), VisitF32x8Max(node);
    case IrOpcode::kI64x4Ne:
      return MarkAsSimd256(node), VisitI64x4Ne(node);
    case IrOpcode::kI64x4GeS:
      return MarkAsSimd256(node), VisitI64x4GeS(node);
    case IrOpcode::kI32x8Ne:
      return MarkAsSimd256(node), VisitI32x8Ne(node);
    case IrOpcode::kI32x8GtU:
      return MarkAsSimd256(node), VisitI32x8GtU(node);
    case IrOpcode::kI32x8GeS:
      return MarkAsSimd256(node), VisitI32x8GeS(node);
    case IrOpcode::kI32x8GeU:
      return MarkAsSimd256(node), VisitI32x8GeU(node);
    case IrOpcode::kI16x16Ne:
      return MarkAsSimd256(node), VisitI16x16Ne(node);
    case IrOpcode::kI16x16GtU:
      return MarkAsSimd256(node), VisitI16x16GtU(node);
    case IrOpcode::kI16x16GeS:
      return MarkAsSimd256(node), VisitI16x16GeS(node);
    case IrOpcode::kI16x16GeU:
      return MarkAsSimd256(node), VisitI16x16GeU(node);
    case IrOpcode::kI8x32Ne:
      return MarkAsSimd256(node), VisitI8x32Ne(node);
    case IrOpcode::kI8x32GtU:
      return MarkAsSimd256(node), VisitI8x32GtU(node);
    case IrOpcode::kI8x32GeS:
      return MarkAsSimd256(node), VisitI8x32GeS(node);
    case IrOpcode::kI8x32GeU:
      return MarkAsSimd256(node), VisitI8x32GeU(node);
    case IrOpcode::kI64x4Sub:
      return MarkAsSimd256(node), VisitI64x4Sub(node);
    case IrOpcode::kI32x8Sub:
      return MarkAsSimd256(node), VisitI32x8Sub(node);
    case IrOpcode::kI16x16Sub:
      return MarkAsSimd256(node), VisitI16x16Sub(node);
    case IrOpcode::kI8x32Sub:
      return MarkAsSimd256(node), VisitI8x32Sub(node);
    case IrOpcode::kF64x4Mul:
      return MarkAsSimd256(node), VisitF64x4Mul(node);
    case IrOpcode::kF32x8Mul:
      return MarkAsSimd256(node), VisitF32x8Mul(node);
    case IrOpcode::kI64x4Mul:
      return MarkAsSimd256(node), VisitI64x4Mul(node);
    case IrOpcode::kI32x8Mul:
      return MarkAsSimd256(node), VisitI32x8Mul(node);
    case IrOpcode::kI16x16Mul:
      return MarkAsSimd256(node), VisitI16x16Mul(node);
    case IrOpcode::kF32x8Div:
      return MarkAsSimd256(node), VisitF32x8Div(node);
    case IrOpcode::kF64x4Div:
      return MarkAsSimd256(node), VisitF64x4Div(node);
    case IrOpcode::kI16x16AddSatS:
      return MarkAsSimd256(node), VisitI16x16AddSatS(node);
    case IrOpcode::kI8x32AddSatS:
      return MarkAsSimd256(node), VisitI8x32AddSatS(node);
    case IrOpcode::kI16x16AddSatU:
      return MarkAsSimd256(node), VisitI16x16AddSatU(node);
    case IrOpcode::kI8x32AddSatU:
      return MarkAsSimd256(node), VisitI8x32AddSatU(node);
    case IrOpcode::kI16x16SubSatS:
      return MarkAsSimd256(node), VisitI16x16SubSatS(node);
    case IrOpcode::kI8x32SubSatS:
      return MarkAsSimd256(node), VisitI8x32SubSatS(node);
    case IrOpcode::kI16x16SubSatU:
      return MarkAsSimd256(node), VisitI16x16SubSatU(node);
    case IrOpcode::kI8x32SubSatU:
      return MarkAsSimd256(node), VisitI8x32SubSatU(node);
    case IrOpcode::kI32x8SConvertF32x8:
      return MarkAsSimd256(node), VisitI32x8SConvertF32x8(node);
    case IrOpcode::kI32x8UConvertF32x8:
      return MarkAsSimd256(node), VisitI32x8UConvertF32x8(node);
    case IrOpcode::kF64x4ConvertI32x4S:
      return MarkAsSimd256(node), VisitF64x4ConvertI32x4S(node);
    case IrOpcode::kF32x8SConvertI32x8:
      return MarkAsSimd256(node), VisitF32x8SConvertI32x8(node);
    case IrOpcode::kF32x8UConvertI32x8:
      return MarkAsSimd256(node), VisitF32x8UConvertI32x8(node);
    case IrOpcode::kF32x4DemoteF64x4:
      return MarkAsSimd256(node), VisitF32x4DemoteF64x4(node);
    case IrOpcode::kI64x4SConvertI32x4:
      return MarkAsSimd256(node), VisitI64x4SConvertI32x4(node);
    case IrOpcode::kI64x4UConvertI32x4:
      return MarkAsSimd256(node), VisitI64x4UConvertI32x4(node);
    case IrOpcode::kI32x8SConvertI16x8:
      return MarkAsSimd256(node), VisitI32x8SConvertI16x8(node);
    case IrOpcode::kI32x8UConvertI16x8:
      return MarkAsSimd256(node), VisitI32x8UConvertI16x8(node);
    case IrOpcode::kI16x16SConvertI8x16:
      return MarkAsSimd256(node), VisitI16x16SConvertI8x16(node);
    case IrOpcode::kI16x16UConvertI8x16:
      return MarkAsSimd256(node), VisitI16x16UConvertI8x16(node);
    case IrOpcode::kI16x16SConvertI32x8:
      return MarkAsSimd256(node), VisitI16x16SConvertI32x8(node);
    case IrOpcode::kI16x16UConvertI32x8:
      return MarkAsSimd256(node), VisitI16x16UConvertI32x8(node);
    case IrOpcode::kI8x32SConvertI16x16:
      return MarkAsSimd256(node), VisitI8x32SConvertI16x16(node);
    case IrOpcode::kI8x32UConvertI16x16:
      return MarkAsSimd256(node), VisitI8x32UConvertI16x16(node);
    case IrOpcode::kF32x8Abs:
      return MarkAsSimd256(node), VisitF32x8Abs(node);
    case IrOpcode::kF64x4Abs:
      return MarkAsSimd256(node), VisitF64x4Abs(node);
    case IrOpcode::kF32x8Neg:
      return MarkAsSimd256(node), VisitF32x8Neg(node);
    case IrOpcode::kF64x4Neg:
      return MarkAsSimd256(node), VisitF64x4Neg(node);
    case IrOpcode::kF32x8Sqrt:
      return MarkAsSimd256(node), VisitF32x8Sqrt(node);
    case IrOpcode::kF64x4Sqrt:
      return MarkAsSimd256(node), VisitF64x4Sqrt(node);
    case IrOpcode::kI32x8Abs:
      return MarkAsSimd256(node), VisitI32x8Abs(node);
    case IrOpcode::kI32x8Neg:
      return MarkAsSimd256(node), VisitI32x8Neg(node);
    case IrOpcode::kI16x16Abs:
      return MarkAsSimd256(node), VisitI16x16Abs(node);
    case IrOpcode::kI16x16Neg:
      return MarkAsSimd256(node), VisitI16x16Neg(node);
    case IrOpcode::kI8x32Abs:
      return MarkAsSimd256(node), VisitI8x32Abs(node);
    case IrOpcode::kI8x32Neg:
      return MarkAsSimd256(node), VisitI8x32Neg(node);
    case IrOpcode::kI64x4Shl:
      return MarkAsSimd256(node), VisitI64x4Shl(node);
    case IrOpcode::kI64x4ShrU:
      return MarkAsSimd256(node), VisitI64x4ShrU(node);
    case IrOpcode::kI32x8Shl:
      return MarkAsSimd256(node), VisitI32x8Shl(node);
    case IrOpcode::kI32x8ShrS:
      return MarkAsSimd256(node), VisitI32x8ShrS(node);
    case IrOpcode::kI32x8ShrU:
      return MarkAsSimd256(node), VisitI32x8ShrU(node);
    case IrOpcode::kI16x16Shl:
      return MarkAsSimd256(node), VisitI16x16Shl(node);
    case IrOpcode::kI16x16ShrS:
      return MarkAsSimd256(node), VisitI16x16ShrS(node);
    case IrOpcode::kI16x16ShrU:
      return MarkAsSimd256(node), VisitI16x16ShrU(node);
    case IrOpcode::kI32x8DotI16x16S:
      return MarkAsSimd256(node), VisitI32x8DotI16x16S(node);
    case IrOpcode::kI16x16RoundingAverageU:
      return MarkAsSimd256(node), VisitI16x16RoundingAverageU(node);
    case IrOpcode::kI8x32RoundingAverageU:
      return MarkAsSimd256(node), VisitI8x32RoundingAverageU(node);
    case IrOpcode::kS256Const:
      return MarkAsSimd256(node), VisitS256Const(node);
    case IrOpcode::kS256Zero:
      return MarkAsSimd256(node), VisitS256Zero(node);
    case IrOpcode::kS256And:
      return MarkAsSimd256(node), VisitS256And(node);
    case IrOpcode::kS256Or:
      return MarkAsSimd256(node), VisitS256Or(node);
    case IrOpcode::kS256Xor:
      return MarkAsSimd256(node), VisitS256Xor(node);
    case IrOpcode::kS256Not:
      return MarkAsSimd256(node), VisitS256Not(node);
    case IrOpcode::kS256Select:
      return MarkAsSimd256(node), VisitS256Select(node);
    case IrOpcode::kS256AndNot:
      return MarkAsSimd256(node), VisitS256AndNot(node);
    case IrOpcode::kF32x8Eq:
      return MarkAsSimd256(node), VisitF32x8Eq(node);
    case IrOpcode::kF64x4Eq:
      return MarkAsSimd256(node), VisitF64x4Eq(node);
    case IrOpcode::kI64x4Eq:
      return MarkAsSimd256(node), VisitI64x4Eq(node);
    case IrOpcode::kI32x8Eq:
      return MarkAsSimd256(node), VisitI32x8Eq(node);
    case IrOpcode::kI16x16Eq:
      return MarkAsSimd256(node), VisitI16x16Eq(node);
    case IrOpcode::kI8x32Eq:
      return MarkAsSimd256(node), VisitI8x32Eq(node);
    case IrOpcode::kF32x8Ne:
      return MarkAsSimd256(node), VisitF32x8Ne(node);
    case IrOpcode::kF64x4Ne:
      return MarkAsSimd256(node), VisitF64x4Ne(node);
    case IrOpcode::kI64x4GtS:
      return MarkAsSimd256(node), VisitI64x4GtS(node);
    case IrOpcode::kI32x8GtS:
      return MarkAsSimd256(node), VisitI32x8GtS(node);
    case IrOpcode::kI16x16GtS:
      return MarkAsSimd256(node), VisitI16x16GtS(node);
    case IrOpcode::kI8x32GtS:
      return MarkAsSimd256(node), VisitI8x32GtS(node);
    case IrOpcode::kF64x4Lt:
      return MarkAsSimd256(node), VisitF64x4Lt(node);
    case IrOpcode::kF32x8Lt:
      return MarkAsSimd256(node), VisitF32x8Lt(node);
    case IrOpcode::kF64x4Le:
      return MarkAsSimd256(node), VisitF64x4Le(node);
    case IrOpcode::kF32x8Le:
      return MarkAsSimd256(node), VisitF32x8Le(node);
    case IrOpcode::kI32x8MinS:
      return MarkAsSimd256(node), VisitI32x8MinS(node);
    case IrOpcode::kI16x16MinS:
      return MarkAsSimd256(node), VisitI16x16MinS(node);
    case IrOpcode::kI8x32MinS:
      return MarkAsSimd256(node), VisitI8x32MinS(node);
    case IrOpcode::kI32x8MinU:
      return MarkAsSimd256(node), VisitI32x8MinU(node);
    case IrOpcode::kI16x16MinU:
      return MarkAsSimd256(node), VisitI16x16MinU(node);
    case IrOpcode::kI8x32MinU:
      return MarkAsSimd256(node), VisitI8x32MinU(node);
    case IrOpcode::kI32x8MaxS:
      return MarkAsSimd256(node), VisitI32x8MaxS(node);
    case IrOpcode::kI16x16MaxS:
      return MarkAsSimd256(node), VisitI16x16MaxS(node);
    case IrOpcode::kI8x32MaxS:
      return MarkAsSimd256(node), VisitI8x32MaxS(node);
    case IrOpcode::kI32x8MaxU:
      return MarkAsSimd256(node), VisitI32x8MaxU(node);
    case IrOpcode::kI16x16MaxU:
      return MarkAsSimd256(node), VisitI16x16MaxU(node);
    case IrOpcode::kI8x32MaxU:
      return MarkAsSimd256(node), VisitI8x32MaxU(node);
    case IrOpcode::kI64x4Splat:
      return MarkAsSimd256(node), VisitI64x4Splat(node);
    case IrOpcode::kI32x8Splat:
      return MarkAsSimd256(node), VisitI32x8Splat(node);
    case IrOpcode::kI16x16Splat:
      return MarkAsSimd256(node), VisitI16x16Splat(node);
    case IrOpcode::kI8x32Splat:
      return MarkAsSimd256(node), VisitI8x32Splat(node);
    case IrOpcode::kF32x8Splat:
      return MarkAsSimd256(node), VisitF32x8Splat(node);
    case IrOpcode::kF64x4Splat:
      return MarkAsSimd256(node), VisitF64x4Splat(node);
    case IrOpcode::kI64x4ExtMulI32x4S:
      return MarkAsSimd256(node), VisitI64x4ExtMulI32x4S(node);
    case IrOpcode::kI64x4ExtMulI32x4U:
      return MarkAsSimd256(node), VisitI64x4ExtMulI32x4U(node);
    case IrOpcode::kI32x8ExtMulI16x8S:
      return MarkAsSimd256(node), VisitI32x8ExtMulI16x8S(node);
    case IrOpcode::kI32x8ExtMulI16x8U:
      return MarkAsSimd256(node), VisitI32x8ExtMulI16x8U(node);
    case IrOpcode::kI16x16ExtMulI8x16S:
      return MarkAsSimd256(node), VisitI16x16ExtMulI8x16S(node);
    case IrOpcode::kI16x16ExtMulI8x16U:
      return MarkAsSimd256(node), VisitI16x16ExtMulI8x16U(node);
    case IrOpcode::kI32x8ExtAddPairwiseI16x16S:
      return MarkAsSimd256(node), VisitI32x8ExtAddPairwiseI16x16S(node);
    case IrOpcode::kI32x8ExtAddPairwiseI16x16U:
      return MarkAsSimd256(node), VisitI32x8ExtAddPairwiseI16x16U(node);
    case IrOpcode::kI16x16ExtAddPairwiseI8x32S:
      return MarkAsSimd256(node), VisitI16x16ExtAddPairwiseI8x32S(node);
    case IrOpcode::kI16x16ExtAddPairwiseI8x32U:
      return MarkAsSimd256(node), VisitI16x16ExtAddPairwiseI8x32U(node);
    case IrOpcode::kF32x8Pmin:
      return MarkAsSimd256(node), VisitF32x8Pmin(node);
    case IrOpcode::kF32x8Pmax:
      return MarkAsSimd256(node), VisitF32x8Pmax(node);
    case IrOpcode::kF64x4Pmin:
      return MarkAsSimd256(node), VisitF64x4Pmin(node);
    case IrOpcode::kF64x4Pmax:
      return MarkAsSimd256(node), VisitF64x4Pmax(node);
    case IrOpcode::kI8x32Shuffle:
      return MarkAsSimd256(node), VisitI8x32Shuffle(node);
    case IrOpcode::kExtractF128:
      return MarkAsSimd128(node), VisitExtractF128(node);
    case IrOpcode::kF32x8Qfma:
      return MarkAsSimd256(node), VisitF32x8Qfma(node);
    case IrOpcode::kF32x8Qfms:
      return MarkAsSimd256(node), VisitF32x8Qfms(node);
    case IrOpcode::kF64x4Qfma:
      return MarkAsSimd256(node), VisitF64x4Qfma(node);
    case IrOpcode::kF64x4Qfms:
      return MarkAsSimd256(node), VisitF64x4Qfms(node);
    case IrOpcode::kI64x4RelaxedLaneSelect:
      return MarkAsSimd256(node), VisitI64x4RelaxedLaneSelect(node);
    case IrOpcode::kI32x8RelaxedLaneSelect:
      return MarkAsSimd256(node), VisitI32x8RelaxedLaneSelect(node);
    case IrOpcode::kI16x16RelaxedLaneSelect:
      return MarkAsSimd256(node), VisitI16x16RelaxedLaneSelect(node);
    case IrOpcode::kI8x32RelaxedLaneSelect:
      return MarkAsSimd256(node), VisitI8x32RelaxedLaneSelect(node);
    case IrOpcode::kI32x8DotI8x32I7x32AddS:
      return MarkAsSimd256(node), VisitI32x8DotI8x32I7x32AddS(node);
    case IrOpcode::kI16x16DotI8x32I7x32S:
      return MarkAsSimd256(node), VisitI16x16DotI8x32I7x32S(node);
    case IrOpcode::kF32x8RelaxedMin:
      return MarkAsSimd256(node), VisitF32x8RelaxedMin(node);
    case IrOpcode::kF32x8RelaxedMax:
      return MarkAsSimd256(node), VisitF32x8RelaxedMax(node);
    case IrOpcode::kF64x4RelaxedMin:
      return MarkAsSimd256(node), VisitF64x4RelaxedMin(node);
    case IrOpcode::kF64x4RelaxedMax:
      return MarkAsSimd256(node), VisitF64x4RelaxedMax(node);
    case IrOpcode::kI32x8RelaxedTruncF32x8S:
      return MarkAsSimd256(node), VisitI32x8RelaxedTruncF32x8S(node);
    case IrOpcode::kI32x8RelaxedTruncF32x8U:
      return MarkAsSimd256(node), VisitI32x8RelaxedTruncF32x8U(node);
#endif  // V8_TARGET_ARCH_X64 && V8_ENABLE_WASM_SIMD256_REVEC
#endif  // V8_ENABLE_WEBASSEMBLY
    default:
      FATAL("Unexpected operator #%d:%s @ node #%d", node->opcode(),
            node->op()->mnemonic(), node->id());
  }
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitNode(
    turboshaft::OpIndex node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  tick_counter_->TickAndMaybeEnterSafepoint();
  const turboshaft::Operation& op = this->Get(node);
  using Opcode = turboshaft::Opcode;
  using Rep = turboshaft::RegisterRepresentation;
  switch (op.opcode) {
    case Opcode::kBranch:
    case Opcode::kGoto:
    case Opcode::kReturn:
    case Opcode::kTailCall:
    case Opcode::kUnreachable:
    case Opcode::kDeoptimize:
    case Opcode::kSwitch:
    case Opcode::kCheckException:
      // Those are already handled in VisitControl.
      DCHECK(op.IsBlockTerminator());
      break;
    case Opcode::kParameter: {
      // Parameters should always be scheduled to the first block.
      DCHECK_EQ(this->rpo_number(this->block(schedule(), node)).ToInt(), 0);
      MachineType type = linkage()->GetParameterType(
          op.Cast<turboshaft::ParameterOp>().parameter_index);
      MarkAsRepresentation(type.representation(), node);
      return VisitParameter(node);
    }
    case Opcode::kChange: {
      const turboshaft::ChangeOp& change = op.Cast<turboshaft::ChangeOp>();
      MarkAsRepresentation(change.to.machine_representation(), node);
      switch (change.kind) {
        case ChangeOp::Kind::kFloatConversion:
          if (change.from == Rep::Float64()) {
            DCHECK_EQ(change.to, Rep::Float32());
            return VisitTruncateFloat64ToFloat32(node);
          } else {
            DCHECK_EQ(change.from, Rep::Float32());
            DCHECK_EQ(change.to, Rep::Float64());
            return VisitChangeFloat32ToFloat64(node);
          }
        case ChangeOp::Kind::kSignedFloatTruncateOverflowToMin:
        case ChangeOp::Kind::kUnsignedFloatTruncateOverflowToMin: {
          using A = ChangeOp::Assumption;
          bool is_signed =
              change.kind == ChangeOp::Kind::kSignedFloatTruncateOverflowToMin;
          switch (multi(change.from, change.to, is_signed, change.assumption)) {
            case multi(Rep::Float32(), Rep::Word32(), true, A::kNoOverflow):
            case multi(Rep::Float32(), Rep::Word32(), true, A::kNoAssumption):
              return VisitTruncateFloat32ToInt32(node);
            case multi(Rep::Float32(), Rep::Word32(), false, A::kNoOverflow):
            case multi(Rep::Float32(), Rep::Word32(), false, A::kNoAssumption):
              return VisitTruncateFloat32ToUint32(node);
            case multi(Rep::Float64(), Rep::Word32(), true, A::kReversible):
              return VisitChangeFloat64ToInt32(node);
            case multi(Rep::Float64(), Rep::Word32(), false, A::kReversible):
              return VisitChangeFloat64ToUint32(node);
            case multi(Rep::Float64(), Rep::Word32(), true, A::kNoOverflow):
              return VisitRoundFloat64ToInt32(node);
            case multi(Rep::Float64(), Rep::Word32(), false, A::kNoAssumption):
            case multi(Rep::Float64(), Rep::Word32(), false, A::kNoOverflow):
              return VisitTruncateFloat64ToUint32(node);
            case multi(Rep::Float64(), Rep::Word64(), true, A::kReversible):
              return VisitChangeFloat64ToInt64(node);
            case multi(Rep::Float64(), Rep::Word64(), false, A::kReversible):
              return VisitChangeFloat64ToUint64(node);
            case multi(Rep::Float64(), Rep::Word64(), true, A::kNoOverflow):
            case multi(Rep::Float64(), Rep::Word64(), true, A::kNoAssumption):
              return VisitTruncateFloat64ToInt64(node);
            default:
              // Invalid combination.
              UNREACHABLE();
          }

          UNREACHABLE();
        }
        case ChangeOp::Kind::kJSFloatTruncate:
          DCHECK_EQ(change.from, Rep::Float64());
          DCHECK_EQ(change.to, Rep::Word32());
          return VisitTruncateFloat64ToWord32(node);
        case ChangeOp::Kind::kJSFloat16TruncateWithBitcast:
          DCHECK_EQ(Rep::Float64(), change.from);
          DCHECK_EQ(Rep::Word32(), change.to);
          return VisitTruncateFloat64ToFloat16RawBits(node);
        case ChangeOp::Kind::kSignedToFloat:
          if (change.from == Rep::Word32()) {
            if (change.to == Rep::Float32()) {
              return VisitRoundInt32ToFloat32(node);
            } else {
              DCHECK_EQ(change.to, Rep::Float64());
              DCHECK_EQ(change.assumption, ChangeOp::Assumption::kNoAssumption);
              return VisitChangeInt32ToFloat64(node);
            }
          } else {
            DCHECK_EQ(change.from, Rep::Word64());
            if (change.to == Rep::Float32()) {
              return VisitRoundInt64ToFloat32(node);
            } else {
              DCHECK_EQ(change.to, Rep::Float64());
              if (change.assumption == ChangeOp::Assumption::kReversible) {
                return VisitChangeInt64ToFloat64(node);
              } else {
                return VisitRoundInt64ToFloat64(node);
              }
            }
          }
          UNREACHABLE();
        case ChangeOp::Kind::kUnsignedToFloat:
          switch (multi(change.from, change.to)) {
            case multi(Rep::Word32(), Rep::Float32()):
              return VisitRoundUint32ToFloat32(node);
            case multi(Rep::Word32(), Rep::Float64()):
              return VisitChangeUint32ToFloat64(node);
            case multi(Rep::Word64(), Rep::Float32()):
              return VisitRoundUint64ToFloat32(node);
            case multi(Rep::Word64(), Rep::Float64()):
              return VisitRoundUint64ToFloat64(node);
            default:
              UNREACHABLE();
          }
        case ChangeOp::Kind::kExtractHighHalf:
          DCHECK_EQ(change.from, Rep::Float64());
          DCHECK_EQ(change.to, Rep::Word32());
          return VisitFloat64ExtractHighWord32(node);
        case ChangeOp::Kind::kExtractLowHalf:
          DCHECK_EQ(change.from, Rep::Float64());
          DCHECK_EQ(change.to, Rep::Word32());
          return VisitFloat64ExtractLowWord32(node);
        case ChangeOp::Kind::kZeroExtend:
          DCHECK_EQ(change.from, Rep::Word32());
          DCHECK_EQ(change.to, Rep::Word64());
          return VisitChangeUint32ToUint64(node);
        case ChangeOp::Kind::kSignExtend:
          DCHECK_EQ(change.from, Rep::Word32());
          DCHECK_EQ(change.to, Rep::Word64());
          return VisitChangeInt32ToInt64(node);
        case ChangeOp::Kind::kTruncate:
          DCHECK_EQ(change.from, Rep::Word64());
          DCHECK_EQ(change.to, Rep::Word32());
          MarkAsWord32(node);
          return VisitTruncateInt64ToInt32(node);
        case ChangeOp::Kind::kBitcast:
          switch (multi(change.from, change.to)) {
```