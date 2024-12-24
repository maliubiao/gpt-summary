Response: The user wants a summary of the functionality of the C++ source code file `v8/src/compiler/backend/instruction-selector.cc`. They have provided a snippet of the code, which appears to be part 4 of 4.

Based on the code snippet, which primarily consists of a large `switch` statement handling different `Opcode` values, the file seems to be responsible for:

1. **Instruction Selection:**  The core function is to translate high-level operations from the Turbofan/Turboshaft intermediate representation (IR) into low-level machine instructions specific to the target architecture. This is evident from the numerous `case` statements handling different `Opcode`s like `kWordBinop`, `kFloatBinop`, `kLoad`, `kStore`, etc., and the calls to `Visit...` functions that generate these instructions.

2. **Representation Handling:** The code explicitly deals with different data representations like `Word32`, `Word64`, `Float32`, `Float64`, `Tagged`, and `Compressed`. It uses `MarkAs...` functions to assign representations to nodes in the IR graph. The `switch` statements often have multiple cases based on the combination of input and output representations.

3. **Architecture Abstraction:**  While the specific instructions generated are architecture-dependent, this file provides a layer of abstraction. It defines the logic for selecting the appropriate instruction based on the operation and data types, and the actual instruction emission is likely delegated to architecture-specific code within the `Visit...` functions.

4. **Handling Specific Operations:**  The code demonstrates handling of various arithmetic, logical, memory access, bit manipulation, and control flow operations. It also includes support for SIMD instructions and atomic operations.

5. **Frame State Management:** The presence of `Opcode::kFrameState` and the `GetFrameStateDescriptor` function indicates that this file is involved in managing the stack frames and their layouts, which is crucial for debugging and exception handling.

6. **Deoptimization:** The `Opcode::kDeoptimizeIf` case shows the file's role in generating code for deoptimizing the execution if certain conditions are met.

7. **WebAssembly Support:** The numerous `Opcode`s prefixed with `kSimd` and the `#ifdef V8_ENABLE_WEBASSEMBLY` blocks suggest that this file handles instruction selection for WebAssembly code as well.

**Relationship with JavaScript:**

This file is a crucial part of the V8 JavaScript engine's compilation pipeline. It takes the optimized IR generated from JavaScript code and translates it into executable machine code.

Here are some examples of how the operations handled in this file relate to JavaScript features:

* **Arithmetic Operations:**  JavaScript's `+`, `-`, `*`, `/`, `%` operators on numbers will be translated into the corresponding `kWordBinop` or `kFloatBinop` operations.

```javascript
let a = 10;
let b = 5;
let sum = a + b; // This might result in a kWordBinop::kAdd operation
let product = a * b; // This might result in a kWordBinop::kMul operation
let quotient = a / b; // This might result in a kFloatBinop::kDiv operation
```

* **Bitwise Operations:** JavaScript's bitwise operators like `&`, `|`, `^`, `~`, `<<`, `>>`, `>>>` will correspond to `kWordUnary` and `kWordBinop` operations.

```javascript
let x = 5; // 0101 in binary
let y = 3; // 0011 in binary
let andResult = x & y; // This will likely result in a kWordBinop::kBitwiseAnd operation
let leftShift = x << 1; // This will likely result in a kShift::kShiftLeft operation
```

* **Memory Access:** Accessing object properties or array elements in JavaScript involves memory loads and stores, which will be handled by `kLoad` and `kStore` operations.

```javascript
let obj = { value: 42 };
let val = obj.value; // This will likely result in a kLoad operation

let arr = [1, 2, 3];
arr[0] = 100; // This will likely result in a kStore operation
```

* **Type Conversions:** JavaScript's dynamic typing often requires type conversions. Operations like `Number()` or bitwise operations on non-integer types might lead to `kBitcast` or `kTryChange` operations.

```javascript
let str = "10";
let num = Number(str); // This could involve operations related to type conversion

let floatVal = 3.14;
let intVal = floatVal | 0; // Bitwise OR with 0 truncates to integer, possibly using bitcast operations
```

* **SIMD Operations (if enabled):**  JavaScript's WebAssembly integration allows the use of SIMD instructions for parallel data processing, which aligns with the `kSimd...` operations.

```javascript
// Example using WebAssembly SIMD API (requires WebAssembly module)
const i32x4 = new Int32x4(1, 2, 3, 4);
const doubled = i32x4.mul(new Int32x4(2, 2, 2, 2)); // This will likely involve kSimd128Binop::kI32x4Mul
```

**Summary of Part 4:**

Given that this is part 4 of 4, this section of the `instruction-selector.cc` file appears to be handling a wide range of more complex and specialized operations. It continues the pattern of mapping Turbofan/Turboshaft IR opcodes to specific machine instruction sequences, covering areas like:

* **Advanced Bit Manipulation:** Reverse bytes, counting leading/trailing zeros, population count.
* **Floating-Point Arithmetic:**  Comprehensive set of unary and binary float operations, including rounding, square root, logarithms, and trigonometric functions.
* **Overflow Checking:** Operations that detect and handle arithmetic overflows.
* **Comparisons:**  Generating instructions for comparing different data types.
* **Atomic Operations:**  Support for atomic loads, stores, and read-modify-write operations for multi-threaded scenarios.
* **SIMD Instructions:** Extensive handling of SIMD operations for both 128-bit and 256-bit vectors (if enabled).
* **Stack Management:** Operations related to stack pointer manipulation and accessing frame constants.
* **Deoptimization and Trapping:** Handling conditional deoptimization and WebAssembly traps.
* **Frame State Management:**  Retrieving frame state information for debugging and exception handling.

In essence, part 4 completes the instruction selection logic by covering a broad spectrum of operations needed for efficient execution of JavaScript and WebAssembly code within the V8 engine.

This is the final part of the `instruction-selector.cc` file, focusing on the code generation for a wide variety of Turboshaft IR operations. Here's a breakdown of its functionality:

**Core Function: Low-Level Instruction Selection**

This part of the code continues the process of translating high-level operations from the Turboshaft intermediate representation (IR) into concrete machine instructions. It does this by:

* **Pattern Matching on Opcodes:** The large `switch (op.opcode())` statement is the central mechanism. It inspects the type of operation (`Opcode`) and dispatches to specific `Visit...` functions to generate the corresponding assembly code.
* **Handling Data Representations:**  The code explicitly considers the data types involved in operations (e.g., `Word32`, `Word64`, `Float32`, `Float64`, `Tagged`). It uses `MarkAs...` functions to annotate nodes in the IR graph with their intended machine representation. The `multi()` helper is used to handle combinations of input and output representations for operations like bitcasts and type changes.
* **Architecture-Specific Code Generation:** The `Visit...` functions (e.g., `VisitInt32Add`, `VisitFloat64Mul`, `VisitLoad`) encapsulate the logic for emitting the actual machine instructions. These functions are likely implemented in architecture-specific files, allowing the core instruction selection logic to be relatively platform-independent.

**Key Areas Covered in This Part:**

* **Type Conversions and Bit Manipulation:**
    * **`kBitcast`:** Handles reinterpreting the bits of a value from one type to another (e.g., integer to float, tagged pointer to raw word).
    * **`kTryChange`:**  Attempts to change the representation of a value, often involving truncation of floating-point numbers to integers.
    * **`kWordUnary`:**  Deals with unary operations on words like reversing bytes, counting leading/trailing zeros, population count, and sign extension.
    * **`kWordBinop`:** Handles binary operations on words (integers) such as addition, subtraction, multiplication, division, modulo, and bitwise operations.
    * **`kShift`:** Generates instructions for bitwise shift and rotate operations.
* **Floating-Point Operations:**
    * **`kFloatUnary`:** Covers unary floating-point operations like absolute value, negation, rounding (down, up, to zero, ties to even), square root, and more advanced mathematical functions (logarithms, exponentials, trigonometry).
    * **`kFloatBinop`:** Handles binary floating-point operations: addition, subtraction, multiplication, division, modulo, minimum, maximum, power, and `atan2`.
* **Checked Arithmetic:**
    * **`kOverflowCheckedBinop`:**  Generates instructions for arithmetic operations that detect and handle overflows.
    * **`kOverflowCheckedUnary`:** Handles checked unary operations (like absolute value with overflow check).
* **Control Flow and Function Calls:**
    * **`kCall` and `kDidntThrow`:** Handles function calls, particularly in the context of exception handling. The code ensures calls are processed after it's known whether exceptions are caught.
    * **`kDeoptimizeIf`:** Generates code to trigger deoptimization if a condition is met.
    * **`kTrapIf` (WebAssembly):**  Generates trap instructions for WebAssembly.
    * **`kCatchBlockBegin`:**  Marks the beginning of a catch block for exception handling.
* **Memory Access:**
    * **`kLoad`:** Generates instructions to load values from memory, handling aligned and unaligned accesses, as well as atomic and protected loads.
    * **`kStore`:** Generates instructions to store values to memory, handling alignment, atomicity, and write barriers.
    * **`kAtomicRMW` and `kAtomicWord32Pair`:** Handle atomic read-modify-write operations and atomic operations on 32-bit pairs, essential for concurrent programming.
    * **`kMemoryBarrier`:**  Emits memory barrier instructions to enforce memory ordering.
* **Comparisons:**
    * **`kComparison`:** Generates instructions for comparing values of different types (integers, floats, tagged pointers).
* **Constants:**
    * **`kConstant`:** Handles loading constant values, determining their representation (integer, float, tagged pointer, etc.).
    * **`kFrameConstant`:** Accesses constants related to the current stack frame.
* **Stack Management:**
    * **`kStackPointerGreaterThan`:**  Checks if the stack pointer is above a certain value.
    * **`kStackSlot`:** Represents a slot on the stack.
    * **`kLoadStackPointer` and `kSetStackPointer` (WebAssembly):** Operations for manipulating the stack pointer in WebAssembly.
* **Tagged Values:**
    * **`kTaggedBitcast`:** Handles bitwise reinterpretation between tagged pointers and raw words (used for Smi encoding).
* **Phi Nodes and Projections:**
    * **`kPhi`:**  Handles merging values at control flow join points.
    * **`kProjection`:** Extracts values from multi-output operations.
* **Debugging and Miscellaneous:**
    * **`kDebugBreak`:**  Inserts a breakpoint for debugging.
    * **`kAbortCSADcheck`:**  Likely related to internal consistency checks during compilation.
    * **`kComment`:** Adds comments to the generated assembly.
* **SIMD (Single Instruction, Multiple Data) Operations (WebAssembly):**  A significant portion of this part deals with generating instructions for SIMD operations, both 128-bit and 256-bit vectors. This includes operations like:
    * Loading and storing SIMD vectors.
    * Unary operations (negation, absolute value, etc.).
    * Binary operations (addition, subtraction, multiplication, etc.).
    * Shift operations.
    * Test operations.
    * Splatting (creating a vector with the same value in all lanes).
    * Shuffling (rearranging elements within a vector).
    * Lane replacement and extraction.
    * Ternary operations (conditional selection within vectors).

**Relationship to JavaScript:**

This file is a crucial component in V8's compilation pipeline. It's responsible for taking the optimized representation of JavaScript code and transforming it into the machine code that the CPU will execute. Here's how it relates:

* **JavaScript Operators:**  Every JavaScript operator (+, -, *, /, &, |, <<, >>, etc.) will eventually be translated into one or more of the opcodes handled in this file. For example, `a + b` might become a `kWordBinop::kAdd` instruction.
* **Data Types:** JavaScript's numbers, strings, objects, and other data types are represented and manipulated using the representations handled here (`Tagged`, `Word32`, `Float64`, etc.).
* **Control Flow:**  JavaScript's `if`, `else`, `for`, `while`, and function calls are implemented using control flow structures that are ultimately translated into instructions by this code.
* **WebAssembly Integration:** If your JavaScript code interacts with WebAssembly modules, the SIMD operations and other WebAssembly-specific opcodes handled here are essential for efficient execution.
* **Performance:** The choices made in this instruction selection phase directly impact the performance of the generated code. Selecting the most efficient machine instructions for each operation is critical for V8's speed.

**In summary, this final part of `instruction-selector.cc` completes the intricate task of converting a high-level, platform-independent representation of code into low-level, architecture-specific machine instructions. It handles a vast array of operations, including advanced arithmetic, bit manipulation, memory access, control flow, and specialized instructions like SIMD, making it a fundamental piece of V8's code generation process.**

Prompt: 
```
这是目录为v8/src/compiler/backend/instruction-selector.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第4部分，共4部分，请归纳一下它的功能

"""

            case multi(Rep::Word32(), Rep::Word64()):
              return VisitBitcastWord32ToWord64(node);
            case multi(Rep::Word32(), Rep::Float32()):
              return VisitBitcastInt32ToFloat32(node);
            case multi(Rep::Word64(), Rep::Float64()):
              return VisitBitcastInt64ToFloat64(node);
            case multi(Rep::Float32(), Rep::Word32()):
              return VisitBitcastFloat32ToInt32(node);
            case multi(Rep::Float64(), Rep::Word64()):
              return VisitBitcastFloat64ToInt64(node);
            default:
              UNREACHABLE();
          }
      }
      UNREACHABLE();
    }
    case Opcode::kTryChange: {
      const TryChangeOp& try_change = op.Cast<TryChangeOp>();
      MarkAsRepresentation(try_change.to.machine_representation(), node);
      DCHECK(try_change.kind ==
                 TryChangeOp::Kind::kSignedFloatTruncateOverflowUndefined ||
             try_change.kind ==
                 TryChangeOp::Kind::kUnsignedFloatTruncateOverflowUndefined);
      const bool is_signed =
          try_change.kind ==
          TryChangeOp::Kind::kSignedFloatTruncateOverflowUndefined;
      switch (multi(try_change.from, try_change.to, is_signed)) {
        case multi(Rep::Float64(), Rep::Word64(), true):
          return VisitTryTruncateFloat64ToInt64(node);
        case multi(Rep::Float64(), Rep::Word64(), false):
          return VisitTryTruncateFloat64ToUint64(node);
        case multi(Rep::Float64(), Rep::Word32(), true):
          return VisitTryTruncateFloat64ToInt32(node);
        case multi(Rep::Float64(), Rep::Word32(), false):
          return VisitTryTruncateFloat64ToUint32(node);
        case multi(Rep::Float32(), Rep::Word64(), true):
          return VisitTryTruncateFloat32ToInt64(node);
        case multi(Rep::Float32(), Rep::Word64(), false):
          return VisitTryTruncateFloat32ToUint64(node);
        default:
          UNREACHABLE();
      }
      UNREACHABLE();
    }
    case Opcode::kConstant: {
      const ConstantOp& constant = op.Cast<ConstantOp>();
      switch (constant.kind) {
        case ConstantOp::Kind::kWord32:
        case ConstantOp::Kind::kWord64:
        case ConstantOp::Kind::kSmi:
        case ConstantOp::Kind::kTaggedIndex:
        case ConstantOp::Kind::kExternal:
          break;
        case ConstantOp::Kind::kFloat32:
          MarkAsFloat32(node);
          break;
        case ConstantOp::Kind::kFloat64:
          MarkAsFloat64(node);
          break;
        case ConstantOp::Kind::kHeapObject:
        case ConstantOp::Kind::kTrustedHeapObject:
          MarkAsTagged(node);
          break;
        case ConstantOp::Kind::kCompressedHeapObject:
          MarkAsCompressed(node);
          break;
        case ConstantOp::Kind::kNumber:
          if (!IsSmiDouble(constant.number().get_scalar())) MarkAsTagged(node);
          break;
        case ConstantOp::Kind::kRelocatableWasmCall:
        case ConstantOp::Kind::kRelocatableWasmStubCall:
        case ConstantOp::Kind::kRelocatableWasmCanonicalSignatureId:
        case ConstantOp::Kind::kRelocatableWasmIndirectCallTarget:
          break;
      }
      VisitConstant(node);
      break;
    }
    case Opcode::kWordUnary: {
      const WordUnaryOp& unop = op.Cast<WordUnaryOp>();
      if (unop.rep == WordRepresentation::Word32()) {
        MarkAsWord32(node);
        switch (unop.kind) {
          case WordUnaryOp::Kind::kReverseBytes:
            return VisitWord32ReverseBytes(node);
          case WordUnaryOp::Kind::kCountLeadingZeros:
            return VisitWord32Clz(node);
          case WordUnaryOp::Kind::kCountTrailingZeros:
            return VisitWord32Ctz(node);
          case WordUnaryOp::Kind::kPopCount:
            return VisitWord32Popcnt(node);
          case WordUnaryOp::Kind::kSignExtend8:
            return VisitSignExtendWord8ToInt32(node);
          case WordUnaryOp::Kind::kSignExtend16:
            return VisitSignExtendWord16ToInt32(node);
        }
      } else {
        DCHECK_EQ(unop.rep, WordRepresentation::Word64());
        MarkAsWord64(node);
        switch (unop.kind) {
          case WordUnaryOp::Kind::kReverseBytes:
            return VisitWord64ReverseBytes(node);
          case WordUnaryOp::Kind::kCountLeadingZeros:
            return VisitWord64Clz(node);
          case WordUnaryOp::Kind::kCountTrailingZeros:
            return VisitWord64Ctz(node);
          case WordUnaryOp::Kind::kPopCount:
            return VisitWord64Popcnt(node);
          case WordUnaryOp::Kind::kSignExtend8:
            return VisitSignExtendWord8ToInt64(node);
          case WordUnaryOp::Kind::kSignExtend16:
            return VisitSignExtendWord16ToInt64(node);
        }
      }
      UNREACHABLE();
    }
    case Opcode::kWordBinop: {
      const WordBinopOp& binop = op.Cast<WordBinopOp>();
      if (binop.rep == WordRepresentation::Word32()) {
        MarkAsWord32(node);
        switch (binop.kind) {
          case WordBinopOp::Kind::kAdd:
            return VisitInt32Add(node);
          case WordBinopOp::Kind::kMul:
            return VisitInt32Mul(node);
          case WordBinopOp::Kind::kSignedMulOverflownBits:
            return VisitInt32MulHigh(node);
          case WordBinopOp::Kind::kUnsignedMulOverflownBits:
            return VisitUint32MulHigh(node);
          case WordBinopOp::Kind::kBitwiseAnd:
            return VisitWord32And(node);
          case WordBinopOp::Kind::kBitwiseOr:
            return VisitWord32Or(node);
          case WordBinopOp::Kind::kBitwiseXor:
            return VisitWord32Xor(node);
          case WordBinopOp::Kind::kSub:
            return VisitInt32Sub(node);
          case WordBinopOp::Kind::kSignedDiv:
            return VisitInt32Div(node);
          case WordBinopOp::Kind::kUnsignedDiv:
            return VisitUint32Div(node);
          case WordBinopOp::Kind::kSignedMod:
            return VisitInt32Mod(node);
          case WordBinopOp::Kind::kUnsignedMod:
            return VisitUint32Mod(node);
        }
      } else {
        DCHECK_EQ(binop.rep, WordRepresentation::Word64());
        MarkAsWord64(node);
        switch (binop.kind) {
          case WordBinopOp::Kind::kAdd:
            return VisitInt64Add(node);
          case WordBinopOp::Kind::kMul:
            return VisitInt64Mul(node);
          case WordBinopOp::Kind::kSignedMulOverflownBits:
            return VisitInt64MulHigh(node);
          case WordBinopOp::Kind::kUnsignedMulOverflownBits:
            return VisitUint64MulHigh(node);
          case WordBinopOp::Kind::kBitwiseAnd:
            return VisitWord64And(node);
          case WordBinopOp::Kind::kBitwiseOr:
            return VisitWord64Or(node);
          case WordBinopOp::Kind::kBitwiseXor:
            return VisitWord64Xor(node);
          case WordBinopOp::Kind::kSub:
            return VisitInt64Sub(node);
          case WordBinopOp::Kind::kSignedDiv:
            return VisitInt64Div(node);
          case WordBinopOp::Kind::kUnsignedDiv:
            return VisitUint64Div(node);
          case WordBinopOp::Kind::kSignedMod:
            return VisitInt64Mod(node);
          case WordBinopOp::Kind::kUnsignedMod:
            return VisitUint64Mod(node);
        }
      }
      UNREACHABLE();
    }
    case Opcode::kFloatUnary: {
      const auto& unop = op.Cast<FloatUnaryOp>();
      if (unop.rep == Rep::Float32()) {
        MarkAsFloat32(node);
        switch (unop.kind) {
          case FloatUnaryOp::Kind::kAbs:
            return VisitFloat32Abs(node);
          case FloatUnaryOp::Kind::kNegate:
            return VisitFloat32Neg(node);
          case FloatUnaryOp::Kind::kRoundDown:
            return VisitFloat32RoundDown(node);
          case FloatUnaryOp::Kind::kRoundUp:
            return VisitFloat32RoundUp(node);
          case FloatUnaryOp::Kind::kRoundToZero:
            return VisitFloat32RoundTruncate(node);
          case FloatUnaryOp::Kind::kRoundTiesEven:
            return VisitFloat32RoundTiesEven(node);
          case FloatUnaryOp::Kind::kSqrt:
            return VisitFloat32Sqrt(node);
          // Those operations are only supported on 64 bit.
          case FloatUnaryOp::Kind::kSilenceNaN:
          case FloatUnaryOp::Kind::kLog:
          case FloatUnaryOp::Kind::kLog2:
          case FloatUnaryOp::Kind::kLog10:
          case FloatUnaryOp::Kind::kLog1p:
          case FloatUnaryOp::Kind::kCbrt:
          case FloatUnaryOp::Kind::kExp:
          case FloatUnaryOp::Kind::kExpm1:
          case FloatUnaryOp::Kind::kSin:
          case FloatUnaryOp::Kind::kCos:
          case FloatUnaryOp::Kind::kSinh:
          case FloatUnaryOp::Kind::kCosh:
          case FloatUnaryOp::Kind::kAcos:
          case FloatUnaryOp::Kind::kAsin:
          case FloatUnaryOp::Kind::kAsinh:
          case FloatUnaryOp::Kind::kAcosh:
          case FloatUnaryOp::Kind::kTan:
          case FloatUnaryOp::Kind::kTanh:
          case FloatUnaryOp::Kind::kAtan:
          case FloatUnaryOp::Kind::kAtanh:
            UNREACHABLE();
        }
      } else {
        DCHECK_EQ(unop.rep, Rep::Float64());
        MarkAsFloat64(node);
        switch (unop.kind) {
          case FloatUnaryOp::Kind::kAbs:
            return VisitFloat64Abs(node);
          case FloatUnaryOp::Kind::kNegate:
            return VisitFloat64Neg(node);
          case FloatUnaryOp::Kind::kSilenceNaN:
            return VisitFloat64SilenceNaN(node);
          case FloatUnaryOp::Kind::kRoundDown:
            return VisitFloat64RoundDown(node);
          case FloatUnaryOp::Kind::kRoundUp:
            return VisitFloat64RoundUp(node);
          case FloatUnaryOp::Kind::kRoundToZero:
            return VisitFloat64RoundTruncate(node);
          case FloatUnaryOp::Kind::kRoundTiesEven:
            return VisitFloat64RoundTiesEven(node);
          case FloatUnaryOp::Kind::kLog:
            return VisitFloat64Log(node);
          case FloatUnaryOp::Kind::kLog2:
            return VisitFloat64Log2(node);
          case FloatUnaryOp::Kind::kLog10:
            return VisitFloat64Log10(node);
          case FloatUnaryOp::Kind::kLog1p:
            return VisitFloat64Log1p(node);
          case FloatUnaryOp::Kind::kSqrt:
            return VisitFloat64Sqrt(node);
          case FloatUnaryOp::Kind::kCbrt:
            return VisitFloat64Cbrt(node);
          case FloatUnaryOp::Kind::kExp:
            return VisitFloat64Exp(node);
          case FloatUnaryOp::Kind::kExpm1:
            return VisitFloat64Expm1(node);
          case FloatUnaryOp::Kind::kSin:
            return VisitFloat64Sin(node);
          case FloatUnaryOp::Kind::kCos:
            return VisitFloat64Cos(node);
          case FloatUnaryOp::Kind::kSinh:
            return VisitFloat64Sinh(node);
          case FloatUnaryOp::Kind::kCosh:
            return VisitFloat64Cosh(node);
          case FloatUnaryOp::Kind::kAcos:
            return VisitFloat64Acos(node);
          case FloatUnaryOp::Kind::kAsin:
            return VisitFloat64Asin(node);
          case FloatUnaryOp::Kind::kAsinh:
            return VisitFloat64Asinh(node);
          case FloatUnaryOp::Kind::kAcosh:
            return VisitFloat64Acosh(node);
          case FloatUnaryOp::Kind::kTan:
            return VisitFloat64Tan(node);
          case FloatUnaryOp::Kind::kTanh:
            return VisitFloat64Tanh(node);
          case FloatUnaryOp::Kind::kAtan:
            return VisitFloat64Atan(node);
          case FloatUnaryOp::Kind::kAtanh:
            return VisitFloat64Atanh(node);
        }
      }
      UNREACHABLE();
    }
    case Opcode::kFloatBinop: {
      const auto& binop = op.Cast<FloatBinopOp>();
      if (binop.rep == Rep::Float32()) {
        MarkAsFloat32(node);
        switch (binop.kind) {
          case FloatBinopOp::Kind::kAdd:
            return VisitFloat32Add(node);
          case FloatBinopOp::Kind::kSub:
            return VisitFloat32Sub(node);
          case FloatBinopOp::Kind::kMul:
            return VisitFloat32Mul(node);
          case FloatBinopOp::Kind::kDiv:
            return VisitFloat32Div(node);
          case FloatBinopOp::Kind::kMin:
            return VisitFloat32Min(node);
          case FloatBinopOp::Kind::kMax:
            return VisitFloat32Max(node);
          case FloatBinopOp::Kind::kMod:
          case FloatBinopOp::Kind::kPower:
          case FloatBinopOp::Kind::kAtan2:
            UNREACHABLE();
        }
      } else {
        DCHECK_EQ(binop.rep, Rep::Float64());
        MarkAsFloat64(node);
        switch (binop.kind) {
          case FloatBinopOp::Kind::kAdd:
            return VisitFloat64Add(node);
          case FloatBinopOp::Kind::kSub:
            return VisitFloat64Sub(node);
          case FloatBinopOp::Kind::kMul:
            return VisitFloat64Mul(node);
          case FloatBinopOp::Kind::kDiv:
            return VisitFloat64Div(node);
          case FloatBinopOp::Kind::kMod:
            return VisitFloat64Mod(node);
          case FloatBinopOp::Kind::kMin:
            return VisitFloat64Min(node);
          case FloatBinopOp::Kind::kMax:
            return VisitFloat64Max(node);
          case FloatBinopOp::Kind::kPower:
            return VisitFloat64Pow(node);
          case FloatBinopOp::Kind::kAtan2:
            return VisitFloat64Atan2(node);
        }
      }
      UNREACHABLE();
    }
    case Opcode::kOverflowCheckedBinop: {
      const auto& binop = op.Cast<OverflowCheckedBinopOp>();
      if (binop.rep == WordRepresentation::Word32()) {
        MarkAsWord32(node);
        switch (binop.kind) {
          case OverflowCheckedBinopOp::Kind::kSignedAdd:
            return VisitInt32AddWithOverflow(node);
          case OverflowCheckedBinopOp::Kind::kSignedMul:
            return VisitInt32MulWithOverflow(node);
          case OverflowCheckedBinopOp::Kind::kSignedSub:
            return VisitInt32SubWithOverflow(node);
        }
      } else {
        DCHECK_EQ(binop.rep, WordRepresentation::Word64());
        MarkAsWord64(node);
        switch (binop.kind) {
          case OverflowCheckedBinopOp::Kind::kSignedAdd:
            return VisitInt64AddWithOverflow(node);
          case OverflowCheckedBinopOp::Kind::kSignedMul:
            return VisitInt64MulWithOverflow(node);
          case OverflowCheckedBinopOp::Kind::kSignedSub:
            return VisitInt64SubWithOverflow(node);
        }
      }
      UNREACHABLE();
    }
    case Opcode::kOverflowCheckedUnary: {
      const auto& unop = op.Cast<OverflowCheckedUnaryOp>();
      if (unop.rep == WordRepresentation::Word32()) {
        MarkAsWord32(node);
        switch (unop.kind) {
          case OverflowCheckedUnaryOp::Kind::kAbs:
            return VisitInt32AbsWithOverflow(node);
        }
      } else {
        DCHECK_EQ(unop.rep, WordRepresentation::Word64());
        MarkAsWord64(node);
        switch (unop.kind) {
          case OverflowCheckedUnaryOp::Kind::kAbs:
            return VisitInt64AbsWithOverflow(node);
        }
      }
      UNREACHABLE();
    }
    case Opcode::kShift: {
      const auto& shift = op.Cast<ShiftOp>();
      if (shift.rep == RegisterRepresentation::Word32()) {
        MarkAsWord32(node);
        switch (shift.kind) {
          case ShiftOp::Kind::kShiftRightArithmeticShiftOutZeros:
          case ShiftOp::Kind::kShiftRightArithmetic:
            return VisitWord32Sar(node);
          case ShiftOp::Kind::kShiftRightLogical:
            return VisitWord32Shr(node);
          case ShiftOp::Kind::kShiftLeft:
            return VisitWord32Shl(node);
          case ShiftOp::Kind::kRotateRight:
            return VisitWord32Ror(node);
          case ShiftOp::Kind::kRotateLeft:
            return VisitWord32Rol(node);
        }
      } else {
        DCHECK_EQ(shift.rep, RegisterRepresentation::Word64());
        MarkAsWord64(node);
        switch (shift.kind) {
          case ShiftOp::Kind::kShiftRightArithmeticShiftOutZeros:
          case ShiftOp::Kind::kShiftRightArithmetic:
            return VisitWord64Sar(node);
          case ShiftOp::Kind::kShiftRightLogical:
            return VisitWord64Shr(node);
          case ShiftOp::Kind::kShiftLeft:
            return VisitWord64Shl(node);
          case ShiftOp::Kind::kRotateRight:
            return VisitWord64Ror(node);
          case ShiftOp::Kind::kRotateLeft:
            return VisitWord64Rol(node);
        }
      }
      UNREACHABLE();
    }
    case Opcode::kCall:
      // Process the call at `DidntThrow`, when we know if exceptions are caught
      // or not.
      break;
    case Opcode::kDidntThrow:
      if (current_block_->begin() == node) {
        DCHECK_EQ(current_block_->PredecessorCount(), 1);
        DCHECK(current_block_->LastPredecessor()
                   ->LastOperation(*this->turboshaft_graph())
                   .Is<CheckExceptionOp>());
        // In this case, the Call has been generated at the `CheckException`
        // already.
      } else {
        VisitCall(op.Cast<DidntThrowOp>().throwing_operation());
      }
      EmitIdentity(node);
      break;
    case Opcode::kFrameConstant: {
      const auto& constant = op.Cast<turboshaft::FrameConstantOp>();
      using Kind = turboshaft::FrameConstantOp::Kind;
      OperandGenerator g(this);
      switch (constant.kind) {
        case Kind::kStackCheckOffset:
          Emit(kArchStackCheckOffset, g.DefineAsRegister(node));
          break;
        case Kind::kFramePointer:
          Emit(kArchFramePointer, g.DefineAsRegister(node));
          break;
        case Kind::kParentFramePointer:
          Emit(kArchParentFramePointer, g.DefineAsRegister(node));
          break;
      }
      break;
    }
    case Opcode::kStackPointerGreaterThan:
      return VisitStackPointerGreaterThan(node);
    case Opcode::kComparison: {
      const ComparisonOp& comparison = op.Cast<ComparisonOp>();
      using Kind = ComparisonOp::Kind;
      switch (multi(comparison.kind, comparison.rep)) {
        case multi(Kind::kEqual, Rep::Word32()):
          return VisitWord32Equal(node);
        case multi(Kind::kEqual, Rep::Word64()):
          return VisitWord64Equal(node);
        case multi(Kind::kEqual, Rep::Float32()):
          return VisitFloat32Equal(node);
        case multi(Kind::kEqual, Rep::Float64()):
          return VisitFloat64Equal(node);
        case multi(Kind::kEqual, Rep::Tagged()):
          if constexpr (Is64() && !COMPRESS_POINTERS_BOOL) {
            return VisitWord64Equal(node);
          }
          return VisitWord32Equal(node);
        case multi(Kind::kSignedLessThan, Rep::Word32()):
          return VisitInt32LessThan(node);
        case multi(Kind::kSignedLessThan, Rep::Word64()):
          return VisitInt64LessThan(node);
        case multi(Kind::kSignedLessThan, Rep::Float32()):
          return VisitFloat32LessThan(node);
        case multi(Kind::kSignedLessThan, Rep::Float64()):
          return VisitFloat64LessThan(node);
        case multi(Kind::kSignedLessThanOrEqual, Rep::Word32()):
          return VisitInt32LessThanOrEqual(node);
        case multi(Kind::kSignedLessThanOrEqual, Rep::Word64()):
          return VisitInt64LessThanOrEqual(node);
        case multi(Kind::kSignedLessThanOrEqual, Rep::Float32()):
          return VisitFloat32LessThanOrEqual(node);
        case multi(Kind::kSignedLessThanOrEqual, Rep::Float64()):
          return VisitFloat64LessThanOrEqual(node);
        case multi(Kind::kUnsignedLessThan, Rep::Word32()):
          return VisitUint32LessThan(node);
        case multi(Kind::kUnsignedLessThan, Rep::Word64()):
          return VisitUint64LessThan(node);
        case multi(Kind::kUnsignedLessThanOrEqual, Rep::Word32()):
          return VisitUint32LessThanOrEqual(node);
        case multi(Kind::kUnsignedLessThanOrEqual, Rep::Word64()):
          return VisitUint64LessThanOrEqual(node);
        default:
          UNREACHABLE();
      }
      UNREACHABLE();
    }
    case Opcode::kLoad: {
      const LoadOp& load = op.Cast<LoadOp>();
      MachineType loaded_type = load.machine_type();
      MarkAsRepresentation(loaded_type.representation(), node);
      if (load.kind.maybe_unaligned) {
        DCHECK(!load.kind.with_trap_handler);
        if (loaded_type.representation() == MachineRepresentation::kWord8 ||
            InstructionSelector::AlignmentRequirements()
                .IsUnalignedLoadSupported(loaded_type.representation())) {
          return VisitLoad(node);
        } else {
          return VisitUnalignedLoad(node);
        }
      } else if (load.kind.is_atomic) {
        if (load.result_rep == Rep::Word32()) {
          return VisitWord32AtomicLoad(node);
        } else {
          DCHECK_EQ(load.result_rep, Rep::Word64());
          return VisitWord64AtomicLoad(node);
        }
      } else if (load.kind.with_trap_handler) {
        DCHECK(!load.kind.maybe_unaligned);
        return VisitProtectedLoad(node);
      } else {
        return VisitLoad(node);
      }
      UNREACHABLE();
    }
    case Opcode::kStore: {
      const StoreOp& store = op.Cast<StoreOp>();
      MachineRepresentation rep =
          store.stored_rep.ToMachineType().representation();
      if (store.kind.maybe_unaligned) {
        DCHECK(!store.kind.with_trap_handler);
        DCHECK_EQ(store.write_barrier, WriteBarrierKind::kNoWriteBarrier);
        if (rep == MachineRepresentation::kWord8 ||
            InstructionSelector::AlignmentRequirements()
                .IsUnalignedStoreSupported(rep)) {
          return VisitStore(node);
        } else {
          return VisitUnalignedStore(node);
        }
      } else if (store.kind.is_atomic) {
        if (store.stored_rep == MemoryRepresentation::Int64() ||
            store.stored_rep == MemoryRepresentation::Uint64()) {
          return VisitWord64AtomicStore(node);
        } else {
          return VisitWord32AtomicStore(node);
        }
      } else if (store.kind.with_trap_handler) {
        DCHECK(!store.kind.maybe_unaligned);
        return VisitProtectedStore(node);
      } else {
        return VisitStore(node);
      }
      UNREACHABLE();
    }
    case Opcode::kTaggedBitcast: {
      const TaggedBitcastOp& cast = op.Cast<TaggedBitcastOp>();
      switch (multi(cast.from, cast.to)) {
        case multi(Rep::Tagged(), Rep::Word32()):
          MarkAsWord32(node);
          if constexpr (Is64()) {
            DCHECK_EQ(cast.kind, TaggedBitcastOp::Kind::kSmi);
            DCHECK(SmiValuesAre31Bits());
            return VisitBitcastSmiToWord(node);
          } else {
            return VisitBitcastTaggedToWord(node);
          }
        case multi(Rep::Tagged(), Rep::Word64()):
          MarkAsWord64(node);
          return VisitBitcastTaggedToWord(node);
        case multi(Rep::Word32(), Rep::Tagged()):
        case multi(Rep::Word64(), Rep::Tagged()):
          if (cast.kind == TaggedBitcastOp::Kind::kSmi) {
            MarkAsRepresentation(MachineRepresentation::kTaggedSigned, node);
            return EmitIdentity(node);
          } else {
            MarkAsTagged(node);
            return VisitBitcastWordToTagged(node);
          }
        case multi(Rep::Compressed(), Rep::Word32()):
          MarkAsWord32(node);
          if (cast.kind == TaggedBitcastOp::Kind::kSmi) {
            return VisitBitcastSmiToWord(node);
          } else {
            return VisitBitcastTaggedToWord(node);
          }
        default:
          UNIMPLEMENTED();
      }
    }
    case Opcode::kPhi:
      MarkAsRepresentation(op.Cast<PhiOp>().rep, node);
      return VisitPhi(node);
    case Opcode::kProjection:
      return VisitProjection(node);
    case Opcode::kDeoptimizeIf:
      if (Get(node).Cast<DeoptimizeIfOp>().negated) {
        return VisitDeoptimizeUnless(node);
      }
      return VisitDeoptimizeIf(node);
#if V8_ENABLE_WEBASSEMBLY
    case Opcode::kTrapIf: {
      const TrapIfOp& trap_if = op.Cast<TrapIfOp>();
      if (trap_if.negated) {
        return VisitTrapUnless(node, trap_if.trap_id);
      }
      return VisitTrapIf(node, trap_if.trap_id);
    }
#endif  // V8_ENABLE_WEBASSEMBLY
    case Opcode::kCatchBlockBegin:
      MarkAsTagged(node);
      return VisitIfException(node);
    case Opcode::kRetain:
      return VisitRetain(node);
    case Opcode::kOsrValue:
      MarkAsTagged(node);
      return VisitOsrValue(node);
    case Opcode::kStackSlot:
      return VisitStackSlot(node);
    case Opcode::kFrameState:
      // FrameState is covered as part of calls.
      UNREACHABLE();
    case Opcode::kLoadRootRegister:
      return VisitLoadRootRegister(node);
    case Opcode::kAssumeMap:
      // AssumeMap is used as a hint for optimization phases but does not
      // produce any code.
      return;
    case Opcode::kDebugBreak:
      return VisitDebugBreak(node);
    case Opcode::kAbortCSADcheck:
      return VisitAbortCSADcheck(node);
    case Opcode::kSelect: {
      const SelectOp& select = op.Cast<SelectOp>();
      // If there is a Select, then it should only be one that is supported by
      // the machine, and it should be meant to be implementation with cmove.
      DCHECK_EQ(select.implem, SelectOp::Implementation::kCMove);
      MarkAsRepresentation(select.rep, node);
      return VisitSelect(node);
    }
    case Opcode::kWord32PairBinop: {
      const Word32PairBinopOp& binop = op.Cast<Word32PairBinopOp>();
      MarkAsWord32(node);
      MarkPairProjectionsAsWord32(node);
      switch (binop.kind) {
        case Word32PairBinopOp::Kind::kAdd:
          return VisitInt32PairAdd(node);
        case Word32PairBinopOp::Kind::kSub:
          return VisitInt32PairSub(node);
        case Word32PairBinopOp::Kind::kMul:
          return VisitInt32PairMul(node);
        case Word32PairBinopOp::Kind::kShiftLeft:
          return VisitWord32PairShl(node);
        case Word32PairBinopOp::Kind::kShiftRightLogical:
          return VisitWord32PairShr(node);
        case Word32PairBinopOp::Kind::kShiftRightArithmetic:
          return VisitWord32PairSar(node);
      }
      UNREACHABLE();
    }
    case Opcode::kAtomicWord32Pair: {
      const AtomicWord32PairOp& atomic_op = op.Cast<AtomicWord32PairOp>();
      if (atomic_op.kind != AtomicWord32PairOp::Kind::kStore) {
        MarkAsWord32(node);
        MarkPairProjectionsAsWord32(node);
      }
      switch (atomic_op.kind) {
        case AtomicWord32PairOp::Kind::kAdd:
          return VisitWord32AtomicPairAdd(node);
        case AtomicWord32PairOp::Kind::kAnd:
          return VisitWord32AtomicPairAnd(node);
        case AtomicWord32PairOp::Kind::kCompareExchange:
          return VisitWord32AtomicPairCompareExchange(node);
        case AtomicWord32PairOp::Kind::kExchange:
          return VisitWord32AtomicPairExchange(node);
        case AtomicWord32PairOp::Kind::kLoad:
          return VisitWord32AtomicPairLoad(node);
        case AtomicWord32PairOp::Kind::kOr:
          return VisitWord32AtomicPairOr(node);
        case AtomicWord32PairOp::Kind::kSub:
          return VisitWord32AtomicPairSub(node);
        case AtomicWord32PairOp::Kind::kXor:
          return VisitWord32AtomicPairXor(node);
        case AtomicWord32PairOp::Kind::kStore:
          return VisitWord32AtomicPairStore(node);
      }
    }
    case Opcode::kBitcastWord32PairToFloat64:
      return MarkAsFloat64(node), VisitBitcastWord32PairToFloat64(node);
    case Opcode::kAtomicRMW: {
      const AtomicRMWOp& atomic_op = op.Cast<AtomicRMWOp>();
      MarkAsRepresentation(atomic_op.memory_rep.ToRegisterRepresentation(),
                           node);
      if (atomic_op.in_out_rep == Rep::Word32()) {
        switch (atomic_op.bin_op) {
          case AtomicRMWOp::BinOp::kAdd:
            return VisitWord32AtomicAdd(node);
          case AtomicRMWOp::BinOp::kSub:
            return VisitWord32AtomicSub(node);
          case AtomicRMWOp::BinOp::kAnd:
            return VisitWord32AtomicAnd(node);
          case AtomicRMWOp::BinOp::kOr:
            return VisitWord32AtomicOr(node);
          case AtomicRMWOp::BinOp::kXor:
            return VisitWord32AtomicXor(node);
          case AtomicRMWOp::BinOp::kExchange:
            return VisitWord32AtomicExchange(node);
          case AtomicRMWOp::BinOp::kCompareExchange:
            return VisitWord32AtomicCompareExchange(node);
        }
      } else {
        DCHECK_EQ(atomic_op.in_out_rep, Rep::Word64());
        switch (atomic_op.bin_op) {
          case AtomicRMWOp::BinOp::kAdd:
            return VisitWord64AtomicAdd(node);
          case AtomicRMWOp::BinOp::kSub:
            return VisitWord64AtomicSub(node);
          case AtomicRMWOp::BinOp::kAnd:
            return VisitWord64AtomicAnd(node);
          case AtomicRMWOp::BinOp::kOr:
            return VisitWord64AtomicOr(node);
          case AtomicRMWOp::BinOp::kXor:
            return VisitWord64AtomicXor(node);
          case AtomicRMWOp::BinOp::kExchange:
            return VisitWord64AtomicExchange(node);
          case AtomicRMWOp::BinOp::kCompareExchange:
            return VisitWord64AtomicCompareExchange(node);
        }
      }
      UNREACHABLE();
    }
    case Opcode::kMemoryBarrier:
      return VisitMemoryBarrier(node);

    case Opcode::kComment:
      return VisitComment(node);

#ifdef V8_ENABLE_WEBASSEMBLY
    case Opcode::kSimd128Constant: {
      const Simd128ConstantOp& constant = op.Cast<Simd128ConstantOp>();
      MarkAsSimd128(node);
      if (constant.IsZero()) return VisitS128Zero(node);
      return VisitS128Const(node);
    }
    case Opcode::kSimd128Unary: {
      const Simd128UnaryOp& unary = op.Cast<Simd128UnaryOp>();
      MarkAsSimd128(node);
      switch (unary.kind) {
#define VISIT_SIMD_UNARY(kind)        \
  case Simd128UnaryOp::Kind::k##kind: \
    return Visit##kind(node);
        FOREACH_SIMD_128_UNARY_OPCODE(VISIT_SIMD_UNARY)
#undef VISIT_SIMD_UNARY
      }
    }
    case Opcode::kSimd128Reduce: {
      const Simd128ReduceOp& reduce = op.Cast<Simd128ReduceOp>();
      MarkAsSimd128(node);
      switch (reduce.kind) {
        case Simd128ReduceOp::Kind::kI8x16AddReduce:
          return VisitI8x16AddReduce(node);
        case Simd128ReduceOp::Kind::kI16x8AddReduce:
          return VisitI16x8AddReduce(node);
        case Simd128ReduceOp::Kind::kI32x4AddReduce:
          return VisitI32x4AddReduce(node);
        case Simd128ReduceOp::Kind::kI64x2AddReduce:
          return VisitI64x2AddReduce(node);
        case Simd128ReduceOp::Kind::kF32x4AddReduce:
          return VisitF32x4AddReduce(node);
        case Simd128ReduceOp::Kind::kF64x2AddReduce:
          return VisitF64x2AddReduce(node);
      }
    }
    case Opcode::kSimd128Binop: {
      const Simd128BinopOp& binop = op.Cast<Simd128BinopOp>();
      MarkAsSimd128(node);
      switch (binop.kind) {
#define VISIT_SIMD_BINOP(kind)        \
  case Simd128BinopOp::Kind::k##kind: \
    return Visit##kind(node);
        FOREACH_SIMD_128_BINARY_OPCODE(VISIT_SIMD_BINOP)
#undef VISIT_SIMD_BINOP
      }
    }
    case Opcode::kSimd128Shift: {
      const Simd128ShiftOp& shift = op.Cast<Simd128ShiftOp>();
      MarkAsSimd128(node);
      switch (shift.kind) {
#define VISIT_SIMD_SHIFT(kind)        \
  case Simd128ShiftOp::Kind::k##kind: \
    return Visit##kind(node);
        FOREACH_SIMD_128_SHIFT_OPCODE(VISIT_SIMD_SHIFT)
#undef VISIT_SIMD_SHIFT
      }
    }
    case Opcode::kSimd128Test: {
      const Simd128TestOp& test = op.Cast<Simd128TestOp>();
      MarkAsWord32(node);
      switch (test.kind) {
#define VISIT_SIMD_TEST(kind)        \
  case Simd128TestOp::Kind::k##kind: \
    return Visit##kind(node);
        FOREACH_SIMD_128_TEST_OPCODE(VISIT_SIMD_TEST)
#undef VISIT_SIMD_TEST
      }
    }
    case Opcode::kSimd128Splat: {
      const Simd128SplatOp& splat = op.Cast<Simd128SplatOp>();
      MarkAsSimd128(node);
      switch (splat.kind) {
#define VISIT_SIMD_SPLAT(kind)        \
  case Simd128SplatOp::Kind::k##kind: \
    return Visit##kind##Splat(node);
        FOREACH_SIMD_128_SPLAT_OPCODE(VISIT_SIMD_SPLAT)
#undef VISIT_SIMD_SPLAT
      }
    }
    case Opcode::kSimd128Shuffle:
      MarkAsSimd128(node);
      return VisitI8x16Shuffle(node);
    case Opcode::kSimd128ReplaceLane: {
      const Simd128ReplaceLaneOp& replace = op.Cast<Simd128ReplaceLaneOp>();
      MarkAsSimd128(node);
      switch (replace.kind) {
        case Simd128ReplaceLaneOp::Kind::kI8x16:
          return VisitI8x16ReplaceLane(node);
        case Simd128ReplaceLaneOp::Kind::kI16x8:
          return VisitI16x8ReplaceLane(node);
        case Simd128ReplaceLaneOp::Kind::kI32x4:
          return VisitI32x4ReplaceLane(node);
        case Simd128ReplaceLaneOp::Kind::kI64x2:
          return VisitI64x2ReplaceLane(node);
        case Simd128ReplaceLaneOp::Kind::kF16x8:
          return VisitF16x8ReplaceLane(node);
        case Simd128ReplaceLaneOp::Kind::kF32x4:
          return VisitF32x4ReplaceLane(node);
        case Simd128ReplaceLaneOp::Kind::kF64x2:
          return VisitF64x2ReplaceLane(node);
      }
    }
    case Opcode::kSimd128ExtractLane: {
      const Simd128ExtractLaneOp& extract = op.Cast<Simd128ExtractLaneOp>();
      switch (extract.kind) {
        case Simd128ExtractLaneOp::Kind::kI8x16S:
          MarkAsWord32(node);
          return VisitI8x16ExtractLaneS(node);
        case Simd128ExtractLaneOp::Kind::kI8x16U:
          MarkAsWord32(node);
          return VisitI8x16ExtractLaneU(node);
        case Simd128ExtractLaneOp::Kind::kI16x8S:
          MarkAsWord32(node);
          return VisitI16x8ExtractLaneS(node);
        case Simd128ExtractLaneOp::Kind::kI16x8U:
          MarkAsWord32(node);
          return VisitI16x8ExtractLaneU(node);
        case Simd128ExtractLaneOp::Kind::kI32x4:
          MarkAsWord32(node);
          return VisitI32x4ExtractLane(node);
        case Simd128ExtractLaneOp::Kind::kI64x2:
          MarkAsWord64(node);
          return VisitI64x2ExtractLane(node);
        case Simd128ExtractLaneOp::Kind::kF16x8:
          MarkAsFloat32(node);
          return VisitF16x8ExtractLane(node);
        case Simd128ExtractLaneOp::Kind::kF32x4:
          MarkAsFloat32(node);
          return VisitF32x4ExtractLane(node);
        case Simd128ExtractLaneOp::Kind::kF64x2:
          MarkAsFloat64(node);
          return VisitF64x2ExtractLane(node);
      }
    }
    case Opcode::kSimd128LoadTransform:
      MarkAsSimd128(node);
      return VisitLoadTransform(node);
    case Opcode::kSimd128LaneMemory: {
      const Simd128LaneMemoryOp& memory = op.Cast<Simd128LaneMemoryOp>();
      MarkAsSimd128(node);
      if (memory.mode == Simd128LaneMemoryOp::Mode::kLoad) {
        return VisitLoadLane(node);
      } else {
        DCHECK_EQ(memory.mode, Simd128LaneMemoryOp::Mode::kStore);
        return VisitStoreLane(node);
      }
    }
    case Opcode::kSimd128Ternary: {
      const Simd128TernaryOp& ternary = op.Cast<Simd128TernaryOp>();
      MarkAsSimd128(node);
      switch (ternary.kind) {
#define VISIT_SIMD_TERNARY(kind)        \
  case Simd128TernaryOp::Kind::k##kind: \
    return Visit##kind(node);
        FOREACH_SIMD_128_TERNARY_OPCODE(VISIT_SIMD_TERNARY)
#undef VISIT_SIMD_TERNARY
      }
    }

    // SIMD256
#if V8_ENABLE_WASM_SIMD256_REVEC
    case Opcode::kSimd256Constant: {
      const Simd256ConstantOp& constant = op.Cast<Simd256ConstantOp>();
      MarkAsSimd256(node);
      if (constant.IsZero()) return VisitS256Zero(node);
      return VisitS256Const(node);
    }
    case Opcode::kSimd256Extract128Lane: {
      MarkAsSimd128(node);
      return VisitExtractF128(node);
    }
    case Opcode::kSimd256LoadTransform: {
      MarkAsSimd256(node);
      return VisitSimd256LoadTransform(node);
    }
    case Opcode::kSimd256Unary: {
      const Simd256UnaryOp& unary = op.Cast<Simd256UnaryOp>();
      MarkAsSimd256(node);
      switch (unary.kind) {
#define VISIT_SIMD_256_UNARY(kind)    \
  case Simd256UnaryOp::Kind::k##kind: \
    return Visit##kind(node);
        FOREACH_SIMD_256_UNARY_OPCODE(VISIT_SIMD_256_UNARY)
#undef VISIT_SIMD_256_UNARY
      }
    }
    case Opcode::kSimd256Binop: {
      const Simd256BinopOp& binop = op.Cast<Simd256BinopOp>();
      MarkAsSimd256(node);
      switch (binop.kind) {
#define VISIT_SIMD_BINOP(kind)        \
  case Simd256BinopOp::Kind::k##kind: \
    return Visit##kind(node);
        FOREACH_SIMD_256_BINARY_OPCODE(VISIT_SIMD_BINOP)
#undef VISIT_SIMD_BINOP
      }
    }
    case Opcode::kSimd256Shift: {
      const Simd256ShiftOp& shift = op.Cast<Simd256ShiftOp>();
      MarkAsSimd256(node);
      switch (shift.kind) {
#define VISIT_SIMD_SHIFT(kind)        \
  case Simd256ShiftOp::Kind::k##kind: \
    return Visit##kind(node);
        FOREACH_SIMD_256_SHIFT_OPCODE(VISIT_SIMD_SHIFT)
#undef VISIT_SIMD_SHIFT
      }
    }
    case Opcode::kSimd256Ternary: {
      const Simd256TernaryOp& ternary = op.Cast<Simd256TernaryOp>();
      MarkAsSimd256(node);
      switch (ternary.kind) {
#define VISIT_SIMD_256_TERNARY(kind)    \
  case Simd256TernaryOp::Kind::k##kind: \
    return Visit##kind(node);
        FOREACH_SIMD_256_TERNARY_OPCODE(VISIT_SIMD_256_TERNARY)
#undef VISIT_SIMD_256_UNARY
      }
    }
    case Opcode::kSimd256Splat: {
      const Simd256SplatOp& splat = op.Cast<Simd256SplatOp>();
      MarkAsSimd256(node);
      switch (splat.kind) {
#define VISIT_SIMD_SPLAT(kind)        \
  case Simd256SplatOp::Kind::k##kind: \
    return Visit##kind##Splat(node);
        FOREACH_SIMD_256_SPLAT_OPCODE(VISIT_SIMD_SPLAT)
#undef VISIT_SIMD_SPLAT
      }
    }
#ifdef V8_TARGET_ARCH_X64
    case Opcode::kSimd256Shufd: {
      MarkAsSimd256(node);
      return VisitSimd256Shufd(node);
    }
    case Opcode::kSimd256Shufps: {
      MarkAsSimd256(node);
      return VisitSimd256Shufps(node);
    }
    case Opcode::kSimd256Unpack: {
      MarkAsSimd256(node);
      return VisitSimd256Unpack(node);
    }
    case Opcode::kSimdPack128To256: {
      MarkAsSimd256(node);
      return VisitSimdPack128To256(node);
    }
#endif  // V8_TARGET_ARCH_X64
#endif  // V8_ENABLE_WASM_SIMD256_REVEC

    case Opcode::kLoadStackPointer:
      return VisitLoadStackPointer(node);

    case Opcode::kSetStackPointer:
      return VisitSetStackPointer(node);

#endif  // V8_ENABLE_WEBASSEMBLY

#define UNREACHABLE_CASE(op) case Opcode::k##op:
      TURBOSHAFT_JS_OPERATION_LIST(UNREACHABLE_CASE)
      TURBOSHAFT_SIMPLIFIED_OPERATION_LIST(UNREACHABLE_CASE)
      TURBOSHAFT_WASM_OPERATION_LIST(UNREACHABLE_CASE)
      TURBOSHAFT_OTHER_OPERATION_LIST(UNREACHABLE_CASE)
      UNREACHABLE_CASE(PendingLoopPhi)
      UNREACHABLE_CASE(Tuple)
      UNREACHABLE_CASE(Dead)
      UNREACHABLE();
#undef UNREACHABLE_CASE
  }
}

template <typename Adapter>
bool InstructionSelectorT<Adapter>::CanProduceSignalingNaN(Node* node) {
  // TODO(jarin) Improve the heuristic here.
  if (node->opcode() == IrOpcode::kFloat64Add ||
      node->opcode() == IrOpcode::kFloat64Sub ||
      node->opcode() == IrOpcode::kFloat64Mul) {
    return false;
  }
  return true;
}

#if V8_TARGET_ARCH_64_BIT
template <typename Adapter>
bool InstructionSelectorT<Adapter>::ZeroExtendsWord32ToWord64(
    node_t node, int recursion_depth) {
  // To compute whether a Node sets its upper 32 bits to zero, there are three
  // cases.
  // 1. Phi node, with a computed result already available in phi_states_:
  //    Read the value from phi_states_.
  // 2. Phi node, with no result available in phi_states_ yet:
  //    Recursively check its inputs, and store the result in phi_states_.
  // 3. Anything else:
  //    Call the architecture-specific ZeroExtendsWord32ToWord64NoPhis.

  // Limit recursion depth to avoid the possibility of stack overflow on very
  // large functions.
  const int kMaxRecursionDepth = 100;

  if (this->IsPhi(node)) {
    if (recursion_depth == 0) {
      if (phi_states_.empty()) {
        // This vector is lazily allocated because the majority of compilations
        // never use it.
        phi_states_ = ZoneVector<Upper32BitsState>(
            node_count_, Upper32BitsState::kNotYetChecked, zone());
      }
    }

    Upper32BitsState current = phi_states_[this->id(node)];
    if (current != Upper32BitsState::kNotYetChecked) {
      return current == Upper32BitsState::kZero;
    }

    // If further recursion is prevented, we can't make any assumptions about
    // the output of this phi node.
    if (recursion_depth >= kMaxRecursionDepth) {
      return false;
    }

    // Optimistically mark the current node as zero-extended so that we skip it
    // if we recursively visit it again due to a cycle. If this optimistic guess
    // is wrong, it will be corrected in MarkNodeAsNotZeroExtended.
    phi_states_[this->id(node)] = Upper32BitsState::kZero;

    int input_count = this->value_input_count(node);
    for (int i = 0; i < input_count; ++i) {
      node_t input = this->input_at(node, i);
      if (!ZeroExtendsWord32ToWord64(input, recursion_depth + 1)) {
        MarkNodeAsNotZeroExtended(node);
        return false;
      }
    }

    return true;
  }
  return ZeroExtendsWord32ToWord64NoPhis(node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::MarkNodeAsNotZeroExtended(node_t node) {
  if (phi_states_[this->id(node)] == Upper32BitsState::kMayBeNonZero) return;
  phi_states_[this->id(node)] = Upper32BitsState::kMayBeNonZero;
  ZoneVector<node_t> worklist(zone_);
  worklist.push_back(node);
  while (!worklist.empty()) {
    node = worklist.back();
    worklist.pop_back();
    // We may have previously marked some uses of this node as zero-extended,
    // but that optimistic guess was proven incorrect.
    if constexpr (Adapter::IsTurboshaft) {
      for (turboshaft::OpIndex use : turboshaft_uses(node)) {
        if (phi_states_[this->id(use)] == Upper32BitsState::kZero) {
          phi_states_[this->id(use)] = Upper32BitsState::kMayBeNonZero;
          worklist.push_back(use);
        }
      }
    } else {
      for (Edge edge : node->use_edges()) {
        Node* use = edge.from();
        if (phi_states_[this->id(use)] == Upper32BitsState::kZero) {
          phi_states_[this->id(use)] = Upper32BitsState::kMayBeNonZero;
          worklist.push_back(use);
        }
      }
    }
  }
}
#endif  // V8_TARGET_ARCH_64_BIT

namespace {

FrameStateDescriptor* GetFrameStateDescriptorInternal(
    Zone* zone, turboshaft::Graph* graph,
    const turboshaft::FrameStateOp& state) {
  const FrameStateInfo& state_info = state.data->frame_state_info;
  uint16_t parameters = state_info.parameter_count();
  uint16_t max_arguments = state_info.max_arguments();
  int locals = state_info.local_count();
  int stack = state_info.stack_count();

  FrameStateDescriptor* outer_state = nullptr;
  if (state.inlined) {
    outer_state = GetFrameStateDescriptorInternal(
        zone, graph,
        graph->Get(state.parent_frame_state())
            .template Cast<turboshaft::FrameStateOp>());
  }

#if V8_ENABLE_WEBASSEMBLY
  if (state_info.type() == FrameStateType::kJSToWasmBuiltinContinuation) {
    auto function_info = static_cast<const JSToWasmFrameStateFunctionInfo*>(
        state_info.function_info());
    return zone->New<JSToWasmFrameStateDescriptor>(
        zone, state_info.type(), state_info.bailout_id(),
        state_info.state_combine(), parameters, locals, stack,
        state_info.shared_info(), outer_state, function_info->signature());
  }
#endif  // V8_ENABLE_WEBASSEMBLY

  return zone->New<FrameStateDescriptor>(
      zone, state_info.type(), state_info.bailout_id(),
      state_info.state_combine(), parameters, max_arguments, locals, stack,
      state_info.shared_info(), state_info.bytecode_array(), outer_state,
      state_info.function_info()->wasm_liftoff_frame_size(),
      state_info.function_info()->wasm_function_index());
}

FrameStateDescriptor* GetFrameStateDescriptorInternal(Zone* zone,
                                                      FrameState state) {
  DCHECK_EQ(IrOpcode::kFrameState, state->opcode());
  DCHECK_EQ(FrameState::kFrameStateInputCount, state->InputCount());
  const FrameStateInfo& state_info = FrameStateInfoOf(state->op());
  uint16_t parameters = state_info.parameter_count();
  uint16_t max_arguments = state_info.max_arguments();
  int locals = state_info.local_count();
  int stack = state_info.stack_count();

  FrameStateDescriptor* outer_state = nullptr;
  if (state.outer_frame_state()->opcode() == IrOpcode::kFrameState) {
    outer_state = GetFrameStateDescriptorInternal(
        zone, FrameState{state.outer_frame_state()});
  }

#if V8_ENABLE_WEBASSEMBLY
  if (state_info.type() == FrameStateType::kJSToWasmBuiltinContinuation) {
    auto function_info = static_cast<const JSToWasmFrameStateFunctionInfo*>(
        state_info.function_info());
    return zone->New<JSToWasmFrameStateDescriptor>(
        zone, state_info.type(), state_info.bailout_id(),
        state_info.state_combine(), parameters, locals, stack,
        state_info.shared_info(), outer_state, function_info->signature());
  }
#endif  // V8_ENABLE_WEBASSEMBLY

  return zone->New<FrameStateDescriptor>(
      zone, state_info.type(), state_info.bailout_id(),
      state_info.state_combine(), parameters, max_arguments, locals, stack,
      state_info.shared_info(), state_info.bytecode_array(), outer_state,
      state_info.function_info()->wasm_liftoff_frame_size(),
      state_info.function_info()->wasm_function_index());
}

}  // namespace

template <>
FrameStateDescriptor*
InstructionSelectorT<TurboshaftAdapter>::GetFrameStateDescriptor(node_t node) {
  const turboshaft::FrameStateOp& state =
      this->turboshaft_graph()
          ->Get(node)
          .template Cast<turboshaft::FrameStateOp>();
  auto* desc = GetFrameStateDescriptorInternal(instruction_zone(),
                                               this->turboshaft_graph(), state);
  *max_unoptimized_frame_height_ =
      std::max(*max_unoptimized_frame_height_,
               desc->total_conservative_frame_size_in_bytes() +
                   (desc->max_arguments() * kSystemPointerSize));
  return desc;
}

template <>
FrameStateDescriptor*
InstructionSelectorT<TurbofanAdapter>::GetFrameStateDescriptor(node_t node) {
  FrameState state{node};
  auto* desc = GetFrameStateDescriptorInternal(instruction_zone(), state);
  *max_unoptimized_frame_height_ =
      std::max(*max_unoptimized_frame_height_,
               desc->total_conservative_frame_size_in_bytes() +
                   (desc->max_arguments() * kSystemPointerSize));
  return desc;
}

#if V8_ENABLE_WEBASSEMBLY
// static
template <typename Adapter>
void InstructionSelectorT<Adapter>::SwapShuffleInputs(
    typename Adapter::SimdShuffleView& view) {
  view.SwapInputs();
}
#endif  // V8_ENABLE_WEBASSEMBLY

template class InstructionSelectorT<TurbofanAdapter>;
template class InstructionSelectorT<TurboshaftAdapter>;

// static
InstructionSelector InstructionSelector::ForTurbofan(
    Zone* zone, size_t node_count, Linkage* linkage,
    InstructionSequence* sequence, Schedule* schedule,
    SourcePositionTable* source_positions, Frame* frame,
    EnableSwitchJumpTable enable_switch_jump_table, TickCounter* tick_counter,
    JSHeapBroker* broker, size_t* max_unoptimized_frame_height,
    size_t* max_pushed_argument_count, SourcePositionMode source_position_mode,
    Features features, EnableScheduling enable_scheduling,
    EnableRootsRelativeAddressing enable_roots_relative_addressing,
    EnableTraceTurboJson trace_turbo) {
  return InstructionSelector(
      new InstructionSelectorT<TurbofanAdapter>(
          zone, node_count, linkage, sequence, schedule, source_positions,
          frame, enable_switch_jump_table, tick_counter, broker,
          max_unoptimized_frame_height, max_pushed_argument_count,
          source_position_mode, features, enable_scheduling,
          enable_roots_relative_addressing, trace_turbo),
      nullptr);
}

InstructionSelector InstructionSelector::ForTurboshaft(
    Zone* zone, size_t node_count, Linkage* linkage,
    InstructionSequence* sequence, turboshaft::Graph* graph, Frame* frame,
    EnableSwitchJumpTable enable_switch_jump_table, TickCounter* tick_counter,
    JSHeapBroker* broker, size_t* max_unoptimized_frame_height,
    size_t* max_pushed_argument_count, SourcePositionMode source_position_mode,
    Features features, EnableScheduling enable_scheduling,
    EnableRootsRelativeAddressing enable_roots_relative_addressing,
    EnableTraceTurboJson trace_turbo) {
  return InstructionSelector(
      nullptr,
      new InstructionSelectorT<TurboshaftAdapter>(
          zone, node_count, linkage, sequence, graph,
          &graph->source_positions(), frame, enable_switch_jump_table,
          tick_counter, broker, max_unoptimized_frame_height,
          max_pushed_argument_count, source_position_mode, features,
          enable_scheduling, enable_roots_relative_addressing, trace_turbo));
}

InstructionSelector::InstructionSelector(
    InstructionSelectorT<TurbofanAdapter>* turbofan_impl,
    InstructionSelectorT<TurboshaftAdapter>* turboshaft_impl)
    : turbofan_impl_(turbofan_impl), turboshaft_impl_(turboshaft_impl) {
  DCHECK_NE(!turbofan_impl_, !turboshaft_impl_);
}

InstructionSelector::~InstructionSelector() {
  DCHECK_NE(!turbofan_impl_, !turboshaft_impl_);
  delete turbofan_impl_;
  delete turboshaft_impl_;
}

#define DISPATCH_TO_IMPL(...)                    \
  DCHECK_NE(!turbofan_impl_, !turboshaft_impl_); \
  if (turbofan_impl_) {                          \
    return turbofan_impl_->__VA_ARGS__;          \
  } else {                                       \
    return turboshaft_impl_->__VA_ARGS__;        \
  }

std::optional<BailoutReason> InstructionSelector::SelectInstructions() {
  DISPATCH_TO_IMPL(SelectInstructions())
}

bool InstructionSelector::IsSupported(CpuFeature feature) const {
  DISPATCH_TO_IMPL(IsSupported(feature))
}

const ZoneVector<std::pair<int, int>>& InstructionSelector::instr_origins()
    const {
  DISPATCH_TO_IMPL(instr_origins())
}

const std::map<NodeId, int> InstructionSelector::GetVirtualRegistersForTesting()
    const {
  DISPATCH_TO_IMPL(GetVirtualRegistersForTesting());
}

#undef DISPATCH_TO_IMPL
#undef VISIT_UNSUPPORTED_OP

}  // namespace compiler
}  // namespace internal
}  // namespace v8

"""


```