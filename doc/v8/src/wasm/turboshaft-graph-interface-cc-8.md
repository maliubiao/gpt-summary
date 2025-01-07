Response:
The user wants a summary of the C++ code provided, specifically focusing on its role in the V8 JavaScript engine's WebAssembly (Wasm) compilation pipeline. I need to identify the core functionalities implemented in `turboshaft-graph-interface.cc`.

Here's a breakdown of the thought process to achieve the desired summary:

1. **Identify the file's purpose:** The filename `turboshaft-graph-interface.cc` strongly suggests this code is responsible for interfacing with a "turboshaft graph."  Turboshaft is V8's next-generation Wasm compiler. The "graph interface" likely means it translates Wasm operations into the intermediate representation (IR) used by Turboshaft.

2. **Scan for key data structures and functions:**  Looking at the code, I see functions like `UnOpImpl` and `BinOpImpl`. These clearly handle WebAssembly unary and binary operations. The `switch` statements within these functions, operating on `WasmOpcode`, confirm this.

3. **Analyze the operations handled:** The `switch` cases in `UnOpImpl` and `BinOpImpl` cover a wide range of Wasm instructions:
    * **Conversions:**  `kExprI32ConvertF32`, `kExprF64SConvertI32`, etc. These handle conversions between different numerical types (integers and floats of various sizes). The "Sat" versions (e.g., `kExprI32SConvertSatF32`) indicate saturating conversions.
    * **Arithmetic:** `kExprI32Add`, `kExprI64Sub`, `kExprF32Mul`, `kExprF64Div`, etc. These are basic arithmetic operations.
    * **Bitwise:** `kExprI32And`, `kExprI32Or`, `kExprI32Shl`, `kExprI64Ror`, etc. These manipulate the bits of integer values.
    * **Comparisons:** `kExprI32Eq`, `kExprI32Ne`, `kExprF32Lt`, `kExprF64Ge`, etc. These compare values.
    * **Floating-point specific:** `kExprF32Floor`, `kExprF64Ceil`, `kExprF64Sin`, `kExprF64Pow`, etc. These perform specialized floating-point operations.
    * **Memory Access (Asmjs):** The `kExprI32AsmjsLoadMem*` opcodes indicate support for Asm.js-style memory access within Wasm.
    * **Reference Operations:** `kExprRefIsNull`, `kExprRefAsNonNull`, `kExprRefEq` handle Wasm reference types.
    * **Reinterpretations:** `kExprF32ReinterpretI32`, `kExprI64ReinterpretF64` handle bitwise reinterpretation of data.
    * **Population Count and Leading/Trailing Zeros:** `kExprI32Popcnt`, `kExprI32Clz`, `kExprI32Ctz`.

4. **Identify architectural considerations:** The code checks `Is64()` in several places. This highlights that the implementation adapts based on whether the target architecture is 32-bit or 64-bit. This is important for operations like 64-bit integer division and conversions.

5. **Look for interactions with the underlying architecture:**  The use of `__` prefixes (e.g., `__ Word32Add`) suggests calls to architecture-specific code generators or helper functions within the Turboshaft framework. The use of `CallC` indicates calls to C runtime functions for operations not directly supported by the target architecture. `ExternalReference` is used to access these external functions.

6. **Consider potential errors:** The code includes checks and traps (`__ TrapIf`) for conditions like division by zero and unrepresentable values during conversions. This hints at common programming errors in Wasm.

7. **Address the `.tq` question:** The prompt asks what it means if the file ended in `.tq`. Knowing that `.tq` files in V8 are Torque (a TypeScript-like language for V8's internal code generation), I need to point this out.

8. **Connect to JavaScript:**  Since this is part of V8, it directly relates to how JavaScript executes WebAssembly. I need to provide examples of JavaScript code that would trigger these underlying Wasm operations.

9. **Infer input/output:**  For the code logic, I need to provide simple examples of Wasm operations and the expected outcome based on the code.

10. **Identify common user errors:** Based on the traps and conversion logic, I can deduce common errors like integer overflow during conversions and division by zero.

11. **Synthesize the summary:** Finally, I need to combine all these observations into a concise summary, addressing all points raised in the prompt and acknowledging that this is part 9 of 12, indicating its role in a larger process.

**(Self-Correction/Refinement during the thought process):**

* Initially, I might just focus on the opcodes. However, realizing the importance of architectural differences (`Is64()`) and the interaction with the C runtime (`CallC`, `ExternalReference`) adds more depth to the analysis.
*  I need to be careful to distinguish between operations that are directly generated as machine code and those that rely on C runtime functions.
* For the JavaScript examples, I need to ensure they are simple and clearly illustrate the corresponding Wasm functionality.
* When discussing common errors, providing concrete examples makes the explanation clearer.
* The "part 9 of 12" detail suggests this code is a stage within a larger compilation pipeline, which should be mentioned in the summary.

By following these steps, I can generate a comprehensive and accurate summary of the provided V8 source code.
`v8/src/wasm/turboshaft-graph-interface.cc` 是 V8 引擎中用于将 WebAssembly (Wasm) 操作转换为 Turboshaft 图形表示形式的代码。Turboshaft 是 V8 的下一代 Wasm 编译器。这个文件的主要功能是**定义了如何将 Wasm 的各种指令映射到 Turboshaft 图形节点的实现**。

以下是它的具体功能分解：

1. **实现 Wasm 单目运算符 (Unary Operators):**  `UnOpImpl` 函数负责处理 Wasm 中的单目运算，例如类型转换、位运算、数学函数等。它接收一个 Wasm 操作码 (`WasmOpcode`) 和一个操作数 (`arg`)，并返回表示该操作的 Turboshaft 图形节点 (`OpIndex`)。

2. **实现 Wasm 双目运算符 (Binary Operators):** `BinOpImpl` 函数负责处理 Wasm 中的双目运算，例如加减乘除、比较运算、位运算等。它接收一个 Wasm 操作码 (`WasmOpcode`) 和两个操作数 (`lhs`, `rhs`)，并返回表示该操作的 Turboshaft 图形节点。

3. **类型转换 (Conversions):**  代码包含了大量的类型转换操作，例如整数和浮点数之间的转换（`kExprI32ConvertF32`、`kExprF64SConvertI32`），以及不同大小整数之间的转换（`kExprI32SExtendI8`）。  其中一些转换还涉及到饱和转换 (`Sat`)，即溢出时会截断到最大或最小值。

4. **算术运算 (Arithmetic Operations):**  支持各种整数和浮点数的算术运算，包括加法、减法、乘法、除法等。对于整数除法，需要处理除零错误和溢出情况。

5. **位运算 (Bitwise Operations):**  实现了各种位运算，如与 (`And`)、或 (`Ior`)、异或 (`Xor`)、左移 (`Shl`)、右移 (`ShrS`, `ShrU`)、循环移位 (`Ror`, `Rol`)。

6. **比较运算 (Comparison Operations):**  支持各种比较运算符，例如相等 (`Eq`)、不等 (`Ne`)、小于 (`Lt`)、小于等于 (`Le`)、大于 (`Gt`)、大于等于 (`Ge`)。

7. **浮点数运算 (Floating-point Operations):**  包含了各种浮点数运算，例如 `floor`、`ceil`、`trunc`、`nearest`、`min`、`max` 以及一些更复杂的数学函数（`acos`、`asin`、`atan`、`cos`、`sin`、`tan`、`exp`、`log`、`pow`、`atan2`、`mod`）。

8. **内存操作 (Memory Operations - Asm.js):**  支持 Asm.js 风格的内存加载操作 (`kExprI32AsmjsLoadMem8S` 等)。

9. **引用类型操作 (Reference Type Operations):**  处理 Wasm 引用类型的操作，例如判断是否为空 (`kExprRefIsNull`)，转换为非空引用 (`kExprRefAsNonNull`)，以及比较引用是否相等 (`kExprRefEq`)。

10. **C 函数调用 (Calling C Functions):**  对于一些无法直接用机器指令实现的复杂操作，代码会调用 C 运行时库的函数，例如 `CallCStackSlotToStackSlot` 和 `BuildCcallConvertFloat`。

11. **架构差异处理:** 代码中会根据目标架构 (`Is64()`) 来选择不同的实现方式，特别是在处理 64 位整数运算时。

**如果 `v8/src/wasm/turboshaft-graph-interface.cc` 以 `.tq` 结尾：**

那么它将是一个 **V8 Torque 源代码**。Torque 是 V8 自研的一种领域特定语言，用于生成高效的 C++ 代码。如果该文件是 `.tq` 文件，那么它会使用 Torque 的语法来定义 Wasm 操作到 Turboshaft 图节点的映射规则，最终 Torque 编译器会将其编译成 C++ 代码。

**与 JavaScript 的关系及示例：**

该文件直接参与了 V8 引擎执行 WebAssembly 代码的过程。当 JavaScript 代码中调用了 WebAssembly 模块时，V8 会解析 Wasm 字节码，并使用 Turboshaft 编译器将其编译成机器码。`turboshaft-graph-interface.cc` 的代码负责将 Wasm 的各种操作转换成 Turboshaft 编译器可以理解的图形表示。

**JavaScript 示例：**

```javascript
const wasmCode = new Uint8Array([
  0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
  0x01, 0x07, 0x01, 0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7f, // 函数签名 (i32, i32) => i32
  0x03, 0x02, 0x01, 0x00, // 导入一个函数
  0x0a, 0x09, 0x01, 0x07, 0x00, 0x20, 0x00, 0x20, 0x01, 0x6a, 0x0b // 函数体：local.get 0; local.get 1; i32.add
]);

const wasmModule = new WebAssembly.Module(wasmCode);
const wasmInstance = new WebAssembly.Instance(wasmModule);

// 调用 Wasm 模块中的函数，这会触发 V8 的 Wasm 编译流程
const result = wasmInstance.exports.add(5, 10);
console.log(result); // 输出 15
```

在这个例子中，Wasm 代码定义了一个简单的加法函数。当 JavaScript 调用 `wasmInstance.exports.add(5, 10)` 时，V8 的 Turboshaft 编译器（包括 `turboshaft-graph-interface.cc` 中的代码）会将 `i32.add` 指令转换为 Turboshaft 图形中的加法节点，最终生成执行加法操作的机器码。

**代码逻辑推理（假设输入与输出）：**

**假设输入：**

* `opcode` 为 `kExprI32Add`
* `lhs` 是表示常量 5 的 Turboshaft 节点
* `rhs` 是表示常量 10 的 Turboshaft 节点

**输出：**

`BinOpImpl` 函数会返回一个新的 `OpIndex`，该 `OpIndex` 指向 Turboshaft 图形中的一个节点，该节点表示将 `lhs` 和 `rhs` 对应的值相加的 `i32.add` 操作。这个节点可能包含指向 `lhs` 和 `rhs` 节点的连接，以及该操作的元数据（例如，结果的类型是 `Word32`）。

**用户常见的编程错误示例：**

1. **整数溢出：**

   ```javascript
   const wasmCode = new Uint8Array([
     // ... (Wasm 模块定义，包含一个将两个 i32 相加的函数) ...
   ]);
   const wasmModule = new WebAssembly.Module(wasmCode);
   const wasmInstance = new WebAssembly.Instance(wasmModule);

   // 假设 Wasm 函数内部执行 i32.add
   const result = wasmInstance.exports.add(2147483647, 1); // 接近 i32 最大值
   console.log(result); // 结果会发生环绕，可能得到一个负数
   ```

   在 `turboshaft-graph-interface.cc` 中，`BinOpImpl` 对 `kExprI32Add` 的处理并不会主动抛出溢出错误（除非启用了特定的检查）。  Wasm 的默认行为是整数溢出时会进行环绕。

2. **除零错误：**

   ```javascript
   const wasmCode = new Uint8Array([
     // ... (Wasm 模块定义，包含一个执行 i32.div_s 的函数) ...
   ]);
   const wasmModule = new WebAssembly.Module(wasmCode);
   const wasmInstance = new WebAssembly.Instance(wasmModule);

   // 假设 Wasm 函数内部执行 i32.div_s
   try {
     const result = wasmInstance.exports.divide(10, 0);
     console.log(result);
   } catch (error) {
     console.error(error); // 会捕获一个 WebAssembly.RuntimeError: integer division by zero
   }
   ```

   在 `turboshaft-graph-interface.cc` 中，对于 `kExprI32DivS` 和 `kExprI32DivU`，`BinOpImpl` 会插入 `__ TrapIf(__ Word32Equal(rhs, 0), TrapId::kTrapDivByZero);` 来检查除零错误，并在运行时触发一个陷阱（trap）。

3. **类型转换错误 (不可表示的值):**

   ```javascript
   const wasmCode = new Uint8Array([
     // ... (Wasm 模块定义，包含一个将 f64 转换为 i32 的函数) ...
   ]);
   const wasmModule = new WebAssembly.Module(wasmCode);
   const wasmInstance = new WebAssembly.Instance(wasmModule);

   // 假设 Wasm 函数内部执行 i32.trunc_f64_s
   try {
     const result = wasmInstance.exports.convert(NaN);
     console.log(result); // 可能会得到 0，或者触发一个陷阱 (取决于具体的转换指令和配置)
   } catch (error) {
     console.error(error);
   }
   ```

   对于某些类型转换，例如将浮点数转换为整数时，如果浮点数的值超出整数的表示范围，`turboshaft-graph-interface.cc` 中的代码会根据具体的转换指令（例如，带饱和的转换或不带饱和的转换）来处理，可能会生成陷阱或者截断到边界值。

**作为第 9 部分的功能归纳：**

作为 12 个部分中的第 9 部分，`v8/src/wasm/turboshaft-graph-interface.cc`  在 V8 的 WebAssembly 编译流程中扮演着至关重要的角色。它的主要功能是：

* **连接 Wasm 前端和 Turboshaft 后端：** 它接收从 Wasm 字节码解析出的操作信息，并将其转换为 Turboshaft 编译器能够理解和优化的图形表示。
* **提供 Wasm 指令的 Turboshaft 实现：** 它为几乎所有的 Wasm 核心指令（单目和双目运算符）提供了到 Turboshaft 图形节点的映射实现。
* **处理平台和架构差异：**  它在实现过程中考虑了不同目标架构的特性，并根据需要调用 C 运行时库函数。
* **支持错误处理和陷阱生成：**  它在图形表示中包含了必要的错误检查，例如除零检查，并在运行时触发相应的陷阱。

总而言之，`v8/src/wasm/turboshaft-graph-interface.cc` 是 Turboshaft 编译器将高级的 Wasm 指令转换为底层的、可优化的图形表示的关键步骤，为后续的优化和代码生成奠定了基础。

Prompt: 
```
这是目录为v8/src/wasm/turboshaft-graph-interface.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/turboshaft-graph-interface.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第9部分，共12部分，请归纳一下它的功能

"""
nrepresentable);
        return result;
      }
      case kExprI32SConvertF64: {
        V<Float64> truncated = UnOpImpl(kExprF64Trunc, arg, kWasmF64);
        V<Word32> result =
            __ TruncateFloat64ToInt32OverflowUndefined(truncated);
        V<Float64> converted_back = __ ChangeInt32ToFloat64(result);
        __ TrapIf(__ Word32Equal(__ Float64Equal(converted_back, truncated), 0),
                  TrapId::kTrapFloatUnrepresentable);
        return result;
      }
      case kExprI32UConvertF64: {
        V<Float64> truncated = UnOpImpl(kExprF64Trunc, arg, kWasmF64);
        V<Word32> result = __ TruncateFloat64ToUint32OverflowToMin(truncated);
        V<Float64> converted_back = __ ChangeUint32ToFloat64(result);
        __ TrapIf(__ Word32Equal(__ Float64Equal(converted_back, truncated), 0),
                  TrapId::kTrapFloatUnrepresentable);
        return result;
      }
      case kExprI64SConvertF32:
        return Is64() ? ExtractTruncationProjections(
                            __ TryTruncateFloat32ToInt64(arg))
                      : BuildCcallConvertFloat(
                            arg, MemoryRepresentation::Float32(),
                            ExternalReference::wasm_float32_to_int64());
      case kExprI64UConvertF32:
        return Is64() ? ExtractTruncationProjections(
                            __ TryTruncateFloat32ToUint64(arg))
                      : BuildCcallConvertFloat(
                            arg, MemoryRepresentation::Float32(),
                            ExternalReference::wasm_float32_to_uint64());
      case kExprI64SConvertF64:
        return Is64() ? ExtractTruncationProjections(
                            __ TryTruncateFloat64ToInt64(arg))
                      : BuildCcallConvertFloat(
                            arg, MemoryRepresentation::Float64(),
                            ExternalReference::wasm_float64_to_int64());
      case kExprI64UConvertF64:
        return Is64() ? ExtractTruncationProjections(
                            __ TryTruncateFloat64ToUint64(arg))
                      : BuildCcallConvertFloat(
                            arg, MemoryRepresentation::Float64(),
                            ExternalReference::wasm_float64_to_uint64());
      case kExprF64SConvertI32:
        return __ ChangeInt32ToFloat64(arg);
      case kExprF64UConvertI32:
        return __ ChangeUint32ToFloat64(arg);
      case kExprF32SConvertI32:
        return __ ChangeInt32ToFloat32(arg);
      case kExprF32UConvertI32:
        return __ ChangeUint32ToFloat32(arg);
      case kExprI32SConvertSatF32: {
        V<Float32> truncated = UnOpImpl(kExprF32Trunc, arg, kWasmF32);
        V<Word32> converted =
            __ TruncateFloat32ToInt32OverflowUndefined(truncated);
        V<Float32> converted_back = __ ChangeInt32ToFloat32(converted);

        Label<Word32> done(&asm_);

        IF (LIKELY(__ Float32Equal(truncated, converted_back))) {
          GOTO(done, converted);
        } ELSE {
          // Overflow.
          IF (__ Float32Equal(arg, arg)) {
            // Not NaN.
            IF (__ Float32LessThan(arg, 0)) {
              // Negative arg.
              GOTO(done,
                   __ Word32Constant(std::numeric_limits<int32_t>::min()));
            } ELSE {
              // Positive arg.
              GOTO(done,
                   __ Word32Constant(std::numeric_limits<int32_t>::max()));
            }
          } ELSE {
            // NaN.
            GOTO(done, __ Word32Constant(0));
          }
        }
        BIND(done, result);

        return result;
      }
      case kExprI32UConvertSatF32: {
        V<Float32> truncated = UnOpImpl(kExprF32Trunc, arg, kWasmF32);
        V<Word32> converted =
            __ TruncateFloat32ToUint32OverflowUndefined(truncated);
        V<Float32> converted_back = __ ChangeUint32ToFloat32(converted);

        Label<Word32> done(&asm_);

        IF (LIKELY(__ Float32Equal(truncated, converted_back))) {
          GOTO(done, converted);
        } ELSE {
          // Overflow.
          IF (__ Float32Equal(arg, arg)) {
            // Not NaN.
            IF (__ Float32LessThan(arg, 0)) {
              // Negative arg.
              GOTO(done, __ Word32Constant(0));
            } ELSE {
              // Positive arg.
              GOTO(done,
                   __ Word32Constant(std::numeric_limits<uint32_t>::max()));
            }
          } ELSE {
            // NaN.
            GOTO(done, __ Word32Constant(0));
          }
        }
        BIND(done, result);

        return result;
      }
      case kExprI32SConvertSatF64: {
        V<Float64> truncated = UnOpImpl(kExprF64Trunc, arg, kWasmF64);
        V<Word32> converted =
            __ TruncateFloat64ToInt32OverflowUndefined(truncated);
        V<Float64> converted_back = __ ChangeInt32ToFloat64(converted);

        Label<Word32> done(&asm_);

        IF (LIKELY(__ Float64Equal(truncated, converted_back))) {
          GOTO(done, converted);
        } ELSE {
          // Overflow.
          IF (__ Float64Equal(arg, arg)) {
            // Not NaN.
            IF (__ Float64LessThan(arg, 0)) {
              // Negative arg.
              GOTO(done,
                   __ Word32Constant(std::numeric_limits<int32_t>::min()));
            } ELSE {
              // Positive arg.
              GOTO(done,
                   __ Word32Constant(std::numeric_limits<int32_t>::max()));
            }
          } ELSE {
            // NaN.
            GOTO(done, __ Word32Constant(0));
          }
        }
        BIND(done, result);

        return result;
      }
      case kExprI32UConvertSatF64: {
        V<Float64> truncated = UnOpImpl(kExprF64Trunc, arg, kWasmF64);
        V<Word32> converted =
            __ TruncateFloat64ToUint32OverflowUndefined(truncated);
        V<Float64> converted_back = __ ChangeUint32ToFloat64(converted);

        Label<Word32> done(&asm_);

        IF (LIKELY(__ Float64Equal(truncated, converted_back))) {
          GOTO(done, converted);
        } ELSE {
          // Overflow.
          IF (__ Float64Equal(arg, arg)) {
            // Not NaN.
            IF (__ Float64LessThan(arg, 0)) {
              // Negative arg.
              GOTO(done, __ Word32Constant(0));
            } ELSE {
              // Positive arg.
              GOTO(done,
                   __ Word32Constant(std::numeric_limits<uint32_t>::max()));
            }
          } ELSE {
            // NaN.
            GOTO(done, __ Word32Constant(0));
          }
        }
        BIND(done, result);

        return result;
      }
      case kExprI64SConvertSatF32: {
        if constexpr (!Is64()) {
          bool is_signed = true;
          return BuildCcallConvertFloatSat(
              arg, MemoryRepresentation::Float32(),
              ExternalReference::wasm_float32_to_int64_sat(), is_signed);
        }
        V<Tuple<Word64, Word32>> converted = __ TryTruncateFloat32ToInt64(arg);
        Label<compiler::turboshaft::Word64> done(&asm_);

        if (SupportedOperations::sat_conversion_is_safe()) {
          return __ Projection<0>(converted);
        }
        IF (LIKELY(__ Projection<1>(converted))) {
          GOTO(done, __ Projection<0>(converted));
        } ELSE {
          // Overflow.
          IF (__ Float32Equal(arg, arg)) {
            // Not NaN.
            IF (__ Float32LessThan(arg, 0)) {
              // Negative arg.
              GOTO(done,
                   __ Word64Constant(std::numeric_limits<int64_t>::min()));
            } ELSE {
              // Positive arg.
              GOTO(done,
                   __ Word64Constant(std::numeric_limits<int64_t>::max()));
            }
          } ELSE {
            // NaN.
            GOTO(done, __ Word64Constant(int64_t{0}));
          }
        }
        BIND(done, result);

        return result;
      }
      case kExprI64UConvertSatF32: {
        if constexpr (!Is64()) {
          bool is_signed = false;
          return BuildCcallConvertFloatSat(
              arg, MemoryRepresentation::Float32(),
              ExternalReference::wasm_float32_to_uint64_sat(), is_signed);
        }
        V<Tuple<Word64, Word32>> converted = __ TryTruncateFloat32ToUint64(arg);
        Label<compiler::turboshaft::Word64> done(&asm_);

        if (SupportedOperations::sat_conversion_is_safe()) {
          return __ template Projection<0>(converted);
        }

        IF (LIKELY(__ template Projection<1>(converted))) {
          GOTO(done, __ template Projection<0>(converted));
        } ELSE {
          // Overflow.
          IF (__ Float32Equal(arg, arg)) {
            // Not NaN.
            IF (__ Float32LessThan(arg, 0)) {
              // Negative arg.
              GOTO(done, __ Word64Constant(int64_t{0}));
            } ELSE {
              // Positive arg.
              GOTO(done,
                   __ Word64Constant(std::numeric_limits<uint64_t>::max()));
            }
          } ELSE {
            // NaN.
            GOTO(done, __ Word64Constant(int64_t{0}));
          }
        }
        BIND(done, result);

        return result;
      }
      case kExprI64SConvertSatF64: {
        if constexpr (!Is64()) {
          bool is_signed = true;
          return BuildCcallConvertFloatSat(
              arg, MemoryRepresentation::Float64(),
              ExternalReference::wasm_float64_to_int64_sat(), is_signed);
        }
        V<Tuple<Word64, Word32>> converted = __ TryTruncateFloat64ToInt64(arg);
        Label<compiler::turboshaft::Word64> done(&asm_);

        if (SupportedOperations::sat_conversion_is_safe()) {
          return __ template Projection<0>(converted);
        }

        IF (LIKELY(__ template Projection<1>(converted))) {
          GOTO(done, __ template Projection<0>(converted));
        } ELSE {
          // Overflow.
          IF (__ Float64Equal(arg, arg)) {
            // Not NaN.
            IF (__ Float64LessThan(arg, 0)) {
              // Negative arg.
              GOTO(done,
                   __ Word64Constant(std::numeric_limits<int64_t>::min()));
            } ELSE {
              // Positive arg.
              GOTO(done,
                   __ Word64Constant(std::numeric_limits<int64_t>::max()));
            }
          } ELSE {
            // NaN.
            GOTO(done, __ Word64Constant(int64_t{0}));
          }
        }
        BIND(done, result);

        return result;
      }
      case kExprI64UConvertSatF64: {
        if constexpr (!Is64()) {
          bool is_signed = false;
          return BuildCcallConvertFloatSat(
              arg, MemoryRepresentation::Float64(),
              ExternalReference::wasm_float64_to_uint64_sat(), is_signed);
        }
        V<Tuple<Word64, Word32>> converted = __ TryTruncateFloat64ToUint64(arg);
        Label<compiler::turboshaft::Word64> done(&asm_);

        if (SupportedOperations::sat_conversion_is_safe()) {
          return __ template Projection<0>(converted);
        }

        IF (LIKELY(__ template Projection<1>(converted))) {
          GOTO(done, __ template Projection<0>(converted));
        } ELSE {
          // Overflow.
          IF (__ Float64Equal(arg, arg)) {
            // Not NaN.
            IF (__ Float64LessThan(arg, 0)) {
              // Negative arg.
              GOTO(done, __ Word64Constant(int64_t{0}));
            } ELSE {
              // Positive arg.
              GOTO(done,
                   __ Word64Constant(std::numeric_limits<uint64_t>::max()));
            }
          } ELSE {
            // NaN.
            GOTO(done, __ Word64Constant(int64_t{0}));
          }
        }
        BIND(done, result);

        return result;
      }
      case kExprF32ConvertF64:
        return __ TruncateFloat64ToFloat32(arg);
      case kExprF64ConvertF32:
        return __ ChangeFloat32ToFloat64(arg);
      case kExprF32ReinterpretI32:
        return __ BitcastWord32ToFloat32(arg);
      case kExprI32ReinterpretF32:
        return __ BitcastFloat32ToWord32(arg);
      case kExprI32Clz:
        return __ Word32CountLeadingZeros(arg);
      case kExprI32Ctz:
        if (SupportedOperations::word32_ctz()) {
          return __ Word32CountTrailingZeros(arg);
        } else {
          // TODO(14108): Use reverse_bits if supported.
          auto sig =
              FixedSizeSignature<MachineType>::Returns(MachineType::Uint32())
                  .Params(MachineType::Uint32());
          return CallC(&sig, ExternalReference::wasm_word32_ctz(), arg);
        }
      case kExprI32Popcnt:
        if (SupportedOperations::word32_popcnt()) {
          return __ Word32PopCount(arg);
        } else {
          auto sig =
              FixedSizeSignature<MachineType>::Returns(MachineType::Uint32())
                  .Params(MachineType::Uint32());
          return CallC(&sig, ExternalReference::wasm_word32_popcnt(), arg);
        }
      case kExprF32Floor:
        if (SupportedOperations::float32_round_down()) {
          return __ Float32RoundDown(arg);
        } else {
          return CallCStackSlotToStackSlot(arg,
                                           ExternalReference::wasm_f32_floor(),
                                           MemoryRepresentation::Float32());
        }
      case kExprF32Ceil:
        if (SupportedOperations::float32_round_up()) {
          return __ Float32RoundUp(arg);
        } else {
          return CallCStackSlotToStackSlot(arg,
                                           ExternalReference::wasm_f32_ceil(),
                                           MemoryRepresentation::Float32());
        }
      case kExprF32Trunc:
        if (SupportedOperations::float32_round_to_zero()) {
          return __ Float32RoundToZero(arg);
        } else {
          return CallCStackSlotToStackSlot(arg,
                                           ExternalReference::wasm_f32_trunc(),
                                           MemoryRepresentation::Float32());
        }
      case kExprF32NearestInt:
        if (SupportedOperations::float32_round_ties_even()) {
          return __ Float32RoundTiesEven(arg);
        } else {
          return CallCStackSlotToStackSlot(
              arg, ExternalReference::wasm_f32_nearest_int(),
              MemoryRepresentation::Float32());
        }
      case kExprF64Floor:
        if (SupportedOperations::float64_round_down()) {
          return __ Float64RoundDown(arg);
        } else {
          return CallCStackSlotToStackSlot(arg,
                                           ExternalReference::wasm_f64_floor(),
                                           MemoryRepresentation::Float64());
        }
      case kExprF64Ceil:
        if (SupportedOperations::float64_round_up()) {
          return __ Float64RoundUp(arg);
        } else {
          return CallCStackSlotToStackSlot(arg,
                                           ExternalReference::wasm_f64_ceil(),
                                           MemoryRepresentation::Float64());
        }
      case kExprF64Trunc:
        if (SupportedOperations::float64_round_to_zero()) {
          return __ Float64RoundToZero(arg);
        } else {
          return CallCStackSlotToStackSlot(arg,
                                           ExternalReference::wasm_f64_trunc(),
                                           MemoryRepresentation::Float64());
        }
      case kExprF64NearestInt:
        if (SupportedOperations::float64_round_ties_even()) {
          return __ Float64RoundTiesEven(arg);
        } else {
          return CallCStackSlotToStackSlot(
              arg, ExternalReference::wasm_f64_nearest_int(),
              MemoryRepresentation::Float64());
        }
      case kExprF64Acos:
        return CallCStackSlotToStackSlot(
            arg, ExternalReference::f64_acos_wrapper_function(),
            MemoryRepresentation::Float64());
      case kExprF64Asin:
        return CallCStackSlotToStackSlot(
            arg, ExternalReference::f64_asin_wrapper_function(),
            MemoryRepresentation::Float64());
      case kExprF64Atan:
        return __ Float64Atan(arg);
      case kExprF64Cos:
        return __ Float64Cos(arg);
      case kExprF64Sin:
        return __ Float64Sin(arg);
      case kExprF64Tan:
        return __ Float64Tan(arg);
      case kExprF64Exp:
        return __ Float64Exp(arg);
      case kExprF64Log:
        return __ Float64Log(arg);
      case kExprI32ConvertI64:
        return __ TruncateWord64ToWord32(arg);
      case kExprI64SConvertI32:
        return __ ChangeInt32ToInt64(arg);
      case kExprI64UConvertI32:
        return __ ChangeUint32ToUint64(arg);
      case kExprF64ReinterpretI64:
        return __ BitcastWord64ToFloat64(arg);
      case kExprI64ReinterpretF64:
        return __ BitcastFloat64ToWord64(arg);
      case kExprI64Clz:
        return __ Word64CountLeadingZeros(arg);
      case kExprI64Ctz:
        if (SupportedOperations::word64_ctz() ||
            (!Is64() && SupportedOperations::word32_ctz())) {
          return __ Word64CountTrailingZeros(arg);
        } else if (Is64()) {
          // TODO(14108): Use reverse_bits if supported.
          auto sig =
              FixedSizeSignature<MachineType>::Returns(MachineType::Uint32())
                  .Params(MachineType::Uint64());
          return __ ChangeUint32ToUint64(
              CallC(&sig, ExternalReference::wasm_word64_ctz(), arg));
        } else {
          // lower_word == 0 ? 32 + CTZ32(upper_word) : CTZ32(lower_word);
          OpIndex upper_word =
              __ TruncateWord64ToWord32(__ Word64ShiftRightLogical(arg, 32));
          OpIndex lower_word = __ TruncateWord64ToWord32(arg);
          auto sig =
              FixedSizeSignature<MachineType>::Returns(MachineType::Uint32())
                  .Params(MachineType::Uint32());
          Label<Word32> done(&asm_);
          IF (__ Word32Equal(lower_word, 0)) {
            GOTO(done,
                 __ Word32Add(CallC(&sig, ExternalReference::wasm_word32_ctz(),
                                    upper_word),
                              32));
          } ELSE {
            GOTO(done,
                 CallC(&sig, ExternalReference::wasm_word32_ctz(), lower_word));
          }
          BIND(done, result);
          return __ ChangeUint32ToUint64(result);
        }
      case kExprI64Popcnt:
        if (SupportedOperations::word64_popcnt() ||
            (!Is64() && SupportedOperations::word32_popcnt())) {
          return __ Word64PopCount(arg);
        } else if (Is64()) {
          // Call wasm_word64_popcnt.
          auto sig =
              FixedSizeSignature<MachineType>::Returns(MachineType::Uint32())
                  .Params(MachineType::Uint64());
          return __ ChangeUint32ToUint64(
              CallC(&sig, ExternalReference::wasm_word64_popcnt(), arg));
        } else {
          // Emit two calls to wasm_word32_popcnt.
          OpIndex upper_word =
              __ TruncateWord64ToWord32(__ Word64ShiftRightLogical(arg, 32));
          OpIndex lower_word = __ TruncateWord64ToWord32(arg);
          auto sig =
              FixedSizeSignature<MachineType>::Returns(MachineType::Uint32())
                  .Params(MachineType::Uint32());
          return __ ChangeUint32ToUint64(__ Word32Add(
              CallC(&sig, ExternalReference::wasm_word32_popcnt(), lower_word),
              CallC(&sig, ExternalReference::wasm_word32_popcnt(),
                    upper_word)));
        }
      case kExprI64Eqz:
        return __ Word64Equal(arg, 0);
      case kExprF32SConvertI64:
        if constexpr (!Is64()) {
          return BuildIntToFloatConversionInstruction(
              arg, ExternalReference::wasm_int64_to_float32(),
              MemoryRepresentation::Int64(), MemoryRepresentation::Float32());
        }
        return __ ChangeInt64ToFloat32(arg);
      case kExprF32UConvertI64:
        if constexpr (!Is64()) {
          return BuildIntToFloatConversionInstruction(
              arg, ExternalReference::wasm_uint64_to_float32(),
              MemoryRepresentation::Uint64(), MemoryRepresentation::Float32());
        }
        return __ ChangeUint64ToFloat32(arg);
      case kExprF64SConvertI64:
        if constexpr (!Is64()) {
          return BuildIntToFloatConversionInstruction(
              arg, ExternalReference::wasm_int64_to_float64(),
              MemoryRepresentation::Int64(), MemoryRepresentation::Float64());
        }
        return __ ChangeInt64ToFloat64(arg);
      case kExprF64UConvertI64:
        if constexpr (!Is64()) {
          return BuildIntToFloatConversionInstruction(
              arg, ExternalReference::wasm_uint64_to_float64(),
              MemoryRepresentation::Uint64(), MemoryRepresentation::Float64());
        }
        return __ ChangeUint64ToFloat64(arg);
      case kExprI32SExtendI8:
        return __ Word32SignExtend8(arg);
      case kExprI32SExtendI16:
        return __ Word32SignExtend16(arg);
      case kExprI64SExtendI8:
        return __ Word64SignExtend8(arg);
      case kExprI64SExtendI16:
        return __ Word64SignExtend16(arg);
      case kExprI64SExtendI32:
        return __ ChangeInt32ToInt64(__ TruncateWord64ToWord32(arg));
      case kExprRefIsNull:
        return __ IsNull(arg, input_type);
      case kExprI32AsmjsLoadMem8S:
        return AsmjsLoadMem(arg, MemoryRepresentation::Int8());
      case kExprI32AsmjsLoadMem8U:
        return AsmjsLoadMem(arg, MemoryRepresentation::Uint8());
      case kExprI32AsmjsLoadMem16S:
        return AsmjsLoadMem(arg, MemoryRepresentation::Int16());
      case kExprI32AsmjsLoadMem16U:
        return AsmjsLoadMem(arg, MemoryRepresentation::Uint16());
      case kExprI32AsmjsLoadMem:
        return AsmjsLoadMem(arg, MemoryRepresentation::Int32());
      case kExprF32AsmjsLoadMem:
        return AsmjsLoadMem(arg, MemoryRepresentation::Float32());
      case kExprF64AsmjsLoadMem:
        return AsmjsLoadMem(arg, MemoryRepresentation::Float64());
      case kExprI32AsmjsSConvertF32:
      case kExprI32AsmjsUConvertF32:
        return __ JSTruncateFloat64ToWord32(__ ChangeFloat32ToFloat64(arg));
      case kExprI32AsmjsSConvertF64:
      case kExprI32AsmjsUConvertF64:
        return __ JSTruncateFloat64ToWord32(arg);
      case kExprRefAsNonNull:
        // We abuse ref.as_non_null, which isn't otherwise used in this switch,
        // as a sentinel for the negation of ref.is_null.
        return __ Word32Equal(__ IsNull(arg, input_type), 0);
      case kExprAnyConvertExtern:
        return __ AnyConvertExtern(arg);
      case kExprExternConvertAny:
        return __ ExternConvertAny(arg);
      default:
        UNREACHABLE();
    }
  }

  OpIndex BinOpImpl(WasmOpcode opcode, OpIndex lhs, OpIndex rhs) {
    switch (opcode) {
      case kExprI32Add:
        return __ Word32Add(lhs, rhs);
      case kExprI32Sub:
        return __ Word32Sub(lhs, rhs);
      case kExprI32Mul:
        return __ Word32Mul(lhs, rhs);
      case kExprI32DivS: {
        __ TrapIf(__ Word32Equal(rhs, 0), TrapId::kTrapDivByZero);
        V<Word32> unrepresentable_condition = __ Word32BitwiseAnd(
            __ Word32Equal(rhs, -1), __ Word32Equal(lhs, kMinInt));
        __ TrapIf(unrepresentable_condition, TrapId::kTrapDivUnrepresentable);
        return __ Int32Div(lhs, rhs);
      }
      case kExprI32DivU:
        __ TrapIf(__ Word32Equal(rhs, 0), TrapId::kTrapDivByZero);
        return __ Uint32Div(lhs, rhs);
      case kExprI32RemS: {
        __ TrapIf(__ Word32Equal(rhs, 0), TrapId::kTrapRemByZero);
        Label<Word32> done(&asm_);
        IF (UNLIKELY(__ Word32Equal(rhs, -1))) {
          GOTO(done, __ Word32Constant(0));
        } ELSE {
          GOTO(done, __ Int32Mod(lhs, rhs));
        };

        BIND(done, result);
        return result;
      }
      case kExprI32RemU:
        __ TrapIf(__ Word32Equal(rhs, 0), TrapId::kTrapRemByZero);
        return __ Uint32Mod(lhs, rhs);
      case kExprI32And:
        return __ Word32BitwiseAnd(lhs, rhs);
      case kExprI32Ior:
        return __ Word32BitwiseOr(lhs, rhs);
      case kExprI32Xor:
        return __ Word32BitwiseXor(lhs, rhs);
      case kExprI32Shl:
        // If possible, the bitwise-and gets optimized away later.
        return __ Word32ShiftLeft(lhs, __ Word32BitwiseAnd(rhs, 0x1f));
      case kExprI32ShrS:
        return __ Word32ShiftRightArithmetic(lhs,
                                             __ Word32BitwiseAnd(rhs, 0x1f));
      case kExprI32ShrU:
        return __ Word32ShiftRightLogical(lhs, __ Word32BitwiseAnd(rhs, 0x1f));
      case kExprI32Ror:
        return __ Word32RotateRight(lhs, __ Word32BitwiseAnd(rhs, 0x1f));
      case kExprI32Rol:
        if (SupportedOperations::word32_rol()) {
          return __ Word32RotateLeft(lhs, __ Word32BitwiseAnd(rhs, 0x1f));
        } else {
          return __ Word32RotateRight(
              lhs, __ Word32Sub(32, __ Word32BitwiseAnd(rhs, 0x1f)));
        }
      case kExprI32Eq:
        return __ Word32Equal(lhs, rhs);
      case kExprI32Ne:
        return __ Word32Equal(__ Word32Equal(lhs, rhs), 0);
      case kExprI32LtS:
        return __ Int32LessThan(lhs, rhs);
      case kExprI32LeS:
        return __ Int32LessThanOrEqual(lhs, rhs);
      case kExprI32LtU:
        return __ Uint32LessThan(lhs, rhs);
      case kExprI32LeU:
        return __ Uint32LessThanOrEqual(lhs, rhs);
      case kExprI32GtS:
        return __ Int32LessThan(rhs, lhs);
      case kExprI32GeS:
        return __ Int32LessThanOrEqual(rhs, lhs);
      case kExprI32GtU:
        return __ Uint32LessThan(rhs, lhs);
      case kExprI32GeU:
        return __ Uint32LessThanOrEqual(rhs, lhs);
      case kExprI64Add:
        return __ Word64Add(lhs, rhs);
      case kExprI64Sub:
        return __ Word64Sub(lhs, rhs);
      case kExprI64Mul:
        return __ Word64Mul(lhs, rhs);
      case kExprI64DivS: {
        if constexpr (!Is64()) {
          return BuildDiv64Call(lhs, rhs, ExternalReference::wasm_int64_div(),
                                wasm::TrapId::kTrapDivByZero);
        }
        __ TrapIf(__ Word64Equal(rhs, 0), TrapId::kTrapDivByZero);
        V<Word32> unrepresentable_condition = __ Word32BitwiseAnd(
            __ Word64Equal(rhs, -1),
            __ Word64Equal(lhs, std::numeric_limits<int64_t>::min()));
        __ TrapIf(unrepresentable_condition, TrapId::kTrapDivUnrepresentable);
        return __ Int64Div(lhs, rhs);
      }
      case kExprI64DivU:
        if constexpr (!Is64()) {
          return BuildDiv64Call(lhs, rhs, ExternalReference::wasm_uint64_div(),
                                wasm::TrapId::kTrapDivByZero);
        }
        __ TrapIf(__ Word64Equal(rhs, 0), TrapId::kTrapDivByZero);
        return __ Uint64Div(lhs, rhs);
      case kExprI64RemS: {
        if constexpr (!Is64()) {
          return BuildDiv64Call(lhs, rhs, ExternalReference::wasm_int64_mod(),
                                wasm::TrapId::kTrapRemByZero);
        }
        __ TrapIf(__ Word64Equal(rhs, 0), TrapId::kTrapRemByZero);
        Label<Word64> done(&asm_);
        IF (UNLIKELY(__ Word64Equal(rhs, -1))) {
          GOTO(done, __ Word64Constant(int64_t{0}));
        } ELSE {
          GOTO(done, __ Int64Mod(lhs, rhs));
        };

        BIND(done, result);
        return result;
      }
      case kExprI64RemU:
        if constexpr (!Is64()) {
          return BuildDiv64Call(lhs, rhs, ExternalReference::wasm_uint64_mod(),
                                wasm::TrapId::kTrapRemByZero);
        }
        __ TrapIf(__ Word64Equal(rhs, 0), TrapId::kTrapRemByZero);
        return __ Uint64Mod(lhs, rhs);
      case kExprI64And:
        return __ Word64BitwiseAnd(lhs, rhs);
      case kExprI64Ior:
        return __ Word64BitwiseOr(lhs, rhs);
      case kExprI64Xor:
        return __ Word64BitwiseXor(lhs, rhs);
      case kExprI64Shl:
        // If possible, the bitwise-and gets optimized away later.
        return __ Word64ShiftLeft(
            lhs, __ Word32BitwiseAnd(__ TruncateWord64ToWord32(rhs), 0x3f));
      case kExprI64ShrS:
        return __ Word64ShiftRightArithmetic(
            lhs, __ Word32BitwiseAnd(__ TruncateWord64ToWord32(rhs), 0x3f));
      case kExprI64ShrU:
        return __ Word64ShiftRightLogical(
            lhs, __ Word32BitwiseAnd(__ TruncateWord64ToWord32(rhs), 0x3f));
      case kExprI64Ror:
        return __ Word64RotateRight(
            lhs, __ Word32BitwiseAnd(__ TruncateWord64ToWord32(rhs), 0x3f));
      case kExprI64Rol:
        if (SupportedOperations::word64_rol()) {
          return __ Word64RotateLeft(
              lhs, __ Word32BitwiseAnd(__ TruncateWord64ToWord32(rhs), 0x3f));
        } else {
          return __ Word64RotateRight(
              lhs, __ Word32BitwiseAnd(
                       __ Word32Sub(64, __ TruncateWord64ToWord32(rhs)), 0x3f));
        }
      case kExprI64Eq:
        return __ Word64Equal(lhs, rhs);
      case kExprI64Ne:
        return __ Word32Equal(__ Word64Equal(lhs, rhs), 0);
      case kExprI64LtS:
        return __ Int64LessThan(lhs, rhs);
      case kExprI64LeS:
        return __ Int64LessThanOrEqual(lhs, rhs);
      case kExprI64LtU:
        return __ Uint64LessThan(lhs, rhs);
      case kExprI64LeU:
        return __ Uint64LessThanOrEqual(lhs, rhs);
      case kExprI64GtS:
        return __ Int64LessThan(rhs, lhs);
      case kExprI64GeS:
        return __ Int64LessThanOrEqual(rhs, lhs);
      case kExprI64GtU:
        return __ Uint64LessThan(rhs, lhs);
      case kExprI64GeU:
        return __ Uint64LessThanOrEqual(rhs, lhs);
      case kExprF32CopySign: {
        V<Word32> lhs_without_sign =
            __ Word32BitwiseAnd(__ BitcastFloat32ToWord32(lhs), 0x7fffffff);
        V<Word32> rhs_sign =
            __ Word32BitwiseAnd(__ BitcastFloat32ToWord32(rhs), 0x80000000);
        return __ BitcastWord32ToFloat32(
            __ Word32BitwiseOr(lhs_without_sign, rhs_sign));
      }
      case kExprF32Add:
        return __ Float32Add(lhs, rhs);
      case kExprF32Sub:
        return __ Float32Sub(lhs, rhs);
      case kExprF32Mul:
        return __ Float32Mul(lhs, rhs);
      case kExprF32Div:
        return __ Float32Div(lhs, rhs);
      case kExprF32Eq:
        return __ Float32Equal(lhs, rhs);
      case kExprF32Ne:
        return __ Word32Equal(__ Float32Equal(lhs, rhs), 0);
      case kExprF32Lt:
        return __ Float32LessThan(lhs, rhs);
      case kExprF32Le:
        return __ Float32LessThanOrEqual(lhs, rhs);
      case kExprF32Gt:
        return __ Float32LessThan(rhs, lhs);
      case kExprF32Ge:
        return __ Float32LessThanOrEqual(rhs, lhs);
      case kExprF32Min:
        return __ Float32Min(rhs, lhs);
      case kExprF32Max:
        return __ Float32Max(rhs, lhs);
      case kExprF64CopySign: {
        V<Word64> lhs_without_sign = __ Word64BitwiseAnd(
            __ BitcastFloat64ToWord64(lhs), 0x7fffffffffffffff);
        V<Word64> rhs_sign = __ Word64BitwiseAnd(__ BitcastFloat64ToWord64(rhs),
                                                 0x8000000000000000);
        return __ BitcastWord64ToFloat64(
            __ Word64BitwiseOr(lhs_without_sign, rhs_sign));
      }
      case kExprF64Add:
        return __ Float64Add(lhs, rhs);
      case kExprF64Sub:
        return __ Float64Sub(lhs, rhs);
      case kExprF64Mul:
        return __ Float64Mul(lhs, rhs);
      case kExprF64Div:
        return __ Float64Div(lhs, rhs);
      case kExprF64Eq:
        return __ Float64Equal(lhs, rhs);
      case kExprF64Ne:
        return __ Word32Equal(__ Float64Equal(lhs, rhs), 0);
      case kExprF64Lt:
        return __ Float64LessThan(lhs, rhs);
      case kExprF64Le:
        return __ Float64LessThanOrEqual(lhs, rhs);
      case kExprF64Gt:
        return __ Float64LessThan(rhs, lhs);
      case kExprF64Ge:
        return __ Float64LessThanOrEqual(rhs, lhs);
      case kExprF64Min:
        return __ Float64Min(lhs, rhs);
      case kExprF64Max:
        return __ Float64Max(lhs, rhs);
      case kExprF64Pow:
        return __ Float64Power(lhs, rhs);
      case kExprF64Atan2:
        return __ Float64Atan2(lhs, rhs);
      case kExprF64Mod:
        return CallCStackSlotToStackSlot(
            lhs, rhs, ExternalReference::f64_mod_wrapper_function(),
            MemoryRepresentation::Float64());
      case kExprRefEq:
        return __ TaggedEqual(lhs, rhs);
      case kExprI32AsmjsDivS: {
        // asmjs semantics return 0 when dividing by 0.
        if (SupportedOperations::int32_div_is_safe()) {
          return __ Int32Div(lhs, rhs);
        }
        Label<Word32> done(&asm_);
        IF (UNLIKELY(__ Word32Equal(rhs, 0))) {
          GOTO(done, __ Word32Constant(0));
        } ELSE {
          IF (UNLIKELY(__ Word32Equal(rhs, -1))) {
            GOTO(done, __ Word32Sub(0, lhs));
          } ELSE {
            GOTO(done, __ Int3
"""


```