Response: The user wants a summary of the C++ source code file `v8/src/wasm/turboshaft-graph-interface.cc`.
Specifically, they want to understand its functionality and how it relates to JavaScript.
They have also indicated that this is part 5 of a 6-part series, suggesting they are looking for a summary specific to this portion of the file.

Based on the provided code snippet, it seems this part of the file focuses on implementing **Wasm instructions** within the Turboshaft compiler pipeline. It defines how various WebAssembly operations (like arithmetic, conversions, memory access, etc.) are translated into lower-level Turboshaft graph operations.

The code heavily uses macros and helper functions (e.g., `UnOpImpl`, `BinOpImpl`, `CallC`, `TrapIf`) to generate the corresponding Turboshaft instructions.

**Key functionalities in this snippet:**

*   **Handling of Unary Operations:** The `UnOpImpl` function seems to be responsible for implementing various unary Wasm instructions. This includes:
    *   Conversions between integer and floating-point types (with overflow and saturation handling).
    *   Floating-point operations (floor, ceil, trunc, nearest).
    *   Bitwise operations (clz, ctz, popcnt).
    *   Reinterpret casts.
    *   Sign extensions.
    *   Reference type checks.
    *   Asm.js specific conversions and loads.
*   **Handling of Binary Operations:** The `BinOpImpl` function handles binary Wasm instructions like:
    *   Integer arithmetic (add, subtract, multiply, divide, remainder).
    *   Bitwise operations (and, or, xor, shift, rotate).
    *   Comparisons.
    *   Floating-point arithmetic.
    *   Memory access (Asm.js specific).
    *   Reference equality.
*   **Memory Access:** The `BoundsCheckMem`, `MemStart`, `MemBuffer`, and `MemSize` functions deal with WebAssembly memory access, including bounds checking and calculating memory addresses.
*   **Function Calls:**  The code includes logic for building both direct and indirect function calls, including signature checking for indirect calls.
*   **Exception Handling:** The `CallAndMaybeCatchException` function shows how exceptions are handled during Wasm calls within the Turboshaft pipeline.

**Relationship to JavaScript:**

This C++ code is part of V8, the JavaScript engine used in Chrome and Node.js. It's crucial for executing WebAssembly code within a JavaScript environment.

**JavaScript Examples:**

The Wasm instructions implemented here directly correspond to features available in WebAssembly, which can be used from JavaScript.

*   **Conversions:**
    ```javascript
    const wasmCode = new Uint8Array([
      0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
      0x01, 0x07, 0x01, 0x60, 0x01, 0x7c, 0x01, 0x7f, 0x03, 0x02, 0x01, 0x00,
      0x0a, 0x09, 0x01, 0x07, 0x00, 0x20, 0x00, 0xb7, 0x0b
    ]);
    const wasmModule = new WebAssembly.Module(wasmCode);
    const wasmInstance = new WebAssembly.Instance(wasmModule);
    // Equivalent to kExprI32SConvertF64: convert a float64 to a signed int32
    const floatValue = 3.14;
    const intResult = wasmInstance.exports.convertFloatToInt(floatValue);
    console.log(intResult); // Output will be 3 (truncation)
    ```

*   **Arithmetic Operations:**
    ```javascript
    const wasmCode = new Uint8Array([
      0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
      0x01, 0x07, 0x01, 0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7f, 0x03, 0x02, 0x01, 0x00,
      0x0a, 0x09, 0x01, 0x07, 0x00, 0x20, 0x00, 0x20, 0x01, 0x6a, 0x0b
    ]);
    const wasmModule = new WebAssembly.Module(wasmCode);
    const wasmInstance = new WebAssembly.Instance(wasmModule);
    // Equivalent to kExprI32Add: adds two i32 values
    const sum = wasmInstance.exports.add(5, 10);
    console.log(sum); // Output will be 15
    ```

*   **Memory Access:**
    ```javascript
    const wasmMemory = new WebAssembly.Memory({ initial: 1 });
    const wasmCode = new Uint8Array([
      0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
      0x02, 0x07, 0x01, 0x00, 0x01, 0x03, 0x02, 0x01, 0x00,
      0x0a, 0x08, 0x01, 0x06, 0x00, 0x41, 0x05, 0x36, 0x02, 0x00, 0x0b
    ]);
    const wasmModule = new WebAssembly.Module(wasmCode);
    const wasmInstance = new WebAssembly.Instance(wasmModule, { mem: wasmMemory });
    const memView = new Uint8Array(wasmMemory.buffer);
    wasmInstance.exports.storeValue(10); // Equivalent to a store operation
    console.log(memView[5]); // Output will be 10
    ```

**Summary of Part 5:**

This section of `turboshaft-graph-interface.cc` focuses on implementing the core logic for translating a wide range of individual WebAssembly instructions into the Turboshaft intermediate representation. It covers unary and binary operations, memory access, and function call mechanisms, including detailed handling of conversions, potential traps (errors), and interactions with the V8 runtime environment. This part is crucial for the Turboshaft compiler to effectively compile and optimize WebAssembly code for execution within the V8 JavaScript engine. It lays the groundwork for translating the high-level Wasm instructions into low-level machine code.

这是 `v8/src/wasm/turboshaft-graph-interface.cc` 文件的第五部分，主要负责将 WebAssembly 的操作码 (opcodes) 转换为 Turboshaft 图 (Turboshaft graph) 中的节点。Turboshaft 是 V8 引擎中用于编译 WebAssembly 代码的一个新的编译器管道。

**本部分的主要功能可以归纳为：**

1. **实现 WebAssembly 的一元操作 (Unary Operations):** `UnOpImpl` 函数针对各种 WebAssembly 的一元操作码，生成相应的 Turboshaft 图节点。这些操作包括：
    *   不同数值类型之间的转换 (例如，浮点数转整数，整数转浮点数)。在转换过程中，会处理溢出、饱和转换等情况，并根据需要插入 trap (错误处理) 节点。
    *   各种浮点数运算 (例如，取整、绝对值等)。
    *   位运算 (例如，计算前导零、尾随零、人口计数)。
    *   类型转换 (例如，重新解释内存表示)。
    *   符号扩展。
    *   类型检查 (例如，检查引用是否为空)。
    *   与 Asm.js 相关的类型转换和加载操作。

2. **实现 WebAssembly 的二元操作 (Binary Operations):** `BinOpImpl` 函数负责将 WebAssembly 的二元操作码转换为 Turboshaft 图节点。这些操作包括：
    *   整数算术运算 (加、减、乘、除、余数)。在除法和余数运算中，会处理除零错误和无法表示的情况。
    *   位运算 (与、或、异或、左移、右移、循环移位)。
    *   比较运算 (等于、不等于、小于、大于等)。
    *   浮点数算术运算 (加、减、乘、除)。
    *   浮点数比较运算。
    *   一些特定的浮点数运算 (例如，`copysign`, `min`, `max`, `pow`, `atan2`, `mod`)。
    *   引用类型的相等性比较。
    *   与 Asm.js 相关的除法、余数和存储操作。

3. **处理内存访问:** `BoundsCheckMem`, `MemStart`, `MemBuffer`, 和 `MemSize` 等函数用于处理 WebAssembly 的内存访问。这包括进行边界检查，计算内存地址等。根据编译选项和内存的属性 (例如，是否是 shared memory)，会选择不同的边界检查策略。

4. **处理函数调用:** 代码中包含了构建直接函数调用和间接函数调用的逻辑。对于间接调用，还需要进行类型签名检查，确保调用目标的函数签名与期望的签名一致。

5. **处理异常:** `CallAndMaybeCatchException` 函数展示了如何在 Turboshaft 图中处理 WebAssembly 函数调用可能抛出的异常。

**与 JavaScript 的关系:**

这段 C++ 代码是 V8 引擎的一部分，V8 引擎是 JavaScript 的运行时环境。WebAssembly 是一种可以在现代 Web 浏览器中运行的新的二进制指令格式。JavaScript 可以加载、编译和执行 WebAssembly 模块。

这段 C++ 代码的功能是 WebAssembly 在 V8 引擎中执行的关键部分。它将 WebAssembly 的底层指令转换为 V8 内部的表示 (Turboshaft 图)，然后 V8 可以进一步优化和执行这些操作。

**JavaScript 示例:**

以下 JavaScript 示例展示了如何调用 WebAssembly 的函数，这些函数内部可能涉及到这里实现的某些操作：

```javascript
// WebAssembly 模块的二进制代码 (简化的例子)
const wasmCode = new Uint8Array([
  0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
  0x01, 0x07, 0x01, 0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7f, // 定义函数签名 (i32, i32) => i32
  0x03, 0x02, 0x01, 0x00,                                 // 导入段
  0x0a, 0x09, 0x01, 0x07, 0x00, 0x20, 0x00, 0x20, 0x01, 0x6a, 0x0b // 代码段 (本地变量 get 0, 本地变量 get 1, i32.add)
]);

// 创建 WebAssembly 模块
const wasmModule = new WebAssembly.Module(wasmCode);

// 创建 WebAssembly 实例
const wasmInstance = new WebAssembly.Instance(wasmModule);

// 调用 WebAssembly 导出的函数 (对应于代码中的 i32.add 操作)
const result = wasmInstance.exports.add(5, 10);
console.log(result); // 输出: 15

// 另一个例子，涉及类型转换
const wasmCodeConvert = new Uint8Array([
  0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
  0x01, 0x07, 0x01, 0x60, 0x01, 0x7c, 0x01, 0x7f, // 定义函数签名 (f64) => i32
  0x03, 0x02, 0x01, 0x00,
  0x0a, 0x08, 0x01, 0x06, 0x00, 0x20, 0x00, 0xb7, 0x0b // 代码段 (本地变量 get 0, f64_s_convert_i32)
]);

const wasmModuleConvert = new WebAssembly.Module(wasmCodeConvert);
const wasmInstanceConvert = new WebAssembly.Instance(wasmModuleConvert);
const floatValue = 3.14;
const intResult = wasmInstanceConvert.exports.floatToInt(floatValue);
console.log(intResult); // 输出: 3 (浮点数到整数的转换)
```

**总结第 5 部分的功能:**

这部分代码是 Turboshaft 编译器将 WebAssembly 指令转换为内部图表示的核心。它详细定义了各种 WebAssembly 操作 (包括算术、类型转换、内存访问、函数调用等) 如何在 Turboshaft 图中表示，并处理了可能出现的错误和边界情况。这对于 V8 引擎执行 WebAssembly 代码至关重要。

Prompt: 
```
这是目录为v8/src/wasm/turboshaft-graph-interface.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第5部分，共6部分，请归纳一下它的功能

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
            GOTO(done, __ Int32Div(lhs, rhs));
          }
        }
        BIND(done, result);
        return result;
      }
      case kExprI32AsmjsDivU: {
        // asmjs semantics return 0 when dividing by 0.
        if (SupportedOperations::uint32_div_is_safe()) {
          return __ Uint32Div(lhs, rhs);
        }
        Label<Word32> done(&asm_);
        IF (UNLIKELY(__ Word32Equal(rhs, 0))) {
          GOTO(done, __ Word32Constant(0));
        } ELSE {
          GOTO(done, __ Uint32Div(lhs, rhs));
        }
        BIND(done, result);
        return result;
      }
      case kExprI32AsmjsRemS: {
        // General case for signed integer modulus, with optimization for
        // (unknown) power of 2 right hand side.
        //
        //   if 0 < rhs then
        //     mask = rhs - 1
        //     if rhs & mask != 0 then
        //       lhs % rhs
        //     else
        //       if lhs < 0 then
        //         -(-lhs & mask)
        //       else
        //         lhs & mask
        //   else
        //     if rhs < -1 then
        //       lhs % rhs
        //     else
        //       zero
        Label<Word32> done(&asm_);
        IF (__ Int32LessThan(0, rhs)) {
          V<Word32> mask = __ Word32Sub(rhs, 1);
          IF (__ Word32Equal(__ Word32BitwiseAnd(rhs, mask), 0)) {
            IF (UNLIKELY(__ Int32LessThan(lhs, 0))) {
              V<Word32> neg_lhs = __ Word32Sub(0, lhs);
              V<Word32> combined = __ Word32BitwiseAnd(neg_lhs, mask);
              GOTO(done, __ Word32Sub(0, combined));
            } ELSE {
              GOTO(done, __ Word32BitwiseAnd(lhs, mask));
            }
          } ELSE {
            GOTO(done, __ Int32Mod(lhs, rhs));
          }
        } ELSE {
          IF (__ Int32LessThan(rhs, -1)) {
            GOTO(done, __ Int32Mod(lhs, rhs));
          } ELSE {
            GOTO(done, __ Word32Constant(0));
          }
        }
        BIND(done, result);
        return result;
      }
      case kExprI32AsmjsRemU: {
        // asmjs semantics return 0 for mod with 0.
        Label<Word32> done(&asm_);
        IF (UNLIKELY(__ Word32Equal(rhs, 0))) {
          GOTO(done, __ Word32Constant(0));
        } ELSE {
          GOTO(done, __ Uint32Mod(lhs, rhs));
        }
        BIND(done, result);
        return result;
      }
      case kExprI32AsmjsStoreMem8:
        AsmjsStoreMem(lhs, rhs, MemoryRepresentation::Int8());
        return rhs;
      case kExprI32AsmjsStoreMem16:
        AsmjsStoreMem(lhs, rhs, MemoryRepresentation::Int16());
        return rhs;
      case kExprI32AsmjsStoreMem:
        AsmjsStoreMem(lhs, rhs, MemoryRepresentation::Int32());
        return rhs;
      case kExprF32AsmjsStoreMem:
        AsmjsStoreMem(lhs, rhs, MemoryRepresentation::Float32());
        return rhs;
      case kExprF64AsmjsStoreMem:
        AsmjsStoreMem(lhs, rhs, MemoryRepresentation::Float64());
        return rhs;
      default:
        UNREACHABLE();
    }
  }

  std::pair<V<WordPtr>, compiler::BoundsCheckResult> BoundsCheckMem(
      const wasm::WasmMemory* memory, MemoryRepresentation repr, OpIndex index,
      uintptr_t offset, compiler::EnforceBoundsCheck enforce_bounds_check,
      compiler::AlignmentCheck alignment_check) {
    // The function body decoder already validated that the access is not
    // statically OOB.
    DCHECK(base::IsInBounds(offset, static_cast<uintptr_t>(repr.SizeInBytes()),
                            memory->max_memory_size));

    wasm::BoundsCheckStrategy bounds_checks = memory->bounds_checks;
    // Convert the index to uintptr.
    // TODO(jkummerow): This should reuse MemoryAddressToUintPtrOrOOBTrap.
    V<WordPtr> converted_index = index;
    if (!memory->is_memory64()) {
      // Note: this doesn't just satisfy the compiler's internal consistency
      // checks, it's also load-bearing to prevent escaping from a compromised
      // sandbox (where in-sandbox corruption can cause the high word of
      // what's supposed to be an i32 to be non-zero).
      converted_index = __ ChangeUint32ToUintPtr(index);
    } else if (kSystemPointerSize == kInt32Size) {
      // Truncate index to 32-bit.
      converted_index = V<WordPtr>::Cast(__ TruncateWord64ToWord32(index));
    }

    const uintptr_t align_mask = repr.SizeInBytes() - 1;
    // Do alignment checks only for > 1 byte accesses (otherwise they trivially
    // pass).
    if (static_cast<bool>(alignment_check) && align_mask != 0) {
      // TODO(14108): Optimize constant index as per wasm-compiler.cc.

      // Unlike regular memory accesses, atomic memory accesses should trap if
      // the effective offset is misaligned.
      // TODO(wasm): this addition is redundant with one inserted by
      // {MemBuffer}.
      OpIndex effective_offset =
          __ WordPtrAdd(MemBuffer(memory->index, offset), converted_index);

      V<Word32> cond = __ TruncateWordPtrToWord32(__ WordPtrBitwiseAnd(
          effective_offset, __ IntPtrConstant(align_mask)));
      __ TrapIfNot(__ Word32Equal(cond, __ Word32Constant(0)),
                   TrapId::kTrapUnalignedAccess);
    }

    // If no bounds checks should be performed (for testing), just return the
    // converted index and assume it to be in-bounds.
    if (bounds_checks == wasm::kNoBoundsChecks) {
      return {converted_index, compiler::BoundsCheckResult::kInBounds};
    }

    if (memory->is_memory64() && kSystemPointerSize == kInt32Size) {
      // In memory64 mode on 32-bit systems, the upper 32 bits need to be zero
      // to succeed the bounds check.
      DCHECK_EQ(kExplicitBoundsChecks, bounds_checks);
      V<Word32> high_word =
          __ TruncateWord64ToWord32(__ Word64ShiftRightLogical(index, 32));
      __ TrapIf(high_word, TrapId::kTrapMemOutOfBounds);
    }

    uintptr_t end_offset = offset + repr.SizeInBytes() - 1u;
    DCHECK_LT(end_offset, memory->max_memory_size);

    // The index can be invalid if we are generating unreachable operations.
    if (end_offset <= memory->min_memory_size && index.valid() &&
        __ output_graph().Get(index).Is<ConstantOp>()) {
      ConstantOp& constant_index_op =
          __ output_graph().Get(index).Cast<ConstantOp>();
      uintptr_t constant_index = memory->is_memory64()
                                     ? constant_index_op.word64()
                                     : constant_index_op.word32();
      if (constant_index < memory->min_memory_size - end_offset) {
        return {converted_index, compiler::BoundsCheckResult::kInBounds};
      }
    }

#if V8_TRAP_HANDLER_SUPPORTED
    if (bounds_checks == kTrapHandler &&
        enforce_bounds_check ==
            compiler::EnforceBoundsCheck::kCanOmitBoundsCheck) {
      if (memory->is_memory64()) {
        // Bounds check `index` against `max_mem_size - end_offset`, such that
        // at runtime `index + end_offset` will be within `max_mem_size`, where
        // the trap handler can handle out-of-bound accesses.
        V<Word32> cond = __ Uint64LessThan(
            V<Word64>::Cast(converted_index),
            __ Word64Constant(uint64_t{memory->max_memory_size - end_offset}));
        __ TrapIfNot(cond, TrapId::kTrapMemOutOfBounds);
      }
      return {converted_index, compiler::BoundsCheckResult::kTrapHandler};
    }
#else
    CHECK_NE(bounds_checks, kTrapHandler);
#endif  // V8_TRAP_HANDLER_SUPPORTED

    V<WordPtr> memory_size = MemSize(memory->index);
    if (end_offset > memory->min_memory_size) {
      // The end offset is larger than the smallest memory.
      // Dynamically check the end offset against the dynamic memory size.
      __ TrapIfNot(
          __ UintPtrLessThan(__ UintPtrConstant(end_offset), memory_size),
          TrapId::kTrapMemOutOfBounds);
    }

    // This produces a positive number since {end_offset <= min_size <=
    // mem_size}.
    V<WordPtr> effective_size = __ WordPtrSub(memory_size, end_offset);
    __ TrapIfNot(__ UintPtrLessThan(converted_index, effective_size),
                 TrapId::kTrapMemOutOfBounds);
    return {converted_index, compiler::BoundsCheckResult::kDynamicallyChecked};
  }

  V<WordPtr> MemStart(uint32_t index) {
    if (index == 0) {
      // TODO(14108): Port TF's dynamic "cached_memory_index" infrastructure.
      return instance_cache_.memory0_start();
    } else {
      // TODO(14616): Fix sharedness.
      V<TrustedFixedAddressArray> instance_memories =
          LOAD_IMMUTABLE_PROTECTED_INSTANCE_FIELD(trusted_instance_data(false),
                                                  MemoryBasesAndSizes,
                                                  TrustedFixedAddressArray);
      return __ Load(instance_memories, LoadOp::Kind::TaggedBase(),
                     MemoryRepresentation::UintPtr(),
                     TrustedFixedAddressArray::OffsetOfElementAt(2 * index));
    }
  }

  V<WordPtr> MemBuffer(uint32_t mem_index, uintptr_t offset) {
    V<WordPtr> mem_start = MemStart(mem_index);
    if (offset == 0) return mem_start;
    return __ WordPtrAdd(mem_start, offset);
  }

  V<WordPtr> MemSize(uint32_t index) {
    if (index == 0) {
      // TODO(14108): Port TF's dynamic "cached_memory_index" infrastructure.
      return instance_cache_.memory0_size();
    } else {
      // TODO(14616): Fix sharedness.
      V<TrustedByteArray> instance_memories =
          LOAD_IMMUTABLE_PROTECTED_INSTANCE_FIELD(trusted_instance_data(false),
                                                  MemoryBasesAndSizes,
                                                  TrustedByteArray);
      return __ Load(
          instance_memories, LoadOp::Kind::TaggedBase().NotLoadEliminable(),
          MemoryRepresentation::UintPtr(),
          TrustedFixedAddressArray::OffsetOfElementAt(2 * index + 1));
    }
  }

  LoadOp::Kind GetMemoryAccessKind(
      MemoryRepresentation repr,
      compiler::BoundsCheckResult bounds_check_result) {
    LoadOp::Kind result;
    if (bounds_check_result == compiler::BoundsCheckResult::kTrapHandler) {
      DCHECK(repr == MemoryRepresentation::Int8() ||
             repr == MemoryRepresentation::Uint8() ||
             SupportedOperations::IsUnalignedLoadSupported(repr));
      result = LoadOp::Kind::Protected();
    } else if (repr != MemoryRepresentation::Int8() &&
               repr != MemoryRepresentation::Uint8() &&
               !SupportedOperations::IsUnalignedLoadSupported(repr)) {
      result = LoadOp::Kind::RawUnaligned();
    } else {
      result = LoadOp::Kind::RawAligned();
    }
    return result.NotLoadEliminable();
  }

  void TraceMemoryOperation(FullDecoder* decoder, bool is_store,
                            MemoryRepresentation repr, V<WordPtr> index,
                            uintptr_t offset) {
    int kAlign = 4;  // Ensure that the LSB is 0, like a Smi.
    V<WordPtr> info = __ StackSlot(sizeof(MemoryTracingInfo), kAlign);
    V<WordPtr> effective_offset = __ WordPtrAdd(index, offset);
    __ Store(info, effective_offset, StoreOp::Kind::RawAligned(),
             MemoryRepresentation::UintPtr(), compiler::kNoWriteBarrier,
             offsetof(MemoryTracingInfo, offset));
    __ Store(info, __ Word32Constant(is_store ? 1 : 0),
             StoreOp::Kind::RawAligned(), MemoryRepresentation::Uint8(),
             compiler::kNoWriteBarrier, offsetof(MemoryTracingInfo, is_store));
    V<Word32> rep_as_int = __ Word32Constant(
        static_cast<int>(repr.ToMachineType().representation()));
    __ Store(info, rep_as_int, StoreOp::Kind::RawAligned(),
             MemoryRepresentation::Uint8(), compiler::kNoWriteBarrier,
             offsetof(MemoryTracingInfo, mem_rep));
    CallRuntime(decoder->zone(), Runtime::kWasmTraceMemory, {info},
                __ NoContextConstant());
  }

  void StackCheck(WasmStackCheckOp::Kind kind, FullDecoder* decoder) {
    if (V8_UNLIKELY(!v8_flags.wasm_stack_checks)) return;
    __ WasmStackCheck(kind);
  }

 private:
  std::pair<V<WasmCodePtr>, V<HeapObject>>
  BuildImportedFunctionTargetAndImplicitArg(FullDecoder* decoder,
                                            uint32_t function_index) {
    ModuleTypeIndex sig_index =
        decoder->module_->functions[function_index].sig_index;
    bool shared = decoder->module_->type(sig_index).is_shared;
    return WasmGraphBuilderBase::BuildImportedFunctionTargetAndImplicitArg(
        function_index, trusted_instance_data(shared));
  }

  // Returns the call target and the implicit argument (WasmTrustedInstanceData
  // or WasmImportData) for an indirect call.
  std::pair<V<WasmCodePtr>, V<ExposedTrustedObject>>
  BuildIndirectCallTargetAndImplicitArg(FullDecoder* decoder,
                                        V<WordPtr> index_wordptr,
                                        CallIndirectImmediate imm,
                                        bool needs_type_or_null_check = true) {
    static_assert(kV8MaxWasmTableSize < size_t{kMaxInt});
    const WasmTable* table = imm.table_imm.table;

    /* Step 1: Load the indirect function tables for this table. */
    V<WasmDispatchTable> dispatch_table;
    if (imm.table_imm.index == 0) {
      dispatch_table =
          LOAD_PROTECTED_INSTANCE_FIELD(trusted_instance_data(table->shared),
                                        DispatchTable0, WasmDispatchTable);
    } else {
      V<ProtectedFixedArray> dispatch_tables =
          LOAD_IMMUTABLE_PROTECTED_INSTANCE_FIELD(
              trusted_instance_data(table->shared), DispatchTables,
              ProtectedFixedArray);
      dispatch_table =
          V<WasmDispatchTable>::Cast(__ LoadProtectedFixedArrayElement(
              dispatch_tables, imm.table_imm.index));
    }

    /* Step 2: Bounds check against the table size. */
    V<Word32> table_length;
    bool needs_dynamic_size =
        !table->has_maximum_size || table->maximum_size != table->initial_size;
    if (needs_dynamic_size) {
      table_length = __ LoadField<Word32>(
          dispatch_table, AccessBuilder::ForWasmDispatchTableLength());
    } else {
      table_length = __ Word32Constant(table->initial_size);
    }
    V<Word32> in_bounds = __ UintPtrLessThan(
        index_wordptr, __ ChangeUint32ToUintPtr(table_length));
    __ TrapIfNot(in_bounds, TrapId::kTrapTableOutOfBounds);

    /* Step 3: Check the canonical real signature against the canonical declared
     * signature. */
    ModuleTypeIndex sig_index = imm.sig_imm.index;
    bool needs_type_check =
        needs_type_or_null_check &&
        !EquivalentTypes(table->type.AsNonNull(), ValueType::Ref(sig_index),
                         decoder->module_, decoder->module_);
    bool needs_null_check =
        needs_type_or_null_check && table->type.is_nullable();

    V<WordPtr> dispatch_table_entry_offset = __ WordPtrAdd(
        __ WordPtrMul(index_wordptr, WasmDispatchTable::kEntrySize),
        WasmDispatchTable::kEntriesOffset);

    if (needs_type_check) {
      CanonicalTypeIndex sig_id = env_->module->canonical_sig_id(sig_index);
      V<Word32> expected_canonical_sig =
          __ RelocatableWasmCanonicalSignatureId(sig_id.index);

      V<Word32> loaded_sig =
          __ Load(dispatch_table, dispatch_table_entry_offset,
                  LoadOp::Kind::TaggedBase(), MemoryRepresentation::Uint32(),
                  WasmDispatchTable::kSigBias);
      V<Word32> sigs_match = __ Word32Equal(expected_canonical_sig, loaded_sig);
      if (!decoder->module_->type(sig_index).is_final) {
        // In this case, a full type check is needed.
        Label<> end(&asm_);

        // First, check if signatures happen to match exactly.
        GOTO_IF(sigs_match, end);

        if (needs_null_check) {
          // Trap on null element.
          __ TrapIf(__ Word32Equal(loaded_sig, -1),
                    TrapId::kTrapFuncSigMismatch);
        }
        bool shared = decoder->module_->type(sig_index).is_shared;
        V<Map> formal_rtt = __ RttCanon(managed_object_maps(shared), sig_index);
        int rtt_depth = GetSubtypingDepth(decoder->module_, sig_index);
        DCHECK_GE(rtt_depth, 0);

        // Since we have the canonical index of the real rtt, we have to load it
        // from the isolate rtt-array (which is canonically indexed). Since this
        // reference is weak, we have to promote it to a strong reference.
        // Note: The reference cannot have been cleared: Since the loaded_sig
        // corresponds to a function of the same canonical type, that function
        // will have kept the type alive.
        V<WeakFixedArray> rtts = LOAD_ROOT(WasmCanonicalRtts);
        V<Object> weak_rtt = __ Load(
            rtts, __ ChangeInt32ToIntPtr(loaded_sig),
            LoadOp::Kind::TaggedBase(), MemoryRepresentation::TaggedPointer(),
            OFFSET_OF_DATA_START(WeakFixedArray), kTaggedSizeLog2);
        V<Map> real_rtt =
            V<Map>::Cast(__ BitcastWordPtrToTagged(__ WordPtrBitwiseAnd(
                __ BitcastHeapObjectToWordPtr(V<HeapObject>::Cast(weak_rtt)),
                ~kWeakHeapObjectMask)));
        V<WasmTypeInfo> type_info =
            __ Load(real_rtt, LoadOp::Kind::TaggedBase(),
                    MemoryRepresentation::TaggedPointer(),
                    Map::kConstructorOrBackPointerOrNativeContextOffset);
        // If the depth of the rtt is known to be less than the minimum
        // supertype array length, we can access the supertype without
        // bounds-checking the supertype array.
        if (static_cast<uint32_t>(rtt_depth) >=
            wasm::kMinimumSupertypeArraySize) {
          V<Word32> supertypes_length =
              __ UntagSmi(__ Load(type_info, LoadOp::Kind::TaggedBase(),
                                  MemoryRepresentation::TaggedSigned(),
                                  WasmTypeInfo::kSupertypesLengthOffset));
          __ TrapIfNot(__ Uint32LessThan(rtt_depth, supertypes_length),
                       OpIndex::Invalid(), TrapId::kTrapFuncSigMismatch);
        }
        V<Map> maybe_match =
            __ Load(type_info, LoadOp::Kind::TaggedBase(),
                    MemoryRepresentation::TaggedPointer(),
                    WasmTypeInfo::kSupertypesOffset + kTaggedSize * rtt_depth);
        __ TrapIfNot(__ TaggedEqual(maybe_match, formal_rtt),
                     OpIndex::Invalid(), TrapId::kTrapFuncSigMismatch);
        GOTO(end);
        BIND(end);
      } else {
        // In this case, signatures must match exactly.
        __ TrapIfNot(sigs_match, TrapId::kTrapFuncSigMismatch);
      }
    } else if (needs_null_check) {
      V<Word32> loaded_sig =
          __ Load(dispatch_table, dispatch_table_entry_offset,
                  LoadOp::Kind::TaggedBase(), MemoryRepresentation::Uint32(),
                  WasmDispatchTable::kSigBias);
      __ TrapIf(__ Word32Equal(-1, loaded_sig), TrapId::kTrapFuncSigMismatch);
    }

    /* Step 4: Extract ref and target. */
    V<WasmCodePtr> target = __ Load(dispatch_table, dispatch_table_entry_offset,
                                    LoadOp::Kind::TaggedBase(),
                                    MemoryRepresentation::WasmCodePointer(),
                                    WasmDispatchTable::kTargetBias);
    V<ExposedTrustedObject> implicit_arg =
        V<ExposedTrustedObject>::Cast(__ LoadProtectedPointerField(
            dispatch_table, dispatch_table_entry_offset,
            LoadOp::Kind::TaggedBase(), WasmDispatchTable::kImplicitArgBias,
            0));

    return {target, implicit_arg};
  }

  // Load the call target and implicit arg (WasmTrustedInstanceData or
  // WasmImportData) from a function reference.
  std::pair<V<WasmCodePtr>, V<ExposedTrustedObject>>
  BuildFunctionReferenceTargetAndImplicitArg(V<WasmFuncRef> func_ref,
                                             ValueType type,
                                             uint64_t expected_sig_hash) {
    if (type.is_nullable() &&
        null_check_strategy_ == compiler::NullCheckStrategy::kExplicit) {
      func_ref = V<WasmFuncRef>::Cast(
          __ AssertNotNull(func_ref, type, TrapId::kTrapNullDereference));
    }

    LoadOp::Kind load_kind =
        type.is_nullable() && null_check_strategy_ ==
                                  compiler::NullCheckStrategy::kTrapHandler
            ? LoadOp::Kind::TrapOnNull().Immutable()
            : LoadOp::Kind::TaggedBase().Immutable();

    V<WasmInternalFunction> internal_function =
        V<WasmInternalFunction>::Cast(__ LoadTrustedPointerField(
            func_ref, load_kind, kWasmInternalFunctionIndirectPointerTag,
            WasmFuncRef::kTrustedInternalOffset));

    return BuildFunctionTargetAndImplicitArg(internal_function,
                                             expected_sig_hash);
  }

  OpIndex AnnotateResultIfReference(OpIndex result, wasm::ValueType type) {
    return type.is_object_reference()
               ? __ AnnotateWasmType(V<Object>::Cast(result), type)
               : result;
  }

  void BuildWasmCall(FullDecoder* decoder, const FunctionSig* sig,
                     V<CallTarget> callee, V<HeapObject> ref,
                     const Value args[], Value returns[],
                     CheckForException check_for_exception =
                         CheckForException::kCatchInThisFrame) {
    const TSCallDescriptor* descriptor = TSCallDescriptor::Create(
        compiler::GetWasmCallDescriptor(__ graph_zone(), sig),
        compiler::CanThrow::kYes, compiler::LazyDeoptOnThrow::kNo,
        __ graph_zone());

    SmallZoneVector<OpIndex, 16> arg_indices(sig->parameter_count() + 1,
                                             decoder->zone());
    arg_indices[0] = ref;
    for (uint32_t i = 0; i < sig->parameter_count(); i++) {
      arg_indices[i + 1] = args[i].op;
    }

    OpIndex call = CallAndMaybeCatchException(
        decoder, callee, base::VectorOf(arg_indices), descriptor,
        check_for_exception, OpEffects().CanCallAnything());

    if (sig->return_count() == 1) {
      returns[0].op = AnnotateResultIfReference(call, sig->GetReturn(0));
    } else if (sig->return_count() > 1) {
      for (uint32_t i = 0; i < sig->return_count(); i++) {
        wasm::ValueType type = sig->GetReturn(i);
        returns[i].op = AnnotateResultIfReference(
            __ Projection(call, i, RepresentationFor(type)), type);
      }
    }
    // Calls might mutate cached instance fields.
    instance_cache_.ReloadCachedMemory();
  }

 private:
  void BuildWasmMaybeReturnCall(FullDecoder* decoder, const FunctionSig* sig,
                                V<CallTarget> callee, V<HeapObject> ref,
                                const Value args[]) {
    if (mode_ == kRegular || mode_ == kInlinedTailCall) {
      const TSCallDescriptor* descriptor = TSCallDescriptor::Create(
          compiler::GetWasmCallDescriptor(__ graph_zone(), sig),
          compiler::CanThrow::kYes, compiler::LazyDeoptOnThrow::kNo,
          __ graph_zone());

      SmallZoneVector<OpIndex, 16> arg_indices(sig->parameter_count() + 1,
                                               decoder->zone_);
      arg_indices[0] = ref;
      for (uint32_t i = 0; i < sig->parameter_count(); i++) {
        arg_indices[i + 1] = args[i].op;
      }
      __ TailCall(callee, base::VectorOf(arg_indices), descriptor);
    } else {
      if (__ generating_unreachable_operations()) return;
      // This is a tail call in the inlinee, which in turn was a regular call.
      // Transform the tail call into a regular call, and return the return
      // values to the caller.
      size_t return_count = sig->return_count();
      SmallZoneVector<Value, 16> returns(return_count, decoder->zone_);
      // Since an exception in a tail call cannot be caught in this frame, we
      // should only catch exceptions in the generated call if this is a
      // recursively inlined function, and the parent frame provides a handler.
      BuildWasmCall(decoder, sig, callee, ref, args, returns.data(),
                    CheckForException::kCatchInParentFrame);
      for (size_t i = 0; i < return_count; i++) {
        return_phis_->AddInputForPhi(i, returns[i].op);
      }
      __ Goto(return_block_);
    }
  }

  template <typename Descriptor>
  std::enable_if_t<!Descriptor::kNeedsContext,
                   compiler::turboshaft::detail::index_type_for_t<
                       typename Descriptor::results_t>>
  CallBuiltinThroughJumptable(
      FullDecoder* decoder, const typename Descriptor::arguments_t& args,
      CheckForException check_for_exception = CheckForException::kNo) {
    DCHECK_NE(check_for_exception, CheckForException::kCatchInParentFrame);

    V<WordPtr> callee =
        __ RelocatableWasmBuiltinCallTarget(Descriptor::kFunction);
    auto arguments = std::apply(
        [](auto&&... as) {
          return base::SmallVector<
              OpIndex, std::tuple_size_v<typename Descriptor::arguments_t> + 1>{
              std::forward<decltype(as)>(as)...};
        },
        args);

    return CallAndMaybeCatchException(
        decoder, callee, base::VectorOf(arguments),
        Descriptor::Create(StubCallMode::kCallWasmRuntimeStub,
                           __ output_graph().graph_zone()),
        check_for_exception, Descriptor::kEffects);
  }

  template <typename Descriptor>
  std::enable_if_t<Descriptor::kNeedsContext,
                   compiler::turboshaft::detail::index_type_for_t<
                       typename Descriptor::results_t>>
  CallBuiltinThroughJumptable(
      FullDecoder* decoder, V<Context> context,
      const typename Descriptor::arguments_t& args,
      CheckForException check_for_exception = CheckForException::kNo) {
    DCHECK_NE(check_for_exception, CheckForException::kCatchInParentFrame);

    V<WordPtr> callee =
        __ RelocatableWasmBuiltinCallTarget(Descriptor::kFunction);
    auto arguments = std::apply(
        [context](auto&&... as) {
          return base::SmallVector<
              OpIndex, std::tuple_size_v<typename Descriptor::arguments_t> + 1>{
              std::forward<decltype(as)>(as)..., context};
        },
        args);

    return CallAndMaybeCatchException(
        decoder, callee, base::VectorOf(arguments),
        Descriptor::Create(StubCallMode::kCallWasmRuntimeStub,
                           __ output_graph().graph_zone()),
        check_for_exception, Descriptor::kEffects);
  }

 private:
  void MaybeSetPositionToParent(OpIndex call,
                                CheckForException check_for_exception) {
    // For tail calls that we transform to regular calls, we need to set the
    // call's position to that of the inlined call node to get correct stack
    // traces.
    if (check_for_exception == CheckForException::kCatchInParentFrame) {
      __ output_graph().operation_origins()[call] = WasmPositionToOpIndex(
          parent_position_.ScriptOffset(), parent_position_.InliningId() == -1
                                               ? kNoInliningId
                                               : parent_position_.InliningId());
    }
  }

  OpIndex CallAndMaybeCatchException(FullDecoder* decoder, V<CallTarget> callee,
                                     base::Vector<const OpIndex> args,
                                     const TSCallDescriptor* descriptor,
                                     CheckForException check_for_exception,
                                     OpEffects effects) {
    if (check_for_exception == CheckForException::kNo) {
      return __ Call(callee, OpIndex::Invalid(), args, descriptor, effects);
    }
    bool handled_in_this_frame =
        decoder && decoder->current_catch() != -1 &&
        check_for_exception == CheckForException::kCatchInThisFrame;
    if (!handled_in_this_frame && mode_ != kInlinedWithCatch) {
      OpIndex call =
          __ Call(callee, OpIndex::Invalid(), args, descriptor, effects);
      MaybeSetPositionToParent(call, check_for_exception);
      return call;
    }

    TSBlock* catch_block;
    if (handled_in_this_frame) {
      Control* current_catch =
          decoder->control_at(decoder->control_depth_of_current_catch());
      catch_block = current_catch->false_or_loop_or_catch_block;
    } else {
      DCHECK_EQ(mode_, kInlinedWithCatch);
      catch_block = return_catch_block_;
    }
    TSBlock* success_block = __ NewBlock();
    TSBlock* exception_block = __ NewBlock();
    OpIndex call;
    {
      Assembler::CatchScope scope(asm_, exception_block);

      call = __ Call(callee, OpIndex::Invalid(), args, descriptor, effects);
      __ Goto(success_block);
    }

    __ Bind(exception_block);
    OpIndex exception = __ CatchBlockBegin();
    if (handled_in_this_frame) {
      // The exceptional operation could have modified memory size; we need
      // to reload the memory context into the exceptional control path.
      instance_cache_.ReloadCachedMemory();
      SetupControlFlowEdge(decoder, catch_block, 0, exception);
    } else {
      DCHECK_EQ(mode_, kInlinedWithCatch);
      if (exception.valid()) return_phis_->AddIncomingException(exception);
      // Reloading the InstanceCache will happen when {return_exception_phis_}
      // are retrieved.
    }
    __ Goto(catch_block);

    __ Bind(success_block);

    MaybeSetPositionToParent(call, check_for_exception);

    return call;
  }

  OpIndex CallCStackSlotToInt32(OpIndex arg, ExternalReference ref,
                                MemoryRepresentation arg_type) {
    OpIndex stack_slot_param =
        __ StackSlot(arg_type.SizeInBytes(), arg_type.SizeInBytes());
    __ Store(stack_slot_param, arg, StoreOp::Kind::RawAligned(), arg_type,
             compiler::WriteBarrierKind::kNoWriteBarrier);
    MachineType reps[]{MachineType::Int32(), MachineType::Pointer()};
    MachineSignature sig(1, 1, reps);
    return CallC(&sig, ref, stack_slot_param);
  }

  V<Word32> CallCStackSlotToInt32(
      ExternalReference ref,
      std::initializer_list<std::pair<OpIndex, MemoryRepresentation>> args) {
    int slot_size = 0;
    for (auto arg : args) slot_size += arg.second.SizeInBytes();
    // Since we are storing the arguments unaligned anyway, we do not need
    // alignment > 0.
    V<WordPtr> stack_slot_param = __ StackSlot(slot_size, 0);
    int offset = 0;
    for (auto arg : args) {
      __ Store(stack_slot_param, arg.first,
               StoreOp::Kind::MaybeUnaligned(arg.second), arg.second,
               compiler::WriteBarrierKind::kNoWriteBarrier, offset);
      offset += arg.second.SizeInBytes();
    }
    MachineType reps[]{MachineType::Int32(), MachineType::Pointer()};
    MachineSignature sig(1, 1, reps);
    return CallC(&sig, ref, stack_slot_param);
  }

  OpIndex CallCStackSlotToStackSlot(
      ExternalReference ref, MemoryRepresentation res_type,
      std::initializer_list<std::pair<OpIndex, MemoryRepresentation>> args) {
    int slot_size = 0;
    for (auto arg : args) slot_size += arg.second.SizeInBytes();
    // Since we are storing the arguments unaligned anyway, we do not need
    // alignment > 0.
    slot_size = std::max<int>(slot_size, res_type.SizeInBytes());
    V<WordPtr> stack_slot_param = __ StackSlot(slot_size, 0);
    int offset = 0;
    for (auto arg : args) {
      __ Store(stack_slot_param, arg.first,
               StoreOp::Kind::MaybeUnaligned(arg.second), arg.second,
               compiler::WriteBarrierKind::kNoWriteBarrier, offset);
      offset += arg.second.SizeInBytes();
    }
    MachineType reps[]{MachineType::Pointer()};
    MachineSignature sig(0, 1, reps);
    CallC(&sig, ref, stack_slot_param);
    return __ Load(stack_slot_param, LoadOp::Kind::RawAligned(), res_type);
  }

  OpIndex CallCStackSlotToStackSlot(OpIndex arg, ExternalReference ref,
                                    MemoryRepresentation arg_type) {
    return CallCStackSlotToStackSlot(arg, ref, arg_type, arg_type);
  }

  OpIndex CallCStackSlotToStackSlot(OpIndex arg, ExternalReference ref,
                                    MemoryRepresentation arg_type,
                                    MemoryRepresentation res_type) {
    return CallCStackSlotToStackSlot(ref, res_type, {{arg, arg_type}});
  }

  OpIndex CallCStackSlotToStackSlot(OpIndex arg0, OpIndex arg1,
                                    ExternalReference ref,
                                    MemoryRepresentation arg_type) {
    return CallCStackSlotToStackSlot(ref, arg_type,
                                     {{arg0, arg_type}, {arg1, arg_type}});
  }

  V<WordPtr> MemOrTableAddressToUintPtrOrOOBTrap(AddressType address_type,
                                                 V<Word> index,
                                                 TrapId trap_reason) {
    // Note: this {ChangeUint32ToUintPtr} doesn't just satisfy the compiler's
    // consistency checks, it's also load-bearing to prevent escaping from a
    // compromised sandbox (where in-sandbox corruption
"""


```