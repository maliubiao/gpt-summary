Response:
My thinking process to analyze the provided C++ code snippet goes like this:

1. **Identify the Language:** The code uses syntax common to C++, like `namespace`, `switch`, `case`, `class`, `Node*`, etc. The inclusion of `wasm::` suggests it's related to WebAssembly within the V8 JavaScript engine.

2. **Locate the File Path:** The prompt mentions `v8/src/compiler/wasm-compiler.cc`. This immediately tells me the code is part of V8's compiler and specifically deals with WebAssembly compilation. The `.cc` extension confirms it's a C++ source file. The prompt explicitly states it's *not* a Torque (`.tq`) file, so I can disregard that possibility.

3. **Scan for Key Class/Function Names:** I look for prominent names. `WasmGraphBuilder` appears frequently, suggesting it's a central class responsible for building a graph representation of WebAssembly code. Functions like `BuildIntConvertFloat`, `BuildI32Ctz`, `BuildF64Trunc`, `MemoryGrow`, `Throw`, `Rethrow`, and the various `BuildI32...` operations stand out as likely implementing specific WebAssembly instructions.

4. **Analyze Function Signatures and Bodies:**  I examine the parameters and return types of the functions. Many functions return `Node*`, which reinforces the idea of building a graph structure. The parameters often include `Node* input`, `wasm::WasmOpcode opcode`, and `wasm::WasmCodePosition position`. This confirms the connection to WebAssembly operations and their locations in the source.

5. **Look for Specific WebAssembly Operations:** I recognize patterns related to common WebAssembly instructions:
    * **Conversions:** `BuildIntConvertFloat`, `BuildF32SConvertI64`, `BuildCcallConvertFloat`. These deal with converting between integer and floating-point types.
    * **Bit Manipulation:** `BuildI32Ctz`, `BuildI64Ctz`, `BuildI32Popcnt`, `BuildI64Popcnt`. These handle bit counting and trailing zeros.
    * **Floating-Point Functions:** `BuildF32Trunc`, `BuildF32Floor`, `BuildF64Acos`, `BuildF64Pow`. These implement standard math functions.
    * **Memory Operations:** `MemoryGrow`. This handles increasing the size of the WebAssembly memory.
    * **Exception Handling:** `Throw`, `Rethrow`, `IsExceptionTagUndefined`, `GetExceptionTag`, `GetExceptionValues`. These implement WebAssembly's exception handling mechanism.
    * **Integer Arithmetic:** `BuildI32DivS`, `BuildI32RemS`, `BuildI32DivU`, `BuildI32RemU`, and their `Asmjs` variants. These are for integer division and remainder operations.

6. **Identify Helper Functions and Data Structures:**  Names like `ConvertOp`, `TruncOp`, `NeOp`, `ConvertTrapTest`, `ConvertSaturateTest`, `ExternalReference`, `MachineType`, `Diamond`, and `gasm_` (likely a pointer to a `GraphAssembler`) suggest supporting functionalities for graph construction and low-level operations.

7. **Infer the Overall Purpose:** Based on the identified operations and the class name, I conclude that `wasm-compiler.cc` (specifically the `WasmGraphBuilder` class) is responsible for translating WebAssembly bytecode into an intermediate representation (the "graph") that V8's optimizing compiler can then process.

8. **Consider JavaScript Relevance:** The presence of `Asmjs` versions of some integer arithmetic functions (`BuildI32AsmjsDivS`, `BuildI32AsmjsRemS`, `BuildI32AsmjsDivU`) indicates a connection to asm.js, a strict subset of JavaScript that served as a precursor to WebAssembly. This hints at the historical context and the integration of WebAssembly into the JavaScript environment.

9. **Look for Potential Programming Errors:** The code includes explicit checks for division by zero (`ZeroCheck32`) and unrepresentable values during conversions (`TrapIfTrue`, `ZeroCheck64`). This suggests common errors that can occur when working with these operations.

10. **Address Specific Questions:**  I then systematically go through the questions in the prompt:
    * **Functionality:** Summarize the identified operations.
    * **Torque:** Confirm it's not a Torque file based on the extension.
    * **JavaScript Relation:** Explain the connection to asm.js and provide JavaScript examples (even if indirectly related, as direct JavaScript equivalents for low-level WebAssembly operations are less common).
    * **Code Logic Inference:** Choose a representative function (like `BuildIntConvertFloat`) and trace its logic with hypothetical inputs and outputs.
    * **Common Errors:**  Use the built-in checks as clues to illustrate common programming errors.
    * **Summary (Part 3 of 12):** Since this is part 3, I would infer that previous parts likely dealt with earlier stages of WebAssembly compilation (parsing, validation), and later parts will handle optimization, code generation, etc. Therefore, part 3 likely focuses on the core translation to the graph representation.

By following these steps, I can effectively analyze the provided code snippet and provide a comprehensive answer to the prompt's questions.
这是v8/src/compiler/wasm-compiler.cc的第三部分源代码，主要集中在 **WebAssembly 指令的图构建 (Graph Building)** 阶段。它定义了 `WasmGraphBuilder` 类中的许多方法，这些方法负责将 WebAssembly 的操作码转换为 V8 编译器内部的图节点表示。

以下是代码片段功能的详细归纳：

**核心功能：将 WebAssembly 指令转换为图节点**

这段代码的核心职责是为各种 WebAssembly 指令生成相应的图节点。`WasmGraphBuilder` 类提供了构建这些节点的工具和方法。

**具体功能点：**

1. **类型转换 (Type Conversion)：**
   - `BuildIntConvertFloat`: 处理浮点数到整数的转换，包括有符号和无符号，以及截断和饱和转换。
   - `BuildCcallConvertFloat`: 使用 C 函数调用进行浮点数到整数的转换（例如，对于超出硬件指令直接支持的范围）。
   - `BuildF32SConvertI64`, `BuildF32UConvertI64`, `BuildF64SConvertI64`, `BuildF64UConvertI64`: 处理整数到浮点数的转换。
   - 提供 `BuildI32AsmjsSConvertF32` 等方法，专门处理 asm.js 风格的类型转换（具有不同的语义）。

2. **位操作 (Bit Manipulation)：**
   - `BuildI32Ctz`, `BuildI64Ctz`: 计算尾部零的个数 (count trailing zeros)。
   - `BuildI32Popcnt`, `BuildI64Popcnt`: 计算 popcount (population count，即二进制表示中 1 的个数)。
   - 这些方法可能会根据目标架构（32 位或 64 位）选择不同的实现方式。

3. **数学函数 (Math Functions)：**
   - `BuildF32Trunc`, `BuildF32Floor`, `BuildF32Ceil`, `BuildF32NearestInt`:  处理 `float32` 类型的截断、向下取整、向上取整和四舍五入到最接近的整数。
   - `BuildF64Trunc`, `BuildF64Floor`, `BuildF64Ceil`, `BuildF64NearestInt`: 处理 `float64` 类型的相应操作。
   - `BuildF64Acos`, `BuildF64Asin`, `BuildF64Pow`, `BuildF64Mod`: 处理 `float64` 类型的反余弦、反正弦、幂运算和取模运算。
   - 这些方法通常会调用 C 函数库来实现这些复杂的数学运算。

4. **内存操作 (Memory Operation)：**
   - `MemoryGrow`: 处理 WebAssembly 内存增长的操作。

5. **异常处理 (Exception Handling)：**
   - `Throw`:  生成抛出异常的图节点。
   - `Rethrow`: 生成重新抛出异常的图节点。
   - `ThrowRef`: 生成抛出引用类型异常的图节点。
   - `IsExceptionTagUndefined`, `ExceptionTagEqual`:  检查异常标签是否未定义或相等。
   - `LoadJSTag`, `LoadTagFromTable`: 加载异常标签。
   - `GetExceptionTag`, `GetExceptionValues`:  获取异常对象的标签和值。
   - `BuildEncodeException32BitValue`, `BuildDecodeException32BitValue`, `BuildDecodeException64BitValue`:  用于编码和解码异常值的辅助方法。

6. **整数运算 (Integer Arithmetic)：**
   - `BuildI32DivS`, `BuildI32RemS`, `BuildI32DivU`, `BuildI32RemU`: 处理有符号和无符号的 32 位整数除法和取模运算。
   - `BuildI32AsmjsDivS`, `BuildI32AsmjsRemS`, `BuildI32AsmjsDivU`:  专门处理 asm.js 风格的整数除法和取模运算（具有不同的语义，例如除零行为）。

**如果 v8/src/compiler/wasm-compiler.cc 以 .tq 结尾：**

如果文件以 `.tq` 结尾，那它将是一个 **V8 Torque 源代码**。Torque 是一种 V8 特有的领域特定语言，用于定义 V8 内部函数的运行时调用。`.tq` 文件通常用于实现 V8 的内置函数和运行时代码，提供类型安全和更易于维护的代码。  然而，根据你的描述，这个文件是 `.cc`，所以它是 C++ 代码。

**与 JavaScript 的关系：**

这段代码直接参与了 WebAssembly 在 V8 中的执行。当 JavaScript 代码调用 WebAssembly 模块时，V8 会解析 WebAssembly 字节码，并使用 `wasm-compiler.cc` 中的代码将其转换为 V8 内部的图表示，以便进行优化和最终的机器码生成。

**JavaScript 示例：**

```javascript
// 假设我们有一个编译好的 WebAssembly 模块实例
const wasmModule = new WebAssembly.Instance(compiledWasmModule);

// 调用 WebAssembly 模块中的一个函数，该函数可能包含一些需要这里代码处理的操作
const result = wasmModule.exports.myFunction(10.5);

console.log(result);
```

在这个例子中，当 `wasmModule.exports.myFunction(10.5)` 被调用时，如果 `myFunction` 的实现涉及到浮点数到整数的转换、位操作、数学运算或异常处理等，那么 `v8/src/compiler/wasm-compiler.cc` 中的相应代码（就像你提供的片段）就会被 V8 编译器的 WebAssembly 支持部分调用，以生成执行这些操作的图节点。

**代码逻辑推理：**

**假设输入：**
- `WasmGraphBuilder` 的一个实例 `builder`
- 一个表示 WebAssembly `f32.convert_s/i32` 指令的操作码 `wasm::kExprI32SConvertF32`
- 一个表示浮点数 `3.14` 的图节点 `input_float`

**预期输出：**
- 一个表示将 `input_float` 转换为有符号 32 位整数的图节点 `output_int`

**代码逻辑 (基于 `BuildIntConvertFloat` 函数)：**

1. 根据操作码 `wasm::kExprI32SConvertF32`，确定目标整数类型是 `MachineType::Int32()`，浮点数类型是 `MachineType::Float32()`。
2. 获取相应的转换操作符 `conv_op`。
3. 由于目标是 `int32`，会先执行截断操作 `TruncOp(float_ty)`，生成一个表示截断后浮点数的节点 `trunc`。
4. 创建一个新的图节点 `converted_value`，使用 `conv_op` 将 `trunc` 转换为整数。
5. 检查 `IsTrappingConvertOp(opcode)`，如果转换可能会导致陷阱（例如，浮点数超出整数范围），则会插入陷阱检查。
6. 由于代码片段中没有显式的陷阱处理，假设 `IsTrappingConvertOp` 返回 true，则会调用 `ConvertTrapTest` 来生成一个测试节点 `test`，用于检查转换是否成功。
7. `TrapIfTrue` 会根据 `test` 的结果，如果转换失败则抛出 `wasm::kTrapFloatUnrepresentable` 异常。
8. 最终返回表示转换结果的 `converted_value` 节点。

**涉及用户常见的编程错误：**

1. **浮点数到整数转换溢出或精度丢失：**
   - **错误示例 (JavaScript / WebAssembly):**
     ```javascript
     // WebAssembly 代码 (text format)
     (module
       (func (export "convert") (param f32) (result i32)
         f32.convert_s/i32))

     // JavaScript
     const wasmModule = ...;
     const convertFunc = wasmModule.exports.convert;
     console.log(convertFunc(1e10)); // 浮点数远大于 i32 的最大值
     ```
   - **`wasm-compiler.cc` 的处理：**  `BuildIntConvertFloat` 中的陷阱检查机制（`TrapIfTrue` 或 `ZeroCheck64`）旨在捕获这类错误，并在 WebAssembly 运行时抛出异常。

2. **除零错误：**
   - **错误示例 (JavaScript / WebAssembly):**
     ```javascript
     // WebAssembly 代码
     (module
       (func (export "divide") (param i32 i32) (result i32)
         local.get 0
         local.get 1
         i32.div_s))

     // JavaScript
     const wasmModule = ...;
     const divideFunc = wasmModule.exports.divide;
     console.log(divideFunc(10, 0));
     ```
   - **`wasm-compiler.cc` 的处理：** `BuildI32DivS` 和 `BuildI32RemS` 函数中的 `ZeroCheck32` 会在除法或取模运算前检查除数是否为零，如果为零则会触发 `wasm::kTrapDivByZero` 或 `wasm::kTrapRemByZero` 陷阱。

**归纳一下它的功能（第 3 部分，共 12 部分）：**

作为 WebAssembly 编译过程的第三部分，这段代码的核心功能是将 WebAssembly 的 **操作码 (opcodes)** 转换为 V8 编译器内部的 **图节点 (graph nodes)**。这个阶段是至关重要的，因为它将高级的 WebAssembly 指令转换为 V8 编译器可以理解和优化的中间表示。

可以推断，在它之前的部分（第 1 和第 2 部分）可能涉及 WebAssembly 模块的解析、验证和初步处理。而在它之后的部分（第 4 到第 12 部分）很可能会涉及图的优化、机器码生成、以及其他与 WebAssembly 执行相关的任务。

总而言之，这部分代码负责 **WebAssembly 到 V8 图表示的转换**，为后续的编译优化和代码生成奠定了基础。它涵盖了各种 WebAssembly 指令，包括类型转换、位操作、数学函数、内存操作、异常处理和整数运算，并考虑了潜在的编程错误，例如除零和类型转换溢出。

### 提示词
```
这是目录为v8/src/compiler/wasm-compiler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/wasm-compiler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共12部分，请归纳一下它的功能
```

### 源代码
```cpp
4Ne;
    default:
      UNREACHABLE();
  }
}

wasm::WasmOpcode LtOp(const MachineType& ty) {
  switch (ty.representation()) {
    case MachineRepresentation::kFloat32:
      return wasm::kExprF32Lt;
    case MachineRepresentation::kFloat64:
      return wasm::kExprF64Lt;
    default:
      UNREACHABLE();
  }
}

Node* ConvertTrapTest(WasmGraphBuilder* builder, wasm::WasmOpcode opcode,
                      const MachineType& int_ty, const MachineType& float_ty,
                      Node* trunc, Node* converted_value) {
  if (int_ty.representation() == MachineRepresentation::kWord32) {
    Node* check = builder->Unop(ConvertBackOp(opcode), converted_value);
    return builder->Binop(NeOp(float_ty), trunc, check);
  }
  return builder->graph()->NewNode(builder->mcgraph()->common()->Projection(1),
                                   trunc, builder->graph()->start());
}

Node* ConvertSaturateTest(WasmGraphBuilder* builder, wasm::WasmOpcode opcode,
                          const MachineType& int_ty,
                          const MachineType& float_ty, Node* trunc,
                          Node* converted_value) {
  Node* test = ConvertTrapTest(builder, opcode, int_ty, float_ty, trunc,
                               converted_value);
  if (int_ty.representation() == MachineRepresentation::kWord64) {
    test = builder->Binop(wasm::kExprI64Eq, test, builder->Int64Constant(0));
  }
  return test;
}

}  // namespace

Node* WasmGraphBuilder::BuildIntConvertFloat(Node* input,
                                             wasm::WasmCodePosition position,
                                             wasm::WasmOpcode opcode) {
  const MachineType int_ty = IntConvertType(opcode);
  const MachineType float_ty = FloatConvertType(opcode);
  const Operator* conv_op = ConvertOp(this, opcode);
  Node* trunc = nullptr;
  Node* converted_value = nullptr;
  const bool is_int32 =
      int_ty.representation() == MachineRepresentation::kWord32;
  if (is_int32) {
    trunc = Unop(TruncOp(float_ty), input);
    converted_value = graph()->NewNode(conv_op, trunc);
  } else {
    trunc = graph()->NewNode(conv_op, input);
    converted_value = graph()->NewNode(mcgraph()->common()->Projection(0),
                                       trunc, graph()->start());
  }
  if (IsTrappingConvertOp(opcode)) {
    Node* test =
        ConvertTrapTest(this, opcode, int_ty, float_ty, trunc, converted_value);
    if (is_int32) {
      TrapIfTrue(wasm::kTrapFloatUnrepresentable, test, position);
    } else {
      ZeroCheck64(wasm::kTrapFloatUnrepresentable, test, position);
    }
    return converted_value;
  }
  if (mcgraph()->machine()->SatConversionIsSafe()) {
    return converted_value;
  }
  Node* test = ConvertSaturateTest(this, opcode, int_ty, float_ty, trunc,
                                   converted_value);
  Diamond tl_d(graph(), mcgraph()->common(), test, BranchHint::kFalse);
  tl_d.Chain(control());
  Node* nan_test = Binop(NeOp(float_ty), input, input);
  Diamond nan_d(graph(), mcgraph()->common(), nan_test, BranchHint::kFalse);
  nan_d.Nest(tl_d, true);
  Node* neg_test = Binop(LtOp(float_ty), input, Zero(this, float_ty));
  Diamond sat_d(graph(), mcgraph()->common(), neg_test, BranchHint::kNone);
  sat_d.Nest(nan_d, false);
  Node* sat_val =
      sat_d.Phi(int_ty.representation(), Min(this, int_ty), Max(this, int_ty));
  Node* nan_val =
      nan_d.Phi(int_ty.representation(), Zero(this, int_ty), sat_val);
  SetControl(tl_d.merge);
  return tl_d.Phi(int_ty.representation(), nan_val, converted_value);
}

Node* WasmGraphBuilder::BuildI32AsmjsSConvertF32(Node* input) {
  // asm.js must use the wacky JS semantics.
  return gasm_->TruncateFloat64ToWord32(gasm_->ChangeFloat32ToFloat64(input));
}

Node* WasmGraphBuilder::BuildI32AsmjsSConvertF64(Node* input) {
  // asm.js must use the wacky JS semantics.
  return gasm_->TruncateFloat64ToWord32(input);
}

Node* WasmGraphBuilder::BuildI32AsmjsUConvertF32(Node* input) {
  // asm.js must use the wacky JS semantics.
  return gasm_->TruncateFloat64ToWord32(gasm_->ChangeFloat32ToFloat64(input));
}

Node* WasmGraphBuilder::BuildI32AsmjsUConvertF64(Node* input) {
  // asm.js must use the wacky JS semantics.
  return gasm_->TruncateFloat64ToWord32(input);
}

Node* WasmGraphBuilder::BuildBitCountingCall(Node* input, ExternalReference ref,
                                             MachineRepresentation input_type) {
  auto sig = FixedSizeSignature<MachineType>::Returns(MachineType::Int32())
                 .Params(MachineType::TypeForRepresentation(input_type, false));
  return BuildCCall(&sig, gasm_->ExternalConstant(ref), input);
}

Node* WasmGraphBuilder::BuildI32Ctz(Node* input) {
  return BuildBitCountingCall(input, ExternalReference::wasm_word32_ctz(),
                              MachineRepresentation::kWord32);
}

Node* WasmGraphBuilder::BuildI64Ctz(Node* input) {
  if (mcgraph()->machine()->Is32()) {
    Node* upper_word = gasm_->TruncateInt64ToInt32(
        Binop(wasm::kExprI64ShrU, input, Int64Constant(32)));
    Node* lower_word = gasm_->TruncateInt64ToInt32(input);
    // return lower_word == 0 ? 32 + CTZ32(upper_word) : CTZ32(lower_word);
    // Build control flow because Word32Select is not always available.
    Diamond d{graph(), mcgraph()->common(),
              gasm_->Word32Equal(lower_word, gasm_->Uint32Constant(0))};
    d.Chain(control());
    Node* original_effect = gasm_->effect();
    // Build the path that uses the upper word.
    SetControl(d.if_true);
    Node* result_from_upper = gasm_->Int32Add(
        BuildBitCountingCall(upper_word, ExternalReference::wasm_word32_ctz(),
                             MachineRepresentation::kWord32),
        gasm_->Int32Constant(32));
    Node* effect_after_upper = gasm_->effect();
    // Build the path that uses the lower word.
    SetEffectControl(original_effect, d.if_false);
    Node* result_from_lower =
        BuildBitCountingCall(lower_word, ExternalReference::wasm_word32_ctz(),
                             MachineRepresentation::kWord32);
    Node* effect_after_lower = gasm_->effect();
    // Merge the two paths.
    Node* ephi = d.EffectPhi(effect_after_upper, effect_after_lower);
    SetEffectControl(ephi, d.merge);
    Node* result_32 = d.Phi(MachineRepresentation::kWord32, result_from_upper,
                            result_from_lower);
    return gasm_->ChangeUint32ToUint64(result_32);
  }
  return gasm_->ChangeUint32ToUint64(
      BuildBitCountingCall(input, ExternalReference::wasm_word64_ctz(),
                           MachineRepresentation::kWord64));
}

Node* WasmGraphBuilder::BuildI32Popcnt(Node* input) {
  return BuildBitCountingCall(input, ExternalReference::wasm_word32_popcnt(),
                              MachineRepresentation::kWord32);
}

Node* WasmGraphBuilder::BuildI64Popcnt(Node* input) {
  if (mcgraph()->machine()->Is32()) {
    // Emit two calls to wasm_word32_popcnt.
    Node* upper_word = gasm_->TruncateInt64ToInt32(
        Binop(wasm::kExprI64ShrU, input, Int64Constant(32)));
    Node* lower_word = gasm_->TruncateInt64ToInt32(input);
    return gasm_->ChangeUint32ToUint64(gasm_->Int32Add(
        BuildBitCountingCall(lower_word,
                             ExternalReference::wasm_word32_popcnt(),
                             MachineRepresentation::kWord32),
        BuildBitCountingCall(upper_word,
                             ExternalReference::wasm_word32_popcnt(),
                             MachineRepresentation::kWord32)));
  }
  return gasm_->ChangeUint32ToUint64(
      BuildBitCountingCall(input, ExternalReference::wasm_word64_popcnt(),
                           MachineRepresentation::kWord64));
}

Node* WasmGraphBuilder::BuildF32Trunc(Node* input) {
  MachineType type = MachineType::Float32();
  ExternalReference ref = ExternalReference::wasm_f32_trunc();

  return BuildCFuncInstruction(ref, type, input);
}

Node* WasmGraphBuilder::BuildF32Floor(Node* input) {
  MachineType type = MachineType::Float32();
  ExternalReference ref = ExternalReference::wasm_f32_floor();
  return BuildCFuncInstruction(ref, type, input);
}

Node* WasmGraphBuilder::BuildF32Ceil(Node* input) {
  MachineType type = MachineType::Float32();
  ExternalReference ref = ExternalReference::wasm_f32_ceil();
  return BuildCFuncInstruction(ref, type, input);
}

Node* WasmGraphBuilder::BuildF32NearestInt(Node* input) {
  MachineType type = MachineType::Float32();
  ExternalReference ref = ExternalReference::wasm_f32_nearest_int();
  return BuildCFuncInstruction(ref, type, input);
}

Node* WasmGraphBuilder::BuildF64Trunc(Node* input) {
  MachineType type = MachineType::Float64();
  ExternalReference ref = ExternalReference::wasm_f64_trunc();
  return BuildCFuncInstruction(ref, type, input);
}

Node* WasmGraphBuilder::BuildF64Floor(Node* input) {
  MachineType type = MachineType::Float64();
  ExternalReference ref = ExternalReference::wasm_f64_floor();
  return BuildCFuncInstruction(ref, type, input);
}

Node* WasmGraphBuilder::BuildF64Ceil(Node* input) {
  MachineType type = MachineType::Float64();
  ExternalReference ref = ExternalReference::wasm_f64_ceil();
  return BuildCFuncInstruction(ref, type, input);
}

Node* WasmGraphBuilder::BuildF64NearestInt(Node* input) {
  MachineType type = MachineType::Float64();
  ExternalReference ref = ExternalReference::wasm_f64_nearest_int();
  return BuildCFuncInstruction(ref, type, input);
}

Node* WasmGraphBuilder::BuildF64Acos(Node* input) {
  MachineType type = MachineType::Float64();
  ExternalReference ref = ExternalReference::f64_acos_wrapper_function();
  return BuildCFuncInstruction(ref, type, input);
}

Node* WasmGraphBuilder::BuildF64Asin(Node* input) {
  MachineType type = MachineType::Float64();
  ExternalReference ref = ExternalReference::f64_asin_wrapper_function();
  return BuildCFuncInstruction(ref, type, input);
}

Node* WasmGraphBuilder::BuildF64Pow(Node* left, Node* right) {
  MachineType type = MachineType::Float64();
  ExternalReference ref = ExternalReference::wasm_float64_pow();
  return BuildCFuncInstruction(ref, type, left, right);
}

Node* WasmGraphBuilder::BuildF64Mod(Node* left, Node* right) {
  MachineType type = MachineType::Float64();
  ExternalReference ref = ExternalReference::f64_mod_wrapper_function();
  return BuildCFuncInstruction(ref, type, left, right);
}

Node* WasmGraphBuilder::BuildCFuncInstruction(ExternalReference ref,
                                              MachineType type, Node* input0,
                                              Node* input1) {
  // We do truncation by calling a C function which calculates the result.
  // The input is passed to the C function as a byte buffer holding the two
  // input doubles. We reserve this byte buffer as a stack slot, store the
  // parameters in this buffer slots, pass a pointer to the buffer to the C
  // function, and after calling the C function we collect the return value from
  // the buffer.
  Node* stack_slot;
  if (input1) {
    stack_slot = StoreArgsInStackSlot(
        {{type.representation(), input0}, {type.representation(), input1}});
  } else {
    stack_slot = StoreArgsInStackSlot({{type.representation(), input0}});
  }

  MachineType sig_types[] = {MachineType::Pointer()};
  MachineSignature sig(0, 1, sig_types);
  Node* function = gasm_->ExternalConstant(ref);
  BuildCCall(&sig, function, stack_slot);

  return gasm_->LoadFromObject(type, stack_slot, 0);
}

Node* WasmGraphBuilder::BuildF32SConvertI64(Node* input) {
  // TODO(titzer/bradnelson): Check handlng of asm.js case.
  return BuildIntToFloatConversionInstruction(
      input, ExternalReference::wasm_int64_to_float32(),
      MachineRepresentation::kWord64, MachineType::Float32());
}
Node* WasmGraphBuilder::BuildF32UConvertI64(Node* input) {
  // TODO(titzer/bradnelson): Check handlng of asm.js case.
  return BuildIntToFloatConversionInstruction(
      input, ExternalReference::wasm_uint64_to_float32(),
      MachineRepresentation::kWord64, MachineType::Float32());
}
Node* WasmGraphBuilder::BuildF64SConvertI64(Node* input) {
  return BuildIntToFloatConversionInstruction(
      input, ExternalReference::wasm_int64_to_float64(),
      MachineRepresentation::kWord64, MachineType::Float64());
}
Node* WasmGraphBuilder::BuildF64UConvertI64(Node* input) {
  return BuildIntToFloatConversionInstruction(
      input, ExternalReference::wasm_uint64_to_float64(),
      MachineRepresentation::kWord64, MachineType::Float64());
}

Node* WasmGraphBuilder::BuildIntToFloatConversionInstruction(
    Node* input, ExternalReference ref,
    MachineRepresentation parameter_representation,
    const MachineType result_type) {
  int stack_slot_size =
      std::max(ElementSizeInBytes(parameter_representation),
               ElementSizeInBytes(result_type.representation()));
  Node* stack_slot =
      graph()->NewNode(mcgraph()->machine()->StackSlot(stack_slot_size));
  auto store_rep =
      StoreRepresentation(parameter_representation, kNoWriteBarrier);
  gasm_->Store(store_rep, stack_slot, 0, input);
  MachineType sig_types[] = {MachineType::Pointer()};
  MachineSignature sig(0, 1, sig_types);
  Node* function = gasm_->ExternalConstant(ref);
  BuildCCall(&sig, function, stack_slot);
  return gasm_->LoadFromObject(result_type, stack_slot, 0);
}

namespace {

ExternalReference convert_ccall_ref(wasm::WasmOpcode opcode) {
  switch (opcode) {
    case wasm::kExprI64SConvertF32:
    case wasm::kExprI64SConvertSatF32:
      return ExternalReference::wasm_float32_to_int64();
    case wasm::kExprI64UConvertF32:
    case wasm::kExprI64UConvertSatF32:
      return ExternalReference::wasm_float32_to_uint64();
    case wasm::kExprI64SConvertF64:
    case wasm::kExprI64SConvertSatF64:
      return ExternalReference::wasm_float64_to_int64();
    case wasm::kExprI64UConvertF64:
    case wasm::kExprI64UConvertSatF64:
      return ExternalReference::wasm_float64_to_uint64();
    default:
      UNREACHABLE();
  }
}

}  // namespace

Node* WasmGraphBuilder::BuildCcallConvertFloat(Node* input,
                                               wasm::WasmCodePosition position,
                                               wasm::WasmOpcode opcode) {
  const MachineType int_ty = IntConvertType(opcode);
  const MachineType float_ty = FloatConvertType(opcode);
  ExternalReference call_ref = convert_ccall_ref(opcode);
  int stack_slot_size = std::max(ElementSizeInBytes(int_ty.representation()),
                                 ElementSizeInBytes(float_ty.representation()));
  Node* stack_slot =
      graph()->NewNode(mcgraph()->machine()->StackSlot(stack_slot_size));
  auto store_rep =
      StoreRepresentation(float_ty.representation(), kNoWriteBarrier);
  gasm_->Store(store_rep, stack_slot, 0, input);
  MachineType sig_types[] = {MachineType::Int32(), MachineType::Pointer()};
  MachineSignature sig(1, 1, sig_types);
  Node* function = gasm_->ExternalConstant(call_ref);
  Node* overflow = BuildCCall(&sig, function, stack_slot);
  if (IsTrappingConvertOp(opcode)) {
    ZeroCheck32(wasm::kTrapFloatUnrepresentable, overflow, position);
    return gasm_->LoadFromObject(int_ty, stack_slot, 0);
  }
  Node* test = Binop(wasm::kExprI32Eq, overflow, Int32Constant(0), position);
  Diamond tl_d(graph(), mcgraph()->common(), test, BranchHint::kFalse);
  tl_d.Chain(control());
  Node* nan_test = Binop(NeOp(float_ty), input, input);
  Diamond nan_d(graph(), mcgraph()->common(), nan_test, BranchHint::kFalse);
  nan_d.Nest(tl_d, true);
  Node* neg_test = Binop(LtOp(float_ty), input, Zero(this, float_ty));
  Diamond sat_d(graph(), mcgraph()->common(), neg_test, BranchHint::kNone);
  sat_d.Nest(nan_d, false);
  Node* sat_val =
      sat_d.Phi(int_ty.representation(), Min(this, int_ty), Max(this, int_ty));
  Node* load = gasm_->LoadFromObject(int_ty, stack_slot, 0);
  Node* nan_val =
      nan_d.Phi(int_ty.representation(), Zero(this, int_ty), sat_val);
  return tl_d.Phi(int_ty.representation(), nan_val, load);
}

Node* WasmGraphBuilder::MemoryGrow(const wasm::WasmMemory* memory,
                                   Node* input) {
  needs_stack_check_ = true;
  if (!memory->is_memory64()) {
    // For 32-bit memories, just call the builtin.
    return gasm_->CallBuiltinThroughJumptable(
        Builtin::kWasmMemoryGrow, Operator::kNoThrow,
        gasm_->Int32Constant(memory->index), input);
  }

  // If the input is not a positive int32, growing will always fail
  // (growing negative or requesting >= 256 TB).
  Node* old_effect = effect();
  Diamond is_32_bit(graph(), mcgraph()->common(),
                    gasm_->Uint64LessThanOrEqual(input, Int64Constant(kMaxInt)),
                    BranchHint::kTrue);
  is_32_bit.Chain(control());

  SetControl(is_32_bit.if_true);

  Node* grow_result =
      gasm_->ChangeInt32ToInt64(gasm_->CallBuiltinThroughJumptable(
          Builtin::kWasmMemoryGrow, Operator::kNoThrow,
          gasm_->Int32Constant(memory->index),
          gasm_->TruncateInt64ToInt32(input)));

  Node* diamond_result = is_32_bit.Phi(MachineRepresentation::kWord64,
                                       grow_result, gasm_->Int64Constant(-1));
  SetEffectControl(is_32_bit.EffectPhi(effect(), old_effect), is_32_bit.merge);
  return diamond_result;
}

Node* WasmGraphBuilder::Throw(uint32_t tag_index, const wasm::WasmTag* tag,
                              const base::Vector<Node*> values,
                              wasm::WasmCodePosition position) {
  needs_stack_check_ = true;
  uint32_t encoded_size = WasmExceptionPackage::GetEncodedSize(tag);

  Node* values_array = gasm_->CallBuiltinThroughJumptable(
      Builtin::kWasmAllocateFixedArray, Operator::kNoThrow,
      gasm_->IntPtrConstant(encoded_size));
  SetSourcePosition(values_array, position);

  uint32_t index = 0;
  const wasm::WasmTagSig* sig = tag->sig;
  MachineOperatorBuilder* m = mcgraph()->machine();
  for (size_t i = 0; i < sig->parameter_count(); ++i) {
    Node* value = values[i];
    switch (sig->GetParam(i).kind()) {
      case wasm::kF32:
        value = gasm_->BitcastFloat32ToInt32(value);
        [[fallthrough]];
      case wasm::kI32:
        BuildEncodeException32BitValue(values_array, &index, value);
        break;
      case wasm::kF64:
        value = gasm_->BitcastFloat64ToInt64(value);
        [[fallthrough]];
      case wasm::kI64: {
        Node* upper32 = gasm_->TruncateInt64ToInt32(
            Binop(wasm::kExprI64ShrU, value, Int64Constant(32)));
        BuildEncodeException32BitValue(values_array, &index, upper32);
        Node* lower32 = gasm_->TruncateInt64ToInt32(value);
        BuildEncodeException32BitValue(values_array, &index, lower32);
        break;
      }
      case wasm::kS128:
        BuildEncodeException32BitValue(
            values_array, &index,
            graph()->NewNode(m->I32x4ExtractLane(0), value));
        BuildEncodeException32BitValue(
            values_array, &index,
            graph()->NewNode(m->I32x4ExtractLane(1), value));
        BuildEncodeException32BitValue(
            values_array, &index,
            graph()->NewNode(m->I32x4ExtractLane(2), value));
        BuildEncodeException32BitValue(
            values_array, &index,
            graph()->NewNode(m->I32x4ExtractLane(3), value));
        break;
      case wasm::kRef:
      case wasm::kRefNull:
      case wasm::kRtt:
        gasm_->StoreFixedArrayElementAny(values_array, index, value);
        ++index;
        break;
      case wasm::kI8:
      case wasm::kI16:
      case wasm::kF16:
      case wasm::kVoid:
      case wasm::kTop:
      case wasm::kBottom:
        UNREACHABLE();
    }
  }
  DCHECK_EQ(encoded_size, index);

  Node* exception_tag = LoadTagFromTable(tag_index);

  Node* throw_call = gasm_->CallBuiltinThroughJumptable(
      Builtin::kWasmThrow, Operator::kNoProperties, exception_tag,
      values_array);
  SetSourcePosition(throw_call, position);
  return throw_call;
}

void WasmGraphBuilder::BuildEncodeException32BitValue(Node* values_array,
                                                      uint32_t* index,
                                                      Node* value) {
  Node* upper_halfword_as_smi =
      gasm_->BuildChangeUint31ToSmi(gasm_->Word32Shr(value, Int32Constant(16)));
  gasm_->StoreFixedArrayElementSmi(values_array, *index, upper_halfword_as_smi);
  ++(*index);
  Node* lower_halfword_as_smi = gasm_->BuildChangeUint31ToSmi(
      gasm_->Word32And(value, Int32Constant(0xFFFFu)));
  gasm_->StoreFixedArrayElementSmi(values_array, *index, lower_halfword_as_smi);
  ++(*index);
}

Node* WasmGraphBuilder::BuildDecodeException32BitValue(Node* values_array,
                                                       uint32_t* index) {
  Node* upper = gasm_->BuildChangeSmiToInt32(
      gasm_->LoadFixedArrayElementSmi(values_array, *index));
  (*index)++;
  upper = gasm_->Word32Shl(upper, Int32Constant(16));
  Node* lower = gasm_->BuildChangeSmiToInt32(
      gasm_->LoadFixedArrayElementSmi(values_array, *index));
  (*index)++;
  Node* value = gasm_->Word32Or(upper, lower);
  return value;
}

Node* WasmGraphBuilder::BuildDecodeException64BitValue(Node* values_array,
                                                       uint32_t* index) {
  Node* upper = Binop(wasm::kExprI64Shl,
                      Unop(wasm::kExprI64UConvertI32,
                           BuildDecodeException32BitValue(values_array, index)),
                      Int64Constant(32));
  Node* lower = Unop(wasm::kExprI64UConvertI32,
                     BuildDecodeException32BitValue(values_array, index));
  return Binop(wasm::kExprI64Ior, upper, lower);
}

Node* WasmGraphBuilder::Rethrow(Node* except_obj) {
  // TODO(v8:8091): Currently the message of the original exception is not being
  // preserved when rethrown to the console. The pending message will need to be
  // saved when caught and restored here while being rethrown.
  return gasm_->CallBuiltinThroughJumptable(
      Builtin::kWasmRethrow, Operator::kNoProperties, except_obj);
}

Node* WasmGraphBuilder::ThrowRef(Node* except_obj) {
  // TODO(v8:8091): Currently the message of the original exception is not being
  // preserved when rethrown to the console. The pending message will need to be
  // saved when caught and restored here while being rethrown.
  return gasm_->CallBuiltinThroughJumptable(
      Builtin::kWasmThrowRef, Operator::kNoProperties, except_obj);
}

Node* WasmGraphBuilder::IsExceptionTagUndefined(Node* tag) {
  return gasm_->TaggedEqual(tag, UndefinedValue());
}

Node* WasmGraphBuilder::LoadJSTag() {
  Node* context =
      LOAD_INSTANCE_FIELD(NativeContext, MachineType::TaggedPointer());
  Node* tag_obj =
      gasm_->Load(MachineType::TaggedPointer(), context,
                  NativeContext::SlotOffset(Context::WASM_JS_TAG_INDEX));
  return gasm_->Load(MachineType::TaggedPointer(), tag_obj,
                     wasm::ObjectAccess::ToTagged(WasmTagObject::kTagOffset));
}

Node* WasmGraphBuilder::ExceptionTagEqual(Node* caught_tag,
                                          Node* expected_tag) {
  return gasm_->WordEqual(caught_tag, expected_tag);
}

Node* WasmGraphBuilder::LoadTagFromTable(uint32_t tag_index) {
  Node* tags_table =
      LOAD_INSTANCE_FIELD(TagsTable, MachineType::TaggedPointer());
  Node* tag = gasm_->LoadFixedArrayElementPtr(tags_table, tag_index);
  return tag;
}

Node* WasmGraphBuilder::GetExceptionTag(Node* except_obj) {
  return gasm_->CallBuiltin(
      Builtin::kWasmGetOwnProperty, Operator::kEliminatable, except_obj,
      LOAD_ROOT(wasm_exception_tag_symbol, wasm_exception_tag_symbol),
      LOAD_INSTANCE_FIELD(NativeContext, MachineType::TaggedPointer()));
}

Node* WasmGraphBuilder::GetExceptionValues(Node* except_obj,
                                           const wasm::WasmTag* tag,
                                           base::Vector<Node*> values) {
  Node* values_array = gasm_->CallBuiltin(
      Builtin::kWasmGetOwnProperty, Operator::kEliminatable, except_obj,
      LOAD_ROOT(wasm_exception_values_symbol, wasm_exception_values_symbol),
      LOAD_INSTANCE_FIELD(NativeContext, MachineType::TaggedPointer()));
  uint32_t index = 0;
  const wasm::WasmTagSig* sig = tag->sig;
  DCHECK_EQ(sig->parameter_count(), values.size());
  for (size_t i = 0; i < sig->parameter_count(); ++i) {
    Node* value;
    switch (sig->GetParam(i).kind()) {
      case wasm::kI32:
        value = BuildDecodeException32BitValue(values_array, &index);
        break;
      case wasm::kI64:
        value = BuildDecodeException64BitValue(values_array, &index);
        break;
      case wasm::kF32: {
        value = Unop(wasm::kExprF32ReinterpretI32,
                     BuildDecodeException32BitValue(values_array, &index));
        break;
      }
      case wasm::kF64: {
        value = Unop(wasm::kExprF64ReinterpretI64,
                     BuildDecodeException64BitValue(values_array, &index));
        break;
      }
      case wasm::kS128:
        value = graph()->NewNode(
            mcgraph()->machine()->I32x4Splat(),
            BuildDecodeException32BitValue(values_array, &index));
        value = graph()->NewNode(
            mcgraph()->machine()->I32x4ReplaceLane(1), value,
            BuildDecodeException32BitValue(values_array, &index));
        value = graph()->NewNode(
            mcgraph()->machine()->I32x4ReplaceLane(2), value,
            BuildDecodeException32BitValue(values_array, &index));
        value = graph()->NewNode(
            mcgraph()->machine()->I32x4ReplaceLane(3), value,
            BuildDecodeException32BitValue(values_array, &index));
        break;
      case wasm::kRef:
      case wasm::kRefNull:
      case wasm::kRtt:
        value = gasm_->LoadFixedArrayElementAny(values_array, index);
        ++index;
        break;
      case wasm::kI8:
      case wasm::kI16:
      case wasm::kF16:
      case wasm::kVoid:
      case wasm::kTop:
      case wasm::kBottom:
        UNREACHABLE();
    }
    values[i] = value;
  }
  DCHECK_EQ(index, WasmExceptionPackage::GetEncodedSize(tag));
  return values_array;
}

Node* WasmGraphBuilder::BuildI32DivS(Node* left, Node* right,
                                     wasm::WasmCodePosition position) {
  ZeroCheck32(wasm::kTrapDivByZero, right, position);
  Node* previous_effect = effect();
  auto [denom_is_m1, denom_is_not_m1] =
      BranchExpectFalse(gasm_->Word32Equal(right, Int32Constant(-1)));
  SetControl(denom_is_m1);
  TrapIfEq32(wasm::kTrapDivUnrepresentable, left, kMinInt, position);
  Node* merge = Merge(control(), denom_is_not_m1);
  SetEffectControl(graph()->NewNode(mcgraph()->common()->EffectPhi(2), effect(),
                                    previous_effect, merge),
                   merge);
  return gasm_->Int32Div(left, right);
}

Node* WasmGraphBuilder::BuildI32RemS(Node* left, Node* right,
                                     wasm::WasmCodePosition position) {
  MachineOperatorBuilder* m = mcgraph()->machine();

  ZeroCheck32(wasm::kTrapRemByZero, right, position);

  Diamond d(graph(), mcgraph()->common(),
            gasm_->Word32Equal(right, Int32Constant(-1)), BranchHint::kFalse);
  d.Chain(control());

  return d.Phi(MachineRepresentation::kWord32, Int32Constant(0),
               graph()->NewNode(m->Int32Mod(), left, right, d.if_false));
}

Node* WasmGraphBuilder::BuildI32DivU(Node* left, Node* right,
                                     wasm::WasmCodePosition position) {
  ZeroCheck32(wasm::kTrapDivByZero, right, position);
  return gasm_->Uint32Div(left, right);
}

Node* WasmGraphBuilder::BuildI32RemU(Node* left, Node* right,
                                     wasm::WasmCodePosition position) {
  ZeroCheck32(wasm::kTrapRemByZero, right, position);
  return gasm_->Uint32Mod(left, right);
}

Node* WasmGraphBuilder::BuildI32AsmjsDivS(Node* left, Node* right) {
  MachineOperatorBuilder* m = mcgraph()->machine();

  Int32Matcher mr(right);
  if (mr.HasResolvedValue()) {
    if (mr.ResolvedValue() == 0) {
      return Int32Constant(0);
    } else if (mr.ResolvedValue() == -1) {
      // The result is the negation of the left input.
      return gasm_->Int32Sub(Int32Constant(0), left);
    }
    return gasm_->Int32Div(left, right);
  }

  // asm.js semantics return 0 on divide or mod by zero.
  if (m->Int32DivIsSafe()) {
    // The hardware instruction does the right thing (e.g. arm).
    return gasm_->Int32Div(left, right);
  }

  // Check denominator for zero.
  Diamond z(graph(), mcgraph()->common(),
            gasm_->Word32Equal(right, Int32Constant(0)), BranchHint::kFalse);
  z.Chain(control());

  // Check denominator for -1. (avoid minint / -1 case).
  Diamond n(graph(), mcgraph()->common(),
            gasm_->Word32Equal(right, Int32Constant(-1)), BranchHint::kFalse);
  n.Chain(z.if_false);

  Node* div = graph()->NewNode(m->Int32Div(), left, right, n.if_false);

  Node* neg = gasm_->Int32Sub(Int32Constant(0), left);

  return z.Phi(MachineRepresentation::kWord32, Int32Constant(0),
               n.Phi(MachineRepresentation::kWord32, neg, div));
}

Node* WasmGraphBuilder::BuildI32AsmjsRemS(Node* left, Node* right) {
  CommonOperatorBuilder* c = mcgraph()->common();
  MachineOperatorBuilder* m = mcgraph()->machine();
  Node* const zero = Int32Constant(0);

  Int32Matcher mr(right);
  if (mr.HasResolvedValue()) {
    if (mr.ResolvedValue() == 0 || mr.ResolvedValue() == -1) {
      return zero;
    }
    return gasm_->Int32Mod(left, right);
  }

  // General case for signed integer modulus, with optimization for (unknown)
  // power of 2 right hand side.
  //
  //   if 0 < right then
  //     msk = right - 1
  //     if right & msk != 0 then
  //       left % right
  //     else
  //       if left < 0 then
  //         -(-left & msk)
  //       else
  //         left & msk
  //   else
  //     if right < -1 then
  //       left % right
  //     else
  //       zero
  //
  // Note: We do not use the Diamond helper class here, because it really hurts
  // readability with nested diamonds.
  Node* const minus_one = Int32Constant(-1);

  const Operator* const merge_op = c->Merge(2);
  const Operator* const phi_op = c->Phi(MachineRepresentation::kWord32, 2);

  Node* check0 = gasm_->Int32LessThan(zero, right);
  Node* branch0 =
      graph()->NewNode(c->Branch(BranchHint::kTrue), check0, control());

  Node* if_true0 = graph()->NewNode(c->IfTrue(), branch0);
  Node* true0;
  {
    Node* msk = graph()->NewNode(m->Int32Add(), right, minus_one);

    Node* check1 = graph()->NewNode(m->Word32And(), right, msk);
    Node* branch1 = graph()->NewNode(c->Branch(), check1, if_true0);

    Node* if_true1 = graph()->NewNode(c->IfTrue(), branch1);
    Node* true1 = graph()->NewNode(m->Int32Mod(), left, right, if_true1);

    Node* if_false1 = graph()->NewNode(c->IfFalse(), branch1);
    Node* false1;
    {
      Node* check2 = graph()->NewNode(m->Int32LessThan(), left, zero);
      Node* branch2 =
          graph()->NewNode(c->Branch(BranchHint::kFalse), check2, if_false1);

      Node* if_true2 = graph()->NewNode(c->IfTrue(), branch2);
      Node* true2 = graph()->NewNode(
          m->Int32Sub(), zero,
          graph()->NewNode(m->Word32And(),
                           graph()->NewNode(m->Int32Sub(), zero, left), msk));

      Node* if_false2 = graph()->NewNode(c->IfFalse(), branch2);
      Node* false2 = graph()->NewNode(m->Word32And(), left, msk);

      if_false1 = graph()->NewNode(merge_op, if_true2, if_false2);
      false1 = graph()->NewNode(phi_op, true2, false2, if_false1);
    }

    if_true0 = graph()->NewNode(merge_op, if_true1, if_false1);
    true0 = graph()->NewNode(phi_op, true1, false1, if_true0);
  }

  Node* if_false0 = graph()->NewNode(c->IfFalse(), branch0);
  Node* false0;
  {
    Node* check1 = graph()->NewNode(m->Int32LessThan(), right, minus_one);
    Node* branch1 =
        graph()->NewNode(c->Branch(BranchHint::kTrue), check1, if_false0);

    Node* if_true1 = graph()->NewNode(c->IfTrue(), branch1);
    Node* true1 = graph()->NewNode(m->Int32Mod(), left, right, if_true1);

    Node* if_false1 = graph()->NewNode(c->IfFalse(), branch1);
    Node* false1 = zero;

    if_false0 = graph()->NewNode(merge_op, if_true1, if_false1);
    false0 = graph()->NewNode(phi_op, true1, false1, if_false0);
  }

  Node* merge0 = graph()->NewNode(merge_op, if_true0, if_false0);
  return graph()->NewNode(phi_op, true0, false0, merge0);
}

Node* WasmGraphBuilder::BuildI32AsmjsDivU(Node* left, Node* right) {
  MachineOperatorBuilder* m = mcgraph()->machine();
  // asm.js semantics return 0 on divide or mod by zero.
  if (m->Uint32DivIsSafe()) {
    // The hardware instruction does the right thing (e.g. arm).
    return gasm_->Uint32Div(left, right);
  }

  // Explicit check for x / 0.
  Diamond z(graph(), mcgraph()->common(),
            gasm_->Word32Equal(ri
```