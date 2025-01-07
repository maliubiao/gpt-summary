Response:
The user wants a summary of the functionality of the provided C++ code snippet.
The code seems to be part of a WebAssembly module generator used for fuzzing.
It focuses on generating different kinds of WebAssembly instructions and data based on specified types.

Here's a breakdown of the thought process to analyze the code:

1. **Identify the core purpose:** The code is within `v8/src/wasm/fuzzing/random-module-generation.cc`. The name suggests it's involved in generating WebAssembly modules randomly, likely for fuzzing purposes. The functions within the provided snippet are named `GenerateI32`, `GenerateI64`, `GenerateF32`, `GenerateF64`, `GenerateS128`, and `GenerateRef`, indicating they generate values or instructions related to these WebAssembly types.

2. **Recognize the structure:** The code uses a `BodyGen` class and methods like `op`, `memop`, `block`, `loop`, `if_`, `br_if`, etc. These correspond to WebAssembly instructions. The `CreateArray` function suggests a selection mechanism for choosing which instruction to generate.

3. **Analyze individual `Generate` functions:**
    * Each `Generate<type>` function seems to handle the generation of a specific WebAssembly value type (i32, i64, f32, f64, s128, ref).
    * They have a recursion check (`GeneratorRecursionScope`, `recursion_limit_reached()`) to prevent infinite loops during generation.
    * For primitive types (i32, i64, f32, f64), if the recursion limit is reached or the data range is small, they generate a constant value (`EmitI32Const`, `EmitF64Const`).
    * Otherwise, they have a list of `alternatives` which are different WebAssembly instructions that produce a value of that type. These alternatives include basic operations (add, sub, mul, div, abs, neg), control flow (block, loop, if), memory operations (load), local/global variable access, calls, and SIMD instructions (for `GenerateS128`).
    * The `GenerateOneOf` function is used to randomly select one of these alternatives.

4. **Identify SIMD and WasmGC features:** The code uses `ShouldGenerateSIMD(options)` and `ShouldGenerateWasmGC(options)` to conditionally include SIMD and WasmGC instructions in the `alternatives`. This confirms the code's role in generating modules with these features.

5. **Focus on `GenerateRef`:** This function is more complex and handles generating reference types. It distinguishes between `kNullable` and `kNonNullable` references. It handles different heap types (`kAny`, `kArray`, `kStruct`, `kEq`) and has fallback mechanisms if generating a specific type fails.

6. **Infer the fuzzing context:** The random selection of instructions and data types is a hallmark of a fuzzer. The goal is to generate a wide variety of valid (and potentially invalid, depending on the larger fuzzing framework) WebAssembly modules to test the V8 engine.

7. **Address specific instructions:**
    * Instructions like `br_if`, `br_table` relate to control flow.
    * `memop` instructions involve memory access.
    * `call`, `call_indirect`, `call_ref` relate to function calls.
    * SIMD instructions (prefixed with `kExprI8x16`, `kExprF32x4`, etc.) operate on vector data.
    * WasmGC instructions (`struct_get`, `array_get`) are used for accessing fields of objects and arrays.

8. **Consider user programming errors:**  Although the code itself generates code, the *types* of instructions it generates can be related to common programming errors. For example, incorrect memory access (out-of-bounds reads/writes), type mismatches in function calls, and misuse of control flow structures are areas where errors often occur.

9. **Address the `.tq` question:** The code is `.cc`, so it's a C++ source file. The provided information states that a `.tq` extension would indicate a Torque file.

10. **Relate to JavaScript:** WebAssembly modules are often used in JavaScript environments. The generated modules would be compiled and instantiated in JavaScript. Examples would involve creating WebAssembly instances, calling exported functions, and observing the results.

11. **Consider the provided input/output question:**  This is challenging without knowing the exact state of the generator. However, we can make hypothetical examples. For instance, if asked to generate an `i32`, it might output an instruction to load a local variable, add two constants, or perform a bitwise operation.

12. **Synthesize the summary:** Combine the above observations into a concise description of the file's purpose and functionality.

By following these steps, we can effectively analyze the provided code snippet and generate a comprehensive summary of its functionality.
Based on the provided C++ code snippet from `v8/src/wasm/fuzzing/random-module-generation.cc`, here's a breakdown of its functionality as part 4 of 7:

**Core Functionality:**

This code snippet focuses on generating random WebAssembly instructions and operands for various data types within the body of a WebAssembly function. It's part of a larger system that generates entire WebAssembly modules for fuzzing purposes. This specific part seems responsible for:

* **Generating expressions of different WebAssembly types:** It has functions like `GenerateI32`, `GenerateI64`, `GenerateF32`, `GenerateF64`, `GenerateS128`, and `GenerateRef` which are responsible for creating instructions that produce values of those respective types.
* **Randomly selecting from available instructions:**  Each `Generate` function for a specific type has a `constexpr auto alternatives` array. This array holds pointers to member functions (likely within the `BodyGen` class) that emit specific WebAssembly instructions. The `GenerateOneOf` function is used to randomly pick one of these instructions.
* **Handling different WebAssembly features:** The code conditionally includes instructions based on whether SIMD (`ShouldGenerateSIMD(options)`) or WasmGC (`ShouldGenerateWasmGC(options)`) features are enabled.
* **Managing recursion depth:** The `GeneratorRecursionScope` and `recursion_limit_reached()` checks are used to prevent the generator from creating excessively deep and complex expressions, which could lead to stack overflow or performance issues.
* **Generating constant values:** When the recursion limit is reached or the available data is small, the generator resorts to emitting constant values for primitive types (`EmitI32Const`, `EmitF64Const`).
* **Generating reference types:** The `GenerateRef` function handles the generation of reference types, including `ref.null`, casting, and accessing fields of structures and arrays. It also considers nullability.

**Specific Instructions Handled in this Snippet:**

The code snippet shows the generation logic for a wide variety of I64 and F32 instructions, including:

* **Control Flow:** `block`, `loop`, `finite_loop`, `if`, `br_if`, `br_on_null`, `br_on_non_null`, `br_table`, `try_block`.
* **Memory Operations:** Various forms of `load` and atomic operations for I64.
* **Local and Global Variables:** `get_local`, `tee_local`, `get_global`.
* **Arithmetic and Logical Operations:**  A variety of operators for I64 and F32.
* **Conversions:** Instructions for converting between different numeric types (I32, I64, F32, F64).
* **Reinterpretations:** Instructions for reinterpreting the bit pattern of one type as another.
* **Selections:** `select` and `select_with_type`.
* **Function Calls:** `call`, `call_indirect`, `call_ref`.
* **SIMD Operations (if enabled):**  Lane extraction for I64x2 and F32x4.
* **WasmGC Operations (if enabled):** `struct_get`, `array_get`.

**Regarding your specific questions:**

* **Is it a v8 torque source code?** No, `v8/src/wasm/fuzzing/random-module-generation.cc` ends with `.cc`, indicating it's a C++ source file, not a Torque (`.tq`) file.
* **Relationship with Javascript and Javascript example:** This code generates WebAssembly, which is designed to run alongside JavaScript in web browsers and Node.js. The generated WebAssembly modules can be instantiated and called from JavaScript.

```javascript
// Assuming you have a generated WebAssembly module (e.g., 'generated.wasm')
fetch('generated.wasm')
  .then(response => response.arrayBuffer())
  .then(bytes => WebAssembly.instantiate(bytes))
  .then(results => {
    const instance = results.instance;
    // If the generated module has an exported function that returns an i64...
    const result = instance.exports.some_i64_returning_function();
    console.log("Result from WebAssembly:", result);
  });
```

* **Code logic inference with assumptions:**

   Let's assume the `options` enable only MVP WebAssembly features. If the generator is asked to `GenerateI64` with a sufficiently large `DataRange`:

   **Hypothetical Input:**  Call to `GenerateI64(data)` with a `DataRange` of 100 bytes.

   **Possible Output:** The generator might randomly select the `&BodyGen::op<kExprI64Add, kI64, kI64>` alternative. This would result in the following WebAssembly bytecode being added to the module being built:

   1. The bytecode for `get_local` or `get_global` (to get two I64 operands).
   2. The bytecode for the `i64.add` instruction.

   If the `DataRange` was very small (e.g., less than 8 bytes), it would likely emit an `i64.const` instruction.

* **User programming errors:** This code helps *test* for errors in the V8 WebAssembly engine. However, the kinds of instructions it generates are related to common WebAssembly programming errors if written manually:

   ```c++ // Hypothetical manual WebAssembly code (text format)
   (module
     (func $add_and_load (param $p i32) (result i64)
       local.get 0
       i64.const 8
       i32.add  // ERROR: Trying to add an i32 to an i64. Type mismatch.
       i64.load  // Potential out-of-bounds access if $p is not a valid address.
     )
   )
   ```

   This snippet illustrates potential errors:
    * **Type Mismatch:** Trying to add an `i32` to an `i64`.
    * **Memory Access Errors:** Loading from a potentially invalid memory address.

* **Summary of Functionality (Part 4):**

   In essence, this part of the `random-module-generation.cc` file is responsible for **randomly generating the *instructions* within the functions of a WebAssembly module, focusing on operations related to I64 and F32 data types, and also handling reference types. It selects from a predefined set of valid WebAssembly instructions and considers the enabled features (like SIMD and WasmGC) to create a diverse range of function bodies for fuzzing the V8 WebAssembly engine.**

Prompt: 
```
这是目录为v8/src/wasm/fuzzing/random-module-generation.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/fuzzing/random-module-generation.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共7部分，请归纳一下它的功能

"""
se>,    //
        &BodyGen::br_if<kI64>,           //
        &BodyGen::br_on_null<kI64>,      //
        &BodyGen::br_on_non_null<kI64>,  //
        &BodyGen::br_table<kI64>,        //

        &BodyGen::memop<kExprI64LoadMem>,                               //
        &BodyGen::memop<kExprI64LoadMem8S>,                             //
        &BodyGen::memop<kExprI64LoadMem8U>,                             //
        &BodyGen::memop<kExprI64LoadMem16S>,                            //
        &BodyGen::memop<kExprI64LoadMem16U>,                            //
        &BodyGen::memop<kExprI64LoadMem32S>,                            //
        &BodyGen::memop<kExprI64LoadMem32U>,                            //
                                                                        //
        &BodyGen::memop<kExprI64AtomicLoad>,                            //
        &BodyGen::memop<kExprI64AtomicLoad8U>,                          //
        &BodyGen::memop<kExprI64AtomicLoad16U>,                         //
        &BodyGen::memop<kExprI64AtomicLoad32U>,                         //
        &BodyGen::memop<kExprI64AtomicAdd, kI64>,                       //
        &BodyGen::memop<kExprI64AtomicSub, kI64>,                       //
        &BodyGen::memop<kExprI64AtomicAnd, kI64>,                       //
        &BodyGen::memop<kExprI64AtomicOr, kI64>,                        //
        &BodyGen::memop<kExprI64AtomicXor, kI64>,                       //
        &BodyGen::memop<kExprI64AtomicExchange, kI64>,                  //
        &BodyGen::memop<kExprI64AtomicCompareExchange, kI64, kI64>,     //
        &BodyGen::memop<kExprI64AtomicAdd8U, kI64>,                     //
        &BodyGen::memop<kExprI64AtomicSub8U, kI64>,                     //
        &BodyGen::memop<kExprI64AtomicAnd8U, kI64>,                     //
        &BodyGen::memop<kExprI64AtomicOr8U, kI64>,                      //
        &BodyGen::memop<kExprI64AtomicXor8U, kI64>,                     //
        &BodyGen::memop<kExprI64AtomicExchange8U, kI64>,                //
        &BodyGen::memop<kExprI64AtomicCompareExchange8U, kI64, kI64>,   //
        &BodyGen::memop<kExprI64AtomicAdd16U, kI64>,                    //
        &BodyGen::memop<kExprI64AtomicSub16U, kI64>,                    //
        &BodyGen::memop<kExprI64AtomicAnd16U, kI64>,                    //
        &BodyGen::memop<kExprI64AtomicOr16U, kI64>,                     //
        &BodyGen::memop<kExprI64AtomicXor16U, kI64>,                    //
        &BodyGen::memop<kExprI64AtomicExchange16U, kI64>,               //
        &BodyGen::memop<kExprI64AtomicCompareExchange16U, kI64, kI64>,  //
        &BodyGen::memop<kExprI64AtomicAdd32U, kI64>,                    //
        &BodyGen::memop<kExprI64AtomicSub32U, kI64>,                    //
        &BodyGen::memop<kExprI64AtomicAnd32U, kI64>,                    //
        &BodyGen::memop<kExprI64AtomicOr32U, kI64>,                     //
        &BodyGen::memop<kExprI64AtomicXor32U, kI64>,                    //
        &BodyGen::memop<kExprI64AtomicExchange32U, kI64>,               //
        &BodyGen::memop<kExprI64AtomicCompareExchange32U, kI64, kI64>,  //

        &BodyGen::get_local<kI64>,                    //
        &BodyGen::tee_local<kI64>,                    //
        &BodyGen::get_global<kI64>,                   //
        &BodyGen::op<kExprSelect, kI64, kI64, kI32>,  //
        &BodyGen::select_with_type<kI64>,             //

        &BodyGen::call<kI64>,           //
        &BodyGen::call_indirect<kI64>,  //
        &BodyGen::call_ref<kI64>,       //
        &BodyGen::try_block<kI64>);     //

    auto constexpr simd_alternatives =
        CreateArray(&BodyGen::simd_lane_op<kExprI64x2ExtractLane, 2, kS128>);

    auto constexpr wasmGC_alternatives =
        CreateArray(&BodyGen::struct_get<kI64>,  //
                    &BodyGen::array_get<kI64>);  //

    constexpr auto alternatives = AppendArrayIf<ShouldGenerateWasmGC(options)>(
        AppendArrayIf<ShouldGenerateSIMD(options)>(mvp_alternatives,
                                                   simd_alternatives),
        wasmGC_alternatives);
    GenerateOneOf(alternatives, data);
  }

  void GenerateF32(DataRange* data) {
    GeneratorRecursionScope rec_scope(this);
    if (recursion_limit_reached() || data->size() <= sizeof(float)) {
      builder_->EmitF32Const(data->getPseudoRandom<float>());
      return;
    }

    constexpr auto mvp_alternatives = CreateArray(
        &BodyGen::sequence<kF32, kVoid>, &BodyGen::sequence<kVoid, kF32>,
        &BodyGen::sequence<kVoid, kF32, kVoid>,

        &BodyGen::op<kExprF32Abs, kF32>,             //
        &BodyGen::op<kExprF32Neg, kF32>,             //
        &BodyGen::op<kExprF32Ceil, kF32>,            //
        &BodyGen::op<kExprF32Floor, kF32>,           //
        &BodyGen::op<kExprF32Trunc, kF32>,           //
        &BodyGen::op<kExprF32NearestInt, kF32>,      //
        &BodyGen::op<kExprF32Sqrt, kF32>,            //
        &BodyGen::op<kExprF32Add, kF32, kF32>,       //
        &BodyGen::op<kExprF32Sub, kF32, kF32>,       //
        &BodyGen::op<kExprF32Mul, kF32, kF32>,       //
        &BodyGen::op<kExprF32Div, kF32, kF32>,       //
        &BodyGen::op<kExprF32Min, kF32, kF32>,       //
        &BodyGen::op<kExprF32Max, kF32, kF32>,       //
        &BodyGen::op<kExprF32CopySign, kF32, kF32>,  //

        &BodyGen::op<kExprF32SConvertI32, kI32>,
        &BodyGen::op<kExprF32UConvertI32, kI32>,
        &BodyGen::op<kExprF32SConvertI64, kI64>,
        &BodyGen::op<kExprF32UConvertI64, kI64>,
        &BodyGen::op<kExprF32ConvertF64, kF64>,
        &BodyGen::op<kExprF32ReinterpretI32, kI32>,

        &BodyGen::block<kF32>,           //
        &BodyGen::loop<kF32>,            //
        &BodyGen::finite_loop<kF32>,     //
        &BodyGen::if_<kF32, kIfElse>,    //
        &BodyGen::br_if<kF32>,           //
        &BodyGen::br_on_null<kF32>,      //
        &BodyGen::br_on_non_null<kF32>,  //
        &BodyGen::br_table<kF32>,        //

        &BodyGen::memop<kExprF32LoadMem>,

        &BodyGen::get_local<kF32>,                    //
        &BodyGen::tee_local<kF32>,                    //
        &BodyGen::get_global<kF32>,                   //
        &BodyGen::op<kExprSelect, kF32, kF32, kI32>,  //
        &BodyGen::select_with_type<kF32>,             //

        &BodyGen::call<kF32>,           //
        &BodyGen::call_indirect<kF32>,  //
        &BodyGen::call_ref<kF32>,       //
        &BodyGen::try_block<kF32>);     //

    auto constexpr simd_alternatives =
        CreateArray(&BodyGen::simd_lane_op<kExprF32x4ExtractLane, 4, kS128>);

    auto constexpr wasmGC_alternatives =
        CreateArray(&BodyGen::struct_get<kF32>,  //
                    &BodyGen::array_get<kF32>);  //

    constexpr auto alternatives = AppendArrayIf<ShouldGenerateWasmGC(options)>(
        AppendArrayIf<ShouldGenerateSIMD(options)>(mvp_alternatives,
                                                   simd_alternatives),
        wasmGC_alternatives);
    GenerateOneOf(alternatives, data);
  }

  void GenerateF64(DataRange* data) {
    GeneratorRecursionScope rec_scope(this);
    if (recursion_limit_reached() || data->size() <= sizeof(double)) {
      builder_->EmitF64Const(data->getPseudoRandom<double>());
      return;
    }

    constexpr auto mvp_alternatives = CreateArray(
        &BodyGen::sequence<kF64, kVoid>, &BodyGen::sequence<kVoid, kF64>,
        &BodyGen::sequence<kVoid, kF64, kVoid>,

        &BodyGen::op<kExprF64Abs, kF64>,             //
        &BodyGen::op<kExprF64Neg, kF64>,             //
        &BodyGen::op<kExprF64Ceil, kF64>,            //
        &BodyGen::op<kExprF64Floor, kF64>,           //
        &BodyGen::op<kExprF64Trunc, kF64>,           //
        &BodyGen::op<kExprF64NearestInt, kF64>,      //
        &BodyGen::op<kExprF64Sqrt, kF64>,            //
        &BodyGen::op<kExprF64Add, kF64, kF64>,       //
        &BodyGen::op<kExprF64Sub, kF64, kF64>,       //
        &BodyGen::op<kExprF64Mul, kF64, kF64>,       //
        &BodyGen::op<kExprF64Div, kF64, kF64>,       //
        &BodyGen::op<kExprF64Min, kF64, kF64>,       //
        &BodyGen::op<kExprF64Max, kF64, kF64>,       //
        &BodyGen::op<kExprF64CopySign, kF64, kF64>,  //

        &BodyGen::op<kExprF64SConvertI32, kI32>,
        &BodyGen::op<kExprF64UConvertI32, kI32>,
        &BodyGen::op<kExprF64SConvertI64, kI64>,
        &BodyGen::op<kExprF64UConvertI64, kI64>,
        &BodyGen::op<kExprF64ConvertF32, kF32>,
        &BodyGen::op<kExprF64ReinterpretI64, kI64>,

        &BodyGen::block<kF64>,           //
        &BodyGen::loop<kF64>,            //
        &BodyGen::finite_loop<kF64>,     //
        &BodyGen::if_<kF64, kIfElse>,    //
        &BodyGen::br_if<kF64>,           //
        &BodyGen::br_on_null<kF64>,      //
        &BodyGen::br_on_non_null<kF64>,  //
        &BodyGen::br_table<kF64>,        //

        &BodyGen::memop<kExprF64LoadMem>,

        &BodyGen::get_local<kF64>,                    //
        &BodyGen::tee_local<kF64>,                    //
        &BodyGen::get_global<kF64>,                   //
        &BodyGen::op<kExprSelect, kF64, kF64, kI32>,  //
        &BodyGen::select_with_type<kF64>,             //

        &BodyGen::call<kF64>,           //
        &BodyGen::call_indirect<kF64>,  //
        &BodyGen::call_ref<kF64>,       //
        &BodyGen::try_block<kF64>);     //

    auto constexpr simd_alternatives =
        CreateArray(&BodyGen::simd_lane_op<kExprF64x2ExtractLane, 2, kS128>);

    auto constexpr wasmGC_alternatives =
        CreateArray(&BodyGen::struct_get<kF64>,  //
                    &BodyGen::array_get<kF64>);  //

    constexpr auto alternatives = AppendArrayIf<ShouldGenerateWasmGC(options)>(
        AppendArrayIf<ShouldGenerateSIMD(options)>(mvp_alternatives,
                                                   simd_alternatives),
        wasmGC_alternatives);
    GenerateOneOf(alternatives, data);
  }

  void GenerateS128(DataRange* data) {
    CHECK(ShouldGenerateSIMD(options));
    GeneratorRecursionScope rec_scope(this);
    has_simd_ = true;
    if (recursion_limit_reached() || data->size() <= sizeof(int32_t)) {
      // TODO(v8:8460): v128.const is not implemented yet, and we need a way to
      // "bottom-out", so use a splat to generate this.
      builder_->EmitI32Const(0);
      builder_->EmitWithPrefix(kExprI8x16Splat);
      return;
    }

    constexpr auto alternatives = CreateArray(
        &BodyGen::simd_const,
        &BodyGen::simd_lane_op<kExprI8x16ReplaceLane, 16, kS128, kI32>,
        &BodyGen::simd_lane_op<kExprI16x8ReplaceLane, 8, kS128, kI32>,
        &BodyGen::simd_lane_op<kExprI32x4ReplaceLane, 4, kS128, kI32>,
        &BodyGen::simd_lane_op<kExprI64x2ReplaceLane, 2, kS128, kI64>,
        &BodyGen::simd_lane_op<kExprF32x4ReplaceLane, 4, kS128, kF32>,
        &BodyGen::simd_lane_op<kExprF64x2ReplaceLane, 2, kS128, kF64>,

        &BodyGen::op_with_prefix<kExprI8x16Splat, kI32>,
        &BodyGen::op_with_prefix<kExprI8x16Eq, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprI8x16Ne, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprI8x16LtS, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprI8x16LtU, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprI8x16GtS, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprI8x16GtU, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprI8x16LeS, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprI8x16LeU, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprI8x16GeS, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprI8x16GeU, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprI8x16Abs, kS128>,
        &BodyGen::op_with_prefix<kExprI8x16Neg, kS128>,
        &BodyGen::op_with_prefix<kExprI8x16Shl, kS128, kI32>,
        &BodyGen::op_with_prefix<kExprI8x16ShrS, kS128, kI32>,
        &BodyGen::op_with_prefix<kExprI8x16ShrU, kS128, kI32>,
        &BodyGen::op_with_prefix<kExprI8x16Add, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprI8x16AddSatS, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprI8x16AddSatU, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprI8x16Sub, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprI8x16SubSatS, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprI8x16SubSatU, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprI8x16MinS, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprI8x16MinU, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprI8x16MaxS, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprI8x16MaxU, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprI8x16RoundingAverageU, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprI8x16Popcnt, kS128>,

        &BodyGen::op_with_prefix<kExprI16x8Splat, kI32>,
        &BodyGen::op_with_prefix<kExprI16x8Eq, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprI16x8Ne, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprI16x8LtS, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprI16x8LtU, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprI16x8GtS, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprI16x8GtU, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprI16x8LeS, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprI16x8LeU, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprI16x8GeS, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprI16x8GeU, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprI16x8Abs, kS128>,
        &BodyGen::op_with_prefix<kExprI16x8Neg, kS128>,
        &BodyGen::op_with_prefix<kExprI16x8Shl, kS128, kI32>,
        &BodyGen::op_with_prefix<kExprI16x8ShrS, kS128, kI32>,
        &BodyGen::op_with_prefix<kExprI16x8ShrU, kS128, kI32>,
        &BodyGen::op_with_prefix<kExprI16x8Add, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprI16x8AddSatS, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprI16x8AddSatU, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprI16x8Sub, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprI16x8SubSatS, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprI16x8SubSatU, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprI16x8Mul, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprI16x8MinS, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprI16x8MinU, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprI16x8MaxS, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprI16x8MaxU, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprI16x8RoundingAverageU, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprI16x8ExtMulLowI8x16S, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprI16x8ExtMulLowI8x16U, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprI16x8ExtMulHighI8x16S, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprI16x8ExtMulHighI8x16U, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprI16x8Q15MulRSatS, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprI16x8ExtAddPairwiseI8x16S, kS128>,
        &BodyGen::op_with_prefix<kExprI16x8ExtAddPairwiseI8x16U, kS128>,

        &BodyGen::op_with_prefix<kExprI32x4Splat, kI32>,
        &BodyGen::op_with_prefix<kExprI32x4Eq, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprI32x4Ne, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprI32x4LtS, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprI32x4LtU, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprI32x4GtS, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprI32x4GtU, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprI32x4LeS, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprI32x4LeU, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprI32x4GeS, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprI32x4GeU, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprI32x4Abs, kS128>,
        &BodyGen::op_with_prefix<kExprI32x4Neg, kS128>,
        &BodyGen::op_with_prefix<kExprI32x4Shl, kS128, kI32>,
        &BodyGen::op_with_prefix<kExprI32x4ShrS, kS128, kI32>,
        &BodyGen::op_with_prefix<kExprI32x4ShrU, kS128, kI32>,
        &BodyGen::op_with_prefix<kExprI32x4Add, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprI32x4Sub, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprI32x4Mul, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprI32x4MinS, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprI32x4MinU, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprI32x4MaxS, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprI32x4MaxU, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprI32x4DotI16x8S, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprI32x4ExtMulLowI16x8S, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprI32x4ExtMulLowI16x8U, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprI32x4ExtMulHighI16x8S, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprI32x4ExtMulHighI16x8U, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprI32x4ExtAddPairwiseI16x8S, kS128>,
        &BodyGen::op_with_prefix<kExprI32x4ExtAddPairwiseI16x8U, kS128>,

        &BodyGen::op_with_prefix<kExprI64x2Splat, kI64>,
        &BodyGen::op_with_prefix<kExprI64x2Eq, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprI64x2Ne, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprI64x2LtS, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprI64x2GtS, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprI64x2LeS, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprI64x2GeS, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprI64x2Abs, kS128>,
        &BodyGen::op_with_prefix<kExprI64x2Neg, kS128>,
        &BodyGen::op_with_prefix<kExprI64x2Shl, kS128, kI32>,
        &BodyGen::op_with_prefix<kExprI64x2ShrS, kS128, kI32>,
        &BodyGen::op_with_prefix<kExprI64x2ShrU, kS128, kI32>,
        &BodyGen::op_with_prefix<kExprI64x2Add, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprI64x2Sub, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprI64x2Mul, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprI64x2ExtMulLowI32x4S, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprI64x2ExtMulLowI32x4U, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprI64x2ExtMulHighI32x4S, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprI64x2ExtMulHighI32x4U, kS128, kS128>,

        &BodyGen::op_with_prefix<kExprF32x4Splat, kF32>,
        &BodyGen::op_with_prefix<kExprF32x4Eq, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprF32x4Ne, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprF32x4Lt, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprF32x4Gt, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprF32x4Le, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprF32x4Ge, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprF32x4Abs, kS128>,
        &BodyGen::op_with_prefix<kExprF32x4Neg, kS128>,
        &BodyGen::op_with_prefix<kExprF32x4Sqrt, kS128>,
        &BodyGen::op_with_prefix<kExprF32x4Add, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprF32x4Sub, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprF32x4Mul, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprF32x4Div, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprF32x4Min, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprF32x4Max, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprF32x4Pmin, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprF32x4Pmax, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprF32x4Ceil, kS128>,
        &BodyGen::op_with_prefix<kExprF32x4Floor, kS128>,
        &BodyGen::op_with_prefix<kExprF32x4Trunc, kS128>,
        &BodyGen::op_with_prefix<kExprF32x4NearestInt, kS128>,

        &BodyGen::op_with_prefix<kExprF64x2Splat, kF64>,
        &BodyGen::op_with_prefix<kExprF64x2Eq, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprF64x2Ne, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprF64x2Lt, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprF64x2Gt, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprF64x2Le, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprF64x2Ge, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprF64x2Abs, kS128>,
        &BodyGen::op_with_prefix<kExprF64x2Neg, kS128>,
        &BodyGen::op_with_prefix<kExprF64x2Sqrt, kS128>,
        &BodyGen::op_with_prefix<kExprF64x2Add, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprF64x2Sub, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprF64x2Mul, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprF64x2Div, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprF64x2Min, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprF64x2Max, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprF64x2Pmin, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprF64x2Pmax, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprF64x2Ceil, kS128>,
        &BodyGen::op_with_prefix<kExprF64x2Floor, kS128>,
        &BodyGen::op_with_prefix<kExprF64x2Trunc, kS128>,
        &BodyGen::op_with_prefix<kExprF64x2NearestInt, kS128>,

        &BodyGen::op_with_prefix<kExprF64x2PromoteLowF32x4, kS128>,
        &BodyGen::op_with_prefix<kExprF64x2ConvertLowI32x4S, kS128>,
        &BodyGen::op_with_prefix<kExprF64x2ConvertLowI32x4U, kS128>,
        &BodyGen::op_with_prefix<kExprF32x4DemoteF64x2Zero, kS128>,
        &BodyGen::op_with_prefix<kExprI32x4TruncSatF64x2SZero, kS128>,
        &BodyGen::op_with_prefix<kExprI32x4TruncSatF64x2UZero, kS128>,

        &BodyGen::op_with_prefix<kExprI64x2SConvertI32x4Low, kS128>,
        &BodyGen::op_with_prefix<kExprI64x2SConvertI32x4High, kS128>,
        &BodyGen::op_with_prefix<kExprI64x2UConvertI32x4Low, kS128>,
        &BodyGen::op_with_prefix<kExprI64x2UConvertI32x4High, kS128>,

        &BodyGen::op_with_prefix<kExprI32x4SConvertF32x4, kS128>,
        &BodyGen::op_with_prefix<kExprI32x4UConvertF32x4, kS128>,
        &BodyGen::op_with_prefix<kExprF32x4SConvertI32x4, kS128>,
        &BodyGen::op_with_prefix<kExprF32x4UConvertI32x4, kS128>,

        &BodyGen::op_with_prefix<kExprI8x16SConvertI16x8, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprI8x16UConvertI16x8, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprI16x8SConvertI32x4, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprI16x8UConvertI32x4, kS128, kS128>,

        &BodyGen::op_with_prefix<kExprI16x8SConvertI8x16Low, kS128>,
        &BodyGen::op_with_prefix<kExprI16x8SConvertI8x16High, kS128>,
        &BodyGen::op_with_prefix<kExprI16x8UConvertI8x16Low, kS128>,
        &BodyGen::op_with_prefix<kExprI16x8UConvertI8x16High, kS128>,
        &BodyGen::op_with_prefix<kExprI32x4SConvertI16x8Low, kS128>,
        &BodyGen::op_with_prefix<kExprI32x4SConvertI16x8High, kS128>,
        &BodyGen::op_with_prefix<kExprI32x4UConvertI16x8Low, kS128>,
        &BodyGen::op_with_prefix<kExprI32x4UConvertI16x8High, kS128>,

        &BodyGen::op_with_prefix<kExprS128Not, kS128>,
        &BodyGen::op_with_prefix<kExprS128And, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprS128AndNot, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprS128Or, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprS128Xor, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprS128Select, kS128, kS128, kS128>,

        &BodyGen::simd_shuffle,
        &BodyGen::op_with_prefix<kExprI8x16Swizzle, kS128, kS128>,

        &BodyGen::memop<kExprS128LoadMem>,                         //
        &BodyGen::memop<kExprS128Load8x8S>,                        //
        &BodyGen::memop<kExprS128Load8x8U>,                        //
        &BodyGen::memop<kExprS128Load16x4S>,                       //
        &BodyGen::memop<kExprS128Load16x4U>,                       //
        &BodyGen::memop<kExprS128Load32x2S>,                       //
        &BodyGen::memop<kExprS128Load32x2U>,                       //
        &BodyGen::memop<kExprS128Load8Splat>,                      //
        &BodyGen::memop<kExprS128Load16Splat>,                     //
        &BodyGen::memop<kExprS128Load32Splat>,                     //
        &BodyGen::memop<kExprS128Load64Splat>,                     //
        &BodyGen::memop<kExprS128Load32Zero>,                      //
        &BodyGen::memop<kExprS128Load64Zero>,                      //
        &BodyGen::simd_lane_memop<kExprS128Load8Lane, 16, kS128>,  //
        &BodyGen::simd_lane_memop<kExprS128Load16Lane, 8, kS128>,  //
        &BodyGen::simd_lane_memop<kExprS128Load32Lane, 4, kS128>,  //
        &BodyGen::simd_lane_memop<kExprS128Load64Lane, 2, kS128>,  //

        &BodyGen::op_with_prefix<kExprI8x16RelaxedSwizzle, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprI8x16RelaxedLaneSelect, kS128, kS128,
                                 kS128>,
        &BodyGen::op_with_prefix<kExprI16x8RelaxedLaneSelect, kS128, kS128,
                                 kS128>,
        &BodyGen::op_with_prefix<kExprI32x4RelaxedLaneSelect, kS128, kS128,
                                 kS128>,
        &BodyGen::op_with_prefix<kExprI64x2RelaxedLaneSelect, kS128, kS128,
                                 kS128>,
        &BodyGen::op_with_prefix<kExprF32x4Qfma, kS128, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprF32x4Qfms, kS128, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprF64x2Qfma, kS128, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprF64x2Qfms, kS128, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprF32x4RelaxedMin, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprF32x4RelaxedMax, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprF64x2RelaxedMin, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprF64x2RelaxedMax, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprI32x4RelaxedTruncF32x4S, kS128>,
        &BodyGen::op_with_prefix<kExprI32x4RelaxedTruncF32x4U, kS128>,
        &BodyGen::op_with_prefix<kExprI32x4RelaxedTruncF64x2SZero, kS128>,
        &BodyGen::op_with_prefix<kExprI32x4RelaxedTruncF64x2UZero, kS128>,
        &BodyGen::op_with_prefix<kExprI16x8DotI8x16I7x16S, kS128, kS128>,
        &BodyGen::op_with_prefix<kExprI32x4DotI8x16I7x16AddS, kS128, kS128,
                                 kS128>);

    GenerateOneOf(alternatives, data);
  }

  void Generate(ValueType type, DataRange* data) {
    switch (type.kind()) {
      case kVoid:
        return GenerateVoid(data);
      case kI32:
        return GenerateI32(data);
      case kI64:
        return GenerateI64(data);
      case kF32:
        return GenerateF32(data);
      case kF64:
        return GenerateF64(data);
      case kS128:
        return GenerateS128(data);
      case kRefNull:
        return GenerateRef(type.heap_type(), data, kNullable);
      case kRef:
        return GenerateRef(type.heap_type(), data, kNonNullable);
      default:
        UNREACHABLE();
    }
  }

  template <ValueKind kind>
  constexpr void Generate(DataRange* data) {
    switch (kind) {
      case kVoid:
        return GenerateVoid(data);
      case kI32:
        return GenerateI32(data);
      case kI64:
        return GenerateI64(data);
      case kF32:
        return GenerateF32(data);
      case kF64:
        return GenerateF64(data);
      case kS128:
        return GenerateS128(data);
      default:
        // For kRefNull and kRef we need the HeapType which we can get from the
        // ValueType.
        UNREACHABLE();
    }
  }

  template <ValueKind T1, ValueKind T2, ValueKind... Ts>
  void Generate(DataRange* data) {
    // TODO(clemensb): Implement a more even split.
    // TODO(mliedtke): Instead of splitting we should probably "reserve" amount
    // x for the first part, any reserved but potentially unused random bytes
    // should then carry over instead of throwing them away which heavily
    // reduces the amount of actually used random input bytes.
    auto first_data = data->split();
    Generate<T1>(&first_data);
    Generate<T2, Ts...>(data);
  }

  void GenerateRef(HeapType type, DataRange* data,
                   Nullability nullability = kNullable) {
    std::optional<GeneratorRecursionScope> rec_scope;
    if (nullability) {
      rec_scope.emplace(this);
    }

    if (recursion_limit_reached() || data->size() == 0) {
      if (nullability == kNullable) {
        ref_null(type, data);
        return;
      }
      // It is ok not to return here because the non-nullable types are not
      // recursive by construction, so the depth is limited already.
    }

    constexpr auto alternatives_indexed_type =
        CreateArray(&BodyGen::new_object,       //
                    &BodyGen::get_local_ref,    //
                    &BodyGen::array_get_ref,    //
                    &BodyGen::struct_get_ref,   //
                    &BodyGen::ref_cast,         //
                    &BodyGen::ref_as_non_null,  //
                    &BodyGen::br_on_cast);      //

    constexpr auto alternatives_func_any =
        CreateArray(&BodyGen::table_get,           //
                    &BodyGen::get_local_ref,       //
                    &BodyGen::array_get_ref,       //
                    &BodyGen::struct_get_ref,      //
                    &BodyGen::ref_cast,            //
                    &BodyGen::any_convert_extern,  //
                    &BodyGen::ref_as_non_null,     //
                    &BodyGen::br_on_cast);         //

    constexpr auto alternatives_other =
        CreateArray(&BodyGen::array_get_ref,    //
                    &BodyGen::get_local_ref,    //
                    &BodyGen::struct_get_ref,   //
                    &BodyGen::ref_cast,         //
                    &BodyGen::ref_as_non_null,  //
                    &BodyGen::br_on_cast);      //

    switch (type.representation()) {
      // For abstract types, sometimes generate one of their subtypes.
      case HeapType::kAny: {
        // Weighted according to the types in the module:
        // If there are D data types and F function types, the relative
        // frequencies for dataref is D, for funcref F, and for i31ref and
        // falling back to anyref 2.
        const uint8_t num_data_types =
            static_cast<uint8_t>(structs_.size() + arrays_.size());
        const uint8_t emit_i31ref = 2;
        const uint8_t fallback_to_anyref = 2;
        uint8_t random = data->get<uint8_t>() %
                         (num_data_types + emit_i31ref + fallback_to_anyref);
        // We have to compute this first so in case GenerateOneOf fails
        // we will continue to fall back on an alternative that is guaranteed
        // to generate a value of the wanted type.
        // In order to know which alternative to fall back to in case
        // GenerateOneOf failed, the random variable is recomputed.
        if (random >= num_data_types + emit_i31ref) {
          if (GenerateOneOf(alternatives_func_any, type, data, nullability)) {
            return;
          }
          random = data->get<uint8_t>() % (num_data_types + emit_i31ref);
        }
        if (random < structs_.size()) {
          GenerateRef(HeapType(HeapType::kStruct), data, nullability);
        } else if (random < num_data_types) {
          GenerateRef(HeapType(HeapType::kArray), data, nullability);
        } else {
          GenerateRef(HeapType(HeapType::kI31), data, nullability);
        }
        return;
      }
      case HeapType::kArray: {
        constexpr uint8_t fallback_to_dataref = 1;
        uint8_t random =
            data->get<uint8_t>() % (arrays_.size() + fallback_to_dataref);
        // Try generating one of the alternatives and continue to the rest of
        // the methods in case it fails.
        if (random >= arrays_.size()) {
          if (GenerateOneOf(alternatives_other, type, data, nullability))
            return;
          random = data->get<uint8_t>() % arrays_.size();
        }
        ModuleTypeIndex index = arrays_[random];
        DCHECK(builder_->builder()->IsArrayType(index));
        GenerateRef(HeapType(index), data, nullability);
        return;
      }
      case HeapType::kStruct: {
        constexpr uint8_t fallback_to_dataref = 2;
        uint8_t random =
            data->get<uint8_t>() % (structs_.size() + fallback_to_dataref);
        // Try generating one of the alternatives
        // and continue to the rest of the methods in case it fails.
        if (random >= structs_.size()) {
          if (GenerateOneOf(alternatives_other, type, data, nullability)) {
            return;
          }
          random = data->get<uint8_t>() % structs_.size();
        }
        ModuleTypeIndex index = structs_[random];
        DCHECK(builder_->builder()->IsStructType(index));
        GenerateRef(HeapType(index), data, nullability);
        return;
      }
      case HeapType::kEq: {
        const uint8_t num_types = arrays_.size() + structs_.size();
        const uint8_t emit_i31ref = 2;
        constexpr uint8_t fallback_to_eqref = 1;
        uint8_t random = data->get<uint8_t>() %
                         (num_types
"""


```