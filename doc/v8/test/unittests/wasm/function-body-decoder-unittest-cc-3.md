Response:
My thought process for analyzing the provided C++ code snippet goes like this:

1. **Identify the Core Purpose:** The filename `function-body-decoder-unittest.cc` immediately suggests this code is a unit test for a component responsible for decoding WebAssembly function bodies. The presence of `TEST_F` macros confirms this.

2. **Recognize the Testing Framework:** The `TEST_F(FunctionBodyDecoderTest, ...)` pattern clearly indicates the use of a C++ testing framework (likely Google Test, a common choice in V8). The `FunctionBodyDecoderTest` class is the fixture for these tests.

3. **Focus on Individual Test Cases:** Each `TEST_F` block represents a specific test scenario. I need to understand what each test is trying to verify about the function body decoder.

4. **Analyze Test Names:** The test names are often descriptive. For example, `BrTable0`, `BrTable1a`, `BrTableSubtyping`, `Brv1`, `Select`, `Throw`, `TryCatch`, etc., clearly point to the WebAssembly instructions being tested (e.g., `br_table`, `brv`, `select`, `throw`, `try`/`catch`).

5. **Examine the Test Logic:** Inside each test, I look for the core actions:
    * **`ExpectValidates(...)`:** This suggests the test is checking if a given sequence of bytecode (representing a WebAssembly function body) is considered valid by the decoder for a specific function signature.
    * **`ExpectFailure(...)`:** This indicates the test is ensuring that an invalid sequence of bytecode is correctly identified as such by the decoder. It often includes an expected error message.
    * **`Validate(...)`:** This seems to be a lower-level validation function, possibly used when the success/failure condition is more complex or based on a conditional.
    * **Bytecode Representation:** Pay attention to the syntax used to represent the WebAssembly bytecode (e.g., `kExprBrTable`, `WASM_BR_TABLE`, `WASM_LOCAL_GET`, etc.). These are macros or constants defined elsewhere in the V8 codebase. While I don't need to know the exact values, understanding their general meaning is crucial.
    * **Function Signatures:**  The `sigs` object likely provides pre-defined function signatures (`v_v`, `i_i`, `i_ii`, etc.) to be used in the tests. This tells me about the expected input and output types of the functions being tested.

6. **Identify Key WebAssembly Features Being Tested:**  Based on the test names and bytecode used, I can identify the specific WebAssembly features under scrutiny:
    * **Control Flow Instructions:** `br`, `br_if`, `br_table`, `block`, `loop`, `if`/`else`.
    * **Value Selection:** `select`.
    * **Exception Handling:** `throw`, `try`/`catch`, `rethrow`, `delegate`, `throw_ref`, `try_table`.
    * **Multi-Value Returns:**  The tests with `_X` suffixes (e.g., `WASM_BLOCK_X`) are testing blocks and loops that can return multiple values.
    * **Bulk Memory Operations:** `memory.init`, `data.drop`, `memory.copy`, `memory.fill`.

7. **Infer Functionality Based on Test Coverage:**  The variety of tests suggests that the `FunctionBodyDecoder` is responsible for a comprehensive set of validation checks, including:
    * **Instruction Existence and Order:** Checking if the instructions form a valid sequence.
    * **Type Correctness:** Verifying that the operands of instructions have the expected types.
    * **Stack Management:** Ensuring the correct number of values are on the stack at various points.
    * **Branch Target Validity:**  Confirming that branch targets are within the valid scope.
    * **Arity Matching:**  Ensuring the number of values pushed and popped by blocks and control flow instructions matches expectations.
    * **Feature Support:**  Some tests (like those with `WASM_FEATURE_SCOPE`) might be conditional based on enabled WebAssembly features.

8. **Connect to Potential User Errors:** As I analyze the `ExpectFailure` tests, I think about how these scenarios might arise as common programming mistakes in WebAssembly:
    * **Incorrect Operand Types:** Trying to add an integer and a float.
    * **Stack Underflow/Overflow:** Not having enough values on the stack when an instruction expects them.
    * **Invalid Branch Targets:**  Branching to a label that doesn't exist or is out of scope.
    * **Type Mismatches in Control Flow:**  Blocks or if/else branches producing values of the wrong type.

9. **Synthesize a Functional Summary:** Based on the above steps, I can formulate a description of the file's functionality.

10. **Address Specific Instructions:**  Go back and check if there are any specific instructions or patterns mentioned in the prompt to address them directly (like the `.tq` extension, though this part of the prompt is contradictory as the filename is `.cc`).

By following this structured approach, I can effectively analyze the C++ unit test code and understand the functionality of the `FunctionBodyDecoder` it's testing.
This is part 4 of a 7-part analysis of the V8 source code file `v8/test/unittests/wasm/function-body-decoder-unittest.cc`. Building upon the previous parts, this section continues to test the functionality of the WebAssembly function body decoder.

Here's a breakdown of the functionality covered in this specific part:

**Core Functionality: Testing WebAssembly Instructions and their Validation**

This section primarily focuses on testing the decoder's ability to correctly validate different WebAssembly instructions, particularly those related to control flow, exception handling, and multi-value returns.

* **`br_table` Instruction (Jump Tables):**
    * **Validations:**  Tests scenarios where `br_table` jumps to valid targets based on an index.
    * **Failures:**  Tests scenarios where `br_table` has invalid indices (out of bounds), incorrect branch depths, or type mismatches with the surrounding blocks. It also tests cases where the `br_table` appears in an invalid context (e.g., without a selector).
    * **Subtyping:** Tests `br_table` in the context of struct subtyping, ensuring type compatibility.
    * **Edge Cases:** Tests scenarios where the `br_table` data is incomplete.

* **`brv` and `brv_if` Instructions (Branch with Value):**
    * **Validations:** Tests branching with a value to a surrounding block or loop.
    * **Type Checking:** Verifies that the type of the value being branched matches the expected type of the target block.
    * **Failures:** Tests scenarios with type mismatches.

* **`select` Instruction (Conditional Selection):**
    * **Validations:** Tests selecting between two values based on a condition (i32).
    * **Type Checking:** Ensures that the two selectable values have the same type.
    * **`select` with Type Annotation:** Tests the `select` instruction with explicit type specification (e.g., `select.i32`, `select.f32`).
    * **Failures:** Tests scenarios with type mismatches between the selectable values or the condition.

* **`throw` Instruction (Throwing Exceptions):**
    * **Validations:** Tests throwing predefined exceptions with the correct number and types of arguments.
    * **Failures:** Tests throwing exceptions with incorrect arguments or invalid exception indices.

* **`try`, `catch`, `rethrow`, `delegate` Instructions (Exception Handling - Legacy):**
    * **Validations:** Tests basic `try-catch` blocks, including `catch-all`.
    * **Nesting:** Tests nested `try-delegate-catch` scenarios.
    * **Failures:** Tests invalid nesting, incorrect usage of `rethrow` and `delegate`, and misplaced `catch` blocks.

* **`throw_ref`, `try_table` Instructions (Exception Handling - Reference Types):**
    * **Validations:** Tests throwing and catching exceptions using reference types (`exnref`). It covers different `catch` kinds: `catch`, `catch_ref`, `catch_all`, and `catch_all_ref`.
    * **Failures:** Tests throwing non-`exnref` values, invalid catch kinds, and type mismatches when branching to `try_table` blocks.

* **Multi-Value Blocks and Loops:**
    * **Validations:** Tests blocks and loops that can return multiple values. Verifies that the correct number and types of values are present on the stack after the block/loop.
    * **Failures:** Tests scenarios where the number or types of returned values are incorrect.

* **Block and Loop Parameters:**
    * **Validations:** Tests blocks and loops that take parameters, ensuring the correct number and types of parameters are provided.
    * **Failures:** Tests scenarios with incorrect parameter counts or types.

* **If-Else with Parameters:**
    * **Validations:** Tests `if-else` statements that can return multiple values, ensuring both branches return the same number and types of values.
    * **Failures:** Tests scenarios where the `if` and `else` branches return a different number or types of values.

* **Regression Test:** Includes a test for a specific bug fix (`Regression709741`).

* **Memory and Data Segment Instructions (`memory.init`, `data.drop`, `memory.copy`, `memory.fill`):**
    * **Validations:** Tests the basic functionality of these instructions, assuming a memory and data segment have been declared.
    * **Failures:** Tests scenarios where data segment indices are invalid.

**Relation to Javascript:**

While this C++ code directly tests the WebAssembly decoder, its functionality is crucial for running WebAssembly code in a JavaScript environment. When JavaScript calls a WebAssembly function, the V8 engine needs to parse and validate the WebAssembly bytecode. This decoder is a key component in that process.

**Example (Illustrative - Simplified):**

Let's consider the `BrTable1a` test:

```c++
TEST_F(FunctionBodyDecoderTest, BrTable1a) {
  ExpectValidates(sigs.v_v(),
                  {B1(WASM_BR_TABLE(WASM_I32V_2(67), 0, BR_TARGET(0)))});
}
```

In JavaScript, a simplified equivalent of what this test validates could be visualized as:

```javascript
// Hypothetical WebAssembly module (very simplified)
const wasmModule = {
  exports: {
    myFunc: () => {
      let index = 67; // WASM_I32V_2(67) -  index value
      switch (index) {
        case 0: // BR_TARGET(0) - Branch to depth 0 (end of the function/block)
          break;
        default:
          break;
      }
    }
  }
};

// When V8 executes 'myFunc', the function body decoder (being tested)
// would validate the underlying bytecode for the switch-like behavior.
wasmModule.exports.myFunc();
```

**Code Logic Inference (Example):**

Consider the `BrTable_invalid_br1` test:

```c++
TEST_F(FunctionBodyDecoderTest, BrTable_invalid_br1) {
  for (int depth = 0; depth < 4; depth++) {
    uint8_t code[] = {
        B1(WASM_BR_TABLE(WASM_LOCAL_GET(0), 0, BR_TARGET(depth)))};
    Validate(depth <= 1, sigs.v_i(), code);
  }
}
```

* **Assumption:** The function takes one i32 argument (`sigs.v_i()`).
* **Input:** A `br_table` instruction where the target depth varies from 0 to 3.
* **Logic:** The `Validate` function checks if the `depth` is less than or equal to 1.
* **Output:**
    * If `depth` is 0 or 1, the `Validate` function will likely pass, indicating the `br_table` is valid for those depths.
    * If `depth` is 2 or 3, the `Validate` function will likely fail, indicating the `br_table` is invalid because it tries to branch too far out.

**Common Programming Errors (Illustrative):**

* **Incorrect `br_table` Index:**  A common error is providing an index that goes beyond the number of target labels. This would be caught by tests like `BrTable0c`. In a real WebAssembly module, this could lead to undefined behavior.
* **Type Mismatch in `select`:** Trying to select between an integer and a float without explicit conversion would be caught by tests like `Select_fail1`. This is a common type error in programming.
* **Mismatched `try-catch` Blocks:**  Not having a matching `catch` for a `try` or having `catch` blocks in the wrong order (like `catch-all` before a specific `catch`) would be caught by tests like `TryCatch`. This mirrors common errors in exception handling in other languages.

**Summary of Functionality in Part 4:**

This part of the `function-body-decoder-unittest.cc` file comprehensively tests the V8 WebAssembly function body decoder's ability to:

* **Validate the structure and semantics of `br_table`, `brv`, and `brv_if` instructions.**
* **Enforce type correctness for `select` instructions, including variations with type annotations.**
* **Verify the proper usage of exception handling instructions (`throw`, `try`, `catch`, `rethrow`, `delegate`, `throw_ref`, `try_table`).**
* **Support and validate multi-value returns from blocks and loops.**
* **Handle parameters for blocks and loops.**
* **Validate `if-else` statements with multi-value returns.**
* **Ensure the correctness of memory and data segment related instructions (`memory.init`, `data.drop`, `memory.copy`, `memory.fill`).**

Essentially, it ensures that the decoder correctly identifies valid and invalid WebAssembly bytecode sequences for a significant portion of the language's control flow and exception handling features. This is crucial for the security and correctness of WebAssembly execution within the V8 JavaScript engine.

Prompt: 
```
这是目录为v8/test/unittests/wasm/function-body-decoder-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/wasm/function-body-decoder-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共7部分，请归纳一下它的功能

"""
ch ^ 1))};

      Validate(type == kWasmI32, &sig, code);
    }
  }
}

TEST_F(FunctionBodyDecoderTest, BrTable0) {
  ExpectFailure(sigs.v_v(), {kExprBrTable, 0, BR_TARGET(0)});
}

TEST_F(FunctionBodyDecoderTest, BrTable0b) {
  static uint8_t code[] = {kExprI32Const, 11, kExprBrTable, 0, BR_TARGET(0)};
  ExpectValidates(sigs.v_v(), code);
  ExpectFailure(sigs.i_i(), code);
}

TEST_F(FunctionBodyDecoderTest, BrTable0c) {
  static uint8_t code[] = {kExprI32Const, 11, kExprBrTable, 0, BR_TARGET(1)};
  ExpectFailure(sigs.v_v(), code);
  ExpectFailure(sigs.i_i(), code);
}

TEST_F(FunctionBodyDecoderTest, BrTable1a) {
  ExpectValidates(sigs.v_v(),
                  {B1(WASM_BR_TABLE(WASM_I32V_2(67), 0, BR_TARGET(0)))});
}

TEST_F(FunctionBodyDecoderTest, BrTable1b) {
  static uint8_t code[] = {B1(WASM_BR_TABLE(WASM_ZERO, 0, BR_TARGET(0)))};
  ExpectValidates(sigs.v_v(), code);
  ExpectFailure(sigs.i_i(), code);
  ExpectFailure(sigs.f_ff(), code);
  ExpectFailure(sigs.d_dd(), code);
}

TEST_F(FunctionBodyDecoderTest, BrTable2a) {
  ExpectValidates(
      sigs.v_v(),
      {B1(WASM_BR_TABLE(WASM_I32V_2(67), 1, BR_TARGET(0), BR_TARGET(0)))});
}

TEST_F(FunctionBodyDecoderTest, BrTable2b) {
  ExpectValidates(sigs.v_v(),
                  {WASM_BLOCK(WASM_BLOCK(WASM_BR_TABLE(
                      WASM_I32V_2(67), 1, BR_TARGET(0), BR_TARGET(1))))});
}

TEST_F(FunctionBodyDecoderTest, BrTableSubtyping) {
  ModuleTypeIndex supertype1 = builder.AddStruct({F(kWasmI8, true)});
  ModuleTypeIndex supertype2 =
      builder.AddStruct({F(kWasmI8, true), F(kWasmI16, false)}, supertype1);
  ModuleTypeIndex subtype = builder.AddStruct(
      {F(kWasmI8, true), F(kWasmI16, false), F(kWasmI32, true)}, supertype2);
  ExpectValidates(
      sigs.v_v(),
      {WASM_BLOCK_R(wasm::ValueType::Ref(supertype1),
                    WASM_BLOCK_R(wasm::ValueType::Ref(supertype2),
                                 WASM_STRUCT_NEW(subtype, WASM_I32V(10),
                                                 WASM_I32V(20), WASM_I32V(30)),
                                 WASM_BR_TABLE(WASM_I32V(5), 1, BR_TARGET(0),
                                               BR_TARGET(1))),
                    WASM_UNREACHABLE),
       WASM_DROP});
}

TEST_F(FunctionBodyDecoderTest, BrTable_off_end) {
  static uint8_t code[] = {
      B1(WASM_BR_TABLE(WASM_LOCAL_GET(0), 0, BR_TARGET(0)))};
  for (size_t len = 1; len < sizeof(code); len++) {
    ExpectFailure(sigs.i_i(), base::VectorOf(code, len), kAppendEnd);
    ExpectFailure(sigs.i_i(), base::VectorOf(code, len), kOmitEnd);
  }
}

TEST_F(FunctionBodyDecoderTest, BrTable_invalid_br1) {
  for (int depth = 0; depth < 4; depth++) {
    uint8_t code[] = {
        B1(WASM_BR_TABLE(WASM_LOCAL_GET(0), 0, BR_TARGET(depth)))};
    Validate(depth <= 1, sigs.v_i(), code);
  }
}

TEST_F(FunctionBodyDecoderTest, BrTable_invalid_br2) {
  for (int depth = 0; depth < 7; depth++) {
    uint8_t code[] = {
        WASM_LOOP(WASM_BR_TABLE(WASM_LOCAL_GET(0), 0, BR_TARGET(depth)))};
    Validate(depth < 2, sigs.v_i(), code);
  }
}

TEST_F(FunctionBodyDecoderTest, BrTable_arity_mismatch1) {
  ExpectFailure(
      sigs.v_v(),
      {WASM_BLOCK(WASM_BLOCK_I(
          WASM_ONE, WASM_BR_TABLE(WASM_ONE, 1, BR_TARGET(0), BR_TARGET(1))))});
}

TEST_F(FunctionBodyDecoderTest, BrTable_arity_mismatch2) {
  ExpectFailure(
      sigs.v_v(),
      {WASM_BLOCK_I(WASM_BLOCK(
          WASM_ONE, WASM_BR_TABLE(WASM_ONE, 1, BR_TARGET(0), BR_TARGET(1))))});
}

TEST_F(FunctionBodyDecoderTest, BrTable_arity_mismatch_loop1) {
  ExpectFailure(
      sigs.v_v(),
      {WASM_LOOP(WASM_BLOCK_I(
          WASM_ONE, WASM_BR_TABLE(WASM_ONE, 1, BR_TARGET(0), BR_TARGET(1))))});
}

TEST_F(FunctionBodyDecoderTest, BrTable_arity_mismatch_loop2) {
  ExpectFailure(
      sigs.v_v(),
      {WASM_BLOCK_I(WASM_LOOP(
          WASM_ONE, WASM_BR_TABLE(WASM_ONE, 1, BR_TARGET(0), BR_TARGET(1))))});
}

TEST_F(FunctionBodyDecoderTest, BrTable_loop_block) {
  ExpectValidates(
      sigs.v_v(),
      {WASM_LOOP(WASM_BLOCK(
          WASM_ONE, WASM_BR_TABLE(WASM_ONE, 1, BR_TARGET(0), BR_TARGET(1))))});
}

TEST_F(FunctionBodyDecoderTest, BrTable_block_loop) {
  ExpectValidates(
      sigs.v_v(),
      {WASM_LOOP(WASM_BLOCK(
          WASM_ONE, WASM_BR_TABLE(WASM_ONE, 1, BR_TARGET(0), BR_TARGET(1))))});
}

TEST_F(FunctionBodyDecoderTest, BrTable_type_mismatch1) {
  ExpectFailure(
      sigs.v_v(),
      {WASM_BLOCK_I(WASM_BLOCK_F(
          WASM_ONE, WASM_BR_TABLE(WASM_ONE, 1, BR_TARGET(0), BR_TARGET(1))))});
}

TEST_F(FunctionBodyDecoderTest, BrTable_type_mismatch2) {
  ExpectFailure(
      sigs.v_v(),
      {WASM_BLOCK_F(WASM_BLOCK_I(
          WASM_ONE, WASM_BR_TABLE(WASM_ONE, 1, BR_TARGET(0), BR_TARGET(1))))});
}

TEST_F(FunctionBodyDecoderTest, BrTable_type_mismatch_unreachable) {
  ExpectFailure(sigs.v_v(),
                {WASM_BLOCK_F(WASM_BLOCK_I(
                    WASM_UNREACHABLE,
                    WASM_BR_TABLE(WASM_ONE, 1, BR_TARGET(0), BR_TARGET(1))))});
}

TEST_F(FunctionBodyDecoderTest, BrUnreachable1) {
  ExpectValidates(sigs.v_i(),
                  {WASM_LOCAL_GET(0), kExprBrTable, 0, BR_TARGET(0)});
}

TEST_F(FunctionBodyDecoderTest, BrUnreachable2) {
  ExpectValidates(sigs.v_i(),
                  {WASM_LOCAL_GET(0), kExprBrTable, 0, BR_TARGET(0), WASM_NOP});
  ExpectFailure(sigs.v_i(),
                {WASM_LOCAL_GET(0), kExprBrTable, 0, BR_TARGET(0), WASM_ZERO});
}

TEST_F(FunctionBodyDecoderTest, Brv1) {
  ExpectValidates(sigs.i_i(), {WASM_BLOCK_I(WASM_BRV(0, WASM_ZERO))});
  ExpectValidates(sigs.i_i(),
                  {WASM_BLOCK_I(WASM_LOOP_I(WASM_BRV(2, WASM_ZERO)))});
}

TEST_F(FunctionBodyDecoderTest, Brv1_type) {
  ExpectValidates(sigs.i_ii(), {WASM_BLOCK_I(WASM_BRV(0, WASM_LOCAL_GET(0)))});
  ExpectValidates(sigs.l_ll(), {WASM_BLOCK_L(WASM_BRV(0, WASM_LOCAL_GET(0)))});
  ExpectValidates(sigs.f_ff(), {WASM_BLOCK_F(WASM_BRV(0, WASM_LOCAL_GET(0)))});
  ExpectValidates(sigs.d_dd(), {WASM_BLOCK_D(WASM_BRV(0, WASM_LOCAL_GET(0)))});
}

TEST_F(FunctionBodyDecoderTest, Brv1_type_n) {
  ExpectFailure(sigs.i_f(), {WASM_BLOCK_I(WASM_BRV(0, WASM_LOCAL_GET(0)))});
  ExpectFailure(sigs.i_d(), {WASM_BLOCK_I(WASM_BRV(0, WASM_LOCAL_GET(0)))});
}

TEST_F(FunctionBodyDecoderTest, BrvIf1) {
  ExpectValidates(sigs.i_v(), {WASM_BLOCK_I(WASM_BRV_IF_ZERO(0, WASM_ZERO))});
}

TEST_F(FunctionBodyDecoderTest, BrvIf1_type) {
  ExpectValidates(sigs.i_i(),
                  {WASM_BLOCK_I(WASM_BRV_IF_ZERO(0, WASM_LOCAL_GET(0)))});
  ExpectValidates(sigs.l_l(),
                  {WASM_BLOCK_L(WASM_BRV_IF_ZERO(0, WASM_LOCAL_GET(0)))});
  ExpectValidates(sigs.f_ff(),
                  {WASM_BLOCK_F(WASM_BRV_IF_ZERO(0, WASM_LOCAL_GET(0)))});
  ExpectValidates(sigs.d_dd(),
                  {WASM_BLOCK_D(WASM_BRV_IF_ZERO(0, WASM_LOCAL_GET(0)))});
}

TEST_F(FunctionBodyDecoderTest, BrvIf1_type_n) {
  ExpectFailure(sigs.i_f(),
                {WASM_BLOCK_I(WASM_BRV_IF_ZERO(0, WASM_LOCAL_GET(0)))});
  ExpectFailure(sigs.i_d(),
                {WASM_BLOCK_I(WASM_BRV_IF_ZERO(0, WASM_LOCAL_GET(0)))});
}

TEST_F(FunctionBodyDecoderTest, Select) {
  ExpectValidates(sigs.i_i(), {WASM_SELECT(WASM_LOCAL_GET(0), WASM_LOCAL_GET(0),
                                           WASM_ZERO)});
  ExpectValidates(sigs.f_ff(),
                  {WASM_SELECT(WASM_F32(0.0), WASM_F32(0.0), WASM_ZERO)});
  ExpectValidates(sigs.d_dd(),
                  {WASM_SELECT(WASM_F64(0.0), WASM_F64(0.0), WASM_ZERO)});
  ExpectValidates(sigs.l_l(),
                  {WASM_SELECT(WASM_I64V_1(0), WASM_I64V_1(0), WASM_ZERO)});
}

TEST_F(FunctionBodyDecoderTest, Select_needs_value_type) {
  ExpectFailure(sigs.a_a(),
                {WASM_SELECT(WASM_LOCAL_GET(0), WASM_LOCAL_GET(0), WASM_ZERO)});
  ExpectFailure(sigs.c_c(),
                {WASM_SELECT(WASM_LOCAL_GET(0), WASM_LOCAL_GET(0), WASM_ZERO)});
}

TEST_F(FunctionBodyDecoderTest, Select_fail1) {
  ExpectFailure(sigs.i_i(), {WASM_SELECT(WASM_F32(0.0), WASM_LOCAL_GET(0),
                                         WASM_LOCAL_GET(0))});
  ExpectFailure(sigs.i_i(), {WASM_SELECT(WASM_LOCAL_GET(0), WASM_F32(0.0),
                                         WASM_LOCAL_GET(0))});
  ExpectFailure(sigs.i_i(), {WASM_SELECT(WASM_LOCAL_GET(0), WASM_LOCAL_GET(0),
                                         WASM_F32(0.0))});
}

TEST_F(FunctionBodyDecoderTest, Select_fail2) {
  for (size_t i = 0; i < arraysize(kValueTypes); i++) {
    ValueType type = kValueTypes[i];
    if (type == kWasmI32) continue;
    // Select without specified type is only allowed for number types.
    if (type == kWasmExternRef) continue;

    ValueType types[] = {type, kWasmI32, type};
    FunctionSig sig(1, 2, types);

    ExpectValidates(&sig, {WASM_SELECT(WASM_LOCAL_GET(1), WASM_LOCAL_GET(1),
                                       WASM_LOCAL_GET(0))});

    ExpectFailure(&sig, {WASM_SELECT(WASM_LOCAL_GET(1), WASM_LOCAL_GET(0),
                                     WASM_LOCAL_GET(0))});

    ExpectFailure(&sig, {WASM_SELECT(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1),
                                     WASM_LOCAL_GET(0))});

    ExpectFailure(&sig, {WASM_SELECT(WASM_LOCAL_GET(0), WASM_LOCAL_GET(0),
                                     WASM_LOCAL_GET(1))});
  }
}

TEST_F(FunctionBodyDecoderTest, Select_TypeCheck) {
  ExpectFailure(sigs.i_i(), {WASM_SELECT(WASM_F32(9.9), WASM_LOCAL_GET(0),
                                         WASM_LOCAL_GET(0))});

  ExpectFailure(sigs.i_i(), {WASM_SELECT(WASM_LOCAL_GET(0), WASM_F64(0.25),
                                         WASM_LOCAL_GET(0))});

  ExpectFailure(sigs.i_i(), {WASM_SELECT(WASM_F32(9.9), WASM_LOCAL_GET(0),
                                         WASM_I64V_1(0))});
}

TEST_F(FunctionBodyDecoderTest, SelectWithType) {
  ExpectValidates(sigs.i_i(), {WASM_SELECT_I(WASM_LOCAL_GET(0),
                                             WASM_LOCAL_GET(0), WASM_ZERO)});
  ExpectValidates(sigs.f_ff(),
                  {WASM_SELECT_F(WASM_F32(0.0), WASM_F32(0.0), WASM_ZERO)});
  ExpectValidates(sigs.d_dd(),
                  {WASM_SELECT_D(WASM_F64(0.0), WASM_F64(0.0), WASM_ZERO)});
  ExpectValidates(sigs.l_l(),
                  {WASM_SELECT_L(WASM_I64V_1(0), WASM_I64V_1(0), WASM_ZERO)});
  ExpectValidates(sigs.a_a(),
                  {WASM_SELECT_R(WASM_REF_NULL(kExternRefCode),
                                 WASM_REF_NULL(kExternRefCode), WASM_ZERO)});
  ExpectValidates(sigs.c_c(),
                  {WASM_SELECT_A(WASM_REF_NULL(kFuncRefCode),
                                 WASM_REF_NULL(kFuncRefCode), WASM_ZERO)});
}

TEST_F(FunctionBodyDecoderTest, SelectWithType_fail) {
  ExpectFailure(sigs.i_i(), {WASM_SELECT_F(WASM_LOCAL_GET(0), WASM_LOCAL_GET(0),
                                           WASM_ZERO)});
  ExpectFailure(sigs.f_ff(),
                {WASM_SELECT_D(WASM_F32(0.0), WASM_F32(0.0), WASM_ZERO)});
  ExpectFailure(sigs.d_dd(),
                {WASM_SELECT_L(WASM_F64(0.0), WASM_F64(0.0), WASM_ZERO)});
  ExpectFailure(sigs.l_l(),
                {WASM_SELECT_I(WASM_I64V_1(0), WASM_I64V_1(0), WASM_ZERO)});
}

TEST_F(FunctionBodyDecoderTest, Throw) {
  uint8_t ex1 = builder.AddException(sigs.v_v());
  uint8_t ex2 = builder.AddException(sigs.v_i());
  uint8_t ex3 = builder.AddException(sigs.v_ii());
  ExpectValidates(sigs.v_v(), {kExprThrow, ex1});
  ExpectValidates(sigs.v_v(), {WASM_I32V(0), kExprThrow, ex2});
  ExpectFailure(sigs.v_v(), {WASM_F32(0.0), kExprThrow, ex2});
  ExpectValidates(sigs.v_v(), {WASM_I32V(0), WASM_I32V(0), kExprThrow, ex3});
  ExpectFailure(sigs.v_v(), {WASM_F32(0.0), WASM_I32V(0), kExprThrow, ex3});
  ExpectFailure(sigs.v_v(), {kExprThrow, 99});
}

TEST_F(FunctionBodyDecoderTest, ThrowUnreachable) {
  uint8_t ex1 = builder.AddException(sigs.v_v());
  uint8_t ex2 = builder.AddException(sigs.v_i());
  ExpectValidates(sigs.i_i(), {WASM_LOCAL_GET(0), kExprThrow, ex1, WASM_NOP});
  ExpectValidates(sigs.v_i(), {WASM_LOCAL_GET(0), kExprThrow, ex2, WASM_NOP});
  ExpectValidates(sigs.i_i(), {WASM_LOCAL_GET(0), kExprThrow, ex1, WASM_ZERO});
  ExpectFailure(sigs.v_i(), {WASM_LOCAL_GET(0), kExprThrow, ex2, WASM_ZERO});
  ExpectFailure(sigs.i_i(),
                {WASM_LOCAL_GET(0), kExprThrow, ex1, WASM_F32(0.0)});
  ExpectFailure(sigs.v_i(),
                {WASM_LOCAL_GET(0), kExprThrow, ex2, WASM_F32(0.0)});
}

#define WASM_TRY_OP kExprTry, kVoidCode

TEST_F(FunctionBodyDecoderTest, TryCatch) {
  WASM_FEATURE_SCOPE(legacy_eh);
  uint8_t ex = builder.AddException(sigs.v_v());
  ExpectValidates(sigs.v_v(), {WASM_TRY_OP, kExprCatch, ex, kExprEnd});
  ExpectValidates(sigs.v_v(),
                  {WASM_TRY_OP, kExprCatch, ex, kExprCatchAll, kExprEnd});
  ExpectValidates(sigs.v_v(), {WASM_TRY_OP, kExprEnd}, kAppendEnd);
  ExpectFailure(sigs.v_v(),
                {WASM_TRY_OP, kExprCatchAll, kExprCatch, ex, kExprEnd},
                kAppendEnd, "catch after catch-all for try");
  ExpectFailure(sigs.v_v(),
                {WASM_TRY_OP, kExprCatchAll, kExprCatchAll, kExprEnd},
                kAppendEnd, "catch-all already present for try");
  ExpectFailure(sigs.v_v(), {kExprCatch, ex, kExprEnd}, kAppendEnd,
                "catch does not match a try");
}

TEST_F(FunctionBodyDecoderTest, Rethrow) {
  WASM_FEATURE_SCOPE(legacy_eh);

  ExpectValidates(sigs.v_v(),
                  {WASM_TRY_OP, kExprCatchAll, kExprRethrow, 0, kExprEnd});
  ExpectFailure(sigs.v_v(),
                {WASM_TRY_OP, kExprRethrow, 0, kExprCatch, kExprEnd},
                kAppendEnd, "rethrow not targeting catch or catch-all");
  ExpectFailure(sigs.v_v(), {WASM_BLOCK(kExprRethrow, 0)}, kAppendEnd,
                "rethrow not targeting catch or catch-all");
  ExpectFailure(sigs.v_v(), {kExprRethrow, 0}, kAppendEnd,
                "rethrow not targeting catch or catch-all");
}

TEST_F(FunctionBodyDecoderTest, TryDelegate) {
  WASM_FEATURE_SCOPE(legacy_eh);
  uint8_t ex = builder.AddException(sigs.v_v());

  ExpectValidates(sigs.v_v(), {WASM_TRY_OP,
                               WASM_TRY_DELEGATE(WASM_STMTS(kExprThrow, ex), 0),
                               kExprCatch, ex, kExprEnd});
  ExpectValidates(
      sigs.v_v(),
      {WASM_BLOCK(WASM_TRY_OP, WASM_TRY_DELEGATE(WASM_STMTS(kExprThrow, ex), 2),
                  kExprCatch, ex, kExprEnd)});
  ExpectValidates(sigs.v_v(),
                  {WASM_TRY_OP, kExprCatch, ex,
                   WASM_TRY_DELEGATE(WASM_STMTS(kExprThrow, ex), 0), kExprEnd},
                  kAppendEnd);
  ExpectValidates(sigs.v_v(),
                  {WASM_TRY_OP,
                   WASM_BLOCK(WASM_TRY_DELEGATE(WASM_STMTS(kExprThrow, ex), 0)),
                   kExprCatch, ex, kExprEnd},
                  kAppendEnd);

  ExpectFailure(
      sigs.v_v(),
      {WASM_BLOCK(WASM_TRY_OP, WASM_TRY_DELEGATE(WASM_STMTS(kExprThrow, ex), 3),
                  kExprCatch, ex, kExprEnd)},
      kAppendEnd, "invalid branch depth: 3");
  ExpectFailure(
      sigs.v_v(),
      {WASM_TRY_OP, WASM_TRY_OP, kExprCatch, ex, kExprDelegate, 0, kExprEnd},
      kAppendEnd, "delegate does not match a try");
  ExpectFailure(
      sigs.v_v(),
      {WASM_TRY_OP, WASM_TRY_OP, kExprCatchAll, kExprDelegate, 1, kExprEnd},
      kAppendEnd, "delegate does not match a try");
}

#undef WASM_TRY_OP

#define WASM_TRY_TABLE_OP kExprTryTable, kVoidCode

TEST_F(FunctionBodyDecoderTest, ThrowRef) {
  WASM_FEATURE_SCOPE(exnref);
  ExpectValidates(sigs.v_v(), {kExprBlock, kExnRefCode, WASM_TRY_TABLE_OP,
                               U32V_1(1), CatchKind::kCatchAllRef, 0, kExprEnd,
                               kExprBr, 1, kExprEnd, kExprThrowRef});
  ExpectValidates(sigs.v_v(), {kExprBlock, kVoidCode, kExprUnreachable,
                               kExprThrowRef, kExprEnd});
  ExpectFailure(
      sigs.v_v(),
      {WASM_REF_NULL(WASM_HEAP_TYPE(HeapType(HeapType::kExtern))),
       kExprThrowRef},
      kAppendEnd,
      "throw_ref[0] expected type exnref, found ref.null of type externref");
}

TEST_F(FunctionBodyDecoderTest, TryTable) {
  WASM_FEATURE_SCOPE(exnref);
  uint8_t ex = builder.AddException(sigs.v_v());
  ExpectValidates(sigs.v_v(),
                  {WASM_TRY_TABLE_OP, U32V_1(1), CatchKind::kCatch, ex,
                   U32V_1(0), kExprEnd},
                  kAppendEnd);
  ExpectValidates(sigs.v_v(),
                  {kExprBlock, kExnRefCode, WASM_TRY_TABLE_OP, U32V_1(1),
                   CatchKind::kCatchRef, ex, U32V_1(0), kExprEnd,
                   kExprUnreachable, kExprEnd, kExprDrop},
                  kAppendEnd);
  ExpectValidates(sigs.v_v(),
                  {WASM_TRY_TABLE_OP, U32V_1(1), CatchKind::kCatchAll,
                   U32V_1(0), kExprEnd, kExprUnreachable},
                  kAppendEnd);
  ExpectValidates(sigs.v_v(),
                  {kExprBlock, kExnRefCode, WASM_TRY_TABLE_OP, U32V_1(1),
                   CatchKind::kCatchAllRef, U32V_1(0), kExprEnd,
                   kExprUnreachable, kExprEnd, kExprDrop},
                  kAppendEnd);
  // All catch kinds at the same time.
  ExpectValidates(
      sigs.v_v(),
      {kExprBlock, kExnRefCode, WASM_TRY_TABLE_OP, U32V_1(4), CatchKind::kCatch,
       ex, U32V_1(1), CatchKind::kCatchRef, ex, U32V_1(0), CatchKind::kCatchAll,
       U32V_1(1), CatchKind::kCatchAllRef, U32V_1(0), kExprEnd,
       kExprUnreachable, kExprEnd, kExprDrop},
      kAppendEnd);
  // Duplicate catch-all.
  ExpectValidates(
      sigs.v_v(),
      {kExprBlock, kExnRefCode, WASM_TRY_TABLE_OP, U32V_1(4),
       CatchKind::kCatchAll, U32V_1(1), CatchKind::kCatchAll, U32V_1(1),
       CatchKind::kCatchAllRef, U32V_1(0), CatchKind::kCatchAllRef, U32V_1(0),
       kExprEnd, kExprUnreachable, kExprEnd, kExprDrop},
      kAppendEnd);
  // Catch-all before catch.
  ExpectValidates(
      sigs.v_v(),
      {WASM_TRY_TABLE_OP, U32V_1(2), CatchKind::kCatchAll, U32V_1(0),
       CatchKind::kCatch, ex, U32V_1(0), kExprEnd, kExprUnreachable},
      kAppendEnd);
  // Non-nullable exnref.
  ValueType kNonNullableExnRef = ValueType::Ref(HeapType::kExn);
  auto sig = FixedSizeSignature<ValueType>::Returns(kNonNullableExnRef);
  ModuleTypeIndex sig_id = builder.AddSignature(&sig);
  ExpectValidates(sigs.v_v(),
                  {kExprBlock, ToByte(sig_id), WASM_TRY_TABLE_OP, U32V_1(1),
                   CatchKind::kCatchRef, ex, U32V_1(0), kExprEnd,
                   kExprUnreachable, kExprEnd, kExprDrop},
                  kAppendEnd);

  constexpr uint8_t kInvalidCatchKind = kLastCatchKind + 1;
  ExpectFailure(sigs.v_v(),
                {WASM_TRY_TABLE_OP, U32V_1(1), kInvalidCatchKind, ex, U32V_1(0),
                 kExprEnd},
                kAppendEnd, "invalid catch kind in try table");
  // Branching to an exnref block with ref-less catch.
  ExpectFailure(sigs.v_v(),
                {kExprBlock, kExnRefCode, WASM_TRY_TABLE_OP, U32V_1(1), kCatch,
                 ex, U32V_1(0), kExprEnd, kExprUnreachable, kExprEnd},
                kAppendEnd,
                "catch kind generates 0 operands, target block expects 1");
  // Branching to a void block with catch-ref.
  ExpectFailure(sigs.v_v(),
                {kExprBlock, kVoidCode, WASM_TRY_TABLE_OP, U32V_1(1), kCatchRef,
                 ex, U32V_1(0), kExprEnd, kExprUnreachable, kExprEnd},
                kAppendEnd,
                "catch kind generates 1 operand, target block expects 0");
}

TEST_F(FunctionBodyDecoderTest, MultiValBlock1) {
  ModuleTypeIndex sig0 = builder.AddSignature(sigs.ii_v());
  ExpectValidates(
      sigs.i_ii(),
      {WASM_BLOCK_X(sig0, WASM_LOCAL_GET(0), WASM_LOCAL_GET(1)), kExprI32Add});
  ExpectFailure(sigs.i_ii(), {WASM_BLOCK_X(sig0, WASM_NOP), kExprI32Add},
                kAppendEnd,
                "expected 2 elements on the stack for fallthru, found 0");
  ExpectFailure(
      sigs.i_ii(), {WASM_BLOCK_X(sig0, WASM_LOCAL_GET(0)), kExprI32Add},
      kAppendEnd, "expected 2 elements on the stack for fallthru, found 1");
  ExpectFailure(sigs.i_ii(),
                {WASM_BLOCK_X(sig0, WASM_LOCAL_GET(0), WASM_LOCAL_GET(1),
                              WASM_LOCAL_GET(0)),
                 kExprI32Add},
                kAppendEnd,
                "expected 2 elements on the stack for fallthru, found 3");
  ExpectFailure(
      sigs.i_ii(),
      {WASM_BLOCK_X(sig0, WASM_LOCAL_GET(0), WASM_LOCAL_GET(1)), kExprF32Add},
      kAppendEnd, "f32.add[0] expected type f32, found block of type i32");

  ModuleTypeIndex sig1 = builder.AddSignature(sigs.v_i());
  ExpectFailure(
      sigs.v_i(),
      {WASM_LOCAL_GET(0), WASM_BLOCK(WASM_BLOCK_X(sig1, WASM_UNREACHABLE))},
      kAppendEnd,
      "not enough arguments on the stack for block (need 1, got 0)");
}

TEST_F(FunctionBodyDecoderTest, MultiValBlock2) {
  ModuleTypeIndex sig0 = builder.AddSignature(sigs.ii_v());
  ExpectValidates(sigs.i_ii(),
                  {WASM_BLOCK_X(sig0, WASM_LOCAL_GET(0), WASM_LOCAL_GET(1)),
                   WASM_I32_ADD(WASM_NOP, WASM_NOP)});
  ExpectFailure(sigs.i_ii(), {WASM_BLOCK_X(sig0, WASM_NOP),
                              WASM_I32_ADD(WASM_NOP, WASM_NOP)});
  ExpectFailure(sigs.i_ii(), {WASM_BLOCK_X(sig0, WASM_LOCAL_GET(0)),
                              WASM_I32_ADD(WASM_NOP, WASM_NOP)});
  ExpectFailure(sigs.i_ii(),
                {WASM_BLOCK_X(sig0, WASM_LOCAL_GET(0), WASM_LOCAL_GET(1),
                              WASM_LOCAL_GET(0)),
                 WASM_I32_ADD(WASM_NOP, WASM_NOP)});
  ExpectFailure(sigs.i_ii(),
                {WASM_BLOCK_X(sig0, WASM_LOCAL_GET(0), WASM_LOCAL_GET(1)),
                 WASM_F32_ADD(WASM_NOP, WASM_NOP)});
}

TEST_F(FunctionBodyDecoderTest, MultiValBlockBr) {
  ModuleTypeIndex sig0 = builder.AddSignature(sigs.ii_v());
  ExpectFailure(sigs.i_ii(), {WASM_BLOCK_X(sig0, WASM_LOCAL_GET(0), WASM_BR(0)),
                              kExprI32Add});
  ExpectValidates(sigs.i_ii(), {WASM_BLOCK_X(sig0, WASM_LOCAL_GET(0),
                                             WASM_LOCAL_GET(1), WASM_BR(0)),
                                kExprI32Add});
}

TEST_F(FunctionBodyDecoderTest, MultiValLoop1) {
  ModuleTypeIndex sig0 = builder.AddSignature(sigs.ii_v());
  ExpectValidates(
      sigs.i_ii(),
      {WASM_LOOP_X(sig0, WASM_LOCAL_GET(0), WASM_LOCAL_GET(1)), kExprI32Add});
  ExpectFailure(sigs.i_ii(), {WASM_LOOP_X(sig0, WASM_NOP), kExprI32Add});
  ExpectFailure(sigs.i_ii(),
                {WASM_LOOP_X(sig0, WASM_LOCAL_GET(0)), kExprI32Add});
  ExpectFailure(sigs.i_ii(), {WASM_LOOP_X(sig0, WASM_LOCAL_GET(0),
                                          WASM_LOCAL_GET(1), WASM_LOCAL_GET(0)),
                              kExprI32Add});
  ExpectFailure(
      sigs.i_ii(),
      {WASM_LOOP_X(sig0, WASM_LOCAL_GET(0), WASM_LOCAL_GET(1)), kExprF32Add});
}

TEST_F(FunctionBodyDecoderTest, MultiValIf) {
  ModuleTypeIndex sig0 = builder.AddSignature(sigs.ii_v());
  ExpectValidates(
      sigs.i_ii(),
      {WASM_IF_ELSE_X(sig0, WASM_LOCAL_GET(0),
                      WASM_SEQ(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1)),
                      WASM_SEQ(WASM_LOCAL_GET(1), WASM_LOCAL_GET(0))),
       kExprI32Add});
  ExpectFailure(sigs.i_ii(),
                {WASM_IF_ELSE_X(sig0, WASM_LOCAL_GET(0), WASM_NOP, WASM_NOP),
                 kExprI32Add});
  ExpectFailure(sigs.i_ii(),
                {WASM_IF_ELSE_X(sig0, WASM_LOCAL_GET(0), WASM_NOP,
                                WASM_SEQ(WASM_LOCAL_GET(1), WASM_LOCAL_GET(0))),
                 kExprI32Add});
  ExpectFailure(
      sigs.i_ii(),
      {WASM_IF_ELSE_X(sig0, WASM_LOCAL_GET(0),
                      WASM_SEQ(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1)), WASM_NOP),
       kExprI32Add});
  ExpectFailure(sigs.i_ii(),
                {WASM_IF_ELSE_X(sig0, WASM_LOCAL_GET(0), WASM_LOCAL_GET(0),
                                WASM_LOCAL_GET(1)),
                 kExprI32Add});
  ExpectFailure(sigs.i_ii(),
                {WASM_IF_ELSE_X(sig0, WASM_LOCAL_GET(0), WASM_LOCAL_GET(0),
                                WASM_SEQ(WASM_LOCAL_GET(1), WASM_LOCAL_GET(0))),
                 kExprI32Add});
  ExpectFailure(sigs.i_ii(),
                {WASM_IF_ELSE_X(sig0, WASM_LOCAL_GET(0),
                                WASM_SEQ(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1)),
                                WASM_LOCAL_GET(1)),
                 kExprI32Add});
  ExpectFailure(
      sigs.i_ii(),
      {WASM_IF_ELSE_X(
           sig0, WASM_LOCAL_GET(0),
           WASM_SEQ(WASM_LOCAL_GET(0), WASM_LOCAL_GET(0), WASM_LOCAL_GET(0)),
           WASM_SEQ(WASM_LOCAL_GET(1), WASM_LOCAL_GET(0), WASM_LOCAL_GET(0))),
       kExprI32Add});
  ExpectFailure(sigs.i_ii(),
                {WASM_IF_ELSE_X(sig0, WASM_LOCAL_GET(0),
                                WASM_SEQ(WASM_LOCAL_GET(0), WASM_LOCAL_GET(0),
                                         WASM_LOCAL_GET(0)),
                                WASM_SEQ(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))),
                 kExprI32Add});
  ExpectFailure(sigs.i_ii(),
                {WASM_IF_ELSE_X(sig0, WASM_LOCAL_GET(0),
                                WASM_SEQ(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1)),
                                WASM_SEQ(WASM_LOCAL_GET(1), WASM_LOCAL_GET(1),
                                         WASM_LOCAL_GET(1))),
                 kExprI32Add});
  ExpectFailure(sigs.i_ii(),
                {WASM_IF_ELSE_X(sig0, WASM_LOCAL_GET(0),
                                WASM_SEQ(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1)),
                                WASM_SEQ(WASM_LOCAL_GET(1), WASM_LOCAL_GET(0))),
                 kExprF32Add});
}

TEST_F(FunctionBodyDecoderTest, BlockParam) {
  ModuleTypeIndex sig1 = builder.AddSignature(sigs.i_i());
  ModuleTypeIndex sig2 = builder.AddSignature(sigs.i_ii());
  ExpectValidates(
      sigs.i_ii(),
      {WASM_LOCAL_GET(0), WASM_BLOCK_X(sig1, WASM_LOCAL_GET(1),
                                       WASM_I32_ADD(WASM_NOP, WASM_NOP))});
  ExpectValidates(sigs.i_ii(),
                  {WASM_LOCAL_GET(0), WASM_LOCAL_GET(1),
                   WASM_BLOCK_X(sig2, WASM_I32_ADD(WASM_NOP, WASM_NOP))});
  ExpectValidates(sigs.i_ii(), {WASM_LOCAL_GET(0), WASM_LOCAL_GET(1),
                                WASM_BLOCK_X(sig1, WASM_NOP),
                                WASM_I32_ADD(WASM_NOP, WASM_NOP)});
  ExpectFailure(sigs.i_ii(),
                {WASM_BLOCK_X(sig1, WASM_NOP), WASM_RETURN(WASM_LOCAL_GET(0))});
  ExpectFailure(sigs.i_ii(), {WASM_BLOCK_X(sig1, WASM_LOCAL_GET(0)),
                              WASM_RETURN(WASM_LOCAL_GET(0))});
  ExpectFailure(
      sigs.i_ii(),
      {WASM_LOCAL_GET(0), WASM_BLOCK_X(sig2, WASM_I32_ADD(WASM_NOP, WASM_NOP)),
       WASM_RETURN(WASM_LOCAL_GET(0))});
  ExpectFailure(sigs.i_ii(),
                {WASM_LOCAL_GET(0), WASM_BLOCK_X(sig1, WASM_F32_NEG(WASM_NOP)),
                 WASM_RETURN(WASM_LOCAL_GET(0))});
}

TEST_F(FunctionBodyDecoderTest, LoopParam) {
  ModuleTypeIndex sig1 = builder.AddSignature(sigs.i_i());
  ModuleTypeIndex sig2 = builder.AddSignature(sigs.i_ii());
  ExpectValidates(sigs.i_ii(), {WASM_LOCAL_GET(0),
                                WASM_LOOP_X(sig1, WASM_LOCAL_GET(1),
                                            WASM_I32_ADD(WASM_NOP, WASM_NOP))});
  ExpectValidates(sigs.i_ii(),
                  {WASM_LOCAL_GET(0), WASM_LOCAL_GET(1),
                   WASM_LOOP_X(sig2, WASM_I32_ADD(WASM_NOP, WASM_NOP))});
  ExpectValidates(sigs.i_ii(), {WASM_LOCAL_GET(0), WASM_LOCAL_GET(1),
                                WASM_LOOP_X(sig1, WASM_NOP),
                                WASM_I32_ADD(WASM_NOP, WASM_NOP)});
  ExpectFailure(sigs.i_ii(),
                {WASM_LOOP_X(sig1, WASM_NOP), WASM_RETURN(WASM_LOCAL_GET(0))});
  ExpectFailure(sigs.i_ii(), {WASM_LOOP_X(sig1, WASM_LOCAL_GET(0)),
                              WASM_RETURN(WASM_LOCAL_GET(0))});
  ExpectFailure(
      sigs.i_ii(),
      {WASM_LOCAL_GET(0), WASM_LOOP_X(sig2, WASM_I32_ADD(WASM_NOP, WASM_NOP)),
       WASM_RETURN(WASM_LOCAL_GET(0))});
  ExpectFailure(sigs.i_ii(),
                {WASM_LOCAL_GET(0), WASM_LOOP_X(sig1, WASM_F32_NEG(WASM_NOP)),
                 WASM_RETURN(WASM_LOCAL_GET(0))});
}

TEST_F(FunctionBodyDecoderTest, LoopParamBr) {
  ModuleTypeIndex sig1 = builder.AddSignature(sigs.i_i());
  ModuleTypeIndex sig2 = builder.AddSignature(sigs.i_ii());
  ExpectValidates(sigs.i_ii(),
                  {WASM_LOCAL_GET(0), WASM_LOOP_X(sig1, WASM_BR(0))});
  ExpectValidates(
      sigs.i_ii(),
      {WASM_LOCAL_GET(0), WASM_LOOP_X(sig1, WASM_BRV(0, WASM_LOCAL_GET(1)))});
  ExpectValidates(sigs.i_ii(), {WASM_LOCAL_GET(0), WASM_LOCAL_GET(1),
                                WASM_LOOP_X(sig2, WASM_BR(0))});
  ExpectValidates(
      sigs.i_ii(),
      {WASM_LOCAL_GET(0), WASM_LOOP_X(sig1, WASM_BLOCK_X(sig1, WASM_BR(1)))});
  ExpectFailure(sigs.i_ii(),
                {WASM_LOCAL_GET(0), WASM_LOOP_X(sig1, WASM_BLOCK(WASM_BR(1))),
                 WASM_RETURN(WASM_LOCAL_GET(0))});
  ExpectFailure(sigs.i_ii(), {WASM_LOCAL_GET(0), WASM_LOCAL_GET(1),
                              WASM_LOOP_X(sig2, WASM_BLOCK_X(sig1, WASM_BR(1))),
                              WASM_RETURN(WASM_LOCAL_GET(0))});
}

TEST_F(FunctionBodyDecoderTest, IfParam) {
  ModuleTypeIndex sig1 = builder.AddSignature(sigs.i_i());
  ModuleTypeIndex sig2 = builder.AddSignature(sigs.i_ii());
  ExpectValidates(sigs.i_ii(),
                  {WASM_LOCAL_GET(0),
                   WASM_IF_X(sig1, WASM_LOCAL_GET(0),
                             WASM_I32_ADD(WASM_NOP, WASM_LOCAL_GET(1)))});
  ExpectValidates(sigs.i_ii(),
                  {WASM_LOCAL_GET(0),
                   WASM_IF_ELSE_X(sig1, WASM_LOCAL_GET(0),
                                  WASM_I32_ADD(WASM_NOP, WASM_LOCAL_GET(1)),
                                  WASM_I32_EQZ(WASM_NOP))});
  ExpectValidates(
      sigs.i_ii(),
      {WASM_LOCAL_GET(0), WASM_LOCAL_GET(1),
       WASM_IF_ELSE_X(sig2, WASM_LOCAL_GET(0), WASM_I32_ADD(WASM_NOP, WASM_NOP),
                      WASM_I32_MUL(WASM_NOP, WASM_NOP))});
  ExpectValidates(sigs.i_ii(), {WASM_LOCAL_GET(0), WASM_LOCAL_GET(1),
                                WASM_IF_X(sig1, WASM_LOCAL_GET(0), WASM_NOP),
                                WASM_I32_ADD(WASM_NOP, WASM_NOP)});
  ExpectValidates(sigs.i_ii(),
                  {WASM_LOCAL_GET(0), WASM_LOCAL_GET(1),
                   WASM_IF_ELSE_X(sig1, WASM_LOCAL_GET(0), WASM_NOP,
                                  WASM_I32_EQZ(WASM_NOP)),
                   WASM_I32_ADD(WASM_NOP, WASM_NOP)});
}

TEST_F(FunctionBodyDecoderTest, Regression709741) {
  AddLocals(kWasmI32, kV8MaxWasmFunctionLocals - 1);
  ExpectValidates(sigs.v_v(), {WASM_NOP});
  uint8_t code[] = {WASM_NOP, WASM_END};

  for (size_t i = 0; i < arraysize(code); ++i) {
    constexpr bool kIsShared = false;
    FunctionBody body(sigs.v_v(), 0, code, code + i, kIsShared);
    WasmDetectedFeatures unused_detected_features;
    DecodeResult result =
        ValidateFunctionBody(this->zone(), WasmEnabledFeatures::All(), module,
                             &unused_detected_features, body);
    if (result.ok()) {
      std::ostringstream str;
      str << "Expected verification to fail";
    }
  }
}

TEST_F(FunctionBodyDecoderTest, MemoryInit) {
  builder.AddMemory();
  builder.SetDataSegmentCount(1);

  ExpectValidates(sigs.v_v(),
                  {WASM_MEMORY_INIT(0, WASM_ZERO, WASM_ZERO, WASM_ZERO)});
  ExpectFailure(sigs.v_v(),
                {WASM_TABLE_INIT(0, 1, WASM_ZERO, WASM_ZERO, WASM_ZERO)});
}

TEST_F(FunctionBodyDecoderTest, MemoryInitInvalid) {
  builder.AddMemory();
  builder.SetDataSegmentCount(1);

  uint8_t code[] = {WASM_MEMORY_INIT(0, WASM_ZERO, WASM_ZERO, WASM_ZERO),
                    WASM_END};
  for (size_t i = 0; i <= arraysize(code); ++i) {
    Validate(i == arraysize(code), sigs.v_v(), base::VectorOf(code, i),
             kOmitEnd);
  }
}

TEST_F(FunctionBodyDecoderTest, DataDrop) {
  builder.AddMemory();
  builder.SetDataSegmentCount(1);

  ExpectValidates(sigs.v_v(), {WASM_DATA_DROP(0)});
  ExpectFailure(sigs.v_v(), {WASM_DATA_DROP(1)});
}

TEST_F(FunctionBodyDecoderTest, DataSegmentIndexUnsigned) {
  builder.AddMemory();
  builder.SetDataSegmentCount(65);

  // Make sure that the index is interpreted as an unsigned number; 64 is
  // interpreted as -64 when decoded as a signed LEB.
  ExpectValidates(sigs.v_v(),
                  {WASM_MEMORY_INIT(64, WASM_ZERO, WASM_ZERO, WASM_ZERO)});
  ExpectValidates(sigs.v_v(), {WASM_DATA_DROP(64)});
}

TEST_F(FunctionBodyDecoderTest, MemoryCopy) {
  builder.AddMemory();

  ExpectValidates(sigs.v_v(),
                  {WASM_MEMORY0_COPY(WASM_ZERO, WASM_ZERO, WASM_ZERO)});
}

TEST_F(FunctionBodyDecoderTest, MemoryFill) {
  builder.AddMemory();

  ExpectValidates(sigs.v_v(),
                  {WASM_MEMORY_FILL(WASM_ZERO, WASM_ZERO, WASM_ZERO)});
}

TEST_F(FunctionBodyDecoderTest, BulkMemoryOpsWithoutMemory) {
  ExpectFailure(sigs.v_v(),
                {WASM
"""


```